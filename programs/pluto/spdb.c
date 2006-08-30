/* Security Policy Data Base (such as it is)
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * RCSID $Id: spdb.c,v 1.121 2005/08/05 19:16:48 mcr Exp $
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>
#include "pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "oswlog.h"

#include "defs.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "smartcard.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "connections.h"	/* needs id.h */
#include "state.h"
#include "packet.h"
#include "keys.h"
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "spdb.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */

#include "alg_info.h"
#include "kernel_alg.h"
#include "ike_alg.h"
#include "db_ops.h"
#define AD(x) x, elemsof(x)	/* Array Description */
#define AD_NULL NULL, 0

#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

/**************** Oakley (main mode) SA database ****************/

/**
 * the XAUTH server/client stuff is a bit confusing.
 * 
 * XAUTH overloads the RSA/PSK types with four more types which
 * mean RSA or PSK, but also include whether one is negotiating
 * that the inititator with be the XAUTH client, or the responder will be
 * XAUTH client. It seems unusual that the responder would be the one
 * to undergo XAUTH, since usually it is a roadwarrior to a gateway,
 *
 * however, the gateway may decide it needs to do a new phase 1, for
 * instance.
 *
 * So, when reading this, say "I'm an XAUTH client and I'm initiating",
 * or "I'm an XAUTH server and I'm initiating". Responses for the responder
 * (and validation of the response by the initiator) are determined by the
 * parse_sa_isakmp() part, which folds the XAUTH types into their native
 * types to figure out if it is acceptable to us.
 *
 *
 */

/*
 * A note about SHA1 usage here. The Hash algorithm is actually not
 * used for authentication. I.e. this is not a keyed MAC.
 * It is used as the Pseudo-random-function (PRF), and is therefore
 * not really impacted by recent SHA1 or MD5 breaks.
 *
 */

/* arrays of attributes for transforms, preshared key */

static struct db_attr otpsk1024des3md5[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_PRESHARED_KEY },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otpsk1536des3md5[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_PRESHARED_KEY },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otpsk1536aesmd5[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_AES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_PRESHARED_KEY },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otpsk1536aessha1[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_AES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA1 },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_PRESHARED_KEY },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otpsk1024des3sha1[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_PRESHARED_KEY },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otpsk1536des3sha1[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_PRESHARED_KEY },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

/* arrays of attributes for transforms, preshared key, Xauth version */

#ifdef XAUTH
static struct db_attr otpsk1024des3md5_xauthc[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitPreShared },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};
static struct db_attr otpsk1024des3sha1_xauthc[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA1 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitPreShared },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otpsk1536des3sha1_xauthc[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA1 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitPreShared },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otpsk1536des3md5_xauthc[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitPreShared },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otpsk1536aesmd5_xauthc[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_AES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitPreShared },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otpsk1536aessha1_xauthc[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_AES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA1 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitPreShared },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otpsk1024des3md5_xauths[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHRespPreShared },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otpsk1024des3sha1_xauths[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHRespPreShared },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otpsk1536des3md5_xauths[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHRespPreShared },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otpsk1536des3sha1_xauths[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA1 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHRespPreShared },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otpsk1536aesmd5_xauths[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_AES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHRespPreShared },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otpsk1536aessha1_xauths[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_AES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA1 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHRespPreShared },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};
#endif

/* arrays of attributes for transforms, RSA signatures */

static struct db_attr otrsasig1536aesmd5[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_AES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_RSA_SIG },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otrsasig1536aessha1[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_AES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA1 },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_RSA_SIG },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otrsasig1024des3md5[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_RSA_SIG },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otrsasig1536des3md5[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_RSA_SIG },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otrsasig1024des3sha1[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_RSA_SIG },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otrsasig1536des3sha1[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_RSA_SIG },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

#ifdef XAUTH
/* arrays of attributes for transforms, RSA signatures, with/Xauth */
/* xauth c is when Initiator will be the xauth client */
static struct db_attr otrsasig1024des3md5_xauthc[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitRSA },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otrsasig1536des3md5_xauthc[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitRSA },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otrsasig1536aesmd5_xauthc[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_AES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitRSA },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otrsasig1536aessha1_xauthc[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_AES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA1 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitRSA },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otrsasig1024des3sha1_xauthc[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA1 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitRSA },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otrsasig1536des3sha1_xauthc[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA1 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitRSA },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

/* arrays of attributes for transforms, RSA signatures, with/Xauth */
/*
 * xauth s is when the Responder will be the xauth client
 * the only time we do this is when we are initiating to a client
 * that we lost contact with. this is rare.
 */
static struct db_attr otrsasig1024des3md5_xauths[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHRespRSA },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otrsasig1536des3md5_xauths[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitRSA },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otrsasig1536aesmd5_xauths[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_AES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_MD5 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHInitRSA },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otrsasig1024des3sha1_xauths[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHRespRSA },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};

static struct db_attr otrsasig1536des3sha1_xauths[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA1 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHRespRSA },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};

static struct db_attr otrsasig1536aessha1_xauths[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_AES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_SHA1 },
	{ OAKLEY_AUTHENTICATION_METHOD, XAUTHRespRSA },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536 },
	};
#endif

/* We won't accept this, but by proposing it, we get to test
 * our rejection.  We better not propose it to an IKE daemon
 * that will accept it!
 */
#ifdef TEST_INDECENT_PROPOSAL
static struct db_attr otpsk1024des3tiger[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC },
	{ OAKLEY_HASH_ALGORITHM, OAKLEY_TIGER },
	{ OAKLEY_AUTHENTICATION_METHOD, OAKLEY_PRESHARED_KEY },
	{ OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024 },
	};
#endif /* TEST_INDECENT_PROPOSAL */

/* tables of transforms, in preference order (select based on AUTH) */

static struct db_trans oakley_trans_psk[] = {
#ifdef TEST_INDECENT_PROPOSAL
	{ KEY_IKE, AD(otpsk1024des3tiger) },
#endif
	{ KEY_IKE, AD(otpsk1536aessha1) },
	{ KEY_IKE, AD(otpsk1536aesmd5) },
	{ KEY_IKE, AD(otpsk1536des3sha1) },
	{ KEY_IKE, AD(otpsk1536des3md5) },
	{ KEY_IKE, AD(otpsk1024des3sha1) },
	{ KEY_IKE, AD(otpsk1024des3md5) },
    };

#ifdef XAUTH
static struct db_trans oakley_trans_psk_xauthc[] = {
	{ KEY_IKE, AD(otpsk1536aesmd5_xauthc) },
	{ KEY_IKE, AD(otpsk1536aessha1_xauthc) },
	{ KEY_IKE, AD(otpsk1536des3sha1_xauthc) },
	{ KEY_IKE, AD(otpsk1536des3md5_xauthc) },
	{ KEY_IKE, AD(otpsk1024des3sha1_xauthc) },
	{ KEY_IKE, AD(otpsk1024des3md5_xauthc) },
    };
static struct db_trans oakley_trans_psk_xauths[] = {
	{ KEY_IKE, AD(otpsk1536aessha1_xauths) },
	{ KEY_IKE, AD(otpsk1536aesmd5_xauths) },
	{ KEY_IKE, AD(otpsk1536des3sha1_xauths) },
	{ KEY_IKE, AD(otpsk1536des3md5_xauths) },
	{ KEY_IKE, AD(otpsk1024des3sha1_xauths) },
	{ KEY_IKE, AD(otpsk1024des3md5_xauths) },
    };
#endif

static struct db_trans oakley_trans_rsasig[] = {
	{ KEY_IKE, AD(otrsasig1536aessha1) },
	{ KEY_IKE, AD(otrsasig1536aesmd5) },
	{ KEY_IKE, AD(otrsasig1536des3sha1) },
	{ KEY_IKE, AD(otrsasig1536des3md5) },
	{ KEY_IKE, AD(otrsasig1024des3sha1) },
	{ KEY_IKE, AD(otrsasig1024des3md5) },
    };

#ifdef XAUTH
static struct db_trans oakley_trans_rsasig_xauthc[] = {
	{ KEY_IKE, AD(otrsasig1536aessha1_xauthc) },
	{ KEY_IKE, AD(otrsasig1536aesmd5_xauthc) },
	{ KEY_IKE, AD(otrsasig1536des3sha1_xauthc) },
	{ KEY_IKE, AD(otrsasig1536des3md5_xauthc) },
	{ KEY_IKE, AD(otrsasig1024des3sha1_xauthc) },
	{ KEY_IKE, AD(otrsasig1024des3md5_xauthc) },
    };
static struct db_trans oakley_trans_rsasig_xauths[] = {
	{ KEY_IKE, AD(otrsasig1536aessha1_xauths) },
	{ KEY_IKE, AD(otrsasig1536aesmd5_xauths) },
	{ KEY_IKE, AD(otrsasig1536des3sha1_xauths) },
	{ KEY_IKE, AD(otrsasig1536des3md5_xauths) },
	{ KEY_IKE, AD(otrsasig1024des3sha1_xauths) },
	{ KEY_IKE, AD(otrsasig1024des3md5_xauths) },
    };
#endif

/* In this table, either PSK or RSA sig is accepted.
 * The order matters, but I don't know what would be best.
 */
static struct db_trans oakley_trans_pskrsasig[] = {
#ifdef TEST_INDECENT_PROPOSAL
	{ KEY_IKE, AD(otpsk1024des3tiger) },
#endif
	{ KEY_IKE, AD(otrsasig1536des3md5) },
	{ KEY_IKE, AD(otpsk1536des3md5) },
	{ KEY_IKE, AD(otrsasig1536des3sha1) },
	{ KEY_IKE, AD(otpsk1536des3sha1) },
	{ KEY_IKE, AD(otrsasig1024des3sha1) },
	{ KEY_IKE, AD(otpsk1024des3sha1) },
	{ KEY_IKE, AD(otrsasig1024des3md5) },
	{ KEY_IKE, AD(otpsk1024des3md5) },
    };

#ifdef XAUTH
static struct db_trans oakley_trans_pskrsasig_xauthc[] = {
	{ KEY_IKE, AD(otrsasig1536des3md5_xauthc) },
	{ KEY_IKE, AD(otpsk1536des3md5_xauthc) },
	{ KEY_IKE, AD(otrsasig1536des3sha1_xauthc) },
	{ KEY_IKE, AD(otpsk1536des3sha1_xauthc) },
	{ KEY_IKE, AD(otrsasig1024des3sha1_xauthc) },
	{ KEY_IKE, AD(otpsk1024des3sha1_xauthc) },
	{ KEY_IKE, AD(otrsasig1024des3md5_xauthc) },
	{ KEY_IKE, AD(otpsk1024des3md5_xauthc) },
    };

static struct db_trans oakley_trans_pskrsasig_xauths[] = {
	{ KEY_IKE, AD(otrsasig1536des3md5_xauths) },
	{ KEY_IKE, AD(otpsk1536des3md5_xauths) },
	{ KEY_IKE, AD(otrsasig1536des3sha1_xauths) },
	{ KEY_IKE, AD(otpsk1536des3sha1_xauths) },
	{ KEY_IKE, AD(otrsasig1024des3sha1_xauths) },
	{ KEY_IKE, AD(otpsk1024des3sha1_xauths) },
	{ KEY_IKE, AD(otrsasig1024des3md5_xauths) },
	{ KEY_IKE, AD(otpsk1024des3md5_xauths) },
    };
#endif

/*
 * array of proposals to be conjoined (can only be one for Oakley)
 * AND of protocols.
 */
static struct db_prop oakley_pc_psk[] =
    { { PROTO_ISAKMP, AD(oakley_trans_psk) } };

static struct db_prop oakley_pc_rsasig[] =
    { { PROTO_ISAKMP, AD(oakley_trans_rsasig) } };

static struct db_prop oakley_pc_pskrsasig[] =
    { { PROTO_ISAKMP, AD(oakley_trans_pskrsasig) } };

#ifdef XAUTH
static struct db_prop oakley_pc_psk_xauths[] =
    { { PROTO_ISAKMP, AD(oakley_trans_psk_xauths) } };

static struct db_prop oakley_pc_rsasig_xauths[] =
    { { PROTO_ISAKMP, AD(oakley_trans_rsasig_xauths) } };

static struct db_prop oakley_pc_pskrsasig_xauths[] =
    { { PROTO_ISAKMP, AD(oakley_trans_pskrsasig_xauths) } };

static struct db_prop oakley_pc_psk_xauthc[] =
    { { PROTO_ISAKMP, AD(oakley_trans_psk_xauthc) } };

static struct db_prop oakley_pc_rsasig_xauthc[] =
    { { PROTO_ISAKMP, AD(oakley_trans_rsasig_xauthc) } };

static struct db_prop oakley_pc_pskrsasig_xauthc[] =
    { { PROTO_ISAKMP, AD(oakley_trans_pskrsasig_xauthc) } };
#endif

/* array of proposal conjuncts (can only be one) (OR of protocol) */
static struct db_prop_conj oakley_props_psk[] = { { AD(oakley_pc_psk) } };

static struct db_prop_conj oakley_props_rsasig[] = { { AD(oakley_pc_rsasig) } };

static struct db_prop_conj oakley_props_pskrsasig[] = { { AD(oakley_pc_pskrsasig) } };

#ifdef XAUTH
static struct db_prop_conj oakley_props_psk_xauthc[] = { { AD(oakley_pc_psk_xauthc) } };

static struct db_prop_conj oakley_props_rsasig_xauthc[] = { { AD(oakley_pc_rsasig_xauthc) } };

static struct db_prop_conj oakley_props_pskrsasig_xauthc[] = { { AD(oakley_pc_pskrsasig_xauthc) } };

static struct db_prop_conj oakley_props_psk_xauths[] = { { AD(oakley_pc_psk_xauths) } };

static struct db_prop_conj oakley_props_rsasig_xauths[] = { { AD(oakley_pc_rsasig_xauths) } };

static struct db_prop_conj oakley_props_pskrsasig_xauths[] = { { AD(oakley_pc_pskrsasig_xauths) } };
#endif

/* the sadb entry, subscripted by POLICY_PSK and POLICY_RSASIG bits */
struct db_sa oakley_sadb[] = {
    { AD_NULL },	                /* none */
    { AD(oakley_props_psk) },	        /* POLICY_PSK */
    { AD(oakley_props_rsasig) },	/* POLICY_RSASIG */
    { AD(oakley_props_pskrsasig) },	/* POLICY_PSK + POLICY_RSASIG */
#ifdef XAUTH
    { AD_NULL },                        /* POLICY_XAUTHSERVER + none */
    { AD(oakley_props_psk_xauths) },    /* POLICY_XAUTHSERVER + PSK */
    { AD(oakley_props_rsasig_xauths) }, /* POLICY_XAUTHSERVER + RSA */
    { AD(oakley_props_pskrsasig_xauths)},/* POLICY_XAUTHSERVER + RSA+PSK */
    { AD_NULL },                        /* POLICY_XAUTHCLIENT + none */
    { AD(oakley_props_psk_xauthc) },    /* POLICY_XAUTHCLIENT + PSK */
    { AD(oakley_props_rsasig_xauthc)},  /* POLICY_XAUTHCLIENT + RSA */
    { AD(oakley_props_pskrsasig_xauthc)},/* POLICY_XAUTHCLIENT + RSA+PSK */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + none */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + PSK */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + RSA */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + RSA+PSK */
#else /* XAUTH */
    { AD_NULL },                        /* POLICY_XAUTHSERVER + none */
    { AD_NULL },                        /* POLICY_XAUTHSERVER + PSK */
    { AD_NULL },                        /* POLICY_XAUTHSERVER + RSA */
    { AD_NULL },                        /* POLICY_XAUTHSERVER + RSA+PSK */
    { AD_NULL },                        /* POLICY_XAUTHCLIENT + none */
    { AD_NULL },                        /* POLICY_XAUTHCLIENT + PSK */
    { AD_NULL },                        /* POLICY_XAUTHCLIENT + RSA */
    { AD_NULL },                        /* POLICY_XAUTHCLIENT + RSA+PSK */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + none */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + PSK */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + RSA */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + RSA+PSK */
#endif /* XAUTH */
    };

#if defined(AGGRESSIVE)
/**************** Oakley (aggressive mode) SA database ****************/
/*
 * the Aggressive mode attributes must be seperate, because there
 * can be no choices --- since we must computer keying material,
 * we must actually just agree on what we are going to use.
 */

#if !defined(XAUTH) && defined(AGGRESSIVE)
#error there is no point in compiling aggressive mode without XAUTH
#endif

/* tables of transforms, in preference order (select based on AUTH) */
static struct db_trans oakley_am_trans_psk[] = {
	{ KEY_IKE, AD(otpsk1536des3sha1) },
    };

static struct db_trans oakley_am_trans_psk_xauthc[] = {
	{ KEY_IKE, AD(otpsk1536des3sha1_xauthc) },
    };
static struct db_trans oakley_am_trans_psk_xauths[] = {
	{ KEY_IKE, AD(otpsk1536des3sha1_xauths) },
    };

static struct db_trans oakley_am_trans_rsasig[] = {
	{ KEY_IKE, AD(otrsasig1536des3sha1) },
    };

static struct db_trans oakley_am_trans_rsasig_xauthc[] = {
	{ KEY_IKE, AD(otrsasig1536des3sha1_xauthc) },
    };
static struct db_trans oakley_am_trans_rsasig_xauths[] = {
	{ KEY_IKE, AD(otrsasig1536des3sha1_xauths) },
    };

/* array of proposals to be conjoined (can only be one for Oakley) */
static struct db_prop oakley_am_pc_psk[] =
    { { PROTO_ISAKMP, AD(oakley_am_trans_psk) } };

static struct db_prop oakley_am_pc_rsasig[] =
    { { PROTO_ISAKMP, AD(oakley_am_trans_rsasig) } };

static struct db_prop oakley_am_pc_psk_xauths[] =
    { { PROTO_ISAKMP, AD(oakley_am_trans_psk_xauths) } };

static struct db_prop oakley_am_pc_rsasig_xauths[] =
    { { PROTO_ISAKMP, AD(oakley_am_trans_rsasig_xauths) } };

static struct db_prop oakley_am_pc_psk_xauthc[] =
    { { PROTO_ISAKMP, AD(oakley_am_trans_psk_xauthc) } };

static struct db_prop oakley_am_pc_rsasig_xauthc[] =
    { { PROTO_ISAKMP, AD(oakley_am_trans_rsasig_xauthc) } };

/* array of proposal conjuncts (can only be one) */
static struct db_prop_conj oakley_am_props_psk[] =
    { { AD(oakley_am_pc_psk) } };

static struct db_prop_conj oakley_am_props_rsasig[] =
    { { AD(oakley_am_pc_rsasig) } };

static struct db_prop_conj oakley_am_props_psk_xauthc[] =
    { { AD(oakley_am_pc_psk_xauthc) } };

static struct db_prop_conj oakley_am_props_rsasig_xauthc[] =
    { { AD(oakley_am_pc_rsasig_xauthc) } };

static struct db_prop_conj oakley_am_props_psk_xauths[] =
    { { AD(oakley_am_pc_psk_xauths) } };

static struct db_prop_conj oakley_am_props_rsasig_xauths[] =
    { { AD(oakley_am_pc_rsasig_xauths) } };

/*
 * the sadb entry, subscripted
 *   by [ WEAK, XAUTHSERVER, XAUTHCLIENT, POLICY_RSASIG, POLICY_PSK ] bits
 */
struct db_sa oakley_am_sadb[] = {
    /* STRONG ALGORITHMS */
    { AD_NULL },	                /* none */
    { AD(oakley_am_props_psk) },	/* POLICY_PSK */
    { AD(oakley_am_props_rsasig) },	/* POLICY_RSASIG */
    { AD_NULL }, 	                /* PSK + RSASIG => invalid in AM */
    { AD_NULL },                        /* POLICY_XAUTHSERVER + none */
    { AD(oakley_am_props_psk_xauths) },    /* POLICY_XAUTHSERVER + PSK */
    { AD(oakley_am_props_rsasig_xauths) }, /* POLICY_XAUTHSERVER + RSA */
    { AD_NULL },                        /* XAUTHSERVER + RSA+PSK=>invalid */
    { AD_NULL },                        /* POLICY_XAUTHCLIENT + none */
    { AD(oakley_am_props_psk_xauthc) },    /* POLICY_XAUTHCLIENT + PSK */
    { AD(oakley_am_props_rsasig_xauthc)},  /* POLICY_XAUTHCLIENT + RSA */
    { AD_NULL },                        /* XAUTHCLIENT + RSA+PSK=>invalid */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + none */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + PSK */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + RSA */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + RSA+PSK */
#if 0
    /* weaker ALGORITHMS */
    { AD_NULL },	                /* none */
    { AD(oakley_am_props_psk) },	/* POLICY_PSK */
    { AD(oakley_am_props_rsasig) },	/* POLICY_RSASIG */
    { AD(oakley_am_props_pskrsasig) },	/* POLICY_PSK + POLICY_RSASIG */
    { AD_NULL },                        /* POLICY_XAUTHSERVER + none */
    { AD(oakley_am_props_psk_xauths) },    /* POLICY_XAUTHSERVER + PSK */
    { AD(oakley_am_props_rsasig_xauths) }, /* POLICY_XAUTHSERVER + RSA */
    { AD(oakley_am_props_pskrsasig_xauths)},/* POLICY_XAUTHSERVER + RSA+PSK */
    { AD_NULL },                        /* POLICY_XAUTHCLIENT + none */
    { AD(oakley_am_props_psk_xauthc) },    /* POLICY_XAUTHCLIENT + PSK */
    { AD(oakley_am_props_rsasig_xauthc)},  /* POLICY_XAUTHCLIENT + RSA */
    { AD(oakley_am_props_pskrsasig_xauthc)},/* POLICY_XAUTHCLIENT + RSA+PSK */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + none */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + PSK */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + RSA */
    { AD_NULL },                        /* XAUTHCLIENT+XAUTHSERVER + RSA+PSK */
#endif
    };

#endif /* AGGRESSIVE */

/**************** IPsec (quick mode) SA database ****************/

/* arrays of attributes for transforms */

static struct db_attr espmd5_attr[] = {
    { AUTH_ALGORITHM, AUTH_ALGORITHM_HMAC_MD5 },
    };

static struct db_attr espsha1_attr[] = {
    { AUTH_ALGORITHM, AUTH_ALGORITHM_HMAC_SHA1 },
    };

static struct db_attr ah_HMAC_MD5_attr[] = {
    { AUTH_ALGORITHM, AUTH_ALGORITHM_HMAC_MD5 },
    };

static struct db_attr ah_HMAC_SHA1_attr[] = {
    { AUTH_ALGORITHM, AUTH_ALGORITHM_HMAC_SHA1 },
    };

/* arrays of transforms, each in in preference order */

static struct db_trans espa_trans[] = {
    { ESP_AES,  AD(espsha1_attr) },
    { ESP_AES,  AD(espmd5_attr) },
    { ESP_3DES,    AD(espsha1_attr) },
    { ESP_3DES,    AD(espmd5_attr) },
    };

static struct db_trans esp_trans[] = {
    { ESP_3DES, AD_NULL },
    };

#ifdef SUPPORT_ESP_NULL
static struct db_trans espnull_trans[] = {
    { ESP_NULL, AD(espsha1_attr) },
    { ESP_NULL, AD(espmd5_attr) },
    };
#endif /* SUPPORT_ESP_NULL */

static struct db_trans ah_trans[] = {
    { AH_SHA, AD(ah_HMAC_SHA1_attr) },
    { AH_MD5, AD(ah_HMAC_MD5_attr) },
    };

static struct db_trans ipcomp_trans[] = {
    { IPCOMP_DEFLATE, AD_NULL },
    };

/* arrays of proposals to be conjoined */

static struct db_prop ah_pc[] = {
    { PROTO_IPSEC_AH, AD(ah_trans) },
    };

#ifdef SUPPORT_ESP_NULL
static struct db_prop espnull_pc[] = {
    { PROTO_IPSEC_ESP, AD(espnull_trans) },
    };
#endif /* SUPPORT_ESP_NULL */

static struct db_prop esp_pc[] = {
    { PROTO_IPSEC_ESP, AD(espa_trans) },
    };

static struct db_prop ah_esp_pc[] = {
    { PROTO_IPSEC_AH, AD(ah_trans) },
    { PROTO_IPSEC_ESP, AD(esp_trans) },
    };

static struct db_prop compress_pc[] = {
    { PROTO_IPCOMP, AD(ipcomp_trans) },
    };

static struct db_prop ah_compress_pc[] = {
    { PROTO_IPSEC_AH, AD(ah_trans) },
    { PROTO_IPCOMP, AD(ipcomp_trans) },
    };

#ifdef SUPPORT_ESP_NULL
static struct db_prop espnull_compress_pc[] = {
    { PROTO_IPSEC_ESP, AD(espnull_trans) },
    { PROTO_IPCOMP, AD(ipcomp_trans) },
    };
#endif /* SUPPORT_ESP_NULL */

static struct db_prop esp_compress_pc[] = {
    { PROTO_IPSEC_ESP, AD(espa_trans) },
    { PROTO_IPCOMP, AD(ipcomp_trans) },
    };

static struct db_prop ah_esp_compress_pc[] = {
    { PROTO_IPSEC_AH, AD(ah_trans) },
    { PROTO_IPSEC_ESP, AD(esp_trans) },
    { PROTO_IPCOMP, AD(ipcomp_trans) },
    };

/* arrays of proposal alternatives (each element is a conjunction) */

static struct db_prop_conj ah_props[] = {
    { AD(ah_pc) },
#ifdef SUPPORT_ESP_NULL
    { AD(espnull_pc) }
#endif
    };

static struct db_prop_conj esp_props[] =
    { { AD(esp_pc) } };

static struct db_prop_conj ah_esp_props[] =
    { { AD(ah_esp_pc) } };

static struct db_prop_conj compress_props[] = {
    { AD(compress_pc) },
    };

static struct db_prop_conj ah_compress_props[] = {
    { AD(ah_compress_pc) },
#ifdef SUPPORT_ESP_NULL
    { AD(espnull_compress_pc) }
#endif
    };

static struct db_prop_conj esp_compress_props[] =
    { { AD(esp_compress_pc) } };

static struct db_prop_conj ah_esp_compress_props[] =
    { { AD(ah_esp_compress_pc) } };

/* The IPsec sadb is subscripted by a bitset (subset of policy)
 * with members from { POLICY_ENCRYPT, POLICY_AUTHENTICATE, POLICY_COMPRESS }
 * shifted right by POLICY_IPSEC_SHIFT.
 */
struct db_sa ipsec_sadb[1 << 3] = {
    { AD_NULL },	/* none */
    { AD(esp_props) },	/* POLICY_ENCRYPT */
    { AD(ah_props) },	/* POLICY_AUTHENTICATE */
    { AD(ah_esp_props) },	/* POLICY_ENCRYPT+POLICY_AUTHENTICATE */
    { AD(compress_props) },	/* POLICY_COMPRESS */
    { AD(esp_compress_props) },	/* POLICY_ENCRYPT+POLICY_COMPRESS */
    { AD(ah_compress_props) },	/* POLICY_AUTHENTICATE+POLICY_COMPRESS */
    { AD(ah_esp_compress_props) },	/* POLICY_ENCRYPT+POLICY_AUTHENTICATE+POLICY_COMPRESS */
    };

#undef AD
#undef AD_NULL

void
free_sa_trans(struct db_trans *tr)
{
    if(tr->attrs) {
	pfree(tr->attrs);
    }
}

void
free_sa_prop(struct db_prop *dp)
{
    int i;
    for(i=0; i<dp->trans_cnt; i++) {
	free_sa_trans(&dp->trans[i]);
    }
    if(dp->trans) {
	pfree(dp->trans);
    }
}

void
free_sa_prop_conj(struct db_prop_conj *pc)
{
    int i;
    for(i=0; i<pc->prop_cnt; i++) {
	free_sa_prop(&pc->props[i]);
    }
    if(pc->props) {
	pfree(pc->props);
    }
}

void
free_sa(struct db_sa *f)
{
    int i;
    if(f == NULL) return;

    for(i=0; i<f->prop_conj_cnt; i++) {
	free_sa_prop_conj(&f->prop_conjs[i]);
    }
    if(f->prop_conjs) {
	pfree(f->prop_conjs);
    }
    if(f) {
	pfree(f);
    }
}

void clone_trans(struct db_trans *tr)
{
    tr->attrs = clone_bytes(tr->attrs
			    , tr->attr_cnt*sizeof(tr->attrs[0])
			    , "sa copy attrs array");
}

void clone_prop(struct db_prop *p, int extra)
{
    int i;

    p->trans = clone_bytes(p->trans
			  , (p->trans_cnt+extra)*sizeof(p->trans[0])
			  , "sa copy trans array");
    for(i=0; i<p->trans_cnt; i++) {
	clone_trans(&p->trans[i]);
    }
}

void clone_propconj(struct db_prop_conj *pc, int extra)
{
    int i;

    pc->props = clone_bytes(pc->props
			   , (pc->prop_cnt+extra)*sizeof(pc->props[0])
			   , "sa copy prop array");
    for(i=0; i<pc->prop_cnt; i++) {
	clone_prop(&pc->props[i], 0);
    }
}

struct db_sa *sa_copy_sa(struct db_sa *sa, int extra)
{
    int i;
    struct db_sa *nsa;

    nsa = clone_thing(*sa, "sa copy prop_conj");
    nsa->prop_conjs =
	clone_bytes(nsa->prop_conjs
		    , (nsa->prop_conj_cnt+extra)*sizeof(nsa->prop_conjs[0])
		    , "sa copy prop conj array");

    for(i=0; i<nsa->prop_conj_cnt; i++) {
	clone_propconj(&nsa->prop_conjs[i], 0);
    }
    
    return nsa;
}

/*
 * clone the sa, but keep only the first proposal
 */
struct db_sa *sa_copy_sa_first(struct db_sa *sa)
{
    struct db_sa *nsa;
    struct db_prop_conj *pc;
    struct db_prop *p;

    nsa = clone_thing(*sa, "sa copy prop_conj");
    if(nsa->prop_conj_cnt == 0) {
      return nsa;
    }
    nsa->prop_conj_cnt = 1;
    nsa->prop_conjs = clone_bytes(nsa->prop_conjs
				  , sizeof(nsa->prop_conjs[0])
				  , "sa copy 1 prop conj array");

    pc = &nsa->prop_conjs[0];
    if(pc->prop_cnt == 0) {
      return nsa;
    }
    pc->prop_cnt = 1;
    pc->props = clone_bytes(pc->props
			    , sizeof(pc->props[0])
			    , "sa copy 1 prop array");

    p = &pc->props[0];
    if(p->trans_cnt == 0) {
      return nsa;
    }
    p->trans_cnt = 1;
    p->trans = clone_bytes(p->trans
			   , sizeof(p->trans[0])
			   , "sa copy 1 trans array");

    clone_trans(&p->trans[0]);
    return nsa;
}

/*
 * this routine takes two proposals and conjoins them (or)
 *
 * 
 */
struct db_sa *
sa_merge_proposals(struct db_sa *a, struct db_sa *b)
{
    struct db_sa *n;
    int i,j,k;

    if(a == NULL || a->prop_conj_cnt == 0) {
	return sa_copy_sa(b, 0);
    }
    if(b == NULL || b->prop_conj_cnt == 0) {
	return sa_copy_sa(a, 0);
    }

    n = clone_thing(*a, "conjoin sa");

    passert(a->prop_conj_cnt == b->prop_conj_cnt);
    passert(a->prop_conj_cnt == 1);

    n->prop_conjs =
	clone_bytes(n->prop_conjs
		    , n->prop_conj_cnt*sizeof(n->prop_conjs[0])
		    , "sa copy prop conj array");

    for(i=0; i<n->prop_conj_cnt; i++) {
	struct db_prop_conj *pca= &n->prop_conjs[i];
	struct db_prop_conj *pcb= &b->prop_conjs[i];

	passert(pca->prop_cnt == pcb->prop_cnt);
	passert(pca->prop_cnt == 1);

	pca->props = clone_bytes(pca->props
				, pca->prop_cnt*sizeof(pca->props[0])
				, "sa copy prop array");

	for(j=0; j<pca->prop_cnt; j++) {
	    struct db_prop *pa = &pca->props[j];
	    struct db_prop *pb = &pcb->props[j];
	    struct db_trans *t;
	    int t_cnt = (pa->trans_cnt+pb->trans_cnt);

	    t = alloc_bytes(t_cnt*sizeof(pa->trans[0])
			    , "sa copy trans array");

	    memcpy(t, pa->trans, (pa->trans_cnt)*sizeof(pa->trans[0]));
	    memcpy(t+(pa->trans_cnt)
		   , pb->trans
		   , (pb->trans_cnt)*sizeof(pa->trans[0]));

	    pa->trans = t;
	    pa->trans_cnt = t_cnt;
	    for(k=0; k<pa->trans_cnt; k++) {
		clone_trans(&pa->trans[k]);
	    }
	}
    }

    return n;
}

/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * End:
 */
