/* Security Policy Data Base (such as it is)
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2003-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2006 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2008-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
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
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libreswan.h>
#include <libreswan/ipsec_policy.h>
#include "libreswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#ifdef XAUTH_HAVE_PAM
#include <security/pam_appl.h>
#endif
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "keys.h"
#include "kernel.h"     /* needs connections.h */
#include "log.h"
#include "spdb.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */

#include "alg_info.h"
#include "kernel_alg.h"
#include "ike_alg.h"
#include "db_ops.h"

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
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otpsk1536des3md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otpsk2048des3md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP2048 },
};

static struct db_attr otpsk1024aesmd5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1024 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otpsk1536aesmd5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otpsk2048aesmd5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP2048 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otpsk1024aessha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1024 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otpsk1536aessha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otpsk2048aessha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP2048 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otpsk1024des3sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otpsk1536des3sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otpsk2048des3sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP2048 },
};

/* arrays of attributes for transforms, preshared key, Xauth version */

#ifdef XAUTH
static struct db_attr otpsk1024des3md5_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  XAUTHInitPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1024 },
};
static struct db_attr otpsk1024des3sha1_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  XAUTHInitPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otpsk1536des3sha1_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  XAUTHInitPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otpsk1536des3md5_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  XAUTHInitPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otpsk1536aesmd5_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  XAUTHInitPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otpsk1536aessha1_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  XAUTHInitPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otpsk1024des3md5_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  XAUTHRespPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otpsk1024des3sha1_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  XAUTHRespPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otpsk1536des3md5_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  XAUTHRespPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otpsk1536des3sha1_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  XAUTHRespPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otpsk1536aesmd5_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  XAUTHRespPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otpsk1536aessha1_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  XAUTHRespPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};
#endif

/* arrays of attributes for transforms, RSA signatures */

static struct db_attr otrsasig1024aesmd5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1024 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otrsasig1536aesmd5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otrsasig2048aesmd5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP2048 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otrsasig1024aessha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1024 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otrsasig1536aessha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otrsasig2048aessha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP2048 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otrsasig1024des3md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otrsasig1536des3md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otrsasig2048des3md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP2048 },
};

static struct db_attr otrsasig1024des3sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otrsasig1536des3sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otrsasig2048des3sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP2048 },
};

#ifdef XAUTH
/* arrays of attributes for transforms, RSA signatures, with/Xauth */
/* xauth c is when Initiator will be the xauth client */
static struct db_attr otrsasig1024des3md5_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otrsasig1536des3md5_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otrsasig1536aesmd5_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otrsasig1536aessha1_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otrsasig1024des3sha1_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otrsasig1536des3sha1_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
};

/* arrays of attributes for transforms, RSA signatures, with/Xauth */
/*
 * xauth s is when the Responder will be the xauth client
 * the only time we do this is when we are initiating to a client
 * that we lost contact with. this is rare.
 */
static struct db_attr otrsasig1024des3md5_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHRespRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otrsasig1536des3md5_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otrsasig1536aesmd5_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otrsasig1024des3sha1_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHRespRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otrsasig1536des3sha1_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHRespRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otrsasig1536aessha1_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHRespRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};
#endif

/* We won't accept this, but by proposing it, we get to test
 * our rejection.  We better not propose it to an IKE daemon
 * that will accept it!
 */
#ifdef TEST_INDECENT_PROPOSAL
static struct db_attr otpsk1024des3tiger[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_TIGER },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val =
		  OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP1024 },
};
#endif /* TEST_INDECENT_PROPOSAL */

/* tables of transforms, in preference order (select based on AUTH) */

static struct db_trans oakley_trans_psk[] = {
#ifdef TEST_INDECENT_PROPOSAL
	{ AD_TR(KEY_IKE, otpsk1024des3tiger) },
#endif
	{ AD_TR(KEY_IKE, otpsk2048aessha1) },
	{ AD_TR(KEY_IKE, otpsk2048aesmd5) },
	{ AD_TR(KEY_IKE, otpsk2048des3sha1) },
	{ AD_TR(KEY_IKE, otpsk2048des3md5) },
	{ AD_TR(KEY_IKE, otpsk1536aessha1) },
	{ AD_TR(KEY_IKE, otpsk1536aesmd5) },
	{ AD_TR(KEY_IKE, otpsk1536des3sha1) },
	{ AD_TR(KEY_IKE, otpsk1536des3md5) },
	{ AD_TR(KEY_IKE, otpsk1024aessha1) },
	{ AD_TR(KEY_IKE, otpsk1024aesmd5) },
	{ AD_TR(KEY_IKE, otpsk1024des3sha1) },
	{ AD_TR(KEY_IKE, otpsk1024des3md5) },
};

#ifdef XAUTH
static struct db_trans oakley_trans_psk_xauthc[] = {
	{ AD_TR(KEY_IKE, otpsk1536aesmd5_xauthc) },
	{ AD_TR(KEY_IKE, otpsk1536aessha1_xauthc) },
	{ AD_TR(KEY_IKE, otpsk1536des3sha1_xauthc) },
	{ AD_TR(KEY_IKE, otpsk1536des3md5_xauthc) },
	{ AD_TR(KEY_IKE, otpsk1024des3sha1_xauthc) },
	{ AD_TR(KEY_IKE, otpsk1024des3md5_xauthc) },
};
static struct db_trans oakley_trans_psk_xauths[] = {
	{ AD_TR(KEY_IKE, otpsk1536aessha1_xauths) },
	{ AD_TR(KEY_IKE, otpsk1536aesmd5_xauths) },
	{ AD_TR(KEY_IKE, otpsk1536des3sha1_xauths) },
	{ AD_TR(KEY_IKE, otpsk1536des3md5_xauths) },
	{ AD_TR(KEY_IKE, otpsk1024des3sha1_xauths) },
	{ AD_TR(KEY_IKE, otpsk1024des3md5_xauths) },
};
#endif

static struct db_trans oakley_trans_rsasig[] = {
	{ AD_TR(KEY_IKE, otrsasig2048aessha1) },
	{ AD_TR(KEY_IKE, otrsasig2048aesmd5) },
	{ AD_TR(KEY_IKE, otrsasig2048des3sha1) },
	{ AD_TR(KEY_IKE, otrsasig2048des3md5) },
	{ AD_TR(KEY_IKE, otrsasig1536aessha1) },
	{ AD_TR(KEY_IKE, otrsasig1536aesmd5) },
	{ AD_TR(KEY_IKE, otrsasig1536des3sha1) },
	{ AD_TR(KEY_IKE, otrsasig1536des3md5) },
	{ AD_TR(KEY_IKE, otrsasig1024des3sha1) },
	{ AD_TR(KEY_IKE, otrsasig1024des3md5) },
	{ AD_TR(KEY_IKE, otrsasig1024aessha1) },
	{ AD_TR(KEY_IKE, otrsasig1024aesmd5) },
};

#ifdef XAUTH
static struct db_trans oakley_trans_rsasig_xauthc[] = {
	{ AD_TR(KEY_IKE, otrsasig1536aessha1_xauthc) },
	{ AD_TR(KEY_IKE, otrsasig1536aesmd5_xauthc) },
	{ AD_TR(KEY_IKE, otrsasig1536des3sha1_xauthc) },
	{ AD_TR(KEY_IKE, otrsasig1536des3md5_xauthc) },
	{ AD_TR(KEY_IKE, otrsasig1024des3sha1_xauthc) },
	{ AD_TR(KEY_IKE, otrsasig1024des3md5_xauthc) },
};
static struct db_trans oakley_trans_rsasig_xauths[] = {
	{ AD_TR(KEY_IKE, otrsasig1536aessha1_xauths) },
	{ AD_TR(KEY_IKE, otrsasig1536aesmd5_xauths) },
	{ AD_TR(KEY_IKE, otrsasig1536des3sha1_xauths) },
	{ AD_TR(KEY_IKE, otrsasig1536des3md5_xauths) },
	{ AD_TR(KEY_IKE, otrsasig1024des3sha1_xauths) },
	{ AD_TR(KEY_IKE, otrsasig1024des3md5_xauths) },
};
#endif

/* In this table, either PSK or RSA sig is accepted.
 * The order matters, but I don't know what would be best.
 */
static struct db_trans oakley_trans_pskrsasig[] = {
#ifdef TEST_INDECENT_PROPOSAL
	{ AD_TR(KEY_IKE, otpsk1024des3tiger) },
#endif
	{ AD_TR(KEY_IKE, otrsasig2048des3sha1) },
	{ AD_TR(KEY_IKE, otpsk2048des3sha1) },
	{ AD_TR(KEY_IKE, otrsasig2048des3md5) },
	{ AD_TR(KEY_IKE, otpsk2048des3md5) },
	{ AD_TR(KEY_IKE, otrsasig1536des3sha1) },
	{ AD_TR(KEY_IKE, otpsk1536des3sha1) },
	{ AD_TR(KEY_IKE, otrsasig1536des3md5) },
	{ AD_TR(KEY_IKE, otpsk1536des3md5) },
	{ AD_TR(KEY_IKE, otrsasig1024des3sha1) },
	{ AD_TR(KEY_IKE, otpsk1024des3sha1) },
	{ AD_TR(KEY_IKE, otrsasig1024des3md5) },
	{ AD_TR(KEY_IKE, otpsk1024des3md5) },
};

#ifdef XAUTH
static struct db_trans oakley_trans_pskrsasig_xauthc[] = {
	{ AD_TR(KEY_IKE, otrsasig1536des3md5_xauthc) },
	{ AD_TR(KEY_IKE, otpsk1536des3md5_xauthc) },
	{ AD_TR(KEY_IKE, otrsasig1536des3sha1_xauthc) },
	{ AD_TR(KEY_IKE, otpsk1536des3sha1_xauthc) },
	{ AD_TR(KEY_IKE, otrsasig1024des3sha1_xauthc) },
	{ AD_TR(KEY_IKE, otpsk1024des3sha1_xauthc) },
	{ AD_TR(KEY_IKE, otrsasig1024des3md5_xauthc) },
	{ AD_TR(KEY_IKE, otpsk1024des3md5_xauthc) },
};

static struct db_trans oakley_trans_pskrsasig_xauths[] = {
	{ AD_TR(KEY_IKE, otrsasig1536des3md5_xauths) },
	{ AD_TR(KEY_IKE, otpsk1536des3md5_xauths) },
	{ AD_TR(KEY_IKE, otrsasig1536des3sha1_xauths) },
	{ AD_TR(KEY_IKE, otpsk1536des3sha1_xauths) },
	{ AD_TR(KEY_IKE, otrsasig1024des3sha1_xauths) },
	{ AD_TR(KEY_IKE, otpsk1024des3sha1_xauths) },
	{ AD_TR(KEY_IKE, otrsasig1024des3md5_xauths) },
	{ AD_TR(KEY_IKE, otpsk1024des3md5_xauths) },
};
#endif

/*
 * array of proposals to be conjoined (can only be one for Oakley)
 * AND of protocols.
 */
static struct db_prop oakley_pc_psk[] =
{ { AD_PR(PROTO_ISAKMP, oakley_trans_psk) } };

static struct db_prop oakley_pc_rsasig[] =
{ { AD_PR(PROTO_ISAKMP, oakley_trans_rsasig) } };

static struct db_prop oakley_pc_pskrsasig[] =
{ { AD_PR(PROTO_ISAKMP, oakley_trans_pskrsasig) } };

#ifdef XAUTH
static struct db_prop oakley_pc_psk_xauths[] =
{ { AD_PR(PROTO_ISAKMP, oakley_trans_psk_xauths) } };

static struct db_prop oakley_pc_rsasig_xauths[] =
{ { AD_PR(PROTO_ISAKMP, oakley_trans_rsasig_xauths) } };

static struct db_prop oakley_pc_pskrsasig_xauths[] =
{ { AD_PR(PROTO_ISAKMP, oakley_trans_pskrsasig_xauths) } };

static struct db_prop oakley_pc_psk_xauthc[] =
{ { AD_PR(PROTO_ISAKMP, oakley_trans_psk_xauthc) } };

static struct db_prop oakley_pc_rsasig_xauthc[] =
{ { AD_PR(PROTO_ISAKMP, oakley_trans_rsasig_xauthc) } };

static struct db_prop oakley_pc_pskrsasig_xauthc[] =
{ { AD_PR(PROTO_ISAKMP, oakley_trans_pskrsasig_xauthc) } };
#endif

/* array of proposal conjuncts (can only be one) (OR of protocol) */
static struct db_prop_conj oakley_props_psk[] = { { AD_PC(oakley_pc_psk) } };

static struct db_prop_conj oakley_props_rsasig[] =
{ { AD_PC(oakley_pc_rsasig) } };

static struct db_prop_conj oakley_props_pskrsasig[] = { { AD_PC(
								  oakley_pc_pskrsasig) } };

#ifdef XAUTH
static struct db_prop_conj oakley_props_psk_xauthc[] = { { AD_PC(
								   oakley_pc_psk_xauthc) } };

static struct db_prop_conj oakley_props_rsasig_xauthc[] = { { AD_PC(
								      oakley_pc_rsasig_xauthc) } };

static struct db_prop_conj oakley_props_pskrsasig_xauthc[] = { { AD_PC(
									 oakley_pc_pskrsasig_xauthc) } };

static struct db_prop_conj oakley_props_psk_xauths[] = { { AD_PC(
								   oakley_pc_psk_xauths) } };

static struct db_prop_conj oakley_props_rsasig_xauths[] = { { AD_PC(
								      oakley_pc_rsasig_xauths) } };

static struct db_prop_conj oakley_props_pskrsasig_xauths[] = { { AD_PC(
									 oakley_pc_pskrsasig_xauths) } };
#endif

/* the sadb entry, subscripted by POLICY_PSK and POLICY_RSASIG bits */
struct db_sa oakley_sadb[] = {
	{ AD_NULL },                                    /* none */
	{ AD_SAp(oakley_props_psk) },                   /* POLICY_PSK */
	{ AD_SAp(oakley_props_rsasig) },                /* POLICY_RSASIG */
	{ AD_SAp(oakley_props_pskrsasig) },             /* POLICY_PSK + POLICY_RSASIG */
#ifdef XAUTH
	{ AD_NULL },                                    /* POLICY_XAUTHSERVER + none */
	{ AD_SAp(oakley_props_psk_xauths) },            /* POLICY_XAUTHSERVER + PSK */
	{ AD_SAp(oakley_props_rsasig_xauths) },         /* POLICY_XAUTHSERVER + RSA */
	{ AD_SAp(oakley_props_pskrsasig_xauths) },      /* POLICY_XAUTHSERVER + RSA+PSK */
	{ AD_NULL },                                    /* POLICY_XAUTHCLIENT + none */
	{ AD_SAp(oakley_props_psk_xauthc) },            /* POLICY_XAUTHCLIENT + PSK */
	{ AD_SAp(oakley_props_rsasig_xauthc) },         /* POLICY_XAUTHCLIENT + RSA */
	{ AD_SAp(oakley_props_pskrsasig_xauthc) },      /* POLICY_XAUTHCLIENT + RSA+PSK */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + none */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + PSK */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + RSA */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + RSA+PSK */
#else /* XAUTH */
	{ AD_NULL },                                    /* POLICY_XAUTHSERVER + none */
	{ AD_NULL },                                    /* POLICY_XAUTHSERVER + PSK */
	{ AD_NULL },                                    /* POLICY_XAUTHSERVER + RSA */
	{ AD_NULL },                                    /* POLICY_XAUTHSERVER + RSA+PSK */
	{ AD_NULL },                                    /* POLICY_XAUTHCLIENT + none */
	{ AD_NULL },                                    /* POLICY_XAUTHCLIENT + PSK */
	{ AD_NULL },                                    /* POLICY_XAUTHCLIENT + RSA */
	{ AD_NULL },                                    /* POLICY_XAUTHCLIENT + RSA+PSK */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + none */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + PSK */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + RSA */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + RSA+PSK */
#endif /* XAUTH */
};

#if defined(AGGRESSIVE)
/**************** Oakley (aggressive mode) SA database ****************/
/*
 * the Aggressive mode attributes must be seperate, because there
 * can be no choices --- since we must computer keying material,
 * we must actually just agree on what we are going to use.
 */

/* tables of transforms, in preference order (select based on AUTH) */
static struct db_trans oakley_am_trans_psk[] = {
	{ AD_TR(KEY_IKE, otpsk1536des3sha1) },
};

#if defined(XAUTH)
static struct db_trans oakley_am_trans_psk_xauthc[] = {
	{ AD_TR(KEY_IKE, otpsk1536des3sha1_xauthc) },
};
static struct db_trans oakley_am_trans_psk_xauths[] = {
	{ AD_TR(KEY_IKE, otpsk1536des3sha1_xauths) },
};
#endif

static struct db_trans oakley_am_trans_rsasig[] = {
	{ AD_TR(KEY_IKE, otrsasig1536des3sha1) },
};

#ifdef XAUTH
static struct db_trans oakley_am_trans_rsasig_xauthc[] = {
	{ AD_TR(KEY_IKE, otrsasig1536des3sha1_xauthc) },
};
static struct db_trans oakley_am_trans_rsasig_xauths[] = {
	{ AD_TR(KEY_IKE, otrsasig1536des3sha1_xauths) },
};
#endif

/* array of proposals to be conjoined (can only be one for Oakley) */
static struct db_prop oakley_am_pc_psk[] =
{ { AD_PR(PROTO_ISAKMP, oakley_am_trans_psk) } };

static struct db_prop oakley_am_pc_rsasig[] =
{ { AD_PR(PROTO_ISAKMP, oakley_am_trans_rsasig) } };

#ifdef XAUTH
static struct db_prop oakley_am_pc_psk_xauths[] =
{ { AD_PR(PROTO_ISAKMP, oakley_am_trans_psk_xauths) } };

static struct db_prop oakley_am_pc_rsasig_xauths[] =
{ { AD_PR(PROTO_ISAKMP, oakley_am_trans_rsasig_xauths) } };

static struct db_prop oakley_am_pc_psk_xauthc[] =
{ { AD_PR(PROTO_ISAKMP, oakley_am_trans_psk_xauthc) } };

static struct db_prop oakley_am_pc_rsasig_xauthc[] =
{ { AD_PR(PROTO_ISAKMP, oakley_am_trans_rsasig_xauthc) } };
#endif

/* array of proposal conjuncts (can only be one) */
static struct db_prop_conj oakley_am_props_psk[] =
{ { AD_PC(oakley_am_pc_psk) } };

static struct db_prop_conj oakley_am_props_rsasig[] =
{ { AD_PC(oakley_am_pc_rsasig) } };

#ifdef XAUTH
static struct db_prop_conj oakley_am_props_psk_xauthc[] =
{ { AD_PC(oakley_am_pc_psk_xauthc) } };

static struct db_prop_conj oakley_am_props_rsasig_xauthc[] =
{ { AD_PC(oakley_am_pc_rsasig_xauthc) } };

static struct db_prop_conj oakley_am_props_psk_xauths[] =
{ { AD_PC(oakley_am_pc_psk_xauths) } };

static struct db_prop_conj oakley_am_props_rsasig_xauths[] =
{ { AD_PC(oakley_am_pc_rsasig_xauths) } };
#endif

/*
 * the sadb entry, subscripted
 *   by [ WEAK, XAUTHSERVER, XAUTHCLIENT, POLICY_RSASIG, POLICY_PSK ] bits
 */
struct db_sa oakley_am_sadb[] = {
	/* STRONG ALGORITHMS */
	{ AD_NULL },                                    /* none */
	{ AD_SAp(oakley_am_props_psk) },                /* POLICY_PSK */
	{ AD_SAp(oakley_am_props_rsasig) },             /* POLICY_RSASIG */
	{ AD_NULL },                                    /* PSK + RSASIG => invalid in AM */
	{ AD_NULL },                                    /* POLICY_XAUTHSERVER + none */
#ifdef XAUTH
	{ AD_SAp(oakley_am_props_psk_xauths) },         /* POLICY_XAUTHSERVER + PSK */
	{ AD_SAp(oakley_am_props_rsasig_xauths) },      /* POLICY_XAUTHSERVER + RSA */
#else
	{ AD_NULL },                                    /* POLICY_XAUTHSERVER + PSK */
	{ AD_NULL },                                    /* POLICY_XAUTHSERVER + RSA */
#endif
	{ AD_NULL },                                    /* XAUTHSERVER + RSA+PSK=>invalid */
	{ AD_NULL },                                    /* POLICY_XAUTHCLIENT + none */
#ifdef XAUTH
	{ AD_SAp(oakley_am_props_psk_xauthc) },         /* POLICY_XAUTHCLIENT + PSK */
	{ AD_SAp(oakley_am_props_rsasig_xauthc) },      /* POLICY_XAUTHCLIENT + RSA */
#else
	{ AD_NULL },                                    /* POLICY_XAUTHCLIENT + PSK */
	{ AD_NULL },                                    /* POLICY_XAUTHCLIENT + RSA */
#endif
	{ AD_NULL },                                    /* XAUTHCLIENT + RSA+PSK=>invalid */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + none */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + PSK */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + RSA */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + RSA+PSK */
#if 0
	/* weaker ALGORITHMS */
	{ AD_NULL },                                    /* none */
	{ AD_SAp(oakley_am_props_psk) },                /* POLICY_PSK */
	{ AD_SAp(oakley_am_props_rsasig) },             /* POLICY_RSASIG */
	{ AD_SAp(oakley_am_props_pskrsasig) },          /* POLICY_PSK + POLICY_RSASIG */
	{ AD_NULL },                                    /* POLICY_XAUTHSERVER + none */
	{ AD_SAp(oakley_am_props_psk_xauths) },         /* POLICY_XAUTHSERVER + PSK */
	{ AD_SAp(oakley_am_props_rsasig_xauths) },      /* POLICY_XAUTHSERVER + RSA */
	{ AD_SAp(oakley_am_props_pskrsasig_xauths) },   /* POLICY_XAUTHSERVER + RSA+PSK */
	{ AD_NULL },                                    /* POLICY_XAUTHCLIENT + none */
	{ AD_SAp(oakley_am_props_psk_xauthc) },         /* POLICY_XAUTHCLIENT + PSK */
	{ AD_SAp(oakley_am_props_rsasig_xauthc) },      /* POLICY_XAUTHCLIENT + RSA */
	{ AD_SAp(oakley_am_props_pskrsasig_xauthc) },   /* POLICY_XAUTHCLIENT + RSA+PSK */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + none */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + PSK */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + RSA */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + RSA+PSK */
#endif
};

#endif /* AGGRESSIVE */

/**************** IPsec (quick mode) SA database ****************/

/* arrays of attributes for transforms */

static struct db_attr espamd5_attr[] = {
	{ .type.ipsec = AUTH_ALGORITHM, AUTH_ALGORITHM_HMAC_MD5 },
	{ .type.ipsec = KEY_LENGTH, 128 },
};

static struct db_attr espasha1_attr[] = {
	{ .type.ipsec = AUTH_ALGORITHM, AUTH_ALGORITHM_HMAC_SHA1 },
	{ .type.ipsec = KEY_LENGTH, 128 },
};

static struct db_attr espmd5_attr[] = {
	{ .type.ipsec = AUTH_ALGORITHM, AUTH_ALGORITHM_HMAC_MD5 },
};

static struct db_attr espsha1_attr[] = {
	{ .type.ipsec = AUTH_ALGORITHM, AUTH_ALGORITHM_HMAC_SHA1 },
};

static struct db_attr ah_HMAC_MD5_attr[] = {
	{ .type.ipsec = AUTH_ALGORITHM, AUTH_ALGORITHM_HMAC_MD5 },
};

static struct db_attr ah_HMAC_SHA1_attr[] = {
	{ .type.ipsec = AUTH_ALGORITHM, AUTH_ALGORITHM_HMAC_SHA1 },
};

/* arrays of transforms, each in in preference order */

static struct db_trans espa_trans[] = {
	{ AD_TR(ESP_AES, espasha1_attr) },
	{ AD_TR(ESP_AES, espamd5_attr) },
	{ AD_TR(ESP_3DES, espsha1_attr) },
	{ AD_TR(ESP_3DES, espmd5_attr) },
};

static struct db_trans esp_trans[] = {
	{ .transid = ESP_3DES, .attrs = NULL },
};

#ifdef SUPPORT_ESP_NULL
static struct db_trans espnull_trans[] = {
	{ AD_TR(ESP_NULL, espsha1_attr) },
	{ AD_TR(ESP_NULL, espmd5_attr) },
};
#endif /* SUPPORT_ESP_NULL */

static struct db_trans ah_trans[] = {
	{ AD_TR(AH_SHA, ah_HMAC_SHA1_attr) },
	{ AD_TR(AH_MD5, ah_HMAC_MD5_attr) },
};

static struct db_trans ipcomp_trans[] = {
	{ .transid = IPCOMP_DEFLATE, .attrs = NULL },
};

/* arrays of proposals to be conjoined */

static struct db_prop ah_pc[] = {
	{ AD_PR(PROTO_IPSEC_AH, ah_trans) },
};

#ifdef SUPPORT_ESP_NULL
static struct db_prop espnull_pc[] = {
	{ AD_PR(PROTO_IPSEC_ESP, espnull_trans) },
};
#endif /* SUPPORT_ESP_NULL */

static struct db_prop esp_pc[] = {
	{ AD_PR(PROTO_IPSEC_ESP, espa_trans) },
};

static struct db_prop ah_esp_pc[] = {
	{ AD_PR(PROTO_IPSEC_AH, ah_trans) },
	{ AD_PR(PROTO_IPSEC_ESP, esp_trans) },
};

static struct db_prop compress_pc[] = {
	{ AD_PR(PROTO_IPCOMP, ipcomp_trans) },
};

static struct db_prop ah_compress_pc[] = {
	{ AD_PR(PROTO_IPSEC_AH, ah_trans) },
	{ AD_PR(PROTO_IPCOMP, ipcomp_trans) },
};

#ifdef SUPPORT_ESP_NULL
static struct db_prop espnull_compress_pc[] = {
	{ AD_PR(PROTO_IPSEC_ESP, espnull_trans) },
	{ AD_PR(PROTO_IPCOMP, ipcomp_trans) },
};
#endif /* SUPPORT_ESP_NULL */

static struct db_prop esp_compress_pc[] = {
	{ AD_PR(PROTO_IPSEC_ESP, espa_trans) },
	{ AD_PR(PROTO_IPCOMP, ipcomp_trans) },
};

static struct db_prop ah_esp_compress_pc[] = {
	{ AD_PR(PROTO_IPSEC_AH, ah_trans) },
	{ AD_PR(PROTO_IPSEC_ESP, esp_trans) },
	{ AD_PR(PROTO_IPCOMP, ipcomp_trans) },
};

/* arrays of proposal alternatives (each element is a conjunction) */

static struct db_prop_conj ah_props[] = {
	{ AD_PC(ah_pc) },
#ifdef SUPPORT_ESP_NULL
	{ AD_PC(espnull_pc) }
#endif
};

static struct db_prop_conj esp_props[] =
{ { AD_PC(esp_pc) } };

static struct db_prop_conj ah_esp_props[] =
{ { AD_PC(ah_esp_pc) } };

static struct db_prop_conj compress_props[] = {
	{ AD_PC(compress_pc) },
};

static struct db_prop_conj ah_compress_props[] = {
	{ AD_PC(ah_compress_pc) },
#ifdef SUPPORT_ESP_NULL
	{ AD_PC(espnull_compress_pc) }
#endif
};

static struct db_prop_conj esp_compress_props[] =
{ { AD_PC(esp_compress_pc) } };

static struct db_prop_conj ah_esp_compress_props[] =
{ { AD_PC(ah_esp_compress_pc) } };

/* The IPsec sadb is subscripted by a bitset (subset of policy)
 * with members from { POLICY_ENCRYPT, POLICY_AUTHENTICATE, POLICY_COMPRESS }
 * shifted right by POLICY_IPSEC_SHIFT.
 */
struct db_sa ipsec_sadb[1 << 3] = {
	{ AD_NULL },                            /* none */
	{ AD_SAc(esp_props) },                  /* POLICY_ENCRYPT */
	{ AD_SAc(ah_props) },                   /* POLICY_AUTHENTICATE */
	{ AD_SAc(ah_esp_props) },               /* POLICY_ENCRYPT+POLICY_AUTHENTICATE */
	{ AD_SAc(compress_props) },             /* POLICY_COMPRESS */
	{ AD_SAc(esp_compress_props) },         /* POLICY_ENCRYPT+POLICY_COMPRESS */
	{ AD_SAc(ah_compress_props) },          /* POLICY_AUTHENTICATE+POLICY_COMPRESS */
	{ AD_SAc(ah_esp_compress_props) },      /* POLICY_ENCRYPT+POLICY_AUTHENTICATE+POLICY_COMPRESS */
};

#undef AD
#undef AD_NULL

void free_sa_trans(struct db_trans *tr)
{
	if (tr->attrs) {
		pfree(tr->attrs);
		tr->attrs = NULL;
	}
}

static void free_sa_v2_trans(struct db_v2_trans *tr)
{
	if (tr->attrs) {
		pfree(tr->attrs);
		tr->attrs = NULL;
	}
}

void free_sa_prop(struct db_prop *dp)
{
	unsigned int i;
	for (i = 0; i < dp->trans_cnt; i++)
		free_sa_trans(&dp->trans[i]);
	if (dp->trans) {
		pfree(dp->trans);
		dp->trans = NULL;
	}
}

static void free_sa_v2_prop(struct db_v2_prop_conj *dp)
{
	unsigned int i;
	for (i = 0; i < dp->trans_cnt; i++)
		free_sa_v2_trans(&dp->trans[i]);
	if (dp->trans) {
		pfree(dp->trans);
		dp->trans = NULL;
	}
}

void free_sa_prop_conj(struct db_prop_conj *pc)
{
	unsigned int i;
	for (i = 0; i < pc->prop_cnt; i++)
		free_sa_prop(&pc->props[i]);
	if (pc->props)
		pfree(pc->props);
}

static void free_sa_v2_prop_disj(struct db_v2_prop *pc)
{
	unsigned int i;
	for (i = 0; i < pc->prop_cnt; i++)
		free_sa_v2_prop(&pc->props[i]);
	if (pc->props)
		pfree(pc->props);
}

void free_sa(struct db_sa *f)
{
	unsigned int i;
	if (f == NULL)
		return;

	for (i = 0; i < f->prop_conj_cnt; i++)
		free_sa_prop_conj(&f->prop_conjs[i]);
	if (f->prop_conjs) {
		pfree(f->prop_conjs);
		f->prop_conjs = NULL;
		f->prop_conj_cnt = 0;
	}

	for (i = 0; i < f->prop_disj_cnt; i++)
		free_sa_v2_prop_disj(&f->prop_disj[i]);
	if (f->prop_disj) {
		pfree(f->prop_disj);
		f->prop_disj = NULL;
		f->prop_disj_cnt = 0;
	}

	if (f)
		pfree(f);
}

void clone_trans(struct db_trans *tr)
{
	tr->attrs = clone_bytes(tr->attrs,
				tr->attr_cnt * sizeof(tr->attrs[0]),
				"sa copy attrs array");
}

void clone_prop(struct db_prop *p, int extra)
{
	unsigned int i;

	p->trans = clone_bytes(p->trans,
			       (p->trans_cnt + extra) * sizeof(p->trans[0]),
			       "sa copy trans array");
	for (i = 0; i < p->trans_cnt; i++)
		clone_trans(&p->trans[i]);
}

void clone_propconj(struct db_prop_conj *pc, int extra)
{
	unsigned int i;

	pc->props = clone_bytes(pc->props,
				(pc->prop_cnt + extra) * sizeof(pc->props[0]),
				"sa copy prop array");
	for (i = 0; i < pc->prop_cnt; i++)
		clone_prop(&pc->props[i], 0);
}

struct db_sa *sa_copy_sa(struct db_sa *sa, int extra)
{
	unsigned int i;
	struct db_sa *nsa;

	nsa = clone_thing(*sa, "sa copy prop_conj");
	nsa->dynamic = TRUE;
	nsa->parentSA = sa->parentSA;

	nsa->prop_conjs =
		clone_bytes(nsa->prop_conjs,
			    (nsa->prop_conj_cnt +
			     extra) * sizeof(nsa->prop_conjs[0]),
			    "sa copy prop conj array");

	for (i = 0; i < nsa->prop_conj_cnt; i++)
		clone_propconj(&nsa->prop_conjs[i], 0);

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
	if (nsa->prop_conj_cnt == 0)
		return nsa;

	nsa->prop_conj_cnt = 1;
	nsa->prop_conjs = clone_bytes(nsa->prop_conjs,
				      sizeof(nsa->prop_conjs[0]),
				      "sa copy 1 prop conj array");

	pc = &nsa->prop_conjs[0];
	if (pc->prop_cnt == 0)
		return nsa;

	pc->prop_cnt = 1;
	pc->props = clone_bytes(pc->props,
				sizeof(pc->props[0]),
				"sa copy 1 prop array");

	p = &pc->props[0];
	if (p->trans_cnt == 0)
		return nsa;

	p->trans_cnt = 1;
	p->trans = clone_bytes(p->trans,
			       sizeof(p->trans[0]),
			       "sa copy 1 trans array");

	clone_trans(&p->trans[0]);
	return nsa;
}

/*
 * this routine takes two proposals and conjoins them (or)
 *
 *
 */
struct db_sa *sa_merge_proposals(struct db_sa *a, struct db_sa *b)
{
	struct db_sa *n;
	unsigned int i, j, k;

	if (a == NULL || a->prop_conj_cnt == 0)
		return sa_copy_sa(b, 0);

	if (b == NULL || b->prop_conj_cnt == 0)
		return sa_copy_sa(a, 0);

	n = clone_thing(*a, "conjoin sa");

	passert(a->prop_conj_cnt == b->prop_conj_cnt);
	passert(a->prop_conj_cnt == 1);

	n->prop_conjs =
		clone_bytes(n->prop_conjs,
			    n->prop_conj_cnt * sizeof(n->prop_conjs[0]),
			    "sa copy prop conj array");

	for (i = 0; i < n->prop_conj_cnt; i++) {
		struct db_prop_conj *pca = &n->prop_conjs[i];
		struct db_prop_conj *pcb = &b->prop_conjs[i];

		passert(pca->prop_cnt == pcb->prop_cnt);
		passert(pca->prop_cnt == 1);

		pca->props = clone_bytes(pca->props,
					 pca->prop_cnt * sizeof(pca->props[0]),
					 "sa copy prop array");

		for (j = 0; j < pca->prop_cnt; j++) {
			struct db_prop *pa = &pca->props[j];
			struct db_prop *pb = &pcb->props[j];
			struct db_trans *t;
			int t_cnt = (pa->trans_cnt + pb->trans_cnt);

			t = alloc_bytes(t_cnt * sizeof(pa->trans[0]),
					"sa copy trans array");

			memcpy(t, pa->trans, (pa->trans_cnt) *
			       sizeof(pa->trans[0]));
			memcpy(t + (pa->trans_cnt),
			       pb->trans,
			       (pb->trans_cnt) * sizeof(pa->trans[0]));

			pa->trans = t;
			pa->trans_cnt = t_cnt;
			for (k = 0; k < pa->trans_cnt; k++)
				clone_trans(&pa->trans[k]);
		}
	}

	n->parentSA = a->parentSA;
	return n;
}
