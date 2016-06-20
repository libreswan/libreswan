/* Security Policy Data Base (such as it is)
 *
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2003-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2006 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2008-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015 Andrew Cagney <andrew.cagney@gmail.com>
 * Copyright (C) 2015 Paul Wouters <pwouters@redhat.com>
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
#include "libreswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
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

#include "nat_traversal.h"

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
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otpsk1536des3md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otpsk2048des3md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP2048 },
};

static struct db_attr otpsk1024aes256md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};
static struct db_attr otpsk1024aes128md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otpsk1536aes256md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};
static struct db_attr otpsk1536aes128md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otpsk2048aes256md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP2048 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};
static struct db_attr otpsk2048aes128md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP2048 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otpsk1024aes256sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};
static struct db_attr otpsk1024aes128sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otpsk1536aes128sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};
static struct db_attr otpsk1536aes256sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};

static struct db_attr otpsk2048aes128sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val = OAKLEY_GROUP_MODP2048 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};
static struct db_attr otpsk2048aes256sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val = OAKLEY_GROUP_MODP2048 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};

static struct db_attr otpsk1024des3sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otpsk1536des3sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otpsk2048des3sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP2048 },
};

/* arrays of attributes for transforms, preshared key, Xauth version */

static struct db_attr otpsk1024des3md5_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = XAUTHInitPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
};
static struct db_attr otpsk1024des3sha1_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = XAUTHInitPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otpsk1536des3sha1_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = XAUTHInitPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otpsk1536des3md5_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = XAUTHInitPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otpsk1536aes256md5_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = XAUTHInitPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};
static struct db_attr otpsk1536aes128md5_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = XAUTHInitPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otpsk1536aes128sha1_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};
static struct db_attr otpsk1536aes256sha1_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};

static struct db_attr otpsk1024des3md5_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = XAUTHRespPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otpsk1024des3sha1_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = XAUTHRespPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otpsk1536des3md5_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = XAUTHRespPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otpsk1536des3sha1_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = XAUTHRespPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otpsk1536aes256md5_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = XAUTHRespPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};
static struct db_attr otpsk1536aes128md5_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = XAUTHRespPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otpsk1536aes128sha1_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHRespPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};
static struct db_attr otpsk1536aes256sha1_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHRespPreShared },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};

/* arrays of attributes for transforms, RSA signatures */

static struct db_attr otrsasig1024aes256md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};
static struct db_attr otrsasig1024aes128md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otrsasig1536aes256md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};
static struct db_attr otrsasig1536aes128md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otrsasig2048aes256md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP2048 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};
static struct db_attr otrsasig2048aes128md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val =
		  OAKLEY_GROUP_MODP2048 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otrsasig1024aes256sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};
static struct db_attr otrsasig1024aes128sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otrsasig1536aes128sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};
static struct db_attr otrsasig1536aes256sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};

static struct db_attr otrsasig2048aes128sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val = OAKLEY_GROUP_MODP2048 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};
static struct db_attr otrsasig2048aes256sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val = OAKLEY_GROUP_MODP2048 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};

static struct db_attr otrsasig1024des3md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otrsasig1536des3md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otrsasig2048des3md5[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP2048 },
};

static struct db_attr otrsasig1024des3sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otrsasig1536des3sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otrsasig2048des3sha1[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = OAKLEY_RSA_SIG },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP2048 },
};

/* arrays of attributes for transforms, RSA signatures, with/Xauth */
/* xauth c is when Initiator will be the xauth client */
static struct db_attr otrsasig1024des3md5_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otrsasig1536des3md5_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otrsasig1536aes256md5_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};
static struct db_attr otrsasig1536aes128md5_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otrsasig1536aes128sha1_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};
static struct db_attr otrsasig1536aes256sha1_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};

static struct db_attr otrsasig1024des3sha1_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otrsasig1536des3sha1_xauthc[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
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
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otrsasig1536des3md5_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otrsasig1536aes256md5_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};
static struct db_attr otrsasig1536aes128md5_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_MD5 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHInitRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};

static struct db_attr otrsasig1024des3sha1_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHRespRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
};

static struct db_attr otrsasig1536des3sha1_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHRespRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1536 },
};

static struct db_attr otrsasig1536aes128sha1_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHRespRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 128 },
};
static struct db_attr otrsasig1536aes256sha1_xauths[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_AES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_SHA1 },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD, .val = XAUTHRespRSA },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION, .val = OAKLEY_GROUP_MODP1536 },
	{ .type.oakley = OAKLEY_KEY_LENGTH, .val = 256 },
};

/* We won't accept this, but by proposing it, we get to test
 * our rejection.  We better not propose it to an IKE daemon
 * that will accept it!
 */
#ifdef TEST_INDECENT_PROPOSAL
static struct db_attr otpsk1024des3tiger[] = {
	{ .type.oakley = OAKLEY_ENCRYPTION_ALGORITHM, .val = OAKLEY_3DES_CBC },
	{ .type.oakley = OAKLEY_HASH_ALGORITHM, .val = OAKLEY_TIGER },
	{ .type.oakley = OAKLEY_AUTHENTICATION_METHOD,
		.val = OAKLEY_PRESHARED_KEY },
	{ .type.oakley = OAKLEY_GROUP_DESCRIPTION,
		.val = OAKLEY_GROUP_MODP1024 },
};
#endif /* TEST_INDECENT_PROPOSAL */

/* tables of transforms, in preference order (select based on AUTH) */

static struct db_trans IKEv1_oakley_trans_psk[] = {
#ifdef TEST_INDECENT_PROPOSAL
	{ AD_TR(KEY_IKE, otpsk1024des3tiger) },
#endif
	{ AD_TR(KEY_IKE, otpsk2048aes256sha1) },
	{ AD_TR(KEY_IKE, otpsk2048aes128sha1) },
	{ AD_TR(KEY_IKE, otpsk2048aes256md5) },
	{ AD_TR(KEY_IKE, otpsk2048aes128md5) },
	{ AD_TR(KEY_IKE, otpsk2048des3sha1) },
	{ AD_TR(KEY_IKE, otpsk2048des3md5) },
	{ AD_TR(KEY_IKE, otpsk1536aes256sha1) },
	{ AD_TR(KEY_IKE, otpsk1536aes128sha1) },
	{ AD_TR(KEY_IKE, otpsk1536aes256md5) },
	{ AD_TR(KEY_IKE, otpsk1536aes128md5) },
	{ AD_TR(KEY_IKE, otpsk1536des3sha1) },
	{ AD_TR(KEY_IKE, otpsk1536des3md5) },
	{ AD_TR(KEY_IKE, otpsk1024aes256sha1) },
	{ AD_TR(KEY_IKE, otpsk1024aes128sha1) },
	{ AD_TR(KEY_IKE, otpsk1024aes256md5) },
	{ AD_TR(KEY_IKE, otpsk1024aes128md5) },
	{ AD_TR(KEY_IKE, otpsk1024des3sha1) },
	{ AD_TR(KEY_IKE, otpsk1024des3md5) },
};

static struct db_trans IKEv1_oakley_trans_psk_xauthc[] = {
	{ AD_TR(KEY_IKE, otpsk1536aes256sha1_xauthc) },
	{ AD_TR(KEY_IKE, otpsk1536aes128sha1_xauthc) },
	{ AD_TR(KEY_IKE, otpsk1536aes256md5_xauthc) },
	{ AD_TR(KEY_IKE, otpsk1536aes128md5_xauthc) },
	{ AD_TR(KEY_IKE, otpsk1536des3sha1_xauthc) },
	{ AD_TR(KEY_IKE, otpsk1536des3md5_xauthc) },
	{ AD_TR(KEY_IKE, otpsk1024des3sha1_xauthc) },
	{ AD_TR(KEY_IKE, otpsk1024des3md5_xauthc) },
};
static struct db_trans IKEv1_oakley_trans_psk_xauths[] = {
	{ AD_TR(KEY_IKE, otpsk1536aes256sha1_xauths) },
	{ AD_TR(KEY_IKE, otpsk1536aes128sha1_xauths) },
	{ AD_TR(KEY_IKE, otpsk1536aes256md5_xauths) },
	{ AD_TR(KEY_IKE, otpsk1536aes128md5_xauths) },
	{ AD_TR(KEY_IKE, otpsk1536des3sha1_xauths) },
	{ AD_TR(KEY_IKE, otpsk1536des3md5_xauths) },
	{ AD_TR(KEY_IKE, otpsk1024des3sha1_xauths) },
	{ AD_TR(KEY_IKE, otpsk1024des3md5_xauths) },
};

static struct db_trans IKEv1_oakley_trans_rsasig[] = {
	{ AD_TR(KEY_IKE, otrsasig2048aes256sha1) },
	{ AD_TR(KEY_IKE, otrsasig2048aes128sha1) },
	{ AD_TR(KEY_IKE, otrsasig2048aes256md5) },
	{ AD_TR(KEY_IKE, otrsasig2048aes128md5) },
	{ AD_TR(KEY_IKE, otrsasig2048des3sha1) },
	{ AD_TR(KEY_IKE, otrsasig2048des3md5) },
	{ AD_TR(KEY_IKE, otrsasig1536aes256sha1) },
	{ AD_TR(KEY_IKE, otrsasig1536aes128sha1) },
	{ AD_TR(KEY_IKE, otrsasig1536aes256md5) },
	{ AD_TR(KEY_IKE, otrsasig1536aes128md5) },
	{ AD_TR(KEY_IKE, otrsasig1536des3sha1) },
	{ AD_TR(KEY_IKE, otrsasig1536des3md5) },
	{ AD_TR(KEY_IKE, otrsasig1024des3sha1) },
	{ AD_TR(KEY_IKE, otrsasig1024des3md5) },
	{ AD_TR(KEY_IKE, otrsasig1024aes256sha1) },
	{ AD_TR(KEY_IKE, otrsasig1024aes128sha1) },
	{ AD_TR(KEY_IKE, otrsasig1024aes256md5) },
	{ AD_TR(KEY_IKE, otrsasig1024aes128md5) },
};

static struct db_trans IKEv1_oakley_trans_rsasig_xauthc[] = {
	{ AD_TR(KEY_IKE, otrsasig1536aes256sha1_xauthc) },
	{ AD_TR(KEY_IKE, otrsasig1536aes128sha1_xauthc) },
	{ AD_TR(KEY_IKE, otrsasig1536aes256md5_xauthc) },
	{ AD_TR(KEY_IKE, otrsasig1536aes128md5_xauthc) },
	{ AD_TR(KEY_IKE, otrsasig1536des3sha1_xauthc) },
	{ AD_TR(KEY_IKE, otrsasig1536des3md5_xauthc) },
	{ AD_TR(KEY_IKE, otrsasig1024des3sha1_xauthc) },
	{ AD_TR(KEY_IKE, otrsasig1024des3md5_xauthc) },
};
static struct db_trans IKEv1_oakley_trans_rsasig_xauths[] = {
	{ AD_TR(KEY_IKE, otrsasig1536aes256sha1_xauths) },
	{ AD_TR(KEY_IKE, otrsasig1536aes128sha1_xauths) },
	{ AD_TR(KEY_IKE, otrsasig1536aes256md5_xauths) },
	{ AD_TR(KEY_IKE, otrsasig1536aes128md5_xauths) },
	{ AD_TR(KEY_IKE, otrsasig1536des3sha1_xauths) },
	{ AD_TR(KEY_IKE, otrsasig1536des3md5_xauths) },
	{ AD_TR(KEY_IKE, otrsasig1024des3sha1_xauths) },
	{ AD_TR(KEY_IKE, otrsasig1024des3md5_xauths) },
};

/* In this table, either PSK or RSA sig is accepted.
 * The order matters, but I don't know what would be best.
 */
static struct db_trans IKEv1_oakley_trans_pskrsasig[] = {
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

static struct db_trans IKEv1_oakley_trans_pskrsasig_xauthc[] = {
	{ AD_TR(KEY_IKE, otrsasig1536des3md5_xauthc) },
	{ AD_TR(KEY_IKE, otpsk1536des3md5_xauthc) },
	{ AD_TR(KEY_IKE, otrsasig1536des3sha1_xauthc) },
	{ AD_TR(KEY_IKE, otpsk1536des3sha1_xauthc) },
	{ AD_TR(KEY_IKE, otrsasig1024des3sha1_xauthc) },
	{ AD_TR(KEY_IKE, otpsk1024des3sha1_xauthc) },
	{ AD_TR(KEY_IKE, otrsasig1024des3md5_xauthc) },
	{ AD_TR(KEY_IKE, otpsk1024des3md5_xauthc) },
};

static struct db_trans IKEv1_oakley_trans_pskrsasig_xauths[] = {
	{ AD_TR(KEY_IKE, otrsasig1536des3md5_xauths) },
	{ AD_TR(KEY_IKE, otpsk1536des3md5_xauths) },
	{ AD_TR(KEY_IKE, otrsasig1536des3sha1_xauths) },
	{ AD_TR(KEY_IKE, otpsk1536des3sha1_xauths) },
	{ AD_TR(KEY_IKE, otrsasig1024des3sha1_xauths) },
	{ AD_TR(KEY_IKE, otpsk1024des3sha1_xauths) },
	{ AD_TR(KEY_IKE, otrsasig1024des3md5_xauths) },
	{ AD_TR(KEY_IKE, otpsk1024des3md5_xauths) },
};

/*
 * array of proposals to be conjoined (can only be one for Oakley)
 * AND of protocols.
 */
static struct db_prop IKEv1_oakley_pc_psk[] =
	{ { AD_PR(PROTO_ISAKMP, IKEv1_oakley_trans_psk) } };

static struct db_prop IKEv1_oakley_pc_rsasig[] =
	{ { AD_PR(PROTO_ISAKMP, IKEv1_oakley_trans_rsasig) } };

static struct db_prop IKEv1_oakley_pc_pskrsasig[] =
	{ { AD_PR(PROTO_ISAKMP, IKEv1_oakley_trans_pskrsasig) } };

static struct db_prop IKEv1_oakley_pc_psk_xauths[] =
	{ { AD_PR(PROTO_ISAKMP, IKEv1_oakley_trans_psk_xauths) } };

static struct db_prop IKEv1_oakley_pc_rsasig_xauths[] =
	{ { AD_PR(PROTO_ISAKMP, IKEv1_oakley_trans_rsasig_xauths) } };

static struct db_prop IKEv1_oakley_pc_pskrsasig_xauths[] =
	{ { AD_PR(PROTO_ISAKMP, IKEv1_oakley_trans_pskrsasig_xauths) } };

static struct db_prop IKEv1_oakley_pc_psk_xauthc[] =
	{ { AD_PR(PROTO_ISAKMP, IKEv1_oakley_trans_psk_xauthc) } };

static struct db_prop IKEv1_oakley_pc_rsasig_xauthc[] =
	{ { AD_PR(PROTO_ISAKMP, IKEv1_oakley_trans_rsasig_xauthc) } };

static struct db_prop IKEv1_oakley_pc_pskrsasig_xauthc[] =
	{ { AD_PR(PROTO_ISAKMP, IKEv1_oakley_trans_pskrsasig_xauthc) } };

/* array of proposal conjuncts (can only be one) (OR of protocol) */
static struct db_prop_conj IKEv1_oakley_props_psk[] =
	{ { AD_PC(IKEv1_oakley_pc_psk) } };

static struct db_prop_conj IKEv1_oakley_props_rsasig[] =
	{ { AD_PC(IKEv1_oakley_pc_rsasig) } };

static struct db_prop_conj IKEv1_oakley_props_pskrsasig[] =
	{ { AD_PC(IKEv1_oakley_pc_pskrsasig) } };

static struct db_prop_conj IKEv1_oakley_props_psk_xauthc[] =
	{ { AD_PC(IKEv1_oakley_pc_psk_xauthc) } };

static struct db_prop_conj IKEv1_oakley_props_rsasig_xauthc[] =
	{ { AD_PC(IKEv1_oakley_pc_rsasig_xauthc) } };

static struct db_prop_conj IKEv1_oakley_props_pskrsasig_xauthc[] =
	{ { AD_PC(IKEv1_oakley_pc_pskrsasig_xauthc) } };

static struct db_prop_conj IKEv1_oakley_props_psk_xauths[] =
	{ { AD_PC(IKEv1_oakley_pc_psk_xauths) } };

static struct db_prop_conj IKEv1_oakley_props_rsasig_xauths[] =
	{ { AD_PC(IKEv1_oakley_pc_rsasig_xauths) } };

static struct db_prop_conj IKEv1_oakley_props_pskrsasig_xauths[] =
	{ { AD_PC(IKEv1_oakley_pc_pskrsasig_xauths) } };

/* the sadb entry, subscripted by IKEv1_sadb_index() */
static struct db_sa IKEv1_oakley_sadb_table[] = {
	{ AD_NULL },                                    /* none */
	{ AD_SAp(IKEv1_oakley_props_psk) },             /* PSK */
	{ AD_SAp(IKEv1_oakley_props_rsasig) },          /* RSASIG */
	{ AD_SAp(IKEv1_oakley_props_pskrsasig) },       /* PSK + RSASIG */

	{ AD_NULL },                                    /* XAUTHSERVER + none */
	{ AD_SAp(IKEv1_oakley_props_psk_xauths) },      /* XAUTHSERVER + PSK */
	{ AD_SAp(IKEv1_oakley_props_rsasig_xauths) },   /* XAUTHSERVER + RSA */
	{ AD_SAp(IKEv1_oakley_props_pskrsasig_xauths) },/* XAUTHSERVER + RSA+PSK */

	{ AD_NULL },                                    /* XAUTHCLIENT + none */
	{ AD_SAp(IKEv1_oakley_props_psk_xauthc) },      /* XAUTHCLIENT + PSK */
	{ AD_SAp(IKEv1_oakley_props_rsasig_xauthc) },   /* XAUTHCLIENT + RSA */
	{ AD_SAp(IKEv1_oakley_props_pskrsasig_xauthc) },/* XAUTHCLIENT + RSA+PSK */

	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + none */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + PSK */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + RSA */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + RSA+PSK */
};

/**************** Oakley (aggressive mode) SA database ****************/
/*
 * the Aggressive mode attributes must be seperate, because there
 * can be no choices --- since we must computer keying material,
 * we must actually just agree on what we are going to use.
 */

/* tables of transforms, in preference order (select based on AUTH) */
static struct db_trans IKEv1_oakley_am_trans_psk[] = {
	{ AD_TR(KEY_IKE, otpsk1536des3sha1) },
};

static struct db_trans IKEv1_oakley_am_trans_psk_xauthc[] = {
	{ AD_TR(KEY_IKE, otpsk1536des3sha1_xauthc) },
};
static struct db_trans IKEv1_oakley_am_trans_psk_xauths[] = {
	{ AD_TR(KEY_IKE, otpsk1536des3sha1_xauths) },
};

static struct db_trans IKEv1_oakley_am_trans_rsasig[] = {
	{ AD_TR(KEY_IKE, otrsasig1536des3sha1) },
};

static struct db_trans IKEv1_oakley_am_trans_rsasig_xauthc[] = {
	{ AD_TR(KEY_IKE, otrsasig1536des3sha1_xauthc) },
};
static struct db_trans IKEv1_oakley_am_trans_rsasig_xauths[] = {
	{ AD_TR(KEY_IKE, otrsasig1536des3sha1_xauths) },
};

/* array of proposals to be conjoined (can only be one for Oakley) */
static struct db_prop oakley_am_pc_psk[] =
	{ { AD_PR(PROTO_ISAKMP, IKEv1_oakley_am_trans_psk) } };

static struct db_prop oakley_am_pc_rsasig[] =
	{ { AD_PR(PROTO_ISAKMP, IKEv1_oakley_am_trans_rsasig) } };

static struct db_prop oakley_am_pc_psk_xauths[] =
	{ { AD_PR(PROTO_ISAKMP, IKEv1_oakley_am_trans_psk_xauths) } };

static struct db_prop oakley_am_pc_rsasig_xauths[] =
	{ { AD_PR(PROTO_ISAKMP, IKEv1_oakley_am_trans_rsasig_xauths) } };

static struct db_prop oakley_am_pc_psk_xauthc[] =
	{ { AD_PR(PROTO_ISAKMP, IKEv1_oakley_am_trans_psk_xauthc) } };

static struct db_prop oakley_am_pc_rsasig_xauthc[] =
	{ { AD_PR(PROTO_ISAKMP, IKEv1_oakley_am_trans_rsasig_xauthc) } };

/* array of proposal conjuncts (can only be one) */
static struct db_prop_conj IKEv1_oakley_am_props_psk[] =
	{ { AD_PC(oakley_am_pc_psk) } };

static struct db_prop_conj IKEv1_oakley_am_props_rsasig[] =
	{ { AD_PC(oakley_am_pc_rsasig) } };

static struct db_prop_conj IKEv1_oakley_am_props_psk_xauthc[] =
	{ { AD_PC(oakley_am_pc_psk_xauthc) } };

static struct db_prop_conj IKEv1_oakley_am_props_rsasig_xauthc[] =
	{ { AD_PC(oakley_am_pc_rsasig_xauthc) } };

static struct db_prop_conj IKEv1_oakley_am_props_psk_xauths[] =
	{ { AD_PC(oakley_am_pc_psk_xauths) } };

static struct db_prop_conj IKEv1_oakley_am_props_rsasig_xauths[] =
	{ { AD_PC(oakley_am_pc_rsasig_xauths) } };

/* the sadb entry, subscripted by IKEv1_sadb_index() */
static struct db_sa IKEv1_oakley_am_sadb_table[] = {
	{ AD_NULL },                                    /* none */
	{ AD_SAp(IKEv1_oakley_am_props_psk) },          /* PSK */
	{ AD_SAp(IKEv1_oakley_am_props_rsasig) },       /* RSASIG */
	{ AD_NULL },                                    /* PSK+RSASIG => invalid in AM */

	{ AD_NULL },                                    /* XAUTHSERVER + none */
	{ AD_SAp(IKEv1_oakley_am_props_psk_xauths) },   /* XAUTHSERVER + PSK */
	{ AD_SAp(IKEv1_oakley_am_props_rsasig_xauths) },/* XAUTHSERVER + RSA */
	{ AD_NULL },                                    /* XAUTHSERVER + RSA+PSK => invalid */

	{ AD_NULL },                                    /* XAUTHCLIENT + none */
	{ AD_SAp(IKEv1_oakley_am_props_psk_xauthc) },   /* XAUTHCLIENT + PSK */
	{ AD_SAp(IKEv1_oakley_am_props_rsasig_xauthc) },/* XAUTHCLIENT + RSA */
	{ AD_NULL },                                    /* XAUTHCLIENT + RSA+PSK => invalid */

	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + none */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + PSK */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + RSA */
	{ AD_NULL },                                    /* XAUTHCLIENT+XAUTHSERVER + RSA+PSK */
};

/*
 * The oakley sadb is subscripted by a bitset computed by
 * IKEv1_sadb_index().
 *
 * POLICY_PSK, POLICY_RSASIG, and XAUTH for this end (ideosyncratic).
 */
static int IKEv1_sadb_index(lset_t x, struct connection *c)
{
	return (x & LRANGES(POLICY_PSK, POLICY_RSASIG)) |
		((lset_t)c->spd.this.xauth_server << (POLICY_RSASIG_IX+1)) |
		((lset_t)c->spd.this.xauth_client << (POLICY_RSASIG_IX+2));
}

struct db_sa *IKEv1_oakley_sadb(lset_t x, struct connection *c)
{
	return &IKEv1_oakley_sadb_table[IKEv1_sadb_index(x, c)];
}

struct db_sa *IKEv1_oakley_am_sadb(lset_t x, struct connection *c)
{
	return &IKEv1_oakley_am_sadb_table[IKEv1_sadb_index(x, c)];
}

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

static struct db_trans espnull_trans[] = {
	{ AD_TR(ESP_NULL, espsha1_attr) },
	{ AD_TR(ESP_NULL, espmd5_attr) },
};

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

static struct db_prop espnull_pc[] = {
	{ AD_PR(PROTO_IPSEC_ESP, espnull_trans) },
};

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

static struct db_prop espnull_compress_pc[] = {
	{ AD_PR(PROTO_IPSEC_ESP, espnull_trans) },
	{ AD_PR(PROTO_IPCOMP, ipcomp_trans) },
};

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
	{ AD_PC(espnull_pc) },
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
	{ AD_PC(espnull_compress_pc) },
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

static void free_sa_trans(struct db_trans *tr)
{
	if (tr->attrs != NULL) {
		pfree(tr->attrs);
		tr->attrs = NULL;
	}
}

static void free_sa_prop(struct db_prop *dp)
{
	if (dp->trans != NULL) {
		unsigned int i;

		for (i = 0; i < dp->trans_cnt; i++)
			free_sa_trans(&dp->trans[i]);
		pfree(dp->trans);
		dp->trans = NULL;
		dp->trans_cnt = 0;
	}
	passert(dp->trans_cnt == 0);
}

static void free_sa_prop_conj(struct db_prop_conj *pc)
{
	if (pc->props != NULL) {
		unsigned int i;

		for (i = 0; i < pc->prop_cnt; i++)
			free_sa_prop(&pc->props[i]);
		pfree(pc->props);
		pc->props = NULL;
		pc->prop_cnt = 0;
	}
	passert(pc->prop_cnt == 0);
}

void free_sa(struct db_sa **sapp)
{
	struct db_sa *f = *sapp;

	if (f != NULL) {
		unsigned int i;

		if (f->prop_conjs != NULL) {
			for (i = 0; i < f->prop_conj_cnt; i++)
				free_sa_prop_conj(&f->prop_conjs[i]);
			pfree(f->prop_conjs);
			f->prop_conjs = NULL;
			f->prop_conj_cnt = 0;
		}
		passert(f->prop_conj_cnt == 0);

		pfree(f);
		*sapp = NULL;
	}
}

/*
 * NOTE: "unshare" means turn each pointer to a shared object
 * into a pointer to a clone of that object.  Even though the old pointer
 * is overwritten, this isn't a leak since something else must have had
 * a pointer to it.
 *
 * In these particular routines, this allows cloning to proceed top-down.
 */

static void unshare_trans(struct db_trans *tr)
{
	tr->attrs = clone_bytes(tr->attrs, tr->attr_cnt * sizeof(tr->attrs[0]),
		"sa copy attrs array");
}

static void unshare_prop(struct db_prop *p)
{
	unsigned int i;

	p->trans = clone_bytes(p->trans,  p->trans_cnt * sizeof(p->trans[0]),
		"sa copy trans array");
	for (i = 0; i < p->trans_cnt; i++)
		unshare_trans(&p->trans[i]);
}

static void unshare_propconj(struct db_prop_conj *pc)
{
	unsigned int i;

	pc->props = clone_bytes(pc->props, pc->prop_cnt * sizeof(pc->props[0]),
		"sa copy prop array");
	for (i = 0; i < pc->prop_cnt; i++)
		unshare_prop(&pc->props[i]);
}

struct db_sa *sa_copy_sa(struct db_sa *sa)
{
	unsigned int i;
	struct db_sa *nsa;

	nsa = clone_thing(*sa, "sa copy prop_conj");
	nsa->dynamic = TRUE;
	nsa->parentSA = sa->parentSA;

	nsa->prop_conjs = clone_bytes(nsa->prop_conjs,
		sizeof(nsa->prop_conjs[0]) * nsa->prop_conj_cnt,
		"sa copy prop conj array");
	for (i = 0; i < nsa->prop_conj_cnt; i++)
		unshare_propconj(&nsa->prop_conjs[i]);

	return nsa;
}

/*
 * clone the sa, but keep only the first transform (if any) of the first proposal (if any)
 * ??? does this make sense?
 */
struct db_sa *sa_copy_sa_first(struct db_sa *sa)
{
	struct db_sa *nsa;
	struct db_prop_conj *pc;
	struct db_prop *p;

	/* first do a shallow copy */
	nsa = clone_thing(*sa, "sa copy prop_conj");
	nsa->dynamic = TRUE;
	if (nsa->prop_conj_cnt == 0)
		return nsa;

	/* truncate to first prop_conj */
	nsa->prop_conj_cnt = 1;
	nsa->prop_conjs = clone_bytes(nsa->prop_conjs,
				      sizeof(nsa->prop_conjs[0]),
				      "sa copy 1 prop conj array");

	pc = &nsa->prop_conjs[0];
	if (pc->prop_cnt == 0)
		return nsa;

	/* truncate to first prop */
	pc->prop_cnt = 1;
	pc->props = clone_bytes(pc->props,
				sizeof(pc->props[0]),
				"sa copy 1 prop array");

	p = &pc->props[0];
	if (p->trans_cnt == 0)
		return nsa;

	/* truncate to first trans */
	p->trans_cnt = 1;
	p->trans = clone_bytes(p->trans,
			       sizeof(p->trans[0]),
			       "sa copy 1 trans array");

	unshare_trans(&p->trans[0]);
	return nsa;
}

/*
 * this routine takes two proposals and conjoins them (or)
 */
struct db_sa *sa_merge_proposals(struct db_sa *a, struct db_sa *b)
{
	struct db_sa *n;
	unsigned int i, j, k;

	if (a == NULL || a->prop_conj_cnt == 0)
		return sa_copy_sa(b);

	if (b == NULL || b->prop_conj_cnt == 0)
		return sa_copy_sa(a);

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
			int t_cnt = pa->trans_cnt + pb->trans_cnt;

			t = alloc_bytes(t_cnt * sizeof(pa->trans[0]),
					"sa copy trans array");

			memcpy(t, pa->trans, pa->trans_cnt *
			       sizeof(pa->trans[0]));
			memcpy(t + pa->trans_cnt,
			       pb->trans,
			       pb->trans_cnt * sizeof(pa->trans[0]));

			pa->trans = t;
			pa->trans_cnt = t_cnt;
			for (k = 0; k < pa->trans_cnt; k++)
				unshare_trans(&pa->trans[k]);
		}
	}

	n->parentSA = a->parentSA;
	return n;
}
