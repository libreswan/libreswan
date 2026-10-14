/* Authentication, for libreswan
 *
 * Copyright (C) 2022,2026 Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifndef AUTHBY_H
#define AUTHBY_H

#include <stdbool.h>
#include <stddef.h>	/* for size_t */

#include "shunk.h"
#include "auth.h"

struct jambuf;
struct hash_desc;

/*
 * A bitset of possible auth methods.
 *
 * Currently its implemented as a bool array (see flags.h).
 *
 * Code needing to test for an individual auth method should use
 * authby_has(authby, auth).
 */

struct authby {
	bool authby[AUTH_ROOF];
};

/*
 * Macros for building authby structures.
 *
 * Note the strict grouping.  For instance AUTHBY_RSASSA_SHA2 includes
 * *all* RSA SHA2 algorithms - i.e., both RSASSA PKCS#1 v1.5 and
 * RSASSA-PSS.
 */
#define AUTHBY_EAPONLY				\
	.authby[AUTH_EAPONLY] = true

#define AUTHBY_PSK				\
	.authby[AUTH_PSK] = true

#define AUTHBY_NULL				\
	.authby[AUTH_NULL] = true

#define AUTHBY_NEVER				\
	.authby[AUTH_NEVER] = true

#define AUTHBY_EDDSA				\
	.authby[AUTH_EDDSA_ED25519] = true

#define AUTHBY_MLDSA_44				\
	.authby[AUTH_MLDSA_44] = true
#define AUTHBY_MLDSA_65				\
	.authby[AUTH_MLDSA_65] = true
#define AUTHBY_MLDSA_87				\
	.authby[AUTH_MLDSA_87] = true
#define AUTHBY_MLDSA				\
	AUTHBY_MLDSA_44,			\
	AUTHBY_MLDSA_65,			\
	AUTHBY_MLDSA_87

#define AUTHBY_RSASIG_IKEv1			\
	.authby[AUTH_RSASIG_IKEv1] = true

#define AUTHBY_RSASSA_PKCS1_V1_5_SHA1_RAW		\
	.authby[AUTH_RSASSA_PKCS1_V1_5_SHA1_RAW] = true
#define AUTHBY_RSASSA_PKCS1_V1_5_SHA1_BLOB		\
	.authby[AUTH_RSASSA_PKCS1_V1_5_SHA1_BLOB] = true
#define AUTHBY_RSASSA_PKCS1_V1_5_SHA1			\
	AUTHBY_RSASSA_PKCS1_V1_5_SHA1_RAW,		\
	AUTHBY_RSASSA_PKCS1_V1_5_SHA1_BLOB

#define AUTHBY_RSASSA_PKCS1_V1_5_SHA2_256_BLOB			\
	.authby[AUTH_RSASSA_PKCS1_V1_5_SHA2_256_BLOB] = true
#define AUTHBY_RSASSA_PKCS1_V1_5_SHA2_384_BLOB			\
	.authby[AUTH_RSASSA_PKCS1_V1_5_SHA2_384_BLOB] = true
#define AUTHBY_RSASSA_PKCS1_V1_5_SHA2_512_BLOB			\
	.authby[AUTH_RSASSA_PKCS1_V1_5_SHA2_512_BLOB] = true
#define AUTHBY_RSASSA_PKCS1_V1_5_SHA2_BLOB	\
	AUTHBY_RSASSA_PKCS1_V1_5_SHA2_256_BLOB,	\
	AUTHBY_RSASSA_PKCS1_V1_5_SHA2_384_BLOB,	\
	AUTHBY_RSASSA_PKCS1_V1_5_SHA2_512_BLOB
#define AUTHBY_RSASSA_PKCS1_V1_5_SHA2		\
	AUTHBY_RSASSA_PKCS1_V1_5_SHA2_BLOB

#define AUTHBY_RSASSA_PKCS1_V1_5_BLOB		\
	AUTHBY_RSASSA_PKCS1_V1_5_SHA1_BLOB,	\
	AUTHBY_RSASSA_PKCS1_V1_5_SHA2_BLOB

#define AUTHBY_RSASSA_PKCS1_V1_5		\
	AUTHBY_RSASSA_PKCS1_V1_5_SHA1,		\
	AUTHBY_RSASSA_PKCS1_V1_5_SHA2

#define AUTHBY_RSASSA_PKCS1_V1_5		\
	AUTHBY_RSASSA_PKCS1_V1_5_SHA1,		\
	AUTHBY_RSASSA_PKCS1_V1_5_SHA2

#define AUTHBY_RSASSA_PSS_SHA2_256_BLOB			\
	.authby[AUTH_RSASSA_PSS_SHA2_256_BLOB] = true
#define AUTHBY_RSASSA_PSS_SHA2_384_BLOB			\
	.authby[AUTH_RSASSA_PSS_SHA2_384_BLOB] = true
#define AUTHBY_RSASSA_PSS_SHA2_512_BLOB			\
	.authby[AUTH_RSASSA_PSS_SHA2_512_BLOB] = true

#define AUTHBY_RSASSA_PSS_BLOB			\
	AUTHBY_RSASSA_PSS_SHA2_256_BLOB,	\
	AUTHBY_RSASSA_PSS_SHA2_384_BLOB,	\
	AUTHBY_RSASSA_PSS_SHA2_512_BLOB

#define AUTHBY_RSASSA_SHA2_256			\
	AUTHBY_RSASSA_PSS_SHA2_256_BLOB,	\
	AUTHBY_RSASSA_PKCS1_V1_5_SHA2_256_BLOB
#define AUTHBY_RSASSA_SHA2_384			\
	AUTHBY_RSASSA_PSS_SHA2_384_BLOB,	\
	AUTHBY_RSASSA_PKCS1_V1_5_SHA2_384_BLOB
#define AUTHBY_RSASSA_SHA2_512			\
	AUTHBY_RSASSA_PSS_SHA2_512_BLOB,	\
	AUTHBY_RSASSA_PKCS1_V1_5_SHA2_512_BLOB

#define AUTHBY_RSASSA_SHA1			\
	AUTHBY_RSASSA_PKCS1_V1_5_SHA1

#define AUTHBY_RSASSA_SHA2			\
	AUTHBY_RSASSA_SHA2_256,			\
	AUTHBY_RSASSA_SHA2_384,			\
	AUTHBY_RSASSA_SHA2_512

#define AUTHBY_RSASSA_BLOB			\
	AUTHBY_RSASSA_PSS_BLOB,			\
	AUTHBY_RSASSA_PKCS1_V1_5_BLOB

#define AUTHBY_RSASSA				\
	AUTHBY_RSASSA_SHA1,			\
	AUTHBY_RSASSA_SHA2

#define AUTHBY_ECDSA_SHA2_256				\
	.authby[AUTH_ECDSA_SHA2_256_BLOB] = true,	\
	.authby[AUTH_ECDSA_SHA2_256_RAW] = true
#define AUTHBY_ECDSA_SHA2_384				\
	.authby[AUTH_ECDSA_SHA2_384_BLOB] = true,	\
	.authby[AUTH_ECDSA_SHA2_384_RAW] = true
#define AUTHBY_ECDSA_SHA2_512				\
	.authby[AUTH_ECDSA_SHA2_512_BLOB] = true,	\
	.authby[AUTH_ECDSA_SHA2_512_RAW] = true
#define AUTHBY_ECDSA_SHA2			\
	AUTHBY_ECDSA_SHA2_256,			\
	AUTHBY_ECDSA_SHA2_384,			\
	AUTHBY_ECDSA_SHA2_512
#define AUTHBY_ECDSA_BLOB				\
	.authby[AUTH_ECDSA_SHA2_256_BLOB] = true,	\
	.authby[AUTH_ECDSA_SHA2_384_BLOB] = true,	\
	.authby[AUTH_ECDSA_SHA2_512_BLOB] = true
#define AUTHBY_ECDSA_RAW				\
	.authby[AUTH_ECDSA_SHA2_256_RAW] = true,	\
	.authby[AUTH_ECDSA_SHA2_384_RAW] = true,	\
	.authby[AUTH_ECDSA_SHA2_512_RAW] = true
#define AUTHBY_ECDSA				\
	AUTHBY_ECDSA_BLOB,			\
	AUTHBY_ECDSA_RAW

/* all algs IKEv1 and IKEv2 allow */

#define AUTHBY_ALL_IKEv2_DEFAULTS		\
	(struct authby) {			\
		AUTHBY_RSASSA,			\
	}

/*
 * Returns all the authentication methods that are supported using RFC
 * 7427's new "Digital Signature" AUTH payload identified by a BLOB
 * prefix.
 */

struct authby authby_v2AUTH_digsig_payload(void);
bool authby_has_v2AUTH_digsig_payload(struct authby authby);

/*
 * Set of authentication methods that use a pubkey (Digital Signature
 * Algorithm).  In addition to the new "Digital Signature" method
 * requiring RFC 7427 (Digital Signature AUTH payload) this includes
 * methods that require an AUTH specific.
 */
struct authby authby_v2AUTH_pubkey(void);
bool authby_has_v2AUTH_pubkey(struct authby);

struct authby authby_and(struct authby lhs, struct authby rhs);
struct authby authby_or(struct authby lhs, struct authby rhs);
struct authby authby_not(struct authby lhs);

bool authby_has_all(struct authby authby, struct authby all);
bool authby_has_any(struct authby authby, struct authby some);
bool authby_has_none(struct authby authby, struct authby none);

/*
 * Mask out all but HASH algorithms.
 *
 * As a special case, sha1 allows the RSA 1.5 bit.
 */

struct authby authby_and_hash(struct authby authby, const struct hash_desc *hash);
bool authby_has_hash(struct authby authby, const struct hash_desc *hash);

bool authby_is_set(struct authby authby);
unsigned authby_count(struct authby authby);
bool authby_eq(struct authby, struct authby);

struct authby authby_from_auth(enum auth auth);

struct authby authby_and_auth(struct authby, enum auth);

struct authby authby_add(struct authby, enum auth);
bool authby_has(struct authby, enum auth);

typedef struct {
	char buf[sizeof("PSK+RSASIG+ECDSA+EDDSA+MLDSA+AUTH_NEVER+AUTH_NULL+"
		"RSASIG_v1_5+RSASIG_SHA2_256+RSASIG_SHA2_384+RSASIG_SHA2_512+"
		"ECDSA_SHA2_256+ECDSA_SHA2_384+ECDSA_SHA2_512+"
		"MLDSA_44+MLDSA_65+MLDSA_87") + 1/*canary*/];
} authby_buf;

const char *str_authby(struct authby authby, authby_buf *buf);
size_t jam_authby(struct jambuf *buf, struct authby authby);

bool tto_ikev2_authby(shunk_t input, struct authby *update);
void jam_authbys_auth(struct jambuf *buf);

/* try to match what extract.c accepts and the auth: logs */
const char *str_authby_auth(struct authby authby, authby_buf *buf);
size_t jam_authby_auth(struct jambuf *buf, struct authby authby);

void jam_authby_sighash_policy(struct jambuf *buf, struct authby authby);

#endif
