/* Authentication, for libreswan
 *
 * Copyright (C) 2022 Andrew Cagney
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

#include "auth.h"

struct jambuf;
struct hash_desc;

struct authby {
	/*
	 * XXX: add new authby flags to this array so there's less to
	 * move over down the track.
	 */
	bool authby[AUTH_ROOF];
#define authby_eaponly authby[AUTH_EAPONLY]
#define AUTHBY_EAPONLY				\
	.authby_eaponly = true

#define authby_psk authby[AUTH_PSK]
#define AUTHBY_PSK				\
	.authby_psk = true

#define authby_null authby[AUTH_NULL]
#define AUTHBY_NULL				\
	.authby_null = true

#define authby_never authby[AUTH_NEVER]
#define AUTHBY_NEVER				\
	.authby_never = true

#define authby_eddsa authby[AUTH_EDDSA]
#define AUTHBY_EDDSA				\
	.authby_eddsa = true

	/* XXX: should be IKEv1 only */
#define authby_rsasig_raw authby[AUTH_RSASIG_RAW]
#define AUTHBY_RSASIG_RAW			\
	.authby_rsasig_raw = true

#define authby_rsasig_v1_5_sha1 authby[AUTH_RSASIG_V1_5_SHA1]
#define AUTHBY_RSASIG_V1_5_SHA1			\
	.authby_rsasig_v1_5_sha1 = true

#define authby_rsasig_v1_5_sha2_256 authby[AUTH_RSASIG_V1_5_SHA2_256]
#define authby_rsasig_v1_5_sha2_384 authby[AUTH_RSASIG_V1_5_SHA2_384]
#define authby_rsasig_v1_5_sha2_512 authby[AUTH_RSASIG_V1_5_SHA2_512]
#define AUTHBY_RSASIG_V1_5_SHA2_256		\
	.authby_rsasig_v1_5_sha2_256 = true
#define AUTHBY_RSASIG_V1_5_SHA2_384		\
	.authby_rsasig_v1_5_sha2_384 = true
#define AUTHBY_RSASIG_V1_5_SHA2_512		\
	.authby_rsasig_v1_5_sha2_512 = true
#define AUTHBY_RSASIG_V1_5_SHA2			\
	AUTHBY_RSASIG_V1_5_SHA2_256,		\
	AUTHBY_RSASIG_V1_5_SHA2_384,		\
	AUTHBY_RSASIG_V1_5_SHA2_512

#define AUTHBY_RSASIG_V1_5			\
	AUTHBY_RSASIG_V1_5_SHA1,		\
	AUTHBY_RSASIG_V1_5_SHA2

#define authby_rsasig_sha2_256 authby[AUTH_RSASIG_SHA2_256]
#define authby_rsasig_sha2_384 authby[AUTH_RSASIG_SHA2_384]
#define authby_rsasig_sha2_512 authby[AUTH_RSASIG_SHA2_512]
#define AUTHBY_RSASIG_SHA2_256			\
	.authby_rsasig_sha2_256 = true
#define AUTHBY_RSASIG_SHA2_384			\
	.authby_rsasig_sha2_384 = true
#define AUTHBY_RSASIG_SHA2_512			\
	.authby_rsasig_sha2_512 = true
#define AUTHBY_RSASIG_SHA2			\
	AUTHBY_RSASIG_SHA2_256,			\
	AUTHBY_RSASIG_SHA2_384,			\
	AUTHBY_RSASIG_SHA2_512
#define AUTHBY_RSASIG				\
	AUTHBY_RSASIG_RAW,			\
	AUTHBY_RSASIG_V1_5,			\
	AUTHBY_RSASIG_SHA2

#define authby_ecdsa_sha2_256 authby[AUTH_ECDSA_SHA2_256]
#define authby_ecdsa_sha2_384 authby[AUTH_ECDSA_SHA2_384]
#define authby_ecdsa_sha2_512 authby[AUTH_ECDSA_SHA2_512]
#define AUTHBY_ECDSA_SHA2_256			\
	.authby_ecdsa_sha2_256 = true
#define AUTHBY_ECDSA_SHA2_384			\
	.authby_ecdsa_sha2_384 = true
#define AUTHBY_ECDSA_SHA2_512			\
	.authby_ecdsa_sha2_512 = true
#define AUTHBY_ECDSA_SHA2			\
	AUTHBY_ECDSA_SHA2_256,			\
	AUTHBY_ECDSA_SHA2_384,			\
	AUTHBY_ECDSA_SHA2_512
#define AUTHBY_ECDSA				\
	AUTHBY_ECDSA_SHA2

};

/* all algs IKEv1 and IKEv2 allow */

#define AUTHBY_ALL authby_not((struct authby) {0})

#define AUTHBY_IKEv2				\
	AUTHBY_PSK,				\
	AUTHBY_NULL,				\
	AUTHBY_NEVER,				\
	AUTHBY_EAPONLY,				\
	AUTHBY_EDDSA,				\
	AUTHBY_RSASIG_V1_5,			\
	AUTHBY_RSASIG_SHA2,			\
	AUTHBY_ECDSA_SHA2

#define AUTHBY_ALL_IKEv2_DEFAULTS		\
	(struct authby) {			\
		AUTHBY_RSASIG_V1_5,		\
		AUTHBY_RSASIG_SHA2,		\
	}

/*
 * Returns all the authentication methods that are supported using RFC
 * 7427's new "Digital Signature" AUTH payload.
 */

struct authby supported_ikev2_digsig_auth_payloads(void);
bool authby_has_supported_ikev2_digsig_payload(struct authby);

#define AUTHBY_IKEv2_ONLY			\
	AUTHBY_RSASIG_V1_5,			\
	AUTHBY_RSASIG_SHA2,			\
	AUTHBY_ECDSA_SHA2,			\
	AUTHBY_EDDSA

struct authby authby_xor(struct authby lhs, struct authby rhs);
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
struct authby authby_or_auth(struct authby, enum auth);
bool authby_has_auth(struct authby, enum auth);

/*
 * Do the authentication methods include pubkey (digital signature)
 * algorithms.  This is not the same has a pubkey method that works
 * with RFC 7427 (Digital Signature AUTH payload).
 */
bool authby_has_pubkey(struct authby);

typedef struct {
	char buf[sizeof("PSK+RSASIG+ECDSA+EDDSA+AUTH_NEVER+AUTH_NULL+"
		"RSASIG_v1_5+RSASIG_SHA2_256+RSASIG_SHA2_384+RSASIG_SHA2_512+"
		"ECDSA_SHA2_256+ECDSA_SHA2_384+ECDSA_SHA2_512") + 1/*canary*/];
} authby_buf;

const char *str_authby(struct authby authby, authby_buf *buf);
size_t jam_authby(struct jambuf *buf, struct authby authby);

/* try to match what extract.c accepts and the auth: logs */
const char *str_authby_auth(struct authby authby, authby_buf *buf);
size_t jam_authby_auth(struct jambuf *buf, struct authby authby);

void jam_authby_sighash_policy(struct jambuf *buf, struct authby authby);

#endif
