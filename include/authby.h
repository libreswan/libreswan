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

#include "lset.h"

enum auth;
struct jambuf;
struct hash_desc;

enum authby_kind {
	AUTHBY_KIND_EAPONLY,
#define AUTHBY_KIND_ROOF (AUTHBY_KIND_EAPONLY+1)
};

struct authby {
	/*
	 * XXX: add new authby flags to this array so there's less to
	 * move over down the track.
	 */
	bool flag[AUTHBY_KIND_ROOF];
#define authby_eaponly flag[AUTHBY_KIND_EAPONLY]

	bool psk;	/* flag[AUTHBY_KIND_PSK] */
#define authby_psk psk

	bool null;	/* flag[AUTHBY_KIND_NULL] */
#define authby_null null

	bool never;	/* flag[AUTHBY_KIND_NEVER] */
#define authby_never never

	bool eddsa;	/* flag[AUTHBY_KIND_EDDSA] */
#define authby_eddsa eddsa
#define AUTHBY_EDDSA				\
	.authby_eddsa = true

	/* XXX: should be IKEv1 only */
	bool rsasig;	/* flag[AUTHBY_KIND_RSASIG_RAW] */
#define authby_rsasig_raw rsasig
#define AUTHBY_RSASIG_RAW			\
	.authby_rsasig_raw = true

	bool rsasig_v1_5_sha1;
#define authby_rsasig_v1_5_sha1 rsasig_v1_5_sha1
#define AUTHBY_RSASIG_V1_5_SHA1			\
	.rsasig_v1_5_sha1 = true

	bool rsasig_v1_5_sha2_256;
	bool rsasig_v1_5_sha2_384;
	bool rsasig_v1_5_sha2_512;
#define authby_rsasig_v1_5_sha2_256 rsasig_v1_5_sha2_256
#define authby_rsasig_v1_5_sha2_384 rsasig_v1_5_sha2_384
#define authby_rsasig_v1_5_sha2_512 rsasig_v1_5_sha2_512
#define AUTHBY_RSASIG_V1_5_SHA2			\
	.authby_rsasig_v1_5_sha2_256 = true,		\
	.authby_rsasig_v1_5_sha2_384 = true,		\
	.authby_rsasig_v1_5_sha2_512 = true

#define AUTHBY_RSASIG_V1_5			\
	AUTHBY_RSASIG_V1_5_SHA1,		\
	AUTHBY_RSASIG_V1_5_SHA2

	bool rsasig_sha2_256;
	bool rsasig_sha2_384;
	bool rsasig_sha2_512;
#define authby_rsasig_sha2_256 rsasig_sha2_256
#define authby_rsasig_sha2_384 rsasig_sha2_384
#define authby_rsasig_sha2_512 rsasig_sha2_512
#define AUTHBY_RSASIG_SHA2			\
	.authby_rsasig_sha2_256 = true,		\
	.authby_rsasig_sha2_384 = true,		\
	.authby_rsasig_sha2_512 = true
#define AUTHBY_RSASIG				\
	AUTHBY_RSASIG_RAW,			\
	AUTHBY_RSASIG_V1_5,			\
	AUTHBY_RSASIG_SHA2

	bool ecdsa_sha2_256;
	bool ecdsa_sha2_384;
	bool ecdsa_sha2_512;
#define authby_ecdsa_sha2_256 ecdsa_sha2_256
#define authby_ecdsa_sha2_384 ecdsa_sha2_384
#define authby_ecdsa_sha2_512 ecdsa_sha2_512
#define AUTHBY_ECDSA_SHA2			\
	.authby_ecdsa_sha2_256 = true,		\
	.authby_ecdsa_sha2_384 = true,		\
	.authby_ecdsa_sha2_512 = true
#define AUTHBY_ECDSA				\
	AUTHBY_ECDSA_SHA2

};

/* all algs IKEv1 and IKEv2 allow */

#define AUTHBY_ALL authby_not((struct authby) {0})

#define AUTHBY_IKEv1				\
	.psk = true,				\
	.null = true,				\
	.never = true,				\
	AUTHBY_RSASIG_RAW

#define AUTHBY_IKEv2				\
	.psk = true,				\
	.null = true,				\
	.never = true,				\
	.authby_eaponly = true,			\
	AUTHBY_EDDSA,				\
	AUTHBY_RSASIG_V1_5,			\
	AUTHBY_RSASIG_SHA2,			\
	AUTHBY_ECDSA_SHA2

#define AUTHBY_ALL_IKEv1_DEFAULTS		\
	(struct authby) {			\
		AUTHBY_RSASIG_RAW,		\
	}

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

bool authby_le(struct authby lhs, struct authby rhs);
bool authby_is_set(struct authby authby);
unsigned authby_count(struct authby authby);
bool authby_eq(struct authby, struct authby);

struct authby authby_and_auth(struct authby, enum auth);
bool authby_has_auth(struct authby, enum auth);

lset_t authby_sighash_policy(struct authby);

/*
 * Do the authentication methods include pubkey (digital signature)
 * algorithms.  This is not the same has a pubkey method that works
 * with RFC 7427 (Digital Signature AUTH payload).
 */
bool authby_has_pubkey(struct authby);

enum auth auth_from_authby(struct authby authby);
struct authby authby_from_auth(enum auth auth);

typedef struct {
	char buf[sizeof("PSK+RSASIG+ECDSA+EDDSA+AUTH_NEVER+AUTH_NULL+"
		"RSASIG_v1_5+RSASIG_SHA2_256+RSASIG_SHA2_384+RSASIG_SHA2_512+"
		"ECDSA_SHA2_256+ECDSA_SHA2_384+ECDSA_SHA2_512") + 1/*canary*/];
} authby_buf;

const char *str_authby(struct authby authby, authby_buf *buf);

size_t jam_authby(struct jambuf *buf, struct authby authby);

#endif
