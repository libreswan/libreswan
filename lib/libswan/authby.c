/* Authentication, for libreswan
 *
 * Copyright (C) 2022 Andrew Cagney <cagney@gnu.org>
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

#include "authby.h"
#include "auth.h"

#include "ike_alg_hash.h"

#include "constants.h"		/* for enum keyword_auth */
#include "jambuf.h"
#include "lswlog.h"		/* for bad_case() */

#define REDUCE_SHA2(TYPE, LHS, OP, AUTH)	\
	(TYPE)(LHS).AUTH##_sha2_256 OP		\
	(TYPE)(LHS).AUTH##_sha2_384 OP		\
	(TYPE)(LHS).AUTH##_sha2_512

#define REDUCE(TYPE, LHS, OP)			\
	((TYPE)(LHS).null OP			\
	 (TYPE)(LHS).never OP			\
	 (TYPE)(LHS).psk OP			\
	 (TYPE)(LHS).eddsa OP			\
	 (TYPE)(LHS).rsasig OP			\
	 (TYPE)(LHS).rsasig_v1_5_sha1 OP		\
	 REDUCE_SHA2(TYPE, LHS, OP, rsasig_v1_5) OP \
	 REDUCE_SHA2(TYPE, LHS, OP, rsasig) OP	\
	 REDUCE_SHA2(TYPE, LHS, OP, ecdsa))

#define OP_SHA2(LHS, OP, RHS, AUTH)				\
	.AUTH##_sha2_256 = (LHS).AUTH##_sha2_256 OP (RHS).AUTH##_sha2_256, \
	.AUTH##_sha2_384 = (LHS).AUTH##_sha2_384 OP (RHS).AUTH##_sha2_384, \
	.AUTH##_sha2_512 = (LHS).AUTH##_sha2_512 OP (RHS).AUTH##_sha2_512

#define OP(LHS, OP, RHS)					\
	(struct authby) {					\
		.null = (LHS).null OP (RHS).null,		\
		.never = (LHS).never OP (RHS).never,		\
		.psk = (LHS).psk OP (RHS).psk,			\
		.rsasig = (LHS).rsasig OP (RHS).rsasig,		\
		.eddsa = (LHS).eddsa OP (RHS).eddsa,		\
		.rsasig_v1_5_sha1 = (LHS).rsasig_v1_5_sha1 OP (RHS).rsasig_v1_5_sha1, \
		OP_SHA2(LHS, OP, RHS, rsasig_v1_5),		\
		OP_SHA2(LHS, OP, RHS, rsasig),			\
		OP_SHA2(LHS, OP, RHS, ecdsa),			\
	}

bool authby_is_set(struct authby authby)
{
	return authby_count(authby) > 0;
}

unsigned authby_count(struct authby authby)
{
	return REDUCE(unsigned, authby, +);
}

struct authby authby_xor(struct authby lhs, struct authby rhs)
{
	return OP(lhs, !=, rhs);
}

struct authby authby_not(struct authby lhs)
{
	return authby_xor(lhs, AUTHBY_ALL);
}

struct authby authby_and(struct authby lhs, struct authby rhs)
{
	return OP(lhs, &&, rhs);
}

struct authby authby_or(struct authby lhs, struct authby rhs)
{
	return OP(lhs, ||, rhs);
}

bool authby_eq(struct authby lhs, struct authby rhs)
{
	struct authby eq = OP(lhs, ==, rhs);
	return REDUCE(bool, eq, &&);
}

bool authby_le(struct authby lhs, struct authby rhs)
{
	struct authby le = OP(lhs, <=, rhs);
	return REDUCE(bool, le, &&);
}

bool authby_has_all(struct authby authby, struct authby all)
{
	struct authby and = authby_and(authby, all);
	return authby_eq(and, all); /*all*/
}

bool authby_has_any(struct authby authby, struct authby some)
{
	struct authby and = authby_and(authby, some);
	return authby_count(and) > 0; /* at least 1 */
}

bool authby_has_none(struct authby authby, struct authby none)
{
	struct authby and = authby_and(authby, none);
	return authby_count(and) == 0; /*none*/
}

struct authby authby_and_hash(struct authby authby,
			      const struct hash_desc *hash)
{
	if (hash == &ike_alg_hash_sha1) {
		/* sha1 is only allowed with rsasig_v1.5 */
		return (struct authby) {
			.rsasig_v1_5_sha1 = authby.rsasig_v1_5_sha1,
		};
	}
	/*
	 * Allow PKCS#1 RSA v1.5 with SHA2; even though it doesn't
	 * have an explicit bit.
	 */
#define AND_HASH(HASH)						\
	if (hash == &ike_alg_hash_##HASH) {			\
		return (struct authby) {			\
			.rsasig_v1_5_##HASH = authby.rsasig_v1_5_##HASH, \
			.rsasig_##HASH = authby.rsasig_##HASH,	\
			.ecdsa_##HASH = authby.ecdsa_##HASH,	\
		};						\
	}
	AND_HASH(sha2_256);
	AND_HASH(sha2_384);
	AND_HASH(sha2_512);
#undef AND_HASH
	if (hash == &ike_alg_hash_identity) {
		/* only allow algs that don't need a hash */
		return (struct authby) {
			.eddsa = authby.eddsa,
		};
	}
	return (struct authby) {0};
}

bool authby_has_hash(struct authby authby,
		     const struct hash_desc *hash)
{
	return authby_is_set(authby_and_hash(authby, hash));
}

bool auth_in_authby(enum auth auth, struct authby authby)
{
	struct authby auth_bit = authby_from_auth(auth);
	/* auth bit must be set */
	return authby_is_set(authby_and(auth_bit, authby));
}

bool authby_has_supported_ikev2_digsig_payload(struct authby authby)
{
	return authby_has_any(authby, supported_ikev2_digsig_auth_payloads());
}

enum auth auth_from_authby(struct authby authby)
{
	/*
	 * XXX: check for IKEv1 and SHA2 RSA, and then later check for
	 * v1.5 RSA.  It's just how it has always been.
	 */
	return (authby_has_any(authby, (struct authby) {
				AUTHBY_RSASIG_RAW,
				AUTHBY_RSASIG_SHA2,
			}) ? AUTH_RSASIG :
		authby_has_any(authby, (struct authby) {
				AUTHBY_ECDSA_SHA2,
			}) ? AUTH_ECDSA :
		authby_has_any(authby, (struct authby) {
				AUTHBY_EDDSA,
			}) ? AUTH_EDDSA :
		authby_has_any(authby, (struct authby) {
				AUTHBY_RSASIG_V1_5,
			}) ? AUTH_RSASIG :
		authby.psk ? AUTH_PSK :
		authby.null ? AUTH_NULL :
		authby.never ? AUTH_NEVER :
		AUTH_UNSET);
}

struct authby authby_from_auth(enum auth auth)
{
	switch (auth) {
	case AUTH_UNSET:
	case AUTH_NEVER: return (struct authby) { .never = true, };
	case AUTH_NULL: return (struct authby) { .null = true, };
	case AUTH_PSK: return (struct authby) { .psk = true, };
	case AUTH_ECDSA: return (struct authby) {
			AUTHBY_ECDSA_SHA2,
		};
	case AUTH_EDDSA: return (struct authby) { .eddsa = true, };
	case AUTH_RSASIG: return (struct authby) {
			AUTHBY_RSASIG_RAW,
			AUTHBY_RSASIG_V1_5,
			AUTHBY_RSASIG_SHA2,
		};
	case AUTH_EAPONLY: return (struct authby) {0};
	}
	bad_case(auth);
}

size_t jam_authby(struct jambuf *buf, struct authby authby)
{
#define JAM_STRING(N)					\
	{						\
		s += jam_string(buf, sep);		\
		s += jam_string(buf, #N);		\
		sep = "+";				\
	}
#define JAM_AUTHBY(F, N)				\
	{						\
		if (authby.F) {				\
			JAM_STRING(N);			\
		}					\
	}
	size_t s = 0;
	const char *sep = "";
	JAM_AUTHBY(psk, PSK);
	if (authby_has_all(authby, (struct authby) {
				AUTHBY_RSASIG_RAW,
				AUTHBY_RSASIG_V1_5,
				AUTHBY_RSASIG_SHA2,
			})) {
		/* legacy */
		JAM_STRING(RSASIG);
	} else if (authby_has_all(authby, (struct authby) {
				AUTHBY_RSASIG_RAW,
			}) &&
		!authby_has_any(authby, (struct authby) {
				AUTHBY_RSASIG_V1_5,
				AUTHBY_RSASIG_SHA2,
			})) {
		/* IKEv1 */
		JAM_STRING(RSASIG);
	} else if (authby_has_all(authby, (struct authby) {
				AUTHBY_RSASIG_V1_5,
				AUTHBY_RSASIG_SHA2,
			}) &&
		!authby_has_all(authby, (struct authby) {
				AUTHBY_RSASIG_RAW,
			})) {
		/* IKEv2 */
		JAM_STRING(RSASIG);
	} else {
		JAM_AUTHBY(rsasig, RSASIG);
		if (authby_has_all(authby, (struct authby) {
					AUTHBY_RSASIG_SHA2,
				})) {
			JAM_STRING(RSASIG_SHA2);
		} else {
			JAM_AUTHBY(rsasig_sha2_256, RSASIG_SHA2_256);
			JAM_AUTHBY(rsasig_sha2_384, RSASIG_SHA2_384);
			JAM_AUTHBY(rsasig_sha2_512, RSASIG_SHA2_512);
		}
		if (authby_has_all(authby, (struct authby) {
					AUTHBY_RSASIG_V1_5,
				})) {
			JAM_STRING(RSASIG_v1_5);
		} else {
			JAM_AUTHBY(rsasig_v1_5_sha1, RSASIG_v1_5_SHA1);
			JAM_AUTHBY(rsasig_v1_5_sha2_256, RSASIG_V1_5_SHA2_256);
			JAM_AUTHBY(rsasig_v1_5_sha2_384, RSASIG_V1_5_SHA2_384);
			JAM_AUTHBY(rsasig_v1_5_sha2_512, RSASIG_V1_5_SHA2_512);
		}
	}
	/*
	 * When AUTHBY has all the ECDSA_SHA2 bits set, use the the
	 * short-hand ECDSA.  This matches auth=ecdsa which will set
	 * all the bits below.
	 */
	if (authby_has_all(authby, (struct authby) {
				AUTHBY_ECDSA_SHA2,
			})) {
		JAM_STRING(ECDSA);
	} else {
		JAM_AUTHBY(ecdsa_sha2_256, ECDSA_SHA2_256);
		JAM_AUTHBY(ecdsa_sha2_384, ECDSA_SHA2_384);
		JAM_AUTHBY(ecdsa_sha2_512, ECDSA_SHA2_512);
	}
	JAM_AUTHBY(eddsa, EDDSA);
	JAM_AUTHBY(never, AUTH_NEVER);
	JAM_AUTHBY(null, AUTH_NULL);
#undef JAM_STRING
#undef JAM_AUTHBY
	if (s == 0) {
		s += jam_string(buf, "none");
	}
	return s;
}

const char *str_authby(struct authby authby, authby_buf *buf)
{
	struct jambuf jambuf = ARRAY_AS_JAMBUF(buf->buf);
	jam_authby(&jambuf, authby);
	return buf->buf;
}

lset_t authby_sighash_policy(struct authby authby)
{
	lset_t sighash_policy = LEMPTY;
	if (authby_has_hash(authby, &ike_alg_hash_sha2_256)) {
		sighash_policy |= POL_SIGHASH_SHA2_256;
	}
	if (authby_has_hash(authby, &ike_alg_hash_sha2_384)) {
		sighash_policy |= POL_SIGHASH_SHA2_384;
	}
	if (authby_has_hash(authby, &ike_alg_hash_sha2_512)) {
		sighash_policy |= POL_SIGHASH_SHA2_512;
	}
	if (authby_has_hash(authby, &ike_alg_hash_identity)) {
		sighash_policy |= POL_SIGHASH_IDENTITY;
	}

	return sighash_policy;
}

struct authby supported_ikev2_digsig_auth_payloads(void)
{
	return (struct authby) {
#ifdef USE_EDDSA
		AUTHBY_EDDSA,
#endif
		AUTHBY_RSASIG_V1_5,
		AUTHBY_RSASIG_SHA2,
		AUTHBY_ECDSA_SHA2,
	};
}

bool authby_has_pubkey(struct authby authby)
{
	return authby_has_any(authby, (struct authby) {
			AUTHBY_RSASIG_RAW,
#ifdef USE_EDDSA
			AUTHBY_EDDSA,
#endif
			AUTHBY_RSASIG_V1_5,
			AUTHBY_RSASIG_SHA2,
			AUTHBY_ECDSA_SHA2,
		});
}
