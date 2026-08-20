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

#define REDUCE(TYPE, LHS, OP)			\
	((TYPE)(LHS).null OP			\
	 (TYPE)(LHS).never OP			\
	 (TYPE)(LHS).psk OP			\
	 (TYPE)(LHS).rsasig OP			\
	 (TYPE)(LHS).rsasig_v1_5 OP		\
	 (TYPE)(LHS).eddsa OP			\
	 (TYPE)(LHS).ecdsa OP			\
	 (TYPE)(LHS).rsasig_sha2_256 OP		\
	 (TYPE)(LHS).rsasig_sha2_384 OP		\
	 (TYPE)(LHS).rsasig_sha2_512 OP		\
	 (TYPE)(LHS).ecdsa_sha2_256 OP		\
	 (TYPE)(LHS).ecdsa_sha2_384 OP		\
	 (TYPE)(LHS).ecdsa_sha2_512)

#define OP(LHS, OP, RHS)						\
	({								\
		struct authby tmp_ = {					\
			.null = (LHS).null OP (RHS).null,		\
			.never = (LHS).never OP (RHS).never,		\
			.psk = (LHS).psk OP (RHS).psk,			\
			.rsasig = (LHS).rsasig OP (RHS).rsasig,		\
			.eddsa = (LHS).eddsa OP (RHS).eddsa,		\
			.ecdsa = (LHS).ecdsa OP (RHS).ecdsa,		\
			.rsasig_v1_5 = (LHS).rsasig_v1_5 OP (RHS).rsasig_v1_5, \
			.rsasig_sha2_256 = (LHS).rsasig_sha2_256 OP (RHS).rsasig_sha2_256, \
			.rsasig_sha2_384 = (LHS).rsasig_sha2_384 OP (RHS).rsasig_sha2_384, \
			.rsasig_sha2_512 = (LHS).rsasig_sha2_512 OP (RHS).rsasig_sha2_512, \
			.ecdsa_sha2_256 = (LHS).ecdsa_sha2_256 OP (RHS).ecdsa_sha2_256, \
			.ecdsa_sha2_384 = (LHS).ecdsa_sha2_384 OP (RHS).ecdsa_sha2_384, \
			.ecdsa_sha2_512 = (LHS).ecdsa_sha2_512 OP (RHS).ecdsa_sha2_512, \
		};							\
		tmp_;							\
	})

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
			.rsasig_v1_5 = authby.rsasig_v1_5,
		};
	}
#define AND_HASH(HASH)						\
	if (hash == &ike_alg_hash_##HASH) {			\
		return (struct authby) {			\
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
		authby = authby_and(authby, authby_not(AUTHBY_ALL_ECDSA_SHA2));
		authby = authby_and(authby, authby_not(AUTHBY_ALL_RSASIG_SHA2));
		authby.rsasig_v1_5 = false;
		return authby;
	}
	return (struct authby) {0};
}

bool auth_in_authby(enum auth auth, struct authby authby)
{
	struct authby auth_bit = authby_from_auth(auth);
	/* auth bit must be set */
	return authby_is_set(authby_and(auth_bit, authby));
}

bool digital_signature_in_authby(struct authby authby)
{
	return authby_is_set(authby_and(AUTHBY_DIGITAL_SIGNATURE, authby));
}

enum auth auth_from_authby(struct authby authby)
{
	return (authby.rsasig ? AUTH_RSASIG :
		authby_has_any(authby, AUTHBY_ALL_ECDSA_SHA2) ? AUTH_ECDSA :
		authby.eddsa ? AUTH_EDDSA :
		authby.rsasig_v1_5 ? AUTH_RSASIG :
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
	case AUTH_ECDSA: return AUTHBY_ALL_ECDSA_SHA2;
	case AUTH_EDDSA: return (struct authby) { .eddsa = true, };
	case AUTH_RSASIG: return (struct authby) {
			.rsasig = true,
			.rsasig_v1_5 = true,
			.rsasig_sha2_256 = true,
			.rsasig_sha2_384 = true,
			.rsasig_sha2_512 = true,
		};
	case AUTH_EAPONLY: return (struct authby) {0};
	}
	bad_case(auth);
}

size_t jam_authby(struct jambuf *buf, struct authby authby)
{
#define JAM_AUTHBY(F, N)				\
	{						\
		if (authby.F) {				\
			s += jam_string(buf, sep);	\
			s += jam_string(buf, #N);	\
			sep = "+";			\
		}					\
	}
	size_t s = 0;
	const char *sep = "";
	JAM_AUTHBY(psk, PSK);
	JAM_AUTHBY(rsasig, RSASIG);
	if (!authby_le(AUTHBY_ALL_RSASIG_SHA2, authby)) {
		JAM_AUTHBY(rsasig_sha2_256, RSASIG_SHA2_256);
		JAM_AUTHBY(rsasig_sha2_384, RSASIG_SHA2_384);
		JAM_AUTHBY(rsasig_sha2_512, RSASIG_SHA2_512);
	}
	/*
	 * When AUTHBY has all the ECDSA_SHA2 bits set, use the the
	 * short-hand ECDSA.  This matches auth=ecdsa which will set
	 * all the bits below.
	 */
	if (authby_has_all(authby, AUTHBY_ALL_ECDSA_SHA2)) {
		pexpect(authby.ecdsa);
		s += jam_string(buf, sep); sep = "+";
		s += jam_string(buf, "ECDSA");
	} else {
		JAM_AUTHBY(ecdsa_sha2_256, ECDSA_SHA2_256);
		JAM_AUTHBY(ecdsa_sha2_384, ECDSA_SHA2_384);
		JAM_AUTHBY(ecdsa_sha2_512, ECDSA_SHA2_512);
	}
	JAM_AUTHBY(eddsa, EDDSA);
	JAM_AUTHBY(never, AUTH_NEVER);
	JAM_AUTHBY(null, AUTH_NULL);
	JAM_AUTHBY(rsasig_v1_5, RSASIG_v1_5);
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
