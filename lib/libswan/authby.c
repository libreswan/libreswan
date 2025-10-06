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

#include "constants.h"		/* for enum keyword_auth */
#include "jambuf.h"
#include "lswlog.h"		/* for bad_case() */

#define REDUCE(LHS, OP)				\
	((LHS).null OP				\
	 (LHS).never OP				\
	 (LHS).psk OP				\
	 (LHS).rsasig OP			\
	 (LHS).rsasig_v1_5 OP			\
	 (LHS).eddsa OP				\
	 (LHS).ecdsa)

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
		};							\
		tmp_;							\
	})

bool authby_is_set(struct authby authby)
{
	return REDUCE(authby, ||);
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
	return REDUCE(eq, &&);
}

bool authby_le(struct authby lhs, struct authby rhs)
{
	struct authby le = OP(lhs, <=, rhs);
	return REDUCE(le, &&);
}

bool authby_has(struct authby authby, enum auth auth)
{
	struct authby auth_bit = authby_from_auth(auth);
	/* auth bit must be set */
	return authby_is_set(authby_and(auth_bit, authby));
}

bool authby_has_digsig(struct authby lhs)
{
	return (authby_has(lhs, AUTH_ECDSA) ||
		authby_has(lhs, AUTH_EDDSA) ||
		authby_has(lhs, AUTH_RSASIG));
}

enum auth auth_from_authby(struct authby authby)
{
	return (authby.rsasig ? AUTH_RSASIG :
		authby.ecdsa ? AUTH_ECDSA :
		authby.eddsa ? AUTH_EDDSA :
		authby.rsasig_v1_5 ? AUTH_RSASIG :
		authby.psk ? AUTH_PSK :
		authby.null ? AUTH_NULL :
		authby.never ? AUTH_NEVER :
		AUTH_UNSET);
}

struct authby authby_from_auth(enum auth auth)
{
#define AUTH(BY) case AUTH_##BY: return AUTHBY_##BY
	switch (auth) {
		AUTH(ECDSA);
		AUTH(EDDSA);
		AUTH(PSK);
		AUTH(NULL);
		AUTH(NEVER);
	case AUTH_RSASIG:
		return (struct authby) { .rsasig = true, .rsasig_v1_5 = true };
	case AUTH_UNSET:
		return AUTHBY_NEVER;
	case AUTH_EAPONLY:
		return (struct authby) {0};
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
	JAM_AUTHBY(ecdsa, ECDSA);
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
