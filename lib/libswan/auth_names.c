/* table of auth names, for libreswan
 *
 * Copyright (C) 2023-2025 Andrew Cagney
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

#include "auth.h"

#include "enum_names.h"
#include "lswcdefs.h"		/* for ARRAY_REF */

static const char *const auth_name[] = {
#define S(E) [E - AUTH_FLOOR] = #E
	S(AUTH_NEVER),
	S(AUTH_PSK),
	S(AUTH_RSASIG),
	S(AUTH_ECDSA),
	S(AUTH_NULL),
	S(AUTH_EAPONLY),
#undef R
};

static const struct enum_names auth_real_names = {
	AUTH_FLOOR, AUTH_ROOF-1,
	ARRAY_REF(auth_name),
	"AUTH_", /* prefix */
	NULL,
};

static const char *auth_alias_name[] = {
	"secret",
};

/*
 * XXX: note hack, PSK is mapped to SECRET.
 */

const struct enum_names auth_names = {
	AUTH_PSK, AUTH_PSK,
	ARRAY_REF(auth_alias_name),
	NULL,
	&auth_real_names,
};
