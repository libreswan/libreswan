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
#include "names.h"
#include "lswcdefs.h"		/* for ARRAY_PTR */

static const char *const auth_name[] = {
#define S(E) [E - AUTH_FLOOR] = #E
	S(AUTH_EAPONLY),
	S(AUTH_ECDSA_SHA2_256),
	S(AUTH_ECDSA_SHA2_384),
	S(AUTH_ECDSA_SHA2_512),
	S(AUTH_EDDSA),
	S(AUTH_NEVER),
	S(AUTH_NULL),
	S(AUTH_PSK),
	S(AUTH_RSASIG_RAW),
	S(AUTH_RSASIG_SHA2_256),
	S(AUTH_RSASIG_SHA2_384),
	S(AUTH_RSASIG_SHA2_512),
	S(AUTH_RSASIG_V1_5_SHA1),
	S(AUTH_RSASIG_V1_5_SHA2_256),
	S(AUTH_RSASIG_V1_5_SHA2_384),
	S(AUTH_RSASIG_V1_5_SHA2_512),
#undef S
};

static const struct enum_names auth_enum_names = {
	AUTH_FLOOR, AUTH_ROOF-1,
	ARRAY_PTR(auth_name),
	"AUTH_", /* prefix */
	NULL,
};

/*
 * XXX: note hack, PSK is mapped to SECRET.
 */

const struct names auth_names = {
	.enum_names = & auth_enum_names,
};
