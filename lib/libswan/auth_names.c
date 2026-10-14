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
	S(AUTH_ECDSA_SHA2_256_BLOB),
	S(AUTH_ECDSA_SHA2_256_RAW),
	S(AUTH_ECDSA_SHA2_384_BLOB),
	S(AUTH_ECDSA_SHA2_384_RAW),
	S(AUTH_ECDSA_SHA2_512_BLOB),
	S(AUTH_ECDSA_SHA2_512_RAW),
	S(AUTH_EDDSA_ED25519),
	S(AUTH_MLDSA_44),
	S(AUTH_MLDSA_65),
	S(AUTH_MLDSA_87),
	S(AUTH_NEVER),
	S(AUTH_NULL),
	S(AUTH_PSK),
	/**/
	S(AUTH_RSASIG_IKEv1),
	/*RSASSA-PSS in AUTH DIGSIG payload*/
	S(AUTH_RSASSA_PSS_SHA2_256_BLOB),
	S(AUTH_RSASSA_PSS_SHA2_384_BLOB),
	S(AUTH_RSASSA_PSS_SHA2_512_BLOB),
	S(AUTH_RSASSA_PKCS1_V1_5_SHA1_RAW),
	S(AUTH_RSASSA_PKCS1_V1_5_SHA1_BLOB),
	S(AUTH_RSASSA_PKCS1_V1_5_SHA2_256_BLOB),
	S(AUTH_RSASSA_PKCS1_V1_5_SHA2_384_BLOB),
	S(AUTH_RSASSA_PKCS1_V1_5_SHA2_512_BLOB),
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
