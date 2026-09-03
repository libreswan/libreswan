/* ikev2 auth method names, for libreswan
 *
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 1998-2002,2015  D. Hugh Redelmeier.
 * Copyright (C) 2016-2026 Andrew Cagney
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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

#include "ietf_constants.h"
#include "enum_names.h"
#include "names.h"

static const char *const ikev2_auth_method_name[] = {
#define S(E) [E - IKEv2_AUTH_RESERVED] = #E
	S(IKEv2_AUTH_RESERVED),
	S(IKEv2_AUTH_RSA_DIGITAL_SIGNATURE),
	S(IKEv2_AUTH_SHARED_KEY_MAC),
	S(IKEv2_AUTH_DSS_DIGITAL_SIGNATURE),
	/* 4 - 8 unassigned */
	S(IKEv2_AUTH_ECDSA_SHA2_256_P256),
	S(IKEv2_AUTH_ECDSA_SHA2_384_P384),
	S(IKEv2_AUTH_ECDSA_SHA2_512_P521),
	S(IKEv2_AUTH_GENERIC_SECURE_PASSWORD_AUTHENTICATION_METHOD), /* 12 - RFC 6467 */
	S(IKEv2_AUTH_NULL),
	S(IKEv2_AUTH_DIGITAL_SIGNATURE), /* 14 - RFC 7427 */
#undef S
};

const struct enum_names ikev2_auth_method_names = {
	IKEv2_AUTH_RESERVED,
	IKEv2_AUTH_DIGITAL_SIGNATURE,
	ARRAY_PTR(ikev2_auth_method_name),
	"IKEv2_AUTH_", /* prefix */
	NULL
};

const struct names ikev2_auth_method_nom = {
	.enum_names = &ikev2_auth_method_names,
};
