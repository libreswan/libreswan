/* PSK authentication variations
 *
 * Copyright (C) 2026 Andrew Cagney
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

#include "psk_auth_method.h"
#include "names.h"
#include "enum_names.h"

static const char *psk_auth_method_enum_name[] = {
#define S(E) [E-PSK_AUTH_NULL] = #E
	S(PSK_AUTH_NULL),
	S(PSK_AUTH_SHARED_KEY),
#undef S
};

static const struct enum_names psk_auth_method_enum_names = {
	PSK_AUTH_NULL, PSK_AUTH_SHARED_KEY,
	ARRAY_PTR(psk_auth_method_enum_name),
	"PSK_AUTH_",
	NULL,
};

const struct names psk_auth_method_names = {
	.enum_names = &psk_auth_method_enum_names,
};

/**/

static const char *psk_auth_method_enum_story[] = {
#define S(E,N) [E-PSK_AUTH_NULL] = N
	S(PSK_AUTH_NULL, "null"),
	S(PSK_AUTH_SHARED_KEY, "secret"),
#undef S
};

static const struct enum_names psk_auth_method_enum_stories = {
	PSK_AUTH_NULL, PSK_AUTH_SHARED_KEY,
	ARRAY_PTR(psk_auth_method_enum_story),
	"PSK_AUTH_",
	NULL,
};

const struct names psk_auth_method_stories = {
	.enum_names = &psk_auth_method_enum_stories,
};
