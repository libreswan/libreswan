/* Send CA policy names, for libreswan
 *
 * Copyright (C) 2025 Andrew Cagney
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

#include "send_ca_policy.h"
#include "enum_names.h"
#include "lswcdefs.h"

static const char *send_ca_policy_name[] = {
#define S(E) [E] = #E
	S(CA_SEND_NONE),
	S(CA_SEND_ISSUER),
	S(CA_SEND_ALL),
#undef S
};

const struct enum_names send_ca_policy_names  = {
	CA_SEND_NONE, CA_SEND_ALL,
	ARRAY_REF(send_ca_policy_name),
	.en_prefix = "CA_SEND_",
};
