/* impair constants, for libreswan
 *
 * Copyright (C) 2026 Andrew Cagney <cagney@gnu.org>
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

#include "impair.h"
#include "names.h"
#include "enum_names.h"

static const char *impair_payload_name[] = {
#define S(E) [E] = #E
	S(IMPAIR_PAYLOAD_EMIT_NEVER),
	S(IMPAIR_PAYLOAD_EMIT_EMPTY),
	S(IMPAIR_PAYLOAD_EMIT_DUPLICATE),
	S(IMPAIR_PAYLOAD_IGNORE),
#undef S
};

static const struct enum_names impair_payload_enum_names = {
	0, IMPAIR_PAYLOAD_ROOF-1,
	ARRAY_PTR(impair_payload_name),
	.en_prefix = "IMPAIR_PAYLOAD_",
};

const struct names impair_payload_names = {
	.enum_names = &impair_payload_enum_names,
};
