/* direction of travel, for libreswan
 *
 * Copyright (C) 2021-2024,2026  Andrew Cagney
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

#include "direction.h"
#include "enum_names.h"
#include "names.h"

/* enum direction_names */

static const char *direction_name[] = {
#define S(E) [E-DIRECTION_INBOUND] = #E
	S(DIRECTION_OUTBOUND),
	S(DIRECTION_INBOUND),
#undef S
};

static const struct enum_names direction_enum_names = {
	DIRECTION_INBOUND,
	DIRECTION_OUTBOUND,
	ARRAY_PTR(direction_name),
	.en_prefix = "DIRECTION_",
};

const struct names direction_names = {
	.enum_names = &direction_enum_names,
};
