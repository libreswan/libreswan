/* updown names, for libreswan
 *
 * Copyright (C) 2025-2026  Andrew Cagney
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

#include "updown_config.h"
#include "enum_names.h"
#include "names.h"

static const char *updown_config_name[] = {
#define C(E) [E] = #E
	C(UPDOWN_CONFIG_ASYNC),
	C(UPDOWN_CONFIG_EXEC),
#undef C
};

static const struct enum_names updown_config_enum_names = {
	0, UPDOWN_CONFIG_ROOF-1,
	ARRAY_PTR(updown_config_name),
	"UPDOWN_CONFIG_",
	NULL,
};

const struct names updown_config_names = {
	.enum_names = &updown_config_enum_names,
};
