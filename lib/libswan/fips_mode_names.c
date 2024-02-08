/* fips_mode_names, for libreswan
 *
 * Copyright (C) 2024 Andrew Cagney
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

#include "fips_mode.h"
#include "enum_names.h"
#include "lswcdefs.h"

const char *fips_mode_name[] = {
#define S(E) [E - FIPS_MODE_FLOOR] = #E
	S(FIPS_MODE_ON),
	S(FIPS_MODE_OFF),
};

const struct enum_names fips_mode_names = {
	FIPS_MODE_FLOOR, FIPS_MODE_ROOF-1,
	ARRAY_REF(fips_mode_name),
	"FIPS_MODE_",
	NULL,
};
