/* binary IEC 60027-2 scale, for libreswan
 *
 * Copyright (C) 2022 Antony Antony <antony@phenome.org>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 */

#include "binaryscale-iec-60027-2.h"

#include "scale.h"
#include "lswcdefs.h"
#include "constants.h"		/* for binary_per_kilo */

static const struct scale binary_scale[] = {
	{"",   1, },
	{"Ki", 1 * binary_per_kilo, },
	{"Mi", 1 * binary_per_mega, },
	{"Gi", 1 * binary_per_giga, },
	{"Ti", 1 * binary_per_tera, },
	{"Pi", 1 * binary_per_peta, },
	{"Ei", 1 * binary_per_exa, },
};

const struct scales binary_scales = {
	.base = 1024,
	.name = "binary",
	.default_scale = 0,
	.scale = { ARRAY_REF(binary_scale), },
};

static const struct scale binary_byte_scale[] = {
	{"",    1, },
	{"KiB", 1 * binary_per_kilo, },
	{"MiB", 1 * binary_per_mega, },
	{"GiB", 1 * binary_per_giga, },
	{"TiB", 1 * binary_per_tera, },
	{"PiB", 1 * binary_per_peta, },
	{"PiB", 1 * binary_per_exa, },
};

const struct scales binary_byte_scales = {
	.base = 1024,
	.name = "binary byte",
	.default_scale = 0,
	.scale = { ARRAY_REF(binary_byte_scale), },
};
