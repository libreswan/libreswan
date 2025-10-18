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
	{ 1,                   "",   NULL, NULL, },
	{ 1 * binary_per_kilo, "Ki", NULL, NULL, },
	{ 1 * binary_per_mega, "Mi", NULL, NULL, },
	{ 1 * binary_per_giga, "Gi", NULL, NULL, },
	{ 1 * binary_per_tera, "Ti", NULL, NULL, },
	{ 1 * binary_per_peta, "Pi", NULL, NULL, },
	{ 1 * binary_per_exa,  "Ei", NULL, NULL, },
};

const struct scales binary_scales = {
	.name = "binary",
	.default_scale = 0,
	LIST_REF(binary_scale),
};

static const struct scale binary_byte_scale[] = {
	{ 1,                   "",    "byte",     "bytes", },
	{ 1 * binary_per_kilo, "KiB", "kilobyte", "kilobytes", },
	{ 1 * binary_per_mega, "MiB", "megabyte", "megabytes", },
	{ 1 * binary_per_giga, "GiB", "gigabyte", "gigabytes", },
	{ 1 * binary_per_tera, "TiB", "terabyte", "terrabytes", },
	{ 1 * binary_per_peta, "PiB", "petabyte", "petabytes", },
	{ 1 * binary_per_exa,  "PiB", "exabyte",  "exabytes", },
};

const struct scales binary_byte_scales = {
	.name = "binary byte",
	.default_scale = 0,
	LIST_REF(binary_byte_scale),
};
