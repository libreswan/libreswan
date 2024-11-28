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

#include "binary-iec-60027-2.h"

#include "lswcdefs.h"
#include "constants.h"		/* for binary_per_kilo */
#include "binaryscale-iec-60027-2.h"

static const struct scale binaryscale[] = {
	{"",   1, },
	{"Ki", 1 * binary_per_kilo, },
	{"Mi", 1 * binary_per_mega, },
	{"Gi", 1 * binary_per_giga, },
	{"Ti", 1 * binary_per_tera, },
	{"Pi", 1 * binary_per_peta, },
	{"Ei", 1 * binary_per_exa, },
};

static const struct scale binarybytescale[] = {
	{"",    1, },
	{"KiB", 1 * binary_per_kilo, },
	{"MiB", 1 * binary_per_mega, },
	{"GiB", 1 * binary_per_giga, },
	{"TiB", 1 * binary_per_tera, },
	{"PiB", 1 * binary_per_peta, },
	{"PiB", 1 * binary_per_exa, },
};

static const struct scales binaryscales = {
	.base = 1024,
	.scale = { ARRAY_REF(binaryscale), },
};

static const struct scales binarybytescales = {
	.base = 1024,
	.scale = { ARRAY_REF(binarybytescale), },
};

const struct scale *ttobinaryscale(shunk_t cursor)
{
	return ttoscale(cursor, &binaryscales, 0);
}

const struct scale *ttobinarybytesscale(shunk_t cursor)
{
	return ttoscale(cursor, &binarybytescales, 0);
}
