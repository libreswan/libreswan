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

const struct binaryscale bin_default = {"", .b = 1, };
const struct binaryscale bin_kilo = {"Ki", .b = 1 * binary_per_kilo, };
const struct binaryscale bin_mega = {"Mi", .b = 1 * binary_per_mega, };
const struct binaryscale bin_giga = {"Gi", .b = 1 * binary_per_giga, };
const struct binaryscale bin_tera = {"Ti", .b = 1 * binary_per_tera, };
const struct binaryscale bin_peta = {"Pi", .b = 1 * binary_per_peta, };
const struct binaryscale bin_exa = {"Ei", .b = 1 * binary_per_exa, };

const struct binaryscale bin_bytedefult = {"", .b = 1};
const struct binaryscale bin_kilobytes = {"KiB", .b = 1 * binary_per_kilo, };
const struct binaryscale bin_megabytes = {"MiB", .b = 1 * binary_per_mega, };
const struct binaryscale bin_gigabytes = {"GiB", .b = 1 * binary_per_giga, };
const struct binaryscale bin_terabytes = {"TiB", .b = 1 * binary_per_tera, };
const struct binaryscale bin_petabytes = {"PiB", .b = 1 * binary_per_peta, };
const struct binaryscale bin_exabytes = {"PiB", .b = 1 * binary_per_exa, };

static const struct binaryscale *binaryscales[] = {
	&bin_kilo,
	&bin_mega,
	&bin_giga,
	&bin_tera,
	&bin_peta,
	&bin_exa,
};

static const struct binaryscale *binarybytesscales[] = {
	&bin_kilobytes,
	&bin_megabytes,
	&bin_gigabytes,
	&bin_terabytes,
	&bin_petabytes,
	&bin_exabytes,
};

const struct binaryscale *ttobinaryscale(shunk_t cursor)
{
	if (cursor.len == 0)
		return &bin_default; /* default scaling */

	FOR_EACH_ELEMENT(scale, binaryscales) {
		if (hunk_strcaseeq(cursor, (*scale)->suffix))
			return *scale;
	}

	return NULL;
}

const struct binaryscale *ttobinarybytesscale(shunk_t cursor)
{
	if (cursor.len == 0)
		return  &bin_bytedefult; /* default scaling */

	FOR_EACH_ELEMENT(scale, binarybytesscales) {
		if (hunk_strcaseeq(cursor, (*scale)->suffix))
			return *scale;
	}

	return NULL;
}
