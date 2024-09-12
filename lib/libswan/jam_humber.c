/* routines for state objects, for libreswan
 *
 * Copyright (C) 2022 Antony Antony <antony@phenome.org>
 * Copyright (C) 2022 Andrew Cagney
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

#include "constants.h"
#include "jambuf.h"

/*
 * Make large numbers clearer by expressing them as Ki,Mi,Gi,Ti,Pi,Ei
 * and 2^64 will be 16Ei based on
 *
 * https://en.wikipedia.org/wiki/Binary_prefix IEC 60027-2 standard.
 */

size_t jam_humber(struct jambuf *buf, uintmax_t num)
{
	/* in assending order */
	static const struct {
		uintmax_t binary_per;
		const char *suffix;
	} map[] = {
		{
			.binary_per = binary_per_exa,
			.suffix = "Ei",
		},
		{
			.binary_per = binary_per_peta,
			.suffix = "Pi",
		},
		{
			.binary_per = binary_per_tera,
			.suffix = "Ti",
		},
		{
			.binary_per = binary_per_giga,
			.suffix = "Gi",
		},
		{
			.binary_per = binary_per_mega,
			.suffix = "Mi",
		},
		{
			.binary_per = binary_per_kilo,
			.suffix = "Ki",
		},
	};

	const char *suffix = "";
	uint64_t to_print = num;
	FOR_EACH_ELEMENT(m, map) {
		if (num > m->binary_per) {
			to_print = num / m->binary_per;
			suffix = m->suffix;
			break;
		}
	}

	/* fractions? */
	return jam(buf, "%ju%s", to_print, suffix);
}

const char *str_humber(uintmax_t num, humber_buf *buf)
{
	struct jambuf jb = ARRAY_AS_JAMBUF(buf->buf);
	jam_humber(&jb, num);
	return buf->buf;
}
