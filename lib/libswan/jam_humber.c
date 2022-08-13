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
 * readable_humber: make large numbers clearer by expressing them
 * as Ki,Mi,Gi,Ti,Pi,Ei and 2^64 will be 16Ei based on
 * https://en.wikipedia.org/wiki/Binary_prefix IEC 60027-2 standard.
 * The prefix and suffix2 are literally copied into the output.
 * e.g. use sufix2 "B" for Bytes.
 */

size_t jam_humber(struct jambuf *buf, uint64_t num)
{
	const char *suffix;
	uint64_t to_print;

	if (num >= binary_per_exa) {
		to_print = num / binary_per_exa;
		suffix = "Ei";
	} else if (num >= binary_per_peta) {
		to_print = num / binary_per_peta;
		suffix = "Pi";
	} else if (num >= binary_per_tera) {
		to_print = num / binary_per_tera;
		suffix = "Ti";
	} else if (num >= binary_per_giga) {
		to_print = num / binary_per_giga;
		suffix = "Gi";
	} else if (num >= binary_per_mega) {
		to_print = num / binary_per_mega;
		suffix = "Mi";
	} else if (num >= binary_per_kilo) {
		to_print = num / binary_per_kilo;
		suffix = "Ki";
	} else {
		to_print = num;
		suffix = "";
	}

	return jam(buf, "%"PRIu64"%s", to_print, suffix);
}
