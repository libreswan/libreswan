/* Output raw bytes, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney
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
 *
 */

#include <stdio.h>
#include <stdarg.h>

#include "lswlog.h"

size_t lswlog_bytes(struct lswlog *buf, const uint8_t *bytes,
		    size_t sizeof_bytes)
{
	if (bytes == NULL) {
		return lswlogs(buf, NULL); /* appends error */
	}

	size_t size = 0;
	const char *sep = "";
	for (size_t byte = 0; byte < sizeof_bytes; byte++) {
		size += lswlogf(buf, "%s%02x", sep, bytes[byte]);
		/*
		 * Roughly mimic DBG_dump(): use a space separator;
		 * and after the 4th byte, a double space separator.
		 *
		 * This is so that values dumped by DBG_dump() and
		 * lswlog_bytes() have the same 'look' - make
		 * searching and grepping easier.
		 */
		sep = (byte % 4 == 3) ? "  " : " ";
	}
	return size;
}
