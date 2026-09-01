/* enums as names, for libreswan
 *
 * Copyright (C) 2025 Andrew Cagney
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

#include <stdio.h>
#include <string.h>

#include "names.h"
#include "jambuf.h"

void bad_name(unsigned long val, name_buf *b)
{
	snprintf(b->tmp, sizeof(b->tmp), "%lu", val);
	b->buf = b->tmp;
}

size_t jam_bad(struct jambuf *buf, const char *prefix, unsigned long val)
{
	size_t s = 0;
	if (prefix != NULL) {
		s += jam_string(buf, prefix);
		const char c = prefix[strlen(prefix)-1];
		/*
		 * Typically .prefix has a trailing "_", but when it
		 * doesn't add one.
		 */
		if (c != '_' && c != '.') {
			s += jam_string(buf, ".");
		}
	}
	s += jam(buf, "%lu", val);
	return s;
}
