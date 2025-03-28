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

#ifndef NAMES_H
#define NAMES_H

struct jambuf;

typedef struct name_buf {
	const char *buf;
	char tmp[((sizeof(unsigned long) * 241 + 99) / 100)*2 + sizeof("_??")];
} name_buf;

/*
 * Used by KEYWORD lookup code to report renames et.al.
 *
 * It's assumed names are small and the upper bits can be used as
 * flags.  It's also assumed that enums are >=32-bit.
 */
enum name_flags {
	NAME_IMPLEMENTED_AS = (1<<30),
	NAME_RENAMED_TO,
#define NAME_FLAGS (0x3 <<30)
};

void bad_name(unsigned long val, name_buf *b);
size_t jam_bad(struct jambuf *buf, const char *prefix, unsigned long val);

#endif
