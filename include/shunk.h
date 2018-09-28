/*
 * string fragments, for libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
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

#ifndef SHUNK_H
#define SHUNK_H

#include <stdbool.h>
#include <stddef.h>	/* size_t */

/*
 * shunk_t is a rip of of chunk_t, but with a character pointer.  It
 * is intended for string slicing.
 */

struct shunk {
	const char *ptr;
	size_t len;
};

typedef struct shunk shunk_t;

extern const shunk_t empty_shunk;

shunk_t shunk1(const char *ptr); /* strlen() implied */
shunk_t shunk2(const char *ptr, int len);

/*
 * shunk version of strsep() (which is like strtok())
 *
 * Split SHUNK in two using the DELIM set.  Return a shunk of the
 * characters up to but not including DELIM (or the entire string if
 * DELIM isn't found.  Update SHUNK to be one past DELIM.
 *
 * XXX: should this return the DELIM?
 */
shunk_t shunk_strsep(shunk_t *shunk, const char *delim);

/*
 * shunk version of string compare functions (or at least libreswan's
 * versions).
 */
bool shunk_caseeq(shunk_t lhs, shunk_t rhs);
bool shunk_strcaseeq(shunk_t shunk, const char *string);

bool shunk_caseeat(shunk_t *lhs, shunk_t rhs);
bool shunk_strcaseeat(shunk_t *lhs, const char *string);

/*
 * Number conversion.  like strtoul() et.al.
 */
bool shunk_tou(shunk_t lhs, unsigned *value, int base);

/*
 * To print, use: printf(PRI_SHUNK, pri_shunk(shunk));
 *
 * XXX: I suspect ISO-C reserves the PRIabc (no underscore) name
 * space, so throw in an underscore so that it is clear that this has
 * nothing to do with ISO-C.  While the name PRI_shunk() is tacky, it
 * does have some upper case letters (all macros shall be upper case,
 * right?).
 */

#define PRI_SHUNK "%.*s"
#define PRI_shunk(SHUNK) ((int) (SHUNK).len), ((SHUNK).ptr)

#endif
