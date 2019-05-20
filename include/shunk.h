/* constant string (octet) fragments, for libreswan
 *
 * Copyright (C) 2018-2019 Andrew Cagney <cagney@gnu.org>
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
 * Think of shunk_t and shunk_t as opposite solutions to the same
 * problem - carving up streams of octets:
 *
 * shunk_t's buffer is constant making it good for manipulating static
 * constant data (such as "a string"), chunk_t's is not.
 *
 * shunk_t's buffer is of type 'char' (which may or may not be signed)
 * making it easier to manipulate strings, chunk_t's is uint8_t making
 * it easier to manipulate raw bytes.
 */

struct shunk {
	const char *ptr;
	size_t len;
};

typedef struct shunk shunk_t;

/*
 * Just like for strings, an empty or zero length shunk such as
 * {.ptr="",.len = 0} should not be confused with the NULL shunk
 * (i.e., {.ptr=NULL,.len=0}).
 *
 * Use 'null_shunk' in initialisers.  The only exception is static
 * initializers - which will get a compiler error - and NULL_SHUNK can
 * be used.
 */

#define NULL_SHUNK { .ptr = NULL, .len = 0, }
extern const shunk_t null_shunk;

shunk_t shunk1(const char *ptr); /* strlen() implied */
shunk_t shunk2(const char *ptr, int len);

/*
 * A shunk version of strsep() (which is like strtok()) - split INPUT
 * in two using a character from the DELIM set.
 *
 * If INPUT contains a character from the DELIM set, return the
 * characters before the DELIM character as the next TOKEN, and set
 * INPUT to the sub-string following the DELIM character.
 *
 * If INPUT contains no character from the DELIM set, return INPUT as
 * the next TOKEN (possibly empty), and set INPUT to the null_shunk.
 *
 * If INPUT is the null_shunk, return the null_shunk as the next
 * TOKEN, string remains unchanged (still the null_shunk).
 *
 * One way to implement a simple parser is to use TOKEN.ptr==NULL as
 * an end-of-input indicator:
 *
 *     shunk_t token = shunk_strsep(&input, ",");
 *     while (token.ptr != NULL) {
 *       ... process token ...
 *       token = shunk_strsep(&input, ",");
 *     }
 *
 * XXX: Provided INPUT.ptr is non-NULL, INPUT.ptr[-1] is the DELIM
 * character; should this be made an explict parameter.
 */
shunk_t shunk_strsep(shunk_t *input, const char *delim);

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
