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
#include <stdint.h>	/* uint8_t */

/*
 * Think of shunk_t and shunk_t as opposite solutions to the same
 * problem - carving up streams of octets:
 *
 * shunk_t's buffer is constant making it good for manipulating static
 * constant data (such as "a string"), chunk_t's is not.
 */

struct shunk {
	const void *ptr;
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
extern const shunk_t empty_shunk;

shunk_t shunk1(const char *ptr); /* strlen() implied */
shunk_t shunk2(const void *ptr, int len);

#define THING_AS_SHUNK(THING) shunk2(&(THING), sizeof(THING))

/* shunk[START..END) */
shunk_t shunk_slice(shunk_t s, size_t start, size_t stop);

/*
 * A shunk version of strsep() / strtok(): split off from INPUT a
 * possibly empty TOKEN containing characters not found in DELIMS and
 * the delimiting character (or NUL).
 *
 * Return the TOKEN (or the NULL_TOKEN if INPUT is exhausted); if
 * DELIM is non-NULL, set *DELIM to the delimiting character or NUL;
 * and update *INPUT.
 *
 * For the final token, *DELIM is set to NUL, and INPUT is marked as
 * being exhausted by setting it to the NULL_SHUNK.
 *
 * When called with exhausted INPUT (aka the NULL_SHUNK), the
 * NULL_SHUNK is returned as the token and *DELIM is set to NUL.
 *
 * One way to implement a simple parser is to use TOKEN.ptr==NULL as
 * an end-of-input indicator:
 *
 *     char sep;
 *     shunk_t token = shunk_token(&input, &sep, ",");
 *     while (token.ptr != NULL) {
 *       ... process token ...
 *       token = shunk_token(&input, &sep, ",");
 *     }
 *
 */
shunk_t shunk_token(shunk_t *input, char *delim, const char *delims);

/*
 * shunk version of string compare functions (or at least libreswan's
 * versions).
 *
 * (Confusingly and just like POSIX, *case* ignores case).
 *
 * Just like a NULL and EMPTY ("") string, a NULL (uninitialized) and
 * EMPTY (pointing somewhere but no bytes) shunks are considered
 * different.
 */
bool shunk_caseeq(shunk_t lhs, shunk_t rhs);
bool shunk_strcaseeq(shunk_t shunk, const char *string);

bool shunk_eq(shunk_t l, shunk_t r);
bool shunk_memeq(shunk_t l, const void *r, size_t sizeof_r);
#define shunk_thingeq(SHUNK, THING) shunk_memeq(SHUNK, &(THING), sizeof(THING))

bool shunk_caseeat(shunk_t *lhs, shunk_t rhs);
bool shunk_strcaseeat(shunk_t *lhs, const char *string);

bool shunk_isdigit(shunk_t s, size_t offset);
bool shunk_ischar(shunk_t s, size_t offset, const char *chars);

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
#define pri_shunk(SHUNK) ((int) (SHUNK).len), (const char *) ((SHUNK).ptr)

#endif
