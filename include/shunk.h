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
#include <stdint.h>	/* uint8_t uintmax_t */

#include "hunk.h"
#include "err.h"
#include "where.h"

/*
 * Think of shunk_t and chunk_t as opposite solutions to the same
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

extern const shunk_t null_shunk;
extern const shunk_t empty_shunk;

shunk_t shunk1(const char *ptr); /* strlen() implied */
shunk_t shunk2(const void *ptr, size_t len);

#define HUNK_AS_SHUNK(HUNK)			\
	({					\
		typeof(HUNK) *h_ = &(HUNK);	\
		shunk2(h_->ptr, h_->len);	\
	})
#define THING_AS_SHUNK(THING) shunk2(&(THING), sizeof(THING))

/*
 * Split INPUT using DELIM (and shunk_token()) returning an array of
 * shunks POINTING INTO INPUT.
 *
 * To discard blanks and empty fields specify:
 *
 *   delims=", ", opts=EAT_EMPTY_SHUNKS.
 *
 * See also alloc_items() and ITEMS_FOR_EACH().
 */

struct shunks {
	bool kept_empty_shunks;
	unsigned len;
	shunk_t item[];
};

enum shunks_opt {
	KEEP_EMPTY_SHUNKS,
	EAT_EMPTY_SHUNKS,
};

struct shunks *ttoshunks(shunk_t input, const char *delim, enum shunks_opt opt);

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
 *     while (true) {
 *         shunk_t token = shunk_token(&input, &sep, ",");
 *         if (token.ptr == NULL) {
 *             break;
 *         }
 *         ... process token ...
 *     }
 *
 */
shunk_t shunk_token(shunk_t *input, char *delim, const char *delims);

/* only the shunk_t** pointer needs freeing */
shunk_t *clone_shunk_tokens(shunk_t input, const char *delim, where_t here);

/*
 * Return the sequence of characters in ACCEPT, update INPUT.
 *
 * When input is exhausted the NULL_SHUNK is returned (rather than the
 * EMPTY_SHUNK).
 *
 * edge cases (these might change a little):
 *
 * span("", "accept"): returns the token EMPTY_SHUNK and sets input to
 * NULL_SHUNK so the next call returns the NULL_SHUNK.
 *
 * span("a", "accept"): returns the token "a" and sets input to
 * NULL_SHUNK so the next call returns the NULL_SHUNK.
 */
shunk_t shunk_span(shunk_t *input, const char *accept);

/*
 * Number conversion; loosely based on strtoul(START, END, BASE).
 *
 * Parse INPUT according to BASE (see strtoul()). Should the numeric
 * value be missing or invalid, or the value overflow uintmax_t then
 * an error is returned.
 *
 * If CURSOR is NULL, having text following the numeric value is
 * considered an error (strtoul() silently ignores trailing junk when
 * END=NULL).
 *
 * If CURSOR is non-NULL, it is set to the text following the numeric
 * value.
 */
err_t shunk_to_uintmax(shunk_t input, shunk_t *cursor, unsigned base, uintmax_t *value);
err_t shunk_to_intmax(shunk_t input, shunk_t *cursor, unsigned base, intmax_t *value);

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

#define jam_shunk(BUF, SHUNK) jam(BUF, PRI_SHUNK, pri_shunk(SHUNK))

#endif
