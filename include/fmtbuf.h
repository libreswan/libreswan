/* string format buffer, for libreswan
 *
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
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

#ifndef FMTBUF_H
#define FMTBUF_H

#include <stdbool.h>
#include <stdarg.h>		/* for va_list */
#include <stdint.h>		/* for uint8_t */
#include <stddef.h>		/* for size_t */

#include "lswcdefs.h"		/* for PRINTF_LIKE */
#include "chunk.h"

/*
 * fmtbuf_t provides a mechanism for accumulating formatted strings
 * into a string buffer, vis:
 *
 *    fmtbuf_t buf = ...() -- see below
 *    if (string != NULL)
 *      fmt(&buf, " string: %s", string);
 *    if (i > 100)
 *      fmt(&buf, " large i: %d", i);
 *
 * Should there be too much output then it is truncated (leaving
 * "...").
 */

/*
 * The format buffer:
 *
 * ARRAY, a previously allocated array, containing the accumulated
 * NUL-terminated + CANARY-terminated output.
 *
 * ROOF:
 *
 * The offset of the the last character in the array.  It contains a
 * canary intended to catch overflows.  When sizeof(ARRAY) is needed,
 * ROOF should be used as otherwise the canary may be corrupted.
 *
 *   ROOF < sizeof(ARRAY)
 *   ARRAY[ROOF-0] = CANARY
 *   ARRAY[ROOF-1] == '\0'
 *
 * TOTAL:
 *
 * The number of characters that should have been written to the
 * ARRAY.
 *
 * When TOTAL<ROOF it is also strlen(ARRAY) and the index of the next
 * location vis:
 *
 *   TOTAL < ROOF => ARRAY[TOTAL] == '\0'
 *
 * When TOTAL>=ROOF, overflow has occured and no futher characters are
 * written.
 *
 * When TOTAL==ROOF-1 the buffer is full.  Technically there is still
 * space for a string of length 0.  However any larger string will
 * trigger the overflow code and the last few characters will be
 * overwritten with DOTS.
 */

typedef struct lswlog {
	char *array;
	size_t total;
	size_t roof;
	const char *dots;
} fmtbuf_t;

bool fmtbuf_ok(fmtbuf_t *buf);

/*
 * Wrap a character array up in a fmtbuf_t so that it can be used to
 * accumulate strings.  Simplify the common use:
 *
 * typedef struct { char buf[SIZE]; } TYPE_buf;
 * const char *str_TYPE(TYPE_t *t, TYPE_buf *out) {
 *   fmtbuf_t buf = ARRAY_AS_FMTBUF(out->buf);
 *   fmt_...(&buf, ...);
 *   return out->buf;
 * }
 */

fmtbuf_t array_as_fmtbuf(char *array, size_t sizeof_array);
#define ARRAY_AS_FMTBUF(ARRAY) array_as_fmtbuf((ARRAY), sizeof(ARRAY));
/* includes '\0' */
chunk_t fmtbuf_as_chunk(fmtbuf_t *buf);

/*
 * Routines for accumulating output in the fmtbuf buffer.
 *
 * If there is insufficient space, the output is truncated and "..."
 * is appended.
 *
 * Similar to C99 snprintf() et.al., these functions return the
 * untruncated size of output that the call would append (the value
 * can never be negative).
 *
 * While probably not directly useful, it provides a sink for code
 * that needs to consume an otherwise ignored return value (the
 * compiler attribute warn_unused_result can't be suppressed using a
 * (void) cast).
 */

size_t fmt(fmtbuf_t *buf, const char *format, ...) PRINTF_LIKE(2);
size_t fmt_string(fmtbuf_t *buf, const char *string);
size_t fmt_fmtbuf(fmtbuf_t *buf, fmtbuf_t *in);

size_t fmt_va_list(fmtbuf_t *buf, const char *format, va_list ap);

/* _(in FUNC() at FILE:LINE) */
size_t fmt_source_line(fmtbuf_t *buf, const char *func,
			  const char *file, unsigned long line);
/* <string without binary characters> */
size_t fmt_sanitized(fmtbuf_t *buf, const char *string);
/* _Errno E: <strerror(E)> */
size_t fmt_errno(fmtbuf_t *buf, int e);
/* <hex-byte>:<hex-byte>... */
size_t fmt_bytes(fmtbuf_t *buf, const uint8_t *bytes,
		 size_t sizeof_bytes);

/*
 * Code wrappers that cover up the details of allocating,
 * initializing, de-allocating (and possibly logging) a 'struct
 * fmtbuf' buffer.
 *
 * BUF (a C variable name) is declared locally as a pointer to a
 * per-thread 'struct fmtbuf' buffer.
 *
 * Implementation notes:
 *
 * This implementation stores the output in an array on the thread's
 * stack.  It could just as easily use the heap (but that would
 * involve memory overheads) or even a per-thread static variable.
 * Since the BUF variable is a pointer the specifics of the
 * implementation are hidden.
 *
 * This implementation, unlike DBG(), does not have a code block
 * parameter.  Instead it uses a sequence of for-loops to set things
 * up for a code block.  This avoids problems with "," within macro
 * parameters confusing the parser.  It also permits a simple
 * consistent indentation style.
 *
 * The stack array is left largely uninitialized (just a few strategic
 * entries are set).  This avoids the need to zero LOG_WITH bytes.
 *
 * Apparently chaining void function calls using a comma is valid C?
 */

/*
 * To debug, set this to printf or similar.
 */
extern int (*fmtbuf_debugf)(const char *format, ...) PRINTF_LIKE(1);

#endif
