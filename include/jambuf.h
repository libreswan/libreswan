/* buffer for jamming strings into, for libreswan
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

#ifndef JAMBUF_H
#define JAMBUF_H

#include <stdbool.h>
#include <stdarg.h>		/* for va_list */
#include <stdint.h>		/* for uint8_t */
#include <stddef.h>		/* for size_t */

#include "lswcdefs.h"		/* for PRINTF_LIKE */
#include "shunk.h"

#define LOG_WIDTH	((size_t)1024)	/* roof of number of chars in log line */

/*
 * struct jambuf provides a mechanism for accumulating formatted
 * strings into a string buffer, vis:
 *
 *    struct jambuf buf = ...() -- see below
 *    if (string != NULL)
 *      jam(&buf, " string: %s", string);
 *    if (i > 100)
 *      jam(&buf, " large i: %d", i);
 *
 * Should there be too much output then it is truncated (leaving
 * "...").
 */

/*
 * The jam buffer:
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
 * When TOTAL>=ROOF, overflow has occurred and no further characters are
 * written.
 *
 * When TOTAL==ROOF-1 the buffer is full.  Technically there is still
 * space for a string of length 0.  However any larger string will
 * trigger the overflow code and the last few characters will be
 * overwritten with DOTS.
 */

struct jambuf {
	char *array;
	size_t total;
	size_t roof;
	const char *dots;
};

bool jambuf_ok(struct jambuf *buf);

/*
 * Wrap a character array up in a struct jambuf so that it can be used to
 * accumulate strings.  Simplify the common use:
 *
 * typedef struct { char buf[SIZE]; } TYPE_buf;
 * const char *str_TYPE(TYPE_t *t, TYPE_buf *out) {
 *   struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
 *   jam_...(&buf, ...);
 *   return out->buf;
 * }
 */

struct jambuf array_as_jambuf(char *array, size_t sizeof_array);
#define ARRAY_AS_JAMBUF(ARRAY) array_as_jambuf((ARRAY), sizeof(ARRAY))

/* primitive to construct a JAMBUF on the stack. */
#define JAMBUF(BUF)							\
	/* create the buffer */						\
	for (char lswbuf[LOG_WIDTH], *lswbuf_ = lswbuf;			\
	     lswbuf_ != NULL; lswbuf_ = NULL)				\
		/* create the jambuf */					\
		for (struct jambuf jambuf = ARRAY_AS_JAMBUF(lswbuf),	\
			     *BUF = &jambuf;				\
		     BUF != NULL; BUF = NULL)

/*
 * Assuming the jambuf is an array, poke around in the jambuf's
 * internal buffer.
 *
 * _as_shunk() returns the buffer contents (not including the trailing
 * '\0') so is useful for calls like fwrite().
 *
 * _cursor() returns the current cursor position (where the next
 * string will be jammed); *cursor is always '\0'.
 */

shunk_t jambuf_as_shunk(struct jambuf *buf);
const char *jambuf_cursor(struct jambuf *buf);

/*
 * Assuming the jambuf is an array, save/restore the 'cursor'.
 *
 * See x509 code, where part way through scribbing all over the buf it
 * detects and error and throws everything away.
 */

typedef struct { size_t total; } jampos_t;
jampos_t jambuf_get_pos(struct jambuf *buf);
void jambuf_set_pos(struct jambuf *buf, const jampos_t *pos);

/*
 * Routines for accumulating output in the jambuf buffer.
 *
 * If there is insufficient space, the output is truncated and "..."
 * is appended.
 *
 * Similar to C99 snprintf() et.al., these functions return the
 * untruncated size of output that the call would append (the value
 * can never be negative).
 *
 * While typically not useful, the return value does get used when
 * trying to pretty-print a table of values.
 */

size_t jam_va_list(struct jambuf *buf, const char *format, va_list ap) VPRINTF_LIKE(2);
size_t jam_raw_bytes(struct jambuf *buf, const void *bytes, size_t nr_bytes);

size_t jam(struct jambuf *buf, const char *format, ...) PRINTF_LIKE(2);

size_t jam_bool(struct jambuf *buf, bool b);
size_t jam_char(struct jambuf *buf, char c);
size_t jam_string(struct jambuf *buf, const char *string);
size_t jam_jambuf(struct jambuf *buf, struct jambuf *in);


/*
 * Jam a string of bytes formatted in some way.
 */

typedef size_t (jam_bytes_fn)(struct jambuf *buf, const void *bytes, size_t size);

/*
 * bytes as hex ...
 */

/* upper case hex - B1B2... */
jam_bytes_fn jam_HEX_bytes;
#define jam_HEX_hunk(BUF, HUNK)						\
	({								\
		typeof(HUNK) hunk_ = (HUNK); /* evaluate once */	\
		jam_HEX_bytes(BUF, hunk_.ptr, hunk_.len);		\
	})

/* lower case hex - b1b2... */
jam_bytes_fn jam_hex_bytes;
#define jam_hex_hunk(BUF, HUNK)						\
	({								\
		typeof(HUNK) hunk_ = (HUNK); /* evaluate once */	\
		jam_hex_bytes(BUF, hunk_.ptr, hunk_.len);		\
	})

/* hex bytes - b1 b2 b3 b4  b6 b6 b7 b8 - like DBG_dump */
jam_bytes_fn jam_dump_bytes;
#define jam_dump_hunk(BUF, HUNK)					\
	({								\
		typeof(HUNK) hunk_ = (HUNK); /* evaluate once */	\
		jam_dump_bytes(BUF, hunk_.ptr, hunk_.len);		\
	})

/*
 * bytes as base64 ...
 */

jam_bytes_fn jam_base64_bytes;
#define jam_base64_hunk(BUF, HUNK)					\
	({								\
		typeof(HUNK) hunk_ = (HUNK); /* evaluate once */	\
		jam_base64_bytes(BUF, hunk_.ptr, hunk_.len);		\
	})

/*
 * bytes as a string.
 */

/* (isprint(b1) ? \NNN : b1)... */
jam_bytes_fn jam_sanitized_bytes;
#define jam_sanitized_hunk(BUF, HUNK)					\
	({								\
		typeof(HUNK) hunk_ = (HUNK); /* evaluate once */	\
		jam_sanitized_bytes(BUF, hunk_.ptr, hunk_.len);		\
	})

/* (ismeta(b1)) ? \NNN : b1)... (i.e., escaped for shell within quotes) */
jam_bytes_fn jam_shell_quoted_bytes;
#define jam_shell_quoted_hunk(BUF, HUNK)				\
	({								\
		typeof(HUNK) hunk_ = (HUNK); /* evaluate once */	\
		jam_shell_quoted_bytes(BUF, hunk_.ptr, hunk_.len);	\
	})

/* convert lowercase to uppercase, i.e., [a-z] [A-Z] */

jam_bytes_fn jam_uppercase_bytes;
size_t jam_string_uppercase(struct jambuf *buf, const char *string);

/* convert [_A-Z] to [-a-z]; see jam_enum_human() */

jam_bytes_fn jam_human_bytes;
size_t jam_string_human(struct jambuf *buf, const char *string);

/*
 * jam_humber():
 *
 * Make large numbers clearer by expressing them as Ki, Mi, Gi, Ti,
 * Pi, Ei and 2^64 will be 16Ei based on
 * https://en.wikipedia.org/wiki/Binary_prefix IEC 60027-2 standard.
 * The prefix and suffix2 are literally copied into the output.
 * e.g. use sufix2 "B" for Bytes.
 */

typedef struct {
	/* lets say 3 decimal digits per byte which is way over */
	char buf[sizeof(uintmax_t)*3 + 2/*Gi*/ + 1/*NUL*/ + 1/*CANARY*/];
}  humber_buf;

size_t jam_humber(struct jambuf *buf, uintmax_t num);
const char *str_humber(uintmax_t num, humber_buf *b);

/*
 * Code wrappers that cover up the details of allocating,
 * initializing, de-allocating (and possibly logging) a 'struct
 * jambuf' buffer.
 *
 * BUF (a C variable name) is declared locally as a pointer to a
 * per-thread 'struct jambuf' buffer.
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
extern int (*jambuf_debugf)(const char *format, ...) PRINTF_LIKE(1);

/* <strerror(ERROR)> (errno ERROR) */
size_t jam_errno(struct jambuf *buf, int error);

#endif
