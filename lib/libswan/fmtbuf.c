/* string format buffer, for libreswan
 *
 * Copyright (C) 2017-2019 Andrew Cagney
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
#include <stdlib.h>

#include "fmtbuf.h"
#include "lswalloc.h"
#include "lswlog.h"		/* for passert() */

/*
 * Since 'char' can be unsigned need to cast -2 onto a char sized
 * value.
 *
 * The octal equivalent would be something like '\376' but who uses
 * octal :-)
 */
#define FMTBUF_CANARY ((char) -2)

/*
 * This is the one place where PASSERT() can't be used - it will
 * recursively end up back here!
 */
static void assert_fmtbuf(fmtbuf_t *buf)
{
#define A(ASSERTION) if (!(ASSERTION)) abort()
	A(buf->dots != NULL);
	/* LEN/BOUND well defined */
	A(buf->len <= buf->bound);
	A(buf->bound < buf->roof);
	/* always NUL terminated */
	A(buf->array[buf->len] == '\0');
	A(buf->array[buf->bound] == '\0');
	/* overflow? */
	A(buf->array[buf->roof] == FMTBUF_CANARY);
#undef A
}

static int fmtbuf_debugf_nop(const char *format UNUSED, ...)
{
	return 0;
}

int (*fmtbuf_debugf)(const char *format, ...) = fmtbuf_debugf_nop;

/*
 * Constructor
 */

fmtbuf_t array_as_fmtbuf(char *array, size_t sizeof_array)
{
	/* pointers back at buf */
	fmtbuf_t buf = {
		.array = array,
		.len = 0,
		.bound = sizeof_array - 2,
		.roof = sizeof_array - 1,
		.dots = "...",
	};
	buf.array[buf.bound] = buf.array[buf.len] = '\0';
	buf.array[buf.roof] = FMTBUF_CANARY;
	assert_fmtbuf(&buf);
	return buf;
}

/*
 * Determine where, within LOG's message buffer, to write the string.
 */

struct dest {
	char *start;
	size_t size;
};

static struct dest dest(fmtbuf_t *buf)
{
	fmtbuf_debugf("dest(.buf=%p)\n", buf);
	fmtbuf_debugf("\tbbound=%zu\n", buf->bound);
	assert_fmtbuf(buf);

	/*
	 * Where will the next message be written?
	 */
	passert(buf->bound < buf->roof);
	passert(buf->len <= buf->bound);
	char *start = buf->array + buf->len;
	fmtbuf_debugf("\tstart=%p\n", start);
	passert(start < buf->array + buf->roof);
	passert(start[0] == '\0');

	/*
	 * How much space remains?
	 *
	 * If the buffer is full (LEN==BOUND-1) then size=1 - a string
	 * of length 0 (but size 1 - the NUL) will still fit.
	 *
	 * If the buffer has overflowed (LEN==BOUND) (output has
	 * already been truncated) then size=0.
	 */
	passert(buf->bound < buf->roof);
	passert(buf->len <= buf->bound);
	size_t size = buf->bound - buf->len;
	fmtbuf_debugf("\tsize=%zd\n", size);
	passert(buf->len + size < buf->roof);

	struct dest d = {
		.start = start,
		.size = size,
	};

	fmtbuf_debugf("\t->{.start=%p,.size=%zd}\n",
		      d.start, d.size);
	return d;
}

/*
 * The output needs to be truncated, overwrite the end of the buffer
 * with DOTS.
 */
static void truncate_buf(fmtbuf_t *buf)
{
	fmtbuf_debugf("truncate_buf(.buf=%p)\n", buf);
	fmtbuf_debugf("\tblen=%zu\n", buf->len);
	fmtbuf_debugf("\tbbound=%zu\n", buf->bound);
	fmtbuf_debugf("\tbdots=%s\n", buf->dots);
	assert_fmtbuf(buf);

	/*
	 * Transition from "full" to overfull (truncated).
	 */
	passert(buf->len == buf->bound - 1);
	buf->len = buf->bound;

	/*
	 * Backfill with DOTS.
	 */
	passert(buf->bound < buf->roof);
	passert(buf->bound >= strlen(buf->dots));
	char *dest = buf->array + buf->bound - strlen(buf->dots);
	fmtbuf_debugf("\tdest=%p\n", dest);
	memcpy(dest, buf->dots, strlen(buf->dots) + 1);
}

/*
 * Try to append output to BUF.  Either copy the raw string or
 * VPRINTF.
 */

static size_t concat(fmtbuf_t *buf, const char *string)
{
	/* Just in case a NULL ends up here */
	if (string == NULL) {
		string = "(null)";
	}

	struct dest d = dest(buf);

	/*
	 * N (the return value) is the number of characters, not
	 * including the trailing NUL, that should have been written
	 * to the buffer.
	 */
	size_t n = strlen(string);

	if (d.size > n) {
		/*
		 * There is space for all N characters and a trailing
		 * NUL, copy everything over.
		 */
		memcpy(d.start, string, n + 1);
		buf->len += n;
	} else if (d.size > 0) {
		/*
		 * Not enough space, perform a partial copy of the
		 * string ...
		 */
		memcpy(d.start, string, d.size - 1);
		d.start[d.size - 1] = '\0';
		buf->len += d.size - 1;
		passert(buf->len == buf->bound - 1);
		/*
		 * ... and then go back and blat the end with DOTS.
		 */
		truncate_buf(buf);
	}
	/* already overflowed */

	assert_fmtbuf(buf);
	return n;
}

size_t fmt_va_list(fmtbuf_t *buf, const char *format, va_list ap)
{
	struct dest d = dest(buf);

	/*
	 * N (the return value) is the number of characters, not not
	 * including the trailing NUL, that should have been written
	 * to the buffer.
	 *
	 * If N is negative than an "output error" (will that happen?)
	 * occurred (that or a very old, non-compliant, s*printf()
	 * implementation that returns -1 instead of the required
	 * size).
	 */
	int sn = vsnprintf(d.start, d.size, format, ap);
	if (sn < 0) {
		/*
		 * Return something "HUGE" so callers can assume all
		 * values are unsigned.
		 *
		 * Calling PEXPECT_LOG() here is recursive; is this a
		 * problem? (if it is then we hope things crash).
		 */
		PEXPECT_LOG("vsnprintf() unexpectedly returned the -ve value %d", sn);
		return buf->roof;
	}
	size_t n = sn;

	if (d.size > n) {
		/*
		 * Everything, including the trailing NUL, fitted.
		 * Update the length.
		 */
		buf->len += n;
	} else if (d.size > 0) {
		/*
		 * The message didn't fit so only d.size-1 characters
		 * of the message were written.  Update things ...
		 */
		buf->len += d.size - 1;
		passert(buf->len == buf->bound - 1);
		/*
		 * ... and then mark the buffer as truncated.
		 */
		truncate_buf(buf);
	}
	/* already overflowed */

	assert_fmtbuf(buf);
	return n;
}

size_t fmt(fmtbuf_t *buf, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	size_t n = fmt_va_list(buf, format, ap);
	va_end(ap);
	return n;
}

size_t fmt_string(fmtbuf_t *buf, const char *string)
{
	return concat(buf, string);
}

size_t fmt_fmtbuf(fmtbuf_t *buf, fmtbuf_t *fmtbuf)
{
	return concat(buf, fmtbuf->array);
}

bool fmtbuf_ok(fmtbuf_t *buf)
{
	struct dest d = dest(buf);
	return d.size > 0; /* no overflow */
}
