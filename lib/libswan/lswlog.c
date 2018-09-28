/* expectation failure, for libreswan
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
#include <stdlib.h>

#include "lswlog.h"
#include "lswalloc.h"

/*
 * This is the one place where PASSERT() can't be used - it will
 * recursively end up back here!
 */
static void check_lswbuf(struct lswlog *buf)
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
	A(buf->array[buf->roof] == LSWBUF_CANARY);
#undef A
}

static int lswlog_debugf_nop(const char *format UNUSED, ...)
{
	return 0;
}

int (*lswlog_debugf)(const char *format, ...) = lswlog_debugf_nop;

/*
 * Constructor
 */

struct lswlog *lswlog(struct lswlog *buf, char *array,
		      size_t sizeof_array)
{
	*buf = (struct lswlog) {
		.array = array,
		.len = 0,
		.bound = sizeof_array - 2,
		.roof = sizeof_array - 1,
		.dots = "...",
	};
	buf->array[buf->bound] = buf->array[buf->len] = '\0';
	buf->array[buf->roof] = LSWBUF_CANARY;
	check_lswbuf(buf);
	return buf;
}

/*
 * Determine where, within LOG's message buffer, to write the string.
 */

struct dest {
	char *start;
	size_t size;
};

static struct dest dest(struct lswlog *log)
{
	lswlog_debugf("dest(.log=%p)\n", log);
	lswlog_debugf("\tbbound=%zu\n", log->bound);
	check_lswbuf(log);

	/*
	 * Where will the next message be written?
	 */
	passert(log->bound < log->roof);
	passert(log->len <= log->bound);
	char *start = log->array + log->len;
	lswlog_debugf("\tstart=%p\n", start);
	passert(start < log->array + log->roof);
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
	passert(log->bound < log->roof);
	passert(log->len <= log->bound);
	size_t size = log->bound - log->len;
	lswlog_debugf("\tsize=%zd\n", size);
	passert(log->len + size < log->roof);

	struct dest d = {
		.start = start,
		.size = size,
	};

	lswlog_debugf("\t->{.start=%p,.size=%zd}\n",
		      d.start, d.size);
	return d;
}

/*
 * The output needs to be truncated, overwrite the end of the buffer
 * with DOTS.
 */
static void truncate_buf(struct lswlog *log)
{
	lswlog_debugf("truncate_buf(.log=%p)\n", log);
	lswlog_debugf("\tblen=%zu\n", log->len);
	lswlog_debugf("\tbbound=%zu\n", log->bound);
	lswlog_debugf("\tbdots=%s\n", log->dots);
	check_lswbuf(log);

	/*
	 * Transition from "full" to overfull (truncated).
	 */
	passert(log->len == log->bound - 1);
	log->len = log->bound;

	/*
	 * Backfill with DOTS.
	 */
	passert(log->bound < log->roof);
	passert(log->bound >= strlen(log->dots));
	char *dest = log->array + log->bound - strlen(log->dots);
	lswlog_debugf("\tdest=%p\n", dest);
	memcpy(dest, log->dots, strlen(log->dots) + 1);
}

/*
 * Try to append output to BUF.  Either copy the raw string or
 * VPRINTF.
 */

static size_t concat(struct lswlog *log, const char *string)
{
	/* Just in case a NULL ends up here */
	if (string == NULL) {
		string = "(null)";
	}

	struct dest d = dest(log);

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
		log->len += n;
	} else if (d.size > 0) {
		/*
		 * Not enough space, perform a partial copy of the
		 * string ...
		 */
		memcpy(d.start, string, d.size - 1);
		d.start[d.size - 1] = '\0';
		log->len += d.size - 1;
		passert(log->len == log->bound - 1);
		/*
		 * ... and then go back and blat the end with DOTS.
		 */
		truncate_buf(log);
	}
	/* already overflowed */

	check_lswbuf(log);
	return n;
}

static size_t append(struct lswlog *log, const char *format, va_list ap)
{
	struct dest d = dest(log);

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
		return log->roof;
	}
	size_t n = sn;

	if (d.size > n) {
		/*
		 * Everything, including the trailing NUL, fitted.
		 * Update the length.
		 */
		log->len += n;
	} else if (d.size > 0) {
		/*
		 * The message didn't fit so only d.size-1 characters
		 * of the message were written.  Update things ...
		 */
		log->len += d.size - 1;
		passert(log->len == log->bound - 1);
		/*
		 * ... and then mark the buffer as truncated.
		 */
		truncate_buf(log);
	}
	/* already overflowed */

	check_lswbuf(log);
	return n;
}

size_t lswlogvf(struct lswlog *log, const char *format, va_list ap)
{
	return append(log, format, ap);
}

size_t lswlogf(struct lswlog *log, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	size_t n = append(log, format, ap);
	va_end(ap);
	return n;
}

size_t lswlogs(struct lswlog *log, const char *string)
{
	return concat(log, string);
}

size_t lswlogl(struct lswlog *log, struct lswlog *buf)
{
	return concat(log, buf->array);
}
