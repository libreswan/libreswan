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
	/* termination */
	A(buf->total >= buf->roof || buf->array[buf->total] == '\0');
	A(buf->array[buf->roof-1] == '\0');
	A(buf->array[buf->roof-0] == FMTBUF_CANARY);
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
	fmtbuf_debugf("%s(array=%p,sizeof_array=%zu)\n",
		      __func__, array, sizeof_array);
	/* pointers back at buf */
	fmtbuf_t buf = {
		.array = array,
		.total = 0,
		.roof = sizeof_array - 1,
		.dots = "...",
	};
	buf.array[buf.roof-1] = buf.array[buf.total] = '\0';
	buf.array[buf.roof-0] = FMTBUF_CANARY;
	assert_fmtbuf(&buf);
	fmtbuf_debugf("\t->{.array=%p,.total=%zu,.roof=%zu,.dots='%s'}\n",
		      buf.array, buf.total, buf.roof, buf.dots);
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
	/*
	 * Where will the next message be written?
	 */
	struct dest d = {
		.start = NULL,
		.size = 0,
	};
	if (buf->total < buf->roof) {
		d.start = buf->array + buf->total;
		d.size = buf->roof - buf->total;
	} else {
		/* point start somewhere */
		d.start = buf->array + buf->roof - 1;
		d.size = 0;
	}
	passert(d.start[0] == '\0');
	fmtbuf_debugf("%s(buf=%p)->{.start=%p,.size=%zd}\n",
		      __func__, buf, d.start, d.size);
	return d;
}

/*
 * The output needs to be truncated, overwrite the end of the buffer
 * with DOTS.
 */
static void truncate_buf(fmtbuf_t *buf)
{
	fmtbuf_debugf("truncate_buf(.buf=%p)\n", buf);
	fmtbuf_debugf("\tlength=%zu\n", buf->total);
	fmtbuf_debugf("\tdots=%s\n", buf->dots);
	/*
	 * buffer is full to overflowing
	 */
	passert(buf->total >= buf->roof);
	passert(buf->array[buf->roof - 1] == '\0');
	passert(buf->array[buf->roof - 2] != '\0');
	/*
	 * Backfill with DOTS.
	 */
	passert(buf->roof > strlen(buf->dots));
	char *dest = buf->array + buf->roof - strlen(buf->dots) - 1;
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

	buf->total += n;
	if (d.size > n) {
		/*
		 * There is space for all N characters and a trailing
		 * NUL, copy everything over.
		 */
		memcpy(d.start, string, n + 1);
	} else if (d.size > 0) {
		/*
		 * Not enough space, perform a partial copy of the
		 * string ...
		 */
		memcpy(d.start, string, d.size - 1);
		d.start[d.size - 1] = '\0';
		/*
		 * ... and then go back and blat the end with DOTS.
		 */
		truncate_buf(buf);
	}
	return n;
}

size_t fmt_va_list(fmtbuf_t *buf, const char *format, va_list ap)
{
	assert_fmtbuf(buf);
	struct dest d = dest(buf);

	/*
	 * N (the return value) is the number of characters, not
	 * including the trailing NUL, that should have been written
	 * to the buffer.
	 */
	int sn = vsnprintf(d.start, d.size, format, ap);
	if (sn < 0) {
		/*
		 * A negative return value indicates an "output
		 * error", but there is no output so it can't happen
		 * (that or a very old, non-compliant, s*printf()
		 * implementation that returns -1 instead of the
		 * required size).
		 */
		abort();
	}
	size_t n = sn;

	buf->total += n;
	if (d.size > 0 && n >= d.size) {
		/*
		 * There was some space but the entire message didn't
		 * fit - d.size-1 characters were written.  Truncate
		 * the buffer.
		 */
		truncate_buf(buf);
	}
	assert_fmtbuf(buf);
	return n;
}

size_t fmt(fmtbuf_t *buf, const char *format, ...)
{
	/* fmt_va_list does assert */
	va_list ap;
	va_start(ap, format);
	size_t n = fmt_va_list(buf, format, ap);
	va_end(ap);
	return n;
}

size_t fmt_string(fmtbuf_t *buf, const char *string)
{
	assert_fmtbuf(buf);
	size_t n = concat(buf, string);
	assert_fmtbuf(buf);
	return n;
}

size_t fmt_fmtbuf(fmtbuf_t *buf, fmtbuf_t *fmtbuf)
{
	assert_fmtbuf(buf);
	size_t n = concat(buf, fmtbuf->array);
	assert_fmtbuf(buf);
	return n;
}

bool fmtbuf_ok(fmtbuf_t *buf)
{
	assert_fmtbuf(buf);
	return buf->total < buf->roof;
}

chunk_t fmtbuf_as_chunk(fmtbuf_t *buf)
{
	assert_fmtbuf(buf);
	if (buf->total >= buf->roof) {
		return chunk(buf->array, buf->roof);
	} else {
		return chunk(buf->array, buf->total + 1);
	}
}
