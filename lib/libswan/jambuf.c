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

#include "jambuf.h"
#include "lswalloc.h"
#include "lswlog.h"		/* for passert() */

/*
 * Since 'char' can be unsigned need to cast -2 onto a char sized
 * value.
 *
 * The octal equivalent would be something like '\376' but who uses
 * octal :-)
 */
#define JAMBUF_CANARY ((char) -2)

/*
 * This is the one place where PASSERT() can't be used - it will
 * recursively end up back here!
 */
static void assert_jambuf(jambuf_t *buf)
{
#define A(ASSERTION) if (!(ASSERTION)) abort()
	A(buf->dots != NULL);
	/* termination */
	A(buf->total >= buf->roof || buf->array[buf->total] == '\0');
	A(buf->array[buf->roof-1] == '\0');
	A(buf->array[buf->roof-0] == JAMBUF_CANARY);
#undef A
}

static int jambuf_debugf_nop(const char *format UNUSED, ...)
{
	return 0;
}

int (*jambuf_debugf)(const char *format, ...) = jambuf_debugf_nop;

/*
 * Constructor
 */

jambuf_t array_as_jambuf(char *array, size_t sizeof_array)
{
	jambuf_debugf("%s(array=%p,sizeof_array=%zu)\n",
		      __func__, array, sizeof_array);
	/* pointers back at buf */
	jambuf_t buf = {
		.array = array,
		.total = 0,
		.roof = sizeof_array - 1,
		.dots = "...",
	};
	buf.array[buf.roof-1] = buf.array[buf.total] = '\0';
	buf.array[buf.roof-0] = JAMBUF_CANARY;
	assert_jambuf(&buf);
	jambuf_debugf("\t->{.array=%p,.total=%zu,.roof=%zu,.dots='%s'}\n",
		      buf.array, buf.total, buf.roof, buf.dots);
	return buf;
}

/*
 * Determine where, within LOG's message buffer, to write the string.
 */

struct dest {
	/* next character position (always points at '\0') */
	char *cursor;
	/* free space */
	size_t size;
};

static struct dest dest(jambuf_t *buf)
{
	/*
	 * Where will the next message be written?
	 */
	struct dest d = {
		.cursor = NULL,
		.size = 0,
	};
	if (buf->total < buf->roof) {
		d.cursor = buf->array + buf->total;
		d.size = buf->roof - buf->total;
	} else {
		/* point start at terminating '\0' */
		d.cursor = buf->array + buf->roof - 1;
		d.size = 0;
	}
	passert(d.cursor[0] == '\0');
	jambuf_debugf("%s(buf=%p)->{.cursor=%p,.size=%zd}\n",
		      __func__, buf, d.cursor, d.size);
	return d;
}

/*
 * The output needs to be truncated, overwrite the end of the buffer
 * with DOTS.
 */
static void truncate_buf(jambuf_t *buf)
{
	jambuf_debugf("truncate_buf(.buf=%p)\n", buf);
	jambuf_debugf("\tlength=%zu\n", buf->total);
	jambuf_debugf("\tdots=%s\n", buf->dots);
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
	jambuf_debugf("\tdest=%p\n", dest);
	memcpy(dest, buf->dots, strlen(buf->dots) + 1);
}

/*
 * Try to append STRING[0..N) to BUF.  Don't assume STRING is NUL
 * terminated.
 *
 * N (the return value) is the number of characters, not including the
 * trailing NUL, that should have been written to the buffer.
 */

static size_t concat(jambuf_t *buf, const char *string, size_t n)
{
	struct dest d = dest(buf);

	buf->total += n;
	if (d.size > n) {
		/*
		 * There is space for all N characters and a trailing
		 * NUL, copy the string and add a NULL (remember can't
		 * assume STRING contains a NUL).
		 */
		memcpy(d.cursor, string, n);
		d.cursor[n] = '\0';
	} else if (d.size > 0) {
		/*
		 * Not enough space, perform a partial copy of the
		 * string ...
		 */
		memcpy(d.cursor, string, d.size - 1);
		d.cursor[d.size - 1] = '\0';
		/*
		 * ... and then go back and blat the end with DOTS.
		 */
		truncate_buf(buf);
	}
	return n;
}

size_t jam_va_list(jambuf_t *buf, const char *format, va_list ap)
{
	assert_jambuf(buf);
	struct dest d = dest(buf);

	/*
	 * N (the return value) is the number of characters, not
	 * including the trailing NUL, that should have been written
	 * to the buffer.
	 */
	int sn = vsnprintf(d.cursor, d.size, format, ap);
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
	assert_jambuf(buf);
	return n;
}

size_t jam(jambuf_t *buf, const char *format, ...)
{
	/* jam_va_list does assert */
	va_list ap;
	va_start(ap, format);
	size_t n = jam_va_list(buf, format, ap);
	va_end(ap);
	return n;
}

size_t jam_char(jambuf_t *buf, char c)
{
	assert_jambuf(buf);
	size_t n = concat(buf, &c, 1);
	assert_jambuf(buf);
	return n;
}

size_t jam_string(jambuf_t *buf, const char *string)
{
	assert_jambuf(buf);
	/*
	 * Just in case a NULL ends up here.  This has the side effect
	 * of returning "6" for a NULL string.
	 */
	if (string == NULL) {
		string = "(null)";
	}
	size_t n = concat(buf, string, strlen(string));
	assert_jambuf(buf);
	return n;
}

size_t jam_jambuf(jambuf_t *buf, jambuf_t *jambuf)
{
	assert_jambuf(buf);
	struct dest s = dest(jambuf);
	size_t n = concat(buf, jambuf->array, s.cursor - jambuf->array);
	assert_jambuf(buf);
	return n;
}

bool jambuf_ok(jambuf_t *buf)
{
	assert_jambuf(buf);
	return buf->total < buf->roof;
}

const char *jambuf_pos(jambuf_t *buf)
{
	assert_jambuf(buf);
	struct dest d = dest(buf);
	return d.cursor;
}

chunk_t jambuf_as_chunk(jambuf_t *buf)
{
	assert_jambuf(buf);
	struct dest d = dest(buf);
	passert(d.cursor[0] == '\0');
	return chunk(buf->array, d.cursor - buf->array + 1);
}

shunk_t jambuf_as_shunk(jambuf_t *buf)
{
	assert_jambuf(buf);
	struct dest d = dest(buf);
	return shunk2(buf->array, d.cursor - buf->array);
}
