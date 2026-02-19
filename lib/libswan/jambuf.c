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
#include <errno.h>		/* for ERANGE */

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
static void assert_jambuf(struct jambuf *buf)
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

struct jambuf array_as_jambuf(char *array, size_t sizeof_array)
{
	jambuf_debugf("%s(array=%p,sizeof_array=%zu)\n",
		      __func__, array, sizeof_array);
	/* pointers back at buf */
	struct jambuf buf = {
		.array = array,
		.total = 0,
		.roof = sizeof_array - 1,
		.dots = "...",
	};
	buf.array[buf.roof-1] = buf.array[buf.total/*0*/] = '\0';
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
	/*
	 * Position in the buffer to store the next string (always
	 * points at the trailing '\n' character of the string so far).
	 */
	char *cursor;
	/*
	 * Free space, or zero when the stream has been truncated.
	 *
	 * Up to SIZE-1 + the trailing '\0' can be written.
	 */
	size_t size;
};

static struct dest dest(struct jambuf *buf)
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
static void truncate_buf(struct jambuf *buf)
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

size_t jam_raw_bytes(struct jambuf *buf, const void *string, size_t n)
{
	assert_jambuf(buf);
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
	assert_jambuf(buf);
	return n;
}

size_t jam_va_list(struct jambuf *buf, const char *format, va_list ap)
{
	assert_jambuf(buf);
	struct dest d = dest(buf);

	/*
	 * The return value (N) is the number of characters, not
	 * including the trailing NUL, that should have been written
	 * to the buffer.
	 *
	 * The buffer will contain up to d.size-1 characters plus a
	 * trailing NUL.
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

size_t jam(struct jambuf *buf, const char *format, ...)
{
	/* jam_va_list does assert */
	va_list ap;
	va_start(ap, format);
	size_t n = jam_va_list(buf, format, ap);
	va_end(ap);
	return n;
}

size_t jam_bool(struct jambuf *buf, bool b)
{
	return jam(buf, "%s", bool_str(b));
}

size_t jam_char(struct jambuf *buf, char c)
{
	return jam_raw_bytes(buf, &c, 1);
}

size_t jam_string(struct jambuf *buf, const char *string)
{
	/*
	 * Just in case a NULL ends up here.  This has the side effect
	 * of returning "6" for a NULL string.
	 */
	if (string == NULL) {
		string = "(null)";
	}
	return jam_raw_bytes(buf, string, strlen(string));
}

size_t jam_errno(struct jambuf *buf, int error)
{
	assert_jambuf(buf);
	struct dest d = dest(buf);
	if (d.size == 0) {
		/* should be strlen(strerror()) */
		return 1;
	}

	/*
	 * strerror_r() will store up to d.size-1 characters plus a
	 * trailing NUL.
	 */
	int e = strerror_r(error, d.cursor, d.size);
	int n = strlen(d.cursor);
	buf->total += n;
	if (e == ERANGE) {
		/*
		 * Need to force overflow as strerror_r() only stores
		 * up to d.size-1 characters (excluding '\0') which
		 * leaves buf->total==buf->roof-1.
		 */
		buf->total = buf->roof;
		truncate_buf(buf);
	} else if (e != EINVAL) {
		/* assume unknown E already includes number */
		n += jam(buf, " (errno %d)", error);
	}
	assert_jambuf(buf);
	return n;
}

size_t jam_jambuf(struct jambuf *buf, struct jambuf *jambuf)
{
	shunk_t s = jambuf_as_shunk(jambuf);
	return jam_raw_bytes(buf, s.ptr, s.len);
}

bool jambuf_ok(struct jambuf *buf)
{
	assert_jambuf(buf);
	return buf->total < buf->roof;
}

const char *jambuf_cursor(struct jambuf *buf)
{
	assert_jambuf(buf);
	struct dest d = dest(buf);
	return d.cursor;
}

shunk_t jambuf_as_shunk(struct jambuf *buf)
{
	assert_jambuf(buf);
	struct dest d = dest(buf);
	return shunk2(buf->array, d.cursor - buf->array);
}

jampos_t jambuf_get_pos(struct jambuf *buf)
{
	assert_jambuf(buf);
	jampos_t pos = {
		.total = buf->total,
	};
	return pos;
}

void jambuf_set_pos(struct jambuf *buf, const jampos_t *pos)
{
	assert_jambuf(buf);
	if (pos->total >= buf->roof) {
		/* "set" was already overflowed */
		buf->total = pos->total;
	} else if (/* no overflow at all */
		buf->total < buf->roof ||
		/* overflowed post "set" but space to restore */
		pos->total + strlen(buf->dots) < buf->roof) {
		/*
		 * Either no overflow, or there's space to recover
		 * from an overflow (can't recover when pos->total has
		 * been scribbled on with dots).
		 */
		buf->array[pos->total] = '\0';
		buf->total = pos->total;
	} else {
		/*
		 * Can't recover from overflow (pos->total was
		 * scribbed on with dots) so leave things overflowing.
		 */
		buf->total = buf->roof;
	}
	assert_jambuf(buf);
}
