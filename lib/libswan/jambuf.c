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
#define ARRAYBUF_CANARY ((char) -2)

static struct jammer arraybuf; /* forward */

/*
 * This is the one place where PASSERT() can't be used - it will
 * recursively end up back here!
 */
static void arraybuf_assert(jambuf_t *buf)
{
#define A(ASSERTION) if (!(ASSERTION)) abort()
	A(buf->dots != NULL);
	A(buf->jammer == &arraybuf);
	/* termination */
	char *array = buf->handle;
	A(buf->total >= buf->roof || array[buf->total] == '\0');
	A(array[buf->roof-1] == '\0');
	A(array[buf->roof-0] == ARRAYBUF_CANARY);
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
		.handle = array,
		.total = 0,
		.roof = sizeof_array - 1,
		.dots = "...",
		.jammer = &arraybuf,
	};
	array[buf.roof-1] = array[buf.total] = '\0';
	array[buf.roof-0] = ARRAYBUF_CANARY;
	arraybuf_assert(&buf);
	jambuf_debugf("\t->{.array=%p,.total=%zu,.roof=%zu,.dots='%s'}\n",
		      array, buf.total, buf.roof, buf.dots);
	return buf;
}

/*
 * Determine where, within LOG's message buffer, to write the string.
 */

struct arraybuf_dest {
	/* next character position (always points at '\0') */
	char *cursor;
	/* free space */
	size_t size;
};

static struct arraybuf_dest arraybuf_dest(jambuf_t *buf)
{
	arraybuf_assert(buf);
	/*
	 * Where will the next message be written?
	 */
	char *array = buf->handle;
	struct arraybuf_dest d = {
		.cursor = NULL,
		.size = 0,
	};
	if (buf->total < buf->roof) {
		d.cursor = array + buf->total;
		d.size = buf->roof - buf->total;
	} else {
		/* point start at terminating '\0' */
		d.cursor = array + buf->roof - 1;
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
static void arraybuf_truncate(jambuf_t *buf)
{
	jambuf_debugf("arraybuf_truncate(.buf=%p)\n", buf);
	jambuf_debugf("\tlength=%zu\n", buf->total);
	jambuf_debugf("\tdots=%s\n", buf->dots);
	/*
	 * buffer is full to overflowing
	 */
	char *array = buf->handle;
	passert(buf->total >= buf->roof);
	passert(array[buf->roof - 1] == '\0');
	passert(array[buf->roof - 2] != '\0');
	/*
	 * Backfill with DOTS.
	 */
	passert(buf->roof > strlen(buf->dots));
	char *dest = array + buf->roof - strlen(buf->dots) - 1;
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

static size_t arraybuf_jam_raw_bytes(jambuf_t *buf, const void *string, size_t n)
{
	struct arraybuf_dest d = arraybuf_dest(buf);

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
		arraybuf_truncate(buf);
	}
	arraybuf_assert(buf);
	return n;
}

static size_t arraybuf_jam_va_list(jambuf_t *buf, const char *format, va_list ap)
{
	arraybuf_assert(buf);
	struct arraybuf_dest d = arraybuf_dest(buf);

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
		arraybuf_truncate(buf);
	}
	arraybuf_assert(buf);
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
	return jam_raw_bytes(buf, &c, 1);
}

size_t jam_string(jambuf_t *buf, const char *string)
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

size_t jam_jambuf(jambuf_t *buf, jambuf_t *jambuf)
{
	shunk_t s = jambuf_as_shunk(jambuf);
	return jam_raw_bytes(buf, s.ptr, s.len);
}

static bool arraybuf_ok(jambuf_t *buf)
{
	arraybuf_assert(buf);
	return buf->total < buf->roof;
}

const char *jambuf_cursor(jambuf_t *buf)
{
	/* arraybuf only */
	arraybuf_assert(buf);
	struct arraybuf_dest d = arraybuf_dest(buf);
	return d.cursor;
}

shunk_t jambuf_as_shunk(jambuf_t *buf)
{
	/* arraybuf only */
	struct arraybuf_dest d = arraybuf_dest(buf);
	char *array = buf->handle;
	return shunk2(array, d.cursor - array);
}

jampos_t jambuf_get_pos(jambuf_t *buf)
{
	arraybuf_assert(buf);
	jampos_t pos = {
		.total = buf->total,
	};
	return pos;
}

void jambuf_set_pos(jambuf_t *buf, const jampos_t *pos)
{
	arraybuf_assert(buf);
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
		char *array = buf->handle;
		array[pos->total] = '\0';
		buf->total = pos->total;
	} else {
		/*
		 * Can't recover from overflow (pos->total was
		 * scribbed on with dots) so leave things overflowing.
		 */
		buf->total = buf->roof;
	}
	arraybuf_assert(buf);
}

static struct jammer arraybuf = {
	.jambuf_ok = arraybuf_ok,
	.jam_va_list = arraybuf_jam_va_list,
	.jam_raw_bytes = arraybuf_jam_raw_bytes,
};

bool jambuf_ok(jambuf_t *buf)
{
	return buf->jammer->jambuf_ok(buf);
}

size_t jam_raw_bytes(jambuf_t *buf, const void *bytes, size_t nr)
{
	return buf->jammer->jam_raw_bytes(buf, bytes, nr);
}

size_t jam_va_list(jambuf_t *buf, const char *format, va_list ap)
{
	return buf->jammer->jam_va_list(buf, format, ap);
}

static bool filebuf_ok(jambuf_t *buf)
{
	/* is this meaningless? */
	return ferror(buf->handle) || feof(buf->handle);
}

static size_t filebuf_jam_va_list(jambuf_t *buf, const char *format, va_list ap)
{
	return vfprintf(buf->handle, format, ap);
}

static size_t filebuf_jam_raw_bytes(jambuf_t *buf, const void *bytes, size_t nr)
{
	return fwrite(bytes, nr, 1, buf->handle);
}

static struct jammer filebuf = {
	.jambuf_ok = filebuf_ok,
	.jam_va_list = filebuf_jam_va_list,
	.jam_raw_bytes = filebuf_jam_raw_bytes,
};

jambuf_t file_as_jambuf(FILE *file)
{
	jambuf_t buf = {
		.handle = file,
		.jammer = &filebuf,
	};
	return buf;
}
