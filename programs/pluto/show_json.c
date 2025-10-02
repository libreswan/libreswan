/* show functions in JSON format, for libreswan
 *
 * Copyright (C) 2025 Daiki Ueno <dueno@redhat.com>
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

#include "log.h"
#include "show.h"
#include "show_ops.h"

static size_t jam_json_quoted_bytes(struct jambuf *buf, const void *ptr, size_t size)
{
	size_t n = 0;
	const char *chars = ptr;
	for (unsigned i = 0; i < size; i++) {
		char c = chars[i];
		switch (c) {
		case '"':
		case '\\':
			n += jam_char(buf, '\\');
			/* FALLTHROUGH */
		default:
			n += jam_char(buf, chars[i]);
		}
	}
	return n;
}

#define jam_json_quoted_hunk(BUF, HUNK)				\
	({								\
		typeof(HUNK) hunk_ = (HUNK); /* evaluate once */	\
		jam_json_quoted_bytes(BUF, hunk_.ptr, hunk_.len);	\
	})

VPRINTF_LIKE(2)
static void json_raw_va_list(struct jambuf *buf, const char *message, va_list ap)
{
	jam_va_list(buf, message, ap);
}

VPRINTF_LIKE(2)
static void json_string_va_list(struct jambuf *buf, const char *message, va_list ap)
{
	JAMBUF(buf2) {
		jam_char(buf, '"');
		jam_va_list(buf2, message, ap);
		jam_json_quoted_hunk(buf, jambuf_as_shunk(buf2));
		jam_char(buf, '"');
	}
}

VPRINTF_LIKE(2)
static void json_member_start(struct jambuf *buf, const char *name)
{
	JAMBUF(buf2) {
		jam_char(buf, '"');
		jam_string(buf2, name);
		jam_json_quoted_hunk(buf, jambuf_as_shunk(buf2));
		jam_string(buf, "\": ");
	}
}

static void json_member_end(struct jambuf *buf UNUSED)
{
}

static void json_array_start(struct jambuf *buf)
{
	jam_string(buf, "[");
}

static void json_array_end(struct jambuf *buf)
{
	jam_string(buf, "]");
}

static void json_object_start(struct jambuf *buf)
{
	jam_string(buf, "{");
}

static void json_object_end(struct jambuf *buf)
{
	jam_string(buf, "}");
}

static void json_separator(struct jambuf *buf)
{
	jam_string(buf, ", ");
}

const struct show_ops show_json_ops = {
	.raw_va_list = json_raw_va_list,
	.string_va_list = json_string_va_list,
	.member_start = json_member_start,
	.member_end = json_member_end,
	.array_start = json_array_start,
	.array_end = json_array_end,
	.object_start = json_object_start,
	.object_end = json_object_end,
	.separator = json_separator,
};
