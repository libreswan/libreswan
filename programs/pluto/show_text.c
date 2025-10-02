/* show functions in text format, for libreswan
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
#include "show_ops.h"
#include "show.h"

VPRINTF_LIKE(2)
static void raw_va_list(struct jambuf *buf, const char *message, va_list ap)
{
	jam_va_list(buf, message, ap);
}

static void discard(struct jambuf *buf UNUSED)
{
}

VPRINTF_LIKE(2)
static void member_start(struct jambuf *buf, const char *name)
{
	jam_string(buf, name);
	jam_string(buf, "=");
}

static void separator(struct jambuf *buf)
{
	jam_string(buf, ", ");
}

const struct show_ops show_text_ops = {
	.raw_va_list = raw_va_list,
	.string_va_list = raw_va_list,
	.member_start = member_start,
	.member_end = discard,
	.array_start = discard,
	.array_end = discard,
	.object_start = discard,
	.object_end = discard,
	.separator = separator,
};
