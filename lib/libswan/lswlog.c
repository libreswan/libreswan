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
 * Constructor
 */

struct lswlog *lswlog(struct lswlog *buf, char *array,
		      size_t sizeof_array)
{
	*buf = array_as_fmtbuf(array, sizeof_array);
	return buf;
}

size_t lswlogvf(struct lswlog *log, const char *format, va_list ap)
{
	return fmt_va_list(log, format, ap);
}

size_t lswlogf(struct lswlog *log, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	size_t n = fmt_va_list(log, format, ap);
	va_end(ap);
	return n;
}

size_t lswlogs(struct lswlog *log, const char *string)
{
	return fmt_string(log, string);
}

size_t lswlogl(struct lswlog *log, struct lswlog *buf)
{
	return fmt_fmtbuf(log, buf);
}
