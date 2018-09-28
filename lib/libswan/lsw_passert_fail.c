/*
 * abort log function, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
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
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

#include "lswlog.h"

void lsw_passert_fail(const char *file,
		      unsigned long line,
		      const char *func,
		      const char *fmt, ...)
{
	LSWBUF(buf) {
		lswlog_passert_prefix(buf);
		va_list ap;
		va_start(ap, fmt);
		lswlogvf(buf, fmt, ap);
		va_end(ap);
		lswlog_passert_suffix(buf, func, file, line);
	}
	/* above will panic but compiler doesn't know this */
	abort();
}
