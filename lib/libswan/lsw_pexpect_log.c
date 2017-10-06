/* expectation failure, for libreswan
 *
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include <stdio.h>
#include <stdarg.h>

#include "lswlog.h"

void lsw_pexpect_log(const char *file,
		     unsigned long line,
		     const char *func,
		     const char *fmt, ...)
{
	LSWBUF(buf) {
		lswlog_pre(buf);
		lswlogs(buf, "EXPECTATION FAILED: ");
		va_list ap;
		va_start(ap, fmt);
		lswlogvf(buf, fmt, ap);
		va_end(ap);
		lswlog_source_line(buf, func, file, line);
		lswlog_to_error_stream(buf);
	}
}
