/*
 * abort log function, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
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
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

#include "lswlog.h"

void lsw_passert_fail(const char *file_str,
		      unsigned long line_no,
		      const char *func_str,
		      const char *fmt, ...)
{
	va_list args;
	char message[LOG_WIDTH];	/* longer messages will be truncated */

	va_start(args, fmt);
	vsnprintf(message, sizeof(message), fmt, args);
	va_end(args);

	libreswan_loglog(RC_LOG_SERIOUS,
			 "ABORT: ASSERTION FAILED: %s (in %s() at %s:%lu)",
			 message, func_str, file_str, line_no);

	/* this needs to panic */
	abort();
}
