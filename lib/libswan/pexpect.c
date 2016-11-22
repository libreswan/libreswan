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

void pexpect_log(const char *file_str,
		 unsigned long line_no,
		 const char *func_str,
		 const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char m[LOG_WIDTH] = {0};
	vsnprintf(m, sizeof(m), fmt, ap);
	passert(strlen(m) < sizeof(m));
	va_end(ap);

	loglog(RC_LOG_SERIOUS, "EXPECTATION FAILED: %s (in %s at %s:%lu)",
	       m, func_str, file_str, line_no);
}
