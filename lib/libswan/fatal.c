/* log wrapper, for libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
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

#include "lswlog.h"

void fatal(const char *fmt, ...)
{
	JAMBUF(buf) {
		/* FATAL ERROR: <cur-prefix><message> */
		jam(buf, "FATAL ERROR: ");
		jam_cur_prefix(buf);
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);
		lswlog_to_error_stream(buf);
	}
	libreswan_exit(PLUTO_EXIT_FAIL);
}
