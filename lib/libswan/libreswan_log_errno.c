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

void libreswan_log_errno(int e, const char *fmt, ...)
{
	JAMBUF(buf) {
		/* ERROR: <prefix>: <message>. Errno N: <errmess> */
		jam(buf, "ERROR: ");
		jam_cur_prefix(buf);
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);
		jam_string(buf, ".");
		jam(buf, " "PRI_ERRNO, pri_errno(e));
		lswlog_to_error_stream(buf);
	}
}
