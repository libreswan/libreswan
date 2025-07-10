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

void llog_errno(enum stream stream, const struct logger *logger, int error, const char *fmt, ...)
{
	JAMBUF(buf) {
		jam_stream_prefix(buf, logger, stream);
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);
		/* NO ": "; not a *perror() function */
		jam_errno(buf, error);
		jambuf_to_logger(buf, logger, stream);
	}
}
