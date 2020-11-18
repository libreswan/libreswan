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

void fatal(enum pluto_exit_code rc, struct logger *logger, const char *fmt, ...)
{
	JAMBUF(buf) {
		/* XXX: The message format is:
		 *   FATAL ERROR: <log-prefix><message...>
		 * and not:
		 *   <log-prefix>FATAL ERROR: <message...>
		 */
		jam(buf, "FATAL ERROR: ");
		jam_logger_prefix(buf, logger);
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);
		jambuf_to_logger(buf, logger, ERROR_FLAGS);
	}
	libreswan_exit(rc);
}
