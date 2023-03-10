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

VPRINTF_LIKE(3)
static void jam_fatal(struct jambuf *buf, const struct logger *logger,
		      const char *fmt, va_list ap)
{
	/* XXX: The message format is:
	 *   FATAL ERROR: <log-prefix><message...>
	 * and not:
	 *   <log-prefix>FATAL ERROR: <message...>
	 */
	jam_string(buf, FATAL_PREFIX);
	jam_logger_prefix(buf, logger);
	jam_va_list(buf, fmt, ap);
}

void fatal(enum pluto_exit_code rc, const struct logger *logger, const char *fmt, ...)
{
	char output[LOG_WIDTH];
	struct jambuf buf = ARRAY_AS_JAMBUF(output);
	va_list ap;
	va_start(ap, fmt);
	jam_fatal(&buf, logger, fmt, ap);
	va_end(ap);
	jambuf_to_logger(&buf, logger, ERROR_FLAGS);
	libreswan_exit(rc);
}

void fatal_errno(enum pluto_exit_code rc, const struct logger *logger,
		 int error, const char *fmt, ...)
{
	char output[LOG_WIDTH];
	struct jambuf buf = ARRAY_AS_JAMBUF(output);
	va_list ap;
	va_start(ap, fmt);
	jam_fatal(&buf, logger, fmt, ap);
	va_end(ap);
	jam_string(&buf, ": ");
	jam_errno(&buf, error);
	jambuf_to_logger(&buf, logger, ERROR_FLAGS);
	libreswan_exit(rc);
}
