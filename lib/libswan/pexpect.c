/* pexpect, for libreswan
 *
 * Copyright (C) 2020 Andrew Cagney
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

void log_pexpect(where_t where, const char *message, ...)
{
	JAMBUF(buf) {
		jam_string(buf, "EXPECTATION FAILED: ");
		va_list args;
		va_start(args, message);
		jam_va_list(buf, message, args);
		va_end(args);
		jam(buf, " "PRI_WHERE, pri_where(where));
		jambuf_to_error_stream(buf); /* XXX: grrr */
	}
}

void llog_pexpect_fail(struct logger *logger, where_t where, const char *message, ...)
{
	JAMBUF(buf) {
		jam_string(buf, "EXPECTATION FAILED: ");
		jam_logger_prefix(buf, logger);
		va_list ap;
		va_start(ap, message);
		jam_va_list(buf, message, ap);
		va_end(ap);
		jam(buf, " "PRI_WHERE, pri_where(where));
		jambuf_to_logger(buf, logger, ERROR_FLAGS);
	}
}
