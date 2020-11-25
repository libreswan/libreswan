/*
 * abort functions, for libreswan
 *
 * Copyright (C) 2017, 2020 Andrew Cagney
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

#include "passert.h"
#include "lswlog.h"

void lsw_passert_fail(where_t where, const char *fmt, ...)
{
	JAMBUF(buf) {
		jam_string(buf, "ABORT: ASSERTION FAILED: ");
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);
		jam(buf, " "PRI_WHERE, pri_where(where));
		jambuf_to_error_stream(buf); /* XXX: grrr */
	}
	abort();
}

void passert_fail(struct logger *logger, where_t where, const char *fmt, ...)
{
	JAMBUF(buf) {
		jam_string(buf, "ABORT: ASSERTION FAILED: ");
		jam_logger_prefix(buf, logger);
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);
		jam(buf, " "PRI_WHERE, pri_where(where));
		jambuf_to_logger(buf, logger, ERROR_FLAGS);
	}
	abort();
}
