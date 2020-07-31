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

void lswlog_passert_prefix(struct jambuf *buf)
{
	jam_cur_prefix(buf);
	jam_string(buf, "ABORT: ASSERTION FAILED: ");
}

void lswlog_passert_suffix(struct jambuf *buf, where_t where)
{
	jam(buf, " "PRI_WHERE, pri_where(where));
	lswlog_to_error_stream(buf);
	/* this needs to panic */
	abort();
}

void lsw_passert_fail(where_t where, const char *fmt, ...)
{
	LSWBUF(buf) {
		lswlog_passert_prefix(buf);
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);
		lswlog_passert_suffix(buf, where);
	}
	/* above will panic but compiler doesn't know this */
	abort();
}

void log_passert(struct logger *logger, where_t where, const char *fmt, ...)
{
	LOG_MESSAGE(ERROR_STREAM|RC_LOG_SERIOUS, logger, buf) {
		jam_string(buf, "ABORT: ASSERTION FAILED: ");
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);
		jam(buf, " "PRI_WHERE, pri_where(where));
	}
	abort();
}
