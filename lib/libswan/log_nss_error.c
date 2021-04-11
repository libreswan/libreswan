/* Output an (NS)PR error, for libreswan
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
 */

#include <stdio.h>
#include <stdarg.h>

#include <prerror.h>
#include <secerr.h>

#include "lswlog.h"
#include "lswalloc.h"
#include "lswnss.h"

/*
 * See https://bugzilla.mozilla.org/show_bug.cgi?id=172051
 */

PRINTF_LIKE_VA(2)
static void jam_va_nss_error(struct jambuf *buf, const char *message, va_list ap)
{
	jam(buf, "NSS: ");
	jam_va_list(buf, message, ap);
	va_end(ap);
	jam(buf, ": ");
	jam_nss_error(buf);
}

void log_nss_error(lset_t rc_flags, struct logger *logger,
		   const char *message, ...)
{
	LLOG_JAMBUF(rc_flags, logger, buf) {
		va_list ap;
		va_start(ap, message);
		jam_va_nss_error(buf, message, ap);
		va_end(ap);
	}
}

diag_t diag_nss_error(const char *message, ...)
{
	char lswbuf[LOG_WIDTH];
	struct jambuf buf = ARRAY_AS_JAMBUF(lswbuf);
	va_list ap;
	va_start(ap, message);
	jam_va_nss_error(&buf, message, ap);
	va_end(ap);
	return diag_jambuf(&buf);
}

void passert_nss_error(struct logger *logger, where_t where,
		       const char *message, ...)
{
	char scratch[LOG_WIDTH];
	struct jambuf buf[1] = { ARRAY_AS_JAMBUF(scratch), };
	va_list ap;
	va_start(ap, message);
	jam_va_nss_error(buf, message, ap);
	va_end(ap);
	/* XXX: double copy */
	passert_fail(logger, where, PRI_SHUNK, pri_shunk(jambuf_as_shunk(buf)));
}

void pexpect_nss_error(struct logger *logger, where_t where,
		       const char *message, ...)
{
	char scratch[LOG_WIDTH];
	struct jambuf buf[1] = { ARRAY_AS_JAMBUF(scratch), };
	va_list ap;
	va_start(ap, message);
	jam_va_nss_error(buf, message, ap);
	va_end(ap);
	/* XXX: double copy */
	pexpect_fail(logger, where, PRI_SHUNK, pri_shunk(jambuf_as_shunk(buf)));
}

void DBG_nss_error(struct logger *logger, const char *message, ...)
{
	char scratch[LOG_WIDTH];
	struct jambuf buf[1] = { ARRAY_AS_JAMBUF(scratch), };
	va_list ap;
	va_start(ap, message);
	jam_va_nss_error(buf, message, ap);
	va_end(ap);
	jambuf_to_logger(buf, logger, DEBUG_STREAM);
}
