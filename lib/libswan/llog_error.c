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

<<<<<<< HEAD:lib/libswan/llog_errno.c
void llog_errno(lset_t rc_flags, struct logger *logger, int error, const char *fmt, ...)
=======
void llog_error(lset_t rc_flags, struct logger *logger, int error, const char *fmt, ...)
>>>>>>> 6c9d2a4dbb (jambuf: add jam_errno()):lib/libswan/llog_error.c
{
	JAMBUF(buf) {
		/* XXX: notice how <prefix> is in the middle */
		/* ERROR: <prefix><message> */
		jam(buf, "ERROR: ");
		jam_logger_prefix(buf, logger);
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);
<<<<<<< HEAD:lib/libswan/llog_errno.c
		/* XXX: not thread safe */
		jam(buf, PRI_ERRNO, pri_errno(error));
=======
		if (error != 0) {
			jam_errno(buf, error);
		}
>>>>>>> 6c9d2a4dbb (jambuf: add jam_errno()):lib/libswan/llog_error.c
		jambuf_to_logger(buf, logger, rc_flags);
	}
}
