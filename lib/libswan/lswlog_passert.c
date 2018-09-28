/* Output an expection failure, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney
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

#include <stdlib.h>

#include "lswlog.h"

void lswlog_passert_prefix(struct lswlog *buf)
{
	lswlog_log_prefix(buf);
	lswlogs(buf, "ABORT: ASSERTION FAILED: ");
}

void lswlog_passert_suffix(struct lswlog *buf, const char *func,
			   const char *file, unsigned long line)
{
	lswlog_source_line(buf, func, file, line);
	lswlog_to_error_stream(buf);
	/* this needs to panic */
	abort();
}
