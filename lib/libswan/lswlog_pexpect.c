/* Output an expection failure, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include "lswlog.h"

void lswlog_pexpect_prefix(struct lswlog *buf)
{
	lswlog_log_prefix(buf);
	lswlogs(buf, "EXPECTATION FAILED: ");
}

void lswlog_pexpect_suffix(struct lswlog *buf, const char *func,
			     const char *file, unsigned long line)
{
	lswlog_source_line(buf, func, file, line);
	lswlog_to_error_stream(buf);
}
