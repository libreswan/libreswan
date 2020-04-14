/* Output an expectation failure, for libreswan
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

#include "lswlog.h"

void lswlog_pexpect_prefix(struct lswlog *buf)
{
	jam_cur_prefix(buf);
	lswlogs(buf, "EXPECTATION FAILED: ");
}

void lswlog_pexpect_suffix(struct lswlog *buf, where_t where)
{
	jam(buf, " "PRI_WHERE, pri_where(where));
	lswlog_to_error_stream(buf);
}
