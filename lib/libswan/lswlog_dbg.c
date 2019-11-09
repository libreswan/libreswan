/* Output a formatted debug string, for libreswan
 *
 * Copyright (C) 2017 Paul Wouters <pwouters@redhat.com>
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

#include <stdio.h>
#include <stdarg.h>

#include "lswlog.h"

lset_t cur_debugging = DBG_NONE;	/* default to reporting nothing */

void lswlog_dbg_pre(struct lswlog *buf)
{
	lswlogs(buf, DEBUG_PREFIX);
	if (DBGP(DBG_ADD_PREFIX)) {
		lswlog_log_prefix(buf);
	}
}
