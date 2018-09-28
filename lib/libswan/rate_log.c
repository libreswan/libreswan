/* Rate limit logging, for libreswan
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

#define RATE_LIMIT 1000

void rate_log(const char *fmt, ...)
{
	static int nr = 0;
	if (nr >= RATE_LIMIT) {
		if (nr == RATE_LIMIT) {
			nr++;
			libreswan_log("rate limited log exceed %d entries",
				      RATE_LIMIT);
		}
		LSWDBGP(DBG_MASK, buf) {
			va_list ap;
			va_start(ap, fmt);
			lswlogvf(buf, fmt, ap);
			va_end(ap);
		}
	} else {
		nr++;
		LSWLOG(buf) {
			va_list ap;
			va_start(ap, fmt);
			lswlogvf(buf, fmt, ap);
			va_end(ap);
		}
	}
}
