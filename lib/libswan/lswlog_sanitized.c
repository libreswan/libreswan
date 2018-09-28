/* Output a sanitized string, for libreswan
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

#include <stdio.h>
#include <stdarg.h>

#include "lswlog.h"

size_t lswlog_sanitized(struct lswlog *buf, const char *raw)
{
	if (raw == NULL) {
		return lswlogs(buf, raw); /* appends error */
	}

	size_t size = 0;
	for (const char *p = raw; *p; p++) {
		/* space for at least '\000' and then some */
		char tmp[sizeof("\\000") + 1] = { *p, };
		sanitize_string(tmp, sizeof(tmp));
		size += lswlogs(buf, tmp);
	}
	return size;
}
