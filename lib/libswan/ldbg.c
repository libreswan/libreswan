/* logging, for libreswan
 *
 * Copyright (C) 2022 Andrew Cagney
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

#include <stdarg.h>

#include "lswlog.h"

void ldbg(const struct logger *logger, const char *message, ...)
{
	if (LDBGP(DBG_BASE, logger)) {
		va_list ap;
		va_start(ap, message);
		llog_va_list(DEBUG_STREAM, logger, message, ap);
		va_end(ap);
	}
}

void ldbgf(lset_t cond, const struct logger *logger, const char *message, ...)
{
	if (LDBGP(cond, logger)) {
		va_list ap;
		va_start(ap, message);
		llog_va_list(DEBUG_STREAM, logger, message, ap);
		va_end(ap);
	}
}
