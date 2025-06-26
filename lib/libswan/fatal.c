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

#include "fatal.h"

#include "constants.h"		/* for enum pluto_exit_code */
#include "lswlog.h"		/* for LOG_WIDTH et.al. */

void fatal(enum pluto_exit_code pluto_exit_code, const struct logger *logger,
	   int error, const char *fmt, ...)
{
	struct logjam logjam;
	struct jambuf *buf = jambuf_from_logjam(&logjam, logger, pluto_exit_code,
						NULL/*where*/, FATAL_STREAM);
	{
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);
		if (error != 0) {
			jam_string(buf, ": ");
			jam_errno(buf, error);
		}
	}
	fatal_logjam_to_logger(&logjam);
}

void fatal_logjam_to_logger(struct logjam *logjam)
{
	logjam_to_logger(logjam);
	libreswan_exit(logjam->barf.pluto_exit_code);
}
