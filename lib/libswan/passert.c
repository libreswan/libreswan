/*
 * abort functions, for libreswan
 *
 * Copyright (C) 2017, 2020 Andrew Cagney
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

#include <stdlib.h>		/* for abort() */

#include "passert.h"
#include "lswlog.h"

void llog_passert(const struct logger *logger, where_t where, const char *fmt, ...)
{
	struct logjam logjam;
	struct jambuf *buf = jambuf_from_logjam(&logjam, logger, 0, where, PASSERT_STREAM);
	{
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);
	}
	passert_logjam_to_logger(&logjam);
}

void passert_logjam_to_logger(struct logjam *logjam)
{
	logjam_to_logger(logjam);
	abort();
}
