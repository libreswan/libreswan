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
 *
 */

#include <stdlib.h>		/* for abort() */

#include "lswlog.h"

struct jambuf *jambuf_from_logbuf(struct logbuf *logbuf, const struct logger *logger, lset_t rc_flags)
{
	/*
	 * Note: don't initialize entire logbuf; as that would zero
	 * the very large array[LOG_WIDTH].
	 */
	logbuf->log = (struct logjam) {
		.rc_flags = rc_flags,
		.jambuf = ARRAY_AS_JAMBUF(logbuf->array),
		.logger = logger,
	};
	jam_logger_rc_prefix(&logbuf->log.jambuf, logger, rc_flags);
	return &logbuf->log.jambuf;
}

void logbuf_to_logger(struct logbuf *logbuf)
{
	jambuf_to_logger(&logbuf->log.jambuf, logbuf->log.logger, logbuf->log.rc_flags);
}
