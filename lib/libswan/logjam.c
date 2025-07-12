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

#include "logjam.h"
#include "lswlog.h"

struct jambuf *jambuf_from_logjam(struct logjam *logjam,
				   const struct logger *logger,
				   enum pluto_exit_code pluto_exit_code,
				   where_t where,
				   enum stream stream)
{
	/*
	 * Note: don't initialize entire logjam; as that would zero
	 * the very large array[LOG_WIDTH].
	 */
	logjam->barf = (struct barf) {
		.stream = stream,
		.jambuf = ARRAY_AS_JAMBUF(logjam->array),
		.logger = logger,
		.where = where,
		.pluto_exit_code = pluto_exit_code,
	};
	jam_stream_prefix(&logjam->barf.jambuf, logger, stream);
	return &logjam->barf.jambuf;
}

void logjam_to_logger(struct logjam *logjam)
{
	if (logjam->barf.where != NULL) {
		jam_string(&logjam->barf.jambuf, " ");
		jam_where(&logjam->barf.jambuf, logjam->barf.where);
	}
	jambuf_to_logger(&logjam->barf.jambuf, logjam->barf.logger, logjam->barf.stream);
	if ((logjam->barf.stream & STREAM_MASK) == PASSERT_STREAM) {
		abort();
	}
}

void barf(enum stream stream, struct logger *logger,
	  enum pluto_exit_code pluto_exit_code, where_t where,
	  const char *fmt, ...)
{
	BARF_JAMBUF(stream, logger, pluto_exit_code, where, buf) {
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);
	}
}
