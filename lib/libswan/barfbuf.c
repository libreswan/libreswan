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

struct jambuf *jambuf_from_barfbuf(struct barfbuf *barfbuf,
				   const struct logger *logger,
				   enum pluto_exit_code pec,
				   where_t where,
				   lset_t rc_flags)
{
	/*
	 * Note: don't initialize entire barfbuf; as that would zero
	 * the very large array[LOG_WIDTH].
	 */
	barfbuf->barf = (struct barfjam) {
		.rc_flags = rc_flags,
		.jambuf = ARRAY_AS_JAMBUF(barfbuf->array),
		.logger = logger,
		.where = where,
		.pec = pec,
	};
	jam_logger_rc_prefix(&barfbuf->barf.jambuf, logger, rc_flags);
	return &barfbuf->barf.jambuf;
}

void barfbuf_to_logger(struct barfbuf *barfbuf)
{
	if (barfbuf->barf.where != NULL) {
		jam(&barfbuf->barf.jambuf, " "PRI_WHERE, pri_where(barfbuf->barf.where));
	}
	jambuf_to_logger(&barfbuf->barf.jambuf, barfbuf->barf.logger, barfbuf->barf.rc_flags);
	if ((barfbuf->barf.rc_flags & STREAM_MASK) == PASSERT_STREAM) {
		abort();
	}
}
