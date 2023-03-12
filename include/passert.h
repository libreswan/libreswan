/*
 * Panic, for libreswan.
 *
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003  Michael Richardson <mcr@freeswan.org>
 * Copyright (C) 2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2015-2016 Andrew Cagney <cagney@gnu.org>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 */

#ifndef _LIBRESWAN_PASSERT_H
#define _LIBRESWAN_PASSERT_H

#include <string.h>		/* for strrchr() */
#include <stdbool.h>

#include "err.h"		/* for err_t */
#include "lswcdefs.h"		/* for NEVER_RETURNS PRINTF_LIKE() */
#include "where.h"
#include "lset.h"

struct logger;

/* our versions of assert: log result */

/*
 * Preferred: can log with prefix to whack from a thread.
 */

#ifndef GLOBAL_LOGGER
extern const struct logger global_logger;
#define GLOBAL_LOGGER
#endif

/*
 * XXX: GCC, at least can't understand that LLOG_PASSERT_JAMBUF()
 * never returns.  Hence code sometimes calls
 * passert_jambuf_to_logger() explicitly.
 */

extern void llog_passert(const struct logger *logger, where_t where,
			 const char *message, ...) NEVER_RETURNS PRINTF_LIKE(3);

void passert_jambuf_to_logger(struct jambuf *buf,
			      where_t where, const struct logger *logger,
			      lset_t rc_flags) NEVER_RETURNS;

#define LLOG_PASSERT_JAMBUF(LOGGER, WHERE, BUF)				\
	JAMBUF(BUF)							\
	for (jam_logger_rc_prefix(BUF, LOGGER, PASSERT_FLAGS);		\
	     BUF != NULL;						\
	     passert_jambuf_to_logger(BUF, WHERE, (LOGGER), PASSERT_FLAGS), BUF = NULL)

#define PASSERT_WHERE(LOGGER, WHERE, ASSERTION)				\
	({								\
		/* wrapping ASSERTION in parens suppresses -Wparen */	\
		bool assertion__ = ASSERTION; /* no parens */		\
		if (!assertion__) {					\
			const struct logger *logger_ = LOGGER;		\
			llog_passert(logger_, WHERE, "%s", #ASSERTION);	\
		}							\
		/* return something so flipping to pexpect() is easy */	\
		(void) true;						\
	})

#define PASSERT(LOGGER, ASSERTION)		\
	PASSERT_WHERE(LOGGER, HERE, ASSERTION)

#define passert(ASSERTION)				\
	PASSERT_WHERE(&global_logger, HERE, ASSERTION)

/* evaluate x exactly once; assert that err_t result is NULL; */
#define happy(x) /* TBD: use ??? */				\
	{							\
		err_t ugh = x;					\
		if (ugh != NULL) {				\
			llog_passert(&global_logger, HERE,	\
				     "%s", ugh);		\
		}						\
	}

#endif /* _LIBRESWAN_PASSERT_H */
