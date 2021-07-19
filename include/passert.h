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

struct logger;

/* our versions of assert: log result */

/*
 * preferredL can log with prefix to whack from a thread.
 */

extern void llog_passert(const struct logger *logger, where_t where,
			 const char *message, ...) NEVER_RETURNS PRINTF_LIKE(3);

#define PASSERT(LOGGER, ASSERTION)					\
	({								\
		/* wrapping ASSERTION in parens suppresses -Wparen */	\
		bool assertion__ = ASSERTION; /* no parens */		\
		if (!assertion__) {					\
			where_t here = HERE;				\
			const struct logger *logger_ = LOGGER;		\
			llog_passert(logger_, here, "%s", #ASSERTION);	\
		}							\
		true;							\
	})

/*
 * older: message does not reach whack
 */

#ifndef FAILSAFE_LOGGER
extern const struct logger failsafe_logger;
#define FAILSAFE_LOGGER
#endif

#define PASSERT_FAIL(FMT, ...) llog_passert(&failsafe_logger, HERE, FMT,##__VA_ARGS__)
#define passert(ASSERTION)     PASSERT(&failsafe_logger, ASSERTION)
#define lsw_passert_fail(WHERE, FMT, ...) llog_passert(&failsafe_logger, WHERE, FMT,##__VA_ARGS__)
#define passert_fail llog_passert

/* evaluate x exactly once; assert that err_t result is NULL; */
#define happy(x) /* TBD: use ??? */			\
	{						\
		err_t ugh = x;				\
		if (ugh != NULL) {			\
			PASSERT_FAIL("%s", ugh);	\
		}					\
	}

#endif /* _LIBRESWAN_PASSERT_H */
