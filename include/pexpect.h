/* logging declarations
 *
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2004 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
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

#ifndef PEXPECT_H
#define PEXPECT_H

#include <stdarg.h>
#include <stdio.h>		/* for FILE */
#include <stddef.h>		/* for size_t */

#include "lset.h"
#include "lswcdefs.h"
#include "jambuf.h"
#include "passert.h"
#include "constants.h"		/* for DBG_... */
#include "where.h"		/* used by macros */
#include "fd.h"			/* for null_fd */
#include "impair.h"
#include "logjam.h"

#include "global_logger.h"

struct jambuf;

/*
 * Log an expectation failure message to the error streams.  That is
 * the main log (level LOG_ERR) and whack log (level RC_LOG_SERIOUS).
 *
 * When evaluating ASSERTION, do not wrap it in parentheses as it will
 * suppress the warning for 'foo = bar'.
 *
 * Because static analyzer tools are easily confused, explicitly
 * return the assertion result.
 */

extern void llog_pexpect(const struct logger *logger, where_t where,
			 const char *message, ...) PRINTF_LIKE(3);

#define LLOG_PEXPECT_JAMBUF(LOGGER, WHERE, BUF)				\
	/* create the buffer */						\
	for (struct logjam logjam_, *lbp_ = &logjam_;		\
	     lbp_ != NULL; lbp_ = NULL)					\
		/* create the jambuf */					\
		for (struct jambuf *BUF =				\
			     jambuf_from_logjam(&logjam_, LOGGER,	\
						 0, WHERE, PEXPECT_STREAM); \
		     BUF != NULL;					\
		     logjam_to_logger(&logjam_), BUF = NULL)

#define PEXPECT_WHERE(LOGGER, WHERE, ASSERTION)				\
	({								\
		/* wrapping ASSERTION in parens suppresses -Wparen */	\
		bool assertion__ = ASSERTION; /* no parens */		\
		if (!assertion__) {					\
			const struct logger *logger_ = LOGGER;		\
			llog_pexpect(logger_, WHERE, "%s", #ASSERTION);	\
		}							\
		assertion__; /* result */				\
	})

#define PEXPECT(LOGGER, ASSERTION)					\
	PEXPECT_WHERE(LOGGER, HERE, ASSERTION)

#define PBAD_WHERE(LOGGER, WHERE, BAD)					\
	({								\
		/* wrapping BAD in parens suppresses -Wparen */		\
		bool bad_ = BAD; /* no parens */			\
		if (bad_) {						\
			const struct logger *logger_ = LOGGER;		\
			llog_pexpect(logger_, WHERE, "not (%s)", #BAD); \
		}							\
		bad_; /* result */					\
	})

#define PBAD(LOGGER, BAD) PBAD_WHERE(LOGGER, HERE, BAD)

#define pbad(BAD) PBAD_WHERE(&global_logger, HERE, BAD)

#define pexpect(ASSERTION)  PEXPECT_WHERE(&global_logger, HERE, ASSERTION)

#endif

