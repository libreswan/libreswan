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

/*
 * Pair a jambuf with a fixed size buffer plus wrappers to decorate
 * the output.
 */

#ifndef LOGJAM_H
#define LOGJAM_H

#include "lset.h"
#include "where.h"
#include "jambuf.h"
#include "constants.h"		/* for enum pluto_exit_code */

struct logger;
enum stream;

#define DEBUG_PREFIX		"| "
#define ERROR_PREFIX		"ERROR: "
#define PEXPECT_PREFIX		"EXPECTATION FAILED: "
#define PASSERT_PREFIX		"FATAL: ASSERTION FAILED: "
#define FATAL_PREFIX		"FATAL ERROR: "
/*define PRINTF_PREFIX		""*/

#define PEXPECT_FLAGS		(PEXPECT_STREAM|RC_INTERNAL_ERROR)
#define PASSERT_FLAGS		(PASSERT_STREAM|RC_INTERNAL_ERROR)
#define PRINTF_FLAGS		(NO_PREFIX|WHACK_STREAM)

struct logjam {
	char array[LOG_WIDTH];
	struct barf {
		const struct logger *logger;
		struct jambuf jambuf;
		lset_t rc_flags;
		where_t where;
		enum pluto_exit_code pluto_exit_code;
	} barf;
};

struct jambuf *jambuf_from_logjam(struct logjam *logjam,
				  const struct logger *logger,
				  enum pluto_exit_code pluto_exit_code,
				  where_t where,
				  lset_t rc_flags) MUST_USE_RESULT;

void logjam_to_logger(struct logjam *buf); /* may not return */

#define BARF_JAMBUF(RC_FLAGS, LOGGER, PLUTO_EXIT_CODE, WHERE, BUF)	\
	/* create the buffer */						\
	for (struct logjam logjam_, *bf_ = &logjam_;			\
	     bf_ != NULL; bf_ = NULL)					\
		/* create the jambuf */					\
		for (struct jambuf *BUF =				\
			     jambuf_from_logjam(&logjam_, LOGGER,	\
						PLUTO_EXIT_CODE, \
						WHERE, RC_FLAGS);	\
		     BUF != NULL;					\
		     logjam_to_logger(&logjam_), BUF = NULL)

PRINTF_LIKE(5)
void barf(enum stream stream, struct logger *logger,
	  enum pluto_exit_code pluto_exit_code, where_t where,
	  const char *fmt, ...);

#endif
