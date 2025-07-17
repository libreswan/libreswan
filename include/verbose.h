/* verbose wrapper around logger
 *
 * Copyright (C) 2024  Andrew Cagney
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

#ifndef VERBOSE_H
#define VERBOSE_H

#include "where.h"
#include "pluto_constants.h"	/* for enum stream; */

/*
 * Pass-by-value wrapper around logger to make it easy to generate
 * indented debug/verbose logs.
 *
 * Standalone tools, such as <<ipsec showroute>>, can enable more
 * verbose logging when --verbose is specified, vis:
 *
 *	struct verbose verbose = VERBOSE(LOG_STREAM, logger, NULL);
 *
 * While pluto, internally, enables more verbose debug logging:
 *
 *	struct verbose verbose = VERBOSE(DEBUG_STREAM, logger, NULL);
 *
 * Functions then pass verbose by value, and increment .level as
 * needed.
 */

struct verbose {
	const struct logger *logger;
	enum stream stream;
	int level;
	const char *prefix;
	where_t where;
};

/*
 * The verbose() function is configured using VERBOSE(STREAM, LOGGER,
 * PREFIX):
 *
 *   VERBOSE(NO_STREAM, logger, prefix):
 *
 *     With NO_STREAM, verbose() does not emit any output.
 *
 *   VERBOSE(DEBUG_STREAM, logger, prefix):
 *
 *     With DEBUG_STREAM, and provided DBG_BASE debugging is enabled,
 *     verbose() emits a debug-log with PREFIX and indentation
 *     prepended.
 *
 *     i.e., verbose() and vdbg() become identical
 *
 *   VERBOSE(RC_LOG, logger, prefix):
 *   VERBOSE(LOG_STREAM, logger, prefix):
 *
 *     With some other stream, verbose() emits the log message with
 *     PREFIX and indentation prepended using that stream.
 *
 * The other functions are not affected by VERBOSE()'s STREAM/RC
 * parameter:
 *
 *   vdbg(): provided DBG_BASE debugging is enabled, emits a debug-log
 *   with with both PREFIX and indentation prepended (else nothing is
 *   emitted)
 *
 *   vlog(), vfatal(), et.al.: emits a log message using RC_LOG with
 *   NO PREFIX and NO indentation (i.e., a shortcut for llog(RC_LOG,
 *   verbose.logger, ...).
 *
 */

#define VERBOSE(STREAM, LOGGER, PREFIX)					\
	{								\
		.logger = LOGGER,					\
			.prefix = PREFIX,				\
			.stream = (STREAM != DEBUG_STREAM ? STREAM :	\
				   LDBGP(DBG_BASE, LOGGER) ? DEBUG_STREAM : \
				   NO_STREAM),				\
			.where = HERE,					\
			}

/*
 * Format the prefix, handle poorly constructed struct verbose.
 */

#define PRI_VERBOSE "%s%s%*s"
#define pri_verbose \
	(verbose.prefix == NULL ? "" : verbose.prefix), \
		(verbose.prefix == NULL ? "" : ": "),	\
		(verbose.level * 2), ""

/*
 * Normal logging: the message is always logged (no indentation); just
 * a wrapper around llog(verbose.logger)
 *
 * vfatal() and verror(), like perror() add ": ", before FMT when
 * ERRNO is non-zero.
 */

#define vlog(FMT, ...)						\
	llog(RC_LOG, verbose.logger, FMT, ##__VA_ARGS__)

#define VLOG_JAMBUF(BUF)				\
	LLOG_JAMBUF(RC_LOG, verbose.logger, BUF)

#define vlog_errno(ERRNO, FMT, ...)					\
	llog_errno(RC_LOG, verbose.logger, ERRNO, FMT, ##__VA_ARGS__)

#define vlog_pexpect(WHERE, FMT, ...)				\
	llog_pexpect(verbose.logger, WHERE, FMT, ##__VA_ARGS__)

#define vlog_passert(WHERE, FMT, ...)				\
	llog_passert(verbose.logger, WHERE, FMT, ##__VA_ARGS__)

#define vwarning(FMT, ...)						\
	llog(WARNING_STREAM, verbose.logger, FMT, ##__VA_ARGS__)

#define verror(ERROR, FMT, ...)					\
	llog_error(verbose.logger, ERROR, FMT, ##__VA_ARGS__)

#define vfatal(EXIT_CODE, ERRNO, FMT, ...)				\
	fatal(EXIT_CODE, verbose.logger, ERRNO, FMT, ##__VA_ARGS__)

#define vbad(BAD) PBAD(verbose.logger, BAD)

#define vexpect(EXPECT) PEXPECT_WHERE(verbose.logger, verbose.where, EXPECT)
#define vassert(ASSERT) PASSERT_WHERE(verbose.logger, verbose.where, ASSERT)

#define vexpect_where(WHERE, EXPECT) PEXPECT_WHERE(verbose.logger, WHERE, EXPECT)
#define vassert_where(WHERE, ASSERT) PASSERT_WHERE(verbose.logger, WHERE, ASSERT)

/*
 * Debug-logging: when the logger has debugging enabled, the message
 * is logged, prefixed by indentation.
 *
 * These all have the same feel as the LDBG*() series.
 */

#define VDBGP()	LDBGP(DBG_BASE, verbose.logger)

#define vdbg(FMT, ...)							\
	{								\
		if (VDBGP()) {						\
			VDBG_log(FMT, ##__VA_ARGS__);			\
		}							\
	}

#define VDBG_log(FMT, ...)			\
	llog(DEBUG_STREAM, verbose.logger,	\
	     PRI_VERBOSE""FMT,			\
	     pri_verbose, ##__VA_ARGS__)

#define vdbg_errno(ERRNO, FMT, ...)				\
	{							\
		if (VDBGP()) {					\
			VDBG_errno(errno_, FMT, ##__VA_ARGS__);	\
		}						\
	}

#define VDBG_errno(ERRNO, FMT, ...)					\
	{								\
		int errno_ = ERRNO; /* save value across va args */	\
		llog_errno(DEBUG_STREAM, verbose.logger, errno_,	\
			   PRI_VERBOSE""FMT,				\
			   pri_verbose, ##__VA_ARGS__);			\
	}

#define VDBG_JAMBUF(BUF)						\
	for (bool cond_ = VDBGP(); cond_; cond_ = false)		\
		LLOG_JAMBUF(DEBUG_STREAM, verbose.logger, BUF)		\
			for (jam(BUF, PRI_VERBOSE, pri_verbose);	\
			     cond_; cond_ = false)

/*
 * Informational log: when verbose.rc_info is non-zero, the message is
 * logged, prefixed by indentation.
 *
 * Use this for messages that, depending on the caller, should be
 * suppressed, pretty-logged or pretty-debug-logged.
 *
 * XXX: handle poorly constructed struct verbose.
 */

#define verbose(FMT, ...)						\
	{								\
		if (verbose.stream != 0 &&				\
		    verbose.stream != NO_STREAM) {			\
			llog(verbose.stream, verbose.logger,		\
			     PRI_VERBOSE""FMT,				\
			     pri_verbose, ##__VA_ARGS__);		\
		}							\
	}

#define VERBOSE_JAMBUF(BUF)						\
	for (bool cond_ = (verbose.stream != NO_STREAM);		\
	     cond_; cond_ = false)					\
		LLOG_JAMBUF(verbose.stream, verbose.logger, BUF)	\
			for (jam(BUF, PRI_VERBOSE, pri_verbose);	\
			     cond_; cond_ = false)

#endif
