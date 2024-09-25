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

/*
 * Pass-by-value wrapper around logger to make it easy to generate
 * indented debug/verbose logs.
 *
 * Standalone tools, such as <<ipsec showroute>>, can enable more
 * verbose logging when --verbose is specified, vis:
 *
 *	struct verbose verbose = {
 *		.logger = logger,
 *		.rc_flags = (verbose ? LOG_STREAM : 0),
 *	};
 *
 * While pluto, internally, enables more verbose debug logging:
 *
 *	struct verbose verbose = {
 *		.logger = logger,
 *		.rc_flags = (DBGP(DBG_BASE) ? DEBUG_STREAM : 0),
 *	};
 *
 * Functions then pass verbose by value, and increment .level as
 * needed.
 */

#include "lset.h"

struct verbose {
	const struct logger *logger;
	lset_t rc_flags;
	int level;
};

#define VERBOSE_LOG(LOGGER, MESSAGE, ...)		\
	struct verbose verbose = {			\
		.logger = (LOGGER),			\
		.rc_flags = RC_LOG,			\
	};						\
	verbose(MESSAGE, ##__VA_ARGS__);		\
	verbose.level++;

#define VERBOSE_DBGP(COND, LOGGER, MESSAGE, ...)			\
	struct verbose verbose = {					\
		.logger = (LOGGER),					\
		.rc_flags = (LDBGP(COND, LOGGER) ? DEBUG_STREAM : 0),	\
	};								\
	verbose("%s() "MESSAGE, __func__, ##__VA_ARGS__);		\
	verbose.level++;

#define PRI_VERBOSE "%*s"
#define pri_verbose (verbose.level * 2), ""

/*
 * Normal logging: the message is always logged (no indentation); just
 * a wrapper around llog(verbose.logger)
 */
#define vlog(FMT, ...)					\
	llog(RC_LOG, verbose.logger, FMT, ##__VA_ARGS__);

/*
 * Debug-logging: when the logger has debugging enabled, the message is
 * logged, prefixed by indentation.
 */

#define vdbg(FMT, ...)							\
	{								\
		if (LDBGP(DBG_BASE, verbose.logger)) {			\
			llog(DEBUG_STREAM, verbose.logger,		\
			     PRI_VERBOSE""FMT,				\
			     pri_verbose, ##__VA_ARGS__);		\
		}							\
	}

/*
 * Informational log: when verbose.rc_info is non-zero, the message is
 * logged, prefixed by indentation.
 *
 * Use this for messages that, depending on the caller, should be
 * supressed, pretty-logged or pretty-debug-logged.
 */

#define verbose(FMT, ...)							\
	{								\
		if (verbose.rc_flags != 0) {				\
			llog(verbose.rc_flags, verbose.logger,		\
			     PRI_VERBOSE""FMT,				\
			     pri_verbose, ##__VA_ARGS__);		\
		}							\
	}

#define vbad(BAD) PBAD(verbose.logger, BAD)
#define vexpect(EXPECT) PEXPECT(verbose.logger, EXPECT)
#define vassert(ASSERT) PASSERT(verbose.logger, ASSERT)

#endif
