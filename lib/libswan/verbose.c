/* verbose wrapper around logger
 *
 * Copyright (C) 2025  Andrew Cagney
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

#include "verbose.h"
#include "lswlog.h"

static void jam_vtime_prefix(struct jambuf *buf,
			     const struct verbose *verbose)
{
	jam_logger_prefix(buf, verbose->logger);
	jam(buf, PRI_VERBOSE, pri_verbose(verbose));
}

vtime_t vdbg_start_where(struct verbose *verbose,
			 const char *fmt, ...)
{
	vtime_t start = {0};
	if (verbose->debug ||
	    LDBGP(DBG_CPU_USAGE, verbose->logger)) {
		LLOG_JAMBUF(DEBUG_STREAM, verbose->logger, buf) {
			jam_vtime_prefix(buf, verbose);
			jam_string(buf, " starting ");
			/* FMT, ... */
			va_list ap;
			va_start(ap, fmt);
			jam_va_list(buf, fmt, ap);
			va_end(ap);
		}
		start.time = cputime_start();
	}
	start.level = verbose->level++;
	return start;
}

struct cpu_usage vdbg_stop_where(struct verbose *verbose,
				 const vtime_t *start,
				 const char *fmt, ...)
{
	struct cpu_usage usage = {0};
	verbose->level = start->level;
	if (verbose->debug ||
	    LDBGP(DBG_CPU_USAGE, verbose->logger)) {
		usage = cputime_stop(start->time);
		LLOG_JAMBUF(DEBUG_STREAM, verbose->logger, buf) {
			jam_vtime_prefix(buf, verbose);
			jam(buf, PRI_CPU_USAGE" in ", pri_cpu_usage(usage));
			/* FMT, ... */
			va_list ap;
			va_start(ap, fmt);
			jam_va_list(buf, fmt, ap);
			va_end(ap);
		}
	}
	return usage;
}
