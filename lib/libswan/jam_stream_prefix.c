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

/* XXX: The message format is:
 *   FATAL ERROR: <log-prefix><message...><diag>
 *   EXPECTATION FAILED: <log-prefix><message...><diag>
 *   | <log-prefix><message...><diag>
 * and not:
 *   <log-prefix>FATAL ERROR: <message...><diag>
 *   <log-prefix>| <message...><diag>
 *   <log-prefix>EXPECTATION_FAILED: <message...><diag>
 * say
 */

void jam_stream_prefix(struct jambuf *buf, const struct logger *logger, enum stream stream)
{
	switch (stream) {
	case PRINTF_STREAM:
	case NO_STREAM:
		/* suppress all prefixes */
		return;
	case DEBUG_STREAM:
		jam_string(buf, DEBUG_PREFIX);
		/* add prefix when enabled */
		if (LDBGP(DBG_ADD_PREFIX, logger) ||
		    logger->debugging != LEMPTY) {
			jam_logger_prefix(buf, logger);
		}
		return;
	case PEXPECT_STREAM:
		jam_string(buf, PEXPECT_PREFIX);
		jam_logger_prefix(buf, logger);
		return;
	case PASSERT_STREAM:
		jam_string(buf, PASSERT_PREFIX);
		jam_logger_prefix(buf, logger);
		return;
	case FATAL_STREAM:
		jam_string(buf, FATAL_PREFIX);
		jam_logger_prefix(buf, logger);
		return;
	case ERROR_STREAM:
	case ALL_STREAMS:
	case LOG_STREAM:
	case WHACK_STREAM:
		jam_logger_prefix(buf, logger);
		return;
	}

	abort(); /* not passert as goes recursive */
}
