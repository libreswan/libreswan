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

#include "lswlog.h"

void jam_logger_rc_prefix(struct jambuf *buf, const struct logger *logger, lset_t rc_flags)
{
	if (rc_flags & NO_PREFIX) {
		return;
	}
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
	enum stream stream = (rc_flags & STREAM_MASK);
	switch (stream) {
	case DEBUG_STREAM:
		jam_string(buf, DEBUG_PREFIX);
		break;
	case PEXPECT_STREAM:
		jam_string(buf, PEXPECT_PREFIX);
		break;
	case ERROR_STREAM:
		break;
	case ALL_STREAMS:
	case LOG_STREAM:
	case WHACK_STREAM:
	case NO_STREAM:
		break;
	}
	if (stream != DEBUG_STREAM ||
	    DBGP(DBG_ADD_PREFIX) ||
	    logger->debugging != LEMPTY) {
		jam_logger_prefix(buf, logger);
	}
}
