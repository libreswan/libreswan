/* log limiter, for libreswan's pluto
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
 */

#ifndef LOG_LIMITER_H
#define LOG_LIMITER_H

#include "lset.h"

struct msg_digest;
struct logger;

/*
 * rate limited logging
 */

enum log_limiter {
	MD_LOG_LIMITER,
	CERTIFICATE_LOG_LIMITER,
#define LOG_LIMITER_ROOF (CERTIFICATE_LOG_LIMITER+1)
};

/*
 * Returns non-LEMPTY RC_FLAGS (either RC_LOG, or DEBUG_STREAM) when
 * the message should be logged.  For instance:
 *
 *    lset_t rc_flags = log_limiter_rc_flags(logger, MD_LOG_LIMITER);
 *    if (rc_flags != LEMPTY) {
 *        llog(rc_flags, logger, "a log-limited message");
 *    }
 *
 */

lset_t log_limiter_rc_flags(struct logger *logger, enum log_limiter limiter);

void init_log_limiter(struct logger *logger);

#endif
