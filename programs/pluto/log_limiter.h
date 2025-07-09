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

#include "lswcdefs.h"
#include "lset.h"

struct msg_digest;
struct logger;

/*
 * rate limited logging
 */

enum log_limiter {
	MD_LOG_LIMITER,
	UNSECURED_LOG_LIMITER,
	CERTIFICATE_LOG_LIMITER,
	MSG_ERRQUEUE_LOG_LIMITER,
	PAYLOAD_ERRORS_LOG_LIMITER,
#define LOG_LIMITER_ROOF (PAYLOAD_ERRORS_LOG_LIMITER+1)
};

/*
 * Returns the stream to use (either RC_LOG or DEBUG_STREAM), or when
 * over limit has been exceeded, NO_STREAM.  For instance:
 *
 *    enum stream stream = log_limiter_stream(logger, MD_LOG_LIMITER);
 *    if (stream != NO_STREAM) {
 *        llog(stream, logger, "a log-limited message");
 *    }
 *
 */

enum stream log_limiter_stream(struct logger *logger, enum log_limiter limiter);

void limited_llog(struct logger *logger, enum log_limiter limiter,
		  const char *format, ...) PRINTF_LIKE(3);

void init_log_limiter(struct logger *logger);

#endif
