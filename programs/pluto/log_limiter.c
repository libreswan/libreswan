/* log limiter, for libreswan
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

#include <pthread.h>    /* Must be the first include file; XXX: why? */

#include "log_limiter.h"
#include "log.h"

#include "defs.h"
#include "demux.h"

#define RATE_LIMIT 1000

struct limiter {
	pthread_mutex_t mutex;
	const unsigned limit;
	volatile unsigned count;
	const char *what;
};

struct limiter log_limiters[LOG_LIMITER_ROOF] = {
	[MD_LOG_LIMITER] = {
		.limit = RATE_LIMIT,
		.what = "message digest",
	},
	[UNSECURED_LOG_LIMITER] = {
		.limit = RATE_LIMIT,
		.what = "unsecured message",
	},
	[CERTIFICATE_LOG_LIMITER] = {
		.limit = 10,
		.what = "bad certificate",
	},
	[PAYLOAD_ERRORS_LOG_LIMITER] = {
		.what = "payload errors",
		.limit = RATE_LIMIT,
	},
};

static unsigned log_limit(const struct limiter *limiter)
{
	if (impair.log_rate_limit.enabled) {
		return impair.log_rate_limit.value;
	}

	/* --impair log-rate-limit:no */
	return limiter->limit;
}

lset_t log_limiter_rc_flags(struct logger *logger, enum log_limiter log_limiter)
{
	struct limiter *limiter = &log_limiters[log_limiter];

	/* allow imparing to override specified limit */
	unsigned limit = log_limit(limiter);

	enum limiting {
		UNDER_LIMIT,
		AT_LIMIT,
		OVER_LIMIT,
	} limiting;

	pthread_mutex_lock(&limiter->mutex);
	{
		if (limiter->count > limit) {
			limiting = OVER_LIMIT;
		} else if (limiter->count == limit) {
			limiting = AT_LIMIT;
			limiter->count++;
		} else {
			limiting = UNDER_LIMIT;
			limiter->count++;
		}
	}
	pthread_mutex_unlock(&limiter->mutex);

	switch (limiting) {
	case UNDER_LIMIT:
		return RC_LOG;
	case AT_LIMIT:
		llog(RC_LOG, logger,
		     "%s rate limited log reached limit of %u entries",
		     limiter->what, limit);
		return RC_LOG; /* let this one through */
	case OVER_LIMIT:
		return (LDBGP(DBG_BASE, logger) ? DEBUG_STREAM : LEMPTY);
	}

	bad_case(limiting);
}

void limited_llog(struct logger *logger, enum log_limiter log_limiter,
		  const char *format, ...)
{
	lset_t rc_flags = log_limiter_rc_flags(logger, log_limiter);
	if (rc_flags != LEMPTY) {
		va_list ap;
		va_start(ap, format);
		llog_va_list(rc_flags, logger, format, ap);
		va_end(ap);
	}
}

static global_timer_cb reset_log_limiter;	/* type check */

static void reset_log_limiter(struct logger *logger)
{
	FOR_EACH_ELEMENT(limiter, log_limiters) {
		pthread_mutex_lock(&limiter->mutex);
		{
			if (limiter->count > log_limit(limiter)) {
				llog(RC_LOG, logger, "%s rate limited log reset",
				     limiter->what);
			}
			limiter->count = 0;
		}
		pthread_mutex_unlock(&limiter->mutex);
	}
}

void init_log_limiter(struct logger *logger)
{
	PASSERT(logger, elemsof(log_limiters) == LOG_LIMITER_ROOF);
	FOR_EACH_ELEMENT(limiter, log_limiters) {
		ldbg(logger, "initializing limiter %td: %s %u",
		     limiter-log_limiters, limiter->what, limiter->limit);
		PASSERT(logger, limiter->what != NULL);
		PASSERT(logger, limiter->limit > 0);
		pthread_mutex_init(&limiter->mutex, NULL);

	}
	enable_periodic_timer(EVENT_RESET_LOG_LIMITER,
			      reset_log_limiter,
			      RESET_LOG_LIMITER_FREQUENCY);
}
