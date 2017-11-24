/*
 * Retransmits, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <stdbool.h>

#include "defs.h"
#include "state.h"
#include "connections.h"
#include "retransmit.h"

#include "monotime.h"
#include "deltatime.h"
#include "timer.h"

#include "log.h"

unsigned long retransmit_count(struct state *st)
{
	retransmit_t *rt = &st->st_retransmit;
	return rt->nr_duplicate_replies + rt->nr_retransmits;
}

/*
 * Update the amount of time to wait, setting it to the delay required
 * after this re-transmit.
 *
 * The equation used is:
 *
 *     COUNT = min(NR_RETRANSMITS, floor(log2(R_TIMEOUT/R_INTERVAL)))
 *     DELAY * 2 ** COUNT
 *
 * Where floor(log2(R_TIMEOUT/R_INTERVAL)) comes from re-aranging:
 *
 *     DELAY*2**NR_RETRANSMITS <= TIMEOUT *
 *
 * Including the initial hardwired delay, the resulting sequence is:
 *
 *     DELAY,
 *     DELAY*1, DELAY*2, DELAY*4, ...,
 *     DELAY*2**floor(log2(TIMEOUT/DELAY)),
 *     DELAY*2**floor(log2(TIMEOUT/DELAY)), ...
 *
 * But all this complexity is avoided by simply doubling delay, and
 * updating it provided it is less than R_TIMEOUT.

 */
static void double_delay(retransmit_t *rt, unsigned long nr_retransmits)
{
	if (nr_retransmits > 0) {
		deltatime_t delay = deltatime_add(rt->delay, rt->delay);
		if (deltatime_cmp(delay, rt->timeout) < 0) {
			rt->delay = delay;
		}
	}
}

/*
 * If there is still space, increment the retransmit counter.
 *
 * Used by the duplicate packet code to cap the number of times
 * duplicate packets are replied to.
 */
bool count_duplicate(struct state *st, unsigned long limit)
{
	retransmit_t *rt = &st->st_retransmit;
	unsigned long nr_retransmits = retransmit_count(st);
	if (nr_retransmits < limit) {
		double_delay(rt, nr_retransmits);
		rt->nr_duplicate_replies++;
		DBG(DBG_RETRANSMITS,
		    DBG_log("#%ld %s: retransmits: duplicate reply %lu + retransmit %lu of duplicate limit %lu (retransmit limit %lu)",
			    st->st_serialno, st->st_state_name,
			    rt->nr_duplicate_replies, rt->nr_retransmits,
			    limit, rt->limit));
		return true;
	} else {
		DBG(DBG_RETRANSMITS,
		    DBG_log("#%ld %s: retransmits: total duplicate replies (%lu) + retransmits (%lu) exceeds duplicate limit %lu (retransmit limit %lu)",
			    st->st_serialno, st->st_state_name,
			    rt->nr_duplicate_replies, +rt->nr_retransmits,
			    limit, rt->limit));
		return false;
	}
}

void clear_retransmits(struct state *st)
{
	retransmit_t *rt = &st->st_retransmit;
	rt->nr_duplicate_replies = 0;
	rt->nr_retransmits = 0;
	rt->limit = 0;
	rt->delay = deltatime(0);
	rt->stop = monotime_epoch;
	rt->timeout = deltatime(0);
	DBG(DBG_RETRANSMITS,
	    DBG_log("#%ld %s: retransmits: cleared",
		    st->st_serialno, st->st_state_name));
}

void start_retransmits(struct state *st, enum event_type type)
{
	struct connection *c = st->st_connection;
	retransmit_t *rt = &st->st_retransmit;
	rt->nr_duplicate_replies = 0;
	rt->nr_retransmits = 0;
	rt->limit = MAXIMUM_RETRANSMITS_PER_EXCHANGE;
	rt->type = type;
	rt->delay = c->r_interval;
	if (IMPAIR(RETRANSMITS)) {
		/*
		 * Speed up impaired retransmits by using DELAY as the
		 * timeout
		 */
		LSWLOG(buf) {
			lswlogs(buf, "IMPAIR RETRANSMITS: scheduling timeout in ");
			lswlog_deltatime(buf, rt->delay);
			lswlogs(buf, " seconds");
		}
		rt->timeout = rt->delay;
	} else {
		rt->timeout = c->r_timeout;
	}
	rt->stop = monotimesum(mononow(), rt->timeout);
	event_schedule(rt->type, rt->delay, st);
	LSWDBGP(DBG_RETRANSMITS, buf) {
		lswlogf(buf, "#%ld %s: retransmits: first event in ",
			st->st_serialno, st->st_state_name);
		lswlog_deltatime(buf, rt->delay);
		lswlogs(buf, " seconds; timeout in ");
		lswlog_deltatime(buf, rt->timeout);
		lswlogf(buf, " seconds; limit of %lu retransmits", rt->limit);
	}
}

/*
 * Determine what to do with this retransmit event; if necessary
 * schedule a further event.
 *
 * This doesn't clear the re-transmit variables when the cap is
 * reached - so that the caller has access to the capped values.
 */

enum retransmit_status retransmit(struct state *st)
{
	retransmit_t *rt = &st->st_retransmit;

	/*
	 * Are re-transmits being impaired:
	 *
	 * - don't send the retransmit packet
	 *
	 * - trigger the retransmit timeout path after the first delay
	 */
	if (IMPAIR(RETRANSMITS)) {
		libreswan_log("suppressing retransmit because IMPAIR_RETRANSMITS is set");
		return RETRANSMIT_IMPAIRED_AND_CAPPED;
	}

	/*
	 * Exceeded limits - timeout or number of retransmits?
	 */
	unsigned long nr_retransmits = retransmit_count(st);
	bool too_many_retransmits = nr_retransmits >= rt->limit;
	monotime_t now = mononow();
	if (too_many_retransmits || monobefore(rt->stop, now)) {
		return RETRANSMIT_CAPPED;
	}

	double_delay(rt, nr_retransmits);
	rt->nr_retransmits++;
	event_schedule(rt->type, rt->delay, st);
	LSWLOG_LOGWHACK(RC_RETRANSMISSION, buf) {
		lswlogf(buf, "%s: retransmission; will wait ",
			st->st_finite_state->fs_name);
		lswlog_deltatime(buf, rt->delay);
		lswlogs(buf, " seconds for response");
	}
	return RETRANSMIT_YES;
}
