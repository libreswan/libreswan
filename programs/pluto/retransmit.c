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
	rt->start = monotime_epoch;
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
	rt->start = mononow();
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
		return RETRANSMITS_TIMED_OUT;
	}

	/*
	 * Exceeded limits - timeout or number of retransmits?
	 */
	unsigned long nr_retransmits = retransmit_count(st);
	bool too_many_retransmits = nr_retransmits >= rt->limit;
	monotime_t now = mononow();
	deltatime_t waited = monotimediff(now, rt->start);
	if (too_many_retransmits || deltatime_cmp(waited, rt->timeout) >= 0) {
		LSWLOG_LOG_WHACK(RC_NORETRANSMISSION, buf) {
			lswlogf(buf, "%s: ", st->st_finite_state->fs_name);
			if (too_many_retransmits) {
				lswlogf(buf, "max number of retransmissions (%lu) reached after ",
					nr_retransmits);
				lswlog_deltatime(buf, waited);
				lswlogs(buf, " seconds");
			} else {
				lswlog_deltatime(buf, rt->timeout);
				lswlogf(buf, " second timeout exceeded after %lu retransmits",
					nr_retransmits);
			}
			switch (st->st_state) {
			case STATE_MAIN_I3:
			case STATE_AGGR_I2:
				lswlogs(buf, ".  Possible authentication failure: no acceptable response to our first encrypted message");
				break;
			case STATE_MAIN_I1:
			case STATE_AGGR_I1:
				lswlogs(buf, ".  No response (or no acceptable response) to our first IKEv1 message");
				break;
			case STATE_QUICK_I1:
				if (st->st_connection->newest_ipsec_sa == SOS_NOBODY) {
					lswlogs(buf, ".  No acceptable response to our first Quick Mode message: perhaps peer likes no proposal");
				}
				break;
			case STATE_PARENT_I2:
				lswlogs(buf, ".  Possible authentication failure: no acceptable response to our first encrypted message");
				break;
			case STATE_PARENT_I1:
				lswlogs(buf, ".  No response (or no acceptable response) to our first IKEv2 message");
				break;
			default:
				lswlogf(buf, ".  No response (or no acceptable response) to our %s message",
					st->st_ikev2 ? "IKEv2" : "IKEv1");
				break;
			}
		}
		return RETRANSMITS_TIMED_OUT;
	}

	double_delay(rt, nr_retransmits);
	rt->nr_retransmits++;
	event_schedule(rt->type, rt->delay, st);
	LSWLOG_LOG_WHACK(RC_RETRANSMISSION, buf) {
		lswlogf(buf, "%s: retransmission; will wait ",
			st->st_finite_state->fs_name);
		lswlog_deltatime(buf, rt->delay);
		lswlogs(buf, " seconds for response");
	}
	return RETRANSMIT_YES;
}
