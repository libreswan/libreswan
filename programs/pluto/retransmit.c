/*
 * Retransmits, for libreswan
 *
 * Copyright (C) 2017-2018 Andrew Cagney
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

#include "defs.h"
#include "state.h"
#include "connections.h"
#include "retransmit.h"
#include "monotime.h"
#include "deltatime.h"
#include "server.h"
#include "log.h"
#include "iface.h"

#define dbg_retransmit(ST, FMT, ...)				\
	{							\
		dbg("#%ld %s: retransmits: "FMT,		\
		    st->st_serialno, st->st_state->name,	\
		    ##__VA_ARGS__);				\
	}

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
		if (deltatime_cmp(delay, <, rt->timeout)) {
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
		dbg_retransmit(st, "duplicate reply %lu + retransmit %lu of duplicate limit %lu (retransmit limit %lu)",
			       rt->nr_duplicate_replies, rt->nr_retransmits,
			       limit, rt->limit);
		return true;
	} else {
		dbg_retransmit(st, "total duplicate replies (%lu) + retransmits (%lu) exceeds duplicate limit %lu (retransmit limit %lu)",
			       rt->nr_duplicate_replies, +rt->nr_retransmits,
			       limit, rt->limit);
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
	event_delete(EVENT_RETRANSMIT, st);
	dbg_retransmit(st, "cleared");
}

void start_retransmits(struct state *st)
{
	struct connection *c = st->st_connection;
	retransmit_t *rt = &st->st_retransmit;
	rt->nr_duplicate_replies = 0;
	rt->nr_retransmits = 0;
	rt->limit = MAXIMUM_RETRANSMITS_PER_EXCHANGE;
	/* correct values */
	rt->timeout = c->r_timeout;
	rt->delay = c->r_interval;
	if (impair.suppress_retransmits) {
		/*
		 * Suppress retransmits by using the full TIMEOUT as
		 * the delay.
		 *
		 * Use this to stop retransmits in the middle of an
		 * operation that is expected to be slow (and the
		 * network is assumed to be reliable).
		 */
		rt->delay = c->r_timeout;
		deltatime_buf db;
		log_state(RC_LOG, st, "IMPAIR: suppressing retransmits; scheduling timeout in %s seconds",
			  str_deltatime(rt->delay, &db));
	}
	rt->start = mononow();
	rt->delays = rt->delay;
	event_schedule(EVENT_RETRANSMIT, rt->delay, st);
	deltatime_buf db, tb;
	monotime_buf mb;
	dbg_retransmit(st, "first event in %s seconds; timeout in %s seconds; limit of %lu retransmits; current time is %s",
		       str_deltatime(rt->delay, &db),
		       str_deltatime(rt->timeout, &tb),
		       rt->limit,
		       str_monotime(rt->start, &mb));
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
	if (impair.timeout_on_retransmit) {
		log_state(RC_LOG, st, "IMPAIR: retransmit so timing out SA (may retry)");
		return RETRANSMITS_TIMED_OUT;
	}
	if (impair.delete_on_retransmit) {
		log_state(RC_LOG, st, "IMPAIR: retransmit so deleting SA");
		return DELETE_ON_RETRANSMIT;
	}

	if (st->st_interface->protocol == &ip_protocol_tcp) {
		log_state(RC_LOG, st, "TCP: retransmit skipped because TCP is handling retransmits");
		return RETRANSMIT_NO;
	}

	/*
	 * Exceeded limits - timeout or number of retransmits?
	 *
	 * There seems to be a discrepancy between monotime() and
	 * event-loop time that causes a 15s timer to expire after
	 * only 14.964s!  Get around this by comparing both the
	 * accumulated delays (aka deltatime) and the monotime
	 * differeance against the timeout.
	 *
	 * One working theory as to the cause is that monotime uses
	 * CLOCK_BOOTTIME (and/or CLOCK_MONOTONIC), while the
	 * event-loop library is still using gettimeofday.
	 */
	monotime_t now = mononow();
	unsigned long nr_retransmits = retransmit_count(st);
	bool retransmit_count_exceeded = nr_retransmits >= rt->limit;
	bool deltatime_exceeds_limit = deltatime_cmp(rt->delays, >=, rt->timeout);
	deltatime_t waited = monotimediff(now, rt->start);
	bool monotime_exceeds_limit = deltatime_cmp(waited, >=, rt->timeout);
	monotime_buf mb;

	dbg_retransmit(st, "current time %s", str_monotime(now, &mb));
	/* number of packets so far */
	dbg_retransmit(st, "retransmit count %lu exceeds limit? %s", nr_retransmits,
		       retransmit_count_exceeded ? "YES" : "NO");
	/* accumulated delay (ignores timewarp) */
	deltatime_buf dt;
	dbg_retransmit(st, "deltatime %s  exceeds limit? %s",
		       str_deltatime(rt->delays, &dt),
		       deltatime_exceeds_limit ? "YES" : "NO");
	/* waittime, perhaps went to sleep but can warp */
	deltatime_buf wb;
	dbg_retransmit(st, "monotime %s exceeds limit? %s",
		       str_deltatime(waited, &wb),
		       monotime_exceeds_limit ? "YES" : "NO");

	if (retransmit_count_exceeded ||
	    monotime_exceeds_limit ||
	    deltatime_exceeds_limit) {
		LLOG_JAMBUF(RC_NORETRANSMISSION, st->st_logger, buf) {
			jam(buf, "%s: ", st->st_state->name);
			if (retransmit_count_exceeded) {
				jam(buf, "max number of retransmissions (%lu) reached after ",
					nr_retransmits);
				jam_deltatime(buf, waited);
				jam_string(buf, " seconds");
			} else {
				jam_deltatime(buf, rt->timeout);
				jam(buf, " second timeout exceeded after %lu retransmits",
					nr_retransmits);
			}
			switch (st->st_state->kind) {
#ifdef USE_IKEv1
			case STATE_MAIN_I3:
			case STATE_AGGR_I2:
				jam_string(buf, ".  Possible authentication failure: no acceptable response to our first encrypted message");
				break;
			case STATE_MAIN_I1:
			case STATE_AGGR_I1:
				jam_string(buf, ".  No response (or no acceptable response) to our first IKEv1 message");
				break;
			case STATE_QUICK_I1:
				if (st->st_connection->newest_ipsec_sa == SOS_NOBODY) {
					jam_string(buf, ".  No acceptable response to our first Quick Mode message: perhaps peer likes no proposal");
				}
				break;
#endif
			case STATE_PARENT_I2:
				jam_string(buf, ".  Possible authentication failure: no acceptable response to our first encrypted message");
				break;
			case STATE_PARENT_I1:
				jam_string(buf, ".  No response (or no acceptable response) to our first IKEv2 message");
				break;
			default:
				jam(buf, ".  No response (or no acceptable response) to our %s message",
					enum_name(&ike_version_names, st->st_ike_version));
				break;
			}
		}
		return RETRANSMITS_TIMED_OUT;
	}

	double_delay(rt, nr_retransmits);
	rt->nr_retransmits++;
	rt->delays = deltatime_add(rt->delays, rt->delay);
	event_schedule(EVENT_RETRANSMIT, rt->delay, st);
	LLOG_JAMBUF(RC_RETRANSMISSION, st->st_logger, buf) {
		jam(buf, "%s: retransmission; will wait ",
			st->st_state->name);
		jam_deltatime(buf, rt->delay);
		jam_string(buf, " seconds for response");
	}
	return RETRANSMIT_YES;
}

void suppress_retransmits(struct state *st)
{
	retransmit_t *rt = &st->st_retransmit;
	if (rt->limit == 0) {
		dbg_retransmit(st, "no retransmits to suppress");
		return;
	}

	monotime_t now = mononow();
	rt->delay = monotimediff(monotime_add(rt->start, rt->timeout), now);
	rt->delays = deltatime_add(rt->delays, rt->delay);
	event_delete(EVENT_RETRANSMIT, st);
	event_schedule(EVENT_RETRANSMIT, rt->delay, st);
	LLOG_JAMBUF(RC_RETRANSMISSION, st->st_logger, buf) {
		jam(buf, "%s: suppressing retransmits; will wait ",
			st->st_state->name);
		jam_deltatime(buf, rt->delay);
		jam_string(buf, " seconds for retry");
	}
}
