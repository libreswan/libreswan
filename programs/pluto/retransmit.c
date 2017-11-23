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
 * If there is still space, increment the retransmit counter.
 *
 * Used by the duplicate packet code to cap the number of times
 * duplicate packets are replied to.
 */
bool count_duplicate(struct state *st, unsigned long limit)
{
	retransmit_t *rt = &st->st_retransmit;
	if (retransmit_count(st) < limit) {
		rt->nr_duplicate_replies++;
		DBG(DBG_RETRANSMITS,
		    DBG_log("#%ld %s: retransmits: duplicate reply %lu + retransmit %lu of duplicate limit %lu (retransmit limit %lu)",
			    st->st_serialno, enum_name(&state_names, st->st_state),
			    rt->nr_duplicate_replies, rt->nr_retransmits,
			    limit, rt->limit));
		return true;
	} else {
		DBG(DBG_RETRANSMITS,
		    DBG_log("#%ld %s: retransmits: total duplicate replies (%lu) + retransmits (%lu) exceeds duplicate limit %lu (retransmit limit %lu)",
			    st->st_serialno, enum_name(&state_names, st->st_state),
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
	rt->timeout = monotime_epoch;
	DBG(DBG_RETRANSMITS,
	    DBG_log("#%ld %s: retransmits: cleared",
		    st->st_serialno, enum_name(&state_names, st->st_state)));
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
		rt->timeout = monotimesum(mononow(), rt->delay);
	} else {
		rt->timeout = monotimesum(mononow(), c->r_timeout);
	}
	event_schedule(rt->type, rt->delay, st);
	LSWDBGP(DBG_RETRANSMITS, buf) {
		lswlogf(buf, "#%ld %s: retransmits: first event in ",
			st->st_serialno, enum_name(&state_names, st->st_state));
		lswlog_deltatime(buf, rt->delay);
		lswlogs(buf, " seconds; cap: ");
		lswlog_deltatime(buf, c->r_timeout);
		lswlogf(buf, " seconds; limit: %lu retransmits", rt->limit);
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
	struct connection *c = st->st_connection;
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
	 * Exceeded limit?
	 *
	 * XXX: The count is updated _after_ the value is read (the
	 * original code used post increment).  This, combined with
	 * code below computing the delay using the retransmit count,
	 * results in to a delay sequence of DELAY, DELAY(*1),
	 * DELAY*2, DELAY*4, ...  It isn't clear if this was
	 * intentional.
	 */
	unsigned long nr_retransmits = retransmit_count(st);
	rt->nr_retransmits++; /* "post increment" */
	if (nr_retransmits >= rt->limit) {
		DBG(DBG_RETRANSMITS,
		    DBG_log("#%ld %s: retransmits: capped as retransmit limit %lu exceeded (%lu duplicate replies + %lu retransmits)",
			    st->st_serialno, enum_name(&state_names, st->st_state),
			    rt->limit, rt->nr_duplicate_replies, nr_retransmits));
		return RETRANSMIT_CAPPED;
	}

	/*
	 * Calculate the delay.
	 *
	 * Because the retries counter can be changed by both a retry
	 * and a duplicate, re-compute the necessary delay each time vis:
	 *
	 *    DELAY * 2**nr_retransmits
	 *
	 * However, because of the post increment above, the value
	 * used is off by one and the actual delay sequence is DELAY,
	 * DELAY(*1), DELAY*2, DELAY*4, ...
	 *
	 * XXX: The below performs the exponent using timeradd() 'cos
	 * it is easy and has more precision than using an integer;
	 * beside there are at most 12 operations.
	 *
	 * XXX: Shouldn't the implicit delay==0 check have been
	 * performed earlier; is it even needed?
	 *
	 * XXX: The r_timeout comparison looks wrong.  It should be
	 * comparing "now"-"start" >= r_timeout.  That way a 2 minute
	 * limit means a two minute limit, not something else.
	 *
	 * XXX: The delay should be allowed to grow expotentally;
	 * instead just let it grow to some value and then keep
	 * re-using that.
	 */
	rt->delay = c->r_interval;
	if (deltatime_cmp(rt->delay, deltatime(0)) == 0) {
		DBG(DBG_RETRANSMITS,
		    DBG_log("#%ld %s: retransmits: capped as interval is zero!?!",
			    st->st_serialno, enum_name(&state_names, st->st_state)));
		return RETRANSMIT_CAPPED;
	}
	for (unsigned long i = 0; i < nr_retransmits; i++) {
		rt->delay = deltatime_add(rt->delay, rt->delay);
		if (deltatime_cmp(c->r_timeout, deltatime(0)) > 0 &&
		    deltatime_cmp(rt->delay, c->r_timeout) >= 0) {
			/*
			 * XXX: This is the wrong comparision, it
			 * should be checking "now" - "start" >=
			 * r_timeout.
			 */
			LSWDBGP(DBG_RETRANSMITS, buf) {
				lswlogf(buf, "#%ld %s: retransmits: delay exceeded timeout ",
					st->st_serialno, enum_name(&state_names, st->st_state));
				lswlog_deltatime(buf, c->r_timeout);
			}
			return RETRANSMIT_CAPPED;
		}
	}

	event_schedule(rt->type, rt->delay, st);
	LSWLOG_LOGWHACK(RC_RETRANSMISSION, buf) {
		lswlogf(buf, "%s: retransmission; will wait ",
			st->st_finite_state->fs_name);
		lswlog_deltatime(buf, rt->delay);
		lswlogs(buf, " seconds for response");
	}
	return RETRANSMIT_YES;
}
