/* IKEv2 LIVENESS probe
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2005-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
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
#include "log.h"
#include "connections.h"
#include "iface.h"
#include "kernel.h"
#include "ikev2_send.h"
#include "pluto_stats.h"
#include "timer.h"
#include "server.h"
#include "ikev2.h"			/* for struct state_v2_microcode */
#include "ikev2_liveness.h"
#include "state_db.h"			/* for state_by_serialno() */
#include "ikev2_states.h"

static stf_status send_v2_liveness_request(struct ike_sa *ike,
					   struct child_sa *child UNUSED,
					   struct msg_digest *md UNUSED)
{
	/*
	 * XXX: What does it mean to send a liveness probe for a CHILD
	 * SA?  Since the packet contents are empty there's nothing
	 * for the other end to identify which child this is for!
	 *
	 * XXX: See record 'n'_send for how screwed up all this is:
	 * need to pass in the CHILD SA so that it's liveness
	 * timestamp (and not the IKE) gets updated.
	 */
	pstats_ike_dpd_sent++;
	stf_status e = record_v2_informational_request("liveness probe informational request",
						       ike, &ike->sa/*sender*/,
						       NULL/*no payloads to emit*/);
	if (e != STF_OK) {
		return STF_INTERNAL_ERROR;
	}
	return STF_OK;
}

static void schedule_liveness(struct child_sa *child, deltatime_t time_since_last_contact,
			      const char *reason)
{
	struct connection *c = child->sa.st_connection;
	deltatime_t delay = c->dpd_delay;
	/* reduce wait if contact was by some other means */
	delay = deltatime_sub(delay, time_since_last_contact);
	/* in case above screws up? */
	delay = deltatime_max(c->dpd_delay, deltatime(MIN_LIVENESS));
	LSWDBGP(DBG_BASE, buf) {
		deltatime_buf db;
		endpoint_buf remote_buf;
		jam(buf, "liveness: #%lu scheduling next check for %s in %s seconds",
		    child->sa.st_serialno,
		    str_endpoint(&child->sa.st_remote_endpoint, &remote_buf),
		    str_deltatime(delay, &db));
		if (deltatime_cmp(time_since_last_contact, !=, deltatime(0))) {
			deltatime_buf lcb;
			jam(buf, " (%s was %s seconds ago)",
			    reason, str_deltatime(time_since_last_contact, &lcb));
		} else {
			jam(buf, " (%s)", reason);
		}
	}
	event_schedule(EVENT_v2_LIVENESS, delay, &child->sa);
}

/* note: this mutates *st by calling get_sa_info */
void liveness_check(struct state *st)
{
	passert(st->st_ike_version == IKEv2);
	struct state *pst = state_by_serialno(st->st_clonedfrom);
	if (pst == NULL) {
		/*
		 * When the retransmits timeout the IKE SA gets
		 * deleted, but not the child.
		 *
		 * XXX: might need to tone this down.
		 */
		dbg("liveness: state #%lu has no IKE SA; deleting orphaned child",
		    st->st_serialno);
		event_delete(EVENT_SO_DISCARD, st);
		event_schedule(EVENT_SO_DISCARD, deltatime(0), st);
		return;
	}
	struct ike_sa *ike = pexpect_ike_sa(pst);

	struct child_sa *child = pexpect_child_sa(st);
	if (child == NULL) {
		return;
	}
	struct connection *c = child->sa.st_connection;
	struct v2_msgid_window *our = &ike->sa.st_v2_msgid_windows.initiator;
	/* if nothing else this is when the state was created */
	pexpect(!is_monotime_epoch(our->last_contact));
	monotime_t now = mononow();

	/*
	 * If the child is lingering (replaced but not yet deleted),
	 * don't do liveness.
	 */
	if (c->newest_ipsec_sa != child->sa.st_serialno) {
		dbg("liveness: #%lu was replaced by #%lu so not needed",
		    child->sa.st_serialno, c->newest_ipsec_sa);
		return;
	}

	/*
	 * If there's been traffic flowing through the CHILD SA and it
	 * was less than .dpd_delay ago then re-schedule the probe.
	 *
	 * XXX: is this useful?  Liveness should be checking
	 * round-trip but this is just looking at incoming data -
	 * outgoing data could lost and this traffic is all
	 * re-transmit requests ...
	 */
	deltatime_t time_since_last_message;
	if (get_sa_info(&child->sa, true, &time_since_last_message) &&
	    /* time_since_last_message < .dpd_delay */
	    deltatime_cmp(time_since_last_message, <, c->dpd_delay)) {
		/*
		 * Update .st_liveness_last, with the time of this
		 * traffic (unless other traffic is more recent).
		 */
		monotime_t last_contact = monotime_sub(now, time_since_last_message);
		if (monobefore(our->last_contact, last_contact)) {
			monotime_buf m0, m1;
			dbg("liveness: #%lu updating #%lu last contact from %s to %s (last IPsec traffic flow)",
			    child->sa.st_serialno, ike->sa.st_serialno,
			    str_monotime(our->last_contact, &m0),
			    str_monotime(last_contact, &m1));
			our->last_contact = last_contact;
		}
		/*
		 * schedule in .dpd_delay seconds, but adjust for:
		 * time since last traffic, and min liveness vis
		 *
		 * max(dpd_delay - time_since_last_message, * deltatime(MIN_LIVENESS))
		 */
		schedule_liveness(child, time_since_last_message, "recent IPsec traffic");
		return;
	}

	/*
	 * If there's already a message request outstanding assume it
	 * will succeed - if it doesn't the entire family will be
	 * killed.
	 *
	 * No probe is needed for another .dpd_delay seconds.
	 */
	if (v2_msgid_request_outstanding(ike)) {
		schedule_liveness(child, deltatime(0), "request outstanding");
		return;
	}

	/*
	 * If there's an exchange pending; assume it will succeed (for
	 * instance last exchange just finished, next exchange about
	 * to start), reschedule the probe.
	 */
	if (v2_msgid_request_pending(ike)) {
		schedule_liveness(child, deltatime(0), "request pending");
		return;
	}

	/*
	 * If was a successful exchange less than .dpd_delay ago,
	 * reschedule the probe.
	 */
	deltatime_t time_since_last_contact = monotimediff(now, our->last_contact);
	if (deltatime_cmp(time_since_last_contact, <, c->dpd_delay)) {
		schedule_liveness(child, time_since_last_contact, "successful exchange");
		return;
	}

	endpoint_buf remote_buf;
	struct state *handler = &ike->sa;
	dbg("liveness: #%lu queueing liveness probe for %s using #%lu",
	    child->sa.st_serialno,
	    str_endpoint(&child->sa.st_remote_endpoint, &remote_buf),
	    handler->st_serialno);
	initiate_v2_liveness(child->sa.st_logger, ike);

	/* in case above screws up? */
	schedule_liveness(child, deltatime(0), "backup for liveness probe");
}

/*
 * XXX: where to put this?
 */

static const struct state_v2_microcode v2_liveness_probe = {
	.story = "liveness probe",
	.state = STATE_V2_ESTABLISHED_IKE_SA,
	.next_state = STATE_V2_ESTABLISHED_IKE_SA,
	.send = MESSAGE_REQUEST,
	.processor = send_v2_liveness_request,
	.timeout_event =  EVENT_RETAIN,
	.flags = SMF2_SUPPRESS_SUCCESS_LOG,
};

void initiate_v2_liveness(struct logger *logger, struct ike_sa *ike)
{
	const struct state_v2_microcode *transition = &v2_liveness_probe;
	if (ike->sa.st_state->kind != transition->state) {
		log_message(RC_LOG, logger,
			    "liveness: #%lu unexpectedly in state %s; should be %s",
			    ike->sa.st_serialno, ike->sa.st_state->short_name,
			    finite_states[transition->state]->short_name);
		return;
	}

	v2_msgid_queue_initiator(ike, &ike->sa, ISAKMP_v2_INFORMATIONAL,
				 transition, NULL);
}
