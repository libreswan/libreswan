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

#include "ikev2_liveness.h"

static stf_status ikev2_send_livenss_probe(struct state *st)
{
	struct ike_sa *ike = ike_sa(st);
	if (ike == NULL) {
		DBG(DBG_CONTROL,
		    DBG_log("IKE SA does not exist for this child SA - should not happen"));
		DBG(DBG_CONTROL,
		    DBG_log("INFORMATIONAL exchange cannot be sent"));
		return STF_IGNORE;
	}

	/*
	 * XXX: What does it mean to send a liveness probe for a CHILD
	 * SA?  Since the packet contents are empty there's nothing
	 * for the other end to identify which child this is for!
	 *
	 * XXX: See record 'n'_send for how screwed up all this is:
	 * need to pass in the CHILD SA so that it's liveness
	 * timestamp (and not the IKE) gets updated.
	 */
	stf_status e = record_v2_informational_request("liveness probe informational request",
						       ike, st/*sender*/,
						       NULL /* beast master */);
	pstats_ike_dpd_sent++;
	if (e == STF_OK) {
		send_recorded_v2_ike_msg(st, "liveness probe informational request");
		/*
		 * XXX: record 'n' send violates the RFC.  This code should
		 * instead let success_v2_state_transition() deal with things.
		 */
		dbg_v2_msgid(ike, st, "XXX: in %s() hacking around record'n'send bypassing send queue",
			     __func__);
		v2_msgid_update_sent(ike, &ike->sa, NULL /* new exchange */, MESSAGE_REQUEST);
	}
	return e;
}

static bool parent_vanished(struct state *st)
{
	struct connection *c = st->st_connection;
	struct state *pst = state_with_serialno(st->st_clonedfrom);

	if (pst != NULL) {
		if (c != pst->st_connection) {
			char cib1[CONN_INST_BUF];
			char cib2[CONN_INST_BUF];

			fmt_conn_instance(c, cib1);
			fmt_conn_instance(pst->st_connection, cib2);

			DBG(DBG_CONTROLMORE,
				DBG_log("\"%s\"%s #%lu parent connection of this state is diffeent \"%s\"%s #%lu",
					c->name, cib1, st->st_serialno,
					pst->st_connection->name, cib2,
					pst->st_serialno));
		}
		return FALSE;
	}

	loglog(RC_LOG_SERIOUS, "liveness_check error, no IKEv2 parent state #%lu to take %s",
			st->st_clonedfrom,
			enum_name(&dpd_action_names, c->dpd_action));

	return TRUE;
}

/* note: this mutates *st by calling get_sa_info */
void liveness_check(struct state *st)
{
	passert(st->st_ike_version == IKEv2);

	struct state *pst = NULL;
	deltatime_t last_msg_age;

	struct connection *c = st->st_connection;

	set_cur_state(st);

	/* this should be called on a child sa */
	if (IS_CHILD_SA(st)) {
		if (parent_vanished(st)) {
			liveness_action(c, st->st_ike_version);
			return;
		} else {
			pst = state_with_serialno(st->st_clonedfrom);
		}
	} else {
		pexpect(pst == NULL); /* no more dpd in IKE state */
		pst = st;
	}

	pexpect_st_local_endpoint(st);
	address_buf this_buf;
	const char *this_ip = ipstr(&st->st_interface->local_endpoint, &this_buf);
	address_buf that_buf;
	const char *that_ip = ipstr(&st->st_remote_endpoint, &that_buf);

	/*
	 * If we are a lingering (replaced) IPsec SA, don't do liveness
	 */
	if (pst->st_connection->newest_ipsec_sa != st->st_serialno) {
		DBG(DBG_DPD,
		   DBG_log("liveness: no need to send or schedule DPD for replaced IPsec SA"));
		return;
	}

	/*
	 * don't bother sending the check and reset
	 * liveness stats if there has been incoming traffic
	 */
	if (get_sa_info(st, TRUE, &last_msg_age) &&
		deltaless(last_msg_age, c->dpd_timeout)) {
		pst->st_pend_liveness = FALSE;
		pst->st_last_liveness = monotime_epoch;
	} else {
		monotime_t tm = mononow();
		monotime_t last_liveness = pst->st_last_liveness;

		/* ensure that the very first liveness_check works out */
		if (is_monotime_epoch(last_liveness)) {
			pst->st_last_liveness = last_liveness = tm;
			LSWDBGP(DBG_DPD, buf) {
				lswlogf(buf, "#%lu liveness initial timestamp set ",
					st->st_serialno);
				lswlog_monotime(buf, tm);
			}
		}

		LSWDBGP(DBG_DPD, buf) {
			lswlogf(buf, "#%lu liveness_check - last_liveness: ",
				st->st_serialno);
			lswlog_monotime(buf, last_liveness);
			lswlogf(buf, ", now: ");
			lswlog_monotime(buf, tm);
			lswlogf(buf, " parent #%lu", pst->st_serialno);
		}

		deltatime_t timeout = deltatime_max(c->dpd_timeout,
						    deltatime_mulu(c->dpd_delay, 3));

		if (pst->st_pend_liveness &&
		    deltatime_cmp(monotimediff(tm, last_liveness), timeout) >= 0) {
			LSWLOG(buf) {
				lswlogf(buf, "liveness_check - peer %s has not responded in %jd seconds, with a timeout of ",
					log_ip ? that_ip : "<ip address>",
					deltasecs(monotimediff(tm, last_liveness)));
				lswlog_deltatime(buf, timeout);
				lswlogf(buf, ", taking %s",
					enum_name(&dpd_action_names, c->dpd_action));
			}
			liveness_action(c, st->st_ike_version);
			return;
		} else {
			stf_status ret = ikev2_send_livenss_probe(st);

			DBG(DBG_DPD,
				DBG_log("#%lu liveness_check - peer %s is missing - giving them some time to come back",
					st->st_serialno, that_ip));

			if (ret != STF_OK) {
				DBG(DBG_DPD,
					DBG_log("#%lu failed to send liveness informational from %s to %s using parent  #%lu",
						st->st_serialno,
						this_ip,
						that_ip,
						pst->st_serialno));
				return; /* this prevents any new scheduling ??? */
			}
		}
	}

	DBG(DBG_DPD, DBG_log("#%lu liveness_check - peer %s is ok schedule new",
				st->st_serialno, that_ip));
	deltatime_t delay = deltatime_max(c->dpd_delay, deltatime(MIN_LIVENESS));
	event_schedule(EVENT_v2_LIVENESS, delay, st);
}
