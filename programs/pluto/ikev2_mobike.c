/* IKEv2 Mobile IKE (MOBIKE), for Libreswan
 *
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010-2019 Tuomo Soini <tis@foobar.fi
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2018 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017-2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2017-2018 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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

#include "defs.h"

#include "state.h"
#include "log.h"
#include "demux.h"
#include "connections.h"
#include "ikev2_nat.h"
#include "ikev2_send.h"
#include "iface.h"
#include "kernel.h"
#include "addr_lookup.h"
#include "ipsecconf/confread.h"
#include "ikev2_message.h"
#include "routing.h"
#include "ikev2_mobike.h"
#include "orient.h"
#include "ikev2.h"
#include "ikev2_states.h"
#include "ikev2_informational.h"

static emit_v2_INFORMATIONAL_request_payload_fn add_mobike_payloads; /* type check */

static bool add_mobike_response_payloads(shunk_t cookie2, struct msg_digest *md,
					 struct pbs_out *pbs, struct ike_sa *ike);

/*
 * We have successfully decrypted this packet, so we can update
 * the remote IP / port
 */
static bool update_mobike_endpoints(struct ike_sa *ike, const struct msg_digest *md)
{
	struct connection *c = ike->sa.st_connection;
	const struct ip_info *afi = endpoint_type(&md->iface->local_endpoint);

	/*
	 * AA_201705 is this the right way to find Child SA(s)?
	 * would it work if there are multiple Child SAs on this parent??
	 * would it work if the Child SA connection is different from IKE SA?
	 * for now just do this one connection, later on loop over all Child SAs
	 */
	struct child_sa *child = child_sa_by_serialno(c->established_child_sa);
	if (child == NULL) {
		/*
		 * XXX: Technically, losing the first child (it gets
		 * torn down but others remain) is perfectly
		 * reasonable.  However, per above comments, handling
		 * multiple Child SAs is still a TODO item.
		 */
		llog_pexpect(ike->sa.logger, HERE,
			     "IKE SA lost first Child SA "PRI_SO, pri_so(c->established_child_sa));
		return false;
	}

	/* check for all conditions before updating IPsec SA's */
	if (afi != address_type(&c->remote->host.addr)) {
		llog_sa(RC_LOG, ike,
			  "MOBIKE: AF change switching between v4 and v6 not supported");
		return false;
	}

	passert(child->sa.st_connection == ike->sa.st_connection);

	ip_endpoint old_endpoint;
	ip_endpoint new_endpoint;

	enum message_role md_role = v2_msg_role(md);
	switch (md_role) {
	case MESSAGE_RESPONSE:
		/* MOBIKE inititor processing response */
		old_endpoint = ike->sa.st_iface_endpoint->local_endpoint;

		child->sa.st_v2_mobike.local_endpoint = ike->sa.st_v2_mobike.local_endpoint;
		child->sa.st_v2_mobike.host_nexthop = ike->sa.st_v2_mobike.host_nexthop;

		new_endpoint = ike->sa.st_v2_mobike.local_endpoint;
		break;
	case MESSAGE_REQUEST:
		/* MOBIKE responder processing request */
		old_endpoint = ike->sa.st_remote_endpoint;

		child->sa.st_v2_mobike.remote_endpoint = md->sender;
		ike->sa.st_v2_mobike.remote_endpoint = md->sender;

		new_endpoint =md->sender;
		break;
	default:
		bad_case(md_role);
	}

	char buf[256];
	endpoint_buf old;
	endpoint_buf new;
	snprintf(buf, sizeof(buf), "MOBIKE update %s address %s -> %s",
		 md_role == MESSAGE_RESPONSE ? "local" : "remote",
		 str_endpoint_sensitive(&old_endpoint, &old),
		 str_endpoint_sensitive(&new_endpoint, &new));

	dbg("#%lu pst=#%lu %s", child->sa.st_serialno,
	    ike->sa.st_serialno, buf);

	if (endpoint_eq_endpoint(old_endpoint, new_endpoint)) {
		if (md_role == MESSAGE_REQUEST) {
			/* on responder NAT could hide end-to-end change */
			endpoint_buf b;
			llog_sa(RC_LOG, ike,
				  "MOBIKE success no change to kernel SA same IP address and port %s",
				  str_endpoint_sensitive(&old_endpoint, &b));

			return true;
		}
	}

	if (!kernel_ops_migrate_ipsec_sa(child)) {
		llog_sa(RC_LOG, ike, "%s FAILED", buf);
		return false;
	}

	llog_sa(RC_LOG, ike, " success %s", buf);

	switch (md_role) {
	case MESSAGE_RESPONSE:
		/* MOBIKE initiator processing response */
		c->local->host.addr = endpoint_address(child->sa.st_v2_mobike.local_endpoint);
		dbg("%s() %s.host_port: %u->%u", __func__, c->local->config->leftright,
		    c->local->host.port, endpoint_hport(child->sa.st_v2_mobike.local_endpoint));
		c->local->host.port = endpoint_hport(child->sa.st_v2_mobike.local_endpoint);
		c->local->host.nexthop = child->sa.st_v2_mobike.host_nexthop;
		break;
	case MESSAGE_REQUEST:
		/* MOBIKE responder processing request */
		c->remote->host.addr = endpoint_address(md->sender);
		dbg("%s() %s.host_port: %u->%u", __func__, c->remote->config->leftright,
		    c->remote->host.port, endpoint_hport(md->sender));
		c->remote->host.port = endpoint_hport(md->sender);

		/* for the consistency, correct output in ipsec status */
		child->sa.st_remote_endpoint = ike->sa.st_remote_endpoint = md->sender;
		break;
	default:
		bad_case(md_role);
	}

	iface_endpoint_delref(&ike->sa.st_iface_endpoint);
	iface_endpoint_delref(&child->sa.st_iface_endpoint);
	ike->sa.st_iface_endpoint = iface_endpoint_addref(md->iface);
	child->sa.st_iface_endpoint = iface_endpoint_addref(md->iface);

	/*
	 * Force a re-orientation which will rebuild much of the
	 * host-pair DB.
	 *
	 * Since IKE holds a reference to C, C can't be deleted.
	 */
	if (!orient(c, ike->sa.logger)) {
		llog_pexpect(ike->sa.logger, HERE,
			     "%s after mobike failed", "orient");
		return false;
	}

	if (md_role == MESSAGE_RESPONSE) {
		/* MOBIKE initiator processing response */
		connection_resume(child, HERE);
		ike->sa.st_v2_mobike.deleted_local_addr = unset_address;
		child->sa.st_v2_mobike.deleted_local_addr = unset_address;
		if (dpd_active_locally(child->sa.st_connection) &&
		    child->sa.st_v2_liveness_event == NULL) {
			dbg("dpd re-enabled after mobike, scheduling ikev2 liveness checks");
			deltatime_t delay = deltatime_max(child->sa.st_connection->config->dpd.delay, deltatime(MIN_LIVENESS));
			event_schedule(EVENT_v2_LIVENESS, delay, &child->sa);
		}
	}

	return true;
}

/* can an established state initiate or respond to mobike probe */
static bool mobike_check_established(struct ike_sa *ike)
{
	struct connection *c = ike->sa.st_connection;
	bool ret = (c->config->mobike &&
		    ike->sa.st_v2_mobike.enabled &&
		    IS_IKE_SA_ESTABLISHED(&ike->sa));

	return ret;
}

bool process_v2N_mobike_requests(struct ike_sa *ike, struct msg_digest *md,
				 struct pbs_out *pbs)
{
	if (!mobike_check_established(ike)) {
		return true;
	}

#if 0
	if (DBGP(DBG_BASE) && md->pd[PD_v2N_NO_NATS_ALLOWED] != NULL) {
		DBG_log("NO_NATS_ALLOWED payload ignored (not yet supported)");
	}
#endif

#if 0
	if (DBGP(DBG_BASE) && md->pd[PD_v2N_ADDITIONAL_IP4_ADDRESS] != NULL) {
		DBG_log("ADDITIONAL_IP4_ADDRESS payload ignored (not yet supported)");
	}
#endif

#if 0
	if (DBGP(DBG_BASE) && md->pd[PD_v2N_ADDITIONAL_IP6_ADDRESS] != NULL) {
		DBG_log("ADDITIONAL_IP6_ADDRESS payload ignored (not yet supported)");
	}
#endif

#if 0
	if (DBGP(DBG_BASE) && md->pd[PD_v2N_NO_ADDITIONAL_ADDRESSES] != NULL) {
		DBG_log("Received NO_ADDITIONAL_ADDRESSES - no need to act on this");
	}
#endif

	bool ntfy_update_sa = (md->pd[PD_v2N_UPDATE_SA_ADDRESSES] != NULL);

	bool ntfy_natd = (md->pd[PD_v2N_NAT_DETECTION_DESTINATION_IP] != NULL ||
			  md->pd[PD_v2N_NAT_DETECTION_SOURCE_IP] != NULL);

	shunk_t cookie2 = null_shunk;
	if (md->pd[PD_v2N_COOKIE2] != NULL) {
		shunk_t tmp = pbs_in_left(&md->pd[PD_v2N_COOKIE2]->pbs);
		if (tmp.len > IKEv2_MAX_COOKIE_SIZE) {
			dbg("MOBIKE COOKIE2 notify payload too big - ignored");
		} else {
			cookie2 = tmp;
			if (DBGP(DBG_BASE)) {
				DBG_dump_hunk("MOBIKE COOKIE2 received:", cookie2);
			}
		}
	}

	if (ntfy_update_sa) {
		if (LHAS(ike->sa.hidden_variables.st_nat_traversal, NATED_HOST)) {
			llog_sa(RC_LOG, ike,
				  "Ignoring MOBIKE UPDATE_SA since we are behind NAT");
		} else {
			if (!update_mobike_endpoints(ike, md))
				ntfy_natd = false;
			update_ike_endpoints(ike, md); /* update state sender so we can find it for IPsec SA */
		}
	}

	if (!ntfy_update_sa && ntfy_natd &&
	    !LHAS(ike->sa.hidden_variables.st_nat_traversal, NATED_HOST)) {
		/*
		 * If this is a MOBIKE probe, use the received IP:port
		 * for only this reply packet, without updating IKE
		 * endpoint and without UPDATE_SA.
		 */
		ike->sa.st_v2_mobike.remote_endpoint = md->sender;
	}

	if (ntfy_update_sa) {
		llog_sa(RC_LOG, ike,
			  "MOBIKE request: updating IPsec SA by request");
	} else {
		dbg("MOBIKE request: not updating IPsec SA");
	}

	if (ntfy_natd) {
		return add_mobike_response_payloads(cookie2, md, pbs, ike);
	}

	return true;

}

static void process_v2N_mobike_responses(struct ike_sa *ike, struct msg_digest *md)
{
	bool may_mobike = mobike_check_established(ike);
	if (!may_mobike) {
		dbg("MOBIKE response: not updating IPsec SA");
		return;
	}

	/* ??? there is currently no need for separate natd_[sd] variables */
	bool natd_s = md->pd[PD_v2N_NAT_DETECTION_SOURCE_IP] != NULL;
	bool natd_d = md->pd[PD_v2N_NAT_DETECTION_DESTINATION_IP] != NULL;
	bool ret = natd_s && natd_d;

	/* XXX: keep testsuite happy */
	if (natd_s) {
		dbg("TODO: process v2N_NAT_DETECTION_SOURCE_IP in MOBIKE response ");
	}
	if (natd_d) {
		dbg("TODO: process v2N_NAT_DETECTION_DESTINATION_IP in MOBIKE response ");
	}

	if (ret && !update_mobike_endpoints(ike, md)) {
		/* IPs already updated from md */
		dbg("MOBIKE response: update MOBIKE failed; not updating IPsec SA");
		return;
	}

	llog_sa(RC_LOG, ike, "MOBIKE response: updating IPsec SA");
	update_ike_endpoints(ike, md); /* update state sender so we can find it for IPsec SA */
	return;
}

void mobike_possibly_send_recorded(struct ike_sa *ike, struct msg_digest *md)
{
	if (mobike_check_established(ike) &&
	    !LHAS(ike->sa.hidden_variables.st_nat_traversal, NATED_HOST) &&
	    !endpoint_eq_endpoint(md->sender, ike->sa.st_remote_endpoint)) {
		/* swap out the remote-endpoint; restored below */
		ip_endpoint old_remote = ike->sa.st_remote_endpoint;
		ike->sa.st_remote_endpoint = md->sender; /* tmp */
		/* swap out the interface; restored below */
		struct iface_endpoint *old_interface = ike->sa.st_iface_endpoint;
		ike->sa.st_iface_endpoint = md->iface; /* tmp-new */
		/*
		 * XXX: hopefully this call doesn't muddle the IKE
		 * Message IDs.
		 */
		send_recorded_v2_message(ike, "reply packet for process_encrypted_informational_ikev2",
					 ike->sa.st_v2_msgid_windows.responder.outgoing_fragments);
		/* restore established address and interface */
		ike->sa.st_remote_endpoint = old_remote;
		ike->sa.st_iface_endpoint = old_interface; /* restore-old */
	}
}

bool add_mobike_response_payloads(shunk_t cookie2, struct msg_digest *md,
				  struct pbs_out *pbs, struct ike_sa *ike)
{
	dbg("adding NATD%s payloads to MOBIKE response",
	    cookie2.len != 0 ? " and cookie2" : "");
	/* assumptions from ikev2_out_nat_v2n() and caller */
	pexpect(v2_msg_role(md) == MESSAGE_REQUEST);
	pexpect(!ike_spi_is_zero(&ike->sa.st_ike_spis.responder));
	return (ikev2_out_nat_v2n(pbs, &ike->sa, &ike->sa.st_ike_spis.responder) &&
		(cookie2.len == 0 || emit_v2N_hunk(v2N_COOKIE2, cookie2, pbs)));
}

static bool add_mobike_payloads(struct ike_sa *ike,
				struct child_sa *null_child,
				struct pbs_out *pbs)
{
	PASSERT(ike->sa.logger, null_child == NULL);

	ip_endpoint local_endpoint = ike->sa.st_v2_mobike.local_endpoint;
	ip_endpoint remote_endpoint = ike->sa.st_remote_endpoint;
	if (!emit_v2N(v2N_UPDATE_SA_ADDRESSES, pbs)) {
		return false;
	}
	if (!ikev2_out_natd(&local_endpoint, &remote_endpoint,
			    &ike->sa.st_ike_spis, pbs)) {
		return false;
	}
	return true;
}

void record_newaddr(ip_address *ip, char *a_type)
{
	address_buf ip_str;
	dbg("XFRM RTM_NEWADDR %s %s", str_address(ip, &ip_str), a_type);
	struct state_filter sf = {
		.ike_version = IKEv2,
		.where = HERE,
	};
	while (next_state(NEW2OLD, &sf)) {

		if (!IS_IKE_SA(sf.st)) {
			continue;
		}

		struct ike_sa *ike = pexpect_ike_sa(sf.st);
		if (!mobike_check_established(ike)) {
			continue;
		}

		if (address_is_specified(ike->sa.st_v2_mobike.deleted_local_addr)) {
			/*
			 * A work around for delay between new address
			 * and new route A better fix would be listen
			 * to RTM_NEWROUTE, RTM_DELROUTE
			 */
			if (ike->sa.st_v2_addr_change_event == NULL) {
				event_schedule(EVENT_v2_ADDR_CHANGE,
					       RTM_NEWADDR_ROUTE_DELAY,
					       &ike->sa);
			} else {
				address_buf b;
				dbg(PRI_SO" MOBIKE ignore address %s change pending previous",
				    ike->sa.st_serialno, str_address_sensitive(ip, &b));
			}
		}
	}
}

void record_deladdr(ip_address *ip, char *a_type)
{
	address_buf ip_str;
	dbg("XFRM RTM_DELADDR %s %s", str_address(ip, &ip_str), a_type);
	struct state_filter sf = {
		.ike_version = IKEv2,
		.where = HERE,
	};
	while (next_state(NEW2OLD, &sf)) {

		if (!IS_IKE_SA(sf.st)) {
			continue;
		}

		struct ike_sa *ike = pexpect_ike_sa(sf.st);

		if (!mobike_check_established(ike)) {
			continue;
		}

		ip_address local_address = endpoint_address(ike->sa.st_iface_endpoint->local_endpoint);
		/* ignore port */
		if (!sameaddr(ip, &local_address)) {
			continue;
		}

		ip_address ip_p = ike->sa.st_v2_mobike.deleted_local_addr;
		ike->sa.st_v2_mobike.deleted_local_addr = local_address;
		struct child_sa *child = child_sa_by_serialno(ike->sa.st_connection->established_child_sa);
		if (child == NULL) {
			llog_pexpect(ike->sa.logger, HERE,
				     "newest Child SA "PRI_SO" lost",
				     pri_so(ike->sa.st_connection->established_child_sa));
			continue;
		}

		/*
		 * "down" / "unroute" the connection but _don't_
		 * delete the kernel state / policy.
		 *
		 * Presumably the kernel policy (at least) is acting
		 * like a trap while mibike migrates things?
		 */
		connection_suspend(child, HERE);

		event_delete(EVENT_v2_LIVENESS, &child->sa);

		if (ike->sa.st_v2_addr_change_event == NULL) {
			event_schedule(EVENT_v2_ADDR_CHANGE, deltatime(0), &ike->sa);
		} else {
			address_buf o, n;
			dbg(PRI_SO" MOBIKE new RTM_DELADDR %s pending previous %s",
			    ike->sa.st_serialno,
			    str_address(ip, &n),
			    str_address(&ip_p, &o));
		}
	}
}

static stf_status process_v2_INFORMATIONAL_mobike_response(struct ike_sa *ike,
							   struct child_sa *null_child,
							   struct msg_digest *md)
{
	passert(v2_msg_role(md) == MESSAGE_RESPONSE);
	pexpect(null_child == NULL);

	/*
	 * Process NOTIFY payloads
	 */

	if (md->chain[ISAKMP_NEXT_v2N] != NULL) {
		process_v2N_mobike_responses(ike, md);
	}
	return STF_OK;
}

static const struct v2_transition v2_INFORMATIONAL_mobike_initiate_transition = {
	.story = "MOBIKE",
	.from = { &state_v2_ESTABLISHED_IKE_SA, },
	.to = &state_v2_ESTABLISHED_IKE_SA,
};

static const struct v2_transition v2_INFORMATIONAL_mobike_response_transition[] = {
	{ .story      = "Informational Response",
	  .from = { &state_v2_ESTABLISHED_IKE_SA, },
	  .to = &state_v2_ESTABLISHED_IKE_SA,
	  .exchange   = ISAKMP_v2_INFORMATIONAL,
	  .recv_role  = MESSAGE_RESPONSE,
	  .message_payloads.required = v2P(SK),
	  .encrypted_payloads.optional = v2P(N) | v2P(CP),
	  .processor  = process_v2_INFORMATIONAL_mobike_response,
	  .llog_success = ldbg_v2_success,
	  .timeout_event = EVENT_RETAIN, },
};

static const struct v2_transitions v2_INFORMATIONAL_mobike_response_transitions = {
	ARRAY_REF(v2_INFORMATIONAL_mobike_response_transition),
};

const struct v2_exchange v2_INFORMATIONAL_mobike_exchange = {
	.type = ISAKMP_v2_INFORMATIONAL,
	.subplot = "MOBIKE probe",
	.secured = true,
	.initiate = &v2_INFORMATIONAL_mobike_initiate_transition,
	.response = &v2_INFORMATIONAL_mobike_response_transitions,
};

static void record_n_send_v2_mobike_probe_request(struct ike_sa *ike)
{
	/*
	 * 3.5.  Changing Addresses in IPsec SAs
	 * https://datatracker.ietf.org/doc/html/rfc4555#section-3.5
	 *
	 *   The description in the rest of this section assumes that the
	 *   initiator has already decided what the new addresses should be.  When
	 *   this decision has been made, the initiator:
	 *
	 * This code path was triggered by the kernel detecting
	 * an address change.  Does that mean the decision has been
	 * made?
	 *
	 *   o  Updates the IKE_SA with the new addresses, and sets the
	 *      "pending_update" flag in the IKE_SA.
	 *
	 * Here the caller switches things, and then switches things
	 * back.
	 *
	 *   o  If there are outstanding IKEv2 requests (requests for which the
	 *      initiator has not yet received a reply), continues retransmitting
	 *      them using the addresses in the IKE_SA (the new addresses).
	 *
	 * Unfortunately, not implemented.
	 *
	 *   o  When the window size allows, sends an INFORMATIONAL request
	 *      containing the UPDATE_SA_ADDRESSES notification (which does not
	 *      contain any data), and clears the "pending_update" flag.  The
	 *      request will be as follows:
	 *
	 * The message is always sent.
	 *
	 * If there's a message outstanding the below will likely
	 * pexpect().
	 */

	dbg_v2_msgid(ike, "record'n'send MOBIKE probe request");

	v2_msgid_start_record_n_send(ike, &v2_INFORMATIONAL_mobike_exchange);
	if (!record_v2_INFORMATIONAL_request("mobike informational request",
					     ike->sa.logger, ike, /*child*/NULL,
					     add_mobike_payloads)) {
		/* already logged? */
		return;
	}

	v2_msgid_finish(ike, NULL/*md*/, HERE);
	send_recorded_v2_message(ike, "mobike informational request",
				 ike->sa.st_v2_msgid_windows.initiator.outgoing_fragments);
}

static void initiate_mobike_probe(struct ike_sa *ike,
				  struct iface_endpoint *new_iface,
				  ip_address new_nexthop)
{
	/*
	 * caveat: could a CP initiator find an address received
	 * from the pool as a new source address?
	 */

	address_buf g;
	endpoint_buf lb, rb;
	dbg(PRI_SO" MOBIKE new local %s remote %s and gateway %s",
	    ike->sa.st_serialno,
	    str_endpoint(&new_iface->local_endpoint, &lb),
	    str_endpoint(&ike->sa.st_remote_endpoint, &rb),
	    str_address(&new_nexthop, &g));
	/*
	 * The interface changed (new address in .address) but
	 * continue to use the existing port.
	 */
	ike->sa.st_v2_mobike.local_endpoint = new_iface->local_endpoint;
	ike->sa.st_v2_mobike.host_nexthop = new_nexthop; /* for updown, after xfrm migration */

	/* notice how it gets set back below */
	struct iface_endpoint *old_iface = ike->sa.st_iface_endpoint;
	ike->sa.st_iface_endpoint = new_iface; /* tmp-new */

	record_n_send_v2_mobike_probe_request(ike);

	ike->sa.st_iface_endpoint = old_iface; /* restore-old */
}

static struct iface_endpoint *find_new_iface(struct ike_sa *ike, ip_address new_src_addr)
{
	/*
	 * Merge the old port in with the new interface address, and
	 * then look at up.
	 */
	ip_port port = endpoint_port(ike->sa.st_iface_endpoint->local_endpoint);
	ip_endpoint local_endpoint = endpoint_from_address_protocol_port(new_src_addr,
									 ike->sa.st_iface_endpoint->io->protocol,
									 port);
	struct iface_endpoint *iface =
		find_iface_endpoint_by_local_endpoint(local_endpoint); /* must delref */
	if (iface == NULL) {
		endpoint_buf b;
		dbg(PRI_SO" no interface for %s try to initialize",
		    ike->sa.st_serialno, str_endpoint(&local_endpoint, &b));
		find_ifaces(false, ike->sa.logger);
		iface = find_iface_endpoint_by_local_endpoint(local_endpoint);
		if (iface ==  NULL) {
			return NULL;
		}
	}

	return iface;
}

void ikev2_addr_change(struct state *ike_sa)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		return;
	}

	if (!mobike_check_established(ike)) {
		return;
	}

	if (kernel_ops->migrate_ipsec_sa == NULL) {
		llog_sa(RC_LOG, ike, "%s does not support MOBIKE",
			kernel_ops->interface_name);
		return;
	}

	ip_address dest = endpoint_address(ike->sa.st_remote_endpoint);
	struct ip_route route;
	switch (get_route(dest, &route, ike->sa.logger)) {
	case ROUTE_SUCCESS:
	{
		struct iface_endpoint *iface = find_new_iface(ike, route.source); /* must delref */
		if (iface != NULL) {
			initiate_mobike_probe(ike, iface, route.gateway);
			iface_endpoint_delref(&iface);
		}
		break;
	}
	case ROUTE_GATEWAY_FAILED:
	{
		/* keep this DEBUG, if a libreswan log, too many false +ve */
		address_buf b;
		dbg(PRI_SO" no local gateway to reach %s",
		    ike->sa.st_serialno, str_address(&dest, &b));
		break;
	}
	case ROUTE_SOURCE_FAILED:
	{
		address_buf g, b;
		llog_sa(RC_LOG, ike,
			"no local source address to reach remote %s, local gateway %s",
			str_address_sensitive(&dest, &b),
			str_address(&route.gateway, &g));
		break;
	}
	case ROUTE_FATAL:
		/* already logged */
		break;
	}
}
