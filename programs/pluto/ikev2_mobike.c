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

#include "ikev2_mobike.h"

static bool add_mobike_response_payloads(shunk_t cookie2, struct msg_digest *md,
					 struct pbs_out *pbs, struct ike_sa *ike);

/* can an established state initiate or respond to mobike probe */
static bool mobike_check_established(struct state *st)
{
	struct connection *c = st->st_connection;
	bool ret = (LIN(POLICY_MOBIKE, c->policy) &&
		    st->st_ike_seen_v2n_mobike_supported &&
		    st->st_ike_sent_v2n_mobike_supported &&
		    IS_IKE_SA_ESTABLISHED(st));

	return ret;
}

bool process_v2N_mobike_requests(struct ike_sa *ike, struct msg_digest *md,
				 struct pbs_out *pbs)
{
	if (!mobike_check_established(&ike->sa)) {
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
		shunk_t tmp = pbs_in_left_as_shunk(&md->pd[PD_v2N_COOKIE2]->pbs);
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
			log_state(RC_LOG, &ike->sa,
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
		ike->sa.st_mobike_remote_endpoint = md->sender;
	}

	if (ntfy_update_sa) {
		log_state(RC_LOG, &ike->sa,
			  "MOBIKE request: updating IPsec SA by request");
	} else {
		dbg("MOBIKE request: not updating IPsec SA");
	}

	if (ntfy_natd) {
		return add_mobike_response_payloads(cookie2, md, pbs, ike);
	}

	return true;

}

void process_v2N_mobike_responses(struct ike_sa *ike, struct msg_digest *md)
{
	bool may_mobike = mobike_check_established(&ike->sa);
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

	log_state(RC_LOG, &ike->sa, "MOBIKE response: updating IPsec SA");
	update_ike_endpoints(ike, md); /* update state sender so we can find it for IPsec SA */
	return;
}

void mobike_possibly_send_recorded(struct ike_sa *ike, struct msg_digest *md)
{
	if (mobike_check_established(&ike->sa) &&
	    !LHAS(ike->sa.hidden_variables.st_nat_traversal, NATED_HOST) &&
	    !endpoint_eq_endpoint(md->sender, ike->sa.st_remote_endpoint)) {
		/* swap out the remote-endpoint; restored below */
		ip_endpoint old_remote = ike->sa.st_remote_endpoint;
		ike->sa.st_remote_endpoint = md->sender; /* tmp */
		/* swap out the interface; restored below */
		struct iface_endpoint *old_interface = ike->sa.st_interface;
		ike->sa.st_interface = md->iface; /* tmp-new */
		/*
		 * XXX: hopefully this call doesn't muddle the IKE
		 * Message IDs.
		 */
		send_recorded_v2_message(ike, "reply packet for process_encrypted_informational_ikev2",
					 MESSAGE_RESPONSE);
		/* restore established address and interface */
		ike->sa.st_remote_endpoint = old_remote;
		ike->sa.st_interface = old_interface; /* restore-old */
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

#ifdef KERNEL_XFRM
static payload_emitter_fn add_mobike_payloads;
static bool add_mobike_payloads(struct state *st, pb_stream *pbs)
{
	ip_endpoint local_endpoint = st->st_mobike_local_endpoint;
	ip_endpoint remote_endpoint = st->st_remote_endpoint;
	return emit_v2N(v2N_UPDATE_SA_ADDRESSES, pbs) &&
		ikev2_out_natd(&local_endpoint, &remote_endpoint,
			       &st->st_ike_spis, pbs);
}
#endif

void record_newaddr(ip_address *ip, char *a_type)
{
	address_buf ip_str;
	dbg("XFRM RTM_NEWADDR %s %s", str_address(ip, &ip_str), a_type);
	struct state_filter sf = { .where = HERE, };
	while (next_state_new2old(&sf)) {
		struct state *st = sf.st;

		if (!mobike_check_established(st))
			continue;

		if (address_is_specified(st->st_deleted_local_addr)) {
			/*
			 * A work around for delay between new address
			 * and new route A better fix would be listen
			 * to RTM_NEWROUTE, RTM_DELROUTE
			 */
			if (st->st_v2_addr_change_event == NULL) {
				event_schedule(EVENT_v2_ADDR_CHANGE,
					       RTM_NEWADDR_ROUTE_DELAY, st);
			} else {
				address_buf b;
				dbg("#%lu MOBIKE ignore address %s change pending previous",
				    st->st_serialno, str_address_sensitive(ip, &b));
			}
		}
	}
}

void record_deladdr(ip_address *ip, char *a_type)
{
	address_buf ip_str;
	dbg("XFRM RTM_DELADDR %s %s", str_address(ip, &ip_str), a_type);
	struct state_filter sf = { .where = HERE, };
	while (next_state_new2old(&sf)) {
		struct state *st = sf.st;

		if (!mobike_check_established(st))
			continue;

		ip_address local_address = endpoint_address(st->st_interface->local_endpoint);
		/* ignore port */
		if (!sameaddr(ip, &local_address)) {
			continue;
		}

		ip_address ip_p = st->st_deleted_local_addr;
		st->st_deleted_local_addr = local_address;
		struct state *cst = state_by_serialno(st->st_connection->newest_ipsec_sa);
		if (cst == NULL) {
			llog_pexpect(st->st_logger, HERE, "newest Child SA "PRI_SO" lost",
				     pri_so(st->st_connection->newest_ipsec_sa));
			continue;
		}

		migration_down(cst->st_connection, cst);
		unroute_connection(st->st_connection);

		event_delete(EVENT_v2_LIVENESS, cst);

		if (st->st_v2_addr_change_event == NULL) {
			event_schedule(EVENT_v2_ADDR_CHANGE, deltatime(0), st);
		} else {
			ipstr_buf o, n;
			dbg("#%lu MOBIKE new RTM_DELADDR %s pending previous %s",
			    st->st_serialno, ipstr(ip, &n), ipstr(&ip_p, &o));
		}
	}
}

#ifdef KERNEL_XFRM
static void initiate_mobike_probe(struct state *st, struct starter_end *this,
				  struct iface_endpoint *new_iface)
{
	struct ike_sa *ike = ike_sa(st, HERE);
	/*
	 * caveat: could a CP initiator find an address received
	 * from the pool as a new source address?
	 */

	ipstr_buf s, g;
	endpoint_buf b;
	dbg("#%lu MOBIKE new source address %s remote %s and gateway %s",
	    st->st_serialno, ipstr(&this->addr, &s),
	    str_endpoint(&st->st_remote_endpoint, &b),
	    ipstr(&this->nexthop, &g));
	/*
	 * XXX: why not local_endpoint or is this redundant?
	 *
	 * The interface changed (new address in .address) but
	 * continue to use the existing port.
	 */
	ip_port port = endpoint_port(st->st_interface->local_endpoint);
	st->st_mobike_local_endpoint = endpoint_from_address_protocol_port(this->addr,
									   st->st_interface->io->protocol,
									   port);
	st->st_mobike_host_nexthop = this->nexthop; /* for updown, after xfrm migration */
	/* notice how it gets set back below */
	struct iface_endpoint *old_iface = st->st_interface;
	st->st_interface = new_iface; /* tmp-new */

	stf_status e = record_v2_informational_request("mobike informational request",
						       ike, st/*sender*/,
						       add_mobike_payloads);
	if (e == STF_OK) {
		send_recorded_v2_message(ike, "mobike informational request",
					 MESSAGE_REQUEST);
		/*
		 * XXX: record 'n' send violates the RFC.  This code should
		 * instead let success_v2_state_transition() deal with things.
		 */
		dbg_v2_msgid(ike, st, "XXX: in %s() hacking around record'n'send bypassing send queue",
			     __func__);
		v2_msgid_update_sent(ike, &ike->sa, NULL /* new exchange */, MESSAGE_REQUEST);
	}
	st->st_interface = old_iface; /* restore-old */
}
#endif

#ifdef KERNEL_XFRM
static struct iface_endpoint *ikev2_src_iface(struct state *st,
					      struct starter_end *this)
{
	/* success found a new source address */
	ip_port port = endpoint_port(st->st_interface->local_endpoint);
	ip_endpoint local_endpoint = endpoint_from_address_protocol_port(this->addr,
									 st->st_interface->io->protocol,
									 port);
	struct iface_endpoint *iface = find_iface_endpoint_by_local_endpoint(local_endpoint);
	if (iface == NULL) {
		endpoint_buf b;
		dbg("#%lu no interface for %s try to initialize",
		    st->st_serialno, str_endpoint(&local_endpoint, &b));
		find_ifaces(false, st->st_logger);
		iface = find_iface_endpoint_by_local_endpoint(local_endpoint);
		if (iface ==  NULL) {
			return NULL;
		}
	}

	return iface;
}
#endif

void ikev2_addr_change(struct state *st)
{
	if (!mobike_check_established(st))
		return;

#ifdef KERNEL_XFRM

	/* let's re-discover local address */

	struct starter_end this = {
		.addrtype = KH_DEFAULTROUTE,
		.nexttype = KH_DEFAULTROUTE,
		.host_family = endpoint_type(&st->st_remote_endpoint),
	};

	struct starter_end that = {
		.addrtype = KH_IPADDR,
		.host_family = endpoint_type(&st->st_remote_endpoint),
		.addr = endpoint_address(st->st_remote_endpoint),
	};

	/*
	 * mobike need two lookups. one for the gateway and
	 * the one for the source address
	 */
	lset_t verbose_rc_flags = DBGP(DBG_BASE) ? DEBUG_STREAM : LEMPTY;
	switch (resolve_defaultroute_one(&this, &that, verbose_rc_flags,
					 st->st_logger)) {

	case RESOLVE_FAILURE:
	{
		/* keep this DEBUG, if a libreswan log, too many false +ve */
		address_buf b;
		dbg("#%lu no local gateway to reach %s",
		    st->st_serialno, str_address(&that.addr, &b));
		break;
	}

	case RESOLVE_SUCCESS:
	{
		/* cannot happen */
		/* ??? original code treated this as failure */
		/* bad_case(0); */
		address_buf b;
		log_state(RC_LOG, st,
			  "no local gateway to reach %s (unexpected SUCCESS from first resolve_defaultroute_one())",
			  str_address(&that.addr, &b));
		break;
	}

	case RESOLVE_PLEASE_CALL_AGAIN: /* please call again: more to do */
		switch (resolve_defaultroute_one(&this, &that, verbose_rc_flags,
						 st->st_logger)) {

		case RESOLVE_FAILURE:
		{
			address_buf g, b;
			log_state(RC_LOG, st, "no local source address to reach remote %s, local gateway %s",
				  str_address_sensitive(&that.addr, &b),
				  str_address(&this.nexthop, &g));
			break;
		}

		case RESOLVE_SUCCESS:
		{
			struct iface_endpoint *iface = ikev2_src_iface(st, &this);
			if (iface != NULL)
				initiate_mobike_probe(st, &this, iface);
			break;
		}

		case RESOLVE_PLEASE_CALL_AGAIN: /* please call again: more to do */
		{
			/* cannot happen */
			/* ??? original code treated this as failure */
			/* bad_case(1); */
			address_buf g, b;
			log_state(RC_LOG, st, "no local source address to reach remote %s, local gateway %s (unexpected TRY AGAIN from second resolve_defaultroute_one())",
				  str_address_sensitive(&that.addr, &b),
				  str_address(&this.nexthop, &g));
			break;
		}

		}
		break;
	}

#else /* !defined(KERNEL_XFRM) */

	log_state(RC_LOG, st, "without NETKEY we cannot ikev2_addr_change()");

#endif
}
