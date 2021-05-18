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
#include "nat_traversal.h"
#include "ikev2_send.h"
#include "iface.h"
#include "kernel.h"
#include "addr_lookup.h"
#include "ipsecconf/confread.h"

#include "ikev2_mobike.h"

/* can an established state initiate or respond to mobike probe */
bool mobike_check_established(const struct state *st)
{
	struct connection *c = st->st_connection;
	bool ret = (LIN(POLICY_MOBIKE, c->policy) &&
		    st->st_ike_seen_v2n_mobike_supported &&
		    st->st_ike_sent_v2n_mobike_supported &&
		    IS_ISAKMP_SA_ESTABLISHED(st->st_state));

	return ret;
}

bool process_mobike_resp(struct msg_digest *md)
{
	struct state *st = md->v1_st;
	struct ike_sa *ike = ike_sa(st, HERE);
	bool may_mobike = mobike_check_established(st);
	/* ??? there is currently no need for separate natd_[sd] variables */
	bool natd_s = FALSE;
	bool natd_d = FALSE;
	struct payload_digest *ntfy;

	if (!may_mobike) {
		return FALSE;
	}

	for (ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		switch (ntfy->payload.v2n.isan_type) {
		case v2N_NAT_DETECTION_DESTINATION_IP:
			natd_d =  TRUE;
			dbg("TODO: process %s in MOBIKE response ",
			    enum_name(&ikev2_notify_names, ntfy->payload.v2n.isan_type));
			break;
		case v2N_NAT_DETECTION_SOURCE_IP:
			natd_s = TRUE;
			dbg("TODO: process %s in MOBIKE response ",
			    enum_name(&ikev2_notify_names, ntfy->payload.v2n.isan_type));

			break;
		}
	}

	/* use of bitwise & on bool values is correct but odd */
	bool ret  = natd_s & natd_d;

	if (ret && !update_mobike_endpoints(ike, md)) {
		/* IPs already updated from md */
		return FALSE;
	}
	update_ike_endpoints(ike, md); /* update state sender so we can find it for IPsec SA */

	return ret;
}

void mobike_reset_remote(struct state *st, struct mobike *est_remote)
{
	if (est_remote->interface == NULL)
		return;

	st->st_remote_endpoint = est_remote->remote;
	st->st_interface = est_remote->interface;
	pexpect_st_local_endpoint(st);
	st->st_mobike_remote_endpoint = unset_endpoint;
}

/* MOBIKE liveness/update response. set temp remote address/interface */
void mobike_switch_remote(struct msg_digest *md, struct mobike *est_remote)
{
	struct state *st = md->v1_st;

	est_remote->interface = NULL;

	if (mobike_check_established(st) &&
	    !LHAS(st->hidden_variables.st_nat_traversal, NATED_HOST) &&
	    !endpoint_eq_endpoint(md->sender, st->st_remote_endpoint)) {
		/* remember the established/old address and interface */
		est_remote->remote = st->st_remote_endpoint;
		est_remote->interface = st->st_interface;

		/* set temp one and after the message sent reset it */
		st->st_remote_endpoint = md->sender;
		st->st_interface = md->iface;
		pexpect_st_local_endpoint(st);
	}
}

stf_status add_mobike_response_payloads(chunk_t *cookie2,	/* freed by us */
					struct msg_digest *md,
					pb_stream *pbs)
{
	dbg("adding NATD%s payloads to MOBIKE response",
	    cookie2->len != 0 ? " and cookie2" : "");

	stf_status r = STF_INTERNAL_ERROR;

	struct state *st = md->v1_st;
	/* assumptions from ikev2_out_nat_v2n() and caller */
	pexpect(v2_msg_role(md) == MESSAGE_REQUEST);
	pexpect(!ike_spi_is_zero(&st->st_ike_spis.responder));
	if (ikev2_out_nat_v2n(pbs, st, &st->st_ike_spis.responder) &&
	    (cookie2->len == 0 || emit_v2N_hunk(v2N_COOKIE2, *cookie2, pbs)))
		r = STF_OK;

	free_chunk_content(cookie2);
	return r;
}

#ifdef XFRM_SUPPORT
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

static void ikev2_record_newaddr(struct state *st, void *arg_ip)
{
	ip_address *ip = arg_ip;

	if (!mobike_check_established(st))
		return;

	if (address_is_specified(st->st_deleted_local_addr)) {
		/*
		 * A work around for delay between new address and new route
		 * A better fix would be listen to  RTM_NEWROUTE, RTM_DELROUTE
		 */
		if (st->st_addr_change_event == NULL) {
			event_schedule(EVENT_v2_ADDR_CHANGE,
				       RTM_NEWADDR_ROUTE_DELAY, st);
		} else {
			address_buf b;
			dbg("#%lu MOBIKE ignore address %s change pending previous",
			    st->st_serialno, str_address_sensitive(ip, &b));
		}
	}
}

void record_newaddr(ip_address *ip, char *a_type)
{
	address_buf ip_str;
	dbg("XFRM RTM_NEWADDR %s %s", str_address(ip, &ip_str), a_type);
	for_each_state(ikev2_record_newaddr, ip, __func__);
}

static void ikev2_record_deladdr(struct state *st, void *arg_ip)
{
	ip_address *ip = arg_ip;

	if (!mobike_check_established(st))
		return;

	pexpect_st_local_endpoint(st);
	ip_address local_address = endpoint_address(st->st_interface->local_endpoint);
	/* ignore port */
	if (sameaddr(ip, &local_address)) {
		ip_address ip_p = st->st_deleted_local_addr;
		st->st_deleted_local_addr = local_address;
		struct state *cst = state_with_serialno(st->st_connection->newest_ipsec_sa);
		migration_down(cst->st_connection, cst);
		unroute_connection(st->st_connection);

		event_delete(EVENT_v2_LIVENESS, cst);

		if (st->st_addr_change_event == NULL) {
			event_schedule(EVENT_v2_ADDR_CHANGE, deltatime(0), st);
		} else {
			ipstr_buf o, n;
			dbg("#%lu MOBIKE new RTM_DELADDR %s pending previous %s",
			    st->st_serialno, ipstr(ip, &n), ipstr(&ip_p, &o));
		}
	}
}

void record_deladdr(ip_address *ip, char *a_type)
{
	address_buf ip_str;
	dbg("XFRM RTM_DELADDR %s %s", str_address(ip, &ip_str), a_type);
	for_each_state(ikev2_record_deladdr, ip, __func__);
}

#ifdef XFRM_SUPPORT
static void initiate_mobike_probe(struct state *st, struct starter_end *this,
				  const struct iface_endpoint *iface)
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
	pexpect_st_local_endpoint(st);
	/*
	 * XXX: why not local_endpoint or is this redundant?
	 *
	 * The interface changed (new address in .address) but
	 * continue to use the existing port.
	 */
	ip_port port = endpoint_port(st->st_interface->local_endpoint);
	st->st_mobike_local_endpoint = endpoint_from_address_protocol_port(this->addr,
									   st->st_interface->protocol,
									   port);
	st->st_mobike_host_nexthop = this->nexthop; /* for updown, after xfrm migration */
	const struct iface_endpoint *o_iface = st->st_interface;
	/* notice how it gets set back below */
	st->st_interface = iface;

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
	st->st_interface = o_iface;
	pexpect_st_local_endpoint(st);
}
#endif

#ifdef XFRM_SUPPORT
static const struct iface_endpoint *ikev2_src_iface(struct state *st,
						struct starter_end *this)
{
	/* success found a new source address */
	pexpect_st_local_endpoint(st);
	ip_port port = endpoint_port(st->st_interface->local_endpoint);
	ip_endpoint local_endpoint = endpoint_from_address_protocol_port(this->addr,
									 st->st_interface->protocol,
									 port);
	const struct iface_endpoint *iface = find_iface_endpoint_by_local_endpoint(local_endpoint);
	if (iface == NULL) {
		endpoint_buf b;
		dbg("#%lu no interface for %s try to initialize",
		    st->st_serialno, str_endpoint(&local_endpoint, &b));
		/* XXX: should this be building a global logger? */
		struct logger global_logger[1] = { GLOBAL_LOGGER(whack_log_fd), };
		find_ifaces(false, global_logger);
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

#ifdef XFRM_SUPPORT

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
	switch (resolve_defaultroute_one(&this, &that, true, st->st_logger)) {
	case 0:	/* success */
		/* cannot happen */
		/* ??? original code treated this as failure */
		/* bad_case(0); */
		log_state(RC_LOG, st, "unexpected SUCCESS from first resolve_defaultroute_one");
		/* FALL THROUGH */
	case -1:	/* failure */
	{
		/* keep this DEBUG, if a libreswan log, too many false +ve */
		address_buf b;
		dbg("#%lu no local gateway to reach %s",
		    st->st_serialno, str_address(&that.addr, &b));
		break;
	}

	case 1: /* please call again: more to do */
		switch (resolve_defaultroute_one(&this, &that, true, st->st_logger)) {
		case 1: /* please call again: more to do */
			/* cannot happen */
			/* ??? original code treated this as failure */
			/* bad_case(1); */
			log_state(RC_LOG, st, "unexpected TRY AGAIN from second resolve_defaultroute_one");
			/* FALL THROUGH */
		case -1:	/* failure */
		{
			address_buf g, b;
			log_state(RC_LOG, st, "no local source address to reach remote %s, local gateway %s",
				  str_address_sensitive(&that.addr, &b),
				  str_address(&this.nexthop, &g));
			break;
		}

		case 0:	/* success */
		{
			const struct iface_endpoint *iface = ikev2_src_iface(st, &this);
			if (iface != NULL)
				initiate_mobike_probe(st, &this, iface);
			break;
		}

		}
		break;
	}

#else /* !defined(XFRM_SUPPORT) */

	log_state(RC_LOG, st, "without NETKEY we cannot ikev2_addr_change()");

#endif
}
