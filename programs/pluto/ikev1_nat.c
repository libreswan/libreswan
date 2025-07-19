/* Libreswan NAT-Traversal
 *
 * Copyright (C) 2002-2003 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2005 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2006 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2007-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2009 Gilles Espinasse <g.esp@free.fr>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2011 Shinichi Furuso <Shinichi.Furuso@jp.sony.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2014 Antony Antony <antony@phenome.org>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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
#include "log.h"
#include "nat_traversal.h"
#include "ikev1_nat.h"
#include "state.h"
#include "connections.h"
#include "iface.h"
#include "ip_info.h"
#include "pending.h"
#include "ikev1_vendorid.h"

/*
 * Add NAT-Traversal VIDs (supported ones)
 *
 * Used when we're Initiator
 */
bool emit_nat_traversal_vid(struct pbs_out *outs, const struct connection *c)
{
	ldbg(outs->logger, "nat add vid");

	/*
	 * Some Cisco's have a broken NAT-T implementation where it
	 * sends one NAT payload per draft, and one NAT payload for RFC.
	 * nat-ikev1-method={both|drafts|rfc} helps us claim we only support the
	 * drafts, so we don't hit the bad Cisco code.
	 *
	 * nat-ikev1-method=none was added as a workaround for some clients
	 * that want to do no-encapsulation, but are triggered for encapsulation
	 * when they see NATT payloads.
	 */
	switch (c->config->ikev1_natt) {
	case NATT_RFC:
		ldbg(outs->logger, "skipping VID_NATT drafts");
		return out_v1VID(outs, VID_NATT_RFC);

	case NATT_BOTH:
		ldbg(outs->logger, "emitting draft and RFC NATT VIDs");
		return (out_v1VID(outs, VID_NATT_RFC) &&
			/* drafts */
			out_v1VID(outs, VID_NATT_IETF_03) &&
			out_v1VID(outs, VID_NATT_IETF_02_N) &&
			out_v1VID(outs, VID_NATT_IETF_02));

	case NATT_DRAFTS:
		ldbg(outs->logger, "skipping VID_NATT_RFC");
		return (out_v1VID(outs, VID_NATT_IETF_03) &&
			out_v1VID(outs, VID_NATT_IETF_02_N) &&
			out_v1VID(outs, VID_NATT_IETF_02));

	case NATT_NONE:
		/* This should never be reached, but makes compiler happy */
		ldbg(outs->logger, "not emitting any NATT VID's");
		return true;

	default:
		bad_case(c->config->ikev1_natt);
	}
}

static enum natt_method nat_traversal_vid_to_method(enum known_vendorid nat_t_vid,
						    struct logger *logger)
{
	switch (nat_t_vid) {
	case VID_NATT_IETF_00:
		ldbg(logger, "NAT_TRAVERSAL_METHOD_IETF_00_01 no longer supported");
		return NAT_TRAVERSAL_METHOD_none;

	case VID_NATT_IETF_02:
	case VID_NATT_IETF_02_N:
	case VID_NATT_IETF_03:
		ldbg(logger, "returning NAT-T method NAT_TRAVERSAL_METHOD_IETF_02_03");
		return NAT_TRAVERSAL_METHOD_IETF_02_03;

	case VID_NATT_IETF_04:
	case VID_NATT_IETF_05:
	case VID_NATT_IETF_06:
	case VID_NATT_IETF_07:
	case VID_NATT_IETF_08:
	case VID_NATT_DRAFT_IETF_IPSEC_NAT_T_IKE:
		ldbg(logger, "NAT-T VID draft-ietf-ipsc-nat-t-ike-04 to 08 assumed to function as RFC 3947 ");
		return NAT_TRAVERSAL_METHOD_IETF_RFC;

	case VID_NATT_RFC:
		ldbg(logger, "returning NAT-T method NAT_TRAVERSAL_METHOD_IETF_RFC");
		return NAT_TRAVERSAL_METHOD_IETF_RFC;

	default:
		return 0;
	}
}

void check_nat_traversal_vid(struct ike_sa *ike, const struct msg_digest *md)
{
	ldbg(ike->sa.logger, "sender checking NAT-T: conn %s; VID %d",
	     (ike->sa.st_connection->config->ikev1_natt == NATT_NONE ? "disabled" : "enabled"),
	     md->v1_quirks.qnat_traversal_vid);
	if ((md->v1_quirks.qnat_traversal_vid != VID_none) &&
	    (ike->sa.st_connection->config->ikev1_natt != NATT_NONE)) {
		enum natt_method v = nat_traversal_vid_to_method(md->v1_quirks.qnat_traversal_vid,
								 ike->sa.logger);

		ike->sa.hidden_variables.st_nat_traversal = LELEM(v);
		name_buf vb;
		ldbg(ike->sa.logger, "flagging possible NAT-traversal with method %s",
		    str_enum_long(&natt_method_names, v, &vb));
	}
}

static void ikev1_natd_lookup(struct msg_digest *md, struct state *st)
{
	const struct hash_desc *const hasher = st->st_oakley.ta_prf->hasher;
	const struct payload_digest *const hd = md->chain[ISAKMP_NEXT_NATD_RFC];

	passert(md->iface != NULL);

	/* Count NAT-D */
	int i = 0;
	for (const struct payload_digest *p = hd; p != NULL; p = p->next)
		i++;

	/*
	 * We need at least 2 NAT-D (1 for us, many for peer)
	 */
	if (i < 2) {
		llog(RC_LOG, st->logger,
		     "NAT-Traversal: Only %d NAT-D - Aborting NAT-Traversal negotiation",
		     i);
		st->hidden_variables.st_nat_traversal = LEMPTY;
		return;
	}

	/* First: one with my IP & port */

	struct crypt_mac hash_local = natd_hash(hasher, &st->st_ike_spis,
						md->iface->local_endpoint,
						st->logger);

	/* Second: one with sender IP & port */

	struct crypt_mac hash_remote = natd_hash(hasher, &st->st_ike_spis,
						 md->sender, st->logger);

	if (LDBGP(DBG_BASE, st->logger)) {
		LDBG_log(st->logger, "expected NAT-D(local):");
		LDBG_hunk(st->logger, hash_local);
		LDBG_log(st->logger, "expected NAT-D(remote):");
		LDBG_hunk(st->logger, hash_remote);
	}

	bool found_local = false;
	bool found_remote = false;

	for (const struct payload_digest *p = hd; p != NULL; p = p->next) {

		shunk_t left = pbs_in_left(&p->pbs);
		if (LDBGP(DBG_BASE, st->logger)) {
			LDBG_log(st->logger, "received NAT-D:");
			LDBG_hunk(st->logger, left);
		}

		if (hunk_eq(left, hash_local))
			found_local = true;
		if (hunk_eq(left, hash_remote))
			found_remote = true;
		if (found_local && found_remote)
			break;
	}

	natd_lookup_common(st, md->sender, found_local, found_remote);
}

bool ikev1_nat_traversal_add_natd(struct pbs_out *outs,
				  const struct msg_digest *md)
{
	const struct state *st = md->v1_st;
	/*
	 * XXX: This seems to be a very convoluted way of coming up
	 * with the RCOOKIE.  It would probably be easier to just pass
	 * in the RCOOKIE - the callers should know if it is zero, or
	 * found in the MD.
	 */
	ike_spis_t ike_spis = {
		.initiator = st->st_ike_spis.initiator,
		.responder = ike_spi_is_zero(&st->st_ike_spis.responder) ?
		md->hdr.isa_ike_responder_spi : st->st_ike_spis.responder,
	};

	passert(st->st_oakley.ta_prf != NULL);

	ldbg(outs->logger, "emitting NAT-D payloads");

	unsigned remote_port = endpoint_hport(st->st_remote_endpoint);
	unsigned short local_port = endpoint_hport(st->st_iface_endpoint->local_endpoint);
	if (st->st_connection->config->encapsulation == YNA_YES) {
		ldbg(outs->logger, "NAT-T: encapsulation=yes, so mangling hash to force NAT-T detection");
		local_port = remote_port = 0;
	}

	struct_desc *pd = (st->hidden_variables.st_nat_traversal & NAT_T_WITH_RFC_VALUES ? &isakmp_nat_d :
			   &isakmp_nat_d_drafts);

	/* first: emit payload with hash of sender IP & port */

	const ip_endpoint remote_endpoint = set_endpoint_port(md->sender, ip_hport(remote_port));
	struct crypt_mac hash;

	hash = natd_hash(st->st_oakley.ta_prf->hasher,
			 &ike_spis, remote_endpoint,
			 st->logger);
	if (!ikev1_out_generic_raw(pd, outs, hash.ptr, hash.len,
				   "NAT-D"))
		return false;

	/* second: emit payload with hash of my IP & port */

	const ip_endpoint local_endpoint = set_endpoint_port(md->iface->local_endpoint, ip_hport(local_port));
	hash = natd_hash(st->st_oakley.ta_prf->hasher,
			 &ike_spis, local_endpoint,
			 st->logger);
	return ikev1_out_generic_raw(pd, outs, hash.ptr, hash.len,
				     "NAT-D");
}

/*
 * nat_traversal_natoa_lookup()
 *
 * Look for NAT-OA in message
 */

void nat_traversal_natoa_lookup(struct msg_digest *md,
				struct hidden_variables *hv,
				struct logger *logger)
{
	passert(md->iface != NULL);

	/* Initialize NAT-OA */
	hv->st_nat_oa = ipv4_info.address.zero;

	/* Count NAT-OA */
	const struct payload_digest *p;
	int i = 0;
	for (p = md->chain[ISAKMP_NEXT_NATOA_RFC]; p != NULL; p = p->next) {
		i++;
	}

	ldbg(logger, "NAT-Traversal: received %d NAT-OA.", i);

	if (i == 0)
		return;

	if (!hv->st_nated_peer) {
		llog(RC_LOG, logger,
		     "NAT-Traversal: received %d NAT-OA. Ignored because peer is not NATed",
		     i);
		return;
	}

	if (i > 1) {
		llog(RC_LOG, logger,
		     "NAT-Traversal: received %d NAT-OA. Using first; ignoring others",
		     i);
	}

	/* Take first */
	p = md->chain[ISAKMP_NEXT_NATOA_RFC];

	if (LDBGP(DBG_BASE, logger)) {
		shunk_t nat_ao = pbs_in_all(&p->pbs);
		LDBG_log(logger, "NAT-OA:");
		LDBG_hunk(logger, nat_ao);
	}

	ip_address ip;
	struct pbs_in pbs = p->pbs;

	const struct ip_info *ipv;
	switch (p->payload.nat_oa.isanoa_idtype) {
	case ID_IPV4_ADDR:
		ipv = &ipv4_info;
		break;
	case ID_IPV6_ADDR:
		ipv = &ipv6_info;
		break;
	default:
		llog(RC_LOG, logger,
			    "NAT-Traversal: invalid ID Type (%d) in NAT-OA - ignored",
			    p->payload.nat_oa.isanoa_idtype);
		return;
	}

	diag_t d = pbs_in_address(&pbs, &ip, ipv, "NAT-Traversal: NAT-OA IP");
	if (d != NULL) {
		llog(RC_LOG, logger, "%s", str_diag(d));
		pfree_diag(&d);
		return;
	}

	if (!address_is_specified(ip)) {
		address_buf b;
		llog(RC_LOG, logger,
		     "NAT-Traversal: received %s NAT-OA...",
		     str_address(&ip, &b));
	} else {
		address_buf b;
		ldbg(logger, "received NAT-OA: %s", str_address(&ip, &b));
		hv->st_nat_oa = ip;
	}
}

static bool emit_one_natoa(struct pbs_out *outs,
			   struct_desc *pd,
			   const ip_address ip,
			   const char *nm)
{
	struct isakmp_nat_oa natoa = {
		.isanoa_idtype = address_info(ip)->id_ip_addr,
	};

	struct pbs_out pbs;
	if (!pbs_out_struct(outs, natoa, pd, &pbs)) {
		return false;
	}

	if (!pbs_out_address(&pbs, ip, nm)) {
		/* already logged */
		return false;
	}

	address_buf ab;
	ldbg(outs->logger, "NAT-OAi (S): %s", str_address(&ip, &ab));
	close_pbs_out(&pbs);
	return true;
}

bool v1_nat_traversal_add_initiator_natoa(struct pbs_out *outs, struct state *st)
{
	ip_address ipinit = st->st_iface_endpoint->ip_dev->local_address;
	ip_address ipresp = endpoint_address(st->st_remote_endpoint);

	struct_desc *pd = (st->hidden_variables.st_nat_traversal & NAT_T_WITH_RFC_VALUES ? &isakmp_nat_oa :
			   &isakmp_nat_oa_drafts);

	return (emit_one_natoa(outs, pd, ipinit, "NAT-OAi") &&
		emit_one_natoa(outs, pd, ipresp, "NAT-OAr"));
}

static void nat_traversal_show_result(struct state *st, uint16_t sport)
{
	lset_t nt = st->hidden_variables.st_nat_traversal;
	const char *rslt = (st->hidden_variables.st_nated_host ? "I am behind NAT" :
			    st->hidden_variables.st_nated_peer ? "peer behind NAT" :
			    "no NAT detected");

	name_buf nb;
	ldbg(st->logger, "NAT-Traversal: Result using %s sender port %" PRIu16 ": %s",
	     LHAS(nt, NAT_TRAVERSAL_METHOD_IETF_RFC) ? str_enum_long(&natt_method_names,
								     NAT_TRAVERSAL_METHOD_IETF_RFC, &nb) :
	     LHAS(nt, NAT_TRAVERSAL_METHOD_IETF_02_03) ? str_enum_long(&natt_method_names,
								       NAT_TRAVERSAL_METHOD_IETF_02_03, &nb) :
	     "unknown or unsupported method",
	     sport,
	     rslt);
}

void ikev1_natd_init(struct ike_sa *ike, struct msg_digest *md)
{
	lset_buf lb;
	ldbg(ike->sa.logger, "init checking NAT-T: conn %s; vid %s",
	     ike->sa.st_connection->config->ikev1_natt == NATT_NONE ? "disabled" : "enabled",
	     str_lset(&natt_method_names, ike->sa.hidden_variables.st_nat_traversal, &lb));

	if (ike->sa.st_connection->config->ikev1_natt == NATT_NONE) {
		ldbg(ike->sa.logger, "skip NATD payloads due to nat-ikev1-method=none configuration");
		return;
	}

	if (ike->sa.hidden_variables.st_nat_traversal != LEMPTY) {
		if (PBAD(ike->sa.logger, ike->sa.st_oakley.ta_prf == NULL)) {
			/*
			 * This connection is doomed - no PRF for NATD
			 * hash Probably in FIPS trying MD5 ?
			 *
			 * Nothing will get send, so just do nothing
			 */
			llog(RC_LOG, ike->sa.logger,
			     "cannot compute NATD payloads without valid PRF");
			return;
		}
		ikev1_natd_lookup(md, &ike->sa);

		if (ike->sa.hidden_variables.st_nat_traversal != LEMPTY) {
			nat_traversal_show_result(&ike->sa, endpoint_hport(md->sender));
		}
	}

	schedule_v1_nat_keepalive(&ike->sa);
}

/*
 * XXX: there should be no maybes about this - each of the callers
 * know the state and hence, know if there's any point in calling this
 * function.
 */
static void v1_natify_initiator_endpoints(struct state *st, where_t where);

void v1_maybe_natify_initiator_endpoints(struct state *st, where_t where)
{
	/*
	 * If we're initiator and NAT-T is detected, we
	 * need to change port (MAIN_I3, QUICK_I1 or AGGR_I2)
	 */
	/* XXX This code does not properly support non-default IKE ports! */
	if ((st->st_state->kind == STATE_MAIN_I3 ||
	     st->st_state->kind == STATE_QUICK_I1 ||
	     st->st_state->kind == STATE_AGGR_I2) &&
	    nat_traversal_detected(st) &&
	    endpoint_hport(st->st_iface_endpoint->local_endpoint) != NAT_IKE_UDP_PORT) {
		ldbg(st->logger, "NAT-T: "PRI_SO" in %s floating IKEv1 ports to PLUTO_NAT_PORT %d",
		     pri_so(st->st_serialno), st->st_state->short_name,
		     NAT_IKE_UDP_PORT);
		v1_natify_initiator_endpoints(st, where);
	}
}

/*
 * Update the initiator endpoints so that all further exchanges are
 * encapsulated in UDP and exchanged between :PLUTO_NAT_PORTs (i.e.,
 * :4500).
 */
void v1_natify_initiator_endpoints(struct state *st, where_t where)
{
	/*
	 * Float the local endpoint's port to :PLUTO_NAT_PORT (:4500)
	 * and then re-bind the interface so that all further
	 * exchanges use that port.
	 */
	endpoint_buf b1, b2;
	ip_endpoint new_local_endpoint = set_endpoint_port(st->st_iface_endpoint->local_endpoint, ip_hport(NAT_IKE_UDP_PORT));
	ldbg(st->logger, "NAT: "PRI_SO" floating local endpoint from %s to %s using NAT_IKE_UDP_PORT "PRI_WHERE,
	     pri_so(st->st_serialno),
	     str_endpoint(&st->st_iface_endpoint->local_endpoint, &b1),
	     str_endpoint(&new_local_endpoint, &b2),
	     pri_where(where));
	/*
	 * If not already ...
	 */
	if (!endpoint_eq_endpoint(new_local_endpoint, st->st_iface_endpoint->local_endpoint)) {
		/*
		 * For IPv4, both :PLUTO_PORT and :PLUTO_NAT_PORT are
		 * opened by server.c so the new endpoint using
		 * :PLUTO_NAT_PORT should exist.  IPv6 nat isn't
		 * supported.
		 *
		 * Returns a new reference.
		 */
		struct iface_endpoint *i = find_iface_endpoint_by_local_endpoint(new_local_endpoint);
		if (pexpect(i != NULL)) {
			endpoint_buf b;
			ldbg(st->logger, "NAT: "PRI_SO" floating endpoint ended up on interface %s %s",
			     pri_so(st->st_serialno), i->ip_dev->real_device_name,
			     str_endpoint(&i->local_endpoint, &b));
			iface_endpoint_delref(&st->st_iface_endpoint);
			st->st_iface_endpoint = i;
		}
	}

	/*
	 * Float the remote port to :PLUTO_NAT_PORT (:4500)
	 */
	ip_endpoint new_endpoint = set_endpoint_port(st->st_remote_endpoint,
						     ip_hport(NAT_IKE_UDP_PORT));
	endpoint_buf oep, nep;
	ldbg(st->logger,
	     "NAT-T: "PRI_SO" floating remote port from %s to %s using NAT_IKE_UDP_PORT "PRI_WHERE,
	     pri_so(st->st_serialno),
	     str_endpoint(&st->st_remote_endpoint, &oep),
	     str_endpoint(&new_endpoint, &nep),
	     pri_where(where));
	st->st_remote_endpoint = new_endpoint;
}
