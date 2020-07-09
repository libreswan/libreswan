/*
 * Libreswan NAT-Traversal
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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>     /* used only if MSG_NOSIGNAL not defined */
#include <stdint.h> /* for uint32_t */
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/udp.h>

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "log.h"
#include "server.h"
#include "state.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"
#include "packet.h"
#include "demux.h"
#include "kernel.h"
#include "whack.h"
#include "timer.h"
#include "ike_alg.h"
#include "ike_alg_hash.h"
#include "pluto_crypt.h"  /* for pluto_crypto_req & pluto_crypto_req_cont */
#include "ikev2.h"
#include "crypt_hash.h"
#include "ip_address.h"
#include "ike_spi.h"
#include "crypto.h"
#include "vendor.h"
#include "send.h"
#include "nat_traversal.h"
#include "ikev2_send.h"
#include "state_db.h"
#include "ip_info.h"
#include "iface.h"

/* As per https://tools.ietf.org/html/rfc3948#section-4 */
#define DEFAULT_KEEP_ALIVE_SECS  20

bool nat_traversal_enabled = TRUE; /* can get disabled if kernel lacks support */

static deltatime_t nat_kap = DELTATIME_INIT(DEFAULT_KEEP_ALIVE_SECS);	/* keep-alive period */
static bool nat_kap_event = FALSE;

void init_nat_traversal(deltatime_t keep_alive_period)
{
	if (deltamillisecs(keep_alive_period) != 0)
		nat_kap = keep_alive_period;

	dbg("init_nat_traversal() initialized with keep_alive=%jds",
	    deltasecs(keep_alive_period));
	libreswan_log("NAT-Traversal support %s",
		nat_traversal_enabled ? " [enabled]" : " [disabled]");

	init_oneshot_timer(EVENT_NAT_T_KEEPALIVE, nat_traversal_ka_event);
}

static struct crypt_mac natd_hash(const struct hash_desc *hasher,
				  const ike_spis_t *spis,
				  const ip_endpoint *endpoint)
{
	/* only responder's IKE SPI can be zero */
	if (ike_spi_is_zero(&spis->initiator)) {
		dbg("nat: IKE.SPIi is unexpectedly zero");
		pexpect(impair.ike_initiator_spi-1/*1-bias*/ == 0);
	}
	if (ike_spi_is_zero(&spis->responder)) {
		/* IKE_SA_INIT exchange */
		dbg("nat: IKE.SPIr is zero");
	}

	/*
	 * RFC 3947
	 *
	 *   HASH = HASH(IKE.SPIi | IKE.SPIr | IP | Port)
	 *
	 * All values in network order
	 */
	struct crypt_hash *ctx = crypt_hash_init("NATD", hasher);

	crypt_hash_digest_thing(ctx, "IKE SPIi", spis->initiator);
	crypt_hash_digest_thing(ctx, "IKE SPIr", spis->responder);

	ip_address ip = endpoint_address(endpoint);
	shunk_t ap = address_as_shunk(&ip);
	crypt_hash_digest_hunk(ctx, "IP addr", ap);

	uint16_t np = nport(endpoint_port(endpoint));
	crypt_hash_digest_thing(ctx, "PORT", np);
	struct crypt_mac hash = crypt_hash_final_mac(&ctx);

	if (DBGP(DBG_BASE)) {
		DBG_log("natd_hash: hasher=%p(%d)", hasher,
			(int)hasher->hash_digest_size);
		DBG_dump_thing("natd_hash: icookie=", spis->initiator);
		DBG_dump_thing("natd_hash: rcookie=", spis->responder);
		DBG_dump_hunk("natd_hash: ip=", ap);
		DBG_dump_thing("natd_hash: port=", np);
		DBG_dump_hunk("natd_hash: hash=", hash);
	}
	return hash;
}

/*
 * Add  NAT-Traversal IKEv2 Notify payload (v2N)
 */
bool ikev2_out_nat_v2n(pb_stream *outs, struct state *st,
		       const ike_spi_t *ike_responder_spi)
{
	/*
	 * IKE SA INIT exchange can have responder's SPI still zero.
	 * While .st_ike_spis.responder should also be zero it often
	 * isn't - code likes to install the responder's SPI before
	 * everything is ready (only to have to the remove it).
	 */
	ike_spis_t ike_spis = {
		.initiator = st->st_ike_spis.initiator,
		.responder = *ike_responder_spi,
	};

	/* if encapsulation=yes, force NAT-T detection by using wrong port for hash calc */
	pexpect_st_local_endpoint(st);
	uint16_t lport = endpoint_hport(&st->st_interface->local_endpoint);
	if (st->st_connection->encaps == yna_yes) {
		dbg("NAT-T: encapsulation=yes, so mangling hash to force NAT-T detection");
		lport = 0;
	}
	ip_endpoint local_endpoint = set_endpoint_hport(&st->st_interface->local_endpoint, lport);
	ip_endpoint remote_endpoint = st->st_remote_endpoint;
	return ikev2_out_natd(&local_endpoint, &remote_endpoint,
			      &ike_spis, outs);
}

bool ikev2_out_natd(const ip_endpoint *local_endpoint,
		    const ip_endpoint *remote_endpoint,
		    const ike_spis_t *ike_spis,
		    pb_stream *outs)
{
	struct crypt_mac hb;

	dbg(" NAT-Traversal support %s add v2N payloads.",
	    nat_traversal_enabled ? " [enabled]" : " [disabled]");

	/* First: one with local (source) IP & port */

	hb = natd_hash(&ike_alg_hash_sha1, ike_spis, local_endpoint);
	if (!emit_v2N_hunk(v2N_NAT_DETECTION_SOURCE_IP, hb, outs)) {
		return false;
	}

	/* Second: one with remote (destination) IP & port */

	hb = natd_hash(&ike_alg_hash_sha1, ike_spis, remote_endpoint);
	if (!emit_v2N_hunk(v2N_NAT_DETECTION_DESTINATION_IP, hb, outs)) {
		return false;
	}

	return true;
}

/*
 * Add NAT-Traversal VIDs (supported ones)
 *
 * Used when we're Initiator
 */
bool nat_traversal_insert_vid(pb_stream *outs, const struct connection *c)
{
	dbg("nat add vid");

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
	switch (c->ikev1_natt) {
	case NATT_RFC:
		dbg("skipping VID_NATT drafts");
		return out_vid(outs, VID_NATT_RFC);

	case NATT_BOTH:
		dbg("sending draft and RFC NATT VIDs");
		if (!out_vid(outs, VID_NATT_RFC))
			return FALSE;
		/* FALL THROUGH */
	case NATT_DRAFTS:
		dbg("skipping VID_NATT_RFC");
		return
			out_vid(outs, VID_NATT_IETF_03) &&
			out_vid(outs, VID_NATT_IETF_02_N) &&
			out_vid(outs, VID_NATT_IETF_02);

	case NATT_NONE:
		/* This should never be reached, but makes compiler happy */
		dbg("not sending any NATT VID's");
		return TRUE;

	default:
		bad_case(c->ikev1_natt);
	}
}

static enum natt_method nat_traversal_vid_to_method(enum known_vendorid nat_t_vid)
{
	switch (nat_t_vid) {
	case VID_NATT_IETF_00:
		dbg("NAT_TRAVERSAL_METHOD_IETF_00_01 no longer supported");
		return NAT_TRAVERSAL_METHOD_none;

	case VID_NATT_IETF_02:
	case VID_NATT_IETF_02_N:
	case VID_NATT_IETF_03:
		dbg("returning NAT-T method NAT_TRAVERSAL_METHOD_IETF_02_03");
		return NAT_TRAVERSAL_METHOD_IETF_02_03;

	case VID_NATT_IETF_04:
	case VID_NATT_IETF_05:
	case VID_NATT_IETF_06:
	case VID_NATT_IETF_07:
	case VID_NATT_IETF_08:
	case VID_NATT_DRAFT_IETF_IPSEC_NAT_T_IKE:
		dbg("NAT-T VID draft-ietf-ipsc-nat-t-ike-04 to 08 assumed to function as RFC 3947 ");
		/* FALL THROUGH */
	case VID_NATT_RFC:
		dbg("returning NAT-T method NAT_TRAVERSAL_METHOD_IETF_RFC");
		return NAT_TRAVERSAL_METHOD_IETF_RFC;

	default:
		return 0;
	}
}

void set_nat_traversal(struct state *st, const struct msg_digest *md)
{
	dbg("sender checking NAT-T: %s; VID %d",
	    nat_traversal_enabled ? "enabled" : "disabled",
	    md->quirks.qnat_traversal_vid);
	if (nat_traversal_enabled && md->quirks.qnat_traversal_vid != VID_none) {
		enum natt_method v = nat_traversal_vid_to_method(md->quirks.qnat_traversal_vid);

		st->hidden_variables.st_nat_traversal = LELEM(v);
		dbg("enabling possible NAT-traversal with method %s",
		    enum_name(&natt_method_names, v));
	}
}

static void natd_lookup_common(struct state *st,
	const ip_address *sender,
	bool found_me, bool found_peer)
{
	st->hidden_variables.st_natd = address_any(&ipv4_info);

	/* update NAT-T settings for local policy */
	switch (st->st_connection->encaps) {
	case yna_auto:
		dbg("NAT_TRAVERSAL encaps using auto-detect");
		if (!found_me) {
			dbg("NAT_TRAVERSAL this end is behind NAT");
			st->hidden_variables.st_nat_traversal |= LELEM(NATED_HOST);
			st->hidden_variables.st_natd = *sender;
		} else {
			dbg("NAT_TRAVERSAL this end is NOT behind NAT");
		}

		if (!found_peer) {
			address_buf b;
			dbg("NAT_TRAVERSAL that end is behind NAT %s",
			    str_address(sender, &b));
			st->hidden_variables.st_nat_traversal |= LELEM(NATED_PEER);
			st->hidden_variables.st_natd = *sender;
		} else {
			dbg("NAT_TRAVERSAL that end is NOT behind NAT");
		}
		break;

	case yna_no:
		st->hidden_variables.st_nat_traversal |= LEMPTY;
		dbg("NAT_TRAVERSAL local policy prohibits encapsulation");
		break;

	case yna_yes:
		dbg("NAT_TRAVERSAL local policy enforces encapsulation");
		dbg("NAT_TRAVERSAL forceencaps enabled");
		st->hidden_variables.st_nat_traversal |=
			LELEM(NATED_PEER) | LELEM(NATED_HOST);
		st->hidden_variables.st_natd = *sender;
		break;
	}

	if (st->st_connection->nat_keepalive) {
		address_buf b;
		dbg("NAT_TRAVERSAL nat-keepalive enabled %s", str_address(sender, &b));
	}
}

static void ikev1_natd_lookup(struct msg_digest *md)
{
	struct state *st = md->st;
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
		loglog(RC_LOG_SERIOUS,
			"NAT-Traversal: Only %d NAT-D - Aborting NAT-Traversal negotiation",
			i);
		st->hidden_variables.st_nat_traversal = LEMPTY;
		return;
	}

	/* First: one with my IP & port */

	struct crypt_mac hash_local = natd_hash(hasher, &st->st_ike_spis,
						&md->iface->local_endpoint);

	/* Second: one with sender IP & port */

	struct crypt_mac hash_remote = natd_hash(hasher, &st->st_ike_spis,
						 &md->sender);

	if (DBGP(DBG_BASE)) {
		DBG_dump_hunk("expected NAT-D(local):", hash_local);
		DBG_dump_hunk("expected NAT-D(remote):", hash_remote);
	}

	bool found_local = false;
	bool found_remote = false;

	for (const struct payload_digest *p = hd; p != NULL; p = p->next) {
		if (DBGP(DBG_BASE)) {
			DBG_dump("received NAT-D:", p->pbs.cur,
				 pbs_left(&p->pbs));
		}

		shunk_t left = pbs_in_left_as_shunk(&p->pbs);
		if (hunk_eq(left, hash_local))
			found_local = true;
		if (hunk_eq(left, hash_remote))
			found_remote = true;
		if (found_local && found_remote)
			break;
	}

	natd_lookup_common(st, &md->sender, found_local, found_remote);
}

bool ikev1_nat_traversal_add_natd(pb_stream *outs,
				  const struct msg_digest *md)
{
	const struct state *st = md->st;
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

	dbg("sending NAT-D payloads");

	unsigned remote_port = endpoint_hport(&st->st_remote_endpoint);
	pexpect_st_local_endpoint(st);
	unsigned short local_port = endpoint_hport(&st->st_interface->local_endpoint);
	if (st->st_connection->encaps == yna_yes) {
		dbg("NAT-T: encapsulation=yes, so mangling hash to force NAT-T detection");
		local_port = remote_port = 0;
	}

	struct_desc *pd = LDISJOINT(st->hidden_variables.st_nat_traversal, NAT_T_WITH_RFC_VALUES) ?
		&isakmp_nat_d_drafts : &isakmp_nat_d;

	/* first: emit payload with hash of sender IP & port */

	const ip_endpoint remote_endpoint = set_endpoint_hport(&md->sender,
							       remote_port);
	struct crypt_mac hash;

	hash = natd_hash(st->st_oakley.ta_prf->hasher,
			 &ike_spis, &remote_endpoint);
	if (!ikev1_out_generic_raw(pd, outs, hash.ptr, hash.len,
				   "NAT-D"))
		return FALSE;

	/* second: emit payload with hash of my IP & port */

	const ip_endpoint local_endpoint = set_endpoint_hport(&md->iface->local_endpoint,
							      local_port);
	hash = natd_hash(st->st_oakley.ta_prf->hasher,
			 &ike_spis, &local_endpoint);
	return ikev1_out_generic_raw(pd, outs, hash.ptr, hash.len,
				     "NAT-D");
}

/*
 * nat_traversal_natoa_lookup()
 *
 * Look for NAT-OA in message
 */
void nat_traversal_natoa_lookup(struct msg_digest *md,
				struct hidden_variables *hv)
{
	passert(md->iface != NULL);

	/* Initialize NAT-OA */
	hv->st_nat_oa = address_any(&ipv4_info);

	/* Count NAT-OA */
	const struct payload_digest *p;
	int i = 0;
	for (p = md->chain[ISAKMP_NEXT_NATOA_RFC]; p != NULL; p = p->next) {
		i++;
	}

	dbg("NAT-Traversal: received %d NAT-OA.", i);

	if (i == 0)
		return;

	if (!LHAS(hv->st_nat_traversal, NATED_PEER)) {
		loglog(RC_LOG_SERIOUS,
			"NAT-Traversal: received %d NAT-OA. Ignored because peer is not NATed",
			i);
		return;
	}

	if (i > 1) {
		loglog(RC_LOG_SERIOUS,
			"NAT-Traversal: received %d NAT-OA. Using first; ignoring others",
			i);
	}

	/* Take first */
	p = md->chain[ISAKMP_NEXT_NATOA_RFC];

	if (DBGP(DBG_BASE)) {
		DBG_dump("NAT-OA:", p->pbs.start, pbs_room(&p->pbs));
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
		loglog(RC_LOG_SERIOUS,
			"NAT-Traversal: invalid ID Type (%d) in NAT-OA - ignored",
			p->payload.nat_oa.isanoa_idtype);
		return;
	}

	if (!pbs_in_address(&ip, ipv, &pbs, "NAT-Traversal: NAT-OA IP")) {
		return;
	}

	ipstr_buf b;
	dbg("received NAT-OA: %s", ipstr(&ip, &b));

	if (address_is_any(&ip)) {
		loglog(RC_LOG_SERIOUS,
			"NAT-Traversal: received 0.0.0.0 NAT-OA...");
	} else {
		hv->st_nat_oa = ip;
	}
}

static bool emit_one_natoa(pb_stream *outs,
			   struct_desc *pd,
			   const ip_address *ip,
			   const char *nm)
{
	pb_stream pbs;

	struct isakmp_nat_oa natoa = {
		.isanoa_idtype = addrtypeof(ip) == AF_INET ?
			ID_IPV4_ADDR : ID_IPV6_ADDR,
	};
	if (!out_struct(&natoa, pd, outs, &pbs) ||
	    !pbs_out_address(ip, &pbs, nm))
		return FALSE;

	address_buf ab;
	dbg("NAT-OAi (S): %s", str_address(ip, &ab));
	close_output_pbs(&pbs);
	return TRUE;
}

bool nat_traversal_add_natoa(pb_stream *outs, struct state *st,
			     bool initiator)
{
	const ip_address *ipinit, *ipresp;

	pexpect_st_local_endpoint(st);
	if (initiator) {
		ipinit = &st->st_interface->local_endpoint;
		ipresp = &st->st_remote_endpoint;
	} else {
		ipresp = &st->st_interface->local_endpoint;
		ipinit = &st->st_remote_endpoint;
	}

	struct_desc *pd = LDISJOINT(st->hidden_variables.st_nat_traversal, NAT_T_WITH_RFC_VALUES) ?
		&isakmp_nat_oa_drafts : &isakmp_nat_oa;

	return
		emit_one_natoa(outs, pd, ipinit, "NAT-OAi") &&
		emit_one_natoa(outs, pd, ipresp, "NAT-OAr");
}

static void nat_traversal_show_result(lset_t nt, uint16_t sport)
{
	const char *rslt = (nt & NAT_T_DETECTED) ?
		bitnamesof(natt_bit_names, nt & NAT_T_DETECTED) :
		"no NAT detected";

	dbg("NAT-Traversal: Result using %s sender port %" PRIu16 ": %s",
	    LHAS(nt, NAT_TRAVERSAL_METHOD_IETF_RFC) ?
	    enum_name(&natt_method_names,
		      NAT_TRAVERSAL_METHOD_IETF_RFC) :
	    LHAS(nt, NAT_TRAVERSAL_METHOD_IETF_02_03) ?
	    enum_name(&natt_method_names,
		      NAT_TRAVERSAL_METHOD_IETF_02_03) :
	    "unknown or unsupported method",
	    sport,
	    rslt);
}

void ikev1_natd_init(struct state *st, struct msg_digest *md)
{
	dbg("init checking NAT-T: %s; %s",
	    nat_traversal_enabled ? "enabled" : "disabled",
	    bitnamesof(natt_bit_names, st->hidden_variables.st_nat_traversal));

	if (st->hidden_variables.st_nat_traversal != LEMPTY) {
		if (md->st->st_oakley.ta_prf == NULL) {
			/*
			 * This connection is doomed - no PRF for NATD hash
			 * Probably in FIPS trying MD5 ?
			 * Nothing will get send, so just do nothing
			 */
			loglog(RC_LOG_SERIOUS, "Cannot compute NATD payloads without valid PRF");
			return;
		}
		ikev1_natd_lookup(md);

		if (st->hidden_variables.st_nat_traversal != LEMPTY) {
			nat_traversal_show_result(
				st->hidden_variables.st_nat_traversal,
				endpoint_hport(&md->sender));
		}
	}
	if (st->hidden_variables.st_nat_traversal & NAT_T_WITH_KA) {
		dbg(" NAT_T_WITH_KA detected");
		nat_traversal_new_ka_event();
	}
}

void nat_traversal_new_ka_event(void)
{
	if (nat_kap_event)
		return;	/* Event already schedule */

	schedule_oneshot_timer(EVENT_NAT_T_KEEPALIVE, nat_kap);
	nat_kap_event = TRUE;
}

static void nat_traversal_send_ka(struct state *st)
{
	set_cur_state(st);
	endpoint_buf b;
	dbg("ka_event: send NAT-KA to %s (state=#%lu)",
	    str_endpoint(&st->st_remote_endpoint, &b),
	    st->st_serialno);

	/* send keep alive */
	dbg("sending NAT-T Keep Alive");
	send_keepalive(st, "NAT-T Keep Alive");
	reset_cur_state();
}

/*
 * Find ISAKMP States with NAT-T and send keep-alive
 */
static void nat_traversal_ka_event_state(struct state *st, void *data)
{
	unsigned int *nat_kap_st = (unsigned int *)data;
	const struct connection *c = st->st_connection;

	if (!LHAS(st->hidden_variables.st_nat_traversal, NATED_HOST)) {
		dbg("not behind NAT: no NAT-T KEEP-ALIVE required for conn %s",
		    c->name);
		return;
	}

	if (!c->nat_keepalive) {
		dbg("Suppressing sending of NAT-T KEEP-ALIVE for conn %s (nat-keepalive=no)",
		    c->name);
		return;
	}
	/* XXX: .st_interface, not c.interface - can be different */
	if (!st->st_interface->io->send_keepalive) {
		dbg("skipping NAT-T KEEP-ALIVE: #%lu does not need it for %s protocol",
		    st->st_serialno, st->st_interface->protocol->name);
		return;
	}
	if (c->newest_isakmp_sa != st->st_serialno) {
		dbg("skipping NAT-T KEEP-ALIVE: #%lu is not current IKE SA", st->st_serialno);
		return;
	}

	/*
	 * As long as we don't check get_sa_info() in IPsec SA's, and for
	 * IKEv1 IPsec SA's always send a keepalive, we might as well
	 * _not_ send keepalives for IKEv1 IKE SA's.
	 *
	 * XXX: IKEv2?
	 */

	switch (st->st_ike_version) {
	case IKEv2:
		/*
		 * - IKE SA established
		 * - we are behind NAT
		 * - NAT-KeepAlive needed (we are NATed)
		 */
		if (!IS_IKE_SA_ESTABLISHED(st)) {
			dbg("skipping NAT-T KEEP-ALIVE: #%lu is not established", st->st_serialno);
			return;
		}

		/*
		 * If this IKE SA sent a packet recently, no need for
		 * anything eg, if short DPD timers are used we can
		 * skip this.
		 */
		if (!is_monotime_epoch(st->st_last_liveness) &&
		    deltasecs(monotimediff(mononow(), st->st_last_liveness)) < DEFAULT_KEEP_ALIVE_SECS)
		{
			dbg("NAT-T KEEP-ALIVE packet not required as recent DPD event used the IKE SA on conn %s",
			    c->name);
			return;
		}

		/*
		 * TODO or not?
		 *
		 * We could also check If there is IPsec SA
		 * encapsulation traffic, since then we also do not
		 * need to send keepalives, but that check is a little
		 * expensive as we have to find some/all IPsec states
		 * and ask the kernel, every 20s.
		 */
		dbg("we are behind NAT: sending of NAT-T KEEP-ALIVE for conn %s",
		    c->name);

		(*nat_kap_st)++;
		nat_traversal_send_ka(st);
		return;

	case IKEv1:
		/*
		 * IKE SA and IPsec SA keepalives happen over the same port/NAT mapping.
		 * If the IKE SA is idle and triggers keepalives, we don't need to check
		 * IPsec SA's being idle. If we were to check IPsec SA, we could then
		 * also update the IKE SA st->st_last_liveness, but we think this is
		 * too expensive (call get_sa_info() to kernel _and_ find IKE SA.
		 *
		 * For IKEv2, just use the one IKE SA instead of the one or more IPsec SA's
		 * (and ignore whether IPsec SA was active or not)
		 *
		 * for IKEv1, there can be orphan IPsec SA's. We still are not checking
		 * the kernel, so we just have to always send the keepalive.
		 */
		if (!IS_IPSEC_SA_ESTABLISHED(st)) {
			dbg("skipping NAT-T KEEP-ALIVE: #%lu is not established", st->st_serialno);
			return;
		}
		nat_traversal_send_ka(st);
		(*nat_kap_st)++;
		return;

	}
	bad_case(st->st_ike_version);
}

void nat_traversal_ka_event(struct fd *unused_whackfd UNUSED)
{
	unsigned int nat_kap_st = 0;

	nat_kap_event = FALSE;  /* ready to be reschedule */

	for_each_state(nat_traversal_ka_event_state, &nat_kap_st, __func__);

	if (nat_kap_st != 0) {
		/*
		 * If there are still states who needs Keep-Alive,
		 * schedule new event
		 */
		nat_traversal_new_ka_event();
	}
}

struct new_mapp_nfo {
	struct ike_sa *ike;
	const ip_endpoint *new_remote_endpoint;
};

static bool nat_traversal_find_new_mapp_state(struct state *st, void *data)
{
	struct new_mapp_nfo *nfo = data;
	if (pexpect(st->st_serialno == nfo->ike->sa.st_serialno ||
		    st->st_clonedfrom == nfo->ike->sa.st_serialno)) {
		endpoint_buf b1;
		endpoint_buf b2;
		ip_endpoint st_remote_endpoint = st->st_remote_endpoint;
		dbg("new NAT mapping for #%lu, was %s, now %s",
		    st->st_serialno,
		    str_endpoint(&st_remote_endpoint, &b1),
		    str_endpoint(nfo->new_remote_endpoint, &b2));

		/* update it */
		st->st_remote_endpoint = *nfo->new_remote_endpoint;
		st->hidden_variables.st_natd = endpoint_address(nfo->new_remote_endpoint);
		struct connection *c = st->st_connection;
		if (c->kind == CK_INSTANCE)
			c->spd.that.host_addr = endpoint_address(nfo->new_remote_endpoint);
	}
	return false;
}

void nat_traversal_new_mapping(struct ike_sa *ike,
			       const ip_endpoint *new_remote_endpoint)
{
	endpoint_buf b;
	dbg("state #%lu NAT-T: new mapping %s",
	    ike->sa.st_serialno, str_endpoint(new_remote_endpoint, &b));

	struct new_mapp_nfo nfo = {
		.ike = ike,
		.new_remote_endpoint = new_remote_endpoint,
	};

	state_by_ike_spis(ike->sa.st_ike_version,
			  NULL /* clonedfrom */,
			  NULL /* v1_msgid */,
			  NULL /* role */,
			  &ike->sa.st_ike_spis,
			  nat_traversal_find_new_mapp_state,
			  &nfo,
			  __func__);
}

/* this should only be called after packet has been verified/authenticated! */
void nat_traversal_change_port_lookup(struct msg_digest *md, struct state *st)
{
	pexpect_st_local_endpoint(st);

	if (st == NULL)
		return;

	if (st->st_interface->protocol == &ip_protocol_tcp ||
	    (md != NULL && md->iface->protocol == &ip_protocol_tcp)) {
		/* XXX: when is MD NULL? */
		return;
	}

	if (md != NULL) {

		/*
		 * If source port/address has changed, update (including other
		 * states and established kernel SA)
		 */
		if (!endpoint_eq(md->sender, st->st_remote_endpoint)) {
			nat_traversal_new_mapping(ike_sa(st, HERE), &md->sender);
		}

		/*
		 * If interface type has changed, update local port (500/4500)
		 */
		if (md->iface != st->st_interface) {
			endpoint_buf b1, b2;
			dbg("NAT-T: #%lu updating local interface from %s to %s (using md->iface in %s())",
			    st->st_serialno,
			    str_endpoint(&st->st_interface->local_endpoint, &b1),
			    str_endpoint(&md->iface->local_endpoint, &b2), __func__);
			st->st_interface = md->iface;
		}
	}
	pexpect_st_local_endpoint(st);
}

/*
 * XXX: there should be no maybes about this - each of the callers
 * know the state and hence, know if there's any point in calling this
 * function.
 */
static void v1_natify_initiator_endpoints(struct state *st, where_t where);

void v1_maybe_natify_initiator_endpoints(struct state *st, where_t where)
{
	pexpect_st_local_endpoint(st);
	/*
	 * If we're initiator and NAT-T is detected, we
	 * need to change port (MAIN_I3, QUICK_I1 or AGGR_I2)
	 */
	/* XXX This code does not properly support non-default IKE ports! */
	if ((st->st_state->kind == STATE_MAIN_I3 ||
	     st->st_state->kind == STATE_QUICK_I1 ||
	     st->st_state->kind == STATE_AGGR_I2) &&
	    (st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) &&
	    endpoint_hport(&st->st_interface->local_endpoint) != NAT_IKE_UDP_PORT) {
		dbg("NAT-T: #%lu in %s floating IKEv1 ports to PLUTO_NAT_PORT %d",
		    st->st_serialno, st->st_state->short_name,
		    NAT_IKE_UDP_PORT);
		v1_natify_initiator_endpoints(st, where);
		/*
		 * Also update pending connections or they will be deleted if
		 * uniqueids option is set.
		 * THIS does NOTHING as, both arguments are "st"!
		 *
		 * XXX: so can it be deleted, it would kill the
		 * function.
		 */
		update_pending(pexpect_ike_sa(st), pexpect_ike_sa(st));
	}
	pexpect_st_local_endpoint(st);
}

void show_setup_natt(struct show *s)
{
	show_separator(s);
	show_comment(s, "nat-traversal=%s, keep-alive=%ld, nat-ikeport=%d",
		     bool_str(nat_traversal_enabled),
		     (long) deltasecs(nat_kap),
		     NAT_IKE_UDP_PORT);
}

bool v2_nat_detected(struct ike_sa *ike, struct msg_digest *md)
{
	/* TODO: This use must be allowed even with USE_SHA1=false */
	static const struct hash_desc *hasher = &ike_alg_hash_sha1;

	passert(ike != NULL);
	passert(md->iface != NULL);

	/* must have both */
	if (md->pbs[PBS_v2N_NAT_DETECTION_SOURCE_IP] == NULL ||
	    md->pbs[PBS_v2N_NAT_DETECTION_DESTINATION_IP] == NULL) {
		return false;
	}
	/* table of both */
	const struct pbs_in *(detection_payloads[]) = {
		md->pbs[PBS_v2N_NAT_DETECTION_DESTINATION_IP],
		md->pbs[PBS_v2N_NAT_DETECTION_SOURCE_IP],
	};

	/*
	 * XXX: use the the IKE SPIs from the message header.
	 *
	 * The IKE_SA_INIT initiator doesn't know the responder's SPI
	 * so will have sent hashes using a responder SPI of 0.
	 *
	 * On the other hand, the responder does no its own SPI and so
	 * hashes against that.
	 */

	/* First: one with my IP & port. */
	struct crypt_mac hash_local = natd_hash(hasher, &md->hdr.isa_ike_spis,
						&md->iface->local_endpoint);
	/* Second: one with sender IP & port */
	struct crypt_mac hash_remote = natd_hash(hasher, &md->hdr.isa_ike_spis,
						 &md->sender);

	bool found_local = false;
	bool found_remote = false;

	for (const struct pbs_in **p = detection_payloads;
	     p < detection_payloads + elemsof(detection_payloads);
	     p++) {
		passert(*p != NULL);
		shunk_t hash = pbs_in_left_as_shunk(*p);
		/* redundant, also checked by hunk_eq() */
		if (hash.len != hasher->hash_digest_size)
			continue;
		/* ??? do we know from the isan_type which of these to test? */
		/* XXX: should this check pbs_left(), see other code */
		if (hunk_eq(hash, hash_local)) {
			found_local = true;
		}
		if (hunk_eq(hash, hash_remote)) {
			found_remote = true;
		}
	}

	natd_lookup_common(&ike->sa, &md->sender, found_local, found_remote);
	return (ike->sa.hidden_variables.st_nat_traversal & NAT_T_DETECTED);
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
	pexpect_st_local_endpoint(st);
	endpoint_buf b1, b2;
	ip_endpoint new_local_endpoint = set_endpoint_hport(&st->st_interface->local_endpoint, NAT_IKE_UDP_PORT);
	dbg("NAT: #%lu floating local endpoint from %s to %s using NAT_IKE_UDP_PORT "PRI_WHERE,
	    st->st_serialno,
	    str_endpoint(&st->st_interface->local_endpoint, &b1),
	    str_endpoint(&new_local_endpoint, &b2),
	    pri_where(where));
	/*
	 * If not already ...
	 */
	if (!endpoint_eq(new_local_endpoint, st->st_interface->local_endpoint)) {
		/*
		 * For IPv4, both :PLUTO_PORT and :PLUTO_NAT_PORT are
		 * opened by server.c so the new endpoint using
		 * :PLUTO_NAT_PORT should exist.  IPv6 nat isn't
		 * supported.
		 */
		struct iface_port *i = find_iface_port_by_local_endpoint(&new_local_endpoint);
		if (pexpect(i != NULL)) {
			endpoint_buf b;
			dbg("NAT: #%lu floating endpoint ended up on interface %s %s",
			    st->st_serialno, i->ip_dev->id_rname,
			    str_endpoint(&i->local_endpoint, &b));
			st->st_interface = i;
		}
	}
	pexpect_st_local_endpoint(st);

	/*
	 * Float the remote port to :PLUTO_NAT_PORT (:4500)
	 */
	dbg("NAT-T: #%lu floating remote port from %d to %d using NAT_IKE_UDP_PORT "PRI_WHERE,
	    st->st_serialno, endpoint_hport(&st->st_remote_endpoint), NAT_IKE_UDP_PORT,
	    pri_where(where));
	st->st_remote_endpoint = set_endpoint_hport(&st->st_remote_endpoint,
						    NAT_IKE_UDP_PORT);
}

bool v2_natify_initiator_endpoints(struct ike_sa *ike, where_t where)
{
	/*
	 * Float the local port to :PLUTO_NAT_PORT (:4500).  This
	 * means rebinding the interface.
	 */
	if (ike->sa.st_interface->esp_encapsulation_enabled) {
		endpoint_buf b1;
		dbg("NAT: #%lu not floating local port; interface %s supports encapsulated ESP "PRI_WHERE,
		    ike->sa.st_serialno,
		    str_endpoint(&ike->sa.st_interface->local_endpoint, &b1),
		    pri_where(where));
	} else if (ike->sa.st_interface->float_nat_initiator) {
		/*
		 * For IPv4, both :PLUTO_PORT and :PLUTO_NAT_PORT are
		 * opened by server.c so the new endpoint using
		 * :PLUTO_NAT_PORT should exist.  IPv6 nat isn't
		 * supported.
		 */
		ip_endpoint new_local_endpoint = set_endpoint_hport(&ike->sa.st_interface->local_endpoint, NAT_IKE_UDP_PORT);
		struct iface_port *i = find_iface_port_by_local_endpoint(&new_local_endpoint);
		if (i == NULL) {
			endpoint_buf b2;
			log_state(RC_LOG/*fatal!*/, &ike->sa,
				  "NAT: can not float to %s as no such interface",
				  str_endpoint(&new_local_endpoint, &b2));
			return false; /* must enable NAT */
		}
		endpoint_buf b1, b2;
		dbg("NAT: #%lu floating local port from %s to %s using NAT_IKE_UDP_PORT "PRI_WHERE,
		    ike->sa.st_serialno,
		    str_endpoint(&ike->sa.st_interface->local_endpoint, &b1),
		    str_endpoint(&new_local_endpoint, &b2),
		    pri_where(where));
		ike->sa.st_interface = i;
	} else {
		endpoint_buf b1;
		log_state(RC_LOG/*fatal!*/, &ike->sa,
			  "NAT: can not switch to NAT port and interface %s does not support NAT",
			  str_endpoint(&ike->sa.st_interface->local_endpoint, &b1));
		return false;
	}

	/*
	 * Float the remote port to :PLUTO_NAT_PORT (:4500).
	 */
	if (ike->sa.st_connection->spd.that.raw.host.ikeport != 0) {
		dbg("NAT: #%lu not floating remote port; hardwired to ikeport=%u "PRI_WHERE,
		    ike->sa.st_serialno, ike->sa.st_connection->spd.that.raw.host.ikeport,
		    pri_where(where));
	} else if (endpoint_hport(&ike->sa.st_remote_endpoint) == NAT_IKE_UDP_PORT) {
		dbg("NAT: #%lu not floating remote port; already pointing at PLUTO_NAT_PORT %u "PRI_WHERE,
		    ike->sa.st_serialno, NAT_IKE_UDP_PORT, pri_where(where));
	} else {
		dbg("NAT: #%lu floating remote port from %d to %d using NAT_IKE_UDP_PORT "PRI_WHERE,
		    ike->sa.st_serialno, endpoint_hport(&ike->sa.st_remote_endpoint), NAT_IKE_UDP_PORT,
		    pri_where(where));
		ike->sa.st_remote_endpoint = set_endpoint_hport(&ike->sa.st_remote_endpoint,
								NAT_IKE_UDP_PORT);
	}

	return true;
}
