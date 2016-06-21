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
 * Copyright (C) 2012-2014 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2014 Antony Antony <antony@phenome.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>     /* used only if MSG_NOSIGNAL not defined */
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <libreswan.h>
#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>
#include <libreswan/ipsec_tunnel.h>
#include <libreswan/ipsec_param.h>

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
#include "ikev2.h"

#include "cookie.h"
#include "sha1.h"
#include "crypto.h"
#include "vendor.h"

#include "natt_defines.h"
#include "nat_traversal.h"


/* As per https://tools.ietf.org/html/rfc3948#section-4 */
#define DEFAULT_KEEP_ALIVE_PERIOD  20

bool nat_traversal_enabled = TRUE; /* can get disabled if kernel lacks support */

static time_t nat_kap = DEFAULT_KEEP_ALIVE_PERIOD;	/* keep-alive period */
static bool nat_kap_event = FALSE;

#define IKEV2_NATD_HASH_SIZE	SHA1_DIGEST_SIZE

void init_nat_traversal(unsigned int keep_alive_period)
{
	{
		FILE *f = fopen("/proc/net/ipsec/natt", "r");

		/* ??? this only checks if the file starts with '0'; seems sloppy */
		if (f != NULL) {
			int n = getc(f);

			if (n == '0') {
				nat_traversal_enabled = FALSE;
				libreswan_log(
					"  KLIPS does not have NAT-Traversal built in (see /proc/net/ipsec/natt)\n");
			}
			fclose(f);
		}
	}


	if (keep_alive_period != 0)
		nat_kap = keep_alive_period;

	DBG(DBG_NATT, DBG_log("init_nat_traversal() initialized with keep_alive=%d",
		keep_alive_period));
	libreswan_log("NAT-Traversal support %s",
		nat_traversal_enabled ? " [enabled]" : " [disabled]");

}

static void natd_hash(const struct hash_desc *hasher, unsigned char *hash,
		const u_int8_t *icookie, const u_int8_t *rcookie,
		const ip_address *ip,
		u_int16_t port /* host order */)
{
	union hash_ctx ctx;

	if (is_zero_cookie(icookie))
		DBG(DBG_NATT, DBG_log("natd_hash: Warning, icookie is zero !!"));
	if (is_zero_cookie(rcookie))
		DBG(DBG_NATT, DBG_log("natd_hash: Warning, rcookie is zero !!"));

	/*
	 * RFC 3947
	 *
	 *   HASH = HASH(CKY-I | CKY-R | IP | Port)
	 *
	 * All values in network order
	 */
	hasher->hash_init(&ctx);
	hasher->hash_update(&ctx, icookie, COOKIE_SIZE);
	hasher->hash_update(&ctx, rcookie, COOKIE_SIZE);
	switch (addrtypeof(ip)) {
	case AF_INET:
		hasher->hash_update(&ctx,
				(const u_char *)&ip->u.v4.sin_addr.s_addr,
				sizeof(ip->u.v4.sin_addr.s_addr));
		break;
	case AF_INET6:
		hasher->hash_update(&ctx,
				(const u_char *)&ip->u.v6.sin6_addr.s6_addr,
				sizeof(ip->u.v6.sin6_addr.s6_addr));
		break;
	}
	{
		u_int16_t netorder_port = htons(port);

		hasher->hash_update(&ctx, (const u_char *)&netorder_port, sizeof(netorder_port));
	}
	hasher->hash_final(hash, &ctx);
	DBG(DBG_NATT, {
			DBG_log("natd_hash: hasher=%p(%d)", hasher,
				(int)hasher->hash_digest_len);
			DBG_dump("natd_hash: icookie=", icookie, COOKIE_SIZE);
			DBG_dump("natd_hash: rcookie=", rcookie, COOKIE_SIZE);
			switch (addrtypeof(ip)) {
			case AF_INET:
				DBG_dump("natd_hash: ip=",
					&ip->u.v4.sin_addr.s_addr,
					sizeof(ip->u.v4.sin_addr.s_addr));
				break;
			}
			DBG_log("natd_hash: port=%d", port);
			DBG_dump("natd_hash: hash=", hash,
				hasher->hash_digest_len);
		});
}

/*
 * Add  NAT-Traversal IKEv2 Notify payload (v2N)
 */
bool ikev2_out_nat_v2n(u_int8_t np, pb_stream *outs, struct msg_digest *md)
{
	struct state *st = md->st;

	unsigned char hb[IKEV2_NATD_HASH_SIZE];
	chunk_t hch = { hb, sizeof(hb) };

	DBG(DBG_NATT,
		DBG_log(" NAT-Traversal support %s add v2N payloads.",
			nat_traversal_enabled ? " [enabled]" : " [disabled]"));

	/*
	 *  First: one with local (source) IP & port
	 */
	natd_hash(&crypto_hasher_sha1, hb, st->st_icookie,
		is_zero_cookie(st->st_rcookie) ?
			md->hdr.isa_rcookie : st->st_rcookie,
		&st->st_localaddr, st->st_localport);

	/* In v2, for parent, protoid must be 0 and SPI must be empty */
	if (!ship_v2N(ISAKMP_NEXT_v2N, ISAKMP_PAYLOAD_NONCRITICAL,
		PROTO_v2_RESERVED, &empty_chunk,
		v2N_NAT_DETECTION_SOURCE_IP, &hch, outs))
		return FALSE;
	/*
	 * Second: one with remote (destination) IP & port
	 */
	natd_hash(&crypto_hasher_sha1, hb, st->st_icookie,
		is_zero_cookie(st->st_rcookie) ? md->hdr.isa_rcookie :
		st->st_rcookie, &st->st_remoteaddr, st->st_remoteport);

	/* In v2, for parent, protoid must be 0 and SPI must be empty */
	if (!ship_v2N(np, ISAKMP_PAYLOAD_NONCRITICAL,
		PROTO_v2_RESERVED, &empty_chunk,
		v2N_NAT_DETECTION_DESTINATION_IP, &hch, outs))
		return FALSE;
	return TRUE;
}

/*
 * Add NAT-Traversal VIDs (supported ones)
 *
 * Used when we're Initiator
 */
bool nat_traversal_insert_vid(u_int8_t np, pb_stream *outs, const struct state *st)
{
	DBG(DBG_NATT, DBG_log("nat add vid"));

	/*
	 * Some Cisco's have a broken NAT-T implementation where it
	 * sends one NAT payload per draft, and one NAT payload for RFC.
	 * ikev1_natt={both|drafts|rfc} helps us claim we only support the
	 * drafts, so we don't hit the bad Cisco code.
	 */
	switch (st->st_connection->ikev1_natt) {
	case natt_rfc:
		DBG(DBG_NATT, DBG_log("skipping VID_NATT drafts"));
		if (!out_vid(np, outs, VID_NATT_RFC))
			return FALSE;
		break;
	case natt_both:
		DBG(DBG_NATT, DBG_log("sending draft and RFC NATT VIDs"));
		if (!out_vid(ISAKMP_NEXT_VID, outs, VID_NATT_RFC))
			return FALSE;
		/* FALL THROUGH */
	case natt_drafts:
		if (st->st_connection->ikev1_natt == natt_drafts) {
			DBG(DBG_NATT, DBG_log("skipping VID_NATT_RFC"));
		}
		if (!out_vid(ISAKMP_NEXT_VID, outs, VID_NATT_IETF_03))
			return FALSE;
		if (!out_vid(ISAKMP_NEXT_VID, outs, VID_NATT_IETF_02_N))
			return FALSE;
		if (!out_vid(np, outs, VID_NATT_IETF_02))
			return FALSE;
		break;
	}
	return TRUE;
}

static enum natt_method nat_traversal_vid_to_method(enum known_vendorid nat_t_vid)
{
	switch (nat_t_vid) {
	case VID_NATT_IETF_00:
		DBG(DBG_NATT,
			DBG_log("NAT_TRAVERSAL_METHOD_IETF_00_01 no longer supported"));
		return NAT_TRAVERSAL_METHOD_none;

	case VID_NATT_IETF_02:
	case VID_NATT_IETF_02_N:
	case VID_NATT_IETF_03:
		DBG(DBG_NATT,
			DBG_log("returning NAT-T method NAT_TRAVERSAL_METHOD_IETF_02_03"));
		return NAT_TRAVERSAL_METHOD_IETF_02_03;

	case VID_NATT_IETF_04:
	case VID_NATT_IETF_05:
	case VID_NATT_IETF_06:
	case VID_NATT_IETF_07:
	case VID_NATT_IETF_08:
	case VID_NATT_DRAFT_IETF_IPSEC_NAT_T_IKE:
		DBG(DBG_NATT,
			DBG_log("NAT-T VID draft-ietf-ipsc-nat-t-ike-04 to 08 assumed to function as RFC 3947 "));
		/* FALL THROUGH */
	case VID_NATT_RFC:
		DBG(DBG_NATT,
			DBG_log("returning NAT-T method NAT_TRAVERSAL_METHOD_IETF_RFC"));
		return NAT_TRAVERSAL_METHOD_IETF_RFC;

	default:
		return 0;
	}
}

void set_nat_traversal(struct state *st, const struct msg_digest *md)
{
	DBG(DBG_NATT, DBG_log("sender checking NAT-T: %s and %d",
				     nat_traversal_enabled ? "enabled" : "disabled",
				     md->quirks.qnat_traversal_vid));
	if (nat_traversal_enabled && md->quirks.qnat_traversal_vid != VID_none) {
		enum natt_method v = nat_traversal_vid_to_method(md->quirks.qnat_traversal_vid);

		st->hidden_variables.st_nat_traversal = LELEM(v);
		DBG(DBG_NATT, DBG_log("enabling possible NAT-traversal with method %s",
			      enum_name(&natt_method_names, v)));
	}
}

static void natd_lookup_common(struct state *st,
	const ip_address *sender,
	bool found_me, bool found_him)
{
	zero(&st->hidden_variables.st_natd);	/* ??? odd way to set an ip_address field */
	anyaddr(AF_INET, &st->hidden_variables.st_natd);

	if (!found_me) {
		DBG(DBG_NATT,
			DBG_log("NAT_TRAVERSAL this end is behind NAT"));
		st->hidden_variables.st_nat_traversal |= LELEM(NATED_HOST);
		st->hidden_variables.st_natd = *sender;
	}

	if (!found_him) {
		DBG(DBG_NATT, {
			ipstr_buf b;
			DBG_log("NAT_TRAVERSAL that end is behind NAT %s",
				ipstr(sender, &b));
		});
		st->hidden_variables.st_nat_traversal |= LELEM(NATED_PEER);
		st->hidden_variables.st_natd = *sender;
	}

	if (st->st_connection->forceencaps) {
		DBG(DBG_NATT,
			DBG_log("NAT_TRAVERSAL forceencaps enabled"));

		st->hidden_variables.st_nat_traversal |=
			LELEM(NATED_PEER) | LELEM(NATED_HOST);
		st->hidden_variables.st_natd = *sender;
	}

	if (st->st_connection->nat_keepalive) {
		DBG(DBG_NATT, {
			ipstr_buf b;
			DBG_log("NAT_TRAVERSAL nat_keepalive enabled %s",
				ipstr(sender, &b));
		});
	}
}

static void ikev1_natd_lookup(struct msg_digest *md)
{
	unsigned char hash_me[MAX_DIGEST_LEN];
	unsigned char hash_him[MAX_DIGEST_LEN];
	struct state *st = md->st;
	const struct hash_desc *const hasher = st->st_oakley.prf_hasher;
	const size_t hl = hasher->hash_digest_len;
	const struct payload_digest *const hd = md->chain[ISAKMP_NEXT_NATD_RFC];
	const struct payload_digest *p;
	bool found_me = FALSE;
	bool found_him = FALSE;
	int i;

	passert(md->iface != NULL);

	/* Count NAT-D */
	i = 0;
	for (p = hd; p != NULL; p = p->next)
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

	/*
	 * First one with my IP & port
	 */
	natd_hash(hasher, hash_me, st->st_icookie,
		st->st_rcookie, &md->iface->ip_addr, md->iface->port);

	/*
	 * The other with sender IP & port
	 */
	natd_hash(hasher, hash_him, st->st_icookie,
		st->st_rcookie, &md->sender, md->sender_port);

	DBG(DBG_NATT, {
		DBG_dump("expected NAT-D(me):", hash_me, hl);
		DBG_dump("expected NAT-D(him):", hash_him, hl);
	});

	for (p = hd; p != NULL; p = p->next) {
		DBG(DBG_NATT,
			DBG_dump("received NAT-D:", p->pbs.cur,
				pbs_left(&p->pbs)));

		if (pbs_left(&p->pbs) == hl) {
			if (memeq(p->pbs.cur, hash_me, hl))
				found_me = TRUE;

			if (memeq(p->pbs.cur, hash_him, hl))
				found_him = TRUE;

			if (found_me && found_him)
				break;
		}
	}

	natd_lookup_common(st, &md->sender, found_me, found_him);
}

bool ikev1_nat_traversal_add_natd(u_int8_t np, pb_stream *outs,
			struct msg_digest *md)
{
	unsigned char hash[MAX_DIGEST_LEN];
	struct state *st = md->st;
	unsigned int nat_np;
	const ip_address *first, *second;
	unsigned short firstport, secondport;

	passert(st->st_oakley.prf_hasher != NULL);

	DBG(DBG_EMITTING | DBG_NATT, DBG_log("sending NAT-D payloads"));

	nat_np = (st->hidden_variables.st_nat_traversal & NAT_T_WITH_RFC_VALUES) != LEMPTY ?
		ISAKMP_NEXT_NATD_RFC : ISAKMP_NEXT_NATD_DRAFTS;

	out_modify_previous_np(nat_np, outs);

	first = &md->sender;
	firstport = st->st_remoteport;

	second = &md->iface->ip_addr;
	secondport = st->st_localport;

	if (FALSE) {
		const ip_address *t;
		unsigned short p;

		t = first;
		first = second;
		second = t;

		p = firstport;
		firstport = secondport;
		secondport = p;
	}

	if (st->st_connection->forceencaps) {
		DBG(DBG_NATT,
			DBG_log("NAT-T: forceencaps=yes, so mangling hash to force NAT-T detection"));
		firstport = secondport = 0;
	}

	/*
	 * First one with sender IP & port
	 */
	natd_hash(st->st_oakley.prf_hasher, hash, st->st_icookie,
		is_zero_cookie(st->st_rcookie) ? md->hdr.isa_rcookie :
		st->st_rcookie, first, firstport);

	if (!ikev1_out_generic_raw(nat_np, &isakmp_nat_d, outs, hash,
				st->st_oakley.prf_hasher->hash_digest_len,
				"NAT-D"))
		return FALSE;

	/*
	 * Second one with my IP & port
	 */
	natd_hash(st->st_oakley.prf_hasher, hash,
		st->st_icookie, is_zero_cookie(st->st_rcookie) ?
		md->hdr.isa_rcookie : st->st_rcookie, second, secondport);

	return ikev1_out_generic_raw(np, &isakmp_nat_d, outs,
			hash, st->st_oakley.prf_hasher->hash_digest_len,
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
	struct payload_digest *p;
	int i;
	ip_address ip;

	passert(md->iface != NULL);

	/* Initialize NAT-OA */
	anyaddr(AF_INET, &hv->st_nat_oa);

	/* Count NAT-OA */
	for (p = md->chain[ISAKMP_NEXT_NATOA_RFC], i = 0;
		p != NULL;
		p = p->next, i++) {
	}

	DBG(DBG_NATT,
		DBG_log("NAT-Traversal: received %d NAT-OA.", i));

	if (i == 0) {
		return;
	} else if (!LHAS(hv->st_nat_traversal, NATED_PEER)) {
		loglog(RC_LOG_SERIOUS,
			"NAT-Traversal: received %d NAT-OA. Ignored because peer is not NATed",
			i);
		return;
	} else if (i > 1) {
		loglog(RC_LOG_SERIOUS,
			"NAT-Traversal: received %d NAT-OA. Using first, ignoring others",
			i);
	}

	/* Take first */
	p = md->chain[ISAKMP_NEXT_NATOA_RFC];

	DBG(DBG_PARSING,
		DBG_dump("NAT-OA:", p->pbs.start, pbs_room(&p->pbs)));

	switch (p->payload.nat_oa.isanoa_idtype) {
	case ID_IPV4_ADDR:
		if (pbs_left(&p->pbs) != sizeof(struct in_addr)) {
			loglog(RC_LOG_SERIOUS,
				"NAT-Traversal: received IPv4 NAT-OA with invalid IP size (%d)",
				(int)pbs_left(&p->pbs));
			return;
		}

		initaddr(p->pbs.cur, pbs_left(&p->pbs), AF_INET, &ip);
		break;

	case ID_IPV6_ADDR:
		if (pbs_left(&p->pbs) != sizeof(struct in6_addr)) {
			loglog(RC_LOG_SERIOUS,
				"NAT-Traversal: received IPv6 NAT-OA with invalid IP size (%d)",
				(int)pbs_left(&p->pbs));
			return;
		}

		initaddr(p->pbs.cur, pbs_left(&p->pbs), AF_INET6, &ip);
		break;
	default:
		loglog(RC_LOG_SERIOUS,
			"NAT-Traversal: invalid ID Type (%d) in NAT-OA - ignored",
			p->payload.nat_oa.isanoa_idtype);
		return;
	}

	DBG(DBG_NATT, {
		ipstr_buf b;
		DBG_log("received NAT-OA: %s",
			ipstr(&ip, &b));
	});

	if (isanyaddr(&ip)) {
		loglog(RC_LOG_SERIOUS,
			"NAT-Traversal: received 0.0.0.0 NAT-OA...");
	} else {
		hv->st_nat_oa = ip;
	}
}

bool nat_traversal_add_natoa(u_int8_t np, pb_stream *outs,
			struct state *st, bool initiator)
{
	struct isakmp_nat_oa natoa;
	unsigned char ip_val[sizeof(struct in6_addr)];
	size_t ip_len = 0;
	ip_address *ipinit, *ipresp;
	unsigned int nat_np;

	if (initiator) {
		ipinit = &st->st_localaddr;
		ipresp = &st->st_remoteaddr;
	} else {
		ipresp = &st->st_localaddr;
		ipinit = &st->st_remoteaddr;
	}

	passert(st->st_connection != NULL);

	nat_np = (st->hidden_variables.st_nat_traversal &
		NAT_T_WITH_RFC_VALUES) != LEMPTY ?
		  ISAKMP_NEXT_NATOA_RFC : ISAKMP_NEXT_NATOA_DRAFTS;

	out_modify_previous_np(nat_np, outs);

	zero(&natoa);	/* OK: no pointer fields */
	natoa.isanoa_np = nat_np;

	switch (addrtypeof(ipinit)) {
	case AF_INET:
		ip_len = sizeof(ipinit->u.v4.sin_addr.s_addr);
		memcpy(ip_val, &ipinit->u.v4.sin_addr.s_addr, ip_len);
		natoa.isanoa_idtype = ID_IPV4_ADDR;
		break;
	case AF_INET6:
		ip_len = sizeof(ipinit->u.v6.sin6_addr.s6_addr);
		memcpy(ip_val, &ipinit->u.v6.sin6_addr.s6_addr, ip_len);
		natoa.isanoa_idtype = ID_IPV6_ADDR;
		break;
	default:
		loglog(RC_LOG_SERIOUS,
			"NAT-Traversal: invalid addrtypeof()=%d",
			addrtypeof(ipinit));
		return FALSE;
	}

	{
		pb_stream pbs;

		if (!out_struct(&natoa, &isakmp_nat_oa, outs, &pbs))
			return FALSE;

		if (!out_raw(ip_val, ip_len, &pbs, "NAT-OAi"))
			return FALSE;

		DBG(DBG_NATT,
			DBG_dump("NAT-OAi (S):", ip_val, ip_len));
		close_output_pbs(&pbs);
	}

	/* output second NAT-OA */
	zero(&natoa);	/* OK: no pointer fields */
	natoa.isanoa_np = np;

	switch (addrtypeof(ipresp)) {
	case AF_INET:
		ip_len = sizeof(ipresp->u.v4.sin_addr.s_addr);
		memcpy(ip_val, &ipresp->u.v4.sin_addr.s_addr, ip_len);
		natoa.isanoa_idtype = ID_IPV4_ADDR;
		break;
	case AF_INET6:
		ip_len = sizeof(ipresp->u.v6.sin6_addr.s6_addr);
		memcpy(ip_val, &ipresp->u.v6.sin6_addr.s6_addr, ip_len);
		natoa.isanoa_idtype = ID_IPV6_ADDR;
		break;
	default:
		loglog(RC_LOG_SERIOUS,
			"NAT-Traversal: invalid addrtypeof()=%d",
			addrtypeof(ipresp));
		return FALSE;
	}

	{
		pb_stream pbs;
		if (!out_struct(&natoa, &isakmp_nat_oa, outs, &pbs))
			return FALSE;

		if (!out_raw(ip_val, ip_len, &pbs, "NAT-OAr"))
			return FALSE;

		DBG(DBG_NATT,
			DBG_dump("NAT-OAr (S):", ip_val, ip_len));

		close_output_pbs(&pbs);
	}
	return TRUE;
}

static void nat_traversal_show_result(lset_t nt, u_int16_t sport)
{
	const char *rslt = (nt & NAT_T_DETECTED) ?
		bitnamesof(natt_bit_names, nt & NAT_T_DETECTED) :
		"no NAT detected";

	DBG(DBG_NATT, DBG_log(
		"NAT-Traversal: Result using %s sender port %" PRIu16 ": %s",
		LHAS(nt, NAT_TRAVERSAL_METHOD_IETF_RFC) ?
			enum_name(&natt_method_names,
				  NAT_TRAVERSAL_METHOD_IETF_RFC) :
		LHAS(nt, NAT_TRAVERSAL_METHOD_IETF_02_03) ?
			enum_name(&natt_method_names,
				  NAT_TRAVERSAL_METHOD_IETF_02_03) :
		"unknown or unsupported method",
		sport,
		rslt));
}

void ikev1_natd_init(struct state *st, struct msg_digest *md)
{
	DBG(DBG_NATT,
	    DBG_log("checking NAT-t: %s and %s",
		    nat_traversal_enabled ? "enabled" : "disabled",
		    bitnamesof(natt_bit_names, st->hidden_variables.st_nat_traversal)));

	if (st->hidden_variables.st_nat_traversal != LEMPTY) {
		if (md->st->st_oakley.prf_hasher == NULL) {
			/*
			 * This connection is doomed - no PRF for NATD hash
			 * Probably in FIPS trying MD5 ?
			 * Nothing will get send, so just do nothing
			 */
			return;
		}
		ikev1_natd_lookup(md);

		if (st->hidden_variables.st_nat_traversal != LEMPTY) {
			nat_traversal_show_result(
				st->hidden_variables.st_nat_traversal,
				md->sender_port);
		}
	}
	if (st->hidden_variables.st_nat_traversal & NAT_T_WITH_KA) {
		DBG(DBG_NATT, DBG_log(" NAT_T_WITH_KA detected"));
		nat_traversal_new_ka_event();
	}
}

int nat_traversal_espinudp_socket(int sk, const char *fam)
{
	int r;
	struct ifreq ifr;
	int *fdp = (int *) &ifr.ifr_data;
	const char *ifn;

	DBG(DBG_NATT, DBG_log("NAT-Traversal: Trying new style NAT-T"));
	zero(&ifr);
	switch (kern_interface) {
	case USE_MASTKLIPS:	/* using mast0 will break it! */
	case USE_KLIPS:
		ifn = "ipsec0";
		break;
	case USE_NETKEY:
		/* Let's hope we have at least one ethernet device */
		ifn = "eth0";
		break;
	case USE_BSDKAME:
		/* Let's hope we have at least one ethernet device */
		ifn = "en0";
		break;
	default:
		/* ??? We have nothing, really prob just abort and return -1 */
		ifn = "eth0";
		break;
	}
	strncpy(ifr.ifr_name, ifn, sizeof(ifr.ifr_name));

	fdp[0] = sk;
	fdp[1] = ESPINUDP_WITH_NON_ESP; /* no longer support non-ike or non-floating */
	r = ioctl(sk, IPSEC_UDP_ENCAP_CONVERT, &ifr);
	if (r == -1) {
		DBG(DBG_NATT,
			DBG_log("NAT-Traversal: ESPINUDP(%d) setup failed for new style NAT-T family %s (errno=%d)",
				ESPINUDP_WITH_NON_ESP, fam, errno));
	} else {
		DBG(DBG_NATT,
			DBG_log("NAT-Traversal: ESPINUDP(%d) setup succeeded for new style NAT-T family %s",
				ESPINUDP_WITH_NON_ESP, fam));
		return r;
	}

#if defined(KLIPS)
	DBG(DBG_NATT, DBG_log("NAT-Traversal: Trying old style NAT-T"));
	const int type = ESPINUDP_WITH_NON_ESP;
	r = setsockopt(sk, SOL_UDP, UDP_ESPINUDP, &type, sizeof(type));
	if (r == -1) {
		DBG(DBG_NATT,
			DBG_log("NAT-Traversal: ESPINUDP(%d) setup failed for old style NAT-T family %s (errno=%d)",
				ESPINUDP_WITH_NON_ESP, fam, errno));
	} else {
		DBG(DBG_NATT,
			DBG_log("NAT-Traversal: ESPINUDP(%d) setup succeeded for old style NAT-T family %s",
				ESPINUDP_WITH_NON_ESP, fam));
		return r;
	}
# else
	DBG(DBG_NATT,
		DBG_log("NAT-Traversal: ESPINUDP() setup for old style NAT-T family not available - KLIPS support not compiled in"));
# endif

	loglog(RC_LOG_SERIOUS,
		"NAT-Traversal: ESPINUDP(%d) not supported by kernel for family %s",
		ESPINUDP_WITH_NON_ESP, fam);
	libreswan_log("NAT-Traversal is turned OFF due to lack of KERNEL support");
	nat_traversal_enabled = FALSE;
	return -1;
}

void nat_traversal_new_ka_event(void)
{
	if (nat_kap_event)
		return;	/* Event already schedule */

	event_schedule(EVENT_NAT_T_KEEPALIVE, nat_kap, NULL);
	nat_kap_event = TRUE;
}

static void nat_traversal_send_ka(struct state *st)
{
	set_cur_state(st);
	DBG(DBG_NATT | DBG_DPD, {
		ipstr_buf b;
		DBG_log("ka_event: send NAT-KA to %s:%d (state=#%lu)",
			ipstr(&st->st_remoteaddr, &b),
			st->st_remoteport,
			st->st_serialno);
	});

	/* send keep alive */
	DBG(DBG_NATT | DBG_DPD, DBG_log("sending NAT-T Keep Alive"));
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

	if (c == NULL)
		return;

	if (!c->nat_keepalive) {
		DBG(DBG_NATT,
			DBG_log("Suppressing sending of NAT-T KEEP-ALIVE by per-conn configuration (nat_keepalive=no)"));
		return;
	}
	DBG(DBG_NATT,
		DBG_log("Sending of NAT-T KEEP-ALIVE enabled by per-conn configuration (nat_keepalive=yes)"));

	if (IS_ISAKMP_SA_ESTABLISHED(st->st_state) &&
	    LHAS(st->hidden_variables.st_nat_traversal, NATED_HOST)) {
		/*
		 * - ISAKMP established
		 * - we are behind NAT
		 * - NAT-KeepAlive needed (we are NATed)
		 */
		if (c->newest_isakmp_sa != st->st_serialno) {
			/*
			 * if newest is also valid, ignore this one,
			 * we will only use newest.
			 */
			struct state *st_newest = state_with_serialno(c->newest_isakmp_sa);

			if (st_newest != NULL &&
				IS_ISAKMP_SA_ESTABLISHED(st->st_state) &&
				LHAS(st_newest->hidden_variables.st_nat_traversal,
					NATED_HOST))
				return;
		}
		/*
		 * TODO: We should check idleness of SA before sending
		 * keep-alive. If there is traffic, no need for it
		 */
		nat_traversal_send_ka(st);
		(*nat_kap_st)++;
	}

	if ((st->st_state == STATE_QUICK_R2 ||
	     st->st_state == STATE_QUICK_I2) &&
	    LHAS(st->hidden_variables.st_nat_traversal, NATED_HOST)) {
		/*
		 * - IPSEC SA established
		 * - NAT-Traversal detected
		 * - NAT-KeepAlive needed (we are NATed)
		 */
		if (c->newest_ipsec_sa != st->st_serialno) {
			/*
			 * if newest is also valid, ignore this one,
			 * we will only use newest.
			 */
			struct state *st_newest = state_with_serialno(c->newest_ipsec_sa);

			if (st_newest != NULL &&
			    (st_newest->st_state == STATE_QUICK_R2 ||
			     st_newest->st_state == STATE_QUICK_I2) &&
			    LHAS(st_newest->hidden_variables.st_nat_traversal,
				 NATED_HOST))
				return;
		}
		nat_traversal_send_ka(st);
		(*nat_kap_st)++;
	}

}

void nat_traversal_ka_event(void)
{
	unsigned int nat_kap_st = 0;

	nat_kap_event = FALSE;  /* ready to be reschedule */

	for_each_state(nat_traversal_ka_event_state, &nat_kap_st);

	if (nat_kap_st != 0) {
		/*
		 * If there are still states who needs Keep-Alive,
		 * schedule new event
		 */
		nat_traversal_new_ka_event();
	}
}

struct new_mapp_nfo {
	struct state *st;
	ip_address addr;
	u_int16_t port;
};

static void nat_traversal_find_new_mapp_state(struct state *st, void *data)
{
	struct new_mapp_nfo *nfo = (struct new_mapp_nfo *)data;

	if ((IS_CHILD_SA(nfo->st) &&
		(st->st_serialno == nfo->st->st_clonedfrom ||
		 st->st_clonedfrom == nfo->st->st_clonedfrom)) ||
	    st->st_serialno == nfo->st->st_serialno)
	{
		ipstr_buf b1, b2;
		struct connection *c = st->st_connection;

		libreswan_log("new NAT mapping for #%lu, was %s:%d, now %s:%d",
			st->st_serialno,
			ipstr(&st->st_remoteaddr, &b1),
			st->st_remoteport,
			ipstr(&nfo->addr, &b2),
			nfo->port);

		/* update it */
		st->st_remoteaddr = nfo->addr;
		st->st_remoteport = nfo->port;
		st->hidden_variables.st_natd = nfo->addr;

		if (c->kind == CK_INSTANCE)
			c->spd.that.host_addr = nfo->addr;
	}
}

static int nat_traversal_new_mapping(struct state *st,
				const ip_address *nsrc,
				u_int16_t nsrcport)
{
	struct new_mapp_nfo nfo;

	DBG(DBG_NATT, {
		ipstr_buf b;
		DBG_log("state #%lu NAT-T: new mapping %s:%d",
			st->st_serialno,
			ipstr(nsrc, &b),
			nsrcport);
	});

#if 0
	if (!sameaddr(src, dst)) {
		ipstr_buf a, b;

		loglog(RC_LOG_SERIOUS,
			"nat_traversal_new_mapping: address change currently not supported [%s:%d,%s:%d]",
			ipstr(src, &a), sport,
			ipstr(dst, &b), dport);
		return -1;
	}

	if (sport == dport) {
		/* no change */
		return 0;
	}
#endif

	nfo.st    = st;
	nfo.addr  = *nsrc;
	nfo.port  = nsrcport;

	for_each_state(nat_traversal_find_new_mapp_state, &nfo);

	return 0;
}

/* this should only be called after packet has been verified/authenticated! */
void nat_traversal_change_port_lookup(struct msg_digest *md, struct state *st)
{
	struct iface_port *i = NULL;

	if (st == NULL)
		return;

	if (md != NULL) {
		/*
		 * If source port/address has changed, update (including other
		 * states and established kernel SA)
		 */
		if (st->st_remoteport != md->sender_port ||
			!sameaddr(&st->st_remoteaddr, &md->sender)) {

			nat_traversal_new_mapping(st, &md->sender,
						md->sender_port);
		}

		/*
		 * If interface type has changed, update local port (500/4500)
		 */
		if (md->iface->port != st->st_localport) {
			st->st_localport = md->iface->port;
			DBG(DBG_NATT,
				DBG_log("NAT-T: updating local port to %d",
					st->st_localport));
		}
	}

	/*
	 * If we're initiator and NAT-T is detected, we
	 * need to change port (MAIN_I3, QUICK_I1 or AGGR_I2)
	 */
	if ((st->st_state == STATE_MAIN_I3 ||
	     st->st_state == STATE_QUICK_I1 ||
	     st->st_state == STATE_AGGR_I2) &&
	    (st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) &&
	    st->st_localport != pluto_nat_port) {
		DBG(DBG_NATT,
			DBG_log("NAT-T: floating local port %d to nat port %d",
				st->st_localport, pluto_nat_port));

		st->st_localport  = pluto_nat_port;
		st->st_remoteport = pluto_nat_port;

		/*
		 * Also update pending connections or they will be deleted if
		 * uniqueids option is set.
		 * THIS does NOTHING as, both arguments are "st"!
		 */
		update_pending(st, st);
	}

	/*
	 * Find valid interface according to local port (500/4500)
	 */
	if (!sameaddr(&st->st_localaddr, &st->st_interface->ip_addr) ||
	     st->st_localport != st->st_interface->port) {

		DBG(DBG_NATT, {
			ipstr_buf b1;
			ipstr_buf b2;
			DBG_log("NAT-T connection has wrong interface definition %s:%u vs %s:%u",
				ipstr(&st->st_localaddr, &b1),
				st->st_localport,
				ipstr(&st->st_interface->ip_addr, &b2),
				st->st_interface->port);
		});

		for (i = interfaces; i !=  NULL; i = i->next) {
			if (sameaddr(&st->st_localaddr, &i->ip_addr) &&
			    st->st_localport == i->port) {
				DBG(DBG_NATT,
					DBG_log("NAT-T: updated to use interface %s:%d",
						i->ip_dev->id_rname,
						i->port));
				st->st_interface = i;
				break;
			}
		}
	}
}

struct new_klips_mapp_nfo {
	struct k_sadb_sa *sa;
	ip_address src, dst;
	u_int16_t sport, dport;
};

static void nat_t_new_klips_mapp(struct state *st, void *data)
{
	struct connection *c = st->st_connection;
	struct new_klips_mapp_nfo *nfo = (struct new_klips_mapp_nfo *)data;

	if (c != NULL && st->st_esp.present &&
	    sameaddr(&st->st_remoteaddr, &nfo->src) &&
	    st->st_esp.our_spi == nfo->sa->sadb_sa_spi)
		nat_traversal_new_mapping(st, &nfo->dst, nfo->dport);
}

void process_pfkey_nat_t_new_mapping(
		struct sadb_msg *msg __attribute__ ((unused)),
		struct sadb_ext *extensions[K_SADB_EXT_MAX + 1])
{
	struct new_klips_mapp_nfo nfo;
	struct sadb_address *srcx =
		(void *) extensions[K_SADB_EXT_ADDRESS_SRC];
	struct sadb_address *dstx =
		(void *) extensions[K_SADB_EXT_ADDRESS_DST];
	struct sockaddr *srca, *dsta;
	err_t ugh = NULL;

	nfo.sa = (void *) extensions[K_SADB_EXT_SA];

	if (!nfo.sa || !srcx || !dstx) {
		libreswan_log("K_SADB_X_NAT_T_NEW_MAPPING message from KLIPS malformed: got NULL params");
		return;
	}

	srca = ((struct sockaddr *)(void *)&srcx[1]);
	dsta = ((struct sockaddr *)(void *)&dstx[1]);

	if (srca->sa_family != AF_INET || dsta->sa_family != AF_INET) {
		ugh = "only AF_INET supported";
	} else {
		initaddr(
			(const void *) &((const struct sockaddr_in *)srca)->sin_addr,
			sizeof(((const struct sockaddr_in *)srca)->sin_addr),
			srca->sa_family, &nfo.src);
		nfo.sport =
			ntohs(((const struct sockaddr_in *)srca)->sin_port);
		initaddr(
			(const void *) &((const struct sockaddr_in *)dsta)->sin_addr,
			sizeof(((const struct sockaddr_in *)dsta)->sin_addr),
			dsta->sa_family, &nfo.dst);
		nfo.dport =
			ntohs(((const struct sockaddr_in *)dsta)->sin_port);

		DBG(DBG_NATT, {
			char text_said[SATOT_BUF];
			ip_said said;
			ipstr_buf bs;
			ipstr_buf bd;

			initsaid(&nfo.src, nfo.sa->sadb_sa_spi, SA_ESP,
				&said);
			satot(&said, 0, text_said, SATOT_BUF);
			DBG_log("new klips mapping %s %s:%d %s:%d",
				text_said,
				ipstr(&nfo.src, &bs), nfo.sport,
				ipstr(&nfo.dst, &bd), nfo.dport);
		});

		for_each_state(nat_t_new_klips_mapp, &nfo);
	}

	if (ugh != NULL)
		libreswan_log(
			"K_SADB_X_NAT_T_NEW_MAPPING message from KLIPS malformed: %s",
			ugh);
}

void show_setup_natt(void)
{
	whack_log(RC_COMMENT, " ");     /* spacer */
	whack_log(RC_COMMENT, "nat-traversal=%s, keep-alive=%ld, nat-ikeport=%d",
		nat_traversal_enabled ? "yes" : "no",
		(long) nat_kap,
		pluto_nat_port);
}

void ikev2_natd_lookup(struct msg_digest *md, const u_char *rcookie)
{
	unsigned char hash_me[IKEV2_NATD_HASH_SIZE];
	unsigned char hash_him[IKEV2_NATD_HASH_SIZE];
	struct payload_digest *p;
	struct state *st = md->st;
	bool found_me = FALSE;
	bool found_him = FALSE;

	passert(st != NULL);
	passert(md->iface != NULL);

	/*
	 * First one with my IP & port
	 */
	natd_hash(&crypto_hasher_sha1, hash_me, st->st_icookie, rcookie,
		&md->iface->ip_addr, md->iface->port);

	/*
	 * The others with sender IP & port
	 */
	natd_hash(&crypto_hasher_sha1, hash_him, st->st_icookie, rcookie,
		&md->sender, md->sender_port);

	for (p = md->chain[ISAKMP_NEXT_v2N]; p != NULL; p = p->next) {
		if (pbs_left(&p->pbs) != IKEV2_NATD_HASH_SIZE)
			continue;

		switch (p->payload.v2n.isan_type) {
		case v2N_NAT_DETECTION_DESTINATION_IP:
		case v2N_NAT_DETECTION_SOURCE_IP:
			/* ??? do we know from the isan_type which of these to test? */
			if (memeq(p->pbs.cur, hash_me, sizeof(hash_me)))
				found_me = TRUE;
			if (memeq(p->pbs.cur, hash_him, sizeof(hash_him)))
				found_him = TRUE;
			break;
		default:
			continue;
		}
		if (found_me && found_him)
			break;
	}

	natd_lookup_common(st, &md->sender, found_me, found_him);

	if ((st->st_state == STATE_PARENT_I1) &&
		(st->hidden_variables.st_nat_traversal
			& NAT_T_DETECTED)) {
		DBG(DBG_NATT, {
			ipstr_buf b;
			DBG_log("NAT-T: floating to port %s:%d",
				ipstr(&md->sender, &b), pluto_nat_port);
		});
		st->st_localport  = pluto_nat_port;
		st->st_remoteport = pluto_nat_port;

		nat_traversal_change_port_lookup(NULL, st);
	}
}
