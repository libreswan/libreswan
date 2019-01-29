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
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/udp.h>

#include <libreswan.h>
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

/* As per https://tools.ietf.org/html/rfc3948#section-4 */
#define DEFAULT_KEEP_ALIVE_SECS  20

bool nat_traversal_enabled = TRUE; /* can get disabled if kernel lacks support */

static deltatime_t nat_kap = DELTATIME_INIT(DEFAULT_KEEP_ALIVE_SECS);	/* keep-alive period */
static bool nat_kap_event = FALSE;

#define IKEV2_NATD_HASH_SIZE	SHA1_DIGEST_SIZE

void init_nat_traversal(deltatime_t keep_alive_period)
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


	if (deltamillisecs(keep_alive_period) != 0)
		nat_kap = keep_alive_period;

	DBG(DBG_NATT,
	    DBG_log("init_nat_traversal() initialized with keep_alive=%jds",
		    deltasecs(keep_alive_period)));
	libreswan_log("NAT-Traversal support %s",
		nat_traversal_enabled ? " [enabled]" : " [disabled]");

}

static void natd_hash(const struct hash_desc *hasher, unsigned char *hash,
		      const ike_spis_t *spis,
		      const ip_address *ip, uint16_t port /* host order */)
{
	/* only responder's IKE SPI can be zero */
	pexpect(!ike_spi_is_zero(&spis->initiator));

	if (ike_spi_is_zero(&spis->responder)) {
		/* IKE_SA_INIT exchange */
		dbg("natd_hash: rcookie is zero");
	}

	/*
	 * RFC 3947
	 *
	 *   HASH = HASH(CKY-I | CKY-R | IP | Port)
	 *
	 * All values in network order
	 */
	struct crypt_hash *ctx = crypt_hash_init("NATD", hasher);

	crypt_hash_digest_bytes(ctx, "ICOOKIE/IKE SPIi",
				&spis->initiator, sizeof(spis->initiator));
	crypt_hash_digest_bytes(ctx, "RCOOKIE/IKE SPIr",
				&spis->responder, sizeof(spis->responder));

	const unsigned char *ab;
	size_t al = addrbytesptr_read(ip, &ab);
	crypt_hash_digest_bytes(ctx, "IP addr", ab, al);

	{
		uint16_t netorder_port = htons(port);
		crypt_hash_digest_bytes(ctx, "PORT",
					&netorder_port, sizeof(netorder_port));
	}
	crypt_hash_final_bytes(&ctx, hash, hasher->hash_digest_size);
	if (DBGP(DBG_BASE)) {
		DBG_log("natd_hash: hasher=%p(%d)", hasher,
			(int)hasher->hash_digest_size);
		DBG_dump("natd_hash: icookie=", &spis->initiator, sizeof(spis->initiator));
		DBG_dump("natd_hash: rcookie=", &spis->responder, sizeof(spis->responder));
		DBG_dump("natd_hash: ip=", ab, al);
		DBG_log("natd_hash: port=%d", port);
		DBG_dump("natd_hash: hash=", hash,
			 hasher->hash_digest_size);
	}
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
	uint16_t lport = st->st_localport;

	/* if encapsulation=yes, force NAT-T detection by using wrong port for hash calc */
	if (st->st_connection->encaps == yna_yes) {
		dbg("NAT-T: encapsulation=yes, so mangling hash to force NAT-T detection");
		lport = 0;
	}

	return ikev2_out_natd(&st->st_localaddr, lport,
				&st->st_remoteaddr, st->st_remoteport,
				&ike_spis, outs);
}

bool ikev2_out_natd(const ip_address *localaddr, uint16_t localport,
		    const ip_address *remoteaddr, uint16_t remoteport,
		    const ike_spis_t *ike_spis,
		    pb_stream *outs)
{
	unsigned char hb[IKEV2_NATD_HASH_SIZE];
	chunk_t hch = { hb, sizeof(hb) };

	DBG(DBG_NATT,
		DBG_log(" NAT-Traversal support %s add v2N payloads.",
			nat_traversal_enabled ? " [enabled]" : " [disabled]"));

	/* First: one with local (source) IP & port */

	natd_hash(&ike_alg_hash_sha1, hb, ike_spis,
		  localaddr, localport);

	if (!emit_v2Nchunk(v2N_NAT_DETECTION_SOURCE_IP, &hch, outs))
		return FALSE;

	/* Second: one with remote (destination) IP & port */

	natd_hash(&ike_alg_hash_sha1, hb, ike_spis,
		  remoteaddr, remoteport);

	return emit_v2Nchunk(v2N_NAT_DETECTION_DESTINATION_IP, &hch, outs);
}

/*
 * Add NAT-Traversal VIDs (supported ones)
 *
 * Used when we're Initiator
 */
bool nat_traversal_insert_vid(uint8_t np, pb_stream *outs, const struct connection *c)
{
	DBG(DBG_NATT, DBG_log("nat add vid"));

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
		DBG(DBG_NATT, DBG_log("skipping VID_NATT drafts"));
		return out_vid(np, outs, VID_NATT_RFC);

	case NATT_BOTH:
		DBG(DBG_NATT, DBG_log("sending draft and RFC NATT VIDs"));
		if (!out_vid(ISAKMP_NEXT_VID, outs, VID_NATT_RFC))
			return FALSE;
		/* FALL THROUGH */
	case NATT_DRAFTS:
		DBG(DBG_NATT, DBG_log("skipping VID_NATT_RFC"));
		return
			out_vid(ISAKMP_NEXT_VID, outs, VID_NATT_IETF_03) &&
			out_vid(ISAKMP_NEXT_VID, outs, VID_NATT_IETF_02_N) &&
			out_vid(np, outs, VID_NATT_IETF_02);

	case NATT_NONE:
		/* This should never be reached, but makes compiler happy */
		DBG(DBG_NATT, DBG_log("not sending any NATT VID's"));
		return TRUE;

	default:
		bad_case(c->ikev1_natt);
	}
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
	DBG(DBG_NATT, DBG_log("sender checking NAT-T: %s; VID %d",
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
	anyaddr(AF_INET, &st->hidden_variables.st_natd);

	/* update NAT-T settings for local policy */
	switch (st->st_connection->encaps) {
	case yna_auto:
		DBG(DBG_NATT, DBG_log("NAT_TRAVERSAL encaps using auto-detect"));
		if (!found_me) {
			DBG(DBG_NATT, DBG_log("NAT_TRAVERSAL this end is behind NAT"));
			st->hidden_variables.st_nat_traversal |= LELEM(NATED_HOST);
			st->hidden_variables.st_natd = *sender;
		} else {
			DBG(DBG_NATT, DBG_log("NAT_TRAVERSAL this end is NOT behind NAT"));
		}

		if (!found_him) {
			DBG(DBG_NATT, {
				ipstr_buf b;
				DBG_log("NAT_TRAVERSAL that end is behind NAT %s",
					ipstr(sender, &b));
			});
			st->hidden_variables.st_nat_traversal |= LELEM(NATED_PEER);
			st->hidden_variables.st_natd = *sender;
		} else {
			DBG(DBG_NATT, DBG_log("NAT_TRAVERSAL that end is NOT behind NAT"));
		}
		break;

	case yna_no:
		st->hidden_variables.st_nat_traversal |= LEMPTY;
		DBG(DBG_NATT, DBG_log("NAT_TRAVERSAL local policy prohibits encapsulation"));
		break;

	case yna_yes:
		DBG(DBG_NATT, DBG_log("NAT_TRAVERSAL local policy enforces encapsulation"));

		DBG(DBG_NATT, DBG_log("NAT_TRAVERSAL forceencaps enabled"));
		st->hidden_variables.st_nat_traversal |=
			LELEM(NATED_PEER) | LELEM(NATED_HOST);
		st->hidden_variables.st_natd = *sender;
		break;
	}

	if (st->st_connection->nat_keepalive) {
		DBG(DBG_NATT, {
			ipstr_buf b;
			DBG_log("NAT_TRAVERSAL nat-keepalive enabled %s",
				ipstr(sender, &b));
		});
	}
}

static void ikev1_natd_lookup(struct msg_digest *md)
{
	struct state *st = md->st;
	const struct hash_desc *const hasher = st->st_oakley.ta_prf->hasher;
	const size_t hl = hasher->hash_digest_size;
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

	unsigned char hash_me[MAX_DIGEST_LEN];

	natd_hash(hasher, hash_me, &st->st_ike_spis,
		  &md->iface->ip_addr, md->iface->port);

	/* Second: one with sender IP & port */

	unsigned char hash_him[MAX_DIGEST_LEN];

	natd_hash(hasher, hash_him,
		  &st->st_ike_spis,
		  &md->sender, hportof(&md->sender));

	DBG(DBG_NATT, {
		DBG_dump("expected NAT-D(me):", hash_me, hl);
		DBG_dump("expected NAT-D(him):", hash_him, hl);
	});

	bool found_me = FALSE;
	bool found_him = FALSE;

	for (const struct payload_digest *p = hd; p != NULL; p = p->next) {
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

bool ikev1_nat_traversal_add_natd(uint8_t np, pb_stream *outs,
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

	DBG(DBG_EMITTING | DBG_NATT, DBG_log("sending NAT-D payloads"));

	const ip_address *first = &md->sender;
	unsigned short firstport = st->st_remoteport;

	const ip_address *second = &md->iface->ip_addr;
	unsigned short secondport = st->st_localport;

	if (st->st_connection->encaps == yna_yes) {
		DBG(DBG_NATT,
			DBG_log("NAT-T: encapsulation=yes, so mangling hash to force NAT-T detection"));
		firstport = secondport = 0;
	}

	struct_desc *pd = LDISJOINT(st->hidden_variables.st_nat_traversal, NAT_T_WITH_RFC_VALUES) ?
		&isakmp_nat_d_drafts : &isakmp_nat_d;
	unsigned int nat_np = pd->pt;

	unsigned char hash[MAX_DIGEST_LEN];

	/* first: emit payload with hash of sender IP & port */

	natd_hash(st->st_oakley.ta_prf->hasher, hash,
		  &ike_spis, first, firstport);

	if (!ikev1_out_generic_raw(nat_np, pd, outs, hash,
				   st->st_oakley.ta_prf->hasher->hash_digest_size,
				   "NAT-D"))
		return FALSE;

	/* second: emit payload with hash of my IP & port */

	natd_hash(st->st_oakley.ta_prf->hasher, hash,
		  &ike_spis, second, secondport);

	return ikev1_out_generic_raw(np, pd, outs, hash,
		st->st_oakley.ta_prf->hasher->hash_digest_size,
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
	anyaddr(AF_INET, &hv->st_nat_oa);

	/* Count NAT-OA */
	const struct payload_digest *p;
	int i = 0;
	for (p = md->chain[ISAKMP_NEXT_NATOA_RFC]; p != NULL; p = p->next) {
		i++;
	}

	DBG(DBG_NATT,
		DBG_log("NAT-Traversal: received %d NAT-OA.", i));

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

	DBG(DBG_PARSING,
		DBG_dump("NAT-OA:", p->pbs.start, pbs_room(&p->pbs)));

	ip_address ip;

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

static bool emit_one_natoa(
	uint8_t np,
	pb_stream *outs,
	struct_desc *pd,
	const ip_address *ip,
	const char *nm)
{
	const unsigned char *ip_val;
	size_t ip_len = addrbytesptr_read(ip, &ip_val);
	passert(ip_len != 0);

	pb_stream pbs;

	struct isakmp_nat_oa natoa = {
		.isanoa_np = np,
		.isanoa_idtype = addrtypeof(ip) == AF_INET ?
			ID_IPV4_ADDR : ID_IPV6_ADDR,
	};
	if (!out_struct(&natoa, pd, outs, &pbs) ||
	    !out_raw(ip_val, ip_len, &pbs, nm))
		return FALSE;

	DBG(DBG_NATT,
		DBG_dump("NAT-OAi (S):", ip_val, ip_len));
	close_output_pbs(&pbs);
	return TRUE;
}

bool nat_traversal_add_natoa(uint8_t np, pb_stream *outs,
			struct state *st, bool initiator)
{
	const ip_address *ipinit, *ipresp;

	if (initiator) {
		ipinit = &st->st_localaddr;
		ipresp = &st->st_remoteaddr;
	} else {
		ipresp = &st->st_localaddr;
		ipinit = &st->st_remoteaddr;
	}

	struct_desc *pd = LDISJOINT(st->hidden_variables.st_nat_traversal, NAT_T_WITH_RFC_VALUES) ?
		&isakmp_nat_oa_drafts : &isakmp_nat_oa;

	return
		emit_one_natoa(pd->pt, outs, pd, ipinit, "NAT-OAi") &&
		emit_one_natoa(np, outs, pd, ipresp, "NAT-OAr");
}

static void nat_traversal_show_result(lset_t nt, uint16_t sport)
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
	    DBG_log("init checking NAT-T: %s; %s",
		    nat_traversal_enabled ? "enabled" : "disabled",
		    bitnamesof(natt_bit_names, st->hidden_variables.st_nat_traversal)));

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
				hportof(&md->sender));
		}
	}
	if (st->hidden_variables.st_nat_traversal & NAT_T_WITH_KA) {
		DBG(DBG_NATT, DBG_log(" NAT_T_WITH_KA detected"));
		nat_traversal_new_ka_event();
	}
}

int nat_traversal_espinudp_socket(int sk, const char *fam)
{
#if defined(NETKEY_SUPPORT) || defined(BSD_KAME)
	if (kern_interface == USE_NETKEY || kern_interface == USE_BSDKAME) {
		DBG(DBG_NATT, DBG_log("NAT-Traversal: Trying sockopt style NAT-T"));

		/*
		 * The SOL (aka socket level) is really the the
		 * protocol number which, for UDP, is always 17.
		 * Linux provides a SOL_* macro, the others don't.
		 */
#if defined(SOL_UDP)
		const int sol_udp = SOL_UDP;
#elif defined(IPPROTO_UDP)
		const int sol_udp = IPPROTO_UDP;
#endif

		/*
		 * Was UDP_ESPINUDP (aka 100).  Linux/NetBSD have the
		 * value 100, FreeBSD has the value 1.
		 */
		const int sol_name = UDP_ENCAP;

		/*
		 * Was ESPINUDP_WITH_NON_ESP (aka 2) defined in
		 * "libreswan.h" which smells like something intended
		 * for the KLIPS module. <netinet/udp.h> defines the
		 * below across linux and *BSD.
		 */
		const int sol_value = UDP_ENCAP_ESPINUDP;

		int r = setsockopt(sk, sol_udp, sol_name, &sol_value, sizeof(sol_value));
		if (r == -1) {
			DBG(DBG_NATT,
				DBG_log("NAT-Traversal: ESPINUDP(%d) setup failed for sockopt style NAT-T family %s (errno=%d)",
					sol_value, fam, errno));
		} else {
			DBG(DBG_NATT,
				DBG_log("NAT-Traversal: ESPINUDP(%d) setup succeeded for sockopt style NAT-T family %s",
					sol_value, fam));
			return r;
		}
	} else {
		DBG(DBG_NATT,
			DBG_log("NAT-Traversal: ESPINUDP() support for sockopt style NAT-T family not available for this kernel"));
	}
#else
	DBG(DBG_NATT,
		DBG_log("NAT-Traversal: ESPINUDP() support for sockopt style NAT-T family not compiled in"));
#endif

#if defined(KLIPS)
	if (kern_interface == USE_KLIPS) {
		struct ifreq ifr;
		int *fdp = (int *) &ifr.ifr_data;
		DBG(DBG_NATT, DBG_log("NAT-Traversal: Trying old ioctl style NAT-T"));
		zero(&ifr);
		const char *const ifn = "ipsec0"; /* mast must use ipsec0 too */
		fill_and_terminate(ifr.ifr_name, ifn, sizeof(ifr.ifr_name));
		fdp[0] = sk;
		fdp[1] = ESPINUDP_WITH_NON_ESP; /* no longer support non-ike or non-floating */
		int r = ioctl(sk, IPSEC_UDP_ENCAP_CONVERT, &ifr); /* private to KLIPS only */
		if (r == -1) {
			DBG(DBG_NATT,
				DBG_log("NAT-Traversal: ESPINUDP(%d) setup failed for old ioctl style NAT-T family %s (errno=%d)",
					ESPINUDP_WITH_NON_ESP, fam, errno));
		} else {
			DBG(DBG_NATT,
				DBG_log("NAT-Traversal: ESPINUDP(%d) setup succeeded for old ioctl style NAT-T family %s",
					ESPINUDP_WITH_NON_ESP, fam));
			return r;
		}
	} else {
		DBG(DBG_NATT,
			DBG_log("NAT-Traversal: ESPINUDP() support for ioctl style NAT-T family not available for this kernel"));
	}
#else
	DBG(DBG_NATT,
		DBG_log("NAT-Traversal: ESPINUDP() support for ioctl style NAT-T family not compiled in"));
#endif

	/* all methods failed to detect NAT-T support */
	loglog(RC_LOG_SERIOUS,
	       "NAT-Traversal: ESPINUDP for this kernel not supported or not found for family %s",
	       fam);
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

	if (!LHAS(st->hidden_variables.st_nat_traversal, NATED_HOST)) {
		DBG(DBG_NATT,
			DBG_log("not behind NAT: no NAT-T KEEP-ALIVE required for conn %s",
				c->name));
	}

	if (!c->nat_keepalive) {
		DBG(DBG_NATT,
			DBG_log("Suppressing sending of NAT-T KEEP-ALIVE for conn %s (nat-keepalive=no)",
				c->name));
		return;
	}

	/*
	 * As long as we don't check get_sa_info() in IPsec SA's, and for
	 * IKEv1 IPsec SA's always send a keepalive, we might as well
	 * _not_ send keepalives for IKEv1 IKE SA's.
	 */
	if ((st->st_ike_version == IKEv2) && IS_IKE_SA_ESTABLISHED(st)) {
		/*
		 * - IKE SA established
		 * - we are behind NAT
		 * - NAT-KeepAlive needed (we are NATed)
		 */
		if (c->newest_isakmp_sa != st->st_serialno)
			return;

		/* consider this connection for the next global loop */
		(*nat_kap_st)++;

		/*
		 * If this IKE SA sent a packet recently, no need for anything
		 * eg, if short DPD timers are used we can skip this.
		 */
		if (!is_monotime_epoch(st->st_last_liveness) &&
			deltasecs(monotimediff(mononow(), st->st_last_liveness)) < DEFAULT_KEEP_ALIVE_SECS)
		{
			DBG(DBG_NATT, DBG_log("NAT-T: keepalive packet not required as recent DPD event used the IKE SA on conn %s",
				c->name));
			return;
		}

		/*
		 * TODO or not?
		 * We could also check If there is IPsec SA encapsulation traffic, since
		 * then we also do not need to send keepalives, but that check is a little
		 * expensive as we have to find some/all IPsec states and ask the kernel,
		 * every 20s.
		 */
		DBG(DBG_NATT,
			DBG_log("we are behind NAT: sending of NAT-T KEEP-ALIVE for conn %s (nat-keepalive=yes)",
				c->name));
		nat_traversal_send_ka(st);
		return;
	}

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
	if (st->st_ike_version == IKEv1 && IS_IPSEC_SA_ESTABLISHED(st) &&
		c->newest_ipsec_sa == st->st_serialno)
	{
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
	uint16_t port;
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

		DBG(DBG_CONTROLMORE, DBG_log("new NAT mapping for #%lu, was %s:%d, now %s:%d",
			st->st_serialno,
			ipstr(&st->st_remoteaddr, &b1),
			st->st_remoteport,
			ipstr(&nfo->addr, &b2),
			nfo->port));

		/* update it */
		st->st_remoteaddr = nfo->addr;
		st->st_remoteport = nfo->port;
		st->hidden_variables.st_natd = nfo->addr;

		if (c->kind == CK_INSTANCE)
			c->spd.that.host_addr = nfo->addr;
	}
}

void nat_traversal_new_mapping(struct state *st,
			       const ip_address *nsrc,
			       uint16_t nsrcport)
{
	struct new_mapp_nfo nfo;

	DBG(DBG_NATT, {
		ipstr_buf b;
		DBG_log("state #%lu NAT-T: new mapping %s:%d",
			st->st_serialno,
			ipstr(nsrc, &b),
			nsrcport);
	});

	nfo.st    = st;
	nfo.addr  = *nsrc;
	nfo.port  = nsrcport;

	for_each_state(nat_traversal_find_new_mapp_state, &nfo);
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
		if (st->st_remoteport != hportof(&md->sender) ||
		    !sameaddr(&st->st_remoteaddr, &md->sender)) {
			nat_traversal_new_mapping(st, &md->sender,
						hportof(&md->sender));
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

void show_setup_natt(void)
{
	whack_log(RC_COMMENT, " ");     /* spacer */
	whack_log(RC_COMMENT, "nat-traversal=%s, keep-alive=%ld, nat-ikeport=%d",
		  bool_str(nat_traversal_enabled),
		  (long) deltasecs(nat_kap),
		  pluto_nat_port);
}

void ikev2_natd_lookup(struct msg_digest *md, const ike_spi_t *ike_responder_spi)
{
	struct state *st = md->st;
	ike_spis_t ike_spis = {
		.initiator = st->st_ike_spis.initiator,
		.responder = *ike_responder_spi,
	};

	passert(st != NULL);
	passert(md->iface != NULL);

	/*
	 * First: one with my IP & port
	 * TODO: This use must be allowed even with USE_SHA1=false
	 */

	unsigned char hash_me[IKEV2_NATD_HASH_SIZE];

	natd_hash(&ike_alg_hash_sha1, hash_me, &ike_spis,
		  &md->iface->ip_addr, md->iface->port);

	/* Second: one with sender IP & port */

	unsigned char hash_him[IKEV2_NATD_HASH_SIZE];

	natd_hash(&ike_alg_hash_sha1, hash_him, &ike_spis,
		  &md->sender, hportof(&md->sender));

	bool found_me = FALSE;
	bool found_him = FALSE;

	for (struct payload_digest *p = md->chain[ISAKMP_NEXT_v2N]; p != NULL; p = p->next) {
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
	}

	natd_lookup_common(st, &md->sender, found_me, found_him);

	if (st->st_state == STATE_PARENT_I1 &&
	    (st->hidden_variables.st_nat_traversal & NAT_T_DETECTED)) {
		DBG(DBG_NATT, {
			ipstr_buf b;
			DBG_log("NAT-T: floating to port %s:%d",
				ipstr(&md->sender, &b), pluto_nat_port);
		});
		st->st_localport = pluto_nat_port;
		st->st_remoteport = pluto_nat_port;

		nat_traversal_change_port_lookup(NULL, st);
	}
}
