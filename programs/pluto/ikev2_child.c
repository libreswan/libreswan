/*
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2011-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012,2016-2017 Antony Antony <appu@phenome.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2014-2015 Andrew cagney <cagney@gnu.org>
 * Copyright (C) 2017 Antony Antony <antony@phenome.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"
#include "libswan.h"

#include "defs.h"
#include "cookie.h"
#include "id.h"
#include "x509.h"
#include "pluto_x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "crypto.h"
#include "ike_alg.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */
#include "pluto_crypt.h"  /* for pluto_crypto_req & pluto_crypto_req_cont */
#include "ikev2.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "timer.h"
#include "whack.h"      /* requires connections.h */
#include "server.h"
#include "vendor.h"
#include "kernel.h"
#include "virtual.h"	/* needs connections.h */
#include "hostpair.h"
#include "addresspool.h"
#include "rnd.h"
#include "ip_address.h"
#include "ikev2_send.h"

void ikev2_print_ts(const struct traffic_selector *ts)
{
	DBG(DBG_CONTROLMORE, {
		char b[RANGETOT_BUF];

		rangetot(&ts->net, 0, b, sizeof(b));
		DBG_log("printing contents struct traffic_selector");
		DBG_log("  ts_type: %s", enum_name(&ikev2_ts_type_names, ts->ts_type));
		DBG_log("  ipprotoid: %d", ts->ipprotoid);
		DBG_log("  port range: %d-%d", ts->startport, ts->endport);
		DBG_log("  ip range: %s", b);
	});
}

/* rewrite me with addrbytesptr_write() */
struct traffic_selector ikev2_end_to_ts(const struct end *e)
{
	struct traffic_selector ts;

	zero(&ts);	/* OK: no pointer fields */

	/* subnet => range */
	ts.net.start = e->client.addr;
	ts.net.end = e->client.addr;
	switch (addrtypeof(&e->client.addr)) {
	case AF_INET:
	{
		struct in_addr v4mask = bitstomask(e->client.maskbits);

		ts.ts_type = IKEv2_TS_IPV4_ADDR_RANGE;
		ts.net.start.u.v4.sin_addr.s_addr &= v4mask.s_addr;
		ts.net.end.u.v4.sin_addr.s_addr |= ~v4mask.s_addr;
		break;
	}
	case AF_INET6:
	{
		struct in6_addr v6mask = bitstomask6(e->client.maskbits);

		ts.ts_type = IKEv2_TS_IPV6_ADDR_RANGE;
		ts.net.start.u.v6.sin6_addr.s6_addr32[0] &= v6mask.s6_addr32[0];
		ts.net.start.u.v6.sin6_addr.s6_addr32[1] &= v6mask.s6_addr32[1];
		ts.net.start.u.v6.sin6_addr.s6_addr32[2] &= v6mask.s6_addr32[2];
		ts.net.start.u.v6.sin6_addr.s6_addr32[3] &= v6mask.s6_addr32[3];

		ts.net.end.u.v6.sin6_addr.s6_addr32[0] |= ~v6mask.s6_addr32[0];
		ts.net.end.u.v6.sin6_addr.s6_addr32[1] |= ~v6mask.s6_addr32[1];
		ts.net.end.u.v6.sin6_addr.s6_addr32[2] |= ~v6mask.s6_addr32[2];
		ts.net.end.u.v6.sin6_addr.s6_addr32[3] |= ~v6mask.s6_addr32[3];
		break;
	}

	}
	/* Setting ts_type IKEv2_TS_FC_ADDR_RANGE (RFC-4595) not yet supported */

	ts.ipprotoid = e->protocol;

	/*
	 * if port is %any or 0 we mean all ports (or all iccmp/icmpv6)
	 * See RFC-5996 Section 3.13.1 handling for ICMP(1) and ICMPv6(58)
	 *   we only support providing Type, not Code, eg protoport=1/1
	 */
	if (e->port == 0 || e->has_port_wildcard) {
		ts.startport = 0;
		ts.endport = 65535;
	} else {
		ts.startport = e->port;
		ts.endport = e->port;
	}

	return ts;
}

static stf_status ikev2_emit_ts(pb_stream *outpbs,
				const struct_desc *ts_desc,
				const struct traffic_selector *ts,
				enum next_payload_types_ikev2 np)
{
	pb_stream ts_pbs;

	{
		struct ikev2_ts its = {
			.isat_lt = np, /* LT is IKEv1 name? */
			.isat_critical = ISAKMP_PAYLOAD_NONCRITICAL,
			.isat_num = 1,
		};

		if (!out_struct(&its, ts_desc, outpbs, &ts_pbs))
			return STF_INTERNAL_ERROR;
	}

	pb_stream ts_pbs2;

	{
		struct ikev2_ts1 its1 = {
			.isat1_ipprotoid = ts->ipprotoid,   /* protocol as per local policy */
			.isat1_startport = ts->startport,   /* ports as per local policy */
			.isat1_endport = ts->endport,
		};
		switch (ts->ts_type) {
		case IKEv2_TS_IPV4_ADDR_RANGE:
			its1.isat1_type = IKEv2_TS_IPV4_ADDR_RANGE;
			its1.isat1_sellen = 2 * 4 + 8; /* See RFC 5669 SEction 13.3.1, 8 octet header plus 2 ip addresses */
			break;
		case IKEv2_TS_IPV6_ADDR_RANGE:
			its1.isat1_type = IKEv2_TS_IPV6_ADDR_RANGE;
			its1.isat1_sellen = 2 * 16 + 8; /* See RFC 5669 SEction 13.3.1, 8 octet header plus 2 ip addresses */
			break;
		case IKEv2_TS_FC_ADDR_RANGE:
			DBG_log("IKEv2 Traffic Selector IKEv2_TS_FC_ADDR_RANGE not yet supported");
			return STF_INTERNAL_ERROR;

		default:
			DBG_log("IKEv2 Traffic Selector type '%d' not supported",
				ts->ts_type);
		}

		if (!out_struct(&its1, &ikev2_ts1_desc, &ts_pbs, &ts_pbs2))
			return STF_INTERNAL_ERROR;
	}

	/* now do IP addresses */
	switch (ts->ts_type) {
	case IKEv2_TS_IPV4_ADDR_RANGE:
		if (!out_raw(&ts->net.start.u.v4.sin_addr.s_addr, 4, &ts_pbs2,
			     "ipv4 start") ||
		    !out_raw(&ts->net.end.u.v4.sin_addr.s_addr, 4, &ts_pbs2,
			     "ipv4 end"))
			return STF_INTERNAL_ERROR;

		break;
	case IKEv2_TS_IPV6_ADDR_RANGE:
		if (!out_raw(&ts->net.start.u.v6.sin6_addr.s6_addr, 16, &ts_pbs2,
			     "ipv6 start") ||
		    !out_raw(&ts->net.end.u.v6.sin6_addr.s6_addr, 16, &ts_pbs2,
			     "ipv6 end"))
			return STF_INTERNAL_ERROR;

		break;
	case IKEv2_TS_FC_ADDR_RANGE:
		DBG_log("Traffic Selector IKEv2_TS_FC_ADDR_RANGE not supported");
		return STF_FAIL;

	default:
		DBG_log("Failed to create unknown IKEv2 Traffic Selector payload '%d'",
			ts->ts_type);
		return STF_FAIL;
	}

	close_output_pbs(&ts_pbs2);
	close_output_pbs(&ts_pbs);

	return STF_OK;
}

stf_status ikev2_emit_ts_payloads(const struct child_sa *child,
				  pb_stream *outpbs,
				  enum sa_role role,
				  const struct connection *c0,
				  const enum next_payload_types_ikev2 np)
{
	const struct traffic_selector *ts_i, *ts_r;

	switch (role) {
	case SA_INITIATOR:
		ts_i = &child->sa.st_ts_this;
		ts_r = &child->sa.st_ts_that;
		break;
	case SA_RESPONDER:
		ts_i = &child->sa.st_ts_that;
		ts_r = &child->sa.st_ts_this;
		break;
	default:
		bad_case(role);
	}

	/*
	 * XXX: this looks wrong
	 *
	 * - instead of emitting two traffic selector payloads (TSi
	 *   TSr) each containg all the corresponding traffic
	 *   selectors, it is emitting a sequence of traffic selector
	 *   payloads each containg just one traffic selector
	 *
	 * - should multiple initiator (responder) traffic selector
	 *   payloads be emitted then they will all contain the same
	 *   value - the loop control variable SR is never referenced
	 *
	 * - should multiple traffic selector payload be emitted then
	 *   the next payload type for all but the last v2TSr payload
	 *   will be wrong - it is always set to the type of the
	 *   payload after these
	 */

	for (const struct spd_route *sr = &c0->spd; sr != NULL;
	     sr = sr->spd_next) {
		stf_status ret = ikev2_emit_ts(outpbs, &ikev2_ts_i_desc, ts_i,
					       ISAKMP_NEXT_v2TSr);

		if (ret != STF_OK)
			return ret;
		ret = ikev2_emit_ts(outpbs, &ikev2_ts_r_desc, ts_r, np);
		if (ret != STF_OK)
			return ret;
	}

	return STF_OK;
}

/* return number of traffic selectors found; -1 for error */
int ikev2_parse_ts(struct payload_digest *const ts_pd,
		   struct traffic_selector *array,
		   unsigned int array_roof)
{
	unsigned int i;

	if (ts_pd->payload.v2ts.isat_num >= array_roof) {
		DBGF(DBG_CONTROLMORE,
		     "TS contains %d entries which exceeds hardwired max of %d",
		     ts_pd->payload.v2ts.isat_num, array_roof);
		return -1;	/* won't fit in array */
	}

	for (i = 0; i < ts_pd->payload.v2ts.isat_num; i++) {
		pb_stream addr;
		struct ikev2_ts1 ts1;

		if (!in_struct(&ts1, &ikev2_ts1_desc, &ts_pd->pbs, &addr))
			return -1;

		zero(&array[i]);	/* OK: no pointer fields */
		switch (ts1.isat1_type) {
		case IKEv2_TS_IPV4_ADDR_RANGE:
			array[i].ts_type = IKEv2_TS_IPV4_ADDR_RANGE;
			SET_V4(array[i].net.start);
			if (!in_raw(&array[i].net.start.u.v4.sin_addr.s_addr,
				    sizeof(array[i].net.start.u.v4.sin_addr.s_addr),
				    &addr, "ipv4 ts low"))
				return -1;

			SET_V4(array[i].net.end);

			if (!in_raw(&array[i].net.end.u.v4.sin_addr.s_addr,
				    sizeof(array[i].net.end.u.v4.sin_addr.s_addr),
				    &addr, "ipv4 ts high"))
				return -1;

			break;

		case IKEv2_TS_IPV6_ADDR_RANGE:
			array[i].ts_type = IKEv2_TS_IPV6_ADDR_RANGE;
			SET_V6(array[i].net.start);

			if (!in_raw(&array[i].net.start.u.v6.sin6_addr.s6_addr,
				    sizeof(array[i].net.start.u.v6.sin6_addr.s6_addr),
				    &addr, "ipv6 ts low"))
				return -1;

			SET_V6(array[i].net.end);

			if (!in_raw(&array[i].net.end.u.v6.sin6_addr.s6_addr,
				    sizeof(array[i].net.end.u.v6.sin6_addr.s6_addr),
				    &addr, "ipv6 ts high"))
				return -1;

			break;

		default:
			return -1;
		}

		if (pbs_left(&addr) != 0)
			return -1;

		array[i].ipprotoid = ts1.isat1_ipprotoid;

		/* should be converted to host byte order for local processing */
		array[i].startport = ts1.isat1_startport;
		array[i].endport = ts1.isat1_endport;
	}

	return i;
}

/*
 * Check if our policy's protocol (proto) matches
 * the Traffic Selector protocol (ts_proto).
 * If superset_ok, narrowing ts_proto 0 to our proto is OK (responder narrowing)
 * If subset_ok, narrowing our proto 0 to ts_proto is OK (initiator narrowing).
 * Returns 0 for no match, 1 for narrowed match, 255 for exact match.
 */
static int ikev2_match_protocol(uint8_t proto, uint8_t ts_proto,
	bool superset_ok, bool subset_ok, const char *which, int index)
{
	int f = 0;	/* strength of match */
	const char *m = "no";

	if (proto == ts_proto) {
		f = 255;	/* ??? odd value */
		m = "exact";
	} else if (superset_ok && ts_proto == 0) {
		f = 1;
		m = "superset";
	} else if (subset_ok && proto == 0) {
		f = 1;
		m = "subset";
	}
	DBG(DBG_CONTROL,
	    DBG_log("protocol %d and %s[%d].ipprotoid %d: %s match",
		    proto,
		    which, index,
		    ts_proto,
		    m));
	return f;
}

/*
 * returns -1 on no match; otherwise a weight of how great the match was.
 * *best_tsi_i and *best_tsr_i are set if there was a match.
 * Almost identical to ikev2_evaluate_connection_port_fit:
 * any change should be done to both.
 */
int ikev2_evaluate_connection_protocol_fit(const struct connection *d,
					   const struct spd_route *sr,
					   enum original_role role,
					   const struct traffic_selector *tsi,
					   const struct traffic_selector *tsr,
					   int tsi_n,
					   int tsr_n,
					   int *best_tsi_i,
					   int *best_tsr_i)
{
	int tsi_ni;
	int bestfit_pr = -1;
	const struct end *ei, *er;
	bool narrowing = (d->policy & POLICY_IKEV2_ALLOW_NARROWING) != LEMPTY;

	if (role == ORIGINAL_INITIATOR) {
		ei = &sr->this;
		er = &sr->that;
	} else {
		ei = &sr->that;
		er = &sr->this;
	}
	/* compare tsi/r array to this/that, evaluating protocol how well it fits */
	/* ??? stupid n**2 algorithm */
	for (tsi_ni = 0; tsi_ni < tsi_n; tsi_ni++) {
		int tsr_ni;

		int fitrange_i = ikev2_match_protocol(ei->protocol, tsi[tsi_ni].ipprotoid,
			role == ORIGINAL_RESPONDER && narrowing,
			role == ORIGINAL_INITIATOR && narrowing,
			"tsi", tsi_ni);

		if (fitrange_i == 0)
			continue;	/* save effort! */

		for (tsr_ni = 0; tsr_ni < tsr_n; tsr_ni++) {
			int fitrange_r = ikev2_match_protocol(er->protocol, tsr[tsr_ni].ipprotoid,
				role == ORIGINAL_RESPONDER && narrowing,
				role == ORIGINAL_INITIATOR && narrowing,
				"tsr", tsr_ni);

			if (fitrange_r == 0)
				continue;	/* save effort! */

			int matchiness = fitrange_i + fitrange_r;	/* ??? arbitrary objective function */

			if (matchiness > bestfit_pr) {
				*best_tsi_i = tsi_ni;
				*best_tsr_i = tsr_ni;
				bestfit_pr = matchiness;
				DBG(DBG_CONTROL,
				    DBG_log("    best protocol fit so far: tsi[%d] fitrange_i %d, tsr[%d] fitrange_r %d, matchiness %d",
					    *best_tsi_i, fitrange_i,
					    *best_tsr_i, fitrange_r,
					    matchiness));
			}
		}
	}
	DBG(DBG_CONTROL, DBG_log("    protocol_fitness %d", bestfit_pr));
	return bestfit_pr;
}


/*
 * Check if our policy's port (port) matches
 * the Traffic Selector port range (ts.startport to ts.endport)
 * Note port == 0 means port range 0 to 65535.
 * If superset_ok, narrowing ts port range to our port range is OK (responder narrowing)
 * If subset_ok, narrowing our port range to ts port range is OK (initiator narrowing).
 * Returns 0 if no match; otherwise number of ports within match
 */
static int ikev2_match_port_range(uint16_t port, struct traffic_selector ts,
	bool superset_ok, bool subset_ok, const char *which, int index)
{
	uint16_t low = port;
	uint16_t high = port == 0 ? 65535 : port;
	int f = 0;	/* strength of match */
	const char *m = "no";

	if (ts.startport > ts.endport) {
		m = "invalid range in";
	} else if (ts.startport == low && ts.endport == high) {
		f = 1 + (high - low);
		m = "exact";
	} else if (superset_ok && ts.startport <= low && high <= ts.endport) {
		f = 1 + (high - low);
		m = "superset";
	} else if (subset_ok && low <= ts.startport && ts.endport <= high) {
		f = 1 + (ts.endport - ts.startport);
		m = "subset";
	}
	DBG(DBG_CONTROL,
	    DBG_log("   %s[%d] %u-%u: %s port match with %u.  fitness %d",
		    which, index,
		    ts.startport, ts.endport,
		    m,
		    port,
		    f));
	return f;
}

/*
 * returns -1 on no match; otherwise a weight of how great the match was.
 * *best_tsi_i and *best_tsr_i are set if there was a match.
 * Almost identical to ikev2_evaluate_connection_protocol_fit:
 * any change should be done to both.
 */
int ikev2_evaluate_connection_port_fit(const struct connection *d,
				       const struct spd_route *sr,
				       enum original_role role,
				       const struct traffic_selector *tsi,
				       const struct traffic_selector *tsr,
				       int tsi_n,
				       int tsr_n,
				       int *best_tsi_i,
				       int *best_tsr_i)
{
	int tsi_ni;
	int bestfit_p = -1;
	const struct end *ei, *er;
	bool narrowing = (d->policy & POLICY_IKEV2_ALLOW_NARROWING) != LEMPTY;

	if (role == ORIGINAL_INITIATOR) {
		ei = &sr->this;
		er = &sr->that;
	} else {
		ei = &sr->that;
		er = &sr->this;
	}
	/* compare tsi/r array to this/that, evaluating how well each port range fits */
	/* ??? stupid n**2 algorithm */
	for (tsi_ni = 0; tsi_ni < tsi_n; tsi_ni++) {
		int tsr_ni;

		int fitrange_i = ikev2_match_port_range(ei->port, tsi[tsi_ni],
			role == ORIGINAL_RESPONDER && narrowing,
			role == ORIGINAL_INITIATOR && narrowing,
			"tsi", tsi_ni);

		if (fitrange_i == 0)
			continue;	/* save effort! */

		for (tsr_ni = 0; tsr_ni < tsr_n; tsr_ni++) {
			int fitrange_r = ikev2_match_port_range(er->port, tsr[tsr_ni],
				role == ORIGINAL_RESPONDER && narrowing,
				role == ORIGINAL_INITIATOR && narrowing,
				"tsr", tsr_ni);

			if (fitrange_r == 0)
				continue;	/* no match */

			int matchiness = fitrange_i + fitrange_r;	/* ??? arbitrary objective function */

			if (matchiness > bestfit_p) {
				*best_tsi_i = tsi_ni;
				*best_tsr_i = tsr_ni;
				bestfit_p = matchiness;
				DBG(DBG_CONTROL,
				    DBG_log("    best ports fit so far: tsi[%d] fitrange_i %d, tsr[%d] fitrange_r %d, matchiness %d",
					    *best_tsi_i, fitrange_i,
					    *best_tsr_i, fitrange_r,
					    matchiness));
			}
		}
	}
	DBG(DBG_CONTROL, DBG_log("    port_fitness %d", bestfit_p));
	return bestfit_p;
}

/*
 * RFC 5996 section 2.9 "Traffic Selector Negotiation"
 * Future: section 2.19 "Requesting an Internal Address on a Remote Network"
 */
int ikev2_evaluate_connection_fit(const struct connection *d,
				  const struct spd_route *sr,
				  enum original_role role,
				  const struct traffic_selector *tsi,
				  const struct traffic_selector *tsr,
				  int tsi_n,
				  int tsr_n)
{
	int tsi_ni;
	int bestfit = -1;
	const struct end *ei, *er;

	if (role == ORIGINAL_INITIATOR) {
		ei = &sr->this;
		er = &sr->that;
	} else {
		ei = &sr->that;
		er = &sr->this;
	}

	DBG(DBG_CONTROLMORE, {
		char ei3[SUBNETTOT_BUF];
		char er3[SUBNETTOT_BUF];
		char cib[CONN_INST_BUF];
		subnettot(&ei->client,  0, ei3, sizeof(ei3));
		subnettot(&er->client,  0, er3, sizeof(er3));
		DBG_log("  ikev2_evaluate_connection_fit evaluating our conn=\"%s\"%s I=%s:%d/%d R=%s:%d/%d %s to their:",
			d->name, fmt_conn_instance(d, cib),
			ei3, ei->protocol, ei->port,
			er3, er->protocol, er->port,
			is_virtual_connection(d) ? "(virt)" : "");
	});

	/* compare tsi/r array to this/that, evaluating how well it fits */
	for (tsi_ni = 0; tsi_ni < tsi_n; tsi_ni++) {
		int tsr_ni;

		for (tsr_ni = 0; tsr_ni < tsr_n; tsr_ni++) {
			/* does it fit at all? */

			DBG(DBG_CONTROLMORE, {
				char bi[RANGETOT_BUF];
				char br[RANGETOT_BUF];

				rangetot(&tsi[tsi_ni].net, 0, bi, sizeof(bi));
				rangetot(&tsr[tsi_ni].net, 0, br, sizeof(br));
				DBG_log("    tsi[%u]=%s proto=%d portrange %d-%d, tsr[%u]=%s proto=%d portrange %d-%d",
					tsi_ni,
					bi,
					tsi[tsi_ni].ipprotoid,
					tsi[tsi_ni].startport,
					tsi[tsi_ni].endport,
					tsr_ni,
					br,
					tsr[tsr_ni].ipprotoid,
					tsr[tsr_ni].startport,
					tsr[tsr_ni].endport);
			});
			/* do addresses fit into the policy? */

			/*
			 * NOTE: Our parser/config only allows 1 CIDR, however IKEv2 ranges can be non-CIDR
			 *       for now we really support/limit ourselves to a single CIDR
			 */
			if (addrinsubnet(&tsi[tsi_ni].net.start, &ei->client) &&
			    addrinsubnet(&tsi[tsi_ni].net.end, &ei->client) &&
			    addrinsubnet(&tsr[tsr_ni].net.start,  &er->client) &&
			    addrinsubnet(&tsr[tsr_ni].net.end, &er->client)) {
				/*
				 * now, how good a fit is it? --- sum of bits gives
				 * how good a fit this is.
				 */
				int ts_range1 = iprange_bits(
					tsi[tsi_ni].net.start, tsi[tsi_ni].net.end);
				int maskbits1 = ei->client.maskbits;
				int fitbits1 = maskbits1 + ts_range1;

				int ts_range2 = iprange_bits(
					tsr[tsr_ni].net.start, tsr[tsr_ni].net.end);
				int maskbits2 = er->client.maskbits;
				int fitbits2 = maskbits2 + ts_range2;

				/* ??? this objective function is odd and arbitrary */
				int fitbits = (fitbits1 << 8) + fitbits2;

				/*
				 * comparing for ports
				 * for finding better local policy
				 */
				/* ??? arbitrary modification to objective function */
				DBG(DBG_CONTROL,
				    DBG_log("ei->port %d tsi[tsi_ni].startport %d  tsi[tsi_ni].endport %d",
					    ei->port,
					    tsi[tsi_ni].startport,
					    tsi[tsi_ni].endport));

				if (ei->port != 0 &&
				    tsi[tsi_ni].startport == ei->port &&
				    tsi[tsi_ni].endport == ei->port)
					fitbits = fitbits << 1;

				if (er->port != 0 &&
				    tsr[tsr_ni].startport == er->port &&
				    tsr[tsr_ni].endport == er->port)
					fitbits = fitbits << 1;

				DBG(DBG_CONTROLMORE,
					    DBG_log("      has ts_range1=%u maskbits1=%u ts_range2=%u maskbits2=%u fitbits=%d <> %d",
						    ts_range1, maskbits1,
						    ts_range2, maskbits2,
						    fitbits, bestfit));

				if (fitbits > bestfit)
					bestfit = fitbits;
			}
		}
	}

	return bestfit;
}

/*
 * find the best connection and, if it is AUTH exchange, create the child state
 */
stf_status ikev2_resp_accept_child_ts(
	const struct msg_digest *md,
	struct state **ret_cst,	/* where to return child state */
	enum original_role role, enum isakmp_xchg_types isa_xchg)
{
	struct connection *c = md->st->st_connection;

	DBG(DBG_CONTROLMORE,
	    DBG_log("TS: parse initiator traffic selectors"));
	/* ??? is 16 an undocumented limit - IKEv2 has no limit */
	struct traffic_selector tsi[16];
	const int tsi_n = ikev2_parse_ts(md->chain[ISAKMP_NEXT_v2TSi],
					 tsi, elemsof(tsi));

	DBG(DBG_CONTROLMORE,
	    DBG_log("TS: parse responder traffic selectors"));
	/* ??? is 16 an undocumented limit - IKEv2 has no limit */
	struct traffic_selector tsr[16];
	const int tsr_n = ikev2_parse_ts(md->chain[ISAKMP_NEXT_v2TSr],
					 tsr, elemsof(tsr));

	/* best so far */
	int bestfit_n = -1;
	int bestfit_p = -1;
	int bestfit_pr = -1;
	const struct spd_route *bsr = NULL;	/* best spd_route so far */

	int best_tsi_i = -1;
	int best_tsr_i = -1;

	*ret_cst = NULL;	/* no child state yet */

	/* ??? not very clear diagnostic for our user */
	if (tsi_n < 0 || tsr_n < 0)
		return STF_FAIL + v2N_TS_UNACCEPTABLE;

	/* find best spd in c */
	const struct spd_route *sra;

	for (sra = &c->spd; sra != NULL; sra = sra->spd_next) {
		int bfit_n = ikev2_evaluate_connection_fit(c, sra, role, tsi,
				tsr, tsi_n, tsr_n);

		if (bfit_n > bestfit_n) {
			DBG(DBG_CONTROLMORE,
			    DBG_log("prefix fitness found a better match c %s",
				    c->name));
			int bfit_p = ikev2_evaluate_connection_port_fit(
				    c, sra, role, tsi, tsr, tsi_n, tsr_n,
				    &best_tsi_i, &best_tsr_i);

			if (bfit_p > bestfit_p) {
				DBG(DBG_CONTROLMORE,
				    DBG_log("port fitness found better match c %s, tsi[%d],tsr[%d]",
					    c->name, best_tsi_i, best_tsr_i));
				int bfit_pr =
					ikev2_evaluate_connection_protocol_fit(
						c, sra, role,
						tsi, tsr, tsi_n, tsr_n,
						&best_tsi_i, &best_tsr_i);

				if (bfit_pr > bestfit_pr) {
					DBG(DBG_CONTROLMORE,
					    DBG_log("protocol fitness found better match c %s, tsi[%d],tsr[%d]",
						    c->name,
						    best_tsi_i,
						    best_tsr_i));

					bestfit_p = bfit_p;
					bestfit_n = bfit_n;
					bsr = sra;
				} else {
					DBG(DBG_CONTROLMORE,
					    DBG_log("protocol fitness rejected c %s c->name",
						    c->name));
				}
			} else {
				DBG(DBG_CONTROLMORE,
						DBG_log("port fitness rejected c %s c->name", c->name));
			}
		} else {
			DBG(DBG_CONTROLMORE,
			    DBG_log("prefix fitness rejected c %s c->name", c->name));
		}
	}

	/*
	 * ??? the use of hp looks nonsensical.
	 * Either the first non-empty host_pair should be used
	 * (like the current code) and the following should
	 * be broken into two loops: first find the non-empty
	 * host_pair list, second look through the host_pair list.
	 * OR
	 * what's really meant is look at the host_pair for
	 * each sra, something that matches the current
	 * nested loop structure but not what it actually does.
	 */

	struct connection *best = c;	/* best connection so far */
	const struct host_pair *hp = NULL;

	for (sra = &c->spd; hp == NULL && sra != NULL;
	     sra = sra->spd_next)
	{
		hp = find_host_pair(&sra->this.host_addr,
				    sra->this.host_port,
				    &sra->that.host_addr,
				    sra->that.host_port);

		DBG(DBG_CONTROLMORE, {
			char s2[SUBNETTOT_BUF];
			char d2[SUBNETTOT_BUF];

			subnettot(&sra->this.client, 0, s2,
				  sizeof(s2));
			subnettot(&sra->that.client, 0, d2,
				  sizeof(d2));

			DBG_log("  checking hostpair %s -> %s is %s",
				s2, d2,
				hp == NULL ? "not found" : "found");
		});

		if (hp == NULL)
			continue;

		struct connection *d;

		for (d = hp->connections; d != NULL; d = d->hp_next) {
			/* groups are templates instantiated as GROUPINSTANCE */
			if (d->policy & POLICY_GROUP)
				continue;

			/*
			 * ??? same_id && match_id seems redundant.
			 * if d->spd.this.id.kind == ID_NONE, both TRUE
			 * else if c->spd.this.id.kind == ID_NONE,
			 *     same_id treats it as a wildcard and match_id
			 *     does not.  Odd.
			 * else if kinds differ, match_id FALSE
			 * else if kind ID_DER_ASN1_DN, wildcards are forbidden by same_id
			 * else match_id just calls same_id.
			 * So: if wildcards are desired, just use match_id.
			 * If they are not, just use same_id
			 */
			int wildcards;	/* value ignored */
			int pathlen;	/* value ignored */
			if (!(same_id(&c->spd.this.id,
				      &d->spd.this.id) &&
			      match_id(&c->spd.that.id,
				       &d->spd.that.id, &wildcards) &&
			      trusted_ca_nss(c->spd.that.ca,
					 d->spd.that.ca, &pathlen)))
			{
				DBG(DBG_CONTROLMORE, DBG_log("connection \"%s\" does not match IDs or CA of current connection \"%s\"",
					d->name, c->name));
				continue;
			}
			DBG(DBG_CONTROLMORE, DBG_log("investigating connection \"%s\" as a better match", d->name));

			const struct spd_route *sr;

			for (sr = &d->spd; sr != NULL; sr = sr->spd_next) {
				int newfit = ikev2_evaluate_connection_fit(
					d, sr, role, tsi, tsr, tsi_n, tsr_n);

				if (newfit > bestfit_n) {
					/* ??? what does this comment mean? */
					/* will complicated this with narrowing */
					DBG(DBG_CONTROLMORE,
					    DBG_log("prefix fitness found a better match d %s",
						    d->name));
					int bfit_p =
						ikev2_evaluate_connection_port_fit(
							d, sr, role,
							tsi, tsr,
							tsi_n, tsr_n,
							&best_tsi_i,
							&best_tsr_i);

					if (bfit_p > bestfit_p) {
						DBG(DBG_CONTROLMORE, DBG_log(
							    "port fitness found better match d %s, tsi[%d],tsr[%d]",
							    d->name,
							    best_tsi_i,
							    best_tsr_i));
						int bfit_pr =
							ikev2_evaluate_connection_protocol_fit(
								d, sr, role,
								tsi, tsr,
								tsi_n, tsr_n,
								&best_tsi_i,
								&best_tsr_i);

						if (bfit_pr > bestfit_pr) {
							DBG(DBG_CONTROLMORE,
							    DBG_log("protocol fitness found better match d %s, tsi[%d],tsr[%d]",
								    d->name,
								    best_tsi_i,
								    best_tsr_i));

							bestfit_p = bfit_p;
							bestfit_n = newfit;
							best = d;
							bsr = sr;
						} else {
							DBG(DBG_CONTROLMORE,
							    DBG_log("protocol fitness rejected d %s",
								    d->name));
						}
					} else {
						DBG(DBG_CONTROLMORE,
							DBG_log("port fitness rejected d %s",
								d->name));
					}

				} else {
					DBG(DBG_CONTROLMORE,
					    DBG_log("prefix fitness rejected d %s",
						    d->name));
				}
			}
		}
	}

	if (best == c) {
		DBG(DBG_CONTROLMORE, DBG_log("we did not switch connection"));
	}

	if (bsr == NULL) {
		DBG(DBG_CONTROLMORE, DBG_log("failed to find anything; can we instantiate another template?"));

		for (struct connection *t = connections; t != NULL; t = t->ac_next) {
			if (LIN(POLICY_GROUPINSTANCE, t->policy) && (t->kind == CK_TEMPLATE)) {
				/* ??? clang 6.0.0 thinks best might be NULL but I don't see how */
				if (!streq(t->foodgroup, best->foodgroup) ||
				    streq(best->name, t->name) ||
				    !subnetinsubnet(&best->spd.that.client, &t->spd.that.client) ||
				    !sameaddr(&best->spd.this.client.addr, &t->spd.this.client.addr))
					continue;

				/* ??? why require best->name and t->name to be different */

				DBG(DBG_CONTROLMORE,
					DBG_log("investigate %s which is another group instance of %s with different protoports",
						t->name, t->foodgroup));
				/*
				 * ??? this code seems to assume that tsi and tsr contain exactly one element.
				 * Any fewer and the code references an uninitialized value.
				 * Any more would be ignored, and that's surely wrong.
				 * It would be nice if the purpose of this block of code were documented.
				 */
				pexpect(tsi_n == 1);
				int t_sport = tsi[0].startport == tsi[0].endport ? tsi[0].startport :
						tsi[0].startport == 0 && tsi[0].endport == 65535 ? 0 : -1;
				pexpect(tsr_n == 1);
				int t_dport = tsr[0].startport == tsr[0].endport ? tsr[0].startport :
						tsr[0].startport == 0 && tsr[0].endport == 65535 ? 0 : -1;

				if (t_sport == -1 || t_dport == -1)
					continue;

				if ((t->spd.that.protocol != tsi[0].ipprotoid) ||
					(best->spd.this.port != t_sport) ||
					(best->spd.that.port != t_dport))
						continue;

				DBG(DBG_CONTROLMORE, DBG_log("updating connection of group instance for protoports"));
				best->spd.that.protocol = t->spd.that.protocol;
				best->spd.this.port = t->spd.this.port;
				best->spd.that.port = t->spd.that.port;
				pfreeany(best->name);
				best->name = clone_str(t->name, "hidden switch template name update");
				bsr = &best->spd;
				break;
			}
		}

		if (bsr == NULL) {
			/* nothing to instantiate from other group templates either */
				return STF_FAIL + v2N_TS_UNACCEPTABLE;
		}
	}

	struct state *cst = md->st;	/* child state */

	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA) {
		update_state_connection(cst, best);
	} else {
		/*
		 * ??? is this only for AUTH exchange?
		 *
		 * XXX: comments above clearly suggest CST is the
		 * child, yet this code only works if CST is actually
		 * a parent!!!
		 */
		cst = ikev2_duplicate_state(pexpect_ike_sa(cst), IPSEC_SA,
					    md->message_role == MESSAGE_REQUEST ? SA_RESPONDER :
					    md->message_role == MESSAGE_RESPONSE ? SA_INITIATOR :
					    0);
		cst->st_connection = best;	/* safe: from duplicate_state */
		insert_state(cst); /* needed for delete - we should never have duplicated before we were sure */
	}

	if (role == ORIGINAL_INITIATOR) {
		pexpect(best_tsi_i >= 0);
		pexpect(best_tsr_i >= 0);	/* ??? Coverity thinks that this might fail */
		cst->st_ts_this = tsi[best_tsi_i];
		cst->st_ts_that = tsr[best_tsr_i];
	} else {
		cst->st_ts_this = ikev2_end_to_ts(&bsr->this);
		cst->st_ts_that = ikev2_end_to_ts(&bsr->that);
	}
	ikev2_print_ts(&cst->st_ts_this);
	ikev2_print_ts(&cst->st_ts_that);

	*ret_cst = cst;	/* success! */
	return STF_OK;	/* ignored because *ret_cst is not NULL */
}

static stf_status ikev2_cp_reply_state(const struct msg_digest *md,
	struct state **ret_cst,
	enum isakmp_xchg_types isa_xchg)
{
	ip_address ipv4;
	struct connection *c = md->st->st_connection;

	err_t e = lease_an_address(c, md->st, &ipv4);
	if (e != NULL) {
		libreswan_log("ikev2 lease_an_address failure %s", e);
		return STF_INTERNAL_ERROR;
	}

	struct state *cst;

	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA) {
		cst = md->st;
		update_state_connection(cst, c);
	} else {
		cst = ikev2_duplicate_state(pexpect_ike_sa(md->st), IPSEC_SA,
					    md->message_role == MESSAGE_REQUEST ? SA_RESPONDER :
					    md->message_role == MESSAGE_RESPONSE ? SA_INITIATOR :
					    0);
		cst->st_connection = c;	/* safe: from duplicate_state */
		insert_state(cst); /* needed for delete - we should never have duplicated before we were sure */
	}

	struct spd_route *spd = &md->st->st_connection->spd;
	spd->that.has_lease = TRUE;
	spd->that.client.addr = ipv4;
	spd->that.client.maskbits = 32; /* export it as value */
	spd->that.has_client = TRUE;

	cst->st_ts_this = ikev2_end_to_ts(&spd->this);
	cst->st_ts_that = ikev2_end_to_ts(&spd->that);

	*ret_cst = cst;	/* success! */
	return STF_OK;
}

stf_status ikev2_child_sa_respond(struct msg_digest *md,
				  pb_stream *outpbs,
				  enum isakmp_xchg_types isa_xchg)
{
	/*
	 * XXX: This function was only called with ORIGINAL_ROLE set
	 * to ORIGINAL_RESPONDER so it was hardwired.  Looking at the
	 * calls:
	 *
	 * - in the original responder's AUTH code so
	 *   ORIGINAL_RESPONDER is correct
	 *
	 * - CHILD_SA reply code (?), since either end can send such a
	 *   request, the end's original role may not be
	 *   ORIGINAL_RESPONDER.
	 *
	 * Looking at the code:
	 *
	 * - it isn't clear if the notification parsing checks need to
	 *   be conditional on ORIGINAL_ROLE or message responder?
	 *
	 *   Does it need the IKE SA ROLE, or the CHILD SA ROLE?
	 *
	 * - The function ikev2_derive_child_keys() needs to know the
	 *   initiator and responder when assigning keying material.
	 *
	 *   But who is the initiator and who is the responder?
	 *
	 *   Section 1.3.1 (Creating new Child SAs...) refers to the
	 *   end sending the CHILD_SA request as the initiator (i.e.,
	 *   as determined by the message_role), but Section 2.17
	 *   (Generating Keying Material for Child SAs) could be read
	 *   as refering to the original roles (I suspect it isn't).
	 *
	 *   So either ike_sa(cst) .sa .st_original_role or md
	 *   .message_role should be used here?
	 *
	 *   Either way, something is wrong as this call hard-wires
	 *   the responder but the second call is using ORIGINAL_ROLE!
	 *
	 * Consequently 'role' should be deleted and code should
	 * instead be passed SA_RESPONDER.
	 */
	const enum original_role role = ORIGINAL_RESPONDER;

	struct state *cst;	/* child state */
	struct state *pst;
	struct connection *c = md->st->st_connection;
	bool send_use_transport;
	stf_status ret = STF_FAIL;

	pst = IS_CHILD_SA(md->st) ?
		state_with_serialno(md->st->st_clonedfrom) : md->st;

	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA &&
			md->st->st_ipsec_pred != SOS_NOBODY) {
		/* this is Child SA rekey we already have child state object */
		cst = md->st;
	} else if (c->pool != NULL && md->chain[ISAKMP_NEXT_v2CP] != NULL) {
		RETURN_STF_FAILURE_STATUS(ikev2_cp_reply_state(md, &cst,
					isa_xchg));
	} else if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA) {
		cst = md->st;
	} else {
		ret = ikev2_resp_accept_child_ts(md, &cst, role,
				isa_xchg);
	}

	if (cst == NULL)
		return ret;	/* things went badly */

	md->st = cst;
	c = cst->st_connection;

	/*
	 * The notifies have not yet been processed here, so we cannot
	 * look at st_seen_use_transport in either st or pst.
	 * If we change to comply to RFC style transport mode
	 * negotiation, reading ntfy's will have to be done here.
	 */
	send_use_transport = ((c->policy & POLICY_TUNNEL) == LEMPTY);

	if (c->spd.that.has_lease &&
			md->chain[ISAKMP_NEXT_v2CP] != NULL &&
			cst->st_state != STATE_V2_REKEY_IKE_R) {
		ikev2_send_cp(pst, ISAKMP_NEXT_v2SA, outpbs);
	} else if (md->chain[ISAKMP_NEXT_v2CP] != NULL) {
		DBG(DBG_CONTROL, DBG_log("#%lu %s ignoring unexpected v2CP payload",
					cst->st_serialno,
					enum_name(&state_names, cst->st_state)));
	}

	/* start of SA out */
	{
		/* ??? this code won't support AH + ESP */
		struct ipsec_proto_info *proto_info
			= ikev2_child_sa_proto_info(cst, c->policy);

		if (isa_xchg != ISAKMP_v2_CREATE_CHILD_SA)  {
			RETURN_STF_FAILURE_STATUS(ikev2_process_child_sa_pl(md, FALSE));
		}
		proto_info->our_spi = ikev2_child_sa_spi(&c->spd, c->policy);
		chunk_t local_spi;
		setchunk(local_spi, (uint8_t*)&proto_info->our_spi,
				sizeof(proto_info->our_spi));
		if (!ikev2_emit_sa_proposal(outpbs,
					cst->st_accepted_esp_or_ah_proposal,
					&local_spi)) {
			DBG(DBG_CONTROL, DBG_log("problem emitting accepted proposal (%d)", ret));
			return STF_INTERNAL_ERROR;
		}
	}

	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA) {
		/* send NONCE */
		struct ikev2_generic in = {
			.isag_critical = build_ikev2_critical(false),
		};
		pb_stream pb_nr;
		if (!out_struct(&in, &ikev2_nonce_desc, outpbs, &pb_nr) ||
		    !out_chunk(cst->st_nr, &pb_nr, "IKEv2 nonce"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&pb_nr);

		/*
		 * XXX: shoudn't this be conditional on the local end
		 * having computed KE and not what the remote sent?
		 */
		if (md->chain[ISAKMP_NEXT_v2KE] != NULL)  {
			if (!emit_v2KE(&cst->st_gr, cst->st_oakley.ta_dh, outpbs))
				return STF_INTERNAL_ERROR;
		}
	}

	if (role == ORIGINAL_RESPONDER) {
		struct payload_digest *ntfy;

		/*
		 * Paul: This is the second time we are processing NOTIFY's
		 * I suspect we are only interested in those related to
		 * the Child SA and mark those on the child state. But this
		 * code is used in IKE_AUTH as well as CREATE_CHILD_SA, so
		 * we end up double logging bad payloads on the responder.
		 */
		/* Process all NOTIFY payloads */
		for (ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
			switch (ntfy->payload.v2n.isan_type) {
			case v2N_NAT_DETECTION_SOURCE_IP:
			case v2N_NAT_DETECTION_DESTINATION_IP:
			case v2N_IKEV2_FRAGMENTATION_SUPPORTED:
			case v2N_COOKIE:
			case v2N_USE_PPK:
				DBG(DBG_CONTROL, DBG_log("received %s which is not valid for current exchange",
					enum_name(&ikev2_notify_names,
						ntfy->payload.v2n.isan_type)));
				break;

			case v2N_USE_TRANSPORT_MODE:
				DBG(DBG_CONTROL, DBG_log("received USE_TRANSPORT_MODE"));
				cst->st_seen_use_transport = TRUE;
				break;
			case v2N_ESP_TFC_PADDING_NOT_SUPPORTED:
				DBG(DBG_CONTROL, DBG_log("received ESP_TFC_PADDING_NOT_SUPPORTED"));
				cst->st_seen_no_tfc = TRUE;
				break;
			case v2N_MOBIKE_SUPPORTED:
				DBG(DBG_CONTROL, DBG_log("received v2N_MOBIKE_SUPPORTED"));
				cst->st_seen_mobike = pst->st_seen_mobike = TRUE;
				break;
			case v2N_INITIAL_CONTACT:
				DBG(DBG_CONTROL, DBG_log("received v2N_INITIAL_CONTACT"));
				cst->st_seen_initialc = pst->st_seen_initialc = TRUE;
				break;
			case v2N_REKEY_SA:
				DBG(DBG_CONTROL, DBG_log("received REKEY_SA already proceesd"));
				break;
			case v2N_PPK_IDENTITY:
				DBG(DBG_CONTROL, DBG_log("received PPK_IDENTITY already processed"));
				break;
			case v2N_NO_PPK_AUTH:
				DBG(DBG_CONTROL, DBG_log("received NO_PPK_AUTH already processed"));
				break;
			default:
				libreswan_log("received unsupported NOTIFY %s ",
					enum_name(&ikev2_notify_names,
						ntfy->payload.v2n.isan_type));
			}
		}
	}

	{
		bool send_ntfy = send_use_transport || c->send_no_esp_tfc;

		/* verify if transport / tunnel mode is matches */
		if ((c->policy & POLICY_TUNNEL) == LEMPTY) {
			/* we should have received transport mode request - and send one */
			if (!cst->st_seen_use_transport) {
				libreswan_log("policy dictates Transport Mode, but peer requested Tunnel Mode");
				return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
			}
		} else {
			if (cst->st_seen_use_transport) {
				/* RFC allows us to ignore their (wrong) request for transport mode */
				libreswan_log("policy dictates Tunnel Mode, ignoring peer's request for Transport Mode");
			}
		}

		/*
		 * XXX: see above notes on 'role' - this must be the
		 * SA_RESPONDER.
		 */
		stf_status ret = ikev2_emit_ts_payloads(pexpect_child_sa(cst), outpbs,
							SA_RESPONDER, c,
							(send_ntfy ? ISAKMP_NEXT_v2N
							 : ISAKMP_NEXT_v2NONE));

		if (ret != STF_OK)
			return ret;	/* should we delete_state cst? */
	}

	if (role == ORIGINAL_RESPONDER) {
		if (cst->st_seen_use_transport) {
			if (c->policy & POLICY_TUNNEL) {
				libreswan_log("Local policy is tunnel mode - ignoring request for transport mode");
			} else {
				DBG(DBG_CONTROL, DBG_log("Local policy is transport mode and received USE_TRANSPORT_MODE"));
				if (cst->st_esp.present) {
					cst->st_esp.attrs.encapsulation =
						ENCAPSULATION_MODE_TRANSPORT;
				}
				if (cst->st_ah.present) {
					cst->st_ah.attrs.encapsulation =
						ENCAPSULATION_MODE_TRANSPORT;
				}
				/* In v2, for parent, protoid must be 0 and SPI must be empty */
				if (!ship_v2Ns(c->send_no_esp_tfc ? ISAKMP_NEXT_v2N : ISAKMP_NEXT_v2NONE,
				      v2N_USE_TRANSPORT_MODE, outpbs))
					return STF_INTERNAL_ERROR;
			}
		} else {
			/* the peer wants tunnel mode */
			if ((c->policy & POLICY_TUNNEL) == LEMPTY) {
				libreswan_log("Local policy is transport mode, but peer did not request that");
				return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
			}
		}

		if (c->send_no_esp_tfc) {
			DBG(DBG_CONTROL, DBG_log("Sending ESP_TFC_PADDING_NOT_SUPPORTED"));
			if (!ship_v2Ns(ISAKMP_NEXT_v2NONE,
			      v2N_ESP_TFC_PADDING_NOT_SUPPORTED, outpbs))
				return STF_INTERNAL_ERROR;
		}
	}

	ikev2_derive_child_keys(pexpect_child_sa(cst));

	/*
	 * Check to see if we need to release an old instance
	 * Note that this will call delete on the old connection
	 * we should do this after installing ipsec_sa, but that will
	 * give us a "eroute in use" error.
	 */
	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA) {
		/* skip check for rekey */
		pst->st_connection->newest_isakmp_sa = pst->st_serialno;
	} else {
		ISAKMP_SA_established(pst);
	}

	/* install inbound and outbound SPI info */
	if (!install_ipsec_sa(cst, TRUE))
		return STF_FATAL;

	/* mark the connection as now having an IPsec SA associated with it. */
	set_newest_ipsec_sa(enum_name(&ikev2_exchange_names, isa_xchg), cst);

	return STF_OK;
}

static void ikev2_set_domain(pb_stream *cp_a_pbs, struct state *st)
{
	bool responder = (st->st_state != STATE_PARENT_I2);

	if (!responder) {
		char *safestr = cisco_stringify(cp_a_pbs, "INTERNAL_DNS_DOMAIN");
		append_st_cfg_domain(st, safestr);
	} else {
		libreswan_log("initiator INTERNAL_DNS_DOMAIN CP ignored");
	}
}

static bool ikev2_set_dns(pb_stream *cp_a_pbs, struct state *st, int af)
{
	ip_address ip;
	char ip_str[ADDRTOT_BUF];
	struct connection *c = st->st_connection;
	err_t ugh = initaddr(cp_a_pbs->cur, pbs_left(cp_a_pbs), af, &ip);
	bool responder = (st->st_state != STATE_PARENT_I2);

	if (c->policy & POLICY_OPPORTUNISTIC) {
		libreswan_log("ignored INTERNAL_IP%s_DNS CP payload for Opportunistic IPsec",
			af == AF_INET ? "4" : "6");
		return TRUE;
	}

	addrtot(&ip, 0, ip_str, sizeof(ip_str));

	if ((ugh != NULL && st->st_state == STATE_PARENT_I2)) {
		libreswan_log("ERROR INTERNAL_IP%s_DNS malformed: %s",
			af == AF_INET ? "4" : "6", ugh);
		return FALSE;
	}

	if (isanyaddr(&ip)) {
		libreswan_log("ERROR INTERNAL_IP%s_DNS %s is invalid",
			af == AF_INET ? "4" : "6",
			ugh == NULL ? ip_str : ugh);
		return FALSE;
	}

	if (!responder) {
		libreswan_log("received INTERNAL_IP%s_DNS %s",
			af == AF_INET ? "4" : "6", ip_str);
		append_st_cfg_dns(st, ip_str);
	} else {
		libreswan_log("initiator INTERNAL_IP%s_DNS CP ignored",
			af == AF_INET ? "4" : "6");
	}

	return TRUE;
}

static bool ikev2_set_ia(pb_stream *cp_a_pbs, struct state *st, int af)
{
	ip_address ip;
	ipstr_buf ip_str;
	struct connection *c = st->st_connection;
	err_t ugh = initaddr(cp_a_pbs->cur, pbs_left(cp_a_pbs), af, &ip);
	bool responder = st->st_state != STATE_PARENT_I2;

	if ((ugh != NULL && st->st_state == STATE_PARENT_I2) || isanyaddr(&ip)) {
		libreswan_log("ERROR INTERNAL_IP%s_ADDRESS malformed: %s",
			af == AF_INET ? "4" : "6", ugh);
		return FALSE;
	}

	if (isanyaddr(&ip)) {
		libreswan_log("ERROR INTERNAL_IP%s_ADDRESS %s is invalid",
			af == AF_INET ? "4" : "6",
			ipstr(&ip, &ip_str));
		return FALSE;
	}

	libreswan_log("received INTERNAL_IP%s_ADDRESS %s",
		af == AF_INET ? "4" : "6",
		ipstr(&ip, &ip_str));

	if (responder) {
		libreswan_log("bogus responder CP ignored");
		return TRUE;
	}

	c->spd.this.has_client = TRUE;
	c->spd.this.has_internal_address = TRUE;

	if (c->spd.this.cat) {
		DBG(DBG_CONTROL, DBG_log("CAT is set, not setting host source IP address to %s",
			ipstr(&ip, &ip_str)));
		if (sameaddr(&c->spd.this.client.addr, &ip)) {
			/* The address we received is same as this side
			 * should we also check the host_srcip */
			DBG(DBG_CONTROL, DBG_log("#%lu %s[%lu] received INTERNAL_IP%s_ADDRESS that is same as this.client.addr %s. Will not add CAT iptable rules",
				st->st_serialno, c->name, c->instance_serial,
				af == AF_INET ? "4" : "6",
				ipstr(&ip, &ip_str)));
		} else {
			c->spd.this.client.addr = ip;
			if (af == AF_INET)
				c->spd.this.client.maskbits = 32;
			else
				c->spd.this.client.maskbits = 128;
			st->st_ts_this = ikev2_end_to_ts(&c->spd.this);
			c->spd.this.has_cat = TRUE; /* create iptable entry */
		}
	} else {
		addrtosubnet(&ip, &c->spd.this.client);
		setportof(0, &c->spd.this.client.addr); /* ??? redundant? */
		/* only set sourceip= value if unset in configuration */
		if (addrlenof(&c->spd.this.host_srcip) == 0 ||
			isanyaddr(&c->spd.this.host_srcip)) {
				DBG(DBG_CONTROL, DBG_log("setting host source IP address to %s",
					ipstr(&ip, &ip_str)));
				c->spd.this.host_srcip = ip;
		}
	}

	return TRUE;
}

bool ikev2_parse_cp_r_body(struct payload_digest *cp_pd, struct state *st)
{
	struct ikev2_cp *cp =  &cp_pd->payload.v2cp;
	struct connection *c = st->st_connection;
	pb_stream *attrs = &cp_pd->pbs;

	DBG(DBG_CONTROLMORE, DBG_log("#%lu %s[%lu] parsing ISAKMP_NEXT_v2CP payload",
				st->st_serialno, c->name, c->instance_serial));

	if (st->st_state == STATE_PARENT_I2 && cp->isacp_type !=  IKEv2_CP_CFG_REPLY) {
		loglog(RC_LOG_SERIOUS, "ERROR expected IKEv2_CP_CFG_REPLY got a %s",
			enum_name(&ikev2_cp_type_names, cp->isacp_type));
		return FALSE;
	}

	if (st->st_state == STATE_PARENT_R1 && cp->isacp_type !=  IKEv2_CP_CFG_REQUEST) {
		loglog(RC_LOG_SERIOUS, "ERROR expected IKEv2_CP_CFG_REQUEST got a %s",
			enum_name(&ikev2_cp_type_names, cp->isacp_type));
		return FALSE;
	}

	while (pbs_left(attrs) > 0) {
		struct ikev2_cp_attribute cp_a;
		pb_stream cp_a_pbs;

		if (!in_struct(&cp_a, &ikev2_cp_attribute_desc,
					attrs, &cp_a_pbs)) {
			loglog(RC_LOG_SERIOUS, "ERROR malformed CP attribute");
			return FALSE;
		}

		switch (cp_a.type) {
		case IKEv2_INTERNAL_IP4_ADDRESS | ISAKMP_ATTR_AF_TLV:
			if (!ikev2_set_ia(&cp_a_pbs, st, AF_INET)) {
				loglog(RC_LOG_SERIOUS, "ERROR malformed INTERNAL_IP4_ADDRESS attribute");
				return FALSE;
			}
			break;

		case IKEv2_INTERNAL_IP4_DNS | ISAKMP_ATTR_AF_TLV:
			if (!ikev2_set_dns(&cp_a_pbs, st, AF_INET)) {
				loglog(RC_LOG_SERIOUS, "ERROR malformed INTERNAL_IP4_DNS attribute");
				return FALSE;
			}
			break;

		case IKEv2_INTERNAL_IP6_ADDRESS | ISAKMP_ATTR_AF_TLV:
			if (!ikev2_set_ia(&cp_a_pbs, st, AF_INET6)) {
				loglog(RC_LOG_SERIOUS, "ERROR malformed INTERNAL_IP6_ADDRESS attribute");
				return FALSE;
			}
			break;

		case IKEv2_INTERNAL_IP6_DNS | ISAKMP_ATTR_AF_TLV:
			if (!ikev2_set_dns(&cp_a_pbs, st, AF_INET6)) {
				loglog(RC_LOG_SERIOUS, "ERROR malformed INTERNAL_IP6_DNS attribute");
				return FALSE;
			}
			break;

		case IKEv2_INTERNAL_DNS_DOMAIN | ISAKMP_ATTR_AF_TLV:
			ikev2_set_domain(&cp_a_pbs, st); /* can't fail */
			break;

		default:
			libreswan_log("unknown attribute %s length %u",
				enum_name(&ikev2_cp_attribute_type_names,
					cp_a.type),
				cp_a.len);
			break;
		}
	}
	return TRUE;
}
