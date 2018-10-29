/* IKEv2 Traffic Selectors, for libreswan
 *
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

#include "lswlog.h"

#include "defs.h"
#include "ikev2_ts.h"
#include "connections.h"	/* for struct end */
#include "demux.h"
#include "virtual.h"
#include "hostpair.h"
#include "ikev2.h"		/* for v2_msg_role() */

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
static int ikev2_parse_ts(struct payload_digest *const ts_pd,
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
static int ikev2_evaluate_connection_protocol_fit(const struct connection *d,
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
static int ikev2_evaluate_connection_port_fit(const struct connection *d,
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
static int ikev2_evaluate_connection_fit(const struct connection *d,
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
					    v2_msg_role(md) == MESSAGE_REQUEST ? SA_RESPONDER :
					    v2_msg_role(md) == MESSAGE_RESPONSE ? SA_INITIATOR :
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

/* check TS payloads, response */
stf_status ikev2_process_ts_respnse(struct msg_digest *md)
{
	struct state *st = md->st;
	struct connection *c = st->st_connection;

	/* check TS payloads */
	{
		int bestfit_n, bestfit_p, bestfit_pr;
		int best_tsi_i, best_tsr_i;
		bestfit_n = -1;
		bestfit_p = -1;
		bestfit_pr = -1;

		/* Check TSi/TSr https://tools.ietf.org/html/rfc5996#section-2.9 */
		DBG(DBG_CONTROLMORE,
		    DBG_log("TS: check narrowing - we are responding to I2"));


		DBG(DBG_CONTROLMORE,
		    DBG_log("TS: parse initiator traffic selectors"));
		struct payload_digest *const tsi_pd = md->chain[ISAKMP_NEXT_v2TSi];
		/* ??? is 16 an undocumented limit - IKEv2 has no limit */
		struct traffic_selector tsi[16];
		const int tsi_n = ikev2_parse_ts(tsi_pd, tsi, elemsof(tsi));

		DBG(DBG_CONTROLMORE,
		    DBG_log("TS: parse responder traffic selectors"));
		struct payload_digest *const tsr_pd = md->chain[ISAKMP_NEXT_v2TSr];
		/* ??? is 16 an undocumented limit - IKEv2 has no limit */
		struct traffic_selector tsr[16];
		const int tsr_n = ikev2_parse_ts(tsr_pd, tsr, elemsof(tsr));

		if (tsi_n < 0 || tsr_n < 0)
			return STF_FAIL + v2N_TS_UNACCEPTABLE;

		DBG(DBG_CONTROLMORE, DBG_log("Checking TSi(%d)/TSr(%d) selectors, looking for exact match",
			tsi_n, tsr_n));

		{
			const struct spd_route *sra = &c->spd;
			int bfit_n = ikev2_evaluate_connection_fit(
				c, sra, ORIGINAL_INITIATOR,
				tsi, tsr,
				tsi_n, tsr_n);

			if (bfit_n > bestfit_n) {
				DBG(DBG_CONTROLMORE,
				    DBG_log("prefix fitness found a better match c %s",
					    c->name));

				int bfit_p = ikev2_evaluate_connection_port_fit(
					c, sra, ORIGINAL_INITIATOR,
					tsi, tsr,
					tsi_n, tsr_n,
					&best_tsi_i, &best_tsr_i);

				if (bfit_p > bestfit_p) {
					DBG(DBG_CONTROLMORE,
					    DBG_log("port fitness found better match c %s, tsi[%d],tsr[%d]",
						    c->name, best_tsi_i, best_tsr_i));

					int bfit_pr = ikev2_evaluate_connection_protocol_fit(
						c, sra, ORIGINAL_INITIATOR,
						tsi, tsr,
						tsi_n, tsr_n,
						&best_tsi_i, &best_tsr_i);

					if (bfit_pr > bestfit_pr) {
						DBG(DBG_CONTROLMORE,
						    DBG_log("protocol fitness found better match c %s, tsi[%d], tsr[%d]",
							    c->name, best_tsi_i,
							    best_tsr_i));
						bestfit_p = bfit_p;
						bestfit_n = bfit_n;
					} else {
						DBG(DBG_CONTROLMORE,
						    DBG_log("protocol fitness rejected c %s",
							    c->name));
					}
				} else {
					DBG(DBG_CONTROLMORE,
							DBG_log("port fitness rejected c %s",
								c->name));
				}
			} else {
				DBG(DBG_CONTROLMORE,
				    DBG_log("prefix fitness rejected c %s",
					    c->name));
			}
		}

		if (bestfit_n > 0 && bestfit_p > 0) {
			DBG(DBG_CONTROLMORE,
			    DBG_log("found an acceptable TSi/TSr Traffic Selector"));
			memcpy(&st->st_ts_this, &tsi[best_tsi_i],
			       sizeof(struct traffic_selector));
			memcpy(&st->st_ts_that, &tsr[best_tsr_i],
			       sizeof(struct traffic_selector));
			ikev2_print_ts(&st->st_ts_this);
			ikev2_print_ts(&st->st_ts_that);

			ip_subnet tmp_subnet_i;
			ip_subnet tmp_subnet_r;
			rangetosubnet(&st->st_ts_this.net.start,
				      &st->st_ts_this.net.end, &tmp_subnet_i);
			rangetosubnet(&st->st_ts_that.net.start,
				      &st->st_ts_that.net.end, &tmp_subnet_r);

			c->spd.this.client = tmp_subnet_i;
			c->spd.this.port = st->st_ts_this.startport;
			c->spd.this.protocol = st->st_ts_this.ipprotoid;
			setportof(htons(c->spd.this.port),
				  &c->spd.this.host_addr);
			setportof(htons(c->spd.this.port),
				  &c->spd.this.client.addr);

			c->spd.this.has_client =
				!(subnetishost(&c->spd.this.client) &&
				addrinsubnet(&c->spd.this.host_addr,
					  &c->spd.this.client));

			c->spd.that.client = tmp_subnet_r;
			c->spd.that.port = st->st_ts_that.startport;
			c->spd.that.protocol = st->st_ts_that.ipprotoid;
			setportof(htons(c->spd.that.port),
				  &c->spd.that.host_addr);
			setportof(htons(c->spd.that.port),
				  &c->spd.that.client.addr);

			c->spd.that.has_client =
				!(subnetishost(&c->spd.that.client) &&
				addrinsubnet(&c->spd.that.host_addr,
					  &c->spd.that.client));
		} else {
			DBG(DBG_CONTROLMORE,
			    DBG_log("reject responder TSi/TSr Traffic Selector"));
			/* prevents parent from going to I3 */
			return STF_FAIL + v2N_TS_UNACCEPTABLE;
		}
	} /* end of TS check block */

	return STF_OK;
}
