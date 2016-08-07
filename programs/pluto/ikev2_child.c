/* IKEv2 - CHILD SA - calculations
 *
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2011-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012,2016 Antony Antony <appu@phenome.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2014-2015 Andrew cagney <cagney@gnu.org>
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
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "ike_alg.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */
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

void ikev2_print_ts(struct traffic_selector *ts)
{
	ipstr_buf b;

	DBG(DBG_CONTROLMORE,
		DBG_log("printing contents struct traffic_selector");
		DBG_log("  ts_type: %s", enum_name(&ikev2_ts_type_names, ts->ts_type));
		DBG_log("  ipprotoid: %d", ts->ipprotoid);
		DBG_log("  startport: %d", ts->startport);
		DBG_log("  endport: %d", ts->endport);
		DBG_log("  ip low: %s", ipstr(&ts->low, &b));
		DBG_log("  ip high: %s", ipstr(&ts->high, &b));
	);
}

/* rewrite me with addrbytesptr() */
struct traffic_selector ikev2_end_to_ts(const struct end *e)
{
	struct traffic_selector ts;
	struct in6_addr v6mask;

	zero(&ts);	/* OK: no pointer fields */

	switch (e->client.addr.u.v4.sin_family) {
	case AF_INET:
		ts.ts_type = IKEv2_TS_IPV4_ADDR_RANGE;
		ts.low = e->client.addr;
		ts.low.u.v4.sin_addr.s_addr &=
			bitstomask(e->client.maskbits).s_addr;
		ts.high = e->client.addr;
		ts.high.u.v4.sin_addr.s_addr |=
			~bitstomask(e->client.maskbits).s_addr;
		break;

	case AF_INET6:
		ts.ts_type = IKEv2_TS_IPV6_ADDR_RANGE;
		v6mask = bitstomask6(e->client.maskbits);

		ts.low = e->client.addr;
		ts.low.u.v6.sin6_addr.s6_addr32[0] &= v6mask.s6_addr32[0];
		ts.low.u.v6.sin6_addr.s6_addr32[1] &= v6mask.s6_addr32[1];
		ts.low.u.v6.sin6_addr.s6_addr32[2] &= v6mask.s6_addr32[2];
		ts.low.u.v6.sin6_addr.s6_addr32[3] &= v6mask.s6_addr32[3];

		ts.high = e->client.addr;
		ts.high.u.v6.sin6_addr.s6_addr32[0] |= ~v6mask.s6_addr32[0];
		ts.high.u.v6.sin6_addr.s6_addr32[1] |= ~v6mask.s6_addr32[1];
		ts.high.u.v6.sin6_addr.s6_addr32[2] |= ~v6mask.s6_addr32[2];
		ts.high.u.v6.sin6_addr.s6_addr32[3] |= ~v6mask.s6_addr32[3];
		break;

		/* Setting ts_type IKEv2_TS_FC_ADDR_RANGE (RFC-4595) not yet supproted */
	}

	ts.ipprotoid = e->protocol;

	/*
	 * if port is %any or 0 we mean all ports (or all iccmp/icmpv6
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

static stf_status ikev2_emit_ts(struct msg_digest *md UNUSED,
			 pb_stream *outpbs,
			 unsigned int lt,
			 struct traffic_selector *ts,
			 enum original_role role UNUSED)
{
	struct ikev2_ts its;
	struct ikev2_ts1 its1;
	pb_stream ts_pbs;
	pb_stream ts_pbs2;

	its.isat_lt = lt;
	its.isat_critical = ISAKMP_PAYLOAD_NONCRITICAL;
	its.isat_num = 1;

	if (!out_struct(&its, &ikev2_ts_desc, outpbs, &ts_pbs))
		return STF_INTERNAL_ERROR;

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

	its1.isat1_ipprotoid = ts->ipprotoid;   /* protocol as per local policy*/
	its1.isat1_startport = ts->startport;   /* ports as per local policy*/
	its1.isat1_endport = ts->endport;
	if (!out_struct(&its1, &ikev2_ts1_desc, &ts_pbs, &ts_pbs2))
		return STF_INTERNAL_ERROR;

	/* now do IP addresses */
	switch (ts->ts_type) {
	case IKEv2_TS_IPV4_ADDR_RANGE:
		if (!out_raw(&ts->low.u.v4.sin_addr.s_addr, 4, &ts_pbs2,
			     "ipv4 low") ||
		    !out_raw(&ts->high.u.v4.sin_addr.s_addr, 4, &ts_pbs2,
			     "ipv4 high"))
			return STF_INTERNAL_ERROR;

		break;
	case IKEv2_TS_IPV6_ADDR_RANGE:
		if (!out_raw(&ts->low.u.v6.sin6_addr.s6_addr, 16, &ts_pbs2,
			     "ipv6 low") ||
		    !out_raw(&ts->high.u.v6.sin6_addr.s6_addr, 16, &ts_pbs2,
			     "ipv6 high"))
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

stf_status ikev2_calc_emit_ts(struct msg_digest *md,
			      pb_stream *outpbs,
			      const enum original_role role,
			      const struct connection *c0,
			      const enum next_payload_types_ikev2 np)
{
	struct state *st = md->st;
	struct traffic_selector *ts_i, *ts_r;

	if (role == ORIGINAL_INITIATOR) {
		ts_i = &st->st_ts_this;
		ts_r = &st->st_ts_that;
	} else {
		ts_i = &st->st_ts_that;
		ts_r = &st->st_ts_this;
	}

	const struct spd_route *sr;

	for (sr = &c0->spd; sr != NULL; sr = sr->spd_next) {
		stf_status ret = ikev2_emit_ts(md, outpbs, ISAKMP_NEXT_v2TSr,
				    ts_i, ORIGINAL_INITIATOR);

		if (ret != STF_OK)
			return ret;

		ret = ikev2_emit_ts(md, outpbs, np, ts_r, ORIGINAL_RESPONDER);

		if (ret != STF_OK)
			return ret;
	}

	return STF_OK;
}

/* return number of traffic selectors found; -1 for error */
int ikev2_parse_ts(struct payload_digest *const ts_pd,
		   struct traffic_selector *array,
		   unsigned int array_max)
{
	unsigned int i;

	for (i = 0; i < ts_pd->payload.v2ts.isat_num; i++) {
		pb_stream addr;
		struct ikev2_ts1 ts1;

		if (!in_struct(&ts1, &ikev2_ts1_desc, &ts_pd->pbs, &addr))
			return -1;

		if (i >= array_max)
			return -1;

		zero(&array[i]);	/* OK: no pointer fields */
		switch (ts1.isat1_type) {
		case IKEv2_TS_IPV4_ADDR_RANGE:
			array[i].ts_type = IKEv2_TS_IPV4_ADDR_RANGE;
			array[i].low.u.v4.sin_family = AF_INET;
#ifdef NEED_SIN_LEN
			array[i].low.u.v4.sin_len =
				sizeof(struct sockaddr_in);
#endif
			if (!in_raw(&array[i].low.u.v4.sin_addr.s_addr,
				    sizeof(array[i].low.u.v4.sin_addr.s_addr),
				    &addr, "ipv4 ts"))
				return -1;

			array[i].high.u.v4.sin_family = AF_INET;
#ifdef NEED_SIN_LEN
			array[i].high.u.v4.sin_len =
				sizeof(struct sockaddr_in);
#endif

			if (!in_raw(&array[i].high.u.v4.sin_addr.s_addr,
				    sizeof(array[i].high.u.v4.sin_addr.s_addr),
				    &addr, "ipv4 ts"))
				return -1;

			break;

		case IKEv2_TS_IPV6_ADDR_RANGE:
			array[i].ts_type = IKEv2_TS_IPV6_ADDR_RANGE;
			array[i].low.u.v6.sin6_family = AF_INET6;
#ifdef NEED_SIN_LEN
			array[i].low.u.v6.sin6_len =
				sizeof(struct sockaddr_in6);
#endif

			if (!in_raw(&array[i].low.u.v6.sin6_addr.s6_addr,
				    sizeof(array[i].low.u.v6.sin6_addr.s6_addr),
				    &addr, "ipv6 ts"))
				return -1;

			array[i].high.u.v6.sin6_family = AF_INET6;
#ifdef NEED_SIN_LEN
			array[i].high.u.v6.sin6_len =
				sizeof(struct sockaddr_in6);
#endif

			if (!in_raw(&array[i].high.u.v6.sin6_addr.s6_addr,
				    sizeof(array[i].high.u.v6.sin6_addr.s6_addr),
				    &addr, "ipv6 ts"))
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
static int ikev2_match_protocol(u_int8_t proto, u_int8_t ts_proto,
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
	int narrowing = (d->policy & POLICY_IKEV2_ALLOW_NARROWING);

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

			int matchiness;

			if (fitrange_r == 0)
				continue;	/* save effort! */

			matchiness = fitrange_i + fitrange_r;	/* ??? arbitrary objective function */

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
static int ikev2_match_port_range(u_int16_t port, struct traffic_selector ts,
	bool superset_ok, bool subset_ok, const char *which, int index)
{
	u_int16_t low = port;
	u_int16_t high = port == 0 ? 65535 : port;
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
	int narrowing = (d->policy & POLICY_IKEV2_ALLOW_NARROWING);

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

			int matchiness;

			if (fitrange_r == 0)
				continue;	/* no match */

			matchiness = fitrange_i + fitrange_r;	/* ??? arbitrary objective function */

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
				ipstr_buf bli;
				ipstr_buf bhi;
				ipstr_buf blr;
				ipstr_buf bhr;
				DBG_log("    tsi[%u]=%s/%s proto=%d portrange %d-%d, tsr[%u]=%s/%s proto=%d portrange %d-%d",
					tsi_ni,
					ipstr(&tsi[tsi_ni].low, &bli),
					ipstr(&tsi[tsi_ni].high, &bhi),
					tsi[tsi_ni].ipprotoid,
					tsi[tsi_ni].startport,
					tsi[tsi_ni].endport,
					tsr_ni,
					ipstr(&tsr[tsr_ni].low, &blr),
					ipstr(&tsr[tsr_ni].high, &bhr),
					tsr[tsr_ni].ipprotoid,
					tsr[tsr_ni].startport,
					tsr[tsr_ni].endport);
			});
			/* do addresses fit into the policy? */

			/*
			 * NOTE: Our parser/config only allows 1 CIDR, however IKEv2 ranges can be non-CIDR
			 *       for now we really support/limit ourselves to a single CIDR
			 */
			if (addrinsubnet(&tsi[tsi_ni].low, &ei->client) &&
			    addrinsubnet(&tsi[tsi_ni].high, &ei->client) &&
			    addrinsubnet(&tsr[tsr_ni].low,  &er->client) &&
			    addrinsubnet(&tsr[tsr_ni].high, &er->client)) {
				/*
				 * now, how good a fit is it? --- sum of bits gives
				 * how good a fit this is.
				 */
				int ts_range1 = ikev2_calc_iprangediff(
					tsi[tsi_ni].low, tsi[tsi_ni].high);
				int maskbits1 = ei->client.maskbits;
				int fitbits1 = maskbits1 + ts_range1;

				int ts_range2 = ikev2_calc_iprangediff(
					tsr[tsr_ni].low, tsr[tsr_ni].high);
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
static stf_status ikev2_create_responder_child_state(
	const struct msg_digest *md,
	struct state **ret_cst,	/* where to return child state */
	enum original_role role, enum isakmp_xchg_types isa_xchg)
{
	struct connection *c = md->st->st_connection;

	/* ??? is 16 an undocumented limit? */
	struct traffic_selector tsi[16], tsr[16];
	const int tsi_n = ikev2_parse_ts(md->chain[ISAKMP_NEXT_v2TSi],
		tsi, elemsof(tsi));
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

	struct connection *b = c;	/* best connection so far */
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
			int wildcards, pathlen; /* XXX */

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
			if (!(same_id(&c->spd.this.id,
				      &d->spd.this.id) &&
			      match_id(&c->spd.that.id,
				       &d->spd.that.id, &wildcards) &&
			      trusted_ca_nss(c->spd.that.ca,
					 d->spd.that.ca, &pathlen)))
				continue;

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
							d, sra, role,
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
								d, sra, role,
								tsi, tsr, tsi_n,
								tsr_n,
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
							b = d;
							bsr = sr;
						} else {
							DBG(DBG_CONTROLMORE,
							    DBG_log("protocol fitness rejected d %s c->name",
								    d->name));
						}
					} else {
						DBG(DBG_CONTROLMORE,
								DBG_log("port fitness rejected d %s c->name",
									c->name));
					}

				} else {
					DBG(DBG_CONTROLMORE,
					    DBG_log("prefix fitness rejected d %s",
						    d->name));
				}
			}
		}
	}

	/* b is now the best connection (if there is one!) */

	if (bsr == NULL) {
		/* ??? why do we act differently based on role?
		 * Paul: that's wrong. prob the idea was to not
		 * send a notify if we are message initiator
		 */
		if (role == ORIGINAL_INITIATOR)
			return STF_FAIL;
		else
			return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
	}

	struct state *cst = md->st;	/* child state */

	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA) {
		update_state_connection(cst, b);
	} else {
		/* ??? is this only for AUTH exchange? */
		cst = duplicate_state(cst);
		cst->st_connection = b;	/* safe: from duplicate_state */
		insert_state(cst); /* needed for delete - we should never have duplicated before we were sure */
	}

	if (role == ORIGINAL_INITIATOR) {
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

	err_t e = lease_an_address(c, &ipv4);
	if (e != NULL) {
		libreswan_log("ikev2 lease_an_address failure %s", e);
		return STF_INTERNAL_ERROR;
	}

	struct state *cst;

	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA) {
		cst = md->st;
		update_state_connection(cst, c);
	} else {
		cst = duplicate_state(md->st);
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
				  enum original_role role,
				  pb_stream *outpbs,
				  enum isakmp_xchg_types isa_xchg)
{
	struct state *cst;	/* child state */
	struct state *pst = md->st;	/* parent state */
	struct connection *c = md->st->st_connection;
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
	bool send_use_transport;
	stf_status ret;

	if (c->pool != NULL && md->chain[ISAKMP_NEXT_v2CP] != NULL) {
		ret = ikev2_cp_reply_state(md, &cst, isa_xchg);
		if (ret != STF_OK)
			return ret;
	} else {
		ret = ikev2_create_responder_child_state(md, &cst, role,
				isa_xchg);
	}
	if (cst == NULL)
		return ret;	/* things went badly */

	md->st = cst;
	c = cst->st_connection;

	/*
	 * The notifies are read into the parent state even though it is
	 * child state related
	 */
	send_use_transport = ( pst->st_seen_use_transport &&
		 (c->policy & POLICY_TUNNEL) == LEMPTY);

	if (c->spd.that.has_lease && md->chain[ISAKMP_NEXT_v2CP] != NULL) {
		ikev2_send_cp(c, ISAKMP_NEXT_v2SA, outpbs);
	}

	/* start of SA out */
	{
		enum next_payload_types_ikev2 next_payload_type =
			(isa_xchg == ISAKMP_v2_CREATE_CHILD_SA
			 ? ISAKMP_NEXT_v2Nr
			 : ISAKMP_NEXT_v2TSi);

		/* ??? this code won't support AH + ESP */
		struct ipsec_proto_info *proto_info
			= ikev2_esp_or_ah_proto_info(cst, c->policy);

		ikev2_proposals_from_alg_info_esp(c->name, "responder",
						  c->alg_info_esp, c->policy,
						  &c->esp_or_ah_proposals);
		passert(c->esp_or_ah_proposals != NULL);

		stf_status ret = ikev2_process_sa_payload("ESP/AH responder",
							  &sa_pd->pbs,
							  /*expect_ike*/ FALSE,
							  /*expect_spi*/ TRUE,
							  /*expect_accepted*/ FALSE,
							  c->policy & POLICY_OPPORTUNISTIC,
							  &cst->st_accepted_esp_or_ah_proposal,
							  c->esp_or_ah_proposals);

		if (ret == STF_OK) {
			passert(cst->st_accepted_esp_or_ah_proposal != NULL);
			DBG(DBG_CONTROL, DBG_log_ikev2_proposal("ESP/AH", cst->st_accepted_esp_or_ah_proposal));
			if (!ikev2_proposal_to_proto_info(cst->st_accepted_esp_or_ah_proposal, proto_info)) {
				DBG(DBG_CONTROL, DBG_log("proposed/accepted a proposal we don't actually support!"));
				ret =  STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
			} else {
				proto_info->our_spi = ikev2_esp_or_ah_spi(&c->spd, c->policy);
				chunk_t local_spi;
				setchunk(local_spi, (uint8_t*)&proto_info->our_spi,
					 sizeof(proto_info->our_spi));
				if (!ikev2_emit_sa_proposal(outpbs,
							    cst->st_accepted_esp_or_ah_proposal,
							    &local_spi, next_payload_type)) {
					DBG(DBG_CONTROL, DBG_log("problem emitting accepted proposal (%d)", ret));
					ret = STF_INTERNAL_ERROR;
				}
			}
		}

		if (ret != STF_OK)
			return ret;
	}

	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA) {
		/* send NONCE */
		struct ikev2_generic in;
		pb_stream pb_nr;

		zero(&in);	/* OK: no pointer fields */
		in.isag_np = ISAKMP_NEXT_v2TSi;
		in.isag_critical = ISAKMP_PAYLOAD_NONCRITICAL;
		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
			libreswan_log(" setting bogus ISAKMP_PAYLOAD_LIBRESWAN_BOGUS flag in ISAKMP payload");
			in.isag_critical |= ISAKMP_PAYLOAD_LIBRESWAN_BOGUS;
		}
		if (!out_struct(&in, &ikev2_nonce_desc, outpbs, &pb_nr) ||
				!out_chunk(cst->st_nr, &pb_nr, "IKEv2 nonce"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&pb_nr);
	}

	if (role == ORIGINAL_RESPONDER) {
		struct payload_digest *ntfy;

		/* Process all NOTIFY payloads */
		for (ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
			switch (ntfy->payload.v2n.isan_type) {
			case v2N_NAT_DETECTION_SOURCE_IP:
			case v2N_NAT_DETECTION_DESTINATION_IP:
			case v2N_IKEV2_FRAGMENTATION_SUPPORTED:
			case v2N_COOKIE:
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
			default:
				DBG(DBG_CONTROL, DBG_log("received %s but ignoring it",
					enum_name(&ikev2_notify_names,
						ntfy->payload.v2n.isan_type)));
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

		stf_status ret = ikev2_calc_emit_ts(md, outpbs, role, c,
			send_ntfy ? ISAKMP_NEXT_v2N : ISAKMP_NEXT_v2NONE);

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
				if (!ship_v2N(c->send_no_esp_tfc ? ISAKMP_NEXT_v2N : ISAKMP_NEXT_v2NONE,
				      ISAKMP_PAYLOAD_NONCRITICAL,
				      PROTO_v2_RESERVED,
				      &empty_chunk,
				      v2N_USE_TRANSPORT_MODE,
				      &empty_chunk,
				      outpbs))
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
				if (!ship_v2N(ISAKMP_NEXT_v2NONE,
				      ISAKMP_PAYLOAD_NONCRITICAL,
				      PROTO_v2_RESERVED,
				      &empty_chunk,
				      v2N_ESP_TFC_PADDING_NOT_SUPPORTED,
				      &empty_chunk,
				      outpbs))
				return STF_INTERNAL_ERROR;
		}
	}

	ikev2_derive_child_keys(cst, role);

	ISAKMP_SA_established(pst->st_connection, pst->st_serialno);

	/* install inbound and outbound SPI info */
	if (!install_ipsec_sa(cst, TRUE))
		return STF_FATAL;

	/* mark the connection as now having an IPsec SA associated with it. */
	cst->st_connection->newest_ipsec_sa = cst->st_serialno;
	log_newest_sa_change("inR2", cst);

	return STF_OK;
}

static bool ikev2_set_dns(pb_stream *cp_a_pbs, struct state *st)
{
	ip_address ip;
	ipstr_buf ip_str;
	struct connection *c = st->st_connection;
	err_t ugh = initaddr(cp_a_pbs->cur, pbs_left(cp_a_pbs), AF_INET, &ip);

	if (ugh != NULL) {
		libreswan_log("ERROR INTERNAL_IP4_DNS malformed: %s", ugh);
		return FALSE;
	}

	if (isanyaddr(&ip)) {
		libreswan_log("ERROR INTERNAL_IP4_DNS %s is invalid",
				ipstr(&ip, &ip_str));
		return FALSE;
	}

	libreswan_log("received INTERNAL_IP4_DNS %s",
			ipstr(&ip, &ip_str));

	char *old = c->cisco_dns_info;

	if (old == NULL) {
		c->cisco_dns_info = clone_str(ip_str.buf, "ikev2 cisco_dns_info");
	} else {
		/*
		 * concatenate new IP address  string on end of existing
		 * string, separated by ' '.
		 */
		size_t sz_old = strlen(old);
		size_t sz_added = strlen(ip_str.buf) + 1;
		char *new = alloc_bytes(sz_old + 1 + sz_added,
				"ikev2 cisco_dns_info+");

		memcpy(new, old, sz_old);
		new[sz_old] = ' ';
		memcpy(new + sz_old + 1, ip_str.buf, sz_added);
		c->cisco_dns_info = new;
		pfree(old);
	}
	return TRUE;
}

static bool ikev2_set_ia(pb_stream *cp_a_pbs, struct state *st)
{
	ip_address ip;
	ipstr_buf ip_str;
	struct connection *c = st->st_connection;
	err_t ugh = initaddr(cp_a_pbs->cur, pbs_left(cp_a_pbs), AF_INET, &ip);

	if (ugh != NULL) {
		libreswan_log("ERROR INTERNAL_IP4_ADDRESS malformed: %s", ugh);
		return FALSE;
	}

	if (isanyaddr(&ip)) {
		libreswan_log("ERROR INTERNAL_IP4_ADDRESS %s is invalid",
			ipstr(&ip, &ip_str));
		return FALSE;
	}

	libreswan_log("received INTERNAL_IP4_ADDRESS %s",
			ipstr(&ip, &ip_str));

	c->spd.this.has_client = TRUE;
	c->spd.this.has_internal_address = TRUE;

	if (c->spd.this.cat) {
		DBG(DBG_CONTROL, DBG_log("CAT is set, not setting host source IP address to %s",
			ipstr(&ip, &ip_str)));
		if (sameaddr (&c->spd.this.client.addr, &ip)) {
			/* The address we received is same as this side
			 * should we also check the host_srcip */
			DBG(DBG_CONTROL, DBG_log("#%lu %s[%lu] received NTERNAL_IP4_ADDRESS which is same as this.client.addr %s. Will not add CAT iptable rules",
				st->st_serialno, c->name, c->instance_serial,
				ipstr(&ip, &ip_str)));
		} else {
			c->spd.this.client.addr = ip;
			c->spd.this.client.maskbits = 32;
			st->st_ts_this = ikev2_end_to_ts(&c->spd.this);
			c->spd.this.has_cat = TRUE; /* create iptable entry */
		}
	} else {
		addrtosubnet(&ip, &c->spd.this.client);
		setportof(0, &c->spd.this.client.addr); /* ??? redundant? */
		/* ??? the following test seems obscure.  What's it about? */
		if (addrbytesptr(&c->spd.this.host_srcip, NULL) == 0 ||
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

	if (cp->isacp_type !=  IKEv2_CP_CFG_REPLY) {
		libreswan_log("ERROR expected IKEv2_CP_CFG_REPLY got a %s",
			enum_name(&ikev2_cp_type_names,cp->isacp_type));
		return FALSE;
	}
	while (pbs_left(attrs) > 0) {
		struct ikev2_cp_attribute cp_a;
		pb_stream cp_a_pbs;

		if (!in_struct(&cp_a, &ikev2_cp_attribute_desc,
					attrs, &cp_a_pbs)) {
			/* reject malformed */
			return STF_FAIL;
		}

		switch (cp_a.type) {
		case INTERNAL_IP4_ADDRESS | ISAKMP_ATTR_AF_TLV:
			if (!ikev2_set_ia(&cp_a_pbs, st))
				return FALSE;
			break;

		case INTERNAL_IP4_DNS | ISAKMP_ATTR_AF_TLV:
			if (!ikev2_set_dns(&cp_a_pbs, st))
				return FALSE;
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
