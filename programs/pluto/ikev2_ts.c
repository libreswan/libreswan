/* IKEv2 Traffic Selectors, for libreswan
 *
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2011-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012,2016-2017 Antony Antony <appu@phenome.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2014-2015, 2018 Andrew cagney <cagney@gnu.org>
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

/*
 * While the RFC seems to suggest that the traffic selectors come in
 * pairs, strongswan, at least, doesn't.
 */
struct traffic_selectors {
	unsigned nr;
	/* ??? is 16 an undocumented limit - IKEv2 has no limit */
	struct traffic_selector ts[16];
};

struct ends {
	const struct end *i;
	const struct end *r;
};

enum fit {
	END_EQUALS_TS = 1,
	END_NARROWER_THAN_TS,
	END_WIDER_THAN_TS,
};

static const char *fit_string(enum fit fit)
{
	switch (fit) {
	case END_EQUALS_TS: return "==";
	case END_NARROWER_THAN_TS: return "<=";
	case END_WIDER_THAN_TS: return ">=";
	default: bad_case(fit);
	}
}

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
				const struct traffic_selector *ts)
{
	pb_stream ts_pbs;

	{
		struct ikev2_ts its = {
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

stf_status v2_emit_ts_payloads(const struct child_sa *child,
			       pb_stream *outpbs,
			       const struct connection *c0)
{
	const struct traffic_selector *ts_i, *ts_r;

	switch (child->sa.st_sa_role) {
	case SA_INITIATOR:
		ts_i = &child->sa.st_ts_this;
		ts_r = &child->sa.st_ts_that;
		break;
	case SA_RESPONDER:
		ts_i = &child->sa.st_ts_that;
		ts_r = &child->sa.st_ts_this;
		break;
	default:
		bad_case(child->sa.st_sa_role);
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
		stf_status ret = ikev2_emit_ts(outpbs, &ikev2_ts_i_desc, ts_i);

		if (ret != STF_OK)
			return ret;
		ret = ikev2_emit_ts(outpbs, &ikev2_ts_r_desc, ts_r);
		if (ret != STF_OK)
			return ret;
	}

	return STF_OK;
}

/* return success */
static bool v2_parse_ts(struct payload_digest *const ts_pd,
			struct traffic_selectors *tss,
			const char *which)
{
	DBGF(DBG_MASK, "%s: parsing %u traffic selectors",
	     which, ts_pd->payload.v2ts.isat_num);

	if (ts_pd->payload.v2ts.isat_num == 0) {
		libreswan_log("%s payload contains no entries when at least one is expected",
			      which);
		return false;
	}

	if (ts_pd->payload.v2ts.isat_num >= elemsof(tss->ts)) {
		libreswan_log("%s contains %d entries which exceeds hardwired max of %zu",
			      which, ts_pd->payload.v2ts.isat_num, elemsof(tss->ts));
		return false;	/* won't fit in array */
	}

	for (tss->nr = 0; tss->nr < ts_pd->payload.v2ts.isat_num; tss->nr++) {
		struct traffic_selector *ts = &tss->ts[tss->nr];

		pb_stream addr;
		struct ikev2_ts1 ts1;
		if (!in_struct(&ts1, &ikev2_ts1_desc, &ts_pd->pbs, &addr))
			return false;

		switch (ts1.isat1_type) {
		case IKEv2_TS_IPV4_ADDR_RANGE:
			ts->ts_type = IKEv2_TS_IPV4_ADDR_RANGE;
			SET_V4(ts->net.start);
			if (!in_raw(&ts->net.start.u.v4.sin_addr.s_addr,
				    sizeof(ts->net.start.u.v4.sin_addr.s_addr),
				    &addr, "ipv4 ts low"))
				return false;

			SET_V4(ts->net.end);

			if (!in_raw(&ts->net.end.u.v4.sin_addr.s_addr,
				    sizeof(ts->net.end.u.v4.sin_addr.s_addr),
				    &addr, "ipv4 ts high"))
				return false;

			break;

		case IKEv2_TS_IPV6_ADDR_RANGE:
			ts->ts_type = IKEv2_TS_IPV6_ADDR_RANGE;
			SET_V6(ts->net.start);

			if (!in_raw(&ts->net.start.u.v6.sin6_addr.s6_addr,
				    sizeof(ts->net.start.u.v6.sin6_addr.s6_addr),
				    &addr, "ipv6 ts low"))
				return false;

			SET_V6(ts->net.end);

			if (!in_raw(&ts->net.end.u.v6.sin6_addr.s6_addr,
				    sizeof(ts->net.end.u.v6.sin6_addr.s6_addr),
				    &addr, "ipv6 ts high"))
				return false;

			break;

		default:
			return false;
		}

		if (pbs_left(&addr) != 0)
			return false;

		ts->ipprotoid = ts1.isat1_ipprotoid;

		ts->startport = ts1.isat1_startport;
		ts->endport = ts1.isat1_endport;
		if (ts->startport > ts->endport) {
			libreswan_log("%s traffic selector %d has an invalid port range",
				      which, tss->nr);
			return false;
		}
	}

	DBGF(DBG_MASK, "%s: parsed %d traffic selectors", which, tss->nr);
	return true;
}

static bool v2_parse_tss(const struct msg_digest *md,
			 struct traffic_selectors *tsi,
			 struct traffic_selectors *tsr)
{
	if (!v2_parse_ts(md->chain[ISAKMP_NEXT_v2TSi], tsi, "TSi")) {
		return false;
	}

	if (!v2_parse_ts(md->chain[ISAKMP_NEXT_v2TSr], tsr, "TSr")) {
		return false;
	}

	return true;
}

#define MATCH_PREFIX "        "

/*
 * Check if our policy's protocol (proto) matches the Traffic Selector
 * protocol (ts_proto).
 */

static int ikev2_match_protocol(const struct end *end,
				const struct traffic_selector *ts,
				enum fit fit,
				const char *which, int index)
{
	int f = 0;	/* strength of match */

	switch (fit) {
	case END_EQUALS_TS:
		if (end->protocol == ts->ipprotoid) {
			f = 255;	/* ??? odd value */
		}
		break;
	case END_NARROWER_THAN_TS:
		if (ts->ipprotoid == 0) { /* wild-card */
			f = 1;
		}
		break;
	case END_WIDER_THAN_TS:
		if (end->protocol == 0) { /* wild-card */
			f = 1;
		}
		break;
	default:
		bad_case(fit);
	}
	LSWDBGP(DBG_MASK, buf) {
		lswlogf(buf, MATCH_PREFIX "match end->protocol=%s%d %s %s[%d].ipprotoid=%s%d: ",
			end->protocol == 0 ? "*" : "", end->protocol,
			fit_string(fit),
			which, index, ts->ipprotoid == 0 ? "*" : "", ts->ipprotoid);
		if (f > 0) {
			lswlogf(buf, "YES fitness %d", f);
		} else {
			lswlogf(buf, "NO");
		}
	}
	return f;
}

/*
 * Check if our policy's port (port) matches
 * the Traffic Selector port range (ts.startport to ts.endport)
 * Note port == 0 means port range 0 to 65535.
 * If superset_ok, fit ts port range to our port range is OK (responder fit)
 * If subset_ok, fit our port range to ts port range is OK (initiator fit).
 * Returns 0 if no match; otherwise number of ports within match
 */
static int ikev2_match_port_range(const struct end *end,
				  const struct traffic_selector *ts,
				  enum fit fit,
				  const char *which, int index)
{
	uint16_t end_low = end->port;
	uint16_t end_high = end->port == 0 ? 65535 : end->port;
	int f = 0;	/* strength of match */

	switch (fit) {
	case END_EQUALS_TS:
		if (end_low == ts->startport && end_high == ts->endport) {
			f = 1 + (end_high - end_low);
		}
		break;
	case END_NARROWER_THAN_TS:
		if (end_low >= ts->startport && end_high <= ts->endport) {
			f = 1 + (end_high - end_low);
		}
		break;
	case END_WIDER_THAN_TS:
		if (end_low <= ts->startport && end_high >= ts->endport) {
			f = 1 + (ts->endport - ts->startport);
		}
		break;
	default:
		bad_case(fit);
	}
	LSWDBGP(DBG_MASK, buf) {
		lswlogf(buf, MATCH_PREFIX "match port end->port=%u..%u %s %s[%d].{start,end}port=%u..%u: ",
			end_low, end_high,
			fit_string(fit),
			which, index, ts->startport, ts->endport);
		if (f > 0) {
			lswlogf(buf, "YES fitness %d", f);
		} else {
			lswlogf(buf, "NO");
		}
	}
	return f;
}

/*
 * Does TS fit inside of END?
 *
 * Given other code flips the comparison depending initiator or
 * responder, is this right?
 *
 * NOTE: Our parser/config only allows 1 CIDR, however IKEv2 ranges
 *       can be non-CIDR for now we really support/limit ourselves to
 *       a single CIDR
 *
 * XXX: what exactly is CIDR?
 */

static int match_address_range(const struct end *end,
			       const struct traffic_selector *ts,
			       enum fit fit,
			       const char *which, int index)
{
	/*
	 * Pre-compute possible fit --- sum of bits gives how good a
	 * fit this is.
	 */
	int ts_range = iprange_bits(ts->net.start, ts->net.end);
	int maskbits = end->client.maskbits;
	int fitbits = maskbits + ts_range;

	int f = 0;

	/*
	 * NOTE: Our parser/config only allows 1 CIDR, however IKEv2
	 *       ranges can be non-CIDR for now we really
	 *       support/limit ourselves to a single CIDR
	 *
	 * XXX: so what is CIDR?
	 */
	ip_address floor = ip_subnet_floor(&end->client);
	ip_address ceiling = ip_subnet_ceiling(&end->client);
	passert(addrcmp(&floor, &ceiling) <= 0);
	passert(addrcmp(&ts->net.start, &ts->net.end) <= 0);
	switch (fit) {
	case END_EQUALS_TS:
		if (addrcmp(&floor, &ts->net.start) == 0 &&
		    addrcmp(&ceiling, &ts->net.end) == 0) {
			f = fitbits;
		}
		break;
	case END_NARROWER_THAN_TS:
		if (addrcmp(&floor, &ts->net.start) >= 0 &&
		    addrcmp(&ceiling, &ts->net.end) <= 0) {
			f = fitbits;
		}
		break;
	case END_WIDER_THAN_TS:
		if (addrcmp(&floor, &ts->net.start) <= 0 &&
		    addrcmp(&ceiling, &ts->net.end) >= 0) {
			f = fitbits;
		}
		break;
	default:
		bad_case(fit);
	}

	/*
	 * comparing for ports for finding better local policy
	 *
	 * XXX: why do this?
	 */
	/* ??? arbitrary modification to objective function */
	if (end->port != 0 &&
	    ts->startport == end->port &&
	    ts->endport == end->port)
		f = f << 1;

	LSWDBGP(DBG_MASK, buf) {
	    char end_client[SUBNETTOT_BUF];
	    subnettot(&end->client,  0, end_client, sizeof(end_client));
	    char ts_net[RANGETOT_BUF];
	    rangetot(&ts->net, 0, ts_net, sizeof(ts_net));
	    lswlogf(buf, MATCH_PREFIX "match address end->client=%s %s %s[%u]net=%s: ",
		    end_client,
		    fit_string(fit),
		    which, index, ts_net);
	    if (f > 0) {
		    lswlogf(buf, "YES fitness %d", f);
	    } else {
		    lswlogf(buf, "NO");
	    }
	}
	return f;
}

struct score {
	bool ok;
	int address;
	int port;
	int protocol;
};

static struct score score_end(const struct end *end,
			      const struct traffic_selector *ts,
			      enum fit fit,
			      const char *what, int index)
{
	DBG(DBG_CONTROLMORE,
	    char ts_net[RANGETOT_BUF];
	    rangetot(&ts->net, 0, ts_net, sizeof(ts_net));
	    DBG_log("    %s[%u] .net=%s .iporotoid=%d .{start,end}port=%d..%d",
		    what, index,
		    ts_net,
		    ts->ipprotoid,
		    ts->startport,
		    ts->endport));

	struct score score = { .ok = false, };
	score.address = match_address_range(end, ts, fit, what, index);
	if (score.address <= 0) {
		return score;
	}
	score.port = ikev2_match_port_range(end, ts, fit, what, index);
	if (score.port <= 0) {
		return score;
	}
	score.protocol = ikev2_match_protocol(end, ts, fit, what, index);
	if (score.protocol <= 0) {
		return score;
	}
	score.ok = true;
	return score;
}

struct best_score {
	bool ok;
	int address;
	int port;
	int protocol;
	const struct traffic_selector *tsi;
	const struct traffic_selector *tsr;
};
#define  NO_SCORE { .ok = false, .address = -1, .port = -1, .protocol = -1, }

static bool score_gt(const struct best_score *score, const struct best_score *best)
{
	return (score->address > best->address ||
		(score->address == best->address &&
		 score->port > best->port) ||
		(score->address == best->address &&
		 score->port == best->port &&
		 score->protocol > best->protocol));
}

static struct best_score score_ends(enum fit fit,
				    const struct connection *d,
				    const struct ends *ends,
				    const struct traffic_selectors *tsi,
				    const struct traffic_selectors *tsr)
{
	DBG(DBG_CONTROLMORE, {
		char ei3[SUBNETTOT_BUF];
		char er3[SUBNETTOT_BUF];
		char cib[CONN_INST_BUF];
		subnettot(&ends->i->client,  0, ei3, sizeof(ei3));
		subnettot(&ends->r->client,  0, er3, sizeof(er3));
		DBG_log("evaluating our conn=\"%s\"%s I=%s:%d/%d R=%s:%d/%d%s to their:",
			d->name, fmt_conn_instance(d, cib),
			ei3, ends->i->protocol, ends->i->port,
			er3, ends->r->protocol, ends->r->port,
			is_virtual_connection(d) ? " (virt)" : "");
	});

	struct best_score best_score = NO_SCORE;

	/* compare tsi/r array to this/that, evaluating how well it fits */
	for (unsigned tsi_ni = 0; tsi_ni < tsi->nr; tsi_ni++) {
		const struct traffic_selector *tni = &tsi->ts[tsi_ni];

		/* choice hardwired! */
		struct score score_i = score_end(ends->i, tni, fit, "TSi", tsi_ni);
		if (!score_i.ok) {
			continue;
		}

		for (unsigned tsr_ni = 0; tsr_ni < tsr->nr; tsr_ni++) {
			const struct traffic_selector *tnr = &tsr->ts[tsr_ni];

			struct score score_r = score_end(ends->r, tnr, fit, "TSr", tsr_ni);
			if (!score_r.ok) {
				continue;
			}

			struct best_score score = {
				.ok = true,
				/* ??? this objective function is odd and arbitrary */
				.address = (score_i.address << 8) + score_r.address,
				/* ??? arbitrary objective function */
				.port = score_i.port + score_r.port,
				/* ??? arbitrary objective function */
				.protocol = score_i.protocol + score_r.protocol,
				/* which one */
				.tsi = tni, .tsr = tnr,
			};

			/* score >= best_score? */
			if (score_gt(&score, &best_score)) {
				best_score = score;
				DBGF(DBG_MASK, "best fit so far: TSi[%d] TSr[%d]",
				     tsi_ni, tsr_ni);
			}
		}
	}

	return best_score;
}

/*
 * find the best connection and, if it is AUTH exchange, create the
 * child state
 *
 * XXX: creating child as a side effect is pretty messed up.
 */
bool v2_process_ts_request(struct child_sa *child,
			   const struct msg_digest *md)
{
	passert(v2_msg_role(md) == MESSAGE_REQUEST);
	passert(child->sa.st_sa_role == SA_RESPONDER);

	/*
	 * XXX: md->st here is parent????  Lets find out.
	 */
	if (md->st == &child->sa) {
		dbg("Child SA TS Request has child->sa == md->st; so using child connection");
	} else if (md->st == &ike_sa(&child->sa)->sa) {
		dbg("Child SA TS Request has ike->sa == md->st; so using parent connection");
	} else {
		dbg("Child SA TS Request has an unknown md->st; so using unknown connection");
	}
	struct connection *c = md->st->st_connection;

	struct traffic_selectors tsi = { .nr = 0, };
	struct traffic_selectors tsr = { .nr = 0, };
	if (!v2_parse_tss(md, &tsi, &tsr)) {
		return false;
	}

	/* best so far; start with state's connection */
	struct best_score best_score = NO_SCORE;
	const struct spd_route *best_spd_route = NULL;
	struct connection *best_connection = c;

	/* find best spd in c */

	dbg("looking for best SPD in current connection");
	for (const struct spd_route *sra = &c->spd; sra != NULL; sra = sra->spd_next) {

		/* responder */
		const struct ends ends = {
			.i = &sra->that,
			.r = &sra->this,
		};
		enum fit responder_fit =
			(c->policy & POLICY_IKEV2_ALLOW_NARROWING)
			? END_NARROWER_THAN_TS
			: END_EQUALS_TS;

		struct best_score score = score_ends(responder_fit, c, &ends, &tsi, &tsr);
		if (!score.ok) {
			continue;
		}
		if (score_gt(&score, &best_score)) {
			dbg("    found better spd route for TSi[%zu],TSr[%zu]",
			    score.tsi - tsi.ts, score.tsr - tsr.ts);
			best_score = score;
			best_spd_route = sra;
			passert(best_connection == c);
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

	dbg("looking for better host pair");
	const struct host_pair *hp = NULL;
	for (const struct spd_route *sra = &c->spd;
	     hp == NULL && sra != NULL; sra = sra->spd_next) {
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

		for (struct connection *d = hp->connections;
		     d != NULL; d = d->hp_next) {
			/* groups are templates instantiated as GROUPINSTANCE */
			if (d->policy & POLICY_GROUP) {
				continue;
			}
			dbg("  investigating connection \"%s\" as a better match", d->name);

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
					 d->spd.that.ca, &pathlen))) {
				dbg("    connection \"%s\" does not match IDs or CA of current connection \"%s\"",
				    d->name, c->name);
				continue;
			}

			const struct spd_route *sr;

			for (sr = &d->spd; sr != NULL; sr = sr->spd_next) {

				/* responder */
				const struct ends ends = {
					.i = &sr->that,
					.r = &sr->this,
				};
				/* responder -- note D! */
				enum fit responder_fit =
					(d->policy & POLICY_IKEV2_ALLOW_NARROWING)
					? END_NARROWER_THAN_TS
					: END_EQUALS_TS;

				struct best_score score = score_ends(responder_fit, d/*note D*/,
								     &ends, &tsi, &tsr);
				if (!score.ok) {
					continue;
				}
				if (score_gt(&score, &best_score)) {
					dbg("    protocol fitness found better match d %s, TSi[%zu],TSr[%zu]",
					    d->name,
					    score.tsi - tsi.ts, score.tsr - tsr.ts);
					best_connection = d;
					best_score = score;
					best_spd_route = sr;
				}
			}
		}
	}

	if (best_connection == c) {
		dbg("  did not find a better connection using host pair");
	}

	if (best_spd_route == NULL && c->kind != CK_INSTANCE) {
		/*
		 * Don't try to look for something else to
		 * 'instantiate' when the current connection is
		 * permanent.
		 *
		 * XXX: Is this missing an opportunity?  Could there
		 * be a better connection to instantiate when the
		 * current one is permanent?
		 *
		 * XXX: 'instantiate', not really?  The code below
		 * blats the current instance with new values -
		 * something that should not be done to a permanent
		 * connection.
		 */
		pexpect(c->kind == CK_PERMANENT);
		dbg("no best spd route; but the current %s connection \"%s\" is not a CK_INSTANCE",
		    enum_name(&connection_kind_names, c->kind), c->name);
	} else if (best_spd_route == NULL) {
		/*
		 * Rather than overwrite the current INSTANCE; would
		 * it be better to instantiate a new instance, and
		 * then replace it?  Would also address the above.
		 */
		pexpect(c->kind == CK_INSTANCE);
		LSWDBGP(DBG_MASK, buf) {
			lswlogf(buf, "can the current %s connection \"%s\"",
				enum_name(&connection_kind_names, c->kind), c->name);
			if (c->foodgroup != NULL) {
				lswlogf(buf, "; food-group: \"%s\"", c->foodgroup);
			}
#define BP_MASK (POLICY_NEGO_PASS |					\
		 POLICY_DONT_REKEY |					\
		 POLICY_REAUTH |					\
		 POLICY_OPPORTUNISTIC |					\
		 POLICY_GROUP |						\
		 POLICY_GROUTED |					\
		 POLICY_GROUPINSTANCE |					\
		 POLICY_UP |						\
		 POLICY_XAUTH |						\
		 POLICY_MODECFG_PULL |					\
		 POLICY_AGGRESSIVE |					\
		 POLICY_OVERLAPIP |					\
		 POLICY_IKEV2_ALLOW_NARROWING)
			lswlogf(buf, "; %s", prettypolicy(c->policy & BP_MASK));
			lswlogs(buf, " be overwritten with a better instantiation?");
		}
		/* since an SPD_ROUTE wasn't found */
		passert(best_connection == c);

		for (struct connection *t = connections; t != NULL; t = t->ac_next) {
			/* require a template */
			if (t->kind != CK_TEMPLATE) {
				continue;
			}
			LSWDBGP(DBG_MASK, buf) {
				lswlogf(buf, "  investigating %s connection \"%s\"",
					enum_name(&connection_kind_names, t->kind), t->name);
				if (t->foodgroup != NULL) {
					lswlogf(buf, "; food-group: \"%s\"", t->foodgroup);
				}
				lswlogf(buf, "; %s", prettypolicy(t->policy & BP_MASK));
			}
			/* XXX: why does this matter; does it imply t->foodgroup != NULL? */
			if (!LIN(POLICY_GROUPINSTANCE, t->policy)) {
				dbg("    skipping; not a group instance");
				continue;
			}
			/* when OE, don't change food groups? */
			if (!streq(c->foodgroup, t->foodgroup)) {
				dbg("    skipping; wrong foodgroup name");
				continue;
			}
			/* ??? why require current connection->name and t->name to be different */
			/* XXX: don't re-instantiate the same connection template???? */
			if (streq(c->name, t->name)) {
				dbg("    skipping; name same as current connection");
				continue;
			}
			/* require initiator's subnet <= T; why? */
			if (!subnetinsubnet(&c->spd.that.client, &t->spd.that.client)) {
				dbg("    skipping; current connection's initiator subnet is not <= template");
				continue;
			}
			/* require responder address match; why? */
			if (!sameaddr(&c->spd.this.client.addr, &t->spd.this.client.addr)) {
				dbg("    skipping; responder addresses don't match");
				continue;
			}

			/*
			 * ??? this code seems to assume that tsi and
			 * tsr contain exactly one element.  Any fewer
			 * and the code references an uninitialized
			 * value.  Any more would be ignored, and
			 * that's surely wrong.  It would be nice if
			 * the purpose of this block of code were
			 * documented.
			 *
			 * XXX: parse_ts() checks that there is at
			 * least one element, and the RFC says to go
			 * out of your way to match the first TS[ir]
			 * as a pair.
			 */
			pexpect(tsi.nr == 1);
			int t_sport =
				tsi.ts[0].startport == tsi.ts[0].endport ? tsi.ts[0].startport :
				tsi.ts[0].startport == 0 && tsi.ts[0].endport == 65535 ? 0 : -1;
			pexpect(tsr.nr == 1);
			int t_dport =
				tsr.ts[0].startport == tsr.ts[0].endport ? tsr.ts[0].startport :
				tsr.ts[0].startport == 0 && tsr.ts[0].endport == 65535 ? 0 : -1;

			if (t_sport == -1 || t_dport == -1)
				continue;

			if ((t->spd.that.protocol != tsi.ts[0].ipprotoid) ||
			    (c->spd.this.port != t_sport) ||
			    (c->spd.that.port != t_dport))
				continue;

			dbg("  overwriting connection of group instance for protoports");
			passert(best_connection == c);
			c->spd.that.protocol = t->spd.that.protocol;
			c->spd.this.port = t->spd.this.port;
			c->spd.that.port = t->spd.that.port;
			pfreeany(c->name);
			c->name = clone_str(t->name, "hidden switch template name update");
			best_spd_route = &c->spd;
			break;
		}
	}


	if (best_spd_route == NULL) {
		dbg("giving up");
		return false;
	}

	/*
	 * this both replaces the child's connection, and flips any
	 * underlying current-connection
	 *
	 * XXX: but this is responder code, there probably isn't a
	 * current-connection - it would have gone straight to current
	 * state>
	 *
	 * update_state_connection(), if the connection changes,
	 * de-references the old connection; which is what really
	 * matters
	 */
	update_state_connection(&child->sa, best_connection);

	child->sa.st_ts_this = ikev2_end_to_ts(&best_spd_route->this);
	child->sa.st_ts_that = ikev2_end_to_ts(&best_spd_route->that);

	ikev2_print_ts(&child->sa.st_ts_this);
	ikev2_print_ts(&child->sa.st_ts_that);

	return true;
}

/* check TS payloads, response */
bool v2_process_ts_response(struct child_sa *child,
			    struct msg_digest *md)
{
	passert(child->sa.st_sa_role == SA_INITIATOR);
	passert(v2_msg_role(md) == MESSAGE_RESPONSE);

	struct connection *c = child->sa.st_connection;

	struct traffic_selectors tsi = { .nr = 0, };
	struct traffic_selectors tsr = { .nr = 0, };
	if (!v2_parse_tss(md, &tsi, &tsr)) {
		return false;
	}

	/* initiator */
	const struct spd_route *sra = &c->spd;
	const struct ends e = {
		.i = &sra->this,
		.r = &sra->that,
	};
	enum fit initiator_widening =
		(c->policy & POLICY_IKEV2_ALLOW_NARROWING)
		? END_WIDER_THAN_TS
		: END_EQUALS_TS;

	struct best_score best = score_ends(initiator_widening, c, &e, &tsi, &tsr);

	if (!best.ok) {
			DBG(DBG_CONTROLMORE,
			    DBG_log("reject responder TSi/TSr Traffic Selector"));
			/* prevents parent from going to I3 */
			return false;
	}

	DBG(DBG_CONTROLMORE,
	    DBG_log("found an acceptable TSi/TSr Traffic Selector"));
	struct state *st = &child->sa;
	memcpy(&st->st_ts_this, best.tsi,
	       sizeof(struct traffic_selector));
	memcpy(&st->st_ts_that, best.tsr,
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

	return true;
}
