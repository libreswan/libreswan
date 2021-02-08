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
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#include "log.h"
#include "ikev2_ts.h"
#include "connections.h"	/* for struct end */
#include "demux.h"
#include "virtual_ip.h"
#include "hostpair.h"
#include "ip_info.h"
#include "ip_selector.h"

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
	if (DBGP(DBG_BASE)) {
		DBG_log("printing contents struct traffic_selector");
		DBG_log("  ts_type: %s", enum_name(&ikev2_ts_type_names, ts->ts_type));
		DBG_log("  ipprotoid: %d", ts->ipprotoid);
		DBG_log("  port range: %d-%d", ts->startport, ts->endport);
		range_buf b;
		DBG_log("  ip range: %s", str_range(&ts->net, &b));
		if (ts->sec_label.len != 0)
			DBG_dump_hunk("security label:", ts->sec_label);
	}
}

/* rewrite me with address_as_{chunk,shunk}()? */
/* For now, note the struct traffic_selector can contain
 * two selectors - an IPvX range and a sec_label
 */
struct traffic_selector ikev2_end_to_ts(const struct end *e)
{
	struct traffic_selector ts;

	zero(&ts);	/* OK: no pointer fields */

	switch (subnet_type(&e->client)->af) {
	case AF_INET:
		ts.ts_type = IKEv2_TS_IPV4_ADDR_RANGE;
		break;
	case AF_INET6:
		ts.ts_type = IKEv2_TS_IPV6_ADDR_RANGE;
		break;
	}

	/* subnet => range */
	ts.net = range_from_subnet(&e->client);
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

	ts.sec_label = e->sec_label;

	return ts;
}

/*
 * A struct end is converted to a struct traffic_selector.
 * This (currently) can contain both an IP range AND a
 * SEC_LABEL, which will get output here as two Traffic
 * Selectors. The label is optional, the IP range is
 * mandatory.
 */
static stf_status ikev2_emit_ts(pb_stream *outpbs,
				const struct_desc *ts_desc,
				const struct traffic_selector *ts)
{
	pb_stream ts_pbs;
	bool with_label = ts->sec_label.len != 0;

	if (ts->ts_type != IKEv2_TS_IPV4_ADDR_RANGE &&
		ts->ts_type != IKEv2_TS_IPV6_ADDR_RANGE)
	{
		return STF_INTERNAL_ERROR;
	}

	{
		struct ikev2_ts its = {
			.isat_critical = ISAKMP_PAYLOAD_NONCRITICAL,
			/*
			 * If there is a security label in the Traffic Selector,
			 * then we must send a TS_SECLABEL substructure as part of the
			 * Traffic Selector (TS) Payload.
			 * That means the TS Payload contains two TS substructures:
			 *  - One for the address/port range
			 *  - One for the TS_SECLABEL
			 */
			.isat_num = with_label ? 2 : 1,
		};

		if (!out_struct(&its, ts_desc, outpbs, &ts_pbs))
			return STF_INTERNAL_ERROR;
	}

	{
		pb_stream ts_range_pbs;
		struct ikev2_ts_header ts_header = {
			.isath_ipprotoid = ts->ipprotoid
		};

		switch (ts->ts_type) {
		case IKEv2_TS_IPV4_ADDR_RANGE:
			ts_header.isath_type = IKEv2_TS_IPV4_ADDR_RANGE;
			break;
		case IKEv2_TS_IPV6_ADDR_RANGE:
			ts_header.isath_type = IKEv2_TS_IPV6_ADDR_RANGE;
			break;
		}

		if (!out_struct(&ts_header, &ikev2_ts_header_desc, &ts_pbs, &ts_range_pbs))
			return STF_INTERNAL_ERROR;


		struct ikev2_ts_portrange ts_ports = {
			.isatpr_startport = ts->startport,
			.isatpr_endport = ts->endport
		};

		if (!out_struct(&ts_ports, &ikev2_ts_portrange_desc, &ts_range_pbs, NULL))
			return STF_INTERNAL_ERROR;

		diag_t d;
		d = pbs_out_address(&ts_range_pbs, &ts->net.start, "IP start");
		if (d != NULL) {
			log_diag(RC_LOG_SERIOUS, outpbs->outs_logger, &d, "%s", "");
			return STF_INTERNAL_ERROR;
		}
		d = pbs_out_address(&ts_range_pbs, &ts->net.end, "IP end");
		if (d != NULL) {
			log_diag(RC_LOG_SERIOUS, outpbs->outs_logger, &d, "%s", "");
			return STF_INTERNAL_ERROR;
		}
		close_output_pbs(&ts_range_pbs);
	}

	if (with_label)
	{
		pb_stream ts_label_pbs;
		struct ikev2_ts_header ts_header = {
			.isath_type = IKEv2_TS_SECLABEL,
			.isath_ipprotoid = 0 /* really RESERVED, not iprotoid */
		};
		/* Output the header of the TS_SECLABEL substructure payload. */
		if (!out_struct(&ts_header, &ikev2_ts_header_desc, &ts_pbs, &ts_label_pbs)) {
			return STF_INTERNAL_ERROR;
		}

		/* Output the security label value of the TS_SECLABEL substructure payload. */
		diag_t d = pbs_out_raw(&ts_label_pbs, ts->sec_label.ptr, ts->sec_label.len, "output Security label");
		if (d != NULL) {
			log_diag(RC_LOG_SERIOUS, outpbs->outs_logger, &d, "%s", "");
			return STF_INTERNAL_ERROR;
		}
		close_output_pbs(&ts_label_pbs);
	}

	close_output_pbs(&ts_pbs);
	return STF_OK;
}

static struct traffic_selector impair_ts_to_subnet(const struct traffic_selector *ts)
{
	struct traffic_selector ts_ret = *ts;

	ts_ret.net.end = ts_ret.net.start;
	ts_ret.net.is_subnet = true;

	return ts_ret;
}


static struct traffic_selector impair_ts_to_supernet(const struct traffic_selector *ts)
{
	struct traffic_selector ts_ret = *ts;

	if (ts_ret.ts_type == IKEv2_TS_IPV4_ADDR_RANGE)
		ts_ret.net = range_from_subnet(&ipv4_info.all_addresses);
	else if (ts_ret.ts_type == IKEv2_TS_IPV6_ADDR_RANGE)
		ts_ret.net = range_from_subnet(&ipv6_info.all_addresses);

	ts_ret.net.is_subnet = true;

	ts_ret.sec_label = ts->sec_label;

	return ts_ret;
}

stf_status v2_emit_ts_payloads(const struct child_sa *child,
			       pb_stream *outpbs,
			       const struct connection *c0)
{
	const struct traffic_selector *ts_i, *ts_r;
	struct traffic_selector ts_i_impaired, ts_r_impaired;


	switch (child->sa.st_sa_role) {
	case SA_INITIATOR:
		ts_i = &child->sa.st_ts_this;
		ts_r = &child->sa.st_ts_that;
		if (child->sa.st_state->kind == STATE_V2_REKEY_CHILD_I0 &&
				impair.rekey_initiate_supernet) {
			ts_i_impaired =  impair_ts_to_supernet(ts_i);
			ts_i = ts_r =  &ts_i_impaired; /* supernet TSi = TSr = 0/0 */
			range_buf tsi_buf;
                        range_buf tsr_buf;
			dbg("rekey-initiate-supernet TSi and TSr set to %s %s",
					str_range(&ts_i->net, &tsi_buf),
					str_range(&ts_r->net, &tsr_buf));

		} else if (child->sa.st_state->kind == STATE_V2_REKEY_CHILD_I0 &&
				impair.rekey_initiate_subnet) {
			ts_i_impaired =  impair_ts_to_subnet(ts_i);
			ts_r_impaired =  impair_ts_to_subnet(ts_r);
			ts_i = &ts_i_impaired;
			ts_r = &ts_r_impaired;
			range_buf tsi_buf;
			range_buf tsr_buf;
			dbg("rekey-initiate-subnet TSi and TSr set to %s %s",
					str_range(&ts_i->net, &tsi_buf),
					str_range(&ts_r->net, &tsr_buf));

		}

		break;
	case SA_RESPONDER:
		ts_i = &child->sa.st_ts_that;
		ts_r = &child->sa.st_ts_this;
		if (child->sa.st_state->kind == STATE_V2_REKEY_CHILD_R0 &&
				impair.rekey_respond_subnet) {
			ts_i_impaired =  impair_ts_to_subnet(ts_i);
			ts_r_impaired =  impair_ts_to_subnet(ts_r);

			ts_i = &ts_i_impaired;
			ts_r = &ts_r_impaired;
			range_buf tsi_buf;
			range_buf tsr_buf;
			dbg("rekey-respond-subnet TSi and TSr set to %s %s",
					str_range(&ts_i->net, &tsi_buf),
					str_range(&ts_r->net, &tsr_buf));
		}
		if (child->sa.st_state->kind == STATE_V2_REKEY_CHILD_R0 &&
				impair.rekey_respond_supernet) {
			ts_i_impaired =  impair_ts_to_supernet(ts_i);
			ts_i = ts_r =  &ts_i_impaired; /* supernet TSi = TSr = 0/0 */
			range_buf tsi_buf;
                        range_buf tsr_buf;
			dbg("rekey-respond-supernet TSi and TSr set to %s %s",
					str_range(&ts_i->net, &tsi_buf),
					str_range(&ts_r->net, &tsr_buf));
		}
		break;
	default:
		bad_case(child->sa.st_sa_role);
	}

	/*
	 * XXX: this looks wrong
	 *
	 * - instead of emitting two traffic selector payloads (TSi
	 *   TSr) each containing all the corresponding traffic
	 *   selectors, it is emitting a sequence of traffic selector
	 *   payloads each containing just one traffic selector
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
			const char *which, struct logger *logger)
{
	dbg("%s: parsing %u traffic selectors",
	    which, ts_pd->payload.v2ts.isat_num);

	if (ts_pd->payload.v2ts.isat_num == 0) {
		llog(RC_LOG, logger, "%s payload contains no entries when at least one is expected",
			      which);
		return false;
	}

	if (ts_pd->payload.v2ts.isat_num >= elemsof(tss->ts)) {
		llog(RC_LOG, logger, "%s contains %d entries which exceeds hardwired max of %zu",
			which, ts_pd->payload.v2ts.isat_num, elemsof(tss->ts));
		return false;	/* won't fit in array */
	}

	for (tss->nr = 0; tss->nr < ts_pd->payload.v2ts.isat_num; ) {
		diag_t d;
		struct traffic_selector *ts = &tss->ts[tss->nr];

		*ts = (struct traffic_selector){0};

		struct ikev2_ts_header ts_h;
		struct pbs_in ts_body_pbs;

		d = pbs_in_struct(&ts_pd->pbs, &ikev2_ts_header_desc,
			  &ts_h, sizeof(ts_h), &ts_body_pbs);

		switch (ts_h.isath_type) {
		case IKEv2_TS_IPV4_ADDR_RANGE:
		case IKEv2_TS_IPV6_ADDR_RANGE:
		{
			ts->ipprotoid = ts_h.isath_ipprotoid;

			/* read and fill in port range */
			struct ikev2_ts_portrange pr;

			d = pbs_in_struct(&ts_body_pbs, &ikev2_ts_portrange_desc,
				  &pr, sizeof(pr), NULL);
			if (d != NULL) {
				log_diag(RC_LOG, logger, &d, "%s", "");
				return false;
			}

			ts->startport = pr.isatpr_startport;
			ts->endport = pr.isatpr_endport;

			if (ts->startport > ts->endport) {
				llog(RC_LOG, logger,
					    "%s traffic selector %d has an invalid port range - ignored",
					    which, tss->nr);
				continue;
			}

			/* read and fill in IP address range */
			const struct ip_info *ipv;
			switch (ts_h.isath_type) {
			case IKEv2_TS_IPV4_ADDR_RANGE:
				ipv = &ipv4_info;
				break;
			case IKEv2_TS_IPV6_ADDR_RANGE:
				ipv = &ipv6_info;
				break;
			default:
				bad_case(ts_h.isath_type); /* make compiler happy */
			}


			d = pbs_in_address(&ts_body_pbs, &ts->net.start, ipv, "TS IP start");
			if (d != NULL) {
				log_diag(RC_LOG, logger, &d, "%s", "");
				return false;
			}

			d = pbs_in_address(&ts_body_pbs, &ts->net.end, ipv, "TS IP end");
			if (d != NULL) {
				log_diag(RC_LOG, logger, &d, "%s", "");
				return false;
			}

			/* XXX: does this matter? */
			if (pbs_left(&ts_body_pbs) != 0)
				return false;
			ts->ts_type = ts_h.isath_type;
			break;
		}

		case IKEv2_TS_SECLABEL:
		{
			if (ts_h.isath_ipprotoid != 0) {
				llog(RC_LOG, logger, "Traffic Selector of type Security Label should not have non-zero IP protocol '%u' - ignored",
					ts_h.isath_ipprotoid);
			}

			size_t sl_len = pbs_left(&ts_body_pbs);

			if (sl_len == 0) {
				llog(RC_LOG, logger, "Traffic Selector of type Security Label cannot be zero length - ignoring this TS");
				continue;
			}

			ts->sec_label = alloc_chunk(sl_len, "incoming TS sec_label");
			d = pbs_in_raw(&ts_body_pbs, ts->sec_label.ptr, sl_len, "TS Security Label content");

			if (d != NULL) {
				log_diag(RC_LOG, logger, &d, "%s", "");
				return false;
			}
			ts->ts_type = ts_h.isath_type;
			break;
		}

		case IKEv2_TS_FC_ADDR_RANGE:
			llog(RC_LOG, logger, "Encountered Traffic Selector Type FC_ADDR_RANGE not supported");
			return false;

		default:
			llog(RC_LOG, logger, "Encountered Traffic Selector of unknown Type");
			return false;
		}
		tss->nr++;
	}

	dbg("%s: parsed %d traffic selectors", which, tss->nr);
	return true;
}

static bool v2_parse_tss(const struct msg_digest *md,
			 struct traffic_selectors *tsi,
			 struct traffic_selectors *tsr,
			 struct logger *logger)
{
	if (!v2_parse_ts(md->chain[ISAKMP_NEXT_v2TSi], tsi, "TSi", logger)) {
		return false;
	}

	if (!v2_parse_ts(md->chain[ISAKMP_NEXT_v2TSr], tsr, "TSr", logger)) {
		return false;
	}

	return true;
}

#define MATCH_PREFIX "        "

/*
 * Check if our policy's protocol (proto) matches the Traffic Selector
 * protocol (ts_proto).
 */

static int narrow_protocol(const struct end *end,
			   const struct traffic_selectors *tss,
			   enum fit fit,
			   const char *which, unsigned index)
{
	const struct traffic_selector *ts = &tss->ts[index];
	int protocol = -1;

	switch (fit) {
	case END_EQUALS_TS:
		if (end->protocol == ts->ipprotoid) {
			protocol = end->protocol;
		}
		break;
	case END_NARROWER_THAN_TS:
		if (ts->ipprotoid == 0 /* wild-card */ ||
		    ts->ipprotoid == end->protocol) {
			protocol = end->protocol;
		}
		break;
	case END_WIDER_THAN_TS:
		if (end->protocol == 0 /* wild-card */ ||
		    end->protocol == ts->ipprotoid) {
			protocol = ts->ipprotoid;
		}
		break;
	default:
		bad_case(fit);
	}
	dbg(MATCH_PREFIX "narrow protocol end=%s%d %s %s[%u]=%s%d: %d",
	    end->protocol == 0 ? "*" : "", end->protocol,
	    fit_string(fit),
	    which, index, ts->ipprotoid == 0 ? "*" : "", ts->ipprotoid,
	    protocol);
	return protocol;
}

static int score_narrow_protocol(const struct end *end,
				 const struct traffic_selectors *tss,
				 enum fit fit,
				 const char *which, unsigned index)
{
	int f;	/* strength of match */

	int protocol = narrow_protocol(end, tss, fit, which, index);
	if (protocol == 0) {
		f = 255;	/* ??? odd value */
	} else if (protocol > 0) {
		f = 1;
	} else {
		f = 0;
	}
	LSWDBGP(DBG_BASE, buf) {
		const struct traffic_selector *ts = &tss->ts[index];
		jam(buf, MATCH_PREFIX "match end->protocol=%s%d %s %s[%u].ipprotoid=%s%d: ",
			end->protocol == 0 ? "*" : "", end->protocol,
			fit_string(fit),
			which, index, ts->ipprotoid == 0 ? "*" : "", ts->ipprotoid);
		if (f > 0) {
			jam(buf, "YES fitness %d", f);
		} else {
			jam(buf, "NO");
		}
	}
	return f;
}

/*
 * Narrow the END/TS ports according to FIT.
 *
 * Returns 0 (all ports), a specific port number, or -1 (no luck).
 *
 * Since 'struct end' only describes all-ports or a single port; only
 * narrow to that.
 */

static int narrow_port(const struct end *end,
		       const struct traffic_selectors *tss,
		       enum fit fit,
		       const char *which, unsigned index)
{
	passert(index < tss->nr);
	const struct traffic_selector *ts = &tss->ts[index];

	int end_low = end->port;
	int end_high = end->port == 0 ? 65535 : end->port;
	int port = -1;

	switch (fit) {
	case END_EQUALS_TS:
		if (end_low == ts->startport && ts->endport == end_high) {
			/* end=ts=0-65535 || end=ts=N-N */
			port = end_low;
		}
		break;
	case END_NARROWER_THAN_TS:
		if (ts->startport <= end_low && end_high <= ts->endport) {
			/* end=ts=0-65535 || ts=N<=end<=M */
			port = end_low;
		}
		break;
	case END_WIDER_THAN_TS:
		if (end_low < ts->startport && ts->endport < end_high &&
		    ts->startport == ts->endport) {
			/*ts=0<N-N<65535*/
			port = ts->startport;
		} else if (end_low == ts->startport && ts->endport == end_high) {
			/* end=ts=0-65535 || end=ts=N-N */
			port = ts->startport;
		}
		break;
	default:
		bad_case(fit);
	}
	dbg(MATCH_PREFIX "narrow port end=%u..%u %s %s[%u]=%u..%u: %d",
	    end_low, end_high,
	    fit_string(fit),
	    which, index, ts->startport, ts->endport,
	    port);
	return port;
}

/*
 * Assign a score to the narrowed port, rationale for score lost in
 * time?
 */

static int score_narrow_port(const struct end *end,
			     const struct traffic_selectors *tss,
			     enum fit fit,
			     const char *which, unsigned index)
{
	int f;	/* strength of match */

	int port = narrow_port(end, tss, fit, which, index);
	if (port > 0) {
		f = 1;
	} else if (port == 0) {
		f = 65536; /* from 1 + 65535-0 */
	} else {
		f = 0;
	}
	if (f > 0) {
		dbg(MATCH_PREFIX "  %s[%u] port match: YES fitness %d",
		    which, index, f);
	} else {
		dbg(MATCH_PREFIX "  %s[%u] port match: NO",
		    which, index);
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
 */

static int score_address_range(const struct end *end,
			       const struct traffic_selectors *tss,
			       enum fit fit,
			       const char *which, unsigned index)
{
	const struct traffic_selector *ts = &tss->ts[index];
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
	ip_range range = range_from_subnet(&end->client);
	passert(addrcmp(&range.start, &range.end) <= 0);
	passert(addrcmp(&ts->net.start, &ts->net.end) <= 0);
	switch (fit) {
	case END_EQUALS_TS:
		if (addrcmp(&range.start, &ts->net.start) == 0 &&
		    addrcmp(&range.end, &ts->net.end) == 0) {
			f = fitbits;
		}
		break;
	case END_NARROWER_THAN_TS:
		if (addrcmp(&range.start, &ts->net.start) >= 0 &&
		    addrcmp(&range.end, &ts->net.end) <= 0) {
			f = fitbits;
		}
		break;
	case END_WIDER_THAN_TS:
		if (addrcmp(&range.start, &ts->net.start) <= 0 &&
		    addrcmp(&range.end, &ts->net.end) >= 0) {
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

	LSWDBGP(DBG_BASE, buf) {
	    jam(buf, MATCH_PREFIX "match address end->client=");
	    jam_subnet(buf, &end->client);
	    jam(buf, " %s %s[%u]net=", fit_string(fit), which, index);
	    jam_range(buf, &ts->net);
	    jam(buf, ": ");
	    if (f > 0) {
		jam(buf, "YES fitness %d", f);
	    } else {
		jam(buf, "NO");
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
			      const struct traffic_selectors *tss,
			      enum fit fit,
			      const char *what, unsigned index)
{
	const struct traffic_selector *ts = &tss->ts[index];
	range_buf ts_net;

	if (ts->sec_label.len == 0) {
		dbg("    %s[%u] .net=%s .iporotoid=%d .{start,end}port=%d..%d",
			what, index,
			str_range(&ts->net, &ts_net),
			ts->ipprotoid,
			ts->startport,
			ts->endport);
	} else if (ts->sec_label.len != 0) {

		dbg("    %s[%u] security_label:%.*s",
			what, index,
			(int)ts->sec_label.len, ts->sec_label.ptr);
	} else {
		dbg("    %s[%u] unknown Traffic Selector Type",
			what, index);
	}

	struct score score = {
		.ok = false,
	};

	switch(ts->ts_type) {
	case IKEv2_TS_IPV4_ADDR_RANGE:
	case IKEv2_TS_IPV6_ADDR_RANGE:
		score.address = score_address_range(end, tss, fit, what, index);
		if (score.address <= 0) {
			return score;
		}
		score.port = score_narrow_port(end, tss, fit, what, index);
		if (score.port <= 0) {
			return score;
		}
		score.protocol = score_narrow_protocol(end, tss, fit, what, index);
		if (score.protocol <= 0) {
			return score;
		}
		score.ok = true;
		return score;
	case IKEv2_TS_SECLABEL:
	default:
		return score;
	}
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

static bool score_ends_seclabel(const struct ends *ends,
				const struct connection *d,
				const struct traffic_selectors *tsi,
				const struct traffic_selectors *tsr)
{
	/* sec_labels are symmetric, pick from one end */
	bool require_label = d->spd.this.sec_label.len != 0;
	bool recv_label_i = false;
	bool recv_label_r = false;
	bool match_i = false;
	bool match_r = false;

	for (unsigned tsi_n = 0; tsi_n < tsi->nr; tsi_n++) {
		const struct traffic_selector *cur = &tsi->ts[tsi_n];
		if (cur->ts_type == IKEv2_TS_SECLABEL) {
			recv_label_i = true;
			if (cur->sec_label.len == 0) {
				// complain loudly
				continue;
			} else {
				if (hunk_eq(ends->i->sec_label, cur->sec_label)) {
					match_i = true;
					dbg("PAUL: ikev2ts #1: hunk_eq matches security label");
				} else {
					dbg("PAUL: ikev2ts #1: hunk_eq does not match security label");
					DBG_dump_hunk("PAUL:ends->i->sec_label", ends->i->sec_label);
					DBG_dump_hunk("PAUL:cur->sec_label", cur->sec_label);
					continue; // hope for a better one
				}
			}

			for (unsigned tsr_n = 0; tsr_n < tsr->nr; tsr_n++) {
				const struct traffic_selector *cur = &tsr->ts[tsr_n];
				if (cur->ts_type == IKEv2_TS_SECLABEL) {
					recv_label_r = true;
					if (cur->sec_label.len == 0) {
						// complain loudly
						dbg("PAUL: IKEv2_TS_SECLABEL but zero length cur->sec_label");
						continue;
					} else {
						if (hunk_eq(ends->r->sec_label, cur->sec_label)) {
							dbg("PAUL: ikev2ts #2: hunk_eq matches security label");
							match_r = true;
						} else {
							dbg("PAUL: ikev2ts #2: hunk_eq does not match security label");
							DBG_dump_hunk("PAUL:ends->r->sec_label", ends->r->sec_label);
							DBG_dump_hunk("PAUL:cur->sec_label", cur->sec_label);
							continue; // hope for a better one
						}
					}
				}
			}
		}
	}

	if (recv_label_r != recv_label_i)
		return false;

	if (!require_label && !recv_label_i)
		return true;

	return require_label == recv_label_i && match_i && match_r;
}

static struct best_score score_ends_iprange(enum fit fit,
				    const struct connection *d,
				    const struct ends *ends,
				    const struct traffic_selectors *tsi,
				    const struct traffic_selectors *tsr)
{
	if (DBGP(DBG_BASE)) {
		selector_buf ei3;
		selector_buf er3;
		connection_buf cib;
		DBG_log("evaluating our conn="PRI_CONNECTION" I=%s:%d/%d R=%s:%d/%d%s to their:",
			pri_connection(d, &cib),
			str_selector(&ends->i->client, &ei3), ends->i->protocol, ends->i->port,
			str_selector(&ends->r->client, &er3), ends->r->protocol, ends->r->port,
			is_virtual_connection(d) ? " (virt)" : "");
	}

	struct best_score best_score = NO_SCORE;

	/* compare tsi/r array to this/that, evaluating how well it fits */
	for (unsigned tsi_n = 0; tsi_n < tsi->nr; tsi_n++) {
		const struct traffic_selector *tni = &tsi->ts[tsi_n];

		/* choice hardwired for IPrange and sec_label */
		struct score score_i = score_end(ends->i, tsi, fit, "TSi", tsi_n);
		if (!score_i.ok) {
			continue;
		}

		for (unsigned tsr_n = 0; tsr_n < tsr->nr; tsr_n++) {
			const struct traffic_selector *tnr = &tsr->ts[tsr_n];

			struct score score_r = score_end(ends->r, tsr, fit, "TSr", tsr_n);
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
				dbg("best fit so far: TSi[%d] TSr[%d]",
				    tsi_n, tsr_n);
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
	} else if (md->st == &ike_sa(&child->sa, HERE)->sa) {
		dbg("Child SA TS Request has ike->sa == md->st; so using parent connection");
	} else {
		dbg("Child SA TS Request has an unknown md->st; so using unknown connection");
	}
	struct connection *c = md->st->st_connection;

	struct traffic_selectors tsi = { .nr = 0, };
	struct traffic_selectors tsr = { .nr = 0, };
	if (!v2_parse_tss(md, &tsi, &tsr, child->sa.st_logger)) {
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


		if (!score_ends_seclabel(&ends, c, &tsi, &tsr)) {
			continue;
		}

		enum fit responder_fit =
			(c->policy & POLICY_IKEV2_ALLOW_NARROWING)
			? END_NARROWER_THAN_TS
			: END_EQUALS_TS;
		struct best_score score = score_ends_iprange(responder_fit, c, &ends, &tsi, &tsr);
		if (!score.ok) {
			continue;
		}

		if (score_gt(&score, &best_score)) {
			dbg("    found better spd route for TSi[%td],TSr[%td]",
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
				    &sra->that.host_addr);

		if (DBGP(DBG_BASE)) {
			selector_buf s2;
			selector_buf d2;
			DBG_log("  checking hostpair %s -> %s is %s",
				str_selector(&sra->this.client, &s2),
				str_selector(&sra->that.client, &d2),
				hp == NULL ? "not found" : "found");
		}

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

				if (!score_ends_seclabel(&ends, d, &tsi, &tsr))
					continue;
				struct best_score score = score_ends_iprange(responder_fit, d/*note D*/,
								     &ends, &tsi, &tsr);
				if (!score.ok) {
					continue;
				}
				if (score_gt(&score, &best_score)) {
					dbg("    protocol fitness found better match d %s, TSi[%td],TSr[%td]",
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

#define CONNECTION_POLICIES (POLICY_NEGO_PASS |				\
			     POLICY_DONT_REKEY |			\
			     POLICY_REAUTH |				\
			     POLICY_OPPORTUNISTIC |			\
			     POLICY_GROUP |				\
			     POLICY_GROUTED |				\
			     POLICY_GROUPINSTANCE |			\
			     POLICY_UP |				\
			     POLICY_XAUTH |				\
			     POLICY_MODECFG_PULL |			\
			     POLICY_AGGRESSIVE |			\
			     POLICY_OVERLAPIP |				\
			     POLICY_IKEV2_ALLOW_NARROWING)

	/*
	 * Try instantiating something better.
	 */
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
	} else if (best_spd_route == NULL &&
		   ((c->policy & POLICY_GROUPINSTANCE) ||
		    c->policy & POLICY_IKEV2_ALLOW_NARROWING)) {
		/*
		 * Is there something better than the current
		 * connection?
		 *
		 * Rather than overwrite the current INSTANCE; would
		 * it be better to instantiate a new instance, and
		 * then replace it?  Would also address the above.
		 */
		pexpect(c->kind == CK_INSTANCE);
		/* since an SPD_ROUTE wasn't found */
		passert(best_connection == c);
		dbg("no best spd route; looking for a better template connection to instantiate");

		dbg("FOR_EACH_CONNECTION_... in %s", __func__);
		for (struct connection *t = connections; t != NULL; t = t->ac_next) {
			/* require a template */
			if (t->kind != CK_TEMPLATE) {
				continue;
			}
			LSWDBGP(DBG_BASE, buf) {
				jam(buf, "  investigating template \"%s\";",
					t->name);
				if (t->foodgroup != NULL) {
					jam(buf, " food-group=\"%s\"", t->foodgroup);
				}
				jam(buf, " policy=");
				jam_policy(buf, t->policy & CONNECTION_POLICIES);
			}

			/*
			 * Is it worth looking at the template.
			 *
			 * XXX: treat the combination the same as
			 * group instance, like the old code did; is
			 * this valid?
			 */
			switch (c->policy & (POLICY_GROUPINSTANCE |
					     POLICY_IKEV2_ALLOW_NARROWING)) {
			case POLICY_GROUPINSTANCE:
			case POLICY_GROUPINSTANCE | POLICY_IKEV2_ALLOW_NARROWING: /* XXX: true */
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
				break;
			case POLICY_IKEV2_ALLOW_NARROWING:
				if (!LIN(POLICY_IKEV2_ALLOW_NARROWING, t->policy)) {
					dbg("    skipping; cannot narrow");
					continue;
				}
				break;
			default:
				bad_case(c->policy); /* not quite true */
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

			/* require a valid narrowed port? */
			enum fit fit;
			switch (c->policy & (POLICY_GROUPINSTANCE |
					     POLICY_IKEV2_ALLOW_NARROWING)) {
			case POLICY_GROUPINSTANCE:
			case POLICY_GROUPINSTANCE | POLICY_IKEV2_ALLOW_NARROWING: /* XXX: true */
				/* exact match; XXX: 'cos that is what old code did */
				fit = END_EQUALS_TS;
				break;
			case POLICY_IKEV2_ALLOW_NARROWING:
				/* narrow END's port to TS port */
				fit = END_WIDER_THAN_TS;
				break;
			default:
				bad_case(c->policy);
			}

			passert(tsi.nr >= 1);
			int tsi_port = narrow_port(&t->spd.that, &tsi,
						   fit, "TSi", 0);
			if (tsi_port < 0) {
				dbg("    skipping; TSi port too wide");
				continue;
			}
			int tsi_protocol = narrow_protocol(&t->spd.that, &tsi,
							   fit, "TSi", 0);
			if (tsi_protocol < 0) {
				dbg("    skipping; TSi protocol too wide");
				continue;
			}

			passert(tsr.nr >= 1);
			int tsr_port = narrow_port(&t->spd.this, &tsr,
						   fit, "TRi", 0);
			if (tsr_port < 0) {
				dbg("    skipping; TSr port too wide");
				continue;
			}
			int tsr_protocol = narrow_protocol(&t->spd.this, &tsr,
							   fit, "TSr", 0);
			if (tsr_protocol < 0) {
				dbg("    skipping; TSr protocol too wide");
				continue;
			}

			passert(best_connection == c); /* aka st->st_connection, no leak */

			bool shared = v2_child_connection_probably_shared(child);
			if (shared) {
				/* instantiate it, filling in peer's ID */
				best_connection = instantiate(t, &c->spd.that.host_addr,
							      NULL);
			}

			/* "this" == responder; see function name */
			best_connection->spd.this.port = tsr_port;
			best_connection->spd.that.port = tsi_port;
			best_connection->spd.this.protocol = tsr_protocol;
			best_connection->spd.that.protocol = tsi_protocol;
			best_spd_route = &best_connection->spd;

			if (shared) {
				char old[CONN_INST_BUF];
				char new[CONN_INST_BUF];
				dbg("switching from \"%s\"%s to \"%s\"%s",
				    c->name, fmt_conn_instance(c, old),
				    best_connection->name, fmt_conn_instance(best_connection, new));
			} else {
				char cib[CONN_INST_BUF];
				dbg("  overwrote connection with instance %s%s",
				    best_connection->name, fmt_conn_instance(best_connection, cib));
			}
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
	 * state.
	 *
	 * XXX: ah, but the state code does: set-state; set-connection
	 * (yes order is wrong).  Why does it bother?
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
	if (!v2_parse_tss(md, &tsi, &tsr, child->sa.st_logger)) {
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

	if (!score_ends_seclabel(&e, c, &tsi, &tsr))
		return false;

	struct best_score best = score_ends_iprange(initiator_widening, c, &e, &tsi, &tsr);

	if (!best.ok) {
		dbg("reject responder TSi/TSr Traffic Selector");
		/* prevents parent from going to I3 */
		return false;
	}

	dbg("found an acceptable TSi/TSr Traffic Selector");
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
	update_selector_hport(&c->spd.this.client, c->spd.this.port);

	c->spd.this.has_client =
		!(subnetishost(&c->spd.this.client) &&
		  addrinsubnet(&c->spd.this.host_addr,
			       &c->spd.this.client));

	c->spd.that.client = tmp_subnet_r;
	c->spd.that.port = st->st_ts_that.startport;
	c->spd.that.protocol = st->st_ts_that.ipprotoid;
	update_selector_hport(&c->spd.that.client, c->spd.that.port),

	c->spd.that.has_client =
		!(subnetishost(&c->spd.that.client) &&
		  addrinsubnet(&c->spd.that.host_addr,
			       &c->spd.that.client));

	return true;
}

/*
 * RFC 7296 https://tools.ietf.org/html/rfc7296#section-2.8
 * "when rekeying, the new Child SA SHOULD NOT have different Traffic
 *  Selectors and algorithms than the old one."
 *
 * However, when narrowed down, the original TSi/TSr is wider than the
 * returned narrowed TSi/TSr. Windows 10 is known to use the original
 * and not the narrowed TSi/TSr.
 *
 * RFC 7296 #1.3.3 "The Traffic Selectors for traffic to be sent
 * on that SA are specified in the TS payloads in the response,
 * which may be a subset of what the initiator of the Child SA proposed."
 *
 * However, the rekey initiator, when it is the original initiator of
 * the Child SA, may request a super set. And responder should
 * respond with same set as initially negotiated, ie RFC 7296 #2.8
 *
 * See RFC 7296 Section 1.7. for the above change.
 * Significant Differences between RFC 4306 and RFC 5996
 *
 * We already matched the right connection by the SPI of v2N_REKEY_SA
 */
bool child_rekey_responder_ts_verify(struct child_sa *child, struct msg_digest *md)
{
	if (!pexpect(child->sa.st_state->kind == STATE_V2_REKEY_CHILD_R0))
		return false;

	const struct connection *c = child->sa.st_connection;
	struct traffic_selectors their_tsis = { .nr = 0, };
	struct traffic_selectors their_tsrs = { .nr = 0, };

	if (!v2_parse_tss(md, &their_tsis, &their_tsrs, child->sa.st_logger)) {
		log_state(RC_LOG_SERIOUS, &child->sa,
			  "received malformed TSi/TSr payload(s)");
		return false;
	}

	const struct ends ends = {
		.i = &c->spd.that,
		.r = &c->spd.this,
	};

	enum fit fitness = END_NARROWER_THAN_TS;

	if (!score_ends_seclabel(&ends, c, &their_tsis, &their_tsrs)) {
		log_state(RC_LOG_SERIOUS, &child->sa,
			  "rekey: received Traffic Selectors mismatch configured selectors for Security Label");
		return false;
	}

	struct best_score score = score_ends_iprange(fitness, c, &ends, &their_tsis,
			&their_tsrs);

	if (!score.ok) {
		log_state(RC_LOG_SERIOUS, &child->sa,
			  "rekey: received Traffic Selectors does not contain existing IPsec SA Traffic Selectors");
		return false;
	}

	return true;
}
