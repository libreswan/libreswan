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
 * Copyright (C) 2021 Paul Wouters <paul.wouters@aiven.io>
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
#include "host_pair.h"
#include "ip_info.h"
#include "ip_selector.h"
#include "labeled_ipsec.h"
#include "ip_range.h"
#include "iface.h"

/*
 * While the RFC seems to suggest that the traffic selectors come in
 * pairs, strongswan, at least, doesn't.
 */

struct traffic_selectors {
	const char *name;
	bool contains_sec_label;
	unsigned nr;
	/* ??? is 16 an undocumented limit - IKEv2 has no limit */
	struct traffic_selector ts[16];
};

struct traffic_selector_payloads {
	struct traffic_selectors i;
	struct traffic_selectors r;
};

static const struct traffic_selector_payloads empty_traffic_selectors = {
	.i = {
		.name = "TSi",
	},
	.r = {
		.name = "TSr",
	},
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

void dbg_v2_ts(const struct traffic_selector *ts, const char *prefix, ...)
{
	if (DBGP(DBG_BASE)) {
		va_list ap;
		va_start(ap, prefix);
		DBG_va_list(prefix, ap);
		va_end(ap);
		DBG_log("  ts_type: %s", enum_name(&ikev2_ts_type_names, ts->ts_type));
		DBG_log("  ipprotoid: %d", ts->ipprotoid);
		DBG_log("  port range: %d-%d", ts->startport, ts->endport);
		range_buf b;
		DBG_log("  ip range: %s", str_range(&ts->net, &b));
		DBG_log("  sec_label: "PRI_SHUNK, pri_shunk(ts->sec_label));
	}
}

static void traffic_selector_to_end(const struct traffic_selector *ts, struct end *end,
				    const char *story)
{
	dbg_v2_ts(ts, "%s() %s", __func__, story);
	ip_subnet subnet;
	happy(range_to_subnet(ts->net, &subnet));
	const ip_protocol *protocol = protocol_by_ipproto(ts->ipprotoid);
	/* XXX: check port range valid */
	ip_port port = ip_hport(ts->startport);
	end->client = selector_from_subnet_protocol_port(subnet, protocol, port);
	/* redundant */
	end->port = ts->startport;
	end->protocol = ts->ipprotoid;
	end->has_client = !selector_eq_address(end->client, end->host_addr);
}

/* rewrite me with address_as_{chunk,shunk}()? */
/* For now, note the struct traffic_selector can contain
 * two selectors - an IPvX range and a sec_label
 */
struct traffic_selector traffic_selector_from_end(const struct end *e, const char *what)
{
	struct traffic_selector ts = {
		/*
		 * Setting ts_type IKEv2_TS_FC_ADDR_RANGE (RFC-4595)
		 * not yet supported.
		 */
		.ts_type = selector_type(&e->client)->ikev2_ts_addr_range_type,
		/* subnet => range */
		.net = selector_range(e->client),
		.ipprotoid = e->protocol,
		/*
		 * Use the 'instance/narrowed' label from the ACQUIRE
		 * and stored in the connection instance's sends, if
		 * present.
		 */
		.sec_label = HUNK_AS_SHUNK(e->sec_label),
	};

	/*
	 * if port is %any or 0 we mean all ports (or all
	 * iccmp/icmpv6).
	 *
	 * See RFC-5996 Section 3.13.1 handling for ICMP(1) and
	 * ICMPv6(58) we only support providing Type, not Code, eg
	 * protoport=1/1
	 */
	if (e->port == 0 || e->has_port_wildcard) {
		ts.startport = 0;
		ts.endport = 65535;
	} else {
		ts.startport = e->port;
		ts.endport = e->port;
	}

	dbg_v2_ts(&ts, "%s TS", what);
	return ts;
}

/*
 * A struct end is converted to a struct traffic_selector.
 *
 * This (currently) can contain both an IP range AND a SEC_LABEL,
 * which will get output here as two Traffic Selectors. The label is
 * optional, the IP range is mandatory.
 */
static stf_status emit_v2TS(struct pbs_out *outpbs,
			    const struct_desc *ts_desc,
			    const struct traffic_selector *ts)
{
	struct pbs_out ts_pbs;
	bool with_label = (ts->sec_label.len > 0);

	if (ts->ts_type != IKEv2_TS_IPV4_ADDR_RANGE &&
	    ts->ts_type != IKEv2_TS_IPV6_ADDR_RANGE) {
		return STF_INTERNAL_ERROR;
	}

	{
		struct ikev2_ts its = {
			.isat_critical = ISAKMP_PAYLOAD_NONCRITICAL,
			/*
			 * If there is a security label in the Traffic
			 * Selector, then we must send a TS_SECLABEL
			 * substructure as part of the Traffic
			 * Selector (TS) Payload.
			 *
			 * That means the TS Payload contains two TS
			 * substructures:
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
		d = pbs_out_address(&ts_range_pbs, range_start(ts->net), "IP start");
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, outpbs->outs_logger, &d, "%s", "");
			return STF_INTERNAL_ERROR;
		}
		d = pbs_out_address(&ts_range_pbs, range_end(ts->net), "IP end");
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, outpbs->outs_logger, &d, "%s", "");
			return STF_INTERNAL_ERROR;
		}
		close_output_pbs(&ts_range_pbs);
	}

	/*
	 * Emit the security label, if known.
	 */
	if (with_label) {

		struct ikev2_ts_header ts_header = {
			.isath_type = IKEv2_TS_SECLABEL,
			.isath_ipprotoid = 0 /* really RESERVED, not iprotoid */
		};
		/* Output the header of the TS_SECLABEL substructure payload. */
		struct pbs_out ts_label_pbs;
		if (!out_struct(&ts_header, &ikev2_ts_header_desc, &ts_pbs, &ts_label_pbs)) {
			return STF_INTERNAL_ERROR;
		}

		/*
		 * Output the security label value of the TS_SECLABEL
		 * substructure payload.
		 *
		 * If we got ACQUIRE, or received a subset TS_LABEL,
		 * use that one - it is subset of connection policy
		 * one
		 */

		dbg("emitting sec_label="PRI_SHUNK, pri_shunk(ts->sec_label));

		diag_t d = pbs_out_hunk(&ts_label_pbs, ts->sec_label, "output Security label");
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, outpbs->outs_logger, &d, "%s", "");
			return STF_INTERNAL_ERROR;
		}

		close_output_pbs(&ts_label_pbs);
	}

	close_output_pbs(&ts_pbs);
	return STF_OK;
}

static struct traffic_selector impair_ts_to_subnet(const struct traffic_selector ts)
{
	struct traffic_selector ts_ret = ts;

	ts_ret.net.end = ts_ret.net.start;
	ts_ret.net.is_subnet = true;

	return ts_ret;
}


static struct traffic_selector impair_ts_to_supernet(const struct traffic_selector ts)
{
	struct traffic_selector ts_ret = ts;

	if (ts_ret.ts_type == IKEv2_TS_IPV4_ADDR_RANGE)
		ts_ret.net = range_from_subnet(ipv4_info.subnet.all);
	else if (ts_ret.ts_type == IKEv2_TS_IPV6_ADDR_RANGE)
		ts_ret.net = range_from_subnet(ipv6_info.subnet.all);

	ts_ret.net.is_subnet = true;

	ts_ret.sec_label = ts.sec_label;

	return ts_ret;
}

stf_status emit_v2TS_payloads(struct pbs_out *outpbs, const struct child_sa *child)
{
	stf_status ret;
	struct traffic_selector ts_i, ts_r;

	switch (child->sa.st_sa_role) {
	case SA_INITIATOR:
		ts_i = traffic_selector_from_end(&child->sa.st_connection->spd.this, "this TSi");
		ts_r = traffic_selector_from_end(&child->sa.st_connection->spd.that, "that TSr");
		if (child->sa.st_state->kind == STATE_V2_REKEY_CHILD_I0 &&
		    impair.rekey_initiate_supernet) {
			ts_i = ts_r = impair_ts_to_supernet(ts_i);
			range_buf tsi_buf;
			range_buf tsr_buf;
			dbg("rekey-initiate-supernet TSi and TSr set to %s %s",
					str_range(&ts_i.net, &tsi_buf),
					str_range(&ts_r.net, &tsr_buf));

		} else if (child->sa.st_state->kind == STATE_V2_REKEY_CHILD_I0 &&
			   impair.rekey_initiate_subnet) {
			ts_i = impair_ts_to_subnet(ts_i);
			ts_r = impair_ts_to_subnet(ts_r);
			range_buf tsi_buf;
			range_buf tsr_buf;
			dbg("rekey-initiate-subnet TSi and TSr set to %s %s",
					str_range(&ts_i.net, &tsi_buf),
					str_range(&ts_r.net, &tsr_buf));

		}

		break;
	case SA_RESPONDER:
		ts_i = traffic_selector_from_end(&child->sa.st_connection->spd.that, "that TSi");
		ts_r = traffic_selector_from_end(&child->sa.st_connection->spd.this, "this TSr");
		if (child->sa.st_state->kind == STATE_V2_REKEY_CHILD_R0 &&
		    impair.rekey_respond_subnet) {
			ts_i = impair_ts_to_subnet(ts_i);
			ts_r = impair_ts_to_subnet(ts_r);
			range_buf tsi_buf;
			range_buf tsr_buf;
			dbg("rekey-respond-subnet TSi and TSr set to %s %s",
					str_range(&ts_i.net, &tsi_buf),
					str_range(&ts_r.net, &tsr_buf));
		}
		if (child->sa.st_state->kind == STATE_V2_REKEY_CHILD_R0 &&
				impair.rekey_respond_supernet) {
			ts_i = ts_r = impair_ts_to_supernet(ts_i);
			range_buf tsi_buf;
			range_buf tsr_buf;
			dbg("rekey-respond-supernet TSi and TSr set to %s %s",
					str_range(&ts_i.net, &tsi_buf),
					str_range(&ts_r.net, &tsr_buf));
		}
		break;
	default:
		bad_case(child->sa.st_sa_role);
	}

	ret = emit_v2TS(outpbs, &ikev2_ts_i_desc, &ts_i);
	if (ret != STF_OK)
		return ret;

	ret = emit_v2TS(outpbs, &ikev2_ts_r_desc, &ts_r);
	if (ret != STF_OK)
		return ret;

	return STF_OK;
}

/* return success */
static bool v2_parse_tss(struct payload_digest *const ts_pd,
			 struct traffic_selectors *tss,
			 struct logger *logger)
{
	dbg("%s: parsing %u traffic selectors",
	    tss->name, ts_pd->payload.v2ts.isat_num);

	if (ts_pd->payload.v2ts.isat_num == 0) {
		llog(RC_LOG, logger,
		     "%s payload contains no entries when at least one is expected",
		     tss->name);
		return false;
	}

	if (ts_pd->payload.v2ts.isat_num >= elemsof(tss->ts)) {
		llog(RC_LOG, logger,
		     "%s contains %d entries which exceeds hardwired max of %zu",
		     tss->name, ts_pd->payload.v2ts.isat_num, elemsof(tss->ts));
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
				llog_diag(RC_LOG, logger, &d, "%s", "");
				return false;
			}

			ts->startport = pr.isatpr_startport;
			ts->endport = pr.isatpr_endport;

			if (ts->startport > ts->endport) {
				llog(RC_LOG, logger,
				     "%s traffic selector %d has an invalid port range - ignored",
				     tss->name, tss->nr);
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

			ip_address start;
			d = pbs_in_address(&ts_body_pbs, &start, ipv, "TS IP start");
			if (d != NULL) {
				llog_diag(RC_LOG, logger, &d, "%s", "");
				return false;
			}

			ip_address end;
			d = pbs_in_address(&ts_body_pbs, &end, ipv, "TS IP end");
			if (d != NULL) {
				llog_diag(RC_LOG, logger, &d, "%s", "");
				return false;
			}

			/* XXX: does this matter? */
			if (pbs_left(&ts_body_pbs) != 0)
				return false;

			err_t err = addresses_to_nonzero_range(start, end, &ts->net);

			/* pluto doesn't yet do full ranges; check for subnet */
			ip_subnet ignore;
			err = err == NULL ? range_to_subnet(ts->net, &ignore) : err;

			if (err != NULL) {
				address_buf sb, eb;
				llog(RC_LOG, logger, "Traffic Selector range %s-%s invalid: %s",
				     str_address_sensitive(&start, &sb),
				     str_address_sensitive(&end, &eb),
				     err);
				return false;
			}

			ts->ts_type = ts_h.isath_type;
			break;
		}

		case IKEv2_TS_SECLABEL:
		{
			if (ts_h.isath_ipprotoid != 0) {
				llog(RC_LOG, logger, "Traffic Selector of type Security Label should not have non-zero IP protocol '%u' - ignored",
					ts_h.isath_ipprotoid);
			}

			shunk_t sec_label = pbs_in_left_as_shunk(&ts_body_pbs);
			err_t ugh = vet_seclabel(sec_label);
			if (ugh != NULL) {
				llog(RC_LOG, logger, "Traffic Selector %s", ugh);
				/* ??? should we just ignore?  If so, use continue */
				return false;
			}

			ts->sec_label = sec_label;
			ts->ts_type = ts_h.isath_type;
			tss->contains_sec_label = true;
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

	dbg("%s: parsed %d traffic selectors", tss->name, tss->nr);
	return true;
}

static bool v2_parse_tsp(const struct msg_digest *md,
			 struct traffic_selector_payloads *tsp,
			 struct logger *logger)
{
	if (!v2_parse_tss(md->chain[ISAKMP_NEXT_v2TSi], &tsp->i, logger)) {
		return false;
	}

	if (!v2_parse_tss(md->chain[ISAKMP_NEXT_v2TSr], &tsp->r, logger)) {
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
			   enum fit fit, unsigned index)
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
	    tss->name, index, ts->ipprotoid == 0 ? "*" : "", ts->ipprotoid,
	    protocol);
	return protocol;
}

static int score_narrow_protocol(const struct end *end,
				 const struct traffic_selectors *tss,
				 enum fit fit, unsigned index)
{
	int f;	/* strength of match */

	int protocol = narrow_protocol(end, tss, fit, index);
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
			tss->name, index, ts->ipprotoid == 0 ? "*" : "", ts->ipprotoid);
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
		       enum fit fit, unsigned index)
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
	    tss->name, index, ts->startport, ts->endport,
	    port);
	return port;
}

/*
 * Assign a score to the narrowed port, rationale for score lost in
 * time?
 */

static int score_narrow_port(const struct end *end,
			     const struct traffic_selectors *tss,
			     enum fit fit, unsigned index)
{
	int f;	/* strength of match */

	int port = narrow_port(end, tss, fit, index);
	if (port > 0) {
		f = 1;
	} else if (port == 0) {
		f = 65536; /* from 1 + 65535-0 */
	} else {
		f = 0;
	}
	if (f > 0) {
		dbg(MATCH_PREFIX "  %s[%u] port match: YES fitness %d",
		    tss->name, index, f);
	} else {
		dbg(MATCH_PREFIX "  %s[%u] port match: NO",
		    tss->name, index);
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
			       enum fit fit, unsigned index)
{
	const struct traffic_selector *ts = &tss->ts[index];
	/*
	 * Pre-compute possible fit --- sum of bits gives how good a
	 * fit this is.
	 */
	int ts_range = range_host_bits(ts->net);
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
	ip_range range = selector_range(end->client);
	switch (fit) {
	case END_EQUALS_TS:
		if (range_eq_range(range, ts->net)) {
			f = fitbits;
		}
		break;
	case END_NARROWER_THAN_TS:
		if (range_in_range(range, ts->net)) {
			f = fitbits;
		}
		break;
	case END_WIDER_THAN_TS:
		if (range_in_range(ts->net, range)) {
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
	    jam_selector(buf, &end->client);
	    jam(buf, " %s %s[%u]net=", fit_string(fit), tss->name, index);
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
			      enum fit fit, unsigned index)
{
	const struct traffic_selector *ts = &tss->ts[index];

	LSWDBGP(DBG_BASE, buf) {
		jam(buf, "    %s[%u] ", tss->name, index);
		if (ts->sec_label.len == 0) {
			range_buf ts_net;
			jam(buf, ".net=%s .iporotoid=%d .{start,end}port=%d..%d",
			    str_range(&ts->net, &ts_net),
			    ts->ipprotoid,
			    ts->startport,
			    ts->endport);
		} else if (ts->sec_label.len != 0) {
			/* XXX: assumes sec label is printable */
			jam(buf, "security_label:");
			jam_sanitized_hunk(buf, ts->sec_label);
		} else {
			jam(buf, "unknown Traffic Selector Type");
		}
	}

	struct score score = {
		.ok = false,
	};

	switch(ts->ts_type) {
	case IKEv2_TS_IPV4_ADDR_RANGE:
	case IKEv2_TS_IPV6_ADDR_RANGE:
		score.address = score_address_range(end, tss, fit, index);
		if (score.address <= 0) {
			return score;
		}
		score.port = score_narrow_port(end, tss, fit, index);
		if (score.port <= 0) {
			return score;
		}
		score.protocol = score_narrow_protocol(end, tss, fit, index);
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

/*
 * Return true for sec_label expected and good XOR not expected and
 * not present.
 *
 * Return false when required sec_label is missing or bad; or
 * sec_label encountered when it wasn't expected.
 *
 * The code calls sec_label_within_range() to check that the "source
 * context has the access permission for the specified class on the
 * "target context" (see selinux_check_access()):
 *
 * - for the initiator searching for a matching template connection to
 *   instantiate, the "source context" is the sec_label from acquire,
 *   and the "target context" is the sec_label in the template
 *   connection.
 *
 * - for the responder searching for a template connection to match
 *   the on-wire TS, the "source context" is the sec_label included in
 *   the traffic selector, and the "target context" is (again) the
 *   sec_label in the template connection.
 *
 * However, when the initiator gets back the responder's accepted TS
 * containing a sec_label, the initiator only checks it is identical
 * to what was sent out in the initiator's TS:
 *
 * - the RFC makes vague references to narrowing; but what that means
 *   for sec_labels isn't clear
 *
 * - one interpretation, that the responder's "source context" has
 *   "access permission" for the initiator's "source context" seems to
 *   always fail when enforcing is enabled (suspect
 *   selinux_check_access() requires a "ptarget context").
 */

enum sec_label_compare {
	TS_WITHIN_CONNECTION_SEC_LABEL = 1,
	TS_EQUALS_CONNECTION_SEC_LABEL,
};

static bool check_tss_sec_label(enum sec_label_compare compare,
				const struct traffic_selectors *tss,
				chunk_t connection_sec_label,
				shunk_t *selected_sec_label,
				struct logger *logger)
{
	passert(tss->contains_sec_label);

	*selected_sec_label = null_shunk;
	for (unsigned i = 0; i < tss->nr; i++) {
		const struct traffic_selector *ts = &tss->ts[i];
		if (ts->ts_type != IKEv2_TS_SECLABEL) {
			continue;
		}

		passert(vet_seclabel(ts->sec_label) == NULL);

		switch (compare) {
		case TS_WITHIN_CONNECTION_SEC_LABEL:
			if (!sec_label_within_range(ts->sec_label, connection_sec_label, logger)) {
				dbg("ikev2ts: %s sec_label="PRI_SHUNK" is not within range connection sec_label="PRI_SHUNK,
				    tss->name, pri_shunk(ts->sec_label), pri_shunk(connection_sec_label));
				continue;
			}
			break;
		case TS_EQUALS_CONNECTION_SEC_LABEL:
			if (!hunk_eq(ts->sec_label, connection_sec_label)) {
				dbg("ikev2ts: %s sec_label="PRI_SHUNK" is not equal to connection sec_label="PRI_SHUNK,
				    tss->name, pri_shunk(ts->sec_label), pri_shunk(connection_sec_label));
				continue;
			}
			break;
		}

		dbg("ikev2ts: received %s label within range of our security label",
		    tss->name);

		/* XXX we return the first match.  Should we return the best? */
		*selected_sec_label = ts->sec_label;	/* first match */
		return true;
	}

	return false;
}

static bool score_tsp_sec_label(enum sec_label_compare compare,
				const struct traffic_selector_payloads *tsp,
				chunk_t connection_sec_label,
				shunk_t *selected_sec_label,
				struct logger *logger)
{
	if (connection_sec_label.len == 0) {
		/* This endpoint is not configured to use labeled IPsec. */
		if (tsp->i.contains_sec_label || tsp->r.contains_sec_label) {
			dbg("error: received sec_label but this end is *not* configured to use sec_label");
			return false;
		}
		/* No sec_label was found and none was expected */
		return true;	/* success: no label, as expected */
	}

	/* This endpoint is configured to use labeled IPsec. */
	passert(vet_seclabel(HUNK_AS_SHUNK(connection_sec_label)) == NULL);

	if (!tsp->i.contains_sec_label || !tsp->r.contains_sec_label) {
		dbg("error: connection requires sec_label but not received TSi/TSr with sec_label");
		return false;
	}

	if (!check_tss_sec_label(compare, &tsp->i, connection_sec_label, selected_sec_label, logger) ||
	    !check_tss_sec_label(compare, &tsp->r, connection_sec_label, selected_sec_label, logger)) {
		return false;
	}

	/* security label required and matched */
	return true;
}

static struct best_score score_ends_iprange(enum fit fit,
					    const struct connection *d,
					    const struct ends *ends,
					    const struct traffic_selector_payloads *tsp)
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
	for (unsigned tsi_n = 0; tsi_n < tsp->i.nr; tsi_n++) {
		const struct traffic_selector *tni = &tsp->i.ts[tsi_n];

		/* choice hardwired for IPrange and sec_label */
		struct score score_i = score_end(ends->i, &tsp->i, fit, tsi_n);
		if (!score_i.ok) {
			continue;
		}

		for (unsigned tsr_n = 0; tsr_n < tsp->r.nr; tsr_n++) {
			const struct traffic_selector *tnr = &tsp->r.ts[tsr_n];

			struct score score_r = score_end(ends->r, &tsp->r, fit, tsr_n);
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

static struct connection *scribble_ts_on_connection(struct connection *t, struct child_sa *child,
						    const struct traffic_selector_payloads *tsp,
						    enum fit fit, bool definitely_shared,
						    const shunk_t best_sec_label)
{
	passert(tsp->i.nr >= 1);
	int tsi_port = narrow_port(&t->spd.that, &tsp->i, fit, 0);
	if (tsi_port < 0) {
		dbg("    skipping; TSi port too wide");
		return NULL;
	}

	int tsi_protocol = narrow_protocol(&t->spd.that, &tsp->r, fit, 0);
	if (tsi_protocol < 0) {
		dbg("    skipping; TSi protocol too wide");
		return NULL;
	}

	passert(tsp->r.nr >= 1);
	int tsr_port = narrow_port(&t->spd.this, &tsp->r, fit, 0);
	if (tsr_port < 0) {
		dbg("    skipping; TSr port too wide");
		return NULL;
	}

	int tsr_protocol = narrow_protocol(&t->spd.this, &tsp->r, fit, 0);
	if (tsr_protocol < 0) {
		dbg("    skipping; TSr protocol too wide");
		return NULL;
	}

	struct connection *c;
	if (definitely_shared || v2_child_connection_probably_shared(child)) {
		/* instantiate it, filling in peer's ID */
		c = instantiate(t, &child->sa.st_connection->spd.that.host_addr, NULL);
	} else {
		c = child->sa.st_connection;
	}

	/* "this" == responder; see function name */
	c->spd.this.port = tsr_port;
	c->spd.that.port = tsi_port;
	c->spd.this.protocol = tsr_protocol;
	c->spd.that.protocol = tsi_protocol;
	/* hack */
	dbg("XXX: updating best connection's ports/protocols");
	update_selector_hport(&c->spd.this.client, tsr_port);
	update_selector_hport(&c->spd.that.client, tsi_port);
	update_selector_ipproto(&c->spd.this.client, tsr_protocol);
	update_selector_ipproto(&c->spd.that.client, tsi_protocol);

	free_chunk_content(&c->spd.this.sec_label);
	free_chunk_content(&c->spd.that.sec_label);
	if (best_sec_label.len > 0) {
		connection_buf tb;
		dbg("responder storing sec_label="PRI_SHUNK" in "PRI_CONNECTION,
		    pri_shunk(best_sec_label), pri_connection(c, &tb));
		c->spd.this.sec_label = clone_hunk(best_sec_label, "this_sec_label");
		c->spd.that.sec_label = clone_hunk(best_sec_label, "that_sec_label");
	}

	if (c != child->sa.st_connection) {
		connection_buf from, to;
		dbg("  switching #%lu from "PRI_CONNECTION" to just-instantiated "PRI_CONNECTION,
		    child->sa.st_serialno,
		    pri_connection(child->sa.st_connection, &from),
		    pri_connection(c, &to));
	} else {
		connection_buf cib;
		dbg("  overwrote #%lu connection "PRI_CONNECTION,
		    child->sa.st_serialno, pri_connection(c, &cib));
	}
	return c;
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
	struct connection *c = child->sa.st_connection;

	struct traffic_selector_payloads tsp = empty_traffic_selectors;
	if (!v2_parse_tsp(md, &tsp, child->sa.st_logger)) {
		return false;
	}

	/* best so far; start with state's connection */
	struct best_score best_score = NO_SCORE;
	const struct spd_route *best_spd_route = NULL;
	struct connection *best_connection = c;
	shunk_t best_sec_label = null_shunk;

	/* find best spd in c */

	connection_buf ccb;
	dbg("responder looking for best SPD in current connection "PRI_CONNECTION,
	    pri_connection(c, &ccb));
	for (const struct spd_route *sra = &c->spd; sra != NULL; sra = sra->spd_next) {

		/* responder */
		const struct ends ends = {
			.i = &sra->that,
			.r = &sra->this,
		};

		shunk_t selected_sec_label = null_shunk;
		if (!score_tsp_sec_label(TS_WITHIN_CONNECTION_SEC_LABEL,
					 &tsp, c->spd.this.sec_label,
					 &selected_sec_label,
					 child->sa.st_logger)) {
			/*
			 * Either:
			 *  - Security label required, but not found.
			 *    OR
			 *  - Security label *not* required, but found.
			 */
			continue;
		}

		enum fit responder_fit =
			(c->policy & POLICY_IKEV2_ALLOW_NARROWING)
			? END_NARROWER_THAN_TS
			: END_EQUALS_TS;
		struct best_score score = score_ends_iprange(responder_fit, c, &ends, &tsp);
		if (!score.ok) {
			continue;
		}

		if (score_gt(&score, &best_score)) {
			dbg("    found better spd route for TSi[%td],TSr[%td]",
			    score.tsi - tsp.i.ts, score.tsr - tsp.r.ts);
			best_score = score;
			best_spd_route = sra;
			best_sec_label = selected_sec_label;
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

	const ip_address local = md->iface->ip_dev->id_address;
	FOR_EACH_THING(remote, endpoint_address(md->sender), unset_address) {

		FOR_EACH_HOST_PAIR_CONNECTION(local, remote, d) {

			/* groups are templates instantiated as GROUPINSTANCE */
			if (d->policy & POLICY_GROUP) {
				continue;
			}

			/*
			 * For labeled IPsec, always start with the
			 * template.  Who are we to argue if the
			 * kernel asks for a new SA with, seemingly, a
			 * security label that matches an existing
			 * connection instance.
			 */
			if (c->ike_version == IKEv2 && c->spd.this.sec_label.len > 0 && c->kind != CK_TEMPLATE) {
				connection_buf cb;
				dbg("skipping non-template IKEv2 "PRI_CONNECTION" with a security label",
				    pri_connection(c, &cb));
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

			/* conns created as aliases from the same source have identical ID/CA */
			if (!(c->connalias != NULL && d->connalias != NULL && streq(c->connalias, d->connalias))) {
				if (!(same_id(&c->spd.this.id, &d->spd.this.id) &&
					match_id(&c->spd.that.id, &d->spd.that.id, &wildcards) &&
					trusted_ca_nss(c->spd.that.ca, d->spd.that.ca, &pathlen)))
				{
					dbg("    connection \"%s\" does not match IDs or CA of current connection \"%s\"",
						d->name, c->name);
					continue;
				}
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

				/* Returns NULL(ok), &null_shunk(skip), memory(ok). */
				shunk_t selected_sec_label = null_shunk;
				if (!score_tsp_sec_label(TS_WITHIN_CONNECTION_SEC_LABEL,
							 &tsp, d->spd.this.sec_label,
							 &selected_sec_label, child->sa.st_logger)) {
					/*
					 * Either:
					 *  - Security label required, but not found.
					 *    OR
					 *  - Security label *not* required, but found.
					 */
					continue;
				}

				struct best_score score = score_ends_iprange(responder_fit, d/*note D*/,
									     &ends, &tsp);
				if (!score.ok) {
					continue;
				}
				if (score_gt(&score, &best_score)) {
					dbg("    protocol fitness found better match d %s, TSi[%td],TSr[%td]",
					    d->name,
					    score.tsi - tsp.i.ts, score.tsr - tsp.r.ts);
					best_connection = d;
					best_score = score;
					best_spd_route = sr;
					best_sec_label = selected_sec_label;
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
		pexpect((c->kind == CK_PERMANENT) ||
			(c->kind == CK_TEMPLATE && c->spd.this.sec_label.len > 0));
		dbg("no best spd route; but the current %s connection \"%s\" is not a CK_INSTANCE; giving up",
		    enum_name(&connection_kind_names, c->kind), c->name);
		llog_sa(RC_LOG_SERIOUS, child, "No IKEv2 connection found with compatible Traffic Selectors");
		return false;
	}

	if (best_spd_route == NULL && ((c->policy & POLICY_GROUPINSTANCE) ||
				       (c->policy & POLICY_IKEV2_ALLOW_NARROWING))) {
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
			if (!selector_in_selector(c->spd.that.client, t->spd.that.client)) {
				dbg("    skipping; current connection's initiator subnet is not <= template");
				continue;
			}
			/* require responder address match; why? */
			ip_address c_this_client_address = selector_prefix(c->spd.this.client);
			ip_address t_this_client_address = selector_prefix(t->spd.this.client);
			if (!address_eq_address(c_this_client_address, t_this_client_address)) {
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

			passert(best_connection == c); /* aka st->st_connection, no leak */
			pexpect(best_connection == child->sa.st_connection);
			struct connection *s = scribble_ts_on_connection(t, child, &tsp, fit,
									 /*definitely_shared?*/false,
									 best_sec_label);
			if (s == NULL) {
				continue;
			}

			best_connection = s;
			/* switch */
			best_spd_route = &best_connection->spd;
			break;
		}
	} else if (best_connection == c &&
		   c->kind == CK_TEMPLATE &&
		   c->spd.this.sec_label.len > 0) {
		dbg("  instantiating template security label connection");
		/* sure looks like a sec-label template */
		struct connection *s = scribble_ts_on_connection(c, child, &tsp,
								 END_WIDER_THAN_TS,
								 /*definitely_shared?*/true,
								 best_sec_label);
		if (!pexpect(s != NULL)) {
			return false;
		}
		best_connection = s;
		/* switch */
		best_spd_route = &best_connection->spd;
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

	return true;
}

/* check TS payloads, response */
bool v2_process_ts_response(struct child_sa *child,
			    struct msg_digest *md)
{
	passert(child->sa.st_sa_role == SA_INITIATOR);
	passert(v2_msg_role(md) == MESSAGE_RESPONSE);

	struct connection *c = child->sa.st_connection;

	struct traffic_selector_payloads tsp = empty_traffic_selectors;
	if (!v2_parse_tsp(md, &tsp, child->sa.st_logger)) {
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

	/* Returns NULL(ok), &null_shunk(skip), memory(ok). */
	shunk_t selected_sec_label = null_shunk;
	if (!score_tsp_sec_label(TS_EQUALS_CONNECTION_SEC_LABEL,
				 &tsp, c->spd.this.sec_label,
				 &selected_sec_label, child->sa.st_logger)) {
		/*
		 * Either:
		 *  - Security label required, but not found.
		 *    OR
		 *  - Security label *not* required, but found.
		 */
		return false;
	}

	struct best_score best = score_ends_iprange(initiator_widening, c, &e, &tsp);

	if (!best.ok) {
		dbg("reject responder TSi/TSr Traffic Selector");
		/* prevents parent from going to I3 */
		return false;
	}

	traffic_selector_to_end(best.tsi, &c->spd.this,
				"scribble accepted TSi response on initiator's this");
	traffic_selector_to_end(best.tsr, &c->spd.that,
				"scribble accepted TSr response on initiator's that");

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
	struct traffic_selector_payloads their_tsp = empty_traffic_selectors;

	if (!v2_parse_tsp(md, &their_tsp, child->sa.st_logger)) {
		log_state(RC_LOG_SERIOUS, &child->sa,
			  "received malformed TSi/TSr payload(s)");
		return false;
	}

	const struct ends ends = {
		.i = &c->spd.that,
		.r = &c->spd.this,
	};

	enum fit fitness = END_NARROWER_THAN_TS;

	/* Returns NULL(ok), &null_shunk(skip), memory(ok). */
	shunk_t selected_sec_label = null_shunk;
	if (!score_tsp_sec_label(TS_EQUALS_CONNECTION_SEC_LABEL,
				 &their_tsp, c->spd.this.sec_label,
				 &selected_sec_label,
				 child->sa.st_logger)) {
		/*
		 * Either:
		 *  - Security label required, but not found.
		 *    OR
		 *  - Security label *not* required, but found.
		 */
		log_state(RC_LOG_SERIOUS, &child->sa,
			  "rekey: received Traffic Selectors mismatch configured selectors for Security Label");
		return false;
	}

	struct best_score score = score_ends_iprange(fitness, c, &ends, &their_tsp);

	if (!score.ok) {
		log_state(RC_LOG_SERIOUS, &child->sa,
			  "rekey: received Traffic Selectors does not contain existing IPsec SA Traffic Selectors");
		return false;
	}

	return true;
}
