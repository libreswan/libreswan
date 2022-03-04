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
#include "pending.h"		/* for connection_is_pending() */

typedef struct {
	struct logger *logger;
	unsigned level;
} indent_t;

#define TS_INDENT "ts:%*s "
#define ts_indent indent.level*2, ""
#define dbg_ts(FORMAT, ...) ldbg(indent.logger, TS_INDENT""FORMAT, ts_indent, ##__VA_ARGS__)

struct narrowed_traffic_selector {
	const char *name;
	int port;
	const struct ip_protocol *protocol;
	ip_range range;
};

struct narrowed_traffic_selectors {
	bool ok;
	struct narrowed_traffic_selector i;
	struct narrowed_traffic_selector r;
};

/*
 * While the RFC seems to suggest that the traffic selectors come in
 * pairs, strongswan, at least, doesn't.
 */

struct traffic_selectors {
	const char *ts_name;
	const char *end_name;
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
		.ts_name = "TSi",
		.end_name = "initiator",
	},
	.r = {
		.ts_name = "TSr",
		.end_name = "responder",
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

static const char *str_end_fit_ts(enum fit fit)
{
	switch (fit) {
	case END_EQUALS_TS: return /*end*/"EQUALS"/*ts*/;
	case END_NARROWER_THAN_TS: return /*end*/"NARROWER-THAN"/*ts*/;
	case END_WIDER_THAN_TS: return /*end*/"WIDER-THAN"/*ts*/;
	default: bad_case(fit);
	}
}

static const char *str_fit_story(enum fit fit)
{
	switch (fit) {
	case END_EQUALS_TS: return "must match";
	case END_NARROWER_THAN_TS: return "use END, but must fit within TS";
	case END_WIDER_THAN_TS: return "use TS, but must fit within END";
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

static void traffic_selector_to_end(const struct narrowed_traffic_selector *n,
				    struct end *end, const char *story)
{
	range_buf rb;
	dbg("%s() %s; protocol=%s port=%d range=%s",
	    __func__, story, n->protocol->name, n->port, str_range(&n->range, &rb));
	ip_port port = ip_hport(n->port);
	end->client = selector_from_range_protocol_port(n->range, n->protocol, port);
	/* redundant? */
	end->has_client = !selector_eq_address(end->client, end->host->addr);
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
		.ipprotoid = e->client.ipproto,
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
	if (e->client.hport == 0 || e->config->client.protoport.has_port_wildcard) {
		ts.startport = 0;
		ts.endport = 65535;
	} else {
		ts.startport = e->client.hport;
		ts.endport = e->client.hport;
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
	    tss->ts_name, ts_pd->payload.v2ts.isat_num);

	if (ts_pd->payload.v2ts.isat_num == 0) {
		llog(RC_LOG, logger,
		     "%s payload contains no entries when at least one is expected",
		     tss->ts_name);
		return false;
	}

	if (ts_pd->payload.v2ts.isat_num >= elemsof(tss->ts)) {
		llog(RC_LOG, logger,
		     "%s contains %d entries which exceeds hardwired max of %zu",
		     tss->ts_name, ts_pd->payload.v2ts.isat_num, elemsof(tss->ts));
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
				     tss->ts_name, tss->nr);
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

	dbg("%s: parsed %d traffic selectors", tss->ts_name, tss->nr);
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

/*
 * Check if our policy's protocol (proto) matches the Traffic Selector
 * protocol (ts_proto).
 */

static const struct ip_protocol *narrow_protocol(const struct end *end,
						 const struct traffic_selectors *tss,
						 enum fit fit, unsigned index,
						 indent_t indent)
{
	const struct traffic_selector *ts = &tss->ts[index];
	int ipproto = -1;

	switch (fit) {
	case END_EQUALS_TS:
		if (end->client.ipproto == ts->ipprotoid) {
			ipproto = end->client.ipproto;
		}
		break;
	case END_NARROWER_THAN_TS:
		if (ts->ipprotoid == 0 /* wild-card */ ||
		    ts->ipprotoid == end->client.ipproto) {
			ipproto = end->client.ipproto;
		}
		break;
	case END_WIDER_THAN_TS:
		if (end->client.ipproto == 0 /* wild-card */ ||
		    end->client.ipproto == ts->ipprotoid) {
			ipproto = ts->ipprotoid;
		}
		break;
	default:
		bad_case(fit);
	}
	const struct ip_protocol *protocol = ipproto >= 0 ? protocol_by_ipproto(ipproto) : NULL;
	dbg_ts("narrow protocol: END %s.client.ipproto=%s%d %s TS %s[%u]=%s%d ==> %s (%s)",
	       tss->end_name, end->client.ipproto == 0 ? "*" : "", end->client.ipproto,
	       str_end_fit_ts(fit),
	       tss->ts_name, index, ts->ipprotoid == 0 ? "*" : "", ts->ipprotoid,
	       (protocol == NULL ? "<unset>" : protocol->name),
	       str_fit_story(fit));
	return protocol;
}

/*
 * Narrow the END/TS ports according to FIT.
 *
 * Returns 0 (all ports), a specific port number, or -1 (no luck).
 *
 * Since 'struct end' only describes all-ports or a single port; can
 * only narrow to that.
 */

static int narrow_port(const struct end *end,
		       const struct traffic_selectors *tss,
		       enum fit fit, unsigned index,
		       indent_t indent)
{
	passert(index < tss->nr);
	const struct traffic_selector *ts = &tss->ts[index];

	int end_low = end->client.hport;
	int end_high = end->client.hport == 0 ? 65535 : end->client.hport;
	int port_low = -1;
	int port_high = -1;

	switch (fit) {
	case END_EQUALS_TS:
		if (end_low == ts->startport && ts->endport == end_high) {
			/* end=ts=[0..65535] || end=ts=[N..N] */
			port_low = end_low;
			port_high = end_high;
		}
		break;
	case END_NARROWER_THAN_TS:
		if (ts->startport <= end_low && end_high <= ts->endport) {
			/* end=ts=[0..65535] || ts=N<=end<=M */
			port_low = end_low;
			port_high = end_high;
		}
		break;
	case END_WIDER_THAN_TS:
		if (end_low < ts->startport && ts->endport < end_high &&
		    ts->startport == ts->endport) {
			/*ts=0<[N..N]<65535*/
			port_low = ts->startport;
			port_high = ts->endport;
		} else if (end_low == ts->startport && ts->endport == end_high) {
			/* end=ts=[0..65535] || end=ts=[N..N] */
			port_low = ts->startport;
			port_high = ts->endport;
		}
		break;
	default:
		bad_case(fit);
	}
	dbg_ts("narrow port: END %s.client.port=%u..%u %s TS %s[%u]=%u..%u ==> %d..%d(%d) (%s)",
	       tss->end_name, end_low, end_high,
	       str_end_fit_ts(fit),
	       tss->ts_name, index, ts->startport, ts->endport,
	       port_low, port_high, port_low,
	       str_fit_story(fit));
	return port_low;
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

static ip_range narrow_range(const struct end *end,
			     const struct traffic_selectors *tss,
			     enum fit fit,
			     unsigned index, indent_t indent)
{
	/*
	 * NOTE: Our parser/config only allows 1 CIDR, however IKEv2
	 *       ranges can be non-CIDR for now we really
	 *       support/limit ourselves to a single CIDR
	 *
	 * XXX: so what is CIDR?
	 */
	const struct traffic_selector *ts = &tss->ts[index];
	ip_range range = unset_range;
	ip_range client_range = selector_range(end->client);
	switch (fit) {
	case END_EQUALS_TS:
		if (range_eq_range(client_range, ts->net)) {
			range = client_range;
		}
		break;
	case END_NARROWER_THAN_TS:
		if (range_in_range(client_range, ts->net)) {
			range = client_range;
		}
		break;
	case END_WIDER_THAN_TS:
		if (range_in_range(ts->net, client_range)) {
			range = ts->net;
		}
		break;
	default:
		bad_case(fit);
	}

	selector_buf cb;
	range_buf tsb, rb;
	dbg_ts("narrow range: END %s.client.selector=%s %s TS %s[%u]=%s ==> %s (%s)",
	       tss->end_name, str_selector(&end->client, &cb),
	       str_end_fit_ts(fit),
	       tss->ts_name, index, str_range(&ts->net, &tsb),
	       str_range(&range, &rb), str_fit_story(fit));
	return range;
}

static bool narrow_ts_end(struct narrowed_traffic_selector *n,
			  const struct end *end,
			  const struct traffic_selectors *tss,
			  enum fit fit, unsigned index,
			  indent_t indent)
{
	passert(tss->nr >= 1);
	*n = (struct narrowed_traffic_selector) {
		.name = tss->end_name,
	};

	const struct traffic_selector *ts = &tss->ts[index];
	switch (ts->ts_type) {
	case IKEv2_TS_IPV4_ADDR_RANGE:
	case IKEv2_TS_IPV6_ADDR_RANGE:
		break;
	default:
		return false;
	}

	n->port = narrow_port(end, tss, fit, index, indent);
	if (n->port < 0) {
		dbg_ts("skipping; %s port too wide", tss->ts_name);
		return false;
	}

	n->protocol = narrow_protocol(end, tss, fit, index, indent);
	if (n->protocol == NULL) {
		dbg_ts("skipping; %s protocol too wide", tss->ts_name);
		return false;
	}

	n->range = narrow_range(end, tss, fit, index, indent);
	if (range_is_unset(&n->range)) {
		dbg_ts("skipping; %s range too wide", tss->ts_name);
		return false;
	}

	return true;
}

static struct narrowed_traffic_selectors narrow_tss_ends(struct ends *ends,
							 const struct traffic_selector_payloads *tsp,
							 enum fit fit, unsigned index,
							 indent_t indent)
{
	struct narrowed_traffic_selectors n = {
		.ok = false, /* until proven */
	};

	/* Remember: THAT=INITIATOR; THIS=RESPONDER. */

	if (!narrow_ts_end(&n.i, ends->i, &tsp->i, fit, index, indent)) {
		return n;
	}

	if (!narrow_ts_end(&n.r, ends->r, &tsp->r, fit, index, indent)) {
		return n;
	}

	n.ok = true;
	return n;
}

static int score_narrowed_protocol(const struct narrowed_traffic_selector *ts,
				   indent_t indent)
{
	int f;	/* strength of match */
	if (ts->protocol == NULL) {
		f = 0;
	} else if (ts->protocol == &ip_protocol_all) {
		f = 255;	/* ??? odd value */
	} else {
		f = 1;
	}

	dbg_ts("%s: narrowed %s protocol %s has fitness %d",
	       (f > 0 ? "YES" : "NO"),
	       ts->name,
	       (ts->protocol == NULL ? "<unset>" : ts->protocol->name),
	       f);
	return f;
}

/*
 * Assign a score to the narrowed port, rationale for score lost in
 * time?
 */

static int score_narrowed_port(const struct narrowed_traffic_selector *ts,
			       indent_t indent)
{
	int f;	/* strength of match */
	if (ts->port > 0) {
		f = 1;
	} else if (ts->port == 0) {
		f = 65536; /* from 1 + 65535-0 */
	} else {
		f = 0;
	}

	dbg_ts("%s: narrowed %s port %d has fitness %d",
	       f > 0 ? "YES" : "NO", ts->name, ts->port, f);
	return f;
}

static int score_narrowed_range(const struct narrowed_traffic_selector *ts,
				indent_t indent)
{
	int f;
	if (range_is_unset(&ts->range)) {
		f = 0;
	} else {
		f = range_prefix_len(ts->range) + 1;
	}

	range_buf rb;
	dbg_ts("%s: narrowed %s address-range %s has fitness %d",
	       (f > 0 ? "YES" : "NO"), ts->name, str_range(&ts->range, &rb), f);
	return f;
}

struct score {
	bool ok;
	int range;
	int port;
	int protocol;
};

static struct score score_narrowed_ts(const struct narrowed_traffic_selector *ts,
				      indent_t indent)
{
	indent.level++;

	struct score score = {
		.ok = false,
	};

	score.range = score_narrowed_range(ts, indent);
	if (score.range <= 0) {
		return score;
	}
	score.port = score_narrowed_port(ts, indent);
	if (score.port <= 0) {
		return score;
	}
	score.protocol = score_narrowed_protocol(ts, indent);
	if (score.protocol <= 0) {
		return score;
	}
	/* made it! */
	score.ok = true;
	return score;
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

static bool check_tss_sec_label(const struct traffic_selectors *tss,
				chunk_t config_sec_label,
				shunk_t *selected_sec_label,
				struct logger *logger,
				indent_t indent)
{
	passert(tss->contains_sec_label);

	*selected_sec_label = null_shunk;
	for (unsigned i = 0; i < tss->nr; i++) {
		const struct traffic_selector *ts = &tss->ts[i];
		if (ts->ts_type != IKEv2_TS_SECLABEL) {
			continue;
		}

		passert(vet_seclabel(ts->sec_label) == NULL);

		if (!sec_label_within_range("Traffic Selector",
					    ts->sec_label, config_sec_label, logger)) {
			dbg_ts("%s sec_label="PRI_SHUNK" is not within range connection sec_label="PRI_SHUNK,
			       tss->ts_name, pri_shunk(ts->sec_label), pri_shunk(config_sec_label));
			continue;
		}

		dbg_ts("received %s label within range of our security label",
		    tss->ts_name);

		/* XXX we return the first match.  Should we return the best? */
		*selected_sec_label = ts->sec_label;	/* first match */
		return true;
	}

	return false;
}

static bool score_tsp_sec_label(const struct traffic_selector_payloads *tsp,
				chunk_t config_sec_label,
				shunk_t *selected_sec_label,
				struct logger *logger,
				indent_t indent)
{
	if (config_sec_label.len == 0) {
		/* This endpoint is not configured to use labeled IPsec. */
		if (tsp->i.contains_sec_label || tsp->r.contains_sec_label) {
			dbg_ts("error: received sec_label but this end is *not* configured to use sec_label");
			return false;
		}
		/* No sec_label was found and none was expected */
		return true;	/* success: no label, as expected */
	}

	/* This endpoint is configured to use labeled IPsec. */
	passert(vet_seclabel(HUNK_AS_SHUNK(config_sec_label)) == NULL);

	if (!tsp->i.contains_sec_label || !tsp->r.contains_sec_label) {
		dbg_ts("error: connection requires sec_label but not received TSi/TSr with sec_label");
		return false;
	}

	if (!check_tss_sec_label(&tsp->i, config_sec_label, selected_sec_label, logger, indent) ||
	    !check_tss_sec_label(&tsp->r, config_sec_label, selected_sec_label, logger, indent)) {
		return false;
	}

	/* security label required and matched */
	return true;
}

struct best_score {
	bool ok;
	int range;
	int port;
	int protocol;
	struct narrowed_traffic_selectors n;
};
#define  NO_SCORE { .ok = false, .range = -1, .port = -1, .protocol = -1, }

static bool score_gt(const struct best_score *score, const struct best_score *best)
{
	return ((score->range > best->range) ||
		(score->range == best->range && score->port > best->port) ||
		(score->range == best->range && score->port == best->port && score->protocol > best->protocol));
}

static struct best_score score_ends(enum fit fit,
				    const struct connection *d,
				    const struct ends *ends,
				    const struct traffic_selector_payloads *tsp,
				    indent_t indent)
{
	selector_buf ei3;
	selector_buf er3;
	dbg_ts("evaluating%s END %s=%s:%d/%d %s=%s:%d/%d %s TS:",
	       (is_virtual_connection(d) ? " (virt)" : ""),
	       tsp->i.end_name, str_selector_subnet_port(&ends->i->client, &ei3),
	       ends->i->client.ipproto,
	       ends->i->client.hport,
	       tsp->r.end_name, str_selector_subnet_port(&ends->r->client, &er3),
	       ends->r->client.ipproto,
	       ends->r->client.hport,
	       str_end_fit_ts(fit));

	indent.level++;

	struct best_score best_score = NO_SCORE;

	/* compare tsi/r array to this/that, evaluating how well it fits */
	for (unsigned tsi_n = 0; tsi_n < tsp->i.nr; tsi_n++) {

		struct narrowed_traffic_selector narrowed_tsi;
		if (!narrow_ts_end(&narrowed_tsi, ends->i, &tsp->i, fit, tsi_n, indent)) {
			continue;
		}

		/* choice hardwired for IPrange and sec_label */
		struct score score_i = score_narrowed_ts(&narrowed_tsi, indent);
		if (!score_i.ok) {
			continue;
		}

		for (unsigned tsr_n = 0; tsr_n < tsp->r.nr; tsr_n++) {

			struct narrowed_traffic_selector narrowed_tsr;
			if (!narrow_ts_end(&narrowed_tsr, ends->r, &tsp->r, fit, tsr_n, indent)) {
				continue;
			}

			struct score score_r = score_narrowed_ts(&narrowed_tsr, indent);
			if (!score_r.ok) {
				continue;
			}
			struct best_score score = {
				.ok = true,
				/* ??? this objective function is odd and arbitrary */
				.range = (score_i.range << 8) + score_r.range,
				/* ??? arbitrary objective function */
				.port = score_i.port + score_r.port,
				/* ??? arbitrary objective function */
				.protocol = score_i.protocol + score_r.protocol,
				/* which one */
				.n = {
					.ok = true,
					.i = narrowed_tsi,
					.r = narrowed_tsr,
				},
			};

			/* score >= best_score? */
			if (score_gt(&score, &best_score)) {
				best_score = score;
				dbg_ts("best score so far: TSi[%d] TSr[%d]",
				       tsi_n, tsr_n);
			}
		}
	}

	return best_score;
}

static bool v2_child_connection_probably_shared(struct child_sa *child,
						indent_t indent)
{
	struct connection *c = child->sa.st_connection;

	if (connection_is_pending(c)) {
		dbg_ts("#%lu connection is also pending; but what about pending for this state???",
		       child->sa.st_serialno);
		return true;
	}

	struct ike_sa *ike = ike_sa(&child->sa, HERE);
	struct state_filter sf = { .where = HERE, };
	while (next_state_new2old(&sf)) {
		struct state *st = sf.st;
		if (st->st_connection != c) {
			continue;
		}
		if (st == &child->sa) {
			dbg_ts("ignoring ourselves #%lu sharing connection %s",
			       st->st_serialno, c->name);
			continue;
		}
		if (st == &ike->sa) {
			dbg_ts("ignoring IKE SA #%lu sharing connection %s with #%lu",
			       st->st_serialno, c->name, child->sa.st_serialno);
			continue;
		}
		dbg_ts("#%lu and #%lu share connection %s",
		       child->sa.st_serialno, st->st_serialno,
		       c->name);
		return true;
	}

	return false;
}

static void scribble_request_ts_on_connection(struct child_sa *child,
					      struct connection *c,
					      struct narrowed_traffic_selectors n,
					      indent_t indent)
{
	if (c != child->sa.st_connection) {
		connection_buf from, to;
		dbg_ts("switching #%lu from "PRI_CONNECTION" to just-instantiated "PRI_CONNECTION,
		       child->sa.st_serialno,
		       pri_connection(child->sa.st_connection, &from),
		       pri_connection(c, &to));
	} else {
		connection_buf cib;
		dbg_ts("overwrote #%lu connection "PRI_CONNECTION,
		       child->sa.st_serialno, pri_connection(c, &cib));
	}

	/*
	 * hack
	 *
	 * Responder processing a request so THIS==RESPONDER and
	 * THAT=INITIATOR.
	 */
	dbg_ts("XXX: updating best connection's ports/protocols");
	c->spd.this.client = selector_from_range_protocol_port(n.r.range, n.r.protocol, ip_hport(n.r.port));
	c->spd.that.client = selector_from_range_protocol_port(n.i.range, n.i.protocol, ip_hport(n.i.port));
}

/*
 * Find the best connection: possibly scribbling on the just
 * instantiated child; possibly instantiating a new connection;
 * possibly giving up.
 */

bool v2_process_request_ts_payloads(struct child_sa *child,
				    const struct msg_digest *md)
{
	indent_t indent = {child->sa.st_logger, 0};
	passert(v2_msg_role(md) == MESSAGE_REQUEST);
	passert(child->sa.st_sa_role == SA_RESPONDER);

	struct traffic_selector_payloads tsp = empty_traffic_selectors;
	if (!v2_parse_tsp(md, &tsp, child->sa.st_logger)) {
		return false;
	}

	/*
	 * Start with nothing.  The loop then evaluates each
	 * connection, including the child's existing connection.
	 *
	 * Note in particular the code that allows C to be evaluated
	 * when it is an ID_NULL OE instance (normally these are
	 * excluded).
	 */
	struct best {
		struct best_score score;
		const struct spd_route *spd_route;
		struct connection *connection;
		shunk_t selected_sec_label;
	} best = {
		.score = NO_SCORE,
		.spd_route = NULL,
		.connection = NULL,
		.selected_sec_label = null_shunk,
	};

#define CONNECTION_POLICIES	(POLICY_DONT_REKEY |		\
				 POLICY_REAUTH |		\
				 POLICY_OPPORTUNISTIC |		\
				 POLICY_GROUP |			\
				 POLICY_GROUTED |		\
				 POLICY_GROUPINSTANCE |		\
				 POLICY_UP |			\
				 POLICY_XAUTH |			\
				 POLICY_MODECFG_PULL |		\
				 POLICY_AGGRESSIVE |		\
				 POLICY_OVERLAPIP |		\
				 POLICY_IKEV2_ALLOW_NARROWING)

	/*
	 * XXX: This double loop is performing two searches:
	 *
	 * - look for any matching local<->remote address: aka INSTANCE
	 * - look for any matching local<->* address: aka all TEMPLATEs
	 *
	 * If the connection has POLICY_IKEV2_ALLOW_NARROWING then
	 * score ends using the comparison END_NARROWER_THAN_TS (else
	 * equality).
	 */

	connection_buf cb;
	policy_buf pb;
	struct connection *const c = child->sa.st_connection;
	dbg_ts("looking to best connection "PRI_CONNECTION" "PRI_CO" with policy <%s>:",
	       pri_connection(c, &cb), pri_co(c->serialno),
	       str_policy(c->policy & CONNECTION_POLICIES, &pb));

	const ip_address local = md->iface->ip_dev->id_address;
	FOR_EACH_THING(remote, endpoint_address(md->sender), unset_address) {
		indent.level = 1;

		address_buf rab, lab;
		dbg_ts("searching host_pair %s->%s",
		       str_address(&remote, &rab), str_address(&local, &lab));

		FOR_EACH_HOST_PAIR_CONNECTION(local, remote, d) {
			indent.level = 2;

			/* XXX: sec_label connections all look a-like, include CO */
			connection_buf cb;
			policy_buf pb;
			dbg_ts("evaluating connection "PRI_CONNECTION" "PRI_CO" with policy <%s>:",
			       pri_connection(d, &cb), pri_co(d->serialno),
			       str_policy(d->policy & CONNECTION_POLICIES, &pb));

			indent.level = 3;

			if (d->config->ike_version != IKEv2) {
				connection_buf cb;
				dbg_ts("skipping "PRI_CONNECTION", not IKEv2",
				       pri_connection(d, &cb));
				continue;
			}

			/*
			 * Groups are like template templates?  They
			 * get instantiated into GROUPINSTANCEs (when
			 * this happens the POLICY_GROUP bit is
			 * stripped off and POLICY_GROUPINSTANCE is
			 * added)?
			 *
			 * They also seem to be very like sec_labels
			 * which start as templates, become hybrid
			 * template instances, and finally instances.
			 */
			if (d->policy & POLICY_GROUP) {
				connection_buf cb;
				dbg_ts("skipping "PRI_CONNECTION", group policy",
				       pri_connection(d, &cb));
				continue;
			}

			/*
			 * Normally OE instances are never considered
			 * when switching.  The exception being the
			 * current connection - it needs a score.
			 */
			if (d->kind == CK_INSTANCE &&
			    d->remote->host.id.kind == ID_NULL &&
			    d != child->sa.st_connection) {
				connection_buf cb;
				dbg_ts("skipping "PRI_CONNECTION", ID_NULL instance (and not original)",
				       pri_connection(d, &cb));
				continue;
			}

			/*
			 * For labeled IPsec, always start with the
			 * hybrid sec_label template instance.
			 *
			 * Who are we to argue if the kernel asks for
			 * a new SA with, seemingly, a security label
			 * that matches an existing connection
			 * instance.
			 */
			if (d->config->sec_label.len > 0 &&
			    d->kind != CK_TEMPLATE) {
				connection_buf cb;
				dbg_ts("skipping "PRI_CONNECTION",  non-template IKEv2 with a security label",
				       pri_connection(d, &cb));
				continue;
			}

			shunk_t selected_sec_label = null_shunk;
			if (!score_tsp_sec_label(&tsp, d->config->sec_label,
						 &selected_sec_label,
						 child->sa.st_logger, indent)) {
				/*
				 * Either:
				 *  - Security label required, but not found.
				 *    OR
				 *  - Security label *not* required, but found.
				 */
				connection_buf cb;
				dbg_ts("skipping "PRI_CONNECTION",  sec_label mis-match",
				       pri_connection(d, &cb));
				continue;
			}

			/*
			 * ??? same_id && match_id seems redundant.
			 * if d->local->host.id.kind == ID_NONE, both TRUE
			 * else if c->local->host.id.kind == ID_NONE,
			 *     same_id treats it as a wildcard and match_id
			 *     does not.  Odd.
			 * else if kinds differ, match_id FALSE
			 * else if kind ID_DER_ASN1_DN, wildcards are forbidden by same_id
			 * else match_id just calls same_id.
			 * So: if wildcards are desired, just use match_id.
			 * If they are not, just use same_id
			 */

			/* conns created as aliases from the same source have identical ID/CA */
			if (!(c->connalias != NULL &&
			      d->connalias != NULL &&
			      streq(c->connalias, d->connalias))) {
				int wildcards;	/* value ignored */
				int pathlen;	/* value ignored */

				if (!(same_id(&c->local->host.id, &d->local->host.id) &&
				      match_id("ts:       ", &c->remote->host.id, &d->remote->host.id, &wildcards) &&
				      trusted_ca(ASN1(c->remote->config->host.ca),
						 ASN1(d->remote->config->host.ca), &pathlen))) {
					connection_buf cb;
					dbg_ts("skipping "PRI_CONNECTION" does not match IDs or CA of current connection \"%s\"",
					       pri_connection(d, &cb), c->name);
					continue;
				}
			}

			/* responder -- note D! */
			enum fit responder_fit;
			if (d->policy & POLICY_IKEV2_ALLOW_NARROWING) {
				if (d->kind == CK_TEMPLATE) {
					/*
					 * A template starts wider
					 * than the TS and then, when
					 * it is instantiated, gets
					 * narrowed.
					 */
					responder_fit = END_WIDER_THAN_TS;
				} else {
					/*
					 * An existing instance needs
					 * to just accomodate the
					 * existing traffic
					 * selectors?!?
					 *
					 * XXX: should this instead
					 * only allow a strict equals?
					 */
					responder_fit = END_NARROWER_THAN_TS;
				}
			} else {
				responder_fit = END_EQUALS_TS;
			}

			for (const struct spd_route *sr = &d->spd;
			     sr != NULL; sr = sr->spd_next) {

				/* responder */
				const struct ends ends = {
					.i = &sr->that,
					.r = &sr->this,
				};

				struct best_score score = score_ends(responder_fit, d/*note D*/,
								     &ends, &tsp, indent);
				if (!score.ok) {
					continue;
				}
				if (score_gt(&score, &best.score)) {
					connection_buf cb;
					dbg_ts("protocol fitness found better match "PRI_CONNECTION"",
					       pri_connection(d, &cb));
					best = (struct best) {
						.connection = d,
						.score = score,
						.spd_route = sr,
						.selected_sec_label = selected_sec_label,
					};
				}
			}
		}
	}

	indent.level = 1;

	if (best.connection == NULL) {
		connection_buf cb;
		dbg_ts("connection "PRI_CONNECTION" "PRI_CO" is as good as it gets",
		       pri_connection(c, &cb), pri_so(c->serialno));
	} else {
		connection_buf cb, bcb;
		dbg_ts("connection "PRI_CONNECTION" "PRI_CO" best by "PRI_CONNECTION" "PRI_CO"%s%s",
		       pri_connection(c, &cb), pri_so(c->serialno),
		       pri_connection(best.connection, &bcb), pri_so(best.connection->serialno),
		       (best.connection->kind == CK_TEMPLATE ? " needs instantiating!" : ""),
		       (best.connection->policy & POLICY_GROUPINSTANCE ? " group-instance!" : ""))
	}

	/*
	 * Did the the search fail badly?
	 *
	 * - no existing connection (or connection template) matched
	 *   the proposed traffic selectors.
	 *
	 * - more importantly, the existing connection is "permanent"
	 *   (or permanent like) so there isn't the option of
	 *   instantiating something better (switching away from
	 *   permenant connections isn't allowed; explaining why might
	 *   be helpful here).
	 */
	if (best.connection == NULL &&
	    c->kind != CK_INSTANCE) {
		pexpect((c->kind == CK_PERMANENT) ||
			(c->kind == CK_TEMPLATE && c->config->sec_label.len > 0));
		/*
		 * Don't try to look for something else to
		 * 'instantiate' when the current connection is
		 * permanent.
		 *
		 * XXX: What about CK_TEMPLATE?
		 *
		 * Only when the connection also has a SEC_LABEL so is
		 * more like an instance.  Non-SEC_LABEL templates get
		 * instantiated before this code is called.
		 *
		 * XXX: Is this missing an opportunity?  Could there
		 * be a better connection to instantiate when the
		 * current one is permanent?
		 *
		 * XXX: 'instantiate', not really?  The code below
		 * sometimes blats the current instance with new
		 * values - something that should not be done to a
		 * permanent connection.
		 */
		dbg_ts("no best spd route; but the current %s connection \"%s\" is not a CK_INSTANCE; giving up",
		       enum_name(&connection_kind_names, c->kind), c->name);
		llog_sa(RC_LOG_SERIOUS, child, "No IKEv2 connection found with compatible Traffic Selectors");
		return false;
	}

	/*
	 *
	 * Now retry the search looking for group instances:
	 *
	 * Why?
	 *
	 * Who knows, but I suspect it goes back to the original
	 * choice made during IKE_SA_INIT where:
	 *
	 * - OE templates (group instances?!?) connections
	 *
	 *   During IKE_SA_INIT, the OE connection with the narrowest
	 *   <remote.client> subnet that contained <remote.address>
	 *   was chosen; so now it is looking to see if one of the
	 *   other OE connections does better
	 *
	 * SEC_LABLES and other connections, by this point, are locked
	 * in.
	 */

	if (best.connection == NULL &&
	    c->config->sec_label.len == 0 &&
	    c->policy & POLICY_GROUPINSTANCE) {
		/*
		 * Is there something better than the current
		 * connection?
		 *
		 * Rather than overwrite the current INSTANCE; would
		 * it be better to instantiate a new instance, and
		 * then replace it?
		 *
		 * Would also address the above.
		 *
		 * If the connection seems to be shared, this happens.
		 */
		dbg_ts("no best spd route; looking for a better template connection to instantiate");

		struct connection_filter cf = {
			.kind = CK_TEMPLATE /* require a template */,
			.where = HERE,
		};
		while (next_connection_new2old(&cf)) {
			struct connection *t = cf.c;
			indent.level = 2;

			LSWDBGP(DBG_BASE, buf) {
				jam(buf, TS_INDENT, ts_indent);
				jam(buf, "investigating template \"%s\";",
					t->name);
				if (t->foodgroup != NULL) {
					jam(buf, " food-group=\"%s\"", t->foodgroup);
				}
				jam(buf, " with policy <");
				jam_policy(buf, t->policy & CONNECTION_POLICIES);
				jam(buf, ">");
			}

			indent.level++;

			/*
			 * Is it worth looking at the template.
			 *
			 * XXX: treat the combination the same as
			 * group instance, like the old code did; is
			 * this valid?
			 */

			/*
			 * XXX: why does this matter; does it imply
			 * t->foodgroup != NULL?
			 */
			if (!LIN(POLICY_GROUPINSTANCE, t->policy)) {
				dbg_ts("skipping; not a group instance");
				continue;
			}
			/* when OE, don't change food groups? */
			if (!streq(c->foodgroup, t->foodgroup)) {
				dbg_ts("skipping; wrong foodgroup name");
				continue;
			}
			/*
			 * ??? why require current connection->name
			 * and t->name to be different.
			 *
			 * XXX: don't re-instantiate the same
			 * connection template????
			 */
			if (streq(c->name, t->name)) {
				dbg_ts("skipping; name same as current connection");
				continue;
			}

			/*
			 * Require that the connection instantiated
			 * during IKE_SA_INIT has a client that falls
			 * within T.
			 *
			 * Why?
			 *
			 * Something to do with the IKE_SA_INIT client
			 * being chosen because it had the narrowest
			 * client selector?
			 */
			if (!selector_in_selector(c->spd.that.client, t->spd.that.client)) {
				dbg_ts("skipping; current connection's initiator subnet is not <= template");
				continue;
			}
			/* require responder address match; why? */
			ip_address c_this_client_address = selector_prefix(c->spd.this.client);
			ip_address t_this_client_address = selector_prefix(t->spd.this.client);
			if (!address_eq_address(c_this_client_address, t_this_client_address)) {
				dbg_ts("skipping; responder addresses don't match");
				continue;
			}

			/* require a valid narrowed port? */
			/* exact match; XXX: 'cos that is what old code did */
			enum fit responder_fit = END_EQUALS_TS;

			/* responder: THIS=RESPONDER; THAT=INITIATOR */
			struct ends ends = {
				.i = &t->spd.that,
				.r = &t->spd.this,
			};

			struct narrowed_traffic_selectors n = narrow_tss_ends(&ends, &tsp,
									      responder_fit,
									      0, indent);
			if (!n.ok) {
				continue;
			}

			indent.level--;

			/*
			 * XXX: isn't this a template, or are group
			 * instances shared?
			 */
			struct connection *s;
			if (v2_child_connection_probably_shared(child, indent)) {
				/* instantiate it, filling in peer's ID */
				s = instantiate(t, &child->sa.st_connection->remote->host.addr,
						NULL, /*sec_label*/null_shunk);
			} else {
				s = child->sa.st_connection;
			}
			scribble_request_ts_on_connection(child, s, n, indent);

			/* switch */
			best = (struct best) {
				.connection = s,
				.spd_route = &s->spd,
				.score = {
					.n = n,
				},
			};
			break;
		}
	}

	/*
	 * Is best.connection is a template:
	 *
	 * - a hybrid template-instance sec_label connection
	 *
	 *   XXX:
	 *
	 *   If it is then, expect it to be the connection we started
	 *   with.  All the above achieved nothing (other than check
	 *   that this isn't already instantiated???, and set
	 *   best_sec_label).  All that's needed here is for the
	 *   hybrid template-instance to be instantiated.
	 *
	 * - a more straight forward template that needs narrowing
	 */

	indent.level = 1;
	if (best.connection != NULL &&
	    best.connection->kind == CK_TEMPLATE) {
		dbg_ts("instantiating the template connection");
		indent.level = 2;

		if (best.connection->config->sec_label.len > 0) {
			pexpect(best.connection == child->sa.st_connection); /* big circle */
			pexpect(best.selected_sec_label.len > 0);
			pexpect(best.connection->spd.this.sec_label.len == 0);
		}

		/*
		 * Convert the hybrid sec_label template-instance into
		 * a proper instance, and then update its selectors.
		 */
		struct connection *s = instantiate(best.connection,
						   &child->sa.st_connection->remote->host.addr,
						   NULL, best.selected_sec_label);
		scribble_request_ts_on_connection(child, s, best.score.n, indent);

		/* switch to instance */
		best = (struct best) {
			.connection = s,
			.spd_route = &s->spd,
			.selected_sec_label = best.selected_sec_label,
		};
	}

	indent.level = 1;

	if (best.connection == NULL) {
		dbg_ts("giving up");
		return false;
	}

	/*
	 * If needed, replace the child's connection.
	 *
	 * switch_state_connection(), if the connection changes,
	 * de-references the old connection; which is what really
	 * matters
	 */
	if (best.connection != child->sa.st_connection) {
		connswitch_state_and_log(&child->sa, best.connection);
	}

	return true;
}

/* check TS payloads, response */
bool v2_process_ts_response(struct child_sa *child,
			    struct msg_digest *md)
{
	indent_t indent = {child->sa.st_logger, 0};

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

	/*
	 * When allow narrowing, it's ok for the responders TS to be
	 * smaller than the END.
	 */
	enum fit initiator_fit =
		((c->policy & POLICY_IKEV2_ALLOW_NARROWING) ? END_WIDER_THAN_TS
		 : END_EQUALS_TS);

	/* Returns NULL(ok), &null_shunk(skip), memory(ok). */
	shunk_t selected_sec_label = null_shunk;
	if (!score_tsp_sec_label(&tsp, c->config->sec_label,
				 &selected_sec_label,
				 child->sa.st_logger, indent)) {
		/*
		 * Either:
		 *  - Security label required, but not found.
		 *    OR
		 *  - Security label *not* required, but found.
		 */
		return false;
	}

	struct best_score best = score_ends(initiator_fit, c, &e, &tsp, indent);

	if (!best.ok) {
		dbg_ts("reject responder TSi/TSr Traffic Selector");
		/* prevents parent from going to I3 */
		return false;
	}

	traffic_selector_to_end(&best.n.i, &c->spd.this,
				"scribble accepted TSi response on initiator's this");
	traffic_selector_to_end(&best.n.r, &c->spd.that,
				"scribble accepted TSr response on initiator's that");
	rehash_db_spd_route_remote_client(&c->spd);

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
bool verify_rekey_child_request_ts(struct child_sa *child, struct msg_digest *md)
{
	indent_t indent = {child->sa.st_logger, 0};

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

	enum fit responder_fit = END_NARROWER_THAN_TS;

	/* Returns NULL(ok), &null_shunk(skip), memory(ok). */
	shunk_t selected_sec_label = null_shunk;
	if (!score_tsp_sec_label(&their_tsp, c->config->sec_label,
				 &selected_sec_label,
				 child->sa.st_logger, indent)) {
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

	struct best_score score = score_ends(responder_fit, c, &ends, &their_tsp, indent);

	if (!score.ok) {
		log_state(RC_LOG_SERIOUS, &child->sa,
			  "rekey: received Traffic Selectors does not contain existing IPsec SA Traffic Selectors");
		return false;
	}

	return true;
}
