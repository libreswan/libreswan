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
		DBG_log("  sec_ctx_value: %s", (ts->sec_ctx ? ts->sec_ctx->sec_ctx_value : "<NULL>"));
	}
}

/* rewrite me with address_as_{chunk,shunk}()? */
/**
 * ikev2_update_ts_from_end: Update the fields in the given traffic selector
 * using the endpoint specifications.
 *
 * @param[out]	ts	Traffic selector to be updated.
 * @param[in]	e	Endpoint specification.
 */
static void ikev2_update_ts_from_end(struct traffic_selector *const ts, struct end const *const e)
{
	switch (subnet_type(&e->client)->af) {
	case AF_INET:
		ts->ts_type = IKEv2_TS_IPV4_ADDR_RANGE;
		break;
	case AF_INET6:
		ts->ts_type = IKEv2_TS_IPV6_ADDR_RANGE;
		break;
	}

	/* subnet => range */
	ts->net = range_from_subnet(&e->client);
	/* Setting ts_type IKEv2_TS_FC_ADDR_RANGE (RFC-4595) not yet supported */

	ts->ipprotoid = e->protocol;

	/*
	 * if port is %any or 0 we mean all ports (or all iccmp/icmpv6)
	 * See RFC-5996 Section 3.13.1 handling for ICMP(1) and ICMPv6(58)
	 *   we only support providing Type, not Code, eg protoport=1/1
	 */
	if (e->port == 0 || e->has_port_wildcard) {
		ts->startport = 0;
		ts->endport = 65535;
	} else {
		ts->startport = e->port;
		ts->endport = e->port;
	}
}

/* See header file for function prototype comments. */
struct traffic_selector ikev2_make_ts(struct end const *const e,
				      struct xfrm_user_sec_ctx_ike *const sec_ctx) {
	struct traffic_selector ts;
	zero(&ts);
	ikev2_update_ts_from_end(&ts, e);
	ts.sec_ctx = sec_ctx;
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
			/*
			 * If there is a security label in the Traffic Selector,
			 * then we must send a TS_SECLABEL substructure as part of the
			 * Traffic Selector (TS) Payload.
			 * That means the TS Payload contains two TS substructures:
			 *  - One for the address/port range
			 *  - One for the TS_SECLABEL
			 */
			.isat_num = ts->sec_ctx ? 2 : 1,
		};

		if (!out_struct(&its, ts_desc, outpbs, &ts_pbs))
			return STF_INTERNAL_ERROR;
	}

	/*
	 * Output a TS_SECLABEL substructure as part of the TS Payload if a
	 * security label exists.
	 */
	if (ts->sec_ctx) {
		/* Sanity check: +1 is for the NUL-termination character. */
		passert((strlen(ts->sec_ctx->sec_ctx_value) + 1) == ts->sec_ctx->ctx.ctx_len);
		if (ts->sec_ctx->ctx.ctx_len == 0) {
			/* Zero-length security labels not allowed by the labeled IPsec RFC. */
			loglog(RC_LOG_SERIOUS, "ERROR: Trying to output a zero length security label: %s",
				ts->sec_ctx->sec_ctx_value);
			return STF_INTERNAL_ERROR;
		}

		/* Initialize the header of the TS_SECLABEL substructure payload. */
		struct ikev2_ts_seclabel ts_seclabel;
		ts_seclabel.isa_tssec_type = IKEv2_TS_SECLABEL;
		ts_seclabel.isa_tssec_reserved = 0;
		/* Length of the TS_SECLABEL substructure = 4 (size of header) + security label length */
		ts_seclabel.isa_tssec_sellen =
			ikev2_ts_seclabel_header_len + ts->sec_ctx->ctx.ctx_len;

		/* Output the header of the TS_SECLABEL substructure payload. */
		if (!out_struct(&ts_seclabel, &ikev2_ts_seclabel_desc, &ts_pbs, NULL)) {
			loglog(RC_LOG_SERIOUS, "ERROR: Could not output TS_SECLABEL header. Security label = %s", ts->sec_ctx->sec_ctx_value);
			return STF_INTERNAL_ERROR;
		}
		
		/* Output the security label value of the TS_SECLABEL substructure payload. */
		diag_t label_out_error =
			pbs_out_raw(&ts_pbs, ts->sec_ctx->sec_ctx_value, ts->sec_ctx->ctx.ctx_len, "Security label value");
		if (label_out_error != NULL) {
			loglog(RC_LOG_SERIOUS, "ERROR: Could not output TS_SECLABEL security label value. Security label = %s", ts->sec_ctx->sec_ctx_value);
			log_diag(RC_LOG_SERIOUS, outpbs->out_logger, &label_out_error, "%s", "");
			return STF_INTERNAL_ERROR;
		}
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
			break;
		case IKEv2_TS_IPV6_ADDR_RANGE:
			its1.isat1_type = IKEv2_TS_IPV6_ADDR_RANGE;
			break;
		case IKEv2_TS_FC_ADDR_RANGE:
			DBG_log("IKEv2 Traffic Selector IKEv2_TS_FC_ADDR_RANGE not yet supported");
			return STF_INTERNAL_ERROR;

		default:
			DBG_log("IKEv2 Traffic Selector type '%d' not supported",
				ts->ts_type);
			return STF_INTERNAL_ERROR;	/* ??? should be bad_case()? */
		}

		if (!out_struct(&its1, &ikev2_ts1_desc, &ts_pbs, &ts_pbs2))
			return STF_INTERNAL_ERROR;
	}

	/* now do IP addresses */
	switch (ts->ts_type) {
	case IKEv2_TS_IPV4_ADDR_RANGE:
	case IKEv2_TS_IPV6_ADDR_RANGE:
	{
		diag_t d;
		d = pbs_out_address(&ts_pbs2, &ts->net.start, "IP start");
		if (d != NULL) {
			log_diag(RC_LOG_SERIOUS, outpbs->out_logger, &d, "%s", "");
			return STF_INTERNAL_ERROR;
		}
		d = pbs_out_address(&ts_pbs2, &ts->net.end, "IP end");
		if (d != NULL) {
			log_diag(RC_LOG_SERIOUS, outpbs->out_logger, &d, "%s", "");
			return STF_INTERNAL_ERROR;
		}
		break;
	}
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

	ts_ret.sec_ctx = ts->sec_ctx;

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

/**
 * parse_ts_seclabel: Parse a TS_SECLABEL substructure from an incoming Traffic
 * Selector (TS) Payload.
 *
 * @param[in,out]	seclabel_count	Number of TS_SECLABEL substructures parsed
 * 					in the current TS Payload.
 * @param[out]		ts		Incoming Traffic Selector substructure
 * 					currently being processed in the TS Payload.
 * @param[in,out]	ins		Input packet byte stream for the incoming
 * 					TS Payload.
 * @param[out]		seclabel_index	Set to `ts_index` if the TS_SECLABEL substructure
 * 					parsing is successful.
 * @param[in]		ts_index	Index of the incoming Traffic Selector substructure
 * 					currently being processed in the TS Payload.
 *
 * @return	True if parsing a TS_SECLABEL substructure is successful.
 */
static bool parse_ts_seclabel(uint32_t* const seclabel_count,
			      struct traffic_selector *const ts,
			      struct pbs_in *const ins,
			      int *const seclabel_index,
			      int const ts_index) {
	if (*seclabel_count == 1) {
		/*
		 * Current implementation only allows 1 TS_SECLABEL
		 * substructure at most in a Traffic Selector (TS) Payload.
		 */
		loglog(RC_LOG_SERIOUS, "ERROR: Multiple TS_SECLABEL not supported - already found a TS_SECLABEL during input processing");
		return false;
	}

	/* ts_seclabel: TS_SECLABEL substructure of the TS Payload. */
	struct ikev2_ts_seclabel ts_seclabel;

	/* Parse the header of the TS_SECLABEL substructure. */
	if (!in_struct(&ts_seclabel, &ikev2_ts_seclabel_desc, ins, NULL)) {
		loglog(RC_LOG_SERIOUS, "ERROR: Could not parse header of TS_SECLABEL substructure");
		return false;
	}
	passert(ts_seclabel.isa_tssec_type == IKEv2_TS_SECLABEL);

	/* TS_SECLABEL substructure payload length */
	uint16_t const payloadLen = ts_seclabel.isa_tssec_sellen;
	/* TS_SECLABEL substructure payload header length */
	if (payloadLen < ikev2_ts_seclabel_header_len) {
		/* Bad payload length: too small */
		loglog(RC_LOG_SERIOUS,
		       "ERROR: TS_SECLABEL payloadLen (%u) < "
			"ikev2_ts_seclabel_header_len (%u)",
		       payloadLen,
		       ikev2_ts_seclabel_header_len);
		return false;
	}

	/* Length of the security label. */
	uint16_t const labelLen = payloadLen - ikev2_ts_seclabel_header_len;
	if (labelLen == 0) {
		/*
		 * Zero-length security labels disallowed by
		 * the labeled IPsec standard.
		 */
		loglog(RC_LOG_SERIOUS, "ERROR: Zero TS_SECLABEL label length");
		return false;
	}

	if (labelLen > MAX_SECCTX_LEN) {
		/*
		 * Security label exceeds maximum allowed size.
		 */
		loglog(RC_LOG_SERIOUS, "ERROR: Incoming TS_SECLABEL label length (%u) exceeds maximum allowed buffer size (%u)", labelLen, MAX_SECCTX_LEN);
		return false;
	}


	ts->ts_type = IKEv2_TS_SECLABEL;

	struct xfrm_user_sec_ctx_ike incoming_ctx;
	/* FIXME: These are hardcoded to correspond to SELinux. */
	incoming_ctx.ctx.ctx_doi = 1;
	incoming_ctx.ctx.ctx_alg = 1;

	incoming_ctx.ctx.ctx_len = labelLen;

	/* Parse the security label value of the TS_SECLABEL substructure. */
	if (!in_raw(incoming_ctx.sec_ctx_value, labelLen, ins,
				"Traffic Selector Security Label")) {
		loglog(RC_LOG_SERIOUS, "ERROR: Could not read TS_SECLABEL security label value");
		return false;
	}

	/* Incoming security label MUST be NUL-terminated. */
	if (incoming_ctx.sec_ctx_value[labelLen - 1] != '\0') {
		loglog(RC_LOG_SERIOUS, "ERROR: Incoming TS_SECLABEL security label value not NUL-terminated: %s", incoming_ctx.sec_ctx_value);
		return false;
	}

	/* Clone the security label from its current temporary storage. */
	ts->sec_ctx = clone_thing(incoming_ctx,
			"struct xfrm_user_sec_ctx_ike : cloned from input buffer "
			"in parse_ts_label()");

	/* Track the number of TS_SECLABEL substructures. */
	*seclabel_count = *seclabel_count + 1;

	/* Record the Traffic Selector substructure index at which TS_SECLABEL was found. */
	*seclabel_index = ts_index;

	return true;
}

/* return success */
static bool v2_parse_ts(struct payload_digest *const ts_pd,
			struct traffic_selectors *tss,
			const char *which, struct logger *logger)
{
	dbg("%s: parsing %u traffic selectors",
	    which, ts_pd->payload.v2ts.isat_num);

	if (ts_pd->payload.v2ts.isat_num == 0) {
		log_message(RC_LOG, logger, "%s payload contains no entries when at least one is expected",
			      which);
		return false;
	}

	if (ts_pd->payload.v2ts.isat_num >= elemsof(tss->ts)) {
		log_message(RC_LOG, logger, "%s contains %d entries which exceeds hardwired max of %zu",
			      which, ts_pd->payload.v2ts.isat_num, elemsof(tss->ts));
		return false;	/* won't fit in array */
	}

	/*
	 * Traffic Selector (TS) Payload input parsing algorithm:
	 *
	 * let ts_seclabel = <NONE>
	 * For each substructure in TS Payload:
	 *     let ts_type = <Traffic Selector substructure type>
	 *     if ts_type == TS_SECLABEL:
	 *         Process TS_SECLABEL Traffic Selector substructure into tss[current_index]
	 *         ts_seclabel = tss[current_index]
	 *     else:
	 *         Process IKEv2_TS_{IPV4,IPV6}_ADDR_RANGE Traffic Selector substructure
	 *           into tss[current_index]
	 *
	 * If ts_seclabel != <NONE>
	 *     For each entry in tss:
	 *         if entry != ts_seclabel
	 *             entry.sec_ctx = ts_seclabel.sec_ctx
	 */

	/*
	 * addr_range_count: Number of address range substructures in the
	 * Traffic Selector (TS) payload
	 */
	uint32_t addr_range_count = 0;
	/*
	 * seclabel_count: Number of security label substructures in the TS
	 * payload.
	 * NOTE: Currently, only 1 TS_SECLABEL substructure is expected in the
	 * TS Payload.
	 */
	uint32_t seclabel_count = 0;
	/*
	 * seclabel_index: Index of the TS_SECLABEL substructure in the array of Traffic
	 * Selectors corresponding to the TS Payload.
	 * NOTE: Currently, only 1 TS_SECLABEL substructure is expected in the
	 * TS Payload.
	 */
	int seclabel_index = -1;
	for (tss->nr = 0; tss->nr < ts_pd->payload.v2ts.isat_num; tss->nr++) {
		struct traffic_selector *ts = &tss->ts[tss->nr];
		/* Zero-out the Traffic Selector to prevent garbage data. */
		zero(ts);

		/* ts_type: Traffic Selector Type */
		uint8_t ts_type;
		/*
		 * Peek at the Traffic Selector Type in the input stream in order to figure
		 * out which substructure to process next.
		 */
		if (!peek_raw(&ts_type, sizeof(ts_type), &ts_pd->pbs, "Traffic Selector Type")) {
			return false;
		}

		if (ts_type == IKEv2_TS_SECLABEL) {
			/* Parse a TS_SECLABEL substructure in the TS Payload. */
			if (!parse_ts_seclabel(&seclabel_count, ts, &ts_pd->pbs, &seclabel_index, tss->nr)) {
				return false;
			}
			continue;
		}

		pb_stream addr;
		struct ikev2_ts1 ts1;

		if (!in_struct(&ts1, &ikev2_ts1_desc, &ts_pd->pbs, &addr)) {
			return false;
		}
		++addr_range_count;

		const struct ip_info *ipv;
		switch (ts1.isat1_type) {
		case IKEv2_TS_IPV4_ADDR_RANGE:
			ts->ts_type = IKEv2_TS_IPV4_ADDR_RANGE;
			ipv = &ipv4_info;
			break;
		case IKEv2_TS_IPV6_ADDR_RANGE:
			ts->ts_type = IKEv2_TS_IPV6_ADDR_RANGE;
			ipv = &ipv6_info;
			break;
		default:
			return false;
		}

		if (!pbs_in_address(&ts->net.start, ipv, &addr, "TS low")) {
			return false;
		}
		if (!pbs_in_address(&ts->net.end, ipv, &addr, "TS high")) {
			return false;
		}
		/* XXX: does this matter? */
		if (pbs_left(&addr) != 0)
			return false;

		ts->ipprotoid = ts1.isat1_ipprotoid;

		ts->startport = ts1.isat1_startport;
		ts->endport = ts1.isat1_endport;
		if (ts->startport > ts->endport) {
			log_message(RC_LOG, logger,
				    "%s traffic selector %d has an invalid port range",
				    which, tss->nr);
			return false;
		}
	}

	if (seclabel_count > 0) {
		/* TS_SECLABEL Traffic Selector(s) are present in the TS payload. */
		if (addr_range_count == 0) {
			/* TS_SECLABEL _MUST_ accompany an IP address range. */
			loglog(RC_LOG_SERIOUS, "ERROR: TS_SECLABEL (count = %u) found without any IP address ranges", seclabel_count);
			return false;
		}

		passert(seclabel_index >= 0);
		/*
		 * Copy the sole security label to all *_ADDR_RANGE Traffic
		 * Selector structs. This is so that the security label is used
		 * as a selector in conjunction with the selector parameters
		 * present in those *_ADDR_RANGE Traffic Selectors.
		 */
		for (unsigned int i = 0; i < tss->nr; ++i) {
			struct traffic_selector *ts = &tss->ts[i];
			if (i == (unsigned int)seclabel_index) {
				continue;
			}
			passert(ts->ts_type == IKEv2_TS_IPV4_ADDR_RANGE ||
				ts->ts_type == IKEv2_TS_IPV6_ADDR_RANGE);

			ts->sec_ctx = tss->ts[seclabel_index].sec_ctx;
		}
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

/**
 * free_sec_ctx_in_tss: Free any memory allocated for security labels in the specified
 * set of traffic selectors.
 *
 * @param[in,out]	tss	Set of traffic selectors.
 */
static void free_sec_ctx_in_tss(struct traffic_selectors *const tss) {
	if ((tss->nr > 0) && (tss->ts[0].sec_ctx != NULL)) {
		/*
		 * Currently, a set of Traffic Selectors will only have a single
		 * security label (if any) shared among said Traffic Selectors.
		 * So you only need to free using just one of the security label
		 * pointers.
		 */
		pfreeany(tss->ts[0].sec_ctx);
	}
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
 *
 * XXX: what exactly is CIDR?
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

/**
 * seclabel_narrow_status: Indicates the outcome of a security label "narrowing."
 */
enum seclabel_narrow_status {
	/**
	 * "Narrowing" successful
	 */
	NARROW_OK,
	/**
	 * "Narrowing" was unsuccessful: generic error
	 */
	NARROW_ERROR,
	/**
	 * "Narrowing" was unsuccessful: the existing security label in a IPsec
	 * SA has a different length than the proposed security label
	 */
	NARROW_MISMATCH_EXISTING_LABEL_LENGTH,
	/**
	 * "Narrowing" was unsuccessful: the existing security label in a IPsec
	 * SA has a different string value than the proposed security label
	 */
	NARROW_MISMATCH_EXISTING_LABEL_VALUE,
	/**
	 * "Narrowing" was unsuccessful: the proposed security label in an
	 * incoming Traffic Selector is NULL while there is already an existing
	 * security label in a IPsec SA
	 */
	NARROW_MISSING_TS_SECLABEL,
	/**
	 * "Narrowing" was unsuccessful: the connection configuration does NOT
	 * support using security lables for IPsec SAs
	 */
	NARROW_NO_POLICY_LABEL,
	/**
	 * "Narrowing" was unsuccessful: proposed security label is not
	 * compatible with the connection's configured security policy label.
	 */
	NARROW_INCOMPATIBLE_LABEL,
	/**
	 * "Narrowing" was unsuccessful: "Narrowing" security label does not
	 * apply in the current scenario.
	 */
	NARROW_NOT_APPLICABLE
};


/**
 * seclabel_narrow_result: Stores the result of a security label "narrowing"
 * operation.
 */
struct seclabel_narrow_result {
	/**
	 * `status` indicates if "narrowing" was successful or not.
	 */
	enum seclabel_narrow_status status;
	/**
	 * `sec_ctx` is the security label to be used after "narrowing" (if any).
	 */
	struct xfrm_user_sec_ctx_ike *sec_ctx;
};

#ifndef HAVE_LABELED_IPSEC

/**
 * narrow_seclabel: "Narrow" a security label for use with an IPsec SA.
 * NOTE: This is a stub used when labeled IPsec support is not compiled in.
 *
 * @param[in]	tss	Set of Traffic Selectors.
 * @param[in]	index	Index of the Traffic Selector in `tss` containing the
 * 			security label.
 *
 * @return	Result of the security label "narrowing" operation.
 */
static struct seclabel_narrow_result narrow_seclabel(struct traffic_selectors const *tss,
						     unsigned const index,
						     enum fit const fit UNUSED,
						     struct state const* child_state UNUSED,
						     char const *const what UNUSED) {
	struct traffic_selector const *ts = &tss->ts[index];
	struct seclabel_narrow_result result = { .status = NARROW_OK, .sec_ctx = NULL };
	if (ts->sec_ctx != NULL) {
		loglog(RC_LOG_SERIOUS, "IKEv2: Received security label but labeled IPsec support not compiled in");
		result.status = NARROW_ERROR;
		result.sec_ctx = NULL;
	}
	return result;
}

#else	/* #ifndef HAVE_LABELED_IPSEC */

#include "security_selinux.h"

/* Helper macro for defining cases in narrow_status_string(). */
#define NARROW_STATUS_CASE_STR(value) case value: return #value

/**
 * narrow_status_string: Return the stringified form of
 * `seclabel_narrow_status` enum values.
 *
 * @param[in]	status	Enum value to be stringified.
 *
 * @return	Stringified form of `status`.
 */
static char const *narrow_status_string(enum seclabel_narrow_status const status) {
	switch (status) {
	NARROW_STATUS_CASE_STR(NARROW_OK);
	NARROW_STATUS_CASE_STR(NARROW_ERROR);
	NARROW_STATUS_CASE_STR(NARROW_MISMATCH_EXISTING_LABEL_LENGTH);
	NARROW_STATUS_CASE_STR(NARROW_MISMATCH_EXISTING_LABEL_VALUE);
	NARROW_STATUS_CASE_STR(NARROW_MISSING_TS_SECLABEL);
	NARROW_STATUS_CASE_STR(NARROW_NO_POLICY_LABEL);
	NARROW_STATUS_CASE_STR(NARROW_INCOMPATIBLE_LABEL);
	NARROW_STATUS_CASE_STR(NARROW_NOT_APPLICABLE);
	default: bad_case(status);
	}
	passert(!"Should not reach here");
	return "";
}

/**
 * narrow_seclabel: "Narrow" a security label for use with an child/IPsec SA.
 *
 * @param[in]	tss	Set of Traffic Selectors.
 * @param[in]	index	Index of the Traffic Selector in `tss` containing the
 * 			security label.
 * @param[in]	fit	What type of "narrowing" should be applied to the
 * 			security label.
 * @param[in]	child_state	State of the child/IPsec SA for which the
 * 				security label should be "narrowed."
 * @param[in]	what	Description of `tss`.
 *
 * @return	Result of the security label "narrowing" operation.
 */
static struct seclabel_narrow_result narrow_seclabel(struct traffic_selectors const *tss,
						     unsigned const index,
						     enum fit const fit,
						     struct state const* child_state,
						     char const *const what) {
	/* result: Result of security label narrowing. */
	struct seclabel_narrow_result result = { .status = NARROW_ERROR, .sec_ctx = NULL };
	/* ts: Traffic Selector being examined. */
	struct traffic_selector const *ts = &tss->ts[index];

	switch (fit) {
	case END_EQUALS_TS:
		if (child_state->sec_ctx != NULL) {
			/* The child/IPsec SA has a valid security label. */
			if (ts->sec_ctx != NULL) {
				/*
				 * The child/IPsec SA already has a valid security label.
				 * Check if it matches the Traffic Selector's security label.
				 */
				if (child_state->sec_ctx->ctx.ctx_len != ts->sec_ctx->ctx.ctx_len) {
					/* Label length mismatch. */
					result.status = NARROW_MISMATCH_EXISTING_LABEL_LENGTH;
					result.sec_ctx = NULL;
					loglog(RC_LOG_SERIOUS,
					       "ERROR: %s child_state->sec_ctx->ctx.ctx_len = %u ts->sec_ctx->ctx.ctx_len = %u child_state->sec_ctx->sec_ctx_value = %s ts->sec_ctx->sec_ctx_value = %s",
					       narrow_status_string(result.status),
					       child_state->sec_ctx->ctx.ctx_len,
					       ts->sec_ctx->ctx.ctx_len,
					       child_state->sec_ctx->sec_ctx_value,
					       ts->sec_ctx->sec_ctx_value);
					break;
				}
				if (!streq(child_state->sec_ctx->sec_ctx_value,
					   ts->sec_ctx->sec_ctx_value)) {
					/* Label value mismatch. */
					result.status = NARROW_MISMATCH_EXISTING_LABEL_VALUE;
					result.sec_ctx = NULL;
					loglog(RC_LOG_SERIOUS,
					       "ERROR: %s child_state->sec_ctx->sec_ctx_value = %s ts->sec_ctx->sec_ctx_value = %s",
					       narrow_status_string(result.status),
					       child_state->sec_ctx->sec_ctx_value,
					       ts->sec_ctx->sec_ctx_value);
					break;
				}

				/*
				 * The child/IPsec SA's existing security label matches that of
				 * the Traffic Selector's security label.
				 * NOTE: Use the child SA's security label in the return value,
				 * since it has an equal or longer lifetime than the one in the
				 * Traffic Selector.
				 */
				result.status = NARROW_OK;
				result.sec_ctx = child_state->sec_ctx;
				break;
			} else {
				/*
				 * The child/IPsec SA already has a valid security label,
				 * while the Traffic Selector doesn't have a security label.
				 */
				result.status = NARROW_MISSING_TS_SECLABEL;
				result.sec_ctx = NULL;
				loglog(RC_LOG_SERIOUS,
				       "ERROR: %s child_state->sec_ctx->sec_ctx_value = %s",
				       narrow_status_string(result.status),
				       child_state->sec_ctx->sec_ctx_value);
				break;
			}
		} else {
			/* The child/IPsec SA does NOT have a security label. */
			if (ts->sec_ctx != NULL) {
				/*
				 * - The child/IPsec SA does NOT have a security label
				 *   while the Traffic Selector does.
				 * - We are probably responding to a child SA connection
				 *   request, i.e. the Traffic Selector is incoming.
				 *
				 * Check if the Traffic Selector's security label is valid.
				 */
				if (child_state->st_connection->policy_label == NULL) {
					/*
					 * The connection configuration does NOT have
					 * security labeling enabled.
					 */
					result.status = NARROW_NO_POLICY_LABEL;
					result.sec_ctx = NULL;
					loglog(RC_LOG_SERIOUS,
					       "ERROR: %s ts->sec_ctx->sec_ctx_value = %s",
					       narrow_status_string(result.status),
					       ts->sec_ctx->sec_ctx_value);
					break;
				}

				if(!within_range(ts->sec_ctx->sec_ctx_value,
						 child_state->st_connection->policy_label)) {
					/*
					 * The Traffic Selector's security label is not
					 * compatible with the connection's configured security
					 * policy label.
					 */
					result.status = NARROW_INCOMPATIBLE_LABEL;
					result.sec_ctx = NULL;
					loglog(RC_LOG_SERIOUS,
					       "ERROR: %s ts->sec_ctx->sec_ctx_value = %s policy_label = %s",
					       narrow_status_string(result.status),
					       ts->sec_ctx->sec_ctx_value,
					       child_state->st_connection->policy_label);
					break;
				}

				/*
				 * The Traffic Selector's security label _is_ compatible
				 * with the connection's configured security policy label,
				 * i.e. it can be used with this child/IPsec SA if desired.
				 */
				result.status = NARROW_OK;
				result.sec_ctx = ts->sec_ctx;
				break;

			} else {
				/*
				 * Neither the child/IPsec SA nor the Traffic Selector has
				 * a security label.
				 */
				result.status = NARROW_OK;
				result.sec_ctx = NULL;
				break;
			}
		}
		passert(!"Should not reach here");
		break;
	case END_NARROWER_THAN_TS:
		/* This case is for when the endpoint allows optional labeling. */
		if (child_state->sec_ctx != NULL) {
			/* The child/IPsec SA has a valid security label. */
			if (ts->sec_ctx != NULL) {
				/*
				 * - The child/IPsec SA already has a valid security label.
				 * - In optional labeling, if an endpoint already has a security
				 *   label, then it should match the security label in the
				 *   Traffic Selector.
				 * - If you have two different security labels, then you cannot
				 *   narrow them. Hence, they have to match exactly.
				 *   - Recall that security labels are opaque to `pluto`.
				 *
				 * Check if it matches the Traffic Selector's security label.
				 */
				if (child_state->sec_ctx->ctx.ctx_len != ts->sec_ctx->ctx.ctx_len) {
					/* Label length mismatch. */
					result.status = NARROW_MISMATCH_EXISTING_LABEL_LENGTH;
					result.sec_ctx = NULL;
					loglog(RC_LOG_SERIOUS,
					       "ERROR: %s child_state->sec_ctx->ctx.ctx_len = %u ts->sec_ctx->ctx.ctx_len = %u child_state->sec_ctx->sec_ctx_value = %s ts->sec_ctx->sec_ctx_value = %s",
					       narrow_status_string(result.status),
					       child_state->sec_ctx->ctx.ctx_len,
					       ts->sec_ctx->ctx.ctx_len,
					       child_state->sec_ctx->sec_ctx_value,
					       ts->sec_ctx->sec_ctx_value);

					break;
				}
				if (!streq(child_state->sec_ctx->sec_ctx_value,
					   ts->sec_ctx->sec_ctx_value)) {
					/* Label value mismatch. */
					result.status = NARROW_MISMATCH_EXISTING_LABEL_VALUE;
					result.sec_ctx = NULL;
					loglog(RC_LOG_SERIOUS,
					       "ERROR: %s child_state->sec_ctx->sec_ctx_value = %s ts->sec_ctx->sec_ctx_value = %s",
					       narrow_status_string(result.status),
					       child_state->sec_ctx->sec_ctx_value,
					       ts->sec_ctx->sec_ctx_value);
					break;
				}

				/*
				 * The child/IPsec SA's existing security label matches that of
				 * the Traffic Selector's security label.
				 * NOTE: Use the child SA's security label in the return value,
				 * since it has an equal or longer lifetime than the one in the
				 * Traffic Selector.
				 */
				result.status = NARROW_OK;
				result.sec_ctx = child_state->sec_ctx;
				break;
			} else {
				/*
				 * The child/IPsec SA already has a valid security label,
				 * while the Traffic Selector doesn't have a security label.
				 * Since the endpoint should be narrower than the Traffic Selector,
				 * don't use the existing security label in the child/IPsec SA.
				 */
				result.status = NARROW_OK;
				result.sec_ctx = NULL;
				break;
			}
		} else {
			/* The child/IPsec SA does NOT have a security label. */
			if (ts->sec_ctx != NULL) {
				/*
				 * - The child/IPsec SA does NOT have a security label
				 *   while the Traffic Selector does.
				 * - We are probably responding to a child SA connection
				 *   request, i.e. the Traffic Selector is incoming.
				 *
				 * Check if the Traffic Selector's security label is valid.
				 */
				if (child_state->st_connection->policy_label == NULL) {
					/*
					 * The connection configuration does NOT have
					 * security labeling enabled.
					 *
					 * Since the endpoint can be narrower than the
					 * Traffic Selector, not using a security label
					 * is OK.
					 */
					result.status = NARROW_OK;
					result.sec_ctx = NULL;
					break;
				}

				if(!within_range(ts->sec_ctx->sec_ctx_value,
						 child_state->st_connection->policy_label)) {
					/*
					 * The Traffic Selector's security label is not
					 * compatible with the connection's configured security
					 * policy label.
					 *
					 * Since the endpoint can be narrower than the
					 * Traffic Selector, not using a security label
					 * is OK.
					 */
					result.status = NARROW_OK;
					result.sec_ctx = NULL;
					break;
				}

				/*
				 * The Traffic Selector's security label _is_ compatible
				 * with the connection's configured security policy label,
				 * i.e. it can be used with this child/IPsec SA if desired.
				 */
				result.status = NARROW_OK;
				result.sec_ctx = ts->sec_ctx;
				break;

			} else {
				/*
				 * Neither the child/IPsec SA nor the Traffic Selector has
				 * a security label.
				 */
				result.status = NARROW_OK;
				result.sec_ctx = NULL;
				break;
			}
		}
		passert(!"Should not reach here");
		break;
	case END_WIDER_THAN_TS:
		/*
		 * This case does NOT apply to security labels:
		 * the endpoint cannot use a security label while the Traffic Selector indicates
		 * that the endpoint should NOT use a security label.
		 */
		result.status = NARROW_NOT_APPLICABLE;
		result.sec_ctx = NULL;
		loglog(RC_LOG_SERIOUS, "ERROR: Security label narrowing not applicable");
		break;
	default:
		bad_case(fit);
	}

	dbg(MATCH_PREFIX "narrow seclabel end=%s %s %s[%u]=%s: status = %s sec_ctx = %s",
		(child_state->sec_ctx ? child_state->sec_ctx->sec_ctx_value : "<NULL>"),
		fit_string(fit),
		what,
		index,
		(ts->sec_ctx ? ts->sec_ctx->sec_ctx_value : "<NULL>"),
		narrow_status_string(result.status),
		(result.sec_ctx ? result.sec_ctx->sec_ctx_value : "<NULL>"));
	return result;
}

#endif	/* #ifndef HAVE_LABELED_IPSEC */

struct score {
	bool ok;
	int address;
	int port;
	int protocol;
	/**
	 * `label_score` is the score assigned to the "narrowed" security label component.
	 * A value > 0 means the "narrowing" was successful.
	 */
	int label_score;
	/**
	 * `sec_ctx` is the security label chosen for this score (if any).
	 */
	struct xfrm_user_sec_ctx_ike *sec_ctx;
};

/**
 * score_narrow_seclabel: Compute the score of a security label "narrowing" operation.
 *
 * @param[in,out]	score	Score for Traffic Selector narrowing operations.
 * @param[in]		tss	Set of Traffic Selectors.
 * @param[in]		index	Index of the Traffic Selector in `tss` containing the
 * 				security label.
 * @param[in]		fit	What type of "narrowing" should be applied to the
 * 				security label.
 * @param[in]		child_state	State of the child/IPsec SA for which the
 * 					security label should be "narrowed."
 * @param[in]		what	Description of `tss`.
 */
static void score_narrow_seclabel(struct score *score,
				  struct traffic_selectors const *tss,
				  unsigned const index,
				  enum fit const fit,
				  struct state const* child_state,
				  char const *const what) {
	struct seclabel_narrow_result result = narrow_seclabel(tss, index, fit, child_state, what);
	score->label_score = (result.status == NARROW_OK) ? 1 : 0;
	if (score->label_score > 0) {
		dbg(MATCH_PREFIX " %s[%u] seclabel match: YES fitness %d", what, index, score->label_score);
		score->sec_ctx = result.sec_ctx;
	} else {
		dbg(MATCH_PREFIX " %s[%u] seclabel match: NO", what, index);
	}
}

/**
 * score_end: Narrow Traffic Selectors and score the result.
 *
 * @param[in]	end	Endpoint specification.
 * @param[in]	tss	Set of Traffic Selectors.
 * @param[in]	fit	What type of narrowing should be applied to the
 * 			everything EXCEPT for the security label.
 * @param[in]	seclabel_fit	What type of "narrowing" should be applied to the
 * 				security label.
 * @param[in]	child_state	State of the child/IPsec SA for which the
 * 				security label should be "narrowed."
 * @param[in]	what	Description of `tss`.
 * @param[in]	index	Index of the Traffic Selector in `tss` containing the
 * 			security label.
 *
 * @return	Score of the narrowing operation.
 */
static struct score score_end(const struct end *end,
			      const struct traffic_selectors *tss,
			      enum fit fit,
			      enum fit const seclabel_fit,
			      struct state *const child_state,
			      const char *what,
			      unsigned index)
{
	const struct traffic_selector *ts = &tss->ts[index];
	range_buf ts_net;
	dbg("    %s[%u] .net=%s .iporotoid=%d .{start,end}port=%d..%d .seclabel=%s",
	    what, index,
	    str_range(&ts->net, &ts_net),
	    ts->ipprotoid,
	    ts->startport,
	    ts->endport,
	    (ts->sec_ctx ? ts->sec_ctx->sec_ctx_value : "<NULL>"));

	struct score score = { .ok = false, };
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
	score_narrow_seclabel(&score, tss, index, seclabel_fit, child_state, what);
	if(score.label_score <= 0) {
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
	/**
	 * `sec_ctx` corresponds to the security label chosen for this score.
	 */
	struct xfrm_user_sec_ctx_ike *sec_ctx;
};
#define  NO_SCORE { .ok = false, .address = -1, .port = -1, .protocol = -1, .sec_ctx = NULL }

static bool score_gt(const struct best_score *score, const struct best_score *best)
{
	/* Assumption: score->sec_ctx if not NULL is valid. */
	return (score->address > best->address ||
		(score->address == best->address &&
		 score->port > best->port) ||
		(score->address == best->address &&
		 score->port == best->port &&
		 score->protocol > best->protocol) ||
		(score->address == best->address &&
		 score->port == best->port &&
		 score->protocol == best->protocol &&
		 (score->sec_ctx != NULL && best->sec_ctx == NULL)));
}

static struct best_score score_ends(enum fit fit,
				    const struct connection *d,
				    const struct ends *ends,
				    enum fit const seclabel_fit,
				    struct state *const child_state,
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
		if (tni->ts_type == IKEv2_TS_SECLABEL) {
			/*
			 * Do NOT score a TS_SECLABEL Traffic Selector.
			 * Security label, if one exists, will be scored
			 * as part of an address range Traffic Selector.
			 */
			continue;
		}

		/* choice hardwired! */
		struct score score_i = score_end(ends->i, tsi, fit, seclabel_fit, child_state, "TSi", tsi_n);
		if (!score_i.ok) {
			continue;
		}

		for (unsigned tsr_n = 0; tsr_n < tsr->nr; tsr_n++) {
			const struct traffic_selector *tnr = &tsr->ts[tsr_n];
			if (tnr->ts_type == IKEv2_TS_SECLABEL) {
				/*
				 * See comment above regarding not scoring a TS_SECLABEL
				 * Traffic Selector.
				 */
				continue;
			}

			struct score score_r = score_end(ends->r, tsr, fit, seclabel_fit, child_state, "TSr", tsr_n);
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
				/* security label */
				.sec_ctx = score_i.sec_ctx,
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

/**
 * update_state_sec_ctx: Update the specified state's security label to a new
 * security label IF appropriate.
 *
 * @param[in,out]	st	IPsec SA state.
 * @param[in,out]	new_sec_ctx	New security label. 
 * 					NOTE: This function takes "ownership" of
 * 					`new_sec_ctx`. That means this function
 * 					frees the memory pointed to by
 * 					`new_sec_ctx` if this function cannot
 * 					assign it to `st` (i.e. pass "ownership"
 * 					to `st`).
 * @param[in]		role	IPsec SA role, i.e. Initiator or Responder.
 *
 * @return	True if updating `st`'s security label was successful.
 */
static bool update_state_sec_ctx(struct state *const st,
	   			 struct xfrm_user_sec_ctx_ike *new_sec_ctx,
				 char const* const role) {
	if (st->sec_ctx == new_sec_ctx) {
		/* Idempotent operation. Nothing to do. */
		return true;
	}

	/* return_val: True if updating `st->sec_ctx` with `new_sec_ctx` was successful. */
	bool return_val = false;
	if (st->sec_ctx == NULL) {
		/*
		 * state does not have a security context.
		 * Set the state's security context to the new security context.
		 * NOTE: The new security context may be NULL.
		 */
		st->sec_ctx = new_sec_ctx;
		return_val = true;
	} else {
		/* state already has a security label; do NOT overwrite. */
		if (new_sec_ctx != NULL) {
			if (streq(st->sec_ctx->sec_ctx_value, new_sec_ctx->sec_ctx_value)) {
				/*
				 * The new security context is simply a duplicate of the
				 * existing one. Hence, not an error.
				 */
				return_val = true;
			} else {
				/*
				 * An actual new + different security context is trying to
				 * replace the existing security context in the state.
				 */
				loglog(RC_LOG_SERIOUS, "%s: security context already exists = %s, new context = %s", role, st->sec_ctx->sec_ctx_value, new_sec_ctx->sec_ctx_value);
				return_val = false;
			}
		} else {
			/*
			 * A NULL security context is trying to replace the
			 * existing security context in the state.
			 */
			libreswan_log("%s: security context already exists = %s, no new context", role, st->sec_ctx->sec_ctx_value);
			return_val = false;
		}

		/*
		 * The caller passes "ownership" of `new_sec_ctx` into this function.
		 * That means if this function does NOT assign `new_sec_ctx` to `st->sec_ctx`
		 * and thereby pass the ownership to `st`, then this function must free
		 * `new_sec_ctx` before returning.
		 */
		if (new_sec_ctx != NULL) {
			pfreeany(new_sec_ctx);
		}
	}

	return return_val;
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
		/*
		 * Free memory allocated for security labels inside `tsi` and `tsr` to
		 * prevent memory leaks.
		 */
		free_sec_ctx_in_tss(&tsi);
		free_sec_ctx_in_tss(&tsr);
		return false;
	}

	/* best so far; start with state's connection */
	struct best_score best_score = NO_SCORE;
	const struct spd_route *best_spd_route = NULL;
	struct connection *best_connection = c;

	/* best_sec_ctx: More suitable security label to use if any */
	struct xfrm_user_sec_ctx_ike *best_sec_ctx = NULL;

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
		/*
		 * seclabel_fit: Indicates requirements for security label.
		 * For mandatory security labeling, there is no "narrowing", i.e.
		 * both endpoints MUST use security labels if one side requests it.
		 *
		 * FIXME: Once optional labeling is implemented, `seclabel_fit` can be
		 * END_NARROWER_THAN_TS as well.
		 */
		enum fit const seclabel_fit = END_EQUALS_TS;

		struct best_score score = score_ends(responder_fit, c, &ends,
						     seclabel_fit, &child->sa,
						     &tsi, &tsr);
		if (!score.ok) {
			continue;
		}
		if (score_gt(&score, &best_score)) {
			dbg("    found better spd route for TSi[%td],TSr[%td]",
			    score.tsi - tsi.ts, score.tsr - tsr.ts);
			best_score = score;
			best_spd_route = sra;
			best_sec_ctx = best_score.sec_ctx;
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
				/*
				 * seclabel_fit: Indicates requirements for security label.
				 * For mandatory security labeling, there is no "narrowing", i.e.
				 * both endpoints MUST use security labels if one side requests it.
				 *
				 * FIXME: Once optional labeling is implemented, `seclabel_fit` can be
				 * END_NARROWER_THAN_TS as well.
				 */
				enum fit const seclabel_fit = END_EQUALS_TS;

				struct best_score score = score_ends(responder_fit, d/*note D*/,
								     &ends,
								     seclabel_fit, &child->sa,
								     &tsi, &tsr);
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
					best_sec_ctx = best_score.sec_ctx;
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
				jam(buf, " policy=%s", prettypolicy(t->policy & CONNECTION_POLICIES));
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

			/*
			 * seclabel_fit: Indicates requirements for security label.
			 * For mandatory security labeling, there is no "narrowing", i.e.
			 * both endpoints MUST use security labels if one side requests it.
			 *
			 * FIXME: Once optional labeling is implemented, `seclabel_fit` can be
			 * END_NARROWER_THAN_TS as well.
			 */
			enum fit const seclabel_fit = END_EQUALS_TS;
			/* tsi_seclabel: Result of "narrowing" a security label. */
			struct seclabel_narrow_result tsi_seclabel = narrow_seclabel(
				&tsi, 0, seclabel_fit, &child->sa, "TSi");
			if (tsi_seclabel.status != NARROW_OK) {
				dbg("    skipping; TSi seclabel could not be \"narrowed\"");
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

			/* tsi_seclabel: Result of "narrowing" a security label. */
			struct seclabel_narrow_result tsr_seclabel = narrow_seclabel(
				&tsr, 0, seclabel_fit, &child->sa, "TSr");
			if (tsr_seclabel.status != NARROW_OK) {
				dbg("    skipping; TSr seclabel could not be \"narrowed\"");
				continue;
			}

			passert((tsi_seclabel.sec_ctx == tsr_seclabel.sec_ctx) ||
				(tsi_seclabel.sec_ctx && tsr_seclabel.sec_ctx &&
				 streq(tsi_seclabel.sec_ctx->sec_ctx_value, tsr_seclabel.sec_ctx->sec_ctx_value)));

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
			best_sec_ctx = tsi_seclabel.sec_ctx;

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

	/* does_tsi_have_seclabel: True if TSi has a security label */
	bool const does_tsi_have_seclabel = (tsi.nr > 0 && tsi.ts[0].sec_ctx != NULL);
	/* does_tsr_have_seclabel: True if TSr has a security label */
	bool const does_tsr_have_seclabel = (tsr.nr > 0 && tsr.ts[0].sec_ctx != NULL);

	/*
	 * Check if picking a security label was successful provided that one
	 * was available.
	 */
	if ((does_tsi_have_seclabel || does_tsr_have_seclabel) &&
	    (best_sec_ctx == NULL)) {
		/* Picking a security label was unsuccessful. */
		loglog(RC_LOG_SERIOUS,
		       "(%s) Error: Responder could not pick a TS_SECLABEL security label: TSi[0].sec_ctx = %s TSr[0].sec_ctx = %s",
		       __func__,
		       (does_tsi_have_seclabel ? tsi.ts[0].sec_ctx->sec_ctx_value : "<NULL>"),
		       (does_tsr_have_seclabel ? tsr.ts[0].sec_ctx->sec_ctx_value : "<NULL>"));
		free_sec_ctx_in_tss(&tsi);
		free_sec_ctx_in_tss(&tsr);
		/* This results in a TS_UNACCEPTABLE further up the call stack. */
		return false;
	}

	if (best_sec_ctx != NULL) {
		/*
		 * If `best_sec_ctx` is pointing to memory allocated inside `tsi` or `tsr`,
		 * we need to clone it before freeing said memory in `tsi` and `tsr`.
		 */
		if (does_tsi_have_seclabel && (best_sec_ctx == tsi.ts[0].sec_ctx)) {
			/*
			 * `best_sec_ctx` is from TSi.
			 * Clone it before freeing the label in TSi.
			 */
			best_sec_ctx = clone_thing(*best_sec_ctx,
						   "struct xfrm_user_sec_ctx_ike : cloned from TSi in v2_process_ts_request()");
		} else if (does_tsr_have_seclabel && (best_sec_ctx == tsr.ts[0].sec_ctx)) {
			/*
			 * `best_sec_ctx` is from TSr.
			 * Clone it before freeing the label in TSr.
			 */
			best_sec_ctx = clone_thing(*best_sec_ctx,
						   "struct xfrm_user_sec_ctx_ike : cloned from TSr in v2_process_ts_request()");
		}
	}

	/*
	 * Free memory allocated for security labels inside `tsi` and `tsr` to
	 * prevent memory leaks.
	 */
	free_sec_ctx_in_tss(&tsi);
	free_sec_ctx_in_tss(&tsr);

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

	/*
	 * Update the child/IPsec SA's state with the chosen security label if
	 * possible.
	 */
	struct state *const st = &child->sa;
	if (!update_state_sec_ctx(st, best_sec_ctx, "Responder")) {
		loglog(RC_LOG_SERIOUS, "%s: Could not update state's security label to %s for %s",
		       __func__,
		       (best_sec_ctx ? best_sec_ctx->sec_ctx_value : "<NULL>"),
		       "Responder");
		return false;
	}

	st->st_ts_this = ikev2_make_ts(&best_spd_route->this, st->sec_ctx);
	st->st_ts_that = ikev2_make_ts(&best_spd_route->that, st->sec_ctx);

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
		/* Free any memory allocated for security labels to prevent leaks. */
		free_sec_ctx_in_tss(&tsi);
		free_sec_ctx_in_tss(&tsr);
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
	/*
	 * seclabel_fit: Indicates requirements for security label.
	 * For mandatory security labeling, there is no "narrowing", i.e.
	 * both endpoints MUST use security labels if one side requests it.
	 *
	 * FIXME: Once optional labeling is implemented, `seclabel_fit` can be
	 * END_NARROWER_THAN_TS as well.
	 */
	enum fit const seclabel_fit = END_EQUALS_TS;

	struct best_score best = score_ends(initiator_widening, c, &e,
					    seclabel_fit, &child->sa,
					    &tsi, &tsr);

	if (!best.ok) {
		dbg("reject responder TSi/TSr Traffic Selector");
		/* Free any memory allocated for security labels to prevent leaks. */
		free_sec_ctx_in_tss(&tsi);
		free_sec_ctx_in_tss(&tsr);
		/* prevents parent from going to I3 */
		return false;
	}

	dbg("found an acceptable TSi/TSr Traffic Selector");
	struct state *st = &child->sa;
	memcpy(&st->st_ts_this, best.tsi,
	       sizeof(struct traffic_selector));
	memcpy(&st->st_ts_that, best.tsr,
	       sizeof(struct traffic_selector));

	struct xfrm_user_sec_ctx_ike *incoming_sec_ctx = best.sec_ctx;
	if (incoming_sec_ctx != NULL) {
		/*
		 * If `incoming_sec_ctx` is pointing to memory allocated inside `tsi` or `tsr`,
		 * we need to clone it before freeing said memory in `tsi` and `tsr`.
		 */
		if ((tsi.nr > 0) && (incoming_sec_ctx == tsi.ts[0].sec_ctx)) {
			/*
			 * `incoming_sec_ctx` is from TSi.
			 * Clone it before freeing the label in TSi.
			 */
			incoming_sec_ctx = clone_thing(*incoming_sec_ctx,
						       "struct xfrm_user_sec_ctx_ike : cloned from TSi in v2_process_ts_response()");
		} else if ((tsr.nr > 0) && (incoming_sec_ctx == tsr.ts[0].sec_ctx)) {
			/*
			 * `incoming_sec_ctx` is from TSr.
			 * Clone it before freeing the label in TSr.
			 */
			incoming_sec_ctx = clone_thing(*incoming_sec_ctx,
						       "struct xfrm_user_sec_ctx_ike : cloned from TSr in v2_process_ts_response()");
		}
	}

	/* Free any memory allocated for security labels to prevent leaks. */
	free_sec_ctx_in_tss(&tsi);
	free_sec_ctx_in_tss(&tsr);

	/* Update the state's security label using `incoming_sec_ctx` IF appropriate. */
	if (!update_state_sec_ctx(st, incoming_sec_ctx, "Initiator")) {
		loglog(RC_LOG_SERIOUS, "%s: Could not update state's security label to %s for %s",
		       __func__,
		       (incoming_sec_ctx ? incoming_sec_ctx->sec_ctx_value : "<NULL>"),
		       "Initiator");
		return false;
	}

	/*
	 * The security labels of the Traffic Selectors inside the state should always
	 * point to the state's current security label.
	 */
	st->st_ts_this.sec_ctx = st->sec_ctx;
	st->st_ts_that.sec_ctx = st->sec_ctx;

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
		  &c->spd.this.client.addr);

	c->spd.this.has_client =
		!(subnetishost(&c->spd.this.client) &&
		  addrinsubnet(&c->spd.this.host_addr,
			       &c->spd.this.client));

	c->spd.that.client = tmp_subnet_r;
	c->spd.that.port = st->st_ts_that.startport;
	c->spd.that.protocol = st->st_ts_that.ipprotoid;
	setportof(htons(c->spd.that.port),
		  &c->spd.that.client.addr);

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

	/*
	 * seclabel_fit: Indicates requirements for security label.
	 * For mandatory security labeling, there is no "narrowing", i.e.
	 * both endpoints MUST use security labels if one side requests it.
	 *
	 * FIXME: Once optional labeling is implemented, `seclabel_fit` can be
	 * END_NARROWER_THAN_TS as well.
	 */
	enum fit const seclabel_fit = END_EQUALS_TS;

	struct best_score score = score_ends(fitness, c, &ends,
					     seclabel_fit, &child->sa,
					     &their_tsis, &their_tsrs);

	/*
	 * Free memory allocated for security labels inside `tsi` and `tsr` to
	 * prevent memory leaks.
	 */
	free_sec_ctx_in_tss(&their_tsis);
	free_sec_ctx_in_tss(&their_tsrs);

	if (!score.ok) {
		log_state(RC_LOG_SERIOUS, &child->sa,
			  "rekey: received Traffic Selectors does not contain existing IPsec SA Traffic Selectors");
		return false;
	}

	return true;
}
