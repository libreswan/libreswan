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
 * Copyright (C) 2019-2023 Andrew Cagney <cagney@gnu.org>
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
#include "connections.h"
#include "demux.h"
#include "ip_info.h"
#include "ip_selector.h"
#include "labeled_ipsec.h"
#include "ip_range.h"
#include "iface.h"
#include "pending.h"		/* for connection_is_pending() */
#include "spd_db.h"	/* for spd_route_db_add_connection() */
#include "instantiate.h"

#define TS_MAX 16 /* arbitrary */

typedef struct {
	struct logger *logger;
	unsigned level;
} indent_t;

#define TS_INDENT "ts:%*s "
#define ts_indent indent.level*2, ""
#define dbg_ts(FORMAT, ...) ldbg(indent.logger, TS_INDENT""FORMAT, ts_indent, ##__VA_ARGS__)

struct score {
	int range;
	int protocol;
	int port;
};

struct narrowed_selector {
	const char *name;	/* XXX: redundant? */
	unsigned nr;
	bool block;
	struct score score;
	ip_selector selector;
};

struct narrowed_selector_payload {
	const char *name;	/* XXX: redundant? */
	struct score score;
	shunk_t sec_label;
	unsigned nr;
	struct narrowed_selector ns[TS_MAX];
};

struct narrowed_selector_payloads {
	struct score score;
	struct narrowed_selector_payload i;
	struct narrowed_selector_payload r;
};

/*
 * While the RFC seems to suggest that the traffic selectors come in
 * pairs, strongswan, at least, doesn't.
 *
 * Try to follow the naming from Traffic Selector clarification
 * https://datatracker.ietf.org/doc/html/draft-ietf-ipsecme-labeled-ipsec#section-1.2
 */

struct traffic_selector {
	unsigned nr;
	uint8_t ts_type;
	uint8_t ipprotoid;
	uint16_t startport;
	uint16_t endport;
	ip_range range;	/* for now, always happens to be a CIDR */
	const char *name; /*static*/
};

struct traffic_selector_payload {
	const char *name;	/* XXX: redundant? */
	shunk_t sec_label;
	unsigned nr;
	/* ??? is 16 an undocumented limit - IKEv2 has no limit */
	struct traffic_selector ts[TS_MAX];
};

struct traffic_selector_payloads {
	struct traffic_selector_payload i;
	struct traffic_selector_payload r;
};

static const struct traffic_selector_payloads empty_traffic_selector_payloads = {
	.i = {
		.name = "TSi",
	},
	.r = {
		.name = "TSr",
	},
};

struct child_selector_end {
	chunk_t sec_label; /*points into config*/
	const ip_selectors *selectors;
};

struct child_selector_ends {
	struct child_selector_end i;
	struct child_selector_end r;
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

static void scribble_accepted_selectors(ip_selectors *selectors,
					const struct narrowed_selector_payload *nsp,
					indent_t indent)
{
	if (selectors->len > 0) {
		pexpect(selectors->len > 0);
		pexpect(selectors->list != NULL);
		ldbg(indent.logger, "skipping scribble as already scribbled");
	} else {
		pexpect(selectors->len == 0);
		pexpect(selectors->list == NULL);
		*selectors = (ip_selectors) {
			.len = nsp->nr,
			.list = alloc_things(ip_selector, nsp->nr, "accepted-selectors"),
		};
		for (unsigned i = 0; i < nsp->nr; i++) {
			selectors->list[i] = nsp->ns[i].selector;
		}
	}
}

static void llog_narrowed_selector_payloads(lset_t rc_flags,
					    struct logger *logger,
					    const struct narrowed_selector_payload *local_nsp,
					    const struct narrowed_selector_payload *remote_nsp)
{
	LLOG_JAMBUF(rc_flags, logger, buf) {
		jam_string(buf, "accepted selectors");
		const char *sep = " [";
		FOR_EACH_THING(nsp, local_nsp, remote_nsp) {
			jam_string(buf, sep); sep = "";
			for (unsigned n = 0; n < nsp->nr; n++) {
				const struct narrowed_selector *ns = &nsp->ns[n];
				jam_string(buf, sep); sep = " ";
				jam_selector(buf, &ns->selector);
				if (ns->block) {
					jam_string(buf, "(block)");
				}
			}
			sep = "]->[";
		}
		jam_string(buf, "]");
	}
}

static void scribble_selectors_on_spd(struct connection *c,
				      const struct narrowed_selector_payload *local_nsp,
				      const struct narrowed_selector_payload *remote_nsp,
				      indent_t indent)
{
	scribble_accepted_selectors(&c->local->child.selectors.accepted, local_nsp, indent);
	scribble_accepted_selectors(&c->remote->child.selectors.accepted, remote_nsp, indent);

	/*
	 * Log accepted list when multiple traffic selectors are
	 * involved.
	 */
	if (local_nsp->nr > 1 || remote_nsp->nr > 1) {
		llog_narrowed_selector_payloads(RC_LOG, indent.logger,
						local_nsp, remote_nsp);
	} else if (DBGP(DBG_BASE)) {
		llog_narrowed_selector_payloads(DEBUG_STREAM, indent.logger,
						local_nsp, remote_nsp);
	}

	/*
	 * Now build spds from selectors.
	 */

	unsigned nr_spds = 0;
	for (unsigned pass = 1; pass <= 2; pass++) {
		if (pass == 2) {
			discard_connection_spds(c);
			alloc_connection_spds(c, nr_spds);
		}
		nr_spds = 0;
		for (const struct narrowed_selector *local_ns = local_nsp->ns;
		     local_ns < local_nsp->ns + local_nsp->nr; local_ns++) {
			for (const struct narrowed_selector *remote_ns = remote_nsp->ns;
			     remote_ns < remote_nsp->ns + remote_nsp->nr; remote_ns++) {
				if (selector_info(local_ns->selector) == selector_info(remote_ns->selector)) {
					if (pass == 2) {
						struct spd *spd = &c->child.spds.list[nr_spds];
						spd->local->client = local_ns->selector;
						spd->remote->client = remote_ns->selector;
						spd->block = local_ns->block || remote_ns->block;
						spd_db_add(spd);
					}
					nr_spds++;
				}
			}
		}
	}
}

static void scribble_ts_request_on_responder(struct child_sa *child,
					     struct connection *c,
					     const struct narrowed_selector_payloads *nsps,
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

	/* end game; polarity reversed */
	scribble_selectors_on_spd(c, /*local*/&nsps->r, /*remote*/&nsps->i, indent);
}

static void scribble_ts_response_on_initiator(struct child_sa *child,
					      const struct narrowed_selector_payloads *nsps,
					      indent_t indent)
{
	/* end game */
	struct connection *c = child->sa.st_connection;
	scribble_selectors_on_spd(c, /*local*/&nsps->i, /*remote*/&nsps->r, indent);

	/*
	 * Redundant (should have been set earlier)?
	 *
	 * Meaningless (with multiple TS)?
	 */
	set_child_has_client(c, local, !selector_eq_address(c->spd->local->client,
							    c->local->host.addr));
	set_child_has_client(c, remote, !selector_eq_address(c->spd->remote->client,
							     c->remote->host.addr));
}

/*
 * A struct spd_end is converted to a struct traffic_selector.
 *
 * This (currently) can contain both an IP range AND a SEC_LABEL,
 * which will get output here as two Traffic Selectors. The label is
 * optional, the IP range is mandatory.
 */

static bool emit_v2TS_selector(struct pbs_out *ts_pbs, ip_selector selector)
{
	const struct ip_info *afi = selector_info(selector);

	struct ikev2_ts_header ts_range_header = {
		.isath_type = afi->ikev2_ts_addr_range_type,
		.isath_ipprotoid = selector.ipproto,
	};

	pb_stream ts_range_pbs;
	if (!pbs_out_struct(ts_pbs, &ikev2_ts_header_desc,
			    &ts_range_header, sizeof(ts_range_header),
			    &ts_range_pbs)) {
		/* already logged */
		return false;
	}

	struct ikev2_ts_portrange ts_ports = {
		.isatpr_startport = selector.hport,
		.isatpr_endport = (selector.hport == 0 ? 65535 : selector.hport),
	};

	if (!pbs_out_struct(&ts_range_pbs, &ikev2_ts_portrange_desc,
			    &ts_ports, sizeof(ts_ports), NULL)) {
		/* already logged */
		return false;
	}

	ip_range range = selector_range(selector);
	if (!pbs_out_address(&ts_range_pbs, range_start(range), "IP start")) {
		/* already logged */
		return false;
	}
	if (!pbs_out_address(&ts_range_pbs, range_end(range), "IP end")) {
		/* already logged */
		return false;
	}
	close_output_pbs(&ts_range_pbs);
	return true;
}

static bool emit_v2TS_sec_label(struct pbs_out *ts_pbs, shunk_t sec_label)
{
	struct ikev2_ts_header ts_sec_label_header = {
		.isath_type = IKEv2_TS_SECLABEL,
		.isath_ipprotoid = 0 /* really RESERVED, not iprotoid */
	};

	/* Output the header of the TS_SECLABEL substructure payload. */
	struct pbs_out ts_label_pbs;
	if (!pbs_out_struct(ts_pbs, &ikev2_ts_header_desc,
			    &ts_sec_label_header, sizeof(ts_sec_label_header),
			    &ts_label_pbs)) {
		/* already logged */
		return false;
	}

	/*
	 * Output the security label value of the TS_SECLABEL
	 * substructure payload.
	 *
	 * If we got ACQUIRE, or received a subset TS_LABEL,
	 * use that one - it is subset of connection policy
	 * one
	 */

	dbg("emitting sec_label="PRI_SHUNK, pri_shunk(sec_label));
	if (!pbs_out_hunk(&ts_label_pbs, sec_label, "output Security label")) {
		/* already logged */
		return false;
	}

	close_output_pbs(&ts_label_pbs);
	return true;
}

static ip_selector impair_selector_to_subnet(ip_selector ts)
{
	const struct ip_info *afi = selector_info(ts);
	ts.maskbits = afi->mask_cnt;
	return ts;
}

static ip_selector impair_selector_to_supernet(ip_selector ts)
{
	ts.maskbits = 0;
	ts.bytes = unset_ip_bytes;
	return ts;
}

static bool emit_v2TS_payload(struct pbs_out *outpbs,
			      const struct child_sa *child,
			      const struct_desc *ts_desc,
			      ip_selectors *selectors,
			      shunk_t sec_label,
			      const struct impair_unsigned *impaired_len,
			      const char *name)
{
	unsigned nr_ts = selectors->len;
	if (sec_label.len > 0) {
		nr_ts++;
	}

	if (impaired_len->enabled) {
		unsigned new_nr = impaired_len->value;
		llog(RC_LOG, outpbs->outs_logger,
		     "IMPAIR: forcing number of %s selectors from %u to %u",
		     name, nr_ts, new_nr);
		nr_ts = new_nr;
	}

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
		.isat_num = nr_ts,
	};

	struct pbs_out ts_pbs;
	if (!out_struct(&its, ts_desc, outpbs, &ts_pbs)) {
		return false;
	}

	FOR_EACH_ITEM(s, selectors) {

		ip_selector ts = *s;
		if (child->sa.st_state->kind == STATE_V2_REKEY_CHILD_R0 &&
		    impair.rekey_respond_subnet) {
			ts = impair_selector_to_subnet(ts);
			selector_buf sb;
			llog_sa(RC_LOG, child, "IMPAIR: rekey-respond-subnet %s set to %s",
				name, str_selector(&ts, &sb));
		}
		if (child->sa.st_state->kind == STATE_V2_REKEY_CHILD_R0 &&
		    impair.rekey_respond_supernet) {
			ts = impair_selector_to_supernet(ts);
			selector_buf sb;
			llog_sa(RC_LOG, child, "IMPAIR: rekey-respond-supernet %s set to %s",
				name, str_selector(&ts, &sb));
		}
		if (child->sa.st_state->kind == STATE_V2_REKEY_CHILD_I0 &&
		    impair.rekey_initiate_supernet) {
			ts = impair_selector_to_supernet(ts);
			selector_buf tsb;
			llog_sa(RC_LOG, child,
				"IMPAIR: rekey-initiate-supernet %s set to %s",
				name, str_selector(&ts, &tsb));
		}
		if (child->sa.st_state->kind == STATE_V2_REKEY_CHILD_I0 &&
		    impair.rekey_initiate_subnet) {
			ts = impair_selector_to_subnet(ts);
			selector_buf tsb;
			llog_sa(RC_LOG, child,
				"IMPAIR: rekey-initiate-subnet %s set to %s",
				name, str_selector(&ts, &tsb));
		}

		if (!emit_v2TS_selector(&ts_pbs, ts)) {
			return false;
		}
	}

	if (sec_label.len > 0 &&
	    !emit_v2TS_sec_label(&ts_pbs, sec_label)) {
		return false;
	}

	close_output_pbs(&ts_pbs);
	return true;
}

bool emit_v2TS_request_payloads(struct pbs_out *out, const struct child_sa *child)
{
	pexpect(child->sa.st_sa_role == SA_INITIATOR);
	struct connection *c = child->sa.st_connection;

	if (!emit_v2TS_payload(out, child, &ikev2_ts_i_desc,
			       &c->local->child.selectors.proposed,
			       HUNK_AS_SHUNK(c->child.sec_label),
			       &impair.number_of_TSi_selectors,
			       "local TSi")) {
		return false;
	}

	if (!emit_v2TS_payload(out, child, &ikev2_ts_r_desc,
			       &c->remote->child.selectors.proposed,
			       HUNK_AS_SHUNK(c->child.sec_label),
			       &impair.number_of_TSr_selectors,
			       "remote TSr")) {
		return false;
	}

	return true;
}

bool emit_v2TS_response_payloads(struct pbs_out *outpbs, const struct child_sa *child)
{
	const struct connection *c = child->sa.st_connection;

	passert(child->sa.st_sa_role == SA_RESPONDER);

	/*
	 * XXX: the CP code brokenly bypasses the TS code leaving the
	 * field unset
	 *
	 * XXX: CK_PERMENANT connections don't need to instantiate so
	 * don't scribble on the TS
	 */
	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		if (c->end[end].child.selectors.accepted.len == 0) {
			ldbg_sa(child, "connection %s does not have accepted selectors",
				c->end[end].config->leftright);
		}
	}

	ip_selectors *accepted_ts_i =
		(c->remote->child.selectors.accepted.len > 0 ? &c->remote->child.selectors.accepted : &c->remote->child.selectors.proposed);
	if (!emit_v2TS_payload(outpbs, child, &ikev2_ts_i_desc, accepted_ts_i,
			       HUNK_AS_SHUNK(c->child.sec_label),
			       &impair.number_of_TSi_selectors,
			       "remote TSi")) {
		return false;
	}

	ip_selectors *accepted_ts_r =
		(c->local->child.selectors.accepted.len > 0 ? &c->local->child.selectors.accepted : &c->local->child.selectors.proposed);
	if (!emit_v2TS_payload(outpbs, child, &ikev2_ts_r_desc, accepted_ts_r,
			       HUNK_AS_SHUNK(c->child.sec_label),
			       &impair.number_of_TSr_selectors,
			       "local TSr")) {
		return false;
	}

	return true;
}

/* return success */
static bool v2_parse_tsp(struct payload_digest *const ts_pd,
			 struct traffic_selector_payload *tsp,
			 struct logger *logger)
{
	diag_t d;
	err_t e;

	dbg("%s: parsing %u traffic selectors",
	    tsp->name, ts_pd->payload.v2ts.isat_num);

	if (ts_pd->payload.v2ts.isat_num == 0) {
		llog(RC_LOG, logger,
		     "%s payload contains no entries when at least one is expected",
		     tsp->name);
		return false;
	}

	/*
	 * Since tsp->ts contains address ranges and not sec-labels,
	 * this check is a little conservative (otoh, there are hardly
	 * ever sec-labels).
	 */
	if (ts_pd->payload.v2ts.isat_num >= elemsof(tsp->ts)) {
		llog(RC_LOG, logger,
		     "%s contains %d entries which exceeds hardwired max of %zu",
		     tsp->name, ts_pd->payload.v2ts.isat_num, elemsof(tsp->ts));
		return false;	/* won't fit in array */
	}

	for (unsigned n = 0; n < ts_pd->payload.v2ts.isat_num; n++) {

		struct ikev2_ts_header ts_h;
		struct pbs_in ts_body_pbs;
		d = pbs_in_struct(&ts_pd->pbs, &ikev2_ts_header_desc,
				  &ts_h, sizeof(ts_h), &ts_body_pbs);
		if (d != NULL) {
			llog_diag(RC_LOG, logger, &d, "%s", "");
			return false;
		}

		switch (ts_h.isath_type) {
		case IKEv2_TS_IPV4_ADDR_RANGE:
		case IKEv2_TS_IPV6_ADDR_RANGE:
		{
			/* read and fill in port range */
			struct ikev2_ts_portrange pr;

			d = pbs_in_struct(&ts_body_pbs, &ikev2_ts_portrange_desc,
				  &pr, sizeof(pr), NULL);
			if (d != NULL) {
				llog_diag(RC_LOG, logger, &d, "%s", "");
				return false;
			}

			if (pr.isatpr_startport > pr.isatpr_endport) {
				llog(RC_LOG, logger,
				     "%s traffic selector %d has an invalid port range - ignored",
				     tsp->name, tsp->nr);
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
			if (pbs_left(&ts_body_pbs) != 0) {
				return false;
			}

			ip_range range;
			e = addresses_to_nonzero_range(start, end, &range);
			if (e != NULL) {
				address_buf sb, eb;
				llog(RC_LOG, logger, "Traffic Selector range %s-%s invalid: %s",
				     str_address_sensitive(&start, &sb),
				     str_address_sensitive(&end, &eb),
				     e);
				return false;
			}

			/* pluto doesn't yet do full ranges; check for subnet */
			ip_subnet ignore;
			e = range_to_subnet(range, &ignore);
			if (e != NULL) {
				address_buf sb, eb;
				llog(RC_LOG, logger, "non-CIDR Traffic Selector range %s-%s is not supported (%s)",
				     str_address_sensitive(&start, &sb),
				     str_address_sensitive(&end, &eb),
				     e);
				return false;
			}

			passert(tsp->nr < elemsof(tsp->ts));
			tsp->ts[tsp->nr] = (struct traffic_selector) {
				.name = tsp->name,
				.nr = n+1, /* count from 1 */
				.range = range,
				.startport = pr.isatpr_startport,
				.endport = pr.isatpr_endport,
				.ipprotoid = ts_h.isath_ipprotoid,
				.ts_type = ts_h.isath_type,
			};
			tsp->nr++;
			break;
		}

		case IKEv2_TS_SECLABEL:
		{
			if (ts_h.isath_ipprotoid != 0) {
				llog(RC_LOG, logger,
				     "Traffic Selector of type Security Label should not have non-zero IP protocol '%u' - ignored",
				     ts_h.isath_ipprotoid);
				/* do not stumble on; this is SE linux */
				return false;
			}

			shunk_t sec_label = pbs_in_left(&ts_body_pbs);
			err_t ugh = vet_seclabel(sec_label);
			if (ugh != NULL) {
				llog(RC_LOG, logger, "Traffic Selector of type Security Label %s", ugh);
				/* do not stumble on; this is SE linux */
				return false;
			}


			if (tsp->sec_label.len > 0) {
				llog(RC_LOG, logger,
				     "duplicate Traffic Selector of type Security Label");
				/* do not stumble on; this is SE linux */
				return false;
			}

			tsp->sec_label = sec_label;
			break;
		}

		case IKEv2_TS_FC_ADDR_RANGE:
			llog(RC_LOG, logger, "Encountered Traffic Selector Type FC_ADDR_RANGE not supported");
			return false;

		default:
			llog(RC_LOG, logger, "Encountered Traffic Selector of unknown Type");
			return false;
		}
	}

	dbg("%s: parsed %d traffic selectors", tsp->name, tsp->nr);
	return true;
}

static bool v2_parse_tsps(const struct msg_digest *md,
			  struct traffic_selector_payloads *tsps,
			  struct logger *logger)
{
	if (!v2_parse_tsp(md->chain[ISAKMP_NEXT_v2TSi], &tsps->i, logger)) {
		return false;
	}

	if (!v2_parse_tsp(md->chain[ISAKMP_NEXT_v2TSr], &tsps->r, logger)) {
		return false;
	}

	return true;
}

/*
 * Check if our policy's protocol (proto) matches the Traffic Selector
 * protocol (ts_proto).
 */

static const struct ip_protocol *narrow_protocol(ip_selector selector,
						 const struct traffic_selector *ts,
						 enum fit fit, indent_t indent)
{
	int ipproto = -1;

	switch (fit) {
	case END_EQUALS_TS:
		if (selector.ipproto == ts->ipprotoid) {
			ipproto = selector.ipproto;
		}
		break;
	case END_NARROWER_THAN_TS:
		if (ts->ipprotoid == 0 /* wild-card */ ||
		    ts->ipprotoid == selector.ipproto) {
			ipproto = selector.ipproto;
		}
		break;
	case END_WIDER_THAN_TS:
		if (selector.ipproto == 0 /* wild-card */ ||
		    selector.ipproto == ts->ipprotoid) {
			ipproto = ts->ipprotoid;
		}
		break;
	default:
		bad_case(fit);
	}
	const struct ip_protocol *protocol = ipproto >= 0 ? protocol_from_ipproto(ipproto) : NULL;
	dbg_ts("narrow protocol: selector.ipproto=%s%d %s %s[%u]=%s%d ==> %s (%s)",
	       (selector.ipproto == 0 ? "*" : ""),
	       selector.ipproto,
	       str_end_fit_ts(fit),
	       ts->name, ts->nr, ts->ipprotoid == 0 ? "*" : "", ts->ipprotoid,
	       (protocol == NULL ? "<unset>" : protocol->name),
	       str_fit_story(fit));
	return protocol;
}

/*
 * Narrow the END/TS ports according to FIT.
 *
 * Returns 0 (all ports), a specific port number, or -1 (no luck).
 *
 * Since 'struct spd_end' only describes all-ports or a single port; can
 * only narrow to that.
 */

static int narrow_port(ip_selector selector,
		       const struct traffic_selector *ts,
		       enum fit fit, indent_t indent)
{
	int end_low = selector.hport;
	int end_high = selector.hport == 0 ? 65535 : selector.hport;
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
	dbg_ts("narrow port: selector.port=%u..%u %s %s[%u]=%u..%u ==> %d..%d(%d) (%s)",
	       end_low, end_high,
	       str_end_fit_ts(fit),
	       ts->name, ts->nr, ts->startport, ts->endport,
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

static ip_range narrow_range(ip_selector selector,
			     const struct traffic_selector *ts,
			     enum fit fit, indent_t indent)
{
	/*
	 * NOTE: Our parser/config only allows 1 CIDR, however IKEv2
	 *       ranges can be non-CIDR for now we really
	 *       support/limit ourselves to a single CIDR
	 *
	 * XXX: so what is CIDR?  It's <prefix>/<length>.
	 */
	ip_range range = unset_range;
	ip_range client_range = selector_range(selector);
	switch (fit) {
	case END_EQUALS_TS:
		if (range_eq_range(client_range, ts->range)) {
			range = client_range;
		}
		break;
	case END_NARROWER_THAN_TS:
		if (range_in_range(client_range, ts->range)) {
			range = client_range;
		}
		break;
	case END_WIDER_THAN_TS:
		if (range_in_range(ts->range, client_range)) {
			range = ts->range;
		}
		break;
	default:
		bad_case(fit);
	}

	range_buf cb;
	range_buf tsb, rb;
	dbg_ts("narrow range: selector.range=%s %s %s[%u]=%s ==> %s (%s)",
	       str_range(&client_range, &cb),
	       str_end_fit_ts(fit),
	       ts->name, ts->nr, str_range(&ts->range, &tsb),
	       str_range(&range, &rb), str_fit_story(fit));
	return range;
}

static bool narrow_ts_to_selector(struct narrowed_selector *n,
				  const struct traffic_selector *ts,
				  ip_selector selector,
				  enum fit fit, indent_t indent)
{
	*n = (struct narrowed_selector) {
		.name = ts->name,
		.nr = ts->nr,
	};

	switch (ts->ts_type) {
	case IKEv2_TS_IPV4_ADDR_RANGE:
	case IKEv2_TS_IPV6_ADDR_RANGE:
		break;
	default:
		return false;
	}

	int hport = narrow_port(selector, ts, fit, indent);
	if (hport < 0) {
		dbg_ts("skipping; %s[%d] port too wide", ts->name, ts->nr);
		return false;
	}

	const struct ip_protocol *protocol = narrow_protocol(selector, ts, fit, indent);
	if (protocol == NULL) {
		dbg_ts("skipping; %s[%d] protocol too wide", ts->name, ts->nr);
		return false;
	}

	ip_range range = narrow_range(selector, ts, fit, indent);
	if (range_is_unset(&range)) {
		dbg_ts("skipping; %s[%d] range too wide", ts->name, ts->nr);
		return false;
	}

	n->selector = selector_from_range_protocol_port(range, protocol,
							ip_hport(hport));
	return true;
}

/*
 * Assign a score to the narrowed port, rationale for score lost in
 * time?
 */

static bool score_narrowed_selector(struct score *score,
				    const struct narrowed_selector *ts,
				    indent_t indent)
{
	if (!pexpect(ts->selector.is_set)) {
		return false;
	}

	indent.level++;
	zero(score);

	ip_range range = selector_range(ts->selector);
	score->range = range_prefix_len(range) + 1;
	range_buf rb;
	dbg_ts("narrowed %s[%u] address-range %s has fitness %d",
	       ts->name, ts->nr, str_range(&range, &rb),
	       score->range);

	score->port = (ts->selector.hport > 0 ? 1 :
			  65536 /* from 1 + 65535-0 */);
	dbg_ts("narrowed %s[%u] port %d has fitness %d",
	       ts->name, ts->nr, ts->selector.hport, score->port);

	/* strength of match; 255: ??? odd value */
	const struct ip_protocol *protocol = selector_protocol(ts->selector);
	score->protocol = (protocol == &ip_protocol_all ? 255 : 1);
	dbg_ts("narrowed %s[%u] protocol %s has fitness %d",
	       ts->name, ts->nr, protocol->name, score->protocol);

	return true;
}

static bool score_gt_best(const struct score *score,
			  const struct score *best)
{
	return ((score->range > best->range) ||
		(score->range == best->range && score->port > best->port) ||
		(score->range == best->range && score->port == best->port && score->protocol > best->protocol));
}

static bool fit_ts_to_selector(struct narrowed_selector *ns,
			       const struct traffic_selector *ts,
			       ip_selector selector,
			       enum fit fit, indent_t indent)
{
	if (!narrow_ts_to_selector(ns, ts, selector, fit, indent)) {
		return false;
	}
	if (!score_narrowed_selector(&ns->score, ns, indent)) {
		return false;
	}
	return true;
}

static bool fit_ts_to_sec_label(struct narrowed_selector_payload *nsp,
				const struct traffic_selector_payload *tsp,
				chunk_t sec_label, enum fit sec_label_fit,
				indent_t indent)
{
	indent.level++;

	if (sec_label.len == 0) {
		/*
		 * This connection is not configured to use labeled
		 * IPsec yet the traffic selector contains them.
		 */
		if (tsp->sec_label.len > 0) {
			dbg_ts("error: received sec_label but this end is *not* configured to use sec_label");
			return false;
		}
		/* No sec_label was found and none was expected */
		return true;	/* success: no label, as expected */
	}

	if (tsp->sec_label.len == 0) {
		dbg_ts("error: connection requires sec_label but not received TSi/TSr with sec_label");
		return false;
	}

	switch (sec_label_fit) {
	case END_WIDER_THAN_TS:
		if (!sec_label_within_range("Traffic Selector",
					    tsp->sec_label, sec_label,
					    indent.logger)) {
			dbg_ts("%s sec_label="PRI_SHUNK" IS NOT within range connection sec_label="PRI_SHUNK,
			       tsp->name, pri_shunk(tsp->sec_label), pri_shunk(sec_label));
			return false;
		}
		break;
	case END_EQUALS_TS:
		if (!hunk_eq(tsp->sec_label, sec_label)) {
			dbg_ts("%s sec_label="PRI_SHUNK" IS equal toconnection sec_label="PRI_SHUNK,
			       tsp->name, pri_shunk(tsp->sec_label), pri_shunk(sec_label));
			return false;
		}
		break;
	default:
		bad_case(sec_label_fit);
	}

	dbg_ts("%s sec_label="PRI_SHUNK" IS within range connection sec_label="PRI_SHUNK,
	       tsp->name, pri_shunk(tsp->sec_label), pri_shunk(sec_label));
	nsp->sec_label = tsp->sec_label;
	return true;
}

static bool append_ns_to_nsp(const struct narrowed_selector *ns,
			     struct narrowed_selector_payload *nsp,
			     indent_t indent)
{
	/*
	 * Save the best overall score.  Presumably duplicates won't
	 * beat the existing score.
	 */
	if (score_gt_best(&ns->score, &nsp->score)) {
		nsp->score = ns->score;
	}

	/*
	 * XXX: filter out duplicates.
	 */

	for (unsigned n = 0; n < nsp->nr; n++) {
		struct narrowed_selector *nso = &nsp->ns[n];

		if (selector_eq_selector(ns->selector, nso->selector)) {
			selector_buf nsb, nsob;
			dbg_ts("%s == %s, dropping",
			       str_selector(&ns->selector, &nsb),
			       str_selector(&nso->selector, &nsob));
			return true;
		}
		if (selector_in_selector(ns->selector, nso->selector)) {
			selector_buf nsb, nsob;
			dbg_ts("%s in %s, dropping",
			       str_selector(&ns->selector, &nsb),
			       str_selector(&nso->selector, &nsob));
			return true;
		}
		if (selector_in_selector(nso->selector, ns->selector)) {
			selector_buf nsb, nsob;
			dbg_ts("%s in %s, widening",
			       str_selector(&ns->selector, &nsb),
			       str_selector(&nso->selector, &nsob));
			*nso = *ns;
			return true;
		}
	}

	/* don't overflow */
	if (nsp->nr >= elemsof(nsp->ns)) {
		return false;
	}

	nsp->ns[nsp->nr] = *ns;
	nsp->nr++;
	return true;
}

static bool append_block_to_nsp(ip_selector selector,
				struct narrowed_selector_payload *nsp)
{
	if (nsp->nr >= elemsof(nsp->ns)) {
		return false;
	}

	nsp->ns[nsp->nr] = (struct narrowed_selector) {
		.name = "block",
		.nr = 0,
		.selector = selector,
		.block = true,
	};
	nsp->nr++;

	return true;
}

static bool fit_tsp_to_end(struct narrowed_selector_payload *nsp,
			   const struct traffic_selector_payload *tsp,
			   const struct child_selector_end *end,
			   enum fit selector_fit,
			   enum fit sec_label_fit,
			   indent_t indent)
{
	if (!fit_ts_to_sec_label(nsp, tsp, end->sec_label, sec_label_fit, indent)) {
		return false;
	}

	bool matched = false;
	nsp->nr = 0; /*passert?*/

	for (unsigned i = 0; i < end->selectors->len; i++) {
		const ip_selector selector = end->selectors->list[i];
		bool match = false;

		for (unsigned i = 0; i < tsp->nr; i++) {
			const struct traffic_selector *ts = &tsp->ts[i];

			struct narrowed_selector ns;
			if (fit_ts_to_selector(&ns, ts, selector,
						selector_fit, indent)) {
				if (!append_ns_to_nsp(&ns, nsp, indent)) {
					llog(RC_LOG_SERIOUS, indent.logger, "TS overflow");
					return false;
				}
				match = matched = true;
			}

		}

		if (!match && selector_fit == END_EQUALS_TS) {
			/*
			 * Track failed selectors so they can be
			 * blocked.  Should work on responder, what
			 * about initiator?
			 */
			if (!append_block_to_nsp(selector, nsp)) {
				llog(RC_LOG_SERIOUS, indent.logger, "TS overflow");
				return false;
			}
		}
	}

	/* not nsp->nr>0 as all could be blocked */
	return matched;
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

static bool fit_tsps_to_ends(struct narrowed_selector_payloads *nsps,
			     const struct traffic_selector_payloads *tsps,
			     const struct child_selector_ends *ends,
			     enum fit selector_fit,
			     enum fit sec_label_fit,
			     indent_t indent)
{
	dbg_ts("evaluating END %s:", str_end_fit_ts(selector_fit));
	indent.level++;

	if (!fit_tsp_to_end(&nsps->i, &tsps->i, &ends->i,
			    selector_fit, sec_label_fit, indent)) {
		return false;
	}
	if (!fit_tsp_to_end(&nsps->r, &tsps->r, &ends->r,
			    selector_fit, sec_label_fit, indent)) {
		return false;
	}

	nsps->score = (struct score) {
		/* ??? this objective function is odd and arbitrary */
		.range = ((nsps->i.score.range << 8) + nsps->r.score.range),
		/* ??? arbitrary objective function */
		.port = (nsps->i.score.port + nsps->r.score.port),
		/* ??? arbitrary objective function */
		.protocol = (nsps->i.score.protocol + nsps->r.score.protocol),
	};

	return true;
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
	while (next_state(NEW2OLD, &sf)) {
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

/*
 * Find the best connection: possibly scribbling on the just
 * instantiated child; possibly instantiating a new connection;
 * possibly giving up.
 */

struct best {
	struct connection *connection;
	bool instantiated;
	struct narrowed_selector_payloads nsps;
};

static bool fit_connection_for_v2TS_request(struct connection *d,
					    const struct traffic_selector_payloads *tsps,
					    struct narrowed_selector_payloads *nsps,
					    indent_t indent)
{
	/* responder -- note D! */
	enum fit responder_selector_fit;
	if (d->config->ikev2_allow_narrowing) {
		if (is_template(d)) {
			/*
			 * A template starts wider
			 * than the TS and then, when
			 * it is instantiated, gets
			 * narrowed.
			 */
			responder_selector_fit = END_WIDER_THAN_TS;
		} else {
			/*
			 * An existing instance needs
			 * to just accommodate the
			 * existing traffic
			 * selectors?!?
			 *
			 * XXX: should this instead
			 * only allow a strict equals?
			 */
			responder_selector_fit = END_NARROWER_THAN_TS;
		}
	} else {
		responder_selector_fit = END_EQUALS_TS;
	}

	/*
	 * Responder expects the TS sec_label to be
	 * narrower than the IKE sec_label.
	 */
	enum fit responder_sec_label_fit = END_WIDER_THAN_TS;

	/* responder so cross the streams */

	const struct child_selector_ends ends = {
		.i.selectors = &d->remote->child.selectors.proposed,
		.i.sec_label = d->config->sec_label,
		.r.selectors = &d->local->child.selectors.proposed,
		.r.sec_label = d->config->sec_label,
	};

	if (!fit_tsps_to_ends(nsps, tsps, &ends,
			      responder_selector_fit,
			      responder_sec_label_fit,
			      indent)) {
		return false;
	}

	return true;
}

static struct best find_best_connection_for_v2TS_request(struct child_sa *child,
							 const struct traffic_selector_payloads *tsps,
							 const struct msg_digest *md)
{
	indent_t indent = {child->sa.logger, 0};
	passert(v2_msg_role(md) == MESSAGE_REQUEST);
	passert(child->sa.st_sa_role == SA_RESPONDER);

	/*
	 * Start with nothing.  The loop then evaluates each
	 * connection, including the child's existing connection.
	 *
	 * Note in particular the code that allows C to be evaluated
	 * when it is an ID_NULL OE instance (normally these are
	 * excluded).
	 */
	struct best best = {0};

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
	struct connection *const cc = child->sa.st_connection;
	dbg_ts("looking to best connection "PRI_CONNECTION" "PRI_CO" with policy <%s>:",
	       pri_connection(cc, &cb), pri_co(cc->serialno),
	       str_connection_policies(cc, &pb));

	const ip_address local = md->iface->ip_dev->local_address;
	FOR_EACH_THING(remote, endpoint_address(md->sender), unset_address) {
		indent.level = 1;

		address_buf rab, lab;
		dbg_ts("searching host_pair %s->%s",
		       str_address(&remote, &rab), str_address(&local, &lab));

		struct connection_filter hpf = {
			.local = &local,
			.remote = &remote,
			.where = HERE,
		};
		while (next_connection(NEW2OLD, &hpf)) {
			struct connection *d = hpf.c;
			indent.level = 2;

			/* XXX: sec_label connections all look a-like, include CO */
			connection_buf cb;
			policy_buf pb;
			dbg_ts("evaluating %s connection "PRI_CONNECTION" "PRI_CO" with policy <%s>:",
			       enum_name_short(&connection_kind_names, cc->local->kind),
			       pri_connection(d, &cb), pri_co(d->serialno),
			       str_connection_policies(d, &pb));

			indent.level = 3;

			if (d->config->ike_version != IKEv2) {
				connection_buf cb;
				dbg_ts("skipping "PRI_CONNECTION", not IKEv2",
				       pri_connection(d, &cb));
				continue;
			}

			/*
			 * Groups are like template templates?  They
			 * get instantiated into CK_TEMPLATE +
			 * GROUPINSTANCE?
			 *
			 * They also seem to be very like sec_labels
			 * which start as templates, become hybrid
			 * template instances, and finally instances.
			 */
			if (is_group(d)) {
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
			if (is_instance(d) &&
			    d->remote->host.id.kind == ID_NULL &&
			    d != child->sa.st_connection) {
				connection_buf cb;
				dbg_ts("skipping "PRI_CONNECTION", ID_NULL instance (and not original)",
				       pri_connection(d, &cb));
				continue;
			}

			/*
			 * For labeled IPsec, always start with the
			 * labeled_instance().
			 *
			 * Who are we to argue if the kernel asks for
			 * a new SA with, seemingly, a security label
			 * that matches an existing connection
			 * instance.
			 */
			if (is_labeled(d)) {
				connection_buf cb;
				dbg_ts("skipping "PRI_CONNECTION", labeled",
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
			if (!(cc->config->connalias != NULL &&
			      d->config->connalias != NULL &&
			      streq(cc->config->connalias, d->config->connalias))) {
				int wildcards;	/* value ignored */
				int pathlen;	/* value ignored */

				if (!(same_id(&cc->local->host.id, &d->local->host.id) &&
				      match_id("ts:       ",
					       &cc->remote->host.id,
					       &d->remote->host.id, &wildcards) &&
				      trusted_ca(ASN1(cc->remote->host.config->ca),
						 ASN1(d->remote->host.config->ca), &pathlen))) {
					connection_buf cb;
					dbg_ts("skipping "PRI_CONNECTION" does not match IDs or CA of current connection \"%s\"",
					       pri_connection(d, &cb), cc->name);
					continue;
				}
			}

			struct narrowed_selector_payloads nsps = {0};
			if (!fit_connection_for_v2TS_request(d, tsps, &nsps, indent)) {
				connection_buf cb;
				dbg_ts("skipping "PRI_CONNECTION" does not score at all",
				       pri_connection(d, &cb));
				continue;
			}

			if (score_gt_best(&nsps.score, &best.nsps.score)) {
				connection_buf cb;
				dbg_ts("protocol fitness found better match "PRI_CONNECTION"",
				       pri_connection(d, &cb));
				best = (struct best) {
					.connection = d,
					.instantiated = false,
					.nsps = nsps,
				};
			}
		}
	}
	return best;
}

bool process_v2TS_request_payloads(struct child_sa *child,
				   const struct msg_digest *md)
{
	indent_t indent = {child->sa.logger, 0};
	passert(v2_msg_role(md) == MESSAGE_REQUEST);
	passert(child->sa.st_sa_role == SA_RESPONDER);
	struct connection *cc = child->sa.st_connection;

	struct traffic_selector_payloads tsps = empty_traffic_selector_payloads;
	if (!v2_parse_tsps(md, &tsps, child->sa.logger)) {
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
	struct best best;
	if (is_labeled(cc)) {
		PEXPECT(child->sa.logger, is_labeled_parent(cc));
		struct narrowed_selector_payloads nsps = {0};
		if (!fit_connection_for_v2TS_request(cc, &tsps, &nsps, indent)) {
			llog_sa(RC_LOG_SERIOUS, child, "proposed Traffic Selectors do not match labeled IKEv2 connection");
			return false;
		}
		best = (struct best) {
			.connection = cc,
			.instantiated = false,
			.nsps = nsps,
		};
	} else {
		best = find_best_connection_for_v2TS_request(child, &tsps, md);
	}

	indent.level = 1;

	if (best.connection == NULL) {
		connection_buf cb;
		dbg_ts("connection "PRI_CONNECTION" "PRI_CO" is as good as it gets",
		       pri_connection(cc, &cb), pri_so(cc->serialno));
	} else {
		connection_buf cb, bcb;
		dbg_ts("connection "PRI_CONNECTION" "PRI_CO" best by "PRI_CONNECTION" "PRI_CO"%s%s",
		       pri_connection(cc, &cb), pri_so(cc->serialno),
		       pri_connection(best.connection, &bcb), pri_so(best.connection->serialno),
		       (is_template(best.connection) ? " needs instantiating!" : ""),
		       (is_group_instance(best.connection) ? " group-instance!" : ""));
	}

	/*
	 * Did the the search fail badly?
	 *
	 * = no existing connection (or connection template) matched
	 *   the proposed traffic selectors.
	 *
	 * = more importantly, the existing connection is "permanent"
	 *   (or permanent like) so there isn't the option of
	 *   instantiating something better (switching away from
	 *   permanent connections isn't allowed; explaining why might
	 *   be helpful here).
	 *
	 * = if the existing connection is LABELED then the search
	 *   should have found the same label
	 */
	if (best.connection == NULL &&
	    (is_permanent(cc) || is_labeled(cc))) {
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
		 *
		 * XXX: For SEC_LABEL, best should have been set back
		 * to CC?!?
		 */
		dbg_ts("no best spd route; but the current %s connection \"%s\" is not a CK_INSTANCE; giving up",
		       enum_name(&connection_kind_names, cc->local->kind), cc->name);
		llog_sa(RC_LOG_SERIOUS, child, "no IKEv2 connection found with compatible Traffic Selectors");
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
	    !is_labeled(cc) &&
	    is_group_instance(cc)) {
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
		while (next_connection(NEW2OLD, &cf)) {
			struct connection *t = cf.c;
			indent.level = 2;

			LDBGP_JAMBUF(DBG_BASE, &global_logger, buf) {
				jam(buf, TS_INDENT, ts_indent);
				jam(buf, "investigating template \"%s\";",
				    t->name);
				jam(buf, " with policy <");
				jam_connection_policies(buf, t);
				jam(buf, ">");
			}

			indent.level = 3;

			/*
			 * Is it worth looking at the template.
			 *
			 * XXX: treat the combination the same as
			 * group instance, like the old code did; is
			 * this valid?
			 */

			/*
			 * XXX: only replace is_group_instance(cc)
			 * with another group instance.
			 *
			 * clonedfrom== test below makes this somewhat
			 * redundant.
			 */
			if (!is_group_instance(t)) {
				dbg_ts("skipping; not a group instance");
				continue;
			}

			/*
			 * Group instances must have a parent group
			 * and that group needs to be shared.
			 */
			PEXPECT(t->logger, t->clonedfrom != NULL);
			if (cc->clonedfrom != t->clonedfrom) {
				dbg_ts("skipping; wrong foodgroup");
				continue;
			}
			/*
			 * ??? why require current connection->name
			 * and t->name to be different.
			 *
			 * XXX: don't re-instantiate the same
			 * connection template????
			 */
			if (streq(cc->name, t->name)) {
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
			if (!selector_in_selector(cc->spd->remote->client,
						  t->spd->remote->client)) {
				dbg_ts("skipping; current connection's initiator subnet is not <= template");
				continue;
			}
			/* require responder address match; why? */
			ip_address cc_this_client_address =
				selector_prefix(cc->spd->local->client);
			ip_address t_this_client_address =
				selector_prefix(t->spd->local->client);
			if (!address_eq_address(cc_this_client_address,
						t_this_client_address)) {
				dbg_ts("skipping; responder addresses don't match");
				continue;
			}

			/* require a valid narrowed port? */
			/* exact match; XXX: 'cos that is what old code did */
			enum fit responder_selector_fit = END_EQUALS_TS;
			enum fit responder_sec_label_fit = END_EQUALS_TS;

			/* responder so cross streams */
			pexpect(t->remote->child.selectors.proposed.list == t->remote->child.selectors.assigned ||
				t->remote->child.selectors.proposed.list == t->remote->config->child.selectors.list);
			pexpect(t->local->child.selectors.proposed.list == t->local->child.selectors.assigned ||
				t->local->child.selectors.proposed.list == t->local->config->child.selectors.list);
			pexpect(selector_eq_selector(t->spd->remote->client,
						     t->remote->child.selectors.proposed.list[0]));
			pexpect(selector_eq_selector(t->spd->local->client,
						     t->local->child.selectors.proposed.list[0]));
			pexpect(!is_labeled(t));
			struct child_selector_ends ends = {
				.i.selectors = &t->remote->child.selectors.proposed,
				.i.sec_label = t->config->sec_label,
				.r.selectors = &t->local->child.selectors.proposed,
				.r.sec_label = t->config->sec_label,
			};

			struct narrowed_selector_payloads nsps;
			if (!fit_tsps_to_ends(&nsps, &tsps, &ends, responder_selector_fit,
					      responder_sec_label_fit, indent)) {
				continue;
			}

			indent.level--;

			/*
			 * XXX: isn't this a template, or are group
			 * instances shared?
			 */
			struct connection *s;
			bool instantiated;
			if (v2_child_connection_probably_shared(child, indent)) {
				/* instantiate it, filling in peer's ID */
				s = spd_instantiate(t, child->sa.st_connection->remote->host.addr, HERE);
				instantiated = true;
			} else {
				s = child->sa.st_connection;
				instantiated = false;
			}
			scribble_ts_request_on_responder(child, s, &nsps, indent);

			/* switch */
			best = (struct best) {
				.connection = s,
				.instantiated = instantiated,
				.nsps = nsps,
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
	if (is_labeled_parent(best.connection)) {
		/*
		 * Convert the hybrid sec_label template-instance into
		 * a proper instance, and then update its selectors.
		 */
		dbg_ts("instantiating the labeled_parent connection");
		indent.level = 2;
		pexpect(best.connection == child->sa.st_connection); /* big circle */
		pexpect(best.nsps.i.sec_label.len > 0);
		pexpect(best.nsps.r.sec_label.len > 0);
		pexpect(best.connection->child.sec_label.len == 0);
		pexpect(address_is_specified(best.connection->remote->host.addr));
		struct connection *s = labeled_parent_instantiate(ike_sa(&child->sa, HERE), best.nsps.i.sec_label, HERE);
		scribble_ts_request_on_responder(child, s, &best.nsps, indent);
		/* switch to instantiated instance; same score */
		best.connection = s;
		best.instantiated = true;
	} else if (best.connection != NULL &&
		   is_template(best.connection)) {
		dbg_ts("instantiating the template connection");
		indent.level = 2;
		pexpect(best.nsps.i.sec_label.len == 0);
		pexpect(best.nsps.r.sec_label.len == 0);
		struct connection *s = spd_instantiate(best.connection, child->sa.st_connection->remote->host.addr, HERE);
		scribble_ts_request_on_responder(child, s, &best.nsps, indent);
		/* switch to instantiated instance; same score */
		best.connection = s;
		best.instantiated = true;
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
		if (best.instantiated) {
			connection_delref(&best.connection, child->sa.logger);
		}
	}

	return true;
}

/* check TS payloads, response */
bool process_v2TS_response_payloads(struct child_sa *child,
				    struct msg_digest *md)
{
	indent_t indent = {child->sa.logger, 0};

	passert(child->sa.st_sa_role == SA_INITIATOR);
	passert(v2_msg_role(md) == MESSAGE_RESPONSE);

	struct connection *c = child->sa.st_connection;

	struct traffic_selector_payloads tsps = empty_traffic_selector_payloads;
	if (!v2_parse_tsps(md, &tsps, child->sa.logger)) {
		return false;
	}

	/* initiator so don't cross streams */
	pexpect(c->remote->child.selectors.proposed.list == c->remote->child.selectors.assigned ||
		c->remote->child.selectors.proposed.list == c->remote->config->child.selectors.list);
	pexpect(c->local->child.selectors.proposed.list == c->local->child.selectors.assigned ||
		c->local->child.selectors.proposed.list == c->local->config->child.selectors.list);
	pexpect(selector_eq_selector(c->spd->remote->client,
				     c->remote->child.selectors.proposed.list[0]));
	pexpect(selector_eq_selector(c->spd->local->client,
				     c->local->child.selectors.proposed.list[0]));

	/* the return needs to match what was proposed */
	const struct child_selector_ends ends = {
		.i.selectors = &c->local->child.selectors.proposed,
		.i.sec_label = c->child.sec_label,
		.r.selectors = &c->remote->child.selectors.proposed,
		.r.sec_label = c->child.sec_label,
	};

	/*
	 * When allow narrowing, it's ok for the responders TS to be
	 * smaller than the END.
	 */
	enum fit initiator_selector_fit =
		(c->config->ikev2_allow_narrowing ? END_WIDER_THAN_TS
		 : END_EQUALS_TS);
	/*
	 * The responders sec_label must exactly match what was
	 * proposed.
	 */
	enum fit initiator_sec_label_fit = END_EQUALS_TS;

	struct narrowed_selector_payloads best = {0};
	if (!fit_tsps_to_ends(&best, &tsps, &ends,
			      initiator_selector_fit,
			      initiator_sec_label_fit, indent)) {
		dbg_ts("reject responder TSi/TSr Traffic Selector");
		/* prevents parent from going to I3 */
		return false;
	}

	scribble_ts_response_on_initiator(child, &best, indent);
	spd_db_rehash_remote_client(c->spd);

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
	indent_t indent = {child->sa.logger, 0};

	if (!pexpect(child->sa.st_state->kind == STATE_V2_REKEY_CHILD_R0))
		return false;

	const struct connection *c = child->sa.st_connection;
	struct traffic_selector_payloads their_tsps = empty_traffic_selector_payloads;

	if (!v2_parse_tsps(md, &their_tsps, child->sa.logger)) {
		llog_sa(RC_LOG_SERIOUS, child,
			  "received malformed TSi/TSr payload(s)");
		return false;
	}

	/* responder so cross streams */
	pexpect(c->remote->child.selectors.proposed.list == c->remote->child.selectors.assigned ||
		c->remote->child.selectors.proposed.list == c->remote->config->child.selectors.list);
	pexpect(c->local->child.selectors.proposed.list == c->local->child.selectors.assigned ||
		c->local->child.selectors.proposed.list == c->local->config->child.selectors.list);
	pexpect(selector_eq_selector(c->spd->remote->client,
				     c->remote->child.selectors.proposed.list[0]));
	pexpect(selector_eq_selector(c->spd->local->client,
				     c->local->child.selectors.proposed.list[0]));
	const struct child_selector_ends ends = {
		.i.selectors = &c->remote->child.selectors.proposed,
		.i.sec_label = c->child.sec_label,
		.r.selectors = &c->local->child.selectors.proposed,
		.r.sec_label = c->child.sec_label,
	};

	enum fit responder_selector_fit = END_NARROWER_THAN_TS;
	enum fit responder_sec_label_fit = END_EQUALS_TS;

	/* best's value isn't relevant, but pacify coverity */
	struct narrowed_selector_payloads best = {0};
	if (!fit_tsps_to_ends(&best, &their_tsps, &ends,
			      responder_selector_fit,
			      responder_sec_label_fit, indent)) {
		llog_sa(RC_LOG_SERIOUS, child,
			  "rekey: received Traffic Selectors does not contain existing IPsec SA Traffic Selectors");
		return false;
	}

	return true;
}
