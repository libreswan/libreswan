/* kernel op wrappers, for libreswan
 *
 * Copyright (C) 2021 Andrew Cagney <cagney@gnu.org>
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

#include "ip_encap.h"

#include "kernel.h"
#include "kernel_ops.h"
#include "log.h"

/*
 * Setup an IPsec route entry.
 *
 * There's lots of redundency here, see debug log lines below.
 */

bool raw_policy(enum kernel_policy_op op,
		const ip_address *src_host,
		const ip_selector *src_client,
		const ip_address *dst_host,
		const ip_selector *dst_client,
		ipsec_spi_t cur_spi,
		ipsec_spi_t new_spi,
		unsigned int transport_proto,
		enum eroute_type esatype,
		const struct kernel_encap *encap,
		deltatime_t use_lifetime,
		uint32_t sa_priority,
		const struct sa_marks *sa_marks,
		const uint32_t xfrm_if_id,
		const shunk_t sec_label,
		struct logger *logger,
		const char *fmt, ...)
{
	LSWDBGP(DBG_BASE, buf) {

		const ip_protocol *src_client_proto = selector_protocol(*src_client);
		const ip_protocol *dst_client_proto = selector_protocol(*dst_client);
		const ip_protocol *esa_proto = protocol_by_ipproto(esatype);

		jam(buf, "kernel: %s() ", __func__);
		jam_enum_short(buf, &kernel_policy_op_names, op);

		jam(buf, " ");
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);

		jam(buf, " ");
		jam_selector(buf, src_client);
		jam(buf, "-%s-", src_client_proto->name);
		jam_address(buf, src_host);
		jam(buf, "==");
		jam_address(buf, dst_host);
		jam(buf, "-%s-", dst_client_proto->name);
		jam_selector(buf, dst_client);

		/*
		 * Dump the {old,new}_spi.
		 *
		 * XXX: this needs to deal with a bug.
		 *
		 * At this point the {cur,new}_spi contains either the
		 * Child SPI in network order, or the enum policy_spi
		 * converted to network order (at other points in the
		 * code the SPI is passed in _host_ order, UGH!).
		 *
		 * Except some code is forgetting to do the network
		 * conversion (mumble something about making it hunk
		 * like to enforce the byte order).
		 */
		const char *spin = " ";
		FOR_EACH_THING(nspi, cur_spi, new_spi) {
			const char *name = NULL;
			bool spi_backwards = false;
			/*
			 * The NSPI converted back to host order
			 * should work; but if it doesn't ...
			 */
			FOR_EACH_THING(spi, ntohl(nspi), nspi) {
				/* includes %, can return NULL */
				name = enum_name(&policy_spi_names, spi);
				if (name != NULL) {
					break;
				}
				spi_backwards = true;
			}
			jam(buf, "%s", spin);
			if (name == NULL) {
				jam(buf, PRI_IPSEC_SPI, pri_ipsec_spi(nspi));
			} else if (!(!spi_backwards)) {
				jam(buf, "htonl(%s)", name);
			} else {
				jam(buf, "%s", name);
			}
			spin = "->";
		}

		/*
		 * TRANSPORT_PROTO is for the client, so presumably it
		 * matches the client's protoco?
		 */
		const ip_protocol *transport_protocol = protocol_by_ipproto(transport_proto);
		jam(buf, " transport_proto=%s", transport_protocol->name);
		if (!(transport_protocol == src_client_proto)) {
			jam(buf, "!=SRC");
		}
		if (!(transport_protocol == dst_client_proto)) {
			jam(buf, "!=DST");
		}

		/*
		 * SA_PROTO, ESATYPE, and PROTO_INFO all describe the
		 * encapsulation (PROTO_INFO is the most detailed as
		 * it can describe both [ESP|AH] and compression).
		 * How redundant is that?
		 */
		jam(buf, " esatype=%s", esa_proto->name);

		jam(buf, " encap=");
		if (encap == NULL) {
			jam(buf, "<null>");
		} else {
			jam(buf, "%s,inner=%s",
			    encap_mode_name(encap->mode),
			    (encap->inner_proto == NULL ? "<null>" : encap->inner_proto->name));
			for (int i = 0; i <= encap->outer; i++) {
				jam(buf, ",");
				const struct encap_rule *rule = &encap->rule[i];
				const ip_protocol *rule_proto = protocol_by_ipproto(rule->proto);
				jam(buf, "%s", rule_proto->name);
				if (i == 0 && !(esa_proto == rule_proto)) {
					jam(buf, "!=ESATYPE");
				}
				jam(buf, "/%d", rule->reqid);
			}
			jam(buf, "}");
		}

		jam(buf, " lifetime=");
		jam_deltatime(buf, use_lifetime);
		jam(buf, "s");

		jam(buf, " priority=%d", sa_priority);

		if (sa_marks != NULL) {
			jam(buf, " sa_marks=");
			const char *dir = "o:";
			FOR_EACH_THING(mark, &sa_marks->out, &sa_marks->in) {
				jam(buf, "%s%x/%x%s",
				    dir, mark->val, mark->mask,
				    mark->unique ? "/unique" : "");
				dir = ",i:";
			}
		}

		jam(buf, " xfrm_if_id=%d", xfrm_if_id);

		jam(buf, " sec_label=");
		jam_sanitized_hunk(buf, sec_label);

	}

	if (esatype == ET_INT) {
		switch(ntohl(new_spi)) {
		case SPI_HOLD:
			dbg("kernel: %s() SPI_HOLD implemented as no-op", __func__);
			return true;
		case SPI_TRAP:
			if (op == KP_ADD_INBOUND ||
			    op == KP_DELETE_INBOUND) {
				dbg("kernel: %s() SPI_TRAP inbound implemented as no-op", __func__);
				return true;
			}
			break;
		}
	}

	bool result = kernel_ops->raw_policy(op,
					     src_host, src_client,
					     dst_host, dst_client,
					     cur_spi, new_spi,
					     transport_proto,
					     esatype, encap,
					     use_lifetime, sa_priority, sa_marks,
					     xfrm_if_id,
					     sec_label,
					     logger);
	dbg("kernel: policy: result=%s", result ? "success" : "failed");

	return result;
}

bool kernel_ops_add_sa(const struct kernel_sa *sa, bool replace, struct logger *logger)
{
	LSWDBGP(DBG_BASE, buf) {

		const ip_protocol *src_proto = selector_protocol(*sa->src.client);
		const ip_protocol *dst_proto = selector_protocol(*sa->dst.client);
		const ip_protocol *esa_proto = protocol_by_ipproto(sa->esatype);

		jam(buf, "kernel: add_sa()");

		jam(buf, " %d", sa->level);
		jam(buf, " %s", sa->inbound ? "inbound" : "outbound");
		jam(buf, " %s", sa->tunnel ? "tunnel" : "transport");

		jam(buf, " ");
		jam_selector(buf, sa->src.client);
		jam(buf, "-%s->", src_proto->name);
		jam_address(buf, sa->src.address);
		jam(buf, "=%s", esa_proto->name);
		jam(buf, "="PRI_IPSEC_SPI, pri_ipsec_spi(sa->spi));
		if (sa->encap_type != NULL) {
			jam(buf, "=%s", sa->encap_type->name);
		}
		jam(buf, "=>");
		jam_address(buf, sa->dst.address);
		jam(buf, "-%s->", dst_proto->name);
		jam_selector(buf, sa->dst.client);

		if (sa->esn) jam(buf, " +esn");
		if (sa->decap_dscp) jam(buf, " +decap_dscp");
		if (sa->nopmtudisc) jam(buf, " +nopmtudisc");

		if (sa->ipcomp_algo != IPCOMP_NONE) {
			jam(buf, " %s", enum_name_short(&ipsec_ipcomp_algo_names, sa->ipcomp_algo));
		}
		if (sa->integ != NULL) {
			jam(buf, " %s:%d", sa->integ->common.fqn, sa->authkeylen);
		}
		if (sa->encrypt != NULL) {
			jam(buf, " %s:%d", sa->encrypt->common.fqn, sa->enckeylen);
		}
	}
	return kernel_ops->add_sa(sa, replace, logger);
}
