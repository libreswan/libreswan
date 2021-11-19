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
		enum what_about_inbound what_about_inbound,
		const ip_selector *src_client,
		const ip_selector *dst_client,
		enum shunt_policy shunt_policy,
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
	const ip_protocol *src_client_proto = selector_protocol(*src_client);
	const ip_protocol *dst_client_proto = selector_protocol(*dst_client);
	const ip_protocol *esa_proto = protocol_by_ipproto(esatype);

	LSWDBGP(DBG_BASE, buf) {

		jam(buf, "kernel: %s() ", __func__);
		jam_enum_short(buf, &kernel_policy_op_names, op);
		if (encap != NULL && (op == KP_DELETE_OUTBOUND ||
				      op == KP_DELETE_INBOUND)) {
			jam(buf, ",ENCAP!=NULL");
		}

		jam_string(buf, " ");
		jam_string(buf, what_about_inbound_name(what_about_inbound));

		jam(buf, " ");
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);

		jam(buf, " ");
		jam_selector_subnet_port(buf, src_client);
		jam(buf, "-%s", src_client_proto->name);
		if (encap == NULL) {
			jam(buf, "-");
		} else {
			jam(buf, "-");
			jam_address(buf, &encap->host.src);
			jam(buf, "==");
			jam_address(buf, &encap->host.dst);
			jam(buf, "-");
		}
		jam(buf, "%s-", dst_client_proto->name);
		jam_selector_subnet_port(buf, dst_client);

		/*
		 * Either:
		 *
		 * - ESATYPE is the magical INT flag and SHUNT_POLICY
		 *   has been set.
		 *
		 * - ESATYPE isn't INT, and SHUNT_POLICY is "unset"
		 *   (it will be ignored).
		 */
		jam_string(buf, " shunt_policy=");
		jam_enum_short(buf, &shunt_policy_names, shunt_policy);
		pexpect(esa_proto == &ip_protocol_internal
			? shunt_policy != SHUNT_UNSET
			: shunt_policy == SHUNT_UNSET);

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
			pexpect(esatype == ET_INT ||
				(op & KERNEL_POLICY_DELETE));
		} else {
			jam(buf, "%s", encap_mode_name(encap->mode));
			jam(buf, ",");
			jam_address(buf, &encap->host.src);
			jam(buf, "=>");
			jam_address(buf, &encap->host.dst);
			jam(buf, ",inner=%s", (encap->inner_proto == NULL ? "<null>" :
					       encap->inner_proto->name));
			pexpect(encap->inner_proto != NULL);
			pexpect(esa_proto == &ip_protocol_internal ||
				esa_proto == encap->inner_proto);

			jam_string(buf, "{");
			const char *sep = "";
			for (int i = 0; i <= encap->outer; i++) {
				const struct encap_rule *rule = &encap->rule[i];
				const ip_protocol *rule_proto = protocol_by_ipproto(rule->proto);
				jam_string(buf, sep); sep = ";";
				jam_string(buf, rule_proto->name);
				if (i == 0) {
					/* inner-most */
					pexpect(esa_proto == &ip_protocol_internal ||
						encap->mode == ENCAP_MODE_TUNNEL ||
						esa_proto == rule_proto);
				}
				jam(buf, ",%d", rule->reqid);
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

	pexpect(src_client_proto == dst_client_proto);

	switch (op) {
	case KP_ADD_INBOUND:
	case KP_DELETE_INBOUND:
	case KP_REPLACE_INBOUND:
		pexpect(what_about_inbound != THIS_IS_NOT_INBOUND);
		break;
	case KP_ADD_OUTBOUND:
	case KP_DELETE_OUTBOUND:
	case KP_REPLACE_OUTBOUND:
		pexpect(what_about_inbound == THIS_IS_NOT_INBOUND);
		break;
	}

	if (esatype == ET_INT) {
		switch(shunt_policy) {
		case SHUNT_HOLD:
			dbg("kernel: %s() SPI_HOLD implemented as no-op", __func__);
			return true;
		case SHUNT_TRAP:
			if (op == KP_ADD_INBOUND ||
			    op == KP_DELETE_INBOUND) {
				dbg("kernel: %s() SPI_TRAP inbound implemented as no-op", __func__);
				return true;
			}
			break;
		default:
			break;
		}
	}

	bool result = kernel_ops->raw_policy(op, what_about_inbound,
					     src_client, dst_client,
					     shunt_policy,
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
		jam_selector_subnet_port(buf, sa->src.client);
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
		jam_selector_subnet_port(buf, sa->dst.client);

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
