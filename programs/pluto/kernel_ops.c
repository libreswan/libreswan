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
#include "kernel_xfrm_interface.h"
#include "ip_info.h"

/*
 * Setup an IPsec route entry.
 *
 * There's lots of redundancy here, see debug log lines below.
 */

bool raw_policy(enum kernel_policy_op op,
		enum direction dir,
		enum expect_kernel_policy expect_kernel_policy,
		const ip_selector *src_client,
		const ip_selector *dst_client,
		enum shunt_policy shunt_policy,
		const struct kernel_policy *policy,
		deltatime_t use_lifetime,
		uint32_t sa_priority,
		const struct sa_marks *sa_marks,
		const struct pluto_xfrmi *xfrmi,
		const shunk_t sec_label,
		struct logger *logger,
		const char *fmt, ...)
{
	const struct ip_protocol *client_proto = selector_protocol(*src_client);
	pexpect(client_proto == selector_protocol(*dst_client));
	if (policy == NULL) {
		pexpect(op == KERNEL_POLICY_OP_DELETE);
		pexpect(shunt_policy == SHUNT_UNSET);
		// not yet: pexpect(sa_priority == 0);
	} else {
		pexpect(policy->priority.value == sa_priority);
		pexpect(policy->shunt == shunt_policy);
		// not yet: pexpect((op == KERNEL_POLICY_OP_DELETE) <=/*implies*/ (policy->priority.value == 0));
		pexpect((op == KERNEL_POLICY_OP_DELETE) <=/*implies*/ (policy->nr_rules == 0));
		pexpect((op == KERNEL_POLICY_OP_DELETE) <=/*implies*/ (shunt_policy == SHUNT_UNSET));
		pexpect((policy->nr_rules == 0) <=/*implies*/ (policy->shunt == SHUNT_UNSET ||
							       policy->shunt == SHUNT_PASS));
		/* policies with matching states are SHUNT_UNSET */
		pexpect((policy->nr_rules > 0) <=/*implies*/ (policy->shunt != SHUNT_PASS));
	}

	LSWDBGP(DBG_BASE, buf) {

		jam(buf, "kernel: %s() ", __func__);

		jam_enum_short(buf, &kernel_policy_op_names, op);
		jam_string(buf, "+");
		jam_enum_short(buf, &direction_names, dir);

		jam_string(buf, " ");
		jam_string(buf, expect_kernel_policy_name(expect_kernel_policy));

		jam(buf, " ");
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);

		jam(buf, " client=");
		jam_selectors(buf, src_client, dst_client);

		jam(buf, " kernel_policy=");
		if (policy == NULL) {
			jam(buf, "<null>");
		} else {
			jam_address(buf, &policy->src.host);
			jam(buf, "==>");
			jam_address(buf, &policy->dst.host);
			jam_string(buf, ",");
			jam_enum(buf, &shunt_policy_names, policy->shunt);
			jam_string(buf, ",");
			jam(buf, ",priority=%"PRI_KERNEL_PRIORITY,
			    pri_kernel_priority(policy->priority));
			/*
			 * Print outer-to-inner and use paren to show
			 * how each wrapps the next.
			 *
			 * XXX: how to also print the encap mode - TCP
			 * or UDP?
			 */
			jam_string(buf, ",");
			jam_enum_short(buf, &encap_mode_names, policy->mode);
			jam_string(buf, "[");
			for (unsigned i = policy->nr_rules; i >= 1; i--) {
				const struct kernel_policy_rule *rule = &policy->rule[i];
				const struct ip_protocol *rule_proto = protocol_from_ipproto(rule->proto);
				jam(buf, "%s.%d(", rule_proto->name, rule->reqid);
			}
			if (policy->nr_rules > 0) {
				/* XXX: should use stuff from selector */
				jam_string(buf, client_proto->name);
			}
			for (unsigned i = policy->nr_rules; i >= 1; i--) {
				jam_string(buf, ")");
			}
			jam_string(buf, "]");
		}

		jam(buf, " lifetime=");
		jam_deltatime(buf, use_lifetime);
		jam(buf, "s");

		if (sa_marks != NULL) {
			jam(buf, " sa_marks=");
			const char *dir = "out:";
			FOR_EACH_THING(mark, &sa_marks->out, &sa_marks->in) {
				jam(buf, "%s%x/%x%s",
				    dir, mark->val, mark->mask,
				    mark->unique ? "/unique" : "");
				dir = ",in:";
			}
		}

		jam(buf, " xfrm_if_id=%d",
		    xfrmi != NULL ? (int)xfrmi->if_id : -1);

		jam(buf, " sec_label=");
		jam_sanitized_hunk(buf, sec_label);

	}

	switch(shunt_policy) {
	case SHUNT_HOLD:
		dbg("kernel: %s() SPI_HOLD implemented as no-op", __func__);
		return true;
	case SHUNT_TRAP:
		if ((op == KERNEL_POLICY_OP_ADD && dir == DIRECTION_INBOUND) ||
		    (op == KERNEL_POLICY_OP_DELETE && dir == DIRECTION_INBOUND)) {
			dbg("kernel: %s() SPI_TRAP add|delete inbound implemented as no-op", __func__);
			return true;
		}
		/* XXX: what about KERNEL_POLICY_OP_REPLACE? */
		break;
	default:
		break;
	}

	bool result = kernel_ops->raw_policy(op, dir,
					     expect_kernel_policy,
					     src_client, dst_client,
					     shunt_policy,
					     policy,
					     use_lifetime, sa_priority,
					     sa_marks, xfrmi,
					     sec_label,
					     logger);
	dbg("kernel: policy: result=%s", result ? "success" : "failed");

	return result;
}

bool kernel_ops_add_sa(const struct kernel_state *sa, bool replace, struct logger *logger)
{
	LSWDBGP(DBG_BASE, buf) {

		jam(buf, "kernel: add_sa()");

		jam(buf, " level=%d", sa->level);
		jam_string(buf, " ");
		jam_enum_short(buf, &direction_names, sa->direction);
		jam(buf, " %s", (sa->tunnel ? "tunnel" : "transport"));

		jam(buf, " ");
		jam_selector(buf, &sa->src.route);
		jam_string(buf, "->");
		jam_address(buf, &sa->src.address);
		jam(buf, "["PRI_IPSEC_SPI"]", pri_ipsec_spi(sa->spi));
		if (sa->encap_type != NULL) {
			jam(buf, "=%s", sa->encap_type->name);
		}
		jam(buf, "==>");
		jam_address(buf, &sa->dst.address);
		jam_string(buf, "->");
		jam_selector(buf, &sa->dst.route);

		if (sa->esn) jam(buf, " +esn");
		if (sa->decap_dscp) jam(buf, " +decap_dscp");
		if (sa->nopmtudisc) jam(buf, " +nopmtudisc");

		jam(buf, " replay_window=%d", sa->replay_window);

		if (sa->ipcomp != NULL) {
			jam(buf, " %s", sa->ipcomp->common.fqn);
		}
		if (sa->integ != NULL) {
			jam(buf, " %s:%zu", sa->integ->common.fqn, sa->integ_key.len);
		}
		if (sa->encrypt != NULL) {
			jam(buf, " %s:%zu", sa->encrypt->common.fqn, sa->encrypt_key.len);
		}
	}

	if (!sa->tunnel/*i.e., transport-mode*/) {
		/*
		 * XXX: since this is for transport mode what is
		 * allowed to change?
		 *
		 * Suspect this code is handling the scenario:
		 *
		 *   l.client <-> l.host <-> r.host <-> r.host+client
		 *
		 * where src.client and dst.host+client are called the
		 * ROUTE.
		 */
		const struct ip_info *afi = address_info(sa->src.address);
		pexpect(selector_info(sa->src.route) == afi);
		pexpect(selector_info(sa->dst.route) == afi);
		if (DBGP(DBG_BASE)) {
			/* XXX: no test triggers these!?! */
			pexpect(selector_prefix_bits(sa->src.route) == afi->mask_cnt);
			pexpect(selector_prefix_bits(sa->dst.route) == afi->mask_cnt);
			/* don't know which of .D/.S is .L/.R */
			pexpect(address_eq_address(sa->src.address, selector_prefix(sa->src.route)));
			pexpect(address_eq_address(sa->dst.address, selector_prefix(sa->dst.route)));
		}
	}
	return kernel_ops->add_sa(sa, replace, logger);
}

bool migrate_ipsec_sa(struct child_sa *child)
{
	if (kernel_ops->migrate_ipsec_sa != NULL) {
		return kernel_ops->migrate_ipsec_sa(child);
	} else {
		dbg("kernel: Unsupported kernel stack in migrate_ipsec_sa");
		return false;
	}
}

ipsec_spi_t kernel_ops_get_ipsec_spi(ipsec_spi_t avoid,
				     const ip_address *src,
				     const ip_address *dst,
				     const struct ip_protocol *proto,
				     reqid_t reqid,
				     uintmax_t min, uintmax_t max,
				     const char *story,	/* often SAID string */
				     struct logger *logger)
{
	LDBG(logger, buf) {
		jam_string(buf, "kernel: get_ipsec_spi() ");
		jam_address(buf, src);
		jam_string(buf, "-");
		jam(buf, "%s", proto->name);
		jam_string(buf, "->");
		jam_address(buf, dst);
		jam(buf, " reqid=%x", reqid);
		jam(buf, " [%jx,%jx]", min, max);
		jam(buf, " for %s ...", story);
	}

	passert(kernel_ops->get_ipsec_spi != NULL);
	ipsec_spi_t spi = kernel_ops->get_ipsec_spi(avoid, src, dst, proto,
						    reqid, min, max, story, logger);
	ldbg(logger, "kernel: get_ipsec_spi() ... allocated "PRI_IPSEC_SPI" for %s",
	     pri_ipsec_spi(spi), story);

	return spi;
}

bool kernel_ops_del_ipsec_spi(ipsec_spi_t spi, const struct ip_protocol *proto,
			      const ip_address *src, const ip_address *dst,
			      struct logger *logger)
{
	ip_said said = said_from_address_protocol_spi(*dst, proto, spi);
	said_buf sbuf;
	const char *said_story = str_said(&said, &sbuf);

	address_buf sb, db;
	dbg("kernel: del_ipsec_spi() deleting sa %s-%s["PRI_IPSEC_SPI"]->%s for %s ...",
	    str_address(src, &sb),
	    proto == NULL ? "<NULL>" : proto->name,
	    pri_ipsec_spi(spi),
	    str_address(dst, &db),
	    said_story);

	passert(kernel_ops->del_ipsec_spi != NULL);
	bool ok =kernel_ops->del_ipsec_spi(spi, proto, src, dst, said_story, logger);
	ldbg(logger, "kernel: get_ipsec_spi() ... %s", ok ? "succeeded" : "failed");

	return ok;
}

bool kernel_ops_detect_offload(const struct raw_iface *ifp, struct logger *logger)
{
	static bool no_offload;
	if (no_offload) {
		ldbg(logger, "no offload already detected");
		return false;
	}

	if (kernel_ops->detect_offload == NULL) {
		ldbg(logger, "%s kernel interface does not support offload",
		     kernel_ops->interface_name);
		no_offload = true;
		return false;
	}

	return kernel_ops->detect_offload(ifp, logger);
}
