/* kernel op wrappers, for libreswan
 *
 * Copyright (C) 2021-2023 Andrew Cagney <cagney@gnu.org>
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
#include "ipsec_interface.h"
#include "ip_info.h"
#include "kernel_iface.h"
#include "kernel_policy.h"

/*
 * Setup an IPsec route entry.
 *
 * There's lots of redundancy here, see debug log lines below.
 */

bool kernel_ops_policy_add(enum kernel_policy_op op,
			   enum direction dir,
			   const ip_selector *src_client,
			   const ip_selector *dst_client,
			   const struct kernel_policy *policy,
			   deltatime_t use_lifetime,
			   struct logger *logger, where_t where, const char *story)
{
	const struct ip_protocol *client_proto = selector_protocol(*src_client);
	pexpect(client_proto == selector_protocol(*dst_client));

	if (DBGP(DBG_ROUTING)) {
		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
			jam(buf, "routing:  %s()", __func__);

			jam_string(buf, " ");
			jam_enum_short(buf, &kernel_policy_op_names, op);
			jam_string(buf, "+");
			jam_enum_short(buf, &direction_names, dir);

			jam(buf, " ");
			jam_string(buf, story);
			jam_string(buf, " ");
			jam_where(buf, where);
		}

		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
			jam(buf, "routing:  ");

			jam(buf, " client=");
			jam_selector(buf, src_client);
			jam_string(buf, "=>"); /* directional */
			jam_selector(buf, dst_client);

			jam(buf, " lifetime=");
			jam_deltatime(buf, use_lifetime);
			jam(buf, "s");
		}

		if (policy->sa_marks != NULL ||
		    policy->xfrmi != NULL) {
			LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
				jam(buf, "routing:  ");

				if (policy->sa_marks != NULL) {
					jam(buf, " sa_marks=");
					const char *dir = "out:";
					FOR_EACH_THING(mark,
						       &policy->sa_marks->out,
						       &policy->sa_marks->in) {
						jam(buf, "%s"PRI_SA_MARK,
						    dir, pri_sa_mark(*mark));
						dir = ",in:";
					}
				}

				if (policy->xfrmi != NULL) {
					jam(buf, " xfrm_if_id=%d", (int)policy->xfrmi->if_id);
				}
			}

		}

		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
			jam(buf, "routing:  ");

			jam_string(buf, " policy=");
			jam_address(buf, &policy->src.host);
			jam(buf, "=>");
			jam_address(buf, &policy->dst.host);
			jam_string(buf, ",");
			jam_enum_short(buf, &shunt_kind_names, policy->kind);
			jam_string(buf, "=");
			jam_enum_short(buf, &shunt_policy_names, policy->shunt);
			jam_string(buf, ",");
			jam(buf, "priority=%"PRI_SPD_PRIORITY,
			    pri_spd_priority(policy->priority));
			/*
			 * Print outer-to-inner and use paren to show
			 * how each wraps the next.
			 *
			 * XXX: how to also print the encap mode - TCP
			 * or UDP?
			 */
			jam_string(buf, ",");
			jam_enum_short(buf, &kernel_mode_names, policy->mode);
			jam_string(buf, "[");
			for (unsigned i = policy->nr_rules; i > 0; i--) {
				const struct kernel_policy_rule *rule = &policy->rule[i-1];
				const struct ip_protocol *rule_proto = protocol_from_ipproto(rule->proto);
				jam(buf, "%s@"PRI_REQID"(", rule_proto->name, rule->reqid);
			}
			if (policy->nr_rules > 0) {
				/* XXX: should use stuff from selector */
				jam_string(buf, client_proto->name);
			}
			for (unsigned i = policy->nr_rules; i > 0; i--) {
				jam_string(buf, ")");
			}
			jam_string(buf, "]");
		}

		if (policy->sec_label.len > 0) {
			LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
				jam(buf, "routing:  ");
				jam_string(buf, " sec_label=");
				jam_sanitized_hunk(buf, policy->sec_label);
			}
		}
	}

	PASSERT(logger, policy != NULL);

	switch(policy->shunt) {
	case SHUNT_IPSEC:
		/*
		 * For an IPsec tunnel to be useful it needs both
		 * inbound and outbound policy.
		 */
		PASSERT(logger, (dir == DIRECTION_OUTBOUND ||
				 dir == DIRECTION_INBOUND));
		PASSERT(logger, policy->nr_rules > 0);
		PASSERT(logger, (policy->kind == SHUNT_KIND_IPSEC));
		break;
	case SHUNT_PASS:
		/*
		 * For instance, in ikev2-33-clearport-01 both inbound
		 * and outbound pass policy is installed.
		 */
		PASSERT(logger, (dir == DIRECTION_OUTBOUND ||
				 dir == DIRECTION_INBOUND));
		PASSERT(logger, policy->nr_rules == 0);
		PASSERT(logger, (policy->kind == SHUNT_KIND_NEVER_NEGOTIATE ||
				 policy->kind == SHUNT_KIND_NEGOTIATION ||
				 /* via FAILURE=NONE */
				 policy->kind == SHUNT_KIND_FAILURE));
		break;
	case SHUNT_DROP:
		/*
		 * For instance, in basic-pluto-19-seedbits, a
		 * never-negotiate drop connection is added.
		 */
		PASSERT(logger, (dir == DIRECTION_OUTBOUND ||
				 dir == DIRECTION_INBOUND));
		PASSERT(logger, policy->nr_rules > 0);
		PASSERT(logger, (policy->kind == SHUNT_KIND_FAILURE ||
				 policy->kind == SHUNT_KIND_NEVER_NEGOTIATE ||
				 policy->kind == SHUNT_KIND_BLOCK));
		break;
	case SHUNT_REJECT:
		/*
		 * For instance, in certoe-10-symmetric-cert-whack, a
		 * block (reject) kernel policy is installed.
		 */
		PASSERT(logger, (dir == DIRECTION_OUTBOUND ||
				 dir == DIRECTION_INBOUND));
		PASSERT(logger, policy->nr_rules > 0);
		PASSERT(logger, (policy->kind == SHUNT_KIND_NEVER_NEGOTIATE));
		break;
	case SHUNT_TRAP:
		PASSERT(logger, (dir == DIRECTION_OUTBOUND));
		PASSERT(logger, policy->nr_rules > 0);
		PASSERT(logger, (policy->kind == SHUNT_KIND_ONDEMAND));
		break;
	case SHUNT_HOLD:
		PASSERT(logger, (dir == DIRECTION_OUTBOUND));
		PASSERT(logger, policy->nr_rules > 0);
		PASSERT(logger, policy->kind == SHUNT_KIND_NEGOTIATION);
		break;
	case SHUNT_NONE:
		/*
		 * FAILURE=NONE should have been turned into
		 * NEGOTIATION=...
		 */
		PASSERT(logger, (policy->kind == SHUNT_KIND_FAILURE));
		PASSERT(logger, policy->nr_rules > 0);
		bad_enum(logger, &shunt_policy_names, policy->shunt);
	case SHUNT_UNSET:
		bad_enum(logger, &shunt_policy_names, policy->shunt);
	}

	bool ok = kernel_ops->policy_add(op, dir,
					 src_client, dst_client,
					 policy,
					 use_lifetime,
					 logger, __func__);

	if (DBGP(DBG_ROUTING)) {
		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
			jam(buf, "routing:   ... %s", bool_str(ok));
		}
	}

	return ok;
}

bool kernel_ops_policy_del(enum direction dir,
			   enum expect_kernel_policy expect_kernel_policy,
			   const ip_selector *src_client,
			   const ip_selector *dst_client,
			   const struct sa_marks *sa_marks,
			   const struct ipsec_interface *xfrmi,
			   enum kernel_policy_id id,
			   const shunk_t sec_label, /*needed*/
			   struct logger *logger, where_t where, const char *story)
{
	const struct ip_protocol *client_proto = selector_protocol(*src_client);
	pexpect(client_proto == selector_protocol(*dst_client));

	if (DBGP(DBG_ROUTING)) {

		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
			jam(buf, "routing:  %s()", __func__);

			jam_string(buf, " ");
			jam_enum_short(buf, &direction_names, dir);

			jam_string(buf, " ");
			jam_string(buf, expect_kernel_policy_name(expect_kernel_policy));

			jam(buf, " ");
			jam_string(buf, story);
			jam_string(buf, " ");
			jam_where(buf, where);

		}

		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
			jam(buf, "routing:  ");

			jam(buf, " client=");
			jam_selector(buf, src_client);
			jam_string(buf, "=>"); /* directional */
			jam_selector(buf, dst_client);
		}

		if (sa_marks != NULL || xfrmi != NULL) {
			LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
				jam(buf, "routing:  ");

				if (sa_marks != NULL) {
					jam(buf, " sa_marks=");
					const char *dir = "out:";
					FOR_EACH_THING(mark, &sa_marks->out, &sa_marks->in) {
						jam(buf, "%s"PRI_SA_MARK,
						    dir, pri_sa_mark(*mark));
						dir = ",in:";
					}
				}

				if (xfrmi != NULL) {
					jam(buf, " xfrm_if_id=%d", (int)xfrmi->if_id);
				}
			}

		}

		if (sec_label.len > 0) {
			LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
				jam(buf, "routing:  ");
				jam_string(buf, " sec_label=");
				jam_sanitized_hunk(buf, sec_label);
			}
		}
	}

	bool ok = kernel_ops->policy_del(dir, expect_kernel_policy,
					 src_client, dst_client,
					 sa_marks, xfrmi, id, sec_label,
					 logger, __func__);

	if (DBGP(DBG_ROUTING)) {
		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
			jam(buf, "routing:   ... %s", bool_str(ok));
		}
	}

	return ok;
}

bool kernel_ops_add_sa(const struct kernel_state *sa, bool replace, struct logger *logger)
{
	if (DBGP(DBG_ROUTING)) {
		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
			jam(buf, "routing:  %s()", __func__);

			jam(buf, " level=%d", sa->level);
			jam_string(buf, " ");
			jam_enum_short(buf, &direction_names, sa->direction);
			jam_string(buf, " ");
			jam_enum_short(buf, &kernel_mode_names, sa->mode);
		}

		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
			jam(buf, "routing:  ");
			jam(buf, " (src) ");
			jam_selector(buf, &sa->src.route);
			jam_string(buf, " -> ");
			jam_address(buf, &sa->src.address);
			jam(buf, "["PRI_IPSEC_SPI"]", pri_ipsec_spi(sa->spi));
			if (sa->encap_type != NULL) {
				jam(buf, "=%s", sa->encap_type->name);
			}
			jam(buf, " ==> ");
			jam_address(buf, &sa->dst.address);
			jam_string(buf, " -> ");
			jam_selector(buf, &sa->dst.route);
			jam(buf, " (dst)");
		}

		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
			jam(buf, "routing:  ");

			if (sa->ipcomp != NULL) {
				jam(buf, " %s", sa->ipcomp->common.fqn);
			}
			if (sa->integ != NULL) {
				jam(buf, " %s:%zu", sa->integ->common.fqn, sa->integ_key.len);
			}
			if (sa->encrypt != NULL) {
				jam(buf, " %s:%zu", sa->encrypt->common.fqn, sa->encrypt_key.len);
			}

			jam(buf, " replay_window=%d", sa->replay_window);
			if (sa->esn) jam(buf, " +esn");
			if (sa->decap_dscp) jam(buf, " +decap_dscp");
			if (!sa->encap_dscp) jam(buf, " +dont_encap_dscp");
			if (sa->nopmtudisc) jam(buf, " +nopmtudisc");

			jam_string(buf, " ...");
		}
	}

	switch (sa->mode) {
	case KERNEL_MODE_TRANSPORT:
	{
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
		PEXPECT(logger, selector_info(sa->src.route) == afi);
		PEXPECT(logger, selector_info(sa->dst.route) == afi);
		if (DBGP(DBG_BASE)) {
			/* XXX: no test triggers these!?! */
			PEXPECT(logger, selector_prefix_bits(sa->src.route) == afi->mask_cnt);
			PEXPECT(logger, selector_prefix_bits(sa->dst.route) == afi->mask_cnt);
			/* don't know which of .D/.S is .L/.R */
			PEXPECT(logger, address_eq_address(sa->src.address, selector_prefix(sa->src.route)));
			PEXPECT(logger, address_eq_address(sa->dst.address, selector_prefix(sa->dst.route)));
		}
		break;
	}
	case KERNEL_MODE_TUNNEL:
		break;
	}

	bool ok = kernel_ops->add_sa(sa, replace, logger);

	if (DBGP(DBG_ROUTING)) {
		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
			jam(buf, "routing:   ... %s", bool_str(ok));
		}
	}

	return ok;
}

bool kernel_ops_migrate_ipsec_sa(struct child_sa *child)
{
	struct logger *logger = child->sa.logger;
	if (kernel_ops->migrate_ipsec_sa == NULL) {
		ldbg(logger, "%s() unsupported kernel stack in migrate_ipsec_sa", __func__);
		return false;
	}

	ldbg(logger, "%s() migrating "PRI_SO" ...", __func__, pri_so(child->sa.st_serialno));

	bool ok = kernel_ops->migrate_ipsec_sa(child);

	ldbg(logger, "%s() ... %s", __func__, bool_str(ok));
	return ok;
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
	if (DBGP(DBG_ROUTING)) {
		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
			jam(buf, "routing:  %s()", __func__);

			jam_string(buf, " ");
			jam_address(buf, src);
			jam_string(buf, "-");
			jam(buf, "%s", proto->name);
			jam_string(buf, "->");
			jam_address(buf, dst);
			jam(buf, " reqid=%x", reqid);
			jam(buf, " [%jx,%jx]", min, max);
			jam(buf, " for %s ...", story);
		}
	}

	passert(kernel_ops->get_ipsec_spi != NULL);
	ipsec_spi_t spi = kernel_ops->get_ipsec_spi(avoid, src, dst, proto,
						    reqid, min, max, story, logger);

	if (DBGP(DBG_ROUTING)) {
		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
			jam(buf, "routing:   ... allocated "PRI_IPSEC_SPI" for %s",
			    pri_ipsec_spi(spi), story);
		}
	}

	return spi;
}

bool kernel_ops_del_ipsec_spi(ipsec_spi_t spi, const struct ip_protocol *proto,
			      const ip_address *src, const ip_address *dst,
			      struct logger *logger)
{
	ip_said said = said_from_address_protocol_spi(*dst, proto, spi);
	said_buf sbuf;
	const char *said_story = str_said(&said, &sbuf);

	if (DBGP(DBG_ROUTING)) {
		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
			address_buf sb, db;
			jam(buf, "routing:  %s() deleting sa %s-%s["PRI_IPSEC_SPI"]->%s for %s ...",
			    __func__,
			    str_address(src, &sb),
			    proto == NULL ? "<NULL>" : proto->name,
			    pri_ipsec_spi(spi),
			    str_address(dst, &db),
			    said_story);
		}
	}

	passert(kernel_ops->del_ipsec_spi != NULL);

	bool ok = kernel_ops->del_ipsec_spi(spi, proto, src, dst, said_story, logger);

	if (DBGP(DBG_ROUTING)) {
		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
			jam(buf, "routing:   ... %s", bool_str(ok));
		}
	}

	return ok;
}

bool kernel_ops_detect_nic_offload(const char *name, struct logger *logger)
{
	static bool no_offload;
	if (no_offload) {
		ldbg(logger, "%s() no offload already detected", __func__);
		return false;
	}

	if (kernel_ops->detect_nic_offload == NULL) {
		ldbg(logger, "%s() %s kernel interface does not support offload",
		     __func__, kernel_ops->interface_name);
		no_offload = true;
		return false;
	}

	ldbg(logger, "%s() %s ...", __func__, name);
	bool ok = kernel_ops->detect_nic_offload(name, logger);
	ldbg(logger, "%s() ... %s", __func__, bool_str(ok));

	return ok;
}
