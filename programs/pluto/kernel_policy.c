/* kernel policy operations, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2009-2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2010 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2015 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2016-2022 Andrew Cagney
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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

#include "ip_info.h"

#include "defs.h"
#include "log.h"

#include "kernel_policy.h"
#include "kernel.h"
#include "kernel_ops.h"
#include "updown.h"
#include "kernel_xfrm_interface.h"		/* for dumping struct pluto_xfrmi */


/*
 * A kernel policy that does not have a state.  Typically constructed
 * from a bare shunt but can also be for a prospective shunt when
 * sec_label gets involved.
 */

static struct kernel_policy kernel_policy_from_void(ip_selector local, ip_selector remote,
						    enum direction direction,
						    spd_priority_t priority,
						    enum shunt_kind shunt_kind,
						    enum shunt_policy shunt_policy,
						    const struct sa_marks *sa_marks,
						    const struct pluto_xfrmi *xfrmi,
						    const shunk_t sec_label,
						    const struct nic_offload *nic_offload,
						    where_t where)
{
	const struct ip_info *child_afi = selector_info(local);
	pexpect(selector_info(remote) == child_afi);

	struct kernel_policy transport_esp = {
		/*
		 * With transport mode, the encapsulated packet on the
		 * host interface must have the same family as the raw
		 * packet on the client interface.  Even though it is
		 * UNSPEC.
		 */
		.local.host = child_afi->address.unspec,
		.remote.host = child_afi->address.unspec,
		/* what will capture packets */
		.local.client = local,
		.local.route = local,
		.remote.client = remote,
		.remote.route = remote,
		/* details */
		.priority = priority,
		.kind = shunt_kind,
		.shunt = shunt_policy,
		.where = where,
		.id = DEFAULT_KERNEL_POLICY_ID,
		.sa_marks = sa_marks,
		.xfrmi = xfrmi,
		.sec_label = sec_label,
		.mode = KERNEL_MODE_TRANSPORT,
		.nic_offload = *nic_offload,
	};

	switch (direction) {
	case DIRECTION_OUTBOUND:
		transport_esp.src = transport_esp.local;
		transport_esp.dst = transport_esp.remote;
		break;
	case DIRECTION_INBOUND:
		transport_esp.src = transport_esp.remote;
		transport_esp.dst = transport_esp.local;
		break;
	default:
		bad_case(direction);
	}

	if (shunt_policy != SHUNT_PASS) {
		transport_esp.nr_rules = 1;
		transport_esp.rule[0] = (struct kernel_policy_rule) {
			.proto = KERNEL_PROTO_ESP,
			.reqid = 0,
		};
	}
	return transport_esp;
}

struct kernel_policy_encap {
	bool ipcomp;
	bool esp;
	bool ah;
};

static struct kernel_policy kernel_policy_from_spd(struct kernel_policy_encap policy,
						   const struct spd *spd,
						   enum kernel_mode kernel_mode,
						   enum direction direction,
						   struct nic_offload *nic_offload,
						   struct logger *logger,
						   where_t where)
{
	/*
	 * With pfkey and transport mode with nat-traversal we need to
	 * change the remote IPsec SA to point to external ip of the
	 * peer.  Here we substitute real client ip with NATD ip.
	 *
	 * Bug #1004 fix.
	 *
	 * There really isn't "client" with XFRM and transport mode so
	 * eroute must be done to natted, visible ip. If we don't hide
	 * internal IP, communication doesn't work.
	 */
	ip_selector remote_route;
	switch (kernel_mode) {
	case KERNEL_MODE_TUNNEL:
	case KERNEL_MODE_IPTFS:
		remote_route = spd->remote->client;
		break;
	case KERNEL_MODE_TRANSPORT:
		remote_route = selector_from_address_protocol_port(spd->remote->host->addr,
								   selector_protocol(spd->remote->client),
								   selector_port(spd->remote->client));
		break;
	default:
		bad_enum(logger, &kernel_mode_names, kernel_mode);
	}

	struct kernel_policy kernel_policy = {
		/* normal */
		.local.client = spd->local->client,
		.local.route = spd->local->client, /* XXX: kernel_route has unset_selector */
		.remote.client = spd->remote->client,
		.remote.route = remote_route, /* note difference */
		.local.host = spd->local->host->addr,
		.remote.host = spd->remote->host->addr,
		/* details */
		.priority = spd_priority(spd),
		.mode = kernel_mode,
		.kind = SHUNT_KIND_IPSEC,
		.shunt = SHUNT_IPSEC,
		.where = where,
		.sa_marks = &spd->connection->sa_marks,
		.xfrmi = spd->connection->xfrmi,
		.id = DEFAULT_KERNEL_POLICY_ID,
		.sec_label = HUNK_AS_SHUNK(spd->connection->config->sec_label),
		.nr_rules = 0,
	};

	if (nic_offload && nic_offload->dev)
		kernel_policy.nic_offload = *nic_offload;


	switch (direction) {
	case DIRECTION_OUTBOUND:
		kernel_policy.src = kernel_policy.local;
		kernel_policy.dst = kernel_policy.remote;
		break;
	case DIRECTION_INBOUND:
		kernel_policy.src = kernel_policy.remote;
		kernel_policy.dst = kernel_policy.local;
		break;
	default:
		bad_case(direction);
	}

	/*
	 * Construct the kernel policy rules inner-to-outer (matching
	 * the flow of an outgoing packet).
	 *
	 * Note: the order is fixed: compress -> encrypt|authenticate.
	 *
	 * Note: only the inner most policy rule gets the tunnel bit
	 * (aka worm) (currently the global .mode is set and kernel
	 * backends handle this).
	 *
	 * Note: the stack order matches kernel_sa's array.
	 */

	reqid_t child_reqid = spd->connection->child.reqid;
	struct kernel_policy_rule *last = kernel_policy.rule;
	if (policy.ipcomp) {
		last->reqid = reqid_ipcomp(child_reqid);
		last->proto = KERNEL_PROTO_IPCOMP;
		last++;
	}
	if (policy.esp) {
		last->reqid = reqid_esp(child_reqid);
		last->proto = KERNEL_PROTO_ESP;
		last++;
	}
	if (policy.ah) {
		last->reqid = reqid_ah(child_reqid);
		last->proto = KERNEL_PROTO_AH;
		last++;
	}

	passert(last < kernel_policy.rule + elemsof(kernel_policy.rule));
	kernel_policy.nr_rules = last - kernel_policy.rule;
	passert(kernel_policy.nr_rules < elemsof(kernel_policy.rule));

	return kernel_policy;
}

static struct kernel_policy kernel_policy_from_state(const struct child_sa *child,
						     const struct spd *spd,
						     enum direction direction,
						     where_t where)
{
	struct nic_offload nic_offload = {};
	struct kernel_policy_encap policy = {0};

	if (child->sa.st_ipcomp.protocol == &ip_protocol_ipcomp) {
		policy.ipcomp = true;
	}

	if (child->sa.st_esp.protocol == &ip_protocol_esp) {
		policy.esp = true;
	}

	if (child->sa.st_ah.protocol == &ip_protocol_ah) {
		policy.ah = true;
	}

	setup_esp_nic_offload(&nic_offload, child->sa.st_connection, child->sa.logger);
	enum kernel_mode kernel_mode = child->sa.st_kernel_mode;
	struct kernel_policy kernel_policy = kernel_policy_from_spd(policy,
								    spd, kernel_mode,
								    direction,
								    &nic_offload,
								    child->sa.logger,
								    where);
	return kernel_policy;
}

/*
 * Install (add, replace) a kernel policy for the SPD.  The kernel
 * policy is "bare" since there isn't yet a state.
 *
 * Unlike install_spd_kernel_policy() this also adds in speculative
 * template / rules.  With sec_labels there's only really a policy for
 * the IKE SA (everything else happens under the hood).
 */

bool add_sec_label_kernel_policy(const struct spd *spd,
				 enum direction direction,
				 struct logger *logger,
				 where_t where, const char *what)
{
	const struct connection *c = spd->connection;
	PASSERT(logger, c->config->sec_label.len > 0);
	enum kernel_mode kernel_mode =
		(c->config->child_sa.encap_mode == ENCAP_MODE_TUNNEL ? KERNEL_MODE_TUNNEL :
		 KERNEL_MODE_TRANSPORT);

	struct nic_offload nic_offload = {};
	setup_esp_nic_offload(&nic_offload, c, logger);

	struct kernel_policy_encap policy = {
		.ipcomp = c->config->child_sa.ipcomp,
		.esp = (c->config->child_sa.encap_proto == ENCAP_PROTO_ESP),
		.ah = (c->config->child_sa.encap_proto == ENCAP_PROTO_AH),
	};
	struct kernel_policy kernel_policy =
		kernel_policy_from_spd(policy, spd, kernel_mode, direction,
				       &nic_offload,
				       logger, where);
	if (!kernel_ops_policy_add(KERNEL_POLICY_OP_ADD, direction,
				   &kernel_policy.src.client,
				   &kernel_policy.dst.client,
				   &kernel_policy,
				   deltatime(0),
				   logger, where, what)) {
		return false;
	}
	return true;
}

/*
 * Add (replace) a kernel policy using information from the SPD.  An
 * SPD is bare when there's no corresponding kernel state.
 */

bool add_spd_kernel_policy(const struct spd *spd,
			   enum kernel_policy_op op,
			   enum direction direction,
			   enum shunt_kind shunt_kind,
			   struct logger *logger,
			   where_t where, const char *what)
{
	const struct connection *c = spd->connection;
	struct nic_offload nic_offload = {};

	PASSERT(logger, (op == KERNEL_POLICY_OP_ADD ||
			 op == KERNEL_POLICY_OP_REPLACE));
#if 0
	/*
	 * XXX: This happens when the code tearing down an IPsec
	 * connection tries to install a bare shunt.  See
	 * teardown_ipsec_kernel_policies() and
	 * ikev1-labeled-ipsec-03-multi-acquires and
	 * ikev1-labeled-ipsec-01.
	 */
	PASSERT(logger, c->config->sec_label.len == 0);
#endif

	/*
	 * XXX: not kernel_policy_from_spd(), sigh:
	 *
	 * _from_spd() adds adds templates / rules based on the policy
	 * which is something an established IPsec SA and sec_label
	 * need, but not this code.
	 *
	 * _from_spd() modifies .client vs .route in strange ways
	 * which is something this code doesn't want (and perpahs
	 * _from_spd shouldn't be doing).
	 */

	setup_esp_nic_offload(&nic_offload, c, logger);
	struct kernel_policy kernel_policy =
		kernel_policy_from_void(spd->local->client, spd->remote->client,
					direction, spd_priority(spd),
					shunt_kind,
					spd->connection->config->shunt[shunt_kind],
					&c->sa_marks, c->xfrmi,
					HUNK_AS_SHUNK(c->config->sec_label),
					&nic_offload,
					where);

	if (!kernel_ops_policy_add(op, direction,
				   &kernel_policy.src.client,
				   &kernel_policy.dst.client,
				   &kernel_policy,
				   deltatime(0),
				   logger, where, what)) {
		return false;
	}

	return true;
}

void add_spd_kernel_policies(struct connection *c,
			     enum kernel_policy_op op,
			     enum direction direction,
			     enum shunt_kind shunt_kind,
			     struct logger *logger, where_t where, const char *story)
{
	FOR_EACH_ITEM(spd, &c->child.spds) {
		if (!add_spd_kernel_policy(spd, op, direction, shunt_kind,
					   logger, where, story)) {
			llog(RC_LOG, logger, "%s failed", story);
		}
	}
}

bool add_kernel_policy(enum kernel_policy_op op,
		       enum direction direction,
		       const ip_selector *local_selector,
		       const ip_selector *remote_selector,
		       const struct kernel_policy *policy,
		       deltatime_t use_lifetime,
		       struct logger *logger, where_t where, const char *story)
{
	/* achieve directionality */
	const ip_selector *src_selector;
	const ip_selector *dst_selector;
	switch (direction) {
	case DIRECTION_OUTBOUND:
		src_selector = local_selector;
		dst_selector = remote_selector;
		break;
	case DIRECTION_INBOUND:
		src_selector = remote_selector;
		dst_selector = local_selector;
		break;
	default:
		bad_case(direction);
	}

	const struct ip_protocol *selector_proto = selector_protocol(*src_selector);
	pexpect(selector_proto == selector_protocol(*dst_selector));

	return kernel_ops_policy_add(op, direction,
				     /* possibly reversed polarity! */
				     src_selector, dst_selector,
				     policy, use_lifetime,
				     logger, where, story);
}

bool replace_spd_kernel_policy(const struct spd *spd,
			       const struct spd_owner *owner,
			       enum direction direction,
			       enum shunt_kind shunt_kind,
			       struct logger *logger,
			       where_t where, const char *what)
{
	struct connection *c = spd->connection;
	struct nic_offload nic_offload = {};

	setup_esp_nic_offload(&nic_offload, c, logger);
	selector_pair_buf spb;
	ldbg(logger, " replacing %s",
	     str_selector_pair(&spd->local->client, &spd->remote->client, &spb));
	if (owner->policy != NULL) {
		connection_buf cb;
		ldbg(logger, "  no! owner is "PRI_CONNECTION,
		     pri_connection(owner->policy->connection, &cb));
		return true;
	}

	struct kernel_policy kernel_policy =
		kernel_policy_from_void(spd->local->client,
					spd->remote->client,
					direction,
					spd_priority(spd),
					shunt_kind,
					spd->connection->config->shunt[shunt_kind],
					&c->sa_marks, c->xfrmi,
					HUNK_AS_SHUNK(c->config->sec_label),
					&nic_offload,
					where);
	return add_kernel_policy(KERNEL_POLICY_OP_REPLACE, direction,
				 &spd->local->client,
				 &spd->remote->client,
				 &kernel_policy,
				 deltatime(0),
				 logger, where, what);

}

static bool restore_spd_kernel_policy(const struct spd *spd,
				      enum direction direction,
				      struct logger *logger,
				      where_t where, const char *what)
{
	struct connection *c = spd->connection;
	enum routing routing = c->routing.state;
	enum shunt_kind shunt_kind = routing_shunt_kind(routing);
	struct nic_offload nic_offload = {};
	selector_pair_buf spb;

	ldbg(logger, "%s() %s", __func__,
	     str_selector_pair(&spd->local->client, &spd->remote->client, &spb));

	setup_esp_nic_offload(&nic_offload, c, logger);
	struct kernel_policy kernel_policy =
		kernel_policy_from_void(spd->local->client,
					spd->remote->client,
					direction,
					spd_priority(spd),
					shunt_kind,
					spd->connection->config->shunt[shunt_kind],
					&c->sa_marks, c->xfrmi,
					HUNK_AS_SHUNK(c->config->sec_label),
					&nic_offload,
					where);
	return add_kernel_policy(KERNEL_POLICY_OP_REPLACE, direction,
				 &spd->local->client,
				 &spd->remote->client,
				 &kernel_policy,
				 deltatime(0),
				 logger, where, what);

}

bool delete_kernel_policy(enum direction direction,
			  enum expect_kernel_policy expect_kernel_policy,
			  const ip_selector *local_selector,
			  const ip_selector *remote_selector,
			  const struct sa_marks *sa_marks,
			  const struct pluto_xfrmi *xfrmi,
			  enum kernel_policy_id id,
			  const shunk_t sec_label,
			  struct logger *logger, where_t where, const char *story)
{
	/* achieve directionality */
	const ip_selector *src_selector;
	const ip_selector *dst_selector;
	switch (direction) {
	case DIRECTION_OUTBOUND:
		src_selector = local_selector;
		dst_selector = remote_selector;
		break;
	case DIRECTION_INBOUND:
		src_selector = remote_selector;
		dst_selector = local_selector;
		break;
	default:
		bad_case(direction);
	}

	const struct ip_protocol *selector_proto = selector_protocol(*src_selector);
	pexpect(selector_proto == selector_protocol(*dst_selector));

	return kernel_ops_policy_del(direction,
				     expect_kernel_policy,
				     /* possibly reversed polarity! */
				     src_selector, dst_selector,
				     sa_marks, xfrmi, id, sec_label,
				     logger, where, story);
}

bool delete_spd_kernel_policy(const struct spd *spd,
			      const struct spd_owner *owner,
			      enum direction direction,
			      enum expect_kernel_policy existing_policy_expectation,
			      struct logger *logger,
			      where_t where,
			      const char *story)
{
	if (direction == DIRECTION_OUTBOUND) {
		if (owner->bare_policy != NULL) {
			const struct connection *oc = owner->bare_policy->connection;
			if (BROKEN_TRANSITION &&
			    oc->config->negotiation_shunt == SHUNT_HOLD &&
			    oc->routing.state == RT_ROUTED_NEGOTIATION) {
				ldbg(oc->logger, "%s() skipping NEGOTIATION=HOLD", __func__);
				return true;
			}
			return restore_spd_kernel_policy(owner->bare_policy,
							 DIRECTION_OUTBOUND,
							 logger, where, story);
		}
	}
	return delete_kernel_policy(direction,
				    existing_policy_expectation,
				    &spd->local->client, &spd->remote->client,
				    &spd->connection->sa_marks,
				    spd->connection->xfrmi,
				    DEFAULT_KERNEL_POLICY_ID,
				    HUNK_AS_SHUNK(spd->connection->config->sec_label),
				    logger, where, story);
}

void delete_spd_kernel_policies(struct spd *spd,
				const struct spd_owner *owner,
				enum expect_kernel_policy inbound_policy_expectation,
				struct logger *logger, where_t where,
				const char *story)
{
	delete_spd_kernel_policy(spd, owner, DIRECTION_OUTBOUND,
				 EXPECT_KERNEL_POLICY_OK,
				 logger, where, story);
	delete_spd_kernel_policy(spd, owner, DIRECTION_INBOUND,
				 inbound_policy_expectation,
				 logger, where, story);
}

/* CAT and it's kittens */

static bool pexpect_cat(const struct connection *c, struct logger *logger)
{
	return (PEXPECT(logger, is_instance(c)) &&
		PEXPECT(logger, c->clonedfrom != NULL) &&
		PEXPECT(logger, c->local->child.config->has_client_address_translation) &&
		PEXPECT(logger, c->local->child.has_cat));
}

bool add_cat_kernel_policy(const struct connection *c,
			   const struct kernel_policy *kernel_policy,
			   enum direction direction,
			   struct logger *logger, where_t where,
			   const char *reason)
{
	ldbg(logger, "%s", reason);
	if (!pexpect_cat(c, logger)) {
		return false;
	}

	ip_selector local_client = selector_from_address(kernel_policy->local.host);
	if (!add_kernel_policy(KERNEL_POLICY_OP_ADD, direction,
			       &local_client, &kernel_policy->remote.route,
			       kernel_policy, deltatime(0),
			       logger, where, reason)) {
		llog(RC_LOG, logger, "%s failed", reason);
		return false;
	}
	return true;
}

static void delete_cat_kernel_policy(const struct spd *spd,
				     const struct spd_owner *owner,
				     enum direction direction,
				     struct logger *logger,
				     where_t where,
				     const char *story)
{
	const struct connection *c = spd->connection;
	ldbg(logger, "%s", story);
	if (!pexpect_cat(c, logger)) {
		return;
	}
	/*
	 * XXX: forming the local CLIENT from the local HOST is
	 * needed.  That is what CAT (client address translation) is
	 * all about.
	 */
	ip_selector local_client = selector_from_address(spd->local->host->addr);
	if (direction == DIRECTION_OUTBOUND) {
		if (owner->bare_cat != NULL) {
			if (!restore_spd_kernel_policy(owner->bare_cat,
						       DIRECTION_OUTBOUND,
						       logger, where, story)) {
				llog(RC_LOG, logger, "%s failed", story);
			}
			return;
		}
	}

	if (!delete_kernel_policy(direction, EXPECT_KERNEL_POLICY_OK,
				  &local_client, &spd->remote->client,
				  &c->sa_marks, c->xfrmi,
				  DEFAULT_KERNEL_POLICY_ID,
				  HUNK_AS_SHUNK(spd->connection->config->sec_label),
				  logger, where, story)) {
		llog(RC_LOG, logger, "%s failed", story);
	}
}

void delete_cat_kernel_policies(const struct spd *spd,
				const struct spd_owner *owner,
				struct logger *logger,
				where_t where)
{
#ifdef USE_NFTABLES
	const char *delete_inbound_cat = "CAT: NFTABLES: removing inbound IPsec policy";
#else
	/* BSD; USE_IPTABLES; ... */
	const char *delete_inbound_cat = NULL;
#endif
	if (spd->local->child->has_cat) {
		delete_cat_kernel_policy(spd, owner, DIRECTION_OUTBOUND, logger, where,
					 "CAT: removing outbound IPsec policy");
		if (delete_inbound_cat != NULL) {
			delete_cat_kernel_policy(spd, owner, DIRECTION_INBOUND,
						 logger, where, delete_inbound_cat);
		}
	}
}

bool install_inbound_ipsec_kernel_policy(struct child_sa *child,
					 struct spd *spd,
					 where_t where)
{
	struct kernel_policy kernel_policy =
		kernel_policy_from_state(child, spd, DIRECTION_INBOUND, where);
	selector_buf sb,db;
	ldbg_sa(child, "kernel: %s() is installing SPD for %s=>%s",
		__func__,
		str_selector(&kernel_policy.src.client, &sb),
		str_selector(&kernel_policy.dst.client, &db));

#ifdef USE_NFTABLES
	const char *add_inbound_cat =
		(spd->local->child->has_cat ? "CAT: NFTABLES: add inbound IPsec policy" :
		 NULL);
#else
	/* BSD; USE_IPTABLES; ... */
	const char *add_inbound_cat = NULL;
#endif
	if (add_inbound_cat != NULL) {
		if(!add_cat_kernel_policy(child->sa.st_connection,
				      &kernel_policy, DIRECTION_INBOUND,
				      child->sa.logger, where, add_inbound_cat)) {
			return false;
		}
	}

	if (!kernel_ops_policy_add(KERNEL_POLICY_OP_ADD,
				   DIRECTION_INBOUND,
				   &kernel_policy.src.route,	/* src_client */
				   &kernel_policy.dst.route,	/* dst_client */
				   &kernel_policy,			/* " */
				   deltatime(0),		/* lifetime */
				   child->sa.logger, where, "add inbound Child SA")) {
		selector_buf sb, db;
		llog_sa(RC_LOG, child,
			"kernel: %s() failed to add SPD for %s=>%s",
			__func__,
			str_selector(&kernel_policy.src.client, &sb),
			str_selector(&kernel_policy.dst.client, &db));
		return false;
	}
	return true;
}

bool install_outbound_ipsec_kernel_policy(struct child_sa *child,
					  struct spd *spd,
					  enum kernel_policy_op op, where_t where)
{
	struct logger *logger = child->sa.logger;
	PASSERT(logger, (op == KERNEL_POLICY_OP_REPLACE ||
			 op == KERNEL_POLICY_OP_ADD));
	const struct kernel_policy kernel_policy =
		kernel_policy_from_state(child, spd, DIRECTION_OUTBOUND, where);
	/* check for no transform at all */
	PASSERT(child->sa.logger, kernel_policy.nr_rules > 0);
	if (spd->local->child->has_cat) {
		/*
		 * CAT means:
		 *
		 * = (possibly) replace the on-demand host_addr ->
		 *   remote_addr policy
		 *
		 * = add outbound client -> client policy for the
		 *   assigned address.
		 */
		if (!add_cat_kernel_policy(child->sa.st_connection,
				      &kernel_policy, DIRECTION_OUTBOUND,
				      child->sa.logger, where,
				      "CAT: add outbound IPsec policy")) {
			return false;
		}
		/*
		 * Now add the client.
		 */
		return kernel_ops_policy_add(op, DIRECTION_OUTBOUND,
					     &kernel_policy.src.route,
					     &kernel_policy.dst.route,
					     &kernel_policy,
					     deltatime(0),
					     logger, where,
					     "CAT: add client->client kernel policy");
	} else {
		/*
		 * Just need client->client policies
		 */
		return kernel_ops_policy_add(op, DIRECTION_OUTBOUND,
					     &kernel_policy.src.route,
					     &kernel_policy.dst.route,
					     &kernel_policy,
					     deltatime(0),
					     logger, where,
					     "install IPsec policy");
	}
}

bool install_bare_kernel_policy(ip_selector src, ip_selector dst,
				enum shunt_kind shunt_kind,
				enum shunt_policy shunt_policy,
				const struct nic_offload *nic_offload,
				struct logger *logger, where_t where)
{
	struct kernel_policy kernel_policy =
		kernel_policy_from_void(src, dst,
					/*always*/DIRECTION_OUTBOUND,
					highest_spd_priority,
					shunt_kind, shunt_policy,
					/*sa_marks*/NULL, /*xfrmi*/NULL,
					/* bare shunt are not
					 * associated with any
					 * connection so no
					 * security label */
					/*sec_label*/null_shunk,
					nic_offload,
					where);
	return kernel_ops_policy_add(KERNEL_POLICY_OP_REPLACE,
				     DIRECTION_OUTBOUND,
				     &kernel_policy.src.client,
				     &kernel_policy.dst.client,
				     &kernel_policy,
				     deltatime(SHUNT_PATIENCE),
				     logger, where, "install bare policy");
}

void replace_ipsec_with_bare_kernel_policy(struct child_sa *child,
					   struct connection *c,
					   struct spd *spd,
					   const struct spd_owner *owner,
					   enum shunt_kind shunt_kind,
					   enum expect_kernel_policy expect_inbound_policy,
					   struct logger *logger, where_t where)
{
	PEXPECT(logger, c->config->shunt[shunt_kind] != SHUNT_NONE);
	if (spd->local->child->has_cat) {
		/*
		 * CAT means:
		 *
		 * = (possibly) replace the on-demand host_addr ->
		 *   remote_addr policy
		 *
		 * = add outbound client -> client policy for the
		 *   assigned address.
		 */
		/* what was installed? */
		const struct kernel_policy kernel_policy =
			kernel_policy_from_state(child, spd, DIRECTION_OUTBOUND, where);
		if (!delete_kernel_policy(DIRECTION_OUTBOUND,
					  EXPECT_KERNEL_POLICY_OK,
					  &kernel_policy.src.route,
					  &kernel_policy.dst.route,
					  kernel_policy.sa_marks,
					  kernel_policy.xfrmi,
					  kernel_policy.id,
					  kernel_policy.sec_label,
					  logger, where,
					  "CAT: delete client->client kernel policy")) {
			llog(RC_LOG, logger,
			     "kernel: %s() delete client->client kernel policy", __func__);
		}
	} else {
		/*
		 * Just need client->client policies
		 */
		if (!add_spd_kernel_policy(spd,
					   KERNEL_POLICY_OP_REPLACE,
					   DIRECTION_OUTBOUND,
					   shunt_kind,
					   logger, where, "replacing")) {
			llog(RC_LOG, logger,
			     "kernel: %s() replace outbound with prospective shunt failed", __func__);
		}
	}
	/*
	 * Always zap inbound.
	 */

	if (!delete_spd_kernel_policy(spd, owner, DIRECTION_INBOUND,
				      expect_inbound_policy,
				      logger, where, "inbound")) {
		llog(RC_LOG, logger,
		     "kernel: %s() inbound delete failed", __func__);
	}
}
