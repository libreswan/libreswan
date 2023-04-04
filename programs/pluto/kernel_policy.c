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
						    kernel_priority_t priority,
						    enum shunt_kind shunt_kind,
						    enum shunt_policy shunt_policy,
						    const struct sa_marks *sa_marks,
						    const struct pluto_xfrmi *xfrmi,
						    const shunk_t sec_label,
						    where_t where)
{
	const ip_selector *src;
	const ip_selector *dst;
	switch (direction) {
	case DIRECTION_OUTBOUND:
		src = &local;
		dst = &remote;
		break;
	case DIRECTION_INBOUND:
		src = &remote;
		dst = &local;
		break;
	default:
		bad_case(direction);
	}

	const struct ip_info *child_afi = selector_type(src);
	pexpect(selector_type(dst) == child_afi);

	struct kernel_policy transport_esp = {
		/* what will capture packets */
		.src.client = *src,
		.dst.client = *dst,
		.src.route = *src,
		.dst.route = *dst,
		.priority = priority,
		.kind = shunt_kind,
		.shunt = shunt_policy,
		.where = where,
		.id = DEFAULT_KERNEL_POLICY_ID,
		.sa_marks = sa_marks,
		.xfrmi = xfrmi,
		.sec_label = sec_label,
		/*
		 * With transport mode, the encapsulated packet on the
		 * host interface must have the same family as the raw
		 * packet on the client interface.  Even though it is
		 * UNSPEC.
		 */
		.src.host = child_afi->address.unspec,
		.dst.host = child_afi->address.unspec,
		.mode = ENCAP_MODE_TRANSPORT,
	};
	if (shunt_policy != SHUNT_PASS) {
		transport_esp.nr_rules = 1;
		transport_esp.rule[0] = (struct kernel_policy_rule) {
			.proto = ENCAP_PROTO_ESP,
			.reqid = 0,
		};
	}
	return transport_esp;
}

static struct kernel_policy kernel_policy_from_spd(lset_t policy,
						   const struct spd_route *spd,
						   enum encap_mode mode,
						   enum direction direction,
						   enum shunt_kind shunt_kind,
						   enum shunt_policy shunt_policy,
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
	ip_selector remote_client;
	switch (mode) {
	case ENCAP_MODE_TUNNEL:
		remote_client = spd->remote->client;
		break;
	case ENCAP_MODE_TRANSPORT:
		remote_client = selector_from_address_protocol_port(spd->remote->host->addr,
								    selector_protocol(spd->remote->client),
								    selector_port(spd->remote->client));
		break;
	default:
		bad_case(mode);
	}

	const struct spd_end *src;
	const struct spd_end *dst;
	ip_selector src_route, dst_route;
	switch (direction) {
	case DIRECTION_INBOUND:
		src = spd->remote;
		dst = spd->local;
		src_route = remote_client;
		dst_route = dst->client;	/* XXX: kernel_route has unset_selector */
		break;
	case DIRECTION_OUTBOUND:
		src = spd->local;
		dst = spd->remote;
		src_route = src->client;	/* XXX: kernel_route has unset_selector */
		dst_route = remote_client;
		break;
	default:
		bad_case(direction);
	}

	struct kernel_policy kernel_policy = {
		.src.client = src->client,
		.dst.client = dst->client,
		.src.host = src->host->addr,
		.dst.host = dst->host->addr,
		.src.route = src_route,
		.dst.route = dst_route,
		.priority = calculate_kernel_priority(spd->connection),
		.mode = mode,
		.kind = shunt_kind,
		.shunt = shunt_policy,
		.where = where,
		.sa_marks = &spd->connection->sa_marks,
		.xfrmi = spd->connection->xfrmi,
		.id = DEFAULT_KERNEL_POLICY_ID,
		.sec_label = HUNK_AS_SHUNK(spd->connection->config->sec_label),
		.nr_rules = 0,
	};

	/*
	 * Construct the kernel policy rules inner-to-outer (matching
	 * the flow of an outgoing packet).
	 *
	 * Note: the order is fixed: compress -> encrypt ->
	 * authenticate.
	 *
	 * Note: only the inner most policy rule gets the tunnel bit
	 * (aka worm) (currently the global .mode is set and kernel
	 * backends handle this).
	 *
	 * Note: the stack order matches kernel_sa's array.
	 */

	reqid_t child_reqid = spd->connection->child.reqid;
	struct kernel_policy_rule *last = kernel_policy.rule;
	if (policy & POLICY_COMPRESS) {
		last->reqid = reqid_ipcomp(child_reqid);
		last->proto = ENCAP_PROTO_IPCOMP;
		last++;
	}
	if (policy & POLICY_ENCRYPT) {
		last->reqid = reqid_esp(child_reqid);
		last->proto = ENCAP_PROTO_ESP;
		last++;
	}
	if (policy & POLICY_AUTHENTICATE) {
		last->reqid = reqid_ah(child_reqid);
		last->proto = ENCAP_PROTO_AH;
		last++;
	}

	passert(last < kernel_policy.rule + elemsof(kernel_policy.rule));
	kernel_policy.nr_rules = last - kernel_policy.rule;
	passert(kernel_policy.nr_rules < elemsof(kernel_policy.rule));

	return kernel_policy;
}

static struct kernel_policy kernel_policy_from_state(const struct state *st,
						     const struct spd_route *spd,
						     enum direction direction,
						     where_t where)
{
	bool tunnel = false;
	lset_t policy = LEMPTY;

	if (st->st_ipcomp.present) {
		policy |= POLICY_COMPRESS;
		tunnel |= (st->st_ipcomp.attrs.mode == ENCAPSULATION_MODE_TUNNEL);
	}

	if (st->st_esp.present) {
		policy |= POLICY_ENCRYPT;
		tunnel |= (st->st_esp.attrs.mode == ENCAPSULATION_MODE_TUNNEL);
	}

	if (st->st_ah.present) {
		policy |= POLICY_AUTHENTICATE;
		tunnel |= (st->st_ah.attrs.mode == ENCAPSULATION_MODE_TUNNEL);
	}

	enum encap_mode mode = (tunnel ? ENCAP_MODE_TUNNEL : ENCAP_MODE_TRANSPORT);
	struct kernel_policy kernel_policy = kernel_policy_from_spd(policy,
								    spd, mode, direction,
								    SHUNT_KIND_IPSEC,
								    SHUNT_IPSEC,
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

bool install_bare_sec_label_kernel_policy(const struct spd_route *spd,
					  enum kernel_policy_op op,
					  enum direction direction,
					  enum expect_kernel_policy existing_policy_expectation,
					  struct logger *logger,
					  where_t where, const char *what)
{
	const struct connection *c = spd->connection;
	PASSERT(logger, (op == KERNEL_POLICY_OP_ADD ||
			 op == KERNEL_POLICY_OP_REPLACE));
	PASSERT(logger, c->config->sec_label.len > 0);
	enum encap_mode encap_mode = (c->policy & POLICY_TUNNEL ? ENCAP_MODE_TUNNEL :
				      ENCAP_MODE_TRANSPORT);
	struct kernel_policy kernel_policy =
		kernel_policy_from_spd(c->policy, spd, encap_mode, direction,
				       SHUNT_KIND_IPSEC,
				       SHUNT_IPSEC,
				       where);
	if (!kernel_ops_raw_policy(op, direction,
				   existing_policy_expectation,
				   &kernel_policy.src.client,
				   &kernel_policy.dst.client,
				   &kernel_policy,
				   deltatime(0),
				   kernel_policy.sa_marks,
				   kernel_policy.xfrmi,
				   kernel_policy.id,
				   kernel_policy.sec_label,
				   where, logger, what)) {
		return false;
	}
	return true;
}

/*
 * Install (add, replace) a kernel policy using information from the
 * SPD.  An SPD is bare when there's no corresponding kernel state.
 */

bool install_bare_spd_kernel_policy(const struct spd_route *spd,
				    enum kernel_policy_op op,
				    enum direction direction,
				    enum expect_kernel_policy existing_policy_expectation,
				    enum shunt_kind shunt_kind,
				    struct logger *logger,
				    where_t where, const char *what)
{
	const struct connection *c = spd->connection;

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

	struct kernel_policy kernel_policy =
		kernel_policy_from_void(spd->local->client, spd->remote->client,
					direction, calculate_kernel_priority(c),
					shunt_kind,
					spd->connection->config->shunt[shunt_kind],
					&c->sa_marks, c->xfrmi,
					HUNK_AS_SHUNK(c->config->sec_label),
					where);

	if (!kernel_ops_raw_policy(op, direction,
				   existing_policy_expectation,
				   &kernel_policy.src.client,
				   &kernel_policy.dst.client,
				   &kernel_policy,
				   deltatime(0),
				   kernel_policy.sa_marks,
				   kernel_policy.xfrmi,
				   kernel_policy.id,
				   kernel_policy.sec_label,
				   where, logger, what)) {
		return false;
	}

	return true;
}

bool delete_kernel_policy(enum direction direction,
			  enum expect_kernel_policy expect_kernel_policy,
			  const ip_selector *local_child,
			  const ip_selector *remote_child,
			  const struct sa_marks *sa_marks,
			  const struct pluto_xfrmi *xfrmi,
			  enum kernel_policy_id id,
			  const shunk_t sec_label,
			  struct logger *logger, where_t where, const char *story)
{
	const ip_selector *src_child;
	const ip_selector *dst_child;
	switch (direction) {
	case DIRECTION_OUTBOUND:
		src_child = local_child;
		dst_child = remote_child;
		break;
	case DIRECTION_INBOUND:
		src_child = remote_child;
		dst_child = local_child;
		break;
	default:
		bad_case(direction);
	}

	const struct ip_protocol *child_proto = selector_protocol(*src_child);
	pexpect(child_proto == selector_protocol(*dst_child));

	bool result = kernel_ops_raw_policy(KERNEL_POLICY_OP_DELETE,
					    direction,
					    expect_kernel_policy,
					    src_child, dst_child,
					    /*policy*/NULL/*delete-not-needed*/,
					    deltatime(0),
					    sa_marks, xfrmi, id, sec_label,
					    where, logger, story);
	dbg("kernel: %s() result=%s", __func__, (result ? "success" : "failed"));
	return result;
}

bool delete_spd_kernel_policy(const struct spd_route *spd,
			      enum direction direction,
			      enum expect_kernel_policy existing_policy_expectation,
			      struct logger *logger,
			      where_t where,
			      const char *story)
{
	return delete_kernel_policy(direction,
				    existing_policy_expectation,
				    &spd->local->client, &spd->remote->client,
				    &spd->connection->sa_marks,
				    spd->connection->xfrmi,
				    DEFAULT_KERNEL_POLICY_ID,
				    HUNK_AS_SHUNK(spd->connection->config->sec_label),
				    logger, where, story);
}

void delete_spd_kernel_policies(const struct spds *spds,
				enum expect_kernel_policy inbound_policy_expectation,
				struct logger *logger, where_t where,
				const char *story)
{
	FOR_EACH_ITEM(spd, spds) {
		/*
		 * XXX: note the hack where missing inbound
		 * policies are ignored.  The connection
		 * should know if there's an inbound policy,
		 * in fact the connection shouldn't even have
		 * inbound policies, just the state.
		 *
		 * For sec_label, it's tearing down the route,
		 * hence that is included.
		 */
		delete_spd_kernel_policy(spd, DIRECTION_OUTBOUND,
					 EXPECT_KERNEL_POLICY_OK,
					 logger, where, story);
		delete_spd_kernel_policy(spd, DIRECTION_INBOUND,
					 inbound_policy_expectation,
					 logger, where, story);
#ifdef IPSEC_CONNECTION_LIMIT
		num_ipsec_eroute--;
#endif
	}
}

/* CAT and it's kittens */

bool install_bare_cat_kernel_policy(const struct spd_route *spd,
				    enum kernel_policy_op op,
				    enum expect_kernel_policy expect_kernel_policy,
				    enum shunt_kind shunt_kind,
				    struct logger *logger,
				    where_t where,
				    const char *reason)
{
	struct connection *c = spd->connection;
	ldbg(logger, "CAT: %s", reason);
	struct kernel_policy kernel_policy =
		kernel_policy_from_void(spd->local->client, spd->remote->client,
					DIRECTION_OUTBOUND,
					calculate_kernel_priority(c),
					shunt_kind, spd->connection->config->shunt[shunt_kind],
					&c->sa_marks, c->xfrmi,
					HUNK_AS_SHUNK(c->config->sec_label),
					where);
	/*
	 * XXX: forming the local CLIENT from the local HOST is
	 * needed.  That is what CAT (client address translation) is
	 * all about.
	 */
	ip_selector local_client = selector_from_address(spd->local->host->addr);
	return kernel_ops_raw_policy(op, DIRECTION_OUTBOUND, expect_kernel_policy,
				     &local_client, &kernel_policy.dst.client,
				     &kernel_policy,
				     deltatime(0),
				     kernel_policy.sa_marks,
				     kernel_policy.xfrmi,
				     kernel_policy.id,
				     kernel_policy.sec_label,
				     where, logger, reason);
}

bool delete_cat_kernel_policy(const struct spd_route *spd,
			      enum expect_kernel_policy expect_kernel_policy,
			      struct logger *logger,
			      where_t where,
			      const char *reason)
{
	struct connection *c = spd->connection;
	ldbg(logger, "CAT: %s", reason);
	/*
	 * XXX: forming the local CLIENT from the local HOST is
	 * needed.  That is what CAT (client address translation) is
	 * all about.
	 */
	ip_selector local_client = selector_from_address(spd->local->host->addr);
	return delete_kernel_policy(DIRECTION_OUTBOUND,
				    expect_kernel_policy,
				    &local_client, &spd->remote->client,
				    &c->sa_marks, c->xfrmi,
				    DEFAULT_KERNEL_POLICY_ID,
				    HUNK_AS_SHUNK(spd->connection->config->sec_label),
				    logger, where, reason);
}

void install_inbound_ipsec_kernel_policy(struct child_sa *child,
					 struct spd_route *spd,
					 where_t where)
{
	struct kernel_policy kernel_policy =
		kernel_policy_from_state(&child->sa, spd, DIRECTION_INBOUND, where);
	selector_pair_buf spb;
	ldbg_sa(child, "kernel: %s() is installing SPD for %s",
		__func__, str_selector_pair(&kernel_policy.src.client, &kernel_policy.dst.client, &spb));

#if defined(HAVE_NFTABLES)
	if (spd->local->child->has_cat) {
		ip_selector client = selector_from_address(spd->local->host->addr);

		if (!raw_policy(KERNEL_POLICY_OP_ADD,
				DIRECTION_INBOUND,
				EXPECT_KERNEL_POLICY_OK,
				&kernel_policy.src.route,	/* src_client */
				&client,
				&kernel_policy,			/* " */
				deltatime(0),		/* lifetime */
				kernel_policy.sa_marks,
				kernel_policy.xfrmi,
				kernel_policy.id,
				kernel_policy.sec_label,
				st->st_logger,
				"%s() add inbound Child SA", __func__)) {
			selector_pair_buf spb;
			llog(RC_LOG, st->st_logger,
			     "kernel: %s() failed to add SPD for %s",
			     __func__,
			     str_selector_pair(&kernel_policy.src.client, &kernel_policy.dst.client, &spb));
		}

	}
#endif

	if (!kernel_ops_raw_policy(KERNEL_POLICY_OP_ADD,
				   DIRECTION_INBOUND,
				   EXPECT_KERNEL_POLICY_OK,
				   &kernel_policy.src.route,	/* src_client */
				   &kernel_policy.dst.route,	/* dst_client */
				   &kernel_policy,			/* " */
				   deltatime(0),		/* lifetime */
				   kernel_policy.sa_marks,
				   kernel_policy.xfrmi,
				   kernel_policy.id,
				   kernel_policy.sec_label,
				   where, child->sa.st_logger, "add inbound Child SA")) {
		selector_pair_buf spb;
		llog_sa(RC_LOG, child,
			"kernel: %s() failed to add SPD for %s",
			__func__,
			str_selector_pair(&kernel_policy.src.client, &kernel_policy.dst.client, &spb));
	}
}

bool install_outbound_ipsec_kernel_policy(struct child_sa *child,
					  struct spd_route *spd,
					  bool replace, where_t where)
{
	enum kernel_policy_op op = (replace ? KERNEL_POLICY_OP_REPLACE :
				    KERNEL_POLICY_OP_ADD);
	const struct kernel_policy kernel_policy =
		kernel_policy_from_state(&child->sa, spd, DIRECTION_OUTBOUND, where);
	/* check for no transform at all */
	PASSERT(child->sa.st_logger, kernel_policy.nr_rules > 0);
	if (spd->local->child->has_cat) {
		ip_selector client = selector_from_address(spd->local->host->addr);
		if (!kernel_ops_raw_policy(op, DIRECTION_OUTBOUND,
					   EXPECT_KERNEL_POLICY_OK,
					   &client,
					   &kernel_policy.dst.route,
					   &kernel_policy,
					   deltatime(0),
					   kernel_policy.sa_marks,
					   kernel_policy.xfrmi,
					   kernel_policy.id,
					   kernel_policy.sec_label,
					   where, child->sa.st_logger,
					   "CAT: install IPsec policy")) {
			llog_sa(RC_LOG, child,
				"CAT: failed to eroute additional Client Address Translation policy");
		}
	}
	return kernel_ops_raw_policy(op, DIRECTION_OUTBOUND,
				     EXPECT_KERNEL_POLICY_OK,
				     &kernel_policy.src.route, &kernel_policy.dst.route,
				     &kernel_policy,
				     deltatime(0),
				     kernel_policy.sa_marks,
				     kernel_policy.xfrmi,
				     kernel_policy.id,
				     kernel_policy.sec_label,
				     where, child->sa.st_logger,
				     "install IPsec policy");
}

bool install_bare_kernel_policy(ip_selector src, ip_selector dst,
				enum shunt_kind shunt_kind,
				enum shunt_policy shunt_policy,
				struct logger *logger, where_t where)
{
	struct kernel_policy kernel_policy =
		kernel_policy_from_void(src, dst,
					/*always*/DIRECTION_OUTBOUND,
					highest_kernel_priority,
					shunt_kind, shunt_policy,
					/*sa_marks*/NULL, /*xfrmi*/NULL,
					/* bare shunt are not
					 * associated with any
					 * connection so no
					 * security label */
					/*sec_label*/null_shunk,
					where);
	return kernel_ops_raw_policy(KERNEL_POLICY_OP_REPLACE,
				     DIRECTION_OUTBOUND,
				     EXPECT_KERNEL_POLICY_OK,
				     &kernel_policy.src.client,
				     &kernel_policy.dst.client,
				     &kernel_policy,
				     deltatime(SHUNT_PATIENCE),
				     kernel_policy.sa_marks/*NULL*/,
				     kernel_policy.xfrmi/*NULL*/,
				     kernel_policy.id, /*0*/
				     kernel_policy.sec_label/*null_shunk*/,
				     where, logger, "install bare policy");
}

void replace_ipsec_with_bare_kernel_policies(struct child_sa *child,
					     enum routing new_routing,
					     enum expect_kernel_policy expect_inbound_policy,
					     where_t where)
{
	struct logger *logger = child->sa.st_logger;
	struct connection *c = child->sa.st_connection;
	enum shunt_kind shunt_kind =
		(new_routing == RT_ROUTED_ONDEMAND ? SHUNT_KIND_ONDEMAND :
		 new_routing == RT_ROUTED_FAILURE ? SHUNT_KIND_FAILURE :
		 SHUNT_KIND_ROOF);
	PASSERT(logger, shunt_kind != SHUNT_KIND_ROOF);
	PASSERT(logger, c->config->shunt[shunt_kind] != SHUNT_NONE);
	/* it's being stripped of the state, hence SOS_NOBODY */
	set_routing(c, new_routing, NULL);

	FOR_EACH_ITEM(spd, &c->child.spds) {

#ifdef USE_CISCO_SPLIT
		if (spd == c->spd && c->remotepeertype == CISCO) {
			/*
			 * XXX: this comment is out-of-date:
			 *
			 * XXX: this is currently the only reason for
			 * spd_next walking.
			 *
			 * Routing should become RT_ROUTED_FAILURE,
			 * but if POLICY_FAIL_NONE, then we just go
			 * right back to RT_ROUTED_PROSPECTIVE as if
			 * no failure happened.
			 */
			ldbg_sa(child,
				"kernel: %s() skipping, first SPD and remotepeertype is CISCO, damage done",
				__func__);
			continue;
		}
#endif

		do_updown(UPDOWN_DOWN, c, spd, &child->sa, logger);

		pexpect(c->config->shunt[shunt_kind] != SHUNT_NONE);
		if (!install_bare_spd_kernel_policy(spd,
						    KERNEL_POLICY_OP_REPLACE,
						    DIRECTION_OUTBOUND,
						    EXPECT_KERNEL_POLICY_OK,
						    shunt_kind,
						    logger, where, "replacing")) {
			llog_sa(RC_LOG, child,
				"kernel: %s() replace outbound with prospective shunt failed", __func__);
		}
		/*
		 * Always zap inbound.
		 */
		if (!delete_spd_kernel_policy(spd, DIRECTION_INBOUND,
					      expect_inbound_policy,
					      logger, where, "inbound")) {
			llog_sa(RC_LOG, child,
				"kernel: %s() inbound delete failed", __func__);
		}
	}
}
