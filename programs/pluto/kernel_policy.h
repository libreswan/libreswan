/* declarations of routines that interface with the kernel's IPsec mechanism
 *
 * Copyright (C) 2023 Andrew Cagney
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

#ifndef KERNEL_POLICY_H
#define KERNEL_POLICY_H

#include <stdbool.h>

#include "where.h"
#include "lset.h"
#include "ip_selector.h"
#include "encap_mode.h"

#include "kernel.h"		/* for kernel_priority_t and kernel_mode */

enum direction;
enum expect_kernel_policy;
enum kernel_policy_op;
enum shunt_policy;
enum kernel_mode;
struct logger;
struct spd;

/*
 * The kernel protocol used to encapsulate.
 *
 * Since ip-xfrm(8) lists esp, ah, comp, route2, hao and setkey(8)
 * lists ah, esp, ipcomp.
 *
 * XXX: The numbers end up being fed into the kernel so need to match
 * IETF equivalents.
 */

enum kernel_proto {
	KERNEL_PROTO_UNSPEC = 0,
	KERNEL_PROTO_ESP = 50,		/* (50)  encryption/auth */
	KERNEL_PROTO_AH = 51,		/* (51)  authentication */
	KERNEL_PROTO_IPCOMP= 108,	/* (108) compression */
};

/*
 * Kernel encapsulation policy.
 *
 * This determine how a packet matching a policy should be
 * encapsulated (processed).  For an outgoing packet, the rules are
 * applied in the specified order (and for incoming, in the reverse
 * order).
 *
 * setkey(8) uses the term "rule" when referring to the tuple
 * protocol/mode/src-dst/level while ip-xfrm(8) uses TMPL to describe
 * something far more complex.
 */

struct kernel_policy_rule {
	enum kernel_proto proto;
	reqid_t reqid;
};

struct kernel_policy_end {
	/*
	 * The SRC/DST selectors of the policy.  This is what captures
	 * the packets so they can be put through the wringer, er,
	 * rules listed below.
	 */
	ip_selector client;
	/*
	 * The route addresses of the encapsulated packets.
	 *
	 * With pfkey and transport mode with nat-traversal we need to
	 * change the remote IPsec SA to point to external ip of the
	 * peer.  Here we substitute real client ip with NATD ip.
	 *
	 * Bug #1004 fix.
	 *
	 * There really isn't "client" with XFRM and transport mode so
	 * eroute must be done to natted, visible ip. If we don't hide
	 * internal IP, communication doesn't work.
	 *
	 * XXX: old comment?
	 */
	ip_selector route;
	/*
	 * The src/dst addresses of the encapsulated packet that are
	 * to go across the public network.
	 *
	 * All rules should use these values?
	 *
	 * With setkey and transport mode, they can be unset; but
	 * libreswan doesn't do that.  Actually they can be IPv[46]
	 * UNSPEC and libreswan does that because XFRM insists on it.
	 */
	ip_address host;
};

struct kernel_policy {
	/*
	 * The src/dst selector and src/dst host (and apparently
	 * route).
	 */
	struct kernel_policy_end local;
	struct kernel_policy_end remote;

	/* same but polarity determined by direction */
	struct kernel_policy_end src;
	struct kernel_policy_end dst;

	spd_priority_t priority;
	enum shunt_kind kind;
	enum shunt_policy shunt;
	where_t where;
	shunk_t sec_label;
	const struct sa_marks *sa_marks;
	const struct pluto_xfrmi *xfrmi;
	enum kernel_policy_id id;
	/*
	 * The rules are applied to an outgoing packet in order they
	 * appear in the rule[] table.  Hence, the output from
	 * .rule[.nr_rules-1] goes across the wire, and rule[0]
	 * specifies the first transform.
	 *
	 * The first transform is also set according to MODE (tunnel
	 * or transport); any other rules are always in transport
	 * mode.
	 */
	enum kernel_mode mode;
	bool iptfs;
	unsigned nr_rules;
	struct kernel_policy_rule rule[3/*IPCOMP+{ESP,AH}+PADDING*/];
	struct nic_offload nic_offload;
};

bool add_sec_label_kernel_policy(const struct spd *spd,
				 enum direction direction,
				 struct logger *logger,
				 where_t where, const char *what);

/*
 * Add/delete a kernel policy.
 *
 * The selectors are LOCAL/REMOTE and _not_ SOURCE/DST.  DIRECTION
 * dictates how to interpret them,
 *
 * The parameter list matches just what is required by the kernel
 * (yes, linux centric) to delete the kernel policy.
 */

bool add_kernel_policy(enum kernel_policy_op op,
		       enum direction direction,
		       const ip_selector *local_selector,
		       const ip_selector *remote_selector,
		       const struct kernel_policy *policy,
		       deltatime_t use_lifetime,
		       struct logger *logger, where_t where, const char *story);

bool delete_kernel_policy(enum direction direction,
			  enum expect_kernel_policy expect_kernel_policy,
			  const ip_selector *local_selector,
			  const ip_selector *remote_selector,
			  const struct sa_marks *sa_marks,
			  const struct pluto_xfrmi *xfrmi,
			  enum kernel_policy_id id,
			  const shunk_t sec_label, /*needed*/
			  struct logger *logger, where_t where, const char *story);

/*
 * Add/delete a bare SPD.
 *
 * Bare Kernel Policies (i.e., do not have a state).
 *
 * These are installed when a connection transitions to and between
 * ROUTED_ONDEMAND and ROUTED_NEGOTIATION.
 */

bool add_spd_kernel_policy(const struct spd *spd,
			   enum kernel_policy_op op,
			   enum direction direction,
			   enum shunt_kind shunt_kind,
			   struct logger *logger, where_t where, const char *what);

void add_spd_kernel_policies(struct connection *c,
			     enum kernel_policy_op op,
			     enum direction direction,
			     enum shunt_kind shunt_kind,
			     struct logger *logger, where_t where, const char *story);

bool replace_spd_kernel_policy(const struct spd *spd,
			       const struct spd_owner *owner,
			       enum direction direction,
			       enum shunt_kind shunt_kind,
			       struct logger *logger,
			       where_t where, const char *what);

bool delete_spd_kernel_policy(const struct spd *spd,
			      const struct spd_owner *owner,
			      enum direction direction,
			      enum expect_kernel_policy existing_policy_expectation,
			      struct logger *logger,
			      where_t where,
			      const char *story);

void delete_spd_kernel_policies(struct spd *spd,
				const struct spd_owner *owner,
				enum expect_kernel_policy inbound_policy_expectation,
				struct logger *logger,
				where_t where,
				const char *story);

/*
 * The always outbound CAT (client address translation) kernel policy
 * maps the local.host -> remote.client.
 */

bool add_cat_kernel_policy(const struct connection *c,
			   const struct kernel_policy *kernel_policy,
			   enum direction direction,
			   struct logger *logger, where_t where,
			   const char *reason);

void add_cat_kernel_policies(const struct connection *c,
			     const struct kernel_policy *kernel_policy,
			     enum direction direction,
			     struct logger *logger, where_t where,
			     const char *reason);

void delete_cat_kernel_policies(const struct spd *spd,
				const struct spd_owner *owner,
				struct logger *logger,
				where_t where);

bool install_inbound_ipsec_kernel_policy(struct child_sa *child, struct spd *spd,
					 where_t where);
bool install_outbound_ipsec_kernel_policy(struct child_sa *child, struct spd *spd,
					  enum kernel_policy_op op, where_t where);

void replace_ipsec_with_bare_kernel_policy(struct child_sa *child,
					   struct connection *c,
					   struct spd *spd,
					   const struct spd_owner *owner,
					   enum shunt_kind shunt_kind,
					   enum expect_kernel_policy expect_inbound_policy,
					   struct logger *logger, where_t where);

bool install_bare_kernel_policy(ip_selector src, ip_selector dst,
				enum shunt_kind shunt_kind,
				enum shunt_policy shunt_policy,
				const struct nic_offload *nic_offload,
				struct logger *logger, where_t where);

#endif
