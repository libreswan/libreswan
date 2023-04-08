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

#include "kernel.h"		/* for kernel_priority_t */

enum direction;
enum expect_kernel_policy;
enum kernel_policy_op;
enum shunt_policy;
enum encap_mode;
struct logger;
struct spd_route;

bool add_sec_label_kernel_policy(const struct spd_route *spd,
				 enum direction direction,
				 struct logger *logger,
				 where_t where, const char *what);

/*
 * Bare Kernel Policies (i.e., do not have a state).
 *
 * These are installed when a connection transitions to
 * ROUTED_PROSPECTIVE, for instance (and presumably ROUTED_HOLD
 * ROUTED_FAILURE).
 */

bool install_bare_spd_kernel_policy(const struct spd_route *spd,
				    enum kernel_policy_op op,
				    enum direction direction,
				    enum shunt_kind shunt_kind,
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
 */

bool delete_spd_kernel_policy(const struct spd_route *spd,
			      enum direction direction,
			      enum expect_kernel_policy existing_policy_expectation,
			      struct logger *logger,
			      where_t where,
			      const char *story);

void delete_spd_kernel_policies(const struct spds *spds,
				enum expect_kernel_policy inbound_policy_expectation,
				struct logger *logger,
				where_t where,
				const char *story);

/*
 * The always outbound CAT (client address translation) kernel policy
 * maps the local.host -> remote.client.
 */

void add_cat_kernel_policy(const struct connection *c,
			   const struct kernel_policy *kernel_policy,
			   enum direction direction,
			   struct logger *logger, where_t where,
			   const char *reason);

void delete_cat_kernel_policy(const struct spd_route *spd,
			      enum direction direction,
			      struct logger *logger, where_t where,
			      const char *story);

void install_inbound_ipsec_kernel_policy(struct child_sa *child, struct spd_route *spd,
					 where_t where);
bool install_outbound_ipsec_kernel_policy(struct child_sa *child, struct spd_route *spd,
					  enum kernel_policy_op op, where_t where);

void replace_ipsec_with_bare_kernel_policies(struct child_sa *child,
					     enum routing new_routing,
					     enum expect_kernel_policy expect_inbound_policy,
					     where_t where);

bool install_bare_kernel_policy(ip_selector src, ip_selector dst,
				enum shunt_kind shunt_kind,
				enum shunt_policy shunt_policy,
				struct logger *logger, where_t where);

#endif
