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

/*
 * Bare Kernel Policies (i.e., do not have a state).
 *
 * These are installed when a connection transitions to
 * ROUTED_PROSPECTIVE, for instance (and presumably ROUTED_HOLD
 * ROUTED_FAILURE).
 */

bool install_bare_sec_label_kernel_policy(const struct spd_route *spd,
					  enum kernel_policy_op op,
					  enum direction direction,
					  enum expect_kernel_policy existing_policy_expectation,
					  struct logger *logger,
					  where_t where, const char *what);

bool install_bare_spd_kernel_policy(const struct spd_route *spd,
				    enum kernel_policy_op op,
				    enum direction direction,
				    enum expect_kernel_policy existing_policy_expectation,
				    enum shunt_kind shunt_kind,
				    struct logger *logger,
				    where_t where, const char *what);

/*
 * Delete a kernel policy.
 *
 * The parameter list matches just what is required by the kernel
 * (yes, linux centric) to delete the kernel policy.
 */

bool delete_kernel_policy(enum direction dir,
			  enum expect_kernel_policy expect_kernel_policy,
			  const ip_selector *local_client,
			  const ip_selector *remote_client,
			  const struct sa_marks *sa_marks,
			  const struct pluto_xfrmi *xfrmi,
			  enum kernel_policy_id id,
			  const shunk_t sec_label, /*needed*/
			  struct logger *logger, where_t where, const char *story);

bool delete_spd_kernel_policy(const struct spd_route *spd,
			      enum direction direction,
			      enum expect_kernel_policy existing_policy_expectation,
			      struct logger *logger,
			      where_t where,
			      const char *story);

void delete_connection_kernel_policies(struct connection *c);

/*
 * The always outbound CAT (client address translation) kernel policy
 * maps the local.host -> remote.client.
 *
 * The bare-cat is installed during acquire.
 */

bool install_bare_cat_kernel_policy(const struct spd_route *spd,
				    enum kernel_policy_op op,
				    enum expect_kernel_policy expect_kernel_policy,
				    enum shunt_kind shunt_kind,
				    struct logger *logger,
				    where_t where,
				    const char *reason);

bool delete_cat_kernel_policy(const struct spd_route *spd,
			      enum expect_kernel_policy existing_policy_expectation,
			      struct logger *logger,
			      where_t where,
			      const char *story);

void install_inbound_ipsec_kernel_policy(struct child_sa *child, struct spd_route *spd,
					 where_t where);
bool install_outbound_ipsec_kernel_policy(struct child_sa *child, struct spd_route *spd,
					  bool replace, where_t where);

void replace_ipsec_with_bare_kernel_policies(struct child_sa *child,
					     enum routing new_routing,
					     enum expect_kernel_policy expect_inbound_policy,
					     where_t where);

void uninstall_ipsec_kernel_policies(struct child_sa *child,
				     enum expect_kernel_policy expect_inbound_policy,
				     where_t where);


bool install_bare_kernel_policy(ip_selector src, ip_selector dst,
				enum shunt_kind shunt_kind,
				enum shunt_policy shunt_policy,
				struct logger *logger, where_t where);

#endif
