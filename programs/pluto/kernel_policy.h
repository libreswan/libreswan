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
 * A kernel policy that does not have a state.  Typically constructed
 * from a bare shunt but can also be for a prospective shunt when
 * sec_label gets involved.
 */

struct kernel_policy kernel_policy_from_void(ip_selector local, ip_selector remote,
					     enum direction direction,
					     kernel_priority_t priority,
					     enum shunt_policy shunt_policy,
					     const struct sa_marks *sa_marks,
					     const struct pluto_xfrmi *xfrmi,
					     const shunk_t sec_label,
					     where_t where);

/*
 * A kernel policy for an SPD.
 */

struct kernel_policy kernel_policy_from_spd(lset_t policy,
					    const struct spd_route *spd,
					    enum encap_mode mode,
					    enum direction direction,
					    where_t where);

/*
 * Kernel policy of an established IPsec connection aka
 * ROUTED_TUNNELED.
 */

struct kernel_policy kernel_policy_from_state(const struct state *st,
					      const struct spd_route *spd,
					      enum direction direction,
					      where_t where);

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
				    enum shunt_policy shunt,
				    struct logger *logger,
				    where_t where, const char *what);

/* CAT (client address translation) kernel policy maps host->client */
bool install_bare_cat_kernel_policy(const struct spd_route *spd,
				    enum kernel_policy_op op,
				    enum direction direction,
				    enum expect_kernel_policy expect_kernel_policy,
				    enum shunt_policy shunt,
				    struct logger *logger,
				    where_t where,
				    const char *reason);
/*
 * Delete a kernel policy.
 *
 * The parameter list matches just what is required by the kernel
 * (yes, linux centric) to delete the kernel policy.
 */

bool delete_kernel_policy(enum direction dir,
			  enum expect_kernel_policy expect_kernel_policy,
			  const ip_selector this_client,
			  const ip_selector that_client,
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

#endif
