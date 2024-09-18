/* kernel operation wrappers, for libreswan
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

#ifndef KERNEL_OPS_H
#define KERNEL_OPS_H

#include "kernel.h"

bool kernel_ops_policy_add(enum kernel_policy_op op,
			   enum direction dir,
			   const ip_selector *src_client,
			   const ip_selector *dst_client,
			   const struct kernel_policy *policy,
			   deltatime_t use_lifetime,
			   struct logger *logger, where_t where, const char *story);

bool kernel_ops_policy_del(enum direction dir,
			   enum expect_kernel_policy expect_kernel_policy,
			   const ip_selector *src_client,
			   const ip_selector *dst_client,
			   const struct sa_marks *sa_marks,
			   const struct ipsec_interface *xfrmi,
			   enum kernel_policy_id id,
			   const shunk_t sec_label, /*needed*/
			   struct logger *logger, where_t where, const char *story);

/*kernel_ops_state()? kernel_ops_sad()?*/
bool kernel_ops_add_sa(const struct kernel_state *sa,
		       bool replace,
		       struct logger *logger);

ipsec_spi_t kernel_ops_get_ipsec_spi(ipsec_spi_t avoid,
				     const ip_address *src,
				     const ip_address *dst,
				     const struct ip_protocol *proto,
				     reqid_t reqid,
				     uintmax_t min, uintmax_t max,
				     const char *story,	/* often SAID string */
				     struct logger *logger);

bool kernel_ops_del_ipsec_spi(ipsec_spi_t spi, const struct ip_protocol *proto,
			      const ip_address *src, const ip_address *dst,
			      struct logger *logger);

#endif
