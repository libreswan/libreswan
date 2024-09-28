/* Kernel interace to IPsec Interface, for libreswan
 *
 * Copyright (C) 2024 Andrew Cagney
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

#include "verbose.h"
#include "ipsec_interface.h"
#include "kernel.h"
#include "kernel_ipsec_interface.h"
#include "log.h"
#include "iface.h"

bool kernel_ipsec_interface_has_cidr(const char *ipsec_if_name,
				     ip_cidr cidr,
				     struct verbose verbose)
{
	cidr_buf cb;
	vdbg("%s:%s() %s %s ...",
	     kernel_ops->ipsec_interface->name, __func__,
	     ipsec_if_name, str_cidr(&cidr, &cb));
	return kernel_ops->ipsec_interface->has_cidr(ipsec_if_name, cidr, verbose);
}

bool kernel_ipsec_interface_add_cidr(const char *ipsec_if_name, ip_cidr cidr,
				     struct verbose verbose)
{
	cidr_buf cb;
	vdbg("%s:%s() %s %s ...",
	     kernel_ops->ipsec_interface->name, __func__,
	     ipsec_if_name, str_cidr(&cidr, &cb));
	verbose.level++;
	return kernel_ops->ipsec_interface->add_cidr(ipsec_if_name, cidr, verbose);
}

void kernel_ipsec_interface_del_cidr(const char *ipsec_if_name, ip_cidr cidr,
				     struct verbose verbose)
{
	cidr_buf cb;
	vdbg("%s:%s() %s %s ...",
	     kernel_ops->ipsec_interface->name, __func__,
	     ipsec_if_name, str_cidr(&cidr, &cb));
	verbose.level++;
	kernel_ops->ipsec_interface->del_cidr(ipsec_if_name, cidr, verbose);
}

bool kernel_ipsec_interface_add(const char *ipsec_if_name /*non-NULL*/,
				const ipsec_interface_id_t ipsec_if_id,
				const struct iface_device *iface,
				struct verbose verbose)
{
	vdbg("%s:%s() %s %u %s ...",
	     kernel_ops->ipsec_interface->name, __func__,
	     ipsec_if_name, ipsec_if_id, iface->real_device_name);
	verbose.level++;
	bool ok = kernel_ops->ipsec_interface->add(ipsec_if_name,
						   ipsec_if_id,
						   iface,
						   verbose);
	unsigned ipsec_if_index = if_nametoindex(ipsec_if_name);
	vdbg("ipsec-interface %s with if_index %u ok: %s",
	     ipsec_if_name, ipsec_if_index, bool_str(ok));
	return ok;
}

bool kernel_ipsec_interface_up(const char *ipsec_if_name,
			       struct verbose verbose)
{
	vdbg("%s:%s() %s ...", kernel_ops->ipsec_interface->name, __func__,
	     ipsec_if_name);
	verbose.level++;
	return kernel_ops->ipsec_interface->up(ipsec_if_name, verbose);
}

bool kernel_ipsec_interface_del(const char *ipsec_if_name /*non-NULL*/,
				struct verbose verbose)
{
	vdbg("%s:%s() %s ...",
	     kernel_ops->ipsec_interface->name, __func__,
	     ipsec_if_name);
	verbose.level++;
	return kernel_ops->ipsec_interface->del(ipsec_if_name, verbose);
}

bool kernel_ipsec_interface_match(struct ipsec_interface_match *match,
				  struct verbose verbose)
{

	vdbg("%s:%s() wildcard %s ipsec_if_name %s ipsec_if_id %u iface_if_index %u",
	     kernel_ops->ipsec_interface->name, __func__,
	     bool_str(match->wildcard),
	     (match->ipsec_if_name != NULL ? match->ipsec_if_name : "N/A"),
	     match->ipsec_if_id,
	     match->iface_if_index);
	verbose.level++;
	return kernel_ops->ipsec_interface->match(match, verbose);
}

void kernel_ipsec_interface_check_stale(struct verbose verbose)
{
	vdbg("%s:%s() ...",
	     kernel_ops->ipsec_interface->name, __func__);
	verbose.level++;
	kernel_ops->ipsec_interface->check_stale(verbose);
}

err_t kernel_ipsec_interface_supported(struct verbose verbose)
{
	vdbg("%s:%s() ...",
	     kernel_ops->ipsec_interface->name, __func__);
	verbose.level++;
	return kernel_ops->ipsec_interface->supported(verbose);
}
