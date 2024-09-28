/* BSD's IPsec Interface, for libreswan
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

#include "ip_info.h"

#include "ipsec_interface.h"
#include "kernel_ipsec_interface.h"
#include "iface.h"
#include "server_run.h"

#include "log.h"

static bool ifconfig_ipsec_interface_has_cidr(const char *ipsec_if_name UNUSED,
					      ip_cidr cidr UNUSED,
					      struct verbose verbose UNUSED)
{
	return false;
}

/*
 * ifconfig ipsec0 inet 172.16.100.1/32 172.16.200.1
 * where 172.16.200.1 is the interface-ip / sourceip.
 */

static bool ifconfig_ipsec_interface_add_cidr(const char *ipsec_if_name,
					      ip_cidr cidr,
					      struct verbose verbose)
{
	/* same scope as add[] */
	cidr_buf cb;
	address_buf ab;
	ip_address address = cidr_address(cidr);
	const struct ip_info *afi = cidr_info(cidr);
	const char *add[] = {
		"ifconfig",
		ipsec_if_name,
		afi->inet_name, /* "inet" or "inet6" */
		str_cidr(&cidr, &cb),
		str_address(&address, &ab),
		NULL,
	};
	return server_runv(add, verbose);
}

static void ifconfig_ipsec_interface_del_cidr(const char *ipsec_if_name,
					      ip_cidr cidr UNUSED,
					      struct verbose verbose)
{
	/* same scope as add[] */
	cidr_buf cb;
	address_buf ab;
	ip_address address = cidr_address(cidr);
	const struct ip_info *afi = cidr_info(cidr);
	const char *delete[] = {
		"ifconfig",
		ipsec_if_name,
		"delete",
		afi->inet_name, /* "inet" or "inet6" */
		str_cidr(&cidr, &cb),
		str_address(&address, &ab),
		NULL,
	};
	server_runv(delete, verbose);
}

static bool ifconfig_ipsec_interface_add(const char *ipsec_if_name,
					 const ipsec_interface_id_t ipsec_if_id UNUSED,
					 const struct iface_device *iface UNUSED,
					 struct verbose verbose)
{
	const char *create[] = {
		"ifconfig",
		ipsec_if_name,
		"create",
		NULL,
	};
	return server_runv(create, verbose);
}

static bool ifconfig_ipsec_interface_up(const char *ipsec_if_name UNUSED,
					struct verbose verbose UNUSED)
{
	const char *up[] = {
		"ifconfig",
		ipsec_if_name,
		"up",
		NULL,
	};
	return server_runv(up, verbose);
}

static bool ifconfig_ipsec_interface_del(const char *ipsec_if_name,
					 struct verbose verbose)
{
	const char *destroy[] = {
		"ifconfig",
		ipsec_if_name,
		"destroy",
		NULL,
	};
	return server_runv(destroy, verbose);
}

static bool ifconfig_ipsec_interface_match(struct ipsec_interface_match *match UNUSED,
					   struct verbose verbose UNUSED)
{
	return false;
}

static void ifconfig_ipsec_interface_check_stale(struct verbose verbose UNUSED)
{
}

static err_t ifconfig_ipsec_interface_supported(struct verbose verbose UNUSED)
{
	return NULL;
}

const struct kernel_ipsec_interface kernel_ipsec_interface_ifconfig = {
	.name = "sec",

	.has_cidr = ifconfig_ipsec_interface_has_cidr,
	.add_cidr = ifconfig_ipsec_interface_add_cidr,
	.del_cidr = ifconfig_ipsec_interface_del_cidr,

	.add = ifconfig_ipsec_interface_add,
	.up = ifconfig_ipsec_interface_up,
	.del = ifconfig_ipsec_interface_del,

	.match = ifconfig_ipsec_interface_match,
	.check_stale = ifconfig_ipsec_interface_check_stale,
	.supported = ifconfig_ipsec_interface_supported,

};
