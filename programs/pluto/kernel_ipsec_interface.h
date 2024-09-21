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

#ifndef KERNEL_IPSEC_INTERFACE_H
#define KERNEL_IPSEC_INTERFACE_H

#include "verbose.h"

struct ipsec_interface_address;
struct ipsec_interface;
struct iface_device;

struct ip_link_match {
	bool wildcard; /* match any valid ipsec-interface */
	const char *ipsec_if_name;
	/* BSD can have zero?  Linux remaps 0 */
	uint32_t ipsec_if_id; /* only when !wildcard */
	char found[IFNAMSIZ];
	diag_t diag;
};

struct kernel_ipsec_interface {
	const char *name;
	/*
	 * On XFRMi IF_ID 0 is invalid; hence remap ipsec-interface=0
	 * to some other value; is this all about preserving old VTI
	 * code?
	 */
	uint32_t map_if_id_zero;

	bool (*ip_addr_if_has_cidr)(const char *ipsec_if_name,
				    ip_cidr cidr,
				    struct verbose verbose);
	bool (*ip_addr_add)(const char *ipsec_if_name,
			    const struct ipsec_interface_address *xfrmi_ipaddr,
			    struct verbose verbose);
	int (*ip_addr_del)(const char *ipsec_if_name,
			   const struct ipsec_interface_address *xfrmi_ipaddr,
			   struct verbose verbose);

	bool (*ip_link_add)(const char *ipsec_if_name /*non-NULL*/,
			    const uint32_t ipsec_if_id,
			    const struct iface_device *physical_device,
			    struct verbose verbose);
	bool (*ip_link_up)(const char *ipsec_if_name,
			   struct verbose verbose);
	bool (*ip_link_del)(const char *ipsec_if_name /*non-NULL*/,
			    struct verbose verbose);

	bool (*ip_link_match)(struct ip_link_match *match,
			     struct verbose verbose);

	void (*check_stale_ipsec_interfaces)(struct logger *logger);
	err_t (*supported)(struct verbose verbose);
	void (*shutdown)(struct verbose verbose);
};

extern const struct kernel_ipsec_interface kernel_ipsec_interface_xfrm;
extern const struct kernel_ipsec_interface kernel_ipsec_interface_bsd;

#endif
