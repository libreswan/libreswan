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

struct ipsec_interface_match {
	const char *ipsec_if_name;	/* when non-NULL */
	unsigned iface_if_index;	/* when non-zero */

	bool wildcard; /* match any valid ipsec-interface */
	/* BSD can have zero?  Linux remaps 0 */
	ipsec_interface_id_t ipsec_if_id; /* only when !wildcard */

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
	ipsec_interface_id_t map_if_id_zero;

	bool (*has_cidr)(const char *ipsec_if_name, ip_cidr cidr,
			 struct verbose verbose);
	bool (*add_cidr)(const char *ipsec_if_name, ip_cidr cidr,
			 struct verbose verbose);
	void (*del_cidr)(const char *ipsec_if_name, ip_cidr cidr,
			 struct verbose verbose);

	bool (*add)(const char *ipsec_if_name /*non-NULL*/,
		    const ipsec_interface_id_t ipsec_if_id,
		    const struct iface_device *physical_device,
		    struct verbose verbose);
	bool (*up)(const char *ipsec_if_name,
		   struct verbose verbose);
	bool (*del)(const char *ipsec_if_name /*non-NULL*/,
		    struct verbose verbose);

	bool (*match)(struct ipsec_interface_match *match,
		      struct verbose verbose);

	reqid_t (*reqid)(ipsec_interface_id_t if_id, struct verbose verbose);

	err_t (*init)(struct verbose verbose);
};

extern const struct kernel_ipsec_interface kernel_ipsec_interface_xfrm;
extern const struct kernel_ipsec_interface kernel_ipsec_interface_ifconfig;

bool kernel_ipsec_interface_has_cidr(const char *ipsec_if_name,
				     ip_cidr cidr,
				     struct verbose verbose);
bool kernel_ipsec_interface_add_cidr(const char *ipsec_if_name, ip_cidr cidr,
				     struct verbose verbose);
void kernel_ipsec_interface_del_cidr(const char *ipsec_if_name, ip_cidr cidr,
				     struct verbose verbose);

bool kernel_ipsec_interface_add(const char *ipsec_if_name /*non-NULL*/,
				const ipsec_interface_id_t ipsec_if_id,
				const struct iface_device *physical_device,
				struct verbose verbose);
bool kernel_ipsec_interface_up(const char *ipsec_if_name,
			       struct verbose verbose);
bool kernel_ipsec_interface_del(const char *ipsec_if_name /*non-NULL*/,
				struct verbose verbose);

bool kernel_ipsec_interface_match(struct ipsec_interface_match *match,
				  struct verbose verbose);

#endif
