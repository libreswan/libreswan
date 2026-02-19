/* generic to kernel iface code, for Libreswan
 *
 * Copyright (C) 2022 Andrew Cagney
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

#ifndef KERNEL_IFACE_H
#define KERNEL_IFACE_H

#include "ip_address.h"
#include "verbose.h"

struct ip_info;

struct kernel_iface {
	ip_address addr;
	struct kernel_iface *next;
	char name[]; /* MUST BE LAST; overalloc hack */
};

extern struct kernel_iface *find_kernel_ifaces(const struct ip_info *afi,
					       struct verbose verbose);
extern struct kernel_iface *find_kernel_ifaces4(struct verbose verbose);
extern struct kernel_iface *find_kernel_ifaces6(struct verbose verbose);

#endif
