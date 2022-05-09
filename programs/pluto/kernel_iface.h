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

#include <net/if.h>		/* for IFNAMSIZ */

#include "ip_address.h"

struct logger;

struct raw_iface {
	ip_address addr;
	char name[IFNAMSIZ + 20]; /* what would be a safe size? */
	struct raw_iface *next;
};

extern struct raw_iface *find_raw_ifaces4(struct logger *logger);
extern struct raw_iface *find_raw_ifaces6(struct logger *logger);
extern void process_raw_ifaces(struct raw_iface *ifaces, struct logger *logger);

extern bool use_interface(const char *rifn);

#endif
