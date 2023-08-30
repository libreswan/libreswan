/*
 * xfrmi declarations, linux kernel IPsec interface/device
 *
 * Copyright (C) 2018-2020 Antony Antony <antony@phenome.org>
 * Copyright (C) 2023 Brady Johnson <bradyallenjohnson@gmail.com>
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

#ifndef KERNEL_XFRM_INTERFACE_H
#define KERNEL_XFRM_INTERFACE_H

#include <stdbool.h>

#include "err.h"
#include "ip_cidr.h"
#include "refcnt.h"
#include "ip_endpoint.h"

#if defined(linux) && defined(KERNEL_XFRM) && defined(USE_XFRM_INTERFACE)
/* how to check defined(XFRMA_IF_ID) && defined(IFLA_XFRM_LINK)? those are enums */
# define IS_XFRMI true
#else
# define IS_XFRMI false
#endif

/* xfrmi interface format. start with ipsec1 IFNAMSIZ - 1 */
#define XFRMI_DEV_FORMAT "ipsec%" PRIu32

/* for ipsec0 we need to map it to a different if_id */
#define PLUTO_XFRMI_REMAP_IF_ID_ZERO	16384

/* And IPv6 str can be 8 4-character groups, separated by a colon (7 max).
 * Also includes room for netmask "/NN" and newline */
#define MAX_IP_CIDR_STR_LEN 44

#define XFRMI_SUCCESS 0
#define XFRMI_FAILURE 1

struct connection;
struct logger;

/* The same interface IP can be used by multiple tunnels, with different remote
 * IPs, so they are ref-counted to control removing the IP from the IF. */
struct pluto_xfrmi_ipaddr {
	ip_cidr if_ip;
	char if_ip_str[MAX_IP_CIDR_STR_LEN];
	refcnt_t refcnt;
	bool pluto_added;
	struct pluto_xfrmi_ipaddr *next;
};

struct pluto_xfrmi {
	char *name;
	uint32_t if_id; /* IFLA_XFRM_IF_ID */
	uint32_t dev_if_id;  /* if_id of device, IFLA_XFRM_LINK */
	struct pluto_xfrmi_ipaddr *if_ips; /* ref-counted IPs on this IF */
	refcnt_t refcnt;
	bool shared;
	bool pluto_added;
	struct pluto_xfrmi *next;
};

/* Both setup_xfrm_interface() and add_xfrm_interface() return true on success, false otherwise */
extern bool setup_xfrm_interface(struct connection *c, uint32_t xfrm_if_id);
extern bool add_xfrm_interface(struct connection *c, struct logger *logger);
extern void stale_xfrmi_interfaces(struct logger *logger);
extern err_t xfrm_iface_supported(struct logger *logger);
extern void free_xfrmi_ipsec1(struct logger *logger);
extern void unreference_xfrmi(struct connection *c);
extern void reference_xfrmi(struct connection *c);

void set_ike_mark_out(const struct connection *c, ip_endpoint *ike_remote);

#endif
