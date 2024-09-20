/* ipsec-interface= structures, for libreswan
 *
 * Copyright (C) 2018-2020 Antony Antony <antony@phenome.org>
 * Copyright (C) 2023 Brady Johnson <bradyallenjohnson@gmail.com>
 * Copyright (C) Andrew Cagney
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

#ifndef IPSEC_INTERFACE_H
#define IPSEC_INTERFACE_H

#include <net/if.h>		/* for IFNAMSIZ */
#include <stdbool.h>

#include "err.h"
#include "ip_cidr.h"
#include "refcnt.h"
#include "ip_endpoint.h"

struct connection;
struct logger;
struct ipsec_interface;	/* forward */

/*
 * The same interface IP can be used by multiple tunnels, with
 * different remote IPs, so they are ref-counted to control removing
 * the IP from the IF.
 */

struct ipsec_interface_address {
	refcnt_t refcnt;
	ip_cidr if_ip;
	bool pluto_added;	/* vs an address on a pre-existing
				 * interface */
	struct ipsec_interface_address *next;
};

struct ipsec_interface_address *alloc_ipsec_interface_address(struct ipsec_interface_address **ptr,
							      ip_cidr if_ip);
void free_ipsec_interface_address_list(struct ipsec_interface_address *ipsec_ifaddr,
				       const struct logger *logger);

struct ipsec_interface {
	refcnt_t refcnt;
	char *name;		/* ipsec<ipsec-interface> */
	uint32_t if_id;		/* <ipsec-interface> but with 0
				 * re-mapped on linux; derived from
				 * IFLA_XFRM_IF_ID */
	uint32_t dev_if_id;	/* on linux, the IFLA_XFRM_LINK ID of
				 * the real device that the
				 * ipsec-interface IF_ID pseudo device
				 * is bound to (on BSD this binding is
				 * done using addresses?) */
	struct ipsec_interface_address *if_ips;
				/* ref-counted IPs on this IF;
				 * ref-counted as multiple connections
				 * may share the same value; this
				 * seems a little weird */
	bool pluto_added;	/* vs a pre-existing interface */
	struct ipsec_interface *next;
};

/* Both add_ipsec_interface() return true on success, false otherwise */

diag_t add_connection_ipsec_interface(struct connection *c, const char *ipsec_interface);
struct ipsec_interface *ipsec_interface_addref(struct ipsec_interface *ipsec_if,
					       struct logger *logger, where_t where);
void ipsec_interface_delref(struct ipsec_interface **ipsec_if,
			    struct logger *logger,
			    where_t where);

/* add/remove the system's interface device and address */
bool add_kernel_ipsec_interface(const struct connection *c, struct logger *logger);
void remove_kernel_ipsec_interface(const struct connection *c, struct logger *logger);

void shutdown_kernel_ipsec_interface(struct logger *logger);
void check_stale_ipsec_interfaces(struct logger *logger);

/* utilities; may at some point be made static */
typedef struct {
	char buf[IFNAMSIZ+1/*NULL*/+1/*CANARY*/];
} ipsec_interface_id_buf;

size_t jam_ipsec_interface_id(struct jambuf *buf, uint32_t if_id);
char *str_ipsec_interface_id(uint32_t if_id, ipsec_interface_id_buf *buf);

#endif
