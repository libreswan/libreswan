/* iface, for libreswan
 *
 * Copyright (C) 1998-2001,2013  D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2019 Andrew Cagney
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

#ifndef IFACE_H
#define IFACE_H

#include <sys/queue.h>

#include "ip_endpoint.h"
#include "refcnt.h"

struct fd;
struct raw_iface;

/* interface: a terminal point for IKE traffic, IPsec transport mode
 * and IPsec tunnels.
 * Essentially:
 * - an IP device (eg. eth1), and
 * - its partner, an ipsec device (eg. ipsec0), and
 * - their shared IP address (eg. 10.7.3.2)
 * Note: the port for IKE is always implicitly UDP/pluto_port.
 *
 * The iface is a unique IP address on a system. It may be used
 * by multiple port numbers. In general, two conns have the same
 * interface if they have the same iface_port->iface_alias.
 */

struct iface_dev {
	LIST_ENTRY(iface_dev) id_entry;
	refcnt_t refcnt;
	char *id_rname; /* real device name */
	bool id_nic_offload;
};

struct iface_dev *create_iface_dev(const struct raw_iface *ifp);

struct iface_port {
	struct iface_dev   *ip_dev;
	ip_endpoint local_endpoint;	/* interface IP address:port */
	int fd;                 /* file descriptor of socket for IKE UDP messages */
	struct iface_port *next;
	bool ike_float;
	enum { IFN_ADD, IFN_KEEP, IFN_DELETE } change;
	struct pluto_event *pev;
};

extern struct iface_port *interfaces;   /* public interfaces */

extern struct iface_port *find_iface_port_by_local_endpoint(ip_endpoint *local_endpoint);
extern bool use_interface(const char *rifn);
extern void find_ifaces(bool rm_dead);
extern void show_ifaces_status(const struct fd *whackfd);
extern void free_ifaces(void);

#endif
