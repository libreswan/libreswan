/* iface, for libreswan
 *
 * Copyright (C) 1998-2001,2013  D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2019-2020 Andrew Cagney
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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
#include "list_entry.h"

struct fd;
struct raw_iface;
struct iface_port;
struct show;
struct iface_dev;

struct iface_packet {
	ssize_t len;
	ip_endpoint sender;
	uint8_t *ptr;
};

enum iface_status {
	IFACE_OK = 0,
	IFACE_EOF,
	IFACE_FATAL,
	IFACE_IGNORE, /* aka EAGAIN */
};

struct iface_io {
	const struct ip_protocol *protocol;
	enum iface_status (*read_packet)(const struct iface_port *ifp,
					 struct iface_packet *);
	ssize_t (*write_packet)(const struct iface_port *ifp,
				const void *ptr, size_t len,
				const ip_endpoint *remote_endpoint);
	void (*cleanup)(struct iface_port *ifp);
	void (*listen)(struct iface_port *fip, struct logger *logger);
	int (*bind_iface_port)(struct iface_dev *ifd,
			       ip_port port, bool add_ike_encapsulation_prefix);
};

extern const struct iface_io udp_iface_io;
extern const struct iface_io iketcp_iface_io; /*IKETCP specific*/

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
	struct list_entry ifd_entry;
	refcnt_t refcnt;
	char *id_rname; /* real device name */
	bool id_nic_offload;
	ip_address id_address;
	enum { IFD_ADD, IFD_KEEP, IFD_DELETE } ifd_change;
};

void release_iface_dev(struct iface_dev **id);
void add_or_keep_iface_dev(struct raw_iface *ifp);
struct iface_dev *find_iface_dev_by_address(const ip_address *address);

struct iface_port {
	struct iface_dev   *ip_dev;
	const struct iface_io *io;
	ip_endpoint local_endpoint;	/* interface IP address:port */
	int fd;                 /* file descriptor of socket for IKE UDP messages */
	struct iface_port *next;
	const struct ip_protocol *protocol;
	bool add_ike_encapsulation_prefix;
	/*
	 * For IKEv2 2.23.  NAT Traversal.  When NAT is detected, must
	 * the initiators float away, switching to port 4500?  This
	 * doesn't make sense for TCP, and this doesn't make sense
	 * when using IKEPORT.
	 */
	bool float_nat_initiator;
	/* udp only */
	struct pluto_event *pev;
	/* tcp port only */
	struct evconnlistener *tcp_accept_listener;
	/* tcp stream only */
	ip_endpoint iketcp_remote_endpoint;
	bool iketcp_server;
	enum iketcp_state { IKETCP_OPEN = 1, IKETCP_PREFIXED, IKETCP_RUNNING, } iketcp_state;
	struct event *iketcp_timeout;
};

void free_any_iface_port(struct iface_port **ifp);

extern struct iface_port *interfaces;   /* public interfaces */

extern struct iface_port *find_iface_port_by_local_endpoint(ip_endpoint *local_endpoint);
extern bool use_interface(const char *rifn);
extern void find_ifaces(bool rm_dead, struct fd *whackfd);
extern void show_ifaces_status(struct show *s);
extern void free_ifaces(void);
void listen_on_iface_port(struct iface_port *ifp, struct logger *logger);
struct iface_port *bind_iface_port(struct iface_dev *ifd, const struct iface_io *io,
				   ip_port port,
				   bool add_ike_encapsulation_prefix,
				   bool float_nat_initiator);

#endif
