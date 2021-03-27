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


#include "ip_endpoint.h"
#include "refcnt.h"
#include "list_entry.h"

struct fd;
struct raw_iface;
struct iface_endpoint;
struct show;
struct iface_dev;
struct logger;

struct iface_packet {
	ssize_t len;
	ip_endpoint sender;
	uint8_t *ptr;
	struct logger *logger; /*global*/
};

enum iface_read_status {
	IFACE_READ_OK = 0,
	IFACE_READ_IGNORE, /* aka EAGAIN */
	IFACE_READ_ABORT, /* on return, delete iface! */
	/* place holders, same as ignore for now */
	IFACE_READ_ERROR,
	IFACE_READ_EOF,
};

struct iface_io {
	bool send_keepalive;
	const struct ip_protocol *protocol;
	enum iface_read_status (*read_packet)(struct iface_endpoint *ifp,
					      struct iface_packet *,
					      struct logger *logger);
	ssize_t (*write_packet)(const struct iface_endpoint *ifp,
				const void *ptr, size_t len,
				const ip_endpoint *remote_endpoint,
				struct logger *logger);
	void (*cleanup)(struct iface_endpoint *ifp);
	void (*listen)(struct iface_endpoint *fip, struct logger *logger);
	int (*bind_iface_endpoint)(struct iface_dev *ifd,
				   ip_port port, bool esp_encapsulation_enabled,
				   struct logger *logger);
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
 * The iface is a unique IP address on a system. It may be used by
 * multiple port numbers. In general, two conns have the same
 * interface if they have the same iface_endpoint->iface_alias.
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
void add_or_keep_iface_dev(struct raw_iface *ifp, struct logger *logger);
struct iface_dev *find_iface_dev_by_address(const ip_address *address);

struct iface_endpoint {
	struct iface_dev   *ip_dev;
	const struct iface_io *io;
	ip_endpoint local_endpoint;	/* interface IP address:port */
	int fd;                 /* file descriptor of socket for IKE UDP messages */
	struct iface_endpoint *next;
	const struct ip_protocol *protocol;
	/*
	 * Here's what the RFC has to say:
	 *
	 * 2.  IKE Protocol Details and Variations
	 *
	 *     The UDP payload of all packets containing IKE messages
	 *     sent on port 4500 MUST begin with the prefix of four
	 *     zeros; otherwise, the receiver won't know how to handle
	 *     them.
	 *
	 * 2.23.  NAT Traversal
	 *
	 *     ... UDP encapsulation MUST NOT be done on port 500.
	 *
	 * 3.1.  The IKE Header
	 *
	 *     When sent on UDP port 500, IKE messages begin
	 *     immediately following the UDP header.  When sent on UDP
	 *     port 4500, IKE messages have prepended four octets of
	 *     zeros.
	 *
	 * I'm assuming that "sent on port ..." is intended to mean
	 * "sent from port ... to port ...".  But now we've got us
	 * deliberately sending from a random port to ...
	 *
	 * to port 500 with no ESP=0:
	 * -> since esp encal is disabled, the kernel passes the packet through
	 * -> pluto responds with no ESP=0
	 *
	 * to port 500 with ESP=0:
	 * -> since esp encal is disabled, the kernel passes the packet through
	 * -> pluto sees the ESP=0 prefix and rejects it
	 *
	 * to port 4500 with no ESP=0:
	 * -> since esp encap is enabled, the kernel will see the leading bytes
	 * are non-zero and eats an ESP packet
	 *
	 * to port 4500 with ESP=0:
	 * -> since esp encap is enabled, and ESP=0, kernel passes the packet through
	 * -> pluto sees ESP=0 prefix
	 * -> pluto responds with ESP=0 prefix
	 *
	 * to a random port:
	 * - to be able to work with NAT esp encap needs to be enabled and that
	 * in turn means all incoming messages must have the ESP=0 prefix
	 * - trying to negotiate to port 500 will fail - the incoming message
	 * will be missing the ESP=0 prefix
	 */
	bool esp_encapsulation_enabled;
	/*
	 * For IKEv2 2.23.  NAT Traversal.  When NAT is detected, must
	 * the initiators float away, switching to port 4500?  This
	 * doesn't make sense for TCP, and this doesn't make sense
	 * when using IKEPORT.
	 */
	bool float_nat_initiator;
	/* udp only */
	struct event *udp_message_listener;
	/* tcp port only */
	struct evconnlistener *tcp_accept_listener;
	/* tcp stream only */
	struct event *iketcp_message_listener;
	ip_endpoint iketcp_remote_endpoint;
	bool iketcp_server;
	enum iketcp_state {
		IKETCP_ACCEPTED = 1,
		IKETCP_PREFIX_RECEIVED, /* received IKETCP */
		IKETCP_ENABLED, /* received at least one packet */
		IKETCP_STOPPED, /* waiting on state to close */
	} iketcp_state;
	struct event *iketcp_timeout;
};

void stop_iketcp_iface_endpoint(struct iface_endpoint **ifp);
void free_any_iface_endpoint(struct iface_endpoint **ifp);

extern struct iface_endpoint *interfaces;   /* public interfaces */

extern struct iface_endpoint *find_iface_endpoint_by_local_endpoint(ip_endpoint local_endpoint);
extern bool use_interface(const char *rifn);
extern void find_ifaces(bool rm_dead, struct logger *logger);
extern void show_ifaces_status(struct show *s);
extern void free_ifaces(struct logger *logger);
void listen_on_iface_endpoint(struct iface_endpoint *ifp, struct logger *logger);
struct iface_endpoint *bind_iface_endpoint(struct iface_dev *ifd, const struct iface_io *io,
					   ip_port port,
					   bool esp_encapsulation_enabled,
					   bool float_nat_initiator,
					   struct logger *logger);

#endif
