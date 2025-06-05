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
#include "shunk.h"

struct fd;
struct kernel_iface;
struct iface_endpoint;
struct show;
struct iface_device;
struct logger;
struct config_setup;

extern unsigned pluto_ike_socket_bufsize; /* pluto IKE socket buffer */
extern bool pluto_ike_socket_errqueue; /* Enable MSG_ERRQUEUE on IKE socket */

extern const char *pluto_listen;	/* from --listen flag */
extern bool pluto_listen_udp;
extern bool pluto_listen_tcp;

struct iface_packet {
	ssize_t len;
	ip_endpoint sender;
	uint8_t *ptr;
	struct logger *logger; /*global*/
};

struct iface_io {
	bool send_keepalive;
	struct {
		int type;
		const char *type_name;
	} socket;
	const struct ip_protocol *protocol;
	struct msg_digest *(*read_packet)(struct iface_endpoint **ifp,
					  struct logger *logger);
	ssize_t (*write_packet)(const struct iface_endpoint *ifp,
				shunk_t packet,
				const ip_endpoint *remote_endpoint,
				struct logger *logger);
	void (*cleanup)(struct iface_endpoint *ifp);
	void (*listen)(struct iface_endpoint *fip, struct logger *logger);
	/* returns 0 or ERRNO */
	int (*enable_esp_encapsulation)(int fd, struct logger *logger);
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

struct iface_device {
	struct list_entry entry;
	refcnt_t refcnt;
	char *real_device_name;
	bool nic_offload;
	ip_address local_address;
	enum { IFD_ADD, IFD_KEEP, IFD_DELETE } ifd_change;
};

struct iface_device *next_iface_device(struct iface_device *);

struct iface_device *find_iface_device_by_address(const ip_address *address);

struct iface_device *iface_device_addref_where(struct iface_device *ifp, where_t where);
#define iface_addref(IFP) iface_device_addref_where(IFP, HERE)

void iface_device_delref_where(struct iface_device **ifp, where_t where);
#define iface_device_delref(IFP) iface_device_delref_where(IFP, HERE)

struct iface_endpoint {
	refcnt_t refcnt;
	struct iface_device *ip_dev;
	const struct iface_io *io;
	ip_endpoint local_endpoint;	/* interface IP address:port */
	int fd;                 /* file descriptor of socket for IKE UDP messages */
	struct iface_endpoint *next;
	struct list_entry entry;
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
	struct {
		struct fd_read_listener *read_listener;
	} udp;
	struct {
		/* tcp port only */
		struct fd_accept_listener *accept_listener;
		/* tcp stream only */
		struct timeout *prefix_timeout;
		struct fd_read_listener *read_listener;
	} iketcp;
	ip_endpoint iketcp_remote_endpoint;
	bool iketcp_server;
	enum iketcp_state {
		IKETCP_ACCEPTED = 1,
		IKETCP_PREFIX_RECEIVED, /* received IKETCP */
		IKETCP_ENABLED, /* received at least one packet */
		IKETCP_STOPPED, /* waiting on state to close */
	} iketcp_state;
};

void stop_iketcp_iface_endpoint(struct iface_endpoint **ifp);

struct iface_endpoint *iface_endpoint_addref_where(struct iface_endpoint *ifp, where_t where);
#define iface_endpoint_addref(IFP) iface_endpoint_addref_where(IFP, HERE)

void iface_endpoint_delref_where(struct iface_endpoint **ifp, where_t where);
#define iface_endpoint_delref(IFP) iface_endpoint_delref_where(IFP, HERE)

extern struct iface_endpoint *find_iface_endpoint_by_local_endpoint(ip_endpoint local_endpoint);
extern void find_ifaces(bool rm_dead, struct logger *logger);
extern void show_ifaces_status(struct show *s);
void listen_on_iface_endpoint(struct iface_endpoint *ifp, struct logger *logger);

enum iface_esp_encapsulation {
	ESP_ENCAPSULATION_ENABLED = 1,
	ESP_ENCAPSULATION_DISABLED,
};

enum iface_initiator_port {
	INITIATOR_PORT_FIXED = 1,
	INITIATOR_PORT_FLOATS,
};

struct iface_endpoint *bind_iface_endpoint(struct iface_device *ifd,
					   const struct iface_io *io,
					   ip_port port,
					   enum iface_esp_encapsulation esp_encapsulation,
					   enum iface_initiator_port initiator_port,
					   struct logger *logger);

/* internal */
struct iface_endpoint *alloc_iface_endpoint(int fd,
					    struct iface_device *ifd,
					    const struct iface_io *io,
					    enum iface_esp_encapsulation esp_encapsulation,
					    enum iface_initiator_port initiator_port,
					    ip_endpoint local_endpoint,
					    where_t where);


void init_ifaces(const struct config_setup *oco, struct logger *logger);
void shutdown_ifaces(struct logger *logger);

#endif
