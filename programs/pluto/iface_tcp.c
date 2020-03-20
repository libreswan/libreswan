/* tcp packet processing, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002, 2013,2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 D. Hugh Redelmeier <hugh@mimosa.com>
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
 *
 */

#include <sys/types.h>
#include <netinet/udp.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <netinet/tcp.h>	/* for TCP_ULP (hopefully) */
#ifndef TCP_ULP
#define TCP_ULP 31
#endif

#include "ip_address.h"

#include "defs.h"
#include "kernel.h"
#include "iface_tcp.h"
#include "server.h"		/* for pluto_sock_bufsize */
#include "iface.h"
#include "demux.h"
#include "state_db.h"		/* for state_by_ike_spis() */
#include "log.h"
#include "ip_info.h"
#include "nat_traversal.h"	/* for nat_traversal_enabled which seems like a broken idea */

static const struct iface_io tcp_iface_io;

static void handle_tcp_packet_cb(evutil_socket_t unused_fd UNUSED,
				 const short unused_event UNUSED,
				 void *arg)
{
	struct iface_port *ifp = arg;
	if (ifp->tcp_espintcp_enabled) {
		handle_packet_cb(ifp);
		return;
	}

	dbg("TCP: reading IKETCP prefix");
	const uint8_t iketcp[] = IKE_IN_TCP_PREFIX;
	uint8_t buf[sizeof(iketcp)];
	ssize_t len = read(ifp->fd, buf, sizeof(buf));
	if (len != sizeof(buf)) {
		libreswan_log("TCP: problem reading IKETCP prefix - returned %zd bytes but expecting %zu",
			      len, sizeof(buf));
		close(ifp->fd);
		return;
	}

	dbg("TCP: verifying IKETCP prefix");
	if (!memeq(buf, iketcp, len)) {
		/* discard this tcp connection */
		libreswan_log("TCP: did not receive the IKE-in-TCP stream prefix, closing socket");
		close(ifp->fd);
		return;
	}

	libreswan_log("TCP: accepting connection, stream prefix received");

	/*
	 * Tell the kernel to load up the ESPINTCP Upper Layer
	 * Protocol.
	 *
	 * From this point on all writes are auto-wrapped in their
	 * length and reads are auto-blocked.
	 */
	dbg("TCP: enabling ESPINTCP");
	if (setsockopt(ifp->fd, IPPROTO_TCP, TCP_ULP,
		       "espintcp", sizeof("espintcp"))) {
		LOG_ERRNO(errno, "setsockopt(SOL_TCP, TCP_ULP) failed in netlink_espintcp(), closing socket");
		close(ifp->fd);
		return;
	}

	/*
	 * TCP: Should hack the callback to the non-IKETCP version,
	 * but this is easier - it seems changing the event handler
	 * while in the event handler isn't allowed.
	 */
	ifp->tcp_espintcp_enabled = true;
}

/*
 * Open a TCP socket connected to st_remote_endpoint.  Since this end
 * opend the socket, this end sends the IKE-in-TCP magic word.
 */

stf_status create_tcp_interface(struct state *st)
{
	dbg("TCP: opening socket");
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		LOG_ERRNO(errno, "TCP: socket() failed");
		return STF_FATAL;
	}

	/*
	 * Connect
	 *
	 * TCP: THIS LOOKS LIKE A BLOCKING CALL
	 *
	 * TCP: Assume st_remote_endpoint is the intended remote?
	 * Should this instead look in the connection?
	 */

	dbg("TCP: connecting");
	{
		ip_sockaddr remote_sockaddr;
		size_t remote_sockaddr_size = endpoint_to_sockaddr(&st->st_remote_endpoint, &remote_sockaddr);
		if (connect(fd, &remote_sockaddr.sa, remote_sockaddr_size) < 0) {
			LOG_ERRNO(errno, "TCP: connect() failed");
			close(fd);
			return STF_FATAL;
		}
	}

	dbg("TCP: getting local randomly assigned port");
	ip_endpoint local_endpoint;
	{
		ip_sockaddr local_sockaddr; /* port gets assigned randomly */
		socklen_t local_sockaddr_size = sizeof(local_sockaddr);
		if (getsockname(fd, &local_sockaddr.sa, &local_sockaddr_size) < 0) {
			LOG_ERRNO(errno, "TCP: failed to get local TCP address");
			close(fd);
			return STF_FATAL;
		}
		err_t err = sockaddr_to_endpoint(&local_sockaddr, local_sockaddr_size,
						 &local_endpoint);
		if (err != NULL) {
			libreswan_log("TCP: failed to get local TCP address, %s", err);
			close(fd);
			return STF_FATAL;
		}
	}

	dbg("TCP: making things non-blocking");
	evutil_make_socket_nonblocking(fd); /* TCP: ignore errors? */
	evutil_make_socket_closeonexec(fd); /* TCP: ignore errors? */

	/* Socket is now connected, send the IKETCP stream */

	dbg("TCP: sending IKE-in-TCP prefix");
	{
		const uint8_t iketcp[] = IKE_IN_TCP_PREFIX;
		if (write(fd, iketcp, sizeof(iketcp)) != (ssize_t)sizeof(iketcp)) {
			LOG_ERRNO(errno, "TCP: send of IKE-in-TCP prefix");
			close(fd);
			return STF_FATAL;
		}
	}

	/*
	 * Tell the kernel to load up the ESPINTCP Upper Layer
	 * Protocol.
	 *
	 * From this point on all writes are auto-wrapped in their
	 * length and reads are auto-blocked.
	 */
	if (setsockopt(fd, IPPROTO_TCP, TCP_ULP, "espintcp", sizeof("espintcp"))) {
		LOG_ERRNO(errno, "setsockopt(SOL_TCP, TCP_ULP) failed in netlink_espintcp()");
		close(fd);
		return STF_FATAL;
	}

	struct iface_port *q = alloc_thing(struct iface_port, "TCP iface_port");
	q->io = &tcp_iface_io;
	q->fd = fd;
	q->local_endpoint = local_endpoint;
	q->ike_float = TRUE;
	q->ip_dev = add_ref(st->st_interface->ip_dev);
	q->protocol = &ip_protocol_tcp;
	q->tcp_remote_endpoint = st->st_remote_endpoint;
	q->tcp_espintcp_enabled = true;

	q->next = interfaces;
	interfaces = q;

	q->pev = add_fd_read_event_handler(q->fd,
					   handle_tcp_packet_cb,
					   q, "iketcpX");

	st->st_interface = q; /* TCP: leaks old st_interface? */
	return STF_OK;
}

static ssize_t write_tcp_packet(const struct iface_port *ifp,
				const void *ptr, size_t len,
				const ip_endpoint *remote_endpoint UNUSED)
{
#if 0
	dbg("TCP: switching off NONBLOCK before write");
	int flags = fcntl(ifp->fd, F_GETFL, 0);
	if (flags == -1) {
		LOG_ERRNO(errno, "TCP: fcntl(F_GETFL)");
	}
	if (fcntl(ifp->fd, F_SETFL, flags & ~O_NONBLOCK) == -1) {
		LOG_ERRNO(errno, "TCP: write - fcntl(F_GETFL)");
	}
#endif
	ssize_t wlen = write(ifp->fd, ptr, len);

#if 0
	dbg("TCP: restoring flags 0-%o after write", flags);
	if (fcntl(ifp->fd, F_SETFL, flags) == -1) {
		LOG_ERRNO(errno, "TCP: fcntl(F_GETFL)");
	}
	dbg("TCP: flags restored");
#endif
	return wlen;
}

static bool read_tcp_packet(const struct iface_port *ifp,
			    struct iface_packet *packet)
{
	/*
	 * Fudge up an MD so that it be used as log context prefix.
	 */
	struct msg_digest stack_md = {
		.iface = ifp,
		.sender = ifp->tcp_remote_endpoint,
	};

	/*
	 * Reads the entire packet _without_ length, if buffer isn't
	 * big enough packet is truncated.
	 */
	dbg("TCP: reading input");
	errno = 0;
	packet->len = read(ifp->fd, packet->ptr, packet->len);
	packet->sender = ifp->tcp_remote_endpoint;
	int packet_errno = errno;
	if (packet_errno != 0) {
		plog_md(&stack_md, "read from TCP socket failed "PRI_ERRNO,
			pri_errno(packet_errno));
		errno = packet_errno;
		return false;
	}

	dbg("TCP: read returned %zd bytes; "PRI_ERRNO"",
	    packet->len, pri_errno(packet_errno));

	if (packet->len < NON_ESP_MARKER_SIZE) {
		plog_md(&stack_md,
			"%zd byte TCP message is way to small",
			packet->len);
		return false;
	}

	static const uint8_t zero_esp_marker[NON_ESP_MARKER_SIZE] = { 0, };
	if (!memeq(packet->ptr, zero_esp_marker, sizeof(zero_esp_marker))) {
		plog_md(&stack_md,
			"%zd byte TCP message missing $d byte zero ESP marker",
			packet->len);
		return false;
	}

	packet->len -= sizeof(zero_esp_marker);
	packet->ptr += sizeof(zero_esp_marker);
	return true;
}

static const struct iface_io tcp_iface_io = {
	.protocol = &ip_protocol_tcp,
	.read_packet = read_tcp_packet,
	.write_packet = write_tcp_packet,
};

void accept_ike_in_tcp_cb(struct evconnlistener *evcon UNUSED,
			  int fd,
			  struct sockaddr *sockaddr, int sockaddr_len,
			  void *arg)
{
	struct iface_port *socket_ifp = arg;

	ip_sockaddr sa = { .sa = *sockaddr, };
	ip_endpoint tcp_remote_endpoint;
	err_t err = sockaddr_to_endpoint(&sa, sockaddr_len, &tcp_remote_endpoint);
	if (err) {
		libreswan_log("TCP: invalid remote address: %s", err);
		close(fd);
		return;
	}

	struct iface_port *ifp = alloc_thing(struct iface_port, "struct iface_port");
	ifp->fd = fd;
	ifp->io = &tcp_iface_io;
	ifp->protocol = &ip_protocol_tcp;
	ifp->ike_float = TRUE;
	ifp->ip_dev = add_ref(socket_ifp->ip_dev); /*TCP: refcnt */
	ifp->tcp_remote_endpoint = tcp_remote_endpoint;
	ifp->local_endpoint = socket_ifp->local_endpoint;

	ifp->pev = add_fd_read_event_handler(ifp->fd,
					     handle_tcp_packet_cb,
					     ifp, "iketcpX");
}

static int create_tcp_socket(const struct iface_dev *ifd, int port)
{
	const struct ip_info *type = address_type(&ifd->id_address);
	int fd = socket(type->af, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		LOG_ERRNO(errno, "socket() in %s()", __func__);
		return -1;
	}

	int fcntl_flags;
	static const int on = TRUE;     /* by-reference parameter; constant, we hope */

	/* Set socket Nonblocking */
	if ((fcntl_flags = fcntl(fd, F_GETFL)) >= 0) {
		if (!(fcntl_flags & O_NONBLOCK)) {
			fcntl_flags |= O_NONBLOCK;
			if (fcntl(fd, F_SETFL, fcntl_flags) == -1) {
				LOG_ERRNO(errno, "fcntl(,, O_NONBLOCK) in create_socket()");
			}
		}
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		LOG_ERRNO(errno, "fcntl(,, FD_CLOEXEC) in create_socket()");
		close(fd);
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		       (const void *)&on, sizeof(on)) < 0) {
		LOG_ERRNO(errno, "setsockopt SO_REUSEADDR in create_socket()");
		close(fd);
		return -1;
	}

#ifdef SO_PRIORITY
	static const int so_prio = 6; /* rumored maximum priority, might be 7 on linux? */
	if (setsockopt(fd, SOL_SOCKET, SO_PRIORITY,
			(const void *)&so_prio, sizeof(so_prio)) < 0) {
		LOG_ERRNO(errno, "setsockopt(SO_PRIORITY) in find_raw_ifaces4()");
		/* non-fatal */
	}
#endif

	if (pluto_sock_bufsize != IKE_BUF_AUTO) {
#if defined(linux)
		/*
		 * Override system maximum
		 * Requires CAP_NET_ADMIN
		 */
		int so_rcv = SO_RCVBUFFORCE;
		int so_snd = SO_SNDBUFFORCE;
#else
		int so_rcv = SO_RCVBUF;
		int so_snd = SO_SNDBUF;
#endif
		if (setsockopt(fd, SOL_SOCKET, so_rcv,
			(const void *)&pluto_sock_bufsize, sizeof(pluto_sock_bufsize)) < 0) {
				LOG_ERRNO(errno, "setsockopt(SO_RCVBUFFORCE) in find_raw_ifaces4()");
		}
		if (setsockopt(fd, SOL_SOCKET, so_snd,
			(const void *)&pluto_sock_bufsize, sizeof(pluto_sock_bufsize)) < 0) {
				LOG_ERRNO(errno, "setsockopt(SO_SNDBUFFORCE) in find_raw_ifaces4()");
		}
	}



	/* To improve error reporting.  See ip(7). */
#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
	if (pluto_sock_errqueue) {
		if (setsockopt(fd, SOL_IP, IP_RECVERR, (const void *)&on, sizeof(on)) < 0) {
			LOG_ERRNO(errno, "setsockopt IP_RECVERR in create_socket()");
			close(fd);
			return -1;
		}
	}
#endif

	/* With IPv6, there is no fragmentation after
	 * it leaves our interface.  PMTU discovery
	 * is mandatory but doesn't work well with IKE (why?).
	 * So we must set the IPV6_USE_MIN_MTU option.
	 * See draft-ietf-ipngwg-rfc2292bis-01.txt 11.1
	 */
#ifdef IPV6_USE_MIN_MTU /* YUCK: not always defined */
	if (addrtypeof(&ifp->addr) == AF_INET6 &&
	    setsockopt(fd, SOL_SOCKET, IPV6_USE_MIN_MTU,
		       (const void *)&on, sizeof(on)) < 0) {
		LOG_ERRNO(errno, "setsockopt IPV6_USE_MIN_MTU in process_raw_ifaces()");
		close(fd);
		return -1;
	}
#endif

	/*
	 * NETKEY requires us to poke an IPsec policy hole that allows
	 * IKE packets, unlike KLIPS which implicitly always allows
	 * plaintext IKE.  This installs one IPsec policy per socket
	 * but this function is called for each: IPv4 port 500 and
	 * 4500 IPv6 port 500
	 */
	if (kernel_ops->poke_ipsec_policy_hole != NULL &&
	    !kernel_ops->poke_ipsec_policy_hole(ifd, fd)) {
		close(fd);
		return -1;
	}

	/*
	 * ??? does anyone care about the value of port of ifp->addr?
	 * Old code seemed to assume that it should be reset to pluto_port.
	 * But only on successful bind.  Seems wrong or unnecessary.
	 */
	ip_endpoint if_endpoint = endpoint(&ifd->id_address, port);
	ip_sockaddr if_sa;
	size_t if_sa_size = endpoint_to_sockaddr(&if_endpoint, &if_sa);
	if (bind(fd, &if_sa.sa, if_sa_size) < 0) {
		endpoint_buf b;
		LOG_ERRNO(errno, "bind() for %s %s in process_raw_ifaces()",
			  ifd->id_rname,
			  str_endpoint(&if_endpoint, &b));
		close(fd);
		return -1;
	}

#if defined(HAVE_UDPFROMTO)
	/* we are going to use udpfromto.c, so initialize it */
	if (udpfromto_init(fd) == -1) {
		LOG_ERRNO(errno, "udpfromto_init() returned an error - ignored");
	}
#endif

	/* poke a hole for IKE messages in the IPsec layer */
	if (kernel_ops->exceptsocket != NULL) {
		if (!kernel_ops->exceptsocket(fd, AF_INET)) {
			close(fd);
			return -1;
		}
	}

	return fd;
}

struct iface_port *tcp_iface_port(struct iface_dev *ifd, int port)
{
	int fd = create_tcp_socket(ifd, port);
	if (fd < 0) {
		return NULL;
	}

	struct iface_port *q = alloc_thing(struct iface_port,
					   "struct iface_port");
	q->ip_dev = add_ref(ifd);

	q->local_endpoint = endpoint(&ifd->id_address, port);
	q->fd = fd;
	q->protocol = &ip_protocol_tcp;
	q->next = interfaces;
	q->ike_float = TRUE;
	interfaces = q;
	return q;
}
