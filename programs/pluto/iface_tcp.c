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
#include "ip_sockaddr.h"

#include "defs.h"
#include "kernel.h"
#include "server.h"		/* for pluto_sock_bufsize */
#include "iface.h"
#include "demux.h"
#include "state_db.h"		/* for state_by_ike_spis() */
#include "log.h"
#include "ip_info.h"
#include "nat_traversal.h"	/* for nat_traversal_enabled which seems like a broken idea */
#include "pluto_stats.h"

static void accept_ike_in_tcp_cb(struct evconnlistener *evcon UNUSED,
				 int accepted_fd,
				 struct sockaddr *sockaddr, int sockaddr_len,
				 void *arg);

static enum iface_status iketcp_read_packet(const struct iface_port *ifp,
					    struct iface_packet *packet)
{
	/*
	 * At this point there's no logger so log it against the
	 * remote endpoint determined earlier.
	 */
	struct logger logger = FROM_LOGGER(&ifp->iketcp_remote_endpoint);

	/*
	 * Reads the entire packet _without_ length, if buffer isn't
	 * big enough packet is truncated.
	 */
	dbg("TCP: reading packet");
	packet->sender = ifp->iketcp_remote_endpoint;
	size_t buf_size = packet->len;
	errno = 0;
	packet->len = read(ifp->fd, packet->ptr, buf_size);
	int packet_errno = errno;
	if (packet_errno != 0) {
		log_message(RC_LOG, &logger,
			    "TCP: read from socket failed "PRI_ERRNO,
			    pri_errno(packet_errno));
		if (packet_errno == EAGAIN) {
			return IFACE_IGNORE;
		} else {
			return IFACE_FATAL;
		}
	}

	dbg("TCP: read %zd of %zu bytes; "PRI_ERRNO"",
	    packet->len, buf_size, pri_errno(packet_errno));

	if (packet->len == 0) {
		/* interpret this as EOF */
		log_message(RC_LOG, &logger,
			    "TCP: %zd byte message flags EOF",
			    packet->len);
		return IFACE_EOF;
	}

	if (packet->len < NON_ESP_MARKER_SIZE) {
		log_message(RC_LOG, &logger,
			    "TCP: %zd byte message is way to small",
			    packet->len);
		return IFACE_FATAL;
	}

	static const uint8_t zero_esp_marker[NON_ESP_MARKER_SIZE] = { 0, };
	if (!memeq(packet->ptr, zero_esp_marker, sizeof(zero_esp_marker))) {
		log_message(RC_LOG, &logger,
			    "TCP: %zd byte message missing %d byte zero ESP marker",
			    packet->len, NON_ESP_MARKER_SIZE);
		return IFACE_FATAL;
	}

	packet->len -= sizeof(zero_esp_marker);
	packet->ptr += sizeof(zero_esp_marker);
	return IFACE_OK;
}

static ssize_t iketcp_write_packet(const struct iface_port *ifp,
				   const void *ptr, size_t len,
				   const ip_endpoint *remote_endpoint UNUSED)
{
	int flags = 0;
	if (impair.tcp_use_blocking_write) {
		libreswan_log("IMPAIR: TCP: switching off NONBLOCK before write");
		flags = fcntl(ifp->fd, F_GETFL, 0);
		if (flags == -1) {
			LOG_ERRNO(errno, "TCP: fcntl(F_GETFL)");
		}
		if (fcntl(ifp->fd, F_SETFL, flags & ~O_NONBLOCK) == -1) {
			LOG_ERRNO(errno, "TCP: write - fcntl(F_GETFL)");
		}
	}
	ssize_t wlen = write(ifp->fd, ptr, len);
	dbg("TCP: wrote %zd of %zu bytes", wlen, len);
	if (impair.tcp_use_blocking_write && flags >= 0) {
		libreswan_log("IMPAIR: TCP: restoring flags 0%o after write", flags);
		if (fcntl(ifp->fd, F_SETFL, flags) == -1) {
			LOG_ERRNO(errno, "TCP: fcntl(F_GETFL)");
		}
	}
	return wlen;
}

static void iketcp_cleanup(struct iface_port *ifp)
{
	dbg("TCP: cleaning up interface");
	switch (ifp->iketcp_state) {
	case IKETCP_RUNNING:
		pstats_iketcp_stopped[ifp->iketcp_server]++;
		break;
	default:
		pstats_iketcp_aborted[ifp->iketcp_server]++;
		break;
	}
	pexpect(ifp->pev == NULL);
	pexpect(ifp->fd < 0);
	pexpect(ifp->ip_dev == NULL);
	free_any_fd_accept_event_handler(&ifp->tcp_accept_listener);
	if (ifp->iketcp_timeout != NULL) {
		dbg("TCP: cleaning up timeout");
		event_del(ifp->iketcp_timeout);
		event_free(ifp->iketcp_timeout);
		ifp->iketcp_timeout = NULL;
	}
}

static void iketcp_server_timeout(evutil_socket_t unused_fd UNUSED,
				  const short unused_event UNUSED,
				  void *arg UNUSED)
{
	struct iface_port *ifp = arg;
	struct logger logger = FROM_LOGGER(&ifp->iketcp_remote_endpoint);
	log_message(RC_LOG, &logger,
		    "TCP: timed out before first message received");
	free_any_iface_port(&ifp);
}

static void iketcp_listen(struct iface_port *ifp,
			  struct logger *logger)
{
	if (ifp->tcp_accept_listener == NULL) {
		ifp->tcp_accept_listener = add_fd_accept_event_handler(ifp, accept_ike_in_tcp_cb);
		if (ifp->tcp_accept_listener == NULL) {
			log_message(RC_LOG, logger,
				    "TCP: failed to create IKE-in-TCP listener");
		}
	}
}

static int bind_tcp_socket(const struct iface_dev *ifd, ip_port port)
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
	if (setsockopt(fd, SOL_SOCKET, SO_PRIORITY, (const void *)&so_prio,
		       sizeof(so_prio)) < 0) {
		LOG_ERRNO(errno, "setsockopt(SO_PRIORITY) in %s()", __func__);
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
		if (setsockopt(fd, SOL_SOCKET, so_rcv, (const void *)&pluto_sock_bufsize,
			       sizeof(pluto_sock_bufsize)) < 0) {
			LOG_ERRNO(errno, "setsockopt(SO_RCVBUFFORCE) in %s()", __func__);
		}
		if (setsockopt(fd, SOL_SOCKET, so_snd, (const void *)&pluto_sock_bufsize,
			       sizeof(pluto_sock_bufsize)) < 0) {
			LOG_ERRNO(errno, "setsockopt(SO_SNDBUFFORCE) in %s()", __func__);
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
	if (addrtypeof(&ifd->id_address) == AF_INET6 &&
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
	ip_endpoint if_endpoint = endpoint3(&ip_protocol_tcp,
					    &ifd->id_address, port);
	ip_sockaddr if_sa = sockaddr_from_endpoint(&if_endpoint);
	if (bind(fd, &if_sa.sa.sa, if_sa.len) < 0) {
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

static int iketcp_bind_iface_port(struct iface_dev *ifd, ip_port port,
						 bool unused_esp_encapsulation_enabled UNUSED)
{
	return bind_tcp_socket(ifd, port);
}

const struct iface_io iketcp_iface_io = {
	.protocol = &ip_protocol_tcp,
	.read_packet = iketcp_read_packet,
	.write_packet = iketcp_write_packet,
	.cleanup = iketcp_cleanup,
	.listen = iketcp_listen,
	.bind_iface_port = iketcp_bind_iface_port,
};

static void iketcp_handle_packet_cb(evutil_socket_t unused_fd UNUSED,
				    const short unused_event UNUSED,
				    void *arg)
{
	struct iface_port *ifp = arg;
	struct logger logger = FROM_LOGGER(&ifp->iketcp_remote_endpoint);

	switch (ifp->iketcp_state) {

	case IKETCP_OPEN:
		dbg("TCP: OPEN: reading IKETCP prefix");
		const uint8_t iketcp[] = IKE_IN_TCP_PREFIX;
		uint8_t buf[sizeof(iketcp)];
		ssize_t len = read(ifp->fd, buf, sizeof(buf));
		if (len < 0) {
			/* too strict? */
			int e = errno;
			log_message(RC_LOG, &logger,
				    "TCP: problem reading IKETCP prefix "PRI_ERRNO,
				    pri_errno(e));
			free_any_iface_port(&ifp);
			return;
		} else if (len != sizeof(buf)) {
			log_message(RC_LOG, &logger,
				    "TCP: problem reading IKETCP prefix - returned %zd bytes but expecting %zu; connection closed",
				    len, sizeof(buf));
			free_any_iface_port(&ifp);
			return;
		}

		dbg("TCP: verifying IKETCP prefix");
		if (!memeq(buf, iketcp, len)) {
			/* discard this tcp connection */
			log_message(RC_LOG, &logger,
				    "TCP: did not receive the IKE-in-TCP stream prefix, closing socket");
			free_any_iface_port(&ifp);
			return;
		}

		/*
		 * Tell the kernel to load up the ESPINTCP Upper Layer
		 * Protocol.
		 *
		 * From this point on all writes are auto-wrapped in
		 * their length and reads are auto-blocked.
		 */
		if (impair.tcp_skip_setsockopt_espintcp) {
			log_message(RC_LOG, &logger, "IMPAIR: TCP: skipping setsockopt(ESPINTCP)");
		} else {
			dbg("TCP: enabling ESPINTCP");
			if (setsockopt(ifp->fd, IPPROTO_TCP, TCP_ULP,
				      "espintcp", sizeof("espintcp"))) {
				int e = errno;
				log_message(RC_LOG, &logger,
					    "TCP: setsockopt(SOL_TCP, TCP_ULP, \"espintcp\") failed, closing socket "PRI_ERRNO,
					    pri_errno(e));
				free_any_iface_port(&ifp);
				return;
			}
		}

		/*
		 * TCP: Should hack the callback to the non-IKETCP
		 * version, but this is easier - it seems changing the
		 * event handler while in the event handler isn't
		 * allowed.
		 */
		ifp->iketcp_state = IKETCP_PREFIXED;
		return;

	case IKETCP_PREFIXED:
		dbg("TCP: PREFIXED: trying to read first packet");
		/* received the first packet; stop the timeout */
		switch (handle_packet_cb(ifp)) {
		case IFACE_OK:
			dbg("TCP: PREFIXED: first packet ok; switching to running and freeing timeout");
			event_del(ifp->iketcp_timeout);
			event_free(ifp->iketcp_timeout);
			ifp->iketcp_timeout = NULL;
			ifp->iketcp_state = IKETCP_RUNNING;
			break;
		case IFACE_IGNORE:
			dbg("TCP: PREFIXED: first packet ignore");
			break;
		case IFACE_EOF:
		case IFACE_FATAL:
			/* already logged */
			free_any_iface_port(&ifp);
			break;
		default:
			bad_case(0);
		}
		return;

	case IKETCP_RUNNING:
		dbg("TCP: RUNNING: trying to read a packet");
		switch (handle_packet_cb(ifp)) {
		case IFACE_OK:
			dbg("TCP: RUNNING: packet read ok");
			break;
		case IFACE_IGNORE:
			dbg("TCP: RUNNING: packet ignored (why?)");
			break;
		case IFACE_EOF:
		case IFACE_FATAL:
			/* already logged */
			free_any_iface_port(&ifp);
			break;
		default:
			bad_case(0);
		}
		return;

	default:
		bad_case(ifp->iketcp_state);
	}
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
		ip_sockaddr remote_sockaddr = sockaddr_from_endpoint(&st->st_remote_endpoint);
		if (connect(fd, &remote_sockaddr.sa.sa, remote_sockaddr.len) < 0) {
			LOG_ERRNO(errno, "TCP: connect() failed");
			close(fd);
			return STF_FATAL;
		}
	}

	dbg("TCP: getting local randomly assigned port");
	ip_endpoint local_endpoint;
	{
		/* port gets assigned randomly */
		ip_sockaddr local_sockaddr = {
			.len = sizeof(local_sockaddr.sa),
		};
		if (getsockname(fd, &local_sockaddr.sa.sa, &local_sockaddr.len) < 0) {
			LOG_ERRNO(errno, "TCP: failed to get local TCP address");
			close(fd);
			return STF_FATAL;
		}
		err_t err = sockaddr_to_endpoint(&ip_protocol_tcp, &local_sockaddr, &local_endpoint);
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

	{
		dbg("TCP: sending IKE-in-TCP prefix");
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
	if (impair.tcp_skip_setsockopt_espintcp) {
		log_state(RC_LOG, st, "IMPAIR: TCP: skipping setsockopt(espintcp)");
	} else {
		dbg("TCP: enabling \"espintcp\"");
		if (setsockopt(fd, IPPROTO_TCP, TCP_ULP, "espintcp", sizeof("espintcp"))) {
			LOG_ERRNO(errno, "setsockopt(SOL_TCP, TCP_ULP) failed in netlink_espintcp()");
			close(fd);
			return STF_FATAL;
		}
	}

	struct iface_port *q = alloc_thing(struct iface_port, "TCP iface initiator");
	q->io = &iketcp_iface_io;
	q->fd = fd;
	q->local_endpoint = local_endpoint;
	q->esp_encapsulation_enabled = true;
	q->float_nat_initiator = false;
	q->ip_dev = add_ref(st->st_interface->ip_dev);
	q->protocol = &ip_protocol_tcp;
	q->iketcp_remote_endpoint = st->st_remote_endpoint;
	q->iketcp_state = IKETCP_RUNNING;
	q->iketcp_server = false;

#if 0
	q->next = interfaces;
	interfaces = q;
#endif

	q->pev = add_fd_read_event_handler(q->fd,
					   iketcp_handle_packet_cb,
					   q, "iketcpX");

	st->st_interface = q; /* TCP: leaks old st_interface? */
	pstats_iketcp_started[q->iketcp_server]++;
	return STF_OK;
}

void accept_ike_in_tcp_cb(struct evconnlistener *evcon UNUSED,
			  int accepted_fd,
			  struct sockaddr *sockaddr, int sockaddr_len,
			  void *arg)
{
	struct iface_port *bind_ifp = arg;

	ip_sockaddr sa = {
		.len = sockaddr_len,
		.sa.sa = *sockaddr,
	};
	ip_endpoint tcp_remote_endpoint;
	err_t err = sockaddr_to_endpoint(&ip_protocol_tcp, &sa, &tcp_remote_endpoint);
	if (err) {
		libreswan_log("TCP: invalid remote address: %s", err);
		close(accepted_fd);
		return;
	}

	struct logger logger = FROM_LOGGER(&tcp_remote_endpoint);
	log_message(RC_LOG, &logger, "TCP: accepting connection");

	struct iface_port *ifp = alloc_thing(struct iface_port, "TCP iface responder");
	ifp->fd = accepted_fd;
	ifp->io = &iketcp_iface_io;
	ifp->protocol = &ip_protocol_tcp;
	ifp->esp_encapsulation_enabled = true;
	ifp->float_nat_initiator = false;
	ifp->ip_dev = add_ref(bind_ifp->ip_dev); /*TCP: refcnt */
	ifp->iketcp_remote_endpoint = tcp_remote_endpoint;
	ifp->local_endpoint = bind_ifp->local_endpoint;
	ifp->iketcp_state = IKETCP_OPEN;
	ifp->iketcp_server = true;

	/* set up a timeout to kill the socket when nothing happens */
	fire_timer_photon_torpedo(&ifp->iketcp_timeout, iketcp_server_timeout,
				  ifp, deltatime(5)); /* TCP: how much? */

	ifp->pev = add_fd_read_event_handler(ifp->fd,
					     iketcp_handle_packet_cb,
					     ifp, "iketcpX");
	pstats_iketcp_started[ifp->iketcp_server]++;
}
