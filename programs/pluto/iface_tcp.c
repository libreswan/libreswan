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

#include <event2/listener.h>

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
	dbg("TCP: socket %d reading packet", ifp->fd);
	packet->sender = ifp->iketcp_remote_endpoint;
	size_t buf_size = packet->len;
	errno = 0;
	packet->len = read(ifp->fd, packet->ptr, buf_size);
	int packet_errno = errno;
	if (packet_errno != 0) {
		log_message(RC_LOG, &logger,
			    "TCP: read from socket %d failed "PRI_ERRNO,
			    ifp->fd, pri_errno(packet_errno));
		if (packet_errno == EAGAIN) {
			return IFACE_IGNORE;
		} else {
			return IFACE_FATAL;
		}
	}

	dbg("TCP: socket %d read %zd of %zu bytes; "PRI_ERRNO"",
	    ifp->fd, packet->len, buf_size, pri_errno(packet_errno));

	if (packet->len == 0) {
		/* interpret this as EOF */
		log_message(RC_LOG, &logger,
			    "TCP: %zd byte message from socket %d indicates EOF",
			    packet->len, ifp->fd);
		return IFACE_EOF;
	}

	if (packet->len < NON_ESP_MARKER_SIZE) {
		log_message(RC_LOG, &logger,
			    "TCP: %zd byte message from socket %d is way to small",
			    packet->len, ifp->fd);
		return IFACE_FATAL;
	}

	static const uint8_t zero_esp_marker[NON_ESP_MARKER_SIZE] = { 0, };
	if (!memeq(packet->ptr, zero_esp_marker, sizeof(zero_esp_marker))) {
		log_message(RC_LOG, &logger,
			    "TCP: %zd byte message from socket %d is missing %d byte zero ESP marker",
			    packet->len, ifp->fd, NON_ESP_MARKER_SIZE);
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
		libreswan_log("IMPAIR: TCP: socket %d switching off NONBLOCK before write",
			      ifp->fd);
		flags = fcntl(ifp->fd, F_GETFL, 0);
		if (flags == -1) {
			LOG_ERRNO(errno, "TCP: fcntl(F_GETFL)");
		}
		if (fcntl(ifp->fd, F_SETFL, flags & ~O_NONBLOCK) == -1) {
			LOG_ERRNO(errno, "TCP: write - fcntl(F_GETFL)");
		}
	}
	ssize_t wlen = write(ifp->fd, ptr, len);
	dbg("TCP: socket %d wrote %zd of %zu bytes", ifp->fd, wlen, len);
	if (impair.tcp_use_blocking_write && flags >= 0) {
		libreswan_log("IMPAIR: TCP: socket %d restoring flags 0%o after write",
			      ifp->fd, flags);
		if (fcntl(ifp->fd, F_SETFL, flags) == -1) {
			LOG_ERRNO(errno, "TCP: fcntl(F_GETFL)");
		}
	}
	return wlen;
}

static void iketcp_cleanup(struct iface_port *ifp)
{
	dbg("TCP: socket %d cleaning up interface", ifp->fd);
	switch (ifp->iketcp_state) {
	case IKETCP_RUNNING:
		pstats_iketcp_stopped[ifp->iketcp_server]++;
		break;
	default:
		pstats_iketcp_aborted[ifp->iketcp_server]++;
		break;
	}
	if (ifp->iketcp_message_listener != NULL) {
		dbg("TCP: socket %d cleaning up message listener %p",
		    ifp->fd, ifp->iketcp_message_listener);
		event_free(ifp->iketcp_message_listener);
		ifp->iketcp_message_listener = NULL;
	}
	if (ifp->tcp_accept_listener != NULL) {
		dbg("TCP: socket %d cleaning up accept listener %p",
		    ifp->fd, ifp->tcp_accept_listener);
		evconnlistener_free(ifp->tcp_accept_listener);
		ifp->tcp_accept_listener = NULL;
	}
	if (ifp->iketcp_timeout != NULL) {
		dbg("TCP: socket %d cleaning up timeout %p",
		    ifp->fd, ifp->iketcp_timeout);
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
		    "TCP: socket %d timed out before first message received",
		    ifp->fd);
	free_any_iface_port(&ifp);
}

static void iketcp_listen(struct iface_port *ifp,
			  struct logger *logger)
{
	if (ifp->tcp_accept_listener == NULL) {
		ifp->tcp_accept_listener = evconnlistener_new(get_pluto_event_base(),
							      accept_ike_in_tcp_cb,
							      ifp, LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC,
							      -1, ifp->fd);
		if (ifp->tcp_accept_listener == NULL) {
			log_message(RC_LOG, logger,
				    "TCP: socket %d failed to create IKE-in-TCP listener",
				    ifp->fd);
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
	.send_keepalive = false,
	.read_packet = iketcp_read_packet,
	.write_packet = iketcp_write_packet,
	.cleanup = iketcp_cleanup,
	.listen = iketcp_listen,
	.bind_iface_port = iketcp_bind_iface_port,
};

static void iketcp_message_listener_cb(evutil_socket_t unused_fd UNUSED,
				       const short unused_event UNUSED,
				       void *arg)
{
	struct iface_port *ifp = arg;
	struct logger logger = FROM_LOGGER(&ifp->iketcp_remote_endpoint);

	switch (ifp->iketcp_state) {

	case IKETCP_OPEN:
		dbg("TCP: OPEN: socket %d reading IKETCP prefix", ifp->fd);
		const uint8_t iketcp[] = IKE_IN_TCP_PREFIX;
		uint8_t buf[sizeof(iketcp)];

		ssize_t len = read(ifp->fd, buf, sizeof(buf));
		if (len < 0) {
			/* too strict? */
			int e = errno;
			log_message(RC_LOG, &logger,
				    "TCP: problem reading IKETCP prefix from socket %d "PRI_ERRNO,
				    ifp->fd, pri_errno(e));
			/*
			 * XXX: Since this is the first attempt at
			 * reading the socket, there isn't a state
			 * that could be sharing IFP.
			 */
			free_any_iface_port(&ifp);
			return;
		}

		if (len != sizeof(buf)) {
			log_message(RC_LOG, &logger,
				    "TCP: problem reading IKETCP prefix from socket %d - returned %zd bytes but expecting %zu; closing socket",
				    ifp->fd, len, sizeof(buf));
			/*
			 * XXX: Since this is the first attempt at
			 * reading the socket, there isn't a state
			 * that could be sharing IFP.
			 */
			free_any_iface_port(&ifp);
			return;
		}

		dbg("TCP: OPEN: socket %d verifying IKETCP prefix", ifp->fd);
		if (!memeq(buf, iketcp, len)) {
			/* discard this tcp connection */
			log_message(RC_LOG, &logger,
				    "TCP: did not receive the IKE-in-TCP stream prefix ; closing socket");
			/*
			 * XXX: Since this is the first attempt at
			 * reading the socket, there isn't a state
			 * that could be sharing IFP.
			 */
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
			dbg("TCP: OPEN: socket %d enabling ESPINTCP", ifp->fd);
			if (setsockopt(ifp->fd, IPPROTO_TCP, TCP_ULP,
				      "espintcp", sizeof("espintcp"))) {
				int e = errno;
				log_message(RC_LOG, &logger,
					    "TCP: setsockopt(%d, SOL_TCP, TCP_ULP, \"espintcp\") failed; closing socket "PRI_ERRNO,
					    ifp->fd, pri_errno(e));
				/*
				 * XXX: Since this is the first
				 * attempt at reading the socket,
				 * there isn't a state that could be
				 * sharing IFP.
				 */
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
		dbg("TCP: PREFIXED: socket %d trying to read first packet", ifp->fd);
		/* received the first packet; stop the timeout */
		switch (handle_packet_cb(ifp)) {
		case IFACE_OK:
			dbg("TCP: PREFIXED: socket %d first packet ok; switching to running and freeing timeout",
			    ifp->fd);
			event_free(ifp->iketcp_timeout);
			ifp->iketcp_timeout = NULL;
			ifp->iketcp_state = IKETCP_RUNNING;
			return;
			break;
		case IFACE_IGNORE:
			dbg("TCP: PREFIXED: socket %d first packet got try-again", ifp->fd);
			return;
		case IFACE_EOF:
		case IFACE_FATAL:
			/* already logged */
			/*
			 * XXX: Since the first packet couldn't be
			 * read, no state was created so there's no
			 * problem with state and event sharing IFP.
			 */
			free_any_iface_port(&ifp);
			return;
		}
		bad_case(0);

	case IKETCP_RUNNING:
	{
		/*
		 * XXX: Both the state machine and this event handler
		 * are sharing EVP.  If the read by handle_packet_cb()
		 * is successful(IFACE_OK) then the message will be
		 * dispatched to the state code and that (as in seen
		 * in the wild) cal call delete_state() which will
		 * delete IFP.
		 */
		int fd = ifp->fd; /* save FD for logging */
		dbg("TCP: RUNNING: socket %d calling handle packet", fd);
		switch (handle_packet_cb(ifp)) {
		case IFACE_OK:
			/* XXX: IFP is unsafe */
			dbg("TCP: RUNNING: socket %d packet read ok; not trusting IFP", fd);
			return;
		case IFACE_IGNORE:
			dbg("TCP: RUNNING: socket %d packet got try-again", fd);
			return;
		case IFACE_EOF:
		case IFACE_FATAL:
			/* already logged */
			/*
			 * XXX: IFP is safe - the read failed, which
			 * means that the state code was never called.
			 *
			 *
			 * Shutdown the event handler, but leave the
			 * rest of EVP alone.  The state, when it is
			 * deleted, will clean up EVP.
			 *
			 * According to the libevent2 book: It is safe
			 * to call event_free() on an event that is
			 * pending or active: doing so makes the event
			 * non-pending and inactive before
			 * deallocating it.
			 */
			event_free(ifp->iketcp_message_listener);
			ifp->iketcp_message_listener = NULL;
			ifp->iketcp_state = IKETCP_STOPPED;
			return;
		}
		bad_case(0);
	}

	case IKETCP_STOPPED:
	{
		/*
		 * XXX: Even though the event handler has been told to
		 * shut down there may still be events outstanding;
		 * drain them.
		 */
		char bytes[10];
		ssize_t size = read(ifp->fd, &bytes, sizeof(bytes));
		if (size < 0) {
			log_message(RC_LOG, &logger,
				    "TCP: STOPPING: read to drain socket %d failed "PRI_ERRNO,
				    ifp->fd, pri_errno(errno));
		} else {
			dbg("TCP: STOPPING: socket %d drained %zd bytes",
			    ifp->fd, size);
		}
		return;
	}
	}
	/* no default - all cases return - missing case error */
	bad_case(ifp->iketcp_state);
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

	dbg("TCP: socket %d connecting to other end", fd);
	ip_sockaddr remote_sockaddr = sockaddr_from_endpoint(&st->st_remote_endpoint);
	if (connect(fd, &remote_sockaddr.sa.sa, remote_sockaddr.len) < 0) {
		LOG_ERRNO(errno, "TCP: connect(%d) failed", fd);
		close(fd);
		return STF_FATAL;
	}

	dbg("TCP: socket %d extracting local randomly assigned port", fd);
	ip_endpoint local_endpoint;
	{
		/* port gets assigned randomly */
		ip_sockaddr local_sockaddr = {
			.len = sizeof(local_sockaddr.sa),
		};
		if (getsockname(fd, &local_sockaddr.sa.sa, &local_sockaddr.len) < 0) {
			LOG_ERRNO(errno, "TCP: failed to get local TCP address from socket %d",
				  fd);
			close(fd);
			return STF_FATAL;
		}
		err_t err = sockaddr_to_endpoint(&ip_protocol_tcp, &local_sockaddr, &local_endpoint);
		if (err != NULL) {
			libreswan_log("TCP: failed to get local TCP address from socket %d, %s",
				      fd, err);
			close(fd);
			return STF_FATAL;
		}
	}

	dbg("TCP: socket %d making things non-blocking", fd);
	evutil_make_socket_nonblocking(fd); /* TCP: ignore errors? */
	evutil_make_socket_closeonexec(fd); /* TCP: ignore errors? */

	/* Socket is now connected, send the IKETCP stream */

	{
		dbg("TCP: socket %d sending IKE-in-TCP prefix", fd);
		const uint8_t iketcp[] = IKE_IN_TCP_PREFIX;
		if (write(fd, iketcp, sizeof(iketcp)) != (ssize_t)sizeof(iketcp)) {
			LOG_ERRNO(errno, "TCP: send of IKE-in-TCP prefix through socket %d", fd);
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
		dbg("TCP: socket %d enabling \"espintcp\"", fd);
		if (setsockopt(fd, IPPROTO_TCP, TCP_ULP, "espintcp", sizeof("espintcp"))) {
			LOG_ERRNO(errno, "setsockopt(SOL_TCP, TCP_ULP) failed in netlink_espintcp()");
			close(fd);
			return STF_FATAL;
		}
	}

	struct iface_port *ifp = alloc_thing(struct iface_port, "TCP iface initiator");
	ifp->io = &iketcp_iface_io;
	ifp->fd = fd;
	ifp->local_endpoint = local_endpoint;
	ifp->esp_encapsulation_enabled = true;
	ifp->float_nat_initiator = false;
	ifp->ip_dev = add_ref(st->st_interface->ip_dev);
	ifp->protocol = &ip_protocol_tcp;
	ifp->iketcp_remote_endpoint = st->st_remote_endpoint;
	ifp->iketcp_state = IKETCP_RUNNING;
	ifp->iketcp_server = false;

#if 0
	ifp->next = interfaces;
	interfaces = q;
#endif

	attach_fd_read_sensor(&ifp->iketcp_message_listener,
			      fd, iketcp_message_listener_cb, ifp);

	st->st_interface = ifp; /* TCP: leaks old st_interface? */
	pstats_iketcp_started[ifp->iketcp_server]++;
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
	attach_fd_read_sensor(&ifp->iketcp_message_listener, ifp->fd,
			      iketcp_message_listener_cb, ifp);

	pstats_iketcp_started[ifp->iketcp_server]++;
}
