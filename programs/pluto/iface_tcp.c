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

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>		/* for read() */

#include <netinet/tcp.h>	/* for TCP_ULP (hopefully) */
#ifndef TCP_ULP
#define TCP_ULP 31
#endif

#include "lsw_socket.h"		/* for cloexec_socket() */
#include "ip_address.h"
#include "ip_sockaddr.h"

#include "defs.h"
#include "kernel.h"		/* for kernel_ops.poke...() */
#include "server.h"		/* for detach_fd_read_listener() */
#include "iface.h"
#include "demux.h"		/* for alloc_md() */
#include "log.h"
#include "ip_info.h"
#include "pluto_stats.h"

static void accept_ike_in_tcp_cb(int accepted_fd, ip_sockaddr *sockaddr,
				 void *arg, struct logger *logger);

/*
 * IKETCP or TCP?
 *
 * In the code: TCP generally refers to the open TCP socket, and
 * IKETCP refers to the stream running the IKETCP / ECPinTCP protocol.
 */

static void jam_iketcp_prefix(struct jambuf *buf, const struct iface_endpoint *ifp)
{
	if (ifp == NULL) {
		jam_string(buf, "TCP: ");
		return;
	}

	static const char *iketcp_state_names[] = {
		[0] = "UNDEFINED",
#define D(X) [IKETCP_##X] = #X
		D(ACCEPTED),
		D(PREFIX_RECEIVED),
		D(ENABLED),
		D(STOPPED),
#undef D
	};
	if (ifp->iketcp_state >= elemsof(iketcp_state_names)) {
		jam(buf, "IKETCP %x?!?: ", ifp->iketcp_state);
	} else {
		jam_string(buf, "IKETCP ");
		jam_string(buf, iketcp_state_names[ifp->iketcp_state]);
		jam_string(buf, ": ");
	}
	if (ifp->fd > 0) {
		/* works as 0 is stdout */
		jam(buf, "socket %d: ", ifp->fd);
	}
}

static void dbg_iketcp(const struct iface_endpoint *ifp, const char *msg, ...) PRINTF_LIKE(2);
void dbg_iketcp(const struct iface_endpoint *ifp, const char *msg, ...)
{
	LDBGP_JAMBUF(DBG_BASE, &global_logger, buf) {
		jam_iketcp_prefix(buf, ifp);
		va_list ap;
		va_start(ap, msg);
		jam_va_list(buf, msg, ap);
		va_end(ap);
	}
}

static PRINTF_LIKE(5)
void llog_iketcp(enum stream stream, struct logger *logger,
		 const struct iface_endpoint *ifp, int error,
		 const char *msg, ...)
{
	LLOG_JAMBUF(stream, logger, buf) {
		jam_iketcp_prefix(buf, ifp);
		va_list ap;
		va_start(ap, msg);
		jam_va_list(buf, msg, ap);
		va_end(ap);
		if (error != 0) {
			jam_errno(buf, error);
		}
	}
}

static void stop_iketcp_read(const char *why, struct iface_endpoint *ifp)
{
	if (ifp->iketcp.read_listener != NULL) {
		dbg_iketcp(ifp, "%s; stopping read event %p",
			   why, ifp->iketcp.read_listener);
		detach_fd_read_listener(&ifp->iketcp.read_listener);
	}
}

static void iketcp_shutdown(struct iface_endpoint **ifp)
{
	stop_iketcp_read("stop", *ifp);
	iface_endpoint_delref(ifp);
}

static void stop_iketcp_timeout(const char *why, struct iface_endpoint *ifp)
{
	if (ifp->iketcp.prefix_timeout != NULL) {
		dbg_iketcp(ifp, "%s; stopping timeout %p", why,
			   ifp->iketcp.prefix_timeout);
		destroy_timeout(&ifp->iketcp.prefix_timeout);
	}
}

static struct msg_digest *read_espintcp_packet(const char *what,
					       struct iface_endpoint **ifp,
					       struct logger *logger)
{
	/*
	 * With TCP, all messages (both IKE and ESP/AH) are prefixed
	 * by the message length.  However, when ESPinTCP mode is
	 * enabled, the kernel strips away the length prefix so that
	 * it is not returned by a read.
	 */
	dbg_iketcp(*ifp, "reading %s", what);
	uint8_t bigbuffer[MAX_INPUT_UDP_SIZE]; /* ??? this buffer seems *way* too big */
	ssize_t packet_len = read((*ifp)->fd, bigbuffer, sizeof(bigbuffer));
	uint8_t *packet_ptr = bigbuffer;
	int packet_errno = errno; /* save!!! */

	if (packet_len < 0 && packet_errno == EAGAIN) {
		llog_iketcp(RC_LOG, logger, *ifp, /*ignore-error*/0,
			    "reading %s returned EAGAIN", what);
		return NULL;
	}

	if (packet_len < 0) {
		llog_iketcp(RC_LOG, logger, *ifp, packet_errno,
			    "reading %s failed: ", what);
		iketcp_shutdown(ifp); /* i.e., delete IFP */
		return NULL;
	}

	dbg_iketcp(*ifp, "read %zd of %zu byte %s", packet_len, sizeof(bigbuffer), what);

	if (packet_len == 0) {
		/* interpret this as EOF */
		llog_iketcp(RC_LOG, logger, *ifp, /*no-error*/0,
			    "%zd byte %s indicates EOF",
			    packet_len, what);
		/* XXX: how to tell state left hanging waiting for input? */
		iketcp_shutdown(ifp); /* i.e., delete IFP */
		return NULL;
	}

	if (packet_len < NON_ESP_MARKER_SIZE) {
		llog_iketcp(RC_LOG, logger, *ifp, /*no-error*/0,
			    "%zd byte %s is way to small",
			    packet_len, what);
		iketcp_shutdown(ifp); /* i.e., delete IFP */
		return NULL;
	}

	/*
	 * TCP is always in encapsulation mode (where each packet is
	 * prefixed either by 0 (IKE) or non-zero (ESP/AH SPI) marker.
	 * Check for and strip away the marker.
	 */
	static const uint8_t zero_esp_marker[NON_ESP_MARKER_SIZE] = { 0, };
	if (!memeq(packet_ptr, zero_esp_marker, sizeof(zero_esp_marker))) {
		llog_iketcp(RC_LOG, logger, *ifp, /*no-error*/0,
			    "%zd byte %s is missing %d byte zero ESP marker",
			    packet_len, what, NON_ESP_MARKER_SIZE);
		iketcp_shutdown(ifp); /* i.e., delete IFP */
		return NULL;
	}

	/* drop the non-ESP marker */
	packet_len -= sizeof(zero_esp_marker);
	packet_ptr += sizeof(zero_esp_marker);

	struct msg_digest *md = alloc_md(*ifp, &(*ifp)->iketcp_remote_endpoint,
					 packet_ptr, packet_len, HERE);
	return md;
}

static struct msg_digest *iketcp_read_packet(struct iface_endpoint **ifp,
					     struct logger *logger)
{
	/*
	 * Switch to an on-stack "from" logger that includes more
	 * context.
	 */
	struct logger from_logger = logger_from(logger, &(*ifp)->iketcp_remote_endpoint);
	logger = &from_logger;

	switch ((*ifp)->iketcp_state) {

	case IKETCP_ACCEPTED:
	{
		/*
		 * Read the "IKETCP" prefix.
		 *
		 * XXX: Since there's no state sharing IFP (this is
		 * first attempt at reading the socket) return
		 * IFACE_READ_ABORT. The caller (the low-level event
		 * handler) will then delete IFP.
		 */

		dbg_iketcp(*ifp, "reading IKETCP prefix");
		const uint8_t iketcp[] = IKE_IN_TCP_PREFIX;
		uint8_t buf[sizeof(iketcp)];
		ssize_t len = read((*ifp)->fd, buf, sizeof(buf));

		if (len < 0) {
			/* too strict? */
			int e = errno;
			llog_iketcp(RC_LOG, logger, (*ifp), e,
				    "error reading 'IKETCP' prefix; closing socket: ");
			iketcp_shutdown(ifp); /* i.e., delete IFP */
			return NULL;
		}

		if (len != sizeof(buf)) {
			llog_iketcp(RC_LOG, logger, (*ifp), /*no-error*/0,
				    "reading 'IKETCP' prefix returned %zd bytes but expecting %zu; closing socket",
				    len, sizeof(buf));
			iketcp_shutdown(ifp); /* i.e., delete IFP */
			return NULL;
		}

		dbg_iketcp(*ifp, "verifying IKETCP prefix");
		if (!memeq(buf, iketcp, len)) {
			/* discard this tcp connection */
			llog_iketcp(RC_LOG, logger, (*ifp), /*no-error*/0,
				    "prefix did not match 'IKETCP'; closing socket");
			iketcp_shutdown(ifp); /* i.e., delete IFP */
			return NULL;
		}

		/*
		 * Tell the kernel to load up the ESPINTCP Upper Layer
		 * Protocol.
		 *
		 * From this point on all writes are auto-wrapped in
		 * their length and reads are auto-blocked.
		 */
		if (impair.tcp_skip_setsockopt_espintcp) {
			llog_iketcp(RC_LOG, logger, (*ifp), /*no-error*/0,
				    "IMPAIR: skipping setsockopt(ESPINTCP)");
		} else {

			dbg_iketcp(*ifp, "enabling ESPINTCP");
			if (setsockopt((*ifp)->fd, IPPROTO_TCP, TCP_ULP,
				      "espintcp", sizeof("espintcp"))) {
				int e = errno;
				llog_iketcp(RC_LOG, logger, *ifp, e,
					    "closing socket; setsockopt(%d, SOL_TCP, TCP_ULP, \"espintcp\") failed: ",
					    (*ifp)->fd);
				iketcp_shutdown(ifp); /* i.e., delete IFP */
				return NULL;
			}
		}

		if (kernel_ops->poke_ipsec_policy_hole != NULL &&
		    !kernel_ops->poke_ipsec_policy_hole((*ifp)->fd, address_info((*ifp)->ip_dev->local_address), logger)) {
			/* already logged */
			iketcp_shutdown(ifp); /* i.e., delete IFP */
			return NULL;
		}

		/*
		 * Return NULL so that the caller knows that there's
		 * no packet to feed into the state machinery.
		 *
		 * Why not update the callback so that it points to a
		 * simple handler?  This is easier, and it seems that
		 * changing the event handler while in the event
		 * handler isn't allowed.
		 */
		(*ifp)->iketcp_state = IKETCP_PREFIX_RECEIVED;
		return NULL;
	}

	case IKETCP_PREFIX_RECEIVED:
	{
		/*
		 * Read the first packet; if successful, stop the
		 * timeout.  If this fails badly,
		 * read_raw_iketcp_packet() will shutdown IFP.
		 */

		struct msg_digest *md = read_espintcp_packet("first packet", ifp, logger);
		if (md == NULL) {
			return NULL;
		}

		dbg_iketcp(*ifp, "first packet ok; switch to enabled (release endpoint)");
		(*ifp)->iketcp_state = IKETCP_ENABLED;
		stop_iketcp_timeout("first packet", *ifp);
		iface_endpoint_delref(ifp);
		return md;
	}

	case IKETCP_ENABLED:
		return read_espintcp_packet("packet", ifp, logger);

	case IKETCP_STOPPED:
	{
		/*
		 * XXX: Even though the event handler has been told to
		 * shut down there may still be events outstanding;
		 * drain them.
		 */
		char bytes[10];
		ssize_t size = read((*ifp)->fd, &bytes, sizeof(bytes));
		if (size < 0) {
			llog_iketcp(RC_LOG, logger, *ifp, errno,
				    "drain failed: ");
		} else {
			dbg_iketcp(*ifp, "drained %zd bytes", size);
		}
		return NULL; /* ignore read */
	}
	}
	/* no default - all cases return - missing case error */
	bad_case((*ifp)->iketcp_state);
}

static ssize_t iketcp_write_packet(const struct iface_endpoint *ifp,
				   shunk_t packet,
				   const ip_endpoint *remote_endpoint UNUSED,
				   struct logger *logger)
{
	int flags = 0;
	if (impair.tcp_use_blocking_write) {
		llog_iketcp(RC_LOG, logger, ifp, /*no-error*/0,
			    "IMPAIR: switching off NONBLOCK before write");
		flags = fcntl(ifp->fd, F_GETFL, 0);
		if (flags == -1) {
			int e = errno;
			llog_iketcp(RC_LOG, logger, ifp, e,
				    "fcntl(%d, F_GETFL, 0) failed: ", ifp->fd);
		}
		if (fcntl(ifp->fd, F_SETFL, flags & ~O_NONBLOCK) == -1) {
			int e = errno;
			llog_iketcp(RC_LOG, logger, ifp, e,
				    "fcntl(%d, F_SETFL, 0%o) failed,: ",
				    ifp->fd, flags);
		}
	}
	ssize_t wlen = write(ifp->fd, packet.ptr, packet.len);
	dbg_iketcp(ifp, "wrote %zd of %zu bytes", wlen, packet.len);
	if (impair.tcp_use_blocking_write && flags >= 0) {
		llog_iketcp(RC_LOG, logger, ifp, /*no-error*/0,
			    "IMPAIR: restoring flags 0%o after write", flags);
		if (fcntl(ifp->fd, F_SETFL, flags) == -1) {
			int e = errno;
			llog_iketcp(RC_LOG, logger, ifp, e,
				    "fcntl(%d, F_SETFL, 0%o) failed: ",
				    ifp->fd, flags);
		}
	}
	return wlen;
}

static void iketcp_cleanup(struct iface_endpoint *ifp)
{
	dbg_iketcp(ifp, "cleaning up interface");
	switch (ifp->iketcp_state) {
	case IKETCP_ENABLED:
		pstats_iketcp_stopped[ifp->iketcp_server]++;
		break;
	default:
		pstats_iketcp_aborted[ifp->iketcp_server]++;
		break;
	}
	stop_iketcp_read("cleaning up", ifp);
	if (ifp->iketcp.accept_listener != NULL) {
		dbg_iketcp(ifp, "cleaning up accept listener %p",
			   ifp->iketcp.accept_listener);
		detach_fd_accept_listener(&ifp->iketcp.accept_listener);
	}
	stop_iketcp_timeout("cleaning up", ifp);
}

static void iketcp_server_timeout(void *arg, const struct timer_event *event)
{
	struct iface_endpoint *ifp = arg;
	/* build up the logger using the stack */
	struct logger from_logger = logger_from(event->logger, &ifp->iketcp_remote_endpoint);
	llog_iketcp(RC_LOG, &from_logger, ifp, /*no-error*/0,
		    "timeout out before first message received");
	iface_endpoint_delref(&ifp);
}

static void iketcp_listen(struct iface_endpoint *ifp,
			  struct logger *logger)
{
	if (ifp->iketcp.accept_listener == NULL) {
		attach_fd_accept_listener("IKETCP", &ifp->iketcp.accept_listener,
					  ifp->fd, accept_ike_in_tcp_cb, ifp);
		if (ifp->iketcp.accept_listener == NULL) {
			llog_iketcp(RC_LOG, logger, ifp, /*no-error*/0,
				    "failed to create IKE-in-TCP listener event");
		}
	}
}

const struct iface_io iketcp_iface_io = {
	.protocol = &ip_protocol_tcp,
	.socket = {
		.type = SOCK_STREAM,
		.type_name = "SOCK_STREAM",
	},
	.send_keepalive = false,
	.read_packet = iketcp_read_packet,
	.write_packet = iketcp_write_packet,
	.cleanup = iketcp_cleanup,
	.listen = iketcp_listen,
};

/*
 * Open a TCP socket connected to st_remote_endpoint.
 *
 * TCP: THIS IS A BLOCKING CALL
 *
 * Since this end is opening the socket, this end is responsible for
 * sending the IKE-in-TCP magic word.
 */

struct iface_endpoint *connect_to_tcp_endpoint(struct iface_device *local_dev,
					       ip_endpoint remote_endpoint,
					       struct logger *logger)
{
	ldbg(logger, "TCP: opening socket");
	PEXPECT(logger, endpoint_protocol(remote_endpoint) == &ip_protocol_tcp);
	const struct ip_info *afi = endpoint_info(remote_endpoint);

	int fd = cloexec_socket(afi->socket.domain, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		llog_error(logger, errno, "TCP: cloexec_socket(%s,SOCK_STREAM,IPPROTO_TCP) failed",
			   afi->socket.domain_name);
		return NULL;
	}

	/* This needs to be called before connect, so TCP handshake
	 * (in plaintext) completes. */
	if (kernel_ops->poke_ipsec_policy_hole != NULL &&
	    !kernel_ops->poke_ipsec_policy_hole(fd, afi, logger)) {
		/* already logged */
		close(fd);
		return NULL;
	}

	/*
	 * Connect
	 *
	 * TCP: THIS IS A BLOCKING CALL
	 *
	 * TCP: Assume st_remote_endpoint is the intended remote?
	 * Should this instead look in the connection?
	 */

	ldbg(logger, "TCP: socket %d: connecting to other end", fd);
	ip_sockaddr remote_sockaddr = sockaddr_from_endpoint(remote_endpoint);
	if (connect(fd, &remote_sockaddr.sa.sa, remote_sockaddr.len) < 0) {
		endpoint_buf eb;
		llog_error(logger, errno, "TCP: socket %d: connecting to %s",
			   fd, str_endpoint(&remote_endpoint, &eb));
		close(fd);
		return NULL;
	}

	ldbg(logger, "TCP: socket %d: extracting local randomly assigned port", fd);
	ip_endpoint local_endpoint;
	{
		/* port gets assigned randomly */
		ip_sockaddr local_sockaddr = {
			.len = sizeof(local_sockaddr.sa),
		};
		if (getsockname(fd, &local_sockaddr.sa.sa, &local_sockaddr.len) < 0) {
			llog_error(logger, errno,
				   "TCP: socket %d: getting local TCP sockaddr", fd);
			close(fd);
			return NULL;
		}
		ip_address local_address;
		ip_port local_port;
		err_t err = sockaddr_to_address_port(&local_sockaddr.sa.sa, local_sockaddr.len,
						     &local_address, &local_port);
		if (err != NULL) {
			llog_pexpect(logger, HERE,
				     "TCP: socket %d: converting sockaddr to address/port: %s", fd, err);
			close(fd);
			return NULL;
		}
		local_endpoint = endpoint_from_address_protocol_port(local_address, &ip_protocol_tcp, local_port);
	}

	ldbg(logger, "TCP: socket %d: making things non-blocking", fd);
	evutil_make_socket_nonblocking(fd); /* TCP: ignore errors? */
	evutil_make_socket_closeonexec(fd); /* TCP: ignore errors? */

	/* Socket is connected, send the IKETCP stream */

	{
		ldbg(logger, "TCP: socket %d: sending IKE-in-TCP prefix", fd);
		const uint8_t iketcp[] = IKE_IN_TCP_PREFIX;
		if (write(fd, iketcp, sizeof(iketcp)) != (ssize_t)sizeof(iketcp)) {
			llog_error(logger, errno,
				   "TCP: socket %d: sending IKE-in-TCP prefix", fd);
			close(fd);
			return NULL;
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
		llog(RC_LOG, logger, "IMPAIR: TCP: skipping setsockopt(espintcp)");
	} else {
		ldbg(logger, "TCP: socket %d: enabling \"espintcp\"", fd);
		if (setsockopt(fd, IPPROTO_TCP, TCP_ULP, "espintcp", sizeof("espintcp"))) {
			llog_error(logger, errno,
				   "TCP: socket %d: setting socket option \"espintcp\"", fd);
			close(fd);
			return NULL;
		}
	}

	struct iface_endpoint *ifp =
		alloc_iface_endpoint(fd, local_dev, &iketcp_iface_io,
				     ESP_ENCAPSULATION_ENABLED,
				     INITIATOR_PORT_FIXED,
				     local_endpoint,
				     HERE);
	ifp->iketcp_remote_endpoint = remote_endpoint;
	ifp->iketcp_state = IKETCP_ENABLED;
	ifp->iketcp_server = false;
#if 0
	/* private */
	ifp->next = interfaces;
	interfaces = q;
#endif

	attach_fd_read_listener(&ifp->iketcp.read_listener,
				fd, "IKETCP",
				process_iface_packet, ifp);

	pstats_iketcp_started[ifp->iketcp_server]++;

	/*
	 * Return a newref.  Caller must either delref or save the
	 * pointer.
	 */
	return iface_endpoint_addref(ifp);
}

void accept_ike_in_tcp_cb(int accepted_fd, ip_sockaddr *sa,
			  void *arg, struct logger *logger)
{
	struct iface_endpoint *bind_ifp = arg;
	ip_address remote_tcp_address;
	ip_port remote_tcp_port;
	err_t err = sockaddr_to_address_port(&sa->sa.sa, sa->len,
					     &remote_tcp_address, &remote_tcp_port);
	if (err != NULL) {
		llog(RC_LOG, logger, "TCP: invalid remote address: %s", err);
		close(accepted_fd);
		return;
	}

	ip_endpoint remote_tcp_endpoint = endpoint_from_address_protocol_port(remote_tcp_address,
									      &ip_protocol_tcp,
									      remote_tcp_port);

	struct iface_endpoint *ifp =
		alloc_iface_endpoint(accepted_fd, bind_ifp->ip_dev, &iketcp_iface_io,
				     ESP_ENCAPSULATION_ENABLED,
				     INITIATOR_PORT_FIXED,
				     bind_ifp->local_endpoint,
				     HERE);
	ifp->iketcp_remote_endpoint = remote_tcp_endpoint;
	ifp->iketcp_state = IKETCP_ACCEPTED;
	ifp->iketcp_server = true;

	struct logger from_logger = logger_from(logger, &remote_tcp_endpoint);
	logger = &from_logger;
	llog_iketcp(RC_LOG, logger, ifp,  /*no-error*/0, "accepted connection");

	/*
	 * Set up a timeout to kill the socket when nothing happens.
	 * The timeout has a reference so unless it is deleted.
	 */
	schedule_timeout("IKETCP", &ifp->iketcp.prefix_timeout,
			 deltatime(5) /* TCP: how much? */,
			 iketcp_server_timeout, ifp);
	attach_fd_read_listener(&ifp->iketcp.read_listener, ifp->fd,
				"IKETCP", process_iface_packet, ifp);

	pstats_iketcp_started[ifp->iketcp_server]++;
}
