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

/* work around weird combo's of glibc and kernel header conflicts */
#ifndef GLIBC_KERN_FLIP_HEADERS
# include "linux/xfrm.h" /* local (if configured) or system copy */
# include "libreswan.h"
#else
# include "libreswan.h"
# include "linux/xfrm.h" /* local (if configured) or system copy */
#endif

/*
 * IKETCP or TCP?
 *
 * In the code: TCP generally refers to the open TCP socket, and
 * IKETCP refers to the stream running the IKETCP / ECPinTCP protocol.
 */

static void jam_iketcp_prefix(struct jambuf *buf, const struct iface_endpoint *ifp)
{
	static const char *iketcp_state_names[] = {
		[0] = "UNDEFINED",
#define D(X) [IKETCP_##X] = #X
		D(ACCEPTED),
		D(PREFIX_RECEIVED),
		D(ENABLED),
		D(STOPPED),
#undef D
	};
	if (ifp == NULL) {
		jam_string(buf, "TCP: ");
	} else if (ifp->iketcp_state >= elemsof(iketcp_state_names)) {
		jam(buf, "IKETCP %x?!?: ", ifp->iketcp_state);
	} else {
		jam_string(buf, "IKETCP ");
		jam_string(buf, iketcp_state_names[ifp->iketcp_state]);
		jam_string(buf, ": ");
	}
}

static void dbg_iketcp(const struct iface_endpoint *ifp, const char *msg, ...) PRINTF_LIKE(2);
void dbg_iketcp(const struct iface_endpoint *ifp, const char *msg, ...)
{
	LSWDBGP(DBG_BASE, buf) {
		jam_iketcp_prefix(buf, ifp);
		va_list ap;
		va_start(ap, msg);
		jam_va_list(buf, msg, ap);
		va_end(ap);
	}
}

static void llog_iketcp(lset_t rc_flags, struct logger *logger, const struct iface_endpoint *ifp,
			const char *msg, ...) PRINTF_LIKE(4);
void llog_iketcp(lset_t rc_flags, struct logger *logger, const struct iface_endpoint *ifp UNUSED,
		 const char *msg, ...)
{
	LLOG_JAMBUF(rc_flags, logger, buf) {
		jam_iketcp_prefix(buf, ifp);
		va_list ap;
		va_start(ap, msg);
		jam_va_list(buf, msg, ap);
		va_end(ap);
	}
}

static void accept_ike_in_tcp_cb(struct evconnlistener *evcon UNUSED,
				 int accepted_fd,
				 struct sockaddr *sockaddr, int sockaddr_len,
				 void *arg);

static enum iface_read_status read_raw_iketcp_packet(const char *prefix,
						     const struct iface_endpoint *ifp,
						     struct iface_packet *packet,
						     struct logger *logger)
{
	/*
	 * Reads the entire packet _without_ length, if buffer isn't
	 * big enough packet is truncated.
	 */
	dbg_iketcp(ifp, "socket %d reading packet", ifp->fd);
	packet->sender = ifp->iketcp_remote_endpoint;
	size_t buf_size = packet->len;
	errno = 0;
	packet->len = read(ifp->fd, packet->ptr, buf_size);
	int packet_errno = errno;
	if (packet_errno != 0) {
		llog_iketcp(RC_LOG, logger, ifp,
			    "%ssocket %d: read failed "PRI_ERRNO,
			    prefix, ifp->fd, pri_errno(packet_errno));
		if (packet_errno == EAGAIN) {
			return IFACE_READ_IGNORE;
		} else {
			return IFACE_READ_ERROR;
		}
	}

	dbg_iketcp(ifp, "socket %d read %zd of %zu bytes; "PRI_ERRNO"",
		   ifp->fd, packet->len, buf_size, pri_errno(packet_errno));

	if (packet->len == 0) {
		/* interpret this as EOF */
		llog_iketcp(RC_LOG, logger, ifp,
			    "%ssocket %d: %zd byte read indicates EOF",
			    prefix, ifp->fd, packet->len);
		return IFACE_READ_EOF;
	}

	if (packet->len < NON_ESP_MARKER_SIZE) {
		llog_iketcp(RC_LOG, logger, ifp,
			    "%ssocket %d: %zd byte message is way to small",
			    prefix, ifp->fd, packet->len);
		return IFACE_READ_ERROR;
	}

	static const uint8_t zero_esp_marker[NON_ESP_MARKER_SIZE] = { 0, };
	if (!memeq(packet->ptr, zero_esp_marker, sizeof(zero_esp_marker))) {
		llog_iketcp(RC_LOG, logger, ifp,
			    "%ssocket %d: %zd byte message is missing %d byte zero ESP marker",
			    prefix, ifp->fd, packet->len, NON_ESP_MARKER_SIZE);
		return IFACE_READ_ERROR;
	}

	packet->len -= sizeof(zero_esp_marker);
	packet->ptr += sizeof(zero_esp_marker);
	return IFACE_READ_OK;
}

static enum iface_read_status iketcp_read_packet(struct iface_endpoint *ifp,
						 struct iface_packet *packet,
						 struct logger *logger)
{
	bool v6 = ifp->ip_dev->id_address.version == 6;

	/*
	 * At this point there's no so log it against the remote
	 * endpoint determined when the connection was accepted.
	 */
	struct logger from_logger = logger_from(logger, &ifp->iketcp_remote_endpoint);
	logger = &from_logger;

	switch (ifp->iketcp_state) {

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

		dbg_iketcp(ifp, "reading IKETCP prefix from socket %d", ifp->fd);
		const uint8_t iketcp[] = IKE_IN_TCP_PREFIX;
		uint8_t buf[sizeof(iketcp)];
		ssize_t len = read(ifp->fd, buf, sizeof(buf));

		if (len < 0) {
			/* too strict? */
			int e = errno;
			llog_iketcp(RC_LOG_SERIOUS, logger, ifp,
				    "closing socket %d: error reading 'IKETCP' prefix "PRI_ERRNO,
				    ifp->fd, pri_errno(e));
			return IFACE_READ_ABORT; /* i.e., delete IFP */
		}

		if (len != sizeof(buf)) {
			llog_iketcp(RC_LOG_SERIOUS, logger, ifp,
				    "closing socket %d: reading 'IKETCP' prefix returned %zd bytes but expecting %zu",
				    ifp->fd, len, sizeof(buf));
			return IFACE_READ_ABORT; /* i.e., delete IFP */
		}

		dbg_iketcp(ifp, "socket %d verifying IKETCP prefix", ifp->fd);
		if (!memeq(buf, iketcp, len)) {
			/* discard this tcp connection */
			llog_iketcp(RC_LOG_SERIOUS, logger, ifp,
				    "closing socket %d: prefix did not match 'IKETCP'", ifp->fd);
			return IFACE_READ_ABORT; /* i.e., delete IFP */
		}

		/*
		 * Tell the kernel to load up the ESPINTCP Upper Layer
		 * Protocol.
		 *
		 * From this point on all writes are auto-wrapped in
		 * their length and reads are auto-blocked.
		 */
		if (impair.tcp_skip_setsockopt_espintcp) {
			llog_iketcp(RC_LOG, logger, ifp,
				    "IMPAIR: skipping setsockopt(ESPINTCP)");
		} else {

			dbg_iketcp(ifp, "socket %d enabling ESPINTCP", ifp->fd);

			if (setsockopt(ifp->fd, IPPROTO_TCP, TCP_ULP,
				      "espintcp", sizeof("espintcp"))) {
				int e = errno;
				llog_iketcp(RC_LOG, logger, ifp,
					    "setsockopt(%d, SOL_TCP, TCP_ULP, \"espintcp\") failed; closing socket "PRI_ERRNO,
					    ifp->fd, pri_errno(e));
				return IFACE_READ_ABORT; /* i.e., delete IFP */
			}

			struct xfrm_userpolicy_info policy_in = {
				.action = XFRM_POLICY_ALLOW,
				.sel.family = v6 ? AF_INET6 :AF_INET,
				.dir = XFRM_POLICY_IN,
			};

			if (setsockopt(ifp->fd, IPPROTO_IP, IP_XFRM_POLICY, &policy_in, sizeof(policy_in))) {
				int e = errno;
				llog_iketcp(RC_LOG, logger, ifp,
					    "closing socket %d: setsockopt(%d, SOL_TCP, IP_XFRM_POLICY, \"policy_in\") failed "PRI_ERRNO,
					    ifp->fd, ifp->fd, pri_errno(e));
				return IFACE_READ_ABORT; /* i.e., delete IFP */
			}

			struct xfrm_userpolicy_info policy_out = {
				.action = XFRM_POLICY_ALLOW,
				.sel.family = v6 ? AF_INET6 :AF_INET,
				.dir = XFRM_POLICY_OUT,
			};

			if (setsockopt(ifp->fd, IPPROTO_IP, IP_XFRM_POLICY, &policy_out, sizeof(policy_out))) {
				int e = errno;
				llog_iketcp(RC_LOG, logger, ifp,
					    "closing socket %d: setsockopt(%d, SOL_TCP, IP_XFRM_POLICY, \"policy_out\") failed "PRI_ERRNO,
					    ifp->fd, ifp->fd, pri_errno(e));
				return IFACE_READ_ABORT; /* i.e., delete IFP */
			}

		}

		/*
		 * Return IGNORE so that the caller knows to not feed
		 * the packet into the state machinery.
		 *
		 * Why not update the callback so that it points to a
		 * simple handler?  This is easier, and it seems that
		 * changing the event handler while in the event
		 * handler isn't allowed.
		 */
		ifp->iketcp_state = IKETCP_PREFIX_RECEIVED;
		return IFACE_READ_IGNORE;
	}

	case IKETCP_PREFIX_RECEIVED:
	{
		/*
		 * Read the first packet; stop the timeout.
		 *
		 * XXX: Since there's no state sharing IFP (so far all
		 * that's happened is "IKETCP" has been read), convert
		 * errors into IFACE_READ_ABORT.  The caller (the
		 * low-level event handler) will then delete IFP.
		 */

		dbg_iketcp(ifp, "reading first packet from socket %d", ifp->fd);
		enum iface_read_status status = read_raw_iketcp_packet("closing ", ifp,
								       packet, logger);

		switch (status) {
		case IFACE_READ_OK:
			dbg_iketcp(ifp, "socket %d first packet ok; switching to running and freeing timeout",
				   ifp->fd);
			event_free(ifp->iketcp_timeout);
			ifp->iketcp_timeout = NULL;
			ifp->iketcp_state = IKETCP_ENABLED;
			return IFACE_READ_OK;
		case IFACE_READ_IGNORE:
			return IFACE_READ_IGNORE;
		case IFACE_READ_ABORT:
		case IFACE_READ_EOF:
		case IFACE_READ_ERROR:
			return IFACE_READ_ABORT;
		}
		bad_case(status);
	}

	case IKETCP_ENABLED:
	{
		dbg_iketcp(ifp, "reading packet from socket %d", ifp->fd);
		return read_raw_iketcp_packet("", ifp, packet, logger);
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
			llog_iketcp(RC_LOG, logger, ifp,
				    "read to drain socket %d failed "PRI_ERRNO,
				    ifp->fd, pri_errno(errno));
		} else {
			dbg_iketcp(ifp, "drained %zd bytes from socket %d",
				   size, ifp->fd);
		}
		return IFACE_READ_IGNORE;
	}
	}
	/* no default - all cases return - missing case error */
	bad_case(ifp->iketcp_state);
}

static ssize_t iketcp_write_packet(const struct iface_endpoint *ifp,
				   const void *ptr, size_t len,
				   const ip_endpoint *remote_endpoint UNUSED,
				   struct logger *logger)
{
	int flags = 0;
	if (impair.tcp_use_blocking_write) {
		llog_iketcp(RC_LOG, logger, ifp,
			    "IMPAIR: socket %d: switching off NONBLOCK before write",
			    ifp->fd);
		flags = fcntl(ifp->fd, F_GETFL, 0);
		if (flags == -1) {
			int e = errno;
			llog_iketcp(RC_LOG_SERIOUS, logger, ifp,
				    "socket %d: fcntl(%d, F_GETFL, 0) failed "PRI_ERRNO,
				    ifp->fd, ifp->fd, pri_errno(e));
		}
		if (fcntl(ifp->fd, F_SETFL, flags & ~O_NONBLOCK) == -1) {
			int e = errno;
			llog_iketcp(RC_LOG_SERIOUS, logger, ifp,
				    "socket %d: fcntl(%d, F_SETFL, 0%o) failed, "PRI_ERRNO,
				    ifp->fd, ifp->fd, flags, pri_errno(e));
		}
	}
	ssize_t wlen = write(ifp->fd, ptr, len);
	dbg_iketcp(ifp, "socket %d wrote %zd of %zu bytes", ifp->fd, wlen, len);
	if (impair.tcp_use_blocking_write && flags >= 0) {
		llog_iketcp(RC_LOG, logger, ifp,
			    "IMPAIR: socket %d: restoring flags 0%o after write",
			    ifp->fd, flags);
		if (fcntl(ifp->fd, F_SETFL, flags) == -1) {
			int e = errno;
			llog_iketcp(RC_LOG_SERIOUS, logger, ifp,
				    "socket %d: fcntl(%d, F_SETFL, 0%o) failed "PRI_ERRNO,
				    ifp->fd, ifp->fd, flags, pri_errno(e));
		}
	}
	return wlen;
}

static void iketcp_cleanup(struct iface_endpoint *ifp)
{
	dbg_iketcp(ifp, "socket %d cleaning up interface", ifp->fd);
	switch (ifp->iketcp_state) {
	case IKETCP_ENABLED:
		pstats_iketcp_stopped[ifp->iketcp_server]++;
		break;
	default:
		pstats_iketcp_aborted[ifp->iketcp_server]++;
		break;
	}
	if (ifp->iketcp_message_listener != NULL) {
		dbg_iketcp(ifp, "socket %d cleaning up message listener %p",
			   ifp->fd, ifp->iketcp_message_listener);
		event_free(ifp->iketcp_message_listener);
		ifp->iketcp_message_listener = NULL;
	}
	if (ifp->tcp_accept_listener != NULL) {
		dbg_iketcp(ifp, "socket %d cleaning up accept listener %p",
			   ifp->fd, ifp->tcp_accept_listener);
		evconnlistener_free(ifp->tcp_accept_listener);
		ifp->tcp_accept_listener = NULL;
	}
	if (ifp->iketcp_timeout != NULL) {
		dbg_iketcp(ifp, "socket %d cleaning up timeout %p",
			   ifp->fd, ifp->iketcp_timeout);
		event_free(ifp->iketcp_timeout);
		ifp->iketcp_timeout = NULL;
	}
}

static void iketcp_server_timeout(evutil_socket_t unused_fd UNUSED,
				  const short unused_event UNUSED,
				  void *arg UNUSED)
{
	struct iface_endpoint *ifp = arg;
	/* build up the logger using the stack */
	struct logger global_logger = GLOBAL_LOGGER(null_fd); /* event-handler */
	struct logger from_logger = logger_from(&global_logger, &ifp->iketcp_remote_endpoint);
	struct logger *logger = &from_logger;
	llog_iketcp(RC_LOG, logger, ifp,
		    "socket %d timed out before first message received",
		    ifp->fd);
	free_any_iface_endpoint(&ifp);
}

static void iketcp_listen(struct iface_endpoint *ifp,
			  struct logger *logger)
{
	if (ifp->tcp_accept_listener == NULL) {
		ifp->tcp_accept_listener = evconnlistener_new(get_pluto_event_base(),
							      accept_ike_in_tcp_cb,
							      ifp, LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC,
							      -1, ifp->fd);
		if (ifp->tcp_accept_listener == NULL) {
			llog_iketcp(RC_LOG, logger, ifp,
				    "failed to create IKE-in-TCP listener for socket %d",
				    ifp->fd);
		}
	}
}

static int bind_tcp_socket(const struct iface_dev *ifd, ip_port port,
			   struct logger *logger)
{
	const struct ip_info *type = address_type(&ifd->id_address);
	int fd = socket(type->af, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		log_errno(logger, errno, "socket() in %s()", __func__);
		return -1;
	}

	int fcntl_flags;
	static const int on = true;     /* by-reference parameter; constant, we hope */

	/* Set socket Nonblocking */
	if ((fcntl_flags = fcntl(fd, F_GETFL)) >= 0) {
		if (!(fcntl_flags & O_NONBLOCK)) {
			fcntl_flags |= O_NONBLOCK;
			if (fcntl(fd, F_SETFL, fcntl_flags) == -1) {
				log_errno(logger, errno, "fcntl(,, O_NONBLOCK) in create_socket()");
			}
		}
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		log_errno(logger, errno, "fcntl(,, FD_CLOEXEC) in create_socket()");
		close(fd);
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		       (const void *)&on, sizeof(on)) < 0) {
		log_errno(logger, errno, "setsockopt SO_REUSEADDR in create_socket()");
		close(fd);
		return -1;
	}

#ifdef SO_PRIORITY
	static const int so_prio = 6; /* rumored maximum priority, might be 7 on linux? */
	if (setsockopt(fd, SOL_SOCKET, SO_PRIORITY, (const void *)&so_prio,
		       sizeof(so_prio)) < 0) {
		log_errno(logger, errno, "setsockopt(SO_PRIORITY) in %s()", __func__);
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
			log_errno(logger, errno, "setsockopt(SO_RCVBUFFORCE) in %s()", __func__);
		}
		if (setsockopt(fd, SOL_SOCKET, so_snd, (const void *)&pluto_sock_bufsize,
			       sizeof(pluto_sock_bufsize)) < 0) {
			log_errno(logger, errno, "setsockopt(SO_SNDBUFFORCE) in %s()", __func__);
		}
	}

	/* To improve error reporting.  See ip(7). */
#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
	if (pluto_sock_errqueue) {
		if (setsockopt(fd, SOL_IP, IP_RECVERR, (const void *)&on, sizeof(on)) < 0) {
			log_errno(logger, errno, "setsockopt IP_RECVERR in create_socket()");
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
		log_errno(logger, errno, "setsockopt IPV6_USE_MIN_MTU in process_raw_ifaces()");
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
	    !kernel_ops->poke_ipsec_policy_hole(ifd, fd, logger)) {
		close(fd);
		return -1;
	}

	/*
	 * ??? does anyone care about the value of port of ifp->addr?
	 * Old code seemed to assume that it should be reset to pluto_port.
	 * But only on successful bind.  Seems wrong or unnecessary.
	 */
	ip_endpoint if_endpoint = endpoint_from_address_protocol_port(ifd->id_address,
								      &ip_protocol_tcp,
								      port);
	ip_sockaddr if_sa = sockaddr_from_endpoint(if_endpoint);
	if (bind(fd, &if_sa.sa.sa, if_sa.len) < 0) {
		endpoint_buf b;
		log_errno(logger, errno, "bind() for %s %s in process_raw_ifaces()",
			  ifd->id_rname,
			  str_endpoint(&if_endpoint, &b));
		close(fd);
		return -1;
	}

#if defined(HAVE_UDPFROMTO)
	/* we are going to use udpfromto.c, so initialize it */
	if (udpfromto_init(fd) == -1) {
		log_errno(logger, errno, "udpfromto_init() returned an error - ignored");
	}
#endif

	/* poke a hole for IKE messages in the IPsec layer */
	if (kernel_ops->exceptsocket != NULL) {
		if (!kernel_ops->exceptsocket(fd, AF_INET, logger)) {
			close(fd);
			return -1;
		}
	}

	return fd;
}

static int iketcp_bind_iface_endpoint(struct iface_dev *ifd, ip_port port,
				      bool unused_esp_encapsulation_enabled UNUSED,
				      struct logger *logger)
{
	return bind_tcp_socket(ifd, port, logger);
}

const struct iface_io iketcp_iface_io = {
	.protocol = &ip_protocol_tcp,
	.send_keepalive = false,
	.read_packet = iketcp_read_packet,
	.write_packet = iketcp_write_packet,
	.cleanup = iketcp_cleanup,
	.listen = iketcp_listen,
	.bind_iface_endpoint = iketcp_bind_iface_endpoint,
};

/*
 * Open a TCP socket connected to st_remote_endpoint.  Since this end
 * opend the socket, this end sends the IKE-in-TCP magic word.
 */

stf_status create_tcp_interface(struct state *st)
{
	dbg("TCP: opening socket");
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		log_errno(st->st_logger, errno, "TCP: socket() failed");
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
	ip_sockaddr remote_sockaddr = sockaddr_from_endpoint(st->st_remote_endpoint);
	if (connect(fd, &remote_sockaddr.sa.sa, remote_sockaddr.len) < 0) {
		log_errno(st->st_logger, errno,
			  "TCP: connect(%d) failed", fd);
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
			log_errno(st->st_logger, errno,
				  "TCP: failed to get local TCP address from socket %d",
				  fd);
			close(fd);
			return STF_FATAL;
		}
		ip_address local_address;
		ip_port local_port;
		err_t err = sockaddr_to_address_port(local_sockaddr, &local_address, &local_port);
		if (err != NULL) {
			log_state(RC_LOG, st,
				  "TCP: failed to get local TCP address from socket %d, %s", fd, err);
			close(fd);
			return STF_FATAL;
		}
		local_endpoint = endpoint_from_address_protocol_port(local_address, &ip_protocol_tcp, local_port);
	}

	dbg("TCP: socket %d making things non-blocking", fd);
	evutil_make_socket_nonblocking(fd); /* TCP: ignore errors? */
	evutil_make_socket_closeonexec(fd); /* TCP: ignore errors? */

	/* Socket is now connected, send the IKETCP stream */

	{
		dbg("TCP: socket %d sending IKE-in-TCP prefix", fd);
		const uint8_t iketcp[] = IKE_IN_TCP_PREFIX;
		if (write(fd, iketcp, sizeof(iketcp)) != (ssize_t)sizeof(iketcp)) {
			log_errno(st->st_logger, errno,
				  "TCP: send of IKE-in-TCP prefix through socket %d", fd);
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
		bool v6 = st->st_remote_endpoint.version == 6;
		struct xfrm_userpolicy_info policy_in = {
			.action = XFRM_POLICY_ALLOW,
			.sel.family = v6 ? AF_INET6 :AF_INET,
			.dir = XFRM_POLICY_IN,
		};
		struct xfrm_userpolicy_info policy_out = {
			.action = XFRM_POLICY_ALLOW,
			.sel.family = v6 ? AF_INET6 :AF_INET,
			.dir = XFRM_POLICY_OUT,
		};
		dbg("TCP: socket %d enabling \"espintcp\"", fd);
		if (setsockopt(fd, IPPROTO_TCP, TCP_ULP, "espintcp", sizeof("espintcp"))) {
			log_errno(st->st_logger, errno,
				  "setsockopt(SOL_TCP, TCP_ULP) failed in netlink_espintcp()");
			close(fd);
			return STF_FATAL;
		}
		if (setsockopt(fd, IPPROTO_IP, IP_XFRM_POLICY, &policy_in, sizeof(policy_in))) {
			log_errno(st->st_logger, errno,
				  "setsockopt(PPROTO_IP, IP_XFRM_POLICY(in)) failed in netlink_espintcp()");
			close(fd);
			return STF_FATAL;
		}
		if (setsockopt(fd, IPPROTO_IP, IP_XFRM_POLICY, &policy_out, sizeof(policy_out))) {
			log_errno(st->st_logger, errno,
				  "setsockopt(PPROTO_IP, IP_XFRM_POLICY(out)) failed in netlink_espintcp()");
			close(fd);
			return STF_FATAL;
		}
	}

	struct iface_endpoint *ifp = alloc_thing(struct iface_endpoint, "TCP iface initiator");
	ifp->io = &iketcp_iface_io;
	ifp->fd = fd;
	ifp->local_endpoint = local_endpoint;
	ifp->esp_encapsulation_enabled = true;
	ifp->float_nat_initiator = false;
	ifp->ip_dev = add_ref(st->st_interface->ip_dev);
	ifp->protocol = &ip_protocol_tcp;
	ifp->iketcp_remote_endpoint = st->st_remote_endpoint;
	ifp->iketcp_state = IKETCP_ENABLED;
	ifp->iketcp_server = false;

#if 0
	ifp->next = interfaces;
	interfaces = q;
#endif

	attach_fd_read_sensor(&ifp->iketcp_message_listener,
			      fd, process_iface_packet, ifp);

	st->st_interface = ifp; /* TCP: leaks old st_interface? */
	pstats_iketcp_started[ifp->iketcp_server]++;
	return STF_OK;
}

void accept_ike_in_tcp_cb(struct evconnlistener *evcon UNUSED,
			  int accepted_fd,
			  struct sockaddr *sockaddr, int sockaddr_len,
			  void *arg)
{
	struct iface_endpoint *bind_ifp = arg;

	struct logger global_logger = GLOBAL_LOGGER(null_fd); /* event-handler */
	struct logger *logger = &global_logger;

	ip_sockaddr sa = {
		.len = sockaddr_len,
		.sa.sa = *sockaddr,
	};
	ip_address remote_tcp_address;
	ip_port remote_tcp_port;
	err_t err = sockaddr_to_address_port(sa, &remote_tcp_address, &remote_tcp_port);
	if (err != NULL) {
		llog(RC_LOG, logger, "TCP: invalid remote address: %s", err);
		close(accepted_fd);
		return;
	}
	ip_endpoint remote_tcp_endpoint = endpoint_from_address_protocol_port(remote_tcp_address,
									      &ip_protocol_tcp,
									      remote_tcp_port);

	struct iface_endpoint *ifp = alloc_thing(struct iface_endpoint, "TCP iface responder");
	ifp->fd = accepted_fd;
	ifp->io = &iketcp_iface_io;
	ifp->protocol = &ip_protocol_tcp;
	ifp->esp_encapsulation_enabled = true;
	ifp->float_nat_initiator = false;
	ifp->ip_dev = add_ref(bind_ifp->ip_dev); /*TCP: refcnt */
	ifp->iketcp_remote_endpoint = remote_tcp_endpoint;
	ifp->local_endpoint = bind_ifp->local_endpoint;
	ifp->iketcp_state = IKETCP_ACCEPTED;
	ifp->iketcp_server = true;

	struct logger from_logger = logger_from(logger, &remote_tcp_endpoint);
	logger = &from_logger;
	llog_iketcp(RC_LOG, logger, ifp, "socket %d: accepted connection", ifp->fd);

	/* set up a timeout to kill the socket when nothing happens */
	fire_timer_photon_torpedo(&ifp->iketcp_timeout, iketcp_server_timeout,
				  ifp, deltatime(5)); /* TCP: how much? */
	attach_fd_read_sensor(&ifp->iketcp_message_listener, ifp->fd,
			      process_iface_packet, ifp);

	pstats_iketcp_started[ifp->iketcp_server]++;
}
