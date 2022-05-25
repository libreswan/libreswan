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
#include "log.h"
#include "ip_info.h"
#include "pluto_stats.h"

/* work around weird combo's of glibc and kernel header conflicts */
#if defined(linux)
# ifndef GLIBC_KERN_FLIP_HEADERS
#  include "linux/xfrm.h" /* local (if configured) or system copy */
#  include "libreswan.h"
# else
#  include "libreswan.h"
#  include "linux/xfrm.h" /* local (if configured) or system copy */
# endif
#endif

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
	LSWDBGP(DBG_BASE, buf) {
		jam_iketcp_prefix(buf, ifp);
		va_list ap;
		va_start(ap, msg);
		jam_va_list(buf, msg, ap);
		va_end(ap);
	}
}

static void llog_iketcp(lset_t rc_flags, struct logger *logger,
			const struct iface_endpoint *ifp, int error,
			const char *msg, ...) PRINTF_LIKE(5);

void llog_iketcp(lset_t rc_flags, struct logger *logger,
		 const struct iface_endpoint *ifp, int error,
		 const char *msg, ...)
{
	LLOG_JAMBUF(rc_flags, logger, buf) {
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
			llog_iketcp(RC_LOG_SERIOUS, logger, (*ifp), e,
				    "error reading 'IKETCP' prefix; closing socket: ");
			iketcp_shutdown(ifp); /* i.e., delete IFP */
			return NULL;
		}

		if (len != sizeof(buf)) {
			llog_iketcp(RC_LOG_SERIOUS, logger, (*ifp), /*no-error*/0,
				    "reading 'IKETCP' prefix returned %zd bytes but expecting %zu; closing socket",
				    len, sizeof(buf));
			iketcp_shutdown(ifp); /* i.e., delete IFP */
			return NULL;
		}

		dbg_iketcp(*ifp, "verifying IKETCP prefix");
		if (!memeq(buf, iketcp, len)) {
			/* discard this tcp connection */
			llog_iketcp(RC_LOG_SERIOUS, logger, (*ifp), /*no-error*/0,
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
#if defined(linux)
			int af = address_type(&(*ifp)->ip_dev->id_address)->af;
			struct xfrm_userpolicy_info policy_in = {
				.action = XFRM_POLICY_ALLOW,
				.sel.family = af,
				.dir = XFRM_POLICY_IN,
			};
			if (setsockopt((*ifp)->fd, IPPROTO_IP, IP_XFRM_POLICY, &policy_in, sizeof(policy_in))) {
				int e = errno;
				llog_iketcp(RC_LOG, logger, *ifp, e,
					    "closing socket; setsockopt(%d, SOL_TCP, IP_XFRM_POLICY, \"policy_in\") failed: ",
					    (*ifp)->fd);
				iketcp_shutdown(ifp); /* i.e., delete IFP */
				return NULL;
			}
			struct xfrm_userpolicy_info policy_out = {
				.action = XFRM_POLICY_ALLOW,
				.sel.family = af,
				.dir = XFRM_POLICY_OUT,
			};
			if (setsockopt((*ifp)->fd, IPPROTO_IP, IP_XFRM_POLICY, &policy_out, sizeof(policy_out))) {
				int e = errno;
				llog_iketcp(RC_LOG, logger, *ifp, e,
					    "closing socket; setsockopt(%d, SOL_TCP, IP_XFRM_POLICY, \"policy_out\") failed: ",
					    (*ifp)->fd);
				iketcp_shutdown(ifp); /* i.e., delete IFP */
				return NULL;
			}
#endif
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
				   const void *ptr, size_t len,
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
			llog_iketcp(RC_LOG_SERIOUS, logger, ifp, e,
				    "fcntl(%d, F_GETFL, 0) failed: ", ifp->fd);
		}
		if (fcntl(ifp->fd, F_SETFL, flags & ~O_NONBLOCK) == -1) {
			int e = errno;
			llog_iketcp(RC_LOG_SERIOUS, logger, ifp, e,
				    "fcntl(%d, F_SETFL, 0%o) failed,: ",
				    ifp->fd, flags);
		}
	}
	ssize_t wlen = write(ifp->fd, ptr, len);
	dbg_iketcp(ifp, "wrote %zd of %zu bytes", wlen, len);
	if (impair.tcp_use_blocking_write && flags >= 0) {
		llog_iketcp(RC_LOG, logger, ifp, /*no-error*/0,
			    "IMPAIR: restoring flags 0%o after write", flags);
		if (fcntl(ifp->fd, F_SETFL, flags) == -1) {
			int e = errno;
			llog_iketcp(RC_LOG_SERIOUS, logger, ifp, e,
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

static void iketcp_server_timeout(void *arg, struct logger *global_logger)
{
	struct iface_endpoint *ifp = arg;
	/* build up the logger using the stack */
	struct logger from_logger = logger_from(global_logger, &ifp->iketcp_remote_endpoint);
	struct logger *logger = &from_logger;
	llog_iketcp(RC_LOG, logger, ifp, /*no-error*/0,
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

static int iketcp_bind_iface_endpoint(struct iface_dev *ifd, ip_port port,
				      struct logger *logger)
{
	const ip_protocol *protocol = &ip_protocol_tcp;
	ip_endpoint endpoint = endpoint_from_address_protocol_port(ifd->id_address, protocol, port);
#define BIND_ERROR(MSG, ...)						\
	{								\
		int e = errno;						\
		endpoint_buf eb;					\
		llog_error(logger, e,					\
			   "bind %s TCP endpoint %s failed, "MSG,	\
			   ifd->id_rname, str_endpoint(&endpoint, &eb),	\
			   ##__VA_ARGS__);				\
	}

	const struct ip_info *type = address_type(&ifd->id_address);
	int fd = socket(type->pf, SOCK_STREAM, protocol->ipproto);
	if (fd < 0) {
		BIND_ERROR("socket(%s, SOCK_STREAM, %s)",
			   type->pf_name, protocol->name);
		return -1;
	}

	int fcntl_flags;
	static const int on = true;     /* by-reference parameter; constant, we hope */

	/* Set socket Nonblocking */
	if ((fcntl_flags = fcntl(fd, F_GETFL)) >= 0) {
		if (!(fcntl_flags & O_NONBLOCK)) {
			fcntl_flags |= O_NONBLOCK;
			if (fcntl(fd, F_SETFL, fcntl_flags) == -1) {
				BIND_ERROR("fcntl(F_SETFL, O_NONBLOCK)");
				/* stumble on */
			}
		}
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		BIND_ERROR("fcntl(F_SETFD, FD_CLOEXEC)");
		close(fd);
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		       (const void *)&on, sizeof(on)) < 0) {
		BIND_ERROR("setsockopt(SOL_SOCKET, SO_REUSEADDR)");
		close(fd);
		return -1;
	}

#ifdef SO_PRIORITY
	static const int so_prio = 6; /* rumored maximum priority, might be 7 on linux? */
	if (setsockopt(fd, SOL_SOCKET, SO_PRIORITY, (const void *)&so_prio,
		       sizeof(so_prio)) < 0) {
		BIND_ERROR("setsockopt(SOL_SOCKET, SO_PRIORITY)");
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
			BIND_ERROR("setsockopt(SOL_SOCKET, SO_RCVBUFFORCE)");
		}
		if (setsockopt(fd, SOL_SOCKET, so_snd, (const void *)&pluto_sock_bufsize,
			       sizeof(pluto_sock_bufsize)) < 0) {
			BIND_ERROR("setsockopt(SOL_SOCKET, SO_SNDBUFFORCE)");
		}
	}

	/* To improve error reporting.  See ip(7). */
#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
	if (pluto_sock_errqueue) {
		if (setsockopt(fd, SOL_IP, IP_RECVERR, (const void *)&on, sizeof(on)) < 0) {
			BIND_ERROR("setsockopt(SOL_IP, IP_RECVERR)");
			close(fd);
			return -1;
		}
	}
#endif

	/*
	 * With IPv6, there is no fragmentation after it leaves our
	 * interface.  PMTU discovery is mandatory but doesn't work
	 * well with IKE (why?).  So we must set the IPV6_USE_MIN_MTU
	 * option.  See draft-ietf-ipngwg-rfc2292bis-01.txt 11.1
	 */
#ifdef IPV6_USE_MIN_MTU /* YUCK: not always defined */
	if (address_type(&ifd->id_address) == &ipv6_info &&
	    setsockopt(fd, IPPROTO_IPV6, IPV6_USE_MIN_MTU,
		       (const void *)&on, sizeof(on)) < 0) {
		BIND_ERROR("setsockopt(IPPROTO_IPV6, IPV6_USE_MIN_MTU)");
		close(fd);
		return -1;
	}
#endif

	/*
	 * NETKEY requires us to poke an IPsec policy hole that allows
	 * IKE packets, unlike KLIPS which implicitly always allows
	 * plaintext IKE.  This installs one IPsec policy per socket
	 * but this function is called for each: IPv4 port 500 and
	 * 4500 IPv6 port 500.
	 */
	if (kernel_ops->poke_ipsec_policy_hole != NULL &&
	    !kernel_ops->poke_ipsec_policy_hole(fd, type, logger)) {
		/* already logged */
		close(fd);
		return -1;
	}

	ip_sockaddr if_sa = sockaddr_from_endpoint(endpoint);
	if (bind(fd, &if_sa.sa.sa, if_sa.len) < 0) {
		BIND_ERROR("bind()");
		close(fd);
		return -1;
	}

	/* poke a hole for IKE messages in the IPsec layer */
	if (kernel_ops->exceptsocket != NULL) {
		if (!kernel_ops->exceptsocket(fd, AF_INET, logger)) {
			/* already logged */
			close(fd);
			return -1;
		}
	}

	return fd;
#undef BIND_ERROR
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
 * Open a TCP socket connected to st_remote_endpoint.
 *
 * Since this end is opening the socket, this end is responsible for
 * sending the IKE-in-TCP magic word.
 */

struct iface_endpoint *open_tcp_endpoint(struct iface_dev *local_dev,
					 ip_endpoint remote_endpoint,
					 struct logger *logger)
{
	dbg("TCP: opening socket");
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		llog_error(logger, errno, "TCP: socket() failed");
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

	dbg("TCP: socket %d: connecting to other end", fd);
	ip_sockaddr remote_sockaddr = sockaddr_from_endpoint(remote_endpoint);
	if (connect(fd, &remote_sockaddr.sa.sa, remote_sockaddr.len) < 0) {
		llog_error(logger, errno, "TCP: connect(%d) failed", fd);
		close(fd);
		return NULL;
	}

	dbg("TCP: socket %d: extracting local randomly assigned port", fd);
	ip_endpoint local_endpoint;
	{
		/* port gets assigned randomly */
		ip_sockaddr local_sockaddr = {
			.len = sizeof(local_sockaddr.sa),
		};
		if (getsockname(fd, &local_sockaddr.sa.sa, &local_sockaddr.len) < 0) {
			llog_error(logger, errno, "TCP: socket %d: failed to get local TCP address from socket", fd);
			close(fd);
			return NULL;
		}
		ip_address local_address;
		ip_port local_port;
		err_t err = sockaddr_to_address_port(&local_sockaddr.sa.sa, local_sockaddr.len,
						     &local_address, &local_port);
		if (err != NULL) {
			llog(RC_LOG, logger, "TCP: socket %d: failed to get local TCP address from socket, %s", fd, err);
			close(fd);
			return NULL;
		}
		local_endpoint = endpoint_from_address_protocol_port(local_address, &ip_protocol_tcp, local_port);
	}

	dbg("TCP: socket %d: making things non-blocking", fd);
	evutil_make_socket_nonblocking(fd); /* TCP: ignore errors? */
	evutil_make_socket_closeonexec(fd); /* TCP: ignore errors? */

	/* Socket is connected, send the IKETCP stream */

	{
		dbg("TCP: socket %d: sending IKE-in-TCP prefix", fd);
		const uint8_t iketcp[] = IKE_IN_TCP_PREFIX;
		if (write(fd, iketcp, sizeof(iketcp)) != (ssize_t)sizeof(iketcp)) {
			llog_error(logger, errno,
				   "TCP: socket %d: send of IKE-in-TCP prefix failed", fd);
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
#if defined(linux)
	} else {
		int af = endpoint_type(&remote_endpoint)->af;
		struct xfrm_userpolicy_info policy_in = {
			.action = XFRM_POLICY_ALLOW,
			.sel.family = af,
			.dir = XFRM_POLICY_IN,
		};
		struct xfrm_userpolicy_info policy_out = {
			.action = XFRM_POLICY_ALLOW,
			.sel.family = af,
			.dir = XFRM_POLICY_OUT,
		};
		dbg("TCP: socket %d: enabling \"espintcp\"", fd);
		if (setsockopt(fd, IPPROTO_TCP, TCP_ULP, "espintcp", sizeof("espintcp"))) {
			llog_error(logger, errno,
				   "setsockopt(SOL_TCP, TCP_ULP) failed in netlink_espintcp()");
			close(fd);
			return NULL;
		}
		if (setsockopt(fd, IPPROTO_IP, IP_XFRM_POLICY, &policy_in, sizeof(policy_in))) {
			llog_error(logger, errno,
				   "setsockopt(PPROTO_IP, IP_XFRM_POLICY(in)) failed in netlink_espintcp()");
			close(fd);
			return NULL;
		}
		if (setsockopt(fd, IPPROTO_IP, IP_XFRM_POLICY, &policy_out, sizeof(policy_out))) {
			llog_error(logger, errno,
				   "setsockopt(PPROTO_IP, IP_XFRM_POLICY(out)) failed in netlink_espintcp()");
			close(fd);
			return NULL;
		}
#endif
	}

	struct iface_endpoint *ifp =
		alloc_iface_endpoint(fd, local_dev, &iketcp_iface_io,
				     /*esp_encapsulation_enabled*/true,
				     /*float_nat_initiator*/false,
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
	 * XXX: caller, if it wants to save the pointer (which
	 * presumably it does), must addref.
	 */
	return ifp;
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
				     /*esp_encapsulation_enabled*/true,
				     /*float_nat_initiator*/false,
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
