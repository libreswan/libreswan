/* udp packet processing, for libreswan
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
#include <sys/socket.h>		/* MSG_ERRQUEUE if defined */
#include <netinet/udp.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef MSG_ERRQUEUE
# include <netinet/in.h> 	/* for IP_RECVERR */
# include <linux/errqueue.h>
# include <poll.h>
#endif

#include "ip_address.h"

#include "defs.h"
#include "kernel.h"
#include "server.h"		/* for pluto_sock_bufsize */
#include "iface.h"
#include "demux.h"
#include "state_db.h"		/* for state_by_ike_spis() */
#include "log.h"
#include "ip_info.h"
#include "ip_sockaddr.h"
#include "nat_traversal.h"	/* for nat_traversal_enabled which seems like a broken idea */

static int bind_udp_socket(const struct iface_dev *ifd, ip_port port)
{
	const struct ip_info *type = address_type(&ifd->id_address);
	int fd = socket(type->af, SOCK_DGRAM, IPPROTO_UDP);
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
		LOG_ERRNO(errno, "setsockopt(SO_PRIORITY) in create_udp_socket()");
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
				LOG_ERRNO(errno, "setsockopt(SO_RCVBUFFORCE) in create_udp_socket()");
		}
		if (setsockopt(fd, SOL_SOCKET, so_snd,
			(const void *)&pluto_sock_bufsize, sizeof(pluto_sock_bufsize)) < 0) {
				LOG_ERRNO(errno, "setsockopt(SO_SNDBUFFORCE) in create_udp_socket()");
		}
	}

	/* To improve error reporting.  See ip(7). */
#ifdef MSG_ERRQUEUE
	if (pluto_sock_errqueue) {
		if (setsockopt(fd, SOL_IP, IP_RECVERR, (const void *)&on, sizeof(on)) < 0) {
			LOG_ERRNO(errno, "setsockopt IP_RECVERR in create_socket()");
			close(fd);
			return -1;
		}
		dbg("MSG_ERRQUEUE enabled on fd %d", fd);
	}
#endif

	/* With IPv6, there is no fragmentation after
	 * it leaves our interface.  PMTU discovery
	 * is mandatory but doesn't work well with IKE (why?).
	 * So we must set the IPV6_USE_MIN_MTU option.
	 * See draft-ietf-ipngwg-rfc2292bis-01.txt 11.1
	 */
#ifdef IPV6_USE_MIN_MTU /* YUCK: not always defined */
	if (type == &ipv6_info &&
	    setsockopt(fd, SOL_SOCKET, IPV6_USE_MIN_MTU,
		       (const void *)&on, sizeof(on)) < 0) {
		LOG_ERRNO(errno, "setsockopt IPV6_USE_MIN_MTU in create_udp_socket()");
		close(fd);
		return -1;
	}
#endif

	/*
	 * NETKEY requires us to poke an IPsec policy hole that allows
	 * IKE packets. This installs one IPsec policy per socket
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
	ip_endpoint if_endpoint = endpoint3(&ip_protocol_udp,
					    &ifd->id_address, port);
	ip_sockaddr if_sa = sockaddr_from_endpoint(&if_endpoint);
	if (bind(fd, &if_sa.sa.sa, if_sa.len) < 0) {
		endpoint_buf b;
		LOG_ERRNO(errno, "bind() for %s %s in process_raw_ifaces()",
			  ifd->id_rname, str_endpoint(&if_endpoint, &b));
		close(fd);
		return -1;
	}

	/* poke a hole for IKE messages in the IPsec layer */
	if (kernel_ops->exceptsocket != NULL) {
		if (!kernel_ops->exceptsocket(fd, AF_INET)) {
			close(fd);
			return -1;
		}
	}

	return fd;
}

static bool nat_traversal_espinudp(int sk, struct iface_dev *ifd)
{
	const char *fam = address_type(&ifd->id_address)->ip_name;
	dbg("NAT-Traversal: Trying sockopt style NAT-T");

	/*
	 * The SOL (aka socket level) is really the the protocol
	 * number which, for UDP, is always 17.  Linux provides a
	 * SOL_* macro, the others don't.
	 */
#if defined(SOL_UDP)
	const int sol_udp = SOL_UDP;
#elif defined(IPPROTO_UDP)
	const int sol_udp = IPPROTO_UDP;
#endif

	/*
	 * Was UDP_ESPINUDP (aka 100).  Linux/NetBSD have the value
	 * 100, FreeBSD has the value 1.
	 */
	const int sol_name = UDP_ENCAP;

	/*
	 * Was ESPINUDP_WITH_NON_ESP (aka 2) defined in "libreswan.h"
	 * which smells like something intended for the old KLIPS
	 * module. <netinet/udp.h> defines the below across linux and
	 * *BSD.
	 */
	const int sol_value = UDP_ENCAP_ESPINUDP;

	int r = setsockopt(sk, sol_udp, sol_name, &sol_value, sizeof(sol_value));
	if (r == -1) {
		dbg("NAT-Traversal: ESPINUDP(%d) setup failed for sockopt style NAT-T family %s (errno=%d)",
		    sol_value, fam, errno);
		/* all methods failed to detect NAT-T support */
		loglog(RC_LOG_SERIOUS,
		       "NAT-Traversal: ESPINUDP for this kernel not supported or not found for family %s",
		       fam);
		libreswan_log("NAT-Traversal is turned OFF due to lack of KERNEL support");
		nat_traversal_enabled = false;
		return false;
	}

	dbg("NAT-Traversal: ESPINUDP(%d) setup succeeded for sockopt style NAT-T family %s",
	    sol_value, fam);
	return true;
}

#ifdef MSG_ERRQUEUE
static bool check_msg_errqueue(const struct iface_port *ifp, short interest, const char *func);
#endif

static enum iface_status udp_read_packet(const struct iface_port *ifp,
					 struct iface_packet *packet)
{
#ifdef MSG_ERRQUEUE
	/*
	 * Even though select(2) says that there is a message, it
	 * might only be a MSG_ERRQUEUE message.  At least sometimes
	 * that leads to a hanging recvfrom.  To avoid what appears to
	 * be a kernel bug, check_msg_errqueue uses poll(2) and tells
	 * us if there is anything for us to read.
	 *
	 * This is early enough that teardown isn't required:
	 * just return on failure.
	 */
	if (pluto_sock_errqueue) {
		threadtime_t errqueue_start = threadtime_start();
		bool errqueue_ok = check_msg_errqueue(ifp, POLLIN, __func__);
		threadtime_stop(&errqueue_start, SOS_NOBODY,
				"%s() calling check_incoming_msg_errqueue()", __func__);
		if (!errqueue_ok) {
			return IFACE_IGNORE; /* no normal message to read */
		}
	}
#endif

	ip_sockaddr from = {
		.len = sizeof(from.sa),
	};
	packet->len = recvfrom(ifp->fd, packet->ptr, packet->len, /*flags*/ 0,
			       &from.sa.sa, &from.len);
	int packet_errno = errno; /* save!!! */

	/*
	 * Try to decode the from address.
	 *
	 * If that fails report some sense of error and then always
	 * give up.
	 */
	const char *from_ugh = sockaddr_to_endpoint(&ip_protocol_udp, &from,
						    &packet->sender);
	if (from_ugh != NULL) {
		if (packet->len >= 0) {
			/* technically it worked, but returned value was useless */
			plog_global("recvfrom on %s returned malformed source sockaddr: %s",
				    ifp->ip_dev->id_rname, from_ugh);
		} else if (from.len == sizeof(from) &&
			   all_zero((const void *)&from, sizeof(from)) &&
			   packet_errno == ECONNREFUSED) {
			/*
			 * Tone down scary message for vague event: We
			 * get "connection refused" in response to
			 * some datagram we sent, but we cannot tell
			 * which one.
			 */
			plog_global("recvfrom on %s failed; some IKE message we sent has been rejected with ECONNREFUSED (kernel supplied no details)",
				    ifp->ip_dev->id_rname);
		} else {
			/* if from==0, this prints "unspecified", not "undisclosed", oops */
			plog_global("recvfrom on %s failed; Pluto cannot decode source sockaddr in rejection: %s "PRI_ERRNO,
				    ifp->ip_dev->id_rname, from_ugh,
				    pri_errno(packet_errno));
		}
		return IFACE_IGNORE;
	}

	/*
	 * Managed to decode the from address; fudge up a logger so
	 * that it be used as log context prefix.
	 */

	struct logger logger = FROM_LOGGER(&packet->sender);

	if (packet->len < 0) {
		log_message(RC_LOG, &logger, "recvfrom on %s failed "PRI_ERRNO,
			    ifp->ip_dev->id_rname, pri_errno(packet_errno));
		return IFACE_IGNORE;
	}

	if (ifp->esp_encapsulation_enabled) {
		uint32_t non_esp;

		if (packet->len < (int)sizeof(uint32_t)) {
			log_message(RC_LOG, &logger, "too small packet (%zd)",
				    packet->len);
			return IFACE_IGNORE;
		}
		memcpy(&non_esp, packet->ptr, sizeof(uint32_t));
		if (non_esp != 0) {
			log_message(RC_LOG, &logger, "has no Non-ESP marker");
			return IFACE_IGNORE;
		}
		packet->ptr += sizeof(uint32_t);
		packet->len -= sizeof(uint32_t);
	}

	/* We think that in 2013 Feb, Apple iOS Racoon
	 * sometimes generates an extra useless buggy confusing
	 * Non ESP Marker
	 */
	{
		static const uint8_t non_ESP_marker[NON_ESP_MARKER_SIZE] =
			{ 0x00, };
		if (ifp->esp_encapsulation_enabled &&
		    packet->len >= NON_ESP_MARKER_SIZE &&
		    memeq(packet->ptr, non_ESP_marker,
			   NON_ESP_MARKER_SIZE)) {
			log_message(RC_LOG, &logger, "mangled with potential spurious non-esp marker");
			return IFACE_IGNORE;
		}
	}

	if (packet->len == 1 && packet->ptr[0] == 0xff) {
		/**
		 * NAT-T Keep-alive packets should be discared by kernel ESPinUDP
		 * layer. But bogus keep-alive packets (sent with a non-esp marker)
		 * can reach this point. Complain and discard them.
		 * Possibly too if the NAT mapping vanished on the initiator NAT gw ?
		 */
		endpoint_buf eb;
		dbg("NAT-T keep-alive (bogus ?) should not reach this point. Ignored. Sender: %s",
		    str_endpoint(&packet->sender, &eb)); /* sensitive? */
		return IFACE_IGNORE;
	}

	return IFACE_OK;
}

static ssize_t udp_write_packet(const struct iface_port *ifp,
				const void *ptr, size_t len,
				const ip_endpoint *remote_endpoint)
{
#ifdef MSG_ERRQUEUE
	if (pluto_sock_errqueue) {
		check_msg_errqueue(ifp, POLLOUT, __func__);
	}
#endif

	ip_sockaddr remote_sa = sockaddr_from_endpoint(remote_endpoint);
	return sendto(ifp->fd, ptr, len, 0, &remote_sa.sa.sa, remote_sa.len);
};

static void handle_udp_packet_cb(evutil_socket_t unused_fd UNUSED,
				 const short unused_event UNUSED,
				 void *arg)
{
	const struct iface_port *ifp = arg;
	handle_packet_cb(ifp);
}

static void udp_listen(struct iface_port *ifp,
		       struct logger *unused_logger UNUSED)
{
	if (ifp->udp_message_listener == NULL) {
		attach_fd_read_sensor(&ifp->udp_message_listener, ifp->fd,
				      handle_udp_packet_cb, ifp);
	}
}

static int udp_bind_iface_port(struct iface_dev *ifd, ip_port port,
			       bool esp_encapsulation_enabled)
{
	int fd = bind_udp_socket(ifd, port);
	if (fd < 0) {
		return -1;
	}
	if (esp_encapsulation_enabled &&
	    !nat_traversal_espinudp(fd, ifd)) {
		dbg("nat-traversal failed");
	}
	return fd;
}

static void udp_cleanup(struct iface_port *ifp)
{
	event_free(ifp->udp_message_listener);
	ifp->udp_message_listener = NULL;
}

const struct iface_io udp_iface_io = {
	.send_keepalive = true,
	.protocol = &ip_protocol_udp,
	.read_packet = udp_read_packet,
	.write_packet = udp_write_packet,
	.listen = udp_listen,
	.bind_iface_port = udp_bind_iface_port,
	.cleanup = udp_cleanup,
};

#ifdef MSG_ERRQUEUE

/* Process any message on the MSG_ERRQUEUE
 *
 * This information is generated because of the IP_RECVERR socket option.
 * The API is sparsely documented, and may be LINUX-only, and only on
 * fairly recent versions at that (hence the conditional compilation).
 *
 * - ip(7) describes IP_RECVERR
 * - recvmsg(2) describes MSG_ERRQUEUE
 * - readv(2) describes iovec
 * - cmsg(3) describes how to process auxiliary messages
 *
 * ??? we should link this message with one we've sent
 * so that the diagnostic can refer to that negotiation.
 *
 * ??? how long can the message be?
 *
 * ??? poll(2) has a very incomplete description of the POLL* events.
 * We assume that POLLIN, POLLOUT, and POLLERR are all we need to deal with
 * and that POLLERR will be on iff there is a MSG_ERRQUEUE message.
 *
 * We have to code around a couple of surprises:
 *
 * - Select can say that a socket is ready to read from, and
 *   yet a read will hang.  It turns out that a message available on the
 *   MSG_ERRQUEUE will cause select to say something is pending, but
 *   a normal read will hang.  poll(2) can tell when a MSG_ERRQUEUE
 *   message is pending.
 *
 *   This is dealt with by calling check_msg_errqueue after select
 *   has indicated that there is something to read, but before the
 *   read is performed.  check_msg_errqueue will return TRUE if there
 *   is something left to read.
 *
 * - A write to a socket may fail because there is a pending MSG_ERRQUEUE
 *   message, without there being anything wrong with the write.  This
 *   makes for confusing diagnostics.
 *
 *   To avoid this, we call check_msg_errqueue before a write.  True,
 *   there is a race condition (a MSG_ERRQUEUE message might arrive
 *   between the check and the write), but we should eliminate many
 *   of the problematic events.  To narrow the window, the poll(2)
 *   will await until an event happens (in the case or a write,
 *   POLLOUT; this should be benign for POLLIN).
 */

static struct state *find_likely_sender(size_t packet_len, uint8_t *buffer,
					size_t sizeof_buffer)
{
	if (packet_len > sizeof_buffer) {
		/*
		 * When the message is too big it is truncated.  But
		 * what about the returned packet length?  Force
		 * truncation.
		 */
		dbg("MSG_ERRQUEUE packet longer than %zu bytes; truncated", sizeof_buffer);
		packet_len = sizeof_buffer;
	}
	if (packet_len < sizeof(struct isakmp_hdr)) {
		dbg("MSG_ERRQUEUE packet is smaller than an IKE header");
		return NULL;
	}
	pb_stream packet_pbs;
	init_pbs(&packet_pbs, buffer, packet_len, __func__);
	struct isakmp_hdr hdr;
	if (!in_struct(&hdr, &raw_isakmp_hdr_desc, &packet_pbs, NULL)) {
		/*
		 * XXX:
		 *
		 * When in_struct() fails it logs an obscure and
		 * typically context free error (for instance, cur_*
		 * is unset when processing error messages); and
		 * there's no clean for this or calling code to pass
		 * in context.
		 *
		 * Fortunately, since the buffer is large enough to
		 * hold the header, there's really not much left that
		 * can trigger an error (everything in ISAKMP_HDR_DESC
		 * that involves validation has its type set to FT_NAT
		 * in RAW_ISAKMP_HDR_DESC).
		 */
		libreswan_log("MSG_ERRQUEUE packet IKE header is corrupt");
		return NULL;
	}
	enum ike_version ike_version = hdr_ike_version(&hdr);
	struct state *st;
	switch (ike_version) {
	case IKEv1:
		/* might work? */
		st = state_by_ike_spis(ike_version,
				       NULL/*ignore-clonedfrom*/,
				       NULL/*ignore-v1_msgid*/,
				       NULL/*ignore-role*/,
				       &hdr.isa_ike_spis,
				       NULL, NULL,
				       __func__);
		break;
	case IKEv2:
	{
		/*
		 * Since this end sent the message mapping IKE_I is
		 * straight forward.
		 */
		enum sa_role ike_role = (hdr.isa_flags & ISAKMP_FLAGS_v2_IKE_I) ? SA_INITIATOR : SA_RESPONDER;
		so_serial_t clonedfrom = SOS_NOBODY;
		st = state_by_ike_spis(ike_version,
				       &clonedfrom/*IKE*/,
				       NULL/*ignore-v1_msgid*/,
				       &ike_role,
				       &hdr.isa_ike_spis,
				       NULL, NULL,
				       __func__);
		break;
	}
	default:
		dbg("MSG_ERRQUEUE packet IKE header version unknown");
		return NULL;
	}
	if (st == NULL) {
		dbg("MSG_ERRQUEUE packet has no matching %s SA",
		    enum_name(&ike_version_names, ike_version));
		return NULL;
	}
	dbg("MSG_ERRQUEUE packet matches %s SA #%lu",
	    enum_name(&ike_version_names, ike_version),
	    st->st_serialno);
	return st;
}

static bool check_msg_errqueue(const struct iface_port *ifp, short interest, const char *before)
{
	struct pollfd pfd;
	int again_count = 0;

	pfd.fd = ifp->fd;
	pfd.events = interest | POLLPRI | POLLOUT;

	while (pfd.revents = 0,
	       poll(&pfd, 1, -1) > 0 && (pfd.revents & POLLERR)) {
		/*
		 * This buffer needs to be large enough to fit the IKE
		 * header so that the IKE SPIs and flags can be
		 * extracted and used to find the sender of the
		 * message.
		 *
		 * Give it double that.
		 */
		uint8_t buffer[sizeof(struct isakmp_hdr) * 2];

		ip_sockaddr from;

		ssize_t packet_len;

		struct msghdr emh;
		struct iovec eiov;
		union {
			/* force alignment (not documented as necessary) */
			struct cmsghdr ecms;

			/* how much space is enough? */
			unsigned char space[256];
		} ecms_buf;

		struct cmsghdr *cm;
		struct state *sender = NULL;

		zero(&from);

		emh.msg_name = &from.sa; /* ??? filled in? */
		emh.msg_namelen = sizeof(from.sa);
		emh.msg_iov = &eiov;
		emh.msg_iovlen = 1;
		emh.msg_control = &ecms_buf;
		emh.msg_controllen = sizeof(ecms_buf);
		emh.msg_flags = 0;

		eiov.iov_base = buffer; /* see readv(2) */
		eiov.iov_len = sizeof(buffer);

		packet_len = recvmsg(ifp->fd, &emh, MSG_ERRQUEUE);

		if (packet_len == -1) {
			if (errno == EAGAIN) {
				/* 32 is picked from thin air */
				if (again_count == 32) {
					loglog(RC_LOG_SERIOUS, "recvmsg(,, MSG_ERRQUEUE): given up reading socket after 32 EAGAIN errors");
					return FALSE;
				}
				again_count++;
				LOG_ERRNO(errno,
					  "recvmsg(,, MSG_ERRQUEUE) on %s failed (noticed before %s) (attempt %d)",
					  ifp->ip_dev->id_rname, before, again_count);
				continue;
			} else {
				LOG_ERRNO(errno,
					  "recvmsg(,, MSG_ERRQUEUE) on %s failed (noticed before %s)",
					  ifp->ip_dev->id_rname, before);
				break;
			}
		} else {
			/*
			 * Getting back a truncated IKE datagram a big
			 * deal - find_likely_sender() only needs the
			 * header when figuring out which state sent
			 * the packet.
			 */
			if (DBGP(DBG_BASE) && (emh.msg_flags & MSG_TRUNC)) {
				DBG_log("recvmsg(,, MSG_ERRQUEUE) on %s returned a truncated (IKE) datagram (MSG_TRUNC)",
					ifp->ip_dev->id_rname);
			}

			sender = find_likely_sender((size_t) packet_len,
						    buffer, sizeof(buffer));
		}

		if (DBGP(DBG_BASE)) {
			if (packet_len > 0) {
				DBG_log("rejected packet:");
				DBG_dump(NULL, buffer, packet_len);
			}
			DBG_log("control:");
			DBG_dump(NULL, emh.msg_control,
				 emh.msg_controllen);
		}

		/* ??? Andi Kleen <ak@suse.de> and misc documentation
		 * suggests that name will have the original destination
		 * of the packet.  We seem to see msg_namelen == 0.
		 * Andi says that this is a kernel bug and has fixed it.
		 * Perhaps in 2.2.18/2.4.0.
		 */
		passert(emh.msg_name == &from.sa);
		if (DBGP(DBG_BASE)) {
			DBG_log("name:");
			DBG_dump(NULL, emh.msg_name, emh.msg_namelen);
		}

		const struct ip_info *afi = aftoinfo(from.sa.sa.sa_family);
		/* usual case :-( */
		char fromstr[sizeof(" for message to ?") + sizeof(endpoint_buf)] = "";
		if (afi != NULL && emh.msg_namelen == afi->sockaddr_size) {
			ip_endpoint endpoint;
			/* this is a udp socket so presumably the endpoint is udp */
			if (sockaddr_to_endpoint(&ip_protocol_udp, &from, &endpoint) == NULL) {
				endpoint_buf ab;
				snprintf(fromstr, sizeof(fromstr),
					 " for message to %s",
					 str_sensitive_endpoint(&endpoint, &ab));
			}
		}

		for (cm = CMSG_FIRSTHDR(&emh)
		     ; cm != NULL
		     ; cm = CMSG_NXTHDR(&emh, cm)) {
			if (cm->cmsg_level == SOL_IP &&
			    cm->cmsg_type == IP_RECVERR) {
				/* ip(7) and recvmsg(2) specify:
				 * ee_origin is SO_EE_ORIGIN_ICMP for ICMP
				 *  or SO_EE_ORIGIN_LOCAL for locally generated errors.
				 * ee_type and ee_code are from the ICMP header.
				 * ee_info is the discovered MTU for EMSGSIZE errors
				 * ee_data is not used.
				 *
				 * ??? recvmsg(2) says "SOCK_EE_OFFENDER" but
				 * means "SO_EE_OFFENDER".  The OFFENDER is really
				 * the router that complained.  As such, the port
				 * is meaningless.
				 */

				/* ??? cmsg(3) claims that CMSG_DATA returns
				 * void *, but RFC 2292 and /usr/include/bits/socket.h
				 * say unsigned char *.  The manual is being fixed.
				 */
				struct sock_extended_err *ee =
					(void *)CMSG_DATA(cm);
				const char *offstr = "unspecified";
				char offstrspace[INET6_ADDRSTRLEN];
				char orname[50];

				if (cm->cmsg_len >
				    CMSG_LEN(sizeof(struct sock_extended_err)))
				{
					const struct sockaddr *offender =
						SO_EE_OFFENDER(ee);

					switch (offender->sa_family) {
					case AF_INET:
						offstr = inet_ntop(
							offender->sa_family,
							&((const
							   struct sockaddr_in *)
							  offender)->sin_addr,
							offstrspace,
							sizeof(offstrspace));
						break;
					case AF_INET6:
						offstr = inet_ntop(
							offender->sa_family,
							&((const
							   struct sockaddr_in6
							   *)offender)->sin6_addr,
							offstrspace,
							sizeof(offstrspace));
						break;
					default:
						offstr = "unknown";
						break;
					}
				}

				switch (ee->ee_origin) {
				case SO_EE_ORIGIN_NONE:
					snprintf(orname, sizeof(orname),
						 "none");
					break;
				case SO_EE_ORIGIN_LOCAL:
					snprintf(orname, sizeof(orname),
						 "local");
					break;
				case SO_EE_ORIGIN_ICMP:
					snprintf(orname, sizeof(orname),
						 "ICMP type %d code %d (not authenticated)",
						 ee->ee_type, ee->ee_code);
					break;
				case SO_EE_ORIGIN_ICMP6:
					snprintf(orname, sizeof(orname),
						 "ICMP6 type %d code %d (not authenticated)",
						 ee->ee_type, ee->ee_code);
					break;
				default:
					snprintf(orname, sizeof(orname),
						 "invalid origin %u",
						 ee->ee_origin);
					break;
				}

				enum stream logger;
				if (packet_len == 1 && buffer[0] == 0xff &&
				    (cur_debugging & DBG_BASE) == 0) {
					/*
					 * don't log NAT-T keepalive related errors unless NATT debug is
					 * enabled
					 */
					logger = NO_STREAM;
				} else if (sender != NULL && sender->st_connection != NULL &&
					   LDISJOINT(sender->st_connection->policy, POLICY_OPPORTUNISTIC)) {
					/*
					 * The sender is known and
					 * this isn't an opportunistic
					 * connection, so log.
					 *
					 * XXX: originally this path
					 * was taken unconditionally
					 * but with opportunistic that
					 * got too verbose.  Is there
					 * a global opportunistic
					 * disabled test so that
					 * behaviour can be restored?
					 *
					 * HACK: So that the logging
					 * system doesn't accidentally
					 * include a prefix for the
					 * wrong state et.al., switch
					 * out everything but SENDER.
					 * Better would be to make the
					 * state/connection an
					 * explicit parameter to the
					 * logging system?
					 */
					logger = ALL_STREAMS;
				} else if (DBGP(DBG_BASE)) {
					/*
					 * Since this output is forced
					 * using DBGP, report the
					 * error using debug-log.
					 *
					 * A NULL SENDER here doesn't
					 * matter - it just gets
					 * ignored.
					 */
					logger = DEBUG_STREAM;
				} else {
					logger = NO_STREAM;
				}
				if (logger != NO_STREAM) {
					endpoint_buf epb;
					struct logger log = (sender != NULL ? *(sender->st_logger) :
							     GLOBAL_LOGGER(null_fd));
					log_message(logger, &log,
						    "ERROR: asynchronous network error report on %s (%s)%s, complainant %s: %s [errno %" PRIu32 ", origin %s]",
						    ifp->ip_dev->id_rname,
						    str_endpoint(&ifp->local_endpoint, &epb),
						    fromstr,
						    offstr,
						    strerror(ee->ee_errno),
						    ee->ee_errno, orname);
				}
			} else if (cm->cmsg_level == SOL_IP &&
				   cm->cmsg_type == IP_PKTINFO) {
				/* do nothing */
			} else {
				/* .cmsg_len is a kernel_size_t(!), but the value
				 * certainly ought to fit in an unsigned long.
				 */
				libreswan_log(
					"unknown cmsg: level %d, type %d, len %zu",
					cm->cmsg_level, cm->cmsg_type,
					 cm->cmsg_len);
			}
		}
	}
	return (pfd.revents & interest) != 0;
}

#endif /* MSG_ERRQUEUE */
