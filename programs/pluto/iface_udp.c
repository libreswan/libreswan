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
#include "iface.h"
#include "demux.h"
#include "state_db.h"		/* for state_by_ike_spis() */
#include "log.h"
#include "log_limiter.h"
#include "ip_info.h"
#include "ip_sockaddr.h"

#ifdef UDP_ENCAP
static int espinudp_enable_esp_encapsulation(int fd, struct logger *logger)
{
	ldbg(logger, "NAT-Traversal: Trying sockopt style NAT-T");

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

	int r = setsockopt(fd, sol_udp, sol_name, &sol_value, sizeof(sol_value));
	if (r == -1) {
		int error = errno; /* save it */
		ldbg(logger, "NAT-Traversal: ESPINUDP(%d) setup failed for sockopt style NAT-T family (errno=%d)",
		     sol_value, error);
		return error;
	}

	ldbg(logger, "NAT-Traversal: ESPINUDP(%d) setup succeeded for sockopt style NAT-T family",
	     sol_value);
	return 0;
}
#endif /* ifdef UDP_ENCAP */

#ifdef MSG_ERRQUEUE
static bool check_msg_errqueue(const struct iface_endpoint *ifp,
			       short interest, const char *func,
			       struct logger *logger);
#endif

static struct msg_digest * udp_read_packet(struct iface_endpoint **ifpp,
					   struct logger *logger)
{
	struct iface_endpoint *ifp = *ifpp; /*never closed? */
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
	if (pluto_ike_socket_errqueue) {
		threadtime_t errqueue_start = threadtime_start();
		bool errqueue_ok = check_msg_errqueue(ifp, POLLIN, __func__,
						      logger);
		threadtime_stop(&errqueue_start, SOS_NOBODY,
				"%s() calling check_incoming_msg_errqueue()", __func__);
		if (!errqueue_ok) {
			return false; /* no normal message to read */
		}
	}
#endif

	/*
	 * COVERITY reports an overflow because FROM.LEN (aka
	 * sizeof(FROM.SA)) > sizeof(from.sa.sa).  That's the point.
	 * The FROM.SA union is big enough to hold sockaddr,
	 * sockaddr_in and sockaddr_in6.
	 */
	ip_sockaddr from = {
		.len = sizeof(from.sa),
	};
	uint8_t bigbuffer[MAX_INPUT_UDP_SIZE]; /* ??? this buffer seems *way* too big */
	ssize_t packet_len = recvfrom(ifp->fd, bigbuffer, sizeof(bigbuffer),
				      /*flags*/ 0, &from.sa.sa, &from.len);
	uint8_t *packet_ptr = bigbuffer;
	int packet_errno = errno; /* save!!! */

	/*
	 * Try to decode the from address.
	 *
	 * If that fails report some sense of error and then always
	 * give up.
	 */
	ip_address sender_udp_address;
	ip_port sender_udp_port;
	const char *from_ugh = sockaddr_to_address_port(&from.sa.sa, from.len,
							&sender_udp_address, &sender_udp_port);
	if (from_ugh != NULL) {
		if (packet_len >= 0) {
			/* technically it worked, but returned value was useless */
			llog(RC_LOG, logger,
			     "recvfrom on %s returned malformed source sockaddr: %s",
			     ifp->ip_dev->real_device_name, from_ugh);
		} else if (from.len == sizeof(from) &&
			   all_zero((const void *)&from, sizeof(from)) &&
			   packet_errno == ECONNREFUSED) {
			/*
			 * Tone down scary message for vague event: We
			 * get "connection refused" in response to
			 * some datagram we sent, but we cannot tell
			 * which one.
			 */
			llog(RC_LOG, logger,
			     "recvfrom on %s failed; some IKE message we sent has been rejected with ECONNREFUSED (kernel supplied no details)",
			     ifp->ip_dev->real_device_name);
		} else {
			/* if from==0, this prints "unspecified", not "undisclosed", oops */
			llog_errno(RC_LOG, logger, packet_errno,
				   "recvfrom on %s failed; cannot decode source sockaddr in rejection: %s: ",
				   ifp->ip_dev->real_device_name, from_ugh);
		}
		return false;
	}

	ip_endpoint sender = endpoint_from_address_protocol_port(sender_udp_address,
								 &ip_protocol_udp,
								 sender_udp_port);

	/*
	 * Managed to decode the from address; change LOGGER to an
	 * on-stack "from" logger so that messages can include more
	 * context.
	 */
	struct logger from_logger = logger_from(logger, &sender);
	logger = &from_logger;

	if (packet_len < 0) {
		llog_errno(RC_LOG, logger, packet_errno,
			   "recvfrom on %s failed: ", ifp->ip_dev->real_device_name);
		return NULL;
	}

	/*
	 * If the socket is in encapsulation mode (where each packet
	 * is prefixed either by 0 (IKE) or non-zero (ESP/AH SPI)
	 * marker.  Check for and strip away the marker.
	 */
	if (ifp->esp_encapsulation_enabled) {
		uint32_t non_esp;

		if (packet_len < (int)sizeof(uint32_t)) {
			llog(RC_LOG, logger, "too small packet (%zd)",
			     packet_len);
			return NULL;
		}
		memcpy(&non_esp, packet_ptr, sizeof(uint32_t));
		if (non_esp != 0) {
			llog(RC_LOG, logger, "has no Non-ESP marker");
			return NULL;
		}
		packet_ptr += sizeof(uint32_t);
		packet_len -= sizeof(uint32_t);
	}

	/*
	 * We think that in 2013 Feb, Apple iOS Racoon sometimes
	 * generates an extra useless buggy confusing Non ESP Marker.
	 */
	{
		static const uint8_t non_ESP_marker[NON_ESP_MARKER_SIZE] = { 0x00, };
		if (ifp->esp_encapsulation_enabled &&
		    packet_len >= NON_ESP_MARKER_SIZE &&
		    memeq(packet_ptr, non_ESP_marker, NON_ESP_MARKER_SIZE)) {
			llog(RC_LOG, logger,
			     "mangled with potential spurious non-esp marker");
			return NULL;
		}
	}

	if (packet_len == 1 && packet_ptr[0] == 0xff) {
		/**
		 * NAT-T Keep-alive packets should be discarded by kernel ESPinUDP
		 * layer. But bogus keep-alive packets (sent with a non-esp marker)
		 * can reach this point. Complain and discard them.
		 * Possibly too if the NAT mapping vanished on the initiator NAT gw ?
		 */
		endpoint_buf eb;
		dbg("NAT-T keep-alive (bogus ?) should not reach this point. Ignored. Sender: %s",
		    str_endpoint(&sender, &eb)); /* sensitive? */
		return NULL;
	}

	struct msg_digest *md = alloc_md(ifp, &sender, packet_ptr, packet_len, HERE);
	return md;
}

#ifdef USE_XFRM_INTERFACE
static uint32_t set_mark_out(const struct logger *logger, uint32_t mark, int fd)
{
	uint32_t old_mark;

	socklen_t len = sizeof(old_mark);

	if (getsockopt(fd, SOL_SOCKET, SO_MARK, &old_mark, &len) < 0) {
		llog_errno(RC_LOG, logger, errno, "getsockopt(SO_MSRK) in set_mark_out()");
		return 0;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_MARK,
				(const void *)&mark, sizeof(mark)) < 0)
		llog_errno(RC_LOG, logger, errno, "setsockopt(SO_MSRK) new in set_mark_out()");

	return old_mark;
}
#endif

static ssize_t udp_write_packet(const struct iface_endpoint *ifp,
				shunk_t packet,
				const ip_endpoint *remote_endpoint,
				struct logger *logger /*possibly*/UNUSED)
{
#ifdef MSG_ERRQUEUE
	if (pluto_ike_socket_errqueue) {
		check_msg_errqueue(ifp, POLLOUT, __func__, logger);
	}
#endif

	ip_sockaddr remote_sa = sockaddr_from_endpoint(*remote_endpoint);

#ifdef USE_XFRM_INTERFACE
	uint32_t old_mark = 0;
	if (remote_endpoint->mark_out > 0)
		old_mark = set_mark_out(logger, remote_endpoint->mark_out, ifp->fd);
#endif

	ssize_t ret = sendto(ifp->fd, packet.ptr, packet.len, 0, &remote_sa.sa.sa, remote_sa.len);

#ifdef USE_XFRM_INTERFACE
	if (remote_endpoint->mark_out > 0)
		set_mark_out(logger, old_mark, ifp->fd);
#endif

	return ret;
};

static void udp_listen(struct iface_endpoint *ifp,
		       struct logger *unused_logger UNUSED)
{
	if (ifp->udp.read_listener == NULL) {
		attach_fd_read_listener(&ifp->udp.read_listener, ifp->fd,
					"udp", process_iface_packet, ifp);
	}
}

static void udp_cleanup(struct iface_endpoint *ifp)
{
	detach_fd_read_listener(&ifp->udp.read_listener);
}

const struct iface_io udp_iface_io = {
	.send_keepalive = true,
	.socket = {
		.type = SOCK_DGRAM,
		.type_name = "SOCK_DGRAM",
	},
	.protocol = &ip_protocol_udp,
	.read_packet = udp_read_packet,
	.write_packet = udp_write_packet,
	.listen = udp_listen,
#ifdef UDP_ENCAP
	.enable_esp_encapsulation = espinudp_enable_esp_encapsulation,
#endif
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
 *   This is dealt with by calling check_msg_errqueue after select has
 *   indicated that there is something to read, but before the read is
 *   performed.  check_msg_errqueue will return "true" if there is
 *   something left to read.
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

	static const uint8_t non_ESP_marker[NON_ESP_MARKER_SIZE] = { 0x00, };
	if (packet_len >= sizeof(non_ESP_marker) &&
	    memeq(buffer, non_ESP_marker, sizeof(non_ESP_marker))) {
		buffer += sizeof(non_ESP_marker);
		packet_len -= sizeof(non_ESP_marker);
		sizeof_buffer -= sizeof(non_ESP_marker);
		dbg("MSG_ERRQUEUE packet has leading ESP:0 marker - discarded");
	}

	if (packet_len < sizeof(struct isakmp_hdr)) {
		dbg("MSG_ERRQUEUE packet is smaller than an IKE header");
		return NULL;
	}

	shunk_t packet = shunk2(buffer, packet_len);
	struct pbs_in packet_pbs = pbs_in_from_shunk(packet, __func__);
	struct isakmp_hdr hdr;
	diag_t d = pbs_in_struct(&packet_pbs, &raw_isakmp_hdr_desc,
				 &hdr, sizeof(hdr), NULL);
	if (d != NULL) {
		/*
		 * XXX: Only thing interesting is that there was an
		 * error, toss the message.
		 */
		pfree_diag(&d);
		return NULL;
	}

	const enum ike_version ike_version = hdr_ike_version(&hdr);
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
		name_buf ib;
		dbg("MSG_ERRQUEUE packet has no matching %s SA",
		    str_enum_long(&ike_version_names, ike_version, &ib));
		return NULL;
	}

	ldbg(st->logger, "MSG_ERRQUEUE packet matches %s SA "PRI_SO"",
	     st->st_connection->config->ike_info->version_name,
	     pri_so(st->st_serialno));
	return st;
}

static bool check_msg_errqueue(const struct iface_endpoint *ifp, short interest,
			       const char *before,
			       struct logger *logger)
{
	struct pollfd pfd;
	int again_count = 0;

	pfd.fd = ifp->fd;
	pfd.events = interest | POLLPRI | POLLOUT;

	while (/*clear .revents*/ pfd.revents = 0,
		/*poll .revents*/ poll(&pfd, 1, -1) > 0 &&
		/*test .revents*/ (pfd.revents & POLLERR)) {

		/*
		 * A single IOV (I/O Vector) pointing at a buffer for
		 * storing the message fragment.
		 *
		 * It needs to be large enough to fit the IKE header +
		 * leading ESP:0 prefix so that the IKE SPIs and flags
		 * can be extracted and used to find the sender of the
		 * message.
		 *
		 * Give it double that.
		 */
		uint8_t buffer[sizeof(struct isakmp_hdr) * 2];
		struct iovec eiov[1] = {
			{
				.iov_base = buffer, /* see readv(2) */
				.iov_len = sizeof(buffer),
			},
		};

		union {
			/* force alignment (not documented as necessary) */
			struct cmsghdr ecms;

			/* how much space is enough? */
			unsigned char space[256];
		} ecms_buf;

		ip_sockaddr from = { 0, };
		struct msghdr emh = {
			.msg_name = &from.sa, /* ??? filled in? */
			.msg_namelen = sizeof(from.sa),
			.msg_iov = eiov,
			.msg_iovlen = elemsof(eiov),
			.msg_control = &ecms_buf,
			.msg_controllen = sizeof(ecms_buf),
			.msg_flags = 0,
		};

		ssize_t packet_len = recvmsg(ifp->fd, &emh, MSG_ERRQUEUE);

		if (packet_len == -1) {
			/* XXX: all paths either break. return, or continue */
			if (errno == EAGAIN) {
				/* 32 is picked from thin air */
				if (again_count == 32) {
					limited_llog(logger, MSG_ERRQUEUE_LOG_LIMITER,
						    "recvmsg(,, MSG_ERRQUEUE): given up reading socket after 32 EAGAIN errors");
					return false;
				}
				again_count++;
				llog_error(logger, errno,
					   "recvmsg(,, MSG_ERRQUEUE) on %s failed (noticed before %s) (attempt %d)",
					   ifp->ip_dev->real_device_name, before, again_count);
				continue;
			}
			llog_error(logger, errno,
				   "recvmsg(,, MSG_ERRQUEUE) on %s failed (noticed before %s)",
				   ifp->ip_dev->real_device_name, before);
			break;
		}
		passert(packet_len >= 0);

		/*
		 * Getting back a truncated IKE datagram isn't a big
		 * deal - find_likely_sender() only needs the header
		 * when figuring out which state sent the packet.
		 */
		if (LDBGP(DBG_BASE, logger) && (emh.msg_flags & MSG_TRUNC)) {
			LDBG_log(logger, "recvmsg(,, MSG_ERRQUEUE) on %s returned a truncated (IKE) datagram (MSG_TRUNC)",
				 ifp->ip_dev->real_device_name);
		}

		if (LDBGP(DBG_BASE, logger)) {
			if (packet_len > 0) {
				LDBG_log(logger, "rejected packet:");
				LDBG_dump(logger, buffer, packet_len);
			}
			LDBG_log(logger, "control:");
			LDBG_dump(logger, emh.msg_control,
				  emh.msg_controllen);
		}

		struct state *sender = find_likely_sender((size_t) packet_len,
							  buffer, sizeof(buffer));

		/* ??? Andi Kleen <ak@suse.de> and misc documentation
		 * suggests that name will have the original destination
		 * of the packet.  We seem to see msg_namelen == 0.
		 * Andi says that this is a kernel bug and has fixed it.
		 * Perhaps in 2.2.18/2.4.0.
		 */
		passert(emh.msg_name == &from.sa);
		if (LDBGP(DBG_BASE, logger)) {
			LDBG_log(logger, "name:");
			LDBG_dump(logger, emh.msg_name, emh.msg_namelen);
		}

		const struct ip_info *afi = aftoinfo(from.sa.sa.sa_family);
		/* usual case :-( */
		char fromstr[sizeof(" for message to ?") + sizeof(endpoint_buf)] = "";
		if (afi != NULL && emh.msg_namelen == afi->sockaddr_size) {
			ip_address sender_udp_address;
			ip_port sender_udp_port;
			if (sockaddr_to_address_port(&from.sa.sa, from.len,
						     &sender_udp_address, &sender_udp_port) == NULL) {
				/* this is a udp socket so presumably the endpoint is udp */
				endpoint_buf ab;
				ip_endpoint endpoint = endpoint_from_address_protocol_port(sender_udp_address,
											   &ip_protocol_udp,
											   sender_udp_port);
				snprintf(fromstr, sizeof(fromstr),
					 " for message to %s",
					 str_endpoint_sensitive(&endpoint, &ab));
			}
		}

		for (struct cmsghdr *cm = CMSG_FIRSTHDR(&emh); cm != NULL; cm = CMSG_NXTHDR(&emh, cm)) {
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

				enum stream log_to;
				if (packet_len == 1 && buffer[0] == 0xff &&
				    (cur_debugging & DBG_BASE) == 0) {
					/*
					 * don't log NAT-T keepalive related errors unless NATT debug is
					 * enabled
					 */
					log_to = NO_STREAM;
				} else if (sender != NULL && sender->st_connection != NULL &&
					   !is_opportunistic(sender->st_connection)) {
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
					log_to = ALL_STREAMS;
				} else if (LDBGP(DBG_BASE, logger)) {
					/*
					 * Since this output is forced
					 * using DBGP, report the
					 * error using debug-log.
					 *
					 * A NULL SENDER here doesn't
					 * matter - it just gets
					 * ignored.
					 */
					log_to = DEBUG_STREAM;
				} else {
					log_to = NO_STREAM;
				}
				if (log_to != NO_STREAM) {
					endpoint_buf epb;
					llog(log_to, (sender != NULL ? sender->logger : logger),
						    "ERROR: asynchronous network error report on %s (%s)%s, complainant %s: %s [errno %" PRIu32 ", origin %s]",
						    ifp->ip_dev->real_device_name,
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
				/* .cmsg_len is a kernel_size_t(!),
				 * but the value certainly ought to
				 * fit in a size_t.
				 */
				llog(RC_LOG, logger,
				     "unknown cmsg: level %d, type %d, len %zu",
				     cm->cmsg_level, cm->cmsg_type,
				     (size_t)cm->cmsg_len);
			}
		}
	}
	return (pfd.revents & interest) != 0;
}

#endif /* MSG_ERRQUEUE */
