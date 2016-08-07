/* demultiplex incoming IKE messages
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * (all the code that used to be here is now in ikev1.c)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>   /* only used for belt-and-suspenders select call */
#include <sys/poll.h>   /* only used for forensic poll call */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
#  include <asm/types.h>        /* for __u8, __u32 */
#  include <linux/errqueue.h>
#  include <sys/uio.h>          /* struct iovec */
#endif

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "cookie.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "ike_alg.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */
#include "ikev1.h"
#include "ikev2.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "timer.h"
#include "udpfromto.h"

/* This file does basic header checking and demux of
 * incoming packets.
 */

void init_demux(void)
{
	init_ikev1();
}

/* forward declarations */
static bool read_packet(struct msg_digest *md);

/* Reply messages are built in this buffer.
 * Only one state transition function can be using it at a time
 * so suspended STFs must save and restore it.
 * It could be an auto variable of complete_state_transition except for the fact
 * that when a suspended STF resumes, its reply message buffer
 * must be at the same location -- there are pointers into it.
 */
pb_stream reply_stream;
u_int8_t reply_buffer[MAX_OUTPUT_UDP_SIZE];

/* process an input packet, possibly generating a reply.
 *
 * If all goes well, this routine eventually calls a state-specific
 * transition function.
 *
 * This routine will not release_any_md(mdp).  It is expected that its
 * caller will do this.  In fact, it will zap *mdp to NULL if it thinks
 * **mdp should not be freed.  So the caller should be prepared for
 * *mdp being set to NULL.
 */
void process_packet(struct msg_digest **mdp)
{
	struct msg_digest *md = *mdp;
	int vmaj, vmin;

	if (!in_struct(&md->hdr, &isakmp_hdr_desc, &md->packet_pbs,
		       &md->message_pbs)) {
		/* The packet was very badly mangled. We can't be sure of any
		 * content - not even to look for major version number!
		 * So we'll just drop it.
		 */
		libreswan_log("Received packet with mangled IKE header - dropped");
		send_notification_from_md(md, PAYLOAD_MALFORMED);
		return;
	}

	if (md->packet_pbs.roof > md->message_pbs.roof) {
		/* Some (old?) versions of the Cisco VPN client send an additional
		 * 16 bytes of zero bytes - Complain but accept it
		 */
		DBG(DBG_CONTROL, {
			DBG_log(
			"size (%u) in received packet is larger than the size specified in ISAKMP HDR (%u) - ignoring extraneous bytes",
			(unsigned) pbs_room(&md->packet_pbs),
			md->hdr.isa_length);
			DBG_dump("extraneous bytes:", md->message_pbs.roof,
				md->packet_pbs.roof - md->message_pbs.roof);
		});
	}

	vmaj = md->hdr.isa_version >> ISA_MAJ_SHIFT;
	vmin = md->hdr.isa_version & ISA_MIN_MASK;

	switch (vmaj) {
	case ISAKMP_MAJOR_VERSION: /* IKEv1 */
		if (vmin > ISAKMP_MINOR_VERSION) {
			/* RFC2408 3.1 ISAKMP Header Format:
			 *
			 * Minor Version (4 bits) - indicates the minor
			 * version of the ISAKMP protocol in use.
			 * Implementations based on this version of the
			 * ISAKMP Internet-Draft MUST set the Minor
			 * Version to 0.  Implementations based on
			 * previous versions of ISAKMP Internet- Drafts
			 * MUST set the Minor Version to 1.
			 * Implementations SHOULD never accept packets
			 * with a minor version number larger than its
			 * own, given the major version numbers are
			 * identical.
			 */
			libreswan_log("ignoring packet with IKEv1 minor version number %d greater than %d", vmin, ISAKMP_MINOR_VERSION);
			send_notification_from_md(md, INVALID_MINOR_VERSION);
			return;
		}
		DBG(DBG_CONTROL,
		    DBG_log(" processing version=%u.%u packet with exchange type=%s (%d)",
			    vmaj, vmin,
			    enum_name(&exchange_names_ikev1orv2, md->hdr.isa_xchg),
			    md->hdr.isa_xchg));
		process_v1_packet(mdp);
		/* our caller will release_any_md(mdp) */
		break;

	case IKEv2_MAJOR_VERSION: /* IKEv2 */
		if (vmin != IKEv2_MINOR_VERSION) {
			/* Unlike IKEv1, for IKEv2 we are supposed to try to
			 * continue on unknown minors
			 */
			libreswan_log("Ignoring unknown IKEv2 minor version number %d", vmin);
		}
		DBG(DBG_CONTROL,
		    DBG_log(" processing version=%u.%u packet with exchange type=%s (%d)",
			    vmaj, vmin,
			    enum_name(&exchange_names_ikev1orv2, md->hdr.isa_xchg),
			    md->hdr.isa_xchg));
		process_v2_packet(mdp);
		/* our caller will release_any_md(mdp) */
		break;

	default:
		libreswan_log("Unexpected IKE major '%d'", vmaj);
		send_notification_from_md(md, INVALID_MAJOR_VERSION);
		return;
	}
}

static void comm_handle(const struct iface_port *ifp);

void comm_handle_cb(evutil_socket_t fd UNUSED, const short event UNUSED, void *arg)
{
	comm_handle((const struct iface_port *) arg);
}


/* wrapper for read_packet and process_packet
 *
 * The main purpose of this wrapper is to factor out teardown code
 * from the many return points in process_packet.  This amounts to
 * releasing the msg_digest and resetting global variables.
 *
 * When processing of a packet is suspended (STF_SUSPEND),
 * process_packet sets md to NULL to prevent the msg_digest being freed.
 * Someone else must ensure that msg_digest is freed eventually.
 *
 * read_packet is broken out to minimize the lifetime of the
 * enormous input packet buffer, an auto.
 */
static void comm_handle(const struct iface_port *ifp)
{
	struct msg_digest *md;

#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
	/* Even though select(2) says that there is a message,
	 * it might only be a MSG_ERRQUEUE message.  At least
	 * sometimes that leads to a hanging recvfrom.  To avoid
	 * what appears to be a kernel bug, check_msg_errqueue
	 * uses poll(2) and tells us if there is anything for us
	 * to read.
	 *
	 * This is early enough that teardown isn't required:
	 * just return on failure.
	 */
	if (!check_msg_errqueue(ifp, POLLIN))
		return; /* no normal message to read */

#endif /* defined(IP_RECVERR) && defined(MSG_ERRQUEUE) */

	md = alloc_md();
	md->iface = ifp;

	if (read_packet(md))
		process_packet(&md);

	release_any_md(&md);

	cur_state = NULL;
	reset_cur_connection();
	cur_from = NULL;
	passert(GLOBALS_ARE_RESET());
}

/* read the message.
 * Since we don't know its size, we read it into
 * an overly large buffer and then copy it to a
 * new, properly sized buffer.
 */
static bool read_packet(struct msg_digest *md)
{
	const struct iface_port *ifp = md->iface;
	int packet_len;
	/* ??? this buffer seems *way* too big */
	u_int8_t bigbuffer[MAX_INPUT_UDP_SIZE];

	u_int8_t *_buffer = bigbuffer;
	union {
		struct sockaddr sa;
		struct sockaddr_in sa_in4;
		struct sockaddr_in6 sa_in6;
	} from
#if defined(HAVE_UDPFROMTO)
	, to
#endif
	;
	socklen_t from_len = sizeof(from);
#if defined(HAVE_UDPFROMTO)
	socklen_t to_len   = sizeof(to);
#endif
	err_t from_ugh = NULL;
	static const char undisclosed[] = "unknown source";

	happy(anyaddr(addrtypeof(&ifp->ip_addr), &md->sender));
	zero(&from.sa);

#if defined(HAVE_UDPFROMTO)
	packet_len = recvfromto(ifp->fd, bigbuffer,
				sizeof(bigbuffer), /*flags*/ 0,
				&from.sa, &from_len,
				&to.sa, &to_len);
#else
	packet_len = recvfrom(ifp->fd, bigbuffer,
			      sizeof(bigbuffer), /*flags*/ 0,
			      &from.sa, &from_len);
#endif

	/* we do not do anything with *to* addresses yet... we will */

	/* First: digest the from address.
	 * We presume that nothing here disturbs errno.
	 */
	if (packet_len == -1 &&
	    from_len == sizeof(from) &&
	    all_zero((const void *)&from.sa, sizeof(from))) {
		/* "from" is untouched -- not set by recvfrom */
		from_ugh = undisclosed;
	} else if (from_len   <
		   (int) (offsetof(struct sockaddr,
				   sa_family) + sizeof(from.sa.sa_family))) {
		from_ugh = "truncated";
	} else {
		const struct af_info *afi = aftoinfo(from.sa.sa_family);

		if (afi == NULL) {
			from_ugh = "unexpected Address Family";
		} else if (from_len != afi->sa_sz) {
			from_ugh = "wrong length";
		} else {
			switch (from.sa.sa_family) {
			case AF_INET:
				from_ugh = initaddr(
					(void *) &from.sa_in4.sin_addr,
					sizeof(from.sa_in4.sin_addr),
					AF_INET, &md->sender);
				setportof(from.sa_in4.sin_port, &md->sender);
				md->sender_port = ntohs(from.sa_in4.sin_port);
				break;
			case AF_INET6:
				from_ugh = initaddr(
					(void *) &from.sa_in6.sin6_addr,
					sizeof(from.sa_in6.
					       sin6_addr),
					AF_INET6, &md->sender);
				setportof(from.sa_in6.sin6_port, &md->sender);
				md->sender_port = ntohs(from.sa_in6.sin6_port);
				break;
			}
		}
	}

	/* now we report any actual I/O error */
	if (packet_len == -1) {
		if (from_ugh == undisclosed &&
		    errno == ECONNREFUSED) {
			/* Tone down scary message for vague event:
			 * We get "connection refused" in response to some
			 * datagram we sent, but we cannot tell which one.
			 */
			libreswan_log(
				"some IKE message we sent has been rejected with ECONNREFUSED (kernel supplied no details)");
		} else if (from_ugh != NULL) {
			log_errno((e,
				   "recvfrom on %s failed; Pluto cannot decode source sockaddr in rejection: %s",
				   ifp->ip_dev->id_rname, from_ugh));
		} else {
			ipstr_buf b;

			log_errno((e, "recvfrom on %s from %s:%u failed",
				   ifp->ip_dev->id_rname,
				   ipstr(&md->sender, &b),
				   (unsigned)md->sender_port));
		}

		return FALSE;
	} else if (from_ugh != NULL) {
		libreswan_log(
			"recvfrom on %s returned malformed source sockaddr: %s",
			ifp->ip_dev->id_rname, from_ugh);
		return FALSE;
	}
	cur_from = &md->sender;
	cur_from_port = md->sender_port;

	if (ifp->ike_float) {
		u_int32_t non_esp;

		if (packet_len < (int)sizeof(u_int32_t)) {
			ipstr_buf b;

			libreswan_log("recvfrom %s:%u too small packet (%d)",
				      ipstr(cur_from, &b), (unsigned) cur_from_port,
				      packet_len);
			return FALSE;
		}
		memcpy(&non_esp, _buffer, sizeof(u_int32_t));
		if (non_esp != 0) {
			ipstr_buf b;

			libreswan_log("recvfrom %s:%u has no Non-ESP marker",
				      ipstr(cur_from, &b),
				      (unsigned) cur_from_port);
			return FALSE;
		}
		_buffer += sizeof(u_int32_t);
		packet_len -= sizeof(u_int32_t);
	}

	/* Clone actual message contents
	 * and set up md->packet_pbs to describe it.
	 */
	init_pbs(&md->packet_pbs
		 , clone_bytes(_buffer, packet_len,
			       "message buffer in comm_handle()")
		 , packet_len, "packet");

	DBG(DBG_RAW | DBG_CRYPT | DBG_PARSING | DBG_CONTROL, {
		ipstr_buf b;
		DBG_log("*received %d bytes from %s:%u on %s (port=%d)",
			(int) pbs_room(&md->packet_pbs),
			ipstr(cur_from, &b), (unsigned) cur_from_port,
			ifp->ip_dev->id_rname,
			ifp->port);
	});

	DBG(DBG_RAW,
	    DBG_dump("", md->packet_pbs.start, pbs_room(&md->packet_pbs)));

	/* We think that in 2013 Feb, Apple iOS Racoon
	 * sometimes generates an extra useless buggy confusing
	 * Non ESP Marker
	 */
	{
		static const u_int8_t non_ESP_marker[NON_ESP_MARKER_SIZE] =
			{ 0x00, };

		if (md->iface->ike_float &&
		    pbs_left(&md->packet_pbs) >= NON_ESP_MARKER_SIZE &&
		    memeq(md->packet_pbs.cur, non_ESP_marker,
			   NON_ESP_MARKER_SIZE)) {
			bool happy = in_raw(NULL, NON_ESP_MARKER_SIZE,
					    &md->packet_pbs,
					    "spurious extra Non ESP Marker");
			libreswan_log(
				"Removed spurious non-esp marker from IKE packet - Racoon bug");
			passert(happy);
		}
	}

	if ((pbs_room(&md->packet_pbs) == 1) &&
	    (md->packet_pbs.start[0] == 0xff)) {
		/**
		 * NAT-T Keep-alive packets should be discared by kernel ESPinUDP
		 * layer. But boggus keep-alive packets (sent with a non-esp marker)
		 * can reach this point. Complain and discard them.
		 */
		DBG(DBG_NATT, {
			ipstr_buf b;
			DBG_log("NAT-T keep-alive (boggus ?) should not reach this point. Ignored. Sender: %s:%u", ipstr(cur_from, &b),
				(unsigned) cur_from_port);
		});
		return FALSE;
	}

	return TRUE;
}
