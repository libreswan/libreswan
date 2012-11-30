/* demultiplex incoming IKE messages
 *
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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
#include <sys/time.h>	/* only used for belt-and-suspenders select call */
#include <sys/poll.h>	/* only used for forensic poll call */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
#  include <asm/types.h>	/* for __u8, __u32 */
#  include <linux/errqueue.h>
#  include <sys/uio.h>	/* struct iovec */
#endif

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "cookie.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#ifdef XAUTH_HAVE_PAM
#include <security/pam_appl.h>
#endif
#include "connections.h"	/* needs id.h */
#include "state.h"
#include "packet.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "ike_alg.h"
#include "log.h"
#include "demux.h"	/* needs packet.h */
#include "ikev1.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "timer.h"
#if 0
#include "whack.h"	/* requires connections.h */
#include "server.h"
#ifdef XAUTH
#include "xauth.h"
#endif
#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif
#include "vendor.h"
#include "dpd.h"
#endif
#include "udpfromto.h"
#include "tpm/tpm.h"

/* This file does basic header checking and demux of
 * incoming packets.
 */

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
 */
void
process_packet(struct msg_digest **mdp)
{
    struct msg_digest *md = *mdp;
    struct state *st = NULL;
    int maj, min;
    enum state_kind from_state = STATE_UNDEFINED;	/* state we started in */
    struct isakmp_hdr *hdr;

#define SEND_NOTIFICATION(t) { \
    if (st) send_notification_from_state(st, from_state, t); \
    else send_notification_from_md(md, t); }

    if (!in_struct(&md->hdr, &isakmp_hdr_desc, &md->packet_pbs, &md->message_pbs))
    {
	/* Identify specific failures:
	 * - bad ISAKMP major/minor version numbers
	 */
	if (md->packet_pbs.roof - md->packet_pbs.cur >= (ptrdiff_t)isakmp_hdr_desc.size)
	{
	    hdr = (struct isakmp_hdr *)md->packet_pbs.cur;
	    maj = (hdr->isa_version >> ISA_MAJ_SHIFT);
	    min = (hdr->isa_version & ISA_MIN_MASK);

	    if ( maj != ISAKMP_MAJOR_VERSION
		 && maj != IKEv2_MAJOR_VERSION)
	    {
		SEND_NOTIFICATION(INVALID_MAJOR_VERSION);
		return;
	    }
	    else if (maj == ISAKMP_MAJOR_VERSION && min != ISAKMP_MINOR_VERSION)
	    {
		/* all IKEv2 minor version are acceptable */
		SEND_NOTIFICATION(INVALID_MINOR_VERSION);
		return;
	    }
	} 
	else {
        /* Although the comments above says that all IKEv2 minor version are acceptable */
        /* but it does not take of it, and in case a peer sends a different minor version */
        /* other than 0, it still sends PAYLOAD_MALFORMED packet, so fixing it here */
        /* it checks if the in_struct failure is due to minor version with ikev2 */
        /* As per RFC 4306/5996, ignore minor version numbers */
	SEND_NOTIFICATION(PAYLOAD_MALFORMED);
	return;
	}
    }

    if (md->packet_pbs.roof != md->message_pbs.roof)
    {
	libreswan_log("size (%u) differs from size specified in ISAKMP HDR (%u)"
	    , (unsigned) pbs_room(&md->packet_pbs), md->hdr.isa_length);
	return;
    }

    maj = (md->hdr.isa_version >> ISA_MAJ_SHIFT);
    min = (md->hdr.isa_version & ISA_MIN_MASK);

    DBG(DBG_CONTROL
	, DBG_log(" processing version=%u.%u packet with exchange type=%s (%d)"
		  , maj, min
		  , enum_name(&exchange_names, md->hdr.isa_xchg)
		  , md->hdr.isa_xchg));

    TCLCALLOUT("processRawPacket", NULL, NULL, md);

    switch(maj) {
    case ISAKMP_MAJOR_VERSION:
	process_v1_packet(mdp);
	break;

    case IKEv2_MAJOR_VERSION:
	process_v2_packet(mdp);
	break;

    default:
	bad_case(maj);
    }
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
void
comm_handle(const struct iface_port *ifp)
{
    static struct msg_digest *md;

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
	return;	/* no normal message to read */
#endif /* defined(IP_RECVERR) && defined(MSG_ERRQUEUE) */

    md = alloc_md();
    md->iface = ifp;

    if (read_packet(md))
	process_packet(&md);

    if (md != NULL)
	release_md(md);

    cur_state = NULL;
    reset_cur_connection();
    cur_from = NULL;
}

/* read the message.
 * Since we don't know its size, we read it into
 * an overly large buffer and then copy it to a
 * new, properly sized buffer.
 */
static bool
read_packet(struct msg_digest *md)
{
    const struct iface_port *ifp = md->iface;
    int packet_len;
    /* ??? this buffer seems *way* too big */
    u_int8_t bigbuffer[MAX_INPUT_UDP_SIZE];
#ifdef NAT_TRAVERSAL
    u_int8_t *_buffer = bigbuffer;
#endif
    union
    {
	struct sockaddr sa;
	struct sockaddr_in sa_in4;
	struct sockaddr_in6 sa_in6;
    } from
#if defined(HAVE_UDPFROMTO)
	  ,to
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
    packet_len = recvfromto(ifp->fd, bigbuffer
			    , sizeof(bigbuffer), /*flags*/0
			    , &from.sa, &from_len
			    , &to.sa, &to_len);
#else
    packet_len = recvfrom(ifp->fd, bigbuffer
			  , sizeof(bigbuffer), /*flags*/0
			  , &from.sa, &from_len);
#endif    

    /* we do not do anything with *to* addresses yet... we will */

    /* First: digest the from address.
     * We presume that nothing here disturbs errno.
     */
    if (packet_len == -1
    && from_len == sizeof(from)
    && all_zero((const void *)&from.sa, sizeof(from)))
    {
	/* "from" is untouched -- not set by recvfrom */
	from_ugh = undisclosed;
    }
    else if (from_len
    < (int) (offsetof(struct sockaddr, sa_family) + sizeof(from.sa.sa_family)))
    {
	from_ugh = "truncated";
    }
    else
    {
	const struct af_info *afi = aftoinfo(from.sa.sa_family);

	if (afi == NULL)
	{
	    from_ugh = "unexpected Address Family";
	}
	else if (from_len != afi->sa_sz)
	{
	    from_ugh = "wrong length";
	}
	else
	{
	    switch (from.sa.sa_family)
	    {
	    case AF_INET:
		from_ugh = initaddr((void *) &from.sa_in4.sin_addr
				    , sizeof(from.sa_in4.sin_addr)
				    , AF_INET, &md->sender);
		setportof(from.sa_in4.sin_port, &md->sender);
		md->sender_port = ntohs(from.sa_in4.sin_port);
		break;
	    case AF_INET6:
		from_ugh = initaddr((void *) &from.sa_in6.sin6_addr
				    , sizeof(from.sa_in6.sin6_addr)
				    , AF_INET6, &md->sender);
		setportof(from.sa_in6.sin6_port, &md->sender);
		md->sender_port = ntohs(from.sa_in6.sin6_port);
		break;
	    }
	}
    }

    /* now we report any actual I/O error */
    if (packet_len == -1)
    {
	if (from_ugh == undisclosed
	&& errno == ECONNREFUSED)
	{
	    /* Tone down scary message for vague event:
	     * We get "connection refused" in response to some
	     * datagram we sent, but we cannot tell which one.
	     */
	    libreswan_log("some IKE message we sent has been rejected with ECONNREFUSED (kernel supplied no details)");
	}
	else if (from_ugh != NULL)
	{
	    log_errno((e, "recvfrom on %s failed; Pluto cannot decode source sockaddr in rejection: %s"
		, ifp->ip_dev->id_rname, from_ugh));
	}
	else
	{
	    log_errno((e, "recvfrom on %s from %s:%u failed"
		, ifp->ip_dev->id_rname
		, ip_str(&md->sender), (unsigned)md->sender_port));
	}

	return FALSE;
    }
    else if (from_ugh != NULL)
    {
	libreswan_log("recvfrom on %s returned malformed source sockaddr: %s"
	    , ifp->ip_dev->id_rname, from_ugh);
	return FALSE;
    }
    cur_from = &md->sender;
    cur_from_port = md->sender_port;

#ifdef NAT_TRAVERSAL
    if (ifp->ike_float == TRUE) {
	u_int32_t non_esp;
	if (packet_len < (int)sizeof(u_int32_t)) {
	    libreswan_log("recvfrom %s:%u too small packet (%d)"
		, ip_str(cur_from), (unsigned) cur_from_port, packet_len);
	    return FALSE;
	}
	memcpy(&non_esp, _buffer, sizeof(u_int32_t));
	if (non_esp != 0) {
	    libreswan_log("recvfrom %s:%u has no Non-ESP marker"
		, ip_str(cur_from), (unsigned) cur_from_port);
	    return FALSE;
	}
	_buffer += sizeof(u_int32_t);
	packet_len -= sizeof(u_int32_t);
    }
#endif

    /* Clone actual message contents
     * and set up md->packet_pbs to describe it.
     */
    init_pbs(&md->packet_pbs
#ifdef NAT_TRAVERSAL
	, clone_bytes(_buffer, packet_len, "message buffer in comm_handle()")
#else
	, clone_bytes(bigbuffer, packet_len, "message buffer in comm_handle()")
#endif
	, packet_len, "packet");

    DBG(DBG_RAW | DBG_CRYPT | DBG_PARSING | DBG_CONTROL,
	{
	    DBG_log("*received %d bytes from %s:%u on %s (port=%d)"
		    , (int) pbs_room(&md->packet_pbs)
		    , ip_str(cur_from), (unsigned) cur_from_port
		    , ifp->ip_dev->id_rname
		    , ifp->port);
	});

    DBG(DBG_RAW,
	DBG_dump("", md->packet_pbs.start, pbs_room(&md->packet_pbs)));

#ifdef NAT_TRAVERSAL
	if ((pbs_room(&md->packet_pbs)==1) && (md->packet_pbs.start[0]==0xff)) {
		/**
		 * NAT-T Keep-alive packets should be discared by kernel ESPinUDP
		 * layer. But boggus keep-alive packets (sent with a non-esp marker)
		 * can reach this point. Complain and discard them.
		 */
		DBG(DBG_NATT,
			DBG_log("NAT-T keep-alive (boggus ?) should not reach this point. "
				"Ignored. Sender: %s:%u", ip_str(cur_from),
				(unsigned) cur_from_port);
			);
		return FALSE;
	}
#endif

    return TRUE;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
