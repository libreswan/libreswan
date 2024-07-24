/* demultiplex incoming IKE messages
 *
 * Copyright (C) 1998-2002,2013-2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013,2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2015 Antony Antony <antony@phenome.org>
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 2022 Paul Wouters <paul.wouters@aiven.io>
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
 * (all the code that used to be here is now in ikev1.c)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>       /* only used for forensic poll call */
#include <sys/types.h>
#include <sys/time.h>   /* only used for belt-and-suspenders select call */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
#  include <asm/types.h>        /* for __u8, __u32 */
#  include <linux/errqueue.h>
#  include <sys/uio.h>          /* struct iovec */
#endif


#include "sysdep.h"
#include "constants.h"

#include "defs.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "crypto.h"
#include "ike_alg.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */
#include "ikev1.h"
#include "ikev2.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "timer.h"
#include "ip_address.h"
#include "ip_endpoint.h"
#include "ip_protocol.h"
#include "ip_info.h"
#include "pluto_stats.h"
#include "ikev1_send.h"
#include "ikev2_send.h"
#include "iface.h"
#include "impair_message.h"
#include "log_limiter.h"

static callback_cb handle_md_event;		/* type assertion */

/*
 * process an input packet, possibly generating a reply.
 *
 * If all goes well, this routine eventually calls a state-specific
 * transition function.
 *
 * This routine will not md_delref(mdp).  It is assumed its caller
 * will do this, and if MD needs to stick around, the callee will
 * md_addref().
 */

void process_md(struct msg_digest *md)
{
	diag_t d = pbs_in_struct(&md->packet_pbs, &isakmp_hdr_desc,
				 &md->hdr, sizeof(md->hdr), &md->message_pbs);
	if (d != NULL) {
		/*
		 * The packet was very badly mangled. We can't be sure
		 * of any content - not even to look for major version
		 * number!  So we'll just drop it.
		 */
		lset_t rc_flags = log_limiter_rc_flags(md->logger, &md_log_limiter);
		if (rc_flags != 0) {
			llog(rc_flags, md->logger,
			     "dropping packet with mangled IKE header: %s",
			     str_diag(d));
		}
		pfree_diag(&d);
		return;
	}

	/*
	 * They map onto the same bytes.
	 */
	shunk_t message = pbs_in_all(&md->message_pbs);
	shunk_t packet = pbs_in_all(&md->packet_pbs);
	PEXPECT(md->logger, message.ptr == packet.ptr);

	if (packet.len > message.len) {
		/*
		 * The extracted message, with its .len set from the
		 * header, is shorter than the raw packet.
		 *
		 * Some (old?) versions of the Cisco VPN client send
		 * an additional 16 bytes of zero bytes - Complain but
		 * accept it
		 */
		if (DBGP(DBG_BASE)) {
			DBG_log("size (%zu) in received packet is larger than the size specified in ISAKMP HDR (%u) - ignoring extraneous bytes",
				packet.len, md->hdr.isa_length);
			shunk_t tail = hunk_slice(packet, message.len, packet.len);
			DBG_dump_hunk("extraneous bytes:", tail);
		}
	}

	unsigned vmaj = md->hdr.isa_version >> ISA_MAJ_SHIFT;
	unsigned vmin = md->hdr.isa_version & ISA_MIN_MASK;

	switch (vmaj) {
	case 0:
		/*
		 * IKEv2 doesn't say what to do with low versions,
		 * just drop them.
		 */
		llog_md(md, "ignoring packet with IKE major version '%d'", vmaj);
		return;

	case ISAKMP_MAJOR_VERSION: /* IKEv1 */
	{
		if (pluto_ikev1_pol == GLOBAL_IKEv1_DROP) {
			llog_md(md,
			     "ignoring IKEv1 packet as global policy is set to silently drop all IKEv1 packets");
			return;
		}
#ifdef USE_IKEv1
		if (pluto_ikev1_pol == GLOBAL_IKEv1_REJECT) {
			llog_md(md,
			     "rejecting IKEv1 packet as global policy is set to reject all IKEv1 packets");
			send_v1_notification_from_md(md, v1N_INVALID_MAJOR_VERSION);
			return;
		}

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
			llog_md(md,
			     "ignoring packet with IKEv1 minor version number %d greater than %d", vmin, ISAKMP_MINOR_VERSION);
			send_v1_notification_from_md(md, v1N_INVALID_MINOR_VERSION);
			return;
		}
		enum_buf xb;
		ldbg(md->logger,
		     " processing version=%u.%u packet with exchange type=%s (%d)",
		     vmaj, vmin,
		     str_enum(&ikev1_exchange_names, md->hdr.isa_xchg, &xb),
		     md->hdr.isa_xchg);
		process_v1_packet(md);
		/* our caller will md_delref(mdp) */
#else
		ldbg(md->logger, "IKEv1 packet dropped"); /* dbg to prevent DoS */
#endif
		break;
	}

	case IKEv2_MAJOR_VERSION: /* IKEv2 */
	{
		if (vmin != IKEv2_MINOR_VERSION) {
			/* Unlike IKEv1, for IKEv2 we are supposed to try to
			 * continue on unknown minors
			 */
			llog_md(md,
			     "Ignoring unknown/unsupported IKEv2 minor version number %d", vmin);
		}
		enum_buf xb;
		pdbg(md->logger,
		     " processing version=%u.%u packet with exchange type=%s (%d)",
		     vmaj, vmin,
		     str_enum(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
		     md->hdr.isa_xchg);
		ikev2_process_packet(md);
		break;
	}

	default:
		llog_md(md, "message contains unsupported IKE major version '%d'", vmaj);
		/*
		 * According to 1.5.  Informational Messages outside
		 * of an IKE SA, [...] the message is always sent
		 * without cryptographic protection (outside of an IKE
		 * SA), and includes either an INVALID_IKE_SPI or an
		 * INVALID_MAJOR_VERSION notification (with no
		 * notification data).  The message is a response
		 * message, and thus it is sent to the IP address and
		 * port from whence it came with the same IKE SPIs and
		 * the Message ID and Exchange Type are copied from
		 * the request.  The Response flag is set to 1, and
		 * the version flags are set in the normal fashion.
		 *
		 * XXX: But this this doesn't specify the I
		 * (Initiator) flag.  Normally the MD's I flag can be
		 * flipped.  But does IKEv++ even have an I
		 * (Initiator) flag?  Presumably it's an initial
		 * response so the flag should be clear.
		 *
		 * XXX: According to 2.5. Version Numbers and Forward
		 * Compatibility, it "SHOULD send an unauthenticated
		 * Notify message of type INVALID_MAJOR_VERSION
		 * containing the highest (closest) version number it
		 * supports".  Does the INVALID_MAJOR_VERSION
		 * notification contain the version or is it implied
		 * by the message header.  Presumably the latter -
		 * nothing describes the Notification Data for this
		 * notification.
		 *
		 * XXX: According to 3.1. The IKE Header,
		 * implementations "MUST reject or ignore messages
		 * containing a version number greater than 2 with an
		 * INVALID_MAJOR_VERSION".  Does this mean reject
		 * IKEv++ messages that contain INVALID_MAJOR_VERSION,
		 * or reject IKEv++ messages by responding with an
		 * INVALID_MAJOR_VERSION.  Presumably the latter.
		 */
		send_v2N_response_from_md(md, v2N_INVALID_MAJOR_VERSION,
					  NULL/*no data*/);
		return;
	}
}

/*
 * wrapper for read_message() and process_md()
 *
 * The main purpose of this wrapper is to factor out teardown code
 * from the many return points in process_md().  This amounts to
 * releasing the msg_digest (if MD needs to be kept around the code
 * requiring it will have taken a reference).
 *
 * read_packet is broken out to minimize the lifetime of the enormous
 * input packet buffer, an auto.
 */

void process_iface_packet(int fd, void *ifp_arg, struct logger *logger)
{
	struct iface_endpoint *ifp = ifp_arg;
	ifp_arg = NULL; /* can no longer be trusted */

	/* on the same page^D^D^D fd? */
	pexpect(ifp->fd == fd);

	threadtime_t md_start = threadtime_start();

	/*
	 *
	 * Read the message into a message digest.
	 *
	 * XXX: Danger
	 *
	 * The read_message() call can invalidate (*IFP).  For
	 * instance when there's a non-recoverable error IFP may be
	 * zapped.
	 */
	struct msg_digest *md = ifp->io->read_packet(&ifp, logger);

	if (md != NULL) {

		if (DBGP(DBG_BASE)) {
			endpoint_buf sb;
			endpoint_buf lb;
			DBG_log("*received %zu bytes from %s on %s %s using %s",
				pbs_in_all(&md->packet_pbs).len,
				str_endpoint(&md->sender, &sb),
				md->iface->ip_dev->real_device_name,
				str_endpoint(&md->iface->local_endpoint, &lb),
				md->iface->io->protocol->name);
			shunk_t packet = pbs_in_all(&md->packet_pbs);
			DBG_dump_hunk(NULL, packet);
		}

		pstats_ike_bytes.in += pbs_in_all(&md->packet_pbs).len;

		md->md_inception = md_start;
		if (!impair_inbound(md)) {
			/*
			 * If this needs to hang onto MD it will save
			 * a reference (aka addref), and the below
			 * won't delete MD.
			 */
			process_md(md);
		}
		md_delref(&md);
		pexpect(md == NULL);
	}

	threadtime_stop(&md_start, SOS_NOBODY,
			"%s() reading and processing packet", __func__);
}

static void handle_md_event(const char *story UNUSED, struct state *st, void *context)
{
	pexpect(st == NULL);
	struct msg_digest *md = context;
	process_md(md);
	md_delref(&md);
	pexpect(md == NULL);
}

void schedule_md_event(const char *story, struct msg_digest *md)
{
	schedule_callback(story, deltatime(0), SOS_NOBODY,
			  handle_md_event, md);
}

enum ike_version hdr_ike_version(const struct isakmp_hdr *hdr)
{
	unsigned vmaj = hdr->isa_version >> ISA_MAJ_SHIFT;
	switch (vmaj) {
	case ISAKMP_MAJOR_VERSION: return IKEv1;
	case IKEv2_MAJOR_VERSION: return IKEv2;
	default: return 0;
	}
}

/*
 * Map the IKEv2 MSG_R bit onto the ENUM message_role.
 *
 * Several reasons:
 *
 * - makes passing a role parameter clearer, that is:
 *       foo(MESSAGE_RESPONSE)
 *   is better than:
 *       foo(true)
 *
 * - zero is 'reserved' for no MD and/or default value so won't match
 *   either of the initiator and/or responder values
 *
 * - encourages the coding style where the two cases - REQUEST and
 *   RESPONSE - are clearly labeled, that is:
 *
 *       switch(role) {
 *       case MESSAGE_REQUEST: ...; break;
 *       case MESSAGE_RESPONSE: ...; break;
 *       default: bad_case(role);
 *       }
 *
 * Separate from this is IKE SA role ORIGINAL_INITIATOR or
 * ORIGINAL_RESPONDER RFC 7296 2.2.
 */
enum message_role v2_msg_role(const struct msg_digest *md)
{
	if (md == NULL) {
		return NO_MESSAGE;
	}
	if (!pexpect(hdr_ike_version(&md->hdr) == IKEv2)) {
		return NO_MESSAGE;
	}
	/* determine the role */
	enum message_role role =
		(md->hdr.isa_flags & ISAKMP_FLAGS_v2_MSG_R) ? MESSAGE_RESPONSE : MESSAGE_REQUEST;
	return role;
}

/*
 * list all the payload types
 */

static void jam_msg_digest(struct jambuf *buf, const char *prefix, const struct msg_digest *md)
{
	jam_string(buf, prefix);

	jam_string(buf, " ");
	const enum ike_version ike_version = hdr_ike_version(&md->hdr);
	jam_enum_enum_short(buf, &exchange_type_names, ike_version,
			    md->hdr.isa_xchg);

	if (ike_version == IKEv2) {
		switch (v2_msg_role(md)) {
		case MESSAGE_REQUEST: jam_string(buf, " request"); break;
		case MESSAGE_RESPONSE: jam_string(buf, " response"); break;
		case NO_MESSAGE: break;
		}
	}

	jam_string(buf, " from ");
	jam_endpoint_address_protocol_port_sensitive(buf, &md->sender);

	const char *sep = " containing ";
	const char *term = "";
	for (unsigned d = 0; d < md->digest_roof; d++) {
		const struct payload_digest *pd = &md->digest[d];
		jam_string(buf, sep);
		if (ike_version == IKEv2 &&
		    d+1 < md->digest_roof &&
		    pd->payload_type == ISAKMP_NEXT_v2SK) {
			/*
			 * HACK to dump decrypted SK payload contents
			 * (which come after the SK payload).
			 */
			sep = "{";
			term = "}";
		} else {
			sep = ",";
		}
		jam_enum_enum_short(buf, &payload_type_names,
				    ike_version,
				    pd->payload_type);
		/* go deeper? */
		switch (pd->payload_type) {
		case ISAKMP_NEXT_v2N:
		{
			enum_buf name;
			if (enum_name_short(&v2_notification_names,
					    pd->payload.v2n.isan_type,
					    &name)) {
				jam(buf, "(%s)", name.buf);
			}
			break;
		}
		}
	}
	jam_string(buf, term);
}

void llog_msg_digest(lset_t rc_flags, struct logger *logger, const char *prefix, const struct msg_digest *md)
{
	LLOG_JAMBUF(rc_flags, logger, buf) {
		jam_msg_digest(buf, prefix, md);
	}
}
