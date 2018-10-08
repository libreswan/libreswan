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
 * Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
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
#include "crypto.h"
#include "ike_alg.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */
#include "ikev1.h"
#include "ikev2.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "timer.h"
#include "udpfromto.h"

#include "ip_address.h"
#include "pluto_stats.h"

/* This file does basic header checking and demux of
 * incoming packets.
 */

void init_demux(void)
{
	init_ikev1();
	init_ikev2();
}

/*
 * read the message.
 *
 * Since we don't know its size, we read it into an overly large
 * buffer and then copy it to a new, properly sized buffer.
 */

static struct msg_digest *read_packet(const struct iface_port *ifp)
{
	int packet_len;
	/* ??? this buffer seems *way* too big */
	uint8_t bigbuffer[MAX_INPUT_UDP_SIZE];

	uint8_t *_buffer = bigbuffer;
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

	ip_address sender;
	happy(anyaddr(addrtypeof(&ifp->ip_addr), &sender));
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
					AF_INET, &sender);
				setportof(from.sa_in4.sin_port, &sender);
				break;
			case AF_INET6:
				from_ugh = initaddr(
					(void *) &from.sa_in6.sin6_addr,
					sizeof(from.sa_in6.
					       sin6_addr),
					AF_INET6, &sender);
				setportof(from.sa_in6.sin6_port, &sender);
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
			LSWLOG_ERRNO(errno, buf) {
				lswlogf(buf, "recvfrom on %s failed; Pluto cannot decode source sockaddr in rejection: %s",
					ifp->ip_dev->id_rname, from_ugh);
			}
		} else {
			LSWLOG_ERRNO(errno, buf) {
				lswlogf(buf, "recvfrom on %s from ",
					ifp->ip_dev->id_rname);
				lswlog_ip(buf, &sender);
				lswlogs(buf, " failed");
			}
		}

		return NULL;
	} else if (from_ugh != NULL) {
		libreswan_log(
			"recvfrom on %s returned malformed source sockaddr: %s",
			ifp->ip_dev->id_rname, from_ugh);
		return NULL;
	}

	if (ifp->ike_float) {
		uint32_t non_esp;

		if (packet_len < (int)sizeof(uint32_t)) {
			LSWLOG(buf) {
				lswlogs(buf, "recvfrom ");
				lswlog_ip(buf, &sender); /* sensitive? */
				lswlogf(buf, " too small packet (%d)",
					packet_len);
			}
			return NULL;
		}
		memcpy(&non_esp, _buffer, sizeof(uint32_t));
		if (non_esp != 0) {
			LSWLOG(buf) {
				lswlogs(buf, "recvfrom ");
				lswlog_ip(buf, &sender);
				lswlogs(buf, " has no Non-ESP marker");
			}
			return NULL;
		}
		_buffer += sizeof(uint32_t);
		packet_len -= sizeof(uint32_t);
	}

	/* We think that in 2013 Feb, Apple iOS Racoon
	 * sometimes generates an extra useless buggy confusing
	 * Non ESP Marker
	 */
	{
		static const uint8_t non_ESP_marker[NON_ESP_MARKER_SIZE] =
			{ 0x00, };
		if (ifp->ike_float &&
		    packet_len >= NON_ESP_MARKER_SIZE &&
		    memeq(_buffer, non_ESP_marker,
			   NON_ESP_MARKER_SIZE)) {
			LSWLOG(buf) {
				lswlogs(buf, "Mangled packet with potential spurious non-esp marker ignored. Sender: ");
				lswlog_ip(buf, &sender); /* sensitiv? */
			}
			return NULL;
		}
	}

	if (packet_len == 1 && _buffer[0] == 0xff) {
		/**
		 * NAT-T Keep-alive packets should be discared by kernel ESPinUDP
		 * layer. But bogus keep-alive packets (sent with a non-esp marker)
		 * can reach this point. Complain and discard them.
		 * Possibly too if the NAT mapping vanished on the initiator NAT gw ?
		 */
		LSWDBGP(DBG_NATT, buf) {
			lswlogs(buf, "NAT-T keep-alive (bogus ?) should not reach this point. Ignored. Sender: ");
			lswlog_ip(buf, &sender);
		};
		return NULL;
	}

	/*
	 * Clone actual message contents and set up md->packet_pbs to
	 * describe it.
	 */
	struct msg_digest *md = alloc_md("msg_digest in read_packet");
	md->iface = ifp;
	md->sender = sender;

	init_pbs(&md->packet_pbs
		 , clone_bytes(_buffer, packet_len,
			       "message buffer in read_packet()")
		 , packet_len, "packet");

	LSWDBGP(DBG_RAW | DBG_CRYPT | DBG_PARSING | DBG_CONTROL, buf) {
		lswlogf(buf, "*received %d bytes from ",
			(int) pbs_room(&md->packet_pbs));
		lswlog_ip(buf, &sender);
		lswlogf(buf, " on %s (port=%d)",
			ifp->ip_dev->id_rname, ifp->port);
	};

	DBG(DBG_RAW,
	    DBG_dump("", md->packet_pbs.start, pbs_room(&md->packet_pbs)));

	pstats_ike_in_bytes += pbs_room(&md->packet_pbs);

	return md;
}

/*
 * process an input packet, possibly generating a reply.
 *
 * If all goes well, this routine eventually calls a state-specific
 * transition function.
 *
 * This routine will not release_any_md(mdp).  It is expected that its
 * caller will do this.  In fact, it will zap *mdp to NULL if it
 * thinks **mdp should not be freed.  So the caller should be prepared
 * for *mdp being set to NULL.
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
		ikev2_process_packet(mdp);
		/* our caller will release_any_md(mdp) */
		break;

	default:
		libreswan_log("Unexpected IKE major '%d'", vmaj);
		send_notification_from_md(md, INVALID_MAJOR_VERSION);
		return;
	}
}

/*
 * Deal with state changes.
 */
static void process_md(struct msg_digest **mdp)
{
	ip_address old_from = push_cur_from((*mdp)->sender);
	process_packet(mdp);
	pop_cur_from(old_from);
	release_any_md(mdp);
	reset_cur_state();
	reset_cur_connection();
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

static bool impair_incoming(struct msg_digest **mdp);

static void comm_handle(const struct iface_port *ifp)
{
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
	if (!check_incoming_msg_errqueue(ifp, "read_packet"))
		return; /* no normal message to read */

	struct msg_digest *md = read_packet(ifp);
	if (md != NULL) {
		if (!impair_incoming(&md)) {
			process_md(&md);
		}
		pexpect(md == NULL);
	}
	pexpect_reset_globals();
}

void comm_handle_cb(evutil_socket_t fd UNUSED, const short event UNUSED, void *arg)
{
	comm_handle((const struct iface_port *) arg);
}

/*
 * Impair pluto by replaying packets.
 *
 * To make things easier, all packets received are saved, in-order, in
 * a list and then various impair operations iterate over this list.
 *
 * For instance, IKEv1 sends back-to-back packets (see XAUTH).  By
 * replaying them (and everything else) this can simulate what happens
 * when the remote starts re-transmitting them.
 */

static void process_md_clone(struct msg_digest *orig, const char *fmt, ...) PRINTF_LIKE(2);
static void process_md_clone(struct msg_digest *orig, const char *fmt, ...)
{
	/* not whack FD yet is expected to be reset! */
	pexpect_reset_globals();
	struct msg_digest *md = clone_md(orig, fmt /* good enough */);

	LSWLOG(buf) {
		lswlogs(buf, "IMPAIR: start processing ");
		va_list ap;
		va_start(ap, fmt);
		lswlogvf(buf, fmt, ap);
		va_end(ap);
		lswlogf(buf, " (%d bytes)", (int)pbs_room(&md->packet_pbs));
	}
	DBG(DBG_RAW,
	    DBG_dump("", md->packet_pbs.start, pbs_room(&md->packet_pbs)));

	process_md(&md);

	LSWLOG(buf) {
		lswlogf(buf, "IMPAIR: stop processing ");
		va_list ap;
		va_start(ap, fmt);
		lswlogvf(buf, fmt, ap);
		va_end(ap);
	}

	pexpect(md == NULL);
	pexpect_reset_globals();
}

static unsigned long replay_count;

struct replay_entry {
	struct list_entry entry;
	struct msg_digest *md;
	unsigned long nr;
};

static size_t log_replay_entry(struct lswlog *buf, void *data)
{
	struct replay_entry *r = (struct replay_entry*)data;
	return lswlogf(buf, "replay packet %lu", r == NULL ? 0L : r->nr);
}

static struct list_head replay_packets;

static struct list_info replay_info = {
	.debug = DBG_CONTROLMORE,
	.name = "replay list",
	.log = log_replay_entry,
};

static void save_any_md_for_replay(struct msg_digest **mdp)
{
	if (mdp != NULL && *mdp != NULL) {
		init_list(&replay_info, &replay_packets);
		struct replay_entry *e = alloc_thing(struct replay_entry, "replay");
		e->md = clone_md(*mdp, "copy of real message");
		e->nr = ++replay_count; /* yes; pre-increment */
		e->entry = list_entry(&replay_info, e); /* back-link */
		insert_list_entry(&replay_packets, &e->entry);
		release_any_md(mdp);
	}
}

static bool impair_incoming(struct msg_digest **mdp)
{
	if (IMPAIR(REPLAY_DUPLICATES)) {
		save_any_md_for_replay(mdp);
		/* MD is the most recent entry */
		struct replay_entry *e = NULL;
		FOR_EACH_LIST_ENTRY_NEW2OLD(&replay_packets, e) {
			process_md_clone(e->md, "original packet");
			process_md_clone(e->md, "duplicate packet");
			break;
		}
	}
	if (IMPAIR(REPLAY_FORWARD)) {
		save_any_md_for_replay(mdp);
		struct replay_entry *e = NULL;
		FOR_EACH_LIST_ENTRY_OLD2NEW(&replay_packets, e) {
			process_md_clone(e->md, "replay forward: packet %lu of %lu",
					 e->nr, replay_count);
		}
	}
	if (IMPAIR(REPLAY_BACKWARD)) {
		save_any_md_for_replay(mdp);
		struct replay_entry *e = NULL;
		FOR_EACH_LIST_ENTRY_NEW2OLD(&replay_packets, e) {
			process_md_clone(e->md, "start replay backward: packet %lu of %lu",
					 e->nr, replay_count);
		}
	}
	/* MDP NULL implies things were impaired */
	return *mdp == NULL;
}

static pluto_event_now_cb handle_md_event; /* type assertion */
static void handle_md_event(struct state *st, struct msg_digest **mdp,
			    void *context)
{
	passert(st == NULL);
	passert(mdp == NULL); /* suspended md from state */
	struct msg_digest *md = context;
	process_md(&md);
	pexpect(md == NULL);
	pexpect_reset_globals();
}

void schedule_md_event(const char *name, struct msg_digest *md)
{
	pluto_event_now(name, SOS_NOBODY, handle_md_event, md);
}

/*
 * cisco_stringify()
 *
 * Auxiliary function for modecfg_inR1()
 * Result is allocated on heap so caller must ensure it is freed.
 */
char *cisco_stringify(pb_stream *pbs, const char *attr_name)
{
	char strbuf[500]; /* Cisco maximum unknown - arbitrary choice */
	size_t len = pbs_left(pbs);

	if (len > sizeof(strbuf) - 1)
		len = sizeof(strbuf) - 1;	/* silently truncate */

	memcpy(strbuf, pbs->cur, len);
	strbuf[len] = '\0';

	/*
	 * ' is poison to the way this string will be used
	 * in system() and hence shell.  Remove any.
	 */
	for (char *s = strbuf;; ) {
		s = strchr(s, '\'');
		if (s == NULL)
			break;
		*s = '?';
	}
	sanitize_string(strbuf, sizeof(strbuf));
	loglog(RC_INFORMATIONAL, "Received %s: %s", attr_name, strbuf);
	return clone_str(strbuf, attr_name);
}
