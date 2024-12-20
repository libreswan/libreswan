/*
 * IKEv1 send packets, for libreswan
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
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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

#include "defs.h"
#include "send.h"
#include "log.h"
#include "ikev1_send.h"
#include "state.h"
#include "server.h"
#include "connections.h"
#include "ip_info.h"
#include "iface.h"
#include "demux.h"
#include "pluto_stats.h"

/*
 * (IKE v1) send fragments of packet.
 *
 * non-IETF magic voodoo we need to consider for interop:
 * - www.cisco.com/en/US/docs/ios/sec_secure_connectivity/configuration/guide/sec_fragment_ike_pack.html
 * - www.cisco.com/en/US/docs/ios-xml/ios/sec_conn_ikevpn/configuration/15-mt/sec-fragment-ike-pack.pdf
 * - msdn.microsoft.com/en-us/library/cc233452.aspx
 * - iOS/Apple racoon source ipsec-164.9 at www.opensource.apple.com (frak length 1280)
 * - stock racoon source (frak length 552)
 */

static bool send_v1_frags(struct state *st, const char *where)
{
	unsigned int fragnum = 0;

	/*
	 * If we are doing NATT, so that the other end doesn't mistake
	 * this message for ESP, each fragment needs a non-ESP_Marker
	 * prefix.  natt_bonus is the size of the addition (0 if not
	 * needed).
	 */
	const size_t natt_bonus =
		st->st_iface_endpoint->esp_encapsulation_enabled ? NON_ESP_MARKER_SIZE : 0;

	/* We limit fragment packets to ISAKMP_FRAG_MAXLEN octets.
	 * max_data_len is the maximum data length that will fit within it.
	 */
	const size_t max_data_len =
		endpoint_info(st->st_remote_endpoint)->ikev1_max_fragment_size
		-
		(natt_bonus + NSIZEOF_isakmp_hdr +
		 NSIZEOF_isakmp_ikefrag);

	uint8_t *packet_cursor = st->st_v1_tpacket.ptr;
	size_t packet_remainder_len = st->st_v1_tpacket.len;

	/* BUG: this code does not use the marshalling code
	 * in packet.h to translate between wire and host format.
	 * This is dangerous.  The following assertion should
	 * fail in most cases where this cheat won't work.
	 */
	passert(sizeof(struct isakmp_hdr) == NSIZEOF_isakmp_hdr &&
		sizeof(struct isakmp_ikefrag) == NSIZEOF_isakmp_ikefrag);

	while (packet_remainder_len > 0) {
		uint8_t frag_prefix[NSIZEOF_isakmp_hdr +
				     NSIZEOF_isakmp_ikefrag];
		const size_t data_len = packet_remainder_len > max_data_len ?
					max_data_len : packet_remainder_len;
		const size_t fragpl_len = NSIZEOF_isakmp_ikefrag + data_len;
		const size_t isakmppl_len = NSIZEOF_isakmp_hdr + fragpl_len;

		/*
		 * process_v1_packet would not accept this if it were greater
		 * than 16 but it is hard to see how this would happen.
		 */
		fragnum++;

		/* emit isakmp header derived from original */
		{
			struct isakmp_hdr *ih =
				(struct isakmp_hdr *) frag_prefix;

			memcpy(ih, st->st_v1_tpacket.ptr, NSIZEOF_isakmp_hdr);
			ih->isa_np = ISAKMP_NEXT_IKE_FRAGMENTATION; /* one octet */
			/*
			 * Do we need to set any of
			 * ISAKMP_FLAGS_v1_ENCRYPTION?  Seems there
			 * might be disagreement between Cisco and
			 * Microsoft.
			 */
			ih->isa_flags &= ~ISAKMP_FLAGS_v1_ENCRYPTION;
			ih->isa_length = htonl(isakmppl_len);
		}

		/* Append the ike frag header */
		{
			struct isakmp_ikefrag *fh =
				(struct isakmp_ikefrag *) (frag_prefix +
							  NSIZEOF_isakmp_hdr);

			fh->isafrag_np = ISAKMP_NEXT_NONE;             /* must be zero */
			fh->isafrag_reserved = 0;       /* reserved at this time, must be zero */
			fh->isafrag_length = htons(fragpl_len);
			fh->isafrag_id = htons(1);      /* In theory required to be unique, in practise not needed? */
			fh->isafrag_number = fragnum;   /* one byte, no htons() call needed */
			fh->isafrag_flags = packet_remainder_len == data_len ?
					    ISAKMP_FRAG_LAST : 0;
		}
		dbg("sending IKE fragment id '%d', number '%u'%s",
		    1, /* hard coded for now, seems to be what all the cool implementations do */
		    fragnum,
		    packet_remainder_len == data_len ? " (last)" : "");

		if (!send_shunks_using_state(st, where,
					     shunk2(frag_prefix,
						    NSIZEOF_isakmp_hdr + NSIZEOF_isakmp_ikefrag),
					     shunk2(packet_cursor, data_len)))
			return false;

		packet_remainder_len -= data_len;
		packet_cursor += data_len;
	}
	return true;
}

static bool should_fragment_v1_ike_msg(struct state *st, size_t len, bool resending)
{
	/*
	 * If we are doing NATT, so that the other end doesn't mistake
	 * this message for ESP, each fragment needs a non-ESP_Marker
	 * prefix.  natt_bonus is the size of the addition (0 if not
	 * needed).
	 */
	if (st->st_iface_endpoint != NULL && st->st_iface_endpoint->esp_encapsulation_enabled)
		len += NON_ESP_MARKER_SIZE;

	/* This condition is complex.  Formatting is meant to help reader.
	 *
	 * Hugh thinks peers banished style would make this earlier version
	 * a little clearer:
	 * len + natt_bonus
	 *    >= (st->st_connection->addr_family == AF_INET
	 *       ? ISAKMP_FRAG_MAXLEN_IPv4 : ISAKMP_FRAG_MAXLEN_IPv6)
	 * && ((  resending
	 *        && (st->st_connection->policy & POLICY_IKE_FRAG_ALLOW)
	 *        && st->st_seen_fragmentation_supported)
	 *     || (st->st_connection->policy & POLICY_IKE_FRAG_FORCE)
	 *     || st->st_v1_seen_fragments))
	 *
	 * ??? the following test does not account for natt_bonus
	 */
	return len >= endpoint_info(st->st_remote_endpoint)->ikev1_max_fragment_size &&
	    (   (resending &&
		 st->st_connection->config->ike_frag.allow &&
		 st->st_v1_seen_fragmentation_supported) ||
		st->st_connection->config->ike_frag.v1_force ||
		st->st_v1_seen_fragments   );
}

static bool send_or_resend_v1_ike_msg_from_state(struct state *st,
						 const char *where,
						 bool resending)
{
	if (st->st_iface_endpoint == NULL) {
		log_state(RC_LOG, st, "Cannot send packet - interface vanished!");
		return false;
	}
	/* another bandaid */
	if (st->st_v1_tpacket.ptr == NULL) {
		log_state(RC_LOG, st, "Cannot send packet - st_v1_tpacket.ptr is NULL");
		return false;
	}

	/*
	 * If we are doing NATT, so that the other end doesn't mistake
	 * this message for ESP, each fragment needs a non-ESP_Marker
	 * prefix.  natt_bonus is the size of the addition (0 if not
	 * needed).
	 */
	size_t natt_bonus = st->st_iface_endpoint->esp_encapsulation_enabled ? NON_ESP_MARKER_SIZE : 0;
	size_t len = st->st_v1_tpacket.len;

	passert(len != 0);

	/*
	 * Decide of whether we're to fragment.  First attempt sends
	 * the packet out as a single blob, second and later attempts
	 * fragment.
	 *
	 * ??? why can't we fragment in STATE_MAIN_I1?  XXX: something
	 * to do with the attacks initial packet?
	 */
	if (st->st_state->kind != STATE_MAIN_I1 &&
	    should_fragment_v1_ike_msg(st, len + natt_bonus, resending)) {
		return send_v1_frags(st, where);
	} else {
		return send_hunk_using_state(st, where, st->st_v1_tpacket);
	}
}

bool resend_recorded_v1_ike_msg(struct state *st, const char *where)
{
	bool ret = send_or_resend_v1_ike_msg_from_state(st, where, true);

	if (st->st_state->kind == STATE_XAUTH_R0 &&
	    !st->st_connection->config->aggressive) {
		/* Only for Main mode + XAUTH */
		event_schedule(EVENT_v1_SEND_XAUTH, deltatime_from_milliseconds(EVENT_v1_SEND_XAUTH_DELAY_MS), st);
	}

	return ret;
}

bool record_and_send_v1_ike_msg(struct state *st, struct pbs_out *pbs, const char *what)
{
	record_outbound_v1_ike_msg(st, pbs, what);
	return send_or_resend_v1_ike_msg_from_state(st, what, false);
}

void record_outbound_v1_ike_msg(struct state *st, struct pbs_out *pbs, const char *what)
{
	shunk_t packet = pbs_out_all(pbs);
	passert(packet.len > 0);
	free_v1_message_queues(st);
	replace_chunk(&st->st_v1_tpacket, packet, what);
}

void free_v1_message_queues(struct state *st)
{
	passert(st->st_ike_version == IKEv1);

	struct v1_ike_rfrag *frag = st->st_v1_rfrags;
	while (frag != NULL) {
		struct v1_ike_rfrag *this = frag;

		frag = this->next;
		pexpect(this->md != NULL);
		md_delref(&this->md);
		pfree(this);
	}

	st->st_v1_rfrags = NULL;
}
