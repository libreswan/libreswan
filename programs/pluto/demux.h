/* demultiplex incoming IKE messages
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2005-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
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

#ifndef _DEMUX_H
#define _DEMUX_H

#include "server.h"
#include "packet.h"
#include "quirks.h"
#include "chunk.h"

struct state;   /* forward declaration of tag */

extern void init_demux(void);
extern event_callback_routine comm_handle_cb;

/* State transition function infrastructure
 *
 * com_handle parses a message, decides what state object it applies to,
 * and calls the appropriate state transition function (STF).
 * These declarations define the interface to these functions.
 *
 * Each STF must be able to be restarted up to any failure point:
 * since an error will not advance the state,
 * a later message will cause the STF to be re-entered.  This
 * explains the use of the replace macro and the care in handling
 * MP_INT members of struct state.
 *
 * A state object (struct state) records what is known about
 * a state between transitions.  Between transitions is roughly:
 * at rest, waiting for an external event.
 *
 * A message digest (struct msg_digest) holds the dissected
 * packet (and more) during a state transition.  This gets
 * a bit muddied by the way packet fragments are re-assembled
 * and the way asyncronous processing cause state transitions
 * to be suspended (eg. crypto helper work).  Think of those
 * things as being within a single state transition.
 */

struct payload_digest {
	pb_stream pbs;
	union payload payload;
	struct payload_digest *next; /* of same kind */
};

struct payload_summary {
	bool parsed;
	v2_notification_t n;
	lset_t present;
	lset_t repeated;
	/* for response, can't use pointers */
	uint8_t data[1];
	size_t data_size;
};

/* message digest
 * Note: raw_packet and packet_pbs are "owners" of space on heap.
 */

struct msg_digest {
	struct msg_digest *next;		/* for free list */
	chunk_t raw_packet;			/* (v1) if encrypted, received packet before decryption */
	const struct iface_port *iface;		/* interface on which message arrived */
	ip_address sender;			/* where message came from (network order) */
	struct isakmp_hdr hdr;			/* message's header */
	bool encrypted;				/* (v1) was it encrypted? */
	enum state_kind from_state;		/* state we started in */
	const struct state_v1_microcode *smc;	/* (v1) microcode for initial state */
	const struct state_v2_microcode *svm;	/* (v2) microcode for initial state */
	bool new_iv_set;			/* (v1) */
	struct state *st;			/* current state object */

	enum message_role message_role;		/* (v2) */
	msgid_t msgid_received;			/* (v2) - Host order! */

	notification_t v1_note;			/* reason for failure */
	bool dpd;				/* (v1) Peer supports RFC 3706 DPD */
	bool ikev2;				/* Peer supports IKEv2 */
	bool fragvid;				/* (v1) Peer supports FRAGMENTATION */
	bool nortel;				/* (v1) Peer requires Nortel specific workaround */
	bool event_already_set;			/* (v1) */
	bool fake;				/* is this a fake (clone) message */

	/*
	 * The packet PBS contains a message PBS and the message PBS
	 * contains payloads one of which (for IKEv2) is the SK which
	 * also contains payloads.
	 *
	 * Danger Will Robinson: since the digest contains a pbs
	 * pointing at one of these PBS fields, and these fields point
	 * at each other, their lifetime is the same as the
	 * msg_digest.
	 */
	pb_stream packet_pbs;			/* whole packet */
	pb_stream message_pbs;			/* message to be processed */

#   define PAYLIMIT 30
	struct payload_digest digest[PAYLIMIT];
	unsigned digest_roof;

	struct payload_summary message_payloads;	/* (v2) */
	struct payload_summary encrypted_payloads;	/* (v2) */

	/*
	 * Indexed by next-payload.  IKEv1 and IKEv2 use the same
	 * array but different ranges.
	 *
	 * Regardless of the IKE version, the index is always less
	 * than LELEM_ROOF.  This is because the next-payload
	 * (converted to a bit map) is also stored in lset_t (lset_t
	 * has LELEM_ROOF as its bound). Any larger value, such as
	 * v2IKE_FRAGMENTATION, must have been droped before things
	 * get this far.
	 *
	 * XXX: While the real upper bound is closer to 53 (vs 64)
	 * there's no value in shaving those few extra bytes - this
	 * structure is transient.
	 *
	 * XXX: Even though the IKEv2 values start at 33, they are not
	 * biased to save space.  This is because it would break the
	 * 1:1 correspondance between the wire-value, this array, and
	 * the lset_t bit (at one point the lset_t values were biased,
	 * the result was confusing custom mapping code everywhere).
	 */
	struct payload_digest *chain[LELEM_ROOF];
	struct isakmp_quirks quirks;
};

extern struct msg_digest *alloc_md(const char *mdname);
struct msg_digest *clone_md(struct msg_digest *md, const char *name);
extern void release_md(struct msg_digest *md);
extern void release_any_md(struct msg_digest **mdp);
void schedule_md_event(const char *name, struct msg_digest *md);

extern void free_md_pool(void);

extern void process_packet(struct msg_digest **mdp);

extern char *cisco_stringify(pb_stream *pbs, const char *attr_name);

#endif /* _DEMUX_H */
