/* demultiplex incoming IKE messages
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2005-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2018-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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
#include "packet.h"		/* for struct pbs_in */
#include "quirks.h"
#include "chunk.h"
#include "ip_address.h"
#include "pluto_timing.h"
#include "refcnt.h"
#include "where.h"

struct state;   /* forward declaration of tag */
struct iface_endpoint;
struct logger;

/*
 * Used by UDP and TCP to inject packets.
 */

void process_iface_packet(int fd, void *ifp_arg, struct logger *logger);

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
 * and the way asynchronous processing cause state transitions
 * to be suspended (eg. crypto helper work).  Think of those
 * things as being within a single state transition.
 */

struct payload_digest {
	struct pbs_in pbs;
	/* Use IKEv2 term: "... the payload type" */
	unsigned payload_type;
	union payload payload;
	struct payload_digest *next; /* of same type */
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

/*
 * Compact enum of useful-to-pluto IKEv2 payloads.  Unlike the
 * official numbers, these are contiguous.
 */

enum v2_pd {
	PD_v2_INVALID = 0,

	PD_v2N_AUTHENTICATION_FAILED,
	PD_v2N_COOKIE,
	PD_v2N_COOKIE2,
	PD_v2N_CHILDLESS_IKEV2_SUPPORTED,
	PD_v2N_ESP_TFC_PADDING_NOT_SUPPORTED,
	PD_v2N_FAILED_CP_REQUIRED,
	PD_v2N_IKEV2_FRAGMENTATION_SUPPORTED,
	PD_v2N_INITIAL_CONTACT,
	PD_v2N_INTERMEDIATE_EXCHANGE_SUPPORTED,
	PD_v2N_INTERNAL_ADDRESS_FAILURE,
	PD_v2N_INVALID_KE_PAYLOAD,
	PD_v2N_INVALID_MAJOR_VERSION,
	PD_v2N_INVALID_SYNTAX,
	PD_v2N_IPCOMP_SUPPORTED,
	PD_v2N_MOBIKE_SUPPORTED,
	PD_v2N_NAT_DETECTION_DESTINATION_IP,
	PD_v2N_NAT_DETECTION_SOURCE_IP,
	PD_v2N_NO_PPK_AUTH,
	PD_v2N_NO_PROPOSAL_CHOSEN,
	PD_v2N_NULL_AUTH,
	PD_v2N_PPK_IDENTITY,
	PD_v2N_REDIRECT,
	PD_v2N_REDIRECTED_FROM,
	PD_v2N_REDIRECT_SUPPORTED,
	PD_v2N_REKEY_SA,
	PD_v2N_SIGNATURE_HASH_ALGORITHMS,
	PD_v2N_SINGLE_PAIR_REQUIRED,
	PD_v2N_TS_UNACCEPTABLE,
	PD_v2N_UNSUPPORTED_CRITICAL_PAYLOAD,
	PD_v2N_UPDATE_SA_ADDRESSES,
	PD_v2N_USE_PPK,
	PD_v2N_USE_TRANSPORT_MODE,
	PD_v2N_USE_AGGFRAG,

	PD_v2_ROOF,
};

#if 0
enum v1_pb {
	PD_v1_INVALID,
	PD_v1_ROOF,
};
#endif

/* message digest
 * Note: raw_packet and packet_pbs are "owners" of space on heap.
 */

struct msg_digest {
	refcnt_t refcnt;
	chunk_t raw_packet;			/* (v1) if encrypted, received packet before decryption */
	struct iface_endpoint *iface;		/* interface on which message arrived */
	ip_endpoint sender;			/* address:port where message came from */
	struct isakmp_hdr hdr;			/* message's header */
	bool encrypted;				/* (v1) was it encrypted? */
	const struct state_v1_microcode *smc;	/* (v1) microcode for initial state */
	bool new_iv_set;			/* (v1) */
	struct state *v1_st;			/* (v1) current state object */
	struct logger *logger;			/* logger for this MD */

	threadtime_t md_inception;		/* when was this started */

	v1_notification_t v1_note;			/* reason for failure */
	bool dpd;				/* (v1) Peer supports RFC 3706 DPD */
	bool ikev2;				/* Peer supports IKEv2 */
	bool fragvid;				/* (v1) Peer supports FRAGMENTATION */
	bool fake_clone;			/* is this a fake (clone) message */
	unsigned v2_frags_total;		/* total fragments */

	/*
	 * Note that .pd[] is indexed using either enum v1_pd or enum
	 * v2_pd and not exchange type, v2_notification_t, ....  This
	 * is because the former is contiguous, while the latter is
	 * very very sparse.
	 */
	const struct payload_digest *pd[PD_v2_ROOF];

	/*
	 * The first IKEv2 error notification found in the payload
	 * (error notifications are <16384), else v2N_NOTHING_WRONG
	 * i.e., 0.
	 *
	 * Error notifications don't necessarially mean that things
	 * have totally failed.  For instance, an IKE_AUTH response
	 * can contain an error notification indicating that the CHILD
	 * SA failed (but the IKE SA succeeded).
	 */
	v2_notification_t v2N_error;

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
	struct pbs_in packet_pbs;			/* whole packet */
	struct pbs_in message_pbs;			/* message to be processed */

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
	 * v2IKE_FRAGMENTATION, must have been dropped before things
	 * get this far.
	 *
	 * XXX: While the real upper bound is closer to 53 (vs 64)
	 * there's no value in shaving those few extra bytes - this
	 * structure is transient.
	 *
	 * XXX: Even though the IKEv2 values start at 33, they are not
	 * biased to save space.  This is because it would break the
	 * 1:1 correspondence between the wire-value, this array, and
	 * the lset_t bit (at one point the lset_t values were biased,
	 * the result was confusing custom mapping code everywhere).
	 */
	struct payload_digest *chain[LELEM_ROOF];
	struct payload_digest *last[LELEM_ROOF];
	struct isakmp_quirks quirks;
};

enum ike_version hdr_ike_version(const struct isakmp_hdr *hdr);
enum message_role v2_msg_role(const struct msg_digest *md);

extern struct msg_digest *alloc_md(struct iface_endpoint *ifp,
				   const ip_endpoint *sender,
				   const uint8_t *packet, size_t packet_len,
				   where_t where);
struct msg_digest *md_addref_where(struct msg_digest *md, where_t where);
#define md_addref(MD) md_addref_where(MD, HERE)
void md_delref_where(struct msg_digest **mdp, where_t where);
#define md_delref(MDP) md_delref_where(MDP, HERE)

/* only the buffer */
struct msg_digest *clone_raw_md(struct msg_digest *md, where_t where);

void schedule_md_event(const char *story, struct msg_digest *md);

void llog_msg_digest(lset_t rc_flags, struct logger *logger,
		     const char *prefix, const struct msg_digest *md);

/* rate limited logging */
void llog_md(const struct msg_digest *md, const char *message, ...) PRINTF_LIKE(2);

void process_md(struct msg_digest *md);

#endif /* _DEMUX_H */
