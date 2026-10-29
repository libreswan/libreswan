/* demultiplex incoming IKE messages
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2005-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2018-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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

#ifndef DEMUX_H
#define DEMUX_H

#include "server.h"
#ifdef USE_IKEv1
#include "ikev1_packet.h"
#endif
#include "ikev2_packet.h"
#include "quirks.h"
#include "chunk.h"
#include "ip_address.h"
#include "pluto_timing.h"
#include "refcnt.h"
#include "where.h"
#include "crypt_mac.h"
#include "verbose.h"

struct state;   /* forward declaration of tag */
struct iface_endpoint;
struct logger;

/*
 * Used by UDP and TCP to inject packets.
 */

void process_iface_packet(struct verbose verbose, int fd, void *ifp_arg);

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
	union {
		struct isakmp_generic generic;
#ifdef USE_IKEv1
		struct isakmp_sa sa;
		struct isakmp_proposal proposal;
		struct isakmp_transform transform;
		struct isakmp_id id; /* Main Mode */
		struct isakmp_cert cert;
		struct isakmp_cr cr;
		struct isakmp_ipsec_id ipsec_id; /* Quick Mode */
		struct isakmp_notification notification;
		struct isakmp_delete delete;
		struct isakmp_nat_oa nat_oa;
		struct isakmp_mode_attr mode_attribute;
#endif
		struct ikev2_generic v2gen;
		struct ikev2_ke_payload v2ke;
		struct ikev2_trans v2trans;
		struct ikev2_prop v2prop;
		struct ikev2_sa v2sa;
		struct ikev2_id v2id;
		struct ikev2_auth v2auth;
		struct ikev2_ts v2ts;
		struct ikev2_cert v2cert;
		struct ikev2_certreq v2certreq;
		struct ikev2_notify v2n;
		struct ikev2_delete v2delete;
		struct ikev2_cp v2cp;
		struct ikev2_cp_attribute v2cp_attribute;
		struct ikev2_skf v2skf;
	} payload;
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

enum v2N_status {
	v2N_status_IGNORE = 0,

	/*
	 * XXX: Error notifications are kept separate.  The first
	 * (there should be only one) is saved in .v2N_error.
	 */

	/*UNSUPPORTED_CRITICAL_PAYLOAD*/	/* IKE FATAL */
	/*INVALID_IKE_SPI*/			/* IKE drop */
	/*INVALID_MAJOR_VERSION*/		/* IKE drop */
	/*INVALID_SYNTAX*/			/* IKE FATAL */
	/*INVALID_MESSAGE_ID*/			/* IKE */
	/*INVALID_SPI*/				/* IKE */
	/*NO_PROPOSAL_CHOSEN*/			/* IKE+CHILD */
	/*INVALID_KE_PAYLOAD*/			/* IKE+CHILD */
	/*AUTHENTICATION_FAILED*/		/* IKE FATAL */
	/*SINGLE_PAIR_REQUIRED*/		/* CHILD fails */
	/*NO_ADDITIONAL_SAS*/			/* CHILD fails */
	/*INTERNAL_ADDRESS_FAILURE*/		/* CHILD fails */
	/*FAILED_CP_REQUIRED*/			/* CHILD fails */
	/*TS_UNACCEPTABLE*/			/* CHILD fails */
	/*INVALID_SELECTORS*/			/* CHILD fails */
	/*TEMPORARY_FAILURE*/			/* IKE+CHILD retry */
	/*CHILD_SA_NOT_FOUND*/			/* CHILD informational */

	/* status notifications */
	v2N_status_ADDITIONAL_KEY_EXCHANGE,
	v2N_status_COOKIE,
	v2N_status_COOKIE2,
	v2N_status_CHILDLESS_IKEV2_SUPPORTED,
	v2N_status_ESP_TFC_PADDING_NOT_SUPPORTED,
	v2N_status_IKEV2_FRAGMENTATION_SUPPORTED,
	v2N_status_INITIAL_CONTACT,
	v2N_status_INTERMEDIATE_EXCHANGE_SUPPORTED,
	v2N_status_IPCOMP_SUPPORTED,
	v2N_status_MOBIKE_SUPPORTED,
	v2N_status_NAT_DETECTION_DESTINATION_IP,
	v2N_status_NAT_DETECTION_SOURCE_IP,
	v2N_status_NO_PPK_AUTH,
	v2N_status_NULL_AUTH,
	v2N_status_PPK_IDENTITY,
	v2N_status_PPK_IDENTITY_KEY,
	v2N_status_REDIRECT,
	v2N_status_REDIRECTED_FROM,
	v2N_status_REDIRECT_SUPPORTED,
	v2N_status_REKEY_SA,
	v2N_status_SIGNATURE_HASH_ALGORITHMS,
	v2N_status_SUPPORTED_AUTH_METHODS,
	v2N_status_UPDATE_SA_ADDRESSES,
	v2N_status_USE_PPK,
	v2N_status_USE_PPK_INT,
	v2N_status_USE_TRANSPORT_MODE,
	v2N_status_USE_AGGFRAG,
	v2N_status_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH,
	v2N_status_TICKET_LT_OPAQUE,
	v2N_status_TICKET_REQUEST,
	v2N_status_TICKET_ACK,
	v2N_status_TICKET_NACK,
	v2N_status_TICKET_OPAQUE,
	v2N_status_SA_RESOURCE_INFO,
	v2N_status_TS_MAX_QUEUE,
	v2N_status_CHILD_SA_PFS_INFO_SUPPORTED,
	v2N_status_ROOF,
};

/* message digest
 *
 * Note: raw_packet and packet_pbs are "owners" of space on heap.
 */

struct msg_digest {
	refcnt_t refcnt;	/* must be first */
	chunk_t v1_raw_packet;			/* (v1) if encrypted,
						 * received packet
						 * before
						 * decryption */

	struct iface_endpoint *iface;		/* interface on which message arrived */
	ip_endpoint sender;			/* address:port where message came from */
	struct isakmp_hdr hdr;			/* message's header */
	bool encrypted;				/* (v1) was it encrypted? */
	const struct state_v1_microcode *smc;	/* (v1) microcode for initial state */
	struct crypt_mac v1_decrypt_iv;		/* (v1) needed to
						 * decrypt the
						 * message */
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
	 * Note that .v2N_status[] is indexed using enum v2N_status.
	 * I.e., NOT exchange type; and NOT_notification_t.
	 *
	 * enum v2N_status is contiguous / compact, while the latter
	 * can be sparse.
	 */
	const struct payload_digest *v2N_status[v2N_status_ROOF];

	/*
	 * The first IKEv2 error notification found in the payload
	 * (error notifications are <16384), else NULL.
	 *
	 * Error notifications don't necessarially mean that things
	 * have totally failed.  For instance, an IKE_AUTH response
	 * can contain an error notification indicating that the CHILD
	 * SA failed (but the IKE SA succeeded).
	 */
	const struct payload_digest *v2N_error;

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
	chunk_t packet;
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
	struct isakmp_quirks v1_quirks;
};

enum ike_version hdr_ike_version(const struct isakmp_hdr *hdr);
enum message_role v2_msg_role(const struct msg_digest *md);

extern struct msg_digest *alloc_md(struct iface_endpoint *ifp,
				   const ip_endpoint sender,
				   const uint8_t *packet, size_t packet_len,
				   struct logger *logger, where_t where);
struct msg_digest *md_addref_where(struct msg_digest *md, where_t where);
#define md_addref(MD) md_addref_where(MD, HERE)
void md_delref_where(struct msg_digest **mdp, where_t where);
#define md_delref(MDP) md_delref_where(MDP, HERE)

/* only the buffer */
struct msg_digest *clone_raw_md(struct msg_digest *md, where_t where);

void jam_msg_digest_payloads(struct jambuf *buf,
			     const struct msg_digest *md);

void schedule_md_event(const char *story, struct msg_digest *md);

/* rate limited logging */
void limited_llog_md(const struct msg_digest *md, const char *message, ...) PRINTF_LIKE(2);

void process_md(struct msg_digest *md);

#endif
