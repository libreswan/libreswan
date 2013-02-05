/* demultiplex incoming IKE messages
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
 */

#ifndef _DEMUX_H
#define _DEMUX_H

#include "server.h"
#include "packet.h"
#include "quirks.h"

struct state;	/* forward declaration of tag */
extern void init_demux(void);
extern bool send_packet(struct state *st, const char *where, bool verbose);
extern void comm_handle(const struct iface_port *ifp);

extern pb_stream reply_stream;
extern u_int8_t reply_buffer[MAX_OUTPUT_UDP_SIZE];

/* State transition function infrastructure
 *
 * com_handle parses a message, decides what state object it applies to,
 * and calls the appropriate state transition function (STF).
 * These declarations define the interface to these functions.
 *
 * Each STF must be able to be restarted up to any failure point:
 * a later message will cause the state to be re-entered.  This
 * explains the use of the replace macro and the care in handling
 * MP_INT members of struct state.
 */

struct payload_digest {
    pb_stream pbs;
    union payload payload;
    struct payload_digest *next;   /* of same kind */
};

/* message digest
 * Note: raw_packet and packet_pbs are "owners" of space on heap.
 */

struct msg_digest {
    struct msg_digest *next;	/* for free list */
    chunk_t raw_packet;		/* if encrypted, received packet before decryption */
    const struct iface_port *iface;	/* interface on which message arrived */
    ip_address sender;	        /* where message came from (network order) */
    u_int16_t sender_port;	/* host order */
    pb_stream packet_pbs;	/* whole packet */
    pb_stream message_pbs;	/* message to be processed */
    pb_stream clr_pbs;          /* place to store decrypted packet */
    struct isakmp_hdr hdr;	/* message's header */
    bool encrypted;	/* was it encrypted? */
    enum state_kind from_state;	/* state we started in */
    const struct state_microcode *smc;	  /* microcode for initial state (v1)*/
    const struct state_v2_microcode *svm; /* microcode for initial state (v2)*/
    bool new_iv_set;
    struct state *st;	/* current state object */
    struct state *pst;  /* parent state object (if any) */

    enum phase1_role role;
    msgid_t          msgid_received;
    
    pb_stream rbody;	/* room for reply body (after header) */
    notification_t note;	/* reason for failure */
    bool dpd;           /* Peer supports RFC 3706 DPD */
    bool ikev2;         /* Peer supports IKEv2 */
    bool event_already_set;
    stf_status result;  /* temporary stored here for access by Tcl */


#   define PAYLIMIT 30
    struct payload_digest
	digest[PAYLIMIT],
	*digest_roof,
	*chain[ISAKMP_NEXT_ROOF];
    struct isakmp_quirks quirks;
};

extern struct msg_digest *alloc_md(void);
extern void release_md(struct msg_digest *md);

typedef stf_status state_transition_fn(struct msg_digest *md);

extern void fmt_ipsec_sa_established(struct state *st
				     , char *sadetails, int sad_len);
extern void fmt_isakmp_sa_established(struct state *st
				      , char *sadetails, int sad_len);

extern void free_md_pool(void);

/* deal with echo request/reply */
extern void receive_ike_echo_request(struct msg_digest *md);
extern void receive_ike_echo_reply(struct msg_digest *md);

extern void process_packet(struct msg_digest **mdp);
extern void process_v1_packet(struct msg_digest **mdp);
extern void process_v2_packet(struct msg_digest **mdp);
extern bool check_msg_errqueue(const struct iface_port *ifp, short interest);


#endif /* _DEMUX_H */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
 
