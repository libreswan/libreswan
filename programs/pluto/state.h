/* state and event objects
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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
 * RCSID $Id: state.h,v 1.100 2005/08/05 19:16:49 mcr Exp $
 */

#ifndef _STATE_H
#define _STATE_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <gmp.h>    /* GNU MP library */
#include "quirks.h"

/* Message ID mechanism.
 *
 * A Message ID is contained in each IKE message header.
 * For Phase 1 exchanges (Main and Aggressive), it will be zero.
 * For other exchanges, which must be under the protection of an
 * ISAKMP SA, the Message ID must be unique within that ISAKMP SA.
 * Effectively, this labels the message as belonging to a particular
 * exchange.
 *
 * RFC2408 "ISAKMP" 3.1 "ISAKMP Header Format" (near end) states that
 * the Message ID must be unique.  We interpret this to be "unique within
 * one ISAKMP SA".
 *
 * BTW, we feel this uniqueness allows rekeying to be somewhat simpler
 * than specified by draft-jenkins-ipsec-rekeying-06.txt.
 */

typedef u_int32_t msgid_t;	/* Network order! */
#define MAINMODE_MSGID    ((msgid_t) 0)

struct state;	/* forward declaration of tag */
extern bool reserve_msgid(struct state *isakmp_sa, msgid_t msgid);
extern msgid_t generate_msgid(struct state *isakmp_sa);


/* Oakley (Phase 1 / Main Mode) transform and attributes
 * This is a flattened/decoded version of what is represented
 * in the Transaction Payload.
 * Names are chosen to match corresponding names in state.
 */
struct oakley_trans_attrs {
    u_int16_t encrypt;		/* Encryption algorithm */
    u_int16_t enckeylen;	/* encryption key len (bits) */
    const struct encrypt_desc *encrypter;	/* package of encryption routines */
    oakley_hash_t hash;		/* Hash algorithm */
    const struct hash_desc *hasher;	/* package of hashing routines */
    oakley_auth_t auth;		/* Authentication method */
#ifdef XAUTH
    u_int16_t xauth;            /* did we negotiate Extended Authentication? */
#endif
    const struct oakley_group_desc *group;	/* Oakley group */
    time_t life_seconds;	/* When this SA expires (seconds) */
    u_int32_t life_kilobytes;	/* When this SA is exhausted (kilobytes) */
#if 0 /* not yet */
    u_int16_t prf;		/* Pseudo Random Function */
#endif
};

/* IPsec (Phase 2 / Quick Mode) transform and attributes
 * This is a flattened/decoded version of what is represented
 * by a Transaction Payload.  There may be one for AH, one
 * for ESP, and a funny one for IPCOMP.
 *
 * Yes, this is screwy -- we keep different direction information
 * in different places. Fix it up sometime.
 */
struct ipsec_trans_attrs {
    u_int8_t transid;	/* transform id */
    ipsec_spi_t spi;	/* his SPI */
    time_t life_seconds;		/* When this SA expires */
    u_int32_t life_kilobytes;	/* When this SA expires */
    u_int16_t encapsulation;
    ipsec_auth_t auth;            
    u_int16_t key_len;
    u_int16_t key_rounds;
#if 0 /* not implemented yet */
    u_int16_t cmprs_dict_sz;
    u_int32_t cmprs_alg;
#endif
};

/* IPsec per protocol state information */
struct ipsec_proto_info {
    bool present;	/* was this transform specified? */
    struct ipsec_trans_attrs attrs;   /* info on remote */
    ipsec_spi_t our_spi;
    u_int16_t keymat_len;	/* same for both */
    u_char *our_keymat;
    u_char *peer_keymat;
};

/* internal state that
 * should get copied by god
 * Eistein would be proud
 */

struct hidden_variables {
    unsigned int   st_malformed_received;
    unsigned int   st_malformed_sent;
    bool           st_xauth_client_done;
    int            st_xauth_client_attempt;
    bool           st_modecfg_server_done;
    bool           st_modecfg_vars_set;
    bool           st_got_certrequest;
    bool           st_modecfg_started;
    bool           st_skeyid_calculated;
    bool           st_dpd;                 /* Peer supports DPD */
    bool           st_dpd_local;	   /* If we want DPD on this conn */
    bool           st_logged_p1algos;      /* if we have logged algos */
    u_int32_t      st_nat_traversal;       /* bit field of permitted
					    * methods. If non-zero, then
					    * NAT-T has been detected, and
					    * should be used. */
    ip_address     st_nat_oa;
    ip_address     st_natd;
};                        

#define set_suspended(st,md) do { st->st_suspended_md=md; \
                                  st->st_suspended_md_func=__FUNCTION__; \
                                  st->st_suspended_md_line=__LINE__; } while(0)

/* state object: record the state of a (possibly nascent) SA
 *
 * Invariants (violated only during short transitions):
 * - each state object will be in statetable exactly once.
 * - each state object will always have a pending event.
 *   This prevents leaks.
 */
struct state
{
    so_serial_t        st_serialno;          /*serial number (for seniority) */
    so_serial_t        st_clonedfrom;        /* serial number of parent */
    int                st_usage;

    struct connection *st_connection;          /* connection for this SA */
    int                st_whack_sock;          /* fd for our Whack TCP socket.
                                                * Single copy: close when
						* freeing struct.
                                                */

    struct msg_digest *st_suspended_md;        /* suspended state-transition */
    const char        *st_suspended_md_func;
    int                st_suspended_md_line;

    struct oakley_trans_attrs st_oakley;

    struct ipsec_proto_info st_ah;
    struct ipsec_proto_info st_esp;
    struct ipsec_proto_info st_ipcomp;

    ipsec_spi_t        st_tunnel_in_spi;          /* KLUDGE */
    ipsec_spi_t        st_tunnel_out_spi;         /* KLUDGE */

    IPsecSAref_t       ref;	   /* our kernel name for our incoming SA */
    IPsecSAref_t       refhim;     /* our kernel name for our outgoing SA */

    const struct oakley_group_desc *st_pfs_group; /*group for Phase 2 PFS */

    u_int32_t          st_doi;                 /* Domain of Interpretation */
    u_int32_t          st_situation;

    lset_t             st_policy;              /* policy for IPsec SA */

    ip_address         st_remoteaddr;          /* where to send packets to */
    u_int16_t          st_remoteport;          /* host byte order */
    
    const struct iface_port *st_interface;     /* where to send from */
    ip_address         st_localaddr;           /* where to send them from */
    u_int16_t          st_localport;           

    msgid_t            st_msgid;               /* MSG-ID from header.  Network Order! */

    msgid_t            st_msgid_phase15;       /* msgid for phase 1.5 */
    msgid_t            st_msgid_phase15b;      /* msgid for phase 1.5 */

    /* only for a state representing an ISAKMP SA */
    struct msgid_list  *st_used_msgids;        /* used-up msgids */

/* symmetric stuff */

  /* initiator stuff */
    chunk_t            st_gi;                  /* Initiator public value */
    u_int8_t           st_icookie[COOKIE_SIZE];/* Initiator Cookie */
    chunk_t            st_ni;                  /* Ni nonce */

  /* responder stuff */
    chunk_t            st_gr;                  /* Responder public value */
    u_int8_t           st_rcookie[COOKIE_SIZE];/* Responder Cookie */
    chunk_t            st_nr;                  /* Nr nonce */


  /* my stuff */

    chunk_t            st_tpacket;             /* Transmitted packet */

    /* Phase 2 ID payload info about my user */
    u_int8_t           st_myuserprotoid;       /* IDcx.protoid */
    u_int16_t          st_myuserport;

  /* his stuff */

    chunk_t            st_rpacket;             /* Received packet */

    /* Phase 2 ID payload info about peer's user */
    u_int8_t           st_peeruserprotoid;     /* IDcx.protoid */
    u_int16_t          st_peeruserport;

/* end of symmetric stuff */

    u_int8_t           st_sec_in_use;      /* bool: does st_sec hold a value */
    MP_INT             st_sec;             /* Our local secret value */
    chunk_t            st_sec_chunk;       /* copy of above */

    chunk_t            st_shared;              /* Derived shared secret
                                                * Note: during Quick Mode,
                                                * presence indicates PFS
                                                * selected.
                                                */
    enum crypto_importance st_import;          /* relative priority of crypto
						* operations
						*/

    /* In a Phase 1 state, preserve peer's public key after authentication */
    struct pubkey     *st_peer_pubkey;

    enum state_kind    st_state;               /* State of exchange */
    u_int8_t           st_retransmit;          /* Number of retransmits */
    unsigned long      st_try;                 /* number of times rekeying attempted */
                                               /* 0 means the only time */
    time_t             st_margin;              /* life after EVENT_SA_REPLACE*/
    unsigned long      st_outbound_count;      /* traffic through eroute */
    time_t             st_outbound_time;       /* time of last change to
						* st_outbound_count */

    bool               st_calculating;         /* set to TRUE, if we are
						* performing cryptographic
						* operations on this state at
						* this time
						*/

    chunk_t            st_p1isa;               /* Phase 1 initiator SA
						  (Payload) for HASH
					       */
    chunk_t            st_skeyid;              /* Key material */
    chunk_t            st_skeyid_d;            /* KM for non-ISAKMP key derivation */
    chunk_t            st_skeyid_a;            /* KM for ISAKMP authentication */
    chunk_t            st_skeyid_e;            /* KM for ISAKMP encryption */
    u_char             st_iv[MAX_DIGEST_LEN];  /* IV for encryption */
    u_char             st_old_iv[MAX_DIGEST_LEN];  /* IV for encryption */
    u_char             st_new_iv[MAX_DIGEST_LEN];
    u_char             st_ph1_iv[MAX_DIGEST_LEN]; /* IV at end if phase 1 */
    unsigned int       st_iv_len;
    unsigned int       st_old_iv_len;
    unsigned int       st_new_iv_len;
    unsigned int       st_ph1_iv_len;

    chunk_t            st_enc_key;             /* Oakley Encryption key */

    struct event      *st_event;               /* backpointer for certain events */
    struct state      *st_hashchain_next;      /* Next in list */
    struct state      *st_hashchain_prev;      /* Previous in list */

    struct hidden_variables hidden_variables;

    unsigned char *st_xauth_username;

    /* RFC 3706 Dead Peer Detection */
    time_t              st_last_dpd;            /* Time of last DPD transmit */
    u_int32_t           st_dpd_seqno;           /* Next R_U_THERE to send */
    u_int32_t           st_dpd_expectseqno;     /* Next R_U_THERE_ACK to receive */
    u_int32_t           st_dpd_peerseqno;       /* global variables */
    struct event        *st_dpd_event;          /* backpointer for DPD events */


    u_int32_t	      st_seen_vendorid;	  /* Bit field about recognized Vendor ID */
    struct isakmp_quirks quirks;          /* work arounds for faults in other
 					   * products */
    
};

/* global variables */

extern u_int16_t pluto_port;	/* Pluto's port */

extern bool states_use_connection(struct connection *c);

/* state functions */

extern struct state *new_state(void);
extern void init_states(void);
extern void insert_state(struct state *st);
extern void unhash_state(struct state *st);
extern void release_whack(struct state *st);
extern void state_eroute_usage(ip_subnet *ours, ip_subnet *his
    , unsigned long count, time_t nw);
extern void delete_state(struct state *st);
struct connection;	/* forward declaration of tag */
extern void delete_states_by_connection(struct connection *c, bool relations);

extern struct state
    *duplicate_state(struct state *st),
    *find_state(const u_char *icookie
	, const u_char *rcookie
	, const ip_address *peer
	, msgid_t msgid),
    *state_with_serialno(so_serial_t sn),
    *find_phase2_state_to_delete(const struct state *p1st, u_int8_t protoid
	, ipsec_spi_t spi, bool *bogus),
    *find_phase1_state(const struct connection *c, lset_t ok_states),
    *find_sender(size_t packet_len, u_char *packet);

extern struct state *find_info_state(const u_char *icookie
				     , const u_char *rcookie
				     , const ip_address *peer
				     , msgid_t msgid);

extern void show_states_status(void);

#if 1
void for_each_state(void *(f)(struct state *, void *data), void *data);
#endif

#if 1
void for_each_state(void *(f)(struct state *, void *data), void *data);
#endif

extern void find_my_cpi_gap(cpi_t *latest_cpi, cpi_t *first_busy_cpi);
extern ipsec_spi_t uniquify_his_cpi(ipsec_spi_t cpi, struct state *st);
extern void fmt_state(struct state *st, time_t n
		     , char *state_buf, size_t state_buf_len
		     , char *state_buf2, size_t state_buf_len2);
extern void delete_states_by_peer(ip_address *peer);
extern void replace_states_by_peer(ip_address *peer);

extern void set_state_ike_endpoints(struct state *st
				    , struct connection *c);

extern void delete_cryptographic_continuation(struct state *st);

#endif /* _STATE_H */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
