/* state and event objects
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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
 */

#ifndef _STATE_H
#define _STATE_H

#include <pthread.h>    /* Must be the first include file */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <gmp.h>    /* GNU MP library */
#include "quirks.h"

#include <nss.h>
#include <pk11pub.h>

#ifdef XAUTH_HAVE_PAM
# include <signal.h>
#endif

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

/* msgid_t defined in defs.h */
#define MAINMODE_MSGID    ((msgid_t) 0)
#define INVALID_MSGID     0xffffffff

struct state;   /* forward declaration of tag */
extern void reserve_msgid(struct state *isakmp_sa, msgid_t msgid);
extern bool unique_msgid(struct state *isakmp_sa, msgid_t msgid);

extern msgid_t generate_msgid(struct state *isakmp_sa);

#define XAUTH_USERNAME_LEN 64

/* Oakley (Phase 1 / Main Mode) transform and attributes
 * This is a flattened/decoded version of what is represented
 * in the Transaction Payload.
 * Names are chosen to match corresponding names in state.
 */
struct trans_attrs {
	u_int16_t encrypt;              /* Encryption algorithm */
	u_int16_t enckeylen;            /* encryption key len (bits) */
	oakley_hash_t prf_hash;         /* Hash algorithm for PRF */
	oakley_hash_t integ_hash;       /* Hash algorithm for integ */

	oakley_auth_t auth;             /* Authentication method (RSA,PSK) */
#ifdef XAUTH
	u_int16_t xauth;                /* did we negotiate Extended Authentication? */
#endif
	u_int16_t groupnum;

	time_t life_seconds;            /* When this SA expires (seconds) */
	u_int32_t life_kilobytes;       /* When this SA is exhausted (kilobytes) */

	/* used in phase1/PARENT SA */
	const struct encrypt_desc *encrypter;   /* package of encryption routines */
	const struct hash_desc *prf_hasher;     /* package of hashing routines */
	const struct hash_desc *integ_hasher;   /* package of hashing routines */
	const struct oakley_group_desc *group;  /* Oakley group */

	/* used in phase2/CHILD_SA */
	struct esp_info *ei;
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
	struct trans_attrs transattrs;
	ipsec_spi_t spi;                /* his SPI */
	time_t life_seconds;            /* When this SA expires */
	u_int32_t life_kilobytes;       /* When this SA expires */
	u_int16_t encapsulation;
#if 0                                   /* not implemented yet */
	u_int16_t cmprs_dict_sz;
	u_int32_t cmprs_alg;
#endif
};

/* IPsec per protocol state information */
struct ipsec_proto_info {
	bool present;                   /* was this transform specified? */
	struct ipsec_trans_attrs attrs; /* info on remote */
	ipsec_spi_t our_spi;
	u_int16_t keymat_len;           /* same for both */
	u_char *our_keymat;
	u_char *peer_keymat;
	u_int our_bytes;
	u_int peer_bytes;
	time_t our_lastused;
	time_t peer_lastused;
};

struct ike_frag {
	struct ike_frag *next;
	struct msg_digest *md;
	int index;
	int last;
	u_int8_t *data;
	size_t size;
};

/*
 * internal state that
 * should get copied by god... to the child SA state.
 * this is to make Einstein happy.
 */

struct hidden_variables {
	unsigned int st_malformed_received;
	unsigned int st_malformed_sent;
	bool st_xauth_client_done;
	int st_xauth_client_attempt;
	bool st_modecfg_server_done;
	bool st_modecfg_vars_set;
	bool st_got_certrequest;
	bool st_modecfg_started;
	bool st_skeyid_calculated;
	bool st_dpd;                            /* Peer supports DPD */
	bool st_dpd_local;                      /* If we want DPD on this conn */
	bool st_logged_p1algos;                 /* if we have logged algos */
	u_int32_t st_nat_traversal;             /* bit field of permitted
	                                         * methods. If non-zero, then
	                                         * NAT-T has been detected, and
	                                         * should be used. */
	ip_address st_nat_oa;
	ip_address st_natd;
};

#define set_suspended(st, md) do { st->st_suspended_md = md; \
				   st->st_suspended_md_func = __FUNCTION__; \
				   st->st_suspended_md_line = __LINE__; \
} while (0)

/* IKEv2, this struct will be mapped into a ikev2_ts1 payload  */
struct traffic_selector {
	u_int8_t ts_type;
	u_int8_t ipprotoid;
	u_int16_t startport;
	u_int16_t endport;
	ip_address low;
	ip_address high;
};

#ifdef HAVE_LABELED_IPSEC
/* security label length should not exceed 256 in most cases,
 * (discussed with kernel and selinux people).
 */
#define MAX_SECCTX_LEN    257 /* including '\0'*/
struct xfrm_user_sec_ctx_ike {
	u_int16_t len;
	u_int16_t exttype;
	u_int8_t ctx_alg; /* LSMs: e.g., selinux == 1 */
	u_int8_t ctx_doi;
	u_int16_t ctx_len;
	char sec_ctx_value[MAX_SECCTX_LEN];
};
#endif

/* state object: record the state of a (possibly nascent) SA
 *
 * Invariants (violated only during short transitions):
 * - each state object will be in statetable exactly once.
 * - each state object will always have a pending event.
 *   This prevents leaks.
 */
struct state {
	so_serial_t st_serialno;                /* serial number (for seniority)*/
	so_serial_t st_clonedfrom;              /* serial number of parent */
	int st_usage;

#ifdef XAUTH_HAVE_PAM
	pthread_mutex_t xauth_mutex;            /* per state xauth_mutex */
	pthread_t xauth_tid;                    /* per state XAUTH_RO thread id */
#endif

	bool st_ikev2;                          /* is this an IKEv2 state? */
	bool st_rekeytov2;                      /* true if this IKEv1 is about
	                                        * to be replaced with IKEv2 */

	struct connection *st_connection;       /* connection for this SA */
	int st_whack_sock;                      /* fd for our Whack TCP socket.
	                                         * Single copy: close when
	                                         * freeing struct.
	                                         */

	struct msg_digest *st_suspended_md;     /* suspended state-transition */
	const char        *st_suspended_md_func;
	int st_suspended_md_line;

	struct ike_frag *ike_frags;                /* collected ike fragments */

	struct trans_attrs st_oakley;

	struct ipsec_proto_info st_ah;
	struct ipsec_proto_info st_esp;
	struct ipsec_proto_info st_ipcomp;

	ipsec_spi_t st_tunnel_in_spi;                   /* KLUDGE */
	ipsec_spi_t st_tunnel_out_spi;                  /* KLUDGE */

	IPsecSAref_t st_ref;                            /* our kernel name for our incoming SA */
	IPsecSAref_t st_refhim;                         /* our kernel name for our outgoing SA */
	bool st_outbound_done;                          /* if true, then outgoing SA already installed */

	const struct oakley_group_desc *st_pfs_group;   /*group for Phase 2 PFS */

	u_int32_t st_doi;                               /* Domain of Interpretation */
	u_int32_t st_situation;

	lset_t st_policy;                       /* policy for IPsec SA */

	ip_address st_remoteaddr;               /* where to send packets to */
	u_int16_t st_remoteport;                /* host byte order */

	const struct iface_port *st_interface;  /* where to send from */  /* dhr 2013: why? There was already connection->interface */
	ip_address st_localaddr;                /* where to send them from */
	u_int16_t st_localport;

	struct db_sa      *st_sadb;

	/* IKEv1 things */
	msgid_t st_msgid;                       /* MSG-ID from header.
	                                           Network Order! */
	bool st_reserve_msgid;                  /* if TRUE, then message id
	                                           has been reserved already */

	msgid_t st_msgid_phase15;               /* msgid for phase 1.5 */
	msgid_t st_msgid_phase15b;              /* msgid for phase 1.5 */
	/* only for a state representing an ISAKMP SA */
	struct msgid_list  *st_used_msgids;     /* used-up msgids */

	/* IKEv2 things */
	/* message ID sequence for things we send (as initiator) */
	msgid_t st_msgid_lastack;               /* last one peer acknowledged */
	msgid_t st_msgid_nextuse;               /* next one to use */

	/* message ID sequence for things we receive (as responder) */
	msgid_t st_msgid_lastrecv;             /* last one peer sent */

	/* symmetric stuff */

	/* initiator stuff */
	chunk_t st_gi;                          /* Initiator public value */
	u_int8_t st_icookie[COOKIE_SIZE];       /* Initiator Cookie */
	chunk_t st_ni;                          /* Ni nonce */

	/* responder stuff */
	chunk_t st_gr;                          /* Responder public value */
	u_int8_t st_rcookie[COOKIE_SIZE];       /* Responder Cookie */
	chunk_t st_nr;                          /* Nr nonce */
	chunk_t st_dcookie;                     /* DOS cookie of responder */

	/* my stuff */
	chunk_t st_tpacket;                     /* Transmitted packet */
	chunk_t st_firstpacket_me;              /* copy of my message 1 */
	chunk_t st_firstpacket_him;             /* copy of his message 1 */

#ifdef HAVE_LABELED_IPSEC
	struct xfrm_user_sec_ctx_ike *sec_ctx;
#endif

	/* Phase 2 ID payload info about my user */
	u_int8_t st_myuserprotoid;             /* IDcx.protoid */
	u_int16_t st_myuserport;

	/* his stuff */

	chunk_t st_rpacket;                    /* Received packet */

	/* Phase 2 ID payload info about peer's user */
	u_int8_t st_peeruserprotoid;           /* IDcx.protoid */
	u_int16_t st_peeruserport;

	/* end of symmetric stuff */

	/* Support quirky feature of Phase 1 ID payload for peer
	 * We don't support this wart for ourselves.
	 * Currently used in Aggressive mode for interop.
	 */
	u_int8_t st_peeridentity_protocol;
	u_int16_t st_peeridentity_port;

	u_int8_t st_sec_in_use;                 /* bool: does st_sec hold a value */
	MP_INT st_sec;                          /* Our local secret value */
	chunk_t st_sec_chunk;                   /* copy of above */
	/*DH public key*/
	chunk_t pubk;

	chunk_t st_shared;                      /* Derived shared secret
	                                         * Note: during Quick Mode,
	                                         * presence indicates PFS
	                                         * selected.
	                                         */
	enum crypto_importance st_import;       /* relative priority of crypto
	                                         * operations
	                                         */

	/* In a Phase 1 state, preserve peer's public key after authentication */
	struct pubkey     *st_peer_pubkey;

	enum state_kind st_state;               /* State of exchange */
	u_int8_t st_retransmit;                 /* Number of retransmits */
	unsigned long st_try;                   /* number of times rekeying
	                                           attempted */
	                                        /* 0 means the only time */
	time_t st_margin;                       /* life after EVENT_SA_REPLACE*/
	unsigned long st_outbound_count;        /* traffic through eroute */
	time_t st_outbound_time;                /* time of last change to
	                                         * st_outbound_count */

	bool st_calculating;                    /* set to TRUE, if we are
	                                         * performing cryptographic
	                                         * operations on this state at
	                                         * this time
	                                         */

	chunk_t st_p1isa;                       /* Phase 1 initiator SA
	                                           (Payload) for HASH
	                                         */
#define st_skeyid   st_skeyseed
	chunk_t st_skeyseed;                    /* Key material */
#define st_skeyid_d st_skey_d
	chunk_t st_skey_d;                      /* KM for non-ISAKMP key derivation */
#define st_skeyid_a st_skey_ai
	chunk_t st_skey_ai;                     /* KM for ISAKMP authentication */
	chunk_t st_skey_ar;                     /* KM for ISAKMP authentication */
#define st_skeyid_e st_skey_ei
	chunk_t st_skey_ei;                     /* KM for ISAKMP encryption */
	chunk_t st_skey_er;                     /* KM for ISAKMP encryption */
	chunk_t st_skey_pi;                     /* KM for ISAKMP encryption */
	chunk_t st_skey_pr;                     /* KM for ISAKMP encryption */
	struct connection *st_childsa;          /* connection included in AUTH */
	struct traffic_selector st_ts_this, st_ts_that;

	u_char st_iv[MAX_DIGEST_LEN];           /* IV for encryption */
	u_char st_old_iv[MAX_DIGEST_LEN];       /* IV for encryption */
	u_char st_new_iv[MAX_DIGEST_LEN];
	u_char st_ph1_iv[MAX_DIGEST_LEN];       /* IV at end if phase 1 */
	unsigned int st_iv_len;
	unsigned int st_old_iv_len;
	unsigned int st_new_iv_len;
	unsigned int st_ph1_iv_len;

	chunk_t st_enc_key;                     /* Oakley Encryption key */

	struct event      *st_event;            /* backpointer for certain
	                                           events */
	struct state      *st_hashchain_next;   /* Next in list */
	struct state      *st_hashchain_prev;   /* Previous in list */

	struct hidden_variables hidden_variables;

	char st_xauth_username[XAUTH_USERNAME_LEN];
	chunk_t st_xauth_password;

	/* RFC 3706 Dead Peer Detection */
	time_t st_last_dpd;                     /* Time of last DPD transmit */
	u_int32_t st_dpd_seqno;                 /* Next R_U_THERE to send */
	u_int32_t st_dpd_expectseqno;           /* Next R_U_THERE_ACK
	                                           to receive */
	u_int32_t st_dpd_peerseqno;             /* global variables */
	struct event       *st_dpd_event;       /* backpointer for DPD events */

	bool st_seen_nortel_vid;                /* To work around a nortel bug */
	struct isakmp_quirks quirks;            /* work arounds for faults in other products */
	bool st_xauth_soft;                     /* XAUTH failed but policy is to soft fail */
	bool st_seen_fragvid;                   /* should really use st_seen_vendorid, but no one else is */
	bool st_seen_fragments;                 /* did we receive ike fragments from peer, if so use them in return as well */
};

/* global variables */

extern u_int16_t pluto_port;            /* Pluto's port */
extern u_int16_t pluto_natt_float_port; /* Pluto's NATT floating port */

extern bool states_use_connection(struct connection *c);

/* state functions */

extern struct state *new_state(void);
extern void init_states(void);
extern void insert_state(struct state *st);
extern void unhash_state(struct state *st);
extern void rehash_state(struct state *st);
extern void release_whack(struct state *st);
extern void state_eroute_usage(ip_subnet *ours, ip_subnet *his,
			       unsigned long count, time_t nw);
extern void delete_state(struct state *st);
struct connection;      /* forward declaration of tag */
extern void delete_states_by_connection(struct connection *c, bool relations);
extern void delete_p2states_by_connection(struct connection *c);
extern void rekey_p2states_by_connection(struct connection *c);

extern struct state
*duplicate_state(struct state *st),
*find_state_ikev1(const u_char * icookie,
		  const u_char * rcookie,
		  msgid_t msgid),
*state_with_serialno(so_serial_t sn),
*find_phase2_state_to_delete(const struct state *p1st, u_int8_t protoid,
			     ipsec_spi_t spi, bool *bogus),
*find_phase1_state(const struct connection *c, lset_t ok_states),
*find_sender(size_t packet_len, u_char * packet);

#ifdef HAVE_LABELED_IPSEC
extern struct state *find_state_ikev1_loopback(const u_char *icookie,
					       const u_char *rcookie,
					       msgid_t msgid,
					       struct msg_digest *md);
#endif
extern struct state *find_state_ikev2_parent(const u_char *icookie,
					     const u_char *rcookie);

extern struct state *find_state_ikev2_parent_init(const u_char *icookie);

extern struct state *find_state_ikev2_child(const u_char *icookie,
					    const u_char *rcookie,
					    msgid_t msgid);

extern struct state *find_state_ikev2_child_to_delete(const u_char *icookie,
						      const u_char *rcookie,
						      u_int8_t protoid,
						      ipsec_spi_t spi);

extern struct state *find_info_state(const u_char *icookie,
				     const u_char *rcookie,
				     const ip_address *peer,
				     msgid_t msgid);

extern void initialize_new_state(struct state *st,
				 struct connection *c,
				 lset_t policy,
				 int try,
				 int whack_sock,
				 enum crypto_importance importance);

extern void show_states_status(void);

#if 1
void for_each_state(void *(f)(struct state *, void *data), void *data);
#endif

extern void find_my_cpi_gap(cpi_t *latest_cpi, cpi_t *first_busy_cpi);
extern ipsec_spi_t uniquify_his_cpi(ipsec_spi_t cpi, struct state *st);
extern void fmt_state(struct state *st, const time_t n,
		      char *state_buf, const size_t state_buf_len,
		      char *state_buf2, const size_t state_buf_len2);
extern void delete_states_by_peer(const ip_address *peer);
extern void replace_states_by_peer(const ip_address *peer);
extern void release_fragments(struct state *st);

extern void set_state_ike_endpoints(struct state *st,
				    struct connection *c);

extern void delete_cryptographic_continuation(struct state *st);
extern void delete_states_dead_interfaces(void);

/*
 * use this guy to change state, this gives us a handle on all state changes
 * which is good for tracking bugs, logging and anything else you might like
 */
#ifdef HAVE_STATSD
#define refresh_state(st) log_state(st, st->st_state)
#define fake_state(st, new_state) log_state(st, new_state)
#define change_state(st, new_state) \
	do { \
		if ((new_state) != (st)->st_state) { \
			log_state((st), (new_state)); \
			(st)->st_state = (new_state); \
		} \
	} while (0)
#else
#define refresh_state(st)               /* do nothing */
#define fake_state(st, new_state)       /* do nothing */
#define change_state(st, new_state) do { (st)->st_state = (new_state); \
} while (0)
#endif

#endif /* _STATE_H */
