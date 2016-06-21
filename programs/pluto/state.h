/* state and event objects, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013-2014 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2014 Antony Antony <antony@phenome.org>
 * Copyright (C) 2015 Andrew Cagney <andrew.cagney@gmail.com>
 * Copyright (C) 2015 Paul Wouters <pwouters@redhat.com>
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

#ifndef _STATE_H
#define _STATE_H

#include <pthread.h>    /* Must be the first include file */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include "quirks.h"

#include <nss.h>
#include <pk11pub.h>
#include <x509.h>

#ifdef XAUTH_HAVE_PAM
# include <signal.h>
#endif

#include "labeled_ipsec.h"	/* for struct xfrm_user_sec_ctx_ike and friends */
#include "state_entry.h"

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

#define v1_MAINMODE_MSGID  ((msgid_t) 0)	/* network and host order */

#define v2_INITIAL_MSGID  ((msgid_t) 0)	/* network and host order */

#define v2_INVALID_MSGID  ((msgid_t) 0xffffffff)	/* network and host order */

struct state;   /* forward declaration of tag */

/* Oakley (Phase 1 / Main Mode) transform and attributes
 * This is a flattened/decoded version of what is represented
 * in the Transaction Payload.
 * Names are chosen to match corresponding names in state.
 */
struct trans_attrs {
	u_int16_t encrypt;		/* Encryption algorithm */
	u_int16_t enckeylen;		/* encryption key len (bits) */
	oakley_hash_t prf_hash;		/* Hash algorithm for PRF */
	oakley_hash_t integ_hash;	/* Hash algorithm for integ */

	oakley_auth_t auth;		/* Authentication method (RSA,PSK) */

	bool doing_xauth;		/* did we negotiate Extended Authentication and still doing it? */

	bool esn_enabled;               /* IKEv2 ESN (extended sequence numbers) */

	oakley_group_t groupnum;		/* for IKEv2 */

	deltatime_t life_seconds;	/* max life of this SA in seconds */
	u_int32_t life_kilobytes;	/* max life of this SA in kilobytes */

	/* used in phase1/PARENT SA */
	const struct encrypt_desc *encrypter;	/* package of encryption routines */
	const struct hash_desc *prf_hasher;	/* package of hashing routines */
	const struct hash_desc *integ_hasher;	/* package of hashing routines */
	const struct oakley_group_desc *group;	/* Oakley group */

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
	ipsec_spi_t spi;                /* their SPI */
	deltatime_t life_seconds;	/* max life of this SA in seconds */
	u_int32_t life_kilobytes;	/* max life of this SA in kilobytes */
	u_int16_t encapsulation;
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
	monotime_t our_lastused;
	monotime_t peer_lastused;
	uint64_t add_time;
};

struct ike_frag {
	struct ike_frag *next;
	struct msg_digest *md;
	int index;
	int last;
	u_int8_t *data;
	size_t size;
};

struct ikev2_frag {
	struct ikev2_frag *next;
	chunk_t cipher;
	/* the rest are only used in re-assembly */
	int np;
	int index;
	int total;
	unsigned int iv;
	chunk_t plain;
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
	bool st_peer_supports_dpd;              /* Peer supports DPD/IKEv2 Liveness
						 * NOTE: dpd_active_locally() tracks
						 * the local enablement of DPD */
	bool st_logged_p1algos;                 /* if we have logged algos */
	lset_t st_nat_traversal;                /* bit field of permitted
						 * methods. If non-zero, then
						 * NAT-T has been detected, and
						 * should be used. */
	ip_address st_nat_oa;
	ip_address st_natd;
};

#define unset_suspended(st) { \
	(st)->st_suspended_md = NULL; \
	(st)->st_suspended_md_func = __FUNCTION__; \
	(st)->st_suspended_md_line = __LINE__; \
    }

#define set_suspended(st, md) { \
	passert((st)->st_suspended_md == NULL); \
	(st)->st_suspended_md = (md); \
	(st)->st_suspended_md_func = __FUNCTION__; \
	(st)->st_suspended_md_line = __LINE__; \
    }

/* IKEv2, this struct will be mapped into a ikev2_ts1 payload  */
struct traffic_selector {
	u_int8_t ts_type;
	u_int8_t ipprotoid;
	u_int16_t startport;
	u_int16_t endport;
	ip_address low;
	ip_address high;
};

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

	pthread_mutex_t xauth_mutex;            /* per state xauth_mutex */
	pthread_t xauth_tid;                    /* per state XAUTH_RO thread id */
	bool has_pam_thread;                    /* per state PAM thread flag */

	bool st_ikev2;                          /* is this an IKEv2 state? */
	bool st_rekeytov2;                      /* true if this IKEv1 is about
						 * to be replaced with IKEv2
						 */

	struct connection *st_connection;       /* connection for this SA */
	int st_whack_sock;                      /* fd for our Whack TCP socket.
						 * Single copy: close when
						 * freeing struct.
						 */

	struct msg_digest *st_suspended_md;     /* suspended state-transition */
	const char        *st_suspended_md_func;
	int st_suspended_md_line;

	/* collected ike fragments */
	union {
		struct ike_frag *ike_frags;
		struct ikev2_frag *ikev2_frags;
	};

	struct trans_attrs st_oakley;

	struct ipsec_proto_info st_ah;
	struct ipsec_proto_info st_esp;
	struct ipsec_proto_info st_ipcomp;

	ipsec_spi_t st_tunnel_in_spi;		/* KLUDGE */
	ipsec_spi_t st_tunnel_out_spi;		/* KLUDGE */

	IPsecSAref_t st_ref;			/* our kernel name for our incoming SA */
	IPsecSAref_t st_refhim;			/* our kernel name for our outgoing SA */
	bool st_outbound_done;			/* if true, then outgoing SA already installed */

	const struct oakley_group_desc *st_pfs_group;   /*group for Phase 2 PFS */

	lset_t st_policy;                       /* policy for IPsec SA */

	ip_address st_remoteaddr;               /* where to send packets to */
	u_int16_t st_remoteport;                /* host byte order */

	const struct iface_port *st_interface;  /* where to send from */  /* dhr 2013: why? There was already connection->interface */
	ip_address st_localaddr;                /* where to send them from */
	u_int16_t st_localport;

	/** IKEv1-only things **/

	msgid_t st_msgid;                       /* MSG-ID from header.
						   Network Order! */
	bool st_msgid_reserved;			/* is msgid reserved yet? */

	msgid_t st_msgid_phase15;               /* msgid for phase 1.5 - Network Order! */

	/* only for a state representing an ISAKMP SA */
	struct msgid_list *st_used_msgids;	/* used-up msgids */

	chunk_t st_rpacket;			/* Received packet - v1 only */

	/* Initialization Vectors for IKE encryption */

	u_char st_new_iv[MAX_DIGEST_LEN];	/* tentative IV (calculated from current packet) */
	u_char st_iv[MAX_DIGEST_LEN];           /* accepted IV (after packet passes muster) */
	u_char st_ph1_iv[MAX_DIGEST_LEN];       /* IV at end of phase 1 */

	unsigned int st_new_iv_len;
	unsigned int st_iv_len;
	unsigned int st_ph1_iv_len;

	/* end of IKEv1-only things */

	/** IKEv2-only things **/

	struct ikev2_proposal *st_accepted_ike_proposal;
	struct ikev2_proposal *st_accepted_esp_or_ah_proposal;

	/* Am I the original initator, or orignal responder (v2 IKE_I flag). */
	enum original_role st_original_role;

	/* message ID sequence for things we send (as initiator) */
	msgid_t st_msgid_lastack;               /* last one peer acknowledged  - host order */
	msgid_t st_msgid_nextuse;               /* next one to use - host order */
	/* message ID sequence for things we receive (as responder) */
	msgid_t st_msgid_lastrecv;             /* last one peer sent - Host order v2 only */

	chunk_t st_firstpacket_me;              /* copy of my message 1 (for hashing) */
	chunk_t st_firstpacket_him;             /* copy of his message 1 (for hashing) */

	/** end of IKEv2-only things **/


	/* symmetric stuff */

	/* initiator stuff */
	chunk_t st_gi;                          /* Initiator public value */
	u_int8_t st_icookie[COOKIE_SIZE];       /* Initiator Cookie */
	chunk_t st_ni;                          /* Ni nonce */

	/* responder stuff */
	chunk_t st_gr;                          /* Responder public value */
	u_int8_t st_rcookie[COOKIE_SIZE];       /* Responder Cookie */
	chunk_t st_nr;                          /* Nr nonce */
	chunk_t st_dcookie;                     /* DOS cookie of responder - v2 only */

	/* my stuff */
	chunk_t st_tpacket;                     /* Transmitted packet */
	struct ikev2_frag *st_tfrags;		/* Transmitted fragments */

#ifdef HAVE_LABELED_IPSEC
	struct xfrm_user_sec_ctx_ike *sec_ctx;
#endif

	/* Phase 2 ID payload info about my user */
	u_int8_t st_myuserprotoid;             /* IDcx.protoid */
	u_int16_t st_myuserport;

	/* his stuff */

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

	/*
	 * Diffie-Hellman exchange values
	 *
	 * st_sec_nss is our local ephemeral secret.  Its sole use is an input
	 * in the calculation of the shared secret.
	 *
	 * st_gi and st_gr (above) are the initiator and responder public
	 * values that are shipped in KE payloads.
	 * On initiator: st_gi = GROUP_GENERATOR ^ st_sec_nss
	 *               st_gr comes from KE
	 * On responder: st_gi comes from KE
	 *               st_gr = GROUP_GENERATOR ^ st_sec_nss
	 *
	 * st_pubk_nss is ???
	 *
	 * st_shared_nss is the output of the DH: an ephemeral secret
	 * shared by the two ends.  Of course the other end might
	 * be a man in the middle unless we authenticate.
	 * st_shared_nss = GROUP_GENERATOR ^ (initiator's st_sec_nss * responder's st_sec_nss)
	 *               = st_gr ^ initiator's st_sec_nss
	 *               = sg_gi ^ responder's st_sec_nss
	 */

	bool st_sec_in_use;		/* bool: do st_sec_nss/st_pubk_nss hold values */

	SECKEYPrivateKey *st_sec_nss;	/* our secret (owned by NSS) */

	SECKEYPublicKey *st_pubk_nss;	/* DH public key (owned by NSS) */

	PK11SymKey *st_shared_nss;	/* Derived shared secret
					 * Note: during Quick Mode,
					 * presence indicates PFS
					 * selected.
					 */
	/* end of DH values */

	enum crypto_importance st_import;       /* relative priority of crypto
						 * operations
						 */

	/* In a Phase 1 state, preserve peer's public key after authentication */
	struct pubkey *st_peer_pubkey;

	enum state_kind st_state;               /* State of exchange */

	u_int8_t st_retransmit;		/* Number of retransmits */
	unsigned long st_try;		/* Number of times rekeying attempted.
					 * 0 means the only time.
					 */
	deltatime_t st_margin;		/* life after EVENT_SA_REPLACE*/
	unsigned long st_outbound_count;	/* traffic through eroute */
	monotime_t st_outbound_time;	/* time of last change to
					 * st_outbound_count
					 */

	bool st_calculating;                    /* set to TRUE, if we are
							 * performing cryptographic
							 * operations on this state at
							 * this time
							 */

	chunk_t st_p1isa;	/* Phase 1 initiator SA (Payload) for HASH */

	/* v1 names are aliases for subset of v2 fields (#define) */
#define st_skeyid_nss   st_skeyseed_nss
	PK11SymKey *st_skeyseed_nss;	/* Key material */
#define st_skeyid_d_nss st_skey_d_nss
	PK11SymKey *st_skey_d_nss;	/* KM for non-ISAKMP key derivation */
#define st_skeyid_a_nss st_skey_ai_nss
	PK11SymKey *st_skey_ai_nss;	/* KM for ISAKMP authentication */
	PK11SymKey *st_skey_ar_nss;	/* KM for ISAKMP authentication */
#define st_skeyid_e_nss st_skey_ei_nss
	PK11SymKey *st_skey_ei_nss;	/* KM for ISAKMP encryption */
	PK11SymKey *st_skey_er_nss;	/* KM for ISAKMP encryption */
	PK11SymKey *st_skey_pi_nss;	/* KM for ISAKMP encryption */
	PK11SymKey *st_skey_pr_nss;	/* KM for ISAKMP encryption */
	chunk_t st_skey_initiator_salt;
	chunk_t st_skey_responder_salt;
	chunk_t st_skey_chunk_SK_pi;
	chunk_t st_skey_chunk_SK_pr;

	/* connection included in AUTH */
	struct traffic_selector st_ts_this;
	struct traffic_selector st_ts_that;

	PK11SymKey *st_enc_key_nss;	/* Oakley Encryption key */

	struct pluto_event *st_event;		/* timer event for this state object */

	/*
	 * hash table entry indexed by ICOOKIE+RCOOKIE
	 */
	struct state_entry st_hash_entry;
	/*
	 * Hash table indexed by ICOOKIE+ZERO_COOKIE.
	 *
	 * Used to robustly find a state based only on ICOOKIE.
	 */
	struct state_entry st_icookie_hash_entry;

	struct hidden_variables hidden_variables;

	char st_username[MAX_USERNAME_LEN];	/* NUL-terminated */
	chunk_t st_xauth_password;

	monotime_t st_last_liveness;		/* Time of last v2 informational (0 means never?) */
	bool st_pend_liveness;			/* Waiting on an informational response */
	struct pluto_event *st_liveness_event;
	struct pluto_event *st_rel_whack_event;
	struct pluto_event *st_send_xauth_event;

	/* RFC 3706 Dead Peer Detection */
	monotime_t st_last_dpd;			/* Time of last DPD transmit (0 means never?) */
	u_int32_t st_dpd_seqno;                 /* Next R_U_THERE to send */
	u_int32_t st_dpd_expectseqno;           /* Next R_U_THERE_ACK to receive */
	u_int32_t st_dpd_peerseqno;             /* global variables */
	u_int32_t st_dpd_rdupcount;		/* openbsd isakmpd bug workaround */
	struct pluto_event *st_dpd_event;	/* backpointer for DPD events */

	bool st_seen_nortel_vid;                /* To work around a nortel bug */
	struct isakmp_quirks quirks;            /* work arounds for faults in other products */
	bool st_xauth_soft;                     /* XAUTH failed but policy is to soft fail */
	bool st_seen_fragvid;                   /* should really use st_seen_vendorid, but no one else is */
	bool st_seen_fragments;                 /* did we receive ike fragments from peer, if so use them in return as well */
	bool st_seen_no_tfc;			/* did we receive ESP_TFC_PADDING_NOT_SUPPORTED */
	bool st_seen_use_transport;		/* did we receive USE_TRANSPORT_MODE */
	generalName_t *st_requested_ca;		/* collected certificate requests */
};

/* global variables */

extern u_int16_t pluto_port;		/* Pluto's port */
extern u_int16_t pluto_nat_port;	/* Pluto's NATT floating port */
extern u_int16_t pluto_nflog_group;	/* NFLOG group - 0 means no logging  */
extern u_int16_t pluto_xfrmlifetime;	/* only used to display in status */

extern bool states_use_connection(const struct connection *c);

/* state functions */

extern struct state *new_state(void);
extern struct state *new_rstate(struct msg_digest *md);

extern void init_states(void);
extern void insert_state(struct state *st);
extern void rehash_state(struct state *st, const u_char *rcookie);
extern void release_whack(struct state *st);
extern void state_eroute_usage(const ip_subnet *ours, const ip_subnet *his,
			       unsigned long count, monotime_t nw);
extern void delete_state(struct state *st);
struct connection;      /* forward declaration of tag */
extern void delete_states_by_connection(struct connection *c, bool relations);
extern void delete_p2states_by_connection(struct connection *c);
extern void rekey_p2states_by_connection(struct connection *c);
extern void delete_my_family(struct state *pst, bool v2_responder_state);

extern struct state
	*duplicate_state(struct state *st),
	*find_state_ikev1(const u_char *icookie,
			  const u_char *rcookie,
			  msgid_t msgid),
	*state_with_serialno(so_serial_t sn),
	*find_phase2_state_to_delete(const struct state *p1st, u_int8_t protoid,
			     ipsec_spi_t spi, bool *bogus),
	*find_phase1_state(const struct connection *c, lset_t ok_states),
	*find_likely_sender(size_t packet_len, u_char * packet);

extern struct state *find_state_ikev2_parent(const u_char *icookie,
					     const u_char *rcookie);

extern struct state *find_state_ikev2_parent_init(const u_char *icookie,
						  enum state_kind expected_state);

extern struct state *find_state_ikev2_child(const u_char *icookie,
					    const u_char *rcookie,
					    msgid_t msgid);

extern struct state *find_state_ikev2_child_to_delete(const u_char *icookie,
						      const u_char *rcookie,
						      u_int8_t protoid,
						      ipsec_spi_t spi);

extern struct state *ikev1_find_info_state(const u_char *icookie,
				     const u_char *rcookie,
				     const ip_address *peer,
				     msgid_t msgid);

extern void initialize_new_state(struct state *st,
				 struct connection *c,
				 lset_t policy,
				 int try,
				 int whack_sock,
				 enum crypto_importance importance);

extern void show_traffic_status(void);
extern void show_states_status(void);

void for_each_state(void (*f)(struct state *, void *data), void *data);

extern void find_my_cpi_gap(cpi_t *latest_cpi, cpi_t *first_busy_cpi);
extern ipsec_spi_t uniquify_his_cpi(ipsec_spi_t cpi, const struct state *st);

extern void fmt_list_traffic(struct state *st, char *state_buf,
			     const size_t state_buf_len);

extern void fmt_state(struct state *st, const monotime_t n,
		      char *state_buf, const size_t state_buf_len,
		      char *state_buf2, const size_t state_buf_len2);

extern void delete_states_by_peer(const ip_address *peer);
extern void replace_states_by_peer(const ip_address *peer);
extern void release_fragments(struct state *st);
extern void v1_delete_state_by_username(struct state *st, void *name);
extern void delete_state_by_id_name(struct state *st, void *name);

extern void set_state_ike_endpoints(struct state *st,
				    struct connection *c);

extern void delete_cryptographic_continuation(struct state *st);
extern void delete_states_dead_interfaces(void);
extern bool dpd_active_locally(const struct state *st);

/*
 * use these to change state, this gives us a handle on all state changes
 * which is good for tracking bugs, logging and anything else you might like
 */
#define refresh_state(st) log_state((st), (st)->st_state)
#define fake_state(st, new_state) log_state((st), (new_state))
extern void change_state(struct state *st, enum state_kind new_state);

extern bool state_busy(const struct state *st);
extern void clear_dh_from_state(struct state *st);
extern bool drop_new_exchanges(void);
extern bool require_ddos_cookies(void);
extern void show_globalstate_status(void);
extern void log_newest_sa_change(char *f, struct state *const st);
extern void update_ike_endpoints(struct state *st, const struct msg_digest *md);

#ifdef XAUTH_HAVE_PAM
void ikev2_free_auth_pam(so_serial_t st_serialno);
#endif
bool shared_phase1_connection(const struct connection *c);

#endif /* _STATE_H */
