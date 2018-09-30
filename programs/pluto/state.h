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
 * Copyright (C) 2014,2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2015-2018 Andrew Cagney
 * Copyright (C) 2015-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2015 Paul Wouters <pwouters@redhat.com>
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

#ifndef _STATE_H
#define _STATE_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "quirks.h"

#include "deltatime.h"
#include "monotime.h"
#include "reqid.h"
#include "fd.h"

#include <nss.h>
#include <pk11pub.h>
#include <x509.h>

#include "labeled_ipsec.h"	/* for struct xfrm_user_sec_ctx_ike and friends */
#include "list_entry.h"
#include "retransmit.h"

/* msgid_t defined in defs.h */

#define v1_MAINMODE_MSGID  ((msgid_t) 0)	/* network and host order */

#define v2_INITIAL_MSGID  ((msgid_t) 0)	/* network and host order */

#define v2_INVALID_MSGID  ((msgid_t) 0xffffffff)	/* network and host order */

struct ikev2_ipseckey_dns; /* forward declaration of tag */

struct state;   /* forward declaration of tag */

/* Oakley (Phase 1 / Main Mode) transform and attributes
 * This is a flattened/decoded version of what is represented
 * in the Transaction Payload.
 * Names are chosen to match corresponding names in state.
 */
struct trans_attrs {
	/*
	 * If IPCOMP, the compession algorithm.
	 *
	 * XXX: code likely still relies on .encrypt having the same
	 * value.  See below.
	 */
	enum ipsec_comp_algo ta_comp;

	/*
	 * Let me see, the IKEV1TA_ENCRYPT field, depending on which
	 * balls are in the air at any one moment, is used for and
	 * contains one of the following:
	 *
	 * IKEv1 IKE (aka Phase 1?): enum ikev1_encr_attribute
	 *
	 * IKEv1 ESP (aka Phase 2?): enum ipsec_cipher_algo
	 *
	 * IKEv1 AH (aka Phase 2?): enum ipsec_authentication_algo (a
	 * scratch variable it seems so that the real integ algorithm
	 * can be verified).

	 * IKEv2 IKE: enum ikev2_trans_type_encr.
	 *
	 * IKEv2 ESP: initially ikev2_trans_type_encr, but then later
	 * switched to enum ipsec_cipher_algo if the IKEv1 value is
	 * available.
	 *
	 * IKEv1 IPCOMP: enum ipsec_comp_algo; at least that is what
	 * I've been told; this code, along with the rest of IKEv1
	 * should go away.
	 *
	 * What could possibly go wrong :-)
	 */
#define ta_ikev1_encrypt ta_encrypt->common.id[IKEv1_ESP_ID]

	/*
	 * IKEv1 IKE: N/A
	 * IKEv1 ESP/AH: enum ikev1_auth_attribute.
	 * IKEv2 IKE/ESP/AH: N/A.
	 *
	 * The only reason to use the expanded form of this macro is
	 * when putting the value on, or getting the value off (i.e.,
	 * lookup), the wire.
	 */
#define ta_ikev1_integ_hash ta_integ->common.id[IKEv1_ESP_ID]

	oakley_auth_t auth;		/* Authentication method (RSA,PSK) */

	bool doing_xauth;		/* did we negotiate Extended Authentication and still doing it? */

	bool esn_enabled;               /* IKEv2 ESN (extended sequence numbers) */

	deltatime_t life_seconds;	/* max life of this SA in seconds */
	uint32_t life_kilobytes;	/* max life of this SA in kilobytes */

	/* negotiated crypto-suite */
	const struct encrypt_desc *ta_encrypt;	/* package of encryption routines */
	uint16_t enckeylen;			/* encryption key len (bits) */
	const struct prf_desc *ta_prf;		/* package of prf routines */
	const struct integ_desc *ta_integ;	/* package of integrity routines */
	const struct oakley_group_desc *ta_dh;	/* Diffie-Helman-Merkel routines */
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
	uint32_t life_kilobytes;	/* max life of this SA in kilobytes */
	uint16_t encapsulation;
};

/* IPsec per protocol state information */
struct ipsec_proto_info {
	bool present;                   /* was this transform specified? */
	struct ipsec_trans_attrs attrs; /* info on remote */
	ipsec_spi_t our_spi;
	uint16_t keymat_len;           /* same for both */
	u_char *our_keymat;
	u_char *peer_keymat;
	uint64_t our_bytes;
	uint64_t peer_bytes;
	monotime_t our_lastused;
	monotime_t peer_lastused;
	uint64_t add_time;
};

struct initiate_list {
	so_serial_t st_serialno;
//	enum initiate_new_exchagnge send_type;
	struct  initiate_list *next;
};

struct ike_frag {
	struct ike_frag *next;
	struct msg_digest *md;
	int index;
	int last;
	uint8_t *data;
	size_t size;
};

struct v2_ike_rfrag {
	chunk_t cipher;
	unsigned int iv;
};

struct v2_ike_rfrags {
	unsigned total;
	unsigned count;
	/*
	 * Next-Payload from first fragment.
	 */
	int first_np;
	/*
	 * For simplicity, index by fragment number which is 1-based;
	 * leaving element 0 empty.
	 */
	struct v2_ike_rfrag frags[MAX_IKE_FRAGMENTS + 1];
};

struct v2_ike_tfrag {
	struct v2_ike_tfrag *next;
	chunk_t cipher;
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
	lset_t st_nat_traversal;                /* bit field of permitted
						 * methods. If non-zero, then
						 * NAT-T has been detected, and
						 * should be used. */
	ip_address st_nat_oa;
	ip_address st_natd;
};

struct msg_digest *unsuspend_md(struct state *st);

/*
 * On entry to this macro, when crypto has been off loaded then
 * st_offloaded_task is non-NULL.  However, with XAUTH immediate,
 * there's nothing to check.
 */
#define suspend_md(ST, MDP) {						\
		DBG(DBG_CONTROL,					\
		    DBG_log("suspending state #%lu and saving MD",	\
			    (ST)->st_serialno));			\
		passert((ST)->st_suspended_md == NULL);			\
		(ST)->st_suspended_md = *(MDP);				\
		*(MDP) = NULL; /* take ownership */			\
		(ST)->st_suspended_md_func = __FUNCTION__;		\
		(ST)->st_suspended_md_line = __LINE__;			\
		passert(state_is_busy(ST));				\
	}

/* IKEv2, this struct will be mapped into a ikev2_ts1 payload  */
struct traffic_selector {
	uint8_t ts_type;
	uint8_t ipprotoid;
	uint16_t startport;
	uint16_t endport;
	ip_range net;	/* for now, always happens to be a CIDR */
};

/*
 * Abstract state machine that drives the parent and child SA.
 *
 * IKEv1 and IKEv2 construct states using this as a base.
 */
struct finite_state {
	enum state_kind fs_state;
	const char *fs_name;
	const char *fs_short_name;
	const char *fs_story;
	lset_t fs_flags;
	enum event_type fs_timeout_event;
	const void *fs_microcode;	/* aka edge */
};

void lswlog_finite_state(struct lswlog *buf, const struct finite_state *fs);

/* this includes space for lurking STATE_IKEv2_ROOF */
extern const struct finite_state *finite_states[STATE_IKE_ROOF];

/*
 * state object: record the state of a (possibly nascent) parent or
 * child SA
 *
 * Invariants (violated only during short transitions):
 *
 * - each state object will be in statetable exactly once.
 *
 * - each state object will always have a pending event.
 *   This prevents leaks.
 */
struct state {
	so_serial_t st_serialno;                /* serial number (for seniority)*/
	so_serial_t st_clonedfrom;              /* serial number of parent */
	so_serial_t st_ike_pred;		/* IKEv2: replacing established IKE SA */
	so_serial_t st_ipsec_pred;		/* replacing established IPsec SA */

#ifdef XAUTH_HAVE_PAM
	struct xauth *st_xauth;			/* per state xauth/pam thread */
#endif

	bool st_ikev2;                          /* is this an IKEv2 state? */
	bool st_ikev2_anon;                     /* is this an anonymous IKEv2 state? */
	bool st_suppress_del_notify;            /* suppress sending DELETE - eg replaced conn */
	bool st_rekeytov2;                      /* true if this IKEv1 is about
						 * to be replaced with IKEv2
						 */

	struct connection *st_connection;       /* connection for this SA */
	fd_t st_whack_sock;                /* fd for our Whack TCP socket.
						 * Single copy: close when
						 * freeing struct.
						 */

	/* collected received fragments */
	struct ike_frag *st_v1_rfrags;
	struct v2_ike_rfrags *st_v2_rfrags;

	struct trans_attrs st_oakley;

	struct ipsec_proto_info st_ah;
	struct ipsec_proto_info st_esp;
	struct ipsec_proto_info st_ipcomp;

	ipsec_spi_t st_tunnel_in_spi;		/* KLUDGE */
	ipsec_spi_t st_tunnel_out_spi;		/* KLUDGE */

	IPsecSAref_t st_ref;			/* our kernel name for our incoming SA */
	IPsecSAref_t st_refhim;			/* our kernel name for our outgoing SA */
	reqid_t st_reqid;			/* bundle of 4 (out,in, compout,compin */

	bool st_outbound_done;			/* if true, then outgoing SA already installed */

	const struct oakley_group_desc *st_pfs_group;   /*group for Phase 2 PFS */
	lset_t st_hash_negotiated;              /* Saving the negotiated hash values here */
	lset_t st_policy;                       /* policy for IPsec SA */

	ip_address st_remoteaddr;               /* where to send packets to */
	uint16_t st_remoteport;                /* host byte order */

	const struct iface_port *st_interface;  /* where to send from */  /* dhr 2013: why? There was already connection->interface */
	ip_address st_localaddr;                /* where to send them from */
	uint16_t st_localport;

	/* IKEv2 MOBIKE probe copies */
	ip_address st_mobike_remoteaddr;
	uint16_t st_mobike_remoteport;
	const struct iface_port *st_mobike_interface;
	ip_address st_deleted_local_addr;	/* kernel deleted address */
	ip_address st_mobike_localaddr;		/* new address to initiate MOBIKE */
	uint16_t st_mobike_localport;		/* is this necessary ? */
	ip_address st_mobike_host_nexthop;	/* for updown script */

	/** IKEv1-only things **/

	msgid_t st_msgid;                       /* MSG-ID from header.
						   Network Order! */
	bool st_msgid_reserved;			/* is msgid reserved yet? */

	msgid_t st_msgid_phase15;               /* msgid for phase 1.5 - Network Order! */

	/* only for a state representing an ISAKMP SA */
	struct msgid_list *st_used_msgids;	/* used-up msgids */

	chunk_t st_rpacket;			/* Received packet - v1 only */

	/*
	 * The last successful state transition (edge, microcode).
	 * Used when transitioning to this current state.
	 */
	const struct state_v1_microcode *st_v1_last_transition;
#if 0
	const struct state_v1_microcode *st_v1_next_transition;
	const struct state_v2_microcode *st_v2_last_transition;
	const struct state_v2_microcode *st_v2_next_transition;
#endif

	/* Initialization Vectors for IKE encryption */

	u_char st_new_iv[MAX_DIGEST_LEN];	/* tentative IV (calculated from current packet) */
	u_char st_iv[MAX_DIGEST_LEN];           /* accepted IV (after packet passes muster) */
	u_char st_ph1_iv[MAX_DIGEST_LEN];       /* IV at end of phase 1 */

	unsigned int st_new_iv_len;
	unsigned int st_iv_len;
	unsigned int st_ph1_iv_len;

	/* end of IKEv1-only things */

	/** IKEv2-only things **/
	bool st_viable_parent;	/* can initiate new CERAET_CHILD_SA */
	struct ikev2_proposal *st_accepted_ike_proposal;
	struct ikev2_proposal *st_accepted_esp_or_ah_proposal;

	/* Am I the original initator, or orignal responder (v2 IKE_I flag). */
	enum original_role st_original_role;
	enum sa_role st_sa_role;

	/* message ID sequence for things we send (as initiator) */
	msgid_t st_msgid_lastack;               /* last one peer acknowledged  - host order */
	msgid_t st_msgid_nextuse;               /* next one to use - host order */
	/* message ID sequence for things we receive (as responder) */
	msgid_t st_msgid_lastrecv;             /* last one peer sent - Host order v2 only */
	msgid_t st_msgid_lastreplied;         /* to decide retransmit CREATE_CHILD_SA */

	chunk_t st_firstpacket_me;              /* copy of my message 1 (for hashing) */
	chunk_t st_firstpacket_him;             /* copy of his message 1 (for hashing) */
	struct initiate_list *send_next_ix;

	struct p_dns_req *ipseckey_dnsr;    /* ipseckey of that end */
	struct p_dns_req *ipseckey_fwd_dnsr;/* validate IDi that IP in forward A/AAAA */

	/** end of IKEv2-only things **/

	char *st_seen_cfg_dns; /* obtained internal nameserver IP's */
	char *st_seen_cfg_domains; /* obtained internal domain names */
	char *st_seen_cfg_banner; /* obtained banner */

	/* symmetric stuff */

	/* initiator stuff */
	chunk_t st_gi;                          /* Initiator public value */
	uint8_t st_icookie[COOKIE_SIZE];       /* Initiator Cookie */
	chunk_t st_ni;                          /* Ni nonce */

	/* responder stuff */
	chunk_t st_gr;                          /* Responder public value */
	uint8_t st_rcookie[COOKIE_SIZE];       /* Responder Cookie */
	chunk_t st_nr;                          /* Nr nonce */
	chunk_t st_dcookie;                     /* DOS cookie of responder - v2 only */

	/* my stuff */
	chunk_t st_tpacket;                     /* Transmitted packet */
	struct v2_ike_tfrag *st_v2_tfrags;	/* Transmitted fragments */

#ifdef HAVE_LABELED_IPSEC
	struct xfrm_user_sec_ctx_ike *sec_ctx;
#endif

	/* Phase 2 ID payload info about my user */
	uint8_t st_myuserprotoid;             /* IDcx.protoid */
	uint16_t st_myuserport;

	/* his stuff */

	/* Phase 2 ID payload info about peer's user */
	uint8_t st_peeruserprotoid;           /* IDcx.protoid */
	uint16_t st_peeruserport;

	/* end of symmetric stuff */

	/* Support quirky feature of Phase 1 ID payload for peer
	 * We don't support this wart for ourselves.
	 * Currently used in Aggressive mode for interop.
	 */
	uint8_t st_peeridentity_protocol;
	uint16_t st_peeridentity_port;

	bool st_peer_alt_id;	/* scratchpad for writing we found alt peer id in CERT */

	/*
	 * Diffie-Hellman exchange values.
	 *
	 * At any point only one of the state or a crypto helper
	 * (request) owns the secret.
	 *
	 * However, because of the way IKEv1 and IKEv2 handle the DH
	 * exchange things get a little messy.
	 *
	 * In IKEv2, since DH and auth involve separate exchanges and
	 * packets, the DH derivation code is free to 'consume' the
	 * secret.  But it doesn't ...
	 *
	 * In IKEv1, both the the DH exchange and authentication can
	 * be combined into a single packet.  Consequently, processing
	 * consits of: first DH is used to derive the shared secret
	 * from DH_SECRET and the keying material; and then
	 * authentication is performed.  However, should
	 * authentication fail, everything thing derived from that
	 * packet gets discarded and this includes the DH derived
	 * shared secret.  When the real packet arrives (or a
	 * re-transmit), the whole process is performed again, and
	 * using the same DH_SECRET.
	 *
	 * Consequently, when the crypto helper gets created, it gets
	 * ownership of the DH_SECRET, and then when it finishes,
	 * ownership is passed back to state.
	 *
	 * This all assumes that the crypto helper gets to delete
	 * DH_SECRET iff state has already been deleted.
	 *
	 * (An alternative would be to reference count dh_secret; or
	 * copy the underlying keying material using NSS, hmm, NSS).
	 */
	struct dh_secret *st_dh_secret;

	PK11SymKey *st_shared_nss;	/* Derived shared secret
					 * Note: during Quick Mode,
					 * presence indicates PFS
					 * selected.
					 */
	/* end of DH values */

	/* In a Phase 1 state, preserve peer's public key after authentication */
	struct pubkey *st_peer_pubkey;

#define st_state st_finite_state->fs_state
#define st_state_name st_finite_state->fs_name
#define st_state_story st_finite_state->fs_story
	const struct finite_state *st_finite_state;	/* Current FSM state */

	retransmit_t st_retransmit;	/* retransmit counters; opaque */
	unsigned long st_try;		/* Number of times rekeying attempted.
					 * 0 means the only time.
					 */
	deltatime_t st_margin;		/* life after EVENT_SA_REPLACE*/
	unsigned long st_outbound_count;	/* traffic through eroute */
	monotime_t st_outbound_time;	/* time of last change to
					 * st_outbound_count
					 */

	/*
	 * ST_OFFLOADED_TASK, when non-NULL, is the task that has been
	 * offloaded to a crypto helper (or for that matter a child
	 * process or anything).
	 *
	 * ST_V1_OFFLOADED_TASK_IN_BACKGROUND is more complicated:
	 *
	 * In IKEv1, the responder in main mode state MAIN_R1, after
	 * sending its KE+NONCE, will kick off the shared DH secret
	 * calculation in the 'background' - that is before it has
	 * received the first encrypted packet and actually needs the
	 * shared DH secret.  The responder than transitions to state
	 * MAIN_R2; and ST_SUSPENDED_MD will be left NULL and the
	 * above is set to TRUE.
	 *
	 * Later, if the shared DH secret is still being calculated
	 * when the responder receives the next, and encrypted,
	 * packet, that packet will be saved in .st_suspended_md and
	 * things will really suspend (instead of clearing
	 * ST_V1_OFFLOADED_TASK_IN_BACKGROUND, ST_SUSPENDED_MD is used
	 * as the state-busy marker).
	 *
	 * IKEv2 doesn't have this complexity and instead waits for
	 * that encrypted packet before kicking off the shared DH
	 * secret calculation.
	 *
	 * But wait, with ST_SUSPENDED_MD, there's more:
	 *
	 * The initial initiator (both IKEv1 and IKEv2), while
	 * KE+NONCE is being calculated, in addition to setting
	 * ST_OFFLOADED_TASK, will have ST_SUSPENDED_MD set to a
	 * 'fake_md' (grep for it).  This is because the initial
	 * initator can't have a real MD, and (presumably) faking one
	 * stops a core dump - the MD contains a pointer to ST and
	 * code likes to use that to find its state.  In the past
	 * (before ST_OFFLOADED_TASK was added), its presence would
	 * have also served as a state-is-busy marker.
	 */
	struct pluto_crypto_req_cont *st_offloaded_task;
	bool st_v1_offloaded_task_in_background;

	struct msg_digest *st_suspended_md;     /* suspended state-transition */
	const char        *st_suspended_md_func;
	int st_suspended_md_line;

	chunk_t st_p1isa;	/* Phase 1 initiator SA (Payload) for HASH */

	/* IKEv1 only */
	PK11SymKey *st_skeyid_nss;	/* Key material */

	/* v1 names are aliases for subset of v2 fields (#define) */
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

	/*
	 * Post-quantum preshared key variables
	 */
	bool st_ppk_used;			/* both ends agreed on PPK ID and PPK */
	bool st_seen_ppk;			/* does remote peer support PPK? */

	chunk_t st_no_ppk_auth;
	PK11SymKey *st_sk_d_no_ppk;
	PK11SymKey *st_sk_pi_no_ppk;
	PK11SymKey *st_sk_pr_no_ppk;

	/* connection included in AUTH */
	struct traffic_selector st_ts_this;
	struct traffic_selector st_ts_that;

	PK11SymKey *st_enc_key_nss;	/* Oakley Encryption key */

	struct pluto_event *st_event;		/* timer event for this state object */

	/* state list entry */
	struct list_entry st_serialno_list_entry;
	/* SERIALNO hash table entry */
	struct list_entry st_serialno_hash_entry;
	/* ICOOKIE:RCOOKIE hash table entry */
	struct list_entry st_cookies_hash_entry;
	/* ICOOKIE hash table entry */
	struct list_entry st_icookie_hash_entry;

	struct hidden_variables hidden_variables;

	char st_xauth_username[MAX_XAUTH_USERNAME_LEN];	/* NUL-terminated */
	chunk_t st_xauth_password;

	monotime_t st_last_liveness;		/* Time of last v2 informational (0 means never?) */
	bool st_pend_liveness;			/* Waiting on an informational response */
	struct pluto_event *st_liveness_event;
	struct pluto_event *st_rel_whack_event;
	struct pluto_event *st_send_xauth_event;
	struct pluto_event *st_addr_change_event;


	/* RFC 3706 Dead Peer Detection */
	monotime_t st_last_dpd;			/* Time of last DPD transmit (0 means never?) */
	uint32_t st_dpd_seqno;                 /* Next R_U_THERE to send */
	uint32_t st_dpd_expectseqno;           /* Next R_U_THERE_ACK to receive */
	uint32_t st_dpd_peerseqno;             /* global variables */
	uint32_t st_dpd_rdupcount;		/* openbsd isakmpd bug workaround */
	struct pluto_event *st_dpd_event;	/* backpointer for DPD events */

	bool st_seen_nortel_vid;                /* To work around a nortel bug */
	struct isakmp_quirks quirks;            /* work arounds for faults in other products */
	bool st_xauth_soft;                     /* XAUTH failed but policy is to soft fail */
	bool st_seen_fragvid;                   /* should really use st_seen_vendorid, but no one else is */
	bool st_seen_hashnotify;		/* did we receive hash algo notification in IKE_INIT, then send in response as well */
	bool st_seen_fragments;                 /* did we receive ike fragments from peer, if so use them in return as well */
	bool st_seen_no_tfc;			/* did we receive ESP_TFC_PADDING_NOT_SUPPORTED */
	bool st_seen_use_transport;		/* did we receive USE_TRANSPORT_MODE */
	bool st_seen_mobike;			/* did we receive MOBIKE */
	bool st_sent_mobike;			/* sent MOBIKE notify */
	bool st_seen_nonats;			/* did we receive NO_NATS_ALLOWED */
	bool st_seen_initialc;			/* did we receive INITIAL_CONTACT */
	generalName_t *st_requested_ca;		/* collected certificate requests */
	uint8_t st_reply_xchg;
	bool st_peer_wants_null;		/* We received IDr payload of type ID_NULL (and we allow POLICY_AUTH_NULL */
};

/*
 * The IKE and CHILD SAs.
 *
 * The terms IKE (parent, phase1) SA and CHILD * (phase2) SA are both
 * taken from the IKEv2 RFC.
 *
 * For the moment, abuse the rule that says you can flip flop between
 * a structure and a pointer to the structure's first entry.  Perhaps,
 * one day, new_state() et.al. will be replaced with functions that
 * return the correct SA.
 *
 * In code suggest:
 *
 *    struct ike_sa *ike; ike->sa.st_...
 *    struct child_sa *child; child->sa.st_...
 *
 * The function ike_sa() returns the IKE SA that the struct state
 * belongs to (an IKE SA belongs to itself).
 *
 * pexpect_ike_sa() is similar, except it complains loudly when ST
 * isn't an IKE SA.
 */

struct ike_sa { struct state sa; };
struct ike_sa *ike_sa(struct state *st);
struct ike_sa *pexpect_ike_sa(struct state *st);
struct child_sa { struct state sa; };
struct child_sa *pexpect_child_sa(struct state *st);

/* global variables */

extern uint16_t pluto_port;		/* Pluto's port */
extern uint16_t pluto_nat_port;	/* Pluto's NATT floating port */
extern uint16_t pluto_nflog_group;	/* NFLOG group - 0 means no logging  */
extern uint16_t pluto_xfrmlifetime;	/* only used to display in status */

extern bool states_use_connection(const struct connection *c);

/* state functions */

extern struct state *new_state(void);
extern struct state *new_rstate(struct msg_digest *md);

extern void init_states(void);
extern void insert_state(struct state *st);
extern void rehash_state(struct state *st, const u_char *icookie,
		const u_char *rcookie);
extern void release_whack(struct state *st);
extern void state_eroute_usage(const ip_subnet *ours, const ip_subnet *his,
			       unsigned long count, monotime_t nw);
extern void delete_state(struct state *st);
extern void delete_states_by_connection(struct connection *c, bool relations);
extern void delete_p2states_by_connection(struct connection *c);
extern void rekey_p2states_by_connection(struct connection *c);
extern void delete_my_family(struct state *pst, bool v2_responder_state);

struct state *ikev1_duplicate_state(struct state *st);
struct state *ikev2_duplicate_state(struct ike_sa *st, sa_t sa_type,
				    enum sa_role sa_role);

extern struct state
	*state_with_serialno(so_serial_t sn),
	*find_phase2_state_to_delete(const struct state *p1st, uint8_t protoid,
			     ipsec_spi_t spi, bool *bogus),
	*find_phase1_state(const struct connection *c, lset_t ok_states),
	*find_likely_sender(size_t packet_len, u_char * packet);

struct state *find_state_ikev1(const uint8_t *icookie, const uint8_t *rcookie,
			       msgid_t msgid);
struct state *find_state_ikev1_init(const uint8_t *icookie, msgid_t msgid);

extern bool find_pending_phase2(const so_serial_t psn,
					const struct connection *c,
					lset_t ok_states);

extern struct state *resp_state_with_msgid(so_serial_t psn, msgid_t st_msgid);

extern struct state *state_with_parent_msgid(so_serial_t psn, msgid_t st_msgid);

extern struct state *find_state_ikev2_parent(const u_char *icookie,
					     const u_char *rcookie);

extern struct state *ikev2_find_state_in_init(const u_char *icookie,
						  enum state_kind expected_state);

extern struct state *find_state_ikev2_child(const enum isakmp_xchg_types ix,
					    const u_char *icookie,
					    const u_char *rcookie,
					    const msgid_t msgid);

extern struct state *find_state_ikev2_child_to_delete(const u_char *icookie,
						      const u_char *rcookie,
						      uint8_t protoid,
						      ipsec_spi_t spi);

extern struct state *ikev1_find_info_state(const u_char *icookie,
				     const u_char *rcookie,
				     const ip_address *peer,
				     msgid_t msgid);

extern void initialize_new_state(struct state *st,
				 struct connection *c,
				 lset_t policy,
				 int try,
				 fd_t whack_sock);

extern void show_traffic_status(const char *name);
extern void show_states_status(void);

extern void ikev2_repl_est_ipsec(struct state *st, void *data);
extern void ikev2_inherit_ipsec_sa(so_serial_t osn, so_serial_t nsn,
				const u_char *icookie,
				const u_char *rcookie);

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

extern bool state_is_busy(const struct state *st);
extern bool verbose_state_busy(const struct state *st);
extern bool drop_new_exchanges(void);
extern bool require_ddos_cookies(void);
extern void show_globalstate_status(void);
extern void set_newest_ipsec_sa(const char *m, struct state *const st);
extern void update_ike_endpoints(struct state *st, const struct msg_digest *md);
extern bool update_mobike_endpoints(struct state *st, const struct msg_digest *md);
extern void ikev2_expire_unused_parent(struct state *pst);

bool shared_phase1_connection(const struct connection *c);

extern void record_deladdr(ip_address *ip, char *a_type);
extern void record_newaddr(ip_address *ip, char *a_type);

extern void append_st_cfg_domain(struct state *st, char *dnsip);
extern void append_st_cfg_dns(struct state *st, const char *dnsip);
extern bool ikev2_viable_parent(const struct ike_sa *ike);

extern bool uniqueIDs;  /* --uniqueids? */
extern void ISAKMP_SA_established(const struct state *pst);

#endif /* _STATE_H */
