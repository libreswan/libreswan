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
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2015-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2015-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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
#include "crypt_mac.h"

#include <nss.h>
#include <pk11pub.h>
#include <x509.h>

#include "labeled_ipsec.h"	/* for struct xfrm_user_sec_ctx_ike and friends */
#include "list_entry.h"
#include "retransmit.h"
#include "ikev2_ts.h"		/* for struct traffic_selector */
#include "ip_subnet.h"
#include "ike_spi.h"
#include "pluto_timing.h"	/* for statetime_t */
#include "ikev2_msgid.h"
#include "ip_endpoint.h"
#include "crypt_mac.h"
#include "show.h"

struct state_v2_microcode;
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
	const struct dh_desc *ta_dh;	/* Diffie-Helman-Merkel routines */
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
	uint16_t mode;			/* transport or tunnel or ... */
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

struct v1_ike_rfrag {
	struct v1_ike_rfrag *next;
	struct msg_digest *md;
	int index;
	int last;
	uint8_t *data;
	size_t size;
};

struct v2_incomming_fragment {
	chunk_t cipher;
	unsigned int iv;
};

struct v2_incomming_fragments {
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
	struct v2_incomming_fragment frags[MAX_IKE_FRAGMENTS + 1];
};

/* hunk like */

struct v2_outgoing_fragment {
	struct v2_outgoing_fragment *next;
	size_t len;
	uint8_t ptr[1]; /* can be bigger */
};

struct v2_id_payload {
	struct ikev2_id header;
	chunk_t data;
	/* MAC of part of header + data */
	struct crypt_mac mac;
	/* Same for non-ppk */
	struct crypt_mac mac_no_ppk_auth;
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

#define suspend_any_md(ST, MD)						\
	{								\
		if (MD != NULL) {					\
			dbg("suspending state #%lu and saving MD %p",	\
			    (ST)->st_serialno, MD);			\
			passert((ST)->st_suspended_md == NULL);		\
			(ST)->st_suspended_md = md_addref(MD, HERE);	\
			(ST)->st_suspended_md_func = __func__;		\
			(ST)->st_suspended_md_line = __LINE__;		\
			passert(state_is_busy(ST));			\
		} else {						\
			dbg("no MD to suspend");			\
		}							\
	}

/*
 * All the hash tables states are stored in.
 */
enum state_hash_tables {
	STATE_SERIALNO_HASH_TABLE,
	STATE_CONNECTION_HASH_TABLE,
	STATE_REQID_HASH_TABLE,
	STATE_IKE_SPIS_HASH_TABLE,
	STATE_IKE_INITIATOR_SPI_HASH_TABLE,
	STATE_HASH_TABLES_ROOF,
};

/*
 * For auditing, why an SA is being deleted.
 */
enum delete_reason {
#define DELETE_REASON_FLOOR 0
	REASON_UNKNOWN = DELETE_REASON_FLOOR, /* aka other */
	REASON_CRYPTO_TIMEOUT,
	REASON_EXCHANGE_TIMEOUT,
	REASON_TOO_MANY_RETRANSMITS,
	REASON_CRYPTO_FAILED,
	REASON_AUTH_FAILED,
	REASON_COMPLETED,
#define DELETE_REASON_ROOF (REASON_COMPLETED + 1)
};

/*
 * For auditing, different categories of a state.  Of most interest is
 * half-open states which suggest libreswan being under attack.
 *
 * "half-open" is where only one packet was received.
 */
enum state_category {
	CAT_UNKNOWN = 0,
	CAT_HALF_OPEN_IKE_SA,
	CAT_OPEN_IKE_SA,
	CAT_ESTABLISHED_IKE_SA,
	CAT_ESTABLISHED_CHILD_SA,
	CAT_INFORMATIONAL,
	CAT_IGNORE,
};

extern enum_names state_category_names;

/*
 * Abstract state machine that drives the parent and child SA.
 *
 * IKEv1 and IKEv2 construct states using this as a base.
 */
struct finite_state {
	enum state_kind kind;
	const char *name;
	const char *short_name;
	const char *story;
	lset_t flags;
	enum state_category category;
	const struct state_v1_microcode *v1_transitions;
	const struct state_v2_microcode *v2_transitions;
	size_t nr_transitions;
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
	realtime_t st_inception;		/* time state is created, for logging */
	struct state_timing st_timing;		/* accumulative cpu time */
	so_serial_t st_serialno;                /* serial number (for seniority)*/
	so_serial_t st_clonedfrom;              /* serial number of parent */
	so_serial_t st_ike_pred;		/* IKEv2: replacing established IKE SA */
	so_serial_t st_ipsec_pred;		/* replacing established IPsec SA */

#ifdef XAUTH_HAVE_PAM
	struct xauth *st_xauth;			/* per state xauth/pam thread */
#endif

	/*
	 * XXX: Can these attributes be moved to struct finite_state?
	 * Probably, but later.
	 *
	 * XXX: Can these attributes be made "const".  Probably,
	 * new_state() could use clone_thing(const state on stack).
	 */
	/*const*/ enum ike_version st_ike_version;	/* IKEv1, IKEv2, ... */
	/*const*/ enum sa_type st_establishing_sa;	/* where is this state going? */

	bool st_ikev2_anon;                     /* is this an anonymous IKEv2 state? */
	bool st_dont_send_delete;		/* suppress sending DELETE - eg replaced conn */

	struct connection *st_connection;       /* connection for this SA */
 	struct logger *st_logger;
#define st_whack_sock st_logger->object_whackfd

	struct trans_attrs st_oakley;

	struct ipsec_proto_info st_ah;
	struct ipsec_proto_info st_esp;
	struct ipsec_proto_info st_ipcomp;

	ipsec_spi_t st_tunnel_in_spi;		/* KLUDGE */
	ipsec_spi_t st_tunnel_out_spi;		/* KLUDGE */
	IPsecSAref_t st_ref;                    /* our kernel name for our incoming SA */
	IPsecSAref_t st_ref_peer;                 /* our kernel name for our outgoing SA */
	reqid_t st_reqid;			/* bundle of 4 (out,in, compout,compin */

	bool st_outbound_done;			/* if true, then outgoing SA already installed */

	const struct dh_desc *st_pfs_group;   /*group for Phase 2 PFS */
	lset_t st_hash_negotiated;              /* Saving the negotiated hash values here */
	lset_t st_policy;                       /* policy for IPsec SA */

	ip_endpoint st_remote_endpoint;        /* where to send packets to */

	/*
	 * dhr 2013: why [.st_interface]? There was already
	 * connection->interface
	 *
	 * XXX: It seems that .st_interface starts out the same as the
	 * connection's interface but then be changed by NAT.  For
	 * instance, when the initial request is sent on :500 but the
	 * response comes back on :4500, .st_interface will switch.
	 *
	 * XXX: It looks like there's redundancy, or at least there
	 * should be consistency between this.{addr,port} and the
	 * local endpoint.  pexpect_st_local_endpoint() is a place
	 * holder as that idear gets explored.
	 */
	const struct iface_port *st_interface;  /* where to send from */
#define pexpect_st_local_endpoint(ST) /* see above */

	bool st_mobike_del_src_ip;		/* for mobike migrate unroute */
	/* IKEv2 MOBIKE probe copies */
	ip_address st_mobike_remote_endpoint;
	ip_address st_deleted_local_addr;	/* kernel deleted address */
	ip_endpoint st_mobike_local_endpoint;	/* new address to initiate MOBIKE */
	ip_address st_mobike_host_nexthop;	/* for updown script */

	/** IKEv1-only things **/
	/* XXX: union { struct { .. } v1; struct {...} v2;} st? */

	struct {
		msgid_t id;             /* MSG-ID from header. Network Order?!? */
		bool reserved;		/* is msgid reserved yet? */
		msgid_t phase15;        /* msgid for phase 1.5 - Network Order! */
	} st_v1_msgid;
	/* only for a state representing an ISAKMP SA */
	struct msgid_list *st_used_msgids;	/* used-up msgids */

	/* collected received fragments */
	struct v1_ike_rfrag *st_v1_rfrags;
	chunk_t st_v1_tpacket;                  /* Transmitted packet */
	chunk_t st_v1_rpacket;			/* Received packet - v1 only */

	/*
	 * State transition, both the one in progress and the most
	 * recent The last successful state transition (edge,
	 * microcode).  Used when transitioning to this current state.
	 */
	const struct state_v1_microcode *st_v1_last_transition;
	const struct state_v1_microcode *st_v1_transition; /* anyone? */
	const struct state_v2_microcode *st_v2_last_transition;
	const struct state_v2_microcode *st_v2_transition;

	/* Initialization Vectors for IKEv1 IKE encryption */

	struct crypt_mac st_v1_new_iv;	/* tentative IV (calculated from current packet) */
	struct crypt_mac st_v1_iv;		/* accepted IV (after packet passes muster) */
	struct crypt_mac st_v1_ph1_iv;	/* IV at end of phase 1 */

	/* end of IKEv1-only things */

	/** IKEv2-only things **/
	/* XXX: union { struct { .. } v1; struct {...} v2;} st? */

	/* collected received fragments */
	struct v2_ike_rfrags *st_v2_rfrags;
	struct v2_outgoing_fragment *st_v2_outgoing[MESSAGE_ROLE_ROOF];
	struct v2_incomming_fragments *st_v2_incomming[MESSAGE_ROLE_ROOF];

	bool st_viable_parent;	/* can initiate new CERAET_CHILD_SA */
	struct ikev2_proposal *st_accepted_ike_proposal;
	struct ikev2_proposal *st_accepted_esp_or_ah_proposal;

	enum sa_role st_sa_role;			/* who initiated the SA */

	struct v2_msgid_wip st_v2_msgid_wip;		/* IKE and CHILD */
	struct v2_msgid_windows st_v2_msgid_windows;	/* IKE */

	/* message ID sequence for things we send (as initiator) */
	msgid_t st_msgid_lastack;               /* last one peer acknowledged  - host order */
	msgid_t st_msgid_nextuse;               /* next one to use - host order */
	/* message ID sequence for things we receive (as responder) */
	msgid_t st_msgid_lastrecv;             /* last one peer sent - Host order v2 only */
	msgid_t st_msgid_lastreplied;         /* to decide retransmit CREATE_CHILD_SA */

	chunk_t st_firstpacket_me;              /* copy of my message 1 (for hashing) */
	chunk_t st_firstpacket_peer;             /* copy of peers message 1 (for hashing) */

	struct p_dns_req *ipseckey_dnsr;    /* ipseckey of that end */
	struct p_dns_req *ipseckey_fwd_dnsr;/* validate IDi that IP in forward A/AAAA */

	shunk_t st_active_redirect_gw;	/* needed for sending of REDIRECT in informational */

	/** end of IKEv2-only things **/

	/*
	 * Identity sent across the wire in the ID[ir] payload as part
	 * of authentication (proof of identity).
	 */
	struct v2_id_payload st_v2_id_payload;

	char *st_seen_cfg_dns; /* obtained internal nameserver IP's */
	char *st_seen_cfg_domains; /* obtained internal domain names */
	char *st_seen_cfg_banner; /* obtained banner */

	/* symmetric stuff */

	ike_spis_t st_ike_spis;
	ike_spis_t st_ike_rekey_spis;		/* what was exchanged */

	/* initiator stuff */
	chunk_t st_gi;                          /* Initiator public value */
	chunk_t st_ni;                          /* Ni nonce */

	/* responder stuff */
	chunk_t st_gr;                          /* Responder public value */
	chunk_t st_nr;                          /* Nr nonce */
	chunk_t st_dcookie;                     /* DOS cookie of responder - v2 only */

	/* my stuff */

	struct xfrm_user_sec_ctx_ike *sec_ctx;

	/* Phase 2 ID payload info about my user */
	uint8_t st_myuserprotoid;             /* IDcx.protoid */
	uint16_t st_myuserport;

	/* peers stuff */

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

	/*
	 * Handle on all the certs extracted from the cert payload and
	 * then verified using the CAs in the NSS Certificate DB.
	 * When the state is deleted do they get released.  We suspect
	 * that they need to lurk in the NSS DB so that the CRL code
	 * can find them.  The first cert in the list is always the
	 * end or EE cert.
	 */
	bool st_peer_alt_id;	/* scratchpad for writing we found alt peer id in CERT */
	struct {
		bool processed;		/* do this once, may not be any */
		bool harmless;		/* something nasty */
		struct certs *verified;	/* list; first is EE */
		struct pubkey_list *pubkey_db;
	} st_remote_certs;

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
	 * consists of: first DH is used to derive the shared secret
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

	const struct finite_state *st_state;	/* Current FSM state */

	/*
	 * Account for why an SA is is started, established, and
	 * finished (deleted).
	 *
	 * SA_TYPE indicates the type of SA (IKE or CHILD) that will
	 * eventually be established.  For instance, when re-keying an
	 * IKE SA where the state is treated like a child until it is
	 * emancipated (it has a parent), SA_TYPE=IKE_SA.  While it
	 * might technically be possible to extract this information
	 * from enum state_kind this is far more robust.
	 *
	 * DELETE_REASON, if the SA establishes it contains
	 * REASON_COMPLETED, else it is explicitly set to failure
	 * indication (or defaults to REASON_UNKNOWN).  Note that the
	 * information can't be reliably extracted from enum
	 * state_kind in delete_state() because, by that point, state
	 * may have further transitioned to STATE_IKESA_DEL etc.
	 * Also, note that the information can't be reliably set in
	 * complete*transition() as, at least in the case of IKEv2,
	 * there can be two states involved where one success and one
	 * fails.
	 */
	struct {
		enum sa_type sa_type;
		enum delete_reason delete_reason;
	} st_pstats;

	retransmit_t st_retransmit;	/* retransmit counters; opaque */
	unsigned long st_try;		/* Number of times rekeying attempted.
					 * 0 means the only time.
					 */
	/*
	 * How much time to allow the replace attempt (i.e., re-key)
	 * before the SA must be killed and then re-started from
	 * scratch.
	 */
	deltatime_t st_replace_margin;
	monotime_t st_replace_by;

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

	chunk_t st_p1isa;	/* v1 Phase 1 initiator SA (Payload) for HASH */

	PK11SymKey *st_skeyid_nss;	/* v1 Key material */

	/* v1 names are aliases for subset of v2 fields (#define) */

#define st_skeyid_d_nss st_skey_d_nss	/* v1 KM for non-ISAKMP key derivation */
	PK11SymKey *st_skey_d_nss;	/* v2 KM for non-ISAKMP key derivation */

#define st_skeyid_a_nss st_skey_ai_nss	/* v1 IKE authentication KM */
	PK11SymKey *st_skey_ai_nss;	/* v2 IKE authentication key for initiator */
	PK11SymKey *st_skey_ar_nss;	/* v2 IKE authentication key for responder */

#define st_skeyid_e_nss st_skey_ei_nss	/* v1 IKE encryption KM */
	PK11SymKey *st_skey_ei_nss;	/* v2 IKE encryption key for initiator */
	PK11SymKey *st_skey_er_nss;	/* v2 IKE encryption key for responder */

	PK11SymKey *st_skey_pi_nss;	/* v2 PPK for initiator */
	PK11SymKey *st_skey_pr_nss;	/* v2 PPK for responder */

	chunk_t st_skey_initiator_salt;	/* v2 */
	chunk_t st_skey_responder_salt;	/* v2 */
	chunk_t st_skey_chunk_SK_pi;	/* v2 */
	chunk_t st_skey_chunk_SK_pr;	/* v2 */

	/*
	 * Post-quantum Preshared Key variables (v2)
	 */
	bool st_ppk_used;			/* both ends agreed on PPK ID and PPK */
	bool st_seen_ppk;			/* does remote peer support PPK? */

	chunk_t st_no_ppk_auth;
	PK11SymKey *st_sk_d_no_ppk;
	PK11SymKey *st_sk_pi_no_ppk;
	PK11SymKey *st_sk_pr_no_ppk;

	/* connection included in AUTH (v2) */
	struct traffic_selector st_ts_this;
	struct traffic_selector st_ts_that;

	PK11SymKey *st_enc_key_nss;	/* Oakley Encryption key */

	struct pluto_event *st_event;		/* timer event for this state object */

	/* state list entry */
	struct list_entry st_serialno_list_entry;

	/* all the hash table entries */
	struct list_entry st_hash_table_entries[STATE_HASH_TABLES_ROOF];

	struct hidden_variables hidden_variables;

	char st_xauth_username[MAX_XAUTH_USERNAME_LEN];	/* NUL-terminated */
	chunk_t st_xauth_password;

	monotime_t st_last_liveness;		/* Time of last v2 informational (0 means never?) */
	bool st_pend_liveness;			/* Waiting on an informational response */
	struct pluto_event *st_liveness_event;	/* IKEv2 only event */
	struct pluto_event *st_rel_whack_event;
	struct pluto_event *st_send_xauth_event;
	struct pluto_event *st_addr_change_event;
	struct pluto_event *st_retransmit_event;

	/* RFC 3706 Dead Peer Detection */
	monotime_t st_last_dpd;			/* Time of last DPD transmit (0 means never?) */
	uint32_t st_dpd_seqno;                 /* Next R_U_THERE to send */
	uint32_t st_dpd_expectseqno;           /* Next R_U_THERE_ACK to receive */
	uint32_t st_dpd_peerseqno;             /* global variables */
	uint32_t st_dpd_rdupcount;		/* openbsd isakmpd bug workaround */
	struct pluto_event *st_dpd_event;	/* backpointer for IKEv1 DPD events */

	bool st_seen_nortel_vid;                /* To work around a nortel bug */
	struct isakmp_quirks quirks;            /* work arounds for faults in other products */
	bool st_xauth_soft;                     /* XAUTH failed but policy is to soft fail */
	bool st_seen_fragmentation_supported;	/* v1 frag vid; v2 frag notify */
	bool st_seen_hashnotify;		/* did we receive hash algo notification in IKE_INIT, then send in response as well */
	bool st_seen_fragments;                 /* did we receive ike fragments from peer, if so use them in return as well */
	bool st_seen_no_tfc;			/* did we receive ESP_TFC_PADDING_NOT_SUPPORTED */
	bool st_seen_use_transport;		/* did we receive USE_TRANSPORT_MODE */
	bool st_seen_use_ipcomp;		/* did we receive request for IPCOMP */
	bool st_seen_mobike;			/* did we receive MOBIKE */
	bool st_sent_mobike;			/* sent MOBIKE notify */
	bool st_seen_nonats;			/* did we receive NO_NATS_ALLOWED */
	bool st_seen_initialc;			/* did we receive INITIAL_CONTACT */
	bool st_seen_redirect_sup;		/* did we receive IKEv2_REDIRECT_SUPPORTED */
	bool st_sent_redirect;			/* did we send IKEv2_REDIRECT in IKE_AUTH (response) */
	bool st_redirected_in_auth;		/* were we redirected in IKE_AUTH */
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
 * The function get_ike_sa() returns the IKE SA that the struct state
 * belongs to (an IKE SA belongs to itself).
 *
 * pexpect_{ike,child}_sa() cast the SA (assuming it makes sense), or
 * NULL.
 */

struct ike_sa { struct state sa; };
struct ike_sa *ike_sa(struct state *st, where_t where);
struct ike_sa *pexpect_ike_sa(struct state *st);
struct child_sa { struct state sa; };
struct child_sa *pexpect_child_sa(struct state *st);

/* global variables */

extern uint16_t pluto_nflog_group;	/* NFLOG group - 0 means no logging  */
extern uint16_t pluto_xfrmlifetime;	/* only used to display in status */

extern bool states_use_connection(const struct connection *c);

/* state functions */

struct ike_sa *new_v1_istate(struct fd *whackfd);
struct ike_sa *new_v1_rstate(struct msg_digest *md);

struct ike_sa *new_v2_ike_state(const struct state_v2_microcode *transition,
				enum sa_role sa_role,
				const ike_spi_t ike_initiator_spi,
				const ike_spi_t ike_responder_spi,
				struct connection *c, lset_t policy,
				int try, struct fd *whack_sock);
/* could eventually be IKE or CHILD SA */
struct child_sa *new_v2_child_state(struct ike_sa *st, enum sa_type sa_type,
				    enum sa_role sa_role, enum state_kind kind,
				    struct fd *whackfd);

void set_v1_transition(struct state *st, const struct state_v1_microcode *transition, where_t where);
void set_v2_transition(struct state *st, const struct state_v2_microcode *transition, where_t where);
void switch_md_st(struct msg_digest *md, struct state *st, where_t where);
void jam_v1_transition(jambuf_t *buf, const struct state_v1_microcode *transition);
void jam_v2_transition(jambuf_t *buf, const struct state_v2_microcode *transition);

extern void init_states(void);
extern void rehash_state(struct state *st,
			 const ike_spi_t *ike_responder_spi);
extern void release_any_whack(struct state *st, where_t where, const char *why);
extern void state_eroute_usage(const ip_subnet *ours, const ip_subnet *peers,
			       unsigned long count, monotime_t nw);
extern void delete_state(struct state *st);
extern void delete_states_by_connection(struct connection *c, bool relations, struct fd *whackfd);
extern void rekey_p2states_by_connection(struct connection *c);
enum send_delete { PROBABLY_SEND_DELETE, DONT_SEND_DELETE, };
extern void delete_ike_family(struct ike_sa *ike, enum send_delete send_delete);
extern void schedule_next_child_delete(struct state *st, struct ike_sa *ike);

struct state *ikev1_duplicate_state(struct state *st, struct fd *whackfd);

extern struct state
	*state_with_serialno(so_serial_t sn),
	*find_phase2_state_to_delete(const struct state *p1st, uint8_t protoid,
			     ipsec_spi_t spi, bool *bogus),
	*find_phase1_state(const struct connection *c, lset_t ok_states);

struct state *find_state_ikev1(const ike_spis_t *ike_spis, msgid_t msgid);
struct state *find_state_ikev1_init(const ike_spi_t *ike_initiator_spi,
				    msgid_t msgid);

extern bool find_pending_phase2(const so_serial_t psn,
					const struct connection *c,
					lset_t ok_states);

extern struct ike_sa *find_v2_ike_sa(const ike_spis_t *ike_spis,
				     enum sa_role local_ike_role);
extern struct ike_sa *find_v2_ike_sa_by_initiator_spi(const ike_spi_t *ike_initiator_spi,
						      enum sa_role local_ike_role);

struct child_sa *find_v2_child_sa_by_outbound_spi(struct ike_sa *ike,
						  uint8_t protoid,
						  ipsec_spi_t outbound_spi);

extern struct state *find_v1_info_state(const ike_spis_t *ike_spis,
					msgid_t msgid);

extern void initialize_new_state(struct state *st,
				 struct connection *c,
				 lset_t policy,
				 int try);

extern void show_traffic_status(struct show *s, const char *name);
extern void show_brief_status(struct show *s);
extern void show_states(struct show *s);

void v2_migrate_children(struct ike_sa *from, struct child_sa *to);

void for_each_state(void (*f)(struct state *, void *data), void *data,
		    const char *func);

extern void find_my_cpi_gap(cpi_t *latest_cpi, cpi_t *first_busy_cpi);
extern ipsec_spi_t uniquify_peer_cpi(ipsec_spi_t cpi, const struct state *st, int tries);

extern void fmt_state(struct state *st, const monotime_t n,
		      char *state_buf, const size_t state_buf_len,
		      char *state_buf2, const size_t state_buf_len2);

extern void delete_states_by_peer(const struct fd *whackfd, const ip_address *peer);
extern void replace_states_by_peer(const ip_address *peer);
extern void v1_delete_state_by_username(struct state *st, void *name);
extern void delete_state_by_id_name(struct state *st, void *name);

extern void delete_cryptographic_continuation(struct state *st);
extern void delete_states_dead_interfaces(struct fd *whackfd);
extern bool dpd_active_locally(const struct state *st);

/*
 * Use this to change state, this gives us a handle on all state
 * changes which is good for tracking bugs, logging and anything else
 * you might like.
 */
extern void change_state(struct state *st, enum state_kind new_state);

extern bool state_is_busy(const struct state *st);
extern bool verbose_state_busy(const struct state *st);
extern bool drop_new_exchanges(void);
extern bool require_ddos_cookies(void);
extern void show_globalstate_status(struct show *s);
extern void set_newest_ipsec_sa(const char *m, struct state *const st);
extern void update_ike_endpoints(struct ike_sa *ike, const struct msg_digest *md);
extern bool update_mobike_endpoints(struct ike_sa *ike, const struct msg_digest *md);
extern void v2_expire_unused_ike_sa(struct ike_sa *ike);

bool shared_phase1_connection(const struct connection *c);
bool v2_child_connection_probably_shared(struct child_sa *child);

extern void record_deladdr(ip_address *ip, char *a_type);
extern void record_newaddr(ip_address *ip, char *a_type);

extern void append_st_cfg_domain(struct state *st, char *dnsip);
extern void append_st_cfg_dns(struct state *st, const char *dnsip);
extern bool ikev2_viable_parent(const struct ike_sa *ike);

extern bool uniqueIDs;  /* --uniqueids? */
extern void IKE_SA_established(const struct ike_sa *ike);
extern void revive_conns(struct fd *whackfd);

void list_state_events(const struct fd *whackfd, monotime_t now);

#endif /* _STATE_H */
