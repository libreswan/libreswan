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
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
 * Copyright (C) 2021 Paul Wouters <paul.wouters@aiven.io>
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

#ifndef STATE_H
#define STATE_H

#include <stddef.h>		/* for size_t */
#include <stdbool.h>

#include <pk11pub.h>
#include <x509.h>

#include "deltatime.h"
#include "monotime.h"
#include "reqid.h"
#include "fd.h"
#include "crypt_mac.h"
#include "ip_subnet.h"
#include "ip_endpoint.h"
#include "ip_selector.h"
#include "kernel_mode.h"
#include "sa_type.h"
#include "quirks.h"
#include "list_entry.h"
#include "retransmit.h"
#include "ikev2_ts.h"		/* for struct traffic_selector */
#include "ike_spi.h"
#include "pluto_timing.h"	/* for statetime_t */
#include "ikev2_msgid.h"

struct whack_message;
struct v2_state_transition;
struct ikev2_ipseckey_dns; /* forward declaration of tag */

struct state;   /* forward declaration of tag */
struct eap_state;

/* Oakley (Phase 1 / Main Mode) transform and attributes
 * This is a flattened/decoded version of what is represented
 * in the Transaction Payload.
 * Names are chosen to match corresponding names in state.
 */
struct trans_attrs {
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

	/* negotiated crypto-suite */
	const struct encrypt_desc *ta_encrypt;	/* package of encryption routines */
	uint16_t enckeylen;			/* encryption key len (bits) */
	const struct ipcomp_desc *ta_ipcomp;	/* package of ipcomp routines */
	const struct prf_desc *ta_prf;		/* package of prf routines */
	const struct integ_desc *ta_integ;	/* package of integrity routines */
	const struct dh_desc *ta_dh;	/* Diffie-Helman-Merkel routines */
};

/*
 * IPsec (Phase 2 / Quick Mode) transform and attributes This is a
 * flattened/decoded version of what is represented by a Transaction
 * Payload.  There may be one for AH, one for ESP, and a funny one for
 * IPCOMP.
 *
 * Yes, this is screwy -- we keep different direction information in
 * different places. Fix it up sometime.
 */

struct ipsec_flow {
	bool expired[SA_EXPIRE_KIND_ROOF];
	uint64_t bytes;
	realtime_t last_used;
	chunk_t keymat;
	ipsec_spi_t spi;
};

struct ipsec_proto_info {
	const struct ip_protocol *protocol;	/* ESP, AH, COMP, ... */
	deltatime_t v1_lifetime;	/* max life of this SA */
	struct trans_attrs trans_attrs;
	struct ipsec_flow inbound;
	struct ipsec_flow outbound;
	uint64_t add_time;
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

/*
 * On entry to this macro, when crypto has been off loaded then
 * st_offloaded.job is non-NULL.  However, with XAUTH immediate,
 * there's nothing to check.
 */

struct msg_digest *unsuspend_any_md_where(struct state *st, where_t where);
#define unsuspend_any_md(ST) unsuspend_any_md_where(ST, HERE)

void suspend_any_md_where(struct state *st, struct msg_digest *md, where_t where);
#define suspend_any_md(ST, MD) suspend_any_md_where(ST, MD, HERE)

/*
 * For auditing, why an SA is being deleted.
 */
enum delete_reason {
#define DELETE_REASON_FLOOR 0
	REASON_UNKNOWN = DELETE_REASON_FLOOR, /* aka other */
	REASON_CRYPTO_TIMEOUT,
	REASON_EXCHANGE_TIMEOUT,
	REASON_TOO_MANY_RETRANSMITS,
	REASON_SUPERSEDED_BY_NEW_SA,
	REASON_CRYPTO_FAILED,
	REASON_AUTH_FAILED,
	REASON_TRAFFIC_SELECTORS_FAILED,
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
	enum state_category category;
	enum ike_version ike_version; /* discriminator */
	union {
		struct {
			lset_t flags;
			const struct state_v1_microcode *transitions;
		} v1;
		struct {
			const struct v2_state_transition *transitions;
			bool secured; /* hence, exchanges must be integrity protected */
		} v2;
	};
	size_t nr_transitions;
};

void lswlog_finite_state(struct jambuf *buf, const struct finite_state *fs);

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

	so_serial_t st_v1_ipsec_pred;		/* IKEv1: replacing established IPsec SA */
	so_serial_t st_v2_ike_pred;		/* IKEv2: replacing established IKE SA */
	so_serial_t st_v2_rekey_pred;		/* IKEv2: rekeying established IKE or CHILD SA */

#ifdef USE_PAM_AUTH
	struct pam_auth *st_pam_auth;		/* per state auth/pam thread */
#endif

	/*
	 * XXX: Can these attributes be moved to struct finite_state?
	 * Probably, but later.
	 *
	 * XXX: Can these attributes be made "const".  Probably,
	 * new_state() could use clone_thing(const state on stack).
	 */
#define st_ike_version st_connection->config->ike_version
	/*const*/ enum sa_type st_sa_type_when_established;	/* where is this state going? */

	bool st_ikev2_anon;                     /* is this an anonymous IKEv2 state? */

	struct connection *st_connection;       /* connection for this SA */
 	struct logger *logger;

	struct trans_attrs st_oakley;

	/* Child SA / IPsec SA */
	enum kernel_mode st_kernel_mode;	/* aka IPsec mode */
	struct ipsec_proto_info st_ah;
	struct ipsec_proto_info st_esp;
	struct ipsec_proto_info st_ipcomp;

	reqid_t st_reqid;			/* bundle of 4 (out,in, compout,compin */

	const struct dh_desc *st_pfs_group;   /*group for Phase 2 PFS */
	lset_t st_policy;                       /* policy for IPsec SA */

	ip_endpoint st_remote_endpoint;        /* where to send packets to */

	/*
	 * Digital Signature authentication.
	 *
	 * During IKE_SA_INIT, the acceptable hash algorithms are
	 * saved in NEGOTIATED_HASHES.
	 *
	 * The IKE_AUTH initiator uses NEGOTIATED_HASHES + POLICY to
	 * select HASH+SIGNER which is then used sign it's
	 * proof-of-identity.
	 *
	 * The IKE_AUTH responder saves the HASH+SIGNER used by the
	 * initiator, it then uses that + POLICY to update HASH+SIGNER,
	 * to sign it's proof-of-identity.
	 *
	 * Because things can be asymetric, the initiator values are
	 * just hints to the responder.
	 */

	struct {
		lset_t negotiated_hashes;		/* from IKE_SA_INIT */
		const struct hash_desc *hash;
		const struct pubkey_signer *signer;
	} st_v2_digsig;

	/*
	 * A connection is oriented to an interface (eth0 192.168.1.23
	 * say) while a state has an endpoint on that interface
	 * (192.168.1.23/tcp/433 say).
	 *
	 * History:
	 *
	 * dhr 2013: why [.st_iface_endpoint]? There was already
	 * connection->interface
	 *
	 * XXX: It seems that .st_iface_endpoint starts out the same as the
	 * connection's interface but then be changed by NAT and/or
	 * TCP.  For instance, when the initial request is sent on
	 * :500 but the response comes back on :4500, and when
	 * negotiation falls back to TCP, .st_iface_endpoint will switch.
	 *
	 * XXX: both .st_iface_endpoint and iface_endpoint are misleading
	 * names: a network interface can have more than one port but
	 * this for just one; and iface_endpoint isn't really like a
	 * simple ip_endpoint.
	 */
	struct iface_endpoint *st_iface_endpoint;  /* where to send from */

	bool st_mobike_del_src_ip;		/* for mobike migrate unroute */
	/* IKEv2 MOBIKE probe copies */
	ip_address st_deleted_local_addr;	/* kernel deleted address */
	ip_endpoint st_mobike_remote_endpoint;
	ip_endpoint st_mobike_local_endpoint;	/* new address to initiate MOBIKE */
	ip_address st_mobike_host_nexthop;	/* for updown script */

	/** IKEv1-only things **/
	/* XXX: union { struct { .. } v1; struct {...} v2;} st? */

#ifdef USE_IKEv1
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

	/* Initialization Vectors for IKEv1 IKE encryption */

	struct crypt_mac st_v1_new_iv;	/* tentative IV (calculated from current packet) */
	struct crypt_mac st_v1_iv;		/* accepted IV (after packet passes muster) */
	struct crypt_mac st_v1_ph1_iv;	/* IV at end of phase 1 */

	/* end of IKEv1-only things */
#endif

	/** IKEv2-only things **/
	/* XXX: union { struct { .. } v1; struct {...} v2;} st? */

	const struct v2_state_transition *st_v2_last_transition;
	const struct v2_state_transition *st_v2_transition;

	/* collected received fragments */
	struct v2_ike_rfrags *st_v2_rfrags;
	struct v2_outgoing_fragment *st_v2_outgoing[MESSAGE_ROLE_ROOF];
	struct v2_incoming_fragments *st_v2_incoming[MESSAGE_ROLE_ROOF];

	bool st_viable_parent;	/* can initiate new CERAET_CHILD_SA */
	struct ikev2_proposal *st_v2_accepted_proposal;
	struct ikev2_proposals *st_v2_create_child_sa_proposals;

	enum sa_role st_sa_role;			/* who initiated the SA */

	struct v2_msgid_windows st_v2_msgid_windows;	/* IKE */

	chunk_t st_firstpacket_me;              /* copy of my message 1 (for hashing) */
	chunk_t st_firstpacket_peer;             /* copy of peers message 1 (for hashing) */

	struct p_dns_req *ipseckey_dnsr;    /* ipseckey of that end */
	struct p_dns_req *ipseckey_fwd_dnsr;/* validate IDi that IP in forward A/AAAA */

	chunk_t st_active_redirect_gw;		/* needed for sending of REDIRECT in informational */

	/*
	 * IKEv2 intermediate exchange.
	 */

	struct {
		chunk_t initiator;	/* calculated from my last Intermediate Exchange packet */
		chunk_t responder;	/* calculated from peers last Intermediate Exchange packet */
		bool used;		/* both ends agree/use Intermediate Exchange */
		uint32_t id;		/* ID of last IKE_INTERMEDIATE exchange */
	} st_v2_ike_intermediate;

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
	 * When the state is deleted they get released.
	 *
	 * We suspect that they continue to lurk in NSS so that the
	 * CRL code can find them.  The first cert in the list is
	 * always the end or EE cert.
	 */
	struct {
		bool processed;		/* do this once, may not be any */
		bool harmless;		/* vs something nasty */
		bool groundhog;
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
	 * from DH_LOCAL and the keying material; and then
	 * authentication is performed.  However, should
	 * authentication fail, everything thing derived from that
	 * packet gets discarded and this includes the DH derived
	 * shared secret.  When the real packet arrives (or a
	 * re-transmit), the whole process is performed again, and
	 * using the same DH_LOCAL.
	 *
	 * Consequently, when the crypto helper gets created, it gets
	 * ownership of the DH_LOCAL, and then when it finishes,
	 * ownership is passed back to state.
	 *
	 * This all assumes that the crypto helper gets to delete
	 * DH_LOCAL iff state has already been deleted.
	 *
	 * (An alternative would be to reference count dh_local; or
	 * copy the underlying keying material using NSS, hmm, NSS).
	 */
	struct dh_local_secret *st_dh_local_secret;

	PK11SymKey *st_dh_shared_secret;	/* Derived shared secret
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
	 * may have further transitioned to STATE_V2_IKE_SA_DELETE etc.
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

	/*
	 * How much time to allow the replace attempt (i.e., re-key)
	 * before the SA must be killed and then re-started from
	 * scratch.
	 */
	deltatime_t st_replace_margin;

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
	struct job *st_offloaded_task;
	bool st_offloaded_task_in_background;

	struct msg_digest *st_suspended_md;  /* suspended state-transition */

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

	struct eap_state  *st_eap;	/* v2 EAP */
	struct msg_digest *st_eap_sa_md; /* v2 EAP initial message with SA request */

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
	PK11SymKey *st_enc_key_nss;	/* Oakley Encryption key */

	/* all the hash table entries */
	struct {
		struct list_entry list;
		struct list_entry clonedfrom;
		struct list_entry serialno;
		struct list_entry connection_serialno;
		struct list_entry reqid;
		struct list_entry ike_spis;
		struct list_entry ike_initiator_spi;
	} state_db_entries;

	struct pending *st_pending;

	struct hidden_variables hidden_variables;

	char st_xauth_username[MAX_XAUTH_USERNAME_LEN];	/* NUL-terminated */
	chunk_t st_xauth_password;

	/*
	 * Events for state object.  Some are shared between IKEv1 and
	 * IKEv2, some are not.
	 */

	struct state_event *st_event;			/* generic timer event for one-off events */

	struct state_event *st_retransmit_event;

	struct state_event *st_v1_send_xauth_event;

	struct state_event *st_v2_liveness_event;
	struct state_event *st_v2_addr_change_event;
	struct state_event *st_v2_refresh_event;	/* REKEY / REAUTH */
	struct state_event *st_v2_lifetime_event;	/* REPLACE / EXPIRE (not DISCARD) */

	/* RFC 3706 Dead Peer Detection */
	monotime_t st_last_dpd;			/* Time of last DPD transmit (0 means never?) */
	uint32_t st_dpd_seqno;                 /* Next R_U_THERE to send */
	uint32_t st_dpd_expectseqno;           /* Next R_U_THERE_ACK to receive */
	uint32_t st_dpd_peerseqno;             /* global variables */
	uint32_t st_dpd_rdupcount;		/* openbsd isakmpd bug workaround */
	struct state_event *st_v1_dpd_event;	/* backpointer for IKEv1 DPD events */

	struct isakmp_quirks quirks;            /* work arounds for faults in other products */
	bool st_xauth_soft;                     /* XAUTH failed but policy is to soft fail */
	bool st_seen_fragmentation_supported;	/* v1 frag vid; v2 frag notify */
	bool st_seen_hashnotify;		/* did we receive hash algo notification in IKE_INIT, then send in response as well */
	bool st_v1_seen_fragments;              /* did we receive ike fragments from peer, if so use them in return as well */
	bool st_seen_no_tfc;			/* did we receive ESP_TFC_PADDING_NOT_SUPPORTED */
	bool st_seen_redirect_sup;		/* did we receive IKEv2_REDIRECT_SUPPORTED */
	bool st_sent_redirect;			/* did we send IKEv2_REDIRECT in IKE_AUTH (response) */
	bool st_skip_revival_as_redirecting;	/* hack */
	generalName_t *st_v1_requested_ca;	/* collected certificate requests */
	uint8_t st_reply_xchg;
	bool st_peer_wants_null;		/* We received IDr payload of type ID_NULL (and we allow auth=NULL / authby=NULL */

	/* IKEv2 stores sec labels in the connection instance */
	chunk_t st_v1_seen_sec_label;
	chunk_t st_v1_acquired_sec_label;

	/* IKEv2 IKE SA only */
	bool st_ike_sent_v2n_mobike_supported;	/* sent MOBIKE_SUPPORTED notify */
	bool st_ike_seen_v2n_mobike_supported;	/* did we receive MOBIKE_SUPPORTED */
	bool st_ike_seen_v2n_initial_contact;	/* did we receive INITIAL_CONTACT */
	bool st_v2_childless_ikev2_supported;	/* childless exchange? */
	/* this a fuzzy bool */
	enum {
		SEEN_NO_v2CERTREQ = 0,
		SEEN_EMPTY_v2CERTREQ = 1,
		SEEN_FULL_v2CERTREQ = 2,
	} st_v2_ike_seen_certreq;

	/*
	 * Hobble what what happens when a state is being deleted.
	 *
	 * Long term, for IKEv2, most of these flags will be true by
	 * default (and IKEv1 will be deleted).
	 *
	 * Both the connection and state code think they are in
	 * control.  For instance, the connection code will delete the
	 * current state only to have the state code recursively
	 * delete that connection.
	 */

	struct {
		/*
		 * In delete_state(), as a last gasp, should a delete
		 * message to delete the SA be sent?
		 *
		 * For instance, when tearing down an SA, instead of
		 * sequencing a delete IKE/Child SA exchange,
		 * delete_state() will generate and send an
		 * out-of-band delete message.  This is known as
		 * record'n'send.  It should go away.
		 *
		 * False means use strange should_send_delete() logic.
		 */
		bool skip_send_delete;

		/*
		 * For the most part delete_state() will log a message
		 * announcing that the state is being deleted if a
		 * delete notify is/nt being sent.
		 *
		 * This suppresses the message.  Instead the caller
		 * (typically via record_n_send_v2_delete()) logs the
		 * message.
		 */
		bool skip_log_message;

	} st_on_delete;
#define on_delete_where(ST, S, WHERE)				\
	{							\
		struct state *s_ = (ST);			\
		pdbg(s_->logger,				\
		     ".st_on_delete."#S" %s->true "PRI_WHERE,	\
		     bool_str(s_->st_on_delete.S),		\
		     pri_where(WHERE));				\
		s_->st_on_delete.S = true;			\
	}
#define on_delete(ST, S)			\
	on_delete_where(ST, S, HERE)
};

void update_st_clonedfrom(struct state *st, so_serial_t clonedfrom);
void update_st_ike_spis(struct child_sa *child, const ike_spis_t *ike_spis);
void update_st_ike_spis_responder(struct ike_sa *ike, const ike_spi_t *ike_responder_spi);

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
 * pexpect_{ike,child}_sa() cast the SA (assuming it makes sense), or
 * NULL.
 */

struct ike_sa { struct state sa; };
struct ike_sa *ike_sa(struct state *st, where_t where); /* requires parent, IKEv[12], oops */
struct ike_sa *ike_sa_where(struct child_sa *child, where_t where); /* IKEv2, parent required */
struct ike_sa *isakmp_sa_where(struct child_sa *child, where_t where); /* IKEv1, parent optional */
struct ike_sa *parent_sa_where(struct child_sa *child, where_t where); /* both the above */
#define parent_sa(CHILD) parent_sa_where(CHILD, HERE)

struct ike_sa *pexpect_ike_sa_where(struct state *st, where_t where);
#define pexpect_ike_sa(ST) pexpect_ike_sa_where(ST, HERE)
#define pexpect_parent_sa(ST) pexpect_ike_sa_where(ST, HERE)

struct child_sa { struct state sa; };
struct child_sa *pexpect_child_sa_where(struct state *st, where_t where);
#define pexpect_child_sa(ST) pexpect_child_sa_where(ST, HERE)

/* global variables */

extern uint16_t pluto_nflog_group;	/* NFLOG group - 0 means no logging */
#ifdef XFRM_LIFETIME_DEFAULT
extern uint16_t pluto_xfrmlifetime;	/* only used to display in status */
#endif

extern bool states_use_connection(const struct connection *c);

/* state functions */

struct ike_sa *new_v1_istate(struct connection *c,
			     enum state_kind new_state_kind);

struct ike_sa *new_v1_rstate(struct connection *c, struct msg_digest *md);
struct child_sa *new_v1_child_sa(struct connection *c,
				 struct ike_sa *ike,
				 enum sa_role sa_role);

struct ike_sa *new_v2_ike_sa_initiator(struct connection *c);

struct ike_sa *new_v2_ike_sa_responder(struct connection *c,
				       const struct v2_state_transition *transition,
				       struct msg_digest *md);

/* could eventually be IKE or CHILD SA */
struct child_sa *new_v2_child_sa(struct connection *c,
				 struct ike_sa *ike,
				 enum sa_type sa_type, /*where is this going?*/
				 enum sa_role sa_role,
				 enum state_kind kind);

void set_v1_transition(struct state *st, const struct state_v1_microcode *transition, where_t where);
void set_v2_transition(struct state *st, const struct v2_state_transition *transition, where_t where);
void switch_md_st(struct msg_digest *md, struct state *st, where_t where);
void jam_v1_transition(struct jambuf *buf, const struct state_v1_microcode *transition);
void jam_v2_transition(struct jambuf *buf, const struct v2_state_transition *transition);

extern void init_states(void);

/*
 * The delete_{ike,child}_sa() variants only delete the <<struct
 * state>> and <<kernel state>>.  They do not send delete, do not
 * delete the connection, do not revive, do not pass go, and of course
 * do not collect $200.
 *
 * They are for connection code which just needs to blow away the
 * state.
 */

void delete_ike_sa(struct ike_sa **ike);
void delete_child_sa(struct child_sa **child);

void llog_sa_delete_n_send(struct ike_sa *ike, struct state *st);

extern void rekey_p2states_by_connection(struct connection *c);
void send_n_log_delete_ike_family_now(struct ike_sa **ike,
				      struct logger *logger,
				      where_t where);

struct state *state_by_serialno(so_serial_t serialno);
struct ike_sa *ike_sa_by_serialno(so_serial_t serialno);
struct child_sa *child_sa_by_serialno(so_serial_t serialno);

struct ike_sa *find_viable_parent_for_connection(const struct connection *c);
struct ike_sa *find_ike_sa_by_connection(const struct connection *c,
					 lset_t ok_states,
					 bool viable_parent);

struct state *find_state_ikev1(const ike_spis_t *ike_spis, msgid_t msgid);
struct state *find_state_ikev1_init(const ike_spi_t *ike_initiator_spi,
				    msgid_t msgid);

extern struct ike_sa *find_v2_ike_sa(const ike_spis_t *ike_spis,
				     enum sa_role local_ike_role);
extern struct ike_sa *find_v2_ike_sa_by_initiator_spi(const ike_spi_t *ike_initiator_spi,
						      enum sa_role local_ike_role);

struct child_sa *find_v2_child_sa_by_outbound_spi(struct ike_sa *ike,
						  uint8_t protoid,
						  ipsec_spi_t outbound_spi);

extern struct state *find_v1_info_state(const ike_spis_t *ike_spis,
					msgid_t msgid);

extern void show_brief_status(struct show *s);

extern ipsec_spi_t uniquify_peer_cpi(ipsec_spi_t cpi, const struct state *st, int tries);

extern void delete_cryptographic_continuation(struct state *st);

/*
 * Use this to change state, this gives us a handle on all state
 * changes which is good for tracking bugs, logging and anything else
 * you might like.
 */

extern void change_v1_state(struct state *st, enum state_kind new_state);
extern void change_v2_state(struct state *st);

extern bool state_is_busy(const struct state *st);
extern bool verbose_state_busy(const struct state *st);
extern bool drop_new_exchanges(void);
extern bool require_ddos_cookies(void);
extern void show_globalstate_status(struct show *s);
extern void update_ike_endpoints(struct ike_sa *ike, const struct msg_digest *md);

extern void append_st_cfg_domain(struct state *st, char *dnsip);
extern void append_st_cfg_dns(struct state *st, const char *dnsip);

extern bool uniqueIDs;  /* --uniqueids? */

void list_state_events(struct show *s, const monotime_t now);
struct child_sa *find_v2_child_sa_by_spi(ipsec_spi_t spi, int8_t protoid,
					 ip_address dst);

void connswitch_state_and_log(struct state *st, struct connection *c);

void DBG_tcpdump_ike_sa_keys(const struct state *st);

/*
 * For iterating over the state DB.
 *
 * - parameters are only matched when non-NULL or non-zero
 * - .st can be deleted between calls
 * - some filters have been optimized using hashing, but
 * - worst case is it scans through all states
 *
 * Note: the ORDER is based on insertion; so when an entry gets
 * re-hashed (i.e., deleted and then inserted) it also becomes the
 * newest entry.
 */

struct state_filter {
	/* filters */
	enum ike_version ike_version;
	const ike_spis_t *ike_spis;	/* hashed */
	so_serial_t clonedfrom;
	co_serial_t connection_serialno;
	/* current result (can be safely deleted) */
	struct state *st;
	/* internal: handle on next entry */
	struct list_entry *internal;
	/* internal: total matches so far */
	unsigned count;
	/* .where MUST BE LAST (See GCC bug 102288) */
	where_t where;
};

bool next_state(enum chrono advance, struct state_filter *query);

extern void set_sa_expire_next_event(enum sa_expire_kind expire, struct child_sa *child);

void jam_humber_uintmax(struct jambuf *buf,
			const char *prefix, uintmax_t val, const char *suffix);

/* IKE SA | ISAKMP SA || Child SA | IPsec SA */
const char *state_sa_name(const struct state *st);
/* IKE | ISAKMP || Child | IPsec */
const char *state_sa_short_name(const struct state *st);

void wipe_old_connections(const struct ike_sa *ike);

#endif /* STATE_H */
