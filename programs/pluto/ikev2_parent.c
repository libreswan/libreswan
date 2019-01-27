/*
 * IKEv2 parent SA creation routines, for Libreswan
 *
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi
 * Copyright (C) 2012-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2018 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013-2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015-2018 Andrew Cagney
 * Copyright (C) 2017-2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2017-2018 Vukasin Karadzic <vukasin.karadzic@gmail.com>
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
 *
 */

#include <unistd.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "state.h"
#include "keys.h" /* needs state.h */
#include "id.h"
#include "connections.h"

#include "crypto.h"
#include "x509.h"
#include "pluto_x509.h"
#include "ike_alg.h"
#include "ike_alg_hash.h"
#include "ike_alg_dh.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "pluto_crypt.h"
#include "packet.h"
#include "demux.h"
#include "ikev2.h"
#include "log.h"
#include "spdb.h"	/* for out_sa */
#include "ipsec_doi.h"
#include "vendor.h"
#include "timer.h"
#include "ike_spi.h"
#include "rnd.h"
#include "pending.h"
#include "kernel.h"
#include "nat_traversal.h"
#include "alg_info.h" /* for ike_info / esp_info */
#include "keyhi.h" /* for SECKEY_DestroyPublicKey */
#include "vendor.h"
#include "crypt_hash.h"
#include "ikev2_ipseckey.h"
#include "ikev2_ppk.h"
#include "ikev2_redirect.h"
#include "xauth.h"
#include "crypt_dh.h"
#include "ietf_constants.h"
#include "ip_address.h"
#include "hostpair.h"
#include "send.h"
#include "ikev2_send.h"
#include "pluto_stats.h"
#include "retry.h"
#include "ipsecconf/confread.h"		/* for struct starter_end */
#include "addr_lookup.h"
#include "impair.h"
#include "ikev2_message.h"
#include "ikev2_ts.h"

#include "crypt_symkey.h" /* for release_symkey */
struct mobike {
	ip_address remoteaddr;
	uint16_t remoteport;
	const struct iface_port *interface;
};

static stf_status ikev2_parent_inI2outR2_auth_tail(struct state *st,
						   struct msg_digest *md,
						   bool pam_status);

static stf_status ikev2_parent_outI1_common(struct msg_digest *md,
					    struct state *st);

static stf_status ikev2_start_new_exchange(struct state *st);

static stf_status ikev2_child_out_tail(struct msg_digest *md);

static bool asn1_hash_in(const struct asn1_hash_blob *asn1_hash_blob, pb_stream *a_pbs,
		   uint8_t size, uint8_t asn1_blob_len);

static bool negotiate_hash_algo_from_notification(struct payload_digest *p, struct state *st)
{
	lset_t sighash_policy = st->st_connection->sighash_policy;

	while (pbs_left(&p->pbs) > 0) {

		uint16_t nh_value;
		passert(sizeof(nh_value) == RFC_7427_HASH_ALGORITHM_IDENTIFIER_SIZE);
		if (!in_raw(&nh_value, sizeof(nh_value), &p->pbs,
			    "hash algorithm identifier (network ordered)"))
			return false;
		uint16_t h_value = ntohs(nh_value);

		switch (h_value)  {
		/* We no longer support SHA1 (as per RFC8247) */
		case IKEv2_AUTH_HASH_SHA2_256:
			if (sighash_policy & POL_SIGHASH_SHA2_256) {
				st->st_hash_negotiated |= NEGOTIATE_AUTH_HASH_SHA2_256;
			}
			break;
		case IKEv2_AUTH_HASH_SHA2_384:
			if (sighash_policy & POL_SIGHASH_SHA2_384) {
				st->st_hash_negotiated |= NEGOTIATE_AUTH_HASH_SHA2_384;
			}
			break;
		case IKEv2_AUTH_HASH_SHA2_512:
			if (sighash_policy & POL_SIGHASH_SHA2_512) {
				st->st_hash_negotiated |= NEGOTIATE_AUTH_HASH_SHA2_512;
			}
			break;
		case IKEv2_AUTH_HASH_IDENTITY:
			st->st_hash_negotiated |= NEGOTIATE_AUTH_HASH_IDENTITY;
			break;
		default:
			libreswan_log("Received and ignored hash algorithm %d", h_value);
		}

	}
	return true;
}

static const struct asn1_hash_blob *blob_for_hash_algo(enum notify_payload_hash_algorithms hash_algo,
			enum keyword_authby authby)
{
	switch(authby) {
	case AUTH_RSASIG:
		switch (hash_algo) {
		case IKEv2_AUTH_HASH_SHA2_256:
			return  &asn1_rsa_pss_sha2_256;
		case IKEv2_AUTH_HASH_SHA2_384:
			return &asn1_rsa_pss_sha2_384;
		case IKEv2_AUTH_HASH_SHA2_512:
			return &asn1_rsa_pss_sha2_512;
		default:
			return NULL;
		}
		break;
	case AUTH_ECDSA:
		switch (hash_algo) {
		case IKEv2_AUTH_HASH_SHA2_256:
			return  &asn1_ecdsa_sha2_256;
		case IKEv2_AUTH_HASH_SHA2_384:
			return &asn1_ecdsa_sha2_384;
		case IKEv2_AUTH_HASH_SHA2_512:
			return &asn1_ecdsa_sha2_512;
		default:
			return NULL;
		}
		break;
	default:
		libreswan_log("Unknown or unsupported authby method for DigSig");
		return NULL;
	}
}

static stf_status ikev2_send_asn1_hash_blob(enum notify_payload_hash_algorithms hash_algo,
		pb_stream *a_pbs, enum keyword_authby authby)
{
	const struct asn1_hash_blob *b = blob_for_hash_algo(hash_algo, authby);

	passert(b != NULL);

	if (!out_raw(b->size_blob, b->size, a_pbs,
	    "Length of the ASN.1 Algorithm Identifier")) {
		loglog(RC_LOG_SERIOUS, "DigSig: failed to emit ASN.1 Algorithm Identifier length");
		return STF_INTERNAL_ERROR;
	}

	if (!out_raw(b->asn1_blob, b->asn1_blob_len, a_pbs,
	    "OID of ASN.1 Algorithm Identifier")) {
		loglog(RC_LOG_SERIOUS, "DigSig: failed to emit OID of ASN.1 Algorithm Identifier");
		return STF_INTERNAL_ERROR;
	}

	return STF_OK;
}

static stf_status ikev2_check_asn1_hash_blob(enum notify_payload_hash_algorithms hash_algo, pb_stream *a_pbs,
	enum keyword_authby authby)
{
	const struct asn1_hash_blob *b = blob_for_hash_algo(hash_algo, authby);

	if (b == NULL) {
		/* TODO display both enum names */
		loglog(RC_LOG_SERIOUS, "Non-negotiable Hash algorithm %d received", hash_algo);
		return STF_FAIL;
	}

	/*
	 * ???
	 * b->size == ASN1_LEN_ALGO_IDENTIFIER; b->asn1_blob_len == ASN1_SHA2_RSA_PSS_SIZE
	 * Why pass these separately to asn1_hash_in?
	 * If these are universal, they could be wired into asn1_hash_in thus avoiding
	 * an array bound that isn't a compile-time constant.
	 * This is the only call to asn1_hash_in: why not inline it?
	 */
	if (!asn1_hash_in(b, a_pbs, ASN1_LEN_ALGO_IDENTIFIER,
		authby == AUTH_RSASIG ? ASN1_SHA2_RSA_PSS_SIZE :
			ASN1_SHA2_ECDSA_SIZE))
		{
			return STF_FAIL;
		}
	return STF_OK;
}

static bool asn1_hash_in(const struct asn1_hash_blob *asn1_hash_blob, pb_stream *a_pbs,
		   uint8_t size, uint8_t asn1_blob_len)
{
	/* ??? dynamic array bounds are deprecated */
	uint8_t check_size[size];
	/* ??? dynamic array bounds are deprecated */
	uint8_t check_blob[asn1_blob_len];

	if (!in_raw(check_size, size, a_pbs,
	    "Algorithm Identifier length"))
		return FALSE;
	/*
	 * ??? The following seems to assume asn1_hash_blob->size == size
	 * This is true, but not self-evident.
	 */
	if (!memeq(check_size, asn1_hash_blob->size_blob, asn1_hash_blob->size)) {
		loglog(RC_LOG_SERIOUS, " Received incorrect size of ASN.1 Algorithm Identifier");
		return FALSE;
	}

	if (!in_raw(check_blob, asn1_blob_len, a_pbs,
	    "Algorithm Identifier value"))
		return FALSE;
	/*
	 * ??? The following seems to assume asn1_hash_blob->asn1_blob_len == asn1_blob_len
	 * This is true, but not self-evident.
	 */
	if (!memeq(check_blob, asn1_hash_blob->asn1_blob, asn1_hash_blob->asn1_blob_len)) {
		loglog(RC_LOG_SERIOUS, " Received incorrect bytes of ASN.1 Algorithm Identifier");
		return FALSE;
	}

	return TRUE;
}

void ikev2_ike_sa_established(struct ike_sa *ike,
			      const struct state_v2_microcode *svm,
			      enum state_kind new_state)
{
	struct connection *c = ike->sa.st_connection;
	/*
	 * Taking it (what???) current from current state I2/R1.
	 * The parent has advanced but not the svm???
	 * Ideally this should be timeout of I3/R2 state svm.
	 * How to find that svm???
	 * I wonder what this comment means?  Needs rewording.
	 *
	 * XXX: .timeout_event is tied to a state transition.  Does
	 * that mean it applies to the transition or to the final
	 * state?  It is kind of treated as all three (the third case
	 * is where a transition gets shared between the parent and
	 * child).
	 */
	pexpect(svm->timeout_event == EVENT_SA_REPLACE);

	/*
	 * update the parent state to make sure that it knows we have
	 * authenticated properly.
	 */
	change_state(&ike->sa, new_state);
	c->newest_isakmp_sa = ike->sa.st_serialno;
	v2_schedule_replace_event(&ike->sa);
	ike->sa.st_viable_parent = TRUE;
}

static stf_status add_st_to_ike_sa_send_list(struct state *st, struct ike_sa *ike)
{
	msgid_t unack = ike->sa.st_msgid_nextuse - ike->sa.st_msgid_lastack - 1;
	stf_status e = STF_OK;
	const char *what;

	if (unack < st->st_connection->ike_window) {
		what  =  "send new exchange now";
	} else  {
		e = STF_SUSPEND;
		what = "wait sending, add to send next list";
		delete_event(st);
		event_schedule_s(EVENT_SA_REPLACE, MAXIMUM_RESPONDER_WAIT, st);
		loglog(RC_LOG_SERIOUS, "message id deadlock? %s using parent #%lu unacknowledged %u next message id=%u ike exchange window %u",
			what, ike->sa.st_serialno, unack,
			ike->sa.st_msgid_nextuse,
			ike->sa.st_connection->ike_window);

		struct initiate_list **pp = &ike->sa.send_next_ix;
		while (*pp != NULL)
			pp = &(*pp)->next;
		*pp = alloc_thing(struct initiate_list, "struct initiate_list");
		**pp = (struct initiate_list) {
			.st_serialno = st->st_serialno,
			.next = NULL };

	}
	DBG(DBG_CONTROLMORE,
		DBG_log("#%lu %s using parent #%lu unacknowledged %u next message id=%u ike exchange window %u",
			st->st_serialno,
			what, ike->sa.st_serialno, unack,
			ike->sa.st_msgid_nextuse,
			ike->sa.st_connection->ike_window));
	return e;
}

static struct msg_digest *fake_md(struct state *st)
{
	struct msg_digest *fake_md = alloc_md("fake IKEv2 msg_digest");
	fake_md->st = st;
	fake_md->from_state = st->st_finite_state->fs_kind;
	fake_md->hdr.isa_msgid = v2_INVALID_MSGID;
	/* asume first microcode is valid */
	fake_md->svm = st->st_finite_state->fs_v2_transitions;
	return fake_md;
}

/*
 * Check that the bundled keying material (KE) matches the accepted
 * proposal and if it doesn't send out a notification returning true.
 */
static bool v2_reject_wrong_ke_for_proposal(struct state *st,
					    struct msg_digest *md,
					    const struct oakley_group_desc *accepted_dh)
{
	passert(md->chain[ISAKMP_NEXT_v2KE] != NULL);
	int ke_group = md->chain[ISAKMP_NEXT_v2KE]->payload.v2ke.isak_group;
	if (accepted_dh->common.id[IKEv2_ALG_ID] != ke_group) {
		struct esb_buf ke_esb;
		libreswan_log("initiator guessed wrong keying material group (%s); responding with INVALID_KE_PAYLOAD requesting %s",
			      enum_show_shortb(&oakley_group_names,
					       ke_group, &ke_esb),
			      accepted_dh->common.name);
		pstats(invalidke_sent_u, ke_group);
		pstats(invalidke_sent_s, accepted_dh->common.id[IKEv2_ALG_ID]);
		/* convert group to a raw buffer */
		uint16_t gr = htons(accepted_dh->group);
		chunk_t nd = CHUNKO(gr);
		if (st != NULL) {
			send_v2N_response_from_state(ike_sa(st), md,
						     v2N_INVALID_KE_PAYLOAD, &nd);
		} else {
			send_v2N_response_from_md(md, v2N_INVALID_KE_PAYLOAD, &nd);
		}
		return true;
	} else {
		return false;
	}
}

/*
 * Called by ikev2_parent_inI2outR2_tail() and ikev2_parent_inR2()
 * Do the actual AUTH payload verification
 */
static bool v2_check_auth(enum ikev2_auth_method recv_auth,
	struct state *st,
	const enum original_role role,
	unsigned char idhash_in[MAX_DIGEST_LEN],
	pb_stream *pbs,
	const enum keyword_authby that_authby)
{
	switch (recv_auth) {
	case IKEv2_AUTH_RSA:
	{
		if (that_authby != AUTH_RSASIG) {
			libreswan_log("Peer attempted RSA authentication but we want %s",
				enum_name(&ikev2_asym_auth_name, that_authby));
			return FALSE;
		}

		stf_status authstat = ikev2_verify_rsa_hash(
				st,
				role,
				idhash_in,
				pbs,
				IKEv2_AUTH_HASH_SHA1);

		if (authstat != STF_OK) {
			libreswan_log("RSA authentication failed");
			return FALSE;
		}
		return TRUE;
	}

	case IKEv2_AUTH_PSK:
	{
		if (that_authby != AUTH_PSK) {
			libreswan_log("Peer attempted PSK authentication but we want %s",
				enum_name(&ikev2_asym_auth_name, that_authby));
			return FALSE;
		}

		stf_status authstat = ikev2_verify_psk_auth(
			AUTH_PSK, st, idhash_in, pbs);

		if (authstat != STF_OK) {
			libreswan_log("PSK Authentication failed: AUTH mismatch!");
			return FALSE;
		}
		return TRUE;
	}

	case IKEv2_AUTH_NULL:
	{
		if (!(that_authby == AUTH_NULL ||
		      (that_authby == AUTH_RSASIG && LIN(POLICY_AUTH_NULL, st->st_connection->policy)))) {
			libreswan_log("Peer attempted NULL authentication but we want %s",
				enum_name(&ikev2_asym_auth_name, that_authby));
			return FALSE;
		}

		stf_status authstat = ikev2_verify_psk_auth(
				AUTH_NULL, st, idhash_in,
				pbs);

		if (authstat != STF_OK) {
			libreswan_log("NULL Authentication failed: AUTH mismatch! (implementation bug?)");
			return FALSE;
		}
		st->st_ikev2_anon = TRUE;
		return TRUE;
	}

	case IKEv2_AUTH_DIGSIG:
	{
		enum notify_payload_hash_algorithms hash_algo;
		bool hash_check = FALSE;
		stf_status authstat;

		if (that_authby != AUTH_ECDSA && that_authby != AUTH_RSASIG) {
			libreswan_log("Peer attempted Authentication through Digital Signature but we want %s",
				enum_name(&ikev2_asym_auth_name, that_authby));
			return FALSE;
		}

		if (st->st_hash_negotiated & NEGOTIATE_AUTH_HASH_SHA2_512) {
			hash_algo = IKEv2_AUTH_HASH_SHA2_512;
		} else if (st->st_hash_negotiated & NEGOTIATE_AUTH_HASH_SHA2_384) {
			hash_check = TRUE;
			hash_algo = IKEv2_AUTH_HASH_SHA2_384;
		} else if (st->st_hash_negotiated & NEGOTIATE_AUTH_HASH_SHA2_256) {
			hash_check = TRUE;
			hash_algo = IKEv2_AUTH_HASH_SHA2_256;
		} else {
			libreswan_log(" Digsig: No valid hash algorithm is negotiated between peers");
			return FALSE;
		}

		stf_status checkstat = ikev2_check_asn1_hash_blob(hash_algo, pbs, that_authby);

		if ((checkstat != STF_OK) && (st->st_hash_negotiated & NEGOTIATE_AUTH_HASH_SHA2_384) &&
					!hash_check) {
			hash_algo = IKEv2_AUTH_HASH_SHA2_384;
			checkstat = ikev2_check_asn1_hash_blob(hash_algo, pbs, that_authby);
		}

		if ((checkstat != STF_OK) && (st->st_hash_negotiated & NEGOTIATE_AUTH_HASH_SHA2_256) &&
					(!hash_check)) {
			hash_algo = IKEv2_AUTH_HASH_SHA2_256;
			checkstat = ikev2_check_asn1_hash_blob(hash_algo, pbs, that_authby);
		}

		if (checkstat != STF_OK ) {
			return FALSE;
		}

		switch (that_authby) {
		case AUTH_RSASIG:
		{
			authstat = ikev2_verify_rsa_hash(st, role, idhash_in, pbs, hash_algo);
			break;
		}

		case AUTH_ECDSA:
		{
			authstat = ikev2_verify_ecdsa_hash(st, role, idhash_in, pbs, hash_algo);
			break;
		}

		default:
			bad_case(that_authby);
			break;
		}

		if (authstat != STF_OK) {
			libreswan_log("Digital Signature authentication using %s failed",
				enum_name(&ikev2_asym_auth_name, that_authby));
			return FALSE;
		}
		return TRUE;
	}

	default:
	{
		libreswan_log("authentication method: %s not supported",
				enum_name(&ikev2_auth_names, recv_auth));
		return FALSE;
	}

	}
}

static bool id_ipseckey_allowed(struct state *st, enum ikev2_auth_method atype)
{
	const struct connection *c = st->st_connection;
	struct id id = st->st_connection->spd.that.id;


	if (!c->spd.that.key_from_DNS_on_demand)
		return FALSE;

	if (c->spd.that.authby == AUTH_RSASIG &&
	    (id.kind == ID_FQDN || id_is_ipaddr(&id)))
{
		switch (atype) {
		case IKEv2_AUTH_RESERVED:
		case IKEv2_AUTH_DIGSIG:
		case IKEv2_AUTH_RSA:
			return TRUE; /* success */
		default:
			break;	/*  failure */
		}
	}

	DBG(DBG_CONTROLMORE, {
		const char *err1 = "%dnsondemand";
		const char *err2 = "";

		if (atype != IKEv2_AUTH_RESERVED && !(atype == IKEv2_AUTH_RSA ||
							atype == IKEv2_AUTH_DIGSIG)) {
			err1 = " initiator IKEv2 Auth Method mismatched ";
			err2 = enum_name(&ikev2_auth_names, atype);
		}

		if (id.kind != ID_FQDN &&
				id.kind != ID_IPV4_ADDR &&
				id.kind != ID_IPV6_ADDR) {
			err1 = " mismatched ID type, that ID is not a FQDN, IPV4_ADDR, or IPV6_ADDR id type=";
			err2 = enum_show(&ike_idtype_names, id.kind);
		}

		char thatid[IDTOA_BUF];
		ipstr_buf ra;
		idtoa(&id, thatid, sizeof(thatid));
		DBG_log("%s #%lu not fetching ipseckey %s%s remote=%s thatid=%s",
			c->name, st->st_serialno,
			err1, err2, ipstr(&st->st_remoteaddr, &ra), thatid);
	});
	return FALSE;
}

/*
 *
 ***************************************************************
 *****                   PARENT_OUTI1                      *****
 ***************************************************************
 *
 *
 * Initiate an Oakley Main Mode exchange.
 *       HDR, SAi1, KEi, Ni   -->
 *
 * Note: this is not called from demux.c, but from ipsecdoi_initiate().
 *
 */
static crypto_req_cont_func ikev2_parent_outI1_continue;

/* extern initiator_function ikev2_parent_outI1; */	/* type assertion */

void ikev2_parent_outI1(fd_t whack_sock,
		       struct connection *c,
		       struct state *predecessor,
		       lset_t policy,
		       unsigned long try
#ifdef HAVE_LABELED_IPSEC
		       , struct xfrm_user_sec_ctx_ike *uctx
#endif
		       )
{
	struct state *st;

	if (drop_new_exchanges()) {
		/* Only drop outgoing opportunistic connections */
		if (c->policy & POLICY_OPPORTUNISTIC) {
			close_any(&whack_sock);
			return;
		}
	}

	st = new_v2_state(STATE_PARENT_I0, SA_INITIATOR,
			  ike_initiator_spi(), zero_ike_spi);

	/* set up new state */
	initialize_new_state(st, c, policy, try, whack_sock);
	passert(st->st_ike_version == IKEv2);
	passert(st->st_state_kind == STATE_PARENT_I0);
	st->st_original_role = ORIGINAL_INITIATOR;
	passert(st->st_sa_role == SA_INITIATOR);
	passert(st->st_msgid_lastack == v2_INVALID_MSGID);
	passert(st->st_msgid_lastrecv == v2_INVALID_MSGID);
	passert(st->st_msgid_nextuse == 0);
	st->st_try = try;

	if (HAS_IPSEC_POLICY(policy)) {
#ifdef HAVE_LABELED_IPSEC
		st->sec_ctx = NULL;
		if (uctx != NULL)
			libreswan_log(
				"Labeled ipsec is not supported with ikev2 yet");
#endif
		add_pending(dup_any(whack_sock), st, c, policy, 1,
			    predecessor == NULL ? SOS_NOBODY : predecessor->st_serialno
#ifdef HAVE_LABELED_IPSEC
			    , st->sec_ctx
#endif
			    );
	}

	if (predecessor != NULL) {
		if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			libreswan_log("initiating v2 parent SA to replace #%lu",
				predecessor->st_serialno);
		}
		if (IS_V2_ESTABLISHED(predecessor->st_state)) {
			if (IS_CHILD_SA(st))
				st->st_ipsec_pred = predecessor->st_serialno;
			else
				st->st_ike_pred = predecessor->st_serialno;
		}
		update_pending(predecessor, st);
		whack_log(RC_NEW_STATE + STATE_PARENT_I1,
			  "%s: initiate, replacing #%lu",
			  st->st_state_name,
			  predecessor->st_serialno);
	} else {
		if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			libreswan_log("initiating v2 parent SA");
		}
		whack_log(RC_NEW_STATE + STATE_PARENT_I1, "initiate");
	}

	if (IS_LIBUNBOUND && id_ipseckey_allowed(st, IKEv2_AUTH_RESERVED)) {
		stf_status ret = idr_ipseckey_fetch(st);
		if (ret != STF_OK) {
			reset_globals();
			return;
		}
	}

	/*
	 * Initialize st->st_oakley, including the group number.
	 * Grab the DH group from the first configured proposal and build KE.
	 */
	struct ikev2_proposals *ike_proposals =
		get_v2_ike_proposals(c, "IKE SA initiator selecting KE");
	st->st_oakley.ta_dh = ikev2_proposals_first_dh(ike_proposals);
	if (st->st_oakley.ta_dh == NULL) {
		libreswan_log("proposals do not contain a valid DH");
		delete_state(st); /* pops state? */
		return;
	}

	/*
	 * Calculate KE and Nonce.
	 */
	request_ke_and_nonce("ikev2_outI1 KE", st,
			     st->st_oakley.ta_dh,
			     ikev2_parent_outI1_continue);
	reset_globals();
}

/*
 * package up the calculated KE value, and emit it as a KE payload.
 * used by IKEv2: parent, child (PFS)
 */
bool emit_v2KE(chunk_t *g, const struct oakley_group_desc *group,
	       pb_stream *outs)
{
	if (impair_ke_payload == SEND_OMIT) {
		libreswan_log("IMPAIR: omitting KE payload");
		return true;
	}

	pb_stream kepbs;

	struct ikev2_ke v2ke = {
		.isak_group = group->common.id[IKEv2_ALG_ID],
	};

	if (!out_struct(&v2ke, &ikev2_ke_desc, outs, &kepbs))
		return FALSE;

	if (impair_ke_payload >= SEND_ROOF) {
		uint8_t byte = impair_ke_payload - SEND_ROOF;
		libreswan_log("IMPAIR: sending bogus KE (g^x) == %u value to break DH calculations",
			      byte);
		/* Only used to test sending/receiving bogus g^x */
		if (!out_repeated_byte(byte, g->len, &kepbs, "ikev2 impair KE (g^x) == 0"))
			return FALSE;
	} else if (impair_ke_payload == SEND_EMPTY) {
		libreswan_log("IMPAIR: sending an empty KE value");
		if (!out_zero(0, &kepbs, "ikev2 impair KE (g^x) == empty"))
			return FALSE;
	} else {
		if (!out_chunk(*g, &kepbs, "ikev2 g^x"))
			return FALSE;
	}

	close_output_pbs(&kepbs);
	return TRUE;
}

void ikev2_parent_outI1_continue(struct state *st, struct msg_digest **mdp,
				 struct pluto_crypto_req *r)
{
	DBG(DBG_CONTROL,
		DBG_log("ikev2_parent_outI1_continue for #%lu",
			st->st_serialno));

	unpack_KE_from_helper(st, r, &st->st_gi);
	unpack_nonce(&st->st_ni, r);
	/* needed by complete state transition */
	if (*mdp == NULL) {
		*mdp = fake_md(st);
	}
	stf_status e = ikev2_parent_outI1_common(*mdp, st);
	/* replace (*mdp)->st with st ... */
	complete_v2_state_transition((*mdp)->st, mdp, e);
}

static stf_status ikev2_parent_outI1_common(struct msg_digest *md UNUSED,
					    struct state *st)
{
	struct connection *c = st->st_connection;

	/* set up reply */
	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	if (IMPAIR(SEND_BOGUS_DCOOKIE)) {
		/* add or mangle a dcookie so what we will send is bogus */
		DBG_log("Mangling dcookie because --impair-send-bogus-dcookie is set");
		freeanychunk(st->st_dcookie);
		st->st_dcookie.ptr = alloc_bytes(1, "mangled dcookie");
		st->st_dcookie.len = 1;
		messupn(st->st_dcookie.ptr, 1);
	}

	/* HDR out */

	pb_stream rbody = open_v2_message(&reply_stream, ike_sa(st),
					  NULL /* request */,
					  ISAKMP_v2_IKE_SA_INIT);
	if (!pbs_ok(&rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/*
	 * https://tools.ietf.org/html/rfc5996#section-2.6
	 * reply with the anti DDOS cookie if we received one (remote is under attack)
	 */
	if (st->st_dcookie.ptr != NULL) {
		/* In v2, for parent, protoid must be 0 and SPI must be empty */
		if (!emit_v2Nchunk(v2N_COOKIE, &st->st_dcookie, &rbody)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* SA out */

	struct ikev2_proposals *ike_proposals =
		get_v2_ike_proposals(c, "IKE SA initiator emitting local proposals");
	if (!ikev2_emit_sa_proposals(&rbody, ike_proposals,
				     (chunk_t*)NULL /* IKE - no CHILD SPI */)) {
		return STF_INTERNAL_ERROR;
	}

	/* ??? from here on, this looks a lot like the end of ikev2_parent_inI1outR1_tail */

	/* send KE */
	if (!emit_v2KE(&st->st_gi, st->st_oakley.ta_dh, &rbody))
		return STF_INTERNAL_ERROR;

	/* send NONCE */
	{
		pb_stream pb;
		struct ikev2_generic in = {
			.isag_np = ISAKMP_NEXT_v2N,
			.isag_critical = build_ikev2_critical(false),
		};

		if (!out_struct(&in, &ikev2_nonce_desc, &rbody, &pb) ||
		    !out_chunk(st->st_ni, &pb, "IKEv2 nonce"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&pb);
	}

	/* Send fragmentation support notification */
	if (c->policy & POLICY_IKE_FRAG_ALLOW) {
		if (!emit_v2N(v2N_IKEV2_FRAGMENTATION_SUPPORTED, &rbody))
			return STF_INTERNAL_ERROR;
	}

	/* Send USE_PPK Notify payload */
	if (LIN(POLICY_PPK_ALLOW, c->policy)) {
		if (!emit_v2N(v2N_USE_PPK, &rbody))
			return STF_INTERNAL_ERROR;
	}

	/* first check if this IKE_SA_INIT came from redirect
	 * instruction.
	 * - if yes, send the v2N_REDIRECTED_FROM
	 *   with the identity of previous gateway
	 * - if not, check if we support redirect mechanism
	 *   and send v2N_REDIRECT_SUPPORTED if we do
	 */
	if (!isanyaddr(&c->temp_vars.redirect_ip)) {
		if (!emit_redirect_notification_decoded_dest(v2N_REDIRECTED_FROM,
				&c->temp_vars.old_gw_address, NULL, NULL, &rbody))
			return STF_INTERNAL_ERROR;
	} else if (LIN(POLICY_ACCEPT_REDIRECT_YES, c->policy)) {
		if (!emit_v2N(v2N_REDIRECT_SUPPORTED, &rbody))
			return STF_INTERNAL_ERROR;
	}

	/* Send SIGNATURE_HASH_ALGORITHMS Notify payload */
	if (!IMPAIR(OMIT_HASH_NOTIFY_REQUEST)) {
		if (((c->policy & POLICY_RSASIG) || (c->policy & POLICY_ECDSA))
			&& (c->sighash_policy != POL_SIGHASH_NONE)) {
			if (!emit_v2N_signature_hash_algorithms(c->sighash_policy, &rbody))
				return STF_INTERNAL_ERROR;
		}
	} else {
		libreswan_log("Impair: Skipping the Signature hash notify in IKE_SA_INIT Request");
	}

	/* Send NAT-T Notify payloads */
	if (!ikev2_out_nat_v2n(&rbody, st, &zero_ike_spi/*responder unknown*/))
		return STF_INTERNAL_ERROR;

	/* something the other end won't like */

	if (IMPAIR(ADD_UNKNOWN_PAYLOAD_TO_SA_INIT)) {
		if (!emit_v2UNKNOWN("IKE_SA_INIT request", &rbody)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* From here on, only payloads left are Vendor IDs */
	if (c->send_vendorid) {
		if (!emit_v2V(pluto_vendorid, &rbody))
			return STF_INTERNAL_ERROR;
	}

	if (c->fake_strongswan) {
		if (!emit_v2V("strongSwan", &rbody))
			return STF_INTERNAL_ERROR;
	}

	if (c->policy & POLICY_AUTH_NULL) {
		if (!emit_v2V("Opportunistic IPsec", &rbody))
			return STF_INTERNAL_ERROR;
	}

	close_output_pbs(&rbody);
	close_output_pbs(&reply_stream);

	/* save packet for later signing */
	freeanychunk(st->st_firstpacket_me);
	st->st_firstpacket_me = clone_out_pbs_as_chunk(&reply_stream,
						       "saved first packet");

	/* Transmit */
	record_outbound_ike_msg(st, &reply_stream, "reply packet for ikev2_parent_outI1_common");

	reset_cur_state();
	return STF_OK;
}

/*
 *
 ***************************************************************
 *                       PARENT_INI1                       *****
 ***************************************************************
 *  -
 *
 *
 */

/* no state: none I1 --> R1
 *                <-- HDR, SAi1, KEi, Ni
 * HDR, SAr1, KEr, Nr, [CERTREQ] -->
 */

static crypto_req_cont_func ikev2_parent_inI1outR1_continue;	/* forward decl and type assertion */
static crypto_transition_fn ikev2_parent_inI1outR1_continue_tail;	/* forward decl and type assertion */

stf_status ikev2_parent_inI1outR1(struct state *null_st, struct msg_digest *md)
{
	passert(null_st == NULL);	/* initial responder -> no state */

	/* authentication policy alternatives in order of decreasing preference */
	static const lset_t policies[] = { POLICY_ECDSA, POLICY_RSASIG, POLICY_PSK, POLICY_AUTH_NULL };

	lset_t policy;
	struct connection *c;
	stf_status e;
	unsigned int i;

	/* XXX in the near future, this loop should find type=passthrough and return STF_DROP */
	for (i=0; i < elemsof(policies); i++) {
		policy = policies[i] | POLICY_IKEV2_ALLOW;
		e = ikev2_find_host_connection(&c, &md->iface->ip_addr,
				md->iface->port, &md->sender, hportof(&md->sender),
				policy);
		if (e == STF_OK)
			break;
	}

	if (e != STF_OK) {
		ipstr_buf b;

		/* we might want to change this to a debug log message only */
		loglog(RC_LOG_SERIOUS, "initial parent SA message received on %s:%u but no suitable connection found with IKEv2 policy",
			ipstr(&md->iface->ip_addr, &b),
			ntohs(portof(&md->iface->ip_addr)));
		return e;
	}

	passert(c != NULL);	/* (e != STF_OK) == (c == NULL) */

	DBG(DBG_CONTROL, {
		char ci[CONN_INST_BUF];
		DBG_log("found connection: %s%s with policy %s",
			c->name, fmt_conn_instance(c, ci),
			bitnamesof(sa_policy_bit_names, policy));});

	/*
	 * Did we overlook a type=passthrough foodgroup?
	 */
	{
		struct connection *tmp = find_host_pair_connections(
			&md->iface->ip_addr, md->iface->port,
			(ip_address *)NULL, hportof(&md->sender));

		for (; tmp != NULL; tmp = tmp->hp_next) {
			if ((tmp->policy & POLICY_SHUNT_MASK) != POLICY_SHUNT_TRAP &&
			    tmp->kind == CK_INSTANCE &&
			    addrinsubnet(&md->sender, &tmp->spd.that.client))
			{
				DBG(DBG_OPPO, DBG_log("passthrough conn %s also matches - check which has longer prefix match", tmp->name));

				if (c->spd.that.client.maskbits  < tmp->spd.that.client.maskbits) {
					DBG(DBG_OPPO, DBG_log("passthrough conn was a better match (%d bits versus conn %d bits) - suppressing NO_PROPSAL_CHOSEN reply",
						tmp->spd.that.client.maskbits,
						c->spd.that.client.maskbits));
					return STF_DROP;
				}
			}
		}
	}

	/* check if we would drop the packet based on VID before we create a state */
	for (struct payload_digest *p = md->chain[ISAKMP_NEXT_v2V]; p != NULL; p = p->next) {
		if (vid_is_oppo((char *)p->pbs.cur, pbs_left(&p->pbs))) {
			if (pluto_drop_oppo_null) {
				DBG(DBG_OPPO, DBG_log("Dropped IKE request for Opportunistic IPsec by global policy"));
				return STF_DROP; /* no state to delete */
			}
			DBG(DBG_OPPO | DBG_CONTROLMORE, DBG_log("Processing IKE request for Opportunistic IPsec"));
			break;
		}
	}

	/* Vendor ID processing */
	for (struct payload_digest *v = md->chain[ISAKMP_NEXT_v2V]; v != NULL; v = v->next) {
		handle_vendorid(md, (char *)v->pbs.cur, pbs_left(&v->pbs), TRUE);
	}

	/*
	 * We've committed to creating a state and, presumably,
	 * dedicating real resources to the connection.
	 */
	pexpect(md->svm == finite_states[STATE_PARENT_R0]->fs_v2_transitions);
	struct state *st = new_v2_state(STATE_PARENT_R0, SA_RESPONDER,
					md->hdr.isa_ike_spis.initiator,
					ike_responder_spi(&md->sender));
	/* set up new state */
	initialize_new_state(st, c, policy, 0, null_fd);
	update_ike_endpoints(st, md);
	passert(st->st_ike_version == IKEv2);
	passert(st->st_state_kind == STATE_PARENT_R0);
	st->st_original_role = ORIGINAL_RESPONDER;
	passert(st->st_sa_role == SA_RESPONDER);
	passert(st->st_msgid_lastack == v2_INVALID_MSGID);
	passert(st->st_msgid_nextuse == 0);

	md->st = st;
	/* set by caller */
	pexpect(md->from_state == STATE_PARENT_R0);
	pexpect(md->svm == finite_states[STATE_PARENT_R0]->fs_v2_transitions);

	/* Get the proposals ready.  */
	struct ikev2_proposals *ike_proposals =
		get_v2_ike_proposals(c, "IKE SA responder matching remote proposals");

	/*
	 * Select the proposal.
	 */
	stf_status ret = ikev2_process_sa_payload("IKE responder",
						  &md->chain[ISAKMP_NEXT_v2SA]->pbs,
						  /*expect_ike*/ TRUE,
						  /*expect_spi*/ FALSE,
						  /*expect_accepted*/ FALSE,
						  LIN(POLICY_OPPORTUNISTIC, c->policy),
						  &st->st_accepted_ike_proposal,
						  ike_proposals);
	if (ret != STF_OK) {
		if (pexpect(ret > STF_FAIL)) {
			send_v2N_response_from_md(md, ret - STF_FAIL, NULL);
		}
		return STF_FATAL;
	}

	DBG(DBG_CONTROL, DBG_log_ikev2_proposal("accepted IKE proposal",
						st->st_accepted_ike_proposal));

	/*
	 * Convert what was accepted to internal form and apply some
	 * basic validation.  If this somehow fails (it shouldn't but
	 * ...), drop everything.
	 */
	if (!ikev2_proposal_to_trans_attrs(st->st_accepted_ike_proposal,
					   &st->st_oakley)) {
		loglog(RC_LOG_SERIOUS, "IKE responder accepted an unsupported algorithm");
		/* STF_INTERNAL_ERROR doesn't delete ST */
		return STF_FATAL;
	}

	/*
	 * Check the MODP group in the payload matches the accepted
	 * proposal.
	 */
	if (v2_reject_wrong_ke_for_proposal(NULL /*not encrypted*/, md,
					    st->st_oakley.ta_dh)) {
		/* already replied */
		return STF_FATAL;
	}

	/*
	 * Check and read the KE contents.
	 */
	/* note: v1 notification! */
	if (!accept_KE(&st->st_gi, "Gi", st->st_oakley.ta_dh,
		       md->chain[ISAKMP_NEXT_v2KE])) {
		send_v2N_response_from_md(md, v2N_INVALID_SYNTAX, NULL);
		return STF_FATAL;
	}

	bool seen_nat = FALSE;
	for (struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		switch(ntfy->payload.v2n.isan_type) {
		case v2N_COOKIE:
			/* already handled earlier */
			break;

		case v2N_SIGNATURE_HASH_ALGORITHMS:
			if (!IMPAIR(IGNORE_HASH_NOTIFY_REQUEST)) {
				if (st->st_seen_hashnotify) {
					DBG(DBG_CONTROL,
					    DBG_log("Ignoring duplicate Signature Hash Notify payload"));
				} else {
					st->st_seen_hashnotify = TRUE;
					if (!negotiate_hash_algo_from_notification(ntfy, st))
						return STF_FATAL;
				}
			} else {
				libreswan_log("Impair: Ignoring the Signature hash notify in IKE_SA_INIT Request");
			}
			break;

		case v2N_IKEV2_FRAGMENTATION_SUPPORTED:
			st->st_seen_fragvid = TRUE;
			break;

		case v2N_USE_PPK:
			st->st_seen_ppk = TRUE;
			break;

		case v2N_REDIRECTED_FROM:	/* currently we don't check address in this payload */
		case v2N_REDIRECT_SUPPORTED:
			st->st_seen_redirect_sup = TRUE;
			break;

		case v2N_NAT_DETECTION_DESTINATION_IP:
		case v2N_NAT_DETECTION_SOURCE_IP:
			if (!seen_nat) {
				/* they used zero - our (the responder) SPI was unknown */
				ikev2_natd_lookup(md, &zero_ike_spi);
				seen_nat = TRUE; /* only do it once */
			}
			break;

		/* These are not supposed to appear in IKE_INIT */
		case v2N_ESP_TFC_PADDING_NOT_SUPPORTED:
		case v2N_USE_TRANSPORT_MODE:
		case v2N_IPCOMP_SUPPORTED:
		case v2N_PPK_IDENTITY:
		case v2N_NO_PPK_AUTH:
		case v2N_MOBIKE_SUPPORTED:
			DBG(DBG_CONTROLMORE, DBG_log("Received unauthenticated %s notify in wrong exchange - ignored",
				enum_name(&ikev2_notify_names,
					ntfy->payload.v2n.isan_type)));
			break;

		default:
			DBG(DBG_CONTROLMORE,
			    DBG_log("Received unauthenticated %s notify - ignored",
				    enum_name(&ikev2_notify_names,
					      ntfy->payload.v2n.isan_type)));
		}
	}

	/* calculate the nonce and the KE */
	request_ke_and_nonce("ikev2_inI1outR1 KE", st,
			     st->st_oakley.ta_dh,
			     ikev2_parent_inI1outR1_continue);
	return STF_SUSPEND;
}

static void ikev2_parent_inI1outR1_continue(struct state *st,
					    struct msg_digest **mdp,
					    struct pluto_crypto_req *r)
{
	DBG(DBG_CONTROL,
		DBG_log("ikev2_parent_inI1outR1_continue for #%lu: calculated ke+nonce, sending R1",
			st->st_serialno));

	passert(*mdp != NULL);
	stf_status e = ikev2_parent_inI1outR1_continue_tail(st, *mdp, r);
	/* replace (*mdp)->st with st ... */
	complete_v2_state_transition((*mdp)->st, mdp, e);
}

/*
 * ikev2_parent_inI1outR1_tail: do what's left after all the crypto
 *
 * Called from:
 *	ikev2_parent_inI1outR1: if KE and Nonce were already calculated
 *	ikev2_parent_inI1outR1_continue: if they needed to be calculated
 */
static stf_status ikev2_parent_inI1outR1_continue_tail(struct state *st,
						       struct msg_digest *md,
						       struct pluto_crypto_req *r)
{
	struct connection *c = st->st_connection;
	bool send_certreq = FALSE;

	/* note that we don't update the state here yet */

	/*
	 * XXX:
	 *
	 * Should this code use clone_in_pbs_as_chunk() which uses
	 * pbs_room() (.roof-.start)?  The original code:
	 *
	 * 	clonetochunk(st->st_firstpacket_him, md->message_pbs.start,
	 *		     pbs_offset(&md->message_pbs),
	 *		     "saved first received packet");
	 *
	 * and clone_out_pbs_as_chunk() both use pbs_offset()
	 * (.cur-.start).
	 *
	 * Suspect it doesn't matter as the code initializing
	 * .message_pbs forces .roof==.cur - look for the comment
	 * "trim padding (not actually legit)".
	 */
	/* record first packet for later checking of signature */
	st->st_firstpacket_him = clone_out_pbs_as_chunk(&md->message_pbs,
							"saved first received packet");

	/* make sure HDR is at start of a clean buffer */
	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		     "reply packet");

	/* HDR out */
	pb_stream rbody = open_v2_message(&reply_stream, ike_sa(st),
					  md /* response */,
					  ISAKMP_v2_IKE_SA_INIT);
	if (!pbs_ok(&rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* start of SA out */
	{
		/*
		 * Since this is the initial IKE exchange, the SPI is
		 * emitted as part of the packet header and not as
		 * part of the proposal.  Hence the NULL SPI.
		 */
		passert(st->st_accepted_ike_proposal != NULL);
		if (!ikev2_emit_sa_proposal(&rbody, st->st_accepted_ike_proposal, NULL)) {
			DBG(DBG_CONTROL, DBG_log("problem emitting accepted proposal"));
			return STF_INTERNAL_ERROR;
		}
	}

	/* Ni in */
	RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_ni, "Ni"));

	/* ??? from here on, this looks a lot like the end of ikev2_parent_outI1_common */

	/*
	 * Unpack and send KE
	 *
	 * Pass the crypto helper's oakley group so that it is
	 * consistent with what was unpacked.
	 *
	 * IKEv2 code (arguably, incorrectly) uses st_oakley.ta_dh to
	 * track the most recent KE sent out.  It should instead be
	 * maintaing a list of KEs sent out (so that they can be
	 * reused should the initial responder flip-flop) and only set
	 * st_oakley.ta_dh once the proposal has been accepted.
	 */
	pexpect(st->st_oakley.ta_dh == r->pcr_d.kn.group);
	unpack_KE_from_helper(st, r, &st->st_gr);
	if (!emit_v2KE(&st->st_gr, r->pcr_d.kn.group, &rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* send NONCE */
	unpack_nonce(&st->st_nr, r);
	{
		pb_stream pb;
		struct ikev2_generic in = {
			.isag_np = ISAKMP_NEXT_v2N,
			.isag_critical = build_ikev2_critical(false),
		};

		if (!out_struct(&in, &ikev2_nonce_desc, &rbody, &pb) ||
		    !out_chunk(st->st_nr, &pb, "IKEv2 nonce"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&pb);
	}

	/* decide to send a CERTREQ - for RSASIG or GSSAPI */
	send_certreq = (((c->policy & POLICY_RSASIG) &&
		!has_preloaded_public_key(st))
		);

	/* Send fragmentation support notification */
	if (c->policy & POLICY_IKE_FRAG_ALLOW) {
		if (!emit_v2N(v2N_IKEV2_FRAGMENTATION_SUPPORTED, &rbody))
			return STF_INTERNAL_ERROR;
	}

	/* Send USE_PPK Notify payload */
	if (st->st_seen_ppk) {
		if (!emit_v2N(v2N_USE_PPK, &rbody))
			return STF_INTERNAL_ERROR;
	 }

	if (st->st_seen_redirect_sup &&
	    (global_redirect == GLOBAL_REDIRECT_YES ||
	     (global_redirect == GLOBAL_REDIRECT_AUTO && require_ddos_cookies())))
	{
		if (global_redirect_to == NULL) {
			loglog(RC_LOG_SERIOUS, "global-redirect-to is not specified; can't redirect requests");
		} else {
			if (!emit_redirect_notification(global_redirect_to, &st->st_ni, &rbody))
				return STF_INTERNAL_ERROR;
		}
	}

	/* Send SIGNATURE_HASH_ALGORITHMS notification only if we received one */
	if (!IMPAIR(IGNORE_HASH_NOTIFY_REQUEST)) {
		if (st->st_seen_hashnotify && ((c->policy & POLICY_RSASIG) || (c->policy & POLICY_ECDSA))
			&& (c->sighash_policy != POL_SIGHASH_NONE)) {
			if (!emit_v2N_signature_hash_algorithms(c->sighash_policy, &rbody))
				return STF_INTERNAL_ERROR;
		}
	} else {
		libreswan_log("Impair: Not sending out signature hash notify");
	}

	/* Send NAT-T Notify payloads */
	if (!ikev2_out_nat_v2n(&rbody, st, &st->st_ike_spis.responder)) {
		return STF_INTERNAL_ERROR;
	}

	/* something the other end won't like */

	if (IMPAIR(ADD_UNKNOWN_PAYLOAD_TO_SA_INIT)) {
		if (!emit_v2UNKNOWN("IKE_SA_INIT reply", &rbody)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* send CERTREQ  */
	if (send_certreq) {
		DBG(DBG_CONTROL, DBG_log("going to send a certreq"));
		ikev2_send_certreq(st, md, &rbody);
	}

	if (c->send_vendorid) {
		if (!emit_v2V(pluto_vendorid, &rbody))
			return STF_INTERNAL_ERROR;
	}

	if (c->fake_strongswan) {
		if (!emit_v2V("strongSwan", &rbody))
			return STF_INTERNAL_ERROR;
	}

	if (c->policy & POLICY_AUTH_NULL) {
		if (!emit_v2V("Opportunistic IPsec", &rbody))
			return STF_INTERNAL_ERROR;
	}

	close_output_pbs(&rbody);
	close_output_pbs(&reply_stream);

	record_outbound_ike_msg(st, &reply_stream,
		"reply packet for ikev2_parent_inI1outR1_tail");

	/* save packet for later signing */
	freeanychunk(st->st_firstpacket_me);
	st->st_firstpacket_me = clone_out_pbs_as_chunk(&reply_stream,
						   "saved first packet");

	/* note: retransmission is driven by initiator, not us */

	return STF_OK;
}

/*
 *
 ***************************************************************
 *                       PARENT_inR1                       *****
 ***************************************************************
 *  -
 *
 *
 */
/* STATE_PARENT_I1: R1B --> I1B
 *                     <--  HDR, N
 * HDR, N(COOKIE), SAi1, KEi, Ni -->
 */
stf_status ikev2_IKE_SA_process_SA_INIT_response_notification(struct state *st,
							      struct msg_digest *md)
{
	struct connection *c = st->st_connection;

	for (struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		if (ntfy->payload.v2n.isan_spisize != 0) {
			rate_log("Notify payload for IKE must have zero length SPI - message dropped");
			return STF_IGNORE;
		}

		if (ntfy->payload.v2n.isan_type >= v2N_STATUS_FLOOR) {
			pstat(ikev2_recv_notifies_s, ntfy->payload.v2n.isan_type);
		} else {
			pstat(ikev2_recv_notifies_e, ntfy->payload.v2n.isan_type);
		}

		switch (ntfy->payload.v2n.isan_type) {
		case v2N_COOKIE:
		{
			/*
			 * Responder replied with N(COOKIE) for DOS avoidance.
			 * See rfc5996bis-04 2.6.
			 * Responder SPI ought to have been 0 (but might not be).
			 * Our state should not advance.  Instead
			 * we should send our I1 packet with the same cookie.
			 */

			/*
			 * RFC-7296 Section 2.6:
			 * The data associated with this notification MUST be
			 * between 1 and 64 octets in length (inclusive)
			 */
			if (ntfy->payload.v2n.isan_length > IKEv2_MAX_COOKIE_SIZE) {
				DBG(DBG_CONTROL, DBG_log("v2N_COOKIE notify payload too big - packet dropped"));
				return STF_IGNORE;
			}

			if (ntfy->next != NULL) {
				DBG(DBG_CONTROL, DBG_log("ignoring Notify payloads after v2N_COOKIE"));
			}

			clonetochunk(st->st_dcookie,
				ntfy->pbs.cur, pbs_left(&ntfy->pbs),
				"saved received dcookie");

			DBG(DBG_CONTROLMORE,
			    DBG_dump_chunk("dcookie received (instead of an R1):",
					   st->st_dcookie);
			    DBG_log("next STATE_PARENT_I1 resend I1 with the dcookie"));

			if (DBGP(DBG_OPPO) || (st->st_connection->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
				libreswan_log("Received anti-DDOS COOKIE, resending I1 with cookie payload");
			}

			/*
			 * Need to wind things back to the point that
			 * the Message ID counter code thinks this is
			 * an initial outgoing message.
			 */
			v2_msgid_restart_init_request(st, md);
			/* re-send the SA_INIT request with cookies added */
			return ikev2_parent_outI1_common(md, st);
		}
		case v2N_INVALID_KE_PAYLOAD:
		{
			/* careful of DDOS, only log with debugging on */
			struct suggested_group sg;

			/* we treat this as a "retransmit" event to rate limit these */
			if (!count_duplicate(st, MAXIMUM_INVALID_KE_RETRANS)) {
				DBG(DBG_CONTROLMORE, DBG_log("ignoring received INVALID_KE packets - received too many (DoS?)"));
				return STF_IGNORE;
			}

			if (ntfy->next != NULL) {
				DBG(DBG_CONTROL, DBG_log("ignoring Notify payloads after v2N_INVALID_KE_PAYLOAD"));
			}

			if (!in_struct(&sg, &suggested_group_desc,
				&ntfy->pbs, NULL))
					return STF_IGNORE;

			pstats(invalidke_recv_s, sg.sg_group);
			pstats(invalidke_recv_u, st->st_oakley.ta_dh->group);

			struct ikev2_proposals *ike_proposals =
				get_v2_ike_proposals(c, "IKE SA initiator validating remote's suggested KE");

			if (ikev2_proposals_include_modp(ike_proposals, sg.sg_group)) {
				DBG(DBG_CONTROLMORE, DBG_log("Suggested modp group is acceptable"));
				/*
				 * Since there must be a group object
				 * for every local proposal, and
				 * sg.sg_group matches one of the
				 * local proposal groups, a lookup of
				 * sg.sg_group must succeed.
				 */
				const struct oakley_group_desc *new_group = ikev2_get_dh_desc(sg.sg_group);
				passert(new_group);
				libreswan_log("Received unauthenticated INVALID_KE_PAYLOAD response to DH %s; resending with suggested DH %s",
					      st->st_oakley.ta_dh->common.name,
					      new_group->common.name);
				st->st_oakley.ta_dh = new_group;
				/* wipe our mismatched KE */
				free_dh_secret(&st->st_dh_secret);
				/* wipe out any saved RCOOKIE */
				DBG(DBG_CONTROLMORE, DBG_log("zeroing any RCOOKIE from unauthenticated INVALID_KE packet"));
				rehash_state(st, &zero_ike_spi);
				/*
				 * get a new KE
				 */
				/* if we received INVALID_KE, msgid was incremented */
				st->st_msgid_lastack = v2_INVALID_MSGID;
				st->st_msgid_lastrecv = v2_INVALID_MSGID;
				st->st_msgid_nextuse = 0;
				st->st_msgid = 0;
				request_ke_and_nonce("rekey outI", st,
						     st->st_oakley.ta_dh,
						     ikev2_parent_outI1_continue);
				/* let caller delete current MD */
				/* XXX: shouldn't this be STF_SUSPEND?!? */
				return STF_IGNORE;
			} else {
				struct esb_buf esb;
				libreswan_log("Discarding unauthenticated INVALID_KE_PAYLOAD response to DH %s; suggested DH %s is not acceptable",
					      st->st_oakley.ta_dh->common.name,
					      enum_show_shortb(&oakley_group_names,
							       sg.sg_group, &esb));
				return STF_IGNORE;
			}
		}

		default:
			/*
			 * For things like v2N_NO_PROPOSAL_CHOSEN and
			 * v2N_UNKNOWN_CRITICIAL_PAYLOAD, because they
			 * were part of the unprotected SA_INIT
			 * message, they really can't be trusted.
			 * Just log and forget.
			 */
			rate_log("%s: received unauthenticated %s - ignored",
				 st->st_state_name,
				 enum_name(&ikev2_notify_names,
					   ntfy->payload.v2n.isan_type));
		}
	}
	return STF_IGNORE;
}

stf_status ikev2_auth_initiator_process_failure_notification(struct state *st,
							     struct msg_digest *md)
{
	v2_notification_t n = md->svm->encrypted_payloads.notification;
	pstat(ikev2_recv_notifies_e, n);
	/*
	 * Always log the notification error and fail;
	 * but do it in slightly different ways so it
	 * is possible to figure out which code path
	 * was taken.
	 */
	libreswan_log("IKE SA authentication request rejected by peer: %s",
		      enum_short_name(&ikev2_notify_names, n));
	/*
	 * 2.21.2.  Error Handling in IKE_AUTH
	 *
	 *             ...  If the error occurred on the responder, the
	 *   notification is returned in the protected response, and is usually
	 *   the only payload in that response.  Although the IKE_AUTH messages
	 *   are encrypted and integrity protected, if the peer receiving this
	 *   notification has not authenticated the other end yet, that peer needs
	 *   to treat the information with caution.
	 *
	 * So assume MITM and schedule a retry.
	 */
	if (ikev2_schedule_retry(st)) {
		return STF_IGNORE; /* drop packet */
	} else {
		return STF_FATAL;
	}
}

stf_status ikev2_auth_initiator_process_unknown_notification(struct state *st UNUSED,
							     struct msg_digest *md)
{
	/*
	 * 3.10.1.  Notify Message Types:
	 *
	 *   Types in the range 0 - 16383 are intended for reporting errors.  An
	 *   implementation receiving a Notify payload with one of these types
	 *   that it does not recognize in a response MUST assume that the
	 *   corresponding request has failed entirely.  Unrecognized error types
	 *   in a request and status types in a request or response MUST be
	 *   ignored, and they should be logged.
	 */

	bool ignore = true;
	for (struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		v2_notification_t n = ntfy->payload.v2n.isan_type;
		const char *name = enum_short_name(&ikev2_notify_names, n);

		if (ntfy->payload.v2n.isan_spisize != 0) {
			/* invalid-syntax, but can't do anything about it */
			rate_log("received an encrypted %s notification with an unexpected non-empty SPI; deleting IKE SA",
				 name);
			return STF_FATAL;
		}

		if (n >= v2N_STATUS_FLOOR) {
			/* just log */
			pstat(ikev2_recv_notifies_s, n);
			if (name == NULL) {
				rate_log("IKE_AUTH response contained an unknown status notification (%d)", n);
			} else {
				rate_log("IKE_AUTH response contained the status notification %s", name);
			}
		} else {
			pstat(ikev2_recv_notifies_e, n);
			ignore = false;
			if (name == NULL) {
				libreswan_log("IKE_AUTH response contained an unknown error notification (%d)", n);
			} else {
				libreswan_log("IKE_AUTH response contained the error notification %s", name);
			}
		}
	}
	if (ignore) {
		return STF_IGNORE;
	}
	/*
	 * 2.21.2.  Error Handling in IKE_AUTH
	 *
	 *             ...  If the error occurred on the responder, the
	 *   notification is returned in the protected response, and is usually
	 *   the only payload in that response.  Although the IKE_AUTH messages
	 *   are encrypted and integrity protected, if the peer receiving this
	 *   notification has not authenticated the other end yet, that peer needs
	 *   to treat the information with caution.
	 *
	 * So assume MITM and schedule a retry.
	 */
	if (ikev2_schedule_retry(st)) {
		return STF_IGNORE; /* drop packet */
	} else {
		return STF_FATAL;
	}
}

/* STATE_PARENT_I1: R1 --> I2
 *                     <--  HDR, SAr1, KEr, Nr, [CERTREQ]
 * HDR, SK {IDi, [CERT,] [CERTREQ,]
 *      [IDr,] AUTH, SAi2,
 *      TSi, TSr}      -->
 */

static crypto_req_cont_func ikev2_parent_inR1outI2_continue;	/* forward decl and type assertion */
static crypto_transition_fn ikev2_parent_inR1outI2_tail;	/* forward decl and type assertion */

stf_status ikev2_parent_inR1outI2(struct state *st, struct msg_digest *md)
{
	struct connection *c = st->st_connection;
	struct payload_digest *ntfy;
	ip_address redirect_ip;

	/* for testing only */
	if (IMPAIR(SEND_NO_IKEV2_AUTH)) {
		libreswan_log(
			"IMPAIR_SEND_NO_IKEV2_AUTH set - not sending IKE_AUTH packet");
		return STF_IGNORE;
	}

	if (need_this_intiator(st)) {
		return STF_DROP;
	}

	for (ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		if (ntfy->payload.v2n.isan_type >= v2N_STATUS_FLOOR) {
			pstat(ikev2_recv_notifies_s, ntfy->payload.v2n.isan_type);
		} else {
			pstat(ikev2_recv_notifies_e, ntfy->payload.v2n.isan_type);
		}

		switch (ntfy->payload.v2n.isan_type) {
		case v2N_COOKIE:
		case v2N_INVALID_KE_PAYLOAD:
		case v2N_NO_PROPOSAL_CHOSEN:
			DBG(DBG_CONTROL, DBG_log("%s cannot appear with other payloads",
				enum_name(&ikev2_notify_names,
						ntfy->payload.v2n.isan_type)));
			return STF_FAIL + v2N_INVALID_SYNTAX;

		case v2N_MOBIKE_SUPPORTED:
		case v2N_USE_TRANSPORT_MODE:
		case v2N_IPCOMP_SUPPORTED:
		case v2N_ESP_TFC_PADDING_NOT_SUPPORTED:
		case v2N_PPK_IDENTITY:
		case v2N_NO_PPK_AUTH:
		case v2N_INITIAL_CONTACT:
			DBG(DBG_CONTROL, DBG_log("%s: received %s which is not valid in the IKE_SA_INIT Exchange - ignoring it",
				st->st_state_name,
				enum_name(&ikev2_notify_names,
					ntfy->payload.v2n.isan_type)));
			break;

		case v2N_NAT_DETECTION_SOURCE_IP:
		case v2N_NAT_DETECTION_DESTINATION_IP:
			/* we do handle these further down */
			break;
		case v2N_IKEV2_FRAGMENTATION_SUPPORTED:
			st->st_seen_fragvid = TRUE;
			break;

		case v2N_USE_PPK:
			st->st_seen_ppk = TRUE;
			break;

		case v2N_REDIRECT:
		{
			DBG(DBG_CONTROL, DBG_log("received v2N_REDIRECT in IKE_SA_INIT reply"));

			if (!LIN(POLICY_ACCEPT_REDIRECT_YES, st->st_connection->policy)) {
				DBG(DBG_CONTROL, DBG_log("ignoring v2N_REDIRECT, we don't allow to be redirected"));
				break;
			}

			err_t e = parse_redirect_payload(&ntfy->pbs,
							   c->accept_redirect_to,
							   &st->st_ni,
							   &redirect_ip);
			if (e != NULL) {
				loglog(RC_LOG_SERIOUS, "warning: parsing of v2N_REDIRECT payload failed: %s", e);
			} else {
				st->st_connection->temp_vars.redirect_ip = redirect_ip;
				event_force(EVENT_v2_REDIRECT, st);
				return STF_SUSPEND;
			}
			break;
		}
		case v2N_SIGNATURE_HASH_ALGORITHMS:
			if (!IMPAIR(IGNORE_HASH_NOTIFY_RESPONSE)) {
				st->st_seen_hashnotify = TRUE;
				if (!negotiate_hash_algo_from_notification(ntfy, st))
					return STF_FATAL;
			} else {
				libreswan_log("Impair: Ignoring the hash notify in IKE_SA_INIT Response");
			}
			break;

		default:
			DBG(DBG_CONTROL, DBG_log("%s: received %s but ignoring it",
				st->st_state_name,
				enum_name(&ikev2_notify_names,
					ntfy->payload.v2n.isan_type)));
		}
	}

	/*
	 * the responder sent us back KE, Gr, Nr, and it's our time to calculate
	 * the shared key values.
	 */

	DBG(DBG_CONTROLMORE,
	    DBG_log("ikev2 parent inR1: calculating g^{xy} in order to send I2"));

	/* KE in */
	if (!accept_KE(&st->st_gr, "Gr", st->st_oakley.ta_dh,
		       md->chain[ISAKMP_NEXT_v2KE])) {
		/*
		 * XXX: Initiator - so this code will not trigger a
		 * notify.  Since packet isn't trusted, should it be
		 * ignored?
		 */
		return STF_FAIL + v2N_INVALID_SYNTAX;
	}

	/* Ni in */
	RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_nr, "Ni"));

	/* We're missing processing a CERTREQ in here */

	/* process and confirm the SA selected */
	{
		/* SA body in and out */
		struct payload_digest *const sa_pd =
			md->chain[ISAKMP_NEXT_v2SA];
		struct ikev2_proposals *ike_proposals =
			get_v2_ike_proposals(c, "IKE SA initiator accepting remote proposal");

		stf_status ret = ikev2_process_sa_payload("IKE initiator (accepting)",
							  &sa_pd->pbs,
							  /*expect_ike*/ TRUE,
							  /*expect_spi*/ FALSE,
							  /*expect_accepted*/ TRUE,
							  LIN(POLICY_OPPORTUNISTIC, c->policy),
							  &st->st_accepted_ike_proposal,
							  ike_proposals);
		if (ret != STF_OK) {
			DBG(DBG_CONTROLMORE, DBG_log("ikev2_parse_parent_sa_body() failed in ikev2_parent_inR1outI2()"));
			return ret;
		}

		if (!ikev2_proposal_to_trans_attrs(st->st_accepted_ike_proposal,
						   &st->st_oakley)) {
			loglog(RC_LOG_SERIOUS, "IKE initiator proposed an unsupported algorithm");
			free_ikev2_proposal(&st->st_accepted_ike_proposal);
			passert(st->st_accepted_ike_proposal == NULL);
			/*
			 * Assume caller et.al. will clean up the
			 * reset of the mess?
			 */
			return STF_FAIL;
		}
	}

	/* update state */
	dbg("Message ID: received INIT response");
	v2_msgid_update_counters(md->st, md);

	/* check v2N_NAT_DETECTION_DESTINATION_IP or/and
	 * v2N_NAT_DETECTION_SOURCE_IP
	 */
	if (md->chain[ISAKMP_NEXT_v2N] != NULL) {
		ikev2_natd_lookup(md, &st->st_ike_spis.responder);
	}

	/* initiate calculation of g^xy */
	start_dh_v2(st, "ikev2_inR1outI2 KE",
		    ORIGINAL_INITIATOR,
		    NULL, NULL, &st->st_ike_spis,
		    ikev2_parent_inR1outI2_continue);
	return STF_SUSPEND;
}

static void ikev2_parent_inR1outI2_continue(struct state *st,
					    struct msg_digest **mdp,
					    struct pluto_crypto_req *r)
{
	DBG(DBG_CONTROL,
		DBG_log("ikev2_parent_inR1outI2_continue for #%lu: calculating g^{xy}, sending I2",
			st->st_serialno));

	passert(*mdp != NULL);
	stf_status e = ikev2_parent_inR1outI2_tail(st, *mdp, r);
	/* replace (*mdp)->st with st ... */
	complete_v2_state_transition((*mdp)->st, mdp, e);
}

/* Misleading name, also used for NULL sized type's */
static stf_status ikev2_ship_cp_attr_ip(uint16_t type, ip_address *ip,
		const char *story, pb_stream *outpbs)
{
	pb_stream a_pbs;

	struct ikev2_cp_attribute attr = {
		.type = type,
		.len = (ip == NULL) ? 0 : addrlenof(ip),
	};

	if (!out_struct(&attr, &ikev2_cp_attribute_desc, outpbs,
				&a_pbs))
		return STF_INTERNAL_ERROR;

	if (attr.len > 0) {
		const unsigned char *byte_ptr;
		addrbytesptr_read(ip, &byte_ptr);
		if (!out_raw(byte_ptr, attr.len, &a_pbs, story))
			return STF_INTERNAL_ERROR;
	}

	close_output_pbs(&a_pbs);
	return STF_OK;
}

static stf_status ikev2_ship_cp_attr_str(uint16_t type, char *str,
		const char *story, pb_stream *outpbs)
{
	pb_stream a_pbs;
	struct ikev2_cp_attribute attr = {
		.type = type,
		.len = (str == NULL) ? 0 : strlen(str),
	};

	if (!out_struct(&attr, &ikev2_cp_attribute_desc, outpbs,
				&a_pbs))
		return STF_INTERNAL_ERROR;

	if (attr.len > 0) {
		if (!out_raw(str, attr.len, &a_pbs, story))
			return STF_INTERNAL_ERROR;
	}

	close_output_pbs(&a_pbs);
	return STF_OK;
}

stf_status ikev2_send_cp(struct state *st, enum next_payload_types_ikev2 np,
				  pb_stream *outpbs)
{
	pb_stream cp_pbs;
	struct connection *c = st->st_connection;
	bool cfg_reply = c->spd.that.has_lease;

	DBG(DBG_CONTROLMORE, DBG_log("Send Configuration Payload %s ",
				cfg_reply ? "reply" : "request"));
	struct ikev2_cp cp = {
		.isacp_np = np,
		.isacp_critical = ISAKMP_PAYLOAD_NONCRITICAL,
		.isacp_type = cfg_reply ? IKEv2_CP_CFG_REPLY : IKEv2_CP_CFG_REQUEST,
	};

	if (!out_struct(&cp, &ikev2_cp_desc, outpbs, &cp_pbs))
		return STF_INTERNAL_ERROR;

	ikev2_ship_cp_attr_ip(addrtypeof(&c->spd.that.client.addr) == AF_INET ?
		IKEv2_INTERNAL_IP4_ADDRESS : IKEv2_INTERNAL_IP6_ADDRESS,
		&c->spd.that.client.addr,
		"Internal IP Address", &cp_pbs);

	if (cfg_reply) {
		if (c->modecfg_dns != NULL) {
			char *ipstr;

			ipstr = strtok(c->modecfg_dns, ", ");
			while (ipstr != NULL) {
				if (strchr(ipstr, '.') != NULL) {
					ip_address ip;
					err_t e  = ttoaddr_num(ipstr, 0, AF_INET, &ip);
					if (e != NULL) {
						loglog(RC_LOG_SERIOUS, "Ignored bogus DNS IP address '%s'", ipstr);
					} else {
						if (ikev2_ship_cp_attr_ip(IKEv2_INTERNAL_IP4_DNS, &ip,
							"IP4_DNS", &cp_pbs) != STF_OK)
								return STF_INTERNAL_ERROR;
					}
				} else if (strchr(ipstr, ':') != NULL) {
					ip_address ip;
					err_t e  = ttoaddr_num(ipstr, 0, AF_INET6, &ip);
					if (e != NULL) {
						loglog(RC_LOG_SERIOUS, "Ignored bogus DNS IP address '%s'", ipstr);
					} else {
						if (ikev2_ship_cp_attr_ip(IKEv2_INTERNAL_IP6_DNS, &ip,
							"IP6_DNS", &cp_pbs) != STF_OK)
								return STF_INTERNAL_ERROR;
					}
				} else {
					loglog(RC_LOG_SERIOUS, "Ignored bogus DNS IP address '%s'", ipstr);
				}
				ipstr = strtok(NULL, ", ");
			}
		}

		if (c->modecfg_domains != NULL) {
			char *domain;

			domain = strtok(c->modecfg_domains, ", ");
			while (domain != NULL) {
				if (ikev2_ship_cp_attr_str(IKEv2_INTERNAL_DNS_DOMAIN, domain,
					"IKEv2_INTERNAL_DNS_DOMAIN", &cp_pbs) != STF_OK)
						return STF_INTERNAL_ERROR;
				domain = strtok(NULL, ", ");
			}
		}
	} else { /* cfg request */
		ikev2_ship_cp_attr_ip(IKEv2_INTERNAL_IP4_ADDRESS,
			 NULL, "IPV4 Address", &cp_pbs);
		ikev2_ship_cp_attr_ip(IKEv2_INTERNAL_IP4_DNS, NULL, "DNSv4", &cp_pbs);

		ikev2_ship_cp_attr_ip(IKEv2_INTERNAL_IP6_ADDRESS,
			 NULL, "IPV6 Address", &cp_pbs);
		ikev2_ship_cp_attr_ip(IKEv2_INTERNAL_IP6_DNS, NULL, "DNSv6", &cp_pbs);
		ikev2_ship_cp_attr_ip(IKEv2_INTERNAL_DNS_DOMAIN, NULL, "Domain", &cp_pbs);
	}

	close_output_pbs(&cp_pbs);

	return STF_OK;
}

static stf_status ikev2_send_auth(struct connection *c,
				  struct state *st,
				  enum original_role role,
				  enum next_payload_types_ikev2 np,
				  unsigned char *idhash_out,
				  pb_stream *outpbs,
				  chunk_t *null_auth /* out */)
{
	pb_stream a_pbs;
	struct state *pst = IS_CHILD_SA(st) ?
		state_with_serialno(st->st_clonedfrom) : st;
	enum keyword_authby authby = c->spd.this.authby;
	enum notify_payload_hash_algorithms hash_algo;

	if (null_auth != NULL)
		*null_auth = EMPTY_CHUNK;

	if (st->st_peer_wants_null) {
		/* we allow authby=null and IDr payload told us to use it */
		authby = AUTH_NULL;
	} else if (authby == AUTH_UNSET) {
		/* asymmetric policy unset, pick up from symmetric policy */
		/* in order of preference! */
		if (c->policy & POLICY_RSASIG) {
			authby = AUTH_RSASIG;
		} else if (c->policy & POLICY_PSK) {
			authby = AUTH_PSK;
		} else if (c->policy & POLICY_AUTH_NULL) {
			authby = AUTH_NULL;
		}
	}

	/* ??? isn't c redundant? */
	pexpect(c == st->st_connection);

	struct ikev2_a a = {
		.isaa_np = np,
		.isaa_critical = build_ikev2_critical(false),
	};

	switch (authby) {
	case AUTH_RSASIG:
		a.isaa_type = pst->st_seen_hashnotify &&
			c->sighash_policy != POL_SIGHASH_NONE ?
				IKEv2_AUTH_DIGSIG : IKEv2_AUTH_RSA;
		break;
	case AUTH_ECDSA:
		a.isaa_type = IKEv2_AUTH_DIGSIG;
		break;
	case AUTH_PSK:
		a.isaa_type = IKEv2_AUTH_PSK;
		break;
	case AUTH_NULL:
		a.isaa_type = IKEv2_AUTH_NULL;
		break;
	case AUTH_NEVER:
	default:
		bad_case(authby);
	}

	if (!out_struct(&a, &ikev2_a_desc, outpbs, &a_pbs)) {
		/* loglog(RC_LOG_SERIOUS, "Failed to emit IKE_AUTH payload"); */
		return STF_INTERNAL_ERROR;
	}

	switch (a.isaa_type) {
	case IKEv2_AUTH_RSA:
		if (!ikev2_calculate_rsa_hash(pst, role, idhash_out, &a_pbs,
			FALSE, /* store-only not set */
			NULL /* store-only chunk unused */,
			IKEv2_AUTH_HASH_SHA1))
		{
			loglog(RC_LOG_SERIOUS, "Failed to find our RSA key");
			return STF_FATAL;
		}
		break;

	case IKEv2_AUTH_PSK:
	case IKEv2_AUTH_NULL:
		/* emit */
		if (!ikev2_emit_psk_auth(authby, pst, idhash_out, &a_pbs))
		{
			loglog(RC_LOG_SERIOUS, "Failed to find our PreShared Key");
			return STF_FATAL;
		}
		break;

	case IKEv2_AUTH_DIGSIG:
	{
		if (pst->st_hash_negotiated & NEGOTIATE_AUTH_HASH_SHA2_512) {
			hash_algo = IKEv2_AUTH_HASH_SHA2_512;
		} else if (pst->st_hash_negotiated & NEGOTIATE_AUTH_HASH_SHA2_384) {
			hash_algo = IKEv2_AUTH_HASH_SHA2_384;
		} else if (pst->st_hash_negotiated & NEGOTIATE_AUTH_HASH_SHA2_256) {
			hash_algo = IKEv2_AUTH_HASH_SHA2_256;
		} else {
			loglog(RC_LOG_SERIOUS, "DigSig: no compatible DigSig hash algo");
			return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
		}

		stf_status sendstat =ikev2_send_asn1_hash_blob(hash_algo, &a_pbs, authby);
		if (sendstat != STF_OK ) {
			return STF_FAIL;
		}

		switch (authby) {
		case AUTH_ECDSA:
		{
			if (!ikev2_calculate_ecdsa_hash(pst, role, idhash_out, &a_pbs,
				FALSE, /* store-only not set */
				NULL /* store-only chunk unused */,
				hash_algo))
			{
				loglog(RC_LOG_SERIOUS, "DigSig: failed to find our ECDSA key");
				return STF_FATAL;
			}
			break;
		}
		case AUTH_RSASIG:
		{
			if (!ikev2_calculate_rsa_hash(pst, role, idhash_out, &a_pbs,
				FALSE, /* store-only not set */
				NULL /* store-only chunk unused */,
				hash_algo))
			{
				loglog(RC_LOG_SERIOUS, "DigSig: failed to find our RSA key");
				return STF_FATAL;
			}
			break;
		}
		default:
			libreswan_log("unknown remote authentication type for DigSig");
			return STF_FAIL;
		}
		break;
	}

	default:
		bad_case(a.isaa_type);
	}

	/* We sent normal IKEv2_AUTH_RSA but if the policy also allows
	 * AUTH_NULL, we will send a Notify with NULL_AUTH in separate
	 * chunk. This is only done on the initiator in IKE_AUTH, and
	 * not repeated in rekeys.
	 */
	if (null_auth != NULL &&
	    authby == AUTH_RSASIG &&
	    c->policy & POLICY_AUTH_NULL) {
		/* store in null_auth */
		if (!ikev2_create_psk_auth(AUTH_NULL, pst, idhash_out,
			null_auth))
		{
			loglog(RC_LOG_SERIOUS, "Failed to calculate additional NULL_AUTH");
			return STF_FATAL;
		}
	}

	close_output_pbs(&a_pbs);
	return STF_OK;
}

static bool need_configuration_payload(const struct connection *const pc,
			    const lset_t st_nat_traversal)
{
	return (pc->spd.this.modecfg_client &&
		(!pc->spd.this.cat || LHAS(st_nat_traversal, NATED_HOST)));
}

static stf_status ikev2_parent_inR1outI2_tail(struct state *pst, struct msg_digest *md,
					      struct pluto_crypto_req *r)
{
	struct connection *const pc = pst->st_connection;	/* parent connection */
	struct ppk_id_payload ppk_id_p;

	if (!finish_dh_v2(pst, r, FALSE))
		/*
		 * XXX: this is the initiator so returning a
		 * notification is kind of useless.
		 */
		return STF_FAIL + v2N_INVALID_SYNTAX; /* STF_FATAL? */

	/*
	 * If we and responder are willing to use a PPK,
	 * we need to generate NO_PPK_AUTH as well as PPK-based AUTH payload
	 */
	if (LIN(POLICY_PPK_ALLOW, pc->policy) && pst->st_seen_ppk) {
		chunk_t *ppk_id;
		chunk_t *ppk = get_ppk(pst->st_connection, &ppk_id);

		if (ppk != NULL) {
			DBG(DBG_CONTROL, DBG_log("found PPK and PPK_ID for our connection"));

			pst->st_sk_d_no_ppk = pst->st_skey_d_nss;
			pst->st_sk_pi_no_ppk = pst->st_skey_pi_nss;
			pst->st_sk_pr_no_ppk = pst->st_skey_pr_nss;
			pst->st_skey_d_nss = NULL;
			pst->st_skey_pi_nss = NULL;
			pst->st_skey_pr_nss = NULL;

			create_ppk_id_payload(ppk_id, &ppk_id_p);
			DBG(DBG_CONTROL, DBG_log("ppk type: %d", (int) ppk_id_p.type));
			DBG(DBG_CONTROL, DBG_dump_chunk("ppk_id from payload:", ppk_id_p.ppk_id));

			ppk_recalculate(ppk, pst->st_oakley.ta_prf,
						&pst->st_skey_d_nss,
						&pst->st_skey_pi_nss,
						&pst->st_skey_pr_nss,
						pst->st_sk_d_no_ppk,
						pst->st_sk_pi_no_ppk,
						pst->st_sk_pr_no_ppk);
			libreswan_log("PPK AUTH calculated as initiator");
		} else {
			if (pc->policy & POLICY_PPK_INSIST) {
				loglog(RC_LOG_SERIOUS, "connection requires PPK, but we didn't find one");
				return STF_FATAL;
			} else {
				libreswan_log("failed to find PPK and PPK_ID, continuing without PPK");
				/* we should omit sending any PPK Identity, so we pretend we didn't see USE_PPK */
				pst->st_seen_ppk = FALSE;
			}
		}
	}

	ikev2_log_parentSA(pst);

	/* XXX This is too early and many failures could lead to not needing a child state */
	struct state *cst = ikev2_duplicate_state(pexpect_ike_sa(pst), IPSEC_SA,
						  SA_INITIATOR);	/* child state */

	/* XXX because the early child state ends up with the try counter check, we need to copy it */
	cst->st_try = pst->st_try;

	cst->st_msgid = pst->st_msgid_nextuse;
	refresh_state(cst);
	md->st = cst;

	/*
	 * XXX: Danger!
	 *
	 * Because the code above has blatted MD->ST with the child
	 * state (CST) and this function's caller is going to try to
	 * complete the V2 state transition on MD->ST (i.e., CST) and
	 * using the state-transition MD->SVM the IKE SA (PST) will
	 * never get to complete its state transition.
	 *
	 * Get around this by forcing the state transition here.
	 *
	 * But what should happen?  A guess is to just leave MD->ST
	 * alone.  The CHILD SA doesn't really exist until after the
	 * IKE SA has processed and approved of the response to this
	 * IKE_AUTH request.
	 */

	pexpect(md->svm->timeout_event == EVENT_RETRANSMIT); /* for CST */
	delete_event(pst);
	event_schedule(EVENT_SA_REPLACE, deltatime(PLUTO_HALFOPEN_SA_LIFE), pst);
	change_state(pst, STATE_PARENT_I2);

	/*
	 * XXX:
	 *
	 * Should this code use clone_in_pbs_as_chunk() which uses
	 * pbs_room() (.roof-.start)?  The original code:
	 *
	 * 	clonetochunk(st->st_firstpacket_him, md->message_pbs.start,
	 *		     pbs_offset(&md->message_pbs),
	 *		     "saved first received packet");
	 *
	 * and clone_out_pbs_as_chunk() both use pbs_offset()
	 * (.cur-.start).
	 *
	 * Suspect it doesn't matter as the code initializing
	 * .message_pbs forces .roof==.cur - look for the comment
	 * "trim padding (not actually legit)".
	 */
	/* record first packet for later checking of signature */
	pst->st_firstpacket_him = clone_out_pbs_as_chunk(&md->message_pbs,
							 "saved first received packet");

	/* beginning of data going out */

	/* make sure HDR is at start of a clean buffer */
	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	/* HDR out */

	pb_stream rbody = open_v2_message(&reply_stream, ike_sa(pst),
					  NULL /* request */,
					  ISAKMP_v2_IKE_AUTH);
	if (!pbs_ok(&rbody)) {
		return STF_INTERNAL_ERROR;
	}

	if (IMPAIR(ADD_UNKNOWN_PAYLOAD_TO_AUTH)) {
		if (!emit_v2UNKNOWN("IKE_AUTH request", &rbody)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* insert an Encryption payload header (SK) */

	v2SK_payload_t sk = open_v2SK_payload(&rbody, ike_sa(pst));
	if (!pbs_ok(&sk.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	/* actual data */

	/* decide whether to send CERT payload */

	/* it should use parent not child state */
	bool send_cert = ikev2_send_cert_decision(cst);
	bool ic =  pc->initial_contact && (pst->st_ike_pred == SOS_NOBODY);
	bool send_idr = ((pc->spd.that.id.kind != ID_NULL && pc->spd.that.id.name.len != 0) ||
				pc->spd.that.id.kind == ID_NULL); /* me tarzan, you jane */

	DBG(DBG_CONTROL, DBG_log("IDr payload will %sbe sent", send_idr ? "" : "NOT "));

	/* send out the IDi payload */

	unsigned char idhash[MAX_DIGEST_LEN];
	unsigned char idhash_npa[MAX_DIGEST_LEN];	/* idhash for NO_PPK_AUTH (npa) */

	{
		struct ikev2_id i_id = {
			.isai_np = ISAKMP_NEXT_v2NONE,
		};
		pb_stream i_id_pbs;
		chunk_t id_b;
		struct hmac_ctx id_ctx;

		hmac_init(&id_ctx, pst->st_oakley.ta_prf, pst->st_skey_pi_nss);
		v2_build_id_payload(&i_id, &id_b,
				 &pc->spd.this);
		i_id.isai_critical = build_ikev2_critical(false);

		/* HASH of ID is not done over common header */
		unsigned char *const id_start =
			sk.pbs.cur + NSIZEOF_isakmp_generic;

		if (!out_struct(&i_id,
				&ikev2_id_i_desc,
				&sk.pbs,
				&i_id_pbs) ||
		    !out_chunk(id_b, &i_id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&i_id_pbs);

		/* calculate hash of IDi for AUTH below */

		const size_t id_len = sk.pbs.cur - id_start;

		DBG(DBG_CRYPT, DBG_dump("idhash calc I2", id_start, id_len));
		hmac_update(&id_ctx, id_start, id_len);
		hmac_final(idhash, &id_ctx);

		if (pst->st_seen_ppk && !LIN(POLICY_PPK_INSIST, pc->policy)) {
			struct hmac_ctx id_ctx_npa;

			hmac_init(&id_ctx_npa, pst->st_oakley.ta_prf, pst->st_sk_pi_no_ppk);
			/* ID payload that we've build is the same */
			hmac_update(&id_ctx_npa, id_start, id_len);
			hmac_final(idhash_npa, &id_ctx_npa);
		}
	}

	if (IMPAIR(ADD_UNKNOWN_PAYLOAD_TO_AUTH_SK)) {
		if (!emit_v2UNKNOWN("IKE_AUTH's SK request", &sk.pbs)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* send [CERT,] payload RFC 4306 3.6, 1.2) */
	if (send_cert) {
		stf_status certstat = ikev2_send_cert(cst, &sk.pbs);
		if (certstat != STF_OK)
			return certstat;

		/* send CERTREQ  */
		bool send_certreq = ikev2_send_certreq_INIT_decision(cst, ORIGINAL_INITIATOR);
		if (send_certreq) {
			char buf[IDTOA_BUF];
			dntoa(buf, IDTOA_BUF, cst->st_connection->spd.that.ca);
			DBG(DBG_X509,
			    DBG_log("Sending [CERTREQ] of %s", buf));
			ikev2_send_certreq(cst, md, &sk.pbs);
		}
	}

	/* you Tarzan, me Jane support */
	if (send_idr) {
		struct ikev2_id r_id;
		pb_stream r_id_pbs;
		chunk_t id_b;
		r_id.isai_type = ID_NONE;

		switch (pc->spd.that.id.kind) {
		case ID_DER_ASN1_DN:
			r_id.isai_type = ID_DER_ASN1_DN;
			break;
		case ID_FQDN:
			r_id.isai_type = ID_FQDN;
			break;
		case ID_USER_FQDN:
			r_id.isai_type = ID_USER_FQDN;
			break;
		case ID_KEY_ID:
			r_id.isai_type = ID_KEY_ID;
			break;
		case ID_NULL:
			r_id.isai_type = ID_NULL;
			break;
		default:
			DBG(DBG_CONTROL, DBG_log("Not sending IDr payload for remote ID type %s",
				enum_show(&ike_idtype_names, pc->spd.that.id.kind)));
			break;
		}

		if (r_id.isai_type != ID_NONE) {
			v2_build_id_payload(&r_id,
				 &id_b,
				 &pc->spd.that);
			r_id.isai_np = ic ? ISAKMP_NEXT_v2N : ISAKMP_NEXT_v2AUTH;

			if (!out_struct(&r_id, &ikev2_id_r_desc, &sk.pbs,
				&r_id_pbs) ||
			    !out_chunk(id_b, &r_id_pbs, "IDr"))
				return STF_INTERNAL_ERROR;

			close_output_pbs(&r_id_pbs);
		}
	}

	if (ic) {
		libreswan_log("sending INITIAL_CONTACT");
		if (!emit_v2N(v2N_INITIAL_CONTACT, &sk.pbs))
			return STF_INTERNAL_ERROR;
	} else {
		DBG(DBG_CONTROL, DBG_log("not sending INITIAL_CONTACT"));
	}

	/* send out the AUTH payload */
	chunk_t null_auth;	/* we must free this */

	stf_status authstat = ikev2_send_auth(pc, cst, ORIGINAL_INITIATOR, 0,
					      idhash, &sk.pbs, &null_auth);
	if (authstat != STF_OK) {
		freeanychunk(null_auth);
		return authstat;
	}

	if (need_configuration_payload(pc, pst->hidden_variables.st_nat_traversal)) {
		stf_status cpstat = ikev2_send_cp(pst, ISAKMP_NEXT_v2SA,
						  &sk.pbs);
		if (cpstat != STF_OK) {
			freeanychunk(null_auth);
			return cpstat;
		}
	}

	/*
	 * Switch to first pending child request for this host pair.
	 * ??? Why so late in this game?
	 *
	 * Then emit SA2i, TSi and TSr and NOTIFY payloads related
	 * to the IPsec SA.
	 */

	/* so far child's connection is same as parent's */
	passert(pc == cst->st_connection);

	lset_t policy = pc->policy;

	/* child connection */
	struct connection *cc = first_pending(pst, &policy, &cst->st_whack_sock);

	if (cc == NULL) {
		cc = pc;
		DBG(DBG_CONTROL, DBG_log("no pending CHILD SAs found for %s Reauthentication so use the original policy",
			cc->name));
	}

	if (cc != cst->st_connection) {
		/* ??? DBG_long not conditional on some DBG selector */
		char cib[CONN_INST_BUF];
		DBG_log("Switching Child connection for #%lu to \"%s\"%s from \"%s\"%s",
				cst->st_serialno, cc->name,
				fmt_conn_instance(cc, cib),
				pc->name, fmt_conn_instance(pc, cib));
	}
	/* ??? this seems very late to change the connection */
	cst->st_connection = cc;	/* safe: from duplicate_state */

	/* code does not support AH+ESP, which not recommended as per RFC 8247 */
	struct ipsec_proto_info *proto_info
		= ikev2_child_sa_proto_info(cst, cc->policy);
	proto_info->our_spi = ikev2_child_sa_spi(&cc->spd, cc->policy);
	const chunk_t local_spi = CHUNKO(proto_info->our_spi);

	/*
	 * A CHILD_SA established during an AUTH exchange does
	 * not propose DH - the IKE SA's SKEYSEED is always
	 * used.
	 */
	struct ikev2_proposals *child_proposals =
		get_v2_ike_auth_child_proposals(cc, "IKE SA initiator emitting ESP/AH proposals");
	if (!ikev2_emit_sa_proposals(&sk.pbs, child_proposals,
				     &local_spi)) {
		freeanychunk(null_auth);
		return STF_INTERNAL_ERROR;
	}

	cst->st_ts_this = ikev2_end_to_ts(&cc->spd.this);
	cst->st_ts_that = ikev2_end_to_ts(&cc->spd.that);

	v2_emit_ts_payloads(pexpect_child_sa(cst), &sk.pbs, cc);

	if ((cc->policy & POLICY_TUNNEL) == LEMPTY) {
		DBG(DBG_CONTROL, DBG_log("Initiator child policy is transport mode, sending v2N_USE_TRANSPORT_MODE"));
		/* In v2, for parent, protoid must be 0 and SPI must be empty */
		if (!emit_v2N(v2N_USE_TRANSPORT_MODE, &sk.pbs)) {
			freeanychunk(null_auth);
			return STF_INTERNAL_ERROR;
		}
	} else {
		DBG(DBG_CONTROL, DBG_log("Initiator child policy is tunnel mode, NOT sending v2N_USE_TRANSPORT_MODE"));
	}

	if (!emit_v2N_compression(cst, true, &sk.pbs)) {
		freeanychunk(null_auth);
		return STF_INTERNAL_ERROR;
	}

	if (cc->send_no_esp_tfc) {
		if (!emit_v2N(v2N_ESP_TFC_PADDING_NOT_SUPPORTED, &sk.pbs)) {
			freeanychunk(null_auth);
			return STF_INTERNAL_ERROR;
		}
	}

	if (LIN(POLICY_MOBIKE, cc->policy)) {
		cst->st_sent_mobike = pst->st_sent_mobike = TRUE;
		if (!emit_v2N(v2N_MOBIKE_SUPPORTED, &sk.pbs)) {
			freeanychunk(null_auth);
			return STF_INTERNAL_ERROR;
		}
	}
	if (pst->st_seen_ppk) {
		pb_stream ppks;

		if (!emit_v2Npl(v2N_PPK_IDENTITY, &sk.pbs, &ppks) ||
		    !emit_unified_ppk_id(&ppk_id_p, &ppks)) {
			freeanychunk(null_auth);
			return STF_INTERNAL_ERROR;
		}
		close_output_pbs(&ppks);

		if (!LIN(POLICY_PPK_INSIST, cc->policy)) {
			ikev2_calc_no_ppk_auth(cc, pst, idhash_npa,
				&pst->st_no_ppk_auth);
			if (!emit_v2Nchunk(v2N_NO_PPK_AUTH, &pst->st_no_ppk_auth,
					&sk.pbs)) {
				freeanychunk(null_auth);
				return STF_INTERNAL_ERROR;
			}
		}
	}

	if (null_auth.ptr != NULL) {
		if (!emit_v2Nchunk(v2N_NULL_AUTH, &null_auth, &sk.pbs)) {
			freeanychunk(null_auth);
			return STF_INTERNAL_ERROR;
		}
		freeanychunk(null_auth);
	}

	/* send CP payloads */
	if (pc->modecfg_domains != NULL || pc->modecfg_dns != NULL) {
		ikev2_send_cp(pst, ISAKMP_NEXT_v2NONE, &sk.pbs);
	}

	if (!close_v2SK_payload(&sk)) {
		return STF_INTERNAL_ERROR;
	}
	close_output_pbs(&rbody);
	close_output_pbs(&reply_stream);

	/*
	 * For AUTH exchange, store the message in the IKE SA.  The
	 * attempt to create the CHILD SA could have failed.
	 */
	return record_outbound_v2SK_msg(&sk.ike->sa, md,
					&reply_stream, &sk,
					"sending IKE_AUTH request");
}

#ifdef XAUTH_HAVE_PAM

static xauth_callback_t ikev2_pam_continue;	/* type assertion */

static void ikev2_pam_continue(struct state *st,
			       struct msg_digest **mdp,
			       const char *name UNUSED,
			       bool success)
{
	stf_status stf;
	if (success) {
		stf = ikev2_parent_inI2outR2_auth_tail(st, *mdp, success);
	} else {
		stf = STF_FAIL + v2N_AUTHENTICATION_FAILED;
	}

	/* replace (*mdp)->st with st ... */
	complete_v2_state_transition((*mdp)->st, mdp, stf);
}

/*
 * In the middle of IKEv2 AUTH exchange, the AUTH payload is verified succsfully.
 * Now invoke the PAM helper to authorize connection (based on name only, not password)
 * When pam helper is done state will be woken up and continue.
 *
 * This routine "suspends" MD/ST; once PAM finishes it will be
 * unsuspended.
 */

static stf_status ikev2_start_pam_authorize(struct state *st)
{
	char thatid[IDTOA_BUF];
	idtoa(&st->st_connection->spd.that.id, thatid, sizeof(thatid));
	libreswan_log("IKEv2: [XAUTH]PAM method requested to authorize '%s'",
		      thatid);
	xauth_fork_pam_process(st,
			       thatid, "password",
			       "IKEv2",
			       ikev2_pam_continue);
	return STF_SUSPEND;
}

#endif /* XAUTH_HAVE_PAM */

/*
 *
 ***************************************************************
 *                       PARENT_inI2                       *****
 ***************************************************************
 *  -
 *
 *
 */

/* STATE_PARENT_R1: I2 --> R2
 *                  <-- HDR, SK {IDi, [CERT,] [CERTREQ,]
 *                             [IDr,] AUTH, SAi2,
 *                             TSi, TSr}
 * HDR, SK {IDr, [CERT,] AUTH,
 *      SAr2, TSi, TSr} -->
 *
 * [Parent SA established]
 */

static crypto_req_cont_func ikev2_ike_sa_process_auth_request_no_skeyid_continue;	/* type asssertion */

stf_status ikev2_ike_sa_process_auth_request_no_skeyid(struct state *st,
						       struct msg_digest *md UNUSED)
{
	/* for testing only */
	if (IMPAIR(SEND_NO_IKEV2_AUTH)) {
		libreswan_log(
			"IMPAIR_SEND_NO_IKEV2_AUTH set - not sending IKE_AUTH packet");
		return STF_IGNORE;
	}

	/*
	 * the initiator sent us an encrypted payload. We need to calculate
	 * our g^xy, and skeyseed values, and then decrypt the payload.
	 */

	DBG(DBG_CONTROLMORE,
	    DBG_log("ikev2 parent inI2outR2: calculating g^{xy} in order to decrypt I2"));

	/* initiate calculation of g^xy */
	start_dh_v2(st, "ikev2_inI2outR2 KE",
		    ORIGINAL_RESPONDER,
		    NULL, NULL, &st->st_ike_spis,
		    ikev2_ike_sa_process_auth_request_no_skeyid_continue);
	return STF_SUSPEND;
}

static void ikev2_ike_sa_process_auth_request_no_skeyid_continue(struct state *st,
								 struct msg_digest **mdp,
								 struct pluto_crypto_req *r)
{
	DBG(DBG_CONTROL,
		DBG_log("ikev2_parent_inI2outR2_continue for #%lu: calculating g^{xy}, sending R2",
			st->st_serialno));

	passert(*mdp != NULL); /* IKE_AUTH request */

	/* extract calculated values from r */

	if (!finish_dh_v2(st, r, FALSE)) {
		/*
		 * Since dh failed, the channel isn't end-to-end
		 * encrypted.  Send back a clear text notify and then
		 * abandon the connection.
		 */
		DBG(DBG_CONTROL, DBG_log("aborting IKE SA: DH failed"));
		send_v2N_response_from_md(*mdp, v2N_INVALID_SYNTAX, NULL);
		/* replace (*mdp)->st with st ... */
		complete_v2_state_transition((*mdp)->st, mdp, STF_FATAL);
		return;
	}

	ikev2_process_state_packet(pexpect_ike_sa(st), st, mdp);
}

static stf_status ikev2_parent_inI2outR2_continue_tail(struct state *st,
						       struct msg_digest *md);

stf_status ikev2_ike_sa_process_auth_request(struct state *st,
					     struct msg_digest *md)
{
	/* The connection is "up", start authenticating it */

	stf_status e = ikev2_parent_inI2outR2_continue_tail(st, md);
	LSWDBGP(DBG_CONTROL, buf) {
		lswlogs(buf, "ikev2_parent_inI2outR2_continue_tail returned ");
		lswlog_v2_stf_status(buf, e);
	}

	/*
	 * if failed OE, delete state completly, no create_child_sa
	 * allowed so childless parent makes no sense. That is also
	 * the reason why we send v2N_AUTHENTICATION_FAILED, even
	 * though authenticated succeeded. It shows the remote end
	 * we have deleted the SA from our end.
	 */
	if (e >= STF_FAIL &&
	    (st->st_connection->policy & POLICY_OPPORTUNISTIC)) {
		DBG(DBG_OPPO,
			DBG_log("(pretending?) Deleting opportunistic Parent with no Child SA"));
		e = STF_FATAL;
		send_v2N_response_from_state(ike_sa(st), md,
					     v2N_AUTHENTICATION_FAILED,
					     NULL/*no data*/);
	}

	return e;
}

static stf_status ikev2_parent_inI2outR2_continue_tail(struct state *st,
						       struct msg_digest *md)
{
	struct ike_sa *ike = ike_sa(st);
	stf_status ret;
	enum ikev2_auth_method atype;

	ikev2_log_parentSA(st);

	struct state *pst = IS_CHILD_SA(md->st) ?
		state_with_serialno(md->st->st_clonedfrom) : md->st;
	/* going to switch to child st. before that update parent */
	if (!LHAS(pst->hidden_variables.st_nat_traversal, NATED_HOST))
		update_ike_endpoints(pst, md);

	nat_traversal_change_port_lookup(md, st); /* shouldn't this be pst? */

	if (!v2_decode_certs(ike, md)) {
		pexpect(ike->sa.st_sa_role == SA_RESPONDER);
		pexpect(ike->sa.st_remote_certs.verified == NULL);
		/*
		 * The 'end-cert' was bad so all the certs have been
		 * tossed.  However, since this is the responder
		 * stumble on.  There might be a connection that still
		 * authenticates (after a switch?).
		 */
		dbg("X509: CERT payload bogus or revoked");
	}
	/* this call might update connection in md->st */
	if (!ikev2_decode_peer_id(md)) {
		event_force(EVENT_SA_EXPIRE, st);
		return STF_FAIL + v2N_AUTHENTICATION_FAILED;
	}

	atype = md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type;
	if (IS_LIBUNBOUND && id_ipseckey_allowed(st, atype)) {
		ret = idi_ipseckey_fetch(md);
		if (ret != STF_OK)
			return ret;
	}

	return ikev2_parent_inI2outR2_id_tail(md);
}

stf_status ikev2_parent_inI2outR2_id_tail(struct msg_digest *md)
{
	struct state *const st = md->st;
	lset_t policy = st->st_connection->policy;
	unsigned char idhash_in[MAX_DIGEST_LEN];
	bool found_ppk = FALSE;
	bool ppkid_seen = FALSE;
	bool noppk_seen = FALSE;
	chunk_t null_auth = EMPTY_CHUNK;
	struct payload_digest *ntfy;

	/*
	 * The NOTIFY payloads we receive in the IKE_AUTH request are either
	 * related to the IKE SA, or the Child SA. Here we only process the
	 * ones related to the IKE SA.
	 */
	for (ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		switch (ntfy->payload.v2n.isan_type) {
		case v2N_PPK_IDENTITY:
		{
			struct ppk_id_payload payl;

			DBG(DBG_CONTROL, DBG_log("received PPK_IDENTITY"));
			if (ppkid_seen) {
				loglog(RC_LOG_SERIOUS, "Only one PPK_IDENTITY payload may be present");
				return STF_FATAL;
			}
			ppkid_seen = TRUE;

			if (!extract_ppk_id(&ntfy->pbs, &payl)) {
				DBG(DBG_CONTROL, DBG_log("failed to extract PPK_ID from PPK_IDENTITY payload. Abort!"));
				return STF_FATAL;
			}

			const chunk_t *ppk = get_ppk_by_id(&payl.ppk_id);
			freeanychunk(payl.ppk_id);
			if (ppk != NULL)
				found_ppk = TRUE;

			if (found_ppk && LIN(POLICY_PPK_ALLOW, policy)) {
				ppk_recalculate(ppk, st->st_oakley.ta_prf,
						&st->st_skey_d_nss,
						&st->st_skey_pi_nss,
						&st->st_skey_pr_nss,
						st->st_skey_d_nss,
						st->st_skey_pi_nss,
						st->st_skey_pr_nss);
				st->st_ppk_used = TRUE;
				libreswan_log("PPK AUTH calculated as responder");
			} else {
				libreswan_log("ignored received PPK_IDENTITY - connection does not require PPK or PPKID not found");
			}
			break;
		}

		case v2N_NO_PPK_AUTH:
		{
			pb_stream pbs = ntfy->pbs;
			size_t len = pbs_left(&pbs);

			DBG(DBG_CONTROL, DBG_log("received NO_PPK_AUTH"));
			if (noppk_seen) {
				loglog(RC_LOG_SERIOUS, "Only one NO_PPK_AUTH payload may be present");
				return STF_FATAL;
			}
			noppk_seen = TRUE;

			if (LIN(POLICY_PPK_INSIST, policy)) {
				DBG(DBG_CONTROL, DBG_log("Ignored NO_PPK_AUTH data - connection insists on PPK"));
				break;
			}

			chunk_t no_ppk_auth = alloc_chunk(len, "NO_PPK_AUTH");

			if (!in_raw(no_ppk_auth.ptr, len, &pbs, "NO_PPK_AUTH extract")) {
				loglog(RC_LOG_SERIOUS, "Failed to extract %zd bytes of NO_PPK_AUTH from Notify payload", len);
				freeanychunk(no_ppk_auth);
				return STF_FATAL;
			}
			st->st_no_ppk_auth = no_ppk_auth;
			break;
		}

		case v2N_MOBIKE_SUPPORTED:
			DBG(DBG_CONTROLMORE, DBG_log("received v2N_MOBIKE_SUPPORTED %s",
				st->st_sent_mobike ?
					"and sent" : "while it did not sent"));
			st->st_seen_mobike = TRUE;
			break;

		case v2N_NULL_AUTH:
		{
			pb_stream pbs = ntfy->pbs;
			size_t len = pbs_left(&pbs);

			DBG(DBG_CONTROL, DBG_log("received v2N_NULL_AUTH"));
			null_auth = alloc_chunk(len, "NULL_AUTH");
			if (!in_raw(null_auth.ptr, len, &pbs, "NULL_AUTH extract")) {
				loglog(RC_LOG_SERIOUS, "Failed to extract %zd bytes of NULL_AUTH from Notify payload", len);
				freeanychunk(null_auth);
				return STF_FATAL;
			}
			break;
		}
		case v2N_INITIAL_CONTACT:
			DBG(DBG_CONTROLMORE, DBG_log("received v2N_INITIAL_CONTACT"));
			st->st_seen_initialc = TRUE;
			break;

		/* Child SA related NOTIFYs are processed later in ikev2_process_ts_and_rest() */
		case v2N_USE_TRANSPORT_MODE:
		case v2N_IPCOMP_SUPPORTED:
		case v2N_ESP_TFC_PADDING_NOT_SUPPORTED:
			break;

		default:
			DBG(DBG_CONTROLMORE, DBG_log("Received unknown/unsupported notify %s - ignored",
				enum_name(&ikev2_notify_names,
					ntfy->payload.v2n.isan_type)));
			break;
		}
	}

	/*
	 * If we found proper PPK ID and policy allows PPK, use that.
	 * Otherwise use NO_PPK_AUTH
	 */
	if (found_ppk && LIN(POLICY_PPK_ALLOW, policy))
		freeanychunk(st->st_no_ppk_auth);

	if (!found_ppk && LIN(POLICY_PPK_INSIST, policy)) {
		loglog(RC_LOG_SERIOUS, "Requested PPK_ID not found and connection requires a valid PPK");
		freeanychunk(null_auth);
		return STF_FATAL;
	}

	/* calculate hash of IDi for AUTH below */
	{
		struct hmac_ctx id_ctx;
		const pb_stream *id_pbs = &md->chain[ISAKMP_NEXT_v2IDi]->pbs;
		unsigned char *idstart = id_pbs->start + NSIZEOF_isakmp_generic;
		unsigned int idlen = pbs_room(id_pbs) - NSIZEOF_isakmp_generic;

		hmac_init(&id_ctx, st->st_oakley.ta_prf, st->st_skey_pi_nss);
		DBG(DBG_CRYPT, DBG_dump("idhash verify I2", idstart, idlen));
		hmac_update(&id_ctx, idstart, idlen);
		hmac_final(idhash_in, &id_ctx);
	}

	/* process CERTREQ payload */
	if (md->chain[ISAKMP_NEXT_v2CERTREQ] != NULL) {
		DBG(DBG_CONTROLMORE,
		    DBG_log("received CERTREQ payload; going to decode it"));
		ikev2_decode_cr(md);
	}

	/* process AUTH payload */

	enum keyword_authby that_authby = st->st_connection->spd.that.authby;

	passert(that_authby != AUTH_NEVER && that_authby != AUTH_UNSET);

	if (!st->st_ppk_used && st->st_no_ppk_auth.ptr != NULL) {
		/*
		 * we didn't recalculate keys with PPK, but we found NO_PPK_AUTH
		 * (meaning that initiator did use PPK) so we try to verify NO_PPK_AUTH.
		 */
		DBG(DBG_CONTROL, DBG_log("going to try to verify NO_PPK_AUTH."));
		/* making a dummy pb_stream so we could pass it to v2_check_auth */
		pb_stream pbs_no_ppk_auth;
		pb_stream pbs = md->chain[ISAKMP_NEXT_v2AUTH]->pbs;
		size_t len = pbs_left(&pbs);
		init_pbs(&pbs_no_ppk_auth, st->st_no_ppk_auth.ptr, len, "pb_stream for verifying NO_PPK_AUTH");

		if (!v2_check_auth(md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type,
			st, ORIGINAL_RESPONDER, idhash_in, &pbs_no_ppk_auth,
			st->st_connection->spd.that.authby))
		{
			send_v2N_response_from_state(ike_sa(st), md,
						     v2N_AUTHENTICATION_FAILED,
						     NULL/*no data*/);
			freeanychunk(null_auth);	/* ??? necessary? */
			return STF_FATAL;
		}
		DBG(DBG_CONTROL, DBG_log("NO_PPK_AUTH verified"));
	} else {
		bool policy_null = LIN(POLICY_AUTH_NULL, st->st_connection->policy);
		bool policy_rsasig = LIN(POLICY_RSASIG, st->st_connection->policy);

		/* if received NULL_AUTH in Notify payload and we only allow NULL Authentication,
		 * proceed with verifying that payload, else verify AUTH normally */
		if (null_auth.ptr != NULL && policy_null && !policy_rsasig) {
			/* making a dummy pb_stream so we could pass it to v2_check_auth */
			pb_stream pbs_null_auth;
			size_t len = null_auth.len;

			DBG(DBG_CONTROL, DBG_log("going to try to verify NULL_AUTH from Notify payload"));
			init_pbs(&pbs_null_auth, null_auth.ptr, len, "pb_stream for verifying NULL_AUTH");
			if (!v2_check_auth(IKEv2_AUTH_NULL,
				st, ORIGINAL_RESPONDER, idhash_in, &pbs_null_auth,
				AUTH_NULL))
			{
				send_v2N_response_from_state(ike_sa(st), md,
							     v2N_AUTHENTICATION_FAILED,
							     NULL/*no data*/);
				freeanychunk(null_auth);
				return STF_FATAL;
			}
			DBG(DBG_CONTROL, DBG_log("NULL_AUTH verified"));
		} else {
			if (!v2_check_auth(md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type,
				st, ORIGINAL_RESPONDER, idhash_in, &md->chain[ISAKMP_NEXT_v2AUTH]->pbs,
				st->st_connection->spd.that.authby)) {
				send_v2N_response_from_state(ike_sa(st), md,
							     v2N_AUTHENTICATION_FAILED,
							     NULL/*no data*/);
				freeanychunk(null_auth);
				return STF_FATAL;
			}
		}
	}

	/* AUTH succeeded */

	freeanychunk(null_auth);

#ifdef XAUTH_HAVE_PAM
	if (st->st_connection->policy & POLICY_IKEV2_PAM_AUTHORIZE)
		return ikev2_start_pam_authorize(st);
#endif
	return ikev2_parent_inI2outR2_auth_tail(st, md, TRUE);
}

static stf_status ikev2_parent_inI2outR2_auth_tail(struct state *st,
						   struct msg_digest *md,
						   bool pam_status)
{
	struct connection *const c = st->st_connection;

	if (!pam_status) {
		/*
		 * TBD: send this notification encrypted because the
		 * AUTH payload succeed
		 */
		send_v2N_response_from_state(ike_sa(st), md,
					     v2N_AUTHENTICATION_FAILED,
					     NULL/*no data*/);
		return STF_FATAL;
	}

	/*
	 * Now create child state.
	 * As we will switch to child state, force the parent to the
	 * new state now.
	 *
	 * XXX: Danger!  md->svm points to a state transition that
	 * mashes the IKE SA's initial state in and the CHILD SA's
	 * final state.  Hence, the need to explicitly force the final
	 * IKE SA state.  There should instead be separate state
	 * transitions for the IKE and CHILD SAs and then have the IKE
	 * SA invoke the CHILD SA's transition.
 	 */
	pexpect(md->svm->next_state == STATE_V2_IPSEC_R);
	ikev2_ike_sa_established(pexpect_ike_sa(st), md->svm,
				 STATE_PARENT_R2);

#ifdef USE_LINUX_AUDIT
	linux_audit_conn(st, LAK_PARENT_START);
#endif

	if (LHAS(st->hidden_variables.st_nat_traversal, NATED_HOST)) {
		/* ensure we run keepalives if needed */
		if (c->nat_keepalive)
			nat_traversal_ka_event();
	}

	/* send response */
	if (LIN(POLICY_MOBIKE, c->policy) && st->st_seen_mobike) {
		if (c->spd.that.host_type == KH_ANY) {
			/* only allow %any connection to mobike */
			st->st_sent_mobike = TRUE;
		} else {
			libreswan_log("not responding with v2N_MOBIKE_SUPPORTED, that end is not %%any");
		}
	}

	bool send_redirect = FALSE;

	if (st->st_seen_redirect_sup &&
	    (LIN(POLICY_SEND_REDIRECT_ALWAYS, c->policy) ||
	     (!LIN(POLICY_SEND_REDIRECT_NEVER, c->policy) &&
	      require_ddos_cookies()))) {
		if (c->redirect_to == NULL) {
			loglog(RC_LOG_SERIOUS, "redirect-to is not specified, can't redirect requests");
		} else {
			send_redirect = TRUE;
		}
	}

	/* make sure HDR is at start of a clean buffer */
	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	/* HDR out */

	pb_stream rbody = open_v2_message(&reply_stream, ike_sa(st),
					  md /* response */,
					  ISAKMP_v2_IKE_AUTH);

	if (IMPAIR(ADD_UNKNOWN_PAYLOAD_TO_AUTH)) {
		if (!emit_v2UNKNOWN("IKE_AUTH reply", &rbody)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* decide to send CERT payload before we generate IDr */
	bool send_cert = ikev2_send_cert_decision(st);

	/* insert an Encryption payload header */

	v2SK_payload_t sk = open_v2SK_payload(&rbody, ike_sa(st));
	if (!pbs_ok(&sk.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	if (IMPAIR(ADD_UNKNOWN_PAYLOAD_TO_AUTH_SK)) {
		if (!emit_v2UNKNOWN("IKE_AUTH's SK reply", &sk.pbs)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* send any NOTIFY payloads */
	if (st->st_sent_mobike) {
		if (!emit_v2N(v2N_MOBIKE_SUPPORTED, &sk.pbs))
			return STF_INTERNAL_ERROR;
	}

	if (st->st_ppk_used) {
		if (!emit_v2N(v2N_PPK_IDENTITY, &sk.pbs))
			return STF_INTERNAL_ERROR;
	}

	if (send_redirect) {
		if (!emit_redirect_notification(c->redirect_to, NULL, &sk.pbs))
			return STF_INTERNAL_ERROR;

		st->st_sent_redirect = TRUE;	/* mark that we have sent REDIRECT in IKE_AUTH */
	}

	if (LIN(POLICY_TUNNEL, c->policy) == LEMPTY && st->st_seen_use_transport) {
		if (!emit_v2N(v2N_USE_TRANSPORT_MODE, &sk.pbs))
			return STF_INTERNAL_ERROR;
	}

	if (!emit_v2N_compression(st, st->st_seen_use_ipcomp, &sk.pbs))
		return STF_INTERNAL_ERROR;

	if (c->send_no_esp_tfc) {
		if (!emit_v2N(v2N_ESP_TFC_PADDING_NOT_SUPPORTED, &sk.pbs))
			return STF_INTERNAL_ERROR;
	}

	/* send out the IDr payload */
	unsigned char idhash_out[MAX_DIGEST_LEN];
	{
		struct ikev2_id r_id = {
			.isai_np = ISAKMP_NEXT_v2NONE,
			.isai_type = ID_NULL,
			/* critical bit zero */
		};
		pb_stream r_id_pbs;
		chunk_t id_b;
		struct hmac_ctx id_ctx;
		unsigned char *id_start;
		unsigned int id_len;

		hmac_init(&id_ctx, st->st_oakley.ta_prf, st->st_skey_pr_nss);
		if (st->st_peer_wants_null) {
			/* make it the Null ID */
			/* r_id already set */
			id_b = EMPTY_CHUNK;
		} else {
			v2_build_id_payload(&r_id,
					 &id_b,
					 &c->spd.this);
		}

		id_start = sk.pbs.cur + NSIZEOF_isakmp_generic;

		if (!out_struct(&r_id, &ikev2_id_r_desc, &sk.pbs,
				&r_id_pbs) ||
		    !out_chunk(id_b, &r_id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&r_id_pbs);

		/* calculate hash of IDi for AUTH below */
		id_len = sk.pbs.cur - id_start;
		DBG(DBG_CRYPT,
		    DBG_dump("idhash calc R2", id_start, id_len));
		hmac_update(&id_ctx, id_start, id_len);
		hmac_final(idhash_out, &id_ctx);
	}

	DBG(DBG_CONTROLMORE,
	    DBG_log("assembled IDr payload"));

	/*
	 * send CERT payload RFC 4306 3.6, 1.2:([CERT,] )
	 * upon which our received I2 CERTREQ is ignored,
	 * but ultimately should go into the CERT decision
	 */
	if (send_cert) {
		stf_status certstat = ikev2_send_cert(st, &sk.pbs);
		if (certstat != STF_OK)
			return certstat;
	}

	/* authentication good, see if there is a child SA being proposed */
	unsigned int auth_np;

	if (md->chain[ISAKMP_NEXT_v2SA] == NULL ||
	    md->chain[ISAKMP_NEXT_v2TSi] == NULL ||
	    md->chain[ISAKMP_NEXT_v2TSr] == NULL) {
		/* initiator didn't propose anything. Weird. Try unpending our end. */
		/* UNPEND XXX */
		if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			libreswan_log("No CHILD SA proposals received.");
		} else {
			DBG(DBG_CONTROLMORE, DBG_log("No CHILD SA proposals received"));
		}
		auth_np = ISAKMP_NEXT_v2NONE;
	} else {
		DBG(DBG_CONTROLMORE, DBG_log("CHILD SA proposals received"));
		auth_np = (c->pool != NULL && md->chain[ISAKMP_NEXT_v2CP] != NULL) ?
			ISAKMP_NEXT_v2CP : ISAKMP_NEXT_v2SA;
	}

	DBG(DBG_CONTROLMORE,
	    DBG_log("going to assemble AUTH payload"));

	/* now send AUTH payload */
	{
		stf_status authstat = ikev2_send_auth(c, st,
						      ORIGINAL_RESPONDER, auth_np,
						      idhash_out,
						      &sk.pbs, NULL);
						      /* ??? NULL - don't calculate additional NULL_AUTH ??? */

		if (authstat != STF_OK)
			return authstat;
	}

	if (auth_np == ISAKMP_NEXT_v2SA || auth_np == ISAKMP_NEXT_v2CP) {
		/* must have enough to build an CHILD_SA */
		stf_status ret = ikev2_child_sa_respond(md, &sk.pbs,
							ISAKMP_v2_IKE_AUTH);

		/* note: st: parent; md->st: child */
		if (ret != STF_OK) {
			LSWDBGP(DBG_CONTROL, buf) {
				lswlogs(buf, "ikev2_child_sa_respond returned ");
				lswlog_v2_stf_status(buf, ret);
			}
			return ret; /* we should continue building a valid reply packet */
		}
	}

	if (!close_v2SK_payload(&sk)) {
		return STF_INTERNAL_ERROR;
	}
	close_output_pbs(&rbody);
	close_output_pbs(&reply_stream);

	/*
	 * For AUTH exchange, store the message in the IKE SA.
	 * The attempt to create the CHILD SA could have
	 * failed.
	 */
	return record_outbound_v2SK_msg(&sk.ike->sa, md,
					&reply_stream, &sk,
					"replying to IKE_AUTH request");
}

stf_status ikev2_process_child_sa_pl(struct msg_digest *md,
		bool expect_accepted)
{
	struct state *st = md->st;
	struct ike_sa *ike = ike_sa(st);
	struct connection *c = st->st_connection;
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
	enum isakmp_xchg_types isa_xchg = md->hdr.isa_xchg;
	struct ipsec_proto_info *proto_info =
		ikev2_child_sa_proto_info(st, c->policy);
	stf_status ret;

	const char *what;
	struct ikev2_proposals *child_proposals;
	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA) {
		if (st->st_state == STATE_V2_CREATE_I) {
			what = "CREATE_CHILD_SA initiator accepting remote ESP/AH proposal";
		} else {
			what = "CREATE_CHILD_SA responder matching remote ESP/AH proposals";
		}
		const struct oakley_group_desc *default_dh = (c->policy & POLICY_PFS) != LEMPTY
			? ike->sa.st_oakley.ta_dh
			: &ike_alg_dh_none;
		child_proposals = get_v2_create_child_proposals(c, what, default_dh);
	} else if (expect_accepted) {
		what = "IKE_AUTH initiator accepting remote ESP/AH proposal";
		child_proposals = get_v2_ike_auth_child_proposals(c, what);
	} else {
		what = "IKE_AUTH responder matching remote ESP/AH proposals";
		child_proposals = get_v2_ike_auth_child_proposals(c, what);
	}

	ret = ikev2_process_sa_payload(what,
				       &sa_pd->pbs,
				       /*expect_ike*/ FALSE,
				       /*expect_spi*/ TRUE,
				       expect_accepted,
				       LIN(POLICY_OPPORTUNISTIC, c->policy),
				       &st->st_accepted_esp_or_ah_proposal,
				       child_proposals);

	if (ret != STF_OK) {
		LSWLOG_RC(RC_LOG_SERIOUS, buf) {
			lswlogs(buf, what);
			lswlogs(buf, " failed, responder SA processing returned ");
			lswlog_v2_stf_status(buf, ret);
		}
		/* XXX: return RET? */
		return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
	}

	DBG(DBG_CONTROL, DBG_log_ikev2_proposal(what, st->st_accepted_esp_or_ah_proposal));
	if (!ikev2_proposal_to_proto_info(st->st_accepted_esp_or_ah_proposal, proto_info)) {
		loglog(RC_LOG_SERIOUS, "%s proposed/accepted a proposal we don't actually support!", what);
		return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
	}

	/*
	 * Update/check the PFS.
	 *
	 * For the responder, go with what ever was negotiated.  For
	 * the initiator, check what was negotiated against what was
	 * sent.
	 *
	 * Because code expects .st_pfs_group to use NULL, and not
	 * &ike_alg_dh_none, to indicate no-DH algorithm, the value
	 * returned by the proposal parser needs to be patched up.
	 */
	const struct oakley_group_desc *accepted_dh =
		proto_info->attrs.transattrs.ta_dh == &ike_alg_dh_none ? NULL
		: proto_info->attrs.transattrs.ta_dh;
	switch (st->st_sa_role) {
	case SA_INITIATOR:
		pexpect(expect_accepted);
		if (accepted_dh != NULL && accepted_dh != st->st_pfs_group) {
			loglog(RC_LOG_SERIOUS,
			       "expecting %s but remote's accepted proposal includes %s",
			       st->st_pfs_group == NULL ? "no DH" : st->st_pfs_group->common.fqn,
			       accepted_dh->common.fqn);
			return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
		}
		st->st_pfs_group = accepted_dh;
		break;
	case SA_RESPONDER:
		pexpect(!expect_accepted);
		pexpect(st->st_sa_role == SA_RESPONDER);
		pexpect(st->st_pfs_group == NULL);
		st->st_pfs_group = accepted_dh;
		break;
	default:
		bad_case(st->st_sa_role);
	}

	/*
	 * Update the state's st_oakley parameters from the proposal,
	 * but retain the previous PRF.  A CHILD_SA always uses the
	 * PRF negotiated when creating initial IKE SA.
	 *
	 * XXX: The mystery is, why is .st_oakley even being updated?
	 * Perhaps it is to prop up code getting the CHILD_SA's PRF
	 * from the child when that code should use the CHILD_SA's IKE
	 * SA; or perhaps it is getting things ready for an IKE SA
	 * re-key?
	 */
	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA && st->st_pfs_group != NULL) {
		dbg("updating #%lu's .st_oakley with preserved PRF, but why update?",
			st->st_serialno);
		struct trans_attrs accepted_oakley = proto_info->attrs.transattrs;
		pexpect(accepted_oakley.ta_prf == NULL);
		accepted_oakley.ta_prf = st->st_oakley.ta_prf;
		st->st_oakley = accepted_oakley;
	}

	return ret;
}

static stf_status ikev2_process_cp_respnse(struct msg_digest *md)
{
	struct state *st = md->st;
	struct connection *c = st->st_connection;

	if (st->st_state == STATE_V2_REKEY_CHILD_I)
		return STF_OK; /* CP response is  not allowed in a REKEY response */

	if (need_configuration_payload(c, st->hidden_variables.st_nat_traversal)) {
		if (md->chain[ISAKMP_NEXT_v2CP] == NULL) {
			/* not really anything to here... but it would be worth unpending again */
			loglog(RC_LOG_SERIOUS, "missing v2CP reply, not attempting to setup child SA");
			/* Delete previous retransmission event. */
			delete_event(st);
			/*
			 * ??? this isn't really a failure, is it?
			 * If none of those payloads appeared, isn't this is a
			 * legitimate negotiation of a parent?
			 */
			return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
		}
		if (!ikev2_parse_cp_r_body(md->chain[ISAKMP_NEXT_v2CP], st))
		{
			return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
		}
	}

	return STF_OK;
}

static void ikev2_rekey_expire_pred(const struct state *st, so_serial_t pred)
{
	struct state *rst = state_with_serialno(pred);
	long lifetime = -1;

	if (rst !=  NULL && IS_V2_ESTABLISHED(rst->st_state)) {
		/* on initiator, delete st_ipsec_pred. The responder should not */
		monotime_t now = mononow();
		const struct pluto_event *ev = rst->st_event;

		if (ev != NULL)
			lifetime = monobefore(now, ev->ev_time) ?
				deltasecs(monotimediff(ev->ev_time, now)) :
				-1 * deltasecs(monotimediff(now, ev->ev_time));
	}

	libreswan_log("rekeyed #%lu %s %s remaining life %lds", pred,
			st->st_state_name,
			rst ==  NULL ? "and the state is gone" : "and expire it",
			lifetime);

	if (lifetime > EXPIRE_OLD_SA) {
		delete_event(rst);
		event_schedule_s(EVENT_SA_EXPIRE, EXPIRE_OLD_SA, rst);
	}
	/* else it should be on its way to expire no need to kick dead state */
}

static stf_status ikev2_process_ts_and_rest(struct msg_digest *md)
{
	struct child_sa *child = pexpect_child_sa(md->st);
	struct state *st = &child->sa;

	RETURN_STF_FAILURE_STATUS(ikev2_process_cp_respnse(md));
	if (!v2_process_ts_response(child, md)) {
		/*
		 * XXX: will this will cause the state machine to
		 * overwrite the AUTH part of the message - which is
		 * wrong.  XXX: does this delete the child state?
		 */
		return STF_FAIL + v2N_TS_UNACCEPTABLE;
	}

	/* examin and accpept SA ESP/AH proposals */
	if (md->hdr.isa_xchg != ISAKMP_v2_CREATE_CHILD_SA)
		RETURN_STF_FAILURE_STATUS(ikev2_process_child_sa_pl(md, TRUE));

	/* examine notification payloads for Child SA properties */
	{
		struct payload_digest *ntfy;

		for (ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
			/*
			 * https://tools.ietf.org/html/rfc7296#section-3.10.1
			 *
			 * Types in the range 0 - 16383 are intended for reporting errors.  An
			 * implementation receiving a Notify payload with one of these types
			 * that it does not recognize in a response MUST assume that the
			 * corresponding request has failed entirely.  Unrecognized error types
			 * in a request and status types in a request or response MUST be
			 * ignored, and they should be logged.
			 *
			 * No known error notify would allow us to continue, so we can fail
			 * whether the error notify is known or unknown.
			 */
			if (ntfy->payload.v2n.isan_type < v2N_INITIAL_CONTACT) {
				loglog(RC_LOG_SERIOUS, "received ERROR NOTIFY (%d): %s ",
					ntfy->payload.v2n.isan_type,
					enum_name(&ikev2_notify_names, ntfy->payload.v2n.isan_type));
				return STF_FATAL;
			}

			/* check for Child SA related NOTIFY payloads */
			switch (ntfy->payload.v2n.isan_type) {
			case v2N_USE_TRANSPORT_MODE:
			{
				if (st->st_connection->policy & POLICY_TUNNEL) {
					/* This means we did not send v2N_USE_TRANSPORT, however responder is sending it in now, seems incorrect */
					DBG(DBG_CONTROLMORE,
					    DBG_log("Initiator policy is tunnel, responder sends v2N_USE_TRANSPORT_MODE notification in inR2, ignoring it"));
				} else {
					DBG(DBG_CONTROLMORE,
					    DBG_log("Initiator policy is transport, responder sends v2N_USE_TRANSPORT_MODE, setting CHILD SA to transport mode"));
					if (st->st_esp.present) {
						st->st_esp.attrs.encapsulation
							= ENCAPSULATION_MODE_TRANSPORT;
					}
					if (st->st_ah.present) {
						st->st_ah.attrs.encapsulation
							= ENCAPSULATION_MODE_TRANSPORT;
					}
				}
				break;
			}
			case v2N_ESP_TFC_PADDING_NOT_SUPPORTED:
			{
				DBG(DBG_CONTROLMORE, DBG_log("Received ESP_TFC_PADDING_NOT_SUPPORTED - disabling TFC"));
				st->st_seen_no_tfc = TRUE;
				break;
			}
			case v2N_IPCOMP_SUPPORTED:
			{
				pb_stream pbs = ntfy->pbs;
				size_t len = pbs_left(&pbs);
				struct ikev2_notify_ipcomp_data n_ipcomp;

				DBG(DBG_CONTROLMORE, DBG_log("received v2N_IPCOMP_SUPPORTED of length %zd", len));
				if ((st->st_connection->policy & POLICY_COMPRESS) == LEMPTY) {
					loglog(RC_LOG_SERIOUS, "Unexpected IPCOMP request as our connection policy did not indicate support for it");
					return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
				}

				if (!in_struct(&n_ipcomp, &ikev2notify_ipcomp_data_desc, &pbs, NULL)) {
					return STF_FATAL;
				}

				if (n_ipcomp.ikev2_notify_ipcomp_trans != IPCOMP_DEFLATE) {
					loglog(RC_LOG_SERIOUS, "Unsupported IPCOMP compression method %d",
						n_ipcomp.ikev2_notify_ipcomp_trans); /* enum_name this later */
					return STF_FATAL;
				}

				if (n_ipcomp.ikev2_cpi < IPCOMP_FIRST_NEGOTIATED) {
					loglog(RC_LOG_SERIOUS, "Illegal IPCOMP CPI %d", n_ipcomp.ikev2_cpi);
					return STF_FATAL;
				}
				DBG(DBG_CONTROL, DBG_log("Received compression CPI=%d", n_ipcomp.ikev2_cpi));

				//st->st_ipcomp.attrs.spi = uniquify_his_cpi((ipsec_spi_t)htonl(n_ipcomp.ikev2_cpi), st, 0);
				st->st_ipcomp.attrs.spi = htonl((ipsec_spi_t)n_ipcomp.ikev2_cpi);
				st->st_ipcomp.attrs.transattrs.ta_comp = n_ipcomp.ikev2_notify_ipcomp_trans;
				st->st_ipcomp.attrs.encapsulation = ENCAPSULATION_MODE_TUNNEL; /* always? */
				st->st_ipcomp.present = TRUE;
				st->st_seen_use_ipcomp = TRUE;
				break;
			}
			default:
				DBG(DBG_CONTROLMORE,
					DBG_log("ignored received NOTIFY (%d): %s ",
						ntfy->payload.v2n.isan_type,
						enum_name(&ikev2_notify_names, ntfy->payload.v2n.isan_type)));
			}
		} /* for */
	} /* notification block */

	ikev2_derive_child_keys(child);

	/* now install child SAs */
	if (!install_ipsec_sa(st, TRUE))
		return STF_FATAL;

	set_newest_ipsec_sa("inR2", st);

	/*
	 * Delete previous retransmission event.
	 */
	delete_event(st);

	if (st->st_state == STATE_V2_REKEY_CHILD_I)
		ikev2_rekey_expire_pred(st, st->st_ipsec_pred);

	return STF_OK;
}

/*
 s
 ***************************************************************
 *                       PARENT_inR2    (I3 state)         *****
 ***************************************************************
 *  - there are no cryptographic continuations, but be certain
 *    that there will have to be DNS continuations, but they
 *    just aren't implemented yet.
 *
 */

/* STATE_PARENT_I2: R2 --> I3
 *                     <--  HDR, SK {IDr, [CERT,] AUTH,
 *                               SAr2, TSi, TSr}
 * [Parent SA established]
 *
 * For error handling in this function, please read:
 * https://tools.ietf.org/html/rfc7296#section-2.21.2
 */

stf_status ikev2_parent_inR2(struct state *st, struct msg_digest *md)
{
	struct ike_sa *ike = ike_sa(st);
	unsigned char idhash_in[MAX_DIGEST_LEN];
	struct payload_digest *ntfy;
	struct state *pst = st;
	bool got_transport = FALSE;
	ip_address redirect_ip;
	bool initiate_redirect = FALSE;

	if (IS_CHILD_SA(st))
		pst = state_with_serialno(st->st_clonedfrom);

	bool ppk_seen_identity = FALSE;
	/* Process NOTIFY payloads related to IKE SA */
	for (ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		switch (ntfy->payload.v2n.isan_type) {
		case v2N_COOKIE:
			DBG(DBG_CONTROLMORE, DBG_log("Ignoring bogus COOKIE notify in IKE_AUTH rpely"));
			break;
		case v2N_MOBIKE_SUPPORTED:
			DBG(DBG_CONTROLMORE, DBG_log("received v2N_MOBIKE_SUPPORTED %s",
						pst->st_sent_mobike ?
						"and sent" : "while it did not sent"));
			st->st_seen_mobike = pst->st_seen_mobike = TRUE;
			break;
		case v2N_PPK_IDENTITY:
			DBG(DBG_CONTROL, DBG_log("received v2N_PPK_IDENTITY, responder used PPK"));
			ppk_seen_identity = TRUE;
			break;
		case v2N_REDIRECT:
		{
			DBG(DBG_CONTROL, DBG_log("received v2N_REDIRECT in IKE_AUTH reply"));

			if (!LIN(POLICY_ACCEPT_REDIRECT_YES, st->st_connection->policy)) {
				DBG(DBG_CONTROL, DBG_log("ignoring v2N_REDIRECT, we don't allow to be redirected"));
				break;
			}

			err_t e = parse_redirect_payload(&ntfy->pbs,
							   st->st_connection->accept_redirect_to,
							   NULL,
							   &redirect_ip);
			if (e != NULL) {
				loglog(RC_LOG_SERIOUS, "warning: parsing of v2N_REDIRECT payload failed: %s", e);
			} else {
				/* initiate later, because we need to wait for AUTH succees */
				initiate_redirect = TRUE;
				st->st_connection->temp_vars.redirect_ip = redirect_ip;
			}
			break;
		}
		case v2N_ESP_TFC_PADDING_NOT_SUPPORTED:
			DBG(DBG_CONTROLMORE, DBG_log("Received ESP_TFC_PADDING_NOT_SUPPORTED - disabling TFC"));
			st->st_seen_no_tfc = TRUE; /* Technically, this should be only on the child state */
			break;
		case v2N_USE_TRANSPORT_MODE:
			DBG(DBG_CONTROLMORE, DBG_log("Received v2N_USE_TRANSPORT_MODE in IKE_AUTH reply"));
			got_transport = TRUE;
			break;
		default:
			DBG(DBG_CONTROLMORE, DBG_log("Received %s notify - ignored",
				enum_name(&ikev2_notify_names,
					ntfy->payload.v2n.isan_type)));
		}
	}

	if (!v2_decode_certs(ike, md)) {
		pexpect(ike->sa.st_sa_role == SA_INITIATOR);
		pexpect(ike->sa.st_remote_certs.verified == NULL);
		/*
		 * One of the certs was bad; no point switching
		 * initiator.
		 */
		libreswan_log("X509: CERT payload bogus or revoked");
		return STF_FAIL + v2N_AUTHENTICATION_FAILED;
	}

	/* XXX this call might change connection in md->st! */
	if (!ikev2_decode_peer_id(md)) {
		event_force(EVENT_SA_EXPIRE, st);
		return STF_FAIL + v2N_AUTHENTICATION_FAILED;
	}

	struct connection *c = st->st_connection;
	enum keyword_authby that_authby = c->spd.that.authby;

	passert(that_authby != AUTH_NEVER && that_authby != AUTH_UNSET);

	if (ppk_seen_identity) {
		if (!LIN(POLICY_PPK_ALLOW, c->policy)) {
			loglog(RC_LOG_SERIOUS, "Received PPK_IDENTITY but connection does not allow PPK");
			return STF_FATAL;
		}
	} else {
		if (LIN(POLICY_PPK_INSIST, c->policy)) {
			loglog(RC_LOG_SERIOUS, "Failed to receive PPK confirmation and connection has ppk=insist");
			send_v2N_response_from_state(ike_sa(st), md,
						     v2N_AUTHENTICATION_FAILED,
						     NULL/*no data*/);
			return STF_FATAL;
		}
	}

	/*
	 * If we sent USE_PPK and we did not receive a PPK_IDENTITY,
	 * it means the responder failed to find our PPK ID, but allowed
	 * the connection to continue without PPK by using our NO_PPK_AUTH
	 * payload. We should revert our key material to NO_PPK versions.
	 */
	if (pst->st_seen_ppk && !ppk_seen_identity && LIN(POLICY_PPK_ALLOW, c->policy)) {
		libreswan_log("Peer wants to continue without PPK - switching to NO_PPK");
		/* destroy the PPK based calculations */
		release_symkey(__func__, "st_skey_d_nss",  &pst->st_skey_d_nss);
		release_symkey(__func__, "st_skey_pi_nss", &pst->st_skey_pi_nss);
		release_symkey(__func__, "st_skey_pr_nss", &pst->st_skey_pr_nss);

		pst->st_skey_d_nss = pst->st_sk_d_no_ppk;
		pst->st_skey_pi_nss = pst->st_sk_pi_no_ppk;
		pst->st_skey_pr_nss = pst->st_sk_pr_no_ppk;
		if (pst != st) {
			release_symkey(__func__, "st_skey_d_nss",  &st->st_skey_d_nss);
			release_symkey(__func__, "st_skey_pi_nss", &st->st_skey_pi_nss);
			release_symkey(__func__, "st_skey_pr_nss", &st->st_skey_pr_nss);
			st->st_skey_d_nss = st->st_sk_d_no_ppk;
			st->st_skey_pi_nss = st->st_sk_pi_no_ppk;
			st->st_skey_pr_nss = st->st_sk_pr_no_ppk;
		}
	}

	{
		struct hmac_ctx id_ctx;
		const pb_stream *id_pbs = &md->chain[ISAKMP_NEXT_v2IDr]->pbs;
		unsigned char *idstart = id_pbs->start + NSIZEOF_isakmp_generic;
		unsigned int idlen = pbs_room(id_pbs) - NSIZEOF_isakmp_generic;

		hmac_init(&id_ctx, pst->st_oakley.ta_prf, pst->st_skey_pr_nss);

		/* calculate hash of IDr for AUTH below */
		DBG(DBG_CRYPT, DBG_dump("idhash auth R2", idstart, idlen));
		hmac_update(&id_ctx, idstart, idlen);
		hmac_final(idhash_in, &id_ctx);
	}

	/* process AUTH payload */

	if (!v2_check_auth(md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type,
		pst, ORIGINAL_INITIATOR, idhash_in, &md->chain[ISAKMP_NEXT_v2AUTH]->pbs,
		that_authby))
	{
		/*
		 * We cannot send a response as we are processing IKE_AUTH reply
		 * the RFC states we should pretend IKE_AUTH was okay, and then
		 * send an INFORMATIONAL DELETE IKE SA but we have not implemented
		 * that yet.
		 */
		return STF_FATAL;
	}
	st->st_ikev2_anon = pst->st_ikev2_anon; /* was set after duplicate_state() */

	/* AUTH succeeded */

	/*
	 * update the parent state to make sure that it knows we have
	 * authenticated properly.
	 *
	 * XXX: Danger!  md->svm points to a state transition that
	 * mashes the IKE SA's initial state in and the CHILD SA's
	 * final state.  Hence, the need to explicitly force the final
	 * IKE SA state.  There should instead be separate state
	 * transitions for the IKE and CHILD SAs and then have the IKE
	 * SA invoke the CHILD SA's transition.
	 */
	pexpect(md->svm->next_state == STATE_V2_IPSEC_I);
	ikev2_ike_sa_established(pexpect_ike_sa(pst), md->svm,
				 STATE_PARENT_I3);

#ifdef USE_LINUX_AUDIT
	linux_audit_conn(st, LAK_PARENT_START);
#endif

	if (LHAS(st->hidden_variables.st_nat_traversal, NATED_HOST)) {
		/* ensure we run keepalives if needed */
		if (c->nat_keepalive)
			nat_traversal_ka_event();
	}

	/* AUTH is ok, we can trust the notify payloads */
	if (got_transport) { /* FIXME: use new RFC logic turning this into a request, not requirement */
		if (LIN(POLICY_TUNNEL, st->st_connection->policy)) {
			loglog(RC_LOG_SERIOUS, "local policy requires Tunnel Mode but peer requires required Transport Mode");
			return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN; /* applies only to Child SA */
		}
	} else {
		if (!LIN(POLICY_TUNNEL, st->st_connection->policy)) {
			loglog(RC_LOG_SERIOUS, "local policy requires Transport Mode but peer requires required Tunnel Mode");
			return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN; /* applies only to Child SA */
		}
	}

	if (initiate_redirect) {
		st->st_redirected_in_auth = TRUE;
		event_force(EVENT_v2_REDIRECT, st);
		return STF_SUSPEND;
	}

	/* See if there is a child SA available */
	if (md->chain[ISAKMP_NEXT_v2SA] == NULL ||
	    md->chain[ISAKMP_NEXT_v2TSi] == NULL ||
	    md->chain[ISAKMP_NEXT_v2TSr] == NULL) {
		/* not really anything to here... but it would be worth unpending again */
		loglog(RC_LOG_SERIOUS, "missing v2SA, v2TSi or v2TSr: not attempting to setup child SA");
		/*
		 * Delete previous retransmission event.
		 */
		delete_event(st);
		/*
		 * ??? this isn't really a failure, is it?
		 * If none of those payloads appeared, isn't this is a
		 * legitimate negotiation of a parent?
		 * Paul: this notify is never sent because w
		 */
		return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
	}

	return ikev2_process_ts_and_rest(md);
}

static bool ikev2_rekey_child_req(struct state *st,
				  enum ikev2_sec_proto_id *rekey_protoid,
				  ipsec_spi_t *rekey_spi)
{
	struct state *rst = state_with_serialno(st->st_ipsec_pred);

	if (st->st_state != STATE_V2_REKEY_CHILD_I0)
		return TRUE;

	if (rst ==  NULL) {
		libreswan_log("Child SA to rekey #%lu vanished abort this exchange",
				st->st_ipsec_pred);
		return FALSE;
	}

	/*
	 * 1.3.3.  Rekeying Child SAs with the CREATE_CHILD_SA
	 * Exchange: The SA being rekeyed is identified by the SPI
	 * field in the Notify payload; this is the SPI the exchange
	 * initiator would expect in inbound ESP or AH packets.
	 */
	if (rst->st_esp.present) {
		*rekey_spi = rst->st_esp.our_spi;
		*rekey_protoid = PROTO_IPSEC_ESP;
	} else if (rst->st_ah.present) {
		*rekey_spi = rst->st_ah.our_spi;
		*rekey_protoid = PROTO_IPSEC_AH;
	} else {
		libreswan_log("Child SA to rekey #%lu is not ESP/AH can't rekey",
				st->st_ipsec_pred);
		return FALSE;
	}

	st->st_ts_this = rst->st_ts_this;
	st->st_ts_that = rst->st_ts_that;

	char cib[CONN_INST_BUF];

	dbg("#%lu initiate rekey request for \"%s\"%s #%lu SPI 0x%x TSi TSr",
	    st->st_serialno,
	    rst->st_connection->name,
	    fmt_conn_instance(rst->st_connection, cib),
	    rst->st_serialno, ntohl(*rekey_spi));

	ikev2_print_ts(&st->st_ts_this);
	ikev2_print_ts(&st->st_ts_that);

	return TRUE;
}

static stf_status ikev2_rekey_child_resp(struct msg_digest *md)
{
	struct state *st = md->st;  /* new child state */

	struct payload_digest *rekey_sa_payload = NULL;
	for (struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		switch (ntfy->payload.v2n.isan_type) {
		case v2N_REKEY_SA:
			if (rekey_sa_payload != NULL) {
				/* will tolerate multiple */
				loglog(RC_LOG_SERIOUS, "ignoring duplicate v2N_REKEY_SA in exchange");
				break;
			}
			dbg("received v2N_REKEY_SA");
			rekey_sa_payload = ntfy;
			break;
		default:
			/*
			 * there is another pass of notify payloads
			 * after this that will handle all other but
			 * REKEY
			 */
			break;
		}
	}

	if (rekey_sa_payload != NULL) {
		struct ike_sa *ike = ike_sa(st);
		struct ikev2_notify *rekey_notify = &rekey_sa_payload->payload.v2n;
		/*
		 * Magically switch to re-keying a CHILD SA.  XXX:
		 * Should state machine split cases based on REKEY_SA?
		 */
		change_state(st, STATE_V2_REKEY_CHILD_R);
		/*
		 * find old state to rekey
		 */
		dbg("CREATE_CHILD_SA IPsec SA rekey Protocol %s",
		    enum_show(&ikev2_protocol_names, rekey_notify->isan_protoid));

		if (rekey_notify->isan_spisize != sizeof(ipsec_spi_t)) {
			libreswan_log("CREATE_CHILD_SA IPsec SA rekey invalid spi size %u",
				      rekey_notify->isan_spisize);
			send_v2N_response_from_state(ike, md,
						     v2N_INVALID_SYNTAX,
						     NULL/*empty data*/);
			return STF_FATAL;
		}

		ipsec_spi_t spi = 0;
		if (!in_raw(&spi, sizeof(spi), &rekey_sa_payload->pbs, "SPI")) {
			send_v2N_response_from_state(ike, md,
						     v2N_INVALID_SYNTAX,
						     NULL/*empty data*/);
			return STF_INTERNAL_ERROR; /* cannot happen */
		}

		if (spi == 0) {
			libreswan_log("CREATE_CHILD_SA IPsec SA rekey contains zero SPI");
			send_v2N_response_from_state(ike, md,
						     v2N_INVALID_SYNTAX,
						     NULL/*empty data*/);
			return STF_FATAL;
		}

		if (rekey_notify->isan_protoid != PROTO_IPSEC_ESP &&
		    rekey_notify->isan_protoid != PROTO_IPSEC_AH) {
			libreswan_log("CREATE_CHILD_SA IPsec SA rekey invalid Protocol ID %s",
				      enum_show(&ikev2_protocol_names, rekey_notify->isan_protoid));
			send_v2N_spi_response_from_state(ike, md,
							 rekey_notify->isan_protoid, &spi,
							 v2N_CHILD_SA_NOT_FOUND,
							 NULL/*empty data*/);
			return STF_FATAL;
		}

		dbg("CREATE_CHILD_S to rekey IPsec SA(0x%08" PRIx32 ") Protocol %s",
		    ntohl((uint32_t) spi),
		    enum_show(&ikev2_protocol_names, rekey_notify->isan_protoid));

		/*
		 * From 1.3.3.  Rekeying Child SAs with the
		 * CREATE_CHILD_SA Exchange: The SA being rekeyed is
		 * identified by the SPI field in the [REKEY_SA]
		 * Notify payload; this is the SPI the exchange
		 * initiator would expect in inbound ESP or AH
		 * packets.
		 *
		 * From our POV, that's the outbound SPI.
		 */
		struct state *rst = find_v2_child_sa_by_outbound_spi(&ike->sa.st_ike_spis,
								     rekey_notify->isan_protoid, spi);
		if (rst == NULL) {
			libreswan_log("CREATE_CHILD_SA no such IPsec SA to rekey SA(0x%08" PRIx32 ") Protocol %s",
				      ntohl((uint32_t) spi),
				      enum_show(&ikev2_protocol_names, rekey_notify->isan_protoid));
			send_v2N_spi_response_from_state(ike, md,
							 rekey_notify->isan_protoid, &spi,
							 v2N_CHILD_SA_NOT_FOUND,
							 NULL/*empty data*/);
			return STF_FATAL;
		}

		st->st_ipsec_pred = rst->st_serialno;

		char cib[CONN_INST_BUF];
		dbg("#%lu rekey request for \"%s\"%s #%lu TSi TSr",
		    st->st_serialno,
		    rst->st_connection->name,
		    fmt_conn_instance(rst->st_connection, cib),
		    rst->st_serialno);
		ikev2_print_ts(&rst->st_ts_this);
		ikev2_print_ts(&rst->st_ts_that);
		st->st_connection = rst->st_connection;
	}

	return STF_OK;
}

static stf_status ikev2_rekey_child_copy_ts(const struct msg_digest *md)
{
	struct state *st = md->st;  /* new child state */
	struct state *rst; /* old child state being rekeyed */
	stf_status ret = STF_OK; /* if no v2N_REKEY_SA return OK */
	struct spd_route *spd;

	if (st->st_ipsec_pred == SOS_NOBODY) {
		/* this is not rekey quietly return */
		return ret;
	}

	rst = state_with_serialno(st->st_ipsec_pred);

	if (rst == NULL) {
		/* ??? RFC 7296 3.10: this notify requires protocol and SPI! */
		return STF_FAIL + v2N_CHILD_SA_NOT_FOUND;
	}

	/*
	 * RFC 7296 #2.9.2 the exact or the superset.
	 * exact is a should. Here libreswan only allow the exact.
	 * Inherit the TSi TSr from old state, IPsec SA.
	 */

	DBG(DBG_CONTROLMORE, {
		char cib[CONN_INST_BUF];

		DBG_log("#%lu inherit spd, TSi TSr, from \"%s\"%s #%lu",
			st->st_serialno,
			rst->st_connection->name,
			fmt_conn_instance(rst->st_connection, cib),
			rst->st_serialno);
	});

	spd = &rst->st_connection->spd;
	st->st_ts_this = ikev2_end_to_ts(&spd->this);
	st->st_ts_that = ikev2_end_to_ts(&spd->that);
	ikev2_print_ts(&st->st_ts_this);
	ikev2_print_ts(&st->st_ts_that);

	return ret;
}

/* once done use the same function in ikev2_parent_inR1outI2_tail too */
static stf_status ikev2_child_add_ipsec_payloads(struct msg_digest *md,
				  pb_stream *outpbs,
				  enum isakmp_xchg_types isa_xchg)
{
	bool send_use_transport;
	/* child connection */
	struct state *cst = md->st;
	struct connection *cc = cst->st_connection;

	send_use_transport = (cc->policy & POLICY_TUNNEL) == LEMPTY;

	/* ??? this code won't support AH + ESP */
	struct ipsec_proto_info *proto_info
		= ikev2_child_sa_proto_info(cst, cc->policy);
	proto_info->our_spi = ikev2_child_sa_spi(&cc->spd, cc->policy);
	chunk_t local_spi = CHUNKO(proto_info->our_spi);

	/*
	 * HACK: Use the CREATE_CHILD_SA proposal suite hopefully
	 * generated during the CHILD SA's initiation.
	 *
	 * XXX: this code should be either using get_v2...() (hard to
	 * figure out what DEFAULT_DH is) or saving the proposal in
	 * the state.
	 */
	passert(cc->v2_create_child_proposals != NULL);
	if (!ikev2_emit_sa_proposals(outpbs, cc->v2_create_child_proposals, &local_spi))
		return STF_INTERNAL_ERROR;

	ipsec_spi_t rekey_spi = 0;
	if (isa_xchg == ISAKMP_v2_CREATE_CHILD_SA) {
		/* send NONCE */

		enum ikev2_sec_proto_id rekey_protoid = PROTO_v2_RESERVED;
		if (!ikev2_rekey_child_req(cst, &rekey_protoid, &rekey_spi))
			return STF_INTERNAL_ERROR;

		struct ikev2_generic in = {
			.isag_critical = build_ikev2_critical(false),
		};
		pb_stream pb_nr;
		if (!out_struct(&in, &ikev2_nonce_desc, outpbs, &pb_nr) ||
		    !out_chunk(cst->st_ni, &pb_nr, "IKEv2 nonce"))
			return STF_INTERNAL_ERROR;
		close_output_pbs(&pb_nr);

		if (cst->st_pfs_group != NULL)  {
			if (!emit_v2KE(&cst->st_gi, cst->st_pfs_group, outpbs)) {
				return STF_INTERNAL_ERROR;
			}
		}

		if (rekey_spi != 0) {
			if (!emit_v2Nsa_pl(v2N_REKEY_SA,
					rekey_protoid, &rekey_spi,
					outpbs, NULL))
				return STF_INTERNAL_ERROR;
		}
	}

	if (rekey_spi == 0) {
		/* not rekey */
		cst->st_ts_this = ikev2_end_to_ts(&cc->spd.this);
		cst->st_ts_that = ikev2_end_to_ts(&cc->spd.that);
	}

	v2_emit_ts_payloads(pexpect_child_sa(cst), outpbs, cc);

	if (send_use_transport) {
		DBG(DBG_CONTROL, DBG_log("Initiator child policy is transport mode, sending v2N_USE_TRANSPORT_MODE"));
		if (!emit_v2N(v2N_USE_TRANSPORT_MODE, outpbs))
			return STF_INTERNAL_ERROR;
	} else {
		DBG(DBG_CONTROL, DBG_log("Initiator child policy is tunnel mode, NOT sending v2N_USE_TRANSPORT_MODE"));
	}

	if (cc->send_no_esp_tfc) {
		if (!emit_v2N(v2N_ESP_TFC_PADDING_NOT_SUPPORTED, outpbs))
			return STF_INTERNAL_ERROR;
	}
	return STF_OK;
}

static stf_status ikev2_child_add_ike_payloads(struct msg_digest *md,
					       pb_stream *outpbs)
{
	struct state *st = md->st;
	struct connection *c = st->st_connection;
	chunk_t local_nonce;
	chunk_t *local_g;

	switch (st->st_state) {
	case STATE_V2_REKEY_IKE_R:
	{
		local_g = &st->st_gr;
		local_nonce = st->st_nr;
		chunk_t local_spi = CHUNKO(st->st_ike_rekey_spis.responder);

		/* send selected v2 IKE SA */
		if (!ikev2_emit_sa_proposal(outpbs, st->st_accepted_ike_proposal,
					    &local_spi)) {
			DBG(DBG_CONTROL, DBG_log("problem emitting accepted ike proposal in CREATE_CHILD_SA"));
			return STF_INTERNAL_ERROR;
		}
		break;
	}
	case STATE_V2_REKEY_IKE_I0:
	{
		local_g = &st->st_gi;
		local_nonce = st->st_ni;
		chunk_t local_spi = CHUNKO(st->st_ike_rekey_spis.initiator);

		struct ikev2_proposals *ike_proposals =
			get_v2_ike_proposals(c, "IKE SA initiating rekey");

		/* send v2 IKE SAs*/
		if (!ikev2_emit_sa_proposals(outpbs, ike_proposals, &local_spi))  {
			libreswan_log("outsa fail");
			DBG(DBG_CONTROL, DBG_log("problem emitting connection ike proposals in CREATE_CHILD_SA"));
			return STF_INTERNAL_ERROR;
		}
		break;
	}
	default:
		bad_case(st->st_state);
	}

	/* send NONCE */
	{
		struct ikev2_generic in = {
			.isag_critical = build_ikev2_critical(false),
		};
		pb_stream nr_pbs;
		if (!out_struct(&in, &ikev2_nonce_desc, outpbs, &nr_pbs) ||
		    !out_chunk(local_nonce, &nr_pbs, "IKEv2 nonce"))
			return STF_INTERNAL_ERROR;
		close_output_pbs(&nr_pbs);
	}

	if (!emit_v2KE(local_g, st->st_oakley.ta_dh, outpbs))
		return STF_INTERNAL_ERROR;

	return STF_OK;
}

/*
 * initiator received Rekey IKE SA (RFC 7296 1.3.3) response
 */

static crypto_req_cont_func ikev2_child_ike_inR_continue;

stf_status ikev2_child_ike_inR(struct state *st /* child state */,
				   struct msg_digest *md)
{
	struct state *pst = state_with_serialno(st->st_clonedfrom);
	passert(pst != NULL);
	struct connection *c = st->st_connection;

	/* Ni in */
	RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_nr, "Nr"));

	/* Get the proposals ready.  */
	struct ikev2_proposals *ike_proposals =
		get_v2_ike_proposals(c, "IKE SA accept response to rekey");

	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
	stf_status ret = ikev2_process_sa_payload("IKE initiator (accepting)",
						  &sa_pd->pbs,
						  /*expect_ike*/ TRUE,
						  /*expect_spi*/ TRUE,
						  /*expect_accepted*/ TRUE,
						  LIN(POLICY_OPPORTUNISTIC, c->policy),
						  &st->st_accepted_ike_proposal,
						  ike_proposals);
	if (ret != STF_OK) {
		dbg("failed to accept IKE SA, REKEY, response, in process_ike_rekey_sa_pl_response");
		return ret;
	}

	DBG(DBG_CONTROL, DBG_log_ikev2_proposal("accepted IKE proposal",
						st->st_accepted_ike_proposal));
	if (!ikev2_proposal_to_trans_attrs(st->st_accepted_ike_proposal,
					   &st->st_oakley)) {
		loglog(RC_LOG_SERIOUS, "IKE responder accepted an unsupported algorithm");
		/* free early return items */
		free_ikev2_proposal(&st->st_accepted_ike_proposal);
		passert(st->st_accepted_ike_proposal == NULL);
		md->st = pst;
		return STF_FAIL;
	}

	 /* KE in */
	if (!accept_KE(&st->st_gr, "Gr", st->st_oakley.ta_dh,
		       md->chain[ISAKMP_NEXT_v2KE])) {
		/*
		 * XXX: Initiator so returning this notification will
		 * go no where.  Need to check RFC for what to do
		 * next.  The packet is trusted but the re-key has
		 * failed.
		 */
		return STF_FAIL + v2N_INVALID_SYNTAX;
	}

	/* fill in the missing responder SPI */
	passert(!ike_spi_is_zero(&st->st_ike_rekey_spis.initiator));
	passert(ike_spi_is_zero(&st->st_ike_rekey_spis.responder));
	ikev2_copy_cookie_from_sa(st->st_accepted_ike_proposal,
				  &st->st_ike_rekey_spis.responder);

	/* initiate calculation of g^xy for rekey */
	start_dh_v2(st, "DHv2 for IKE sa rekey initiator",
		    ORIGINAL_INITIATOR,
		    pst->st_skey_d_nss, /* only IKE has SK_d */
		    pst->st_oakley.ta_prf, /* for IKE/ESP/AH */
		    &st->st_ike_rekey_spis,
		    ikev2_child_ike_inR_continue);
	return STF_SUSPEND;
}

static void ikev2_child_ike_inR_continue(struct state *st,
					 struct msg_digest **mdp,
					 struct pluto_crypto_req *r)
{
	pexpect(st->st_state == STATE_V2_REKEY_IKE_I);

	pexpect(IS_CHILD_SA(st)); /* not yet emancipated */
	pexpect(st->st_sa_role == SA_INITIATOR);
	pexpect(*mdp != NULL);
	pexpect(v2_msg_role(*mdp) == MESSAGE_RESPONSE);
	pexpect((*mdp)->st == st);

	dbg("%s for #%lu %s",
	     __func__, st->st_serialno, st->st_state_name);

	/* and a parent? */
	struct ike_sa *ike = ike_sa(st);
	if (ike == NULL) {
		PEXPECT_LOG("sponsoring child state #%lu has no parent state #%lu",
			    st->st_serialno, st->st_clonedfrom);
		/* XXX: release what? */
		return;
	}
	passert(ike != NULL);

	stf_status e = STF_OK;
	bool only_shared_false = false;
	if (!finish_dh_v2(st, r, only_shared_false)) {
		/*
		 * XXX: this is the initiator so returning a
		 * notification is kind of useless.
		 */
		e = STF_FAIL + v2N_INVALID_SYNTAX;
	}
	if (e == STF_OK) {
		ikev2_rekey_expire_pred(st, st->st_ike_pred);
		e = STF_OK;
	}

	complete_v2_state_transition(st, mdp, e);
}

/*
 * initiator received a create Child SA Response (RFC 7296 1.3.1, 1.3.2)
 */

static dh_callback ikev2_child_inR_continue;

stf_status ikev2_child_inR(struct state *st, struct msg_digest *md)
{
	RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_nr, "Nr"));

	RETURN_STF_FAILURE_STATUS(ikev2_process_child_sa_pl(md, TRUE));

	/* XXX: only for rekey child? */
	if (st->st_pfs_group == NULL)
		return ikev2_process_ts_and_rest(md);

	/*
	 * This is the initiator, accept responder's KE.
	 *
	 * XXX: Above checks st_pfs_group but this uses
	 * st_oakley.ta_dh, presumably they are the same? Lets find
	 * out.
	 */
	pexpect(st->st_oakley.ta_dh == st->st_pfs_group);
	if (!accept_KE(&st->st_gr, "Gr", st->st_oakley.ta_dh,
		       md->chain[ISAKMP_NEXT_v2KE])) {
		/*
		 * XXX: Initiator so this notification result is going
		 * no where.  What should happen?
		 */
		return STF_FAIL + v2N_INVALID_SYNTAX; /* XXX: STF_FATAL? */
	}
	chunk_t remote_ke = st->st_gr;

	/*
	 * XXX: other than logging, these two cases are identical.
	 */
	const char *desc;
	switch (st->st_state) {
	case STATE_V2_CREATE_I:
		desc = "ikev2 Child SA initiator pfs=yes";
		break;
	case STATE_V2_REKEY_CHILD_I:
		desc = "ikev2 Child Rekey SA initiator pfs=yes";
		break;
	default:
		bad_case(st->st_state);
	}
	submit_dh(st, remote_ke, ikev2_child_inR_continue, desc);
	return STF_SUSPEND;
}

static stf_status ikev2_child_inR_continue(struct state *st,
					   struct msg_digest *md)
{
	/*
	 * XXX: Should this routine be split so that each instance
	 * handles only one state transition.  If there's commonality
	 * then the per-transition functions can all call common code.
	 */
	pexpect(st->st_state == STATE_V2_CREATE_I ||
		st->st_state == STATE_V2_REKEY_CHILD_I);

	/* initiator getting back an answer */
	pexpect(IS_CHILD_SA(st));
	pexpect(st->st_sa_role == SA_INITIATOR);
	pexpect(md != NULL);
	pexpect(md->st == st);
	pexpect(v2_msg_role(md) == MESSAGE_RESPONSE);

	dbg("%s for #%lu %s",
	     __func__, st->st_serialno, st->st_state_name);

	/* and a parent? */
	if (ike_sa(st) == NULL) {
		PEXPECT_LOG("sponsoring child state #%lu has no parent state #%lu",
			    st->st_serialno, st->st_clonedfrom);
		/* XXX: release what? */
		return STF_FATAL;
	}

	if (st->st_shared_nss == NULL) {
		/*
		 * XXX: this is the initiator so returning a
		 * notification is kind of useless.
		 */
		return STF_FAIL + v2N_INVALID_SYNTAX;
	}

	return ikev2_process_ts_and_rest(md);
}

/*
 * processing a new Child SA (RFC 7296 1.3.1 or 1.3.3) request
 */

static crypto_req_cont_func ikev2_child_inIoutR_continue;

stf_status ikev2_child_inIoutR(struct state *st /* child state */,
			       struct msg_digest *md)
{
	struct state *pst = state_with_serialno(st->st_clonedfrom);

	passert(pst != NULL);

	freeanychunk(st->st_ni); /* this is from the parent. */
	freeanychunk(st->st_nr); /* this is from the parent. */

	/* Ni in */
	RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_ni, "Ni"));

	RETURN_STF_FAILURE_STATUS(ikev2_process_child_sa_pl(md, FALSE));

	/*
	 * KE in with old(pst) and matching accepted_oakley from
	 * proposals
	 *
	 * XXX: does this code need to insist that the IKE SA
	 * replacement has KE or has SA processor handled that by only
	 * accepting a proposal with KE?
	 */
 	if (st->st_pfs_group != NULL) {
		pexpect(st->st_oakley.ta_dh == st->st_pfs_group);
		if (!accept_KE(&st->st_gi, "Gi", st->st_oakley.ta_dh,
			       md->chain[ISAKMP_NEXT_v2KE])) {
			send_v2N_response_from_state(ike_sa(st), md,
						     v2N_INVALID_SYNTAX,
						     NULL/*no data*/);
			return STF_FATAL;
		}
	}

	/* check N_REKEY_SA in the negotation */
	RETURN_STF_FAILURE_STATUS(ikev2_rekey_child_resp(md));

	if (st->st_ipsec_pred == SOS_NOBODY) {
		/* state m/c created CHILD SA */
		passert(st != NULL);
		passert(st == md->st);
		if (!v2_process_ts_request(pexpect_child_sa(st), md)) {
			return STF_FAIL + v2N_TS_UNACCEPTABLE;
		}
	}

	/*
	 * XXX: a quick eyeball suggests that the only difference
	 * between these two cases is the description.
	 *
	 * ??? if we don't have an md (see above) why are we referencing it?
	 * ??? clang 6.0.0 warns md might be NULL
	 *
	 * XXX: 'see above' is lost; this is a responder state
	 * which _always_ has an MD.
	 */
	switch (st->st_state) {
	case STATE_V2_CREATE_R:
		if (md->chain[ISAKMP_NEXT_v2KE] != NULL) {
			request_ke_and_nonce("Child Responder KE and nonce nr",
					     st, st->st_oakley.ta_dh,
					     ikev2_child_inIoutR_continue);
		} else {
			request_nonce("Child Responder nonce nr",
				      st, ikev2_child_inIoutR_continue);
		}
		return STF_SUSPEND;
	case STATE_V2_REKEY_CHILD_R:
		if (md->chain[ISAKMP_NEXT_v2KE] != NULL) {
			request_ke_and_nonce("Child Rekey Responder KE and nonce nr",
					     st, st->st_oakley.ta_dh,
					     ikev2_child_inIoutR_continue);
		} else {
			request_nonce("Child Rekey Responder nonce nr",
				      st, ikev2_child_inIoutR_continue);
		}
		return STF_SUSPEND;
	default:
		bad_case(st->st_state);
	}
}

static void ikev2_child_inIoutR_continue_continue(struct state *st,
						  struct msg_digest **mdp,
						  struct pluto_crypto_req *r);

static void ikev2_child_inIoutR_continue(struct state *st,
					 struct msg_digest **mdp,
					 struct pluto_crypto_req *r)
{
	/*
	 * XXX: Should this routine be split so that each instance
	 * handles only one state transition.  If there's commonality
	 * then the per-transition functions can all call common code.
	 *
	 * Instead of computing the entire DH as a single crypto task,
	 * does a second continue. Yuck!
	 */
	pexpect(st->st_state == STATE_V2_CREATE_R ||
		st->st_state == STATE_V2_REKEY_CHILD_R);

	/* responder processing request */
	pexpect(IS_CHILD_SA(st));
	pexpect(st->st_sa_role == SA_RESPONDER);
	pexpect(*mdp != NULL);
	pexpect((*mdp)->st == st);

	dbg("%s for #%lu %s",
	     __func__, st->st_serialno, st->st_state_name);

	/* and a parent? */
	struct ike_sa *ike = ike_sa(st);
	if (ike == NULL) {
		PEXPECT_LOG("sponsoring child state #%lu has no parent state #%lu",
			    st->st_serialno, st->st_clonedfrom);
		/* XXX: release what? */
		return;
	}

	stf_status e = STF_OK;
	unpack_nonce(&st->st_nr, r);
	if (r->pcr_type == pcr_build_ke_and_nonce) {
		pexpect((*mdp)->chain[ISAKMP_NEXT_v2KE] != NULL);
		unpack_KE_from_helper(st, r, &st->st_gr);
		/* initiate calculation of g^xy */
		start_dh_v2(st, "DHv2 for child sa", ORIGINAL_RESPONDER,
			    ike->sa.st_skey_d_nss, /* only IKE has SK_d */
			    ike->sa.st_oakley.ta_prf, /* for IKE/ESP/AH */
			    &st->st_ike_spis, /* ignored */
			    ikev2_child_inIoutR_continue_continue);
		e = STF_SUSPEND;
	}
	if (e == STF_OK) {
		e = ikev2_child_out_tail(*mdp);
	}

	complete_v2_state_transition(st, mdp, e);
}

static void ikev2_child_inIoutR_continue_continue(struct state *st,
						  struct msg_digest **mdp,
						  struct pluto_crypto_req *r)
{
	/*
	 * XXX: Should this routine be split so that each instance
	 * handles only one state transition.  If there's commonality
	 * then the per-transition functions can all call common code.
	 */
	pexpect(st->st_state == STATE_V2_CREATE_R ||
		st->st_state == STATE_V2_REKEY_CHILD_R);

	/* 'child' responding to request */
	passert(*mdp != NULL);
	pexpect((*mdp)->st == st);
	passert(st->st_sa_role == SA_RESPONDER);
	passert(v2_msg_role(*mdp) == MESSAGE_REQUEST);
	pexpect(IS_CHILD_SA(st)); /* not yet emancipated */

	dbg("%s for #%lu %s",
	     __func__, st->st_serialno, st->st_state_name);

	/* didn't loose parent? */
	if (ike_sa(st) == NULL) {
		PEXPECT_LOG("sponsoring child state #%lu has no parent state #%lu",
			    st->st_serialno, st->st_clonedfrom);
		/* XXX: release child? */
		return;
	}

	stf_status e = STF_OK;
	bool only_shared_true = true;
	pexpect(r->pcr_type == pcr_compute_dh_v2);
	if (!finish_dh_v2(st, r, only_shared_true)) {
		send_v2N_response_from_state(ike_sa(st), *mdp,
					     v2N_INVALID_SYNTAX, NULL);
		e = STF_FATAL;
	}
	if (e == STF_OK) {
		e = ikev2_child_out_tail(*mdp);
	}
	complete_v2_state_transition(st, mdp, e);
}

/*
 * processsing a new Rekey IKE SA (RFC 7296 1.3.2) request
 */

static crypto_req_cont_func ikev2_child_ike_inIoutR_continue;

stf_status ikev2_child_ike_inIoutR(struct state *st /* child state */,
				   struct msg_digest *md)
{
	struct state *pst = state_with_serialno(st->st_clonedfrom);
	passert(pst != NULL);
	struct connection *c = st->st_connection;

	/* child's role could be different from original ike role, of pst; */
	st->st_original_role = ORIGINAL_RESPONDER;

	freeanychunk(st->st_ni); /* this is from the parent. */
	freeanychunk(st->st_nr); /* this is from the parent. */

	/* Ni in */
	RETURN_STF_FAILURE(accept_v2_nonce(md, &st->st_ni, "Ni"));

	/* Get the proposals ready.  */
	struct ikev2_proposals *ike_proposals =
		get_v2_ike_proposals(c, "IKE SA responding to rekey");

	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
	stf_status ret = ikev2_process_sa_payload("IKE Rekey responder child",
						  &sa_pd->pbs,
						  /*expect_ike*/ TRUE,
						  /*expect_spi*/ TRUE,
						  /*expect_accepted*/ FALSE,
						  LIN(POLICY_OPPORTUNISTIC, c->policy),
						  &st->st_accepted_ike_proposal,
						  ike_proposals);
	if (ret != STF_OK)
		return ret;

	DBG(DBG_CONTROL, DBG_log_ikev2_proposal("accepted IKE proposal",
						st->st_accepted_ike_proposal));

	if (!ikev2_proposal_to_trans_attrs(st->st_accepted_ike_proposal,
					   &st->st_oakley)) {
		loglog(RC_LOG_SERIOUS, "IKE responder accepted an unsupported algorithm");
		/*
		 * XXX; where is 'st' freed?  Should the code instead
		 * tunnel back md.st==st and return STF_FATAL which
		 * will delete the child state?  Or perhaps there a
		 * lurking SO_DISPOSE to clean it up?
		 */
		md->st = pst;
		return STF_IGNORE;
	}

	if (v2_reject_wrong_ke_for_proposal(st/*encrypt*/, md, st->st_oakley.ta_dh)) {
		/*
		 * XXX; where is 'st' freed?  Should the code instead
		 * tunnel back md.st==st and return STF_FATAL which
		 * will delete the child state?  Or perhaps there a
		 * lurking SO_DISPOSE to clean it up?
		 */
		md->st = pst;
		return STF_FAIL; /* XXX; STF_FATAL? */
	}

	/*
	 * Check and read the KE contents.
	 *
	 * responder, so accept initiator's KE in with new
	 * accepted_oakley for IKE.
	 */
	pexpect(st->st_oakley.ta_dh != NULL);
	pexpect(st->st_pfs_group == NULL);
	if (!accept_KE(&st->st_gi, "Gi", st->st_oakley.ta_dh,
		       md->chain[ISAKMP_NEXT_v2KE])) {
		send_v2N_response_from_state(ike_sa(st), md,
					     v2N_INVALID_SYNTAX,
					     NULL/*no data*/);
		return STF_FATAL;
	}

	request_ke_and_nonce("IKE rekey KE response gir", st,
			     st->st_oakley.ta_dh,
			     ikev2_child_ike_inIoutR_continue);
	return STF_SUSPEND;
}

static void ikev2_child_ike_inIoutR_continue_continue(struct state *st,
						      struct msg_digest **mdp,
						      struct pluto_crypto_req *r);

static void ikev2_child_ike_inIoutR_continue(struct state *st,
					     struct msg_digest **mdp,
					     struct pluto_crypto_req *r)
{
	pexpect(st->st_state == STATE_V2_REKEY_IKE_R);

	/* responder processing request */
	pexpect(IS_CHILD_SA(st)); /* not yet emancipated */
	pexpect(st->st_sa_role == SA_RESPONDER);
	pexpect(*mdp != NULL);
	pexpect((*mdp)->st == st);
	pexpect(v2_msg_role(*mdp) == MESSAGE_REQUEST);

	dbg("%s for #%lu %s",
	     __func__, st->st_serialno, st->st_state_name);

	/* and a parent? */
	struct ike_sa *ike = ike_sa(st);
	if (ike == NULL) {
		PEXPECT_LOG("sponsoring child state #%lu has no parent state #%lu",
			    st->st_serialno, st->st_clonedfrom);
		/* XXX: release what? */
		return;
	}
	passert(ike != NULL);

	pexpect(r->pcr_type == pcr_build_ke_and_nonce);
	pexpect((*mdp)->chain[ISAKMP_NEXT_v2KE] != NULL);
	unpack_nonce(&st->st_nr, r);
	unpack_KE_from_helper(st, r, &st->st_gr);

	/* initiate calculation of g^xy */
	passert(ike_spi_is_zero(&st->st_ike_rekey_spis.initiator));
	passert(ike_spi_is_zero(&st->st_ike_rekey_spis.responder));
	ikev2_copy_cookie_from_sa(st->st_accepted_ike_proposal,
				  &st->st_ike_rekey_spis.initiator);
	st->st_ike_rekey_spis.responder = ike_responder_spi(&(*mdp)->sender);
	start_dh_v2(st, "DHv2 for REKEY IKE SA", ORIGINAL_RESPONDER,
		    ike->sa.st_skey_d_nss, /* only IKE has SK_d */
		    ike->sa.st_oakley.ta_prf, /* for IKE/ESP/AH */
		    &st->st_ike_rekey_spis,
		    ikev2_child_ike_inIoutR_continue_continue);

	complete_v2_state_transition(st, mdp, STF_SUSPEND);
}

static void ikev2_child_ike_inIoutR_continue_continue(struct state *st,
						      struct msg_digest **mdp,
						      struct pluto_crypto_req *r)
{
	pexpect(st->st_state == STATE_V2_REKEY_IKE_R);

	/* 'child' responding to request */
	passert(*mdp != NULL);
	pexpect((*mdp)->st == st);
	passert(st->st_sa_role == SA_RESPONDER);
	passert(v2_msg_role(*mdp) == MESSAGE_REQUEST);
	pexpect(IS_CHILD_SA(st)); /* not yet emancipated */

	dbg("%s for #%lu %s",
	     __func__, st->st_serialno, st->st_state_name);

	/* didn't loose parent? */
	if (ike_sa(st) == NULL) {
		PEXPECT_LOG("sponsoring child state #%lu has no parent state #%lu",
			    st->st_serialno, st->st_clonedfrom);
		/* XXX: release child? */
		return;
	}

	stf_status e = STF_OK;
	pexpect(r->pcr_type == pcr_compute_dh_v2);
	bool only_shared_false = false;
	if (!finish_dh_v2(st, r, only_shared_false)) {
		send_v2N_response_from_state(ike_sa(st), *mdp,
					     v2N_INVALID_SYNTAX, NULL);
		e = STF_FATAL;
	}
	if (e == STF_OK) {
		e = ikev2_child_out_tail(*mdp);
	}

	complete_v2_state_transition(st, mdp, e);
}

static stf_status ikev2_child_out_tail(struct msg_digest *md)
{
	struct state *st = md->st;
	struct state *pst = state_with_serialno(st->st_clonedfrom);
	stf_status ret;

	passert(pst != NULL);

	ikev2_log_parentSA(st);

	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer), "reply packet");

	/* HDR out Start assembling respone message */

	pb_stream rbody = open_v2_message(&reply_stream, ike_sa(st),
					  IS_CHILD_SA_RESPONDER(st) ? md : NULL,
					  ISAKMP_v2_CREATE_CHILD_SA);
	if (!IS_CHILD_SA_RESPONDER(st)) {
		/* store it to match response */
		st->st_msgid = pst->st_msgid_nextuse;
	}

	/* insert an Encryption payload header */

	v2SK_payload_t sk = open_v2SK_payload(&rbody, ike_sa(pst));
	if (!pbs_ok(&sk.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	switch (st->st_state) {
	case STATE_V2_REKEY_IKE_R:
	case STATE_V2_REKEY_IKE_I0:
		ret = ikev2_child_add_ike_payloads(md, &sk.pbs);
		break;
	case STATE_V2_CREATE_I0:
	case STATE_V2_REKEY_CHILD_I0:
		ret = ikev2_child_add_ipsec_payloads(md, &sk.pbs,
				ISAKMP_v2_CREATE_CHILD_SA);
		break;
	default:
		/* ??? which states are actually correct? */
		RETURN_STF_FAILURE_STATUS(ikev2_rekey_child_copy_ts(md));
		ret = ikev2_child_sa_respond(md, &sk.pbs,
					     ISAKMP_v2_CREATE_CHILD_SA);
	}

	/* note: pst: parent; md->st: child */

	if (ret != STF_OK) {
		LSWDBGP(DBG_CONTROL, buf) {
			lswlogs(buf, "ikev2_child_sa_respond returned ");
			lswlog_v2_stf_status(buf, ret);
		}
		return ret; /* abort building the response message */
	}

	/* const unsigned int len = pbs_offset(&sk.pbs); */
	if (!close_v2SK_payload(&sk)) {
		return STF_INTERNAL_ERROR;
	}
	close_output_pbs(&rbody);
	close_output_pbs(&reply_stream);

	ret = encrypt_v2SK_payload(&sk);
	if (ret != STF_OK)
		return ret;

	/*
	 * CREATE_CHILD_SA request and response are small 300 - 750 bytes.
	 * ??? Should we support fragmenting?  Maybe one day.
	 */
	record_outbound_ike_msg(pst, &reply_stream,
				"packet from ikev2_child_out_cont");

	if (IS_CHILD_SA_RESPONDER(st))
		pst->st_msgid_lastreplied = md->hdr.isa_msgid;

	if (st->st_state == STATE_V2_CREATE_R ||
			st->st_state == STATE_V2_REKEY_CHILD_R) {
		log_ipsec_sa_established("negotiated new IPsec SA", st);
	}

	return STF_OK;
}

static stf_status ikev2_start_new_exchange(struct state *st)
{
	if (IS_CHILD_SA_INITIATOR(st)) {
		struct ike_sa *ike = ike_sa(st);
		if (!ike->sa.st_viable_parent) {
			st->st_policy = st->st_connection->policy; /* for pick_initiator */

			loglog(RC_LOG_SERIOUS, "no viable to parent to initiate CREATE_CHILD_EXCHANGE %s; trying replace",
					st->st_state_name);
			delete_event(st);
			event_schedule_s(EVENT_SA_REPLACE, REPLACE_ORPHAN, st);
			/* ??? surely this isn't yet a failure or a success */
			return STF_FAIL;
		}
	}

	return STF_OK;
}

void ikev2_child_send_next(struct state *st)
{
	set_cur_state(st);

	stf_status e = ikev2_start_new_exchange(st);
	if (e != STF_OK)
		return;	/* ??? e lost?  probably should call complete_v2_state_transition */

	struct msg_digest *md = unsuspend_md(st);
	e = ikev2_child_out_tail(md);
	/* replace (*mdp)->st with st ... */
	complete_v2_state_transition(md->st, &md, e);
	release_any_md(&md);
	reset_globals();
}

static void delete_or_replace_state(struct state *st) {
	struct connection *c = st->st_connection;

	if (st->st_event == NULL) {
		/* ??? should this be an assert/expect? */
		loglog(RC_LOG_SERIOUS, "received Delete SA payload: delete IPSEC State #%lu. st_event == NULL",
				st->st_serialno);
		delete_state(st);
	} else if (st->st_event->ev_type == EVENT_SA_EXPIRE) {
		/* this state  was going to EXPIRE: hurry it along */
		/* ??? why is this treated specially.  Can we not delete_state()? */
		loglog(RC_LOG_SERIOUS, "received Delete SA payload: expire IPSEC State #%lu now",
				st->st_serialno);
		event_force(EVENT_SA_EXPIRE, st);
	} else if (c->newest_ipsec_sa == st->st_serialno &&
		   (c->policy & POLICY_UP) &&
		   st->st_event->ev_type == EVENT_SA_REPLACE) {
		/*
		 * Last IPsec SA for a permanent  connection that we have initiated.
		 * Replace it now.  Useful if the other peer is rebooting.
		 */
		loglog(RC_LOG_SERIOUS, "received Delete SA payload: replace IPSEC State #%lu now",
				st->st_serialno);
		st->st_replace_margin = deltatime(0);
		event_force(EVENT_SA_REPLACE, st);
	} else {
		loglog(RC_LOG_SERIOUS, "received Delete SA payload: delete IPSEC State #%lu now",
				st->st_serialno);
		delete_state(st);
	}
}

static void set_mobike_remote_addr(struct msg_digest *md, struct state *st)
{
	/*
	 * If this is a MOBIKE probe, use the received IP:port for only this reply packet,
	 * without updating IKE endpoint and without UPDATE_SA.
	 */

	st->st_mobike_remoteaddr = md->sender;
	st->st_mobike_remoteport = hportof(&md->sender);
	st->st_mobike_interface = md->iface;
	/* local_addr and localport are not used in send_packet() ! */
}

/* can an established state initiate or respond to mobike probe */
static bool mobike_check_established(const struct state *st)
{
	struct connection *c = st->st_connection;
	/* notice tricky use of & on booleans */
	bool ret = LIN(POLICY_MOBIKE, c->policy) &
		   st->st_seen_mobike & st->st_sent_mobike &
		   IS_ISAKMP_SA_ESTABLISHED(st->st_state);

	return ret;
}

static bool process_mobike_resp(struct msg_digest *md)
{
	struct state *st = md->st;
	bool may_mobike = mobike_check_established(st);
	/* ??? there is currently no need for separate natd_[sd] variables */
	bool natd_s = FALSE;
	bool natd_d = FALSE;
	struct payload_digest *ntfy;

	if (!may_mobike) {
		return FALSE;
	}

	for (ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		switch (ntfy->payload.v2n.isan_type) {
		case v2N_NAT_DETECTION_DESTINATION_IP:
			natd_d =  TRUE;
			DBG(DBG_CONTROLMORE, DBG_log("TODO: process %s in MOBIKE response ",
						enum_name(&ikev2_notify_names,
							ntfy->payload.v2n.isan_type)));
			break;
		case v2N_NAT_DETECTION_SOURCE_IP:
			natd_s = TRUE;
			DBG(DBG_CONTROLMORE, DBG_log("TODO: process %s in MOBIKE response ",
						enum_name(&ikev2_notify_names,
							ntfy->payload.v2n.isan_type)));

			break;
		}
	}

	/* use of bitwise & on bool values is correct but odd */
	bool ret  = natd_s & natd_d;

	if (ret && !update_mobike_endpoints(st, md)) {
		/* IPs already updated from md */
		return FALSE;
	}
	update_ike_endpoints(st, md); /* update state sender so we can find it for IPsec SA */

	return ret;
}

/* currently we support only MOBIKE notifies and v2N_REDIRECT notify */
static void process_informational_notify_req(struct msg_digest *md, bool *redirect, bool *ntfy_natd,
		chunk_t *cookie2)
{
	struct payload_digest *ntfy;
	struct state *st = md->st;
	bool may_mobike = mobike_check_established(st);
	bool ntfy_update_sa = FALSE;
	ip_address redirect_ip;

	for (ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		switch (ntfy->payload.v2n.isan_type) {
		case v2N_REDIRECT:
			DBG(DBG_CONTROLMORE, DBG_log("received v2N_REDIRECT in informational"));
			err_t e = parse_redirect_payload(&ntfy->pbs,
							 st->st_connection->accept_redirect_to,
							 NULL,
							 &redirect_ip);
			if (e != NULL) {
				loglog(RC_LOG_SERIOUS, "warning: parsing of v2N_REDIRECT payload failed: %s", e);
			} else {
				*redirect = TRUE;
				st->st_connection->temp_vars.redirect_ip = redirect_ip;
			}
			return;

		case v2N_UPDATE_SA_ADDRESSES:
			if (may_mobike) {
				ntfy_update_sa = TRUE;
				DBG(DBG_CONTROLMORE, DBG_log("Need to process v2N_UPDATE_SA_ADDRESSES"));
			} else {
				libreswan_log("Connection does not allow MOBIKE, ignoring UPDATE_SA_ADDRESSES");
			}
			break;

		case v2N_NO_NATS_ALLOWED:
			if (may_mobike)
				st->st_seen_nonats = TRUE;
			else
				libreswan_log("Connection does not allow MOBIKE, ignoring v2N_NO_NATS_ALLOWED");
			break;

		case v2N_NAT_DETECTION_DESTINATION_IP:
		case v2N_NAT_DETECTION_SOURCE_IP:
			*ntfy_natd = TRUE;
			DBG(DBG_CONTROLMORE, DBG_log("TODO: Need to process NAT DETECTION payload if we are initiator"));
			break;

		case v2N_NO_ADDITIONAL_ADDRESSES:
			if (may_mobike) {
				DBG(DBG_CONTROLMORE, DBG_log("Received NO_ADDITIONAL_ADDRESSES - no need to act on this"));
			} else {
				libreswan_log("Connection does not allow MOBIKE, ignoring NO_ADDITIONAL_ADDRESSES payload");
			}
			break;

		case v2N_COOKIE2:
			if (may_mobike) {
				/* copy cookie */
				if (ntfy->payload.v2n.isan_length > IKEv2_MAX_COOKIE_SIZE) {
					DBG(DBG_CONTROL, DBG_log("MOBIKE COOKIE2 notify payload too big - ignored"));
				} else {
					const pb_stream *dc_pbs = &ntfy->pbs;

					clonetochunk(*cookie2, dc_pbs->cur, pbs_left(dc_pbs),
							"saved cookie2");
					DBG_dump_chunk("MOBIKE COOKIE2 received:", *cookie2);
				}
			} else {
				libreswan_log("Connection does not allow MOBIKE, ignoring COOKIE2");
			}
			break;

		case v2N_ADDITIONAL_IP4_ADDRESS:
			DBG(DBG_CONTROL, DBG_log("ADDITIONAL_IP4_ADDRESS payload ignored (not yet supported)"));
			/* not supported yet */
			break;
		case v2N_ADDITIONAL_IP6_ADDRESS:
			DBG(DBG_CONTROL, DBG_log("ADDITIONAL_IP6_ADDRESS payload ignored (not yet supported)"));
			/* not supported yet */
			break;

		default:
			DBG(DBG_CONTROLMORE, DBG_log("Received unexpected %s notify - ignored",
						enum_name(&ikev2_notify_names,
							ntfy->payload.v2n.isan_type)));
			break;
		}
	}

	if (ntfy_update_sa) {
		if (LHAS(st->hidden_variables.st_nat_traversal, NATED_HOST)) {
			libreswan_log("Ignoring MOBIKE UPDATE_SA since we are behind NAT");
		} else {
			if (!update_mobike_endpoints(st, md))
				*ntfy_natd = FALSE;
			update_ike_endpoints(st, md); /* update state sender so we can find it for IPsec SA */
		}
	}

	if (may_mobike && !ntfy_update_sa && *ntfy_natd &&
	    !LHAS(st->hidden_variables.st_nat_traversal, NATED_HOST)) {
		set_mobike_remote_addr(md, st);
	}

	if (ntfy_update_sa)
		libreswan_log("MOBIKE request: updating IPsec SA by request");
	else
		DBG(DBG_CONTROL, DBG_log("MOBIKE request: not updating IPsec SA"));
}

static void mobike_reset_remote(struct state *st, struct mobike *est_remote)
{
	if (est_remote->interface == NULL)
		return;

	st->st_remoteaddr = est_remote->remoteaddr;
	st->st_remoteport = est_remote->remoteport;
	st->st_interface = est_remote->interface;

	anyaddr(AF_INET, &st->st_mobike_remoteaddr);
	st->st_mobike_remoteport = 0;
	st->st_mobike_interface = NULL;
}

/* MOBIKE liveness/update response. set temp remote address/interface */
static void mobike_switch_remote(struct msg_digest *md, struct mobike *est_remote)
{
	struct state *st = md->st;

	est_remote->interface = NULL;

	if (mobike_check_established(st) &&
	    !LHAS(st->hidden_variables.st_nat_traversal, NATED_HOST) &&
	    (!sameaddr(&md->sender, &st->st_remoteaddr) ||
	     hportof(&md->sender) != st->st_remoteport)) {
		/* remember the established/old address and interface */
		est_remote->remoteaddr = st->st_remoteaddr;
		est_remote->remoteport = st->st_mobike_remoteport;
		est_remote->interface = md->iface;

		/* set temp one and after the message sent reset it */
		st->st_remoteaddr = md->sender;
		st->st_remoteport = hportof(&md->sender);
		st->st_interface = md->iface;
	}
}

static stf_status add_mobike_response_payloads(
		chunk_t *cookie2,	/* freed by us */
		struct msg_digest *md,
		pb_stream *pbs)
{
	dbg("adding NATD%s payloads to MOBIKE response",
	    cookie2->len != 0 ? " and cookie2" : "");

	stf_status r = STF_INTERNAL_ERROR;

	struct state *st = md->st;
	/* assumptions from ikev2_out_nat_v2n() and caller */
	pexpect(v2_msg_role(md) == MESSAGE_REQUEST);
	pexpect(!ike_spi_is_zero(&st->st_ike_spis.responder));
	if (ikev2_out_nat_v2n(pbs, st, &st->st_ike_spis.responder) &&
	    (cookie2->len == 0 || emit_v2Nchunk(v2N_COOKIE2, cookie2, pbs)))
		r = STF_OK;

	freeanychunk(*cookie2);
	return r;
}
/*
 *
 ***************************************************************
 *                       INFORMATIONAL                     *****
 ***************************************************************
 *  -
 *
 *
 */

/* RFC 5996 1.4 "The INFORMATIONAL Exchange"
 *
 * HDR, SK {[N,] [D,] [CP,] ...}  -->
 *   <--  HDR, SK {[N,] [D,] [CP], ...}
 */

stf_status process_encrypted_informational_ikev2(struct state *st,
						 struct msg_digest *md)
{
	struct payload_digest *p;
	int ndp = 0;	/* number Delete payloads for IPsec protocols */
	bool del_ike = FALSE;	/* any IKE SA Deletions? */
	bool seen_and_parsed_redirect = FALSE;
	/*
	 * we need connection and boolean below
	 * in a separate variables because we
	 * do something with them after we delete
	 * the state.
	 */
	struct connection *c = st->st_connection;
	bool do_unroute = st->st_sent_redirect && c->kind == CK_PERMANENT;
	chunk_t cookie2 = EMPTY_CHUNK;

	/* Are we responding (as opposed to processing a response)? */
	const bool responding = (md->hdr.isa_flags & ISAKMP_FLAGS_v2_MSG_R) == 0;

	DBG(DBG_PARSING, DBG_log("an informational %s ",
				responding ? "request should send a response" :
					     "response"));
	/*
	 * get parent
	 *
	 * ??? shouldn't st always be the parent?
	 *
	 * XXX: what about when the remote end sends the wrong msgid
	 * and it matches one of the child requests?
	 */
	struct ike_sa *ike = pexpect_ike_sa(st);
	pexpect(!IS_CHILD_SA(st));	/* ??? why would st be a child? */

	if (IS_CHILD_SA(st)) {
		/* we picked incomplete child, change to parent */
		so_serial_t c_serialno = st->st_serialno;

		st = state_with_serialno(st->st_clonedfrom);
		if (st == NULL)
			return STF_INTERNAL_ERROR;

		md->st = st;
		set_cur_state(st);
		DBG(DBG_CONTROLMORE,
		    DBG_log("Informational exchange matched Child SA #%lu - switched to its Parent SA #%lu",
			c_serialno, st->st_serialno));
	}

	/*
	 * Process NOTIFY payloads - ignore MOBIKE when deleting
	 */
	bool send_mobike_resp = FALSE;	/* only if responding */

	if (md->chain[ISAKMP_NEXT_v2D] == NULL) {
		if (responding) {
			process_informational_notify_req(md, &seen_and_parsed_redirect, &send_mobike_resp, &cookie2);
		} else {
			if (process_mobike_resp(md)) {
				libreswan_log("MOBIKE response: updating IPsec SA");
			} else {
				DBG(DBG_CONTROL, DBG_log("MOBIKE response: not updating IPsec SA"));
			}
		}
	} else {
		/*
		 * RFC 7296 1.4.1 "Deleting an SA with INFORMATIONAL Exchanges"
		 */

		/*
		 * Pass 1 over Delete Payloads:
		 *
		 * - Count number of IPsec SA Delete Payloads
		 * - notice any IKE SA Delete Payload
		 * - sanity checking
		 */

		for (p = md->chain[ISAKMP_NEXT_v2D]; p != NULL; p = p->next) {
			struct ikev2_delete *v2del = &p->payload.v2delete;

			switch (v2del->isad_protoid) {
			case PROTO_ISAKMP:
				if (!responding) {
					libreswan_log("Response to Delete improperly includes IKE SA");
					return STF_FAIL + v2N_INVALID_SYNTAX;
				}

				if (del_ike) {
					libreswan_log("Error: INFORMATIONAL Exchange with more than one Delete Payload for the IKE SA");
					return STF_FAIL + v2N_INVALID_SYNTAX;
				}

				if (v2del->isad_nrspi != 0 || v2del->isad_spisize != 0) {
					libreswan_log("IKE SA Delete has non-zero SPI size or number of SPIs");
					return STF_FAIL + v2N_INVALID_SYNTAX;
				}

				del_ike = TRUE;
				break;

			case PROTO_IPSEC_AH:
			case PROTO_IPSEC_ESP:
				if (v2del->isad_spisize != sizeof(ipsec_spi_t)) {
					libreswan_log("IPsec Delete Notification has invalid SPI size %u",
						v2del->isad_spisize);
					return STF_FAIL + v2N_INVALID_SYNTAX;
				}

				if (v2del->isad_nrspi * v2del->isad_spisize != pbs_left(&p->pbs)) {
					libreswan_log("IPsec Delete Notification payload size is %zu but %u is required",
						pbs_left(&p->pbs),
						v2del->isad_nrspi * v2del->isad_spisize);
					return STF_FAIL + v2N_INVALID_SYNTAX;
				}

				ndp++;
				break;

			default:
				libreswan_log("Ignored bogus delete protoid '%d'", v2del->isad_protoid);
			}
		}

		if (del_ike && ndp != 0)
			libreswan_log("Odd: INFORMATIONAL Exchange deletes IKE SA and yet also deletes some IPsec SA");
	}

	/*
	 * response packet preparation: DELETE or non-delete (eg MOBIKE/keepalive/REDIRECT)
	 *
	 * There can be at most one Delete Payload for an IKE SA.
	 * It means that this very SA is to be deleted.
	 *
	 * For each non-IKE Delete Payload we receive,
	 * we respond with a corresponding Delete Payload.
	 * Note that that means we will have an empty response
	 * if no Delete Payloads came in or if the only
	 * Delete Payload is for an IKE SA.
	 *
	 * If we received NAT detection payloads as per MOBIKE, send answers
	 */

	/*
	 * Variables for generating response.
	 * NOTE: only meaningful if "responding" is true!
	 * These declarations must be placed so early because they must be in scope for
	 * all of the several chunks of code that handle responding.
	 *
	 * XXX: in terms of readability and reliability, this
	 * interleaving of initiator vs response code paths is pretty
	 * screwed up.
	 */

	pb_stream rbody;
	v2SK_payload_t sk;
	zero(&rbody);
	zero(&sk);

	if (responding) {
		/* make sure HDR is at start of a clean buffer */
		init_out_pbs(&reply_stream, reply_buffer,
			 sizeof(reply_buffer),
			 "information exchange reply packet");

		/* authenticated decrypted response - It's alive, alive! */
		DBG(DBG_DPD, DBG_log("Received an INFORMATIONAL response, updating st_last_liveness, no pending_liveness"));
		st->st_last_liveness = mononow();
		st->st_pend_liveness = FALSE;

		/* HDR out */

		rbody = open_v2_message(&reply_stream, ike,
					md /* response */,
					ISAKMP_v2_INFORMATIONAL);
		if (!pbs_ok(&rbody)) {
			return STF_INTERNAL_ERROR;
		}

		/* insert an Encryption payload header */

		sk = open_v2SK_payload(&rbody, ike_sa(st));
		if (!pbs_ok(&sk.pbs)) {
			return STF_INTERNAL_ERROR;
		}

		if (send_mobike_resp) {
			stf_status e = add_mobike_response_payloads(
				&cookie2,	/* will be freed */
				md, &sk.pbs);
			if (e != STF_OK)
				return e;
		}
	}

	/*
	 * This happens when we are original initiator,
	 * and we received REDIRECT payload during the active
	 * session.
	 */
	if (seen_and_parsed_redirect)
		event_force(EVENT_v2_REDIRECT, st);

	/*
	 * Do the actual deletion.
	 * If responding, build the body of the response.
	 */

	if (!responding && st->st_state == STATE_IKESA_DEL) {
		/*
		 * this must be a response to our IKE SA delete request
		 * Even if there are are other Delete Payloads,
		 * they cannot matter: we delete the family.
		 */
		delete_my_family(st, TRUE);
		md->st = st = NULL;
	} else if (!responding && md->chain[ISAKMP_NEXT_v2D] == NULL) {
		/*
		 * A liveness update response is handled here
		 */
		DBG(DBG_DPD, DBG_log("Received an INFORMATIONAL non-delete request; updating liveness, no longer pending."));
		st->st_last_liveness = mononow();
		st->st_pend_liveness = FALSE;
	} else if (del_ike) {
		/*
		 * If we are deleting the Parent SA, the Child SAs will be torn down as well,
		 * so no point processing the other Delete SA payloads.
		 * We won't catch nonsense in those payloads.
		 *
		 * But wait: we cannot delete the IKE SA until after we've sent
		 * the response packet.  To be continued...
		 */
		passert(responding);
	} else {
		/*
		 * Pass 2 over the Delete Payloads:
		 * Actual IPsec SA deletion.
		 * If responding, build response Delete Payloads.
		 * If there is no payload, this loop is a no-op.
		 */
		int pli = 0;	/* payload index */

		for (p = md->chain[ISAKMP_NEXT_v2D]; p != NULL; p = p->next) {
			struct ikev2_delete *v2del = &p->payload.v2delete;

			switch (v2del->isad_protoid) {
			case PROTO_ISAKMP:
				PASSERT_FAIL("%s", "unexpected IKE delete");

			case PROTO_IPSEC_AH: /* Child SAs */
			case PROTO_IPSEC_ESP: /* Child SAs */
			{
				/* stuff for responding */
				ipsec_spi_t spi_buf[128];
				uint16_t j = 0;	/* number of SPIs in spi_buf */
				uint16_t i;

				for (i = 0; i < v2del->isad_nrspi; i++) {
					ipsec_spi_t spi;

					if (!in_raw(&spi, sizeof(spi), &p->pbs, "SPI"))
						return STF_INTERNAL_ERROR;	/* cannot happen */

					DBG(DBG_CONTROLMORE, DBG_log(
						    "delete %s SA(0x%08" PRIx32 ")",
						    enum_show(&ikev2_protocol_names,
							    v2del->isad_protoid),
						    ntohl((uint32_t)
							  spi)));

					/*
					 * From 3.11.  Delete Payload:
					 * [the delete payload will]
					 * contain the IPsec protocol
					 * ID of that protocol (2 for
					 * AH, 3 for ESP), and the SPI
					 * is the SPI the sending
					 * endpoint would expect in
					 * inbound ESP or AH packets.
					 *
					 * From our POV, that's the
					 * outbound SPI.
					 */
					struct state *dst = find_v2_child_sa_by_outbound_spi(&st->st_ike_spis,
											     v2del->isad_protoid,
											     spi);

					passert(dst != st);	/* st is an IKE SA */
					if (dst == NULL) {
						libreswan_log(
						    "received delete request for %s SA(0x%08" PRIx32 ") but corresponding state not found",
							    enum_show(&ikev2_protocol_names, v2del->isad_protoid),
								ntohl((uint32_t)spi));
					} else {
						DBG(DBG_CONTROLMORE,
							DBG_log("our side SPI that needs to be deleted: %s SA(0x%08" PRIx32 ")",
								enum_show(&ikev2_protocol_names,
									v2del->isad_protoid),
								ntohl((uint32_t)spi)));
						/* we just received a delete, don't send another delete */
						dst->st_suppress_del_notify = TRUE;
						passert(dst != st);	/* st is a parent */
						if (!del_ike && responding) {
							struct ipsec_proto_info *pr =
								v2del->isad_protoid == PROTO_IPSEC_AH ?
									&dst->st_ah :
									&dst->st_esp;

							if (j < elemsof(spi_buf)) {
								spi_buf[j] = pr->our_spi;
								j++;
							} else {
								libreswan_log("too many SPIs in Delete Notification payload; ignoring 0x%08" PRIx32,
									ntohl(spi));
							}
						}
						delete_or_replace_state(dst);
						/* note: md->st != dst */
					}
				} /* for each spi */

				if (!del_ike && responding) {
					/* build output Delete Payload */

					passert(pli < ndp);
					pli++;
					struct ikev2_delete v2del_tmp = {
						.isad_np = (pli == ndp) ?
							ISAKMP_NEXT_v2NONE : ISAKMP_NEXT_v2D,
						.isad_protoid = v2del->isad_protoid,
						.isad_spisize = v2del->isad_spisize,
						.isad_nrspi = j,
					};

					/* Emit delete payload header and SPI values */
					pb_stream del_pbs;	/* output stream */

					if (!out_struct(&v2del_tmp,
							&ikev2_delete_desc,
							&sk.pbs,
							&del_pbs) ||
					    !out_raw(spi_buf,
							j * sizeof(spi_buf[0]),
							&del_pbs,
							"local SPIs"))
						return STF_INTERNAL_ERROR;

					close_output_pbs(&del_pbs);
				}
			}
			break;

			default:
				/* ignore unrecognized protocol */
				break;
			}
		}  /* for each Delete Payload */
	}

	if (responding) {
		/*
		 * We've now build up the content (if any) of the Response:
		 *
		 * - empty, if there were no Delete Payloads or if we are
		 *   responding to v2N_REDIRECT payload (RFC 5685 Chapter 5).
		 *   Treat as a check for liveness.  Correct response is this
		 *   empty Response.
		 *
		 * - if an ISAKMP SA is mentioned in input message,
		 *   we are sending an empty Response, as per standard.
		 *
		 * - for IPsec SA mentioned, we are sending its mate.
		 *
		 * - for MOBIKE, we send NAT NOTIFY payloads and optionally a COOKIE2
		 *
		 * Close up the packet and send it.
		 */

		/* const size_t len = pbs_offset(&sk.pbs); */
		if (!close_v2SK_payload(&sk)) {
			return STF_INTERNAL_ERROR;
		}
		close_output_pbs(&rbody);
		close_output_pbs(&reply_stream);
;
		stf_status ret = encrypt_v2SK_payload(&sk);
		if (ret != STF_OK)
			return ret;

		struct mobike mobike_remote;

		mobike_switch_remote(md, &mobike_remote);

		/* ??? should we support fragmenting?  Maybe one day. */
		record_and_send_v2_ike_msg(st, &reply_stream,
					   "reply packet for process_encrypted_informational_ikev2");
		st->st_msgid_lastreplied = md->hdr.isa_msgid;

		mobike_reset_remote(st, &mobike_remote);

		/* Now we can delete the IKE SA if we want to */
		if (del_ike) {
			delete_my_family(st, TRUE);
			md->st = st = NULL;
		}
	}

	/*
	 * This is a special case. When we have site to site connection
	 * and one site redirects other in IKE_AUTH reply, he doesn't
	 * unroute. It seems like it was easier to add here this part
	 * than in delete_ipsec_sa() in kernel.c where it should be
	 * (at least it seems like it should be there).
	 *
	 * The need for this special case was discovered by running
	 * various test cases.
	 */
	if (do_unroute) {
		unroute_connection(c);
	}

	/* count as DPD/liveness only if there was no Delete */
	if (!del_ike && ndp == 0) {
		if (responding)
			pstats_ike_dpd_replied++;
		else
			pstats_ike_dpd_recv++;
	}

	dbg("Message ID: processing a informational");
	v2_msgid_update_counters(md->st, md);
	return STF_OK;
}

stf_status ikev2_send_livenss_probe(struct state *st)
{
	struct ike_sa *ike = ike_sa(st);
	if (ike == NULL) {
		DBG(DBG_CONTROL,
		    DBG_log("IKE SA does not exist for this child SA - should not happen"));
		DBG(DBG_CONTROL,
		    DBG_log("INFORMATIONAL exchange cannot be sent"));
		return STF_IGNORE;
	}

	/*
	 * XXX: What does it mean to send a liveness probe for a CHILD
	 * SA?  Since the packet contents are empty there's nothing to
	 * identify the CHILD, just the IKE SA!?!
	 */
	stf_status e = send_v2_informational_request("liveness probe informational request",
						     st, ike, NULL);

	pstats_ike_dpd_sent++;

	return e;
}

#ifdef NETKEY_SUPPORT
static payload_master_t add_mobike_payloads;
static bool add_mobike_payloads(struct state *st, pb_stream *pbs)
{
	return emit_v2N(v2N_UPDATE_SA_ADDRESSES, pbs) &&
		ikev2_out_natd(&st->st_mobike_localaddr, st->st_mobike_localport,
			    &st->st_remoteaddr, st->st_remoteport,
			    &st->st_ike_spis, pbs);
}
#endif

void ikev2_rekey_ike_start(struct state *st)
{
	struct pending p;
	p.whack_sock = null_fd;
	p.isakmp_sa = st;
	p.connection = st->st_connection;
	p.policy = LEMPTY;
	p.try = 1;
	p.replacing = st->st_serialno;
#ifdef HAVE_LABELED_IPSEC
	p.uctx = st->sec_ctx;
#endif
	ikev2_initiate_child_sa(&p);
}

void ikev2_initiate_child_sa(struct pending *p)
{
	struct state *st;
	char replacestr[32];
	enum state_kind new_state = STATE_UNDEFINED;
	sa_t sa_type = IPSEC_SA;
	struct ike_sa *ike = ike_sa(p->isakmp_sa);
	struct connection *c = p->connection;

	if (p->replacing == ike->sa.st_serialno) { /* IKE rekey exchange */
		sa_type = IKE_SA;
		ike->sa.st_viable_parent = FALSE;
	} else {
		if (find_pending_phase2(ike->sa.st_serialno,
					c, IPSECSA_PENDING_STATES)) {
			return;
		}
	}

	passert(c != NULL);

	if (sa_type == IPSEC_SA) {
		st = ikev2_duplicate_state(ike, IPSEC_SA, SA_INITIATOR);
	} else {
		st = ikev2_duplicate_state(ike, IKE_SA, SA_INITIATOR);
		st->st_oakley = ike->sa.st_oakley;
		st->st_ike_rekey_spis.initiator = ike_initiator_spi();
		st->st_ike_pred = ike->sa.st_serialno;
	}

	st->st_whack_sock = p->whack_sock;
	st->st_connection = c;	/* safe: from duplicate_state */

	set_cur_state(st); /* we must reset before exit */
	st->st_try = p->try;

	freeanychunk(st->st_ni); /* this is from the parent. */
	freeanychunk(st->st_nr); /* this is from the parent. */

	st->st_original_role = ORIGINAL_INITIATOR;

	if (sa_type == IPSEC_SA) {
		const struct state *rst = state_with_serialno(p->replacing);

		if (rst != NULL) {
			if (IS_CHILD_SA_ESTABLISHED(rst)) {
				new_state = STATE_V2_REKEY_CHILD_I0;
				st->st_ipsec_pred = rst->st_serialno;
				passert(st->st_connection == rst->st_connection);
				if (HAS_IPSEC_POLICY(rst->st_policy))
					st->st_policy = rst->st_policy;
				else
					p->policy = c->policy; /* where did rst->st_policy go? */
			} else {
				rst = NULL;
				new_state = STATE_V2_CREATE_I0;
			}
		} else {
			new_state = STATE_V2_CREATE_I0;
		}
	} else {
		new_state = STATE_V2_REKEY_IKE_I0;
	}

	st->st_policy = p->policy;

#ifdef HAVE_LABELED_IPSEC
	st->sec_ctx = NULL;
	if (p->uctx != NULL) {
		st->sec_ctx = clone_thing(*p->uctx, "sec ctx structure");
		DBG(DBG_CONTROL,
		    DBG_log("pending phase 2 with security context \"%s\"",
			    st->sec_ctx->sec_ctx_value));
	}
#endif
	change_state(st, new_state); /* from STATE_UNDEFINED */

	refresh_state(st);

	replacestr[0] = '\0';
	if (p->replacing != SOS_NOBODY) {
		snprintf(replacestr, sizeof(replacestr), " to replace #%lu",
				p->replacing);
	}

	passert(st->st_connection != NULL);

	if (sa_type == IPSEC_SA) {
		const struct state *rst = state_with_serialno(p->replacing);

		/*
		 * Use the CREATE_CHILD_SA proposal suite - the
		 * proposal generated during IKE_AUTH will have been
		 * stripped of DH.
		 *
		 * XXX: If the IKE SA's DH changes, then the child
		 * proposals will be re-generated.  Should the child
		 * proposals instead be somehow stored in state and
		 * dragged around?
		 */
		const struct oakley_group_desc *default_dh =
			c->policy & POLICY_PFS ? ike->sa.st_oakley.ta_dh : NULL;
		struct ikev2_proposals *child_proposals =
			get_v2_create_child_proposals(c,
						      "ESP/AH initiator emitting proposals",
						      default_dh);
		/* see ikev2_child_add_ipsec_payloads */
		passert(c->v2_create_child_proposals != NULL);

		st->st_pfs_group = ikev2_proposals_first_dh(child_proposals);

		DBG(DBG_CONTROLMORE, {
			const char *pfsgroupname = st->st_pfs_group == NULL ?
			"no-pfs" : st->st_pfs_group->common.name;

			DBG_log("#%lu schedule %s IPsec SA %s%s using IKE# %lu pfs=%s",
				st->st_serialno,
				rst != NULL ? "rekey initiate" : "initiate",
				prettypolicy(p->policy),
				replacestr,
				ike->sa.st_serialno,
				pfsgroupname);
		});
	} else {
		DBG(DBG_CONTROLMORE, {
			DBG_log("#%lu schedule initiate IKE Rekey SA %s to replace IKE# %lu",
				st->st_serialno,
				prettypolicy(p->policy),
				ike->sa.st_serialno);
		});
	}

	event_force(EVENT_v2_INITIATE_CHILD, st);
	reset_globals();
}

static crypto_req_cont_func ikev2_child_outI_continue;

void ikev2_child_outI(struct state *st)
{
	switch (st->st_state) {

	case STATE_V2_REKEY_CHILD_I0:
		if (st->st_pfs_group == NULL) {
			request_nonce("Child Rekey Initiator nonce ni",
				      st, ikev2_child_outI_continue);
		} else {
			request_ke_and_nonce("Child Rekey Initiator KE and nonce ni",
					     st, st->st_pfs_group,
					     ikev2_child_outI_continue);
		}
		break; /* return STF_SUSPEND; */

	case STATE_V2_CREATE_I0:
		if (st->st_pfs_group == NULL) {
			request_nonce("Child Initiator nonce ni",
				      st, ikev2_child_outI_continue);
		} else {
			request_ke_and_nonce("Child Initiator KE and nonce ni",
					     st, st->st_pfs_group,
					     ikev2_child_outI_continue);
		}
		break; /* return STF_SUSPEND; */

	case STATE_V2_REKEY_IKE_I0:
		request_ke_and_nonce("IKE REKEY Initiator KE and nonce ni",
				     st, st->st_oakley.ta_dh,
				     ikev2_child_outI_continue);
		break; /* return STF_SUSPEND; */

	default:
		bad_case(st->st_state);
	}
}

static void ikev2_child_outI_continue(struct state *st,
				      struct msg_digest **mdp,
				      struct pluto_crypto_req *r)
{
	/*
	 * XXX: Should this routine be split so that each instance
	 * handles only one state transition.  If there's commonality
	 * then the per-transition functions can all call common code.
	 */
	pexpect(st->st_state == STATE_V2_CREATE_I0 ||
		st->st_state == STATE_V2_REKEY_CHILD_I0 ||
		st->st_state == STATE_V2_REKEY_IKE_I0);

	/* child initiating exchange */
	pexpect(IS_CHILD_SA(st));
	pexpect(st->st_sa_role == SA_INITIATOR);

	/* initiating, so *MDP should be NULL; later */
	if (*mdp == NULL) {
		*mdp = fake_md(st);
	}

	dbg("%s for #%lu %s",
	     __func__, st->st_serialno, st->st_state_name);

	/* and a parent? */
	struct ike_sa *ike = ike_sa(st);
	if (ike == NULL) {
		PEXPECT_LOG("sponsoring child state #%lu has no parent state #%lu",
			    st->st_serialno, st->st_clonedfrom);
		/* XXX: release child? */
		return;
	}

	/* IKE SA => DH */
	pexpect(st->st_state == STATE_V2_REKEY_IKE_I0 ? r->pcr_type == pcr_build_ke_and_nonce : true);

	unpack_nonce(&st->st_ni, r);
	if (r->pcr_type == pcr_build_ke_and_nonce)
		unpack_KE_from_helper(st, r, &st->st_gi);
	stf_status e = add_st_to_ike_sa_send_list(st, ike);

	if (e == STF_OK) {
		e = ikev2_start_new_exchange(st);
	}
	if (e == STF_OK) {
		passert(*mdp != NULL);
		e =ikev2_child_out_tail(*mdp);
	}

	passert(*mdp != NULL);
	complete_v2_state_transition(st, mdp, e);
}

/*
 * if this connection has a newer Child SA than this state
 * this negotitation is not relevant any more.
 * would this cover if there are multiple CREATE_CHILD_SA pending on
 * this IKE negotiation ???
 */
bool need_this_intiator(struct state *st)
{
	struct connection *c = st->st_connection;

	if (st->st_state !=  STATE_PARENT_I1)
		return FALSE; /* ignore STATE_V2_CREATE_I ??? */

	if (c->newest_ipsec_sa > st->st_serialno) {
		libreswan_log("suppressing retransmit because superseded by #%lu try=%lu. Drop this negotitation",
				c->newest_ipsec_sa, st->st_try);
		return TRUE;
	}
	return FALSE;
}

void ikev2_record_newaddr(struct state *st, void *arg_ip)
{
	ip_address *ip = arg_ip;

	if (!mobike_check_established(st))
		return;

	if (!isanyaddr(&st->st_deleted_local_addr)) {
		/*
		 * A work around for delay between new address and new route
		 * A better fix would be listen to  RTM_NEWROUTE, RTM_DELROUTE
		 */
		if (st->st_addr_change_event == NULL) {
			event_schedule_s(EVENT_v2_ADDR_CHANGE,
					 RTM_NEWADDR_ROUTE_DELAY, st);
		} else {
			ipstr_buf b;
			DBG(DBG_CONTROL, DBG_log("#%lu MOBIKE ignore address %s change pending previous",
						st->st_serialno,
						sensitive_ipstr(ip, &b)));
		}
	}
}

void ikev2_record_deladdr(struct state *st, void *arg_ip)
{
	ip_address *ip = arg_ip;

	if (!mobike_check_established(st))
		return;

	if (sameaddr(ip, &st->st_localaddr)) {
		ip_address ip_p = st->st_deleted_local_addr;
		st->st_deleted_local_addr = st->st_localaddr;
		struct state *cst = state_with_serialno(st->st_connection->newest_ipsec_sa);
		migration_down(cst->st_connection, cst);
		unroute_connection(st->st_connection);

		delete_liveness_event(cst);

		if (st->st_addr_change_event == NULL) {
			event_schedule_s(EVENT_v2_ADDR_CHANGE, 0, st);
		} else {
			ipstr_buf o, n;
			DBG(DBG_CONTROL, DBG_log("#%lu MOBIKE new RTM_DELADDR %s pending previous %s",
						st->st_serialno,
						sensitive_ipstr(ip, &n),
						sensitive_ipstr(&ip_p, &o)));
		}
	}
}

#ifdef NETKEY_SUPPORT
static void initiate_mobike_probe(struct state *st, struct starter_end *this,
		const struct iface_port *iface)
{
	/*
	 * caveat: could a CP initiator find an address received
	 * from the pool as a new source address?
	 */

	ipstr_buf s, g, b;
	DBG(DBG_CONTROL, DBG_log("#%lu MOBIKE new source address %s remote %s and gateway %s",
				st->st_serialno, ipstr(&this->addr, &s),
				sensitive_ipstr(&st->st_remoteaddr, &b),
				ipstr(&this->nexthop, &g)));
	st->st_mobike_localaddr = this->addr;
	st->st_mobike_localport = st->st_localport;
	st->st_mobike_host_nexthop = this->nexthop; /* for updown, after xfrm migration */
	const struct iface_port *o_iface = st->st_interface;
	st->st_interface = iface;

	send_v2_informational_request("mobike informational request",
				      st, ike_sa(st), add_mobike_payloads);

	st->st_interface = o_iface;
}
#endif

#ifdef NETKEY_SUPPORT
static const struct iface_port *ikev2_src_iface(struct state *st,
						struct starter_end *this)
{
	const struct iface_port *iface;
	ipstr_buf b;

	/* success found a new source address */

	iface = lookup_iface_ip(&this->addr, st->st_localport);
	if (iface ==  NULL) {
		DBG(DBG_CONTROL, DBG_log("#%lu no interface for %s try to initialize",
					st->st_serialno,
					sensitive_ipstr(&this->addr, &b)));
		find_ifaces(FALSE);
		iface = lookup_iface_ip(&this->addr, st->st_localport);
		if (iface ==  NULL) {
			return NULL;
		}
	}

	return iface;
}
#endif

void ikev2_addr_change(struct state *st)
{
	if (!mobike_check_established(st))
		return;

#ifdef NETKEY_SUPPORT

	/* let's re-discover local address */

	struct starter_end this = {
		.addrtype = KH_DEFAULTROUTE,
		.nexttype = KH_DEFAULTROUTE,
		.addr_family = st->st_remoteaddr.u.v4.sin_family
	};

	struct starter_end that = {
		.addrtype = KH_IPADDR,
		.addr_family = st->st_remoteaddr.u.v4.sin_family,
		.addr = st->st_remoteaddr
	};

	/*
	 * mobike need two lookups. one for the gateway and
	 * the one for the source address
	 */
	switch (resolve_defaultroute_one(&this, &that, TRUE)) {
	case 0:	/* success */
		/* cannot happen */
		/* ??? original code treated this as failure */
		/* bad_case(0); */
		libreswan_log("unexpected SUCCESS from first resolve_defaultroute_one");
		/* FALL THROUGH */
	case -1:	/* failure */
		/* keep this DEBUG, if a libreswan log, too many false +ve */
		DBG(DBG_CONTROL, {
			ipstr_buf b;
			DBG_log("#%lu no local gatway to reach %s",
					st->st_serialno,
					sensitive_ipstr(&that.addr, &b));
		});
		break;

	case 1: /* please call again: more to do */
		switch (resolve_defaultroute_one(&this, &that, TRUE)) {
		case 1: /* please call again: more to do */
			/* cannot happen */
			/* ??? original code treated this as failure */
			/* bad_case(1); */
			libreswan_log("unexpected TRY AGAIN from second resolve_defaultroute_one");
			/* FALL THROUGH */
		case -1:	/* failure */
		{
			ipstr_buf g, b;
			libreswan_log("no local source address to reach remote %s, local gateway %s",
					sensitive_ipstr(&that.addr, &b),
					ipstr(&this.nexthop, &g));
			break;
		}

		case 0:	/* success */
		{
			const struct iface_port *iface = ikev2_src_iface(st, &this);
			if (iface != NULL)
				initiate_mobike_probe(st, &this, iface);
			break;
		}

		}
		break;
	}

#else /* !defined(NETKEY_SUPPORT) */

	libreswan_log("without NETKEY we cannot ikev2_addr_change()");

#endif
}

/*
 * Only replace the SA when it's been in use (checking for in-use is a
 * separate operation).
 */

static bool expire_ike_because_child_not_used(struct state *st)
{
	if (!(IS_PARENT_SA_ESTABLISHED(st) ||
	      IS_CHILD_SA_ESTABLISHED(st))) {
		/* for instance, too many retransmits trigger replace */
		return false;
	}

	struct connection *c = st->st_connection;
	if (!(c->policy & POLICY_OPPORTUNISTIC)) {
		/* this is an opportunistic thing */
		return false;
	}

	if (c->spd.that.has_lease) {
		PEXPECT_LOG("#%lu has lease; should not be trying to replace",
			    st->st_serialno);
		return true;
	}

	/* see of (most recent) child is busy */
	struct state *cst;
	struct ike_sa *ike;
	if (IS_IKE_SA(st)) {
		ike = pexpect_ike_sa(st);
		cst = state_with_serialno(c->newest_ipsec_sa);
		if (cst == NULL) {
			PEXPECT_LOG("can't check usage as IKE SA #%lu has no newest child",
				    ike->sa.st_serialno);
			return true;
		}
	} else {
		cst = st;
		ike = ike_sa(st);
	}

	dbg("#%lu check last used on newest CHILD SA #%lu",
	    ike->sa.st_serialno, cst->st_serialno);
	deltatime_t last_used_age;
	if (get_sa_info(cst, TRUE, &last_used_age) &&
	    deltaless(c->sa_rekey_margin, last_used_age)) {
		/* we observed no traffic, let IPSEC SA and IKE SA expire */
		dbg("expiring IKE SA #%lu as CHILD SA #%lu has used %jds ago > %jd",
		    ike->sa.st_serialno,
		    ike->sa.st_serialno,
		    deltasecs(last_used_age),
		    deltasecs(c->sa_rekey_margin));
		return true;
	}
	return false;
}

void v2_schedule_replace_event(struct state *st)
{
	struct connection *c = st->st_connection;

	/* unwrapped deltatime_t in seconds */
	intmax_t delay = deltasecs(IS_PARENT_SA(st) ? c->sa_ike_life_seconds
				   : c->sa_ipsec_life_seconds);
	st->st_replace_by = monotimesum(mononow(), deltatime(delay));

	/*
	 * Important policy lies buried here.  For example, we favour
	 * the initiator over the responder by making the initiator
	 * start rekeying sooner.  Also, fuzz is only added to the
	 * initiator's margin.
	 */

	enum event_type kind;
	const char *story;
	intmax_t marg;
	if ((c->policy & POLICY_OPPORTUNISTIC) &&
	    st->st_connection->spd.that.has_lease) {
		marg = 0;
		kind = EVENT_SA_EXPIRE;
		story = "always expire opportunistic SA with lease";
	} else if (c->policy & POLICY_DONT_REKEY) {
		marg = 0;
		kind = EVENT_SA_EXPIRE;
		story = "policy doesn't allow re-key";
	} else if (IS_IKE_SA(st) && LIN(POLICY_REAUTH, st->st_connection->policy)) {
		marg = 0;
		kind = EVENT_SA_REPLACE;
		story = "IKE SA with policy re-authenticate";
	} else {
		/* unwrapped deltatime_t in seconds */
		marg = deltasecs(c->sa_rekey_margin);

		switch (st->st_sa_role) {
		case SA_INITIATOR:
			marg += marg *
				c->sa_rekey_fuzz / 100.E0 *
				(rand() / (RAND_MAX + 1.E0));
			break;
		case SA_RESPONDER:
			marg /= 2;
			break;
		default:
			bad_case(st->st_sa_role);
		}

		if (delay > marg) {
			delay -= marg;
			kind = EVENT_SA_REKEY;
			story = "attempting re-key";
		} else {
			marg = 0;
			kind = EVENT_SA_REPLACE;
			story = "margin to small for re-key";
		}
	}

	st->st_replace_margin = deltatime(marg);
	if (marg > 0) {
		passert(kind == EVENT_SA_REKEY);
		dbg("#%lu will start re-keying in %jd seconds with margin of %jd seconds (%s)",
		    st->st_serialno, delay, marg, story);
	} else {
		passert(kind == EVENT_SA_REPLACE || kind == EVENT_SA_EXPIRE);
		dbg("#%lu will %s in %jd seconds (%s)",
		    st->st_serialno,
		    kind == EVENT_SA_EXPIRE ? "expire" : "be replaced",
		    delay, story);
	}

	delete_event(st);
	event_schedule(kind, deltatime(delay), st);
}

static void ikev2_log_initiate_child_fail(const struct state *st)
{
	const struct state *pst = state_with_serialno(st->st_clonedfrom);

	if (pst == NULL)
		return;

	msgid_t unack = pst->st_msgid_nextuse - pst->st_msgid_lastack - 1;

	switch (st->st_state) {
	case STATE_V2_REKEY_IKE_I0:
	case STATE_V2_REKEY_CHILD_I0:
	case STATE_V2_CREATE_I0:
		if (unack < st->st_connection->ike_window) {
			loglog(RC_LOG_SERIOUS,
				"expiring %s state. Possible Message Id deadlock?  Parent #%lu unacknowledged %u next Message Id=%u IKE exchange window %u",
				st->st_state_name,
				pst->st_serialno, unack,
				pst->st_msgid_nextuse,
				pst->st_connection->ike_window);
		}
		break;
	default:
		break;
	}
}

void v2_event_sa_rekey(struct state *st)
{
	monotime_t now = mononow();
	const char *satype = IS_IKE_SA(st) ? "IKE" : "CHILD";

	so_serial_t newer_sa = get_newer_sa_from_connection(st);
	if (newer_sa != SOS_NOBODY) {
		/* implies a double re-key? */
		PEXPECT_LOG("not replacing stale %s SA #%lu; as already got a newer #%lu",
			    satype, st->st_serialno, newer_sa);
		event_force(EVENT_SA_EXPIRE, st);
		return;
	}

	if (expire_ike_because_child_not_used(st)) {
		struct ike_sa *ike = ike_sa(st);
		event_force(EVENT_SA_EXPIRE, &ike->sa);
		return;
	}

	if (monobefore(st->st_replace_by, now)) {
		dbg("#%lu has no time to re-key, will replace",
		    st->st_serialno);
		event_force(EVENT_SA_REPLACE, st);
	}

	ikev2_log_initiate_child_fail(st);
	dbg("rekeying stale %s SA", satype);
	if (IS_IKE_SA(st)) {
		pexpect(IS_IKE_SA(st));
		libreswan_log("initiate rekey of IKEv2 CREATE_CHILD_SA IKE Rekey");
		/* ??? why does this not need whack socket fd? */
		ikev2_log_initiate_child_fail(st);
		ikev2_rekey_ike_start(st);
	} else {
		/*
		 * XXX: Don't be fooled, ipsecdoi_replace() is magic -
		 * if the old state still exists it morphs things into
		 * a child re-key.
		 */
		ipsecdoi_replace(st, 1);
	}
	/*
	 * Should the rekey go into the weeds this replace will kick
	 * in.
	 *
	 * XXX: should the next event be SA_EXPIRE instead of
	 * SA_REPLACE?  For an IKE SA it breaks ikev2-32-nat-rw-rekey.
	 * For a CHILD SA perhaps - there is a mystery around what
	 * happens to the new child if the old one disappears.
	 */
	dbg("scheduling drop-dead replace event for #%lu", st->st_serialno);
	delete_liveness_event(st);
	delete_dpd_event(st);
	event_schedule(EVENT_SA_REPLACE, monotimediff(st->st_replace_by, now), st);
}

void v2_event_sa_replace(struct state *st)
{
	const char *satype = IS_IKE_SA(st) ? "IKE" : "CHILD";

	so_serial_t newer_sa = get_newer_sa_from_connection(st);
	if (newer_sa != SOS_NOBODY) {
		/*
		 * For some reason the rekey, above, hasn't completed.
		 * For an IKE SA blow away the entire family
		 * (including the in-progress rekey).  For a CHILD SA
		 * this will delete the old SA but leave the rekey
		 * alone.  Confusing.
		 */
		if (IS_IKE_SA(st)) {
			dbg("replacing entire stale IKE SA #%lu family; rekey #%lu will be deleted",
			    st->st_serialno, newer_sa);
			ipsecdoi_replace(st, 1);
		} else {
			dbg("expiring stale CHILD SA #%lu; newer #%lu will replace?",
			    st->st_serialno, newer_sa);
		}
		/* XXX: are these calls needed? it's about to die */
		delete_liveness_event(st);
		delete_dpd_event(st);
		event_force(EVENT_SA_EXPIRE, st);
		return;
	}

	if (expire_ike_because_child_not_used(st)) {
		struct ike_sa *ike = ike_sa(st);
		event_force(EVENT_SA_EXPIRE, &ike->sa);
		return;
	}

	/*
	 * XXX: For a CHILD SA, will this result in a re-key attempt?
	 */
	ikev2_log_initiate_child_fail(st);
	dbg("replacing stale %s SA", satype);
	ipsecdoi_replace(st, 1);
	delete_liveness_event(st);
	delete_dpd_event(st);
	event_force(EVENT_SA_EXPIRE, st);
}
