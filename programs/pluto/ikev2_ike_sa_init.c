/* Process IKEv2 IKE_SA_INIT packets, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010,2013-2017 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Simon Deziel <simon@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2011-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney
 * Copyright (C) 2016-2018 Antony Antony <appu@phenome.org>
 * Copyright (C) 2017 Sahana Prasad <sahana.prasad07@gmail.com>
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

#include "defs.h"

#include "ikev2_ike_sa_init.h"

#include "demux.h"
#include "log.h"
#include "state.h"
#include "crypt_dh.h"
#include "crypt_ke.h"
#include "ike_alg.h"
#include "ike_alg_integ.h"
#include "connections.h"
#include "ikev2_states.h"
#include "instantiate.h"
#include "pending.h"
#include "ikev2_parent.h"
#include "ikev2_ipseckey.h"
#include "ikev2_proposals.h"
#include "ikev2_redirect.h"
#include "ikev2_vendorid.h"
#include "ikev2_certreq.h"
#include "pluto_stats.h"
#include "ikev2_nat.h"
#include "nat_traversal.h"
#include "ikev2_ike_intermediate.h"
#include "ikev2_ike_auth.h"
#include "ikev2_cookie.h"
#include "ikev2_eap.h"
#include "unpack.h"
#include "ikev2_message.h"
#include "ikev2_send.h"
#include "packet.h"
#include "passert.h"
#include "state.h"
#include "ikev2.h"		/* for ikev2_state_transition_fn */
#include "ikev2_prf.h"
#include "crypt_symkey.h"
#include "ikev2_notification.h"
#include "config_setup.h"

static ke_and_nonce_cb initiate_v2_IKE_SA_INIT_request_continue;	/* type assertion */
static dh_shared_secret_cb process_v2_IKE_SA_INIT_response_continue;	/* type assertion */
static ke_and_nonce_cb process_v2_IKE_SA_INIT_request_continue;		/* forward decl and type assertion */
static ikev2_state_transition_fn process_v2_IKE_SA_INIT_request;
static ikev2_state_transition_fn process_v2_IKE_SA_INIT_response;
static ikev2_state_transition_fn process_v2_IKE_SA_INIT_response_v2N_INVALID_KE_PAYLOAD;

static void llog_process_v2_IKE_SA_INIT_request_success(struct ike_sa *ike);
static void llog_process_v2_IKE_SA_INIT_response_success(struct ike_sa *ike);

static void jam_secured(struct jambuf *buf, struct ike_sa *ike)
{
	PASSERT(ike->sa.logger, ike->sa.st_oakley.ta_encrypt != NULL);
	PASSERT(ike->sa.logger, ike->sa.st_oakley.ta_prf != NULL);
	PASSERT(ike->sa.logger, ike->sa.st_oakley.ta_dh != NULL);

	jam_string(buf, "{");

	jam_string(buf, "cipher=");
	jam_string(buf, ike->sa.st_oakley.ta_encrypt->common.fqn);
	if (ike->sa.st_oakley.enckeylen > 0) {
		/* XXX: also check omit key? */
		jam(buf, "_%d", ike->sa.st_oakley.enckeylen);
	}

	jam_string(buf, " ");

	jam_string(buf, "integ=");
	jam_string(buf, (ike->sa.st_oakley.ta_integ == &ike_alg_integ_none ? "n/a" :
			 ike->sa.st_oakley.ta_integ->common.fqn));

	jam_string(buf, " ");

	jam_string(buf, "prf=");
	jam_string(buf, ike->sa.st_oakley.ta_prf->common.fqn);

	jam_string(buf, " ");

	jam_string(buf, "group=");
	jam_string(buf, ike->sa.st_oakley.ta_dh->common.fqn);

	jam_string(buf, "}");
}

void llog_process_v2_IKE_SA_INIT_request_success(struct ike_sa *ike)
{
	LLOG_JAMBUF(RC_LOG, ike->sa.logger, buf) {
		jam_string(buf, "sent IKE_SA_INIT response to ");
		jam_endpoint_address_protocol_port_sensitive(buf, &ike->sa.st_remote_endpoint);
		jam_string(buf, " ");
		jam_secured(buf, ike);
	}

}

void llog_process_v2_IKE_SA_INIT_response_success(struct ike_sa *ike)
{
	LLOG_JAMBUF(RC_LOG, ike->sa.logger, buf) {

		jam_string(buf, "processed IKE_SA_INIT response from ");
		jam_endpoint_address_protocol_port_sensitive(buf, &ike->sa.st_remote_endpoint);
		jam_string(buf, " ");

		jam_secured(buf, ike);

		jam_string(buf, ", initiating ");
		enum ikev2_exchange ix =
			(ike->sa.st_v2_ike_intermediate.enabled ? ISAKMP_v2_IKE_INTERMEDIATE :
			 ISAKMP_v2_IKE_AUTH);
		jam_enum_short(buf, &ikev2_exchange_names, ix);
	}
}

bool calc_v2_new_ike_keymat(struct ike_sa *ike,
			    const ike_spis_t *new_ike_spis,
			    where_t where)
{
	struct logger *logger = ike->sa.logger;
	PK11SymKey *shared = ike->sa.st_dh_shared_secret;
	const struct prf_desc *prf = ike->sa.st_oakley.ta_prf;

	ldbg(logger, "%s() calculating skeyseed using prf=%s",
	     __func__, prf->common.fqn);

	/* generate SKEYSEED from key=(Ni|Nr), hash of shared */
	PK11SymKey *skeyseed = ikev2_ike_sa_skeyseed(prf, ike->sa.st_ni, ike->sa.st_nr,
						     shared, logger);
	if (skeyseed == NULL) {
		llog_pexpect(logger, where, "rekey SKEYSEED failed");
		return false;
	}

	calc_v2_ike_keymat(&ike->sa, skeyseed, new_ike_spis);
	symkey_delref(logger, "skeyseed", &skeyseed);
	return true;
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
 * Note: this is not called from demux.c, but from initiate().
 *
 */

struct ike_sa *initiate_v2_IKE_SA_INIT_request(struct connection *c,
					       struct state *predecessor,
					       const struct child_policy *policy,
					       const threadtime_t *inception,
					       shunk_t sec_label,
					       bool detach_whack)
{
	struct ike_sa *ike = new_v2_ike_sa_initiator(c);
	if (ike == NULL) {
		return NULL;
	}

	start_v2_exchange(ike, &v2_IKE_SA_INIT_exchange, HERE);

	statetime_t start = statetime_backdate(&ike->sa, inception);

	/* set up new state */
	passert(ike->sa.st_ike_version == IKEv2);
	passert(ike->sa.st_state == &state_v2_IKE_SA_INIT_I0);
	passert(ike->sa.st_sa_role == SA_INITIATOR);

	if (is_labeled(c) && sec_label.len == 0) {
		/*
		 * Establishing a sec_label connection yet there's no
		 * sec-label for the child.  Assume this is a forced
		 * up aka childless IKE SA.
		 */
		PEXPECT(ike->sa.logger, is_labeled_parent(c));
		ldbg(ike->sa.logger,
		     "labeled parent connection with sec_label="PRI_SHUNK" but no child sec_label; assuming childless",
		     pri_shunk(c->config->sec_label));
	} else if (!has_child_policy(policy)) {
		/*
		 * When replacing (re-authenticating) the IKE (ISAKMP)
		 * SA, policy=LEMPTY stopping the code adding a
		 * pending child - the Child will be lurking on the
		 * replace queue!?!
		 */
		ldbg(ike->sa.logger,
		     "omitting CHILD SA payloads from the IKE_AUTH request as no child policy");
	} else if (impair.omit_v2_ike_auth_child) {
		llog_sa(RC_LOG, ike, "IMPAIR: omitting CHILD SA payloads from the IKE_AUTH request");
	} else {
		struct connection *cc;
		if (is_labeled(c)) {
			PEXPECT(ike->sa.logger, is_labeled_parent(c));
			PEXPECT(ike->sa.logger, c == ike->sa.st_connection);
			cc = labeled_parent_instantiate(ike, sec_label, HERE);
		} else {
			cc = connection_addref(c, ike->sa.logger);
		}
		append_pending(ike, cc, policy,
			       (predecessor == NULL ? SOS_NOBODY : predecessor->st_serialno),
			       sec_label, true/*part of initiate*/, detach_whack);
		connection_delref(&cc, ike->sa.logger);
	}

	/*
	 * XXX: this is the first of two IKE_SA_INIT messages that are
	 * logged when building and sending an IKE_SA_INIT request:
	 *
	 * 1. initiating IKEv2 connection
	 *
	 *    The state has been started and the first task has been
	 *    off-loaded.  Since the connection is oriented, it is
	 *    assumed that the peer's address has been resolved.
	 *
	 *    XXX: can the dns lookup be resolved here as part of the
	 *    off load?
	 *
	 * 2. sending IKE_SA_INIT request ...
	 *
	 *    The message has been constructed and sent
	 */

	if (predecessor != NULL) {
		const char *what;
		if (IS_CHILD_SA_ESTABLISHED(predecessor)) {
			what = "established Child SA";
		} else if (IS_IKE_SA_ESTABLISHED(predecessor)) {
			ike->sa.st_v2_ike_pred = predecessor->st_serialno;
			what = "established IKE SA";
		} else if (IS_IKE_SA(predecessor)) {
			what = "establishing IKE SA";
		} else {
			what = "establishing Child SA";
		}
		llog(RC_LOG, ike->sa.logger,
		     "initiating IKEv2 connection to replace %s #%lu",
		     what, predecessor->st_serialno);
		move_pending(ike_sa(predecessor, HERE), ike);
	} else {
		address_buf ab;
		const struct ip_protocol *protocol = endpoint_protocol(ike->sa.st_remote_endpoint);
		ip_address remote_addr = endpoint_address(ike->sa.st_remote_endpoint);
		llog(RC_LOG, ike->sa.logger,
		     "initiating IKEv2 connection to %s using %s",
		     str_address(&remote_addr, &ab),
		     protocol->name);
	}

	/*
	 * XXX: hack: detach from whack _after_ the above message has
	 * been logged.  Better to do that in the caller?
	 */
	if (detach_whack) {
		release_whack(ike->sa.logger, HERE);
	}

	if (IS_LIBUNBOUND && id_ipseckey_allowed(ike, IKEv2_AUTH_RESERVED)) {
		/*
		 * This submits a background task?  How is it ever
		 * synced?
		 *
		 * The value returned (the PUBKEY) is required during
		 * IKE AUTH.
		 */
		if (!initiator_fetch_idr_ipseckey(ike)) {
			llog_sa(RC_LOG, ike,
				"fetching IDr IPsec key using DNS failed");
			delete_ike_sa(&ike);
			return NULL;
		}
	}

	/*
	 * Initialize ike->sa.st_oakley, including the group number.
	 * Grab the DH group from the first configured proposal and build KE.
	 */
	const struct ikev2_proposals *ike_proposals = c->config->v2_ike_proposals;
	ike->sa.st_oakley.ta_dh = ikev2_proposals_first_dh(ike_proposals);
	if (ike->sa.st_oakley.ta_dh == NULL) {
		llog_sa(RC_LOG, ike, "proposals do not contain a valid DH");
		delete_ike_sa(&ike);
		return NULL;
	}

	/*
	 * Calculate KE and Nonce.
	 */
	submit_ke_and_nonce(/*callback*/&ike->sa, /*task*/&ike->sa, /*no-md*/NULL,
			    ike->sa.st_oakley.ta_dh,
			    initiate_v2_IKE_SA_INIT_request_continue,
			    detach_whack, HERE);
	statetime_stop(&start, "%s()", __func__);
	return ike;
}

stf_status initiate_v2_IKE_SA_INIT_request_continue(struct state *ike_st,
						    struct msg_digest *unused_md,
						    struct dh_local_secret *local_secret,
						    chunk_t *nonce)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_st);
	pexpect(ike->sa.st_sa_role == SA_INITIATOR);
	pexpect(unused_md == NULL);
	/* I1 is from INVALID KE */
	pexpect(ike->sa.st_state == &state_v2_IKE_SA_INIT_I0 ||
		ike->sa.st_state == &state_v2_IKE_SA_INIT_I);
	dbg("%s() for #%lu %s",
	     __func__, ike->sa.st_serialno, ike->sa.st_state->name);

	unpack_KE_from_helper(&ike->sa, local_secret, &ike->sa.st_gi);
	unpack_nonce(&ike->sa.st_ni, nonce);
	return record_v2_IKE_SA_INIT_request(ike) ? STF_OK : STF_INTERNAL_ERROR;
}

static bool emit_v2N_SIGNATURE_HASH_ALGORITHMS(lset_t sighash_policy,
					       struct pbs_out *outs)
{
	v2_notification_t ntype = v2N_SIGNATURE_HASH_ALGORITHMS;

	if (impair.omit_v2_notification.enabled &&
	    impair.omit_v2_notification.value == ntype) {
		name_buf eb;
		llog(RC_LOG, outs->logger,
		     "IMPAIR: omitting %s notification",
		     str_enum_short(&v2_notification_names, ntype, &eb));
		return true;
	}

	struct pbs_out n_pbs;

	if (!open_v2N_output_pbs(outs, ntype, &n_pbs)) {
		llog(RC_LOG, outs->logger, "error initializing notify payload for notify message");
		return false;
	}

#define H(POLICY, ID)							\
	if (sighash_policy & POLICY) {					\
		uint16_t hash_id = htons(ID);				\
		passert(sizeof(hash_id) == RFC_7427_HASH_ALGORITHM_IDENTIFIER_SIZE); \
		if (!pbs_out_thing(&n_pbs, hash_id,			\
				 "hash algorithm identifier "#ID)) {	\
			/* already logged */				\
			return false;					\
		}							\
	}
	H(POL_SIGHASH_SHA2_256, IKEv2_HASH_ALGORITHM_SHA2_256);
	H(POL_SIGHASH_SHA2_384, IKEv2_HASH_ALGORITHM_SHA2_384);
	H(POL_SIGHASH_SHA2_512, IKEv2_HASH_ALGORITHM_SHA2_512);
#undef H

	close_output_pbs(&n_pbs);
	return true;
}

bool record_v2_IKE_SA_INIT_request(struct ike_sa *ike)
{
	struct connection *c = ike->sa.st_connection;

	struct v2_message request;
	if (!open_v2_message("IKE_SA_INIT request",
			     ike, ike->sa.logger, NULL/*request*/,
			     ISAKMP_v2_IKE_SA_INIT,
			     reply_buffer, sizeof(reply_buffer),
			     &request, UNENCRYPTED_PAYLOAD)) {
		return false;
	}

	if (impair.send_bogus_dcookie) {
		/* add or mangle a dcookie so what we will send is bogus */
		DBG_log("Mangling dcookie because --impair-send-bogus-dcookie is set");
		uint8_t byte = 0;
		messupn(&byte, sizeof(byte));
		replace_chunk(&ike->sa.st_dcookie, THING_AS_SHUNK(byte), "mangled dcookie");
	}

	/*
	 * https://tools.ietf.org/html/rfc5996#section-2.6
	 * reply with the anti DDOS cookie if we received one (remote is under attack)
	 */
	if (ike->sa.st_dcookie.ptr != NULL) {
		/* In v2, for parent, protoid must be 0 and SPI must be empty */
		if (!emit_v2N_hunk(v2N_COOKIE, ike->sa.st_dcookie, request.pbs)) {
			return false;
		}
	}

	/* SA out */

	const struct ikev2_proposals *ike_proposals = c->config->v2_ike_proposals;
	if (!emit_v2SA_proposals(request.pbs, ike_proposals,
				 null_shunk /* IKE - no CHILD SPI */)) {
		return false;
	}

	/*
	 * ??? from here on, this looks a lot like the end of
	 * ikev2_in_IKE_SA_INIT_I_out_IKE_SA_INIT_R_tail.
	 */

	/* send KE */
	if (!emit_v2KE(ike->sa.st_gi, ike->sa.st_oakley.ta_dh, request.pbs))
		return false;

	/* send NONCE */
	{
		struct pbs_out pb;
		struct ikev2_generic in = {
			.isag_critical = build_ikev2_critical(false, ike->sa.logger),
		};

		if (!out_struct(&in, &ikev2_nonce_desc, request.pbs, &pb) ||
		    !out_hunk(ike->sa.st_ni, &pb, "IKEv2 nonce"))
			return false;

		close_output_pbs(&pb);
	}

	/* Send fragmentation support notification */
	if (c->config->ike_frag.allow) {
		if (!emit_v2N(v2N_IKEV2_FRAGMENTATION_SUPPORTED, request.pbs))
			return false;
	}

	/* Send USE_PPK Notify payload */
	if (c->config->ppk.allow) {
		if (!emit_v2N(v2N_USE_PPK, request.pbs))
			return false;
	}

	/* Send INTERMEDIATE_EXCHANGE_SUPPORTED (and maybe USE_PPK_INT) Notify payload */
	if (c->config->intermediate) {
		if (!emit_v2N(v2N_INTERMEDIATE_EXCHANGE_SUPPORTED, request.pbs))
			return false;
		if (c->config->ppk.allow) {
			if (!emit_v2N(v2N_USE_PPK_INT, request.pbs))
				return false;
		}
	}

	/* first check if this IKE_SA_INIT came from redirect
	 * instruction.
	 * - if yes, send the v2N_REDIRECTED_FROM
	 *   with the identity of previous gateway
	 * - if not, check if we support redirect mechanism
	 *   and send v2N_REDIRECT_SUPPORTED if we do
	 */
	if (address_is_specified(c->redirect.ip)) {
		if (!emit_v2N_REDIRECTED_FROM(&c->redirect.old_gw_address, request.pbs)) {
			return false;
		}
	} else if (c->config->redirect.accept) {
		if (!emit_v2N(v2N_REDIRECT_SUPPORTED, request.pbs))
			return false;
	}

	/*
	 * Send the initiator's SIGNATURE_HASH_ALGORITHMS notification
	 * based on the remote's .authby.
	 *
	 * The initiator would like the responder to prove their
	 * identity using one of these hashes (plus a signature).
	 * Since the initiator can't switch connections the decision is
	 * final.
	 */
	if (authby_has_digsig(c->remote->host.config->authby) &&
	    (c->config->sighash_policy != LEMPTY)) {
		if (!emit_v2N_SIGNATURE_HASH_ALGORITHMS(c->config->sighash_policy, request.pbs)) {
			return false;
		}
	}

	/* Send NAT-T Notify payloads */
	if (!ikev2_out_nat_v2n(request.pbs, &ike->sa, &zero_ike_spi/*responder unknown*/))
		return false;

	/* From here on, only payloads left are Vendor IDs */
	if (c->config->send_vendorid) {
		if (!emit_v2V(request.pbs, config_setup_vendorid()))
			return false;
	}

	if (c->config->send_vid_fake_strongswan) {
		if (!emit_v2VID(request.pbs, VID_STRONGSWAN))
			return false;
	}

	/*
	 * Announce to the world that this end likes NULL
	 * authentication (either accepts NULL authentication or is
	 * going to use to authenticate).
	 *
	 * XXX: is announcing to the world that this end accepts NULL
	 * authentication really a good idea?
	 *
	 * XXX: should this check POLICY_OPPORTUNISTIC?
	 */
	if (c->local->host.config->authby.null ||
	    c->remote->host.config->authby.null) {
		if (!emit_v2VID(request.pbs, VID_OPPORTUNISTIC))
			return false;
	}

	if (!close_and_record_v2_message(&request)) {
		return false;
	}

	/* save packet for later signing */
	replace_chunk(&ike->sa.st_firstpacket_me,
		      pbs_out_all(&request.message),
		      "saved first packet");

	return true;
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

stf_status process_v2_IKE_SA_INIT_request(struct ike_sa *ike,
					  struct child_sa *child,
					  struct msg_digest *md)
{
	/*
	 * This log line establishes that resources (such as the state
	 * structure) have been allocated and the packet is being
	 * processed for real.
	 */
	llog_msg_digest(RC_LOG, ike->sa.logger, "processing", md);

	v2_notification_t n;
	pexpect(child == NULL);
	struct connection *c = ike->sa.st_connection;
	/* set up new state */
	update_ike_endpoints(ike, md);
	passert(ike->sa.st_ike_version == IKEv2);
	passert(ike->sa.st_state == &state_v2_UNSECURED_R);
	passert(ike->sa.st_sa_role == SA_RESPONDER);

	/* Vendor ID processing */
	for (struct payload_digest *v = md->chain[ISAKMP_NEXT_v2V]; v != NULL; v = v->next) {
		handle_v2_vendorid(pbs_in_left(&v->pbs), ike->sa.logger);
	}

	/* Get the proposals ready. */
	const struct ikev2_proposals *ike_proposals = c->config->v2_ike_proposals;

	/*
	 * Select the proposal.
	 */
	n = process_v2SA_payload("IKE responder",
				 &md->chain[ISAKMP_NEXT_v2SA]->pbs,
				 /*expect_ike*/ true,
				 /*expect_spi*/ false,
				 /*expect_accepted*/ false,
				 /*limit-logging*/is_opportunistic(c),
				 &ike->sa.st_v2_accepted_proposal,
				 ike_proposals, ike->sa.logger);
	if (n != v2N_NOTHING_WRONG) {
		pexpect(ike->sa.st_sa_role == SA_RESPONDER);
		record_v2N_response(ike->sa.logger, ike, md,
				    n, empty_shunk,
				    UNENCRYPTED_PAYLOAD);
		/*
		 * STF_FATAL will send the recorded message and then
		 * kill the IKE SA.  Should it instead zombify the IKE
		 * SA so that retransmits get a response?
		 */
		return STF_FATAL;
	}

	if (DBGP(DBG_BASE)) {
		DBG_log_ikev2_proposal("accepted IKE proposal",
				       ike->sa.st_v2_accepted_proposal);
	}

	/*
	 * Convert what was accepted to internal form and apply some
	 * basic validation.  If this somehow fails (it shouldn't but
	 * ...), drop everything.
	 */
	if (!ikev2_proposal_to_trans_attrs(ike->sa.st_v2_accepted_proposal,
					   &ike->sa.st_oakley, ike->sa.logger)) {
		llog_sa(RC_LOG, ike, "IKE responder accepted an unsupported algorithm");
		/* STF_INTERNAL_ERROR doesn't delete ST */
		return STF_FATAL;
	}

	/*
	 * Check that the MODP group in the payload matches the
	 * accepted proposal, and if it does, read it in.
	 */
	if (!v2_accept_ke_for_proposal(ike, &ike->sa, md,
				       ike->sa.st_oakley.ta_dh,
				       UNENCRYPTED_PAYLOAD)) {
		/*
		 * STF_FATAL will send the recorded message and then
		 * kill the IKE SA.  Should it instead zombify the IKE
		 * SA so that retransmits get a response?
		 */
		return STF_FATAL;
	}

	/* extract results */
	ike->sa.st_v2_ike_fragmentation_enabled =
		accept_v2_notification(v2N_IKEV2_FRAGMENTATION_SUPPORTED,
				       ike->sa.logger, md, c->config->ike_frag.allow);

	ike->sa.st_v2_ike_intermediate.enabled =
		accept_v2_notification(v2N_INTERMEDIATE_EXCHANGE_SUPPORTED,
				       ike->sa.logger, md, c->config->intermediate);

	bool ppk_ike_auth_enabled =
		accept_v2_notification(v2N_USE_PPK, ike->sa.logger,
				       md, c->config->ppk.allow);
	bool ppk_ike_intermediate_enabled =
		accept_v2_notification(v2N_USE_PPK_INT, ike->sa.logger,
				       md, c->config->ppk.allow);

	/* PPK (RFC8784 + draft-ietf-ipsecme-ikev2-qr-alt-04) logic */
	if (ike->sa.st_v2_ike_intermediate.enabled && ppk_ike_intermediate_enabled) {
		ike->sa.st_v2_ike_ppk = PPK_IKE_INTERMEDIATE;
	} else if (ppk_ike_auth_enabled) {
		ike->sa.st_v2_ike_ppk = PPK_IKE_AUTH;
	} else {
		ike->sa.st_v2_ike_ppk = PPK_DISABLED;
	}

	if (c->config->ppk.insist && ike->sa.st_v2_ike_ppk == PPK_DISABLED) {
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_NO_PROPOSAL_CHOSEN, empty_shunk,
				    UNENCRYPTED_PAYLOAD);
		llog_sa(RC_LOG, ike,
			"connection has ppk=insist but peer does not support PPK");
		return STF_FATAL;
	}

	ike->sa.st_seen_redirect_sup = (md->pd[PD_v2N_REDIRECTED_FROM] != NULL ||
					md->pd[PD_v2N_REDIRECT_SUPPORTED] != NULL);

	/*
	 * Responder: check v2N_NAT_DETECTION_DESTINATION_IP or/and
	 * v2N_NAT_DETECTION_SOURCE_IP.
	 *
	 *   2.23.  NAT Traversal
	 *
	 *   The IKE initiator MUST check the NAT_DETECTION_SOURCE_IP
	 *   or NAT_DETECTION_DESTINATION_IP payloads if present, and
	 *   if they do not match the addresses in the outer packet,
	 *   MUST tunnel all future IKE and ESP packets associated
	 *   with this IKE SA over UDP port 4500.
	 *
	 * Since this is the responder, there's really not much to do.
	 * It is the initiator that will switch to port 4500 (float
	 * away) when necessary.
	 */
	if (v2_nat_detected(ike, md)) {
		dbg("NAT: responder so initiator gets to switch ports");
		/* should this check that a port is available? */
	}

	if (md->pd[PD_v2N_SIGNATURE_HASH_ALGORITHMS] != NULL) {
		if (!negotiate_hash_algo_from_notification(&md->pd[PD_v2N_SIGNATURE_HASH_ALGORITHMS]->pbs, ike)) {
			record_v2N_response(ike->sa.logger, ike, md,
					    v2N_INVALID_SYNTAX, empty_shunk,
					    UNENCRYPTED_PAYLOAD);
			/*
			 * STF_FATAL will send the recorded
			 * message and then kill the IKE SA.
			 * Should it instead zombify the IKE
			 * SA so that retransmits get a
			 * response?
			 */
			return STF_FATAL;
		}
		ike->sa.st_seen_hashnotify = true;
	}

	/* calculate the nonce and the KE */
	submit_ke_and_nonce(/*callback*/&ike->sa, /*task*/&ike->sa, md,
			    ike->sa.st_oakley.ta_dh,
			    process_v2_IKE_SA_INIT_request_continue,
			    /*detach_whack*/false, HERE);
	return STF_SUSPEND;
}

stf_status process_v2_IKE_SA_INIT_request_continue(struct state *ike_st,
						   struct msg_digest *md,
						   struct dh_local_secret *local_secret,
						   chunk_t *nonce)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_st);
	pexpect(ike->sa.st_sa_role == SA_RESPONDER);
	pexpect(v2_msg_role(md) == MESSAGE_REQUEST); /* i.e., MD!=NULL */
	pexpect(ike->sa.st_state == &state_v2_UNSECURED_R);
	dbg("%s() for #%lu %s: calculated ke+nonce, sending R1",
	    __func__, ike->sa.st_serialno, ike->sa.st_state->name);

	struct connection *c = ike->sa.st_connection;

	/* note that we don't update the state here yet */

	/* Record first packet for later checking of signature.  */
	record_first_v2_packet(ike, md, HERE);

	/* make sure HDR is at start of a clean buffer */

	struct v2_message response;
	if (!open_v2_message("IKE_SA_INIT response",
			     ike, ike->sa.logger, md/*response*/,
			     ISAKMP_v2_IKE_SA_INIT,
			     reply_buffer, sizeof(reply_buffer),
			     &response, UNENCRYPTED_PAYLOAD)) {
		return STF_INTERNAL_ERROR;
	}

	/* start of SA out */
	{
		/*
		 * Since this is the initial IKE exchange, the SPI is
		 * emitted as part of the packet header and not as
		 * part of the proposal.  Hence the NULL SPI.
		 */
		passert(ike->sa.st_v2_accepted_proposal != NULL);
		if (!emit_v2SA_proposal(response.pbs, ike->sa.st_v2_accepted_proposal,
					null_shunk/*IKE has no SPI*/)) {
			dbg("problem emitting accepted proposal");
			return STF_INTERNAL_ERROR;
		}
	}

	/* Ni in */
	if (!accept_v2_nonce(ike->sa.logger, md, &ike->sa.st_ni, "Ni")) {
		/*
		 * Presumably not our fault.  Syntax errors kill the
		 * family, hence FATAL.
		 */
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_INVALID_SYNTAX, empty_shunk/*no-data*/,
				    UNENCRYPTED_PAYLOAD);
		return STF_FATAL;
	}

	/* ??? from here on, this looks a lot like the end of ikev2_parent_outI1_common */

	/*
	 * Unpack and send KE
	 *
	 * Pass the crypto helper's oakley group so that it is
	 * consistent with what was unpacked.
	 *
	 * IKEv2 code (arguably, incorrectly) uses st_oakley.ta_dh to
	 * track the most recent KE sent out.  It should instead be
	 * maintaining a list of KEs sent out (so that they can be
	 * reused should the initial responder flip-flop) and only set
	 * st_oakley.ta_dh once the proposal has been accepted.
	 */
	pexpect(ike->sa.st_oakley.ta_dh == dh_local_secret_desc(local_secret));
	unpack_KE_from_helper(&ike->sa, local_secret, &ike->sa.st_gr);
	if (!emit_v2KE(ike->sa.st_gr, dh_local_secret_desc(local_secret), response.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	/* send NONCE */
	unpack_nonce(&ike->sa.st_nr, nonce);
	{
		struct pbs_out pb;
		struct ikev2_generic in = {
			.isag_critical = build_ikev2_critical(false, ike->sa.logger),
		};

		if (!out_struct(&in, &ikev2_nonce_desc, response.pbs, &pb) ||
		    !out_hunk(ike->sa.st_nr, &pb, "IKEv2 nonce"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&pb);
	}

	/* Send fragmentation support notification response? */
	if (ike->sa.st_v2_ike_fragmentation_enabled) {
		if (!emit_v2N(v2N_IKEV2_FRAGMENTATION_SUPPORTED, response.pbs))
			return STF_INTERNAL_ERROR;
	}

	/* Send INTERMEDIATE_EXCHANGE_SUPPORTED Notify payload */
	if (ike->sa.st_v2_ike_intermediate.enabled) {
		if (!emit_v2N(v2N_INTERMEDIATE_EXCHANGE_SUPPORTED, response.pbs)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* Send USE_PPK / USE_PPK_INT Notify payload */
	if (ike->sa.st_v2_ike_ppk == PPK_IKE_AUTH) {
		if (!emit_v2N(v2N_USE_PPK, response.pbs))
			return STF_INTERNAL_ERROR;
	} else if (ike->sa.st_v2_ike_ppk == PPK_IKE_INTERMEDIATE) {
		if (!emit_v2N(v2N_USE_PPK_INT, response.pbs))
			return STF_INTERNAL_ERROR;
	}

	/*
	 * Send the responder's SIGNATURE_HASH_ALGORITHMS notification
	 * unconditionally:
	 *
	 * + the connection is tentative, remote .authby could be
	 *   wrong (for instance, IKE_AUTH may trigger a switch from
	 *   host-host:PSK -> host-any:RSA).
	 *
	 * + not sending SIGNATURE_HASH_ALGORITHM leaks configuration
	 *   information
	 */
	if (c->config->sighash_policy != LEMPTY) {
		if (!emit_v2N_SIGNATURE_HASH_ALGORITHMS(c->config->sighash_policy, response.pbs)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* Send NAT-T Notify payloads */
	if (!ikev2_out_nat_v2n(response.pbs, &ike->sa, &ike->sa.st_ike_spis.responder)) {
		return STF_INTERNAL_ERROR;
	}

	if (impair.childless_ikev2_supported) {
		llog_sa(RC_LOG, ike, "IMPAIR: omitting CHILDESS_IKEV2_SUPPORTED notify");
	} else {
		if (!emit_v2N(v2N_CHILDLESS_IKEV2_SUPPORTED, response.pbs)) {
			return STF_INTERNAL_ERROR;
		}
		ike->sa.st_v2_childless_ikev2_supported = true;
	}

	/* something the other end won't like */

	/* send CERTREQ */

	if (need_v2CERTREQ_in_IKE_SA_INIT_response(ike)) {
		dbg("going to send a certreq");
		emit_v2CERTREQ(ike, response.pbs);
	}

	if (c->config->send_vendorid) {
		if (!emit_v2V(response.pbs, config_setup_vendorid()))
			return STF_INTERNAL_ERROR;
	}

	if (c->config->send_vid_fake_strongswan) {
		if (!emit_v2VID(response.pbs, VID_STRONGSWAN))
			return STF_INTERNAL_ERROR;
	}

	/*
	 * Announce to the world that this end likes NULL
	 * authentication (either accepts NULL authentication or is
	 * going to use to authenticate).
	 *
	 * XXX: is announcing to the world that this end accepts NULL
	 * authentication really a good idea?
	 *
	 * XXX: should this check POLICY_OPPORTUNISTIC?
	 */
	if (c->local->host.config->authby.null ||
	    c->remote->host.config->authby.null) {
		if (!emit_v2VID(response.pbs, VID_OPPORTUNISTIC))
			return STF_INTERNAL_ERROR;
	}

	if (!close_and_record_v2_message(&response)) {
		return STF_INTERNAL_ERROR;
	}

	/* save packet for later signing */
	replace_chunk(&ike->sa.st_firstpacket_me,
		      pbs_out_all(&response.message),
		      "saved first packet");

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
/* STATE_V2_IKE_SA_INIT_I: R1B --> I1B
 *                     <--  HDR, N
 * HDR, N(COOKIE), SAi1, KEi, Ni -->
 */

static stf_status resubmit_ke_and_nonce(struct ike_sa *ike)
{
	submit_ke_and_nonce(/*callback*/&ike->sa, /*task*/&ike->sa, /*no-md*/NULL,
			    ike->sa.st_oakley.ta_dh,
			    initiate_v2_IKE_SA_INIT_request_continue,
			    /*detach_whack*/false, HERE);
	return STF_SUSPEND;
}

stf_status process_v2_IKE_SA_INIT_response_v2N_INVALID_KE_PAYLOAD(struct ike_sa *ike,
								  struct child_sa *child,
								  struct msg_digest *md)
{
	struct connection *c = ike->sa.st_connection;

	pexpect(child == NULL);
	if (!pexpect(md->pd[PD_v2N_INVALID_KE_PAYLOAD] != NULL)) {
		return STF_INTERNAL_ERROR;
	}
	struct pbs_in invalid_ke_pbs = md->pd[PD_v2N_INVALID_KE_PAYLOAD]->pbs;

	/* careful of DDOS, only log with debugging on? */
	/* we treat this as a "retransmit" event to rate limit these */
	if (!count_duplicate(&ike->sa, MAXIMUM_INVALID_KE_RETRANS)) {
		dbg("ignoring received INVALID_KE packets - received too many (DoS?)");
		return STF_IGNORE;
	}

	/*
	 * There's at least this notify payload, is there more than
	 * one?
	 */
	if (md->chain[ISAKMP_NEXT_v2N]->next != NULL) {
		dbg("ignoring other notify payloads");
	}

	struct suggested_group sg;
	diag_t d = pbs_in_struct(&invalid_ke_pbs, &suggested_group_desc,
				 &sg, sizeof(sg), NULL);
	if (d != NULL) {
		llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
		pfree_diag(&d);
		return STF_IGNORE;
	}

	pstats(invalidke_recv_s, sg.sg_group);
	pstats(invalidke_recv_u, ike->sa.st_oakley.ta_dh->group);

	const struct ikev2_proposals *ike_proposals = c->config->v2_ike_proposals;
	if (!ikev2_proposals_include_modp(ike_proposals, sg.sg_group)) {
		name_buf esb;
		llog_sa(RC_LOG, ike,
			"Discarding unauthenticated INVALID_KE_PAYLOAD response to DH %s; suggested DH %s is not acceptable",
			ike->sa.st_oakley.ta_dh->common.fqn,
			str_enum_short(&oakley_group_names,
				       sg.sg_group, &esb));
		return STF_IGNORE;
	}

	dbg("Suggested modp group is acceptable");
	/*
	 * Since there must be a group object for every local
	 * proposal, and sg.sg_group matches one of the local proposal
	 * groups, a lookup of sg.sg_group must succeed.
	 */
	name_buf ignore;
	const struct dh_desc *new_group = ikev2_dh_desc(sg.sg_group, &ignore);
	passert(new_group != NULL);
	llog_sa(RC_LOG, ike,
		  "Received unauthenticated INVALID_KE_PAYLOAD response to DH %s; resending with suggested DH %s",
		  ike->sa.st_oakley.ta_dh->common.fqn,
		  new_group->common.fqn);
	ike->sa.st_oakley.ta_dh = new_group;
	/* wipe our mismatched KE */
	dh_local_secret_delref(&ike->sa.st_dh_local_secret, HERE);
	/*
	 * get a new KE
	 */
	schedule_reinitiate_v2_ike_sa_init(ike, resubmit_ke_and_nonce);
	return STF_OK;
}

/* STATE_V2_IKE_SA_INIT_I: R1 --> I2
 *                     <--  HDR, SAr1, KEr, Nr, [CERTREQ]
 * HDR, SK {IDi, [CERT,] [CERTREQ,]
 *      [IDr,] AUTH, SAi2,
 *      TSi, TSr}      -->
 */

/*
 * XXX: there's a lot of code duplication between the IKE_AUTH and
 * IKE_INTERMEDIATE paths.
 */

stf_status process_v2_IKE_SA_INIT_response(struct ike_sa *ike,
					   struct child_sa *unused_child UNUSED,
					   struct msg_digest *md)
{
	v2_notification_t n;
	struct connection *c = ike->sa.st_connection;

	/* for testing only */
	if (impair.send_no_ikev2_auth) {
		llog_sa(RC_LOG, ike,
			  "IMPAIR_SEND_NO_IKEV2_AUTH set - not sending IKE_AUTH packet");
		return STF_IGNORE;
	}

	/*
	 * if this connection has a newer Child SA than this state
	 * this negotiation is not relevant any more.  would this
	 * cover if there are multiple CREATE_CHILD_SA pending on this
	 * IKE negotiation ???
	 *
	 * XXX: this is testing for an IKE SA that's been superseded by
	 * a newer IKE SA (not child).  Suspect this is to handle a
	 * race where the other end brings up the IKE SA first?  For
	 * that case, shouldn't this state have been deleted?
	 *
	 * NOTE: a larger serialno does not mean superseded. crossed
	 * streams could mean the lower serial established later and is
	 * the "newest". Should > be replaced with !=   ?
	 */
	if (c->established_child_sa > ike->sa.st_serialno) {
		llog_sa(RC_LOG, ike,
			  "state superseded by #%lu, drop this negotiation",
			  c->established_child_sa);
		return STF_FATAL;
	}

	/*
	 * XXX: this iteration over the notifies modifies state
	 * _before_ the code's committed to creating an SA.  Hack this
	 * by resetting any flags that might be set.
	 *
	 * XXX: comment is probably out-of-date as all fields always
	 * set.
	 */

	ike->sa.st_v2_childless_ikev2_supported =
		(impair.childless_ikev2_supported ? false :
		 md->pd[PD_v2N_CHILDLESS_IKEV2_SUPPORTED] != NULL);

	ike->sa.st_v2_ike_fragmentation_enabled =
		accept_v2_notification(v2N_IKEV2_FRAGMENTATION_SUPPORTED,
				       ike->sa.logger, md, c->config->ike_frag.allow);

	/*
	 * If we see the intermediate AND we are configured to use
	 * intermediate.
	 *
	 * For now, do only one Intermediate Exchange round and
	 * proceed with IKE_AUTH.
	 */
	ike->sa.st_v2_ike_intermediate.enabled =
		accept_v2_notification(v2N_INTERMEDIATE_EXCHANGE_SUPPORTED,
				       ike->sa.logger, md, c->config->intermediate);

	bool ppk_ike_auth_enabled =
		accept_v2_notification(v2N_USE_PPK, ike->sa.logger,
				       md, c->config->ppk.allow);
	bool ppk_ike_intermediate_enabled =
		accept_v2_notification(v2N_USE_PPK_INT, ike->sa.logger,
				       md, c->config->ppk.allow);

	/* PPK (RFC8784 + draft-ietf-ipsecme-ikev2-qr-alt-04) logic */
	if (ike->sa.st_v2_ike_intermediate.enabled && ppk_ike_intermediate_enabled) {
		ike->sa.st_v2_ike_ppk = PPK_IKE_INTERMEDIATE;
	} else if (ppk_ike_auth_enabled) {
		ike->sa.st_v2_ike_ppk = PPK_IKE_AUTH;
	} else {
		ike->sa.st_v2_ike_ppk = PPK_DISABLED;
	}

	if (c->config->ppk.insist && ike->sa.st_v2_ike_ppk == PPK_DISABLED) {
		llog_sa(RC_LOG, ike,
			"connection has ppk=insist but peer does not support PPK");
		return STF_FATAL;
	}

	if (md->pd[PD_v2N_SIGNATURE_HASH_ALGORITHMS] != NULL) {
		if (!negotiate_hash_algo_from_notification(&md->pd[PD_v2N_SIGNATURE_HASH_ALGORITHMS]->pbs, ike)) {
			return STF_FATAL;
		}
		ike->sa.st_seen_hashnotify = true;
	}

	/*
	 * the responder sent us back KE, Gr, Nr, and it's our time to calculate
	 * the shared key values.
	 */

	dbg("ikev2 parent inR1: calculating g^{xy} in order to send I2");

	/* KE in */
	if (!unpack_KE(&ike->sa.st_gr, "Gr", ike->sa.st_oakley.ta_dh,
		       md->chain[ISAKMP_NEXT_v2KE], ike->sa.logger)) {
		/*
		 * XXX: Initiator - so this code will not trigger a
		 * notify.  Since packet isn't trusted, should it be
		 * ignored?
		 *
		 * STF_FATAL will send the code down the retry path.
		 */
		return STF_FATAL;
	}

	/* Ni in */
	if (!accept_v2_nonce(ike->sa.logger, md, &ike->sa.st_nr, "Nr")) {
		/*
		 * Presumably not our fault.  Syntax errors in a
		 * response kill the family (and trigger no further
		 * exchange).
		 *
		 * STF_FATAL will send the code down the retry path.
		 */
		return STF_FATAL;
	}

	/* We're missing processing a CERTREQ in here */

	/* process and confirm the SA selected */
	{
		/* SA body in and out */
		struct payload_digest *const sa_pd =
			md->chain[ISAKMP_NEXT_v2SA];
		const struct ikev2_proposals *ike_proposals = c->config->v2_ike_proposals;

		n = process_v2SA_payload("IKE initiator (accepting)",
					 &sa_pd->pbs,
					 /*expect_ike*/ true,
					 /*expect_spi*/ false,
					 /*expect_accepted*/ true,
					 /*limit-logging*/is_opportunistic(c),
					 &ike->sa.st_v2_accepted_proposal,
					 ike_proposals, ike->sa.logger);
		if (n != v2N_NOTHING_WRONG) {
			dbg("ikev2_parse_parent_sa_body() failed in ikev2_parent_inR1outI2()");
			/*
			 * STF_FATAL will send the code down the retry path.
			 */
			return STF_FATAL; /* initiator; no response */
		}

		if (!ikev2_proposal_to_trans_attrs(ike->sa.st_v2_accepted_proposal,
						   &ike->sa.st_oakley, ike->sa.logger)) {
			llog_sa(RC_LOG, ike,
				"IKE initiator proposed an unsupported algorithm");
			free_ikev2_proposal(&ike->sa.st_v2_accepted_proposal);
			passert(ike->sa.st_v2_accepted_proposal == NULL);
			/*
			 * Assume caller et.al. will clean up the
			 * reset of the mess?
			 *
			 * STF_FATAL will send the code down the retry path.
			 */
			return STF_FATAL;
		}
	}

	/* Record first packet for later checking of signature.  */
	record_first_v2_packet(ike, md, HERE);

	/*
	 * Initiator: check v2N_NAT_DETECTION_DESTINATION_IP or/and
	 * v2N_NAT_DETECTION_SOURCE_IP.
	 *
	 *   2.23.  NAT Traversal
	 *
	 *   The IKE initiator MUST check the NAT_DETECTION_SOURCE_IP
	 *   or NAT_DETECTION_DESTINATION_IP payloads if present, and
	 *   if they do not match the addresses in the outer packet,
	 *   MUST tunnel all future IKE and ESP packets associated
	 *   with this IKE SA over UDP port 4500.
	 *
	 * When detected, float to the NAT port as needed (*ikeport
	 * can't float but already supports NAT).  When the ports
	 * can't support NAT, give up.
	 */

	if (v2_nat_detected(ike, md)) {
		PEXPECT(ike->sa.logger, nat_traversal_detected(&ike->sa));
		if (!v2_natify_initiator_endpoints(ike, HERE)) {
			/* already logged */
			return STF_FATAL;
		}
		if (ike->sa.st_connection->config->nic_offload == NIC_OFFLOAD_PACKET) {
			llog_sa(RC_LOG, ike,
			"connection is NATed but nic-offload=packet does not support NAT");
			return STF_FATAL;
		}
	}

	/*
	 * Initiate the calculation of g^xy.
	 */

	submit_dh_shared_secret(/*callback*/&ike->sa, /*task*/&ike->sa, md,
				ike->sa.st_gr/*initiator needs responder KE*/,
				process_v2_IKE_SA_INIT_response_continue, HERE);
	return STF_SUSPEND;
}

stf_status process_v2_IKE_SA_INIT_response_continue(struct state *ike_sa,
						    struct msg_digest *md)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);

	/*
	 * The DH code should have filled this in.
	 */
	if (ike->sa.st_dh_shared_secret == NULL) {
		/*
		 * XXX: this is the initiator so returning a
		 * notification is kind of useless.
		 *
		 * STF_FATAL will send the code down the retry path.
		 */
		pstat_sa_failed(&ike->sa, REASON_CRYPTO_FAILED);
		return STF_FATAL;
	}

	/*
	 * Form and pass in the full SPI[ir] that will eventually be
	 * used by this IKE SA.  Only once DH has been computed and
	 * the SA is secure (but not authenticated) should the state's
	 * IKE SPIr be updated.
	 */

	pexpect(ike_spi_is_zero(&ike->sa.st_ike_spis.responder));
	ike->sa.st_ike_rekey_spis = (ike_spis_t) {
		.initiator = ike->sa.st_ike_spis.initiator,
		.responder = md->hdr.isa_ike_responder_spi,
	};

	if (!calc_v2_new_ike_keymat(ike, &ike->sa.st_ike_rekey_spis, HERE)) {
		/* already logged */
		return STF_FATAL;
	}

	/*
	 * All systems are go.
	 *
	 * Since DH succeeded, a secure (but unauthenticated) SA
	 * (channel) is available.  From this point on, should things
	 * go south, the state needs to be abandoned (but it shouldn't
	 * happen).
	 */

	/*
	 * Since systems are go, start updating the state, starting
	 * with SPIr.
	 */
	update_st_ike_spis_responder(ike, &md->hdr.isa_ike_responder_spi);

	/*
	 * Parse any CERTREQ in the IKE_SA_INIT response so that it is
	 * available to initiate_v2_IKE_AUTH_request() (possibly after
	 * several IKE_INTERMEDIATE exchanges).
	 */
	process_v2CERTREQ_payload(ike, md);

	/*
	 * The IKE_SA_INIT response has been processed, log completion
	 * and dispatch the next request.
	 */

	const struct v2_exchange *next_exchange;
	if (ike->sa.st_v2_ike_intermediate.enabled) {
		next_exchange = &v2_IKE_INTERMEDIATE_exchange;
	} else {
		next_exchange = &v2_IKE_AUTH_exchange;
	}

	return next_v2_exchange(ike, md, next_exchange, HERE);
}

static const struct v2_transition v2_IKE_SA_INIT_initiate_transition = {
	/* no state:   --> I1
	 * HDR, SAi1, KEi, Ni -->
	 */
	.story      = "initiating IKE_SA_INIT",
	.to = &state_v2_IKE_SA_INIT_I,
	.exchange   = ISAKMP_v2_IKE_SA_INIT,
	.processor  = NULL, /* XXX: should be set */
	.llog_success = llog_v2_success_exchange_sent_to,
	.timeout_event = EVENT_v2_RETRANSMIT,
};

static const struct v2_transition v2_IKE_SA_INIT_responder_transition[] = {
	/* no state: none I1 --> R1
	 *                <-- HDR, SAi1, KEi, Ni
	 * HDR, SAr1, KEr, Nr, [CERTREQ] -->
	 */
	{ .story      = "Respond to IKE_SA_INIT",
	  .to = &state_v2_IKE_SA_INIT_R,
	  .exchange   = ISAKMP_v2_IKE_SA_INIT,
	  .recv_role  = MESSAGE_REQUEST,
	  .message_payloads.required = v2P(SA) | v2P(KE) | v2P(Ni),
	  .processor  = process_v2_IKE_SA_INIT_request,
	  .llog_success = llog_process_v2_IKE_SA_INIT_request_success,
	  .timeout_event = EVENT_v2_DISCARD, },
};

static const struct v2_transition v2_IKE_SA_INIT_response_transition[] = {

	/* STATE_V2_IKE_SA_INIT_I: R1B --> I1B
	 *                     <--  HDR, N
	 * HDR, N, SAi1, KEi, Ni -->
	 */

	{ .story      = "received anti-DDOS COOKIE response; resending IKE_SA_INIT request with cookie payload added",
	  .to = &state_v2_IKE_SA_INIT_I0,
	  .exchange   = ISAKMP_v2_IKE_SA_INIT,
	  .recv_role  = MESSAGE_RESPONSE,
	  .message_payloads.required = v2P(N),
	  .message_payloads.notification = v2N_COOKIE,
	  .processor  = process_v2_IKE_SA_INIT_response_v2N_COOKIE,
	  .llog_success = ldbg_v2_success,
	  .timeout_event = EVENT_v2_DISCARD, },

	{ .story      = "received INVALID_KE_PAYLOAD response; resending IKE_SA_INIT with new KE payload",
	  .to = &state_v2_IKE_SA_INIT_I0,
	  .exchange   = ISAKMP_v2_IKE_SA_INIT,
	  .recv_role  = MESSAGE_RESPONSE,
	  .message_payloads.required = v2P(N),
	  .message_payloads.notification = v2N_INVALID_KE_PAYLOAD,
	  .processor  = process_v2_IKE_SA_INIT_response_v2N_INVALID_KE_PAYLOAD,
	  .llog_success = ldbg_v2_success,
	  .timeout_event = EVENT_v2_DISCARD, },

	{ .story      = "received REDIRECT response; resending IKE_SA_INIT request to new destination",
	  .to = &state_v2_IKE_SA_INIT_I0, /* XXX: never happens STF_SUSPEND */
	  .exchange   = ISAKMP_v2_IKE_SA_INIT,
	  .recv_role  = MESSAGE_RESPONSE,
	  .message_payloads.required = v2P(N),
	  .message_payloads.notification = v2N_REDIRECT,
	  .processor  = process_v2_IKE_SA_INIT_response_v2N_REDIRECT,
	  .llog_success = ldbg_v2_success,
	  .timeout_event = EVENT_v2_DISCARD,
	},

	/* STATE_V2_IKE_SA_INIT_I: R1 --> I2
	 *                     <--  HDR, SAr1, KEr, Nr, [CERTREQ]
	 * HDR, SK {IDi, [CERT,] [CERTREQ,]
	 *      [IDr,] AUTH, SAi2,
	 *      TSi, TSr}      -->
	 */
	{ .story      = "Initiator: process IKE_SA_INIT reply, initiate IKE_AUTH or IKE_INTERMEDIATE",
	  .to = &state_v2_IKE_SA_INIT_IR, /* next exchange does IKE_AUTH | IKE_INTERMEDIATE */
	  .exchange   = ISAKMP_v2_IKE_SA_INIT,
	  .recv_role  = MESSAGE_RESPONSE,
	  .message_payloads.required = v2P(SA) | v2P(KE) | v2P(Nr),
	  .message_payloads.optional = v2P(CERTREQ),
	  .processor  = process_v2_IKE_SA_INIT_response,
	  .llog_success = llog_process_v2_IKE_SA_INIT_response_success,
	  .timeout_event = EVENT_v2_DISCARD, /* timeout set by next transition */
	},

};

V2_STATE(IKE_SA_INIT_I0, "waiting for KE to finish", CAT_IGNORE, /*secured*/false);

V2_STATE(IKE_SA_INIT_R,
	 "sent IKE_SA_INIT response, waiting for IKE_INTERMEDIATE or IKE_AUTH request",
	 CAT_HALF_OPEN_IKE_SA, /*secured*/true,
	 &v2_IKE_AUTH_exchange, &v2_IKE_INTERMEDIATE_exchange, &v2_IKE_AUTH_EAP_exchange);

V2_EXCHANGE(IKE_SA_INIT, "initiate IKE SA",
	    ", preparing IKE_INTERMEDIATE or IKE_AUTH request",
	    CAT_HALF_OPEN_IKE_SA, CAT_OPEN_IKE_SA, /*secured*/false,
	    &state_v2_IKE_SA_INIT_I0);
