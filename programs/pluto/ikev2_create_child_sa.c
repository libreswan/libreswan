/* IKEv2 CREATE_CHILD_SA, for Libreswan
 *
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010-2019 Tuomo Soini <tis@foobar.fi
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2018 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017-2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2017-2018 Vukasin Karadzic <vukasin.karadzic@gmail.com>
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
 *
 */

#include "ike_alg.h"

#include "defs.h"

#include "log.h"
#include "state.h"
#include "state_db.h"
#include "connections.h"
#include "demux.h"
#include "ikev2.h"
#include "ikev2_send.h"
#include "pluto_stats.h"
#include "ikev2_child.h"
#include "ikev2_create_child_sa.h"
#include "addresspool.h"
#include "kernel.h"
#include "ikev2_message.h"
#include "crypt_dh.h"
#include "crypt_ke.h"
#include "unpack.h"
#include "pending.h"
#include "ipsec_doi.h"			/* for capture_child_rekey_policy */
#include "ike_alg_dh.h"			/* for ike_alg_dh_none */
#include "ikev2_proposals.h"
#include "ikev2_parent.h"
#include "ikev2_delete.h"
#include "ikev2_states.h"
#include "ikev2_prf.h"
#include "crypt_symkey.h"
#include "ikev2_notification.h"

static ikev2_state_transition_fn process_v2_CREATE_CHILD_SA_request;

static ikev2_state_transition_fn initiate_v2_CREATE_CHILD_SA_new_child_request;
static ikev2_state_transition_fn initiate_v2_CREATE_CHILD_SA_rekey_child_request;
static ikev2_state_transition_fn initiate_v2_CREATE_CHILD_SA_rekey_ike_request;

static ke_and_nonce_cb process_v2_CREATE_CHILD_SA_rekey_ike_request_continue_1;
static dh_shared_secret_cb process_v2_CREATE_CHILD_SA_rekey_ike_request_continue_2;
static dh_shared_secret_cb process_v2_CREATE_CHILD_SA_rekey_ike_response_continue_1;

static ke_and_nonce_cb process_v2_CREATE_CHILD_SA_request_continue_1;
static dh_shared_secret_cb process_v2_CREATE_CHILD_SA_request_continue_2;

static dh_shared_secret_cb process_v2_CREATE_CHILD_SA_child_response_continue_1;

static ke_and_nonce_cb queue_v2_CREATE_CHILD_SA_rekey_child_request; /* signature check */
static ke_and_nonce_cb queue_v2_CREATE_CHILD_SA_rekey_ike_request; /* signature check */
static ke_and_nonce_cb queue_v2_CREATE_CHILD_SA_new_child_request; /* signature check */

static stf_status process_v2_CREATE_CHILD_SA_request_continue_3(struct ike_sa *ike,
								struct msg_digest *request_md);

static void queue_v2_CREATE_CHILD_SA_initiator(struct state *larval_sa,
					       struct dh_local_secret *local_secret,
					       chunk_t *nonce,
					       const struct v2_exchange *exchange)
{
	dbg("%s() for #%lu %s",
	     __func__, larval_sa->st_serialno, larval_sa->st_state->name);

	struct ike_sa *ike = ike_sa(larval_sa, HERE);
	/* and a parent? */
	if (ike == NULL) {
		/* XXX: drop everything */
		return;
	}

	struct child_sa *larval = pexpect_child_sa(larval_sa);
	if (larval == NULL) {
		/* XXX: drop everything */
		return;
	}

	struct logger *logger = larval->sa.logger;

	PEXPECT(logger, larval->sa.st_sa_role == SA_INITIATOR);
	PEXPECT(logger, (larval->sa.st_state == &state_v2_NEW_CHILD_I0 ||
			 larval->sa.st_state == &state_v2_REKEY_CHILD_I0 ||
			 larval->sa.st_state == &state_v2_REKEY_IKE_I0));
	/*
	 * After initiating a delete the IKE SA transitions to
	 * STATE_V2_IKE_SA_DELETE so accommodate it here (the request
	 * will be queued but never initiated - instead the delete
	 * code will reschedule).
	 *
	 * XXX: 2024-01-29: Note that the STATE_V2_IKE_SA_DELETE is
	 * broken.  When in that state, the IKEv2 state machine will
	 * only accept the delete response which means that the peer
	 * also requesting an IKE SA delete is ignored (see: crossing
	 * IKE SA delete ignored #1587).
	 */
	PEXPECT(logger, ike->sa.st_state == &state_v2_ESTABLISHED_IKE_SA);

	/*
	 * Unpack the crypto material computed out-of-band.
	 *
	 * For Child SAs DH is optional; for IKE SAs it's required.
	 * Hence rekeying the IKE SA implies DH.
	 */
	pexpect((larval->sa.st_state == &state_v2_REKEY_IKE_I0) <=/*implies*/ (local_secret != NULL));
	unpack_nonce(&larval->sa.st_ni, nonce);
	if (local_secret != NULL) {
		unpack_KE_from_helper(&larval->sa, local_secret, &larval->sa.st_gi);
	}

	pdbg(logger, "adding larval SA to IKE SA "PRI_SO" message initiator queue; sec_label="PRI_SHUNK,
	     pri_so(ike->sa.st_serialno),
	     pri_shunk(larval->sa.st_connection->child.sec_label));

	/*
	 * Note: larval SA -> IKE SA hop
	 *
	 * This function is a callback for the larval SA (the
	 * stf_status STF_SKIP_COMPLETE_STATE_TRANSITION will be
	 * returned so that the state machine does not try to update
	 * its state).
	 *
	 * When the queued exchange is initiated, the callback
	 * TRANSITION .processor(IKE) will be called with the IKE SA.
	 */

	PEXPECT(larval->sa.logger,
		larval->sa.st_state->v2.child_transition->exchange == ISAKMP_v2_CREATE_CHILD_SA);
	v2_msgid_queue_exchange(ike, larval, exchange);
}

/*
 * Find all CHILD SAs belonging to FROM and migrate them to TO.
 */

static void migrate_v2_child(struct ike_sa *from, struct child_sa *to,
			     struct child_sa *child)
{
	ldbg_sa(child, "migrating Child SA "PRI_SO" from IKE SA "PRI_SO" to IKE SA "PRI_SO,
		pri_so(child->sa.st_serialno),
		pri_so(from->sa.st_serialno),
		pri_so(to->sa.st_serialno));
	passert(child->sa.st_clonedfrom == from->sa.st_serialno);
	passert(child->sa.st_serialno != to->sa.st_serialno);
	/*
	 * Migrate the Child SA to the new IKE SA.
	 */
	update_st_clonedfrom(&child->sa, to->sa.st_serialno);
	/*
	 * Delete the old IKE_SPI hash entries (both for I and I+R
	 * and), and then inserts new ones using ST's current IKE SPI
	 * values.  The serialno tables are not touched.
	 *
	 * XXX: this is to keep code that still uses
	 * state_by_ike_spis() to find children working.
	 */
	update_st_ike_spis(child, &to->sa.st_ike_spis);
}

static void migrate_v2_children(struct ike_sa *from, struct child_sa *to)
{
	/*
	 * TO is in the process of being emancipated.  Its
	 * .st_clonedfrom has been zapped (i.e., it is no longer a
	 * child of FROM) and the new IKE_SPIs installed (a true child
	 * would have FROM's IKE SPIs).
	 */
	ldbg_sa(to, "migrate children from "PRI_SO" to "PRI_SO,
		pri_so(from->sa.st_serialno),
		pri_so(to->sa.st_serialno));
	passert(to->sa.st_clonedfrom == SOS_NOBODY);
	/* passert(SPIs should be different) */
	struct state_filter child = {
		.clonedfrom = from->sa.st_serialno,
		.search = {
			.order = OLD2NEW,
			.verbose.logger = &global_logger,
			.where = HERE,
		},
	};
	while (next_state(&child)) {
		migrate_v2_child(from, to, pexpect_child_sa(child.st));
	}
}

static void emancipate_larval_ike_sa(struct ike_sa *old_ike, struct child_sa *new_ike)
{
	/* initialize the the new IKE SA. reset and message ID */
	update_st_clonedfrom(&new_ike->sa, SOS_NOBODY);

	v2_msgid_init_ike(pexpect_ike_sa(&new_ike->sa));

	/* Switch to the new IKE SPIs */
	update_st_ike_spis(new_ike, &new_ike->sa.st_ike_rekey_spis);

	migrate_v2_children(old_ike, new_ike);

	dbg("moving over any pending requests");
	v2_msgid_migrate_queue(old_ike, new_ike);
	v2_msgid_schedule_next_initiator(pexpect_ike_sa(&new_ike->sa));

	/* complete the state transition */
	const struct v2_transition *transition = new_ike->sa.st_v2_transition;
	pexpect(transition->to == &state_v2_ESTABLISHED_IKE_SA);
	change_v2_state(&new_ike->sa); /* should trash .st_v2_transition */

	/* child is now a parent */
	v2_ike_sa_established(pexpect_ike_sa(&new_ike->sa), HERE);

	/* Schedule for whatever timeout is specified */
	event_delete(EVENT_v2_DISCARD, &new_ike->sa); /* relying on replace */
	schedule_v2_replace_event(&new_ike->sa);

	/*
	 * Announce this to the world.
	 */
	/* XXX: call transition->llog()? */
	llog_v2_ike_sa_established(old_ike, new_ike);
	release_whack(new_ike->sa.logger, HERE);
}

/*
 * Find the Child SA identified by the v2N_REKEY_SA payload.
 *
 * FALSE: payload corrupt; caller should respond with the fatal
 * v2N_INVALID_SYNTAX.
 *
 * TRUE, CHILD==NULL: payload ok but no matching Child SA was
 * found. The v2N_CHILD_SA_NOT_FOUND response already recorded using
 * information extracted from the rekey notify payload.
 *
 * TRUE, CHILD!=NULL: payload ok, matching Child SA found.
 */

static bool find_v2N_REKEY_SA_child(struct ike_sa *ike,
				    struct msg_digest *md,
				    struct child_sa **child)
{
	*child = NULL;

	/*
	 * Previously decoded and minimially validated by the state
	 * machine using ikev2_notify_desc (i.e., more validation
	 * required).
	 */

	const struct payload_digest *rekey_sa_payload = md->pd[PD_v2N_REKEY_SA];
	if (rekey_sa_payload == NULL) {
		llog_pexpect(ike->sa.logger, HERE,
			     "rekey child can't find its rekey_sa payload");
		return false;
	}

	const struct ikev2_notify *rekey_notify = &rekey_sa_payload->payload.v2n;

	/*
	 * Check the protocol.
	 *
	 * "ikev2_notify_desc" allows 0, IKE, ESP and AH; reject the
	 * first two.  Will also need to check that the protocol
	 * matches that extablished by the Child SA.
	 */

	if (rekey_notify->isan_protoid != PROTO_IPSEC_ESP &&
	    rekey_notify->isan_protoid != PROTO_IPSEC_AH) {
		esb_buf b;
		llog_sa(RC_LOG, ike,
			"CREATE_CHILD_SA IPsec SA rekey invalid Protocol ID %s",
			str_enum(&ikev2_notify_protocol_id_names, rekey_notify->isan_protoid, &b));
		return false;
	}

	esb_buf b;
	ldbg_sa(ike, "CREATE_CHILD_SA IPsec SA rekey Protocol %s",
		str_enum(&ikev2_notify_protocol_id_names, rekey_notify->isan_protoid, &b));

	/*
	 * Get the SPI.
	 *
	 * The SPI (and the protoid?) can be used to find the Child SA
	 * to rekey.
	 */

	if (rekey_notify->isan_spisize != sizeof(ipsec_spi_t)) {
		llog_sa(RC_LOG, ike,
			"CREATE_CHILD_SA IPsec SA rekey invalid spi size %u",
			rekey_notify->isan_spisize);
		return false;
	}

	ipsec_spi_t spi = 0; /* network ordered */
	struct pbs_in rekey_pbs = rekey_sa_payload->pbs;
	diag_t d = pbs_in_thing(&rekey_pbs, spi, "SPI");
	if (d != NULL) {
		/* for instance, truncated SPI */
		llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
		pfree_diag(&d);
		return false;
	}

	if (spi == 0) {
		llog_sa(RC_LOG, ike,
			"CREATE_CHILD_SA IPsec SA rekey contains zero SPI");
		return false;
	}

	esb_buf protoesb;
	ldbg_sa(ike, "CREATE_CHILD_SA to rekey IPsec SA("PRI_IPSEC_SPI") Protocol %s",
		pri_ipsec_spi(spi),
		str_enum(&ikev2_notify_protocol_id_names, rekey_notify->isan_protoid, &protoesb));

	/*
	 * From 1.3.3.  Rekeying Child SAs with the CREATE_CHILD_SA
	 * Exchange: The SA being rekeyed is identified by the SPI
	 * field in the [REKEY_SA] Notify payload; this is the SPI the
	 * exchange initiator would expect in inbound ESP or AH
	 * packets.
	 *
	 * From our, the responder's POV, that's the outbound SPI.
	 */

	struct child_sa *replaced_child = find_v2_child_sa_by_outbound_spi(ike, rekey_notify->isan_protoid, spi);
	if (replaced_child == NULL) {
		esb_buf b;
		llog_sa(RC_LOG, ike,
			"CREATE_CHILD_SA no such IPsec SA to rekey SA("PRI_IPSEC_SPI") Protocol %s",
			pri_ipsec_spi(spi),
			str_enum(&ikev2_notify_protocol_id_names, rekey_notify->isan_protoid, &b));
		record_v2N_spi_response(ike->sa.logger, ike, md,
					rekey_notify->isan_protoid, &spi,
					v2N_CHILD_SA_NOT_FOUND, empty_shunk/*empty data*/,
					ENCRYPTED_PAYLOAD);
		return true;
	}

	ldbg_sa(ike, "#%lu hasa a rekey request for %s #%lu TSi TSr",
		ike->sa.st_serialno, replaced_child->sa.st_connection->name,
		replaced_child->sa.st_serialno);

	*child = replaced_child;
	return true;
}

static bool record_v2_rekey_ike_message(struct ike_sa *ike,
					struct child_sa *larval_ike,
					struct msg_digest *request_md)
{
	passert(ike != NULL);
	pexpect((request_md != NULL) == (larval_ike->sa.st_sa_role == SA_RESPONDER));
	pexpect((request_md == NULL) == (larval_ike->sa.st_state == &state_v2_REKEY_IKE_I0));
	pexpect((request_md != NULL) == (larval_ike->sa.st_state == &state_v2_REKEY_IKE_R0));

	struct v2_message message;
	if (!open_v2_message("CREATE_CHILD_SA rekey ike",
			     ike, larval_ike->sa.logger,
			     request_md, ISAKMP_v2_CREATE_CHILD_SA,
			     reply_buffer, sizeof(reply_buffer),
			     &message, ENCRYPTED_PAYLOAD)) {
		return false;
	}

	/*
	 * Emit the proposal, there's only one.
	 */

	switch (larval_ike->sa.st_sa_role) {
	case SA_INITIATOR:
	{
		/*
		 * Emit the proposal from the old exchange rebuilt to
		 * work as a fresh proposal.
		 */
		shunk_t local_spi = THING_AS_SHUNK(larval_ike->sa.st_ike_rekey_spis.initiator);
		/* send v2 IKE SAs*/
		if (!emit_v2SA_proposals(message.pbs,
					 larval_ike->sa.st_v2_create_child_sa_proposals,
					 local_spi)) {
			llog_sa(RC_LOG, larval_ike, "outsa fail");
			return false;
		}
		break;
	}
	case SA_RESPONDER:
	{
		/*
		 * Emit the agreed to proposal.
		 */
		shunk_t local_spi = THING_AS_SHUNK(larval_ike->sa.st_ike_rekey_spis.responder);
		/* send selected v2 IKE SA */
		if (!emit_v2SA_proposal(message.pbs, larval_ike->sa.st_v2_accepted_proposal, local_spi)) {
			llog_sa(RC_LOG, larval_ike, "outsa fail");
			return false;
		}
		break;
	}
	default:
		bad_case(larval_ike->sa.st_sa_role);
	}

	/* send NONCE */
	{
		struct ikev2_generic in = {
			.isag_critical = build_ikev2_critical(false, larval_ike->sa.logger),
		};
		struct pbs_out nr_pbs;

		if (!pbs_out_struct(message.pbs, &ikev2_nonce_desc, &in, sizeof(in), &nr_pbs)) {
			/* already logged */
			return false; /*fatal*/
		}

		chunk_t local_nonce = ((larval_ike->sa.st_sa_role == SA_INITIATOR) ? larval_ike->sa.st_ni :
				       (larval_ike->sa.st_sa_role == SA_RESPONDER) ? larval_ike->sa.st_nr :
				       empty_chunk);
		if (!pbs_out_hunk(&nr_pbs, local_nonce, "IKEv2 nonce")) {
			/* already logged */
			return false;
		}

		close_output_pbs(&nr_pbs);
	}


	chunk_t local_g = ((larval_ike->sa.st_sa_role == SA_INITIATOR) ? larval_ike->sa.st_gi :
			   (larval_ike->sa.st_sa_role == SA_RESPONDER) ? larval_ike->sa.st_gr :
			   empty_chunk);
	if (!emit_v2KE(local_g, larval_ike->sa.st_oakley.ta_dh, message.pbs)) {
		return false;
	}

	if (!close_and_record_v2_message(&message)) {
		return false;
	}

	return true;
}

/*
 * Process a CREATE_CHILD_SA rekey request.
 */

struct child_sa *submit_v2_CREATE_CHILD_SA_rekey_child(struct ike_sa *ike,
						       struct child_sa *child_being_replaced,
						       bool detach_whack)
{
	struct connection *c = child_being_replaced->sa.st_connection;
	struct logger *logger = child_being_replaced->sa.logger;
	passert(c != NULL);

	dbg("initiating child sa with "PRI_LOGGER, pri_logger(logger));

	pexpect(IS_CHILD_SA_ESTABLISHED(&child_being_replaced->sa));
	struct child_sa *larval_child = new_v2_child_sa(c, ike, CHILD_SA,
							SA_INITIATOR,
							STATE_V2_REKEY_CHILD_I0);
	state_attach(&larval_child->sa, logger);

	free_chunk_content(&larval_child->sa.st_ni); /* this is from the parent. */
	free_chunk_content(&larval_child->sa.st_nr); /* this is from the parent. */

	/*
	 * Start from policy in (ipsec) state, not connection.  This
	 * ensures that rekeying doesn't downgrade security.  I admit
	 * that this doesn't capture everything.
	 */
	larval_child->sa.st_policy = capture_child_rekey_policy(&child_being_replaced->sa);
	larval_child->sa.st_v2_rekey_pred = child_being_replaced->sa.st_serialno;

	larval_child->sa.st_v2_create_child_sa_proposals =
		get_v2_CREATE_CHILD_SA_rekey_child_proposals(ike,
							     child_being_replaced,
							     larval_child->sa.logger);
	larval_child->sa.st_pfs_group =
		ikev2_proposals_first_dh(larval_child->sa.st_v2_create_child_sa_proposals);

	/*
	 * Note: this will callback with the larval SA.
	 *
	 * Later, when the exchange is initiated, the IKE SA (which
	 * could have changed) will be called.
	 */

	child_policy_buf pb;
	dbg("#%lu submitting crypto needed to rekey Child SA #%lu using IKE SA #%lu policy=%s pfs=%s sec_label="PRI_SHUNK,
	    larval_child->sa.st_serialno,
	    child_being_replaced->sa.st_serialno,
	    ike->sa.st_serialno,
	    str_child_policy(&larval_child->sa.st_policy, &pb),
	    (larval_child->sa.st_pfs_group == NULL ? "no-pfs" :
	     larval_child->sa.st_pfs_group->common.fqn),
	    pri_shunk(c->child.sec_label));

	submit_ke_and_nonce(/*callback*/&larval_child->sa, /*task*/&larval_child->sa, /*no-md*/NULL,
			    larval_child->sa.st_pfs_group /*possibly-null*/,
			    queue_v2_CREATE_CHILD_SA_rekey_child_request,
			    detach_whack, HERE);

	return larval_child;
}

static void llog_v2_success_sent_CREATE_CHILD_SA_child_request(struct ike_sa *ike)
{
	/* XXX: should the lerval SA be a parameter? */
	struct child_sa *larval = ike->sa.st_v2_msgid_windows.initiator.wip_sa;
	if (larval == NULL) {
		llog(RC_LOG, ike->sa.logger, "Child SA abandoned");
		return;
	}
	LLOG_JAMBUF(RC_LOG, larval->sa.logger, buf) {
		jam_string(buf, "sent CREATE_CHILD_SA request to ");
		if (larval->sa.st_v2_rekey_pred == SOS_NOBODY) {
			jam_string(buf, "create Child SA");
		} else {
			jam_string(buf, "rekey Child SA ");
			jam_so(buf, larval->sa.st_v2_rekey_pred);
		}
		jam_string(buf, " using IKE SA ");
		jam_so(buf, ike->sa.st_serialno);
		/*
		 * Append some dynamic details (i.e., things that
		 * can't be determined from configstatus.
		 */
		jam_string(buf, " ");
		jam_v2_success_child_sa_request_details(buf, larval);
	}
}

/*
 * IKE SA's CREATE_CHILD_SA response to rekey or create a Child SA
 *
 * Both rekey and new Child SA share a common transition.  It isn't
 * immediately possible to differentiate between them.  Instead
 * .st_v2_larval_initiator_sa is used.
 *
 *                                <--  HDR, SK {SA, Nr, [KEr,]
 *                                              TSi, TSr}
 */

static const struct v2_transition v2_CREATE_CHILD_SA_rekey_child_initiate_transition = {
	.story      = "initiate rekey Child_SA (CREATE_CHILD_SA)",
	.to = &state_v2_ESTABLISHED_IKE_SA,
	.exchange   = ISAKMP_v2_CREATE_CHILD_SA,
	.processor  = initiate_v2_CREATE_CHILD_SA_rekey_child_request,
	.llog_success = llog_v2_success_sent_CREATE_CHILD_SA_child_request,
	.timeout_event = EVENT_RETAIN,
};

static const struct v2_transition v2_CREATE_CHILD_SA_rekey_child_responder_transition[] = {
	/*
	 * IKE SA's CREATE_CHILD_SA request to rekey a Child SA.
	 *
	 * This transition expects both TS (traffic selectors) and
	 * N(REKEY_SA)) payloads.  The rekey Child SA request will
	 * match this, the new Child SA will not and match the weaker
	 * transition that follows.
	 *
	 *   Initiator                         Responder
	 *   ---------------------------------------------------------
	 *   HDR, SK {N(REKEY_SA), SA, Ni, [KEi,]
	 *            TSi, TSr}  -->
	 *
	 * XXX: see ikev2_create_child_sa.c for initiator state.
	 */

	{ .story      = "process rekey Child SA request (CREATE_CHILD_SA)",
	  .to = &state_v2_ESTABLISHED_IKE_SA,
	  .flags = { .release_whack = true, },
	  .exchange   = ISAKMP_v2_CREATE_CHILD_SA,
	  .recv_role  = MESSAGE_REQUEST,
	  .message_payloads.required = v2P(SK),
	  .encrypted_payloads.required = v2P(SA) | v2P(Ni) | v2P(TSi) | v2P(TSr),
	  .encrypted_payloads.optional = v2P(KE) | v2P(N) | v2P(CP),
	  .encrypted_payloads.notification = v2N_REKEY_SA,
	  .processor  = process_v2_CREATE_CHILD_SA_rekey_child_request,
	  .llog_success = ldbg_v2_success,
	  .timeout_event = EVENT_RETAIN, },

};

static const struct v2_transitions v2_CREATE_CHILD_SA_rekey_child_responder_transitions = {
	ARRAY_REF(v2_CREATE_CHILD_SA_rekey_child_responder_transition),
};

static const struct v2_transition v2_CREATE_CHILD_SA_response_transition[] = {

	{ .story      = "process rekey IKE SA response (CREATE_CHILD_SA)",
	  .to = &state_v2_ESTABLISHED_IKE_SA,
	  .exchange   = ISAKMP_v2_CREATE_CHILD_SA,
	  .recv_role  = MESSAGE_RESPONSE,
	  .message_payloads.required = v2P(SK),
	  .encrypted_payloads.required = v2P(SA) | v2P(Ni) |  v2P(KE),
	  .encrypted_payloads.optional = v2P(N),
	  .processor  = process_v2_CREATE_CHILD_SA_rekey_ike_response,
	  .llog_success = ldbg_v2_success,
	  .timeout_event = EVENT_RETAIN, },

	{ .story      = "process Child SA response (new or rekey) (CREATE_CHILD_SA)",
	  .to = &state_v2_ESTABLISHED_IKE_SA,
	  .flags = { .release_whack = true, },
	  .exchange   = ISAKMP_v2_CREATE_CHILD_SA,
	  .recv_role  = MESSAGE_RESPONSE,
	  .message_payloads.required = v2P(SK),
	  .encrypted_payloads.required = v2P(SA) | v2P(Ni) | v2P(TSi) | v2P(TSr),
	  .encrypted_payloads.optional = v2P(KE) | v2P(N) | v2P(CP),
	  .processor  = process_v2_CREATE_CHILD_SA_child_response,
	  .llog_success = ldbg_v2_success,
	  .timeout_event = EVENT_RETAIN, },

	{ .story      = "process CREATE_CHILD_SA failure response (new or rekey Child SA, rekey IKE SA)",
	  .to = &state_v2_ESTABLISHED_IKE_SA,
	  .flags = { .release_whack = true, },
	  .exchange   = ISAKMP_v2_CREATE_CHILD_SA,
	  .recv_role  = MESSAGE_RESPONSE,
	  .message_payloads = { .required = v2P(SK), },
	  .processor  = process_v2_CREATE_CHILD_SA_failure_response,
	  .llog_success = ldbg_v2_success,
	  .timeout_event = EVENT_RETAIN, /* no timeout really */
	},

};

static const struct v2_transitions v2_CREATE_CHILD_SA_response_transitions = {
	ARRAY_REF(v2_CREATE_CHILD_SA_response_transition)
};

const struct v2_exchange v2_CREATE_CHILD_SA_rekey_child_exchange = {
	.type = ISAKMP_v2_CREATE_CHILD_SA,
	.subplot = "rekey Child SA",
	.secured = true,
	.initiate.from = { &state_v2_ESTABLISHED_IKE_SA, },
	.initiate.transition = &v2_CREATE_CHILD_SA_rekey_child_initiate_transition,
	.responder = &v2_CREATE_CHILD_SA_rekey_child_responder_transitions,
	.response = &v2_CREATE_CHILD_SA_response_transitions,
};

stf_status queue_v2_CREATE_CHILD_SA_rekey_child_request(struct state *larval_child_sa,
							struct msg_digest *null_md UNUSED,
							struct dh_local_secret *local_secret,
							chunk_t *nonce)
{
	/*
	 * Note: larval SA -> IKE SA hop
	 *
	 * This function is a callback for the larval SA (the
	 * stf_status STF_SKIP_COMPLETE_STATE_TRANSITION will be
	 * returned so that the state machine does not try to update
	 * its state).
	 *
	 * When the queued exchange is initiated, the callback
	 * TRANSITION .processor(IKE) will be called with the IKE SA.
	 */
	queue_v2_CREATE_CHILD_SA_initiator(larval_child_sa, local_secret, nonce,
					   &v2_CREATE_CHILD_SA_rekey_child_exchange);
	return STF_SKIP_COMPLETE_STATE_TRANSITION;
}

stf_status initiate_v2_CREATE_CHILD_SA_rekey_child_request(struct ike_sa *ike,
							   struct child_sa *larval_child,
							   struct msg_digest *null_md UNUSED)
{
	pexpect(ike->sa.st_v2_msgid_windows.initiator.wip_sa == larval_child);

	if (!ike->sa.st_viable_parent) {
		/*
		 * The concern is that a Child SA assigned to a viable
		 * IKE SA was allocated, sent off to do crypto, and
		 * then queued waiting for an open window, has found
		 * that the IKE SA is no longer viable.  For instance
		 * due to the IKE SA initiating a delete or rekey.
		 *
		 * However, the .st_viable_parent bit is not cleared
		 * by these delete and rekey exchanges.  Instead it is
		 * only cleared by the TERMINATE NOW code (<<ipsec
		 * {delete,unroute} connection>>) to stop terminated
		 * children trying to latch onto the dying IKE SA.
		 *
		 * For an initiated rekey or delete, because the
		 * message window size is 1, the outstanding exchange
		 * blocks the initiation of this new exchange.  Then
		 * when the response is received, the message queue is
		 * either deleted or moved to the new IKE SA (if the
		 * window were to be made bigger then this behaviour
		 * would need to be made explicit).
		 *
		 * XXX: It isn't clear what happens when a rekey
		 * responder also wants to initiate a child exchange.
		 */
		llog_sa(RC_LOG, larval_child,
			"IKE SA #%lu no longer viable for rekey of Child SA #%lu",
			ike->sa.st_serialno, larval_child->sa.st_v2_rekey_pred);
		connection_teardown_child(&larval_child, REASON_DELETED, HERE);
		ike->sa.st_v2_msgid_windows.initiator.wip_sa = larval_child = NULL;
		return STF_OK; /* IKE */
	}

	if (!pexpect(larval_child->sa.st_v2_rekey_pred != SOS_NOBODY)) {
		return STF_INTERNAL_ERROR;
	}

	struct child_sa *prev = child_sa_by_serialno(larval_child->sa.st_v2_rekey_pred);
	if (prev == NULL) {
		/*
		 * XXX: For instance:
		 *
		 * - the old child initiated this replacement
		 *
		 * - this child wondered off to perform DH
		 *
		 * - the old child expires itself (or it gets sent a
		 *   delete)
		 *
		 * - this child finds it has no older sibling
		 *
		 * The older child should have discarded this state.
		 */
		llog_pexpect(larval_child->sa.logger, HERE,
			     "Child SA to rekey #%lu vanished abort this exchange",
			     larval_child->sa.st_v2_rekey_pred);
		return STF_INTERNAL_ERROR;
	}

	if (!prep_v2_child_for_request(larval_child)) {
		delete_child_sa(&larval_child);
		ike->sa.st_v2_msgid_windows.initiator.wip_sa = larval_child = NULL;
		return STF_OK; /* IKE */
	}

	struct v2_message request;
	if (!open_v2_message("rekey Child SA request",
			     ike, larval_child->sa.logger,
			     /*initiator*/NULL, ISAKMP_v2_CREATE_CHILD_SA,
			     reply_buffer, sizeof(reply_buffer), &request,
			     ENCRYPTED_PAYLOAD)) {
		return STF_INTERNAL_ERROR;
	}

	/*
	 * 1.3.3.  Rekeying Child SAs with the CREATE_CHILD_SA
	 * Exchange: The SA being rekeyed is identified by the SPI
	 * field in the Notify payload; this is the SPI the exchange
	 * initiator would expect in inbound ESP or AH packets.
	 */
	{
		enum ikev2_sec_proto_id rekey_protoid;
		ipsec_spi_t rekey_spi;
		if (prev->sa.st_esp.protocol == &ip_protocol_esp) {
			rekey_spi = prev->sa.st_esp.inbound.spi;
			rekey_protoid = PROTO_IPSEC_ESP;
		} else if (prev->sa.st_ah.protocol == &ip_protocol_ah) {
			rekey_spi = prev->sa.st_ah.inbound.spi;
			rekey_protoid = PROTO_IPSEC_AH;
		} else {
			llog_pexpect(larval_child->sa.logger, HERE,
				     "previous Child SA #%lu being rekeyed is not ESP/AH",
				     larval_child->sa.st_v2_rekey_pred);
			return STF_INTERNAL_ERROR;
		}

		if (impair.v2n_rekey_sa_protoid.enabled) {
			enum_buf ebo, ebn;
			enum ikev2_sec_proto_id protoid = impair.v2n_rekey_sa_protoid.value;
			llog_sa(RC_LOG, prev, "IMPAIR: changing REKEY SA notify Protocol ID from %s to %s (%u)",
				str_enum_short(&ikev2_notify_protocol_id_names, rekey_protoid, &ebo),
				str_enum_short(&ikev2_notify_protocol_id_names, protoid, &ebn),
				protoid);
			rekey_protoid = protoid;
		}

		pexpect(rekey_spi != 0);

		struct pbs_out rekey_pbs;
		if (!open_v2N_SA_output_pbs(request.pbs,
					    v2N_REKEY_SA, rekey_protoid, &rekey_spi,
					    &rekey_pbs)) {
			return STF_INTERNAL_ERROR;
		}
		/* no payload */
		close_output_pbs(&rekey_pbs);

	}

	if (!emit_v2_child_request_payloads(ike, larval_child,
					    larval_child->sa.st_v2_create_child_sa_proposals,
					    /*ike_auth_exchange*/false, request.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	if (!close_and_record_v2_message(&request)) {
		return STF_INTERNAL_ERROR;
	}

	/*
	 * Clear any lurking CRYPTO (short term) timeout on the larval
	 * Child SA and transition to the new state.  The IKE SA will
	 * have it's retransmit timer set.
	 */
	event_delete(EVENT_v2_DISCARD, &larval_child->sa);
	change_v2_state(&larval_child->sa);

	return STF_OK; /* IKE */
}

stf_status process_v2_CREATE_CHILD_SA_rekey_child_request(struct ike_sa *ike,
							  struct child_sa *unused_child,
							  struct msg_digest *md)
{
	pexpect(unused_child == NULL);

	struct child_sa *predecessor = NULL;
	if (!find_v2N_REKEY_SA_child(ike, md, &predecessor)) {
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_INVALID_SYNTAX, empty_shunk/*no-data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL;
	}

	if (predecessor == NULL) {
		/* already logged; already recorded */
		return STF_OK; /*IKE*/
	}

	struct child_sa *larval_child =
		ike->sa.st_v2_msgid_windows.responder.wip_sa =
		new_v2_child_sa(predecessor->sa.st_connection,
				       ike, CHILD_SA, SA_RESPONDER,
				       STATE_V2_REKEY_CHILD_R0);

	larval_child->sa.st_v2_rekey_pred = predecessor->sa.st_serialno;
	larval_child->sa.st_v2_create_child_sa_proposals =
		get_v2_CREATE_CHILD_SA_rekey_child_proposals(ike, predecessor,
							     larval_child->sa.logger);

	if (!verify_rekey_child_request_ts(larval_child, md)) {
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_TS_UNACCEPTABLE, empty_shunk/*no data*/,
				    ENCRYPTED_PAYLOAD);
		delete_child_sa(&larval_child);
		ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
		return STF_OK; /*IKE*/
	}

	return process_v2_CREATE_CHILD_SA_request(ike, larval_child, md);
}

/*
 * CREATE_CHILD_SA create child request.
 */

struct child_sa *submit_v2_CREATE_CHILD_SA_new_child(struct ike_sa *ike,
						     struct connection *cc, /* for child + whack */
						     const struct child_policy *policy,
						     bool detach_whack)
{
	/* share the log! */
	if (!detach_whack) {
		state_attach(&ike->sa, cc->logger);
	}

	struct child_sa *larval_child = new_v2_child_sa(cc, ike, CHILD_SA,
							SA_INITIATOR,
							STATE_V2_NEW_CHILD_I0);

	free_chunk_content(&larval_child->sa.st_ni); /* this is from the parent. */
	free_chunk_content(&larval_child->sa.st_nr); /* this is from the parent. */

	larval_child->sa.st_policy = *policy;

	llog_sa(RC_LOG, larval_child,
		"initiating Child SA using IKE SA #%lu", ike->sa.st_serialno);

	larval_child->sa.st_v2_create_child_sa_proposals =
		get_v2_CREATE_CHILD_SA_new_child_proposals(ike, larval_child);
	larval_child->sa.st_pfs_group =
		ikev2_proposals_first_dh(larval_child->sa.st_v2_create_child_sa_proposals);

	/*
	 * Note: this will callback with the larval SA.
	 *
	 * Later, when the exchange is initiated, the IKE SA (which
	 * could have changed) will be called.
	 */

	child_policy_buf pb;
	dbg("#%lu submitting crypto needed to initiate Child SA using IKE SA #%lu policy=%s pfs=%s",
	    larval_child->sa.st_serialno,
	    ike->sa.st_serialno,
	    str_child_policy(policy, &pb),
	    larval_child->sa.st_pfs_group == NULL ? "no-pfs" : larval_child->sa.st_pfs_group->common.fqn);

	submit_ke_and_nonce(/*callback*/&larval_child->sa, /*task*/&larval_child->sa, /*no-md*/NULL,
			    larval_child->sa.st_pfs_group /*possibly-null*/,
			    queue_v2_CREATE_CHILD_SA_new_child_request,
			    detach_whack, HERE);
	return larval_child;
}

static const struct v2_transition v2_CREATE_CHILD_SA_new_child_initiate_transition = {
	.story      = "initiate new Child SA (CREATE_CHILD_SA)",
	.to = &state_v2_ESTABLISHED_IKE_SA,
	.exchange   = ISAKMP_v2_CREATE_CHILD_SA,
	.processor  = initiate_v2_CREATE_CHILD_SA_new_child_request,
	.llog_success = llog_v2_success_sent_CREATE_CHILD_SA_child_request,
	.timeout_event = EVENT_RETAIN,
};

static const struct v2_transition v2_CREATE_CHILD_SA_new_child_responder_transition[] = {
	/*
	 * IKE SA's CREATE_CHILD_SA request to create a new Child SA.
	 *
	 * Note the presence of just TS (traffic selectors) payloads.
	 * Earlier rules will have weeded out both rekey IKE (no TS
	 * payload) and rekey Child (has N(REKEY_SA)) leaving just
	 * create new Child SA.
	 *
	 *   Initiator                         Responder
	 *   ----------------------------------------------------------
	 *   HDR, SK {SA, Ni, [KEi,]
	 *            TSi, TSr}  -->
	 *
	 * XXX: see ikev2_create_child_sa.c for initiator state.
	 */

	{ .story      = "process create Child SA request (CREATE_CHILD_SA)",
	  .to = &state_v2_ESTABLISHED_IKE_SA,
	  .flags = { .release_whack = true, },
	  .exchange   = ISAKMP_v2_CREATE_CHILD_SA,
	  .recv_role  = MESSAGE_REQUEST,
	  .message_payloads.required = v2P(SK),
	  .encrypted_payloads.required = v2P(SA) | v2P(Ni) | v2P(TSi) | v2P(TSr),
	  .encrypted_payloads.optional = v2P(KE) | v2P(N) | v2P(CP),
	  .processor  = process_v2_CREATE_CHILD_SA_new_child_request,
	  .llog_success = ldbg_v2_success,
	  .timeout_event = EVENT_RETAIN, },

};

static const struct v2_transitions v2_CREATE_CHILD_SA_new_child_responder_transitions = {
	ARRAY_REF(v2_CREATE_CHILD_SA_new_child_responder_transition),
};

const struct v2_exchange v2_CREATE_CHILD_SA_new_child_exchange = {
	.type = ISAKMP_v2_CREATE_CHILD_SA,
	.subplot = "new Child SA",
	.secured = true,
	.initiate.from = { &state_v2_ESTABLISHED_IKE_SA, },
	.initiate.transition = &v2_CREATE_CHILD_SA_new_child_initiate_transition,
	.responder = &v2_CREATE_CHILD_SA_new_child_responder_transitions,
	.response = &v2_CREATE_CHILD_SA_response_transitions,
};

stf_status queue_v2_CREATE_CHILD_SA_new_child_request(struct state *larval_child_sa,
							struct msg_digest *null_md UNUSED,
							struct dh_local_secret *local_secret,
							chunk_t *nonce)
{
	/*
	 * Note: larval SA -> IKE SA hop
	 *
	 * This function is a callback for the larval SA (the
	 * stf_status STF_SKIP_COMPLETE_STATE_TRANSITION will be
	 * returned so that the state machine does not try to update
	 * its state).
	 *
	 * When the queued exchange is initiated, the callback
	 * TRANSITION .processor(IKE) will be called with the IKE SA.
	 */
	queue_v2_CREATE_CHILD_SA_initiator(larval_child_sa, local_secret, nonce,
					   &v2_CREATE_CHILD_SA_new_child_exchange);
	return STF_SKIP_COMPLETE_STATE_TRANSITION;
}

stf_status initiate_v2_CREATE_CHILD_SA_new_child_request(struct ike_sa *ike,
							 struct child_sa *larval_child,
							 struct msg_digest *null_md UNUSED)
{
	pexpect(ike->sa.st_v2_msgid_windows.initiator.wip_sa == larval_child);

	if (!ike->sa.st_viable_parent) {
		/*
		 * The concern is that a Child SA assigned to a viable
		 * IKE SA was allocated, sent off to do crypto, and
		 * then queued waiting for an open window, has found
		 * that the IKE SA is no longer viable.  For instance
		 * due to the IKE SA initiating a delete or rekey.
		 *
		 * However, the .st_viable_parent bit is not cleared
		 * by these delete and rekey exchanges.  Instead it is
		 * only cleared by the TERMINATE NOW code (<<ipsec
		 * {delete,unroute} connection>>) to stop terminated
		 * children trying to latch onto the dying IKE SA.
		 *
		 * For an initiated rekey or delete, because the
		 * message window size is 1, the outstanding exchange
		 * blocks the initiation of this new exchange.  Then
		 * when the response is received, the message queue is
		 * either deleted or moved to the new IKE SA (if the
		 * window were to be made bigger then this behaviour
		 * would need to be made explicit).
		 *
		 * XXX: It isn't clear what happens when a rekey
		 * responder also wants to initiate a child exchange.
		 */
		llog_sa(RC_LOG, larval_child,
			"IKE SA #%lu no longer viable for initiating a Child SA",
			ike->sa.st_serialno);
		connection_teardown_child(&larval_child, REASON_DELETED, HERE);
		ike->sa.st_v2_msgid_windows.initiator.wip_sa = larval_child = NULL;
		return STF_OK; /* IKE */
	}

	if (!prep_v2_child_for_request(larval_child)) {
		return STF_INTERNAL_ERROR;
	}

	struct v2_message request;
	if (!open_v2_message("new Child SA request",
			     ike, larval_child->sa.logger,
			     /*initiator*/NULL, ISAKMP_v2_CREATE_CHILD_SA,
			     reply_buffer, sizeof(reply_buffer),
			     &request, ENCRYPTED_PAYLOAD)) {
		return STF_INTERNAL_ERROR;
	}

	if (!emit_v2_child_request_payloads(ike, larval_child,
					    larval_child->sa.st_v2_create_child_sa_proposals,
					    /*ike_auth_exchange*/false, request.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	if (!close_and_record_v2_message(&request)) {
		return STF_INTERNAL_ERROR;
	}

	/*
	 * Clear any lurking CRYPTO (short term) timeout on the larval
	 * Child SA and transition to the new state.  The IKE SA will
	 * have it's retransmit timer set.
	 */
	event_delete(EVENT_v2_DISCARD, &larval_child->sa);
	change_v2_state(&larval_child->sa);

	return STF_OK; /* IKE */
}

stf_status process_v2_CREATE_CHILD_SA_new_child_request(struct ike_sa *ike,
							struct child_sa *unused_child,
							struct msg_digest *md)
{
	pexpect(unused_child == NULL);
	struct child_sa *larval_child =
		ike->sa.st_v2_msgid_windows.responder.wip_sa =
		new_v2_child_sa(ike->sa.st_connection,
				ike, CHILD_SA, SA_RESPONDER,
				STATE_V2_NEW_CHILD_R0);

	larval_child->sa.st_v2_create_child_sa_proposals =
		get_v2_CREATE_CHILD_SA_new_child_proposals(ike, larval_child);

	/* state m/c created CHILD SA */
	pexpect(larval_child->sa.st_v2_ike_pred == SOS_NOBODY);
	pexpect(larval_child->sa.st_v2_rekey_pred == SOS_NOBODY);

	/*
	 * Deal with either CP or TS.
	 *
	 * A CREATE_CHILD_SA can, technically, include both CP
	 * (configuration) and TS (traffic selector) payloads however
	 * it's not known to exist in the wild.
	 */

	if (md->chain[ISAKMP_NEXT_v2CP] != NULL) {
		llog_sa(RC_LOG, larval_child, "ignoring CREATE_CHILD_SA CP payload");
	}

	if (!process_v2TS_request_payloads(larval_child, md)) {
		/* already logged */
		record_v2N_response(larval_child->sa.logger, ike, md,
				    v2N_TS_UNACCEPTABLE, empty_shunk/*no-data*/,
				    ENCRYPTED_PAYLOAD);
		delete_child_sa(&larval_child);
		ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
		return STF_OK; /*IKE*/
	}

	return process_v2_CREATE_CHILD_SA_request(ike, larval_child, md);
}

/*
 * Reject the request: record the notification; delete the larval
 * child and then, when fatal, blow away the IKE SA.
 */

static stf_status reject_CREATE_CHILD_SA_request(struct ike_sa *ike,
						 struct child_sa **larval,
						 struct msg_digest *md,
						 v2_notification_t n,
						 where_t where)
{
	PEXPECT_WHERE(ike->sa.logger, where, v2_msg_role(md) == MESSAGE_REQUEST);
	PEXPECT_WHERE(ike->sa.logger, where, (*larval)->sa.st_sa_role == SA_RESPONDER);
	PEXPECT_WHERE(ike->sa.logger, where, ike->sa.st_v2_msgid_windows.responder.wip_sa == (*larval));
	PEXPECT_WHERE(ike->sa.logger, where, n != v2N_NOTHING_WRONG);
	/*
	 * Queue the response, will be sent by either STF_FATAL or
	 * STF_OK.
	 */
	record_v2N_response(ike->sa.logger, ike, md,
			    n, empty_shunk/*no-data*/,
			    ENCRYPTED_PAYLOAD);
	/*
	 * Child could have been partially routed; need to move it on.
	 */
	connection_teardown_child(larval, REASON_DELETED, where);
	ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
	return v2_notification_fatal(n) ? STF_FATAL : STF_OK; /*IKE*/
}

/*
 * processing a new Child SA (RFC 7296 1.3.1 or 1.3.3) request
 */

stf_status process_v2_CREATE_CHILD_SA_request(struct ike_sa *ike,
					      struct child_sa *larval_child,
					      struct msg_digest *md)
{
	v2_notification_t n;

	pexpect(larval_child != NULL); /* created by caller */

	free_chunk_content(&larval_child->sa.st_ni); /* this is from the parent. */
	free_chunk_content(&larval_child->sa.st_nr); /* this is from the parent. */

	/* Ni in */
	if (!accept_v2_nonce(larval_child->sa.logger, md, &larval_child->sa.st_ni, "Ni")) {
		/*
		 * Presumably not our fault.  Syntax error response
		 * implicitly kills the family.
		 */
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_INVALID_SYNTAX, empty_shunk/*no-data*/,
				    ENCRYPTED_PAYLOAD);
		delete_child_sa(&larval_child);
		ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
		return STF_FATAL; /* invalid syntax means we're dead */
	}

	n = process_childs_v2SA_payload("CREATE_CHILD_SA request",
					ike, larval_child, md,
					larval_child->sa.st_v2_create_child_sa_proposals,
					/*expect-accepted-proposal?*/false);
	if (n != v2N_NOTHING_WRONG) {
		return reject_CREATE_CHILD_SA_request(ike, &larval_child, md, n, HERE);
	}

	/*
	 * KE in with old(pst) and matching accepted_oakley from
	 * proposals
	 *
	 * XXX: does this code need to insist that the IKE SA
	 * replacement has KE or has SA processor handled that by only
	 * accepting a proposal with KE?
	 */
	if (larval_child->sa.st_pfs_group != NULL) {
		pexpect(larval_child->sa.st_oakley.ta_dh == larval_child->sa.st_pfs_group);
		if(!v2_accept_ke_for_proposal(ike, &larval_child->sa, md,
					      larval_child->sa.st_pfs_group,
					      ENCRYPTED_PAYLOAD)) {
			/* passert(reply-recorded) */
			delete_child_sa(&larval_child);
			ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
			return STF_OK; /*IKE*/
		}
	}

	submit_ke_and_nonce(/*callback*/&ike->sa, /*task*/&larval_child->sa, md,
			    (larval_child->sa.st_pfs_group != NULL ? larval_child->sa.st_oakley.ta_dh : NULL),
			    process_v2_CREATE_CHILD_SA_request_continue_1,
			    /*detach_whack*/false, HERE);
	return STF_SUSPEND;
}

static stf_status process_v2_CREATE_CHILD_SA_request_continue_1(struct state *ike_sa,
								struct msg_digest *request_md,
								struct dh_local_secret *local_secret,
								chunk_t *nonce)
{
	/* responder processing request */
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		/* ike_sa is not an ike_sa.  Fail. */
		/* XXX: release what? */
		return STF_INTERNAL_ERROR;
	}

	struct child_sa *larval_child = ike->sa.st_v2_msgid_windows.responder.wip_sa;
	pexpect(v2_msg_role(request_md) == MESSAGE_REQUEST); /* i.e., MD!=NULL */
	pexpect(larval_child->sa.st_sa_role == SA_RESPONDER);
	dbg("%s() for #%lu %s",
	     __func__, larval_child->sa.st_serialno, larval_child->sa.st_state->name);

	/*
	 * XXX: Should this routine be split so that each instance
	 * handles only one state transition.  If there's commonality
	 * then the per-transition functions can all call common code.
	 *
	 * Instead of computing the entire DH as a single crypto task,
	 * does a second continue. Yuck!
	 */
	pexpect(larval_child->sa.st_state == &state_v2_NEW_CHILD_R0 ||
		larval_child->sa.st_state == &state_v2_REKEY_CHILD_R0);

	unpack_nonce(&larval_child->sa.st_nr, nonce);
	if (local_secret == NULL) {
		/* skip step 2 */
		/* may invalidate LARVAL_CHILD */
		return process_v2_CREATE_CHILD_SA_request_continue_3(ike, request_md);
	}

	unpack_KE_from_helper(&larval_child->sa, local_secret, &larval_child->sa.st_gr);
	/* initiate calculation of g^xy */
	submit_dh_shared_secret(/*callback*/&ike->sa, /*task*/&larval_child->sa, request_md,
				larval_child->sa.st_gi,
				process_v2_CREATE_CHILD_SA_request_continue_2,
				HERE);
	return STF_SUSPEND;
}

static stf_status process_v2_CREATE_CHILD_SA_request_continue_2(struct state *ike_sa,
								struct msg_digest *request_md)
{
	/* 'child' responding to request */
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		/* ike_sa is not an ike_sa.  Fail. */
		/* XXX: release what? */
		return STF_OK; /*IKE*/
	}

	struct child_sa *larval_child = ike->sa.st_v2_msgid_windows.responder.wip_sa;
	passert(v2_msg_role(request_md) == MESSAGE_REQUEST); /* i.e., MD!=NULL */
	passert(larval_child->sa.st_sa_role == SA_RESPONDER);
	dbg("%s() for #%lu %s",
	     __func__, larval_child->sa.st_serialno, larval_child->sa.st_state->name);

	/*
	 * XXX: Should this routine be split so that each instance
	 * handles only one state transition.  If there's commonality
	 * then the per-transition functions can all call common code.
	 */
	pexpect(larval_child->sa.st_state == &state_v2_NEW_CHILD_R0 ||
		larval_child->sa.st_state == &state_v2_REKEY_CHILD_R0);

	if (larval_child->sa.st_dh_shared_secret == NULL) {
		log_state(RC_LOG, &larval_child->sa, "DH failed");
		record_v2N_response(larval_child->sa.logger, ike, request_md,
				    v2N_INVALID_SYNTAX, empty_shunk,
				    ENCRYPTED_PAYLOAD);
		delete_child_sa(&larval_child);
		ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
		return STF_FATAL; /* kill IKE family */
	}

	/* may invalidate LARVAL_CHILD */
	return process_v2_CREATE_CHILD_SA_request_continue_3(ike, request_md);
}

stf_status process_v2_CREATE_CHILD_SA_request_continue_3(struct ike_sa *ike,
							 struct msg_digest *request_md)
{
	struct child_sa *larval_child = ike->sa.st_v2_msgid_windows.responder.wip_sa;
	passert(v2_msg_role(request_md) == MESSAGE_REQUEST); /* i.e., MD!=NULL */
	passert(larval_child->sa.st_sa_role == SA_RESPONDER);
	pexpect(larval_child->sa.st_state == &state_v2_NEW_CHILD_R0 ||
		larval_child->sa.st_state == &state_v2_REKEY_CHILD_R0);
	dbg("%s() for #%lu %s",
	     __func__, larval_child->sa.st_serialno, larval_child->sa.st_state->name);

	/*
	 * CREATE_CHILD_SA request and response are small 300 - 750 bytes.
	 * ??? Should we support fragmenting?  Maybe one day.
	 *
	 * XXX: not so; keying material can get large.
	 */

	struct v2_message response;
	if (!open_v2_message("CREATE_CHILD_SA message",
			     ike, larval_child->sa.logger,
			     request_md, ISAKMP_v2_CREATE_CHILD_SA,
			     reply_buffer, sizeof(reply_buffer),
			     &response, ENCRYPTED_PAYLOAD)) {
		return STF_FATAL; /* IKE */
	}

	v2_notification_t n = process_v2_child_request_payloads(ike, larval_child, request_md,
								response.pbs);
	if (n != v2N_NOTHING_WRONG) {
		/* already logged */
		return reject_CREATE_CHILD_SA_request(ike, &larval_child,
						      request_md, n, HERE);
	}

	if (!close_and_record_v2_message(&response)) {
		return STF_INTERNAL_ERROR;
	}

	return STF_OK; /*IKE*/
}

/*
 * Reject the response: delete the child and then, when fatal, blow
 * away the IKE SA.
 *
 * XXX: when the response isn't fatal, the code should initiate a
 * delete exchange for the child (and it's connection).
 */

static stf_status reject_CREATE_CHILD_SA_response(struct ike_sa *ike,
						  struct child_sa **larval,
						  struct msg_digest *md,
						  v2_notification_t n,
						  where_t where)
{
	PEXPECT_WHERE(ike->sa.logger, where, v2_msg_role(md) == MESSAGE_RESPONSE);
	PEXPECT_WHERE(ike->sa.logger, where, (*larval)->sa.st_sa_role == SA_INITIATOR);
	PEXPECT_WHERE(ike->sa.logger, where, ike->sa.st_v2_msgid_windows.initiator.wip_sa == (*larval));
	PEXPECT_WHERE(ike->sa.logger, where, n != v2N_NOTHING_WRONG);

	if (v2_notification_fatal(n)) {
		/* let STF_FATAL clean up mess */
		return STF_FATAL;
	}

	/*
	 * This end (the initiator) did not like something
	 * about the Child SA.
	 *
	 * (If the responder sent back an error notification
	 * to reject the Child SA, then the above call would
	 * have cleaned up the mess and return
	 * v2N_NOTHING_WRONG.  After all, problem solved.
	 */
#if 0
	llog_sa(RC_LOG, ike, "IKE SA established but initiator rejected Child SA response");
#endif
	ike->sa.st_v2_msgid_windows.initiator.wip_sa = NULL;
	passert((*larval) != NULL);
	/*
	 * Needed to un-plug the pending queue.  Without this
	 * the next pending exchange is never started.
	 *
	 * While not obvious from the name - unpend() - the
	 * code is doing two things: removing LARVAL_CHILD's
	 * pending connection; and submitting a request to
	 * initiate the next pending connection, if any.
	 *
	 * The key thing here is that unpend() delays creating
	 * the next child until after the previous child is
	 * done.  Avoiding a race for which child goes next.
	 *
	 * For IKEv2, should merge the pending queue into the
	 * Message ID queue.  Have a queue of exchanges, and a
	 * queue of things to do when there are no exchanges.
	 */
	unpend(ike, (*larval)->sa.st_connection);
	/*
	 * Quickly delete this larval SA.
	 */
	submit_v2_delete_exchange(ike, (*larval));
	return STF_OK; /* IKE */
}

/*
 * initiator received a create Child SA Response (RFC 7296 1.3.1, 1.3.2)
 *
 * Note: "when rekeying, the new Child SA SHOULD NOT have different Traffic
 *        Selectors and algorithms than the old one."
 */

stf_status process_v2_CREATE_CHILD_SA_child_response(struct ike_sa *ike,
						     struct child_sa *larval_child,
						     struct msg_digest *response_md)
{
	v2_notification_t n;
	pexpect(ike != NULL);

	pexpect(larval_child == NULL);
	larval_child = ike->sa.st_v2_msgid_windows.initiator.wip_sa;
	if (!pexpect(larval_child != NULL)) {
		/* XXX: drop everything on the floor */
		return STF_INTERNAL_ERROR;
	}

	pexpect(larval_child->sa.st_sa_kind_when_established == CHILD_SA);

	/*
	 * Drive the larval Child SA's state machine.
	 */
	set_larval_v2_transition(larval_child, &state_v2_ESTABLISHED_CHILD_SA, HERE);

	/* Ni in */
	if (!accept_v2_nonce(larval_child->sa.logger, response_md,
			     &larval_child->sa.st_nr, "Nr")) {
		/*
		 * Presumably not our fault.  Syntax errors in a
		 * response kill the family (and trigger no further
		 * exchange).
		 *
		 * XXX: initiator; need to initiate a fatal error
		 * notification exchange.
		 */
		return STF_FATAL; /* IKE */
	}

	n = process_childs_v2SA_payload("CREATE_CHILD_SA responder matching remote ESP/AH proposals",
					ike, larval_child, response_md,
					larval_child->sa.st_v2_create_child_sa_proposals,
					/*expect-accepted-proposal?*/true);
	if (n != v2N_NOTHING_WRONG) {
		return reject_CREATE_CHILD_SA_response(ike, &larval_child,
						       response_md, n, HERE);
	}

	/*
	 * XXX: only for rekey child?
	 */
	if (larval_child->sa.st_pfs_group == NULL) {
		v2_notification_t n = process_v2_child_response_payloads(ike, larval_child, response_md);
		if (n != v2N_NOTHING_WRONG) {
			return reject_CREATE_CHILD_SA_response(ike, &larval_child,
							       response_md, n, HERE);
		}
		/*
		 * XXX: fudge a state transition.
		 *
		 * Code extracted and simplified from
		 * success_v2_state_transition(); suspect very similar code
		 * will appear in the responder.
		 */
		v2_child_sa_established(ike, larval_child);
		/* hack; cover all bases; handled by close any whacks? */
		release_whack(larval_child->sa.logger, HERE);
		return STF_OK; /* IKE */
	}

	/*
	 * This is the initiator, accept responder's KE.
	 *
	 * XXX: Above checks st_pfs_group but this uses
	 * st_oakley.ta_dh, presumably they are the same? Lets find
	 * out.
	 */
	pexpect(larval_child->sa.st_oakley.ta_dh == larval_child->sa.st_pfs_group);
	if (!unpack_KE(&larval_child->sa.st_gr, "Gr", larval_child->sa.st_oakley.ta_dh,
		       response_md->chain[ISAKMP_NEXT_v2KE], larval_child->sa.logger)) {
		/*
		 * XXX: Initiator; need to initiate a delete exchange.
		 */
		delete_child_sa(&larval_child);
		ike->sa.st_v2_msgid_windows.initiator.wip_sa = larval_child = NULL;
		return STF_OK; /* IKE */
	}

	chunk_t remote_ke = larval_child->sa.st_gr;
	submit_dh_shared_secret(/*callback*/&ike->sa, /*task*/&larval_child->sa, response_md,
				remote_ke,
				process_v2_CREATE_CHILD_SA_child_response_continue_1, HERE);
	return STF_SUSPEND;
}

static stf_status process_v2_CREATE_CHILD_SA_child_response_continue_1(struct state *ike_sa,
								       struct msg_digest *response_md)
{
	/* initiator getting back an answer */
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		/* XXX: drop everything on the floor */
		return STF_INTERNAL_ERROR;
	}

	struct child_sa *larval_child = ike->sa.st_v2_msgid_windows.initiator.wip_sa;
	if (!pexpect(larval_child != NULL)) {
		/* XXX: drop everything on the floor */
		return STF_INTERNAL_ERROR;
	}

	pexpect(v2_msg_role(response_md) == MESSAGE_RESPONSE); /* i.e., MD!=NULL */
	pexpect(larval_child->sa.st_sa_role == SA_INITIATOR);
	pexpect(larval_child->sa.st_sa_kind_when_established == CHILD_SA);
	dbg("%s() for #%lu %s",
	     __func__, larval_child->sa.st_serialno, larval_child->sa.st_state->name);

	/*
	 * XXX: Should this routine be split so that each instance
	 * handles only one state transition.  If there's commonality
	 * then the per-transition functions can all call common code.
	 */
	pexpect(larval_child->sa.st_state == &state_v2_NEW_CHILD_I1 ||
		larval_child->sa.st_state == &state_v2_REKEY_CHILD_I1);

	if (larval_child->sa.st_dh_shared_secret == NULL) {
		/*
		 * XXX: initiator; need to initiate a delete exchange.
		 */
		delete_child_sa(&larval_child);
		ike->sa.st_v2_msgid_windows.initiator.wip_sa = larval_child = NULL;
		return STF_OK; /* IKE */
	}

	v2_notification_t n = process_v2_child_response_payloads(ike, larval_child,
								 response_md);
	if (n != v2N_NOTHING_WRONG) {
		return reject_CREATE_CHILD_SA_response(ike, &larval_child,
						       response_md, n, HERE);
	}

	/*
	 * XXX: fudge a state transition.
	 *
	 * Code extracted and simplified from
	 * success_v2_state_transition(); suspect very similar code
	 * will appear in the responder.
	 */
	v2_child_sa_established(ike, larval_child);
	/* hack; cover all bases; handled by close any whacks? */
	release_whack(larval_child->sa.logger, HERE);

	return STF_OK; /* IKE */
}

/*
 * Rekey the IKE SA (RFC 7296 1.3.2).
 *
 * Note that initiate is a little deceptive.  It is submitting crypto.
 * The initiate proper only happens later when the exchange is added
 * to the message queue.
 */

static bool calc_v2_rekey_ike_keymat(struct ike_sa *old_ike,
				     struct child_sa *larval_ike,
				     const ike_spis_t *new_ike_spis,
				     where_t where)
{
	struct logger *logger = larval_ike->sa.logger;
	PK11SymKey *shared = larval_ike->sa.st_dh_shared_secret;

	const struct prf_desc *old_prf = old_ike->sa.st_oakley.ta_prf;
	PK11SymKey *old_d = old_ike->sa.st_skey_d_nss;
	ldbg(logger, "%s() calculating skeyseed using prf %s",
	     __func__, old_prf->common.fqn);

	PK11SymKey *skeyseed =
		ikev2_ike_sa_rekey_skeyseed(old_prf, old_d,
					    shared,
					    larval_ike->sa.st_ni,
					    larval_ike->sa.st_nr,
					    logger);
	if (skeyseed == NULL) {
		llog_pexpect(logger, where, "rekey SKEYSEED failed");
		return false;
	}

	calc_v2_ike_keymat(&larval_ike->sa, skeyseed, new_ike_spis);
	symkey_delref(logger, "skeyseed", &skeyseed);
	return true;
}

struct child_sa *submit_v2_CREATE_CHILD_SA_rekey_ike(struct ike_sa *ike,
						     bool detach_whack)
{
	struct connection *c = ike->sa.st_connection;

	; /* to be determined */
	struct child_sa *larval_ike = new_v2_child_sa(c, ike, IKE_SA,
						      SA_INITIATOR,
						      STATE_V2_REKEY_IKE_I0);
	state_attach(&larval_ike->sa, ike->sa.logger);
	larval_ike->sa.st_oakley = ike->sa.st_oakley;
	larval_ike->sa.st_ike_rekey_spis.initiator = ike_initiator_spi();
	larval_ike->sa.st_v2_rekey_pred = ike->sa.st_serialno;
	/*
	 * Notice how policy is empty - rekeying an IKE doesn't create
	 * a child.
	 */
	larval_ike->sa.st_policy = (struct child_policy) {0};
	larval_ike->sa.st_v2_create_child_sa_proposals =
		get_v2_CREATE_CHILD_SA_rekey_ike_proposals(ike, larval_ike->sa.logger);

	free_chunk_content(&larval_ike->sa.st_ni); /* this is from the parent. */
	free_chunk_content(&larval_ike->sa.st_nr); /* this is from the parent. */

	/*
	 * Note: this will callback with the larval SA.
	 *
	 * Later, when the exchange is initiated, the IKE SA (which
	 * could have changed) will be called.
	 */

	passert(larval_ike->sa.st_connection != NULL);
	child_policy_buf pb;
	dbg("#%lu submitting crypto needed to rekey IKE SA #%lu policy=%s pfs=%s",
	    larval_ike->sa.st_serialno, ike->sa.st_serialno,
	    str_child_policy(&larval_ike->sa.st_policy, &pb),
	    larval_ike->sa.st_oakley.ta_dh->common.fqn);

	submit_ke_and_nonce(/*callback*/&larval_ike->sa, /*task*/&larval_ike->sa, /*no-md*/NULL,
			    larval_ike->sa.st_oakley.ta_dh,
			    queue_v2_CREATE_CHILD_SA_rekey_ike_request,
			    detach_whack, HERE);
	/* "return STF_SUSPEND" */
	return larval_ike;
}

static void llog_v2_success_rekey_ike_request(struct ike_sa *ike)
{
	/* XXX: should the lerval SA be a parameter? */
	struct child_sa *larval = ike->sa.st_v2_msgid_windows.initiator.wip_sa;
	if (larval != NULL) {
		PEXPECT(larval->sa.logger, larval->sa.st_v2_rekey_pred == ike->sa.st_serialno);
		/*
		 * Yes, "rekey IKE SA #1 using IKE SA #1" is redundant
		 * but consistent with other logs; maybe?
		 */
		llog(RC_LOG, larval->sa.logger,
		     "sent CREATE_CHILD_SA request to rekey IKE SA "PRI_SO" (using IKE SA "PRI_SO")",
		     pri_so(larval->sa.st_v2_rekey_pred),
		     pri_so(ike->sa.st_serialno));
	} else {
		llog(RC_LOG, ike->sa.logger, "rekey of IKE SA abandoned");
	}
}

static const struct v2_transition v2_CREATE_CHILD_SA_rekey_ike_initiate_transition = {
	.story      = "initiate rekey IKE_SA (CREATE_CHILD_SA)",
	.to = &state_v2_ESTABLISHED_IKE_SA,
	.exchange   = ISAKMP_v2_CREATE_CHILD_SA,
	.processor  = initiate_v2_CREATE_CHILD_SA_rekey_ike_request,
	.llog_success = llog_v2_success_rekey_ike_request,
	.timeout_event = EVENT_RETAIN,
};

static const struct v2_transition v2_CREATE_CHILD_SA_rekey_ike_responder_transition[] = {
	/*
	 * IKE SA's CREATE_CHILD_SA exchange to rekey IKE SA.
	 *
	 * Note the lack of a TS (traffic selectors) payload.  Since
	 * rekey and new Child SA exchanges contain TS they won't
	 * match.
	 *
	 *   Initiator                         Responder
	 *   --------------------------------------------------------
	 *   HDR, SK {SA, Ni, KEi} -->
	 *                                <--  HDR, SK {SA, Nr, KEr}
	 *
	 * XXX: see ikev2_create_child_sa.c for initiator state.
	 */

	{ .story      = "process rekey IKE SA request (CREATE_CHILD_SA)",
	  .to = &state_v2_ESTABLISHED_IKE_SA,
	  .flags = { .release_whack = true, },
	  .exchange   = ISAKMP_v2_CREATE_CHILD_SA,
	  .recv_role  = MESSAGE_REQUEST,
	  .message_payloads.required = v2P(SK),
	  .encrypted_payloads.required = v2P(SA) | v2P(Ni) | v2P(KE),
	  .encrypted_payloads.optional = v2P(N),
	  .processor  = process_v2_CREATE_CHILD_SA_rekey_ike_request,
	  .llog_success = ldbg_v2_success,
	  .timeout_event = EVENT_RETAIN },

};

static const struct v2_transitions v2_CREATE_CHILD_SA_rekey_ike_responder_transitions = {
	ARRAY_REF(v2_CREATE_CHILD_SA_rekey_ike_responder_transition),
};

const struct v2_exchange v2_CREATE_CHILD_SA_rekey_ike_exchange = {
	.type = ISAKMP_v2_CREATE_CHILD_SA,
	.subplot = "rekey IKE SA",
	.secured = true,
	.initiate.from = { &state_v2_ESTABLISHED_IKE_SA, },
	.initiate.transition = &v2_CREATE_CHILD_SA_rekey_ike_initiate_transition,
	.responder = &v2_CREATE_CHILD_SA_rekey_ike_responder_transitions,
	.response = &v2_CREATE_CHILD_SA_response_transitions,
};

stf_status queue_v2_CREATE_CHILD_SA_rekey_ike_request(struct state *larval_ike_sa,
						      struct msg_digest *null_md UNUSED,
						      struct dh_local_secret *local_secret,
						      chunk_t *nonce)
{
	/*
	 * Note: larval SA -> IKE SA hop
	 *
	 * This function is a callback for the larval SA (the
	 * stf_status STF_SKIP_COMPLETE_STATE_TRANSITION will be
	 * returned so that the state machine does not try to update
	 * its state).
	 *
	 * When the queued exchange is initiated, the callback
	 * TRANSITION .processor(IKE) will be called with the IKE SA.
	 */
	queue_v2_CREATE_CHILD_SA_initiator(larval_ike_sa, local_secret, nonce,
					   &v2_CREATE_CHILD_SA_rekey_ike_exchange);
	return STF_SKIP_COMPLETE_STATE_TRANSITION;
}

stf_status initiate_v2_CREATE_CHILD_SA_rekey_ike_request(struct ike_sa *ike,
							 struct child_sa *larval_ike,
							 struct msg_digest *null_md)
{
	/*
	 * Since this IKE SA is rekeying, it's no longer viable.
	 */
	if (!pexpect(ike->sa.st_viable_parent)) {
		return STF_INTERNAL_ERROR;
	}

	ike->sa.st_viable_parent = false;

	pexpect(ike->sa.st_v2_msgid_windows.initiator.wip_sa == larval_ike);

	if (!record_v2_rekey_ike_message(ike, larval_ike, null_md)) {
		return STF_INTERNAL_ERROR;
	}

	/*
	 * Clear any lurking CRYPTO (short term) timeout on the larval
	 * IKE SA and transition to the new state.  The current IKE SA
	 * will have it's retransmit timer set.
	 */
	event_delete(EVENT_v2_DISCARD, &larval_ike->sa);
	change_v2_state(&larval_ike->sa);

	return STF_OK; /* IKE */
}

stf_status process_v2_CREATE_CHILD_SA_rekey_ike_request(struct ike_sa *ike,
							struct child_sa *unused_ike,
							struct msg_digest *request_md)
{
	pexpect(unused_ike == NULL);
	v2_notification_t n;

	struct child_sa *larval_ike =
		ike->sa.st_v2_msgid_windows.responder.wip_sa =
		new_v2_child_sa(ike->sa.st_connection,
				ike, IKE_SA, SA_RESPONDER,
				STATE_V2_REKEY_IKE_R0);

	larval_ike->sa.st_v2_rekey_pred = ike->sa.st_serialno;

	struct connection *c = larval_ike->sa.st_connection;

	free_chunk_content(&larval_ike->sa.st_ni); /* this is from the parent. */
	free_chunk_content(&larval_ike->sa.st_nr); /* this is from the parent. */

	/* Ni in */
	if (!accept_v2_nonce(larval_ike->sa.logger, request_md, &larval_ike->sa.st_ni, "Ni")) {
		/*
		 * Presumably not our fault.  A syntax error response
		 * implicitly kills the entire family.
		 *
		 * Already logged?
		 */
		record_v2N_response(ike->sa.logger, ike, request_md,
				    v2N_INVALID_SYNTAX, empty_shunk/*no-data*/,
				    ENCRYPTED_PAYLOAD);
		delete_child_sa(&larval_ike);
		ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
		return STF_FATAL; /* IKE family is doomed */
	}

	/* Get the proposals ready. */
	const struct ikev2_proposals *ike_proposals = c->config->v2_ike_proposals;

	struct payload_digest *const sa_pd = request_md->chain[ISAKMP_NEXT_v2SA];
	n = process_v2SA_payload("IKE Rekey responder child",
				 &sa_pd->pbs,
				 /*expect_ike*/ true,
				 /*expect_spi*/ true,
				 /*expect_accepted*/ false,
				 /*limit-logging*/is_opportunistic(c),
				 &larval_ike->sa.st_v2_accepted_proposal,
				 ike_proposals, larval_ike->sa.logger);
	if (n != v2N_NOTHING_WRONG) {
		pexpect(larval_ike->sa.st_sa_role == SA_RESPONDER);
		record_v2N_response(larval_ike->sa.logger, ike, request_md,
				    n, empty_shunk,
				    ENCRYPTED_PAYLOAD);
		delete_child_sa(&larval_ike);
		ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
		return v2_notification_fatal(n) ? STF_FATAL : STF_OK; /* IKE */
	}

	if (DBGP(DBG_BASE)) {
		DBG_log_ikev2_proposal("accepted IKE proposal",
				       larval_ike->sa.st_v2_accepted_proposal);
	}

	if (!ikev2_proposal_to_trans_attrs(larval_ike->sa.st_v2_accepted_proposal,
					   &larval_ike->sa.st_oakley, larval_ike->sa.logger)) {
		llog_sa(RC_LOG, larval_ike,
			"IKE responder accepted an unsupported algorithm");
		delete_child_sa(&larval_ike);
		ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
		return STF_FATAL; /* IKE family is doomed */
	}

	/*
	 * Check and read the KE contents.
	 *
	 * responder, so accept initiator's KE in with new
	 * accepted_oakley for IKE.
	 */
	pexpect(larval_ike->sa.st_oakley.ta_dh != NULL);
	pexpect(larval_ike->sa.st_pfs_group == NULL);
	if (!v2_accept_ke_for_proposal(ike, &larval_ike->sa, request_md,
				       larval_ike->sa.st_oakley.ta_dh,
				       ENCRYPTED_PAYLOAD)) {
		/* passert(reply-recorded) */
		delete_child_sa(&larval_ike);
		ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
		return STF_OK; /* IKE */
	}

	submit_ke_and_nonce(/*callback*/&ike->sa, /*task*/&ike->sa, request_md,
			    larval_ike->sa.st_oakley.ta_dh,
			    process_v2_CREATE_CHILD_SA_rekey_ike_request_continue_1,
			    /*detach_whack*/false, HERE);
	return STF_SUSPEND;
}

static stf_status process_v2_CREATE_CHILD_SA_rekey_ike_request_continue_1(struct state *ike_sa,
									  struct msg_digest *request_md,
									  struct dh_local_secret *local_secret,
									  chunk_t *nonce)
{
	/* responder processing request */
	pexpect(v2_msg_role(request_md) == MESSAGE_REQUEST); /* i.e., MD!=NULL */

	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		/* ike_sa is not an ike_sa.  Fail. */
		/* XXX: release what? */
		return STF_INTERNAL_ERROR;
	}

	struct child_sa *larval_ike = ike->sa.st_v2_msgid_windows.responder.wip_sa; /* not yet emancipated */
	pexpect(larval_ike->sa.st_sa_role == SA_RESPONDER);
	pexpect(larval_ike->sa.st_state == &state_v2_REKEY_IKE_R0);
	dbg("%s() for #%lu %s",
	     __func__, larval_ike->sa.st_serialno, larval_ike->sa.st_state->name);

	pexpect(local_secret != NULL);
	pexpect(request_md->chain[ISAKMP_NEXT_v2KE] != NULL);
	unpack_nonce(&larval_ike->sa.st_nr, nonce);
	unpack_KE_from_helper(&larval_ike->sa, local_secret, &larval_ike->sa.st_gr);

	/* initiate calculation of g^xy */
	passert(ike_spi_is_zero(&larval_ike->sa.st_ike_rekey_spis.initiator));
	passert(ike_spi_is_zero(&larval_ike->sa.st_ike_rekey_spis.responder));
	ikev2_copy_child_spi_from_proposal(larval_ike->sa.st_v2_accepted_proposal,
					   &larval_ike->sa.st_ike_rekey_spis.initiator);
	larval_ike->sa.st_ike_rekey_spis.responder = ike_responder_spi(&request_md->sender,
								       larval_ike->sa.logger);
	submit_dh_shared_secret(/*callback*/&ike->sa, /*task*/&larval_ike->sa, request_md,
				larval_ike->sa.st_gi/*responder needs initiator KE*/,
				process_v2_CREATE_CHILD_SA_rekey_ike_request_continue_2,
				HERE);

	return STF_SUSPEND;
}

static stf_status process_v2_CREATE_CHILD_SA_rekey_ike_request_continue_2(struct state *ike_sa,
									  struct msg_digest *request_md)
{
	/* IKE SA responder with child */
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		/* XXX: drop everything on the floor */
		return STF_INTERNAL_ERROR;
	}

	/* Just checking this is the rekey IKE SA responder */
	struct child_sa *larval_ike = ike->sa.st_v2_msgid_windows.responder.wip_sa; /* not yet emancipated */
	if (!pexpect(larval_ike != NULL)) {
		/* XXX: drop everything on the floor */
		return STF_INTERNAL_ERROR;
	}

	passert(v2_msg_role(request_md) == MESSAGE_REQUEST); /* i.e., MD!=NULL */
	passert(larval_ike->sa.st_sa_role == SA_RESPONDER);
	pexpect(larval_ike->sa.st_state == &state_v2_REKEY_IKE_R0);
	dbg("%s() for #%lu %s",
	     __func__, larval_ike->sa.st_serialno, larval_ike->sa.st_state->name);

	if (larval_ike->sa.st_dh_shared_secret == NULL) {
		record_v2N_response(ike->sa.logger, ike, request_md,
				    v2N_INVALID_SYNTAX, empty_shunk,
				    ENCRYPTED_PAYLOAD);
		delete_child_sa(&larval_ike);
		ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
		return STF_FATAL; /* IKE family is doomed */
	}

	if (!calc_v2_rekey_ike_keymat(ike, larval_ike,
				      &larval_ike->sa.st_ike_rekey_spis,
				      HERE)) {
		/* already logged */
		return STF_FATAL;
	}

	if (!record_v2_rekey_ike_message(ike, larval_ike, /*responder*/request_md)) {
		return STF_INTERNAL_ERROR;
	}

	emancipate_larval_ike_sa(ike, larval_ike);
	return STF_OK; /* IKE */
}

/*
 * initiator received Rekey IKE SA (RFC 7296 1.3.3) response
 */

stf_status process_v2_CREATE_CHILD_SA_rekey_ike_response(struct ike_sa *ike,
							 struct child_sa *larval_ike,
							 struct msg_digest *response_md)
{
	v2_notification_t n;
	pexpect(ike != NULL);
	pexpect(larval_ike == NULL);
	larval_ike = ike->sa.st_v2_msgid_windows.initiator.wip_sa;
	if (!pexpect(larval_ike != NULL)) {
		/* XXX: drop everything on the floor */
		return STF_INTERNAL_ERROR;
	}

	pexpect(larval_ike->sa.st_sa_kind_when_established == IKE_SA);
	pexpect(ike->sa.st_serialno == larval_ike->sa.st_clonedfrom); /* not yet emancipated */
	struct connection *c = larval_ike->sa.st_connection;

	/*
	 * Drive the larval IKE SA's state machine.
	 */
	set_larval_v2_transition(larval_ike, &state_v2_ESTABLISHED_IKE_SA, HERE);

	/* Ni in */
	if (!accept_v2_nonce(larval_ike->sa.logger, response_md, &larval_ike->sa.st_nr, "Nr")) {
		/*
		 * Presumably not our fault.  Syntax errors in a
		 * response kill the family and trigger no further
		 * exchange.
		 */
		return STF_FATAL; /* NEED RESTART? */
	}

	/*
	 * Parse the proposal, determining what was accepted, and confirm
	 * that it matches the rekey proposal originally sent.
	 */
	struct payload_digest *const sa_pd = response_md->chain[ISAKMP_NEXT_v2SA];
	n = process_v2SA_payload("IKE initiator (accepting)",
				 &sa_pd->pbs,
				 /*expect_ike*/ true,
				 /*expect_spi*/ true,
				 /*expect_accepted*/ true,
				 /*limit-logging*/is_opportunistic(c),
				 &larval_ike->sa.st_v2_accepted_proposal,
				 larval_ike->sa.st_v2_create_child_sa_proposals,
				 larval_ike->sa.logger);
	if (n != v2N_NOTHING_WRONG) {
		/*
		 * XXX: what should happen here?  It feels like a
		 * should-not-happen?
		 */
		ldbg(larval_ike->sa.logger,
		     "failed to accept IKE SA, REKEY, response, in process_v2_CREATE_CHILD_SA_rekey_ike_response");
		PEXPECT(ike->sa.logger, ike->sa.st_v2_msgid_windows.initiator.wip_sa == larval_ike);
		delete_child_sa(&larval_ike);
		ike->sa.st_v2_msgid_windows.initiator.wip_sa = larval_ike = NULL;
		return (v2_notification_fatal(n) ? STF_FATAL : STF_OK); /* IKE */
	}

	if (DBGP(DBG_BASE)) {
		DBG_log_ikev2_proposal("accepted IKE proposal",
				       larval_ike->sa.st_v2_accepted_proposal);
	}
	if (!ikev2_proposal_to_trans_attrs(larval_ike->sa.st_v2_accepted_proposal,
					   &larval_ike->sa.st_oakley, larval_ike->sa.logger)) {
		llog_sa(RC_LOG, larval_ike,
			"IKE responder accepted an unsupported algorithm");
		/* free early return items */
		free_ikev2_proposal(&larval_ike->sa.st_v2_accepted_proposal);
		passert(larval_ike->sa.st_v2_accepted_proposal == NULL);
		return STF_FATAL;
	}

	 /* KE in */
	if (!unpack_KE(&larval_ike->sa.st_gr, "Gr", larval_ike->sa.st_oakley.ta_dh,
		       response_md->chain[ISAKMP_NEXT_v2KE], larval_ike->sa.logger)) {
		/*
		 * XXX: Initiator so returning this notification will
		 * go no where.  Need to check RFC for what to do
		 * next.  The packet is trusted but the re-key has
		 * failed.
		 */
		return STF_FATAL;
	}

	/* fill in the missing responder SPI */
	passert(!ike_spi_is_zero(&larval_ike->sa.st_ike_rekey_spis.initiator));
	passert(ike_spi_is_zero(&larval_ike->sa.st_ike_rekey_spis.responder));
	ikev2_copy_child_spi_from_proposal(larval_ike->sa.st_v2_accepted_proposal,
					   &larval_ike->sa.st_ike_rekey_spis.responder);

	/* initiate calculation of g^xy for rekey */
	submit_dh_shared_secret(/*callback*/&ike->sa, /*task*/&larval_ike->sa, response_md,
				larval_ike->sa.st_gr/*initiator needs responder's KE*/,
				process_v2_CREATE_CHILD_SA_rekey_ike_response_continue_1,
				HERE);
	return STF_SUSPEND;
}

static stf_status process_v2_CREATE_CHILD_SA_rekey_ike_response_continue_1(struct state *ike_sa,
									   struct msg_digest *response_md)
{
	/* IKE SA initiator with child getting back an answer */
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		/* XXX: drop everything on the floor */
		return STF_INTERNAL_ERROR;
	}

	struct child_sa *larval_ike = ike->sa.st_v2_msgid_windows.initiator.wip_sa; /* not yet emancipated */
	if (!pexpect(larval_ike != NULL)) {
		/* XXX: drop everything on the floor */
		return STF_INTERNAL_ERROR;
	}

	/* Just checking this is the rekey IKE SA initiator */
	pexpect(larval_ike->sa.st_sa_role == SA_INITIATOR);
	pexpect(larval_ike->sa.st_sa_kind_when_established == IKE_SA);
	pexpect(larval_ike->sa.st_state == &state_v2_REKEY_IKE_I1);
	pexpect(v2_msg_role(response_md) == MESSAGE_RESPONSE); /* i.e., MD!=NULL */

	dbg("%s() for #%lu %s",
	     __func__, larval_ike->sa.st_serialno, larval_ike->sa.st_state->name);

	/* and a parent? */

	if (larval_ike->sa.st_dh_shared_secret == NULL) {
		/*
		 * XXX: this is the initiator so returning a
		 * notification is kind of useless.
		 */
		return STF_FATAL;
	}

	if (!calc_v2_rekey_ike_keymat(ike, larval_ike,
				      &larval_ike->sa.st_ike_rekey_spis/* new SPIs */,
				      HERE)) {
		/* already logged */
		return STF_FATAL;
	}

	pexpect(larval_ike->sa.st_v2_rekey_pred == ike->sa.st_serialno); /*wow!*/
	ikev2_rekey_expire_predecessor(larval_ike, larval_ike->sa.st_v2_rekey_pred);

	/*
	 * Emancipate: release the Child from the control of its
	 * Parent) making it an IKE SA.  Includes changing state.
	 */
	emancipate_larval_ike_sa(ike, larval_ike);

	return STF_OK; /* IKE */
}

stf_status process_v2_CREATE_CHILD_SA_failure_response(struct ike_sa *ike,
						       struct child_sa *unused_child UNUSED,
						       struct msg_digest *md UNUSED)
{
	passert(ike != NULL);
	passert(unused_child == NULL);
	struct child_sa **larval_child = &ike->sa.st_v2_msgid_windows.initiator.wip_sa;
	if (pbad(*larval_child == NULL)) {
		/* XXX: drop everything on the floor */
		return STF_INTERNAL_ERROR;
	}

        pstat_sa_failed(&(*larval_child)->sa, REASON_TRAFFIC_SELECTORS_FAILED);

	stf_status status = STF_ROOF; /*IKE;place holder*/

	/*
	 * This assumes that the first notify is the (fatal) error
	 * (logging all notifies would probably be bad).
	 */
	for (struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		v2_notification_t n = ntfy->payload.v2n.isan_type;
		if (n < v2N_ERROR_PSTATS_ROOF) {
			pstat(ikev2_recv_notifies_e, n);
			switch (n) {
			case v2N_INVALID_KE_PAYLOAD:
			{
				if (ike->sa.st_oakley.ta_dh == NULL) {
					enum_buf nb;
					llog_sa(RC_LOG, (*larval_child),
						"CREATE_CHILD_SA failed with error notification %s response but no KE was sent",
						str_enum_short(&v2_notification_names, n, &nb));
					status = STF_FATAL;
					break;
				}

				if (!pexpect(md->pd[PD_v2N_INVALID_KE_PAYLOAD] != NULL)) {
					status = STF_INTERNAL_ERROR;
					break;
				}

				struct pbs_in invalid_ke_pbs = md->pd[PD_v2N_INVALID_KE_PAYLOAD]->pbs;
				struct suggested_group sg;
				diag_t d = pbs_in_struct(&invalid_ke_pbs, &suggested_group_desc,
							 &sg, sizeof(sg), NULL);
				if (d != NULL) {
					enum_buf nb;
					llog(RC_LOG, (*larval_child)->sa.logger,
					     "CREATE_CHILD_SA failed with error notification %s response: %s",
					     str_enum_short(&v2_notification_names, n, &nb),
					     str_diag(d));
					pfree_diag(&d);
					status = STF_FATAL;
					break;
				}

				pstats(invalidke_recv_s, sg.sg_group);
				pstats(invalidke_recv_u, ike->sa.st_oakley.ta_dh->group);

				enum_buf nb, sgb;
				llog_sa(RC_LOG, (*larval_child),
					"CREATE_CHILD_SA failed with error notification %s response suggesting %s instead of %s",
					str_enum_short(&v2_notification_names, n, &nb),
					str_enum_short(&oakley_group_names, sg.sg_group, &sgb),
					ike->sa.st_oakley.ta_dh->common.fqn);
				status = STF_OK; /* let IKE stumble on */
				break;
			}
			default:
			{
				enum_buf esb;
				llog_sa(RC_LOG, (*larval_child),
					"CREATE_CHILD_SA failed with error notification %s",
					str_enum_short(&v2_notification_names, n, &esb));
				dbg("re-add child to pending queue with exponential back-off?");
				status = (n == v2N_INVALID_SYNTAX ? STF_FATAL/*kill IKE*/ :
					  STF_OK/*keep IKE*/);
				break;
			}
			}
			break;
		}
	}

	if (status == STF_ROOF) {
		/* there was no reason, huh? */
		status = STF_OK;/*keep IKE?*/
		/* log something */
		llog_sa(RC_LOG, (*larval_child), "state transition '%s' failed",
			(*larval_child)->sa.st_v2_transition->story);
	}

	/*
	 * If LARVAL_CHILD is rekeying (replacing) a Child SA, also
	 * detach the logger from that state.
	 */
	struct state *replacing = state_by_serialno((*larval_child)->sa.st_v2_rekey_pred);
	if (replacing != NULL && IS_CHILD_SA(replacing)) {
		PEXPECT((*larval_child)->sa.logger,
			(*larval_child)->sa.st_sa_kind_when_established == CHILD_SA);
		state_detach(replacing, (*larval_child)->sa.logger);
	}

	connection_teardown_child(larval_child, REASON_DELETED, HERE);

	return status; /* IKE */
}
