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
#ifdef USE_XFRM_INTERFACE
# include "kernel_xfrm_interface.h"
#endif
#include "kernel.h"
#include "ikev2_message.h"
#include "crypt_dh.h"
#include "crypt_ke.h"
#include "unpack.h"
#include "pending.h"
#include "ipsec_doi.h"			/* for capture_child_rekey_policy */
#include "ike_alg_dh.h"			/* for ike_alg_dh_none */
#include "ikev2_proposals.h"

static ikev2_state_transition_fn process_v2_CREATE_CHILD_SA_request;

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
					       const struct v2_state_transition *transition)
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

	pexpect(larval->sa.st_sa_role == SA_INITIATOR);
	pexpect(larval->sa.st_state->kind == STATE_V2_NEW_CHILD_I0 ||
		larval->sa.st_state->kind == STATE_V2_REKEY_CHILD_I0 ||
		larval->sa.st_state->kind == STATE_V2_REKEY_IKE_I0);
	pexpect(ike->sa.st_state->kind == STATE_V2_ESTABLISHED_IKE_SA);

	/*
	 * Unpack the crypto material computed out-of-band.
	 *
	 * For Child SAs DH is optional; for IKE SAs it's required.
	 * Hence rekeying the IKE SA implies DH.
	 */
	pexpect((larval->sa.st_state->kind == STATE_V2_REKEY_IKE_I0) <=/*implies*/ (local_secret != NULL));
	unpack_nonce(&larval->sa.st_ni, nonce);
	if (local_secret != NULL) {
		unpack_KE_from_helper(&larval->sa, local_secret, &larval->sa.st_gi);
	}

	dbg("adding larval SA #%lu to IKE SA #%lu message initiator queue; sec_label="PRI_SHUNK,
	    larval->sa.st_serialno, ike->sa.st_serialno,
	    pri_shunk(larval->sa.st_connection->spd.this.sec_label));

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

	pexpect(larval->sa.st_state->nr_transitions == 1);
	pexpect(larval->sa.st_state->v2.transitions->exchange == ISAKMP_v2_CREATE_CHILD_SA);
	v2_msgid_queue_initiator(ike, larval, transition);
}

static void emancipate_larval_ike_sa(struct ike_sa *old_ike, struct child_sa *new_ike)
{
	/* initialize the the new IKE SA. reset and message ID */
	new_ike->sa.st_clonedfrom = SOS_NOBODY;
	v2_msgid_init_ike(pexpect_ike_sa(&new_ike->sa));

	/* Switch to the new IKE SPIs */
	new_ike->sa.st_ike_spis = new_ike->sa.st_ike_rekey_spis;
	rehash_state_cookies_in_db(&new_ike->sa);

	dbg("NEW_IKE has updated IKE_SPIs, migrate children");
	v2_migrate_children(old_ike, new_ike);

	dbg("moving over any pending requests");
	v2_msgid_migrate_queue(old_ike, new_ike);
	v2_msgid_schedule_next_initiator(pexpect_ike_sa(&new_ike->sa));

	/* complete the state transition */
	const struct v2_state_transition *transition = new_ike->sa.st_v2_transition;
	pexpect(transition->state == new_ike->sa.st_state->kind);
	pexpect(transition->next_state == STATE_V2_ESTABLISHED_IKE_SA);
	change_v2_state(&new_ike->sa); /* should trash .st_v2_transition */

	/* child is now a parent */
	v2_ike_sa_established(pexpect_ike_sa(&new_ike->sa));

	/* Schedule for whatever timeout is specified */
	pexpect(transition->timeout_event == EVENT_SA_REPLACE);
	delete_event(&new_ike->sa); /* relying on replace */
	schedule_v2_replace_event(&new_ike->sa);

	/*
	 * Announce this to the world.
	 */
	/* XXX: call transition->llog()? */
	llog_v2_ike_sa_established(old_ike, new_ike);
	release_whack(new_ike->sa.st_logger, HERE);
}

static struct child_sa *find_v2N_REKEY_SA_child(struct ike_sa *ike,
						struct msg_digest *md)
{
	/*
	 * Previously found by the state machine.
	 */
	const struct payload_digest *rekey_sa_payload = md->pd[PD_v2N_REKEY_SA];
	if (rekey_sa_payload == NULL) {
		llog_pexpect(ike->sa.st_logger, HERE,
			     "rekey child can't find its rekey_sa payload");
		return NULL;
	}
#if 0
	/* XXX: this would require a separate .pd_next link? */
	if (rekey_sa_payload->next != NULL) {
		/* will tolerate multiple */
		log_state(RC_LOG_SERIOUS, &ike->sa,
			  "ignoring duplicate v2N_REKEY_SA in exchange");
	}
#endif

	/*
	 * find old state to rekey
	 */

	const struct ikev2_notify *rekey_notify = &rekey_sa_payload->payload.v2n;
	esb_buf b;
	dbg("CREATE_CHILD_SA IPsec SA rekey Protocol %s",
	    enum_show(&ikev2_notify_protocol_id_names, rekey_notify->isan_protoid, &b));

	if (rekey_notify->isan_spisize != sizeof(ipsec_spi_t)) {
		log_state(RC_LOG, &ike->sa,
			  "CREATE_CHILD_SA IPsec SA rekey invalid spi size %u",
			  rekey_notify->isan_spisize);
		record_v2N_response(ike->sa.st_logger, ike, md, v2N_INVALID_SYNTAX,
				    NULL/*empty data*/, ENCRYPTED_PAYLOAD);
		return NULL;
	}

	ipsec_spi_t spi = 0;
	struct pbs_in rekey_pbs = rekey_sa_payload->pbs;
	diag_t d = pbs_in_raw(&rekey_pbs, &spi, sizeof(spi), "SPI");
	if (d != NULL) {
		llog_diag(RC_LOG, ike->sa.st_logger, &d, "%s", "");
		record_v2N_response(ike->sa.st_logger, ike, md, v2N_INVALID_SYNTAX,
				    NULL/*empty data*/, ENCRYPTED_PAYLOAD);
		return NULL; /* cannot happen; XXX: why? */
	}

	if (spi == 0) {
		log_state(RC_LOG, &ike->sa,
			  "CREATE_CHILD_SA IPsec SA rekey contains zero SPI");
		record_v2N_response(ike->sa.st_logger, ike, md, v2N_INVALID_SYNTAX,
				    NULL/*empty data*/, ENCRYPTED_PAYLOAD);
		return NULL;
	}

	if (rekey_notify->isan_protoid != PROTO_IPSEC_ESP &&
	    rekey_notify->isan_protoid != PROTO_IPSEC_AH) {
		esb_buf b;
		log_state(RC_LOG, &ike->sa,
			  "CREATE_CHILD_SA IPsec SA rekey invalid Protocol ID %s",
			  enum_show(&ikev2_notify_protocol_id_names, rekey_notify->isan_protoid, &b));
		record_v2N_spi_response(ike->sa.st_logger, ike, md,
					rekey_notify->isan_protoid, &spi,
					v2N_CHILD_SA_NOT_FOUND,
					NULL/*empty data*/, ENCRYPTED_PAYLOAD);
		return NULL;
	}

	esb_buf protoesb;
	dbg("CREATE_CHILD_S to rekey IPsec SA(0x%08" PRIx32 ") Protocol %s",
	    ntohl((uint32_t) spi),
	    enum_show(&ikev2_notify_protocol_id_names, rekey_notify->isan_protoid, &protoesb));

	/*
	 * From 1.3.3.  Rekeying Child SAs with the CREATE_CHILD_SA
	 * Exchange: The SA being rekeyed is identified by the SPI
	 * field in the [REKEY_SA] Notify payload; this is the SPI the
	 * exchange initiator would expect in inbound ESP or AH
	 * packets.
	 *
	 * From our POV, that's the outbound SPI.
	 */
	struct child_sa *replaced_child = find_v2_child_sa_by_outbound_spi(ike, rekey_notify->isan_protoid, spi);
	if (replaced_child == NULL) {
		esb_buf b;
		log_state(RC_LOG, &ike->sa,
			  "CREATE_CHILD_SA no such IPsec SA to rekey SA(0x%08" PRIx32 ") Protocol %s",
			  ntohl((uint32_t) spi),
			  enum_show(&ikev2_notify_protocol_id_names, rekey_notify->isan_protoid, &b));
		record_v2N_spi_response(ike->sa.st_logger, ike, md,
					rekey_notify->isan_protoid, &spi,
					v2N_CHILD_SA_NOT_FOUND,
					NULL/*empty data*/, ENCRYPTED_PAYLOAD);
		return NULL;
	}

	connection_buf cb;
	dbg("#%lu hasa a rekey request for "PRI_CONNECTION" #%lu TSi TSr",
	    ike->sa.st_serialno,
	    pri_connection(replaced_child->sa.st_connection, &cb),
	    replaced_child->sa.st_serialno);

	return replaced_child;
}

static bool record_v2_rekey_ike_message(struct ike_sa *ike,
					struct child_sa *larval_ike,
					struct msg_digest *request_md)
{
	passert(ike != NULL);
	pexpect((request_md != NULL) == (larval_ike->sa.st_sa_role == SA_RESPONDER));
	pexpect((request_md == NULL) == (larval_ike->sa.st_state->kind == STATE_V2_REKEY_IKE_I0));
	pexpect((request_md != NULL) == (larval_ike->sa.st_state->kind == STATE_V2_REKEY_IKE_R0));

	struct v2_message message;
	if (!open_v2_message("CREATE_CHILD_SA rekey ike",
			     ike, larval_ike->sa.st_logger,
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
		if (!ikev2_emit_sa_proposals(message.pbs,
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
		if (!ikev2_emit_sa_proposal(message.pbs, larval_ike->sa.st_v2_accepted_proposal, local_spi)) {
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
			.isag_critical = build_ikev2_critical(false, larval_ike->sa.st_logger),
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
						       struct child_sa *child_being_replaced)
{
	struct connection *c = child_being_replaced->sa.st_connection;
	struct logger *logger = child_being_replaced->sa.st_logger;
	passert(c != NULL);

	dbg("initiating child sa with "PRI_LOGGER, pri_logger(logger));

	pexpect(IS_CHILD_SA_ESTABLISHED(&child_being_replaced->sa));
	struct child_sa *larval_child = new_v2_child_state(c, ike, IPSEC_SA,
							   SA_INITIATOR,
							   STATE_V2_REKEY_CHILD_I0,
							   logger->global_whackfd);

	free_chunk_content(&larval_child->sa.st_ni); /* this is from the parent. */
	free_chunk_content(&larval_child->sa.st_nr); /* this is from the parent. */

	/*
	 * Start from policy in (ipsec) state, not connection.  This
	 * ensures that rekeying doesn't downgrade security.  I admit
	 * that this doesn't capture everything.
	 */
	larval_child->sa.st_policy = capture_child_rekey_policy(&child_being_replaced->sa);
	larval_child->sa.st_try = 1;
	larval_child->sa.st_v2_rekey_pred = child_being_replaced->sa.st_serialno;

	larval_child->sa.st_v2_create_child_sa_proposals =
		get_v2_CREATE_CHILD_SA_rekey_child_proposals(ike,
							     child_being_replaced->sa.st_v2_accepted_proposal,
							     larval_child);
	larval_child->sa.st_pfs_group =
		ikev2_proposals_first_dh(larval_child->sa.st_v2_create_child_sa_proposals);

	/*
	 * Note: this will callback with the larval SA.
	 *
	 * Later, when the exchange is initiated, the IKE SA (which
	 * could have changed) will be called.
	 */

	policy_buf pb;
	dbg("#%lu submitting crypto needed to rekey Child SA #%lu using IKE SA #%lu policy=%s pfs=%s sec_label="PRI_SHUNK,
	    larval_child->sa.st_serialno,
	    child_being_replaced->sa.st_serialno,
	    ike->sa.st_serialno,
	    str_policy(larval_child->sa.st_policy, &pb),
	    (larval_child->sa.st_pfs_group == NULL ? "no-pfs" :
	     larval_child->sa.st_pfs_group->common.fqn),
	    pri_shunk(c->spd.this.sec_label));

	submit_ke_and_nonce(&larval_child->sa, larval_child->sa.st_pfs_group /*possibly-null*/,
			    queue_v2_CREATE_CHILD_SA_rekey_child_request, HERE);

	return larval_child;
}

static void llog_v2_success_rekey_child_request(struct ike_sa *ike)
{
	/* XXX: should the lerval SA be a parameter? */
	struct child_sa *larval = ike->sa.st_v2_msgid_windows.initiator.wip_sa;
	if (larval != NULL) {
#if 0
		llog_sa(RC_NEW_V2_STATE + larval->sa.st_state->kind, larval,
			"sent CREATE_CHILD_SA request to rekey IPsec SA "PRI_SO" using IKE SA "PRI_SO,
			pri_so(larval->sa.st_v2_rekey_pred), pri_so(ike->sa.st_serialno));
#else
		llog_sa(RC_NEW_V2_STATE + larval->sa.st_state->kind, larval,
			"sent CREATE_CHILD_SA request to rekey IPsec SA");
#endif
	} else {
		llog_sa(RC_LOG_SERIOUS, ike, "rekey of Child SA abandoned");
	}
}

static const struct v2_state_transition v2_CREATE_CHILD_SA_rekey_child_transition = {
	.story      = "initiate rekey Child_SA (CREATE_CHILD_SA)",
	.state      = STATE_V2_ESTABLISHED_IKE_SA,
	.next_state = STATE_V2_ESTABLISHED_IKE_SA,
	.exchange   = ISAKMP_v2_CREATE_CHILD_SA,
	.send_role  = MESSAGE_REQUEST,
	.processor  = initiate_v2_CREATE_CHILD_SA_rekey_child_request,
	.llog_success = llog_v2_success_rekey_child_request,
	.timeout_event = EVENT_RETAIN,
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
					   &v2_CREATE_CHILD_SA_rekey_child_transition);
	return STF_SKIP_COMPLETE_STATE_TRANSITION;
}

stf_status initiate_v2_CREATE_CHILD_SA_rekey_child_request(struct ike_sa *ike,
							   struct child_sa *larval_child,
							   struct msg_digest *null_md UNUSED)
{
	struct connection *cc = larval_child->sa.st_connection;
	pexpect(ike->sa.st_v2_msgid_windows.initiator.wip_sa == larval_child);

	if (!ike->sa.st_viable_parent) {
		/*
		 * This return will delete the larval child.
		 *
		 * XXX: Several things might happen next:
		 *
		 * - during the delete the revival code will schedule
                 *   a replace for the connection
		 *
		 *   I suspect not as the revival code is, mostly, all
                 *   about IKE SAs.
		 *
		 * - the old Child SA rekey timer expires trigging a
		 *   replace
		 *
		 *   Certainly plausible; assuming nothing else
		 *   happens earlier.
		 *
		 * - the IKE SA is deleted causing the old child to
		 *   also be replaced
		 *
		 *   Most likely?
		 *
		 * What most likely didn't help was scheduling a
		 * replace event for the larval child; only to then
		 * delete that child.  Presumably one of the above
		 * saved the day.  That code was removed.
		 *
		 * XXX: "trying replace" is a policy thing so probably
		 * not always valid.
		 */
		llog_sa(RC_LOG_SERIOUS, larval_child,
			"IKE SA #%lu no longer viable for rekey of Child SA #%lu",
			ike->sa.st_serialno, larval_child->sa.st_v2_rekey_pred);
		larval_child->sa.st_policy = cc->policy; /* for pick_initiator */
		delete_state(&larval_child->sa);
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
		llog_sa(LOG_STREAM/*not-whack*/, larval_child,
			"Child SA to rekey #%lu vanished abort this exchange",
			larval_child->sa.st_v2_rekey_pred);
		return STF_INTERNAL_ERROR;
	}

	if (!prep_v2_child_for_request(larval_child)) {
		delete_state(&larval_child->sa);
		ike->sa.st_v2_msgid_windows.initiator.wip_sa = larval_child = NULL;
		return STF_OK; /* IKE */
	}

	struct v2_message request;
	if (!open_v2_message("rekey Child SA request",
			     ike, larval_child->sa.st_logger,
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
		if (prev->sa.st_esp.present) {
			rekey_spi = prev->sa.st_esp.inbound.spi;
			rekey_protoid = PROTO_IPSEC_ESP;
		} else if (prev->sa.st_ah.present) {
			rekey_spi = prev->sa.st_ah.inbound.spi;
			rekey_protoid = PROTO_IPSEC_AH;
		} else {
			llog_pexpect(larval_child->sa.st_logger, HERE,
				     "previous Child SA #%lu being rekeyed is not ESP/AH",
				     larval_child->sa.st_v2_rekey_pred);
			return STF_INTERNAL_ERROR;
		}

		pexpect(rekey_spi != 0);
		if (!emit_v2Nsa_pl(v2N_REKEY_SA, rekey_protoid, &rekey_spi, request.pbs, NULL)) {
			return STF_INTERNAL_ERROR;
		}
	}

	if (!emit_v2_child_request_payloads(ike, larval_child,
					    larval_child->sa.st_v2_create_child_sa_proposals,
					    request.pbs)) {
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
	delete_event(&larval_child->sa);
	change_v2_state(&larval_child->sa);

	return STF_OK; /* IKE */
}

stf_status process_v2_CREATE_CHILD_SA_rekey_child_request(struct ike_sa *ike,
							  struct child_sa *larval_child,
							  struct msg_digest *md)
{

	struct child_sa *predecessor = find_v2N_REKEY_SA_child(ike, md);
	if (predecessor == NULL) {
		/* already logged; already recorded */
		return STF_OK; /*IKE*/
	}

	pexpect(larval_child == NULL);
	larval_child = new_v2_child_state(predecessor->sa.st_connection,
					  ike, IPSEC_SA, SA_RESPONDER,
					  STATE_V2_REKEY_CHILD_R0,
					  null_fd);
	ike->sa.st_v2_msgid_windows.responder.wip_sa = larval_child;
	larval_child->sa.st_v2_rekey_pred = predecessor->sa.st_serialno;
	larval_child->sa.st_v2_create_child_sa_proposals =
		get_v2_CREATE_CHILD_SA_rekey_child_proposals(ike,
							     predecessor->sa.st_v2_accepted_proposal,
							     larval_child);

	if (!verify_rekey_child_request_ts(larval_child, md)) {
		record_v2N_response(ike->sa.st_logger, ike, md,
				    v2N_TS_UNACCEPTABLE, NULL/*no data*/,
				    ENCRYPTED_PAYLOAD);
		delete_state(&larval_child->sa);
		ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
		return STF_OK; /*IKE*/
	}

	return process_v2_CREATE_CHILD_SA_request(ike, larval_child, md);
}

/*
 * CREATE_CHILD_SA create child request.
 */

void submit_v2_CREATE_CHILD_SA_new_child(struct ike_sa *ike,
					 struct connection *c, /* for child */
					 lset_t policy, int try,
					 struct fd *whackfd)
{
	struct child_sa *larval_child = new_v2_child_state(c, ike, IPSEC_SA,
							   SA_INITIATOR,
							   STATE_V2_NEW_CHILD_I0,
							   whackfd);

	free_chunk_content(&larval_child->sa.st_ni); /* this is from the parent. */
	free_chunk_content(&larval_child->sa.st_nr); /* this is from the parent. */
	larval_child->sa.st_try = try;

	/* share the love; XXX: something better? */
	fd_delref(&ike->sa.st_logger->object_whackfd);
	ike->sa.st_logger->object_whackfd = fd_addref(whackfd);
	larval_child->sa.st_policy = policy;

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

	policy_buf pb;
	dbg("#%lu submitting crypto needed to initiate Child SA using IKE SA #%lu policy=%s pfs=%s",
	    larval_child->sa.st_serialno,
	    ike->sa.st_serialno,
	    str_policy(policy, &pb),
	    larval_child->sa.st_pfs_group == NULL ? "no-pfs" : larval_child->sa.st_pfs_group->common.fqn);

	submit_ke_and_nonce(&larval_child->sa, larval_child->sa.st_pfs_group /*possibly-null*/,
			    queue_v2_CREATE_CHILD_SA_new_child_request, HERE);
}

static void llog_v2_success_new_child_request(struct ike_sa *ike)
{
	/* XXX: should the lerval SA be a parameter? */
	struct child_sa *larval = ike->sa.st_v2_msgid_windows.initiator.wip_sa;
	if (larval != NULL) {
#if 0
		llog_sa(RC_NEW_V2_STATE + larval->sa.st_state->kind, larval,
			"sent CREATE_CHILD_SA request for new IPsec SA using IKE SA "PRI_SO,
			pri_so(ike->sa.st_serialno));
#else
		llog_sa(RC_NEW_V2_STATE + larval->sa.st_state->kind, larval,
			"sent CREATE_CHILD_SA request for new IPsec SA");
#endif
	} else {
		llog_sa(RC_LOG_SERIOUS, ike, "create new Child SA abandoned");
	}
}

static const struct v2_state_transition v2_CREATE_CHILD_SA_new_child_transition = {
	.story      = "initiate new Child SA (CREATE_CHILD_SA)",
	.state      = STATE_V2_ESTABLISHED_IKE_SA,
	.next_state = STATE_V2_ESTABLISHED_IKE_SA,
	.exchange   = ISAKMP_v2_CREATE_CHILD_SA,
	.send_role  = MESSAGE_REQUEST,
	.processor  = initiate_v2_CREATE_CHILD_SA_new_child_request,
	.llog_success = llog_v2_success_new_child_request,
	.timeout_event = EVENT_RETAIN,
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
					   &v2_CREATE_CHILD_SA_new_child_transition);
	return STF_SKIP_COMPLETE_STATE_TRANSITION;
}

stf_status initiate_v2_CREATE_CHILD_SA_new_child_request(struct ike_sa *ike,
							 struct child_sa *larval_child,
							 struct msg_digest *null_md UNUSED)
{
	pexpect(ike->sa.st_v2_msgid_windows.initiator.wip_sa == larval_child);

	if (!ike->sa.st_viable_parent) {
		/*
		 * This return will delete the larval child.
		 *
		 * XXX: Several things might happen next:
		 *
		 * - during the delete the revival code will schedule
                 *   a replace for the connection
		 *
		 *   I suspect not as the revival code is, mostly, all
                 *   about IKE SAs.
		 *
		 * What most likely didn't help was scheduling a
		 * replace event for the larval child; only to then
		 * delete that child.  Presumably one of the above
		 * saved the day.  That code was removed.
		 *
		 * XXX: "trying replace" is a policy thing so probably
		 * not always valid.
		 */
		llog_sa(RC_LOG_SERIOUS, larval_child,
			"IKE SA #%lu no longer viable for initiating a Child SA",
			ike->sa.st_serialno);
		larval_child->sa.st_policy = larval_child->sa.st_connection->policy; /* for pick_initiator */
		delete_state(&larval_child->sa);
		ike->sa.st_v2_msgid_windows.initiator.wip_sa = larval_child = NULL;
		return STF_OK; /* IKE */
	}

	if (!prep_v2_child_for_request(larval_child)) {
		return STF_INTERNAL_ERROR;
	}

	struct v2_message request;
	if (!open_v2_message("new Child SA request",
			     ike, larval_child->sa.st_logger,
			     /*initiator*/NULL, ISAKMP_v2_CREATE_CHILD_SA,
			     reply_buffer, sizeof(reply_buffer),
			     &request, ENCRYPTED_PAYLOAD)) {
		return STF_INTERNAL_ERROR;
	}

	if (!emit_v2_child_request_payloads(ike, larval_child,
					    larval_child->sa.st_v2_create_child_sa_proposals,
					    request.pbs)) {
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
	delete_event(&larval_child->sa);
	change_v2_state(&larval_child->sa);

	return STF_OK; /* IKE */
}

stf_status process_v2_CREATE_CHILD_SA_new_child_request(struct ike_sa *ike,
							struct child_sa *larval_child,
							struct msg_digest *md)
{
	pexpect(larval_child == NULL);
	larval_child = new_v2_child_state(ike->sa.st_connection,
					  ike, IPSEC_SA, SA_RESPONDER,
					  STATE_V2_NEW_CHILD_R0,
					  null_fd);
	ike->sa.st_v2_msgid_windows.responder.wip_sa = larval_child;
	larval_child->sa.st_v2_create_child_sa_proposals =
		get_v2_CREATE_CHILD_SA_new_child_proposals(ike, larval_child);

	/* state m/c created CHILD SA */
	pexpect(larval_child->sa.st_v2_ike_pred == SOS_NOBODY);
	pexpect(larval_child->sa.st_v2_rekey_pred == SOS_NOBODY);
	v2_notification_t n = assign_v2_responders_child_client(larval_child, md);
	if (n != v2N_NOTHING_WRONG) {
		/* already logged */
		record_v2N_response(larval_child->sa.st_logger, ike, md,
				    n, NULL/*no-data*/, ENCRYPTED_PAYLOAD);
		delete_state(&larval_child->sa);
		ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
		return STF_OK; /*IKE*/
	}

	return process_v2_CREATE_CHILD_SA_request(ike, larval_child, md);
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
	if (!accept_v2_nonce(larval_child->sa.st_logger, md, &larval_child->sa.st_ni, "Ni")) {
		/*
		 * Presumably not our fault.  Syntax error response
		 * impicitly kills the family.
		 */
		record_v2N_response(ike->sa.st_logger, ike, md,
				    v2N_INVALID_SYNTAX, NULL/*no-data*/,
				    ENCRYPTED_PAYLOAD);
		delete_state(&larval_child->sa);
		ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
		return STF_FATAL; /* invalid syntax means we're dead */
	}

	n = process_v2_childs_sa_payload("CREATE_CHILD_SA request",
					 ike, larval_child, md,
					 larval_child->sa.st_v2_create_child_sa_proposals,
					 /*expect-accepted-proposal?*/false);
	if (n != v2N_NOTHING_WRONG) {
		record_v2N_response(ike->sa.st_logger, ike, md,
				    n, NULL/*no-data*/, ENCRYPTED_PAYLOAD);
		delete_state(&larval_child->sa);
		ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
		return v2_notification_fatal(n) ? STF_FATAL : STF_OK; /*IKE*/
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
		if (!unpack_KE(&larval_child->sa.st_gi, "Gi", larval_child->sa.st_oakley.ta_dh,
			       md->chain[ISAKMP_NEXT_v2KE], larval_child->sa.st_logger)) {
			record_v2N_response(larval_child->sa.st_logger, ike, md, v2N_INVALID_SYNTAX,
					    NULL/*no data*/, ENCRYPTED_PAYLOAD);
			delete_state(&larval_child->sa);
			ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
			return STF_OK; /*IKE*/
		}
	}

	/*
	 * XXX: note the .st_pfs_group vs .st_oakley.ta_dh
	 * switch-a-roo.  Is this because .st_pfs_group is
	 * acting more like a flag or perhaps, even though DH
	 * was negotiated it can be ignored?
	 */
	submit_ke_and_nonce(&ike->sa,
			    larval_child->sa.st_pfs_group != NULL ? larval_child->sa.st_oakley.ta_dh : NULL,
			    process_v2_CREATE_CHILD_SA_request_continue_1, HERE);
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
	pexpect(larval_child->sa.st_state->kind == STATE_V2_NEW_CHILD_R0 ||
		larval_child->sa.st_state->kind == STATE_V2_REKEY_CHILD_R0);

	unpack_nonce(&larval_child->sa.st_nr, nonce);
	if (local_secret == NULL) {
		/* skip step 2 */
		/* may invalidate LARVAL_CHILD */
		return process_v2_CREATE_CHILD_SA_request_continue_3(ike, request_md);
	}

	unpack_KE_from_helper(&larval_child->sa, local_secret, &larval_child->sa.st_gr);
	/* initiate calculation of g^xy */
	submit_dh_shared_secret(&ike->sa, &larval_child->sa,
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
	pexpect(larval_child->sa.st_state->kind == STATE_V2_NEW_CHILD_R0 ||
		larval_child->sa.st_state->kind == STATE_V2_REKEY_CHILD_R0);

	if (larval_child->sa.st_dh_shared_secret == NULL) {
		log_state(RC_LOG, &larval_child->sa, "DH failed");
		record_v2N_response(larval_child->sa.st_logger, ike, request_md,
				    v2N_INVALID_SYNTAX, NULL,
				    ENCRYPTED_PAYLOAD);
		delete_state(&larval_child->sa);
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
	pexpect(larval_child->sa.st_state->kind == STATE_V2_NEW_CHILD_R0 ||
		larval_child->sa.st_state->kind == STATE_V2_REKEY_CHILD_R0);
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
			     ike, larval_child->sa.st_logger,
			     request_md, ISAKMP_v2_CREATE_CHILD_SA,
			     reply_buffer, sizeof(reply_buffer),
			     &response, ENCRYPTED_PAYLOAD)) {
		return STF_FATAL; /* IKE */
	}

	v2_notification_t n = process_v2_child_request_payloads(ike, larval_child, request_md,
								response.pbs);
	if (n != v2N_NOTHING_WRONG) {
		/* already logged */
		record_v2N_response(larval_child->sa.st_logger, ike, request_md,
				    n, NULL/*no-data*/, ENCRYPTED_PAYLOAD);
		delete_state(&larval_child->sa);
		ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
		return v2_notification_fatal(n) ? STF_FATAL : STF_OK; /*IKE*/
	}

	if (!close_and_record_v2_message(&response)) {
		return STF_INTERNAL_ERROR;
	}

	return STF_OK; /*IKE*/
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

	pexpect(larval_child->sa.st_establishing_sa == IPSEC_SA);

	/*
	 * Drive the larval Child SA's state machine.
	 */
	pexpect(larval_child->sa.st_state->nr_transitions >= 1);
	const struct v2_state_transition *transition =
		&larval_child->sa.st_state->v2.transitions[0];
	pexpect(transition->state == STATE_V2_REKEY_CHILD_I1 ||
		transition->state == STATE_V2_NEW_CHILD_I1);
	pexpect(transition->next_state == STATE_V2_ESTABLISHED_CHILD_SA);
	larval_child->sa.st_v2_transition = transition;

	/* Ni in */
	if (!accept_v2_nonce(larval_child->sa.st_logger, response_md,
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

	n = process_v2_childs_sa_payload("CREATE_CHILD_SA responder matching remote ESP/AH proposals",
					 ike, larval_child, response_md,
					 larval_child->sa.st_v2_create_child_sa_proposals,
					 /*expect-accepted-proposal?*/true);
	if (v2_notification_fatal(n)) {
		return STF_FATAL; /* IKE */
	}

	if (n != v2N_NOTHING_WRONG) {
		/*
		 * Kill the child, but not the IKE SA?
		 *
		 * XXX: initiator; need to initiate a delete
		 * exchange.
		 */
		delete_state(&larval_child->sa);
		ike->sa.st_v2_msgid_windows.initiator.wip_sa = larval_child = NULL;
		return STF_OK; /* IKE */
	}

	/*
	 * XXX: only for rekey child?
	 */
	if (larval_child->sa.st_pfs_group == NULL) {
		v2_notification_t n = process_v2_child_response_payloads(ike, larval_child, response_md);
		if (v2_notification_fatal(n)) {
			return STF_FATAL;
		}
		if (n != v2N_NOTHING_WRONG) {
			/*
			 * Kill the child, but not the IKE SA?
			 *
			 * XXX: initiator; need to initiate a delete
			 * exchange.
			 */
			delete_state(&larval_child->sa);
			ike->sa.st_v2_msgid_windows.initiator.wip_sa = larval_child = NULL;
			return STF_OK; /* IKE */
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
		release_whack(larval_child->sa.st_logger, HERE);
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
		       response_md->chain[ISAKMP_NEXT_v2KE], larval_child->sa.st_logger)) {
		/*
		 * XXX: Initiator; need to initiate a delete exchange.
		 */
		delete_state(&larval_child->sa);
		ike->sa.st_v2_msgid_windows.initiator.wip_sa = larval_child = NULL;
		return STF_OK; /* IKE */
	}

	chunk_t remote_ke = larval_child->sa.st_gr;
	submit_dh_shared_secret(&ike->sa, &larval_child->sa, remote_ke,
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
	pexpect(larval_child->sa.st_establishing_sa == IPSEC_SA);
	dbg("%s() for #%lu %s",
	     __func__, larval_child->sa.st_serialno, larval_child->sa.st_state->name);

	/*
	 * XXX: Should this routine be split so that each instance
	 * handles only one state transition.  If there's commonality
	 * then the per-transition functions can all call common code.
	 */
	pexpect(larval_child->sa.st_state->kind == STATE_V2_NEW_CHILD_I1 ||
		larval_child->sa.st_state->kind == STATE_V2_REKEY_CHILD_I1);

	if (larval_child->sa.st_dh_shared_secret == NULL) {
		/*
		 * XXX: initiator; need to initiate a delete exchange.
		 */
		delete_state(&larval_child->sa);
		ike->sa.st_v2_msgid_windows.initiator.wip_sa = larval_child = NULL;
		return STF_OK; /* IKE */
	}

	v2_notification_t n = process_v2_child_response_payloads(ike, larval_child,
								 response_md);
	if (v2_notification_fatal(n)) {
		/*
		 * XXX: initiator; need to initiate a fatal error
		 * notification exchange.
		 */
		return STF_FATAL; /* IKE */
	}

	if (n != v2N_NOTHING_WRONG) {
		/*
		 * XXX: initiator; need to intiate a delete exchange.
		 */
		delete_state(&larval_child->sa);
		ike->sa.st_v2_msgid_windows.initiator.wip_sa = larval_child = NULL;
		return STF_OK; /* IKE */
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
	release_whack(larval_child->sa.st_logger, HERE);

	return STF_OK; /* IKE */
}

/*
 * Rekey the IKE SA (RFC 7296 1.3.2).
 *
 * Note that initiate is a little deceptive.  It is submitting crypto.
 * The initiate proper only happens later when the exchange is added
 * to the message queue.
 */

struct child_sa *submit_v2_CREATE_CHILD_SA_rekey_ike(struct ike_sa *ike)
{
	struct connection *c = ike->sa.st_connection;

	; /* to be determined */
	struct child_sa *larval_ike = new_v2_child_state(c, ike, IKE_SA,
							 SA_INITIATOR,
							 STATE_V2_REKEY_IKE_I0,
							 ike->sa.st_logger->global_whackfd);
	larval_ike->sa.st_oakley = ike->sa.st_oakley;
	larval_ike->sa.st_ike_rekey_spis.initiator = ike_initiator_spi();
	larval_ike->sa.st_v2_rekey_pred = ike->sa.st_serialno;
	larval_ike->sa.st_try = 1;
	larval_ike->sa.st_policy = LEMPTY;
	larval_ike->sa.st_v2_create_child_sa_proposals =
		ikev2_proposals_from_proposal("rekeying ike", ike->sa.st_v2_accepted_proposal);

	free_chunk_content(&larval_ike->sa.st_ni); /* this is from the parent. */
	free_chunk_content(&larval_ike->sa.st_nr); /* this is from the parent. */

	/*
	 * Note: this will callback with the larval SA.
	 *
	 * Later, when the exchange is initiated, the IKE SA (which
	 * could have changed) will be called.
	 */

	passert(larval_ike->sa.st_connection != NULL);
	policy_buf pb;
	dbg("#%lu submitting crypto needed to rekey IKE SA #%lu policy=%s pfs=%s",
	    larval_ike->sa.st_serialno, ike->sa.st_serialno,
	    str_policy(larval_ike->sa.st_policy, &pb),
	    larval_ike->sa.st_oakley.ta_dh->common.fqn);

	submit_ke_and_nonce(&larval_ike->sa, larval_ike->sa.st_oakley.ta_dh,
			    queue_v2_CREATE_CHILD_SA_rekey_ike_request, HERE);
	/* "return STF_SUSPEND" */
	return larval_ike;
}

static void llog_v2_success_rekey_ike_request(struct ike_sa *ike)
{
	/* XXX: should the lerval SA be a parameter? */
	struct child_sa *larval = ike->sa.st_v2_msgid_windows.initiator.wip_sa;
	if (larval != NULL) {
		pexpect(larval->sa.st_v2_rekey_pred == ike->sa.st_serialno);
#if 0
		llog_sa(RC_NEW_V2_STATE + larval->sa.st_state->kind, larval,
			"sent CREATE_CHILD_SA request to rekey IKE SA "PRI_SO,
			pri_so(larval->sa.st_v2_rekey_pred));
#else
		llog_sa(RC_NEW_V2_STATE + larval->sa.st_state->kind, larval,
			"sent CREATE_CHILD_SA request to rekey IKE SA");
#endif
	} else {
		llog_sa(RC_LOG_SERIOUS, ike, "rekey of IKE SA abandoned");
	}
}

static const struct v2_state_transition v2_CREATE_CHILD_SA_rekey_ike_transition = {
	.story      = "initiate rekey IKE_SA (CREATE_CHILD_SA)",
	.state      = STATE_V2_ESTABLISHED_IKE_SA,
	.next_state = STATE_V2_ESTABLISHED_IKE_SA,
	.exchange   = ISAKMP_v2_CREATE_CHILD_SA,
	.send_role  = MESSAGE_REQUEST,
	.processor  = initiate_v2_CREATE_CHILD_SA_rekey_ike_request,
	.llog_success = llog_v2_success_rekey_ike_request,
	.timeout_event = EVENT_RETAIN,
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
					   &v2_CREATE_CHILD_SA_rekey_ike_transition);
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
	delete_event(&larval_ike->sa);
	change_v2_state(&larval_ike->sa);

	return STF_OK; /* IKE */
}

stf_status process_v2_CREATE_CHILD_SA_rekey_ike_request(struct ike_sa *ike,
							struct child_sa *larval_ike,
							struct msg_digest *request_md)
{
	v2_notification_t n;

	pexpect(larval_ike == NULL);
	larval_ike = new_v2_child_state(ike->sa.st_connection,
					ike, IKE_SA, SA_RESPONDER,
					STATE_V2_REKEY_IKE_R0,
					null_fd);
	ike->sa.st_v2_msgid_windows.responder.wip_sa = larval_ike;
	larval_ike->sa.st_v2_rekey_pred = ike->sa.st_serialno;

	struct connection *c = larval_ike->sa.st_connection;

	free_chunk_content(&larval_ike->sa.st_ni); /* this is from the parent. */
	free_chunk_content(&larval_ike->sa.st_nr); /* this is from the parent. */

	/* Ni in */
	if (!accept_v2_nonce(larval_ike->sa.st_logger, request_md, &larval_ike->sa.st_ni, "Ni")) {
		/*
		 * Presumably not our fault.  A syntax error response
		 * implicitly kills the entire family.
		 *
		 * Already logged?
		 */
		record_v2N_response(ike->sa.st_logger, ike, request_md,
				    v2N_INVALID_SYNTAX, NULL/*no-data*/,
				    ENCRYPTED_PAYLOAD);
		delete_state(&larval_ike->sa);
		ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
		return STF_FATAL; /* IKE family is doomed */
	}

	/* Get the proposals ready. */
	const struct ikev2_proposals *ike_proposals = c->config->v2_ike_proposals;

	struct payload_digest *const sa_pd = request_md->chain[ISAKMP_NEXT_v2SA];
	n = ikev2_process_sa_payload("IKE Rekey responder child",
				     &sa_pd->pbs,
				     /*expect_ike*/ true,
				     /*expect_spi*/ true,
				     /*expect_accepted*/ false,
				     LIN(POLICY_OPPORTUNISTIC, c->policy),
				     &larval_ike->sa.st_v2_accepted_proposal,
				     ike_proposals, larval_ike->sa.st_logger);
	if (n != v2N_NOTHING_WRONG) {
		pexpect(larval_ike->sa.st_sa_role == SA_RESPONDER);
		record_v2N_response(larval_ike->sa.st_logger, ike, request_md,
				    n, NULL, ENCRYPTED_PAYLOAD);
		delete_state(&larval_ike->sa);
		ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
		return v2_notification_fatal(n) ? STF_FATAL : STF_OK; /* IKE */
	}

	if (DBGP(DBG_BASE)) {
		DBG_log_ikev2_proposal("accepted IKE proposal",
				       larval_ike->sa.st_v2_accepted_proposal);
	}

	if (!ikev2_proposal_to_trans_attrs(larval_ike->sa.st_v2_accepted_proposal,
					   &larval_ike->sa.st_oakley, larval_ike->sa.st_logger)) {
		llog_sa(RC_LOG_SERIOUS, larval_ike,
			"IKE responder accepted an unsupported algorithm");
		delete_state(&larval_ike->sa);
		ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
		return STF_FATAL; /* IKE family is doomed */
	}

	if (!v2_accept_ke_for_proposal(ike, &larval_ike->sa, request_md,
				       larval_ike->sa.st_oakley.ta_dh,
				       ENCRYPTED_PAYLOAD)) {
		/* passert(reply-recorded) */
		delete_state(&larval_ike->sa);
		ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
		return STF_OK; /* IKE */
	}

	/*
	 * Check and read the KE contents.
	 *
	 * responder, so accept initiator's KE in with new
	 * accepted_oakley for IKE.
	 */
	pexpect(larval_ike->sa.st_oakley.ta_dh != NULL);
	pexpect(larval_ike->sa.st_pfs_group == NULL);
	if (!unpack_KE(&larval_ike->sa.st_gi, "Gi", larval_ike->sa.st_oakley.ta_dh,
		       request_md->chain[ISAKMP_NEXT_v2KE], larval_ike->sa.st_logger)) {
		/* Already logged */
		record_v2N_response(ike->sa.st_logger, ike, request_md,
				    v2N_INVALID_SYNTAX, NULL/*no data*/,
				    ENCRYPTED_PAYLOAD);
		delete_state(&larval_ike->sa);
		ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
		return STF_FATAL; /* IKE family is doomed */
	}

	submit_ke_and_nonce(&ike->sa, larval_ike->sa.st_oakley.ta_dh,
			    process_v2_CREATE_CHILD_SA_rekey_ike_request_continue_1, HERE);
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
	pexpect(larval_ike->sa.st_state->kind == STATE_V2_REKEY_IKE_R0);
	dbg("%s() for #%lu %s",
	     __func__, larval_ike->sa.st_serialno, larval_ike->sa.st_state->name);

	pexpect(local_secret != NULL);
	pexpect(request_md->chain[ISAKMP_NEXT_v2KE] != NULL);
	unpack_nonce(&larval_ike->sa.st_nr, nonce);
	unpack_KE_from_helper(&larval_ike->sa, local_secret, &larval_ike->sa.st_gr);

	/* initiate calculation of g^xy */
	passert(ike_spi_is_zero(&larval_ike->sa.st_ike_rekey_spis.initiator));
	passert(ike_spi_is_zero(&larval_ike->sa.st_ike_rekey_spis.responder));
	ikev2_copy_cookie_from_sa(larval_ike->sa.st_v2_accepted_proposal,
				  &larval_ike->sa.st_ike_rekey_spis.initiator);
	larval_ike->sa.st_ike_rekey_spis.responder = ike_responder_spi(&request_md->sender,
								       larval_ike->sa.st_logger);
	submit_dh_shared_secret(&ike->sa, &larval_ike->sa,
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
	pexpect(larval_ike->sa.st_state->kind == STATE_V2_REKEY_IKE_R0);
	pexpect(larval_ike->sa.st_v2_transition->state == STATE_V2_REKEY_IKE_R0);
	pexpect(larval_ike->sa.st_v2_transition->next_state == STATE_V2_ESTABLISHED_IKE_SA);
	dbg("%s() for #%lu %s",
	     __func__, larval_ike->sa.st_serialno, larval_ike->sa.st_state->name);

	if (larval_ike->sa.st_dh_shared_secret == NULL) {
		record_v2N_response(ike->sa.st_logger, ike, request_md,
				    v2N_INVALID_SYNTAX, NULL,
				    ENCRYPTED_PAYLOAD);
		delete_state(&larval_ike->sa);
		ike->sa.st_v2_msgid_windows.responder.wip_sa = NULL;
		return STF_FATAL; /* IKE family is doomed */
	}

	calc_v2_keymat(&larval_ike->sa,
		       ike->sa.st_skey_d_nss, /* only IKE has SK_d */
		       ike->sa.st_oakley.ta_prf, /* for IKE/ESP/AH */
		       &larval_ike->sa.st_ike_rekey_spis);

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

	pexpect(larval_ike->sa.st_establishing_sa == IKE_SA);
	pexpect(ike->sa.st_serialno == larval_ike->sa.st_clonedfrom); /* not yet emancipated */
	struct connection *c = larval_ike->sa.st_connection;

	/*
	 * Drive the larval IKE SA's state machine.
	 */
	pexpect(larval_ike->sa.st_state->nr_transitions >= 1);
	const struct v2_state_transition *transition =
		&larval_ike->sa.st_state->v2.transitions[0];
	pexpect(transition->state == STATE_V2_REKEY_IKE_I1);
	pexpect(transition->next_state == STATE_V2_ESTABLISHED_IKE_SA);
	larval_ike->sa.st_v2_transition = transition;

	/* Ni in */
	if (!accept_v2_nonce(larval_ike->sa.st_logger, response_md, &larval_ike->sa.st_nr, "Nr")) {
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
	n = ikev2_process_sa_payload("IKE initiator (accepting)",
				     &sa_pd->pbs,
				     /*expect_ike*/ true,
				     /*expect_spi*/ true,
				     /*expect_accepted*/ true,
				     LIN(POLICY_OPPORTUNISTIC, c->policy),
				     &larval_ike->sa.st_v2_accepted_proposal,
				     larval_ike->sa.st_v2_create_child_sa_proposals,
				     larval_ike->sa.st_logger);
	if (v2_notification_fatal(n)) {
		return STF_FATAL;
	}
	if (n != v2N_NOTHING_WRONG) {
		dbg("failed to accept IKE SA, REKEY, response, in process_v2_CREATE_CHILD_SA_rekey_ike_response");
		delete_state(&larval_ike->sa);
		ike->sa.st_v2_msgid_windows.initiator.wip_sa = larval_ike = NULL;
		return STF_OK; /* IKE */
	}

	if (DBGP(DBG_BASE)) {
		DBG_log_ikev2_proposal("accepted IKE proposal",
				       larval_ike->sa.st_v2_accepted_proposal);
	}
	if (!ikev2_proposal_to_trans_attrs(larval_ike->sa.st_v2_accepted_proposal,
					   &larval_ike->sa.st_oakley, larval_ike->sa.st_logger)) {
		llog_sa(RC_LOG_SERIOUS, larval_ike,
			"IKE responder accepted an unsupported algorithm");
		/* free early return items */
		free_ikev2_proposal(&larval_ike->sa.st_v2_accepted_proposal);
		passert(larval_ike->sa.st_v2_accepted_proposal == NULL);
		return STF_FATAL;
	}

	 /* KE in */
	if (!unpack_KE(&larval_ike->sa.st_gr, "Gr", larval_ike->sa.st_oakley.ta_dh,
		       response_md->chain[ISAKMP_NEXT_v2KE], larval_ike->sa.st_logger)) {
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
	ikev2_copy_cookie_from_sa(larval_ike->sa.st_v2_accepted_proposal,
				  &larval_ike->sa.st_ike_rekey_spis.responder);

	/* initiate calculation of g^xy for rekey */
	submit_dh_shared_secret(&ike->sa, &larval_ike->sa,
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
	pexpect(larval_ike->sa.st_establishing_sa == IKE_SA);
	pexpect(larval_ike->sa.st_state->kind == STATE_V2_REKEY_IKE_I1);
	pexpect(larval_ike->sa.st_v2_transition->state == STATE_V2_REKEY_IKE_I1);
	pexpect(larval_ike->sa.st_v2_transition->next_state == STATE_V2_ESTABLISHED_IKE_SA);
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

	calc_v2_keymat(&larval_ike->sa,
		       ike->sa.st_skey_d_nss, /* only IKE has SK_d */
		       ike->sa.st_oakley.ta_prf, /* for IKE/ESP/AH */
		       &larval_ike->sa.st_ike_rekey_spis/* new SPIs */);

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
						       struct child_sa *child,
						       struct msg_digest *md UNUSED)
{
	passert(ike != NULL);
	passert(child == NULL);
	child = ike->sa.st_v2_msgid_windows.initiator.wip_sa;
	if (!pexpect(child != NULL)) {
		/* XXX: drop everything on the floor */
		return STF_INTERNAL_ERROR;
	}

        pstat_sa_failed(&child->sa, REASON_TRAFFIC_SELECTORS_FAILED);

	for (struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		v2_notification_t n = ntfy->payload.v2n.isan_type;
		if (n < v2N_ERROR_PSTATS_ROOF) {
			pstat(ikev2_recv_notifies_e, n);
			enum_buf esb;
			llog_sa(RC_LOG_SERIOUS, child,
				"CREATE_CHILD_SA failed with error notification %s",
				str_enum_short(&v2_notification_names, n, &esb));
			dbg("re-add child to pending queue with exponential back-off?");
			break;
		}
	}

	/* keep tests happy */
	llog_sa(RC_NOTIFICATION, child, "state transition '%s' failed",
		child->sa.st_v2_transition->story);

	delete_state(&child->sa);
	ike->sa.st_v2_msgid_windows.initiator.wip_sa = child = NULL;

	return STF_OK; /* IKE */
}
