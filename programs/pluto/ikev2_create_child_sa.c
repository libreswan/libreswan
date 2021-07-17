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

static ikev2_state_transition_fn record_v2_CREATE_CHILD_SA;
static ikev2_state_transition_fn process_v2_CREATE_CHILD_SA_request;
static ikev2_state_transition_fn process_v2_CREATE_CHILD_SA_child_response;

static ikev2_state_transition_fn record_v2_CREATE_CHILD_SA_request;

static ke_and_nonce_cb queue_v2_CREATE_CHILD_SA_initiator; /* signature check */

stf_status queue_v2_CREATE_CHILD_SA_initiator(struct state *larval_sa,
					      struct msg_digest *unused_md,
					      struct dh_local_secret *local_secret,
					      chunk_t *nonce)
{
	/* child initiating exchange */
	struct child_sa *larval = pexpect_child_sa(larval_sa);
	struct ike_sa *ike = ike_sa(&larval->sa, HERE);
	pexpect(unused_md == NULL);
	pexpect(larval->sa.st_sa_role == SA_INITIATOR);
	dbg("%s() for #%lu %s",
	     __func__, larval->sa.st_serialno, larval->sa.st_state->name);

	/*
	 * XXX: Should this routine be split so that each instance
	 * handles only one state transition.  If there's commonality
	 * then the per-transition functions can all call common code.
	 */
	pexpect(larval->sa.st_state->kind == STATE_V2_NEW_CHILD_I0 ||
		larval->sa.st_state->kind == STATE_V2_REKEY_CHILD_I0 ||
		larval->sa.st_state->kind == STATE_V2_REKEY_IKE_I0);

	/* and a parent? */
	if (ike == NULL) {
		pexpect_fail(larval->sa.st_logger, HERE,
			     "sponsoring child state #%lu has no parent state #%lu",
			     larval->sa.st_serialno, larval->sa.st_clonedfrom);
		/* XXX: release child? */
		return STF_INTERNAL_ERROR;
	}

	/* IKE SA => DH */
	pexpect(larval->sa.st_state->kind == STATE_V2_REKEY_IKE_I0 ? local_secret != NULL : true);

	unpack_nonce(&larval->sa.st_ni, nonce);
	if (local_secret != NULL) {
		unpack_KE_from_helper(&larval->sa, local_secret, &larval->sa.st_gi);
	}

	dbg("queueing child sa with acquired sec_label="PRI_SHUNK,
	    pri_shunk(larval->sa.st_connection->spd.this.sec_label));

	dbg("adding CHILD SA #%lu to IKE SA #%lu message initiator queue",
	    larval->sa.st_serialno, ike->sa.st_serialno);

	pexpect(larval->sa.st_state->nr_transitions == 1);
	v2_msgid_queue_initiator(ike, larval, &larval->sa,
				 ISAKMP_v2_CREATE_CHILD_SA,
				 larval->sa.st_state->v2_transitions);

	return STF_SUSPEND;
}

static stf_status ikev2_start_new_exchange(struct ike_sa *ike,
					   struct child_sa *child)
{
	switch (child->sa.st_establishing_sa) { /* where we're going */
	case IKE_SA:
		return STF_OK;
	case IPSEC_SA: /* CHILD_SA */
		if (!ike->sa.st_viable_parent) {
			child->sa.st_policy = child->sa.st_connection->policy; /* for pick_initiator */

			log_state(RC_LOG_SERIOUS, &child->sa,
				  "no viable to parent to initiate CREATE_CHILD_EXCHANGE %s; trying replace",
				  child->sa.st_state->name);
			delete_event(&child->sa);
			event_schedule(EVENT_SA_REPLACE, REPLACE_ORPHAN_DELAY, &child->sa);
			/* ??? surely this isn't yet a failure or a success */
			return STF_FAIL;
		}
		return STF_OK;
	default:
		bad_case(child->sa.st_establishing_sa);
	}

}

stf_status record_v2_CREATE_CHILD_SA_request(struct ike_sa *ike,
					     struct child_sa *larval,
					     struct msg_digest *null_md UNUSED)
{
	stf_status e = ikev2_start_new_exchange(ike, larval);
	if (e != STF_OK) {
		return e;
	}
	return record_v2_CREATE_CHILD_SA(ike, larval, NULL);
}

static bool ikev2_rekey_child_req(struct child_sa *child,
				  enum ikev2_sec_proto_id *rekey_protoid,
				  ipsec_spi_t *rekey_spi)
{
	if (!pexpect(child->sa.st_establishing_sa == IPSEC_SA) ||
	    !pexpect(child->sa.st_ipsec_pred != SOS_NOBODY) ||
	    !pexpect(child->sa.st_state->kind == STATE_V2_REKEY_CHILD_I0)) {
		return false;
	}

	struct state *rst = state_with_serialno(child->sa.st_ipsec_pred);
	if (rst ==  NULL) {
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
		log_state(LOG_STREAM/*not-whack*/, &child->sa,
			  "CHILD SA to rekey #%lu vanished abort this exchange",
			  child->sa.st_ipsec_pred);
		return false;
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
		pexpect_fail(child->sa.st_logger, HERE,
			     "CHILD SA to rekey #%lu is not ESP/AH",
			     child->sa.st_ipsec_pred);
		return false;
	}

	connection_buf cib;
	dbg("#%lu initiate rekey request for "PRI_CONNECTION" #%lu SPI 0x%x TSi TSr",
	    child->sa.st_serialno,
	    pri_connection(rst->st_connection, &cib),
	    rst->st_serialno, ntohl(*rekey_spi));

	return true;
}

static bool ikev2_rekey_child_resp(struct ike_sa *ike, struct child_sa *child,
				   struct msg_digest *md)
{
	/*
	 * Previously found by the state machine.
	 */
	const struct payload_digest *rekey_sa_payload = md->pd[PD_v2N_REKEY_SA];
	if (rekey_sa_payload == NULL) {
		pexpect_fail(child->sa.st_logger, HERE,
			     "rekey child can't find its rekey_sa payload");
		return STF_INTERNAL_ERROR;
	}
#if 0
	/* XXX: this would require a separate .pd_next link? */
	if (rekey_sa_payload->next != NULL) {
		/* will tolerate multiple */
		log_state(RC_LOG_SERIOUS, &child->sa,
			  "ignoring duplicate v2N_REKEY_SA in exchange");
	}
#endif

	const struct ikev2_notify *rekey_notify = &rekey_sa_payload->payload.v2n;
	/*
	 * find old state to rekey
	 */
	esb_buf b;
	dbg("CREATE_CHILD_SA IPsec SA rekey Protocol %s",
	    enum_show(&ikev2_notify_protocol_id_names, rekey_notify->isan_protoid, &b));

	if (rekey_notify->isan_spisize != sizeof(ipsec_spi_t)) {
		log_state(RC_LOG, &child->sa,
			  "CREATE_CHILD_SA IPsec SA rekey invalid spi size %u",
			  rekey_notify->isan_spisize);
		record_v2N_response(child->sa.st_logger, ike, md, v2N_INVALID_SYNTAX,
				    NULL/*empty data*/, ENCRYPTED_PAYLOAD);
		return false;
	}

	ipsec_spi_t spi = 0;
	struct pbs_in rekey_pbs = rekey_sa_payload->pbs;
	diag_t d = pbs_in_raw(&rekey_pbs, &spi, sizeof(spi), "SPI");
	if (d != NULL) {
		llog_diag(RC_LOG, child->sa.st_logger, &d, "%s", "");
		record_v2N_response(child->sa.st_logger, ike, md, v2N_INVALID_SYNTAX,
				    NULL/*empty data*/, ENCRYPTED_PAYLOAD);
		return false; /* cannot happen; XXX: why? */
	}

	if (spi == 0) {
		log_state(RC_LOG, &child->sa,
			  "CREATE_CHILD_SA IPsec SA rekey contains zero SPI");
		record_v2N_response(child->sa.st_logger, ike, md, v2N_INVALID_SYNTAX,
				    NULL/*empty data*/, ENCRYPTED_PAYLOAD);
		return false;
	}

	if (rekey_notify->isan_protoid != PROTO_IPSEC_ESP &&
	    rekey_notify->isan_protoid != PROTO_IPSEC_AH) {
		esb_buf b;
		log_state(RC_LOG, &child->sa,
			  "CREATE_CHILD_SA IPsec SA rekey invalid Protocol ID %s",
			  enum_show(&ikev2_notify_protocol_id_names, rekey_notify->isan_protoid, &b));
		record_v2N_spi_response(child->sa.st_logger, ike, md,
					rekey_notify->isan_protoid, &spi,
					v2N_CHILD_SA_NOT_FOUND,
					NULL/*empty data*/, ENCRYPTED_PAYLOAD);
		return false;
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
		log_state(RC_LOG, &child->sa,
			  "CREATE_CHILD_SA no such IPsec SA to rekey SA(0x%08" PRIx32 ") Protocol %s",
			  ntohl((uint32_t) spi),
			  enum_show(&ikev2_notify_protocol_id_names, rekey_notify->isan_protoid, &b));
		record_v2N_spi_response(child->sa.st_logger, ike, md,
					rekey_notify->isan_protoid, &spi,
					v2N_CHILD_SA_NOT_FOUND,
					NULL/*empty data*/, ENCRYPTED_PAYLOAD);
		return false;
	}

	child->sa.st_ipsec_pred = replaced_child->sa.st_serialno;

	connection_buf cb;
	dbg("#%lu rekey request for "PRI_CONNECTION" #%lu TSi TSr",
	    child->sa.st_serialno,
	    pri_connection(replaced_child->sa.st_connection, &cb),
	    replaced_child->sa.st_serialno);
	update_state_connection(&child->sa, replaced_child->sa.st_connection);

	return true;
}

static bool ikev2_rekey_child_copy_ts(struct child_sa *child)
{
	passert(child->sa.st_ipsec_pred != SOS_NOBODY);

	/* old child state being rekeyed */
	struct child_sa *rchild = child_sa_by_serialno(child->sa.st_ipsec_pred);
	if (!pexpect(rchild != NULL)) {
		/*
		 * Something screwed up - can't even start to rekey a
		 * CHILD SA when there's no predicessor.
		 */
		return false;
	}

	/*
	 * RFC 7296 #2.9.2 the exact or the superset.
	 * exact is a should. Here libreswan only allow the exact.
	 * Inherit the TSi TSr from old state, IPsec SA.
	 */

	connection_buf cib;
	dbg("#%lu inherit spd, TSi TSr, from "PRI_CONNECTION" #%lu",
	    child->sa.st_serialno,
	    pri_connection(rchild->sa.st_connection, &cib),
	    rchild->sa.st_serialno);

	return true;
}

/* once done use the same function in ikev2_parent_inR1outI2_tail too */
static stf_status emit_v2_child_sa_request_payloads(struct child_sa *child,
						    struct pbs_out *outpbs)
{
	if (!pexpect(child->sa.st_establishing_sa == IPSEC_SA)) {
		return STF_INTERNAL_ERROR;
	}
	struct connection *cc = child->sa.st_connection;
	bool send_use_transport = (cc->policy & POLICY_TUNNEL) == LEMPTY;

	/* ??? this code won't support AH + ESP */
	struct ipsec_proto_info *proto_info
		= ikev2_child_sa_proto_info(child, cc->policy);
	proto_info->our_spi = ikev2_child_sa_spi(&cc->spd, cc->policy, child->sa.st_logger);
	chunk_t local_spi = THING_AS_CHUNK(proto_info->our_spi);

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

	/*
	 * If rekeying, get the old SPI and protocol.
	 */
	ipsec_spi_t rekey_spi = 0;
	enum ikev2_sec_proto_id rekey_protoid = PROTO_v2_RESERVED;
	if (child->sa.st_ipsec_pred != SOS_NOBODY) {
		if (!ikev2_rekey_child_req(child, &rekey_protoid, &rekey_spi)) {
			/*
			 * XXX: For instance:
			 *
			 * - the old child initiated this replacement
			 *
			 * - this child wondered off to perform DH
			 *
			 * - the old child expires itself (or it gets
			 *   sent a delete)
			 *
			 * - this child finds it has no older sibling
			 *
			 * The older child should have discarded this
			 * state.
			 */
			return STF_INTERNAL_ERROR;
		}
	}

	struct ikev2_generic in = {
		.isag_critical = build_ikev2_critical(false, child->sa.st_logger),
	};
	pb_stream pb_nr;
	if (!out_struct(&in, &ikev2_nonce_desc, outpbs, &pb_nr) ||
	    !out_hunk(child->sa.st_ni, &pb_nr, "IKEv2 nonce"))
		return STF_INTERNAL_ERROR;
	close_output_pbs(&pb_nr);

	if (child->sa.st_pfs_group != NULL) {
		if (!emit_v2KE(&child->sa.st_gi, child->sa.st_pfs_group, outpbs)) {
			return STF_INTERNAL_ERROR;
		}
	}

	if (rekey_spi != 0) {
		if (!emit_v2Nsa_pl(v2N_REKEY_SA,
				   rekey_protoid, &rekey_spi,
				   outpbs, NULL))
			return STF_INTERNAL_ERROR;
	}

	emit_v2TS_payloads(outpbs, child);

	if (send_use_transport) {
		dbg("Initiator child policy is transport mode, sending v2N_USE_TRANSPORT_MODE");
		if (!emit_v2N(v2N_USE_TRANSPORT_MODE, outpbs))
			return STF_INTERNAL_ERROR;
	} else {
		dbg("Initiator child policy is tunnel mode, NOT sending v2N_USE_TRANSPORT_MODE");
	}

	if (cc->send_no_esp_tfc) {
		if (!emit_v2N(v2N_ESP_TFC_PADDING_NOT_SUPPORTED, outpbs))
			return STF_INTERNAL_ERROR;
	}
	return STF_OK;
}

static stf_status emit_v2_rekey_ike_payloads(struct child_sa *child,
					     struct pbs_out *outpbs)
{
	struct connection *c = child->sa.st_connection;
	chunk_t local_nonce;
	chunk_t *local_g;

	switch (child->sa.st_state->kind) {
	case STATE_V2_REKEY_IKE_R0:
	{
		local_g = &child->sa.st_gr;
		local_nonce = child->sa.st_nr;
		chunk_t local_spi = THING_AS_CHUNK(child->sa.st_ike_rekey_spis.responder);

		/* send selected v2 IKE SA */
		if (!ikev2_emit_sa_proposal(outpbs, child->sa.st_accepted_ike_proposal,
					    &local_spi)) {
			dbg("problem emitting accepted ike proposal in CREATE_CHILD_SA");
			return STF_INTERNAL_ERROR;
		}
		break;
	}
	case STATE_V2_REKEY_IKE_I0:
	{
		local_g = &child->sa.st_gi;
		local_nonce = child->sa.st_ni;
		chunk_t local_spi = THING_AS_CHUNK(child->sa.st_ike_rekey_spis.initiator);

		struct ikev2_proposals *ike_proposals =
			get_v2_ike_proposals(c, "IKE SA initiating rekey",
					     child->sa.st_logger);

		/* send v2 IKE SAs*/
		if (!ikev2_emit_sa_proposals(outpbs, ike_proposals,
					     &local_spi)) {
			log_state(RC_LOG, &child->sa, "outsa fail");
			dbg("problem emitting connection ike proposals in CREATE_CHILD_SA");
			return STF_INTERNAL_ERROR;
		}
		break;
	}
	default:
		bad_case(child->sa.st_state->kind);
	}

	/* send NONCE */
	{
		struct ikev2_generic in = {
			.isag_critical = build_ikev2_critical(false, child->sa.st_logger),
		};
		pb_stream nr_pbs;
		if (!out_struct(&in, &ikev2_nonce_desc, outpbs, &nr_pbs) ||
		    !out_hunk(local_nonce, &nr_pbs, "IKEv2 nonce"))
			return STF_INTERNAL_ERROR;
		close_output_pbs(&nr_pbs);
	}

	if (!emit_v2KE(local_g, child->sa.st_oakley.ta_dh, outpbs))
		return STF_INTERNAL_ERROR;

	return STF_OK;
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
	larval_child->sa.st_ipsec_pred = child_being_replaced->sa.st_serialno;

	/*
	 * Use the CREATE_CHILD_SA proposal suite - the
	 * proposal generated during IKE_AUTH will have been
	 * stripped of DH.
	 *
	 * XXX: If the IKE SA's DH changes, then the child
	 * proposals will be re-generated.  Should the child
	 * proposals instead be somehow stored in state and
	 * dragged around?
	 *
	 * XXX: this choice of default_dh is wrong: It should use the
	 * Child SA's DH (assuming child was established using
	 * CREATE_CHILD_SA and negotiated DH) or the IKE SA's DH
	 * (assuming this is the child negotiated using IKE_AUTH), or
	 * ?
	 */
	const struct dh_desc *default_dh =
		c->policy & POLICY_PFS ? ike->sa.st_oakley.ta_dh : NULL;
	struct ikev2_proposals *child_proposals =
		get_v2_create_child_proposals(c,
					      "ESP/AH rekey Child SA initiator emitting proposals",
					      default_dh, logger);
	/* see emit_v2_child_sa_request_payloads */
	passert(c->v2_create_child_proposals != NULL);

	larval_child->sa.st_pfs_group = ikev2_proposals_first_dh(child_proposals, logger);

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
			    queue_v2_CREATE_CHILD_SA_initiator,
			    "Child Rekey Initiator KE and nonce ni");
	/* return STF_SUSPEND */
	return larval_child;
}

stf_status initiate_v2_CREATE_CHILD_SA_rekey_child_request(struct ike_sa *ike,
							   struct child_sa *larval_child,
							   struct msg_digest *md)
{
	return record_v2_CREATE_CHILD_SA_request(ike, larval_child, md);
}

stf_status process_v2_CREATE_CHILD_SA_rekey_child_request(struct ike_sa *ike,
							  struct child_sa *larval_child,
							  struct msg_digest *md)
{
	pexpect(larval_child != NULL);

	pexpect(larval_child->sa.st_ipsec_pred == SOS_NOBODY); /* TBD */
	if (!ikev2_rekey_child_resp(ike, larval_child, md)) {
		/* already logged; already recorded */
		return STF_FAIL;
	}
	pexpect(larval_child->sa.st_ipsec_pred != SOS_NOBODY);

	if (!child_rekey_responder_ts_verify(larval_child, md)) {
		record_v2N_response(ike->sa.st_logger, ike, md,
				    v2N_TS_UNACCEPTABLE, NULL/*no data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FAIL;
	}

	return process_v2_CREATE_CHILD_SA_request(ike, larval_child, md);
}

stf_status process_v2_CREATE_CHILD_SA_rekey_child_response(struct ike_sa *ike,
							   struct child_sa *larval_child,
							   struct msg_digest *md)
{
	return process_v2_CREATE_CHILD_SA_child_response(ike, larval_child, md);
}

/*
 * CREATE_CHILD_SA create child request.
 */

void submit_v2_CREATE_CHILD_SA_new_child(struct ike_sa *ike,
					 struct connection *c, /* for child */
					 lset_t policy, int try,
					 shunk_t sec_label,
					 struct fd *whackfd)
{
	if (c->kind == CK_TEMPLATE && sec_label.len > 0) {
		/* create instance and switch to it */
		ip_address remote_addr = endpoint_address(ike->sa.st_remote_endpoint);
		c = instantiate(c, &remote_addr, NULL);
		/* replace connection template label with ACQUIREd label */
		free_chunk_content(&c->spd.this.sec_label);
		free_chunk_content(&c->spd.that.sec_label);
		c->spd.this.sec_label = clone_hunk(sec_label, "ACQUIRED sec_label");
		c->spd.that.sec_label = clone_hunk(sec_label, "ACQUIRED sec_label");
	}

	struct child_sa *child = new_v2_child_state(c, ike, IPSEC_SA,
						    SA_INITIATOR,
						    STATE_V2_NEW_CHILD_I0,
						    whackfd);

	free_chunk_content(&child->sa.st_ni); /* this is from the parent. */
	free_chunk_content(&child->sa.st_nr); /* this is from the parent. */
	child->sa.st_try = try;

	/* share the love; XXX: something better? */
	close_any(&ike->sa.st_logger->object_whackfd);
	ike->sa.st_logger->object_whackfd = fd_dup(whackfd, HERE);
	child->sa.st_policy = policy;

	llog_sa(RC_LOG, child,
		"initiating Child SA using IKE SA #%lu", ike->sa.st_serialno);


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
	const struct dh_desc *default_dh =
		c->policy & POLICY_PFS ? ike->sa.st_oakley.ta_dh : NULL;
	struct ikev2_proposals *child_proposals =
		get_v2_create_child_proposals(c,
					      "ESP/AH initiator emitting proposals",
					      default_dh,
					      child->sa.st_logger);
	/* see emit_v2_child_sa_request_payloads */
	passert(c->v2_create_child_proposals != NULL);

	child->sa.st_pfs_group = ikev2_proposals_first_dh(child_proposals, child->sa.st_logger);

	policy_buf pb;
	dbg("#%lu submitting crypto needed to initiate Child SA using IKE SA #%lu policy=%s pfs=%s",
	    child->sa.st_serialno,
	    ike->sa.st_serialno,
	    str_policy(policy, &pb),
	    child->sa.st_pfs_group == NULL ? "no-pfs" : child->sa.st_pfs_group->common.fqn);

	submit_ke_and_nonce(&child->sa, child->sa.st_pfs_group /*possibly-null*/,
			    queue_v2_CREATE_CHILD_SA_initiator,
			    "Child Initiator KE? and nonce");
}

stf_status initiate_v2_CREATE_CHILD_SA_new_child_request(struct ike_sa *ike,
							 struct child_sa *larval_child,
							 struct msg_digest *md)
{
	return record_v2_CREATE_CHILD_SA_request(ike, larval_child, md);
}

stf_status process_v2_CREATE_CHILD_SA_new_child_request(struct ike_sa *ike,
							struct child_sa *larval_child,
							struct msg_digest *md)
{
	pexpect(larval_child != NULL);

	/* state m/c created CHILD SA */
	pexpect(larval_child->sa.st_ipsec_pred == SOS_NOBODY);
	v2_notification_t n = assign_v2_responders_child_client(larval_child, md);
	if (n != v2N_NOTHING_WRONG) {
		/* already logged */
		record_v2N_response(larval_child->sa.st_logger, ike, md,
				    n, NULL/*no-data*/, ENCRYPTED_PAYLOAD);
		return STF_FAIL;
	}

	return process_v2_CREATE_CHILD_SA_request(ike, larval_child, md);
}

stf_status process_v2_CREATE_CHILD_SA_new_child_response(struct ike_sa *ike,
							 struct child_sa *larval_child,
							 struct msg_digest *md)
{
	return process_v2_CREATE_CHILD_SA_child_response(ike, larval_child, md);
}

/*
 * processing a new Child SA (RFC 7296 1.3.1 or 1.3.3) request
 */

static ke_and_nonce_cb process_v2_CREATE_CHILD_SA_request_continue;

stf_status process_v2_CREATE_CHILD_SA_request(struct ike_sa *ike,
					      struct child_sa *larval_child,
					      struct msg_digest *md)
{
	pexpect(larval_child != NULL);

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
		return STF_FATAL; /* invalid syntax means we're dead */
	}

	stf_status ps = process_v2_childs_sa_payload("CREATE_CHILD_SA request",
						     ike, larval_child, md,
						     /*expect-accepted-proposal?*/false);
	if (ps > STF_FAIL) {
		v2_notification_t n = ps - STF_FAIL;
		record_v2N_response(ike->sa.st_logger, ike, md,
				    n, NULL/*no-data*/, ENCRYPTED_PAYLOAD);
		return STF_FAIL; /* CHILD, NOT IKE */
	}
	if (ps != STF_OK) {
		return ps;
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
			return STF_FAIL;
		}
	}

	/*
	 * XXX: note the .st_pfs_group vs .st_oakley.ta_dh
	 * switch-a-roo.  Is this because .st_pfs_group is
	 * acting more like a flag or perhaps, even though DH
	 * was negotiated it can be ignored?
	 */
	submit_ke_and_nonce(&larval_child->sa,
			    larval_child->sa.st_pfs_group != NULL ? larval_child->sa.st_oakley.ta_dh : NULL,
			    process_v2_CREATE_CHILD_SA_request_continue,
			    "Child Rekey Responder KE and nonce nr");
	return STF_SUSPEND;
}

static dh_shared_secret_cb process_v2_CREATE_CHILD_SA_request_continue_continue;

static stf_status process_v2_CREATE_CHILD_SA_request_continue(struct state *larval_child_sa,
							      struct msg_digest *md,
							      struct dh_local_secret *local_secret,
							      chunk_t *nonce)
{

	/* responder processing request */
	struct child_sa *larval_child = pexpect_child_sa(larval_child_sa);
	struct ike_sa *ike = ike_sa(&larval_child->sa, HERE);
	pexpect(v2_msg_role(md) == MESSAGE_REQUEST); /* i.e., MD!=NULL */
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

	/* and a parent? */
	if (ike == NULL) {
		pexpect_fail(larval_child->sa.st_logger, HERE,
			     "sponsoring child state #%lu has no parent state #%lu",
			     larval_child->sa.st_serialno, larval_child->sa.st_clonedfrom);
		/* XXX: release what? */
		return STF_INTERNAL_ERROR;
	}

	unpack_nonce(&larval_child->sa.st_nr, nonce);
	if (local_secret != NULL) {
		unpack_KE_from_helper(&larval_child->sa, local_secret, &larval_child->sa.st_gr);
		/* initiate calculation of g^xy */
		submit_dh_shared_secret(&larval_child->sa, larval_child->sa.st_gi,
					process_v2_CREATE_CHILD_SA_request_continue_continue,
					HERE);
		return STF_SUSPEND;
	} else {
		return record_v2_CREATE_CHILD_SA(ike, larval_child, md);
	}
}

static stf_status process_v2_CREATE_CHILD_SA_request_continue_continue(struct state *larval_child_sa,
								       struct msg_digest *md)
{
	/* 'child' responding to request */
	struct child_sa *larval_child = pexpect_child_sa(larval_child_sa);
	struct ike_sa *ike = ike_sa(&larval_child->sa, HERE);
	passert(v2_msg_role(md) == MESSAGE_REQUEST); /* i.e., MD!=NULL */
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

	/* didn't loose parent? */
	if (ike == NULL) {
		pexpect_fail(larval_child->sa.st_logger, HERE,
			     "sponsoring child state #%lu has no parent state #%lu",
			     larval_child->sa.st_serialno, larval_child->sa.st_clonedfrom);
		/* XXX: release child? */
		return STF_FATAL;
	}

	if (larval_child->sa.st_dh_shared_secret == NULL) {
		log_state(RC_LOG, &larval_child->sa, "DH failed");
		record_v2N_response(larval_child->sa.st_logger, ike, md,
				    v2N_INVALID_SYNTAX, NULL,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL; /* kill family */
	}
	return record_v2_CREATE_CHILD_SA(ike, larval_child, md);
}

/*
 * initiator received a create Child SA Response (RFC 7296 1.3.1, 1.3.2)
 *
 * Note: "when rekeying, the new Child SA SHOULD NOT have different Traffic
 *        Selectors and algorithms than the old one."
 */

static dh_shared_secret_cb process_v2_CREATE_CHILD_SA_child_response_continue;

stf_status process_v2_CREATE_CHILD_SA_child_response(struct ike_sa *ike,
						     struct child_sa *larval_child,
						     struct msg_digest *md)
{
	pexpect(larval_child != NULL);

	/* Ni in */
	if (!accept_v2_nonce(larval_child->sa.st_logger, md, &larval_child->sa.st_nr, "Nr")) {
		/*
		 * Presumably not our fault.  Syntax errors in a
		 * response kill the family (and trigger no further
		 * exchange).
		 *
		 * XXX: initiator; need to initiate a fatal error
		 * notification exchange.
		 */
		return STF_FATAL;
	}

	stf_status ps = process_v2_childs_sa_payload("CREATE_CHILD_SA responder matching remote ESP/AH proposals",
						     ike, larval_child, md,
						     /*expect-accepted-proposal?*/true);
	if (ps != STF_OK) {
		/*
		 * Kill the child, but not the IKE SA.
		 *
		 * XXX: initiator; need to initiate a delete exchange.
		 */
		return STF_FAIL;
	}

	/*
	 * XXX: only for rekey child?
	 */
	if (larval_child->sa.st_pfs_group == NULL) {
		v2_notification_t n = ikev2_process_ts_and_rest(ike, larval_child, md);
		if (v2_notification_fatal(n)) {
			/*
			 * XXX: initiator; need to initiate a fatal
			 * error notification exchange.
			 */
			return STF_FATAL;
		} else if (n != v2N_NOTHING_WRONG) {
			/*
			 * XXX: initiator; need to initiate a delete
			 * exchange.
			 */
			return STF_FAIL;
		} else {
			return STF_OK;
		}
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
		       md->chain[ISAKMP_NEXT_v2KE], larval_child->sa.st_logger)) {
		/*
		 * XXX: Initiator; need to initiate a delete exchange.
		 */
		return STF_FAIL; /* XXX: STF_FATAL? */
	}
	chunk_t remote_ke = larval_child->sa.st_gr;
	submit_dh_shared_secret(&larval_child->sa, remote_ke,
				process_v2_CREATE_CHILD_SA_child_response_continue, HERE);
	return STF_SUSPEND;
}

static stf_status process_v2_CREATE_CHILD_SA_child_response_continue(struct state *larval_child_sa,
								     struct msg_digest *md)
{
	/* initiator getting back an answer */
	struct child_sa *larval_child = pexpect_child_sa(larval_child_sa);
	struct ike_sa *ike = ike_sa(&larval_child->sa, HERE);
	pexpect(v2_msg_role(md) == MESSAGE_RESPONSE); /* i.e., MD!=NULL */
	pexpect(larval_child->sa.st_sa_role == SA_INITIATOR);
	dbg("%s() for #%lu %s",
	     __func__, larval_child->sa.st_serialno, larval_child->sa.st_state->name);

	/*
	 * XXX: Should this routine be split so that each instance
	 * handles only one state transition.  If there's commonality
	 * then the per-transition functions can all call common code.
	 */
	pexpect(larval_child->sa.st_state->kind == STATE_V2_NEW_CHILD_I1 ||
		larval_child->sa.st_state->kind == STATE_V2_REKEY_CHILD_I1);

	/* and a parent? */
	if (ike == NULL) {
		pexpect_fail(larval_child->sa.st_logger, HERE,
			     "sponsoring child state #%lu has no parent state #%lu",
			     larval_child->sa.st_serialno, larval_child->sa.st_clonedfrom);
		/* XXX: release what? */
		return STF_FATAL;
	}

	if (larval_child->sa.st_dh_shared_secret == NULL) {
		/*
		 * XXX: initiator; need to initiate a delete exchange.
		 */
		return STF_FAIL;
	}

	v2_notification_t n = ikev2_process_ts_and_rest(ike, larval_child, md);
	if (v2_notification_fatal(n)) {
		/*
		 * XXX: initiator; need to initiate a fatal error
		 * notification exchange.
		 */
		return STF_FATAL;
	} else if (n != v2N_NOTHING_WRONG) {
		/*
		 * XXX: initiator; need to intiate a delete exchange.
		 */
		return STF_FAIL;
	} else {
		return STF_OK;
	}

	return STF_OK;
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
	ike->sa.st_viable_parent = false;

	; /* to be determined */
	struct child_sa *larval_ike = new_v2_child_state(c, ike, IKE_SA,
							 SA_INITIATOR,
							 STATE_V2_REKEY_IKE_I0,
							 ike->sa.st_logger->global_whackfd);
	larval_ike->sa.st_oakley = ike->sa.st_oakley;
	larval_ike->sa.st_ike_rekey_spis.initiator = ike_initiator_spi();
	larval_ike->sa.st_ike_pred = ike->sa.st_serialno;
	larval_ike->sa.st_try = 1;
	larval_ike->sa.st_policy = LEMPTY;

	free_chunk_content(&larval_ike->sa.st_ni); /* this is from the parent. */
	free_chunk_content(&larval_ike->sa.st_nr); /* this is from the parent. */

	passert(larval_ike->sa.st_connection != NULL);
	policy_buf pb;
	dbg("#%lu submitting crypto needed to rekey IKE SA #%lu policy=%s pfs=%s",
	    larval_ike->sa.st_serialno, ike->sa.st_serialno,
	    str_policy(larval_ike->sa.st_policy, &pb),
	    larval_ike->sa.st_oakley.ta_dh->common.fqn);

	submit_ke_and_nonce(&larval_ike->sa, larval_ike->sa.st_oakley.ta_dh,
			    queue_v2_CREATE_CHILD_SA_initiator,
			    "IKE REKEY Initiator KE and nonce ni");
	/* "return STF_SUSPEND" */
	return larval_ike;
}

stf_status initiate_v2_CREATE_CHILD_SA_rekey_ike_request(struct ike_sa *ike,
							 struct child_sa *larval_ike,
							 struct msg_digest *md)
{
	return record_v2_CREATE_CHILD_SA_request(ike, larval_ike, md);
}

static ke_and_nonce_cb process_v2_CREATE_CHILD_SA_rekey_ike_request_continue;

stf_status process_v2_CREATE_CHILD_SA_rekey_ike_request(struct ike_sa *ike,
							struct child_sa *larval_ike,
							struct msg_digest *md)
{
	pexpect(larval_ike != NULL); /* not yet emancipated */
	pexpect(ike != NULL);
	struct connection *c = larval_ike->sa.st_connection;

	free_chunk_content(&larval_ike->sa.st_ni); /* this is from the parent. */
	free_chunk_content(&larval_ike->sa.st_nr); /* this is from the parent. */

	/* Ni in */
	if (!accept_v2_nonce(larval_ike->sa.st_logger, md, &larval_ike->sa.st_ni, "Ni")) {
		/*
		 * Presumably not our fault.  A syntax error response
		 * implicitly kills the entire family.
		 */
		record_v2N_response(ike->sa.st_logger, ike, md,
				    v2N_INVALID_SYNTAX, NULL/*no-data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL; /* we're doomed */
	}

	/* Get the proposals ready. */
	struct ikev2_proposals *ike_proposals =
		get_v2_ike_proposals(c, "IKE SA responding to rekey", ike->sa.st_logger);

	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
	stf_status ret = ikev2_process_sa_payload("IKE Rekey responder child",
						  &sa_pd->pbs,
						  /*expect_ike*/ TRUE,
						  /*expect_spi*/ TRUE,
						  /*expect_accepted*/ FALSE,
						  LIN(POLICY_OPPORTUNISTIC, c->policy),
						  &larval_ike->sa.st_accepted_ike_proposal,
						  ike_proposals, larval_ike->sa.st_logger);
	if (ret != STF_OK) {
		pexpect(larval_ike->sa.st_sa_role == SA_RESPONDER);
		pexpect(ret > STF_FAIL);
		record_v2N_response(larval_ike->sa.st_logger, ike, md, ret - STF_FAIL, NULL,
				    ENCRYPTED_PAYLOAD);
		return STF_FAIL;
	}

	if (DBGP(DBG_BASE)) {
		DBG_log_ikev2_proposal("accepted IKE proposal",
				       larval_ike->sa.st_accepted_ike_proposal);
	}

	if (!ikev2_proposal_to_trans_attrs(larval_ike->sa.st_accepted_ike_proposal,
					   &larval_ike->sa.st_oakley, larval_ike->sa.st_logger)) {
		llog_sa(RC_LOG_SERIOUS, larval_ike,
			"IKE responder accepted an unsupported algorithm");
		return STF_FATAL;
	}

	if (!v2_accept_ke_for_proposal(ike, &larval_ike->sa, md,
				       larval_ike->sa.st_oakley.ta_dh,
				       ENCRYPTED_PAYLOAD)) {
		/* passert(reply-recorded) */
		return STF_FAIL;
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
		       md->chain[ISAKMP_NEXT_v2KE], larval_ike->sa.st_logger)) {
		record_v2N_response(ike->sa.st_logger, ike, md,
				    v2N_INVALID_SYNTAX, NULL/*no data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL; /* kill family */
	}

	submit_ke_and_nonce(&larval_ike->sa, larval_ike->sa.st_oakley.ta_dh,
			    process_v2_CREATE_CHILD_SA_rekey_ike_request_continue,
			    "IKE rekey KE response gir");
	return STF_SUSPEND;
}

static dh_shared_secret_cb process_v2_CREATE_CHILD_SA_rekey_ike_request_continue_continue;	/* type assertion */

static stf_status process_v2_CREATE_CHILD_SA_rekey_ike_request_continue(struct state *larval_ike_sa,
						   struct msg_digest *md,
						   struct dh_local_secret *local_secret,
						   chunk_t *nonce)
{
	/* responder processing request */
	struct child_sa *larval_ike = pexpect_child_sa(larval_ike_sa); /* not yet emancipated */
	struct ike_sa *ike = ike_sa(&larval_ike->sa, HERE);
	pexpect(v2_msg_role(md) == MESSAGE_REQUEST); /* i.e., MD!=NULL */
	pexpect(larval_ike->sa.st_sa_role == SA_RESPONDER);
	pexpect(larval_ike->sa.st_state->kind == STATE_V2_REKEY_IKE_R0);
	dbg("%s() for #%lu %s",
	     __func__, larval_ike->sa.st_serialno, larval_ike->sa.st_state->name);

	/* and a parent? */
	if (ike == NULL) {
		pexpect_fail(larval_ike->sa.st_logger, HERE,
			     "sponsoring child state #%lu has no parent state #%lu",
			     larval_ike->sa.st_serialno, larval_ike->sa.st_clonedfrom);
		/* XXX: release what? */
		return STF_INTERNAL_ERROR;
	}

	pexpect(local_secret != NULL);
	pexpect(md->chain[ISAKMP_NEXT_v2KE] != NULL);
	unpack_nonce(&larval_ike->sa.st_nr, nonce);
	unpack_KE_from_helper(&larval_ike->sa, local_secret, &larval_ike->sa.st_gr);

	/* initiate calculation of g^xy */
	passert(ike_spi_is_zero(&larval_ike->sa.st_ike_rekey_spis.initiator));
	passert(ike_spi_is_zero(&larval_ike->sa.st_ike_rekey_spis.responder));
	ikev2_copy_cookie_from_sa(larval_ike->sa.st_accepted_ike_proposal,
				  &larval_ike->sa.st_ike_rekey_spis.initiator);
	larval_ike->sa.st_ike_rekey_spis.responder = ike_responder_spi(&md->sender,
							    larval_ike->sa.st_logger);
	submit_dh_shared_secret(&larval_ike->sa, larval_ike->sa.st_gi/*responder needs initiator KE*/,
				process_v2_CREATE_CHILD_SA_rekey_ike_request_continue_continue,
				HERE);

	return STF_SUSPEND;
}

static stf_status process_v2_CREATE_CHILD_SA_rekey_ike_request_continue_continue(struct state *larval_ike_sa,
							    struct msg_digest *md)
{
	/* 'child' responding to request */
	struct child_sa *larval_ike = pexpect_child_sa(larval_ike_sa); /* not yet emancipated */
	struct ike_sa *ike = ike_sa(&larval_ike->sa, HERE);
	passert(v2_msg_role(md) == MESSAGE_REQUEST); /* i.e., MD!=NULL */
	passert(larval_ike->sa.st_sa_role == SA_RESPONDER);
	pexpect(larval_ike->sa.st_state->kind == STATE_V2_REKEY_IKE_R0);
	dbg("%s() for #%lu %s",
	     __func__, larval_ike->sa.st_serialno, larval_ike->sa.st_state->name);

	/* didn't loose parent? */
	if (ike == NULL) {
		pexpect_fail(larval_ike->sa.st_logger, HERE,
			     "sponsoring child state #%lu has no parent state #%lu",
			     larval_ike->sa.st_serialno, larval_ike->sa.st_clonedfrom);
		/* XXX: release child? */
		return STF_INTERNAL_ERROR;
	}

	if (larval_ike->sa.st_dh_shared_secret == NULL) {
		record_v2N_response(ike->sa.st_logger, ike, md,
				    v2N_INVALID_SYNTAX, NULL,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL; /* kill family */
	}

	calc_v2_keymat(&larval_ike->sa,
		       ike->sa.st_skey_d_nss, /* only IKE has SK_d */
		       ike->sa.st_oakley.ta_prf, /* for IKE/ESP/AH */
		       &larval_ike->sa.st_ike_rekey_spis);

	return record_v2_CREATE_CHILD_SA(ike, larval_ike, md);
}

/*
 * initiator received Rekey IKE SA (RFC 7296 1.3.3) response
 */

static dh_shared_secret_cb process_v2_CREATE_CHILD_SA_rekey_ike_response_continue;

stf_status process_v2_CREATE_CHILD_SA_rekey_ike_response(struct ike_sa *ike,
							 struct child_sa *larval_ike,
							 struct msg_digest *md)
{
	pexpect(larval_ike != NULL);
	struct state *st = &larval_ike->sa;
	pexpect(ike != NULL);
	pexpect(ike->sa.st_serialno == larval_ike->sa.st_clonedfrom); /* not yet emancipated */
	struct connection *c = st->st_connection;

	/* Ni in */
	if (!accept_v2_nonce(larval_ike->sa.st_logger, md, &larval_ike->sa.st_nr, "Nr")) {
		/*
		 * Presumably not our fault.  Syntax errors in a
		 * response kill the family and trigger no further
		 * exchange.
		 */
		return STF_FATAL; /* NEED RESTART? */
	}

	/* Get the proposals ready. */
	struct ikev2_proposals *ike_proposals =
		get_v2_ike_proposals(c, "IKE SA accept response to rekey",
				     larval_ike->sa.st_logger);

	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
	stf_status ret = ikev2_process_sa_payload("IKE initiator (accepting)",
						  &sa_pd->pbs,
						  /*expect_ike*/ TRUE,
						  /*expect_spi*/ TRUE,
						  /*expect_accepted*/ TRUE,
						  LIN(POLICY_OPPORTUNISTIC, c->policy),
						  &larval_ike->sa.st_accepted_ike_proposal,
						  ike_proposals, larval_ike->sa.st_logger);
	if (ret != STF_OK) {
		dbg("failed to accept IKE SA, REKEY, response, in process_v2_CREATE_CHILD_SA_rekey_ike_response");
		return ret; /* initiator; no response */
	}

	if (DBGP(DBG_BASE)) {
		DBG_log_ikev2_proposal("accepted IKE proposal",
				       larval_ike->sa.st_accepted_ike_proposal);
	}
	if (!ikev2_proposal_to_trans_attrs(larval_ike->sa.st_accepted_ike_proposal,
					   &larval_ike->sa.st_oakley, larval_ike->sa.st_logger)) {
		llog_sa(RC_LOG_SERIOUS, larval_ike,
			"IKE responder accepted an unsupported algorithm");
		/* free early return items */
		free_ikev2_proposal(&larval_ike->sa.st_accepted_ike_proposal);
		passert(larval_ike->sa.st_accepted_ike_proposal == NULL);
		return STF_FATAL;
	}

	 /* KE in */
	if (!unpack_KE(&larval_ike->sa.st_gr, "Gr", larval_ike->sa.st_oakley.ta_dh,
		       md->chain[ISAKMP_NEXT_v2KE], larval_ike->sa.st_logger)) {
		/*
		 * XXX: Initiator so returning this notification will
		 * go no where.  Need to check RFC for what to do
		 * next.  The packet is trusted but the re-key has
		 * failed.
		 */
		return STF_FAIL + v2N_INVALID_SYNTAX;
	}

	/* fill in the missing responder SPI */
	passert(!ike_spi_is_zero(&larval_ike->sa.st_ike_rekey_spis.initiator));
	passert(ike_spi_is_zero(&larval_ike->sa.st_ike_rekey_spis.responder));
	ikev2_copy_cookie_from_sa(larval_ike->sa.st_accepted_ike_proposal,
				  &larval_ike->sa.st_ike_rekey_spis.responder);

	/* initiate calculation of g^xy for rekey */
	submit_dh_shared_secret(&larval_ike->sa, larval_ike->sa.st_gr/*initiator needs responder's KE*/,
				process_v2_CREATE_CHILD_SA_rekey_ike_response_continue,
				HERE);
	return STF_SUSPEND;
}

static stf_status process_v2_CREATE_CHILD_SA_rekey_ike_response_continue(struct state *larval_ike_sa,
					       struct msg_digest *md)
{
	struct child_sa *larval_ike = pexpect_child_sa(larval_ike_sa); /* not yet emancipated */
	struct ike_sa *ike = ike_sa(&larval_ike->sa, HERE);
	pexpect(v2_msg_role(md) == MESSAGE_RESPONSE); /* i.e., MD!=NULL */
	pexpect(larval_ike->sa.st_sa_role == SA_INITIATOR);
	pexpect(larval_ike->sa.st_state->kind == STATE_V2_REKEY_IKE_I1);
	dbg("%s() for #%lu %s",
	     __func__, larval_ike->sa.st_serialno, larval_ike->sa.st_state->name);

	/* and a parent? */
	if (ike == NULL) {
		pexpect_fail(larval_ike->sa.st_logger, HERE,
			     "sponsoring child state #%lu has no parent state #%lu",
			     larval_ike->sa.st_serialno, larval_ike->sa.st_clonedfrom);
		/* XXX: release what? */
		return STF_INTERNAL_ERROR;
	}

	if (larval_ike->sa.st_dh_shared_secret == NULL) {
		/*
		 * XXX: this is the initiator so returning a
		 * notification is kind of useless.
		 */
		return STF_FAIL + v2N_INVALID_SYNTAX;
	}

	calc_v2_keymat(&larval_ike->sa,
		       ike->sa.st_skey_d_nss, /* only IKE has SK_d */
		       ike->sa.st_oakley.ta_prf, /* for IKE/ESP/AH */
		       &larval_ike->sa.st_ike_rekey_spis/* new SPIs */);

	ikev2_rekey_expire_predecessor(larval_ike, larval_ike->sa.st_ike_pred);
	return STF_OK;
}

static stf_status record_v2_CREATE_CHILD_SA(struct ike_sa *ike, struct child_sa *child,
					    struct msg_digest *request_md)
{
	stf_status ret;

	passert(ike != NULL);
	pexpect((request_md != NULL) == (child->sa.st_sa_role == SA_RESPONDER));
	/* 3 initiator initiating states */
	pexpect((request_md == NULL) == (child->sa.st_state->kind == STATE_V2_REKEY_IKE_I0 ||
					 child->sa.st_state->kind == STATE_V2_NEW_CHILD_I0 ||
					 child->sa.st_state->kind == STATE_V2_REKEY_CHILD_I0));
	/* 3 responder replying states */
	pexpect((request_md != NULL) == (child->sa.st_state->kind == STATE_V2_REKEY_IKE_R0 ||
					 child->sa.st_state->kind == STATE_V2_NEW_CHILD_R0 ||
					 child->sa.st_state->kind == STATE_V2_REKEY_CHILD_R0));
	/* 3 initiator receiving; can't happen here */
	pexpect(child->sa.st_state->kind != STATE_V2_REKEY_IKE_I1 &&
		child->sa.st_state->kind != STATE_V2_NEW_CHILD_I1 &&
		child->sa.st_state->kind != STATE_V2_REKEY_CHILD_I1);

	ikev2_log_parentSA(&child->sa);

	struct pbs_out reply_stream = open_pbs_out("reply packet",
						   reply_buffer, sizeof(reply_buffer),
						   child->sa.st_logger);

	/* HDR out Start assembling respone message */

	pb_stream rbody = open_v2_message(&reply_stream, ike, request_md,
					  ISAKMP_v2_CREATE_CHILD_SA);

	/* insert an Encryption payload header */

	struct v2SK_payload sk = open_v2SK_payload(child->sa.st_logger, &rbody, ike);
	if (!pbs_ok(&sk.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	switch (child->sa.st_state->kind) {
	case STATE_V2_REKEY_IKE_R0:
	case STATE_V2_REKEY_IKE_I0:
		ret = emit_v2_rekey_ike_payloads(child, &sk.pbs);
		if (ret != STF_OK) {
			LSWDBGP(DBG_BASE, buf) {
				jam(buf, "emit_v2_rekey_ike_payloads() returned ");
				jam_v2_stf_status(buf, ret);
			}
			return ret; /* abort building the response message */
		}
		break;
	case STATE_V2_NEW_CHILD_I0:
	case STATE_V2_REKEY_CHILD_I0:
		ret = emit_v2_child_sa_request_payloads(child, &sk.pbs);
		if (ret != STF_OK) {
			LSWDBGP(DBG_BASE, buf) {
				jam(buf, "emit_v2_child_sa_request_payloads() returned ");
				jam_v2_stf_status(buf, ret);
			}
			return ret; /* abort building the response message */
		}
		break;
	case STATE_V2_NEW_CHILD_R0:
	case STATE_V2_REKEY_CHILD_R0:
		/*
		 * XXX: this function needs an overhaul, much is dead.
		 */
		if (child->sa.st_state->kind == STATE_V2_NEW_CHILD_R0) {
			if (!pexpect(child->sa.st_ipsec_pred == SOS_NOBODY))
				return STF_INTERNAL_ERROR;
		} else if (child->sa.st_state->kind == STATE_V2_REKEY_CHILD_R0) {
			if (!pexpect(child->sa.st_ipsec_pred != SOS_NOBODY))
				return STF_INTERNAL_ERROR;
			if (!ikev2_rekey_child_copy_ts(child)) {
				/* Should "just work", not working is a screw up */
				return STF_INTERNAL_ERROR;
			}
		} else {
			return STF_INTERNAL_ERROR;
		}
		ret = emit_v2_child_sa_response_payloads(ike, child, request_md, &sk.pbs);
		if (ret != STF_OK) {
			LSWDBGP(DBG_BASE, buf) {
				jam(buf, "emit_v2_child_sa_response_payloads() returned ");
				jam_v2_stf_status(buf, ret);
			}
			return ret; /* abort building the response message */
		}

		/*
		 * Check to see if we need to release an old instance
		 * Note that this will call delete on the old
		 * connection we should do this after installing
		 * ipsec_sa, but that will give us a "eroute in use"
		 * error.
		 */
		ike->sa.st_connection->newest_ike_sa = ike->sa.st_serialno;

		/* install inbound and outbound SPI info */
		if (!install_ipsec_sa(&child->sa, true)) {
			return STF_FATAL;
		}

		/* mark the connection as now having an IPsec SA associated with it. */
		set_newest_ipsec_sa(enum_name(&ikev2_exchange_names,
					      request_md->hdr.isa_xchg),
				    &child->sa);

		break;
	case STATE_V2_REKEY_IKE_I1:
	case STATE_V2_NEW_CHILD_I1:
	case STATE_V2_REKEY_CHILD_I1:
		return STF_INTERNAL_ERROR;
	default:
		bad_case(child->sa.st_state->kind);
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
	record_v2_message(ike, &reply_stream,
			  "packet from ikev2_child_out_cont",
			  request_md != NULL ? MESSAGE_RESPONSE : MESSAGE_REQUEST);

	if (child->sa.st_state->kind == STATE_V2_NEW_CHILD_R0 ||
	    child->sa.st_state->kind == STATE_V2_REKEY_CHILD_R0) {
		log_ipsec_sa_established("negotiated new IPsec SA", &child->sa);
	}

	return STF_OK;
}

stf_status process_v2_CREATE_CHILD_SA_failure_response(struct ike_sa *ike,
                                                struct child_sa *child,
                                                struct msg_digest *md UNUSED)
{
	passert(ike != NULL);
	passert(child != NULL);
        pstat_sa_failed(&child->sa, REASON_TRAFFIC_SELECTORS_FAILED);

	for (struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N]; ntfy != NULL; ntfy = ntfy->next) {
		v2_notification_t n = ntfy->payload.v2n.isan_type;
		/* same scope */
		esb_buf esb;
		const char *name = enum_show_short(&ikev2_notify_names, n, &esb);

		if (n < v2N_ERROR_PSTATS_ROOF) {
			pstat(ikev2_recv_notifies_e, n);
			log_state(RC_LOG_SERIOUS, &ike->sa,
				"CREATE_CHILD_SA failed with error notification %s",
				name);
			// re-add child to pending queue with exponential back-off
			break;
		}
	}
	return STF_FAIL;
}

