/* IKEv2 IKE_FOLLOWUP_KE exchange, for libreswan
 *
 * Copyright (C) 2026 Daiki Ueno <dueno@redhat.com>
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

/*
 * IKE_FOLLOWUP_KE exchange as defined in RFC 9370
 *
 * This exchange provides additional key material after CREATE_CHILD_SA
 * and may be repeated multiple times for post-quantum security.
 *
 * Message flow:
 *   Initiator                         Responder
 *   -------------------------------------------------------------------
 *   HDR, SK {KEi(n), N(ADDITIONAL_KEY_EXCHANGE)(link(n))} -->
 *                          <--  HDR, SK {KEr(n), N(ADDITIONAL_KEY_EXCHANGE)(link(n+1))}
 *   HDR, SK {KEi(n+1), N(ADDITIONAL_KEY_EXCHANGE)(link(n+1))} -->
 *                          <--  HDR, SK {KEr(n+1), N(ADDITIONAL_KEY_EXCHANGE)(link(n+2))}
 */

#include "defs.h"

#include "ike_alg_ke.h"		/* for ike_alg_kem_none; */
#include "state.h"
#include "demux.h"
#include "ikev2.h"
#include "ikev2_send.h"
#include "ikev2_message.h"
#include "ikev2_notification.h"
#include "ikev2_create_child_sa.h"
#include "ikev2_ike_followup_ke.h"
#include "ikev2_ike_intermediate.h" /* for extract_v2KE_for_ke */
#include "ikev2_child.h"
#include "ikev2_parent.h"
#include "crypt_symkey.h"
#include "log.h"
#include "connections.h"
#include "ikev2_states.h"
#include "ikev2_helper.h"
#include "ikev2_ke.h"
#include "ikev2_prf.h"
#include "crypt_dh.h"
#include "crypt_kem.h"
#include "rnd.h"

static ikev2_state_transition_fn process_v2_IKE_FOLLOWUP_KE_rekey_ike_request;
static ikev2_state_transition_fn process_v2_IKE_FOLLOWUP_KE_rekey_ike_response;

static ikev2_helper_fn initiate_v2_IKE_FOLLOWUP_KE_rekey_ike_request_helper;
static ikev2_helper_fn process_v2_IKE_FOLLOWUP_KE_rekey_ike_request_helper;
static ikev2_helper_fn process_v2_IKE_FOLLOWUP_KE_rekey_ike_response_helper;

static ikev2_resume_fn initiate_v2_IKE_FOLLOWUP_KE_rekey_ike_request_continue;
static ikev2_resume_fn process_v2_IKE_FOLLOWUP_KE_rekey_ike_request_continue;
static ikev2_resume_fn process_v2_IKE_FOLLOWUP_KE_rekey_ike_response_continue;

static ikev2_cleanup_fn cleanup_IKE_FOLLOWUP_KE_task;

struct ikev2_task {
	struct ikev2_ike_followup_ke_exchange exchange;
	/* for ADDKE */
	struct kem_initiator *initiator;
	struct kem_responder *responder;
	/* is this the last exchange? */
	bool is_last;
	/* for SKEYSEED */
	PK11SymKey *d;
	PK11SymKey *dh_shared_secret; /* SK(0) */
	struct addke_secrets keys;
	chunk_t ni;
	chunk_t nr;
	/* for KEYMAT */
	ike_spis_t ike_spis;
	size_t nr_keymat_bytes;
	PK11SymKey *keymat;
	const struct prf_desc *prf;
};

void cleanup_IKE_FOLLOWUP_KE_task(struct ikev2_task **task, struct logger *logger)
{
	pfree_kem_initiator(&(*task)->initiator, logger);
	pfree_kem_responder(&(*task)->responder, logger);
	free_chunk_content(&(*task)->ni);
	free_chunk_content(&(*task)->nr);
	symkey_delref(logger, "d", &(*task)->d);
	symkey_delref(logger, "sk(0)", &(*task)->dh_shared_secret);
	FOR_EACH_ITEM(key, &(*task)->keys) {
		symkey_delref(logger, "sk", key);
	}
	symkey_delref(logger, "skeyseed", &(*task)->keymat);
	pfreeany(*task);
}

bool next_is_ikev2_ike_followup_ke_exchange(struct state *st)
{
	unsigned next_exchange = st->st_v2_ike_followup_ke.next_exchange;
	unsigned nr_exchanges = st->st_oakley.ta_addke.len;
	if (nr_exchanges == 0) {
		nr_exchanges++;
	}

	return (next_exchange < nr_exchanges);
}

bool next_ikev2_ike_followup_ke_exchange(struct state *st)
{
	if (!PEXPECT(st->logger, next_is_ikev2_ike_followup_ke_exchange(st))) {
		return false;
	}

	st->st_v2_ike_followup_ke.next_exchange++;

	return true;
}

static struct ikev2_ike_followup_ke_exchange current_ikev2_ike_followup_ke_exchange(struct state *st)
{
	struct ikev2_ike_followup_ke_exchange exchange = {0};

	unsigned next_exchange = st->st_v2_ike_followup_ke.next_exchange;
	if (PBAD(st->logger, next_exchange == 0)) {
		return exchange;
	}

	unsigned current_exchange = next_exchange - 1;
	if (current_exchange < st->st_oakley.ta_addke.len) {
		exchange.kem = st->st_oakley.ta_addke.list[current_exchange].kem;
		/* NONE is allowed, not NULL?!? */
		PASSERT(st->logger, exchange.kem != NULL);
	}

	ldbg(st->logger, "IKE_FOLLOWUP_KE index %d len %d; %s",
	     current_exchange, st->st_oakley.ta_addke.len,
	     (exchange.kem == NULL ? "no" : exchange.kem->common.fqn));

	return exchange;
}

static bool find_v2N_ADDITIONAL_KEY_EXCHANGE_link(struct msg_digest *md,
						  struct addke_link *link,
						  struct logger *logger)
{
	const struct payload_digest *additional_key_exchange_payls =
		md->pd[PD_v2N_ADDITIONAL_KEY_EXCHANGE];

	if (additional_key_exchange_payls == NULL) {
		llog(RC_LOG, logger, "missing ADDITIONAL_KEY_EXCHANGE notification");
		return false;
	}

	struct pbs_in pbs = additional_key_exchange_payls->pbs;
	diag_t d = pbs_in_thing(&pbs, link->bytes, "followup ke link");
	if (d != NULL) {
		llog(RC_LOG, logger, "%s", str_diag(d));
		return false;
	}

	return true;
}

bool extract_ikev2_followup_ke_link(struct state *st,
				    struct msg_digest *md,
				    struct logger *logger)
{
	struct addke_link link;
	if (!find_v2N_ADDITIONAL_KEY_EXCHANGE_link(md, &link, logger)) {
		return false;
	}
	memcpy(&st->st_v2_ike_followup_ke.link.bytes,
	       link.bytes, sizeof(link.bytes));
	return true;
}

static bool validate_ikev2_followup_ke_link(struct state *st,
					    struct msg_digest *md,
					    struct logger *logger)
{
	struct addke_link link;
	if (!find_v2N_ADDITIONAL_KEY_EXCHANGE_link(md, &link, logger)) {
		return false;
	}
	return memeq(st->st_v2_ike_followup_ke.link.bytes,
		     link.bytes, sizeof(link.bytes));
}

void generate_ikev2_followup_ke_link(struct state *st)
{
	struct addke_link *link = &st->st_v2_ike_followup_ke.link;
	get_rnd_bytes(link->bytes, sizeof(link->bytes));
}

/*
 * Initiator: initiate IKE_FOLLOWUP_KE request
 *
 * This sends the initial IKE_FOLLOWUP_KE request with KEi and
 * ADDITIONAL_KEY_EXCHANGE notification with a link received in the
 * previous CREATE_CHILD_SA exchange.
 */
static stf_status initiate_v2_IKE_FOLLOWUP_KE_rekey_ike_request(struct ike_sa *ike,
								struct child_sa *null_child,
								struct msg_digest *null_md)
{
	PEXPECT(ike->sa.logger, null_child == NULL);
	PEXPECT(ike->sa.logger, null_md == NULL);
	PEXPECT(ike->sa.logger, ike->sa.st_sa_role == SA_INITIATOR);

	ldbg(ike->sa.logger, "%s() for "PRI_SO" %s: g^{xy} calculated, sending FOLLOWUP_KE",
	     __func__, pri_so(ike->sa.st_serialno), ike->sa.st_state->name);

	struct child_sa *larval_ike = ike->sa.st_v2_ike_followup_ke.larval_sa;
	if (!pexpect(larval_ike != NULL)) {
		return STF_INTERNAL_ERROR;
	}

	/* advance to the next ike intermediate exchange */
	if (!next_ikev2_ike_followup_ke_exchange(&larval_ike->sa)) {
		return STF_INTERNAL_ERROR;
	}

	struct ikev2_task task = {
		.exchange = current_ikev2_ike_followup_ke_exchange(&larval_ike->sa),
	};

	submit_ikev2_task(ike, null_md,
			  clone_thing(task, "initiator task"),
			  initiate_v2_IKE_FOLLOWUP_KE_rekey_ike_request_helper,
			  initiate_v2_IKE_FOLLOWUP_KE_rekey_ike_request_continue,
			  cleanup_IKE_FOLLOWUP_KE_task,
			  HERE);

	return STF_SUSPEND;
}

stf_status initiate_v2_IKE_FOLLOWUP_KE_rekey_ike_request_helper(struct ikev2_task *task,
								struct msg_digest *null_md,
								struct logger *logger)
{
	PEXPECT(logger, null_md == NULL);

	if (task->exchange.kem != NULL &&
	    task->exchange.kem != &ike_alg_ke_none) {
		diag_t d = kem_initiator_key_gen(task->exchange.kem,
						 &task->initiator, logger);
		if (d != NULL) {
			llog(RC_LOG, logger, "IKE_FOLLOWUP_KE key generation failed: %s", str_diag(d));
			pfree_diag(&d);
			return STF_FATAL;
		}
		if (LDBGP(DBG_BASE, logger)) {
			shunk_t ke = kem_initiator_ke(task->initiator);
			LDBG_log(logger, "initiator ADDKE:");
			LDBG_hunk(logger, &ke);
		}
	}

	return STF_OK;
}

stf_status initiate_v2_IKE_FOLLOWUP_KE_rekey_ike_request_continue(struct ike_sa *ike,
								  struct msg_digest *null_md,
								  struct ikev2_task *task)
{
	PEXPECT(ike->sa.logger, null_md == NULL);

	struct child_sa *larval_ike = ike->sa.st_v2_ike_followup_ke.larval_sa;
	if (!pexpect(larval_ike != NULL)) {
		return STF_INTERNAL_ERROR;
	}

	struct v2_message request;
	if (!open_v2_message("followup key exchange request",
			     ike, ike->sa.logger,
			     NULL/*request*/, ISAKMP_v2_IKE_FOLLOWUP_KE,
			     reply_buffer, sizeof(reply_buffer), &request,
			     ENCRYPTED_PAYLOAD)) {
		return STF_INTERNAL_ERROR;
	}

	if (task->initiator != NULL) {
		if (!emit_v2KE(kem_initiator_ke(task->initiator),
			       task->exchange.kem,
			       request.pbs)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* echo N(ADDITIONAL_KEY_EXCHANGE) from the previous response */
	if (!emit_v2N_bytes(v2N_ADDITIONAL_KEY_EXCHANGE,
			    larval_ike->sa.st_v2_ike_followup_ke.link.bytes,
			    sizeof(larval_ike->sa.st_v2_ike_followup_ke.link.bytes),
			    request.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	if (!close_v2_message(&request)) {
		return STF_INTERNAL_ERROR;
	}

	if (!record_v2_message(&request)) {
		return STF_INTERNAL_ERROR;
	}

	/* save initiator for response processor */
	larval_ike->sa.st_kem.initiator = task->initiator;
	task->initiator = NULL;

	return STF_OK;
}

/*
 * Responder: process IKE_FOLLOWUP_KE request
 *
 * This processes an incoming IKE_FOLLOWUP_KE request and sends a
 * response. This also generates a new link and includes it in the
 * ADDITIONAL_KEY_EXCHANGE notification. If this is the final
 * IKE_FOLLOWUP_KE exchange, this will also calculates SKEYSEED from
 * all the collected SK's and expands key materials from it.
 */
stf_status process_v2_IKE_FOLLOWUP_KE_rekey_ike_request(struct ike_sa *ike,
							struct child_sa *null_child,
							struct msg_digest *md)
{
	PEXPECT(ike->sa.logger, null_child == NULL);

	struct child_sa *larval_ike = ike->sa.st_v2_ike_followup_ke.larval_sa;
	if (!pexpect(larval_ike != NULL)) {
		return STF_INTERNAL_ERROR;
	}

	if (!PEXPECT(larval_ike->sa.logger, next_ikev2_ike_followup_ke_exchange(&larval_ike->sa))) {
		return STF_INTERNAL_ERROR;
	}

	if (!validate_ikev2_followup_ke_link(&larval_ike->sa, md, larval_ike->sa.logger)) {
		shunk_t shunk = (shunk_t) {
			.ptr = larval_ike->sa.st_v2_ike_followup_ke.link.bytes,
			.len = 8,
		};
		llog(RC_LOG, larval_ike->sa.logger, "responder IKE_FOLLOWUP_KE link does not match");
		LDBG_hunk(larval_ike->sa.logger, &shunk);
		return STF_FATAL;
	}

	struct ikev2_task task = {
		.exchange = current_ikev2_ike_followup_ke_exchange(&larval_ike->sa),
	};

	if (!next_is_ikev2_ike_followup_ke_exchange(&larval_ike->sa)) {
		task.is_last = true;
		/* for SKEYSEED */
		task.ni = clone_hunk_as_chunk(&larval_ike->sa.st_ni, "Ni");
		task.nr = clone_hunk_as_chunk(&larval_ike->sa.st_nr, "Nr");
		task.d = symkey_addref(larval_ike->sa.logger, "d", ike->sa.st_skey_d_nss);
		task.dh_shared_secret = symkey_addref(larval_ike->sa.logger, "SK(0)", larval_ike->sa.st_dh_shared_secret);
		task.keys = larval_ike->sa.st_v2_ike_followup_ke.keys;
		FOR_EACH_ITEM(key, &task.keys) {
			symkey_addref(larval_ike->sa.logger, "SK(n)", *key);
		}
		task.prf = larval_ike->sa.st_oakley.ta_prf;
		/* for KEYMAT */
		task.nr_keymat_bytes = nr_ikev2_ike_keymat_bytes(&larval_ike->sa);
		task.ike_spis = larval_ike->sa.st_ike_spis;
	}

	submit_ikev2_task(ike, md,
			  clone_thing(task, "initiator task"),
			  process_v2_IKE_FOLLOWUP_KE_rekey_ike_request_helper,
			  process_v2_IKE_FOLLOWUP_KE_rekey_ike_request_continue,
			  cleanup_IKE_FOLLOWUP_KE_task,
			  HERE);

	return STF_SUSPEND;
}

stf_status process_v2_IKE_FOLLOWUP_KE_rekey_ike_request_helper(struct ikev2_task *task,
							       struct msg_digest *md,
							       struct logger *logger)
{
	if (task->exchange.kem != NULL &&
	    task->exchange.kem != &ike_alg_ke_none) {
		shunk_t initiator_ke;
		if (!extract_v2KE_for_ke(task->exchange.kem, md,
					 &initiator_ke, logger)) {
			return STF_FATAL;
		}
		if (LDBGP(DBG_BASE, logger)) {
			LDBG_log(logger, "ADDKE: responder encapsulating using initiator KE:");
			LDBG_hunk(logger, &initiator_ke);
		}

		diag_t d = kem_responder_encapsulate(task->exchange.kem,
						     initiator_ke,
						     &task->responder, logger);
		if (d != NULL) {
			llog(RC_LOG, logger, "IKE_FOLLOWUP_KE encapsulate failed: %s", str_diag(d));
			pfree_diag(&d);
			return STF_FATAL;
		}
		if (LDBGP(DBG_BASE, logger)) {
			shunk_t ke = kem_responder_ke(task->responder);
			LDBG_log(logger, "ADDKE: responder KE:");
			LDBG_hunk(logger, &ke);
		}

		if (task->is_last) {
			ldbg(logger, "ADDKE: responder calculating skeyseed using prf %s",
			     task->prf->common.fqn);

			if (!pexpect(task->keys.len < elemsof(task->keys.list))) {
				return STF_FATAL;
			}
			PK11SymKey *new_ke_secret =
				kem_responder_shared_key(task->responder);
			task->keys.list[task->keys.len++] =
				symkey_addref(logger, "new_ke_secret", new_ke_secret);

			PK11SymKey *skeyseed =
				ikev2_IKE_FOLLOWUP_KE_skeyseed(task->prf,
							       /*old*/task->d,
							       task->dh_shared_secret,
							       task->ni, task->nr,
							       task->keys.len,
							       task->keys.list,
							       logger);
			if (skeyseed == NULL) {
				llog(RC_LOG, logger, "responder IKE_FOLLOWUP_KE SKEYSEED failed");
				return STF_FATAL;
			}

			ldbg(logger, "ADDKE: responder calculating KEYMAT using prf %s",
			     task->prf->common.fqn);

			task->keymat = ikev2_ike_sa_keymat(task->prf, skeyseed,
							   task->ni, task->nr,
							   &task->ike_spis,
							   task->nr_keymat_bytes,
							   logger);
			symkey_delref(logger, "skeyseed", &skeyseed);
		}
	}

	return STF_OK;
}

stf_status process_v2_IKE_FOLLOWUP_KE_rekey_ike_request_continue(struct ike_sa *ike,
								 struct msg_digest *md,
								 struct ikev2_task *task)
{
	struct child_sa *larval_ike = ike->sa.st_v2_ike_followup_ke.larval_sa;
	if (!pexpect(larval_ike != NULL)) {
		return STF_INTERNAL_ERROR;
	}

	struct v2_message response;
	if (!open_v2_message("followup_ke exchange response",
			     ike, larval_ike->sa.logger,
			     md/*response*/, ISAKMP_v2_IKE_FOLLOWUP_KE,
			     reply_buffer, sizeof(reply_buffer), &response,
			     ENCRYPTED_PAYLOAD)) {
		return STF_INTERNAL_ERROR;
	}

	if (task->responder != NULL) {
		if (!emit_v2KE(kem_responder_ke(task->responder),
			       task->exchange.kem,
			       response.pbs)) {
			return STF_INTERNAL_ERROR;
		}

		generate_ikev2_followup_ke_link(&larval_ike->sa);
		if (!emit_v2N_bytes(v2N_ADDITIONAL_KEY_EXCHANGE,
				    larval_ike->sa.st_v2_ike_followup_ke.link.bytes,
				    sizeof(larval_ike->sa.st_v2_ike_followup_ke.link.bytes),
				    response.pbs)) {
			return STF_INTERNAL_ERROR;
		}
	}
 
	if (!close_v2_message(&response)) {
		return STF_INTERNAL_ERROR;
	}

	if (!record_v2_message(&response)) {
		return STF_INTERNAL_ERROR;
	}

	if (task->is_last) {
		if (!pexpect(task->keymat != NULL)) {
			return STF_FATAL;
		}

		extract_ikev2_ike_keys(&larval_ike->sa, task->keymat);

		/*
		 * Drive the larval IKE SA's state machine.
		 */
		set_larval_v2_transition(larval_ike, &state_v2_ESTABLISHED_IKE_SA, HERE);

		emancipate_larval_ike_sa(ike, larval_ike);
	} else if (task->responder != NULL) {
		struct addke_secrets *keys =
			&ike->sa.st_v2_ike_followup_ke.keys;
		PK11SymKey *new_ke_secret =
			kem_responder_shared_key(task->responder);
		if (!pexpect(keys->len < elemsof(keys->list))) {
			return STF_FATAL;
		}
		keys->list[keys->len++] =
			symkey_addref(larval_ike->sa.logger, "new_ke_secret", new_ke_secret);
	}

	return STF_OK;
}

/*
 * Initiator: process IKE_FOLLOWUP_KE response
 *
 * This processes the IKE_FOLLOWUP_KE response from the responder. If
 * this is the final IKE_FOLLOWUP_KE exchange, this will also
 * calculates SKEYSEED from all the collected SK's and expands key
 * materials from it.
 */
stf_status process_v2_IKE_FOLLOWUP_KE_rekey_ike_response(struct ike_sa *ike,
							 struct child_sa *null_child,
							 struct msg_digest *md)
{
	PEXPECT(ike->sa.logger, null_child == NULL);

	struct child_sa *larval_ike = ike->sa.st_v2_ike_followup_ke.larval_sa;
	if (!pexpect(larval_ike != NULL)) {
		return STF_INTERNAL_ERROR;
	}

	if (!extract_ikev2_followup_ke_link(&larval_ike->sa, md, larval_ike->sa.logger)) {
		return STF_FATAL;
	}

	struct ikev2_task task = {
		.exchange = current_ikev2_ike_followup_ke_exchange(&larval_ike->sa),
	};

	/* for ADDKE decapsulate() */
	task.initiator = larval_ike->sa.st_kem.initiator;
	larval_ike->sa.st_kem.initiator = NULL;

	if (!next_is_ikev2_ike_followup_ke_exchange(&larval_ike->sa)) {
		task.is_last = true;
		/* for SKEYSEED */
		task.ni = clone_hunk_as_chunk(&larval_ike->sa.st_ni, "Ni");
		task.nr = clone_hunk_as_chunk(&larval_ike->sa.st_nr, "Nr");
		task.d = symkey_addref(larval_ike->sa.logger, "d", ike->sa.st_skey_d_nss);
		task.dh_shared_secret = symkey_addref(larval_ike->sa.logger, "SK(0)", larval_ike->sa.st_dh_shared_secret);
		task.keys = larval_ike->sa.st_v2_ike_followup_ke.keys;
		FOR_EACH_ITEM(key, &task.keys) {
			symkey_addref(larval_ike->sa.logger, "SK(n)", *key);
		}
		task.prf = larval_ike->sa.st_oakley.ta_prf;
		/* for KEYMAT */
		task.nr_keymat_bytes = nr_ikev2_ike_keymat_bytes(&larval_ike->sa);
		task.ike_spis = larval_ike->sa.st_ike_spis;
	}

	submit_ikev2_task(ike, md,
			  clone_thing(task, "initiator task"),
			  process_v2_IKE_FOLLOWUP_KE_rekey_ike_response_helper,
			  process_v2_IKE_FOLLOWUP_KE_rekey_ike_response_continue,
			  cleanup_IKE_FOLLOWUP_KE_task,
			  HERE);

	return STF_SUSPEND;
}

stf_status process_v2_IKE_FOLLOWUP_KE_rekey_ike_response_helper(struct ikev2_task *task,
								struct msg_digest *md,
								struct logger *logger)
{
	if (task->initiator != NULL) {
		shunk_t responder_ke = null_shunk;
		if (!extract_v2KE_for_ke(task->exchange.kem, md,
					 &responder_ke, logger)) {
			return STF_FATAL;
		}
		if (LDBGP(DBG_BASE, logger)) {
			LDBG_log(logger, "ADDKE: decapsulating using responder KE:");
			LDBG_hunk(logger, &responder_ke);
		}
		diag_t d = kem_initiator_decapsulate(task->initiator, responder_ke, logger);
		if (d != NULL) {
			llog(RC_LOG, logger, "IKE_FOLLOWUP_KE decapsulate failed: %s", str_diag(d));
			pfree_diag(&d);
			return STF_FATAL;
		}

		if (task->is_last) {
			ldbg(logger, "ADDKE: initiator calculating skeyseed using prf %s",
			     task->prf->common.fqn);
			if (!pexpect(task->keys.len < elemsof(task->keys.list))) {
				return STF_FATAL;
			}
			PK11SymKey *new_ke_secret =
				kem_initiator_shared_key(task->initiator);
			task->keys.list[task->keys.len++] =
				symkey_addref(logger, "new_ke_secret", new_ke_secret);

			PK11SymKey *skeyseed =
				ikev2_IKE_FOLLOWUP_KE_skeyseed(task->prf,
							       /*old*/task->d,
							       task->dh_shared_secret,
							       task->ni, task->nr,
							       task->keys.len,
							       task->keys.list,
							       logger);
			if (skeyseed == NULL) {
				llog(RC_LOG, logger, "initiator IKE_FOLLOWUP_KE SKEYSEED failed");
				return STF_FATAL;
			}

			ldbg(logger, "ADDKE: initiator calculating KEYMAT using prf %s",
			     task->prf->common.fqn);
			task->keymat = ikev2_ike_sa_keymat(task->prf, skeyseed,
							   task->ni, task->nr,
							   &task->ike_spis,
							   task->nr_keymat_bytes,
							   logger);
			symkey_delref(logger, "skeyseed", &skeyseed);
		}
	}

	return STF_OK;
}

stf_status process_v2_IKE_FOLLOWUP_KE_rekey_ike_response_continue(struct ike_sa *ike,
								  struct msg_digest *md,
								  struct ikev2_task *task)
{
	struct child_sa *larval_ike = ike->sa.st_v2_ike_followup_ke.larval_sa;
	if (!pexpect(larval_ike != NULL)) {
		return STF_INTERNAL_ERROR;
	}

	if (task->is_last) {
		if (!PEXPECT(larval_ike->sa.logger, task->keymat != NULL)) {
			return STF_FATAL;
		}

		extract_ikev2_ike_keys(&larval_ike->sa, task->keymat);

		pexpect(larval_ike->sa.st_v2_rekey_pred == ike->sa.st_serialno); /*wow!*/
		ikev2_rekey_expire_predecessor(larval_ike, larval_ike->sa.st_v2_rekey_pred);

		/*
		 * Drive the larval IKE SA's state machine.
		 */
		set_larval_v2_transition(larval_ike, &state_v2_REKEY_IKE_FOLLOWUP_KE_I1, HERE);
		change_v2_state(&larval_ike->sa);

		set_larval_v2_transition(larval_ike, &state_v2_ESTABLISHED_IKE_SA, HERE);

		emancipate_larval_ike_sa(ike, larval_ike);

		return STF_OK; /* IKE */
	} else if (task->initiator != NULL) {
		struct addke_secrets *keys =
			&larval_ike->sa.st_v2_ike_followup_ke.keys;
		PK11SymKey *new_ke_secret =
			kem_initiator_shared_key(task->initiator);
		if (!pexpect(keys->len < elemsof(keys->list))) {
			return STF_FATAL;
		}
		keys->list[keys->len++] =
			symkey_addref(larval_ike->sa.logger, "new_ke_secret", new_ke_secret);
	}

	if (next_is_ikev2_ike_followup_ke_exchange(&larval_ike->sa)) {
		return next_v2_exchange(ike, md, &v2_IKE_FOLLOWUP_KE_rekey_ike_exchange, HERE);
	}

	return STF_OK;
}

static const struct v2_transition v2_IKE_FOLLOWUP_KE_rekey_ike_initiate_transition = {
	.story = "initiate IKE_FOLLOWUP_KE rekey IKE SA",
	.to = &state_v2_ESTABLISHED_IKE_SA,
	.exchange = &v2_IKE_FOLLOWUP_KE_rekey_ike_exchange,
	.processor = initiate_v2_IKE_FOLLOWUP_KE_rekey_ike_request,
	.llog_success = ldbg_success_ikev2,
	.timeout_event = EVENT_RETAIN,
};

static const struct v2_transition v2_IKE_FOLLOWUP_KE_rekey_ike_responder_transition[] = {
	{
		.story = "process IKE_FOLLOWUP_KE rekey IKE SA request",
		.to = &state_v2_ESTABLISHED_IKE_SA,
		.flags = { .release_whack = true, },
		.exchange = &v2_IKE_FOLLOWUP_KE_rekey_ike_exchange,
		.recv_role = MESSAGE_REQUEST,
		.message_payloads.required = v2P(SK),
		.encrypted_payloads.required = v2P(KE),
		.encrypted_payloads.optional = v2P(N),
		.processor = process_v2_IKE_FOLLOWUP_KE_rekey_ike_request,
		.llog_success = ldbg_success_ikev2,
		.timeout_event = EVENT_RETAIN,
	},
};

static const struct v2_transition v2_IKE_FOLLOWUP_KE_rekey_ike_response_transition[] = {
	{
		.story = "process IKE_FOLLOWUP_KE rekey IKE SA response",
		.to = &state_v2_ESTABLISHED_IKE_SA,
		.exchange = &v2_IKE_FOLLOWUP_KE_rekey_ike_exchange,
		.recv_role = MESSAGE_RESPONSE,
		.message_payloads.required = v2P(SK),
		.encrypted_payloads.required = v2P(KE),
		.encrypted_payloads.optional = v2P(N),
		.processor = process_v2_IKE_FOLLOWUP_KE_rekey_ike_response,
		.llog_success = ldbg_success_ikev2,
		.timeout_event = EVENT_RETAIN,
	},

	/* XXX: should be a transition for failure response */
};

const struct v2_exchange v2_IKE_FOLLOWUP_KE_rekey_ike_exchange = {
	.type = ISAKMP_v2_IKE_FOLLOWUP_KE,
	.name = "IKE_FOLLOWUP_KE",
	.secured = true,
	.initiate.from = { &state_v2_ESTABLISHED_IKE_SA, },
	.initiate.transition = &v2_IKE_FOLLOWUP_KE_rekey_ike_initiate_transition,
	.transitions.responder = {
		ARRAY_PTR(v2_IKE_FOLLOWUP_KE_rekey_ike_responder_transition),
	},
	.transitions.response = {
		ARRAY_PTR(v2_IKE_FOLLOWUP_KE_rekey_ike_response_transition),
	},
};
