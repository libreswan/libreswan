/*
 * IKEv2 parent SA creation routines, for Libreswan
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
 * Copyright (C) 2015-2022 Andrew Cagney
 * Copyright (C) 2017-2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2017-2018 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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

#include "defs.h"
#include "log.h"
#include "demux.h"
#include "state.h"
#include "crypt_dh.h"
#include "ikev2_send.h"
#include "ikev2.h"
#include "connections.h"
#include "secrets.h"
#include "initiated_by.h"

#include "ikev2_message.h"
#ifdef USE_PAM_AUTH
#include "pam_auth.h"
#endif
#include "pluto_x509.h"
#include "ikev2_ike_auth.h"
#include "pending.h"
#include "pluto_stats.h"
#include "cert_decode_helper.h"
#include "ikev2_child.h"
#include "ikev2_peer_id.h"
#include "crypt_symkey.h"
#include "nat_traversal.h"
#include "ikev2_auth.h"
#include "ikev2_redirect.h"
#include "ikev2_ipseckey.h"
#include "ikev2_ppk.h"
#include "ikev2_cert.h"
#include "keys.h"
#include "ike_alg_hash.h"
#include "ikev2_psk.h"
#include "ikev2_cp.h"
#include "kernel.h"			/* for install_sec_label_connection_policies() */
#include "ikev2_delete.h"		/* for submit_v2_delete_exchange() */
#include "ikev2_certreq.h"
#include "routing.h"
#include "ikev2_replace.h"
#include "revival.h"
#include "ikev2_parent.h"
#include "ikev2_states.h"
#include "ikev2_ike_session_resume.h"
#include "ikev2_notification.h"
#include "peer_id.h"
#include "ddos.h"
#include "ikev2_nat.h"

static ikev2_llog_success_fn llog_success_process_v2_IKE_AUTH_response;
static ikev2_llog_success_fn llog_success_initiate_v2_IKE_AUTH_request;

static ikev2_state_transition_fn process_v2_IKE_AUTH_request;

static stf_status process_v2_IKE_AUTH_request_tail(struct state *st,
						   struct msg_digest *md,
						   bool pam_status);

static stf_status initiate_v2_IKE_AUTH_request_signature_continue(struct ike_sa *ike,
								  struct msg_digest *md,
								  const struct hash_signature *sig);

static stf_status process_v2_IKE_AUTH_request_post_cert_decode(struct state *st,
							       struct msg_digest *md);

static stf_status process_v2_IKE_AUTH_request_ipseckey_continue(struct ike_sa *ike,
								struct msg_digest *md,
								bool err);

static stf_status process_v2_IKE_AUTH_request_id_tail(struct ike_sa *ike, struct msg_digest *md);

static stf_status process_v2_IKE_AUTH_request_skip_cert_decode(struct ike_sa *ike,
							       struct msg_digest *md);

static stf_status process_v2_IKE_AUTH_response_post_cert_child(struct ike_sa *ike,
							       struct msg_digest *md);

static v2_auth_signature_cb process_v2_IKE_AUTH_request_auth_signature_continue; /* type check */

static stf_status initiate_v2_IKE_AUTH_request(struct ike_sa *ike,
					       struct child_sa *null_child_sa,
					       struct msg_digest *null_md)
{
	pexpect(ike->sa.st_sa_role == SA_INITIATOR);
	PEXPECT(ike->sa.logger, null_md == NULL);
	PEXPECT(ike->sa.logger, null_child_sa == NULL);
	ldbg(ike->sa.logger, "%s() for "PRI_SO" %s: g^{xy} calculated, sending IKE_AUTH",
	     __func__, pri_so(ike->sa.st_serialno), ike->sa.st_state->name);

	struct connection *const pc = ike->sa.st_connection;	/* parent connection */

	/*
	 * Only RFC 8784 PPK mechanism here:
	 *
	 * If we and responder are willing to use a PPK, we need to
	 * generate NO_PPK_AUTH as well as PPK-based AUTH payload.
	 *
	 * Stash the no-ppk keys in st_skey_*_no_ppk, and then
	 * scramble the st_skey_* keys with PPK.
	 */
	if (ike->sa.st_v2_ike_ppk == PPK_IKE_AUTH) {
		const struct secret_ppk_stuff *ppk =
			get_connection_ppk_stuff(ike->sa.st_connection);

		if (ppk != NULL) {
			ldbg(ike->sa.logger, "found PPK and PPK_ID for our connection");

			pexpect(ike->sa.st_sk_d_no_ppk == NULL);
			ike->sa.st_sk_d_no_ppk = symkey_addref(ike->sa.logger, "sk_d_no_ppk",
							       ike->sa.st_skey_d_nss);

			pexpect(ike->sa.st_sk_pi_no_ppk == NULL);
			ike->sa.st_sk_pi_no_ppk = symkey_addref(ike->sa.logger, "sk_pi_no_ppk",
								ike->sa.st_skey_pi_nss);

			pexpect(ike->sa.st_sk_pr_no_ppk == NULL);
			ike->sa.st_sk_pr_no_ppk = symkey_addref(ike->sa.logger, "sk_pr_no_ppk",
								ike->sa.st_skey_pr_nss);

			ppk_recalculate(ppk->key, ike->sa.st_oakley.ta_prf,
					&ike->sa.st_skey_d_nss,
					&ike->sa.st_skey_pi_nss,
					&ike->sa.st_skey_pr_nss,
					ike->sa.logger);
			llog_sa(RC_LOG, ike,
				  "PPK AUTH calculated as initiator");
		} else {
			if (pc->config->ppk.insist) {
				llog_sa(RC_LOG, ike,
					  "connection requires PPK, but we didn't find one");
				return STF_FATAL;
			} else {
				llog_sa(RC_LOG, ike,
					  "failed to find PPK and PPK_ID, continuing without PPK");
				/*
				 * we should omit sending any PPK
				 * Identity, so we pretend we didn't
				 * see USE_PPK.
				 */
				ike->sa.st_v2_ike_ppk = PPK_DISABLED;
			}
		}
	}

	/*
	 * Construct the IDi payload and store it in state so that it
	 * can be emitted later.  Then use that to construct the
	 * "MACedIDFor[I]".
	 *
	 * Code assumes that struct ikev2_id's "IDType|RESERVED" is
	 * laid out the same as the packet.
	 */
	v2_IKE_AUTH_initiator_id_payload(ike);

	return submit_v2AUTH_generate_initiator_signature(ike, null_md,
							  initiate_v2_IKE_AUTH_request_signature_continue);
}

stf_status initiate_v2_IKE_AUTH_request_signature_continue(struct ike_sa *ike,
							   struct msg_digest *null_md,
							   const struct hash_signature *auth_sig)
{
	PEXPECT(ike->sa.logger, null_md == NULL);
	struct connection *const pc = ike->sa.st_connection;	/* parent connection */

	if (auth_sig == NULL || auth_sig->len == 0) {
		llog(RC_LOG, ike->sa.logger, "AUTH signature calculation failed");
		return STF_FATAL;
	}

	/* beginning of data going out */

	struct v2_message request;
	if (!open_v2_message("IKE_AUTH request",
			     ike, ike->sa.logger, NULL/*request*/,
			     ISAKMP_v2_IKE_AUTH,
			     reply_buffer, sizeof(reply_buffer),
			     &request, ENCRYPTED_PAYLOAD)) {
		/* already logged */
		return STF_INTERNAL_ERROR;
	}

	/* actual data */

	/* send out the IDi payload (always) */

	{
		struct pbs_out i_id_pbs;
		if (!pbs_out_struct(request.pbs, ike->sa.st_v2_id_payload.header,
				    &ikev2_id_i_desc, &i_id_pbs)) {
			return STF_INTERNAL_ERROR;
		}
		if (!pbs_out_hunk(&i_id_pbs, ike->sa.st_v2_id_payload.data, "my identity")) {
			return STF_INTERNAL_ERROR;
		}
		if (!close_pbs_out(&i_id_pbs)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* send [CERT,] payload RFC 4306 3.6, 1.2) */

	if (ike->sa.st_v2_resume_session != NULL) {
		ldbg(ike->sa.logger, "resuming, never sending CERT payload");
	} else if (ikev2_send_cert_decision(ike)) {
		stf_status certstat = emit_v2CERT(ike->sa.st_connection, request.pbs);
		if (certstat != STF_OK)
			return certstat;
	}

	/* send CERTREQ */

	if (ike->sa.st_v2_resume_session != NULL) {
		ldbg(ike->sa.logger, "resuming, never sending CERTREQ payload");
	} else if (need_v2CERTREQ_in_IKE_AUTH_request(ike)) {
		dn_buf buf;
		ldbg(ike->sa.logger, "sending [CERTREQ] of %s",
		     str_dn(ASN1(ike->sa.st_connection->remote->host.config->ca), &buf));
		emit_v2CERTREQ(ike, request.pbs);
	}

	/* you Tarzan, me Jane support */

	/* decide whether to send CERT payload */

	bool send_idr = ((pc->remote->host.id.kind != ID_NULL &&
			  pc->remote->host.id.name.len != 0) ||
			 pc->remote->host.id.kind == ID_NULL); /* me tarzan, you jane */

	if (send_idr) {
		ldbg(ike->sa.logger, "sending IDr");
		switch (pc->remote->host.id.kind) {
		case ID_DER_ASN1_DN:
		case ID_FQDN:
		case ID_USER_FQDN:
		case ID_KEY_ID:
		case ID_NULL:
		{
			shunk_t id_b;
			struct ikev2_id r_id =
				build_v2_id_payload(&pc->remote->host, &id_b,
						    "their IDr", ike->sa.logger);
			struct pbs_out r_id_pbs;
			if (!pbs_out_struct(request.pbs, r_id, &ikev2_id_r_desc, &r_id_pbs)) {
				return STF_INTERNAL_ERROR;
			}
			if (!pbs_out_hunk(&r_id_pbs, id_b, "their IDr")) {
				return STF_INTERNAL_ERROR;
			}
			if (!close_pbs_out(&r_id_pbs)) {
				return STF_INTERNAL_ERROR;
			}
			break;
		}
		default:
		{
			name_buf b;
			ldbg(ike->sa.logger, "not sending IDr payload for remote ID type %s",
			     str_enum_short(&ike_id_type_names, pc->remote->host.id.kind, &b));
			break;
		}
		}
	}

	bool ic = (pc->config->send_initial_contact && (ike->sa.st_v2_ike_pred == SOS_NOBODY));
	if (ic) {
		llog_sa(RC_LOG, ike, "sending INITIAL_CONTACT");
		if (!emit_v2N(v2N_INITIAL_CONTACT, request.pbs))
			return STF_INTERNAL_ERROR;
	} else {
		ldbg(ike->sa.logger, "not sending INITIAL_CONTACT");
	}

	/* send out the AUTH payload */

	if (!emit_local_v2AUTH(ike, auth_sig, request.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	if (ike->sa.st_connection->config->mobike) {
		if (!emit_v2N(v2N_MOBIKE_SUPPORTED, request.pbs)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* Notification payload for ticket request */
	if (ike->sa.st_connection->config->session_resumption) {
		llog(RC_LOG, ike->sa.logger, "asking for session resume ticket");
		if (!emit_v2N(v2N_TICKET_REQUEST, request.pbs)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/*
	 * Now that the AUTH payload is done(?), create and emit the
	 * child using the first pending connection (which could be
	 * the IKE SAs connection).
	 *
	 * Then emit SA2i, TSi and TSr and NOTIFY payloads related to
	 * the IPsec SA.
	 *
	 * The returned connection may have whack attached; new*()
	 * will copy it to the Child SA at which point it needs to be
	 * released.
	 */

	/* Child Connection */

	struct connection *cc = first_pending(ike); /*pending owns ref*/
	if (cc == NULL) {
		llog_sa(RC_LOG, ike, "omitting CHILD SA payloads");
	} else {
		/*
		 * XXX: The problem isn't so much that the child state is
		 * created - it provides somewhere to store all the child's
		 * state - but that things switch to the child before the IKE
		 * SA is finished.  Consequently, code is forced to switch
		 * back to the IKE SA.
		 */
		struct child_sa *child = new_v2_child_sa(cc, ike, CHILD_SA,
							 SA_INITIATOR,
							 STATE_V2_NEW_CHILD_I0);
		connection_initiated_child(ike, child, INITIATED_BY_IKE, HERE);

		/*
		 * whack has been attached to the Child SA, release
		 * from the connection.
		 */
		release_whack(cc->logger, HERE);

		ike->sa.st_v2_msgid_windows.initiator.wip_sa = child;

		if (cc != pc) {
			llog(RC_LOG, child->sa.logger,
			     "Child SA initiating pending connection using IKE SA "PRI_SO"'s IKE_AUTH exchange",
			     pri_so(ike->sa.st_serialno));
		}

		if (!prep_v2_child_for_request(child)) {
			return STF_INTERNAL_ERROR;
		}

		/*
		 * A CHILD_SA established during an AUTH exchange does
		 * not propose DH - the IKE SA's SKEYSEED is always
		 * used.
		 */
		const struct ikev2_proposals *child_proposals = cc->config->child.v2_ike_auth_proposals;
		if (!emit_v2_child_request_payloads(ike, child, child_proposals,
						    /*ike_auth_exchange*/true, request.pbs)) {
			return STF_INTERNAL_ERROR;
		}
		/* child ready to go */
		change_v2_state(&child->sa);
	}

	/*
	 * If we and responder are willing to use a PPK, we need to
	 * generate NO_PPK_AUTH as well as PPK-based AUTH payload
	 */
	if (ike->sa.st_v2_ike_ppk == PPK_IKE_AUTH) {
		const struct secret_ppk_stuff *ppk =
			get_connection_ppk_stuff(ike->sa.st_connection);
		const struct ppk_id_payload ppk_id_p =
			ppk_id_payload(PPK_ID_FIXED, HUNK_AS_SHUNK(&ppk->id),
				       ike->sa.logger);

		struct pbs_out ppks;
		if (!open_v2N_output_pbs(request.pbs, v2N_PPK_IDENTITY, &ppks)) {
			return STF_INTERNAL_ERROR;
		}
		if (!emit_unified_ppk_id(&ppk_id_p, &ppks)) {
			return STF_INTERNAL_ERROR;
		}
		close_pbs_out(&ppks);

		if (!cc->config->ppk.insist) {
			if (!ikev2_calc_no_ppk_auth(ike, &ike->sa.st_v2_id_payload.mac_no_ppk_auth,
						    &ike->sa.st_no_ppk_auth)) {
				ldbg(ike->sa.logger, "ikev2_calc_no_ppk_auth() failed dying");
				return STF_FATAL;
			}

			if (!emit_v2N_hunk(v2N_NO_PPK_AUTH,
					   ike->sa.st_no_ppk_auth, request.pbs)) {
				return STF_INTERNAL_ERROR;
			}
		}
	}

	/*
	 * The initiator:
	 *
	 * We sent normal Digital Signature authentication, but if the
	 * policy also allows AUTH_NULL, we will send a Notify with
	 * NULL_AUTH in separate chunk. This is only done on the
	 * initiator in IKE_AUTH, and not repeated in rekeys.
	 */
	if (digital_signature_in_authby(pc->local->host.config->authby) &&
	    pc->local->host.config->authby.null) {
		/* store in null_auth */
		chunk_t null_auth = NULL_HUNK;
		if (!ikev2_create_psk_auth(AUTH_NULL, ike,
					   &ike->sa.st_v2_id_payload.mac,
					   &null_auth)) {
			llog_sa(RC_LOG, ike,
				  "Failed to calculate additional NULL_AUTH");
			return STF_FATAL;
		}
		if (ike->sa.st_v2_ike_intermediate.enabled) {
			ldbg_sa(ike, "disabling IKE_INTERMEDIATE, but why?");
			ike->sa.st_v2_ike_intermediate.enabled = false;
		}
		if (!emit_v2N_hunk(v2N_NULL_AUTH, null_auth, request.pbs)) {
			free_chunk_content(&null_auth);
			return STF_INTERNAL_ERROR;
		}
		free_chunk_content(&null_auth);
	}

	if (!close_and_record_v2_message(&request)) {
		return STF_INTERNAL_ERROR;
	}

	return STF_OK;
}

/* STATE_V2_PARENT_R1: I2 --> R2
 *                  <-- HDR, SK {IDi, [CERT,] [CERTREQ,]
 *                             [IDr,] AUTH, SAi2,
 *                             TSi, TSr}
 * HDR, SK {IDr, [CERT,] AUTH,
 *      SAr2, TSi, TSr} -->
 *
 * [Parent SA established]
 */

#ifdef USE_PAM_AUTH

static pam_auth_callback_fn ikev2_pam_continue;	/* type assertion */

static stf_status ikev2_pam_continue(struct ike_sa *ike,
				     struct msg_digest *md,
				     const char *name UNUSED,
				     bool success)
{
	pexpect(ike->sa.st_sa_role == SA_RESPONDER);
	pexpect(v2_msg_role(md) == MESSAGE_REQUEST); /* i.e., MD!=NULL */
	pexpect(ike->sa.st_state == &state_v2_IKE_SA_INIT_R);
	ldbg(ike->sa.logger, "%s() for "PRI_SO" %s",
	     __func__, pri_so(ike->sa.st_serialno), ike->sa.st_state->name);

	if (!success) {
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_AUTHENTICATION_FAILED, empty_shunk/*no-data*/,
				    ENCRYPTED_PAYLOAD);
		pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
		return STF_FATAL; /* STF_ZOMBIFY */
	}

	return process_v2_IKE_AUTH_request_tail(&ike->sa, md, success);
}

#endif /* USE_PAM_AUTH */

stf_status process_v2_IKE_AUTH_request(struct ike_sa *ike,
				       struct child_sa *unused_child UNUSED,
				       struct msg_digest *md)
{

	/* for testing only */
	if (impair.send_no_ikev2_auth) {
		llog(RC_LOG, ike->sa.logger, "IMPAIR: SEND_NO_IKEV2_AUTH set - not sending IKE_AUTH packet");
		return STF_IGNORE;
	}

	if (ike->sa.st_v2_resume_session != NULL) {
		ldbg(ike->sa.logger, "resuming, skipping cert decode");
		return process_v2_IKE_AUTH_request_skip_cert_decode(ike, md);
	}

	struct payload_digest *cert_payloads = md->chain[ISAKMP_NEXT_v2CERT];
	if (cert_payloads == NULL) {
		ldbg(ike->sa.logger, "skipping cert decode; there are none");
		return process_v2_IKE_AUTH_request_skip_cert_decode(ike, md);
	}

	submit_v2_cert_decode(ike, md, cert_payloads,
			      process_v2_IKE_AUTH_request_post_cert_decode, HERE);
	return STF_SUSPEND;
}

stf_status process_v2_IKE_AUTH_request_skip_cert_decode(struct ike_sa *ike,
							struct msg_digest *md)
{
	ike->sa.st_remote_certs.processed = true;
	ike->sa.st_remote_certs.harmless = true;
	return process_v2_IKE_AUTH_request_post_cert_decode(&ike->sa, md);
}

stf_status process_v2_IKE_AUTH_request_standard_payloads(struct ike_sa *ike, struct msg_digest *md)
{
	/* going to switch to child st. before that update parent */
	if (!ike->sa.hidden_variables.st_nated_host) {
		natify_ikev2_ike_responder_endpoints(ike, md);
	}

	ikev2_nat_change_port_lookup(md, ike); /* why? */

	/*
	 * Decode any certificate requests sent by the initiator.
	 *
	 * This acts as little more than a hint to the responder that
	 * it should include it's CERT chain with its
	 * proof-of-identity.
	 *
	 * The RFCs do discuss the idea of using this to refine the
	 * connection.  Since the ID is available, why bother.
	 */
	if (ike->sa.st_v2_resume_session != NULL) {
		ldbg(ike->sa.logger, "resuming, skipping any CERTREQ payload");
	} else {
		process_v2CERTREQ_payload(ike, md);
	}

	/*
	 * Convert the proposed connections into something this
	 * responder might accept.
	 *
	 * + DIGITAL_SIGNATURE code seems a bit dodgy, should this be
	 * looking inside the auth proposal to see what is actually
	 * required?
	 *
	 * + the legacy ECDSA_SHA2* methods also seem to be a bit
	 * dodgy, shouldn't they also specify the SHA algorithm so
	 * that can be matched?
	 */

	lset_t proposed_initiator_auths;
	if (md->chain[ISAKMP_NEXT_v2AUTH] == NULL) {
		/*
		 * Can only be EAP.  Is EAPONLY right? EAP can be
		 * combined with some other method?
		 */
		proposed_initiator_auths = LELEM(AUTH_EAPONLY);
	} else if (ike->sa.st_v2_resume_session) {
		enum auth auth = resume_session_auth(ike->sa.st_v2_resume_session);
		name_buf rn, an;
		ldbg(ike->sa.logger, "resuming, ignoring v2AUTH method %s, using %s",
		     str_enum_short(&ikev2_auth_method_names,
				    md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2auth.isaa_auth_method, &an),
		     str_enum_short(&auth_names, auth, &rn));
		proposed_initiator_auths = LELEM(auth);
	} else {
		proposed_initiator_auths = proposed_v2AUTH(ike, md);
	}

	if (proposed_initiator_auths == LEMPTY) {
		/* already logged */
		pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_AUTHENTICATION_FAILED, empty_shunk/*no-data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL;
	}

	/*
	 * Decode the peer IDs ready for refining the connection.
	 *
	 * Conceivably, in a multi-homed scenario, it could also
	 * switch based on the contents of the CERTREQ.
	 */

	struct id initiator_id, responder_id;
	diag_t d = ikev2_responder_decode_v2ID_payloads(ike, md, &initiator_id, &responder_id);
	if (d != NULL) {
		llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
		pfree_diag(&d);
		pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_AUTHENTICATION_FAILED, empty_shunk/*no-data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL;
	}

	/*
	 * IKE_SESSION_RESUME 4.3.3.  IKE_AUTH Exchange:
	 *
	 *   The IDi value sent in the IKE_AUTH exchange MUST be
	 *   identical to the value included in the ticket.  A CERT
	 *   payload MUST NOT be included in this exchange, and
	 *   therefore a new IDr value cannot be negotiated (since it
	 *   would not be authenticated).  As a result, the IDr value
	 *   sent (by the gateway, and optionally by the client) in
	 *   this exchange MUST also be identical to the value
	 *   included in the ticket.
	 */

	if (ike->sa.st_v2_resume_session != NULL) {
		if (!verify_resume_session_id(ike->sa.st_v2_resume_session,
					      &initiator_id, &responder_id,
					      ike->sa.logger)) {
			/* already logged */
			pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
			record_v2N_response(ike->sa.logger, ike, md,
					    v2N_AUTHENTICATION_FAILED, empty_shunk/*no-data*/,
					    ENCRYPTED_PAYLOAD);
			return STF_FATAL;
		}
	}

	/*
	 * IS_MOST_REFINED is subtle.
	 *
	 * IS_MOST_REFINED: the state's (possibly updated) connection
	 * is known to be the best there is (best can include the
	 * current connection).
	 *
	 * !IS_MOST_REFINED: is less specific.  For IKEv1, the search
	 * didn't find a best; for IKEv2 it can additionally mean that
	 * there was no search because the initiator proposed
	 * AUTH_NULL.  AUTH_NULL never switches as it is assumed
	 * that the perfect connection was chosen during IKE_SA_INIT.
	 *
	 * Either way, !IS_MOST_REFINED leads to a same_id() and other
	 * checks.
	 *
	 * This may change ike->sa.st_connection!
	 *
	 * We might be surprised!  Which is why C is only captured
	 * _after_ this operation.
	 */
       if (!LHAS(proposed_initiator_auths, AUTH_NULL)) {
	       refine_host_connection_of_state_on_responder(ike, proposed_initiator_auths,
							    &initiator_id,
							    &responder_id);
       }

       d = update_peer_id(ike, &initiator_id, &responder_id);
       if (d != NULL) {
		pfree_diag(&d);
		pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_AUTHENTICATION_FAILED, empty_shunk/*no-data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL;
       }

	const struct connection *c = ike->sa.st_connection;

	/* If initiator has another IKE SA with IKE_AUTH request
	 * outstanding for the same permanent connection then send
	 * TEMPORARY_FAILURE instead of IKE_AUTH response for this
	 * IKE_AUTH request and terminate current IKE SA. This is to
	 * prevent potential crossing streams scenario.
	 */
	if (has_outstanding_ike_auth_request(c, ike, md)) {
		record_v2N_response(ike->sa.logger, ike, md,
                            v2N_TEMPORARY_FAILURE, empty_shunk,
                            ENCRYPTED_PAYLOAD);
		return STF_FATAL;
	}

	/*
	 * This both decodes the initiator's ID and, when necessary,
	 * switches connection based on that ID.
	 *
	 * Conceivably, in a multi-homed scenario, it could also
	 * switch based on the contents of the CERTREQ.
	 */

	bool found_ppk = false;

	/*
	 * The NOTIFY payloads we receive in the IKE_AUTH request are
	 * either related to the IKE SA, or the Child SA. Here we only
	 * process the ones related to the IKE SA.
	 */

	/* Only RFC 8784 PPK mechanism here: */
	if (ike->sa.st_v2_ike_ppk == PPK_IKE_AUTH) {
		if (md->pd[PD_v2N_PPK_IDENTITY] != NULL) {
			ldbg(ike->sa.logger, "received PPK_IDENTITY");
			struct ppk_id_payload payl;
			if (!extract_v2N_ppk_identity(&md->pd[PD_v2N_PPK_IDENTITY]->pbs, &payl, ike)) {
				ldbg(ike->sa.logger, "failed to extract PPK_ID from PPK_IDENTITY payload. Abort!");
				return STF_FATAL;
			}

			const struct secret_ppk_stuff *ppk =
				get_ppk_stuff_by_id(/*ppk_id*/HUNK_AS_SHUNK(&payl.ppk_id),
						    ike->sa.logger);
			if (ppk != NULL) {
				found_ppk = true;
			}

			if (found_ppk && c->config->ppk.allow) {
				ppk_recalculate(ppk->key, ike->sa.st_oakley.ta_prf,
						&ike->sa.st_skey_d_nss,
						&ike->sa.st_skey_pi_nss,
						&ike->sa.st_skey_pr_nss,
						ike->sa.logger);
				ike->sa.st_ppk_ike_auth_used = true;
				llog_sa(RC_LOG, ike,
					"PPK AUTH calculated as responder");
			} else {
				llog_sa(RC_LOG, ike,
					"ignored received PPK_IDENTITY - connection does not require PPK or PPKID not found");
			}
		}
		if (md->pd[PD_v2N_NO_PPK_AUTH] != NULL) {
			ldbg(ike->sa.logger, "received NO_PPK_AUTH");
			if (c->config->ppk.insist) {
				ldbg(ike->sa.logger, "Ignored NO_PPK_AUTH data - connection insists on PPK");
			} else {
				struct pbs_in pbs = md->pd[PD_v2N_NO_PPK_AUTH]->pbs;
				/* zero length doesn't matter? */
				shunk_t no_ppk_auth = pbs_in_left(&pbs);
				replace_chunk(&ike->sa.st_no_ppk_auth,
					no_ppk_auth, "NO_PPK_AUTH extract");
			}
		}
	}

	bool mobike_accepted =
		accept_v2_notification(v2N_MOBIKE_SUPPORTED, ike->sa.logger, md, c->config->mobike);

	if (mobike_accepted) {
		if (c->remote->host.config->host.type == KH_ANY) {
			ldbg_sa(ike, "enabling mobike");
			/* only allow %any connection to mobike */
			ike->sa.st_v2_mobike.enabled = true;
		} else {
			llog_sa(RC_LOG, ike,
				"not responding with v2N_MOBIKE_SUPPORTED, that end is not %%any");
		}
	}

	ike->sa.st_ike_seen_v2n_initial_contact = md->pd[PD_v2N_INITIAL_CONTACT] != NULL;

	/*
	 * Only RFC 8784 PPK mechanism here:
	 *
	 * If we found proper PPK ID and policy allows PPK, use that.
	 * Otherwise use NO_PPK_AUTH
	 */
	if (ike->sa.st_v2_ike_ppk == PPK_IKE_AUTH) {
		if (found_ppk && c->config->ppk.allow) {
			free_chunk_content(&ike->sa.st_no_ppk_auth);
		}

		if (!found_ppk && c->config->ppk.insist) {
			llog_sa(RC_LOG, ike,
				"Requested PPK_ID not found and connection requires a valid PPK");
			record_v2N_response(ike->sa.logger, ike, md,
					    v2N_AUTHENTICATION_FAILED, empty_shunk/*no data*/,
					    ENCRYPTED_PAYLOAD);
			return STF_FATAL;
		}
	}

	return STF_OK;
}

static stf_status process_v2_IKE_AUTH_request_post_cert_decode(struct state *ike_sa,
							       struct msg_digest *md)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);

	stf_status s = process_v2_IKE_AUTH_request_standard_payloads(ike, md);
	if (s != STF_OK)
		return s;

	enum ikev2_auth_method atype = md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2auth.isaa_auth_method;
	if (IS_LIBUNBOUND && id_ipseckey_allowed(ike, atype)) {
		dns_status ret = responder_fetch_idi_ipseckey(ike, md, process_v2_IKE_AUTH_request_ipseckey_continue);
		switch (ret) {
		case DNS_SUSPEND:
			return STF_SUSPEND;
		case DNS_FATAL:
			llog_sa(RC_LOG, ike, "DNS: IPSECKEY not found or usable");
			return STF_FATAL;
		case DNS_OK:
			break;
		}
	}

	return process_v2_IKE_AUTH_request_id_tail(ike, md);
}

stf_status process_v2_IKE_AUTH_request_ipseckey_continue(struct ike_sa *ike,
							 struct msg_digest *md,
							 bool err)
{
	if (err) {
		/* already logged?! */
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_AUTHENTICATION_FAILED, empty_shunk/*no-data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL;
	}
	return process_v2_IKE_AUTH_request_id_tail(ike, md);
}

stf_status process_v2_IKE_AUTH_request_id_tail(struct ike_sa *ike, struct msg_digest *md)
{
	/* calculate hash of IDi for AUTH below */
	struct crypt_mac idhash_in = v2_remote_id_hash(ike, "IDi verify hash", md);

	/* process AUTH payload */

	struct connection *c = ike->sa.st_connection;
	enum auth initiator_auth = (ike->sa.st_v2_resume_session != NULL ? AUTH_PSK :
					    c->remote->host.config->auth);
	struct authby initiator_authby = c->remote->host.config->authby;
	passert(initiator_auth != AUTH_NEVER && initiator_auth != AUTH_UNSET);
	bool remote_can_authby_null = initiator_authby.null;
	bool remote_can_authby_digsig = digital_signature_in_authby(initiator_authby);

	if (!ike->sa.st_ppk_ike_auth_used && ike->sa.st_no_ppk_auth.ptr != NULL) {
		/*
		 * we didn't recalculate keys with PPK, but we found NO_PPK_AUTH
		 * (meaning that initiator did use PPK) so we try to verify NO_PPK_AUTH.
		 */
		ldbg(ike->sa.logger, "going to try to verify NO_PPK_AUTH.");
		/*
		 * Making a dummy struct pbs_in so we could pass it to
		 * v2_check_auth.
		 */
		struct pbs_in pbs = md->chain[ISAKMP_NEXT_v2AUTH]->pbs;
		size_t len = pbs_left(&pbs);
		pexpect(len == ike->sa.st_no_ppk_auth.len);
		struct pbs_in pbs_no_ppk_auth =
			pbs_in_from_shunk(HUNK_AS_SHUNK(&ike->sa.st_no_ppk_auth),
					  "struct pbs_in for verifying NO_PPK_AUTH");
		diag_t d = verify_v2AUTH_and_log(md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2auth.isaa_auth_method,
						 ike, &idhash_in, &pbs_no_ppk_auth,
						 initiator_auth);
		if (d != NULL) {
			llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
			pfree_diag(&d);
			ldbg(ike->sa.logger, "no PPK auth failed");
			record_v2N_response(ike->sa.logger, ike, md,
					    v2N_AUTHENTICATION_FAILED, empty_shunk/*no data*/,
					    ENCRYPTED_PAYLOAD);
			pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
			return STF_FATAL;
		}
		ldbg(ike->sa.logger, "NO_PPK_AUTH verified");
	} else if (md->pd[PD_v2N_NULL_AUTH] != NULL &&
		   remote_can_authby_null && !remote_can_authby_digsig) {
		/*
		 * If received NULL_AUTH in Notify payload and we only
		 * allow NULL Authentication, proceed with verifying
		 * that payload, else verify AUTH normally.
		 */

		/*
		 * Making a dummy struct pbs_in so we could pass it to
		 * v2_check_auth()
		 */
		struct pbs_in pbs_null_auth = md->pd[PD_v2N_NULL_AUTH]->pbs;
		diag_t d = verify_v2AUTH_and_log(IKEv2_AUTH_NULL, ike, &idhash_in,
						 &pbs_null_auth, AUTH_NULL);
		if (d != NULL) {
			llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
			pfree_diag(&d);
			ldbg(ike->sa.logger, "NULL_auth from Notify Payload failed");
			record_v2N_response(ike->sa.logger, ike, md,
					    v2N_AUTHENTICATION_FAILED, empty_shunk/*no data*/,
					    ENCRYPTED_PAYLOAD);
			pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
			return STF_FATAL;
		}
		ldbg(ike->sa.logger, "NULL_AUTH verified");
	} else {
		ldbg(ike->sa.logger, "responder verifying AUTH payload");
		diag_t d = verify_v2AUTH_and_log(md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2auth.isaa_auth_method,
						 ike, &idhash_in,
						 &md->chain[ISAKMP_NEXT_v2AUTH]->pbs,
						 initiator_auth);
		if (d != NULL) {
			llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
			pfree_diag(&d);
			ldbg(ike->sa.logger, "I2 Auth Payload failed");
			record_v2N_response(ike->sa.logger, ike, md,
					    v2N_AUTHENTICATION_FAILED, empty_shunk/*no data*/,
					    ENCRYPTED_PAYLOAD);
			pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
			return STF_FATAL;
		}
	}

	/* AUTH succeeded */

#ifdef USE_PAM_AUTH
	/*
	 * The AUTH payload is verified succsfully.  Now invoke the
	 * PAM helper to authorize connection (based on name only, not
	 * password) When pam helper is done state will be woken up
	 * and continue.
	 */
	if (ike->sa.st_connection->config->ikev2_pam_authorize) {
		id_buf thatidb;
		const char *thatid = str_id(&ike->sa.st_connection->remote->host.id, &thatidb);
		llog_sa(RC_LOG, ike,
			"IKEv2: [XAUTH]PAM method requested to authorize '%s'",
			thatid);
		if (!pam_auth_fork_request(ike, md, thatid, "password",
					   "IKEv2", ikev2_pam_continue)) {
			return STF_FATAL;
		}
		return STF_SUSPEND;
	}
#endif

	return process_v2_IKE_AUTH_request_tail(&ike->sa, md, true);
}

static stf_status process_v2_IKE_AUTH_request_tail(struct state *ike_st,
							  struct msg_digest *md,
							  bool pam_status)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_st);

	if (!pam_status) {
		/*
		 * TBD: send this notification encrypted because the
		 * AUTH payload succeed
		 */
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_AUTHENTICATION_FAILED, empty_shunk/*no data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL;
	}

	/*
	 * Construct the IDr payload and store it in state so that it
	 * can be emitted later.  Then use that to construct the
	 * "MACedIDFor[R]".
	 *
	 * Code assumes that struct ikev2_id's "IDType|RESERVED" is
	 * laid out the same as the packet.
	 */
	v2_IKE_AUTH_responder_id_payload(ike);

	return submit_v2AUTH_generate_responder_signature(ike, md, process_v2_IKE_AUTH_request_auth_signature_continue);
}

bool v2_ike_sa_auth_responder_establish(struct ike_sa *ike, bool *send_redirection)
{
	struct connection *c = ike->sa.st_connection;
	*send_redirection = false;

	/*
	 * Update the parent state to make sure that it knows we have
	 * authenticated properly.
	 */
	v2_ike_sa_established(ike, HERE);

	/*
	 * Wipes any connections that were using an old version of
	 * this SA?  Is this too early or too late?
	 */
	wipe_old_connections(ike);

	if (ike->sa.st_ike_seen_v2n_initial_contact && c->established_child_sa != SOS_NOBODY) {
		/*
		 * XXX: This is for the first child only.
		 *
		 * The IKE SA should be cleaned up after all children
		 * have been replaced (or it expires).
		 *
		 * CREATE_CHILD_SA children should also be cleaned up.
		 */
		if (c->local->host.config->xauth.server &&
		    c->remote->host.config->authby.psk) {
			/*
			 * If we are a server and expect remote
			 * clients to authenticate using PSK, then all
			 * clients use the same group ID.
			 *
			 * Note that "xauth_server" also refers to
			 * IKEv2 CP
			 */
			ldbg(ike->sa.logger, "ignoring initial contact: we are a server using PSK and clients are using a group ID");
		} else if (!pluto_uniqueIDs) {
			ldbg(ike->sa.logger, "ignoring initial contact: uniqueIDs disabled");
		} else {
			struct state *old_p2 = state_by_serialno(c->established_child_sa);
			struct connection *d = old_p2 == NULL ? NULL : old_p2->st_connection;

			if (c == d && same_id(&c->remote->host.id, &d->remote->host.id)) {
				ldbg(ike->sa.logger, "initial Contact received, deleting old state "PRI_SO" from connection %s due to new IKE SA "PRI_SO,
				     pri_so(c->established_child_sa),
				     c->name, pri_so(ike->sa.st_serialno));
				on_delete(old_p2, skip_send_delete);
				event_force(EVENT_v2_DISCARD, old_p2);
			}
		}
	}

	/* send response */

	if (ike->sa.st_seen_redirect_sup &&
	    (c->config->redirect.send_always ||
	     (!c->config->redirect.send_never &&
	      require_ddos_cookies()))) {
		if (c->config->redirect.to == NULL) {
			llog_sa(RC_LOG, ike,
				"redirect-to is not specified, can't redirect requests");
		} else {
			*send_redirection = true;
			return true;
		}
	}

	return true;
}

static stf_status process_v2_IKE_AUTH_request_auth_signature_continue(struct ike_sa *ike,
								      struct msg_digest *md,
								      const struct hash_signature *auth_sig)
{
	if (auth_sig == NULL || auth_sig->len == 0) {
		llog(RC_LOG, ike->sa.logger, "AUTH signature calculation failed");
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_AUTHENTICATION_FAILED,
				    empty_shunk/*no-data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL;
	}

	struct connection *c = ike->sa.st_connection;
	bool send_redirect = false;
	if (!v2_ike_sa_auth_responder_establish(ike, &send_redirect)) {
		return STF_FATAL;
	}

	/* HDR out */

	struct v2_message response;
	if (!open_v2_message("IKE_AUTH response",
			     ike, ike->sa.logger, md/*response*/,
			     ISAKMP_v2_IKE_AUTH,
			     reply_buffer, sizeof(reply_buffer),
			     &response, ENCRYPTED_PAYLOAD)) {
		return STF_INTERNAL_ERROR;
	}

	/* decide to send CERT payload before we generate IDr */

	/* send any NOTIFY payloads */
	if (ike->sa.st_v2_mobike.enabled) {
		if (!emit_v2N(v2N_MOBIKE_SUPPORTED, response.pbs))
			return STF_INTERNAL_ERROR;
	}

	if (ike->sa.st_ppk_ike_auth_used) {
		if (!emit_v2N(v2N_PPK_IDENTITY, response.pbs))
			return STF_INTERNAL_ERROR;
	}

	/*
	 * A redirect does not tear down the IKE SA; instead that is
	 * left to the initiator:
	 *
	 * https://datatracker.ietf.org/doc/html/rfc5685#section-6
	 * 6.  Redirect during IKE_AUTH Exchange
	 *
	 * When the client receives the IKE_AUTH response with the
	 * REDIRECT payload, it SHOULD delete the IKEv2 security
	 * association with the gateway by sending an INFORMATIONAL
	 * message with a DELETE payload.
	 */
	if (send_redirect) {
		if (!emit_v2N_REDIRECT(c->config->redirect.to, response.pbs)) {
			return STF_INTERNAL_ERROR;
		}
		ike->sa.st_sent_redirect = true;	/* mark that we have sent REDIRECT in IKE_AUTH */
	}

	/*
	 * Ticket request is in IKE_AUTH, not IKE_SA_INIT, so no need
	 * to store it in the state.
	 */
	if (md->pd[PD_v2N_TICKET_REQUEST] != NULL) {
		if (c->config->session_resumption) {
			if (!emit_v2N_TICKET_LT_OPAQUE(ike, response.pbs)) {
				return STF_INTERNAL_ERROR;
			}
		} else {
			if (!emit_v2N(v2N_TICKET_NACK, response.pbs)) {
				return STF_INTERNAL_ERROR;
			}
		}
	}

	/* send out the IDr payload */
	{
		struct pbs_out r_id_pbs;
		if (!pbs_out_struct(response.pbs, ike->sa.st_v2_id_payload.header,
				    &ikev2_id_r_desc, &r_id_pbs) ||
		    !pbs_out_hunk(&r_id_pbs, ike->sa.st_v2_id_payload.data, "my identity"))
			return STF_INTERNAL_ERROR;
		close_pbs_out(&r_id_pbs);
		ldbg(ike->sa.logger, "added IDr payload to packet");
	}

	/*
	 * send CERT payload RFC 4306 3.6, 1.2:([CERT,] )
	 * upon which our received I2 CERTREQ is ignored,
	 * but ultimately should go into the CERT decision
	 */
	if (ike->sa.st_v2_resume_session != NULL) {
		ldbg(ike->sa.logger, "resuming, never sending CERT payload");
	} else if (ikev2_send_cert_decision(ike)) {
		stf_status certstat = emit_v2CERT(ike->sa.st_connection, response.pbs);
		if (certstat != STF_OK)
			return certstat;
	}

	/* now send AUTH payload */

	if (!emit_local_v2AUTH(ike, auth_sig, response.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	if (ike->sa.st_v2_ike_intermediate.enabled) {
		ldbg_sa(ike, "disabling IKE_INTERMEDIATE, but why?");
		ike->sa.st_v2_ike_intermediate.enabled = false;
	}

	/*
	 * Try to build a child.
	 *
	 * The result can be fatal, or just doesn't create the child.
	 */

	if (send_redirect) {
		ldbg(ike->sa.logger, "skipping child; redirect response");
	} else if (!process_any_v2_IKE_AUTH_request_child_payloads(ike, md, response.pbs)) {
		/* already logged; already recorded */
		return STF_FATAL;
	}

	if (!close_and_record_v2_message(&response)) {
		return STF_INTERNAL_ERROR;
	}

	return STF_OK;
}

/* STATE_V2_IKE_AUTH_I: R2 --> I3
 *                     <--  HDR, SK {IDr, [CERT,] AUTH,
 *                               [SAr2,] [TSi,] [TSr,]}
 * [Parent SA established]
 *
 * For error handling in this function, please read:
 * https://tools.ietf.org/html/rfc7296#section-2.21.2
 */

static stf_status process_v2_IKE_AUTH_response_post_cert_decode(struct state *st, struct msg_digest *md);

static stf_status process_v2_IKE_AUTH_response(struct ike_sa *ike,
					       struct child_sa *unused_child UNUSED,
					       struct msg_digest *md)
{
	/*
	 * If the initiator rejects the responders authentication it
	 * should immediately send a delete notification and wipe the SA.
	 */
	struct payload_digest *cert_payloads = md->chain[ISAKMP_NEXT_v2CERT];
	if (cert_payloads != NULL) {
		submit_v2_cert_decode(ike, md, cert_payloads,
				      process_v2_IKE_AUTH_response_post_cert_decode, HERE);
		return STF_SUSPEND;
	} else {
		ldbg(ike->sa.logger, "no certs to decode");
		ike->sa.st_remote_certs.processed = true;
		ike->sa.st_remote_certs.harmless = true;
		return process_v2_IKE_AUTH_response_post_cert_decode(&ike->sa, md);
	}
}

static stf_status process_v2_IKE_AUTH_response_post_cert_decode(struct state *ike_sa, struct msg_digest *md)
{
	passert(v2_msg_role(md) == MESSAGE_RESPONSE);
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);

	diag_t d = ikev2_initiator_decode_responder_id(ike, md);
	if (d != NULL) {
		llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
		pfree_diag(&d);
		pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
		/*
		 * We cannot send a response as we are processing
		 * IKE_AUTH reply the RFC states we pretend IKE_AUTH
		 * was okay, and then send an INFORMATIONAL DELETE IKE
		 * SA.
		 */
		return STF_OK_INITIATOR_SEND_DELETE_IKE;
	}

	struct connection *c = ike->sa.st_connection;
	enum auth responder_auth = (ike->sa.st_v2_resume_session != NULL ? AUTH_PSK :
					    c->remote->host.config->auth);

	passert(responder_auth != AUTH_NEVER && responder_auth != AUTH_UNSET);

	if (ike->sa.st_v2_ike_ppk == PPK_IKE_AUTH) {
		if (md->pd[PD_v2N_PPK_IDENTITY] != NULL) {
			if (!c->config->ppk.allow) {
				llog_sa(RC_LOG, ike, "received PPK_IDENTITY but connection does not allow PPK");
				return STF_FATAL;
			}
		} else {
			if (c->config->ppk.insist) {
				llog_sa(RC_LOG, ike,
					"failed to receive PPK confirmation and connection has ppk=insist");
				ldbg(ike->sa.logger, "should be initiating a notify that kills the state");
				pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
				return STF_FATAL;
			}
		}

		/*
		* If we sent USE_PPK and we did not receive a PPK_IDENTITY,
		* it means the responder failed to find our PPK ID, but
		* allowed the connection to continue without PPK by using our
		* NO_PPK_AUTH payload. We should revert our key material to
		* NO_PPK versions.
		*/
		if (md->pd[PD_v2N_PPK_IDENTITY] == NULL && c->config->ppk.allow) {
			/* discard the PPK based calculations */

			llog_sa(RC_LOG, ike, "peer wants to continue without PPK - switching to NO_PPK");

			symkey_delref(ike->sa.logger, "st_skey_d_nss",  &ike->sa.st_skey_d_nss);
			ike->sa.st_skey_d_nss = symkey_addref(ike->sa.logger, "used sk_d from no ppk", ike->sa.st_sk_d_no_ppk);

			symkey_delref(ike->sa.logger, "st_skey_pi_nss", &ike->sa.st_skey_pi_nss);
			ike->sa.st_skey_pi_nss = symkey_addref(ike->sa.logger, "used sk_pi from no ppk", ike->sa.st_sk_pi_no_ppk);

			symkey_delref(ike->sa.logger, "st_skey_pr_nss", &ike->sa.st_skey_pr_nss);
			ike->sa.st_skey_pr_nss = symkey_addref(ike->sa.logger, "used sk_pr from no ppk", ike->sa.st_sk_pr_no_ppk);
		}
	}

	struct crypt_mac idhash_in = v2_remote_id_hash(ike, "idhash auth R2", md);

	/* process AUTH payload */

	ldbg(ike->sa.logger, "initiator verifying AUTH payload");
	d = verify_v2AUTH_and_log(md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2auth.isaa_auth_method,
				  ike, &idhash_in,
				  &md->chain[ISAKMP_NEXT_v2AUTH]->pbs,
				  responder_auth);
	if (d != NULL) {
		llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
		pfree_diag(&d);
		pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
		/*
		 * We cannot send a response as we are processing
		 * IKE_AUTH reply the RFC states we pretend IKE_AUTH
		 * was okay, and then send an INFORMATIONAL DELETE IKE
		 * SA.
		 */
		return STF_OK_INITIATOR_SEND_DELETE_IKE;
	}

	/*
	 * AUTH succeeded
	 *
	 * Update the parent state to make sure that it knows we have
	 * authenticated properly.
	 */
	passert(ike->sa.st_v2_transition->timeout_event == EVENT_v2_REPLACE);
	passert(ike->sa.st_v2_transition->to == &state_v2_ESTABLISHED_IKE_SA);
	change_v2_state(&ike->sa);
	v2_ike_sa_established(ike, HERE);

	/*
	 * IF there's a redirect, process it and return immediately.
	 * Function gets to decide status.
	 */
	stf_status redirect_status = STF_OK;
	if (redirect_ike_auth(ike, md, &redirect_status)) {
		return redirect_status;
	}

	if (md->pd[PD_v2N_TICKET_NACK] != NULL) {
		llog(RC_LOG, ike->sa.logger, "received v2N_TICKET_NACK");
	}

	if (md->pd[PD_v2N_TICKET_ACK] != NULL) {
		llog(RC_LOG, ike->sa.logger, "received v2N_TICKET_ACK");
	}

	if (md->pd[PD_v2N_TICKET_LT_OPAQUE] != NULL) {
		if (!process_v2N_TICKET_LT_OPAQUE(ike, md->pd[PD_v2N_TICKET_LT_OPAQUE])) {
			return STF_FATAL;
		}
	}

	ike->sa.st_v2_mobike.enabled =
		accept_v2_notification(v2N_MOBIKE_SUPPORTED, ike->sa.logger, md, c->config->mobike);

	return process_v2_IKE_AUTH_response_post_cert_child(ike, md);
}

stf_status process_v2_IKE_AUTH_response_post_cert_child(struct ike_sa *ike, struct msg_digest *md)
{
	/*
	 * Figure out if the child is both expected and viable.
	 *
	 * If the Child SA is still standing (because this end
	 * rejected response) then this end needs to initiate a delete
	 * so that the peer is cleaned up.
	 *
	 * See 2.21.2.  Error Handling in IKE_AUTH
	 */

	v2_notification_t n = process_v2_IKE_AUTH_response_child_payloads(ike, md);
	if (n == v2N_NOTHING_WRONG) {
		return STF_OK;
	}

	if (v2_notification_fatal(n)) {
		/* reason already logged */
		/*
		 * There was something "really bad" about the child.
		 *
		 * Should be sending the fatal notification in a new
		 * exchange (see RFC); returning STF_FATAL just causes
		 * the IKE SA to silently self-destruct leaving the
		 * other end hanging.
		 *
		 * XXX: This will clean out any lingering child.
		 *
		 * XXX: Can't use STF_OK_INITIATOR_SEND_DELETE_IKE as
		 * that sends a clean delete and not a dirty notify.
		 */
		return STF_FATAL;
	}

	struct child_sa *larval_child = ike->sa.st_v2_msgid_windows.initiator.wip_sa; /* could be NULL */

	if (!ike->sa.st_connection->policy.up) {
		/* already logged */
		/*
		 * Since the IKE SA has no-reason to be up, delete it.
		 * This will implicitly delete the Child SA (not
		 * exactly what the RFC says, but closer to how UP is
		 * intended to work).  For instance, when the IKE SA +
		 * Child SA are initiated on-demand, this won't leave
		 * a lingering IKE SA.
		 *
		 * Any connections waiting for this IKE SA to
		 * establish (they made a really poor choice) will be
		 * given the boot forcing them to either initiate, or
		 * find another parent.
		 */

		LLOG_JAMBUF(RC_LOG, ike->sa.logger, buf) {
			if (larval_child == NULL) {
				jam_string(buf, "peer rejected Child SA ");
			} else {
				jam_string(buf, "response for Child SA ");
				jam_so(buf, larval_child->sa.st_serialno);
				jam_string(buf, " was rejected");
			}

			jam_string(buf, " (");
			jam_enum_short(buf, &v2_notification_names, n);
			jam_string(buf, ") and IKE SA does not have policy UP");
		}

		/*
		 * This will log that the IKE SA is deleted.
		 */
		return STF_OK_INITIATOR_SEND_DELETE_IKE;
	}

	if (larval_child == NULL) {
		/* already logged */
		name_buf nb;
		ldbg(ike->sa.logger, "leaving IKE SA UP; peer rejected Child SA with %s",
		     str_enum_short(&v2_notification_names, n, &nb));
		return STF_OK;
	}

	/* already logged against child */

	/*
	 * This end (the initiator) did not like something about the
	 * Child SA so need to delete it.
	 *
	 * (If the responder sent back an error notification to reject
	 * the Child SA, then the above call would have cleaned up the
	 * mess and returned v2N_NOTHING_WRONG).
	 */

	PASSERT(ike->sa.logger, larval_child != NULL);
	ike->sa.st_v2_msgid_windows.initiator.wip_sa = NULL;

	name_buf nb;
	llog(RC_LOG, ike->sa.logger,
	     "response for Child SA "PRI_SO" was rejected with %s; initiating delete of Child SA (IKE SA will remain UP)",
	     pri_so(larval_child->sa.st_serialno),
	     str_enum_short(&v2_notification_names, n, &nb));

	/*
	 * Needed to un-plug the pending queue.  Without this the next
	 * pending exchange is never started.
	 *
	 * While not obvious from the name - unpend() - the code is
	 * doing two things: removing LARVAL_CHILD's pending
	 * connection; and submitting a request to initiate the next
	 * pending connection, if any.
	 *
	 * The key thing here is that unpend() delays creating the
	 * next child until after the previous child is done.
	 * Avoiding a race for which child goes next.
	 *
	 * For IKEv2, should merge the pending queue into the Message
	 * ID queue.  Have a queue of exchanges, and a queue of things
	 * to do when there are no exchanges.
	 */
	unpend(ike, larval_child->sa.st_connection);

	/*
	 * Quickly delete this larval SA.  This will, in turn, clean
	 * up larval child.
	 */
	submit_v2_delete_exchange(ike, larval_child);

	return STF_OK;
}

/*
 * 2.21.2.  Error Handling in IKE_AUTH
 *
 *             ...  If the error occurred on the responder, the
 *   notification is returned in the protected response, and is
 *   usually the only payload in that response.  Although the IKE_AUTH
 *   messages are encrypted and integrity protected, if the peer
 *   receiving this notification has not authenticated the other end
 *   yet, that peer needs to treat the information with caution.
 *
 * Continuing to retransmit is pointless - it will get back
 * the same response.
 */

static stf_status process_v2_IKE_AUTH_failure_response(struct ike_sa *ike,
						       struct child_sa *unused_child UNUSED,
						       struct msg_digest *md)
{
	struct child_sa *child = ike->sa.st_v2_msgid_windows.initiator.wip_sa;

	/*
	 * Mark IKE SA as failing.
	 */
	pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);

	/*
	 * Try to print a meaningful log of the notification error;
	 * but do it in slightly different ways so it is possible to
	 * figure out which code path was taken.
	 */

	/*
	 * These are all IKE SA failures - try to blame IKE first.
	 */

	bool logged_something_serious = false;
	FOR_EACH_THING(pd, PD_v2N_INVALID_SYNTAX, PD_v2N_AUTHENTICATION_FAILED,
		       PD_v2N_UNSUPPORTED_CRITICAL_PAYLOAD) {
		if (md->pd[pd] != NULL) {
			v2_notification_t n = md->pd[pd]->payload.v2n.isan_type;
			pstat(ikev2_recv_notifies_e, n);
			name_buf wb;
			llog_sa(RC_LOG, ike,
				"IKE SA authentication request rejected by peer: %s",
				str_enum_short(&v2_notification_names, n, &wb));
			logged_something_serious = true;
			break;
		}
	}

	if (!logged_something_serious) {
		/*
		 * Dump as much information as possible.
		 */
		for (struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N];
		     ntfy != NULL; ntfy = ntfy->next) {
			v2_notification_t n = ntfy->payload.v2n.isan_type;
			/* same scope */
			name_buf esb;
			const char *name = str_enum_short(&v2_notification_names, n, &esb);

			if (ntfy->payload.v2n.isan_spisize != 0) {
				/* invalid-syntax, but can't do anything about it */
				llog_sa(RC_LOG, ike,
					"received an encrypted %s notification with an unexpected non-empty SPI; deleting IKE SA",
					name);
				logged_something_serious = true;
				break;
			}

			if (n >= v2N_STATUS_FLOOR) {
				/* just log */
				pstat(ikev2_recv_notifies_s, n);
				llog_sa(RC_LOG, ike,
					"IKE_AUTH response contained the status notification %s",
					name);
			} else {
				pstat(ikev2_recv_notifies_e, n);
				logged_something_serious = true;
				/*
				 * There won't be a child state
				 * transition, so log if error is
				 * child related.
				 *
				 * see RFC 7296 Section 1.2
				 */
				switch(n) {
				case v2N_NO_PROPOSAL_CHOSEN:
				case v2N_SINGLE_PAIR_REQUIRED:
				case v2N_NO_ADDITIONAL_SAS:
				case v2N_INTERNAL_ADDRESS_FAILURE:
				case v2N_FAILED_CP_REQUIRED:
				case v2N_TS_UNACCEPTABLE:
				case v2N_INVALID_SELECTORS:
					if (child == NULL) {
						llog_sa(RC_LOG, ike,
							  "IKE_AUTH response contained the CHILD SA error notification '%s' but there is no child",
							name);
					} else {
						llog_sa(RC_LOG, child,
							"IKE_AUTH response contained the error notification %s", name);
					}
					break;
				default:
					llog_sa(RC_LOG, ike,
						"IKE_AUTH response contained the error notification %s",
						name);
					break;
				}
				/* first is enough */
				break;
			}
		}
	}

	if (!logged_something_serious) {
		llog_sa(RC_LOG, ike,
			  "IKE SA authentication request rejected by peer: unrecognized response");
	}

	return STF_FATAL;
}

#define STATE_V2_IKE_AUTH_IR STATE_V2_ESTABLISHED_IKE_SA

void llog_success_initiate_v2_IKE_AUTH_request(struct ike_sa *ike,
					       const struct msg_digest *md)
{
	PEXPECT(ike->sa.logger, v2_msg_role(md) == NO_MESSAGE);
	const struct connection *c = ike->sa.st_connection;
	LLOG_JAMBUF(RC_LOG, ike->sa.logger, buf) {
		jam_string(buf, "sent IKE_AUTH request to ");
		jam_endpoint_address_protocol_port_sensitive(buf, &ike->sa.st_remote_endpoint);
		/* AUTH payload (proof-of-identity) */
		jam_string(buf, " with ");
		enum auth authby = local_v2_auth(ike);
		enum ikev2_auth_method auth_method = local_v2AUTH_method(ike, authby);
		jam_enum_human(buf, &ikev2_auth_method_names, auth_method);
		/* ID payload */
		jam_string(buf, " and ");
		jam_enum_short(buf, &ike_id_type_names, c->local->host.id.kind);
		jam_string(buf, " '");
		jam_id_bytes(buf, &c->local->host.id, jam_raw_bytes);
		jam_string(buf, "'");
		/* optional child sa */
		struct child_sa *larval = ike->sa.st_v2_msgid_windows.initiator.wip_sa;
		if (larval != NULL) {
			jam_string(buf, "; Child SA ");
			jam_so(buf, larval->sa.st_serialno);
			jam_string(buf, " ");
			jam_v2_success_child_sa_request_details(buf, larval);
		}
	}
}

/*
 * Initiate IKE_AUTH
 */

static const struct v2_transition v2_IKE_AUTH_initiate_transition = {
	.story      = "initiating IKE_AUTH",
	.to = &state_v2_IKE_AUTH_I,
	.exchange = &v2_IKE_AUTH_exchange,
	.processor  = initiate_v2_IKE_AUTH_request,
	.llog_success = llog_success_initiate_v2_IKE_AUTH_request,
	.timeout_event = EVENT_v2_RETRANSMIT,
};

static const struct v2_transition v2_IKE_AUTH_responder_transition[] = {

	{ .story      = "Responder: process IKE_AUTH request",
	  .to = &state_v2_ESTABLISHED_IKE_SA,
	  .flags = { .release_whack = true, },
	  .exchange = &v2_IKE_AUTH_exchange,
	  .recv_role  = MESSAGE_REQUEST,
	  .message_payloads.required = v2P(SK),
	  .encrypted_payloads.required = v2P(IDi) | v2P(AUTH),
	  .encrypted_payloads.optional = v2P(CERT) | v2P(CERTREQ) | v2P(IDr) | v2P(CP) | v2P(SA) | v2P(TSi) | v2P(TSr),
	  .processor  = process_v2_IKE_AUTH_request,
	  .log_transition_start = true,
	  .llog_success = ldbg_success_ikev2,
	  .timeout_event = EVENT_v2_REPLACE, },

};

void llog_success_process_v2_IKE_AUTH_response(struct ike_sa *ike,
					       const struct msg_digest *md)
{
	PEXPECT(ike->sa.logger, v2_msg_role(md) == MESSAGE_RESPONSE);
 	LLOG_JAMBUF(RC_LOG, ike->sa.logger, buf) {
		jam_string(buf, ike->sa.st_state->story);
	}
}

static const struct v2_transition v2_IKE_AUTH_response_transition[] = {

	/* STATE_V2_IKE_AUTH_I: R2 -->
	 *                     <--  HDR, SK {IDr, [CERT,] AUTH,
	 *                               SAr2, TSi, TSr}
	 * [Parent SA established]
	 */

	/*
	 * This pair of state transitions should be merged?
	 */

	{ .story      = "Initiator: process IKE_AUTH response",
	  .to = &state_v2_ESTABLISHED_IKE_SA,
	  .flags.release_whack = true,
	  .exchange = &v2_IKE_AUTH_exchange,
	  .recv_role  = MESSAGE_RESPONSE,
	  .message_payloads.required = v2P(SK),
	  .encrypted_payloads.required = v2P(IDr) | v2P(AUTH),
	  .encrypted_payloads.optional = v2P(CERT) | v2P(CP) | v2P(SA) | v2P(TSi) | v2P(TSr),
	  .processor  = process_v2_IKE_AUTH_response,
	  .log_transition_start = true,
	  .llog_success = ldbg_success_ikev2,/* logged mid transition */
	  .timeout_event = EVENT_v2_REPLACE,
	},

	{ .story      = "Initiator: processing IKE_AUTH failure response",
	  .to = &state_v2_IKE_AUTH_I,
	  .exchange = &v2_IKE_AUTH_exchange,
	  .recv_role  = MESSAGE_RESPONSE,
	  .message_payloads = { .required = v2P(SK), },
	  /* .encrypted_payloads = { .required = v2P(N), }, */
	  .processor  = process_v2_IKE_AUTH_failure_response,
	  .llog_success = llog_success_process_v2_IKE_AUTH_response,
	},

};

V2_EXCHANGE(IKE_AUTH, "",
	    CAT_OPEN_IKE_SA, CAT_ESTABLISHED_IKE_SA,
	    /*secured*/true,
	    /*llog-processing*/false,
	    &state_v2_IKE_SA_INIT_IR,
	    &state_v2_IKE_INTERMEDIATE_IR,
	    &state_v2_IKE_SESSION_RESUME_IR);
