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
#include "ikev2_cp.h"
#include "kernel.h"			/* for install_sec_label_connection_policies() */
#include "ikev2_delete.h"		/* for submit_v2_delete_exchange() */
#include "ikev2_certreq.h"
#include "routing.h"
#include "ikev2_replace.h"
#include "revival.h"

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

static v2_auth_signature_cb process_v2_IKE_AUTH_request_auth_signature_continue; /* type check */

static stf_status submit_v2_IKE_AUTH_request_signature(struct ike_sa *ike,
						       const struct v2_id_payload *id_payload,
						       const struct hash_desc *hash_algo,
						       const struct pubkey_signer *signer,
						       v2_auth_signature_cb *cb)
{
	struct crypt_mac hash_to_sign = v2_calculate_sighash(ike, &id_payload->mac, hash_algo,
							     LOCAL_PERSPECTIVE);
	if (!submit_v2_auth_signature(ike, &hash_to_sign, hash_algo, signer, cb, HERE)) {
		dbg("submit_v2_auth_signature() died, fatal");
		return STF_FATAL;
	}
	return STF_SUSPEND;
}

stf_status initiate_v2_IKE_AUTH_request(struct ike_sa *ike, struct msg_digest *md)
{
	pexpect(ike->sa.st_sa_role == SA_INITIATOR);
	pexpect(v2_msg_role(md) == MESSAGE_RESPONSE); /* i.e., MD!=NULL */
	dbg("%s() for #%lu %s: g^{xy} calculated, sending IKE_AUTH",
	    __func__, ike->sa.st_serialno, ike->sa.st_state->name);

	struct connection *const pc = ike->sa.st_connection;	/* parent connection */

	/*
	 * If we and responder are willing to use a PPK, we need to
	 * generate NO_PPK_AUTH as well as PPK-based AUTH payload.
	 *
	 * Stash the no-ppk keys in st_skey_*_no_ppk, and then
	 * scramble the st_skey_* keys with PPK.
	 */
	if (pc->config->ppk.allow && ike->sa.st_seen_ppk) {
		chunk_t *ppk_id;
		const shunk_t ppk = get_connection_ppk_initiator(ike->sa.st_connection, &ppk_id);

		if (ppk.ptr != NULL) {
			dbg("found PPK and PPK_ID for our connection");

			pexpect(ike->sa.st_sk_d_no_ppk == NULL);
			ike->sa.st_sk_d_no_ppk = reference_symkey(__func__, "sk_d_no_ppk", ike->sa.st_skey_d_nss);

			pexpect(ike->sa.st_sk_pi_no_ppk == NULL);
			ike->sa.st_sk_pi_no_ppk = reference_symkey(__func__, "sk_pi_no_ppk", ike->sa.st_skey_pi_nss);

			pexpect(ike->sa.st_sk_pr_no_ppk == NULL);
			ike->sa.st_sk_pr_no_ppk = reference_symkey(__func__, "sk_pr_no_ppk", ike->sa.st_skey_pr_nss);

			ppk_recalculate(ppk, ike->sa.st_oakley.ta_prf,
					&ike->sa.st_skey_d_nss,
					&ike->sa.st_skey_pi_nss,
					&ike->sa.st_skey_pr_nss,
					ike->sa.logger);
			llog_sa(RC_LOG, ike,
				  "PPK AUTH calculated as initiator");
		} else {
			if (pc->config->ppk.insist) {
				llog_sa(RC_LOG_SERIOUS, ike,
					  "connection requires PPK, but we didn't find one");
				return STF_FATAL;
			} else {
				llog_sa(RC_LOG, ike,
					  "failed to find PPK and PPK_ID, continuing without PPK");
				/* we should omit sending any PPK Identity, so we pretend we didn't see USE_PPK */
				ike->sa.st_seen_ppk = false;
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

	{
		shunk_t data;
		ike->sa.st_v2_id_payload.header =
			build_v2_id_payload(&pc->local->host, &data,
					    "my IDi", ike->sa.logger);
		ike->sa.st_v2_id_payload.data = clone_hunk(data, "my IDi");
	}

	ike->sa.st_v2_id_payload.mac = v2_hash_id_payload("IDi", ike,
							  "st_skey_pi_nss",
							  ike->sa.st_skey_pi_nss);
	if (ike->sa.st_seen_ppk && !pc->config->ppk.insist) {
		/* ID payload that we've build is the same */
		ike->sa.st_v2_id_payload.mac_no_ppk_auth =
			v2_hash_id_payload("IDi (no-PPK)", ike,
					   "sk_pi_no_pkk",
					   ike->sa.st_sk_pi_no_ppk);
	}

	enum keyword_auth authby = local_v2_auth(ike);
	enum ikev2_auth_method auth_method = local_v2AUTH_method(ike, authby);
	switch (auth_method) {
	case IKEv2_AUTH_RSA:
		return submit_v2_IKE_AUTH_request_signature(ike,
							    &ike->sa.st_v2_id_payload,
							    &ike_alg_hash_sha1,
							    &pubkey_signer_raw_pkcs1_1_5_rsa,
							    initiate_v2_IKE_AUTH_request_signature_continue);

	case IKEv2_AUTH_ECDSA_SHA2_256_P256:
		return submit_v2_IKE_AUTH_request_signature(ike,
							    &ike->sa.st_v2_id_payload,
							    &ike_alg_hash_sha2_256,
							    &pubkey_signer_raw_ecdsa/*_p256*/,
							    initiate_v2_IKE_AUTH_request_signature_continue);
	case IKEv2_AUTH_ECDSA_SHA2_384_P384:
		return submit_v2_IKE_AUTH_request_signature(ike,
							    &ike->sa.st_v2_id_payload,
							    &ike_alg_hash_sha2_384,
							    &pubkey_signer_raw_ecdsa/*_p384*/,
							    initiate_v2_IKE_AUTH_request_signature_continue);
	case IKEv2_AUTH_ECDSA_SHA2_512_P521:
		return submit_v2_IKE_AUTH_request_signature(ike,
							    &ike->sa.st_v2_id_payload,
							    &ike_alg_hash_sha2_512,
							    &pubkey_signer_raw_ecdsa/*_p521*/,
							    initiate_v2_IKE_AUTH_request_signature_continue);

	case IKEv2_AUTH_DIGSIG:
		/*
		 * Save the HASH and SIGNER for later - used when
		 * emitting the siguature (should the signature
		 * instead include the bonus blob?).
		 */
		ike->sa.st_v2_digsig.hash = v2_auth_negotiated_signature_hash(ike);
		if (ike->sa.st_v2_digsig.hash == NULL) {
			return STF_FATAL;
		}

		const struct pubkey_signer *signer;
		switch (authby) {
		case AUTH_RSASIG:
			/* XXX: way to force PKCS#1 1.5? */
			signer = &pubkey_signer_digsig_rsassa_pss;
			break;
		case AUTH_ECDSA:
			signer = &pubkey_signer_digsig_ecdsa;
			break;
		default:
			bad_case(authby);
		}
		enum_buf ana;
		dbg("digsig:   authby %s selects signer %s",
		    str_enum(&keyword_auth_names, authby, &ana),
		    signer->name);
		ike->sa.st_v2_digsig.signer = signer;

		return submit_v2_IKE_AUTH_request_signature(ike,
							    &ike->sa.st_v2_id_payload,
							    ike->sa.st_v2_digsig.hash,
							    ike->sa.st_v2_digsig.signer,
							    initiate_v2_IKE_AUTH_request_signature_continue);

	case IKEv2_AUTH_PSK:
	case IKEv2_AUTH_NULL:
		return initiate_v2_IKE_AUTH_request_signature_continue(ike, md, NULL/*auth_sig*/);

	default:
	{
		enum_buf eb;
		llog_sa(RC_LOG, ike,
			"authentication method %s not supported",
			str_enum(&ikev2_auth_method_names, auth_method, &eb));
		return STF_FATAL;
	}
	}
}

stf_status initiate_v2_IKE_AUTH_request_signature_continue(struct ike_sa *ike,
							   struct msg_digest *md,
							   const struct hash_signature *auth_sig)
{
	struct connection *const pc = ike->sa.st_connection;	/* parent connection */

	/*
	 * XXX:
	 *
	 * Should this code use clone_in_pbs_as_chunk() which uses
	 * pbs_room() (.roof-.start)?  The original code:
	 *
	 * 	clonetochunk(st->st_firstpacket_peer, md->message_pbs.start,
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
	if (md->hdr.isa_xchg != ISAKMP_v2_IKE_INTERMEDIATE) {
		replace_chunk(&ike->sa.st_firstpacket_peer,
			      pbs_out_all(&md->message_pbs),
			      "saved first received non-intermediate packet");
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

	/* decide whether to send CERT payload */

	bool send_cert = ikev2_send_cert_decision(ike);
	bool send_idr = ((pc->remote->host.id.kind != ID_NULL && pc->remote->host.id.name.len != 0) ||
				pc->remote->host.id.kind == ID_NULL); /* me tarzan, you jane */

	if (impair.send_no_idr) {
		llog_sa(RC_LOG, ike, "IMPAIR: omitting IDr payload");
		send_idr = false;
	}

	dbg("IDr payload will %sbe sent", send_idr ? "" : "NOT ");

	/* send out the IDi payload */

	{
		pb_stream i_id_pbs;
		if (!out_struct(&ike->sa.st_v2_id_payload.header,
				&ikev2_id_i_desc,
				request.pbs,
				&i_id_pbs) ||
		    !out_hunk(ike->sa.st_v2_id_payload.data, &i_id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;
		close_output_pbs(&i_id_pbs);
	}

	/* send [CERT,] payload RFC 4306 3.6, 1.2) */

	if (send_cert) {
		stf_status certstat = emit_v2CERT(ike->sa.st_connection, request.pbs);
		if (certstat != STF_OK)
			return certstat;
	}

	/* send CERTREQ */

	if (need_v2CERTREQ_in_IKE_AUTH_request(ike)) {
		if (DBGP(DBG_BASE)) {
			dn_buf buf;
			DBG_log("Sending [CERTREQ] of %s",
				str_dn(ASN1(ike->sa.st_connection->remote->host.config->ca), &buf));
		}
		emit_v2CERTREQ(ike, md, request.pbs);
	}

	/* you Tarzan, me Jane support */
	if (send_idr) {
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
			pb_stream r_id_pbs;
			if (!out_struct(&r_id, &ikev2_id_r_desc, request.pbs,
				&r_id_pbs) ||
			    !out_hunk(id_b, &r_id_pbs, "their IDr"))
				return STF_INTERNAL_ERROR;

			close_output_pbs(&r_id_pbs);
			break;
		}
		default:
		{
			esb_buf b;
			dbg("Not sending IDr payload for remote ID type %s",
			    enum_show(&ike_id_type_names, pc->remote->host.id.kind, &b));
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
		dbg("not sending INITIAL_CONTACT");
	}

	/* send out the AUTH payload */

	if (!emit_local_v2AUTH(ike, auth_sig, &ike->sa.st_v2_id_payload.mac, request.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	if (ike->sa.st_connection->config->mobike) {
		if (!emit_v2N(v2N_MOBIKE_SUPPORTED, request.pbs)) {
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
							 STATE_V2_IKE_AUTH_CHILD_I0);
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
		const struct ikev2_proposals *child_proposals = cc->config->child_sa.v2_ike_auth_proposals;
		if (!emit_v2_child_request_payloads(ike, child, child_proposals, request.pbs)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/*
	 * If we and responder are willing to use a PPK, we need to
	 * generate NO_PPK_AUTH as well as PPK-based AUTH payload
	 */
	if (ike->sa.st_seen_ppk) {
		chunk_t *ppk_id;
		get_connection_ppk_initiator(ike->sa.st_connection, &ppk_id);
		struct ppk_id_payload ppk_id_p = { .type = 0, };
		create_ppk_id_payload(ppk_id, &ppk_id_p);
		if (DBGP(DBG_BASE)) {
			DBG_log("ppk type: %d", (int) ppk_id_p.type);
			DBG_dump_hunk("ppk_id from payload:", ppk_id_p.ppk_id);
		}

		pb_stream ppks;
		if (!emit_v2Npl(v2N_PPK_IDENTITY, request.pbs, &ppks) ||
		    !emit_unified_ppk_id(&ppk_id_p, &ppks)) {
			return STF_INTERNAL_ERROR;
		}
		close_output_pbs(&ppks);

		if (!cc->config->ppk.insist) {
			if (!ikev2_calc_no_ppk_auth(ike, &ike->sa.st_v2_id_payload.mac_no_ppk_auth,
						    &ike->sa.st_no_ppk_auth)) {
				dbg("ikev2_calc_no_ppk_auth() failed dying");
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
	if (authby_has_digsig(pc->local->host.config->authby) &&
	    pc->local->host.config->authby.null) {
		/* store in null_auth */
		chunk_t null_auth = NULL_HUNK;
		if (!ikev2_create_psk_auth(AUTH_NULL, ike,
					   &ike->sa.st_v2_id_payload.mac,
					   &null_auth)) {
			llog_sa(RC_LOG_SERIOUS, ike,
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

static stf_status ikev2_pam_continue(struct state *ike_st,
				     struct msg_digest *md,
				     const char *name UNUSED,
				     bool success)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_st);
	pexpect(ike->sa.st_sa_role == SA_RESPONDER);
	pexpect(v2_msg_role(md) == MESSAGE_REQUEST); /* i.e., MD!=NULL */
	pexpect(ike->sa.st_state->kind == STATE_V2_PARENT_R1);
	dbg("%s() for #%lu %s",
	     __func__, ike->sa.st_serialno, ike->sa.st_state->name);

	if (!success) {
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_AUTHENTICATION_FAILED, NULL/*no-data*/,
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
		llog_sa(RC_LOG, ike,
			  "IMPAIR_SEND_NO_IKEV2_AUTH set - not sending IKE_AUTH packet");
		return STF_IGNORE;
	}

	/*
	 * This log line establishes that the packet's been decrypted
	 * and now it is being processed for real.
	 *
	 * XXX: move this into ikev2.c?
	 */
	LLOG_JAMBUF(RC_LOG, ike->sa.logger, buf) {
		jam(buf, "processing decrypted ");
		jam_msg_digest(buf, md);
	}

	struct payload_digest *cert_payloads = md->chain[ISAKMP_NEXT_v2CERT];
	if (cert_payloads != NULL) {
		submit_v2_cert_decode(ike, md, cert_payloads,
				      process_v2_IKE_AUTH_request_post_cert_decode, HERE);
		return STF_SUSPEND;
	}

	dbg("no certs to decode");
	ike->sa.st_remote_certs.processed = true;
	ike->sa.st_remote_certs.harmless = true;
	return process_v2_IKE_AUTH_request_post_cert_decode(&ike->sa, md);
}

stf_status process_v2_IKE_AUTH_request_standard_payloads(struct ike_sa *ike, struct msg_digest *md)
{
	/* going to switch to child st. before that update parent */
	if (!LHAS(ike->sa.hidden_variables.st_nat_traversal, NATED_HOST))
		update_ike_endpoints(ike, md);

	nat_traversal_change_port_lookup(md, &ike->sa); /* shouldn't this be ike? */

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
	process_v2CERTREQ_payload(ike, md);

	/*
	 * This both decodes the initiator's ID and, when necessary,
	 * switches connection based on that ID.
	 *
	 * Conceivably, in a multi-homed scenario, it could also
	 * switch based on the contents of the CERTREQ.
	 */

	diag_t d = ikev2_responder_decode_initiator_id(ike, md);
	if (d != NULL) {
		llog_diag(RC_LOG_SERIOUS, ike->sa.logger, &d, "%s", "");
		pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_AUTHENTICATION_FAILED, NULL/*no-data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL;
	}

	const struct connection *c = ike->sa.st_connection;
	bool found_ppk = false;

	/*
	 * The NOTIFY payloads we receive in the IKE_AUTH request are
	 * either related to the IKE SA, or the Child SA. Here we only
	 * process the ones related to the IKE SA.
	 */
	if (md->pd[PD_v2N_PPK_IDENTITY] != NULL) {
		dbg("received PPK_IDENTITY");
		struct ppk_id_payload payl;
		if (!extract_v2N_ppk_identity(&md->pd[PD_v2N_PPK_IDENTITY]->pbs, &payl, ike)) {
			dbg("failed to extract PPK_ID from PPK_IDENTITY payload. Abort!");
			return STF_FATAL;
		}

		const shunk_t ppk = get_connection_ppk_responder(ike->sa.st_connection,
								 &payl.ppk_id);
		free_chunk_content(&payl.ppk_id);
		if (ppk.ptr != NULL) {
			found_ppk = true;
		}

		if (found_ppk && c->config->ppk.allow) {
			ppk_recalculate(ppk, ike->sa.st_oakley.ta_prf,
					&ike->sa.st_skey_d_nss,
					&ike->sa.st_skey_pi_nss,
					&ike->sa.st_skey_pr_nss,
					ike->sa.logger);
			ike->sa.st_ppk_used = true;
			llog_sa(RC_LOG, ike,
				"PPK AUTH calculated as responder");
		} else {
			llog_sa(RC_LOG, ike,
				"ignored received PPK_IDENTITY - connection does not require PPK or PPKID not found");
		}
	}
	if (md->pd[PD_v2N_NO_PPK_AUTH] != NULL) {
		dbg("received NO_PPK_AUTH");
		if (c->config->ppk.insist) {
			dbg("Ignored NO_PPK_AUTH data - connection insists on PPK");
		} else {
			struct pbs_in pbs = md->pd[PD_v2N_NO_PPK_AUTH]->pbs;
			/* zero length doesn't matter? */
			shunk_t no_ppk_auth = pbs_in_left(&pbs);
			replace_chunk(&ike->sa.st_no_ppk_auth,
				      no_ppk_auth, "NO_PPK_AUTH extract");
		}
	}

	bool mobike_accepted =
		accept_v2_notification(ike->sa.logger, md, c->config->mobike,
				       v2N_MOBIKE_SUPPORTED);
	if (mobike_accepted) {
		if (c->remote->host.config->type == KH_ANY) {
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
	 * If we found proper PPK ID and policy allows PPK, use that.
	 * Otherwise use NO_PPK_AUTH
	 */
	if (found_ppk && c->config->ppk.allow) {
		free_chunk_content(&ike->sa.st_no_ppk_auth);
	}

	if (!found_ppk && c->config->ppk.insist) {
		llog_sa(RC_LOG_SERIOUS, ike, "Requested PPK_ID not found and connection requires a valid PPK");
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_AUTHENTICATION_FAILED, NULL/*no data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL;
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
		dns_status ret = responder_fetch_idi_ipseckey(ike, process_v2_IKE_AUTH_request_ipseckey_continue);
		switch (ret) {
		case DNS_SUSPEND:
			return STF_SUSPEND;
		case DNS_FATAL:
			llog_sa(RC_LOG_SERIOUS, ike, "DNS: IPSECKEY not found or usable");
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
				    v2N_AUTHENTICATION_FAILED, NULL/*no-data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL;
	}
	return process_v2_IKE_AUTH_request_id_tail(ike, md);
}

stf_status process_v2_IKE_AUTH_request_id_tail(struct ike_sa *ike, struct msg_digest *md)
{
	/* calculate hash of IDi for AUTH below */
	struct crypt_mac idhash_in = v2_id_hash(ike, "IDi verify hash", "IDi",
						pbs_in_all(&md->chain[ISAKMP_NEXT_v2IDi]->pbs),
						"skey_pi", ike->sa.st_skey_pi_nss);

	/* process AUTH payload */

	enum keyword_auth remote_auth = ike->sa.st_connection->remote->host.config->auth;
	struct authby remote_authby = ike->sa.st_connection->remote->host.config->authby;
	passert(remote_auth != AUTH_NEVER && remote_auth != AUTH_UNSET);
	bool remote_can_authby_null = remote_authby.null;
	bool remote_can_authby_digsig = authby_has_digsig(remote_authby);

	if (!ike->sa.st_ppk_used && ike->sa.st_no_ppk_auth.ptr != NULL) {
		/*
		 * we didn't recalculate keys with PPK, but we found NO_PPK_AUTH
		 * (meaning that initiator did use PPK) so we try to verify NO_PPK_AUTH.
		 */
		dbg("going to try to verify NO_PPK_AUTH.");
		/* making a dummy pb_stream so we could pass it to v2_check_auth */
		pb_stream pbs_no_ppk_auth;
		pb_stream pbs = md->chain[ISAKMP_NEXT_v2AUTH]->pbs;
		size_t len = pbs_left(&pbs);
		pexpect(len == ike->sa.st_no_ppk_auth.len);
		init_pbs(&pbs_no_ppk_auth, ike->sa.st_no_ppk_auth.ptr, len, "pb_stream for verifying NO_PPK_AUTH");

		diag_t d = verify_v2AUTH_and_log(md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2auth.isaa_auth_method,
						 ike, &idhash_in, &pbs_no_ppk_auth, remote_auth);
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, ike->sa.logger, &d, "%s", "");
			dbg("no PPK auth failed");
			record_v2N_response(ike->sa.logger, ike, md,
					    v2N_AUTHENTICATION_FAILED, NULL/*no data*/,
					    ENCRYPTED_PAYLOAD);
			pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
			return STF_FATAL;
		}
		dbg("NO_PPK_AUTH verified");
	} else if (md->pd[PD_v2N_NULL_AUTH] != NULL &&
		   remote_can_authby_null && !remote_can_authby_digsig) {
		/*
		 * If received NULL_AUTH in Notify payload and we only
		 * allow NULL Authentication, proceed with verifying
		 * that payload, else verify AUTH normally.
		 */

		/* making a dummy pb_stream so we could pass it to v2_check_auth */
		struct pbs_in pbs_null_auth = md->pd[PD_v2N_NULL_AUTH]->pbs;
		diag_t d = verify_v2AUTH_and_log(IKEv2_AUTH_NULL, ike, &idhash_in,
						 &pbs_null_auth, AUTH_NULL);
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, ike->sa.logger, &d, "%s", "");
			dbg("NULL_auth from Notify Payload failed");
			record_v2N_response(ike->sa.logger, ike, md,
					    v2N_AUTHENTICATION_FAILED, NULL/*no data*/,
					    ENCRYPTED_PAYLOAD);
			pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
			return STF_FATAL;
		}
		dbg("NULL_AUTH verified");
	} else {
		dbg("responder verifying AUTH payload");
		diag_t d = verify_v2AUTH_and_log(md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2auth.isaa_auth_method,
						 ike, &idhash_in, &md->chain[ISAKMP_NEXT_v2AUTH]->pbs,
						 remote_auth);
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, ike->sa.logger, &d, "%s", "");
			dbg("I2 Auth Payload failed");
			record_v2N_response(ike->sa.logger, ike, md,
					    v2N_AUTHENTICATION_FAILED, NULL/*no data*/,
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
		if (!pam_auth_fork_request(&ike->sa, thatid, "password",
					   "IKEv2", ikev2_pam_continue)) {
			return STF_FATAL;
		}
		return STF_SUSPEND;
	}
#endif

	return process_v2_IKE_AUTH_request_tail(&ike->sa, md, true);
}

static stf_status submit_v2_IKE_AUTH_response_signature(struct ike_sa *ike, struct msg_digest *md,
							const struct v2_id_payload *id_payload,
							const struct hash_desc *hash_algo,
							const struct pubkey_signer *signer,
							v2_auth_signature_cb *cb)
{
	struct crypt_mac hash_to_sign = v2_calculate_sighash(ike, &id_payload->mac, hash_algo,
							     LOCAL_PERSPECTIVE);
	if (!submit_v2_auth_signature(ike, &hash_to_sign, hash_algo, signer, cb, HERE)) {
		dbg("submit_v2_auth_signature() died, fatal");
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_AUTHENTICATION_FAILED, NULL/*no data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL;
	}
	return STF_SUSPEND;
}

stf_status generate_v2_responder_auth(struct ike_sa *ike, struct msg_digest *md, v2_auth_signature_cb auth_cb)
{
	struct connection *const c = ike->sa.st_connection;

	/*
	 * Construct the IDr payload and store it in state so that it
	 * can be emitted later.  Then use that to construct the
	 * "MACedIDFor[R]".
	 *
	 * Code assumes that struct ikev2_id's "IDType|RESERVED" is
	 * laid out the same as the packet.
	 */

	if (ike->sa.st_peer_wants_null) {
		/* make it the Null ID */
		ike->sa.st_v2_id_payload.header.isai_type = ID_NULL;
		ike->sa.st_v2_id_payload.data = empty_chunk;
	} else {
		shunk_t data;
		ike->sa.st_v2_id_payload.header =
			build_v2_id_payload(&c->local->host, &data,
					    "my IDr", ike->sa.logger);
		ike->sa.st_v2_id_payload.data = clone_hunk(data, "my IDr");
	}

	/* will be signed in auth payload */
	ike->sa.st_v2_id_payload.mac = v2_hash_id_payload("IDr", ike, "st_skey_pr_nss",
							  ike->sa.st_skey_pr_nss);

	enum keyword_auth authby = local_v2_auth(ike);
	enum ikev2_auth_method auth_method = local_v2AUTH_method(ike, authby);
	switch (auth_method) {

	case IKEv2_AUTH_RSA:
		return submit_v2_IKE_AUTH_response_signature(ike, md,
							     &ike->sa.st_v2_id_payload,
							     &ike_alg_hash_sha1,
							     &pubkey_signer_raw_pkcs1_1_5_rsa,
							     auth_cb);

	case IKEv2_AUTH_ECDSA_SHA2_256_P256:
		return submit_v2_IKE_AUTH_response_signature(ike, md,
							    &ike->sa.st_v2_id_payload,
							    &ike_alg_hash_sha2_256,
							    &pubkey_signer_raw_ecdsa/*_p256*/,
							    auth_cb);
	case IKEv2_AUTH_ECDSA_SHA2_384_P384:
		return submit_v2_IKE_AUTH_response_signature(ike, md,
							    &ike->sa.st_v2_id_payload,
							    &ike_alg_hash_sha2_384,
							    &pubkey_signer_raw_ecdsa/*_p384*/,
							    auth_cb);
	case IKEv2_AUTH_ECDSA_SHA2_512_P521:
		return submit_v2_IKE_AUTH_response_signature(ike, md,
							    &ike->sa.st_v2_id_payload,
							    &ike_alg_hash_sha2_512,
							    &pubkey_signer_raw_ecdsa/*_p521*/,
							    auth_cb);

	case IKEv2_AUTH_DIGSIG:
	{
		/*
		 * Prefer the HASH and SIGNER algorithms saved when
		 * authenticating the initiator (assuming the
		 * initiator was authenticated using DIGSIG).
		 *
		 * For HASH, both ends negotiated acceptable hash
		 * algorithms during IKE_SA_INIT.  For SIGNER, the
		 * algorithm also needs to be consistent with local
		 * AUTHBY.
		 *
		 * Save the decision so it is available when emitting
		 * the computed hash.
		 */
		dbg("digsig: selecting hash and signer");
		const char *hash_story;
		if (ike->sa.st_v2_digsig.hash == NULL) {
			ike->sa.st_v2_digsig.hash = v2_auth_negotiated_signature_hash(ike);
			hash_story = "from policy";
		} else {
			hash_story = "saved earlier";
		}
		if (ike->sa.st_v2_digsig.hash == NULL) {
			record_v2N_response(ike->sa.logger, ike, md,
					    v2N_AUTHENTICATION_FAILED, NULL/*no data*/,
					    ENCRYPTED_PAYLOAD);
			return STF_FATAL;
		}
		dbg("digsig:   using hash %s %s",
		    ike->sa.st_v2_digsig.hash->common.fqn,
		    hash_story);
		const char *signer_story;
		switch (authby) {
		case AUTH_RSASIG:
			if (ike->sa.st_v2_digsig.signer == NULL ||
			    ike->sa.st_v2_digsig.signer->type != &pubkey_type_rsa) {
				ike->sa.st_v2_digsig.signer = &pubkey_signer_digsig_rsassa_pss;
				signer_story = "from policy";
			} else {
				signer_story = "saved earlier";
			}
			break;
		case AUTH_ECDSA:
			/* no choice */
			signer_story = "hardwired";
			ike->sa.st_v2_digsig.signer = &pubkey_signer_digsig_ecdsa;
			break;
		default:
			bad_case(authby);
		}
		dbg("digsig:   using %s signer %s",
		    ike->sa.st_v2_digsig.signer->name, signer_story);

		return submit_v2_IKE_AUTH_response_signature(ike, md,
							     &ike->sa.st_v2_id_payload,
							     ike->sa.st_v2_digsig.hash,
							     ike->sa.st_v2_digsig.signer, auth_cb);
	}

	case IKEv2_AUTH_PSK:
	case IKEv2_AUTH_NULL:
		return auth_cb(ike, md, NULL/*auth_sig*/);

	default:
	{
		enum_buf eb;
		llog_sa(RC_LOG, ike,
			"authentication method %s not supported",
			str_enum(&ikev2_auth_method_names, auth_method, &eb));
		return STF_FATAL;
	}
	}
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
				    v2N_AUTHENTICATION_FAILED, NULL/*no data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL;
	}

	return generate_v2_responder_auth(ike, md, process_v2_IKE_AUTH_request_auth_signature_continue);
}

bool v2_ike_sa_auth_responder_establish(struct ike_sa *ike, bool *send_redirection)
{
	struct connection *c = ike->sa.st_connection;
	*send_redirection = false;

	/*
	 * Update the parent state to make sure that it knows we have
	 * authenticated properly.
	 */
	v2_ike_sa_established(ike);

	/*
	 * Wipes any connections that were using an old version of
	 * this SA?  Is this too early or too late?
	 */
	wipe_old_connections(ike);

	if (ike->sa.st_ike_seen_v2n_initial_contact && c->newest_ipsec_sa != SOS_NOBODY) {
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
			dbg("ignoring initial contact: we are a server using PSK and clients are using a group ID");
		} else if (!uniqueIDs) {
			dbg("ignoring initial contact: uniqueIDs disabled");
		} else {
			struct state *old_p2 = state_by_serialno(c->newest_ipsec_sa);
			struct connection *d = old_p2 == NULL ? NULL : old_p2->st_connection;

			if (c == d && same_id(&c->remote->host.id, &d->remote->host.id)) {
				dbg("Initial Contact received, deleting old state #%lu from connection '%s' due to new IKE SA #%lu",
				    c->newest_ipsec_sa, c->name, ike->sa.st_serialno);
				on_delete(old_p2, skip_send_delete);
				event_force(EVENT_v2_DISCARD, old_p2);
			}
		}
	}

	if (LHAS(ike->sa.hidden_variables.st_nat_traversal, NATED_HOST)) {
		/* ensure we run keepalives if needed */
		if (c->config->nat_keepalive) {
			/* XXX: just trigger this event? */
			nat_traversal_ka_event(ike->sa.logger);
		}
	}

	/* send response */

	if (ike->sa.st_seen_redirect_sup &&
	    (c->config->redirect.send_always ||
	     (!c->config->redirect.send_never &&
	      require_ddos_cookies()))) {
		if (c->config->redirect.to == NULL) {
			llog_sa(RC_LOG_SERIOUS, ike,
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
	bool send_cert = ikev2_send_cert_decision(ike);

	/* send any NOTIFY payloads */
	if (ike->sa.st_v2_mobike.enabled) {
		if (!emit_v2N(v2N_MOBIKE_SUPPORTED, response.pbs))
			return STF_INTERNAL_ERROR;
	}

	if (ike->sa.st_ppk_used) {
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
		if (!emit_redirect_notification(shunk1(c->config->redirect.to), response.pbs))
			return STF_INTERNAL_ERROR;
		ike->sa.st_sent_redirect = true;	/* mark that we have sent REDIRECT in IKE_AUTH */
	}

	/* send out the IDr payload */
	{
		pb_stream r_id_pbs;
		if (!out_struct(&ike->sa.st_v2_id_payload.header,
				&ikev2_id_r_desc, response.pbs, &r_id_pbs) ||
		    !out_hunk(ike->sa.st_v2_id_payload.data,
				  &r_id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;
		close_output_pbs(&r_id_pbs);
		dbg("added IDr payload to packet");
	}

	/*
	 * send CERT payload RFC 4306 3.6, 1.2:([CERT,] )
	 * upon which our received I2 CERTREQ is ignored,
	 * but ultimately should go into the CERT decision
	 */
	if (send_cert) {
		stf_status certstat = emit_v2CERT(ike->sa.st_connection, response.pbs);
		if (certstat != STF_OK)
			return certstat;
	}

	/* now send AUTH payload */

	if (!emit_local_v2AUTH(ike, auth_sig, &ike->sa.st_v2_id_payload.mac, response.pbs)) {
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
		dbg("skipping child; redirect response");
	} else if (!process_any_v2_IKE_AUTH_request_child_sa_payloads(ike, md, response.pbs)) {
		/* already logged; already recorded */
		return STF_FATAL;
	}

	if (!close_and_record_v2_message(&response)) {
		return STF_INTERNAL_ERROR;
	}

	return STF_OK;
}

/* STATE_V2_PARENT_I2: R2 --> I3
 *                     <--  HDR, SK {IDr, [CERT,] AUTH,
 *                               [SAr2,] [TSi,] [TSr,]}
 * [Parent SA established]
 *
 * For error handling in this function, please read:
 * https://tools.ietf.org/html/rfc7296#section-2.21.2
 */

static stf_status process_v2_IKE_AUTH_response_post_cert_decode(struct state *st, struct msg_digest *md);

stf_status process_v2_IKE_AUTH_response(struct ike_sa *ike, struct child_sa *unused_child UNUSED,
					struct msg_digest *md)
{
	/*
	 * If the initiator rejects the responders authentication it
	 * should immediately send a delete notification and wipe the SA.
	 *
	 * This doesn't happen.  Instead the SA is deleted.
	 */
	struct payload_digest *cert_payloads = md->chain[ISAKMP_NEXT_v2CERT];
	if (cert_payloads != NULL) {
		submit_v2_cert_decode(ike, md, cert_payloads,
				      process_v2_IKE_AUTH_response_post_cert_decode, HERE);
		return STF_SUSPEND;
	} else {
		dbg("no certs to decode");
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
		llog_diag(RC_LOG_SERIOUS, ike->sa.logger, &d, "%s", "");
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
	enum keyword_auth that_authby = c->remote->host.config->auth;

	passert(that_authby != AUTH_NEVER && that_authby != AUTH_UNSET);

	if (md->pd[PD_v2N_PPK_IDENTITY] != NULL) {
		if (!c->config->ppk.allow) {
			llog_sa(RC_LOG_SERIOUS, ike, "received PPK_IDENTITY but connection does not allow PPK");
			return STF_FATAL;
		}
	} else {
		if (c->config->ppk.insist) {
			llog_sa(RC_LOG_SERIOUS, ike,
				"failed to receive PPK confirmation and connection has ppk=insist");
			dbg("should be initiating a notify that kills the state");
			pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
			return STF_FATAL;
		}
	}

	/*
	 * If we sent USE_PPK and we did not receive a PPK_IDENTITY,
	 * it means the responder failed to find our PPK ID, but allowed
	 * the connection to continue without PPK by using our NO_PPK_AUTH
	 * payload. We should revert our key material to NO_PPK versions.
	 */
	if (ike->sa.st_seen_ppk &&
	    md->pd[PD_v2N_PPK_IDENTITY] == NULL &&
	    c->config->ppk.allow) {
		/* discard the PPK based calculations */

		llog_sa(RC_LOG, ike, "peer wants to continue without PPK - switching to NO_PPK");

		release_symkey(__func__, "st_skey_d_nss",  &ike->sa.st_skey_d_nss);
		ike->sa.st_skey_d_nss = reference_symkey(__func__, "used sk_d from no ppk", ike->sa.st_sk_d_no_ppk);

		release_symkey(__func__, "st_skey_pi_nss", &ike->sa.st_skey_pi_nss);
		ike->sa.st_skey_pi_nss = reference_symkey(__func__, "used sk_pi from no ppk", ike->sa.st_sk_pi_no_ppk);

		release_symkey(__func__, "st_skey_pr_nss", &ike->sa.st_skey_pr_nss);
		ike->sa.st_skey_pr_nss = reference_symkey(__func__, "used sk_pr from no ppk", ike->sa.st_sk_pr_no_ppk);
	}

	struct crypt_mac idhash_in = v2_id_hash(ike, "idhash auth R2", "IDr",
						pbs_in_all(&md->chain[ISAKMP_NEXT_v2IDr]->pbs),
						"skey_pr", ike->sa.st_skey_pr_nss);

	/* process AUTH payload */

	dbg("initiator verifying AUTH payload");
	d = verify_v2AUTH_and_log(md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2auth.isaa_auth_method,
				  ike, &idhash_in, &md->chain[ISAKMP_NEXT_v2AUTH]->pbs, that_authby);
	if (d != NULL) {
		llog_diag(RC_LOG_SERIOUS, ike->sa.logger, &d, "%s", "");
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
	passert(ike->sa.st_v2_transition->next_state == STATE_V2_ESTABLISHED_IKE_SA);
	change_v2_state(&ike->sa);
	v2_ike_sa_established(ike);

	/*
	 * IF there's a redirect, process it and return immediately.
	 * Function gets to decide status.
	 */
	stf_status redirect_status = STF_OK;
	if (redirect_ike_auth(ike, md, &redirect_status)) {
		return redirect_status;
	}

	ike->sa.st_v2_mobike.enabled =
		accept_v2_notification(ike->sa.logger, md, c->config->mobike,
				       v2N_MOBIKE_SUPPORTED);

	/*
	 * Keep the portal open ...
	 */
	if (LHAS(ike->sa.hidden_variables.st_nat_traversal, NATED_HOST)) {
		/* ensure we run keepalives if needed */
		if (c->config->nat_keepalive) {
			/*
			 * Trigger a keep alive for all states.
			 *
			 * XXX: call nat_traversal_new_ka_event()
			 * instead?  There's no hurry right?
			 */
			nat_traversal_ka_event(ike->sa.logger);
		}
	}

	/*
	 * Figure out of the child is both expected and viable.
	 *
	 * See 2.21.2.  Error Handling in IKE_AUTH
	 */

	v2_notification_t n = process_v2_IKE_AUTH_response_child_sa_payloads(ike, md);

	if (v2_notification_fatal(n)) {
		/* already logged */
		/*
		 * XXX: there was something "really bad" about the
		 * child.  Should be sending the fatal notification in
		 * a new exchange (see RFC); returning STF_FATAL just
		 * causes the IKE SA to silently self-destruct.
		 */
		return STF_FATAL;
	}

	if(n != v2N_NOTHING_WRONG) {
		/* already logged */
		/*
		 * This end (the initiator) did not like something
		 * about the Child SA.
		 *
		 * (If the responder sent back an error notification
		 * to reject the Child SA, then the above call would
		 * have cleaned up the mess and return
		 * v2N_NOTHING_WRONG.  After all, problem solved.
		 */
		llog_sa(RC_LOG_SERIOUS, ike, "IKE SA established but initiator rejected Child SA response");
		struct child_sa *larval_child = ike->sa.st_v2_msgid_windows.initiator.wip_sa;
		ike->sa.st_v2_msgid_windows.initiator.wip_sa = NULL;
		passert(larval_child != NULL);
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
		unpend(ike, larval_child->sa.st_connection);
		/*
		 * Quickly delete this larval SA.
		 */
		submit_v2_delete_exchange(ike, larval_child);
	}

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

stf_status process_v2_IKE_AUTH_failure_response(struct ike_sa *ike,
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
			const char *why = enum_name_short(&v2_notification_names, n);
			llog_sa(RC_LOG_SERIOUS, ike,
				  "IKE SA authentication request rejected by peer: %s", why);
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
			enum_buf esb;
			const char *name = str_enum_short(&v2_notification_names, n, &esb);

			if (ntfy->payload.v2n.isan_spisize != 0) {
				/* invalid-syntax, but can't do anything about it */
				llog_sa(RC_LOG_SERIOUS, ike,
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
						llog_sa(RC_LOG_SERIOUS, ike,
							  "IKE_AUTH response contained the CHILD SA error notification '%s' but there is no child",
							name);
					} else {
						llog_sa(RC_LOG_SERIOUS, child,
							"IKE_AUTH response contained the error notification %s", name);
					}
					break;
				default:
					llog_sa(RC_LOG_SERIOUS, ike,
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
		llog_sa(RC_LOG_SERIOUS, ike,
			  "IKE SA authentication request rejected by peer: unrecognized response");
	}

	return STF_FATAL;
}
