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
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
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
#include "keys.h"
#include "ike_alg_hash.h"
#include "ikev2_cp.h"
#include "kernel.h"			/* for raw_policy() */
#include "ikev2_delete.h"		/* for submit_v2_delete_exchange() */

static stf_status process_v2_IKE_AUTH_request_tail(struct state *st,
							  struct msg_digest *md,
							  bool pam_status);

static stf_status ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_AUTH_I_signature_continue(struct ike_sa *ike,
												 struct msg_digest *md,
												 const struct hash_signature *sig);


stf_status ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_AUTH_I_continue(struct state *ike_st,
										struct msg_digest *md)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_st);
	pexpect(ike->sa.st_sa_role == SA_INITIATOR);
	pexpect(v2_msg_role(md) == MESSAGE_RESPONSE); /* i.e., MD!=NULL */
	dbg("%s() for #%lu %s: g^{xy} calculated, sending IKE_AUTH",
	    __func__, ike->sa.st_serialno, ike->sa.st_state->name);

	struct connection *const pc = ike->sa.st_connection;	/* parent connection */

	if (!(md->hdr.isa_xchg == ISAKMP_v2_IKE_INTERMEDIATE)) {
		if (ike->sa.st_dh_shared_secret == NULL) {
			/*
			* XXX: this is the initiator so returning a
			* notification is kind of useless.
			*/
			pstat_sa_failed(&ike->sa, REASON_CRYPTO_FAILED);
			return STF_FAIL;
		}
		calc_v2_keymat(&ike->sa, NULL, NULL, /*no old keymat*/
			       &ike->sa.st_ike_rekey_spis);
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
	rehash_state(&ike->sa, &md->hdr.isa_ike_responder_spi);

	/*
	 * If we and responder are willing to use a PPK, we need to
	 * generate NO_PPK_AUTH as well as PPK-based AUTH payload.
	 *
	 * Stash the no-ppk keys in st_skey_*_no_ppk, and then
	 * scramble the st_skey_* keys with PPK.
	 */
	if (LIN(POLICY_PPK_ALLOW, pc->policy) && ike->sa.st_seen_ppk) {
		chunk_t *ppk_id;
		chunk_t *ppk = get_connection_ppk(ike->sa.st_connection, &ppk_id);

		if (ppk != NULL) {
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
					ike->sa.st_logger);
			log_state(RC_LOG, &ike->sa,
				  "PPK AUTH calculated as initiator");
		} else {
			if (pc->policy & POLICY_PPK_INSIST) {
				log_state(RC_LOG_SERIOUS, &ike->sa,
					  "connection requires PPK, but we didn't find one");
				return STF_FATAL;
			} else {
				log_state(RC_LOG, &ike->sa,
					  "failed to find PPK and PPK_ID, continuing without PPK");
				/* we should omit sending any PPK Identity, so we pretend we didn't see USE_PPK */
				ike->sa.st_seen_ppk = FALSE;
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
		ike->sa.st_v2_id_payload.header = build_v2_id_payload(&pc->spd.this, &data,
								      "my IDi", ike->sa.st_logger);
		ike->sa.st_v2_id_payload.data = clone_hunk(data, "my IDi");
	}

	ike->sa.st_v2_id_payload.mac = v2_hash_id_payload("IDi", ike,
							  "st_skey_pi_nss",
							  ike->sa.st_skey_pi_nss);
	if (ike->sa.st_seen_ppk && !LIN(POLICY_PPK_INSIST, pc->policy)) {
		/* ID payload that we've build is the same */
		ike->sa.st_v2_id_payload.mac_no_ppk_auth =
			v2_hash_id_payload("IDi (no-PPK)", ike,
					   "sk_pi_no_pkk",
					   ike->sa.st_sk_pi_no_ppk);
	}

	{
		enum keyword_authby authby = v2_auth_by(ike);
		enum ikev2_auth_method auth_method = v2_auth_method(ike, authby);
		switch (auth_method) {
		case IKEv2_AUTH_RSA:
		{
			const struct hash_desc *hash_algo = &ike_alg_hash_sha1;
			struct crypt_mac hash_to_sign =
				v2_calculate_sighash(ike, &ike->sa.st_v2_id_payload.mac,
						     hash_algo, LOCAL_PERSPECTIVE);
			if (!submit_v2_auth_signature(ike, &hash_to_sign, hash_algo,
						      authby, auth_method,
						      ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_AUTH_I_signature_continue)) {
				dbg("submit_v2_auth_signature() died, fatal");
				return STF_FATAL;
			}
			return STF_SUSPEND;
		}
		case IKEv2_AUTH_DIGSIG:
		{
			const struct hash_desc *hash_algo = v2_auth_negotiated_signature_hash(ike);
			if (hash_algo == NULL) {
				return STF_FATAL;
			}
			struct crypt_mac hash_to_sign =
				v2_calculate_sighash(ike, &ike->sa.st_v2_id_payload.mac,
						     hash_algo, LOCAL_PERSPECTIVE);
			if (!submit_v2_auth_signature(ike, &hash_to_sign, hash_algo,
						      authby, auth_method,
						      ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_AUTH_I_signature_continue)) {
				dbg("submit_v2_auth_signature() died, fatal");
				return STF_FATAL;
			}
			return STF_SUSPEND;
		}
		case IKEv2_AUTH_PSK:
		case IKEv2_AUTH_NULL:
		{
			struct hash_signature sig = { .len = 0, };
			return ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_AUTH_I_signature_continue(ike, md, &sig);
		}
		default:
			log_state(RC_LOG, &ike->sa,
				  "authentication method %s not supported",
				  enum_name(&ikev2_auth_names, auth_method));
			return STF_FATAL;
		}
	}
}

static stf_status ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_AUTH_I_signature_continue(struct ike_sa *ike,
												 struct msg_digest *md,
												 const struct hash_signature *auth_sig)
{
	struct connection *const pc = ike->sa.st_connection;	/* parent connection */
	ikev2_log_parentSA(&ike->sa);

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
			      clone_pbs_out_as_chunk(&md->message_pbs, "saved first received non-intermediate packet"));
	}
	/* beginning of data going out */

	/* make sure HDR is at start of a clean buffer */
	struct pbs_out reply_stream = open_pbs_out("reply packet",
						   reply_buffer, sizeof(reply_buffer),
						   ike->sa.st_logger);

	/* HDR out */

	struct pbs_out rbody = open_v2_message(&reply_stream, ike,
					       NULL /* request */,
					       ISAKMP_v2_IKE_AUTH);
	if (!pbs_ok(&rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* insert an Encryption payload header (SK) */

	struct v2SK_payload sk = open_v2SK_payload(ike->sa.st_logger, &rbody, ike);
	if (!pbs_ok(&sk.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	/* actual data */

	/* decide whether to send CERT payload */

	bool send_cert = ikev2_send_cert_decision(ike);
	bool ic =  pc->initial_contact && (ike->sa.st_ike_pred == SOS_NOBODY);
	bool send_idr = ((pc->spd.that.id.kind != ID_NULL && pc->spd.that.id.name.len != 0) ||
				pc->spd.that.id.kind == ID_NULL); /* me tarzan, you jane */

	if (impair.send_no_idr) {
		log_state(RC_LOG, &ike->sa, "IMPAIR: omitting IDr payload");
		send_idr = false;
	}

	dbg("IDr payload will %sbe sent", send_idr ? "" : "NOT ");

	/* send out the IDi payload */

	{
		pb_stream i_id_pbs;
		if (!out_struct(&ike->sa.st_v2_id_payload.header,
				&ikev2_id_i_desc,
				&sk.pbs,
				&i_id_pbs) ||
		    !out_hunk(ike->sa.st_v2_id_payload.data, &i_id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;
		close_output_pbs(&i_id_pbs);
	}

	if (impair.add_unknown_v2_payload_to_sk == ISAKMP_v2_IKE_AUTH) {
		if (!emit_v2UNKNOWN("SK request",
				    impair.add_unknown_v2_payload_to_sk,
				    &sk.pbs)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* send [CERT,] payload RFC 4306 3.6, 1.2) */
	if (send_cert) {
		stf_status certstat = ikev2_send_cert(ike->sa.st_connection, &sk.pbs);
		if (certstat != STF_OK)
			return certstat;

		/* send CERTREQ */
		bool send_certreq = ikev2_send_certreq_INIT_decision(&ike->sa, SA_INITIATOR);
		if (send_certreq) {
			if (DBGP(DBG_BASE)) {
				dn_buf buf;
				DBG_log("Sending [CERTREQ] of %s",
					str_dn(ike->sa.st_connection->spd.that.ca, &buf));
			}
			ikev2_send_certreq(&ike->sa, md, &sk.pbs);
		}
	}

	/* you Tarzan, me Jane support */
	if (send_idr) {
		switch (pc->spd.that.id.kind) {
		case ID_DER_ASN1_DN:
		case ID_FQDN:
		case ID_USER_FQDN:
		case ID_KEY_ID:
		case ID_NULL:
		{
			shunk_t id_b;
			struct ikev2_id r_id = build_v2_id_payload(&pc->spd.that, &id_b,
								   "their IDr",
								   ike->sa.st_logger);
			pb_stream r_id_pbs;
			if (!out_struct(&r_id, &ikev2_id_r_desc, &sk.pbs,
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
			    enum_show(&ike_id_type_names, pc->spd.that.id.kind, &b));
			break;
		}
		}
	}

	if (ic) {
		log_state(RC_LOG, &ike->sa, "sending INITIAL_CONTACT");
		if (!emit_v2N(v2N_INITIAL_CONTACT, &sk.pbs))
			return STF_INTERNAL_ERROR;
	} else {
		dbg("not sending INITIAL_CONTACT");
	}

	/* send out the AUTH payload */

	if (!emit_v2_auth(ike, auth_sig, &ike->sa.st_v2_id_payload.mac, &sk.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	/*
	 * Now that the AUTH payload is done(?), create and emit the
	 * child using the first pending connection (or the IKE SA's
	 * connection) if there isn't one.
	 *
	 * Then emit SA2i, TSi and TSr and NOTIFY payloads related to
	 * the IPsec SA.
	 */

	/* Child Connection */
	lset_t unused_policy = pc->policy; /* unused */
	struct fd *child_whackfd = null_fd; /* must-free */
	struct connection *cc = first_pending(ike, &unused_policy, &child_whackfd);
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
		struct child_sa *child = new_v2_child_state(cc, ike, IPSEC_SA,
							    SA_INITIATOR,
							    STATE_V2_IKE_AUTH_CHILD_I0,
							    child_whackfd);
		close_any(&child_whackfd);
		ike->sa.st_v2_larval_initiator_sa = child;

		/*
		 * XXX because the early child state ends up with the
		 * try counter check, we need to copy it.
		 *
		 * XXX: huh?!?
		 */
		child->sa.st_try = ike->sa.st_try;

		if (cc != pc) {
			/* lie */
			connection_buf cib;
			log_state(RC_LOG, &ike->sa,
				  "switching CHILD #%lu to pending connection "PRI_CONNECTION,
				  child->sa.st_serialno, pri_connection(cc, &cib));
		}

		if (need_v2_configuration_payload(child->sa.st_connection,
						  ike->sa.hidden_variables.st_nat_traversal)) {
			if (!emit_v2_child_configuration_payload(child, &sk.pbs)) {
				return STF_INTERNAL_ERROR;
			}
		}

		/* code does not support AH+ESP, which not recommended as per RFC 8247 */
		struct ipsec_proto_info *proto_info = ikev2_child_sa_proto_info(child, cc->policy);
		proto_info->our_spi = ikev2_child_sa_spi(&cc->spd, cc->policy, child->sa.st_logger);
		const chunk_t local_spi = THING_AS_CHUNK(proto_info->our_spi);

		/*
		 * A CHILD_SA established during an AUTH exchange does
		 * not propose DH - the IKE SA's SKEYSEED is always
		 * used.
		 */
		struct ikev2_proposals *child_proposals =
			get_v2_ike_auth_child_proposals(cc, "IKE SA initiator emitting ESP/AH proposals",
							child->sa.st_logger);
		if (!ikev2_emit_sa_proposals(&sk.pbs, child_proposals, &local_spi)) {
			return STF_INTERNAL_ERROR;
		}

		emit_v2TS_payloads(&sk.pbs, child);

		if ((cc->policy & POLICY_TUNNEL) == LEMPTY) {
			dbg("Initiator child policy is transport mode, sending v2N_USE_TRANSPORT_MODE");
			/* In v2, for parent, protoid must be 0 and SPI must be empty */
			if (!emit_v2N(v2N_USE_TRANSPORT_MODE, &sk.pbs)) {
				return STF_INTERNAL_ERROR;
			}
		} else {
			dbg("Initiator child policy is tunnel mode, NOT sending v2N_USE_TRANSPORT_MODE");
		}

		/*
		 * Propose IPCOMP based on policy.
		 */
		if (cc->policy & POLICY_COMPRESS) {
			if (!emit_v2N_ipcomp_supported(child, &sk.pbs)) {
				return STF_INTERNAL_ERROR;
			}
		}

		if (cc->send_no_esp_tfc) {
			if (!emit_v2N(v2N_ESP_TFC_PADDING_NOT_SUPPORTED, &sk.pbs)) {
				return STF_INTERNAL_ERROR;
			}
		}

		if (LIN(POLICY_MOBIKE, cc->policy)) {
			ike->sa.st_ike_sent_v2n_mobike_supported = true;
			if (!emit_v2N(v2N_MOBIKE_SUPPORTED, &sk.pbs)) {
				return STF_INTERNAL_ERROR;
			}
		}

		/* send CP payloads */
		if (cc->modecfg_domains != NULL || cc->modecfg_dns != NULL) {
			if (!emit_v2_child_configuration_payload(child, &sk.pbs)) {
				return STF_INTERNAL_ERROR;
			}
		}
	}

	/*
	 * If we and responder are willing to use a PPK, we need to
	 * generate NO_PPK_AUTH as well as PPK-based AUTH payload
	 */
	if (ike->sa.st_seen_ppk) {
		chunk_t *ppk_id;
		get_connection_ppk(ike->sa.st_connection, &ppk_id);
		struct ppk_id_payload ppk_id_p = { .type = 0, };
		create_ppk_id_payload(ppk_id, &ppk_id_p);
		if (DBGP(DBG_BASE)) {
			DBG_log("ppk type: %d", (int) ppk_id_p.type);
			DBG_dump_hunk("ppk_id from payload:", ppk_id_p.ppk_id);
		}

		pb_stream ppks;
		if (!emit_v2Npl(v2N_PPK_IDENTITY, &sk.pbs, &ppks) ||
		    !emit_unified_ppk_id(&ppk_id_p, &ppks)) {
			return STF_INTERNAL_ERROR;
		}
		close_output_pbs(&ppks);

		if (!LIN(POLICY_PPK_INSIST, cc->policy)) {
			if (!ikev2_calc_no_ppk_auth(ike, &ike->sa.st_v2_id_payload.mac_no_ppk_auth,
						    &ike->sa.st_no_ppk_auth)) {
				dbg("ikev2_calc_no_ppk_auth() failed dying");
				return STF_FATAL;
			}

			if (!emit_v2N_hunk(v2N_NO_PPK_AUTH,
					   ike->sa.st_no_ppk_auth, &sk.pbs)) {
				return STF_INTERNAL_ERROR;
			}
		}
	}

	/*
	 * The initiator:
	 *
	 * We sent normal IKEv2_AUTH_RSA but if the policy also allows
	 * AUTH_NULL, we will send a Notify with NULL_AUTH in separate
	 * chunk. This is only done on the initiator in IKE_AUTH, and
	 * not repeated in rekeys.
	 */
	if (v2_auth_by(ike) == AUTHBY_RSASIG && pc->policy & POLICY_AUTH_NULL) {
		/* store in null_auth */
		chunk_t null_auth = NULL_HUNK;
		if (!ikev2_create_psk_auth(AUTHBY_NULL, ike,
					   &ike->sa.st_v2_id_payload.mac,
					   &null_auth)) {
			log_state(RC_LOG_SERIOUS, &ike->sa,
				  "Failed to calculate additional NULL_AUTH");
			return STF_FATAL;
		}
		ike->sa.st_v2_ike_intermediate_used = false;
		if (!emit_v2N_hunk(v2N_NULL_AUTH, null_auth, &sk.pbs)) {
			free_chunk_content(&null_auth);
			return STF_INTERNAL_ERROR;
		}
		free_chunk_content(&null_auth);
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
	return record_v2SK_message(&reply_stream, &sk,
				   "sending IKE_AUTH request",
				   MESSAGE_REQUEST);
}

/* STATE_PARENT_R1: I2 --> R2
 *                  <-- HDR, SK {IDi, [CERT,] [CERTREQ,]
 *                             [IDr,] AUTH, SAi2,
 *                             TSi, TSr}
 * HDR, SK {IDr, [CERT,] AUTH,
 *      SAr2, TSi, TSr} -->
 *
 * [Parent SA established]
 */

static dh_shared_secret_cb process_v2_IKE_AUTH_request_no_skeyseed_continue;	/* type assertion */

stf_status process_v2_IKE_AUTH_request_no_skeyseed(struct ike_sa *ike,
						   struct child_sa *unused_child UNUSED,
						   struct msg_digest *md UNUSED)
{
	/*
	 * the initiator sent us an encrypted payload. We need to calculate
	 * our g^xy, and skeyseed values, and then decrypt the payload.
	 */

	dbg("ikev2 parent %s(): calculating g^{xy} in order to decrypt I2", __func__);

	/* initiate calculation of g^xy */
	submit_dh_shared_secret(&ike->sa, ike->sa.st_gi/*responder needs initiator KE*/,
				process_v2_IKE_AUTH_request_no_skeyseed_continue,
				HERE);
	return STF_SUSPEND;
}

static stf_status process_v2_IKE_AUTH_request_no_skeyseed_continue(struct state *ike_st,
								   struct msg_digest *md)
{
 	struct ike_sa *ike = pexpect_ike_sa(ike_st);
	pexpect(ike->sa.st_sa_role == SA_RESPONDER);
	pexpect(v2_msg_role(md) == MESSAGE_REQUEST); /* i.e., MD!=NULL */
	pexpect(ike->sa.st_state->kind == STATE_PARENT_R1);
	dbg("%s() for #%lu %s: calculating g^{xy}, sending R2",
	    __func__, ike->sa.st_serialno, ike->sa.st_state->name);

	/* extract calculated values from r */

	if (ike->sa.st_dh_shared_secret == NULL) {
		/*
		 * Since dh failed, the channel isn't end-to-end
		 * encrypted.  Send back a clear text notify and then
		 * abandon the connection.
		 */
		dbg("aborting IKE SA: DH failed");
		send_v2N_response_from_md(md, v2N_INVALID_SYNTAX, NULL);
		return STF_FATAL;
	}

	calc_v2_keymat(&ike->sa, NULL/*old_skey_d*/, NULL/*old_prf*/,
		       &ike->sa.st_ike_spis/*new SPIs*/);

	ikev2_process_state_packet(ike, &ike->sa, md);
	/* above does complete state transition */
	return STF_SKIP_COMPLETE_STATE_TRANSITION;
}

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
	pexpect(ike->sa.st_state->kind == STATE_PARENT_R1);
	dbg("%s() for #%lu %s",
	     __func__, ike->sa.st_serialno, ike->sa.st_state->name);

	if (!success) {
		record_v2N_response(ike->sa.st_logger, ike, md,
				    v2N_AUTHENTICATION_FAILED, NULL/*no-data*/,
				    ENCRYPTED_PAYLOAD);
		pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
		return STF_FATAL; /* STF_ZOMBIFY */
	}

	return process_v2_IKE_AUTH_request_tail(&ike->sa, md, success);
}

#endif /* USE_PAM_AUTH */

static stf_status process_v2_IKE_AUTH_request_continue_tail(struct state *st,
								   struct msg_digest *md);

stf_status process_v2_IKE_AUTH_request(struct ike_sa *ike,
				       struct child_sa *unused_child UNUSED,
				       struct msg_digest *md)
{

	/* for testing only */
	if (impair.send_no_ikev2_auth) {
		log_state(RC_LOG, &ike->sa,
			  "IMPAIR_SEND_NO_IKEV2_AUTH set - not sending IKE_AUTH packet");
		return STF_IGNORE;
	}

	/*
	 * This log line establishes that the packet's been decrypted
	 * and now it is being processed for real.
	 *
	 * XXX: move this into ikev2.c?
	 */
	LLOG_JAMBUF(RC_LOG, ike->sa.st_logger, buf) {
		jam(buf, "processing decrypted ");
		lswlog_msg_digest(buf, md);
	}

	stf_status e = process_v2_IKE_AUTH_request_continue_tail(&ike->sa, md);
	LSWDBGP(DBG_BASE, buf) {
		jam(buf, "process_v2_IKE_AUTH_request_continue_tail returned ");
		jam_v2_stf_status(buf, e);
	}

	/*
	 * if failed OE, delete state completely, no create_child_sa
	 * allowed so childless parent makes no sense. That is also
	 * the reason why we send v2N_AUTHENTICATION_FAILED, even
	 * though authenticated succeeded. It shows the remote end
	 * we have deleted the SA from our end.
	 */
	if (e >= STF_FAIL &&
	    (ike->sa.st_connection->policy & POLICY_OPPORTUNISTIC)) {
		dbg("deleting opportunistic IKE SA with no Child SA");
		record_v2N_response(ike->sa.st_logger, ike, md,
				    v2N_AUTHENTICATION_FAILED, NULL/*no data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL; /* STF_ZOMBIFY */
	}

	return e;
}

static stf_status process_v2_IKE_AUTH_request_post_cert_decode(struct state *st,
							       struct msg_digest *md);

static stf_status process_v2_IKE_AUTH_request_continue_tail(struct state *st,
								   struct msg_digest *md)
{
	struct ike_sa *ike = ike_sa(st, HERE);

	struct payload_digest *cert_payloads = md->chain[ISAKMP_NEXT_v2CERT];
	if (cert_payloads != NULL) {
		submit_cert_decode(ike, st, md, cert_payloads,
				   process_v2_IKE_AUTH_request_post_cert_decode,
				   "responder decoding certificates");
		return STF_SUSPEND;
	} else {
		dbg("no certs to decode");
		ike->sa.st_remote_certs.processed = true;
		ike->sa.st_remote_certs.harmless = true;
	}
	return process_v2_IKE_AUTH_request_post_cert_decode(st, md);
}

static stf_status process_v2_IKE_AUTH_request_ipseckey_continue(struct ike_sa *ike,
								struct msg_digest *md,
								bool err);

static stf_status process_v2_IKE_AUTH_request_id_tail(struct ike_sa *ike, struct msg_digest *md);

static stf_status process_v2_IKE_AUTH_request_post_cert_decode(struct state *ike_sa,
							       struct msg_digest *md)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	ikev2_log_parentSA(&ike->sa);

	/* going to switch to child st. before that update parent */
	if (!LHAS(ike->sa.hidden_variables.st_nat_traversal, NATED_HOST))
		update_ike_endpoints(ike, md);

	nat_traversal_change_port_lookup(md, &ike->sa); /* shouldn't this be ike? */

	diag_t d = ikev2_responder_decode_initiator_id(ike, md);
	if (d != NULL) {
		llog_diag(RC_LOG_SERIOUS, ike->sa.st_logger, &d, "%s", "");
		pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
		record_v2N_response(ike->sa.st_logger, ike, md,
				    v2N_AUTHENTICATION_FAILED, NULL/*no-data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL;
	}

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
		record_v2N_response(ike->sa.st_logger, ike, md,
				    v2N_AUTHENTICATION_FAILED, NULL/*no-data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL;
	}
	return process_v2_IKE_AUTH_request_id_tail(ike, md);
}

stf_status process_v2_IKE_AUTH_request_id_tail(struct ike_sa *ike, struct msg_digest *md)
{
	lset_t policy = ike->sa.st_connection->policy;
	bool found_ppk = FALSE;
	chunk_t null_auth = EMPTY_CHUNK;

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

		const chunk_t *ppk = get_ppk_by_id(&payl.ppk_id);
		free_chunk_content(&payl.ppk_id);
		if (ppk != NULL) {
			found_ppk = TRUE;
		}

		if (found_ppk && LIN(POLICY_PPK_ALLOW, policy)) {
			ppk_recalculate(ppk, ike->sa.st_oakley.ta_prf,
					&ike->sa.st_skey_d_nss,
					&ike->sa.st_skey_pi_nss,
					&ike->sa.st_skey_pr_nss,
					ike->sa.st_logger);
			ike->sa.st_ppk_used = TRUE;
			log_state(RC_LOG, &ike->sa,
				  "PPK AUTH calculated as responder");
		} else {
			log_state(RC_LOG, &ike->sa,
				  "ignored received PPK_IDENTITY - connection does not require PPK or PPKID not found");
		}
	}
	if (md->pd[PD_v2N_NO_PPK_AUTH] != NULL) {
		pb_stream pbs = md->pd[PD_v2N_NO_PPK_AUTH]->pbs;
		size_t len = pbs_left(&pbs);
		dbg("received NO_PPK_AUTH");
		if (LIN(POLICY_PPK_INSIST, policy)) {
			dbg("Ignored NO_PPK_AUTH data - connection insists on PPK");
		} else {

			chunk_t no_ppk_auth = alloc_chunk(len, "NO_PPK_AUTH");
			diag_t d = pbs_in_raw(&pbs, no_ppk_auth.ptr, len, "NO_PPK_AUTH extract");
			if (d != NULL) {
				llog_diag(RC_LOG_SERIOUS, ike->sa.st_logger, &d,
					 "failed to extract %zd bytes of NO_PPK_AUTH from Notify payload", len);
				free_chunk_content(&no_ppk_auth);
				return STF_FATAL;
			}
			replace_chunk(&ike->sa.st_no_ppk_auth, no_ppk_auth);
		}
	}
	ike->sa.st_ike_seen_v2n_mobike_supported = md->pd[PD_v2N_MOBIKE_SUPPORTED] != NULL;
	if (ike->sa.st_ike_seen_v2n_mobike_supported) {
		dbg("received v2N_MOBIKE_SUPPORTED %s",
		    ike->sa.st_ike_sent_v2n_mobike_supported ?
		    "and sent" : "while it did not sent");
	}
	if (md->pd[PD_v2N_NULL_AUTH] != NULL) {
		pb_stream pbs = md->pd[PD_v2N_NULL_AUTH]->pbs;
		size_t len = pbs_left(&pbs);

		dbg("received v2N_NULL_AUTH");
		null_auth = alloc_chunk(len, "NULL_AUTH");
		diag_t d = pbs_in_raw(&pbs, null_auth.ptr, len, "NULL_AUTH extract");
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, ike->sa.st_logger, &d,
				 "failed to extract %zd bytes of NULL_AUTH from Notify payload: ", len);
			free_chunk_content(&null_auth);
			return STF_FATAL;
		}
	}
	ike->sa.st_ike_seen_v2n_initial_contact = md->pd[PD_v2N_INITIAL_CONTACT] != NULL;

	/*
	 * If we found proper PPK ID and policy allows PPK, use that.
	 * Otherwise use NO_PPK_AUTH
	 */
	if (found_ppk && LIN(POLICY_PPK_ALLOW, policy))
		free_chunk_content(&ike->sa.st_no_ppk_auth);

	if (!found_ppk && LIN(POLICY_PPK_INSIST, policy)) {
		log_state(RC_LOG_SERIOUS, &ike->sa, "Requested PPK_ID not found and connection requires a valid PPK");
		free_chunk_content(&null_auth);
		record_v2N_response(ike->sa.st_logger, ike, md,
				    v2N_AUTHENTICATION_FAILED, NULL/*no data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL;
	}

	/* calculate hash of IDi for AUTH below */
	struct crypt_mac idhash_in = v2_id_hash(ike, "IDi verify hash", "IDi",
						same_pbs_in_as_shunk(&md->chain[ISAKMP_NEXT_v2IDi]->pbs),
						"skey_pi", ike->sa.st_skey_pi_nss);

	/* process CERTREQ payload */
	if (md->chain[ISAKMP_NEXT_v2CERTREQ] != NULL) {
		dbg("received CERTREQ payload; going to decode it");
		ikev2_decode_cr(md, ike->sa.st_logger);
	}

	/* process AUTH payload */

	enum keyword_authby that_authby = ike->sa.st_connection->spd.that.authby;

	passert(that_authby != AUTHBY_NEVER && that_authby != AUTHBY_UNSET);

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
		init_pbs(&pbs_no_ppk_auth, ike->sa.st_no_ppk_auth.ptr, len, "pb_stream for verifying NO_PPK_AUTH");

		diag_t d = v2_authsig_and_log(md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2auth.isaa_auth_method,
					      ike, &idhash_in, &pbs_no_ppk_auth,
					      ike->sa.st_connection->spd.that.authby);
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, ike->sa.st_logger, &d, "%s", "");
			dbg("no PPK auth failed");
			record_v2N_response(ike->sa.st_logger, ike, md,
					    v2N_AUTHENTICATION_FAILED, NULL/*no data*/,
					    ENCRYPTED_PAYLOAD);
			free_chunk_content(&null_auth);	/* ??? necessary? */
			pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
			return STF_FATAL;
		}
		dbg("NO_PPK_AUTH verified");
	} else {
		bool policy_null = LIN(POLICY_AUTH_NULL, ike->sa.st_connection->policy);
		bool policy_rsasig = LIN(POLICY_RSASIG, ike->sa.st_connection->policy);

		/*
		 * if received NULL_AUTH in Notify payload and we only allow NULL Authentication,
		 * proceed with verifying that payload, else verify AUTH normally
		 */
		if (null_auth.ptr != NULL && policy_null && !policy_rsasig) {
			/* making a dummy pb_stream so we could pass it to v2_check_auth */
			pb_stream pbs_null_auth;
			size_t len = null_auth.len;

			dbg("going to try to verify NULL_AUTH from Notify payload");
			init_pbs(&pbs_null_auth, null_auth.ptr, len, "pb_stream for verifying NULL_AUTH");
			diag_t d = v2_authsig_and_log(IKEv2_AUTH_NULL, ike, &idhash_in,
						      &pbs_null_auth, AUTHBY_NULL);
			if (d != NULL) {
				llog_diag(RC_LOG_SERIOUS, ike->sa.st_logger, &d, "%s", "");
				dbg("NULL_auth from Notify Payload failed");
				record_v2N_response(ike->sa.st_logger, ike, md,
						    v2N_AUTHENTICATION_FAILED, NULL/*no data*/,
						    ENCRYPTED_PAYLOAD);
				free_chunk_content(&null_auth);
				pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
				return STF_FATAL;
			}
			dbg("NULL_AUTH verified");
		} else {
			dbg("responder verifying AUTH payload");
			diag_t d = v2_authsig_and_log(md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2auth.isaa_auth_method,
						      ike, &idhash_in, &md->chain[ISAKMP_NEXT_v2AUTH]->pbs,
						      ike->sa.st_connection->spd.that.authby);
			if (d != NULL) {
				llog_diag(RC_LOG_SERIOUS, ike->sa.st_logger, &d, "%s", "");
				dbg("I2 Auth Payload failed");
				record_v2N_response(ike->sa.st_logger, ike, md,
						    v2N_AUTHENTICATION_FAILED, NULL/*no data*/,
						    ENCRYPTED_PAYLOAD);
				free_chunk_content(&null_auth);
				pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
				return STF_FATAL;
			}
		}
	}

	/* AUTH succeeded */

	free_chunk_content(&null_auth);

#ifdef USE_PAM_AUTH
	/*
	 * The AUTH payload is verified succsfully.  Now invoke the
	 * PAM helper to authorize connection (based on name only, not
	 * password) When pam helper is done state will be woken up
	 * and continue.
	 */
	if (ike->sa.st_connection->policy & POLICY_IKEV2_PAM_AUTHORIZE) {
		id_buf thatidb;
		const char *thatid = str_id(&ike->sa.st_connection->spd.that.id, &thatidb);
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

	return process_v2_IKE_AUTH_request_tail(&ike->sa, md, TRUE);
}

static v2_auth_signature_cb process_v2_IKE_AUTH_request_auth_signature_continue; /* type check */

static stf_status process_v2_IKE_AUTH_request_tail(struct state *ike_st,
							  struct msg_digest *md,
							  bool pam_status)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_st);
	struct connection *const c = ike->sa.st_connection;

	if (!pam_status) {
		/*
		 * TBD: send this notification encrypted because the
		 * AUTH payload succeed
		 */
		record_v2N_response(ike->sa.st_logger, ike, md,
				    v2N_AUTHENTICATION_FAILED, NULL/*no data*/,
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

	if (ike->sa.st_peer_wants_null) {
		/* make it the Null ID */
		ike->sa.st_v2_id_payload.header.isai_type = ID_NULL;
		ike->sa.st_v2_id_payload.data = empty_chunk;
	} else {
		shunk_t data;
		ike->sa.st_v2_id_payload.header = build_v2_id_payload(&c->spd.this, &data,
								      "my IDr",
								      ike->sa.st_logger);
		ike->sa.st_v2_id_payload.data = clone_hunk(data, "my IDr");
	}

	/* will be signed in auth payload */
	ike->sa.st_v2_id_payload.mac = v2_hash_id_payload("IDr", ike, "st_skey_pr_nss",
							  ike->sa.st_skey_pr_nss);

	{
		enum keyword_authby authby = v2_auth_by(ike);
		enum ikev2_auth_method auth_method = v2_auth_method(ike, authby);
		switch (auth_method) {
		case IKEv2_AUTH_RSA:
		{
			const struct hash_desc *hash_algo = &ike_alg_hash_sha1;
			struct crypt_mac hash_to_sign =
				v2_calculate_sighash(ike, &ike->sa.st_v2_id_payload.mac,
						     hash_algo, LOCAL_PERSPECTIVE);
			ike->sa.st_v2_ike_intermediate_used = false;
			if (!submit_v2_auth_signature(ike, &hash_to_sign, hash_algo,
						      authby, auth_method,
						      process_v2_IKE_AUTH_request_auth_signature_continue)) {
				dbg("submit_v2_auth_signature() died, fatal");
				record_v2N_response(ike->sa.st_logger, ike, md,
						    v2N_AUTHENTICATION_FAILED, NULL/*no data*/,
						    ENCRYPTED_PAYLOAD);
				return STF_FATAL;
			}
			return STF_SUSPEND;
		}
		case IKEv2_AUTH_DIGSIG:
		{
			const struct hash_desc *hash_algo = v2_auth_negotiated_signature_hash(ike);
			if (hash_algo == NULL) {
				record_v2N_response(ike->sa.st_logger, ike, md,
						    v2N_AUTHENTICATION_FAILED, NULL/*no data*/,
						    ENCRYPTED_PAYLOAD);
				return STF_FATAL;
			}
			struct crypt_mac hash_to_sign =
				v2_calculate_sighash(ike, &ike->sa.st_v2_id_payload.mac,
						     hash_algo, LOCAL_PERSPECTIVE);
			ike->sa.st_v2_ike_intermediate_used = false;
			if (!submit_v2_auth_signature(ike, &hash_to_sign, hash_algo,
						      authby, auth_method,
						      process_v2_IKE_AUTH_request_auth_signature_continue)) {
				dbg("submit_v2_auth_signature() died, fatal");
				record_v2N_response(ike->sa.st_logger, ike, md,
						    v2N_AUTHENTICATION_FAILED, NULL/*no data*/,
						    ENCRYPTED_PAYLOAD);
				return STF_FATAL;
			}
			return STF_SUSPEND;
		}
		case IKEv2_AUTH_PSK:
		case IKEv2_AUTH_NULL:
		{
			struct hash_signature sig = { .len = 0, };
			return process_v2_IKE_AUTH_request_auth_signature_continue(ike, md, &sig);
		}
		default:
			log_state(RC_LOG, &ike->sa,
				  "authentication method %s not supported",
				  enum_name(&ikev2_auth_names, auth_method));
			return STF_FATAL;
		}
	}
}

static stf_status process_v2_IKE_AUTH_request_auth_signature_continue(struct ike_sa *ike,
									     struct msg_digest *md,
									     const struct hash_signature *auth_sig)
{
	struct connection *c = ike->sa.st_connection;

	/*
	 * Update the parent state to make sure that it knows we have
	 * authenticated properly.
	 *
	 * XXX: is this double book keeping?  Same action happens in
	 * success_v2_state_transition() and almost happens in
	 * ikev2_ike_sa_established().
	 */
	c->newest_ike_sa = ike->sa.st_serialno;
	v2_schedule_replace_event(&ike->sa);
	ike->sa.st_viable_parent = true;
	linux_audit_conn(&ike->sa, LAK_PARENT_START);
	pstat_sa_established(&ike->sa);

	if (LHAS(ike->sa.hidden_variables.st_nat_traversal, NATED_HOST)) {
		/* ensure we run keepalives if needed */
		if (c->nat_keepalive) {
			/* XXX: just trigger this event? */
			nat_traversal_ka_event(ike->sa.st_logger);
		}
	}

	/* send response */
	if (LIN(POLICY_MOBIKE, c->policy) && ike->sa.st_ike_seen_v2n_mobike_supported) {
		if (c->spd.that.host_type == KH_ANY) {
			/* only allow %any connection to mobike */
			ike->sa.st_ike_sent_v2n_mobike_supported = true;
		} else {
			log_state(RC_LOG, &ike->sa,
				  "not responding with v2N_MOBIKE_SUPPORTED, that end is not %%any");
		}
	}

	bool send_redirect = FALSE;

	if (ike->sa.st_seen_redirect_sup &&
	    (LIN(POLICY_SEND_REDIRECT_ALWAYS, c->policy) ||
	     (!LIN(POLICY_SEND_REDIRECT_NEVER, c->policy) &&
	      require_ddos_cookies()))) {
		if (c->redirect_to == NULL) {
			log_state(RC_LOG_SERIOUS, &ike->sa,
				  "redirect-to is not specified, can't redirect requests");
		} else {
			send_redirect = TRUE;
		}
	}

	/*
	 * Wipes any connections that were using an old version of
	 * this SA?  Is this too early or too late?
	 *
	 * XXX: The call was originally sandwiched vis:
	 *
	 *    - create child sa()
	 *    - add_xfrmi()
	 *    - IKE_SA_established()
	 *    - install_ipsec_sa()
	 *
	 * which means things were deleted after the child sa was
	 * created.  But now it happens before.  Is this a problem?
	 */
	IKE_SA_established(ike);

	/* make sure HDR is at start of a clean buffer */
	struct pbs_out reply_stream = open_pbs_out("reply packet",
						   reply_buffer, sizeof(reply_buffer),
						   ike->sa.st_logger);

	/* HDR out */

	struct pbs_out rbody = open_v2_message(&reply_stream, ike,
					       md /* response */,
					       ISAKMP_v2_IKE_AUTH);

	/* decide to send CERT payload before we generate IDr */
	bool send_cert = ikev2_send_cert_decision(ike);

	/* insert an Encryption payload header */

	struct v2SK_payload sk = open_v2SK_payload(ike->sa.st_logger, &rbody, ike);
	if (!pbs_ok(&sk.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	if (impair.add_unknown_v2_payload_to_sk == ISAKMP_v2_IKE_AUTH) {
		if (!emit_v2UNKNOWN("SK reply",
				    impair.add_unknown_v2_payload_to_sk,
				    &sk.pbs)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* send any NOTIFY payloads */
	if (ike->sa.st_ike_sent_v2n_mobike_supported) {
		if (!emit_v2N(v2N_MOBIKE_SUPPORTED, &sk.pbs))
			return STF_INTERNAL_ERROR;
	}

	if (ike->sa.st_ppk_used) {
		if (!emit_v2N(v2N_PPK_IDENTITY, &sk.pbs))
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
		if (!emit_redirect_notification(shunk1(c->redirect_to), &sk.pbs))
			return STF_INTERNAL_ERROR;
		ike->sa.st_sent_redirect = true;	/* mark that we have sent REDIRECT in IKE_AUTH */
	}

	if (LIN(POLICY_TUNNEL, c->policy) == LEMPTY && ike->sa.st_seen_use_transport) {
		if (!emit_v2N(v2N_USE_TRANSPORT_MODE, &sk.pbs))
			return STF_INTERNAL_ERROR;
	}

	if (c->send_no_esp_tfc) {
		if (!emit_v2N(v2N_ESP_TFC_PADDING_NOT_SUPPORTED, &sk.pbs))
			return STF_INTERNAL_ERROR;
	}

	/* send out the IDr payload */
	{
		pb_stream r_id_pbs;
		if (!out_struct(&ike->sa.st_v2_id_payload.header,
				&ikev2_id_r_desc, &sk.pbs, &r_id_pbs) ||
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
		stf_status certstat = ikev2_send_cert(ike->sa.st_connection, &sk.pbs);
		if (certstat != STF_OK)
			return certstat;
	}

	/* now send AUTH payload */

	if (!emit_v2_auth(ike, auth_sig, &ike->sa.st_v2_id_payload.mac, &sk.pbs)) {
		return STF_INTERNAL_ERROR;
	}
	ike->sa.st_v2_ike_intermediate_used = false;

	if (c->spd.this.sec_label.len > 0) {
		pexpect(c->kind == CK_TEMPLATE);
		if (!install_se_connection_policies(c, ike->sa.st_logger)) {
			return STF_FATAL;
		}
	}

	/*
	 * Try to build a child.
	 *
	 * The result can be fatal, or just doesn't create the child.
	 */

	if (send_redirect) {
		dbg("skipping child; redirect response");
	} else {
		v2_notification_t cn = process_v2_IKE_AUTH_request_child_sa_payloads(ike, md, &sk.pbs);
		if (v2_notification_fatal(cn)) {
			record_v2N_response(ike->sa.st_logger, ike, md,
					    cn, NULL/*no-data*/,
					    ENCRYPTED_PAYLOAD);
			return STF_FATAL;
		} else if (cn != v2N_NOTHING_WRONG) {
			emit_v2N(cn, &sk.pbs);
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
	stf_status status = record_v2SK_message(&reply_stream, &sk,
						"replying to IKE_AUTH request",
						MESSAGE_RESPONSE);

	return status;
}

/* STATE_PARENT_I2: R2 --> I3
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
		submit_cert_decode(ike, &ike->sa, md, cert_payloads,
				   process_v2_IKE_AUTH_response_post_cert_decode,
				   "initiator decoding certificates");
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
		llog_diag(RC_LOG_SERIOUS, ike->sa.st_logger, &d, "%s", "");
		pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
		/*
		 * We cannot send a response as we are processing
		 * IKE_AUTH reply the RFC states we should pretend
		 * IKE_AUTH was okay, and then send an INFORMATIONAL
		 * DELETE IKE SA but we have not implemented that yet.
		 */
		return STF_V2_DELETE_IKE_AUTH_INITIATOR;
	}

	struct connection *c = ike->sa.st_connection;
	enum keyword_authby that_authby = c->spd.that.authby;

	passert(that_authby != AUTHBY_NEVER && that_authby != AUTHBY_UNSET);

	if (md->pd[PD_v2N_PPK_IDENTITY] != NULL) {
		if (!LIN(POLICY_PPK_ALLOW, c->policy)) {
			llog_sa(RC_LOG_SERIOUS, ike, "received PPK_IDENTITY but connection does not allow PPK");
			return STF_FATAL;
		}
	} else {
		if (LIN(POLICY_PPK_INSIST, c->policy)) {
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
	    LIN(POLICY_PPK_ALLOW, c->policy)) {
		/* discard the PPK based calculations */

		log_state(RC_LOG, &ike->sa, "peer wants to continue without PPK - switching to NO_PPK");

		release_symkey(__func__, "st_skey_d_nss",  &ike->sa.st_skey_d_nss);
		ike->sa.st_skey_d_nss = reference_symkey(__func__, "used sk_d from no ppk", ike->sa.st_sk_d_no_ppk);

		release_symkey(__func__, "st_skey_pi_nss", &ike->sa.st_skey_pi_nss);
		ike->sa.st_skey_pi_nss = reference_symkey(__func__, "used sk_pi from no ppk", ike->sa.st_sk_pi_no_ppk);

		release_symkey(__func__, "st_skey_pr_nss", &ike->sa.st_skey_pr_nss);
		ike->sa.st_skey_pr_nss = reference_symkey(__func__, "used sk_pr from no ppk", ike->sa.st_sk_pr_no_ppk);
	}

	struct crypt_mac idhash_in = v2_id_hash(ike, "idhash auth R2", "IDr",
						same_pbs_in_as_shunk(&md->chain[ISAKMP_NEXT_v2IDr]->pbs),
						"skey_pr", ike->sa.st_skey_pr_nss);

	/* process AUTH payload */

	dbg("initiator verifying AUTH payload");
	d = v2_authsig_and_log(md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2auth.isaa_auth_method,
			       ike, &idhash_in, &md->chain[ISAKMP_NEXT_v2AUTH]->pbs, that_authby);
	if (d != NULL) {
		llog_diag(RC_LOG_SERIOUS, ike->sa.st_logger, &d, "%s", "");
		pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
		/*
		 * We cannot send a response as we are processing
		 * IKE_AUTH reply the RFC states we should pretend
		 * IKE_AUTH was okay, and then send an INFORMATIONAL
		 * DELETE IKE SA but we have not implemented that yet.
		 */
		return STF_V2_DELETE_IKE_AUTH_INITIATOR;
	}

	/*
	 * AUTH succeeed
	 *
	 * update the parent state to make sure that it knows we have
	 * authenticated properly.
	 */
	ikev2_ike_sa_established(ike, md->svm, STATE_V2_ESTABLISHED_IKE_SA);

	/*
	 * IF there's a redirect, process it and return immediately.
	 * Function gets to decide status.
	 */
	stf_status redirect_status = STF_OK;
	if (redirect_ike_auth(ike, md, &redirect_status)) {
		return redirect_status;
	}

	ike->sa.st_ike_seen_v2n_mobike_supported = (md->pd[PD_v2N_MOBIKE_SUPPORTED] != NULL);
	if (ike->sa.st_ike_seen_v2n_mobike_supported) {
		dbg("received v2N_MOBIKE_SUPPORTED %s",
		    (ike->sa.st_ike_sent_v2n_mobike_supported ? "and sent" :
		     "while it did not sent"));
	}

	/*
	 * Keep the portal open ...
	 */
	if (LHAS(ike->sa.hidden_variables.st_nat_traversal, NATED_HOST)) {
		/* ensure we run keepalives if needed */
		if (c->nat_keepalive) {
			/*
			 * Trigger a keep alive for all states.
			 *
			 * XXX: call nat_traversal_new_ka_event()
			 * instead?  There's no hurry right?
			 */
			nat_traversal_ka_event(ike->sa.st_logger);
		}
	}

	if (c->spd.this.sec_label.len > 0) {
		pexpect(c->kind == CK_TEMPLATE);
		if (!install_se_connection_policies(c, ike->sa.st_logger)) {
			return STF_FATAL;
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
		struct child_sa *larval_child = ike->sa.st_v2_larval_initiator_sa;
		ike->sa.st_v2_larval_initiator_sa = NULL;
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
	struct child_sa *child = ike->sa.st_v2_larval_initiator_sa;

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
			const char *why = enum_name_short(&ikev2_notify_names, n);
			log_state(RC_LOG_SERIOUS, &ike->sa,
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
			esb_buf esb;
			const char *name = enum_show_short(&ikev2_notify_names, n, &esb);

			if (ntfy->payload.v2n.isan_spisize != 0) {
				/* invalid-syntax, but can't do anything about it */
				log_state(RC_LOG_SERIOUS, &ike->sa,
					  "received an encrypted %s notification with an unexpected non-empty SPI; deleting IKE SA",
					  name);
				logged_something_serious = true;
				break;
			}

			if (n >= v2N_STATUS_FLOOR) {
				/* just log */
				pstat(ikev2_recv_notifies_s, n);
				log_state(RC_LOG, &ike->sa,
					  "IKE_AUTH response contained the status notification %s", name);
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
						log_state(RC_LOG_SERIOUS, &ike->sa,
							  "IKE_AUTH response contained the CHILD SA error notification '%s' but there is no child", name);
					} else {
						linux_audit_conn(&child->sa, LAK_CHILD_FAIL);
						log_state(RC_LOG_SERIOUS, &child->sa,
							  "IKE_AUTH response contained the error notification %s", name);
					}
					break;
				default:
					log_state(RC_LOG_SERIOUS, &ike->sa,
						  "IKE_AUTH response contained the error notification %s", name);
					break;
				}
				/* first is enough */
				break;
			}
		}
	}

	if (!logged_something_serious) {
		log_state(RC_LOG_SERIOUS, &ike->sa,
			  "IKE SA authentication request rejected by peer: unrecognized response");
	}

	return STF_FATAL;
}
