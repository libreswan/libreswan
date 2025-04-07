/* IKEv2 IKE_INTERMEDIATE exchange, for Libreswan
 *
 * Copyright (C) 2020  Yulia Kuzovkova <ukuzovkova@gmail.com>
 * Copyright (C) 2021  Andrew Cagney
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

#include "state.h"
#include "demux.h"
#include "keys.h"
#include "crypt_dh.h"
#include "ikev2.h"
#include "ikev2_send.h"
#include "ikev2_message.h"
#include "ikev2_ppk.h"
#include "ikev2_ike_intermediate.h"
#include "crypt_symkey.h"
#include "log.h"
#include "connections.h"
#include "unpack.h"
#include "ikev2_nat.h"
#include "ikev2_ike_auth.h"
#include "pluto_stats.h"
#include "crypt_prf.h"
#include "ikev2_states.h"
#include "ikev2_eap.h"
#include "secrets.h"
#include "crypt_cipher.h"
#include "ikev2_prf.h"
#include "ikev2_notification.h"

static dh_shared_secret_cb process_v2_IKE_INTERMEDIATE_response_continue;	/* type assertion */
static ikev2_state_transition_fn process_v2_IKE_INTERMEDIATE_request;	/* type assertion */

/*
 * Without this the code makes little sense.
 * https://datatracker.ietf.org/doc/html/draft-ietf-ipsecme-ikev2-intermediate-08
 *
 *                       1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ^ ^ <-- MESSAGE START
 *  |                       IKE SA Initiator's SPI                  | | |
 *  |                                                               | | |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ I |
 *  |                       IKE SA Responder's SPI                  | K |
 *  |                                                               | E |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   |
 *  |  Next Payload | MjVer | MnVer | Exchange Type |     Flags     | H |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ d |
 *  |                          Message ID                           | r A
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | |
 *  |                       Adjusted Length                         | | |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ v |
 *  |                                                               |   |
 *  ~                 Unencrypted payloads (if any)                 ~   |
 *  |                                                               |   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ^ | <-- ENCRYPTED HEADER
 *  | Next Payload  |C|  RESERVED   |    Adjusted Payload Length    | | |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | v
 *  |                                                               | |
 *  ~                     Initialization Vector                     ~ E
 *  |                                                               | E
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ c ^ <-- PLAIN
 *  |                                                               | r |
 *  ~             Inner payloads (not yet encrypted)                ~   P
 *  |                                                               | P |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ l v
 *  |              Padding (0-255 octets)           |  Pad Length   | d
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
 *  |                                                               | |
 *  ~                    Integrity Checksum Data                    ~ |
 *  |                                                               | |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ v
 *
 *      Figure 1: Data to Authenticate in the IKE_INTERMEDIATE Exchange
 *                                Messages
 *
 *  Figure 1 illustrates the layout of the IntAuth_[i/r]*A (denoted
 *  as A) and the IntAuth_[i/r]*P (denoted as P) chunks in case the
 *  Encrypted payload is not empty.
 */

static void compute_intermediate_mac(struct ike_sa *ike,
				     PK11SymKey *intermediate_key,
				     const uint8_t *message_start,
				     shunk_t plain,
				     chunk_t *int_auth_ir)
{
	/*
	 * Define variables that match the naming scheme used by the
	 * RFC's ASCII diagram above.
	 */

	/*
	 * Extract the message header, will need to patch up the
	 * trailing length field.
	 */
	struct isakmp_hdr adjusted_message_header;
	shunk_t header = {
		.ptr = message_start,
		.len = sizeof(adjusted_message_header),
	};

	struct ikev2_generic adjusted_encrypted_payload_header;
	shunk_t unencrypted_payloads = {
		.ptr = header.ptr + header.len,
		.len = ((const uint8_t*) plain.ptr - message_start
			- ike->sa.st_oakley.ta_encrypt->wire_iv_size
			- sizeof(adjusted_encrypted_payload_header)
			- header.len),
	};

	shunk_t encrypted_payload = {
		.ptr = unencrypted_payloads.ptr + unencrypted_payloads.len,
		.len = plain.len + sizeof(adjusted_encrypted_payload_header),
	};

	/*
	 * Extract the encrypted header, will need to patch up the
	 * trailing Payload Length field.
	 */
	shunk_t encrypted_payload_header = {
		.ptr = encrypted_payload.ptr,
		.len = sizeof(adjusted_encrypted_payload_header),
	};

	/* skip the IV */
	shunk_t inner_payloads = {
		.ptr = plain.ptr,
		.len = plain.len,
	};

	/*
	 * compute the PRF over "A" + "P" as in:
	 *
	 * IntAuth_i1 = prf(SK_pi1,              IntAuth_i1A [| IntAuth_i1P])
	 * IntAuth_i2 = prf(SK_pi2, IntAuth_i1 | IntAuth_i2A [| IntAuth_i2P])
	 *
	 * IntAuth_r1 = prf(SK_pr1,              IntAuth_r1A [| IntAuth_r1P])
	 * IntAuth_r2 = prf(SK_pr2, IntAuth_r1 | IntAuth_r2A [| IntAuth_r2P])
	 */

	/* prf(SK_p[ir](N), ... */
	struct crypt_prf *prf = crypt_prf_init_symkey("prf(IntAuth_*_A [| IntAuth_*_P])",
						      ike->sa.st_oakley.ta_prf,
						      "SK_p", intermediate_key,
						      ike->sa.logger);

	/* prf(..., IntAuth_[ir](N-1) | ...) */
	if (int_auth_ir->len > 0) {
		crypt_prf_update_hunk(prf, "IntAuth_[ir](N-1)", *int_auth_ir);
	}

	/* A: prf(... | IntAuth_[ir](N)A | ...) */

	/* the message header needs its Length adjusted */
	size_t adjusted_payload_length = (header.len
				 + unencrypted_payloads.len
				 + encrypted_payload_header.len
				 + inner_payloads.len);
	dbg("adjusted payload length: %zu", adjusted_payload_length);
	memcpy(&adjusted_message_header, header.ptr, header.len);
	hton_thing(adjusted_payload_length, adjusted_message_header.isa_length);
	crypt_prf_update_thing(prf, "Adjusted Message Header", adjusted_message_header);

	/* Unencrypted payload */
	crypt_prf_update_hunk(prf, "Unencrypted payloads (if any)", unencrypted_payloads);

	/* encrypted payload header needs its Length adjusted */
	size_t adjusted_encrypted_payload_length = encrypted_payload_header.len + inner_payloads.len;
	dbg("adjusted encrypted payload length: %zu", adjusted_encrypted_payload_length);
	memcpy(&adjusted_encrypted_payload_header, encrypted_payload_header.ptr, encrypted_payload_header.len);
	hton_thing(adjusted_encrypted_payload_length, adjusted_encrypted_payload_header.isag_length);
	crypt_prf_update_thing(prf, "Adjusted Encrypted (SK) Header", adjusted_encrypted_payload_header);

	/* P: prf(... | IntAuth_[ir](N)P) */

	crypt_prf_update_bytes(prf, "Inner payloads (decrypted)",
			       inner_payloads.ptr, inner_payloads.len);

	/* extract the mac; replace existing value */
	struct crypt_mac mac = crypt_prf_final_mac(&prf, NULL/*no-truncation*/);
	free_chunk_content(int_auth_ir);
	*int_auth_ir = clone_hunk(mac, "IntAuth");
}

/*
 * Calculate PPK Confirmation = prf(PPK, Ni | Nr | SPIi | SPIr). It is used in
 * draft-ietf-ipsecme-ikev2-qr-alt-04 and only in IKE_INTERMEDIATE exchange.
 * It is called both by initiator and by the responder.
 */
static chunk_t calc_ppk_confirmation(const struct prf_desc *prf_desc,
				     const shunk_t *ppk,
				     const chunk_t Ni, const chunk_t Nr,
				     const ike_spis_t *ike_spis,
				     struct logger *logger)
{
	dbg("calculating PPK Confirmation for PPK_IDENTITY_KEY Notify");
	PK11SymKey *ppk_key = symkey_from_hunk("PPK Keying material", *ppk, logger);

	/* prf(PPK, ... */
	struct crypt_prf *prf = crypt_prf_init_symkey("prf(PPK,)",
						      prf_desc,
						      "PPK", ppk_key,
						      logger);

	crypt_prf_update_hunk(prf, "Ni", Ni);
	crypt_prf_update_hunk(prf, "Nr", Nr);
	crypt_prf_update_hunk(prf, "SPIi", THING_AS_SHUNK(ike_spis->initiator));
	crypt_prf_update_hunk(prf, "SPIr", THING_AS_SHUNK(ike_spis->responder));
	struct crypt_mac ppk_confirmation = crypt_prf_final_mac(&prf, NULL/*no-truncation*/);

	if (DBGP(DBG_CRYPT)) {
		DBG_dump("prf(PPK, Ni | Nr | SPIi | SPIr) (full PPK confirmation)", ppk_confirmation.ptr,
			prf_desc->prf_output_size);
	}

	symkey_delref(logger, "PPK Keying material", &ppk_key);

	/* NOTE: caller should free this */
	chunk_t ret = clone_bytes_as_chunk(ppk_confirmation.ptr, PPK_CONFIRMATION_LEN, "PPK Confirmation data");

	return ret;
}

static stf_status initiate_v2_IKE_INTERMEDIATE_request(struct ike_sa *ike,
						       struct child_sa *null_child,
						       struct msg_digest *null_md)
{
	PEXPECT(ike->sa.logger, null_child == NULL);
	PEXPECT(ike->sa.logger, null_md == NULL);
	pexpect(ike->sa.st_sa_role == SA_INITIATOR);
	dbg("%s() for #%lu %s: g^{xy} calculated, sending INTERMEDIATE",
	    __func__, ike->sa.st_serialno, ike->sa.st_state->name);

	/* beginning of data going out */

	struct v2_message request;
	if (!open_v2_message("intermediate exchange request",
			     ike, ike->sa.logger,
			     NULL/*request*/, ISAKMP_v2_IKE_INTERMEDIATE,
			     reply_buffer, sizeof(reply_buffer), &request,
			     ENCRYPTED_PAYLOAD)) {
		return STF_INTERNAL_ERROR;
	}

	if (ike->sa.st_v2_ike_ppk == PPK_IKE_INTERMEDIATE) {
		struct connection *const c = ike->sa.st_connection;
		struct shunks *ppk_ids_shunks = c->config->ppk_ids_shunks;
		chunk_t ppk_id;
		bool found_one = false;

		if (ppk_ids_shunks == NULL) {
			/* find any matching PPK and PPK_ID */
			const struct secret_ppk_stuff *ppk =
				get_connection_ppk_and_ppk_id(c);
			if (ppk != NULL) {
				ppk_id = ppk->id;
				found_one = true;
				chunk_t ppk_confirmation =
					calc_ppk_confirmation(ike->sa.st_oakley.ta_prf,
							      &ppk->key,
							      ike->sa.st_ni, ike->sa.st_nr,
							      &ike->sa.st_ike_spis,
							      ike->sa.logger);
				struct ppk_id_payload payl = { .type = 0, };
				create_ppk_id_payload(&ppk_id, &payl);
				if (DBGP(DBG_BASE)) {
					DBG_log("ppk type: %d", (int) payl.type);
					DBG_dump_hunk("ppk_id from payload:", payl.ppk_id);
				}

				struct pbs_out ppks;
				if (!open_v2N_output_pbs(request.pbs, v2N_PPK_IDENTITY_KEY, &ppks)) {
					return STF_INTERNAL_ERROR;
				}
				if (!emit_unified_ppk_id(&payl, &ppks)) {
					return STF_INTERNAL_ERROR;
				}
				if (!pbs_out_hunk(&ppks, ppk_confirmation, "PPK Confirmation")) {
					return STF_INTERNAL_ERROR;
				}
				close_output_pbs(&ppks);
				free_chunk_content(&ppk_confirmation);
			}
		} else {
			for (unsigned i = 0; i < ppk_ids_shunks->len; i++) {
				const struct secret_ppk_stuff *ppk =
					get_connection_ppk(c, /*ppk_id*/NULL,
							   /*index*/i);
				if (ppk != NULL) {
					found_one = true;
					chunk_t ppk_confirmation =
						calc_ppk_confirmation(ike->sa.st_oakley.ta_prf,
								      &ppk->key,
								      ike->sa.st_ni, ike->sa.st_nr,
								      &ike->sa.st_ike_spis,
								      ike->sa.logger);
					ppk_id = chunk2((void *) ppk_ids_shunks->list[i].ptr,
						                 ppk_ids_shunks->list[i].len);
					struct ppk_id_payload payl = { .type = 0, };
					create_ppk_id_payload(&ppk_id, &payl);
					struct pbs_out ppks;
					if (!open_v2N_output_pbs(request.pbs, v2N_PPK_IDENTITY_KEY, &ppks)) {
						return STF_INTERNAL_ERROR;
					}
					if (!emit_unified_ppk_id(&payl, &ppks)) {
						return STF_INTERNAL_ERROR;
					}
					if (!pbs_out_hunk(&ppks, ppk_confirmation, "PPK Confirmation")) {
						return STF_INTERNAL_ERROR;
					}
					close_output_pbs(&ppks);
					free_chunk_content(&ppk_confirmation);
				}
			}
		}

		if (!found_one) {
			if (c->config->ppk.insist) {
				llog_sa(RC_LOG, ike,
					"connection requires PPK, but we didn't find one");
				return STF_FATAL;
			} else {
				llog_sa(RC_LOG, ike,
					"failed to find PPK and PPK_ID, continuing without PPK");
			}
		}
	}

	if (!close_v2_message(&request)) {
		return STF_INTERNAL_ERROR;
	}

	/*
	 * For Intermediate Exchange, apply PRF to the peer's messages
	 * and store in state for further authentication.
	 */
	compute_intermediate_mac(ike, ike->sa.st_skey_pi_nss,
				 request.sk.pbs.container->start,
				 HUNK_AS_SHUNK(request.sk.cleartext) /* inner payloads */,
				 &ike->sa.st_v2_ike_intermediate.initiator);

	if (!encrypt_v2SK_payload(&request.sk)) {
		llog(RC_LOG, request.logger,
		     "error encrypting response");
		return STF_INTERNAL_ERROR;
	}

	record_v2_message(&request.message, request.story, request.outgoing_fragments);

	return STF_OK;
}

static bool recalc_v2_ppk_interm_keymat(struct ike_sa *ike,
					shunk_t ppk,
					const ike_spis_t *new_ike_spis,
					where_t where)
{
	struct logger *logger = ike->sa.logger;
	const struct prf_desc *prf = ike->sa.st_oakley.ta_prf;

	ldbg(logger, "%s() calculating skeyseed using prf %s",
	     __func__, prf->common.fqn);

	/*
	 * We need old_skey_d to recalculate SKEYSEED'.
	 */

	PK11SymKey *skeyseed =
		ikev2_ike_sa_ppk_interm_skeyseed(prf,
						 /*old*/ike->sa.st_skey_d_nss,
						 ppk, logger);
	if (skeyseed == NULL) {
		llog_pexpect(logger, where, "ppk SKEYSEED failed");
		return false;
	}

	/* release old keys, salts and cipher contexts */

	symkey_delref(logger, "SK_d", &ike->sa.st_skey_d_nss);
	symkey_delref(logger, "SK_ai", &ike->sa.st_skey_ai_nss);
	symkey_delref(logger, "SK_ar", &ike->sa.st_skey_ar_nss);
	symkey_delref(logger, "SK_ei", &ike->sa.st_skey_ei_nss);
	symkey_delref(logger, "SK_er", &ike->sa.st_skey_er_nss);
	symkey_delref(logger, "SK_pi", &ike->sa.st_skey_pi_nss);
	symkey_delref(logger, "SK_pr", &ike->sa.st_skey_pr_nss);
	free_chunk_content(&ike->sa.st_skey_chunk_SK_pi);
	free_chunk_content(&ike->sa.st_skey_chunk_SK_pr);
	free_chunk_content(&ike->sa.st_skey_initiator_salt);
	free_chunk_content(&ike->sa.st_skey_responder_salt);
	cipher_context_destroy(&ike->sa.st_ike_encrypt_cipher_context, logger);
	cipher_context_destroy(&ike->sa.st_ike_decrypt_cipher_context, logger);

	/* now we have to generate the keys for everything */

	calc_v2_ike_keymat(&ike->sa, skeyseed, new_ike_spis);
	symkey_delref(logger, "skeyseed", &skeyseed);
	return true;
}

stf_status process_v2_IKE_INTERMEDIATE_request(struct ike_sa *ike,
					       struct child_sa *unused_child UNUSED,
					       struct msg_digest *md)
{
	/*
	 * All systems are go.
	 *
	 * Since DH succeeded, a secure (but unauthenticated) SA
	 * (channel) is available.  From this point on, should things
	 * go south, the state needs to be abandoned (but it shouldn't
	 * happen).
	 */

	/* save the most recent ID */

	ike->sa.st_v2_ike_intermediate.id = md->hdr.isa_msgid;
	if (ike->sa.st_v2_ike_intermediate.id > 2/*magic!*/) {
		llog_sa(RC_LOG, ike, "too many IKE_INTERMEDIATE exchanges");
		return STF_FATAL;
	}

	/*
	 * Now that the payload has been decrypted, perform the
	 * intermediate exchange calculation.
	 *
	 * For Intermediate Exchange, apply PRF to the peer's messages
	 * and store in state for further authentication.
	 *
	 * Hence, here the responder uses the initiator's keys.
	 */
	shunk_t plain = pbs_in_all(&md->chain[ISAKMP_NEXT_v2SK]->pbs);
	compute_intermediate_mac(ike, ike->sa.st_skey_pi_nss,
				 md->packet_pbs.start, plain,
				 &ike->sa.st_v2_ike_intermediate.initiator);

	/*
	 * Since systems are go, start updating the state, starting
	 * with SPIr.
	 */
	update_st_ike_spis_responder(ike, &md->hdr.isa_ike_responder_spi);

	/* send Intermediate Exchange response packet */

	/* beginning of data going out */

	struct v2_message response;
	if (!open_v2_message("intermediate exchange response",
			     ike, ike->sa.logger,
			     md/*response*/, ISAKMP_v2_IKE_INTERMEDIATE,
			     reply_buffer, sizeof(reply_buffer), &response,
			     ENCRYPTED_PAYLOAD)) {
		return STF_INTERNAL_ERROR;
	}

	const struct secret_ppk_stuff *ppk = NULL;

	if (ike->sa.st_v2_ike_ppk == PPK_IKE_INTERMEDIATE) {
		const struct payload_digest *ppk_id_key_payls = md->pd[PD_v2N_PPK_IDENTITY_KEY];

		while (ppk_id_key_payls != NULL && ppk == NULL) {
			dbg("received PPK_IDENTITY_KEY");
			struct ppk_id_key_payload payl;
			if (!extract_v2N_ppk_id_key(&ppk_id_key_payls->pbs, &payl, ike)) {
				dbg("failed to extract PPK_ID from PPK_IDENTITY payload. Abort!");
				return STF_FATAL;
			}

			const struct secret_ppk_stuff *ppk_candidate =
				get_connection_ppk(ike->sa.st_connection,
						   /*ppk_id*/&payl.ppk_id_payl.ppk_id,
						   /*index*/0);

			if (ppk_candidate != NULL) {
				chunk_t ppk_confirmation =
					calc_ppk_confirmation(ike->sa.st_oakley.ta_prf,
							      &ppk_candidate->key,
							      ike->sa.st_ni, ike->sa.st_nr,
							      &ike->sa.st_ike_spis,
							      ike->sa.logger);
				if (hunk_eq(ppk_confirmation, payl.ppk_confirmation)) {
					dbg("found matching PPK, send PPK_IDENTITY back");
					ppk = ppk_candidate;
					/* we have a match, send PPK_IDENTITY back */
					struct ppk_id_payload ppk_id_p = { .type = 0, };
					create_ppk_id_payload(&payl.ppk_id_payl.ppk_id, &ppk_id_p);

					struct pbs_out ppks;
					if (!open_v2N_output_pbs(response.pbs, v2N_PPK_IDENTITY, &ppks)) {
						return STF_INTERNAL_ERROR;
					}
					if (!emit_unified_ppk_id(&ppk_id_p, &ppks)) {
						return STF_INTERNAL_ERROR;
					}
					close_output_pbs(&ppks);
				}
				free_chunk_content(&ppk_confirmation);
			}
			free_chunk_content(&payl.ppk_id_payl.ppk_id);
			free_chunk_content(&payl.ppk_confirmation);
			ppk_id_key_payls = ppk_id_key_payls->next;
		}

		if (md->pd[PD_v2N_PPK_IDENTITY_KEY] == NULL || ppk == NULL) {
			if (ike->sa.st_connection->config->ppk.insist) {
				llog_sa(RC_LOG, ike, "No matching (PPK_ID, PPK) found and connection requires \
					      a valid PPK. Abort!");
				record_v2N_response(ike->sa.logger, ike, md,
						    v2N_AUTHENTICATION_FAILED, empty_shunk/*no data*/,
						    ENCRYPTED_PAYLOAD);
				return STF_FATAL;
			} else {
				llog_sa(RC_LOG, ike,
					"failed to find a matching PPK, continuing without PPK");
			}
		}
	}

	if (!close_v2_message(&response)) {
		return STF_INTERNAL_ERROR;
	}

	/*
	 * For Intermediate Exchange, apply PRF to the peer's messages
	 * and store in state for further authentication.
	 */
	compute_intermediate_mac(ike, ike->sa.st_skey_pr_nss,
				 response.sk.pbs.container->start,
				 HUNK_AS_SHUNK(response.sk.cleartext) /* inner payloads */,
				 &ike->sa.st_v2_ike_intermediate.responder);

	if (!encrypt_v2SK_payload(&response.sk)) {
		llog(RC_LOG, response.logger,
		     "error encrypting response");
		return STF_INTERNAL_ERROR;
	}

	record_v2_message(&response.message, response.story, response.outgoing_fragments);

	if (ppk != NULL) {
		recalc_v2_ppk_interm_keymat(ike, ppk->key,
					    &ike->sa.st_ike_spis,
					    HERE);
		llog(RC_LOG, ike->sa.logger,
		     "PPK used in IKE_INTERMEDIATE as responder");
	}

	return STF_OK;
}

static stf_status process_v2_IKE_INTERMEDIATE_response(struct ike_sa *ike,
						       struct child_sa *unused_child UNUSED,
						       struct msg_digest *md)
{
	/*
	 * The function below always schedules a dh calculation - even
	 * when it's been performed earlier (there's something in the
	 * intermediate echange about this?).
	 *
	 * So that things don't pexpect, blow away the old shared secret.
	 */
	dbg("HACK: blow away old shared secret as going to re-compute it");
	symkey_delref(ike->sa.logger, "st_dh_shared_secret", &ike->sa.st_dh_shared_secret);
	struct connection *c = ike->sa.st_connection;

	/* save the most recent ID */
	ike->sa.st_v2_ike_intermediate.id = md->hdr.isa_msgid;

	/*
	 * Now that the payload has been decrypted, perform the
	 * intermediate exchange calculation.
	 *
	 * For Intermediate Exchange, apply PRF to the peer's messages
	 * and store in state for further authentication.
	 *
	 * Hence, here the initiator uses the responder's keys.
	 */
	shunk_t plain = pbs_in_all(&md->chain[ISAKMP_NEXT_v2SK]->pbs);
	compute_intermediate_mac(ike, ike->sa.st_skey_pr_nss,
				 md->packet_pbs.start, plain,
				 &ike->sa.st_v2_ike_intermediate.responder);

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

	dbg("No KE payload in INTERMEDIATE RESPONSE, not calculating keys, going to AUTH by completing state transition");

	/*
	 * Initiate the calculation of g^xy.
	 *
	 * Form and pass in the full SPI[ir] that will eventually be
	 * used by this IKE SA.  Only once DH has been computed and
	 * the SA is secure (but not authenticated) should the state's
	 * IKE SPIr be updated.
	 */

	pexpect(!ike_spi_is_zero(&ike->sa.st_ike_spis.responder));
	ike->sa.st_ike_rekey_spis = (ike_spis_t) {
		.initiator = ike->sa.st_ike_spis.initiator,
		.responder = md->hdr.isa_ike_responder_spi,
	};

	/*
	 * For now, do only one Intermediate Exchange round and
	 * proceed with IKE_AUTH.
	 */
	submit_dh_shared_secret(/*callback*/&ike->sa, /*task*/&ike->sa, md,
				ike->sa.st_gr/*initiator needs responder KE*/,
				process_v2_IKE_INTERMEDIATE_response_continue, HERE);
	return STF_SUSPEND;
}

stf_status process_v2_IKE_INTERMEDIATE_response_continue(struct state *st, struct msg_digest *md)
{
	struct ike_sa *ike = pexpect_ike_sa(st);
	if (ike->sa.st_dh_shared_secret == NULL) {
		/*
		 * XXX: this is the initiator so returning a
		 * notification is kind of useless.
		 */
		pstat_sa_failed(&ike->sa, REASON_CRYPTO_FAILED);
		return STF_FATAL;
	}

	/*
	 * XXX: does the keymat need to be re-computed here?
	 */

	if (ike->sa.st_v2_ike_ppk == PPK_IKE_INTERMEDIATE && md->pd[PD_v2N_PPK_IDENTITY] != NULL) {
		struct ppk_id_payload payl;
		if (!extract_v2N_ppk_identity(&md->pd[PD_v2N_PPK_IDENTITY]->pbs, &payl, ike)) {
			dbg("failed to extract PPK_ID from PPK_IDENTITY payload. Abort!");
			return STF_FATAL;
		}
		const struct secret_ppk_stuff *ppk =
			get_connection_ppk(ike->sa.st_connection,
					   /*ppk_id*/&payl.ppk_id,
					   /*index*/0);
		free_chunk_content(&payl.ppk_id);

		recalc_v2_ppk_interm_keymat(ike, ppk->key,
					    &ike->sa.st_ike_spis,
					    HERE);
		llog(RC_LOG, ike->sa.logger,
		     "PPK used in IKE_INTERMEDIATE as initiator");
	}
	if (md->pd[PD_v2N_PPK_IDENTITY] == NULL) {
		if (ike->sa.st_connection->config->ppk.insist) {
			llog_sa(RC_LOG, ike, "N(PPK_IDENTITY) not received and connection \
					      insists on PPK. Abort!");
			return STF_FATAL;
		} else {
			llog_sa(RC_LOG, ike,
				"N(PPK_IDENTITY) not received, continuing without PPK");
		}
	}
	/*
	 * We've done one intermediate exchange round, now proceed to
	 * IKE AUTH.
	 */
#if 0
	return next_v2_transition(ike, md, &initiate_v2_IKE_INTERMEDIATE_transition, HERE);
#else
	return next_v2_exchange(ike, md, &v2_IKE_AUTH_exchange, HERE);
#endif
}

/*
 * IKE_INTERMEDIATE exchange and transitions.
 */

static const struct v2_transition v2_IKE_INTERMEDIATE_initiate_transition = {
	.story      = "initiating IKE_INTERMEDIATE",
	.to = &state_v2_IKE_INTERMEDIATE_I,
	.exchange   = ISAKMP_v2_IKE_INTERMEDIATE,
	.processor  = initiate_v2_IKE_INTERMEDIATE_request,
	.llog_success = llog_v2_success_exchange_sent_to,
	.timeout_event = EVENT_v2_RETRANSMIT,
};

static const struct v2_transition v2_IKE_INTERMEDIATE_responder_transition[] = {

	{ .story      = "Responder: process IKE_INTERMEDIATE request",
	  .to = &state_v2_IKE_INTERMEDIATE_R,
	  .exchange   = ISAKMP_v2_IKE_INTERMEDIATE,
	  .recv_role  = MESSAGE_REQUEST,
	  .message_payloads.required = v2P(SK),
	  .encrypted_payloads.required = LEMPTY,
	  .encrypted_payloads.optional = LEMPTY,
	  .processor  = process_v2_IKE_INTERMEDIATE_request,
	  .llog_success = llog_v2_success_exchange_processed,
	  .timeout_event = EVENT_v2_DISCARD, },

};

static const struct v2_transition v2_IKE_INTERMEDIATE_response_transition[] = {
	{ .story      = "processing IKE_INTERMEDIATE response",
	  .to = &state_v2_IKE_INTERMEDIATE_IR,
	  .exchange   = ISAKMP_v2_IKE_INTERMEDIATE,
	  .recv_role  = MESSAGE_RESPONSE,
	  .message_payloads.required = v2P(SK),
	  .message_payloads.optional = LEMPTY,
	  .processor  = process_v2_IKE_INTERMEDIATE_response,
	  .llog_success = llog_v2_success_exchange_processed,
	  .timeout_event = EVENT_v2_DISCARD, },
};

V2_STATE(IKE_INTERMEDIATE_R,
	 "sent IKE_INTERMEDIATE response, waiting for IKE_INTERMEDIATE or IKE_AUTH request",
	 CAT_OPEN_IKE_SA, /*secured*/true,
	 &v2_IKE_INTERMEDIATE_exchange, &v2_IKE_AUTH_exchange, &v2_IKE_AUTH_EAP_exchange);

V2_EXCHANGE(IKE_INTERMEDIATE, "key IKE SA",
	    ", initiating IKE_INTERMEDIATE or IKE_AUTH",
	    CAT_OPEN_IKE_SA, CAT_OPEN_IKE_SA, /*secured*/true,
	    &state_v2_IKE_SA_INIT_IR, &state_v2_IKE_INTERMEDIATE_IR);
