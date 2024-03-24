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
#include "crypt_dh.h"
#include "ikev2.h"
#include "ikev2_send.h"
#include "ikev2_message.h"
#include "ikev2_ike_intermediate.h"
#include "crypt_symkey.h"
#include "log.h"
#include "connections.h"
#include "unpack.h"
#include "nat_traversal.h"		/* for NAT_T_DETECTED */
#include "ikev2_nat.h"
#include "ikev2_ike_auth.h"
#include "pluto_stats.h"
#include "crypt_prf.h"

static dh_shared_secret_cb process_v2_IKE_INTERMEDIATE_response_continue;	/* type assertion */

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
	hton_bytes(adjusted_payload_length,
		   &adjusted_message_header.isa_length,
		   sizeof(adjusted_message_header.isa_length));
	crypt_prf_update_thing(prf, "Adjusted Message Header", adjusted_message_header);

	/* Unencrypted payload */
	crypt_prf_update_hunk(prf, "Unencrypted payloads (if any)", unencrypted_payloads);

	/* encrypted payload header needs its Length adjusted */
	size_t adjusted_encrypted_payload_length = encrypted_payload_header.len + inner_payloads.len;
	dbg("adjusted encrypted payload length: %zu", adjusted_encrypted_payload_length);
	memcpy(&adjusted_encrypted_payload_header, encrypted_payload_header.ptr, encrypted_payload_header.len);
	hton_bytes(adjusted_encrypted_payload_length,
		   &adjusted_encrypted_payload_header.isag_length,
		   sizeof(adjusted_encrypted_payload_header.isag_length));
	crypt_prf_update_thing(prf, "Adjusted Encrypted (SK) Header", adjusted_encrypted_payload_header);

	/* P: prf(... | IntAuth_[ir](N)P) */

	crypt_prf_update_bytes(prf, "Inner payloads (decrypted)",
			       inner_payloads.ptr, inner_payloads.len);

	/* extract the mac; replace existing value */
	struct crypt_mac mac = crypt_prf_final_mac(&prf, NULL/*no-truncation*/);
	free_chunk_content(int_auth_ir);
	*int_auth_ir = clone_hunk(mac, "IntAuth");
}

static stf_status initiate_v2_IKE_INTERMEDIATE_request(struct ike_sa *ike,
						       struct child_sa *unused_child UNUSED,
						       struct msg_digest *mdp)
{
	pexpect(ike->sa.st_sa_role == SA_INITIATOR);
	pexpect(v2_msg_role(mdp) == MESSAGE_RESPONSE); /* i.e., MD!=NULL */
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

	/* message is empty! */

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
		return false;
	}

	record_v2_message(&request.message, request.story, request.outgoing_fragments);

	return STF_OK;
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
		llog_sa(RC_LOG_SERIOUS, ike, "too many IKE_INTERMEDIATE exchanges");
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

	/* empty message */

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
		return false;
	}

	record_v2_message(&response.message, response.story, response.outgoing_fragments);

	return STF_OK;
}

stf_status process_v2_IKE_INTERMEDIATE_response(struct ike_sa *ike,
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
	release_symkey(__func__, "st_dh_shared_secret", &ike->sa.st_dh_shared_secret);
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

	/*
	 * We've done one intermediate exchange round, now proceed to
	 * IKE AUTH.
	 */
	return next_v2_transition(ike, md, &v2_IKE_AUTH_initiator_transition, HERE);
}

const struct v2_state_transition v2_IKE_INTERMEDIATE_initiator_transition = {
	.story      = "initiating IKE_INTERMEDIATE",
	.state      = 0,
	.next_state = STATE_V2_PARENT_I2,
	.exchange   = ISAKMP_v2_IKE_INTERMEDIATE,
	.send_role  = MESSAGE_REQUEST,
	.processor  = initiate_v2_IKE_INTERMEDIATE_request,
	.llog_success = llog_v2_success_exchange_sent_to,
	.timeout_event = EVENT_RETRANSMIT,
};
