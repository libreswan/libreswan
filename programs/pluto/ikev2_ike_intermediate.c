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

static dh_shared_secret_cb process_v2_IKE_INTERMEDIATE_request_no_skeyseed_post_dh_shared;	/* type assertion */

stf_status process_v2_IKE_INTERMEDIATE_request_no_skeyseed(struct ike_sa *ike,
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
				process_v2_IKE_INTERMEDIATE_request_no_skeyseed_post_dh_shared,
				HERE);
	return STF_SUSPEND;
}

static stf_status process_v2_IKE_INTERMEDIATE_request_no_skeyseed_post_dh_shared(struct state *ike_st,
										 struct msg_digest *md)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_st);
	pexpect(ike->sa.st_sa_role == SA_RESPONDER);
	pexpect(v2_msg_role(md) == MESSAGE_REQUEST); /* i.e., MD!=NULL */
	pexpect(ike->sa.st_state->kind == STATE_PARENT_R1);
	dbg("%s() for #%lu %s: calculating g^{xy}, sending R2",
	    __func__, ike->sa.st_serialno, ike->sa.st_state->name);

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

	calc_v2_keymat(&ike->sa, NULL, NULL, /* no old keymat */
		       &ike->sa.st_ike_spis);

	ikev2_process_state_packet(ike, &ike->sa, md);
	return STF_SKIP_COMPLETE_STATE_TRANSITION;
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

	/*
	 * Since systems are go, start updating the state, starting
	 * with SPIr.
	 */
	rehash_state(&ike->sa, &md->hdr.isa_ike_responder_spi);

	/* send Intermediate Exchange response packet */

	/* beginning of data going out */

	/* make sure HDR is at start of a clean buffer */
	struct pbs_out reply_stream = open_pbs_out("reply packet",
						   reply_buffer, sizeof(reply_buffer),
						   ike->sa.st_logger);

	/* HDR out */

	pb_stream rbody = open_v2_message(&reply_stream, ike,
					  md /* response */,
					  ISAKMP_v2_IKE_INTERMEDIATE);
	if (!pbs_ok(&rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* insert an Encryption payload header (SK) */

	struct v2SK_payload sk = open_v2SK_payload(ike->sa.st_logger, &rbody, ike);
	if (!pbs_ok(&sk.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	/* send NOTIFY payload */
	if (ike->sa.st_seen_intermediate) {
		if (!emit_v2N(v2N_INTERMEDIATE_EXCHANGE_SUPPORTED, &sk.pbs))
			return STF_INTERNAL_ERROR;
	}

	if (!close_v2SK_payload(&sk)) {
		return STF_INTERNAL_ERROR;
	}
	close_output_pbs(&rbody);
	close_output_pbs(&reply_stream);

	stf_status ret = encrypt_v2SK_payload(&sk);

	if (ret != STF_OK) {
		return ret;
	}

	record_v2_message(ike, &reply_stream,
			  "reply packet for intermediate exchange",
			  MESSAGE_RESPONSE);
	return STF_OK;
}
