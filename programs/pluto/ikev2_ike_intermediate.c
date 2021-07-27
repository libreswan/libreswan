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

static dh_shared_secret_cb process_v2_IKE_INTERMEDIATE_request_no_skeyseed_post_dh_shared;	/* type assertion */

stf_status ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_INTERMEDIATE_I_continue(struct state *ike_st,
											struct msg_digest *mdp)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_st);
	pexpect(ike->sa.st_sa_role == SA_INITIATOR);
	pexpect(v2_msg_role(mdp) == MESSAGE_RESPONSE); /* i.e., MD!=NULL */
	dbg("%s() for #%lu %s: g^{xy} calculated, sending INTERMEDIATE",
	    __func__, ike->sa.st_serialno, ike->sa.st_state->name);

	if (ike->sa.st_dh_shared_secret == NULL) {
		/*
		 * XXX: this is the initiator so returning a
		 * notification is kind of useless.
		 */
		pstat_sa_failed(&ike->sa, REASON_CRYPTO_FAILED);
		return STF_FAIL;
	}

	calc_v2_keymat(&ike->sa, NULL, NULL, /*previous keymat*/
		       &ike->sa.st_ike_rekey_spis);

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
	rehash_state(&ike->sa, &mdp->hdr.isa_ike_responder_spi);

	/* beginning of data going out */

	struct v2_payload request;
	if (!open_v2_payload("intermediate exchange request",
			     ike, ike->sa.st_logger,
			     NULL/*request*/, ISAKMP_v2_IKE_INTERMEDIATE,
			     reply_buffer, sizeof(reply_buffer), &request,
			     ENCRYPTED_PAYLOAD)) {
		return STF_INTERNAL_ERROR;
	}

	/* message is empty! */

	if (!close_and_record_v2_payload(&request)) {
		return STF_INTERNAL_ERROR;
	}

	return STF_OK;
}

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

	struct v2_payload response;
	if (!open_v2_payload("intermediate exchange response",
			     ike, ike->sa.st_logger,
			     md/*response*/, ISAKMP_v2_IKE_INTERMEDIATE,
			     reply_buffer, sizeof(reply_buffer), &response,
			     ENCRYPTED_PAYLOAD)) {
		return STF_INTERNAL_ERROR;
	}

	/* empty message */

	if (!close_and_record_v2_payload(&response)) {
		return STF_INTERNAL_ERROR;
	}

	return STF_OK;
}

stf_status process_v2_IKE_INTERMEDIATE_response(struct ike_sa *ike,
						struct child_sa *unused_child UNUSED,
						struct msg_digest *md)
{
	/*
	 * The function below always schedules a dh calculation - even
	 * when it's been peformed earlier (there's something in the
	 * intermediate echange about this?).
	 *
	 * So that things don't pexpect, blow away the old shared secret.
	 */
	dbg("HACK: blow away old shared secret as going to re-compute it");
	release_symkey(__func__, "st_dh_shared_secret", &ike->sa.st_dh_shared_secret);
	struct connection *c = ike->sa.st_connection;

	/*
	 * if this connection has a newer Child SA than this state
	 * this negotiation is not relevant any more.  would this
	 * cover if there are multiple CREATE_CHILD_SA pending on this
	 * IKE negotiation ???
	 *
	 * XXX: this is testing for an IKE SA that's been superseed by
	 * a newer IKE SA (not child).  Suspect this is to handle a
	 * race where the other end brings up the IKE SA first?  For
	 * that case, shouldn't this state have been deleted?
	 *
	 * NOTE: a larger serialno does not mean superseded. crossed
	 * streams could mean the lower serial established later and is
	 * the "newest". Should > be replaced with !=   ?
	 */
	if (c->newest_ipsec_sa > ike->sa.st_serialno) {
		log_state(RC_LOG, &ike->sa,
			  "state superseded by #%lu try=%lu, drop this negotiation",
			  c->newest_ipsec_sa, ike->sa.st_try);
		return STF_FATAL;
	}

	dbg("No KE payload in INTERMEDIATE RESPONSE, not calculating keys, going to AUTH by completing state transition");

	/*
	 * Initiator: check v2N_NAT_DETECTION_DESTINATION_IP or/and
	 * v2N_NAT_DETECTION_SOURCE_IP.
	 *
	 *   2.23.  NAT Traversal
	 *
	 *   The IKE initiator MUST check the NAT_DETECTION_SOURCE_IP
	 *   or NAT_DETECTION_DESTINATION_IP payloads if present, and
	 *   if they do not match the addresses in the outer packet,
	 *   MUST tunnel all future IKE and ESP packets associated
	 *   with this IKE SA over UDP port 4500.
	 *
	 * When detected, float to the NAT port as needed (*ikeport
	 * can't float but already supports NAT).  When the ports
	 * can't support NAT, give up.
	 */

	if (v2_nat_detected(ike, md)) {
		pexpect(ike->sa.hidden_variables.st_nat_traversal & NAT_T_DETECTED);
		if (!v2_natify_initiator_endpoints(ike, HERE)) {
			/* already logged */
			return STF_FATAL;
		}
	}

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
	 * If we seen the intermediate AND we are configured to use
	 * intermediate.
	 *
	 * For now, do only one Intermediate Exchange round and
	 * proceed with IKE_AUTH.
	 */
	submit_dh_shared_secret(&ike->sa, ike->sa.st_gr/*initiator needs responder KE*/,
				ikev2_in_IKE_SA_INIT_R_or_IKE_INTERMEDIATE_R_out_IKE_AUTH_I_continue,
				HERE);
	return STF_SUSPEND;
}
