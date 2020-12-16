/* IKEv2 Session Resumption RFC 5723
 *
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
 */

#include "defs.h"
#include "state.h"
#include "packet.h"
#include "deltatime.h"
#include "id.h"
#include "chunk.h"
#include "log.h"
#include "ikev2.h"
#include "ikev2_resume.h"
#include "crypt_symkey.h"
#include "ikev2_send.h"
#include "timer.h"
#include "ipsec_doi.h"
#include "ikev2_message.h"
#include "ikev1.h"
#include "ikev1_send.h"
#include "demux.h"
#include "vendor.h"
#include "pending.h"
#include "nat_traversal.h"
#include "pluto_x509.h"
#include "crypt_ke.h"

/* HACK ALERT - needed for out_raw() ??? */
#include "ikev1_message.h"

chunk_t st_to_ticket(const struct state *st)
{
	struct ticket_by_val tkt;

	tkt.sr_serialco = st->st_connection->serial_from.co;
	str_id(&st->st_connection->spd.that.id, &tkt.peer_id);

	/* old skeyseed */
	chunk_t sk = chunk_from_symkey("sk_d_old", st->st_skey_d_nss, st->st_logger);
	passert(sk.len <= MAX_SK_d_LEN);
	memcpy(&tkt.sk_d_old, sk.ptr, sk.len);
	tkt.sk_d_old_len = sk.len;
	free_chunk_content(&sk);

	/*Algorithm description*/
	tkt.sr_encr = st->st_oakley.ta_encrypt->common.id[IKEv2_ALG_ID];
	tkt.sr_prf = st->st_oakley.ta_prf->common.id[IKEv2_ALG_ID];
	tkt.sr_integ = st->st_oakley.ta_integ->common.id[IKEv2_ALG_ID];
	tkt.sr_dh = st->st_oakley.ta_dh->common.id[IKEv2_ALG_ID];
	tkt.sr_enc_keylen = st->st_oakley.enckeylen;
	tkt.sr_auth_method = st->st_connection->spd.that.authby;

	/* caller is responsible for freeing this */
	return clone_bytes_as_chunk(&tkt, sizeof(struct ticket_by_val), "IKEv2 ticket_by_val");
}

/* 
 * builds notificaton payload data for ticket_lt_opaque
 */
static chunk_t build_resume_notification(struct state *st, struct logger *logger)
{
	struct ikev2_ticket_lifetime tl;

	/*
	 * RFC 5723 Section 6.2
	 * The lifetime of the ticket sent by the gateway SHOULD be the minimum
	 * of the IKE SA lifetime (per the gateway's local policy) and its re-
	 * authentication time.
	 */
	tl.sr_lifetime = timercmp(&st->st_connection->sa_ike_life_seconds.dt, &st->st_connection->sa_ipsec_life_seconds.dt, <) ?
						deltasecs(st->st_connection->sa_ike_life_seconds) :
						deltasecs(st->st_connection->sa_ipsec_life_seconds);

	chunk_t ticket = st_to_ticket(st);

	/*
	 * Dummy pbs we need for more elegant notification
	 * data construction (using out_struct and et. al.)
	 */
	uint8_t buf[MIN_OUTPUT_UDP_SIZE];
	struct pbs_out resume_pbs = open_pbs_out("entire resume ticket",
				       buf, sizeof(buf), logger);

	if (!out_struct(&tl, &ikev2_ticket_lt_desc, &resume_pbs, NULL))
		return empty_chunk;

	if (!out_raw(ticket.ptr, ticket.len , &resume_pbs, "resume (encrypted) ticket data"))
		return empty_chunk;

	close_output_pbs(&resume_pbs);
	free_chunk_content(&ticket);

	/* please make sure callee frees this chunk */
	return clone_out_pbs_as_chunk(&resume_pbs, "redirect notify data");
}

bool emit_ticket_lt_opaque_notification(struct state *st, pb_stream *pbs)
{
    chunk_t data = build_resume_notification(st, pbs->outs_logger);

	if (data.len == 0) {
		llog(RC_LOG, st->st_logger, "failed to build session resumption ticket - skipping notify payload");
		return false;
	}

	bool ret = emit_v2N_bytes(v2N_TICKET_LT_OPAQUE, data.ptr, data.len, pbs);
	free_chunk_content(&data);
	return ret;
}

bool emit_ticket_opaque_notification(chunk_t ticket, pb_stream *pbs)
{
	if (ticket.len == 0) {
		dbg("failed to find session resumption ticket - skipping notify payload");
		return false;
	}

	bool ret = emit_v2N_bytes(v2N_TICKET_OPAQUE, ticket.ptr, ticket.len, pbs);
	return ret;
}

bool decrypt_ticket(pb_stream *pbs, size_t len, struct ike_sa *ike)
{
	passert(sizeof(struct ticket_by_val) == len);

	struct ticket_by_val temp;
	if (!pbs_in_raw(pbs, &temp, len, "resumption ticket")){
		return false;
	}

	memcpy(ike->sa.st_sk_d_old, temp.sk_d_old, MAX_SK_d_LEN);
	ike->sa.st_sk_d_old_len = temp.sk_d_old_len;
	if (!set_ikev2_accepted_proposal(ike, temp.sr_enc_keylen, temp.sr_encr, temp.sr_prf, temp.sr_integ, temp.sr_dh)) {
		return false;
	}
	return true;
}

/*
 * Note: This is called on whack command ipsec whack --suspend --name <conection_name> 
 */
void suspend_connection(struct connection *c)
{
	dbg("suspending connection '%s' - deleting states", c->name);
	/* terminate connection, but if an instance, don't delete ourselves */
	c->policy &= ~POLICY_UP;
	delete_states_by_connection(c, false, NULL);
}

/*
 *
 ***************************************************************
 *                       SESSION_RESUME_PARENT_OUTI1       *****
 ***************************************************************
 *
 *
 * Initiate an Oakley Main Mode exchange.
 *       HDR, N(TICKET_OPAQUE), Ni   -->
 *
 * Note: this is not called from demux.c, but from ipsecdoi_initiate(),
 *       if initiator possesses ticket. 
 *
 */

static void ikev2_session_resume_outI1_continue(struct state *st, struct msg_digest *md,
						struct dh_local_secret *local_secret,
						chunk_t *nonce);

void ikev2_session_resume_outI1(struct fd *whack_sock,
				       struct connection *c,
				       struct state *predecessor UNUSED,
				       lset_t policy,
				       unsigned long try,
				       const threadtime_t *inception UNUSED,
				       struct xfrm_user_sec_ctx_ike *uctx UNUSED)
{
	const struct finite_state *fs = finite_states[STATE_PARENT_RESUME_I0];
	pexpect(fs->nr_transitions == 1);
	const struct state_v2_microcode *transition = &fs->v2_transitions[0];
	struct ike_sa *ike = new_v2_ike_state(transition, SA_INITIATOR,
					      ike_initiator_spi(), zero_ike_spi,
					      c, policy, try, whack_sock);

	/* set up new state */
	struct state *st = &ike->sa;
	passert(st->st_ike_version == IKEv2);
	passert(st->st_state->kind == STATE_PARENT_RESUME_I0);
	passert(st->st_sa_role == SA_INITIATOR);
	st->st_try = try;
	ike->sa.st_resuming = TRUE;

	submit_ke_and_nonce(&ike->sa, NULL, ikev2_session_resume_outI1_continue, "Session Resume Initiator Nonce Ni");
}

void ikev2_session_resume_outI1_continue(struct state *st, struct msg_digest *md,
					struct dh_local_secret *local_secret,
					chunk_t *nonce)
{
	dbg("%s() for #%lu %s",
	     __func__, st->st_serialno, st->st_state->name);
	pexpect(md == NULL);

	struct ike_sa *ike = pexpect_ike_sa(st);
	pexpect(ike->sa.st_sa_role == SA_INITIATOR);
	pexpect(st->st_state->kind == STATE_PARENT_RESUME_I0);
	
	unpack_nonce(&st->st_ni, r);
	stf_status e = record_v2_IKE_SA_INIT_OR_RESUME_request(ike) ? STF_OK : STF_INTERNAL_ERROR;
	complete_v2_state_transition(st, NULL, e);
}
