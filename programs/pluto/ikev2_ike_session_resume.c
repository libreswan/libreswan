/* IKEv2 Session Resumption RFC 5723
 *
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
 * Copyright (C) 2024 Andrew Cagney
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

#include "ike_alg_encrypt.h"

#include "defs.h"
#include "ikev2_ike_session_resume.h"
#include "state.h"
#include "packet.h"
#include "deltatime.h"
#include "id.h"
#include "chunk.h"
#include "log.h"
#include "ikev2.h"
#include "crypt_prf.h"
#include "crypt_symkey.h"
#include "ikev2_send.h"
#include "timer.h"
#include "ipsec_doi.h"
#include "ikev2_message.h"
#include "ikev1.h"
#include "ikev1_send.h"
#include "demux.h"
#include "pending.h"
#include "nat_traversal.h"
#include "pluto_x509.h"
#include "ikev2_proposals.h"
#include "terminate.h"
#include "crypt_ke.h"
#include "unpack.h"
#include "ikev2_prf.h"
#include "ikev2_states.h"
#include "ikev2_cookie.h"
#include "ikev2_redirect.h"
#include "ikev2_ike_auth.h"
#include "ikev2_nat.h"
#include "ikev2_vendorid.h"
#include "ikev2_parent.h"
#include "pluto_stats.h"
#include "ikev2_ike_sa_init.h"	/* for initiate_v2_IKE_SA_INIT_request() */
#include "crypt_dh.h"
#include "crypt_cipher.h"
#include "instantiate.h"
#include "ikev2_notification.h"
#include "rnd.h"

static bool skeyseed_v2_sr(struct ike_sa *ike,
			   const ike_spis_t *new_spis,
			   where_t where);
static bool record_v2_IKE_SESSION_RESUME_request(struct ike_sa *ike);
static bool emit_v2N_TICKET_OPAQUE(chunk_t ticket, struct pbs_out *pbs);
static bool decrypt_ticket(struct pbs_in pbs, struct ike_sa *ike);

static stf_status process_v2_IKE_SESSION_RESUME_request_continue(struct state *ike_st,
								 struct msg_digest *md,
								 struct dh_local_secret *local_secret,
								 chunk_t *nonce);
stf_status process_v2_IKE_SESSION_RESUME_response_continue(struct state *ike_sa,
							   struct msg_digest *md);

static ke_and_nonce_cb initiate_v2_IKE_SESSION_RESUME_request_continue;	/* type assertion */
static ikev2_state_transition_fn process_v2_IKE_SESSION_RESUME_response_v2N_REDIRECT;
static ikev2_state_transition_fn process_v2_IKE_SESSION_RESUME_request;	/* type assertion */
static ikev2_state_transition_fn process_v2_IKE_SESSION_RESUME_response; /* type assertion */

struct cipher_context *encrypt;
struct cipher_context *decrypt;

/*
 * Ticket that will be serialized and sent to client.
 *
 * A.1.  Example "Ticket by Value" Format
 *
 *  struct {
 *      [authenticated] struct {
 *          octet format_version;    // 1 for this version of the protocol
 *          octet reserved[3];       // sent as 0, ignored by receiver.
 *          octet key_id[8];         // arbitrary byte string
 *          opaque IV[0..255];       // actual length (possibly 0) depends
 *                                   // on the encryption algorithm
 *
 *          [encrypted] struct {
 *              opaque IDi, IDr;     // the full payloads
 *              octet SPIi[8], SPIr[8];
 *              opaque SA;           // the full SAr payload
 *              octet SK_d[0..255];  // actual length depends on SA value
 *              enum ... authentication_method;
 *              int32 expiration;    // an absolute time value, seconds
 *                                   // since Jan. 1, 1970
 *          } ikev2_state;
 *      } protected_part;
 *      opaque MAC[0..255];          // the length (possibly 0) depends
 *                                   // on the integrity algorithm
 *  } ticket;
 */

struct ticket {
	struct {
		unsigned magic; /* use whack_magic() */
	} aad;
	struct {
		/* plus salt+counter */
		uint8_t bytes[8];
	} iv;
	struct {
		struct encrypted {

			so_serial_t sr_serialco;
			id_buf sr_peer_id;

			/* copy of sk_d_old */
			struct {
				uint8_t ptr[255];
				size_t len;
			} sk_d_old;

			/*
			 * All the chosen Algorithm Description as serializable values
			 * (i.e., not pointers).
			 */
			enum ikev2_trans_type_encr sr_encr;
			enum ikev2_trans_type_prf sr_prf;
			enum ikev2_trans_type_integ sr_integ;
			enum ike_trans_type_dh sr_dh;
			unsigned sr_enc_keylen;

			enum keyword_auth sr_auth_method;
		} state;
		uint8_t tag[16];
	} secured;
};

struct session {
	/*
	 * Local IKE SA parameters used to re-animate the
	 * initiating session-revival IKE SA.
	 */
	co_serial_t sr_serialco;
	id_buf peer_id;

	PK11SymKey *sk_d_old;

	enum ikev2_trans_type_encr sr_encr;
	enum ikev2_trans_type_prf sr_prf;
	enum ikev2_trans_type_integ sr_integ;
	enum ike_trans_type_dh sr_dh;
	unsigned sr_enc_keylen;

	enum keyword_auth sr_auth_method;

	/*
	 * time that ticket was received, and peer specified lifetime;
	 * our_expire+server_expire is expiration.
	 */
	monotime_t sr_our_expire;
	deltatime_t sr_server_expire;

	/*
	 * Blob from peer that contains their equivalent and needs to
	 * be sent in the IKE_SESSION_RESUME request so that they can
	 * re-animating their SA.
	 */
	chunk_t ticket;
};

void pfree_session(struct session **session)
{
	if (*session == NULL) {
		return;
	}
	free_chunk_content(&(*session)->ticket);
	symkey_delref(&global_logger, "session.sk_d_old", &(*session)->sk_d_old);
	pfree((*session));
	(*session) = NULL;
}

void jam_session(struct jambuf *buf, const struct session *session)
{
	jam_string(buf, "ticket: ");
	if (session == NULL) {
		jam_string(buf, "none");
	} else {
		jam(buf, "%zu bytes", session->ticket.len);
		jam_string(buf, " expires: ");
		monotime_t expire =
			monotime_add(session->sr_our_expire,
				     session->sr_server_expire);
		jam_monotime(buf, expire);
	}
}

static bool ike_to_ticket(const struct ike_sa *ike,
			  struct ticket *ticket)
{
	zero(ticket);

	ticket->aad.magic = whack_magic(),

	ticket->secured.state.sr_serialco = ike->sa.st_connection->serialno;
	str_id(&ike->sa.st_connection->local->host.id, &ticket->secured.state.sr_peer_id);

	/* old skeyseed */
	chunk_t sk = chunk_from_symkey("sk_d_old", ike->sa.st_skey_d_nss, ike->sa.logger);
	PASSERT(ike->sa.logger, sk.len <= elemsof(ticket->secured.state.sk_d_old.ptr/*array*/));
	memcpy(ticket->secured.state.sk_d_old.ptr, sk.ptr, sk.len);
	ticket->secured.state.sk_d_old.len = sk.len;
	free_chunk_content(&sk);

	/*Algorithm description*/
#define ID(ALG) ((ALG) != NULL ? (ALG)->common.ikev2_alg_id : 0);
	ticket->secured.state.sr_encr = ID(ike->sa.st_oakley.ta_encrypt);
	ticket->secured.state.sr_prf = ID(ike->sa.st_oakley.ta_prf);
	ticket->secured.state.sr_integ = ID(ike->sa.st_oakley.ta_integ);
	ticket->secured.state.sr_dh = ID(ike->sa.st_oakley.ta_dh);
#undef ID

	ticket->secured.state.sr_enc_keylen = ike->sa.st_oakley.enckeylen;

	ticket->secured.state.sr_auth_method = ike->sa.st_connection->local->config->host.auth;

	if (!cipher_context_op_aead(encrypt,
				    THING_AS_CHUNK(ticket->iv),
				    THING_AS_SHUNK(ticket->aad),
				    THING_AS_CHUNK(ticket->secured),
				    /*text-size*/sizeof(ticket->secured.state),
				    /*tag-size*/sizeof(ticket->secured.tag),
				    ike->sa.logger)) {
		llog(RC_LOG, ike->sa.logger, "crypto failed");
		return false;
	}

	return true;
}

/*
 * Emit IKEv2 Notify TICKET_OPAQUE payload.
 *
 * @param *ticket chunk_t stored encrypted ticket chunk at the client
 * side @param pbs output stream
 */

bool emit_v2N_TICKET_LT_OPAQUE(struct ike_sa *ike, struct pbs_out *pbs)
{
	struct connection *c = ike->sa.st_connection;

	/*
	 * RFC 5723 Section 6.2
	 *
	 * The lifetime of the ticket sent by the gateway SHOULD be
	 * the minimum of the IKE SA lifetime (per the gateway's local
	 * policy) and its re- authentication time.
	 */
	deltatime_t lifetime =
		(deltatime_cmp(c->config->sa_ike_max_lifetime, <, c->config->sa_ipsec_max_lifetime)
		 ? c->config->sa_ike_max_lifetime
		 : c->config->sa_ipsec_max_lifetime);
	struct ikev2_ticket_lifetime tl = {
		.sr_lifetime = deltasecs(lifetime),
	};

	struct ticket ticket;
	if (!ike_to_ticket(ike, &ticket)) {
		llog(RC_LOG, ike->sa.logger, "encryption failed");
		return false;
	}

	struct pbs_out resume_pbs;
	if (!open_v2N_output_pbs(pbs, v2N_TICKET_LT_OPAQUE, &resume_pbs)) {
		return false;
	}

	if (!out_struct(&tl, &ikev2_ticket_lifetime_desc, &resume_pbs, NULL))
		return false;

	if (!pbs_out_thing(&resume_pbs, ticket, "resume (encrypted) ticket data")) {
		return false;
	}

	close_output_pbs(&resume_pbs);

	return true;
}

bool emit_v2N_TICKET_OPAQUE(chunk_t ticket, struct pbs_out *pbs)
{
	if (ticket.len == 0) {
		llog(RC_LOG, pbs->logger,
		     "failed to find session resumption ticket - skipping notify payload");
		return false;
	}

	bool ret = emit_v2N_hunk(v2N_TICKET_OPAQUE, ticket, pbs);
	return ret;
}

bool decrypt_ticket(struct pbs_in pbs, struct ike_sa *ike)
{
	diag_t d;
	struct ticket ticket;

	llog_pexpect(ike->sa.logger, HERE, "the ticket security is not implemented");

	if (pbs_in_left(&pbs).len != sizeof(ticket)) {
		llog(RC_LOG, ike->sa.logger, "invalid ticket: wrong length");
		return false;
	}

	d = pbs_in_thing(&pbs, ticket, "ticket");
	if (d != NULL) {
		llog(RC_LOG, ike->sa.logger, "invalid ticket: %s", str_diag(d));
		pfree_diag(&d);
		return false;
	}

	/* basic sanity check */

	if (ticket.aad.magic != whack_magic()) {
		llog(RC_LOG, ike->sa.logger, "invalid ticket: magic number is wrong");
		return false;
	}

	/* decrypt!?! */

	if (!cipher_context_op_aead(decrypt,
				    THING_AS_CHUNK(ticket.iv),
				    THING_AS_SHUNK(ticket.aad),
				    THING_AS_CHUNK(ticket.secured),
				    /*text-size*/sizeof(ticket.secured.state),
				    /*tag-size*/sizeof(ticket.secured.tag),
				    ike->sa.logger)) {
		llog(RC_LOG, ike->sa.logger, "crypto failed");
		return false;
	}

	if (ticket.secured.state.sk_d_old.len == 0 ||
	    ticket.secured.state.sk_d_old.len > sizeof(ticket.secured.state.sk_d_old.ptr/*array*/)) {
		llog(RC_LOG, ike->sa.logger, "invalid key length %zu",
		     ticket.secured.state.sk_d_old.len);
		return false;
	}

	/* this will be turned into D during IKE_AUTH */
	PASSERT(ike->sa.logger, ike->sa.st_skey_d_nss == NULL);

	ike->sa.st_skey_d_nss = symkey_from_hunk("sk_d_old",
						 ticket.secured.state.sk_d_old,
						 ike->sa.logger);
	if (ike->sa.st_skey_d_nss == NULL) {
		llog(RC_LOG, ike->sa.logger, "failed to re-animate peer's key");
		return false;
	}

	set_ikev2_accepted_proposal(ike,
				    ticket.secured.state.sr_encr,
				    ticket.secured.state.sr_prf,
				    ticket.secured.state.sr_integ,
				    ticket.secured.state.sr_dh,
				    ticket.secured.state.sr_enc_keylen);

	return true;
}

bool record_v2_IKE_SESSION_RESUME_request(struct ike_sa *ike)
{
	struct v2_message request;
	if (!open_v2_message("IKE_SESSION_RESUME request",
			     ike, ike->sa.logger, NULL/*request*/,
			     ISAKMP_v2_IKE_SESSION_RESUME,
			     reply_buffer, sizeof(reply_buffer),
			     &request, UNENCRYPTED_PAYLOAD)) {
		return false;
	}

	/*
	 * https://tools.ietf.org/html/rfc5996#section-2.6
	 * reply with the anti DDOS cookie if we received one (remote is under attack)
	 */
	if (ike->sa.st_dcookie.ptr != NULL) {
		/* In v2, for parent, protoid must be 0 and SPI must be empty */
		if (!emit_v2N_hunk(v2N_COOKIE, ike->sa.st_dcookie, request.pbs)) {
			return false;
		}
	}

	/* send NONCE */
	{
		struct pbs_out pb;
		struct ikev2_generic in = {
			.isag_critical = build_ikev2_critical(false, ike->sa.logger),
		};

		if (!out_struct(&in, &ikev2_nonce_desc, request.pbs, &pb) ||
		    !out_hunk(ike->sa.st_ni, &pb, "IKEv2 nonce"))
			return false;

		close_output_pbs(&pb);
	}

	/* send TICKET_OPAQUE */

    	if (!emit_v2N_TICKET_OPAQUE(ike->sa.st_connection->session->ticket, request.pbs)) {
		return false;
	}

	if (!close_and_record_v2_message(&request)) {
		return false;
	}

	/* save packet for later signing */
	replace_chunk(&ike->sa.st_firstpacket_me,
		      pbs_out_all(&request.message),
		      "saved first packet");

	return true;
}

bool skeyseed_v2_sr(struct ike_sa *ike,
		    const ike_spis_t *new_spis,
		    where_t where)
{
	struct logger *logger = ike->sa.logger;

	PASSERT(logger, ike->sa.st_skey_d_nss != NULL);

	const size_t salt_size = ike->sa.st_oakley.ta_encrypt->salt_size;
	const size_t key_size = ike->sa.st_oakley.enckeylen / BITS_PER_BYTE;

	passert(ike->sa.st_oakley.ta_prf != NULL);
	dbg("calculating skeyseed using prf=%s integ=%s cipherkey-size=%zu salt-size=%zu",
	    ike->sa.st_oakley.ta_prf->common.fqn,
	    (ike->sa.st_oakley.ta_integ ? ike->sa.st_oakley.ta_integ->common.fqn : "n/a"),
	    key_size, salt_size);

	/* old key unpacked by resume */
	pexpect(ike->sa.st_skey_d_nss != NULL);

	PK11SymKey *skeyseed_k =
		ikev2_ike_sa_resume_skeyseed(ike->sa.st_oakley.ta_prf,
					     ike->sa.st_skey_d_nss,
					     ike->sa.st_ni,
					     ike->sa.st_nr,
					     logger);
	if (skeyseed_k == NULL) {
		llog_pexpect(ike->sa.logger, where, "KEYSEED failed");
		return false;
	}

	/* delete the unpacked key so it can be replaced */
	symkey_delref(ike->sa.logger, "session.st_skey_d_nss",
		      &ike->sa.st_skey_d_nss);

	calc_v2_ike_keymat(&ike->sa, skeyseed_k, new_spis);
	symkey_delref(logger, "skeyseed_k", &skeyseed_k);
	return true;
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

struct ike_sa *initiate_v2_IKE_SESSION_RESUME_request(struct connection *c,
						      const struct child_policy *policy,
						      const threadtime_t *inception,
						      shunk_t sec_label UNUSED,
						      bool detach_whack)
{
	monotime_t expire = monotime_add(c->session->sr_our_expire,
					 c->session->sr_server_expire);
	if (monotime_cmp(expire, <,  mononow())) {
		monotime_buf mb;
		llog(RC_LOG, c->logger, "ticket expired %s, dropping it",
		     str_monotime(expire, &mb));
		pfree_session(&c->session);
		return initiate_v2_IKE_SA_INIT_request(c, NULL, policy,
						       inception, sec_label,
						       detach_whack);
	}

	struct ike_sa *ike = new_v2_ike_sa_initiator(c);
	if (ike == NULL) {
		return NULL;
	}

	ike->sa.st_resuming = true;

	if (has_child_policy(policy)) {
		struct connection *cc;
		if (is_labeled(c)) {
			PEXPECT(ike->sa.logger, is_labeled_parent(c));
			PEXPECT(ike->sa.logger, c == ike->sa.st_connection);
			cc = labeled_parent_instantiate(ike, sec_label, HERE);
		} else {
			cc = connection_addref(c, ike->sa.logger);
		}
		append_pending(ike, cc, policy,
			       SOS_NOBODY,
			       sec_label, true/*part of initiate*/, detach_whack);
		connection_delref(&cc, ike->sa.logger);
	}

	start_v2_exchange(ike, &v2_IKE_SESSION_RESUME_exchange, HERE);

	statetime_t start = statetime_backdate(&ike->sa, inception);

	submit_ke_and_nonce(/*callback*/&ike->sa, /*task*/&ike->sa,
			    /*initiator:no-md*/NULL,
			    /*NO KE*/NULL,
			    initiate_v2_IKE_SESSION_RESUME_request_continue,
			    detach_whack, HERE);

	statetime_stop(&start, "%s()", __func__);
	return ike;
}

stf_status initiate_v2_IKE_SESSION_RESUME_request_continue(struct state *ike_sa,
							   struct msg_digest *md UNUSED,
							   struct dh_local_secret *local_secret,
							   chunk_t *nonce/*steal*/)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	PASSERT(ike->sa.logger, md == NULL); /* initiator */
	ldbg(ike->sa.logger, "%s() for #%lu %s",
	     __func__, ike->sa.st_serialno, ike->sa.st_state->name);

	PASSERT(ike->sa.logger, local_secret == NULL);
	unpack_nonce(&ike->sa.st_ni, nonce);

	return record_v2_IKE_SESSION_RESUME_request(ike) ? STF_OK : STF_INTERNAL_ERROR;
}

stf_status process_v2_IKE_SESSION_RESUME_request(struct ike_sa *ike,
						 struct child_sa *child,
						 struct msg_digest *md)
{
	/*
	 * This log line establishes that resources (such as the state
	 * structure) have been allocated and the packet is being
	 * processed for real.
	 */
	llog_msg_digest(RC_LOG, ike->sa.logger, "processing", md);

	pexpect(child == NULL);
	/* set up new state */
	update_ike_endpoints(ike, md);
	passert(ike->sa.st_ike_version == IKEv2);
	passert(ike->sa.st_state == &state_v2_UNSECURED_R);
	passert(ike->sa.st_sa_role == SA_RESPONDER);

	ike->sa.st_resuming = true;

	/* the transition requires this notify! */
	if (PBAD(ike->sa.logger, md->pd[PD_v2N_TICKET_OPAQUE] == NULL)) {
		return STF_FATAL;
	}

	struct pbs_in pbs = md->pd[PD_v2N_TICKET_OPAQUE]->pbs;
	if(!decrypt_ticket(pbs, ike)) {
		return STF_FATAL;
	}

	/*
	 * Convert what was accepted to internal form and apply some
	 * basic validation.  If this somehow fails (it shouldn't but
	 * ...), drop everything.
	 */
	if (!ikev2_proposal_to_trans_attrs(ike->sa.st_v2_accepted_proposal,
					   &ike->sa.st_oakley, ike->sa.logger)) {
		llog_sa(RC_LOG, ike, "IKE responder accepted an unsupported algorithm");
		/* STF_INTERNAL_ERROR doesn't delete ST */
		return STF_FATAL;
	}

	/* Ni in */

	if (!accept_v2_nonce(ike->sa.logger, md, &ike->sa.st_ni, "Ni")) {
		/*
		 * Presumably not our fault.  Syntax errors kill the
		 * family, hence FATAL.
		 */
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_INVALID_SYNTAX, NULL/*no-data*/,
				    UNENCRYPTED_PAYLOAD);
		return STF_FATAL;
	}

	/* calculate the nonce and the KE */
	submit_ke_and_nonce(/*callback*/&ike->sa, /*task*/&ike->sa, md,
			    /*NO KE*/NULL,
			    process_v2_IKE_SESSION_RESUME_request_continue,
			    /*detach_whack*/false, HERE);
	return STF_SUSPEND;
}

stf_status process_v2_IKE_SESSION_RESUME_request_continue(struct state *ike_st,
							  struct msg_digest *md,
							  struct dh_local_secret *local_secret,
							  chunk_t *nonce)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_st);
	pexpect(ike->sa.st_sa_role == SA_RESPONDER);
	pexpect(v2_msg_role(md) == MESSAGE_REQUEST); /* i.e., MD!=NULL */
	pexpect(ike->sa.st_state == &state_v2_UNSECURED_R);
	dbg("%s() for #%lu %s: calculated ke+nonce, sending R1",
	    __func__, ike->sa.st_serialno, ike->sa.st_state->name);

	/* Nr generated */

	PEXPECT(ike->sa.logger, local_secret == NULL);
	unpack_nonce(&ike->sa.st_nr, nonce);

	/*
	 * On the responder, the IKE SA is created with pre-populated
	 * SPIs.
	 */

	pexpect(!ike_spi_is_zero(&ike->sa.st_ike_spis.responder));
	pexpect(!ike_spi_is_zero(&ike->sa.st_ike_spis.initiator));

	if (!skeyseed_v2_sr(ike, &ike->sa.st_ike_spis, HERE)) {
		return STF_FATAL;
	}

	/* hoot! */

	passert(ike->sa.hidden_variables.st_skeyid_calculated);

	/* Record first packet for later checking of signature.  */
	record_first_v2_packet(ike, md, HERE);

	/* make sure HDR is at start of a clean buffer */

	struct v2_message response;
	if (!open_v2_message("IKE_SA_INIT response",
			     ike, ike->sa.logger, md/*response*/,
			     ISAKMP_v2_IKE_SESSION_RESUME,
			     reply_buffer, sizeof(reply_buffer),
			     &response, UNENCRYPTED_PAYLOAD)) {
		return STF_INTERNAL_ERROR;
	}

	/* start of SA out */

	/* send NONCE */

	{
		struct pbs_out pb;
		struct ikev2_generic in = {
			.isag_critical = build_ikev2_critical(false, ike->sa.logger),
		};

		if (!out_struct(&in, &ikev2_nonce_desc, response.pbs, &pb) ||
		    !out_hunk(ike->sa.st_nr, &pb, "IKEv2 nonce"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&pb);
	}

	if (!close_and_record_v2_message(&response)) {
		return STF_INTERNAL_ERROR;
	}

	/* save packet for later signing */
	replace_chunk(&ike->sa.st_firstpacket_me,
		      pbs_out_all(&response.message),
		      "saved first packet");

	return STF_OK;
}

stf_status process_v2_IKE_SESSION_RESUME_response_v2N_REDIRECT(struct ike_sa *ike,
							       struct child_sa *child,
							       struct msg_digest *md)
{
	/* dropping the ticket */
	pfree_session(&ike->sa.st_connection->session);
	return process_v2_IKE_SA_INIT_response_v2N_REDIRECT(ike, child, md);
}

stf_status process_v2_IKE_SESSION_RESUME_response(struct ike_sa *ike,
						  struct child_sa *unused_child UNUSED,
						  struct msg_digest *md)
{
	struct connection *c = ike->sa.st_connection;

	/* for testing only */
	if (impair.send_no_ikev2_auth) {
		llog_sa(RC_LOG, ike,
			  "IMPAIR_SEND_NO_IKEV2_AUTH set - not sending IKE_AUTH packet");
		return STF_IGNORE;
	}

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

	/* Nr in */

	if (!accept_v2_nonce(ike->sa.logger, md, &ike->sa.st_nr, "Nr")) {
		/*
		 * Presumably not our fault.  Syntax errors in a
		 * response kill the family (and trigger no further
		 * exchange).
		 *
		 * STF_FATAL will send the code down the retry path.
		 */
		return STF_FATAL;
	}

	/* process and confirm the SA selected */

	set_ikev2_accepted_proposal(ike,
				    c->session->sr_encr,
				    c->session->sr_prf,
				    c->session->sr_integ,
				    c->session->sr_dh,
				    c->session->sr_enc_keylen);

	if (!ikev2_proposal_to_trans_attrs(ike->sa.st_v2_accepted_proposal,
					   &ike->sa.st_oakley, ike->sa.logger)) {
		llog_sa(RC_LOG, ike,
			"IKE initiator proposed an unsupported algorithm");
		free_ikev2_proposal(&ike->sa.st_v2_accepted_proposal);
		passert(ike->sa.st_v2_accepted_proposal == NULL);
		/*
		 * Assume caller et.al. will clean up the
		 * reset of the mess?
		 *
		 * STF_FATAL will send the code down the retry path.
		 */
		return STF_FATAL;
	}

	/*
	 * Initiate the calculation of g^xy.
	 */

	ldbg(ike->sa.logger, "recovering saved D");

	PASSERT(ike->sa.logger, ike->sa.st_skey_d_nss == NULL);
	ike->sa.st_skey_d_nss = symkey_addref(ike->sa.logger,
					      "session.sk_d_old",
					      ike->sa.st_connection->session->sk_d_old);
	if (ike->sa.st_skey_d_nss == NULL) {
		llog(RC_LOG, ike->sa.logger, "symkey_from_hunk() failed");
		return STF_FATAL;
	}

	/*
	 * Form and pass in the full SPI[ir] that will eventually be
	 * used by this IKE SA.  Only once DH has been computed and
	 * the SA is secure (but not authenticated) should the state's
	 * IKE SPIr be updated.
	 */

	pexpect(ike_spi_is_zero(&ike->sa.st_ike_spis.responder));
	ike->sa.st_ike_rekey_spis = (ike_spis_t) {
		.initiator = ike->sa.st_ike_spis.initiator,
		.responder = md->hdr.isa_ike_responder_spi,
	};

	if (!skeyseed_v2_sr(ike, &ike->sa.st_ike_rekey_spis, HERE)){
		return STF_FATAL;
	}

	/* done with the local session */

	pfree_session(&ike->sa.st_connection->session);

	/*
	 * All systems are go.
	 *
	 * Since DH succeeded, a secure (but unauthenticated) SA
	 * (channel) is available.  From this point on, should things
	 * go south, the state needs to be abandoned (but it shouldn't
	 * happen).
	 */

	/* Record first packet for later checking of signature.  */
	record_first_v2_packet(ike, md, HERE);

	/*
	 * Since systems are go, start updating the state, starting
	 * with SPIr.
	 */
	update_st_ike_spis_responder(ike, &md->hdr.isa_ike_responder_spi);

	return next_v2_exchange(ike, md, &v2_IKE_AUTH_exchange, HERE);
}

bool process_v2N_TICKET_LT_OPAQUE(struct ike_sa *ike,
				  const struct payload_digest *pd)
{
	struct pbs_in pbs = pd->pbs;

	struct ikev2_ticket_lifetime tl;
	diag_t d = pbs_in_struct(&pbs, &ikev2_ticket_lifetime_desc,
				 &tl, sizeof(tl), NULL);
	if (d != NULL) {
		llog(RC_LOG, ike->sa.logger, "received malformed TICKET_LT_OPAQUE payload: %s",
		     str_diag(d));
		pfree_diag(&d);
		return false;
	}

	llog(RC_LOG, ike->sa.logger, "received v2N_TICKET_LT_OPAQUE");

	shunk_t ticket = pbs_in_left(&pbs);

	struct connection *c = ike->sa.st_connection;
	PASSERT(ike->sa.logger, c->session == NULL);

	c->session = alloc_thing(struct session, __func__);
	c->session->sr_our_expire = mononow();
	c->session->sr_server_expire = deltatime(tl.sr_lifetime);
	c->session->ticket = clone_hunk(ticket, __func__);

	c->session->sr_serialco = c->serialno;
	str_id(&c->local->host.id, &c->session->peer_id);
	c->session->sk_d_old = symkey_addref(ike->sa.logger,
					     "session.sk_d_old",
					     ike->sa.st_skey_d_nss);

#define ID(ALG) (ike->sa.st_oakley.ALG == NULL ? 0 :		\
		 ike->sa.st_oakley.ALG->common.ikev2_alg_id)
	c->session->sr_encr = ID(ta_encrypt);
	c->session->sr_prf = ID(ta_prf);
	c->session->sr_dh = ID(ta_dh);
	c->session->sr_integ = ID(ta_integ);
#undef ID
	c->session->sr_enc_keylen = ike->sa.st_oakley.enckeylen;

	c->session->sr_auth_method = c->remote->config->host.auth;
	return true;
}


static const struct v2_transition v2_IKE_SESSION_RESUME_initiate_transition = {
	.story      = "initiating IKE_SESSION_RESUME",
	.to = &state_v2_IKE_SESSION_RESUME_I,
	.exchange   = ISAKMP_v2_IKE_SESSION_RESUME,
	.processor  = NULL, /* XXX: should be set */
	.llog_success = llog_v2_success_exchange_sent_to,
	.timeout_event = EVENT_v2_RETRANSMIT,
};

static const struct v2_transition v2_IKE_SESSION_RESUME_responder_transition[] = {
	{ .story      = "Respond to IKE_SESSION_RESUME",
	  .to = &state_v2_IKE_SESSION_RESUME_R,
	  .exchange   = ISAKMP_v2_IKE_SESSION_RESUME,
	  .recv_role  = MESSAGE_REQUEST,
	  .message_payloads.required = v2P(Ni) | v2P(N),
	  .message_payloads.notification = v2N_TICKET_OPAQUE,
	  .processor  = process_v2_IKE_SESSION_RESUME_request,
	  .llog_success = llog_v2_success_exchange_processed,
	  .timeout_event = EVENT_v2_DISCARD, },
};

static const struct v2_transition v2_IKE_SESSION_RESUME_response_transition[] = {

	{ .story      = "received anti-DDOS COOKIE notify response; resending IKE_SESSION_RESUME request with cookie payload added",
	  .to = &state_v2_IKE_SESSION_RESUME_I0,
	  .exchange   = ISAKMP_v2_IKE_SESSION_RESUME,
	  .recv_role  = MESSAGE_RESPONSE,
	  .message_payloads = { .required = v2P(N), .notification = v2N_COOKIE, },
	  .processor  = process_v2_IKE_SESSION_RESUME_response_v2N_COOKIE,
	  .llog_success = llog_v2_success_exchange_processed,
	  .timeout_event = EVENT_v2_DISCARD, },

	{ .story      = "received REDIRECT notify response; aborting resumption and start IKE_SA_INIT request to new destination",
	  .to = &state_v2_IKE_SESSION_RESUME_I0, /* XXX: never happens STF_SUSPEND */
	  .exchange   = ISAKMP_v2_IKE_SESSION_RESUME,
	  .recv_role  = MESSAGE_RESPONSE,
	  .message_payloads = { .required = v2P(N), .notification = v2N_REDIRECT, },
	  .processor  = process_v2_IKE_SESSION_RESUME_response_v2N_REDIRECT,
	  .llog_success = llog_v2_success_exchange_processed,
	  .timeout_event = EVENT_v2_DISCARD,
	},

	{ .story      = "Initiator: process incoming Session Resume Packet from Responder, initiate IKE_AUTH",
	  .to = &state_v2_IKE_SESSION_RESUME_IR,
	  .exchange   = ISAKMP_v2_IKE_SESSION_RESUME,
	  .recv_role  = MESSAGE_RESPONSE,
	  .message_payloads.required = v2P(Nr),
	  .processor  = process_v2_IKE_SESSION_RESUME_response,
	  .llog_success = llog_v2_success_exchange_processed,
	  .timeout_event = EVENT_v2_DISCARD, /* timeout set by next transition */
	},

};

V2_STATE(IKE_SESSION_RESUME_I0, "waiting for KE to finish", CAT_IGNORE, /*secured*/false);

V2_STATE(IKE_SESSION_RESUME_R0, "processing IKE_SESSION_RESUME request",
	 CAT_HALF_OPEN_IKE_SA, /*secured*/false,
	 &v2_IKE_SESSION_RESUME_exchange);

V2_STATE(IKE_SESSION_RESUME_R,
	 "sent IKE_SESSION_RESUME response, waiting for IKE_AUTH request",
	 CAT_HALF_OPEN_IKE_SA, /*secured*/true,
	 &v2_IKE_AUTH_exchange);

V2_EXCHANGE(IKE_SESSION_RESUME, "initiate IKE SESSION RESUME",
	    ", preparing IKE_AUTH request",
	    CAT_HALF_OPEN_IKE_SA, CAT_OPEN_IKE_SA, /*secured*/false);

void init_ike_session_resume(struct logger *logger)
{
	PK11SlotInfo *slot = PK11_GetBestSlot(CKM_AES_KEY_GEN,
					      lsw_nss_get_password_context(logger));
	PK11SymKey *symkey = PK11_KeyGen(slot, CKM_AES_KEY_GEN, NULL, 128/8, NULL);
	dbg_alloc("symkey", symkey, HERE);
	uint32_t salt = get_rnd_uintmax();
	encrypt = cipher_context_create(&ike_alg_encrypt_aes_gcm_16,
					ENCRYPT,
					FILL_WIRE_IV,
					symkey,
					THING_AS_SHUNK(salt),
					logger);
	decrypt = cipher_context_create(&ike_alg_encrypt_aes_gcm_16,
					DECRYPT,
					USE_WIRE_IV,
					symkey,
					THING_AS_SHUNK(salt),
					logger);
	symkey_delref(logger, "symkey", &symkey);
}

void shutdown_ike_session_resume(struct logger *logger)
{
	cipher_context_destroy(&encrypt, logger);
	cipher_context_destroy(&decrypt, logger);
}
