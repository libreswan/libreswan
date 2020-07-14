/* IKEv2 packet send routines, for Libreswan
 *
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Sahana Prasad <sahana.prasad07@gmail.com>
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

#include "send.h"
#include "ikev2_send.h"
#include "ikev2_message.h"
#include "server.h"
#include "state.h"
#include "connections.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "pluto_stats.h"
#include "demux.h"	/* for struct msg_digest */
#include "rnd.h"
#include "log.h"

bool send_recorded_v2_message(struct ike_sa *ike,
			      const char *where,
			      enum message_role message)
{
	struct v2_outgoing_fragment *frags = ike->sa.st_v2_outgoing[message];
	if (ike->sa.st_interface == NULL) {
		log_state(RC_LOG, &ike->sa, "cannot send packet - interface vanished!");
		return false;
	}
	if (frags == NULL) {
		log_state(RC_LOG, &ike->sa, "no %s message to send", where);
		return false;
	}

	unsigned nr_frags = 0;
	for (struct v2_outgoing_fragment *frag = frags;
	     frag != NULL; frag = frag->next) {
		nr_frags++;
		if (!send_hunk_using_state(&ike->sa, where, *frag)) {
			dbg("send of %s fragment %u failed", where, nr_frags);
			return false;
		}
	}
	dbg("sent %u messages", nr_frags);
	return true;
}

void record_v2_outgoing_fragment(struct pbs_out *pbs,
				 const char *what,
				 struct v2_outgoing_fragment **frags)
{
	pexpect(*frags == NULL);
	chunk_t frag = same_out_pbs_as_chunk(pbs);
	*frags = alloc_bytes(sizeof(struct v2_outgoing_fragment) + frag.len, what);
	(*frags)->len = frag.len;
	memcpy((*frags)->ptr/*array*/, frag.ptr, frag.len);
}

void record_v2_message(struct ike_sa *ike,
		       struct pbs_out *msg,
		       const char *what,
		       enum message_role message)
{
	struct v2_outgoing_fragment **frags = &ike->sa.st_v2_outgoing[message];
	free_v2_outgoing_fragments(frags);
	record_v2_outgoing_fragment(msg, what, frags);
}

/*
 * Send a payload.
 */

bool emit_v2UNKNOWN(const char *victim, enum isakmp_xchg_types exchange_type,
		    struct pbs_out *outs)
{
	log_pbs_out(RC_LOG, outs,
		    "IMPAIR: adding an unknown%s payload of type %d to %s %s",
		    impair.unknown_v2_payload_critical ? " critical" : "",
		    ikev2_unknown_payload_desc.pt,
		    enum_short_name(&ikev2_exchange_names, exchange_type),
		    victim);
	struct ikev2_generic gen = {
		.isag_critical = build_ikev2_critical(impair.unknown_v2_payload_critical),
	};
	struct pbs_out pbs;
	if (!pbs_out_struct(outs, &gen, sizeof(gen), &ikev2_unknown_payload_desc, &pbs)) {
		return false;
	}
	close_output_pbs(&pbs);
	return true;
}

/*
 * Send the STRING out as a V2 Vendor payload.
 *
 * XXX: Perhaps someday STRING will be replaced by enum
 * known_vendorid.
 */
bool emit_v2V(const char *string, pb_stream *outs)
{
	struct ikev2_generic gen = {
		.isag_np = 0,
	};
	struct pbs_out pbs;
	if (!pbs_out_struct(outs, &gen, sizeof(gen), &ikev2_vendor_id_desc, &pbs)) {
		return false;
	}
	if (!out_raw(string, strlen(string), &pbs, string)) {
		return false;
	}
	close_output_pbs(&pbs);
	return true;
}

/*
 * ship_v2N: add notify payload to the rbody
 * (See also specialized versions ship_v2Nsp and ship_v2Ns.)
 *
 * - RFC 7296 3.10 "Notify Payload" says:
 *
 * o  Protocol ID (1 octet) - If this notification concerns an existing
 *    SA whose SPI is given in the SPI field, this field indicates the
 *    type of that SA.  For notifications concerning Child SAs, this
 *    field MUST contain either (2) to indicate AH or (3) to indicate
 *    ESP.  Of the notifications defined in this document, the SPI is
 *    included only with INVALID_SELECTORS, REKEY_SA, and
 *    CHILD_SA_NOT_FOUND.  If the SPI field is empty, this field MUST be
 *    sent as zero and MUST be ignored on receipt.
 *
 * o  SPI Size (1 octet) - Length in octets of the SPI as defined by the
 *    IPsec protocol ID or zero if no SPI is applicable.  For a
 *    notification concerning the IKE SA, the SPI Size MUST be zero and
 *    the field must be empty.
 *
 *    Since all IKEv2 implementations MUST implement the NOTIFY type
 *    payload, these payloads NEVER have the Critical Flag set.
 */


/* emit a v2 Notification payload, with optional SA and optional sub-payload */
bool emit_v2Nsa_pl(v2_notification_t ntype,
		enum ikev2_sec_proto_id protoid,
		const ipsec_spi_t *spi, /* optional */
		pb_stream *outs,
		pb_stream *payload_pbs /* optional */)
{
	/* See RFC 5996 section 3.10 "Notify Payload" */
	passert(protoid == PROTO_v2_RESERVED || protoid == PROTO_v2_AH || protoid == PROTO_v2_ESP);

	switch (ntype) {
	case v2N_INVALID_SELECTORS:
	case v2N_REKEY_SA:
	case v2N_CHILD_SA_NOT_FOUND:
		if (protoid == PROTO_v2_RESERVED || spi == NULL) {
			dbg("XXX: type requires SA; missing");
		}
		break;
	default:
		if (protoid != PROTO_v2_RESERVED || spi != NULL) {
			dbg("XXX: type forbids SA but SA present");
		}
		break;
	}

	dbg("adding a v2N Payload");

	struct ikev2_notify n = {
		.isan_critical = build_ikev2_critical(false),
		.isan_protoid = protoid,
		.isan_spisize = spi != NULL ? sizeof(*spi) : 0,
		.isan_type = ntype,
	};

	pb_stream pls;

	if (!out_struct(&n, &ikev2_notify_desc, outs, &pls) ||
	    (spi != NULL && !out_raw(spi, sizeof(*spi), &pls, "SPI"))) {
		return false;
	}

	if (payload_pbs == NULL)
		close_output_pbs(&pls);
	else
		*payload_pbs = pls;
	return true;
}

/* emit a v2 Notification payload, with optional sub-payload */
bool emit_v2Npl(v2_notification_t ntype,
		pb_stream *outs,
		pb_stream *payload_pbs /* optional */)
{
	return emit_v2Nsa_pl(ntype, PROTO_v2_RESERVED, NULL, outs, payload_pbs);
}

/* emit a v2 Notification payload, with bytes as sub-payload */
bool emit_v2N_bytes(v2_notification_t ntype,
		    const void *bytes, size_t size, /* optional */
		    pb_stream *outs)
{
	pb_stream pl;
	if (!emit_v2Npl(ntype, outs, &pl)) {
		return false;
	}

	/* for some reason out_raw() doesn't like size==0 */
	if (size > 0 && !out_raw(bytes, size, &pl, "Notify data")) {
		return false;
	}

	close_output_pbs(&pl);
	return true;
}

/* output a v2 simple Notification payload */
bool emit_v2N(v2_notification_t ntype,
	       pb_stream *outs)
{
	return emit_v2Npl(ntype, outs, NULL);
}

bool emit_v2N_signature_hash_algorithms(lset_t sighash_policy,
					pb_stream *outs)
{
	pb_stream n_pbs;

	if (!emit_v2Npl(v2N_SIGNATURE_HASH_ALGORITHMS, outs, &n_pbs)) {
		libreswan_log("error initializing notify payload for notify message");
		return false;
	}

#define H(POLICY, ID)							\
	if (sighash_policy & POLICY) {					\
		uint16_t hash_id = htons(ID);				\
		passert(sizeof(hash_id) == RFC_7427_HASH_ALGORITHM_IDENTIFIER_SIZE); \
		if (!out_raw(&hash_id, sizeof(hash_id), &n_pbs,		\
			     "hash algorithm identifier "#ID)) {	\
			return false;					\
		}							\
	}
	H(POL_SIGHASH_SHA2_256, IKEv2_HASH_ALGORITHM_SHA2_256);
	H(POL_SIGHASH_SHA2_384, IKEv2_HASH_ALGORITHM_SHA2_384);
	H(POL_SIGHASH_SHA2_512, IKEv2_HASH_ALGORITHM_SHA2_512);
#undef H

	close_output_pbs(&n_pbs);
	return true;
}

/*
 *
 ***************************************************************
 *                       NOTIFICATION_OUT Complete packet  *****
 ***************************************************************
 *
 */

/*
 * This short/sharp notification is always tied to the IKE SA.
 *
 * For a CREATE_CHILD_SA, things have presumably screwed up so badly
 * that the larval child state is about to be deleted.
 *
 * XXX: suspect calls to this function should be replaced by something
 * like record_v2N_spi_response_from_state() - so that the response is
 * always saved in the state and re-transmits can be handled
 * correctly.
 */

struct response {
	/* CONTAINS POINTERS; pass by ref */
	struct pbs_out message;
	struct pbs_out body;
	enum payload_security security;
	struct logger *logger;
	v2SK_payload_t sk;
	struct pbs_out *pbs; /* where to put message (POINTER!) */
};

static bool open_response(struct response *response,
			  struct logger *logger,
			  uint8_t *buf, size_t sizeof_buf,
			  struct ike_sa *ike,
			  struct msg_digest *md,
			  enum payload_security security)
{
	*response = (struct response) {
		.message = open_pbs_out("message response", buf, sizeof_buf, logger),
		.logger = logger,
		.security = security,
	};

	/*
	 * Never send a response to a response.
	 */
	if (!pexpect(v2_msg_role(md) == MESSAGE_REQUEST)) {
		/* always responding */
		return false;
	}

	response->body = open_v2_message(&response->message, ike,
					 md /* response */,
					 md->hdr.isa_xchg/* same exchange type */);
	if (!pbs_ok(&response->body)) {
		log_message(RC_LOG, response->logger,
			    "error initializing hdr for encrypted notification");
		return false;
	}

	switch (security) {
	case ENCRYPTED_PAYLOAD:
		/* never encrypt an IKE_SA_INIT exchange */
		if (md->hdr.isa_xchg == ISAKMP_v2_IKE_SA_INIT) {
			LOG_PEXPECT("exchange type IKE_SA_INIT is invalid for encrypted notification");
			return false;
		}
		/* check things are at least protected */
		if (!pexpect(ike->sa.hidden_variables.st_skeyid_calculated)) {
			return false;
		}
		response->sk = open_v2SK_payload(logger, &response->body, ike);
		if (!pbs_ok(&response->sk.pbs)) {
			return false;
		}
		response->pbs = &response->sk.pbs;
		break;
	case UNENCRYPTED_PAYLOAD:
		/* unsecured payload when secured allowed? */
		pexpect(!ike->sa.hidden_variables.st_skeyid_calculated);
		response->pbs = &response->body;
		break;
	}
	return true;
}

static bool close_response(struct response *response)
{
	switch (response->security) {
	case ENCRYPTED_PAYLOAD:
		if (!close_v2SK_payload(&response->sk)) {
			return false;
		}
		close_output_pbs(&response->body);
		close_output_pbs(&response->message);
		stf_status ret = encrypt_v2SK_payload(&response->sk);
		if (ret != STF_OK) {
			log_message(RC_LOG, response->logger,
				    "error encrypting response");
			return false;
		}
		break;
	case UNENCRYPTED_PAYLOAD:
		close_output_pbs(&response->body);
		close_output_pbs(&response->message);
		break;
	}
	return true;
}

static bool emit_v2N_spi_response(struct response *response,
				  struct ike_sa *ike,
				  struct msg_digest *md,
				  enum ikev2_sec_proto_id protoid,
				  ipsec_spi_t *spi,
				  v2_notification_t ntype,
				  const chunk_t *ndata /* optional */)
{
	const char *const notify_name = enum_short_name(&ikev2_notify_names, ntype);

	enum isakmp_xchg_types exchange_type = md->hdr.isa_xchg;
	const char *const exchange_name = enum_short_name(&ikev2_exchange_names, exchange_type);

	/*
	 * XXX: this will prefix with cur_state.  For this code path
	 * is it ever different to the IKE SA?
	 */
	endpoint_buf b;
	log_message(RC_NOTIFICATION+ntype, response->logger,
		    "responding to %s message (ID %u) from %s with %s notification %s",
		    exchange_name, md->hdr.isa_msgid,
		    str_sensitive_endpoint(&ike->sa.st_remote_endpoint, &b),
		    response->security == ENCRYPTED_PAYLOAD ? "encrypted" : "unencrypted",
		    notify_name);

	/* actual data */

	/*
	 * 3.10.  Notify Payload: Of the notifications defined in this
	 * document, the SPI is included only with INVALID_SELECTORS,
	 * REKEY_SA, and CHILD_SA_NOT_FOUND.
	*/
	switch (ntype) {
	case v2N_INVALID_SELECTORS:
		/*
		 * MAY be sent in an IKE INFORMATIONAL exchange when a
		 * node receives an ESP or AH packet whose selectors
		 * do not match those of the SA on which it was
		 * delivered (and that caused the packet to be
		 * dropped).  The Notification Data contains the start
		 * of the offending packet (as in ICMP messages) and
		 * the SPI field of the notification is set to match
		 * the SPI of the Child SA.
		*/
		LOG_PEXPECT("trying to send unimplemented %s notification",
			    notify_name);
		return false;
	case v2N_REKEY_SA:
		LOG_PEXPECT("%s notification cannot be part of a response",
			    notify_name);
		return false;
	default:
		break;
	}

	pb_stream n_pbs;
	if (!emit_v2Nsa_pl(ntype, protoid, spi, response->pbs, &n_pbs) ||
	    (ndata != NULL && !pbs_out_hunk(*ndata, &n_pbs, "Notify data"))) {
		return false;
	}

	close_output_pbs(&n_pbs);
	return true;
}

void record_v2N_spi_response(struct logger *logger,
			     struct ike_sa *ike,
			     struct msg_digest *md,
			     enum ikev2_sec_proto_id protoid,
			     ipsec_spi_t *spi,
			     v2_notification_t ntype,
			     const chunk_t *ndata /* optional */,
			     enum payload_security security)
{
	uint8_t buf[MIN_OUTPUT_UDP_SIZE];
	struct response response;
	if (!open_response(&response, logger, buf, sizeof(buf),
			   ike, md, security)) {
		return;
	}
	if (!emit_v2N_spi_response(&response, ike, md,
				   protoid, spi, ntype, ndata)) {
		return;
	}
	if (!close_response(&response)) {
		return;
	}
	record_v2_message(ike, &response.message, "v2N response",
			  MESSAGE_RESPONSE);
	pstat(ikev2_sent_notifies_e, ntype);
}

void record_v2N_response(struct logger *logger,
			 struct ike_sa *ike,
			 struct msg_digest *md,
			 v2_notification_t ntype,
			 const chunk_t *ndata /* optional */,
			 enum payload_security security)
{
	record_v2N_spi_response(logger, ike, md,
				PROTO_v2_RESERVED, NULL/*SPI*/,
				ntype, ndata, security);
}

/*
 * This is called with a pretty messed up MD so trust nothing.  For
 * instance when the version number is wrong.
 */
void send_v2N_response_from_md(struct msg_digest *md,
			       v2_notification_t ntype,
			       const chunk_t *ndata)
{
	passert(md != NULL); /* always a response */

	const char *const notify_name = enum_short_name(&ikev2_notify_names, ntype);
	passert(notify_name != NULL); /* must be known */

	enum isakmp_xchg_types exchange_type = md->hdr.isa_xchg;
	const char *exchange_name = enum_short_name(&ikev2_exchange_names, exchange_type);
	if (exchange_name == NULL) {
		/* when responding to crud, name may not be known */
		exchange_name = "UNKNOWN";
		dbg("message request contains unknown exchange type %d",
		    exchange_type);
	}

	log_md(RC_LOG, md,
	       "responding to %s (%d) message (Message ID %u) with unencrypted notification %s",
	       exchange_name, exchange_type,
	       md->hdr.isa_msgid,
	       notify_name);

	/*
	 * Normally an unencrypted response is only valid for
	 * IKE_SA_INIT or IKE_AUTH (when DH fails).  However "1.5.
	 * Informational Messages outside of an IKE SA" says to
	 * respond to other crud using the initiator's exchange type
	 * and Message ID and an unencrypted response.
	 */
	switch (exchange_type) {
	case ISAKMP_v2_IKE_SA_INIT:
	case ISAKMP_v2_IKE_AUTH:
		break;
	default:
		dbg("normally exchange type %s is encrypted", exchange_name);
	}

	uint8_t buf[MIN_OUTPUT_UDP_SIZE];
	struct pbs_out reply = open_pbs_out("unencrypted notification",
					    buf, sizeof(buf), md->md_logger);
	struct pbs_out rbody = open_v2_message(&reply, NULL/*no state*/,
					       md /* response */,
					       exchange_type);
	if (!pbs_ok(&rbody)) {
		LOG_PEXPECT("error building header for unencrypted %s %s notification with message ID %u",
			    exchange_name, notify_name, md->hdr.isa_msgid);
		return;
	}

	/* build and add v2N payload to the packet */
	chunk_t nhunk = ndata == NULL ? empty_chunk : *ndata;
	if (!emit_v2N_hunk(ntype, nhunk, &rbody)) {
		LOG_PEXPECT("error building unencrypted %s %s notification with message ID %u",
			    exchange_name, notify_name, md->hdr.isa_msgid);
		return;
	}

	close_output_pbs(&rbody);
	close_output_pbs(&reply);

	/*
	 * This notification is fire-and-forget (not a proper
	 * exchange, one with retrying) so it is not saved.
	 */
	send_chunk("v2 notify", SOS_NOBODY, md->iface, md->sender,
		   same_out_pbs_as_chunk(&reply));

	pstat(ikev2_sent_notifies_e, ntype);
}

/*
 * Construct and send an informational request.
 *
 * XXX: This and record_v2_delete() should be merged.  However, there
 * are annoying differences.  For instance, record_v2_delete() updates
 * st->st_msgid but the below doesn't.
 *
 * XXX: but st_msgid isn't used so have things changed?
 */
stf_status record_v2_informational_request(const char *name,
					   struct ike_sa *ike,
					   struct state *sender,
					   payload_emitter_fn *emit_payloads)
{
	/*
	 * Buffer in which to marshal our informational message.  We
	 * don't use reply_buffer/reply_stream because it might be in
	 * use.
	 */
	uint8_t buffer[MIN_OUTPUT_UDP_SIZE];	/* ??? large enough for any informational? */
	struct pbs_out packet = open_pbs_out(name, buffer, sizeof(buffer), sender->st_logger);
	if (!pbs_ok(&packet)) {
		return STF_INTERNAL_ERROR;
	}

	pb_stream message = open_v2_message(&packet, ike,
					    NULL /* request */,
					    ISAKMP_v2_INFORMATIONAL);
	if (!pbs_ok(&message)) {
		return STF_INTERNAL_ERROR;
	}

	v2SK_payload_t sk = open_v2SK_payload(sender->st_logger, &message, ike);
	if (!pbs_ok(&sk.pbs) ||
	    (emit_payloads != NULL && !emit_payloads(sender, &sk.pbs)) ||
	    !close_v2SK_payload(&sk)) {
		return STF_INTERNAL_ERROR;
	}
	close_output_pbs(&message);
	close_output_pbs(&packet);

	stf_status ret = encrypt_v2SK_payload(&sk);
	if (ret != STF_OK) {
		return ret;
	}

	ike->sa.st_pend_liveness = TRUE; /* we should only do this when dpd/liveness is active? */
	record_v2_message(ike, &packet, name, MESSAGE_REQUEST);
	return STF_OK;
}

void free_v2_outgoing_fragments(struct v2_outgoing_fragment **frags)
{
	if (*frags != NULL) {
		struct v2_outgoing_fragment *frag = *frags;
		do {
			struct v2_outgoing_fragment *next = frag->next;
			pfree(frag);
			frag = next;
		} while (frag != NULL);
		*frags = NULL;
	}
}

void free_v2_incomming_fragments(struct v2_incomming_fragments **frags)
{
	if (*frags != NULL) {
		for (unsigned i = 0; i < elemsof((*frags)->frags); i++) {
			struct v2_incomming_fragment *frag = &(*frags)->frags[i];
			free_chunk_content(&frag->cipher);
		}
		pfree(*frags);
		*frags = NULL;
	}
}

void free_v2_message_queues(struct state *st)
{
	for (enum message_role message = MESSAGE_ROLE_FLOOR;
	     message < MESSAGE_ROLE_ROOF; message++) {
		free_v2_outgoing_fragments(&st->st_v2_outgoing[message]);
		free_v2_incomming_fragments(&st->st_v2_incomming[message]);
	}
}
