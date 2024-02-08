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

#include "log.h"
#include "send.h"
#include "ikev2_send.h"
#include "ikev2_message.h"
#include "server.h"
#include "state.h"
#include "connections.h"
#include "ike_alg.h"
#include "pluto_stats.h"
#include "demux.h"	/* for struct msg_digest */
#include "rnd.h"
#include "kernel.h"	/* for get_my_cpi() */

#ifdef USE_XFRM_INTERFACE
#include "kernel_xfrm_interface.h"	/* for set_ike_mark_out() */
#endif

bool send_recorded_v2_message(struct ike_sa *ike,
			      const char *where,
			      enum message_role message)
{
	struct v2_outgoing_fragment *frags = ike->sa.st_v2_outgoing[message];
	if (ike->sa.st_iface_endpoint == NULL) {
		llog_sa(RC_LOG, ike, "cannot send packet - interface vanished!");
		return false;
	}

#ifdef USE_XFRM_INTERFACE
	set_ike_mark_out(ike->sa.st_connection, &ike->sa.st_remote_endpoint);
#endif

	if (frags == NULL) {
		llog_sa(RC_LOG, ike, "no %s message to send", where);
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
				 const char *what UNUSED,
				 struct v2_outgoing_fragment **frags)
{
	pexpect(*frags == NULL);
	shunk_t frag = pbs_out_all(pbs);
	*frags = over_alloc_thing(struct v2_outgoing_fragment, frag.len);
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

bool emit_v2UNKNOWN(const char *victim,
		    enum isakmp_xchg_type exchange_type,
		    const struct impair_unsigned *impairment,
		    struct pbs_out *outs)
{
	if (impairment->value != exchange_type) {
		/* successfully did nothing */
		return true;
	}

	llog(RC_LOG, outs->outs_logger,
	     "IMPAIR: adding an unknown%s payload of type %d to %s %s message",
	     impair.unknown_v2_payload_critical ? " critical" : "",
	     ikev2_unknown_payload_desc.pt,
	     victim,
	     enum_name_short(&ikev2_exchange_names, exchange_type));
	struct ikev2_generic gen = {
		.isag_critical = build_ikev2_critical(impair.unknown_v2_payload_critical, outs->outs_logger),
	};
	struct pbs_out pbs;
	if (!pbs_out_struct(outs, &ikev2_unknown_payload_desc, &gen, sizeof(gen), &pbs)) {
		/* already logged */
		return false; /*fatal*/
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

bool open_v2N_SA_output_pbs(struct pbs_out *outs,
			    v2_notification_t ntype,
			    enum ikev2_sec_proto_id protocol_id,
			    const ipsec_spi_t *spi, /* optional */
			    struct pbs_out *sub_payload)
{
	struct pbs_out tmp;
	if (PBAD(outs->outs_logger, sub_payload == NULL)) {
		sub_payload = &tmp;
	}

	/* See RFC 5996 section 3.10 "Notify Payload" */
	if (!PEXPECT(outs->outs_logger, (impair.emitting ||
					 protocol_id == PROTO_v2_RESERVED ||
					 protocol_id == PROTO_v2_AH ||
					 protocol_id == PROTO_v2_ESP))) {
		return false;
	}

	size_t spi_size = (spi == NULL ? 0 : sizeof(*spi));

	switch (ntype) {
	case v2N_INVALID_SELECTORS:
	case v2N_REKEY_SA:
	case v2N_CHILD_SA_NOT_FOUND:
		if (protocol_id == PROTO_v2_RESERVED || spi_size == 0) {
			ldbg(outs->outs_logger, "XXX: type requires SA; missing");
		}
		break;
	default:
		if (protocol_id != PROTO_v2_RESERVED || spi_size > 0) {
			ldbg(outs->outs_logger, "XXX: type forbids SA but SA present");
		}
		break;
	}

	ldbg(outs->outs_logger, "adding a v2N Payload");

	struct ikev2_notify n = {
		.isan_critical = build_ikev2_critical(false, outs->outs_logger),
		.isan_protoid = protocol_id,
		.isan_spisize = spi_size,
		.isan_type = ntype,
	};

	if (!pbs_out_struct(outs, &ikev2_notify_desc,
			    &n, sizeof(n), sub_payload)) {
		return false;
	}

	if (spi != NULL) {
		if (!pbs_out_thing(sub_payload, *spi, "SPI")) {
			/* already logged */
			return false;
		}
	}

	return true;
}

/* emit a v2 Notification payload, with optional sub-payload */
bool open_v2N_output_pbs(struct pbs_out *outs,
			 v2_notification_t ntype,
			 struct pbs_out *sub_payload)
{
	return open_v2N_SA_output_pbs(outs, ntype, PROTO_v2_RESERVED, NULL, sub_payload);
}

/* emit a v2 Notification payload, with bytes as sub-payload */
bool emit_v2N_bytes(v2_notification_t ntype,
		    const void *bytes, size_t size, /* optional */
		    struct pbs_out *outs)
{
	struct pbs_out pl;
	if (!open_v2N_output_pbs(outs, ntype, &pl)) {
		return false;
	}

	if (!pbs_out_raw(&pl, bytes, size, "Notify data")) {
		/* already logged */
		return false;
	}

	close_output_pbs(&pl);
	return true;
}

/* output a v2 simple Notification payload */
bool emit_v2N(v2_notification_t ntype,
	       pb_stream *outs)
{
	return emit_v2N_bytes(ntype, NULL, 0, outs);
}

bool emit_v2N_SIGNATURE_HASH_ALGORITHMS(lset_t sighash_policy,
					pb_stream *outs)
{
	struct pbs_out n_pbs;

	if (!open_v2N_output_pbs(outs, v2N_SIGNATURE_HASH_ALGORITHMS, &n_pbs)) {
		llog(RC_LOG, outs->outs_logger, "error initializing notify payload for notify message");
		return false;
	}

#define H(POLICY, ID)							\
	if (sighash_policy & POLICY) {					\
		uint16_t hash_id = htons(ID);				\
		passert(sizeof(hash_id) == RFC_7427_HASH_ALGORITHM_IDENTIFIER_SIZE); \
		if (!pbs_out_thing(&n_pbs, hash_id,			\
				 "hash algorithm identifier "#ID)) {	\
			/* already logged */				\
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
 */

static bool emit_v2N_spi_response(struct v2_message *response,
				  struct ike_sa *ike,
				  struct msg_digest *md,
				  enum ikev2_sec_proto_id protoid,
				  ipsec_spi_t *spi,
				  v2_notification_t ntype,
				  const chunk_t *ndata /* optional */)
{
	const char *const notify_name = enum_name_short(&v2_notification_names, ntype);

	enum isakmp_xchg_type exchange_type = md->hdr.isa_xchg;
	const char *const exchange_name = enum_name_short(&ikev2_exchange_names, exchange_type);

	/*
	 * XXX: this will prefix with cur_state.  For this code path
	 * is it ever different to the IKE SA?
	 */
	endpoint_buf b;
	llog(RC_LOG, response->logger,
	     "responding to %s message (ID %u) from %s with %s notification %s",
	     exchange_name, md->hdr.isa_msgid,
	     str_endpoint_sensitive(&ike->sa.st_remote_endpoint, &b),
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
		llog_pexpect(response->logger, HERE,
			     "trying to send unimplemented %s notification",
			     notify_name);
		return false;
	case v2N_REKEY_SA:
		llog_pexpect(response->logger, HERE,
			     "%s notification cannot be part of a response",
			     notify_name);
		return false;
	default:
		break;
	}

	pb_stream n_pbs;
	if (!open_v2N_SA_output_pbs(response->pbs, ntype, protoid, spi, &n_pbs)) {
		return false;
	}

	if (ndata != NULL && !out_hunk(*ndata, &n_pbs, "Notify data")) {
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
	struct v2_message response;

	/*
	 * Never send a response to a response.
	 */
	if (!pexpect(v2_msg_role(md) == MESSAGE_REQUEST)) {
		/* always responding */
		return;
	}

	if (!open_v2_message("v2N response", ike, logger,
			     md/*response*/, md->hdr.isa_xchg/*same exchange type*/,
			     buf, sizeof(buf), &response, security)) {
		return;
	}

	if (!emit_v2N_spi_response(&response, ike, md,
				   protoid, spi, ntype, ndata)) {
		return;
	}

	if (!close_and_record_v2_message(&response)) {
		return;
	}
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
			       const shunk_t *ndata)
{
	passert(md != NULL); /* always a response */

	const char *const notify_name = enum_name_short(&v2_notification_names, ntype);
	passert(notify_name != NULL); /* must be known */

	enum isakmp_xchg_type exchange_type = md->hdr.isa_xchg;
	const char *exchange_name = enum_name_short(&ikev2_exchange_names, exchange_type);
	if (exchange_name == NULL) {
		/* when responding to crud, name may not be known */
		exchange_name = "UNKNOWN";
		dbg("message request contains unknown exchange type %d",
		    exchange_type);
	}

	llog(RC_LOG, md->logger,
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
	struct v2_message response;
	if (!open_v2_message("unencrypted notification response",
			     NULL/*no-IKE*/, md->logger, md/*response*/,
			     exchange_type,
			     buf, sizeof(buf),
			     &response, UNENCRYPTED_PAYLOAD)) {
		llog_pexpect(md->logger, HERE,
			     "error building header for unencrypted %s %s notification with message ID %u",
			     exchange_name, notify_name, md->hdr.isa_msgid);
		return;
	}

	/* build and add v2N payload to the packet */
	shunk_t nhunk = ndata == NULL ? empty_shunk : *ndata;
	if (!emit_v2N_hunk(ntype, nhunk, response.pbs)) {
		llog_pexpect(md->logger, HERE,
			     "error building unencrypted %s %s notification with message ID %u",
			     exchange_name, notify_name, md->hdr.isa_msgid);
		return;
	}

	close_v2_message(&response);

	/*
	 * This notification is fire-and-forget (not a proper
	 * exchange, one with retrying) so it is not saved.
	 */
	send_pbs_out_using_md(md, "v2 notify", &response.message);

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
	 * Buffer in which to marshal our informational message.
	 */
	uint8_t buffer[MIN_OUTPUT_UDP_SIZE];	/* ??? large enough for any informational? */

	struct v2_message request;
	if (!open_v2_message(name, ike, sender->logger,
			     NULL/*request*/, ISAKMP_v2_INFORMATIONAL,
			     buffer, sizeof(buffer), &request,
			     ENCRYPTED_PAYLOAD)) {
		return STF_INTERNAL_ERROR;
	}

	if (emit_payloads != NULL && !emit_payloads(sender, &request.sk.pbs)) {
		return STF_INTERNAL_ERROR;
	}

	if (!close_and_record_v2_message(&request)) {
		return STF_INTERNAL_ERROR;
	}

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

void free_v2_incoming_fragments(struct v2_incoming_fragments **frags)
{
	if (*frags != NULL) {
		for (unsigned i = 0; i < elemsof((*frags)->frags); i++) {
			struct v2_incoming_fragment *frag = &(*frags)->frags[i];
			free_chunk_content(&frag->text);
		}
		md_delref(&(*frags)->md);
		pfree(*frags);
		*frags = NULL;
	}
}

void free_v2_message_queues(struct state *st)
{
	for (enum message_role message = MESSAGE_ROLE_FLOOR;
	     message < MESSAGE_ROLE_ROOF; message++) {
		free_v2_outgoing_fragments(&st->st_v2_outgoing[message]);
		free_v2_incoming_fragments(&st->st_v2_incoming[message]);
	}
}
