/* IKEv2 notify routines, for Libreswan
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
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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
#include "log.h"
#include "ikev2_notification.h"
#include "demux.h"
#include "pluto_stats.h"
#include "ikev2_message.h"	/* for build_ikev2_critical() */
#include "ikev2_send.h"		/* for send_v2_notification_from_md() et.al. */
#include "log_limiter.h"

enum v2_pd v2_pd_from_notification(v2_notification_t n)
{
	switch (n) {
#define C(N) case v2N_##N: return PD_v2N_##N;
	C(AUTHENTICATION_FAILED);
	C(COOKIE);
	C(COOKIE2);
	C(CHILDLESS_IKEV2_SUPPORTED);
	C(ESP_TFC_PADDING_NOT_SUPPORTED);
	C(FAILED_CP_REQUIRED);
	C(IKEV2_FRAGMENTATION_SUPPORTED);
	C(INITIAL_CONTACT);
	C(INTERMEDIATE_EXCHANGE_SUPPORTED);
	C(INTERNAL_ADDRESS_FAILURE);
	C(INVALID_KE_PAYLOAD);
	C(INVALID_MAJOR_VERSION);
	C(INVALID_SYNTAX);
	C(IPCOMP_SUPPORTED);
	C(MOBIKE_SUPPORTED);
	C(NAT_DETECTION_DESTINATION_IP);
	C(NAT_DETECTION_SOURCE_IP);
	C(NO_PPK_AUTH);
	C(NO_PROPOSAL_CHOSEN);
	C(NULL_AUTH);
	C(PPK_IDENTITY);
	C(PPK_IDENTITY_KEY);
	C(REDIRECT);
	C(REDIRECTED_FROM);
	C(REDIRECT_SUPPORTED);
	C(REKEY_SA);
	C(SIGNATURE_HASH_ALGORITHMS);
	C(SINGLE_PAIR_REQUIRED);
	C(TS_UNACCEPTABLE);
	C(UNSUPPORTED_CRITICAL_PAYLOAD);
	C(UPDATE_SA_ADDRESSES);
	C(USE_PPK);
	C(USE_PPK_INT);
	C(USE_TRANSPORT_MODE);
	C(USE_AGGFRAG);
	C(TICKET_LT_OPAQUE);
	C(TICKET_REQUEST);
	C(TICKET_ACK);
	C(TICKET_NACK);
	C(TICKET_OPAQUE);
#undef C
	default: return PD_v2_INVALID;
	}
}

void decode_v2N_payload(struct logger *logger, struct msg_digest *md,
			const struct payload_digest *notify)
{
	v2_notification_t n = notify->payload.v2n.isan_type;

	if (impair.ignore_v2_notification.enabled &&
	    impair.ignore_v2_notification.value == n) {
		name_buf eb;
		llog(RC_LOG, logger, "IMPAIR: ignoring %s notification",
		     str_enum_short(&v2_notification_names, n, &eb));
		return;
	}

	const char *type;
	if (n < 16384) {
		type = "error";
		/*
		 * https://tools.ietf.org/html/rfc7296#section-3.10.1
		 *
		 *   Types in the range 0 - 16383 are intended for
		 *   reporting errors.  An implementation receiving a
		 *   Notify payload with one of these types that it
		 *   does not recognize in a response MUST assume that
		 *   the corresponding request has failed entirely.
		 *   Unrecognized error types in a request and status
		 *   types in a request or response MUST be ignored,
		 *   and they should be logged.
		 *
		 * Record the first error; and complain when there are
		 * more.
		 */
		if (md->v2N_error == v2N_NOTHING_WRONG) {
			md->v2N_error = n;
		} else {
			/* XXX: is this allowed? */
			dbg("message contains multiple error notifications: %d %d",
			    md->v2N_error, n);
		}
	} else {
		type = "status";
	}

	name_buf name;
	if (!enum_name(&v2_notification_names, n, &name)) {
		dbg("%s notification %d is unknown", type, n);
		return;
	}
	enum v2_pd v2_pd = v2_pd_from_notification(n);
	if (v2_pd == PD_v2_INVALID) {
		/* if it was supported there'd be space to save it */
		ldbg(logger, "%s notification %s is not supported", type, name.buf);
		return;
	}
	if (md->pd[v2_pd] != NULL) {
		ldbg(logger, "%s duplicate notification %s ignored", type, name.buf);
		return;
	}
	if (DBGP(DBG_TMI)) {
		LDBG_log(logger, "%s notification %s saved", type, name.buf);
	}
	md->pd[v2_pd] = notify;
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
			    const ipsec_spi_t *spi_or_null, /* optional */
			    struct pbs_out *sub_payload)
{
	struct pbs_out tmp;
	if (PBAD(outs->logger, sub_payload == NULL)) {
		sub_payload = &tmp;
	}

	/* See RFC 5996 section 3.10 "Notify Payload" */
	if (!PEXPECT(outs->logger, (impair.emitting ||
					 protocol_id == PROTO_v2_RESERVED ||
					 protocol_id == PROTO_v2_AH ||
					 protocol_id == PROTO_v2_ESP))) {
		return false;
	}

	size_t spi_size = (spi_or_null == NULL ? 0 : sizeof(*spi_or_null));

	switch (ntype) {
	case v2N_INVALID_SELECTORS:
	case v2N_REKEY_SA:
	case v2N_CHILD_SA_NOT_FOUND:
		if (protocol_id == PROTO_v2_RESERVED || spi_size == 0) {
			ldbg(outs->logger, "XXX: type requires SA; missing");
		}
		break;
	default:
		if (protocol_id != PROTO_v2_RESERVED || spi_size > 0) {
			ldbg(outs->logger, "XXX: type forbids SA but SA present");
		}
		break;
	}

	ldbg(outs->logger, "adding a v2N Payload");

	struct ikev2_notify n = {
		.isan_critical = build_ikev2_critical(false, outs->logger),
		.isan_protoid = protocol_id,
		.isan_spisize = spi_size,
		.isan_type = ntype,
	};

	if (!pbs_out_struct(outs, &ikev2_notify_desc,
			    &n, sizeof(n), sub_payload)) {
		return false;
	}

	if (spi_or_null != NULL) {
		const ipsec_spi_t *spi = spi_or_null; /*not-null*/
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
	if (impair.omit_v2_notification.enabled &&
	    impair.omit_v2_notification.value == ntype) {
		name_buf eb;
		llog(RC_LOG, outs->logger,
		     "IMPAIR: omitting %s notification",
		     str_enum_short(&v2_notification_names, ntype, &eb));
		return true;
	}

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
	       struct pbs_out *outs)
{
	return emit_v2N_bytes(ntype, NULL, 0, outs);
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
				  struct msg_digest *md,
				  enum ikev2_sec_proto_id protoid,
				  ipsec_spi_t *spi_or_null,
				  v2_notification_t ntype,
				  shunk_t ndata /*optional*/)
{
	name_buf notify_name;
	enum_name_short(&v2_notification_names, ntype, &notify_name);

	enum ikev2_exchange exchange_type = md->hdr.isa_xchg;
	name_buf exchange_name;
	enum_name_short(&ikev2_exchange_names, exchange_type, &exchange_name);

	/*
	 * XXX: this will prefix with cur_state.  For this code path
	 * is it ever different to the IKE SA?
	 */
	endpoint_buf b;
	llog(RC_LOG, response->logger,
	     "responding to %s message (ID %u) from %s with %s notification %s",
	     exchange_name.buf,
	     md->hdr.isa_msgid,
	     str_endpoint_sensitive(&md->sender, &b),
	     response->security == ENCRYPTED_PAYLOAD ? "encrypted" : "unencrypted",
	     notify_name.buf);

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
			     notify_name.buf);
		return false;
	case v2N_REKEY_SA:
		llog_pexpect(response->logger, HERE,
			     "%s notification cannot be part of a response",
			     notify_name.buf);
		return false;
	default:
		break;
	}

	struct pbs_out n_pbs;
	if (!open_v2N_SA_output_pbs(response->pbs, ntype,
				    protoid, spi_or_null,
				    &n_pbs)) {
		return false;
	}

	if (ndata.len > 0) {
		if (!pbs_out_hunk(&n_pbs, ndata, "Notify data")) {
			return false;
		}
	}

	close_output_pbs(&n_pbs);
	return true;
}

void record_v2N_spi_response(struct logger *logger,
			     struct ike_sa *ike,
			     struct msg_digest *md,
			     enum ikev2_sec_proto_id protoid,
			     ipsec_spi_t *spi_or_null,/*depends-on-protoid*/
			     v2_notification_t ntype,
			     shunk_t ndata /*optional*/,
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

	if (!emit_v2N_spi_response(&response, md,
				   protoid, spi_or_null,
				   ntype, ndata)) {
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
			 shunk_t ndata /*optional*/,
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

static emit_v2_response_fn emit_v2N_response; /* type check */

struct emit_v2_response_context {
	v2_notification_t ntype;
	const shunk_t nhunk;
};

bool emit_v2N_response(struct pbs_out *pbs,
		       struct emit_v2_response_context *context)
{
	return emit_v2N_hunk(context->ntype, context->nhunk, pbs);
}

void send_v2N_response_from_md(struct msg_digest *md,
			       v2_notification_t ntype,
			       const shunk_t *ndata,
			       const char *details, ...)
{
	passert(md != NULL); /* always a response */

	name_buf notify_name;
	PASSERT(md->logger, enum_name_short(&v2_notification_names, ntype, &notify_name));

	enum ikev2_exchange exchange_type = md->hdr.isa_xchg;
	name_buf exchange_name;
	if (!enum_name_short(&ikev2_exchange_names, exchange_type, &exchange_name)) {
		/* when responding to crud, name may not be known */
		exchange_name.buf = "UNKNOWN";
		dbg("message request contains unknown exchange type %d",
		    exchange_type);
	}

	lset_t rc_flags = log_limiter_rc_flags(md->logger, UNSECURED_LOG_LIMITER);
	if (rc_flags != LEMPTY) {
		LLOG_JAMBUF(rc_flags, md->logger, buf) {
			jam_string(buf, "responding to ");
			jam_enum_short(buf, &ikev2_exchange_names, md->hdr.isa_xchg);
			jam(buf, " request with Message ID %u", md->hdr.isa_msgid);
			jam(buf, " with unencrypted notification %s, ",
			    notify_name.buf);
			va_list ap;
			va_start(ap, details);
			jam_va_list(buf, details, ap);
			va_end(ap);
		}
	}

	struct emit_v2_response_context context = {
		.ntype = ntype,
		.nhunk = (ndata == NULL ? empty_shunk : *ndata),
	};

	if (!send_v2_response_from_md(md, "notification", emit_v2N_response, &context)) {
		return;
	}

	pstat(ikev2_sent_notifies_e, ntype);
}
