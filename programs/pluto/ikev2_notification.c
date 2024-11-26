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
		enum_buf eb;
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

	enum_buf name;
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
			    const ipsec_spi_t *spi, /* optional */
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

	size_t spi_size = (spi == NULL ? 0 : sizeof(*spi));

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
	if (impair.omit_v2_notification.enabled &&
	    impair.omit_v2_notification.value == ntype) {
		enum_buf eb;
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
