/*
 * IKEv2 notify routines, for Libreswan
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
#include "ikev2_notify.h"
#include "demux.h"
#include "pluto_stats.h"

enum v2_pd v2_pd_from_notification(v2_notification_t n)
{
#define C(N) case v2N_##N: return PD_v2N_##N;
	switch (n) {
	C(REKEY_SA);
	C(NO_PPK_AUTH);
	C(PPK_IDENTITY);
	C(SIGNATURE_HASH_ALGORITHMS);
	C(NULL_AUTH);
	C(IPCOMP_SUPPORTED);
	C(IKEV2_FRAGMENTATION_SUPPORTED);
	C(USE_PPK);
	C(REDIRECTED_FROM);
	C(REDIRECT_SUPPORTED);
	C(NAT_DETECTION_SOURCE_IP);
	C(NAT_DETECTION_DESTINATION_IP);
	C(ESP_TFC_PADDING_NOT_SUPPORTED);
	C(USE_TRANSPORT_MODE);
	C(MOBIKE_SUPPORTED);
	C(INITIAL_CONTACT);
	C(REDIRECT);
	C(INVALID_SYNTAX);
	C(AUTHENTICATION_FAILED);
	C(UNSUPPORTED_CRITICAL_PAYLOAD);
	C(COOKIE);
	C(COOKIE2);
	C(INVALID_KE_PAYLOAD);
	C(INVALID_MAJOR_VERSION);
	C(TS_UNACCEPTABLE);
	C(INTERMEDIATE_EXCHANGE_SUPPORTED);
	C(UPDATE_SA_ADDRESSES);
	C(NO_PROPOSAL_CHOSEN);
	C(SINGLE_PAIR_REQUIRED);
	C(INTERNAL_ADDRESS_FAILURE);
	C(FAILED_CP_REQUIRED);
	default: return PD_v2_INVALID;
	}
#undef C
}

void decode_v2N_payload(struct logger *unused_logger UNUSED, struct msg_digest *md,
			const struct payload_digest *notify)
{
	v2_notification_t n = notify->payload.v2n.isan_type;
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

	const char *name = enum_name(&ikev2_notify_names, n); /* might be NULL */
	if (name == NULL) {
		dbg("%s notification %d is unknown", type, n);
		return;
	}
	enum v2_pd v2_pd = v2_pd_from_notification(n);
	if (v2_pd == PD_v2_INVALID) {
		/* if it was supported there'd be space to save it */
		dbg("%s notification %s is not supported", type, name);
		return;
	}
	if (md->pd[v2_pd] != NULL) {
		dbg("%s duplicate notification %s ignored", type, name);
		return;
	}
	if (DBGP(DBG_TMI)) {
		DBG_log("%s notification %s saved", type, name);
	}
	md->pd[v2_pd] = notify;
}
