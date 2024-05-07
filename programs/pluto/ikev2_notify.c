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
#include "log.h"
#include "ikev2_notify.h"
#include "demux.h"
#include "pluto_stats.h"

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
	C(USE_TRANSPORT_MODE);
	C(USE_AGGFRAG);
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
