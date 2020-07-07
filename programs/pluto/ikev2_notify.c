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

enum v2_pbs v2_notification_to_v2_pbs(v2_notification_t n)
{
#define C(N) case v2N_##N: return PBS_v2N_##N;
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
	default: return PBS_v2_INVALID;
	}
#undef C
}

bool decode_v2N_ike_sa_init_request(struct msg_digest *md)
{
	for (struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N];
	     ntfy != NULL; ntfy = ntfy->next) {
		switch (ntfy->payload.v2n.isan_type) {
		case v2N_COOKIE:
			/* already handled earlier */
			break;

		case v2N_REDIRECTED_FROM:	/* currently we don't check address in this payload */
		case v2N_REDIRECT_SUPPORTED:
		case v2N_USE_PPK:
		case v2N_IKEV2_FRAGMENTATION_SUPPORTED:
		case v2N_NAT_DETECTION_SOURCE_IP:
		case v2N_NAT_DETECTION_DESTINATION_IP:
		case v2N_SIGNATURE_HASH_ALGORITHMS:
			/* handled elsewhere */
			break;

		/* These are not supposed to appear in IKE_INIT */
		case v2N_ESP_TFC_PADDING_NOT_SUPPORTED:
		case v2N_USE_TRANSPORT_MODE:
		case v2N_IPCOMP_SUPPORTED:
		case v2N_PPK_IDENTITY:
		case v2N_NO_PPK_AUTH:
		case v2N_MOBIKE_SUPPORTED:
			dbg("received unauthenticated %s notify in wrong exchange - ignored",
			    enum_name(&ikev2_notify_names,
				      ntfy->payload.v2n.isan_type));
			break;

		default:
			dbg("received unauthenticated %s notify - ignored",
			    enum_name(&ikev2_notify_names,
				      ntfy->payload.v2n.isan_type));
		}
	}
	return true;
}

bool decode_v2N_ike_sa_init_response(struct msg_digest *md)
{
	for (struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N];
	     ntfy != NULL; ntfy = ntfy->next) {
		if (ntfy->payload.v2n.isan_type >= v2N_STATUS_FLOOR) {
			pstat(ikev2_recv_notifies_s, ntfy->payload.v2n.isan_type);
		} else {
			pstat(ikev2_recv_notifies_e, ntfy->payload.v2n.isan_type);
		}

		switch (ntfy->payload.v2n.isan_type) {
		case v2N_COOKIE:
		case v2N_INVALID_KE_PAYLOAD:
		case v2N_NO_PROPOSAL_CHOSEN:
			dbg("%s cannot appear with other payloads",
			    enum_name(&ikev2_notify_names,
				      ntfy->payload.v2n.isan_type));
			return false;

		case v2N_MOBIKE_SUPPORTED:
		case v2N_USE_TRANSPORT_MODE:
		case v2N_IPCOMP_SUPPORTED:
		case v2N_ESP_TFC_PADDING_NOT_SUPPORTED:
		case v2N_PPK_IDENTITY:
		case v2N_NO_PPK_AUTH:
		case v2N_INITIAL_CONTACT:
			dbg("received %s which is not valid in the IKE_SA_INIT exchange - ignoring it",
			    enum_name(&ikev2_notify_names,
				      ntfy->payload.v2n.isan_type));
			break;

		case v2N_USE_PPK:
		case v2N_IKEV2_FRAGMENTATION_SUPPORTED:
		case v2N_NAT_DETECTION_SOURCE_IP:
		case v2N_NAT_DETECTION_DESTINATION_IP:
		case v2N_SIGNATURE_HASH_ALGORITHMS:
		case v2N_REDIRECT:
			/* handled elsewhere */
			break;

		default:
			dbg("received %s but ignoring it",
			    enum_name(&ikev2_notify_names,
				      ntfy->payload.v2n.isan_type));
		}
	}
	return true;
}

bool decode_v2N_ike_auth_request(struct msg_digest *md)
{
	/*
	 * The NOTIFY payloads we receive in the IKE_AUTH request are either
	 * related to the IKE SA, or the Child SA. Here we only process the
	 * ones related to the IKE SA.
	 */
	for (struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N];
	     ntfy != NULL; ntfy = ntfy->next) {
		switch (ntfy->payload.v2n.isan_type) {

		/* Child SA related NOTIFYs are processed later in ikev2_process_ts_and_rest() */
		case v2N_MOBIKE_SUPPORTED:
		case v2N_NULL_AUTH:
		case v2N_NO_PPK_AUTH:
		case v2N_USE_TRANSPORT_MODE:
		case v2N_IPCOMP_SUPPORTED:
		case v2N_ESP_TFC_PADDING_NOT_SUPPORTED:
		case v2N_PPK_IDENTITY:
		case v2N_INITIAL_CONTACT:
			/* handled elsewhere */
			break;

		default:
			dbg("received unknown/unsupported notify %s - ignored",
			    enum_name(&ikev2_notify_names,
					ntfy->payload.v2n.isan_type));
			break;
		}
	}
	return true;
}

bool decode_v2N_ike_auth_response(struct msg_digest *md)
{
	/* Process NOTIFY payloads related to IKE SA */
	for (struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N];
	     ntfy != NULL; ntfy = ntfy->next) {
		switch (ntfy->payload.v2n.isan_type) {
		case v2N_COOKIE:
			dbg("Ignoring bogus COOKIE notify in IKE_AUTH rpely");
			break;
		case v2N_REDIRECT:
		case v2N_ESP_TFC_PADDING_NOT_SUPPORTED:
		case v2N_USE_TRANSPORT_MODE:
		case v2N_MOBIKE_SUPPORTED:
		case v2N_PPK_IDENTITY:
			/* handled elsewhere */
			dbg("received %s notify",
			    enum_name(&ikev2_notify_names,
				      ntfy->payload.v2n.isan_type));
			break;
		default:
			dbg("received %s notify - ignored",
			    enum_name(&ikev2_notify_names,
				      ntfy->payload.v2n.isan_type));
		}
	}
	return true;
}

bool decode_v2N_ike_auth_child(struct msg_digest *md)
{
	for (struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N];
	     ntfy != NULL; ntfy = ntfy->next) {
		/*
		 * https://tools.ietf.org/html/rfc7296#section-3.10.1
		 *
		 * Types in the range 0 - 16383 are intended for
		 * reporting errors.  An implementation receiving a
		 * Notify payload with one of these types that it does
		 * not recognize in a response MUST assume that the
		 * corresponding request has failed entirely.
		 * Unrecognized error types in a request and status
		 * types in a request or response MUST be ignored, and
		 * they should be logged.
		 *
		 * No known error notify would allow us to continue,
		 * so we can fail whether the error notify is known or
		 * unknown.
		 */
		if (ntfy->payload.v2n.isan_type < v2N_INITIAL_CONTACT) {
			loglog(RC_LOG_SERIOUS, "received ERROR NOTIFY (%d): %s ",
			       ntfy->payload.v2n.isan_type,
			       enum_name(&ikev2_notify_names, ntfy->payload.v2n.isan_type));
			return false;
		}

		/* check for Child SA related NOTIFY payloads */
		switch (ntfy->payload.v2n.isan_type) {
		case v2N_USE_TRANSPORT_MODE:
		case v2N_ESP_TFC_PADDING_NOT_SUPPORTED:
			/* handled elsewhere */
			break;
		case v2N_IPCOMP_SUPPORTED:
			dbg("received v2N_IPCOMP_SUPPORTED");
			break;
		default:
			dbg("ignored received NOTIFY (%d): %s ",
			    ntfy->payload.v2n.isan_type,
			    enum_name(&ikev2_notify_names, ntfy->payload.v2n.isan_type));
		}
	}
	return true;
}

void decode_v2N_payload(struct logger *unused_logger UNUSED, struct msg_digest *md,
			const struct payload_digest *notify)
{
	v2_notification_t n = notify->payload.v2n.isan_type;
	const char *name = enum_name(&ikev2_notify_names, n);
	if (name == NULL) {
		dbg("ignoring unrecognized %d notify", n);
		return;
	}
	enum v2_pbs v2_pbs = v2_notification_to_v2_pbs(n);
	if (v2_pbs == PBS_v2_INVALID) {
		dbg("ignoring unsupported %s notify", name);
		return;
	}
	if (md->pbs[v2_pbs] != NULL) {
		dbg("ignoring duplicate %s notify", name);
		return;
	}
	if (DBGP(DBG_TMI)) {
		DBG_log("adding %s notify", name);
	}
	md->pbs[v2_pbs] = &notify->pbs;
}
