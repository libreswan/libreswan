/* IKEv2 state machine, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010,2013-2017 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Simon Deziel <simon@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2011-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney
 * Copyright (C) 2016-2018 Antony Antony <appu@phenome.org>
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
 *
 */

#include "defs.h"
#include "state.h"
#include "ikev2_states.h"
#include "demux.h"
#include "ikev2.h"
#include "log.h"
#include "connections.h"

struct finite_state v2_states[] = {

#define S(KIND, STORY, CAT) [KIND - STATE_IKEv2_FLOOR] = {	\
		.kind = KIND,					\
		.name = #KIND,					\
		.short_name = #KIND + 6/*STATE_*/,		\
		.story = STORY,					\
		.category = CAT,				\
	}

	/*
	 * IKEv2 IKE SA initiator, while the the SA_INIT packet is
	 * being constructed, are in state.  Only once the packet has
	 * been sent out does it transition to STATE_PARENT_I1 and
	 * start being counted as half-open.
	 */

	S(STATE_PARENT_I0, "waiting for KE to finish", CAT_IGNORE),

	/*
	 * Count I1 as half-open too because with ondemand, a
	 * plaintext packet (that is spoofed) will trigger an outgoing
	 * IKE SA.
	 */

	S(STATE_PARENT_I1, "sent v2I1, expected v2R1", CAT_HALF_OPEN_IKE_SA),
	S(STATE_PARENT_R0, "processing SA_INIT request", CAT_HALF_OPEN_IKE_SA),
	S(STATE_PARENT_R1, "received v2I1, sent v2R1", CAT_HALF_OPEN_IKE_SA),

	/*
	 * All IKEv1 MAIN modes except the first (half-open) and last
	 * ones are not authenticated.
	 */

	S(STATE_PARENT_I2, "sent v2I2, expected v2R2", CAT_OPEN_IKE_SA),

	/*
	 * IKEv1 established states.
	 *
	 * XAUTH, seems to a second level of authentication performed
	 * after the connection is established and authenticated.
	 */

	/* isn't this an ipsec state */
	S(STATE_V2_CREATE_I0, "STATE_V2_CREATE_I0", CAT_ESTABLISHED_IKE_SA),
	 /* isn't this an ipsec state */
	S(STATE_V2_CREATE_I, "sent IPsec Child req wait response", CAT_ESTABLISHED_IKE_SA),
	S(STATE_V2_REKEY_IKE_I0, "STATE_V2_REKEY_IKE_I0", CAT_ESTABLISHED_IKE_SA),
	S(STATE_V2_REKEY_IKE_I, "STATE_V2_REKEY_IKE_I", CAT_ESTABLISHED_IKE_SA),
	S(STATE_V2_REKEY_CHILD_I0, "STATE_V2_REKEY_CHILD_I0", CAT_ESTABLISHED_IKE_SA),
	S(STATE_V2_REKEY_CHILD_I, "STATE_V2_REKEY_CHILD_I", CAT_ESTABLISHED_IKE_SA),
	S(STATE_V2_CREATE_R, "STATE_V2_CREATE_R", CAT_ESTABLISHED_IKE_SA),
	S(STATE_V2_REKEY_IKE_R, "STATE_V2_REKEY_IKE_R", CAT_ESTABLISHED_IKE_SA),
	S(STATE_V2_REKEY_CHILD_R, "STATE_V2_REKEY_CHILD_R", CAT_ESTABLISHED_IKE_SA),

	/*
	 * IKEv2 established states.
	 */

	S(STATE_PARENT_I3, "PARENT SA established", CAT_ESTABLISHED_IKE_SA),
	S(STATE_PARENT_R2, "received v2I2, PARENT SA established", CAT_ESTABLISHED_IKE_SA),

	S(STATE_V2_IPSEC_I, "IPsec SA established", CAT_ESTABLISHED_CHILD_SA),
	S(STATE_V2_IPSEC_R, "IPsec SA established", CAT_ESTABLISHED_CHILD_SA),

	/* ??? better story needed for these */
	S(STATE_IKESA_DEL, "STATE_IKESA_DEL", CAT_ESTABLISHED_IKE_SA),
	S(STATE_CHILDSA_DEL, "STATE_CHILDSA_DEL", CAT_INFORMATIONAL),
#undef S
};

/* Short forms for building payload type sets */

#define P(N) LELEM(ISAKMP_NEXT_v2##N)

/* From RFC 5996:
 *
 * 3.10 "Notify Payload": N payload may appear in any message
 *
 *      During the initial exchange (SA_INIT) (i.e., DH has been
 *      established) the notify payload can't be encrypted.  For all
 *      other exchanges it should be part of the SK (encrypted)
 *      payload (but beware the DH failure exception).
 *
 * 3.11 "Delete Payload": multiple D payloads may appear in an
 *	Informational exchange
 *
 * 3.12 "Vendor ID Payload": (multiple) may appear in any message
 *
 *      During the initial exchange (SA_INIT) (i.e., DH has been
 *      established) the vendor payload can't be encrypted.  For all
 *      other exchanges it should be part of the SK (encrypted)
 *      payload (but beware the DH failure exception).
 *
 * 3.15 "Configuration Payload":
 * 1.4 "The INFORMATIONAL Exchange": (multiple) Configuration Payloads
 *	may appear in an Informational exchange
 * 2.19 "Requesting an Internal Address on a Remote Network":
 *	In all cases, the CP payload MUST be inserted before the SA payload.
 *	In variations of the protocol where there are multiple IKE_AUTH
 *	exchanges, the CP payloads MUST be inserted in the messages
 *	containing the SA payloads.
 */

static const lset_t everywhere_payloads = P(N) | P(V);	/* can appear in any packet */
static const lset_t repeatable_payloads = P(N) | P(D) | P(CP) | P(V) | P(CERT) | P(CERTREQ);	/* if one can appear, many can appear */

struct ikev2_payload_errors ikev2_verify_payloads(struct msg_digest *md,
						  const struct payload_summary *summary,
						  const struct ikev2_expected_payloads *payloads)
{
	/*
	 * Convert SKF onto SK for the comparison (but only when it is
	 * on its own).
	 */
	lset_t seen = summary->present;
	if ((seen & (P(SKF)|P(SK))) == P(SKF)) {
		seen &= ~P(SKF);
		seen |= P(SK);
	}

	lset_t req_payloads = payloads->required;
	lset_t opt_payloads = payloads->optional;

	struct ikev2_payload_errors errors = {
		.bad = false,
		.excessive = summary->repeated & ~repeatable_payloads,
		.missing = req_payloads & ~seen,
		.unexpected = seen & ~req_payloads & ~opt_payloads & ~everywhere_payloads,
	};

	if ((errors.excessive | errors.missing | errors.unexpected) != LEMPTY) {
		errors.bad = true;
	}

	if (payloads->notification != v2N_NOTHING_WRONG) {
		bool found = false;
		for (struct payload_digest *pd = md->chain[ISAKMP_NEXT_v2N];
		     pd != NULL; pd = pd->next) {
			if (pd->payload.v2n.isan_type == payloads->notification) {
				found = true;
				break;
			}
		}
		if (!found) {
			errors.bad = true;
			errors.notification = payloads->notification;
		}
	}

	return errors;
}

const struct state_v2_microcode *find_v2_state_transition(const struct finite_state *state,
							  struct msg_digest *md)
{
	struct ikev2_payload_errors message_payload_status = { .bad = false };
	struct ikev2_payload_errors encrypted_payload_status = { .bad = false };
	for (unsigned i = 0; i < state->nr_transitions; i++) {
		const struct state_v2_microcode *transition = &state->v2_transitions[i];
		/* message type? */
		if (transition->recv_type != md->hdr.isa_xchg) {
			continue;
		}
		/* role? */
		if (transition->flags & SMF2_MESSAGE_RESPONSE &&
		    v2_msg_role(md) != MESSAGE_RESPONSE) {
			continue;
		}
		if (transition->flags & SMF2_MESSAGE_REQUEST &&
		    v2_msg_role(md) != MESSAGE_REQUEST) {
			continue;
		}
		/* message payloads */
		if (!pexpect(md->message_payloads.parsed)) {
			return NULL;
		}
		struct ikev2_payload_errors message_payload_errors
			= ikev2_verify_payloads(md, &md->message_payloads,
						&transition->message_payloads);
		if (message_payload_errors.bad &&
		    !message_payload_status.bad) {
			/* save first */
			message_payload_status = message_payload_errors;
			continue;
		}
		if (!(transition->message_payloads.required & P(SK))) {
			return transition;
		}
		/* SK{} payloads */
		if (!pexpect(md->encrypted_payloads.parsed)) {
			return NULL;
		}
		struct ikev2_payload_errors encrypted_payload_errors
			= ikev2_verify_payloads(md, &md->encrypted_payloads,
						&transition->encrypted_payloads);
		if (encrypted_payload_errors.bad &&
		    !encrypted_payload_status.bad) {
			/* save first */
			encrypted_payload_status = encrypted_payload_errors;
			continue;
		}
		return transition;
	}
	/*
	 * All branches: log error, [complete transition] (why),
	 * return so first error wins.
	 */
	if (message_payload_status.bad) {
		/*
		 * A very messed up message - none of the state
		 * transitions recognized it!.
		 */
		log_v2_payload_errors(NULL, md, &message_payload_status);
	} else {
		pexpect(encrypted_payload_status.bad);
		log_v2_payload_errors(NULL, md, &encrypted_payload_status);
	}
	return NULL;

}

/*
 * report problems - but less so when OE
 */

void log_v2_payload_errors(struct state *st, struct msg_digest *md,
			   const struct ikev2_payload_errors *errors)
{
	if (!DBGP(DBG_OPPO)) {
		/*
		 * ??? this logic is contorted.
		 * If we have no state, we act as if this is opportunistic.
		 * But if there is a state, but no connection,
		 * we act as if this is NOT opportunistic.
		 */
		if (st == NULL ||
		    (st->st_connection != NULL &&
		     (st->st_connection->policy & POLICY_OPPORTUNISTIC)))
		{
			return;
		}
	}

	/* LOG_MESSAGE(RC_LOG_SERIOUS, st, NULL, &md->from, buf) */
	LSWLOG_RC(RC_LOG_SERIOUS, buf) {
		const enum isakmp_xchg_types ix = md->hdr.isa_xchg;
		jam(buf, "dropping unexpected ");
		jam_enum_short(buf, &ikev2_exchange_names, ix);
		jam(buf, " message");
		/* we want to print and log the first notify payload */
		struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N];
		if (ntfy != NULL) {
			jam(buf, " containing ");
			jam_enum_short(buf, &ikev2_notify_names,
				       ntfy->payload.v2n.isan_type);
			if (ntfy->next != NULL) {
				jam(buf, "...");
			}
			jam(buf, " notification");
		}
		if (md->message_payloads.parsed) {
			jam(buf, "; message payloads: ");
			jam_enum_lset_short(buf, &ikev2_payload_names, ",",
					    md->message_payloads.present);
		}
		if (md->encrypted_payloads.parsed) {
			jam(buf, "; encrypted payloads: ");
			jam_enum_lset_short(buf, &ikev2_payload_names, ",",
					       md->encrypted_payloads.present);
		}
		if (errors->missing != LEMPTY) {
			jam(buf, "; missing payloads: ");
			jam_enum_lset_short(buf, &ikev2_payload_names, ",",
					    errors->missing);
		}
		if (errors->unexpected != LEMPTY) {
			jam(buf, "; unexpected payloads: ");
			jam_enum_lset_short(buf, &ikev2_payload_names, ",",
					    errors->unexpected);
		}
		if (errors->excessive != LEMPTY) {
			jam(buf, "; excessive payloads: ");
			jam_enum_lset_short(buf, &ikev2_payload_names, ",",
					       errors->excessive);
		}
		if (errors->notification != v2N_NOTHING_WRONG) {
			jam(buf, "; missing notification ");
			jam_enum_short(buf, &ikev2_notify_names,
				       errors->notification);
		}
	}
}
