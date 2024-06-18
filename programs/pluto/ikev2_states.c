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

#define ldbg_ft(LOGGER, FORMAT, ...)		\
	ldbg(LOGGER, "ft: %*s"FORMAT, indent*2, "", ##__VA_ARGS__)

#include "defs.h"
#include "state.h"
#include "ikev2_states.h"
#include "demux.h"
#include "ikev2.h"
#include "log.h"
#include "connections.h"
#include "ikev2_notify.h"
#include "ikev2_retransmit.h"
#include "ikev2_ike_sa_init.h"
#include "ikev2_ike_auth.h"
#include "ikev2_ike_sa_init.h"
#include "ikev2_ike_intermediate.h"
#include "ikev2_informational.h"
#include "ikev2_cookie.h"
#include "ikev2_redirect.h"
#include "ikev2_eap.h"
#include "ikev2_create_child_sa.h"
#include "ikev2_delete.h"

struct ikev2_payload_errors {
	bool bad;
	lset_t excessive;
	lset_t missing;
	lset_t unexpected;
	v2_notification_t notification;
};

static void log_v2_payload_errors(struct logger *logger, struct msg_digest *md,
				  const struct ikev2_payload_errors *errors);

static struct ikev2_payload_errors ikev2_verify_payloads(struct msg_digest *md,
							 const struct payload_summary *summary,
							 const struct ikev2_expected_payloads *payloads);

#define V2_CHILD(KIND, STORY, CAT, ...)					\
									\
	const struct finite_state state_v2_##KIND = {			\
		.kind = STATE_V2_##KIND,				\
		.name = #KIND,						\
		/* Not using #KIND + 6 because of clang's -Wstring-plus-int */ \
		.short_name = #KIND,					\
		.story = STORY,						\
		.category = CAT,					\
		.ike_version = IKEv2,					\
		.v2.child_transition = &v2_##KIND##_transition,		\
		##__VA_ARGS__,						\
	}

/*
 * From RFC 5996 syntax: [optional] and {encrypted}
 *
 * Initiator                         Responder
 * -------------------------------------------------------------------
 *
 * IKE_SA_INIT exchange (initial exchange):
 *
 * HDR, SAi1, KEi, Ni            -->
 *                                 <--  HDR, SAr1, KEr, Nr, [CERTREQ]
 *
 * IKE_AUTH exchange (after IKE_SA_INIT exchange):
 *
 * HDR, SK {IDi, [CERT,] [CERTREQ,]
 *        [IDr,] AUTH, SAi2,
 *        TSi, TSr}              -->
 *                                 <--  HDR, SK {IDr, [CERT,] AUTH,
 *                                           SAr2, TSi, TSr}
 * [Parent SA (SAx1) established. Child SA (SAx2) may have been established]
 *
 *
 * Extended IKE_AUTH (see RFC 5996bis 2.6):
 *
 * HDR(A,0), SAi1, KEi, Ni  -->
 *                              <--  HDR(A,0), N(COOKIE)
 * HDR(A,0), N(COOKIE), SAi1,
 *     KEi, Ni  -->
 *                              <--  HDR(A,B), SAr1, KEr,
 *                                       Nr, [CERTREQ]
 * HDR(A,B), SK {IDi, [CERT,]
 *     [CERTREQ,] [IDr,] AUTH,
 *     SAi2, TSi, TSr}  -->
 *                              <--  HDR(A,B), SK {IDr, [CERT,]
 *                                       AUTH, SAr2, TSi, TSr}
 * [Parent SA (SAx1) established. Child SA (SAx2) may have been established]
 *
 *
 * CREATE_CHILD_SA Exchange (new child variant RFC 5996 1.3.1):
 *
 * HDR, SK {SA, Ni, [KEi],
 *            TSi, TSr}  -->
 *                              <--  HDR, SK {SA, Nr, [KEr],
 *                                       TSi, TSr}
 *
 *
 * CREATE_CHILD_SA Exchange (rekey child variant RFC 5996 1.3.3):
 *
 * HDR, SK {N(REKEY_SA), SA, Ni, [KEi],
 *     TSi, TSr}   -->
 *                    <--  HDR, SK {SA, Nr, [KEr],
 *                             TSi, TSr}
 *
 *
 * CREATE_CHILD_SA Exchange (rekey parent SA variant RFC 5996 1.3.2):
 *
 * HDR, SK {SA, Ni, KEi} -->
 *                            <--  HDR, SK {SA, Nr, KEr}
 */

/*
 * CREATE_CHILD_SA exchanges.
 */

/*
 * Child states when rekeying an IKE SA using CREATE_CHILD_SA.
 */

static const struct v2_transition v2_REKEY_IKE_I0_transition = {
	.story      = "initiate rekey IKE_SA (CREATE_CHILD_SA)",
	.from = { &state_v2_REKEY_IKE_I0, },
	.to = &state_v2_REKEY_IKE_I1,
	.exchange   = ISAKMP_v2_CREATE_CHILD_SA,
};

V2_CHILD(REKEY_IKE_I0, "STATE_V2_REKEY_IKE_I0", CAT_IGNORE);

static const struct v2_transition v2_REKEY_IKE_R0_transition = {
	.story      = "process rekey IKE SA request (CREATE_CHILD_SA)",
	.from = { &state_v2_REKEY_IKE_R0, },
	.to = &state_v2_ESTABLISHED_IKE_SA,
	.exchange   = ISAKMP_v2_CREATE_CHILD_SA,
};

V2_CHILD(REKEY_IKE_R0, "STATE_V2_REKEY_IKE_R0", CAT_OPEN_IKE_SA);

static const struct v2_transition v2_REKEY_IKE_I1_transition = {
	.story      = "process rekey IKE SA response (CREATE_CHILD_SA)",
	.from = { &state_v2_REKEY_IKE_I1, },
	.to = &state_v2_ESTABLISHED_IKE_SA,
	.exchange   = ISAKMP_v2_CREATE_CHILD_SA,
};

V2_CHILD(REKEY_IKE_I1, "sent CREATE_CHILD_SA request to rekey IKE SA", CAT_OPEN_CHILD_SA);

/*
 * Child states when rekeying a Child SA using CREATE_CHILD_SA.
 */

static const struct v2_transition v2_REKEY_CHILD_I0_transition = {
	.story      = "initiate rekey Child SA (CREATE_CHILD_SA)",
	.from = { &state_v2_REKEY_CHILD_I0, },
	.to = &state_v2_REKEY_CHILD_I1,
	.exchange   = ISAKMP_v2_CREATE_CHILD_SA,
};

V2_CHILD(REKEY_CHILD_I0, "STATE_V2_REKEY_CHILD_I0", CAT_IGNORE);

static const struct v2_transition v2_REKEY_CHILD_R0_transition = {
	.story      = "process rekey Child SA request (CREATE_CHILD_SA)",
	.from = { &state_v2_REKEY_CHILD_R0, },
	.to = &state_v2_ESTABLISHED_CHILD_SA,
	.exchange   = ISAKMP_v2_CREATE_CHILD_SA,
};

V2_CHILD(REKEY_CHILD_R0, "STATE_V2_REKEY_CHILD_R0", CAT_OPEN_CHILD_SA);

static const struct v2_transition v2_REKEY_CHILD_I1_transition = {
	.story      = "process rekey Child SA response (CREATE_CHILD_SA)",
	.from = { &state_v2_REKEY_CHILD_I1, },
	.to = &state_v2_ESTABLISHED_CHILD_SA,
	.flags = { .release_whack = true, },
	.exchange   = ISAKMP_v2_CREATE_CHILD_SA,
};

V2_CHILD(REKEY_CHILD_I1, "sent CREATE_CHILD_SA request to rekey IPsec SA", CAT_OPEN_CHILD_SA);

/*
 * Child states when creating a new Child SA using CREATE_CHILD_SA.
 */

static const struct v2_transition v2_NEW_CHILD_I0_transition = {
	.story      = "initiate create Child SA (CREATE_CHILD_SA)",
	.from = { &state_v2_NEW_CHILD_I0, },
	.to = &state_v2_NEW_CHILD_I1,
	.exchange   = ISAKMP_v2_CREATE_CHILD_SA,
};

V2_CHILD(NEW_CHILD_I0, "STATE_V2_NEW_CHILD_I0", CAT_IGNORE);

static const struct v2_transition v2_NEW_CHILD_R0_transition = {
	.story      = "process create Child SA request (CREATE_CHILD_SA)",
	.from = { &state_v2_NEW_CHILD_R0, },
	.to = &state_v2_ESTABLISHED_CHILD_SA,
	.exchange   = ISAKMP_v2_CREATE_CHILD_SA,
};

V2_CHILD(NEW_CHILD_R0, "STATE_V2_NEW_CHILD_R0",
	 CAT_OPEN_CHILD_SA);

static const struct v2_transition v2_NEW_CHILD_I1_transition = {
	.story      = "process create Child SA response (CREATE_CHILD_SA)",
	.from = { &state_v2_NEW_CHILD_I1, },
	.to = &state_v2_ESTABLISHED_CHILD_SA,
	.exchange   = ISAKMP_v2_CREATE_CHILD_SA,
};

V2_CHILD(NEW_CHILD_I1, "sent CREATE_CHILD_SA request for new IPsec SA",
	 CAT_OPEN_CHILD_SA);

/*
 * IKEv2 established states.
 */

V2_STATE(ESTABLISHED_IKE_SA, "established IKE SA",
	 CAT_ESTABLISHED_IKE_SA, /*secured*/true,
	 /* informational */
	 &v2_INFORMATIONAL_v2DELETE_exchange,
	 &v2_INFORMATIONAL_v2N_REDIRECT_exchange,
	 &v2_INFORMATIONAL_exchange,
	 /*
	  * Create/Rekey IKE/Child SAs.  Danger: order is important.
	  */
	 &v2_CREATE_CHILD_SA_rekey_ike_exchange,
	 &v2_CREATE_CHILD_SA_rekey_child_exchange,
	 &v2_CREATE_CHILD_SA_new_child_exchange);

V2_STATE(ESTABLISHED_CHILD_SA, "established Child SA",
	 CAT_ESTABLISHED_CHILD_SA, /*secured*/true);

/* ??? better story needed for these */

V2_STATE(ZOMBIE, "deleted state", CAT_ESTABLISHED_IKE_SA, /*secured*/true);

static const struct finite_state *v2_states[] = {
#define S(KIND, ...) [STATE_V2_##KIND - STATE_IKEv2_FLOOR] = &state_v2_##KIND
	S(IKE_SA_INIT_I0),
	S(IKE_SA_INIT_I),
	S(IKE_SA_INIT_R0),
	S(IKE_SA_INIT_R),
	S(IKE_SA_INIT_IR),
	S(IKE_INTERMEDIATE_I),
	S(IKE_INTERMEDIATE_R),
	S(IKE_INTERMEDIATE_IR),
	S(IKE_AUTH_EAP_R),
	S(IKE_AUTH_I),
	S(NEW_CHILD_I0),
	S(NEW_CHILD_I1),
	S(NEW_CHILD_R0),
	S(REKEY_CHILD_I0),
	S(REKEY_CHILD_I1),
	S(REKEY_CHILD_R0),
	S(REKEY_IKE_I0),
	S(REKEY_IKE_I1),
	S(REKEY_IKE_R0),
	S(ESTABLISHED_IKE_SA),
	S(ESTABLISHED_CHILD_SA),
	S(ZOMBIE),
#undef S
};

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

static const lset_t everywhere_payloads = v2P(N) | v2P(V);	/* can appear in any packet */
static const lset_t repeatable_payloads = v2P(N) | v2P(D) | v2P(CP) | v2P(V) | v2P(CERT) | v2P(CERTREQ);	/* if one can appear, many can appear */

struct ikev2_payload_errors ikev2_verify_payloads(struct msg_digest *md,
						  const struct payload_summary *summary,
						  const struct ikev2_expected_payloads *payloads)
{
	/*
	 * Convert SKF onto SK for the comparison (but only when it is
	 * on its own).
	 */
	lset_t seen = summary->present;
	if ((seen & (v2P(SKF)|v2P(SK))) == v2P(SKF)) {
		seen &= ~v2P(SKF);
		seen |= v2P(SK);
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
		enum v2_pd v2_pd = v2_pd_from_notification(payloads->notification);
		if (md->pd[v2_pd] == NULL) {
			errors.bad = true;
			errors.notification = payloads->notification;
		}
	}

	return errors;
}

static const struct v2_transition *find_v2_transition(struct logger *logger, unsigned indent,
						      const struct v2_transitions *transitions,
						      struct msg_digest *md,
						      struct ikev2_payload_errors *message_payload_status,
						      struct ikev2_payload_errors *encrypted_payload_status)
{
	FOR_EACH_ITEM(transition, transitions) {

		ldbg_ft(logger, "trying %s ...", transition->story);

		/* message type? */
		if (transition->exchange != md->hdr.isa_xchg) {
			enum_buf xb;
			ldbg_ft(logger, "  exchange type does not match %s",
				str_enum_short(&ikev2_exchange_names, transition->exchange, &xb));
			continue;
		}

		/* role? */
		if (transition->recv_role != v2_msg_role(md)) {
			enum_buf rb;
			ldbg_ft(logger, "  message role does not match %s",
				str_enum_short(&message_role_names, transition->recv_role, &rb));
			continue;
		}

		/* message payloads */
		if (!PEXPECT(logger, md->message_payloads.parsed)) {
			return NULL;
		}
		struct ikev2_payload_errors message_payload_errors
			= ikev2_verify_payloads(md, &md->message_payloads,
						&transition->message_payloads);
		if (message_payload_errors.bad) {
			ldbg_ft(logger, "  message payloads do not match");
			/* save error for last pattern!?! */
			*message_payload_status = message_payload_errors;
			continue;
		}

		/*
		 * The caller isn't expecting secured payloads (i.e.,
		 * it isn't secured).  There is no SK or SKF payload
		 * so checking is complete and things have matched.
		 */
		if (encrypted_payload_status == NULL) {
			PEXPECT(logger, (transition->message_payloads.required & v2P(SK)) == LEMPTY);
			ldbg_ft(logger, "  unsecured message matched");
			return transition;
		}

		/*
		 * Since SK{} payloads are expected, the caller should
		 * have parsed them.
		 */
		if (!PEXPECT(logger, (transition->message_payloads.required & v2P(SK)) != LEMPTY)) {
			continue;
		}
		if (!PEXPECT(logger, md->encrypted_payloads.parsed)) {
			return NULL;
		}

		struct ikev2_payload_errors encrypted_payload_errors
			= ikev2_verify_payloads(md, &md->encrypted_payloads,
						&transition->encrypted_payloads);
		if (encrypted_payload_errors.bad) {
			ldbg_ft(logger, "  secured payloads do not match");
			/* save error for last pattern!?! */
			*encrypted_payload_status = encrypted_payload_errors;
			continue;
		}

		ldbg_ft(logger, "  secured message matched");
		return transition;
	}

	return NULL;
}

const struct v2_transition *find_v2_secured_transition(struct ike_sa *ike,
						       struct msg_digest *md,
						       bool *secured_payload_failed)
{
	enum_buf xb, rb;
	unsigned indent = 0;
	ldbg_ft(ike->sa.logger, "looking for secured transition matching exchange %s %s ...",
		str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
		str_enum_short(&message_role_names, v2_msg_role(md), &rb));
	indent = 1;
	PASSERT(ike->sa.logger, secured_payload_failed != NULL);

	struct ikev2_payload_errors message_payload_status = { .bad = false };
	struct ikev2_payload_errors encrypted_payload_status = { .bad = false };

	enum message_role role = v2_msg_role(md);
	switch (role) {
	default:
	case NO_MESSAGE:
		bad_enum(md->logger, &message_role_names, role);
		break;
	case MESSAGE_REQUEST:
	{
		/*
		 * Does the message match one of the responder state's
		 * exchanges?
		 *
		 * For instance, the IKE_SA_INIT responder state
		 * accepts a request for the IKE_AUTH and
		 * IKE_INTERMEDIATE exchanges.  With a matching
		 * exchange, look for a matching transition.
		 */
		FOR_EACH_ITEM(exchangep, ike->sa.st_state->v2.ike_exchanges) {
			const struct v2_exchange *exchange = (*exchangep);
			ldbg_ft(ike->sa.logger, "trying exchange %s ...", exchange->subplot);
			if (exchange->type != md->hdr.isa_xchg) {
				ldbg_ft(ike->sa.logger, "  wrong exchange type");
				continue;
			}
			const struct v2_transition *t =
				find_v2_transition(ike->sa.logger, indent+1,
						   exchange->responder,
						   md, &message_payload_status,
						   &encrypted_payload_status);
			if (t != NULL) {
				return t;
			}
		}
		break;
	}
	case MESSAGE_RESPONSE:
	{
		const struct v2_exchange *exchange = ike->sa.st_v2_msgid_windows.initiator.exchange;
		PASSERT(ike->sa.logger, exchange != NULL);
		ldbg_ft(ike->sa.logger, "trying outstanding exchange %s", exchange->subplot);
		const struct v2_transition *t =
			find_v2_transition(ike->sa.logger, indent+1,
					   exchange->response,
					   md, &message_payload_status,
					   &encrypted_payload_status);
		if (t != NULL) {
			return t;
		}
	}
	}

	/*
	 * Always log an error.
	 *
	 * Does the order of message_payload vs secured_payload
	 * matter?  Probably not: all the state transitions for a
	 * secured state have the same message payload set so either
	 * they all match or they all fail.
	 */
	if (message_payload_status.bad) {
		/*
		 * A very messed up message - none of the state
		 * transitions recognized it!.
		 */
		log_v2_payload_errors(ike->sa.logger, md,
				      &message_payload_status);
		return NULL;
	}

	if (encrypted_payload_status.bad) {
		log_v2_payload_errors(ike->sa.logger, md,
				      &encrypted_payload_status);
		/*
		 * Notify caller so that evasive action can be taken.
		 */
		*secured_payload_failed = true;
		return NULL;
	}

	llog(RC_LOG, ike->sa.logger, "no useful state microcode entry found for incoming secured packet");
	return NULL;
}

const struct v2_transition *find_v2_unsecured_transition(struct logger *logger,
							 const struct v2_transitions *transitions,
							 struct msg_digest *md)
{
	unsigned indent = 0;
	enum_buf xb, rb;
	ldbg_ft(logger, "looking for an unsecured transition matching exchange %s %s ...",
		str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
		str_enum_short(&message_role_names, v2_msg_role(md), &rb));
	indent = 1;

	struct ikev2_payload_errors message_payload_status = { .bad = false };
	const struct v2_transition *t = find_v2_transition(logger, indent,
							   transitions, md,
							   &message_payload_status, NULL);
	if (t != NULL) {
		return t;
	}

	/*
	 * A very messed up message - none of the state
	 * transitions recognized it!.
	 */
	if (message_payload_status.bad) {
		log_v2_payload_errors(logger, md,
				      &message_payload_status);
		return NULL;
	}

	llog(RC_LOG, logger, "no useful state microcode entry found for incoming unsecured packet");
	return NULL;
}

bool is_plausible_secured_v2_exchange(struct ike_sa *ike, struct msg_digest *md)
{
	enum message_role role = v2_msg_role(md);
	unsigned indent = 0;

	enum_buf xb, rb;
	ldbg_ft(ike->sa.logger, "looking for plausible secured exchange matching %s %s ...",
		str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
		str_enum_short(&message_role_names, v2_msg_role(md), &rb));
	indent = 1;

	/*
	 * See if the decrypted message payloads include the secured
	 * SK|SKF payload.
	 *
	 * At this point, only the message payloads have been parsed.
	 */
	PASSERT(ike->sa.logger, md->message_payloads.parsed);
	PEXPECT(ike->sa.logger, !md->encrypted_payloads.parsed);
	if ((md->message_payloads.present & (v2P(SK) | v2P(SKF))) == LEMPTY) {
		llog(RC_LOG, ike->sa.logger, "missing SK or SKF payload; message dropped");
		return false;
	}

	/*
	 * Is there an exchange with the same message type?
	 */
	const struct v2_exchange *exchange = NULL;
	switch (role) {
	case NO_MESSAGE:
		bad_case(role);
	case MESSAGE_REQUEST:
		FOR_EACH_ITEM(e, ike->sa.st_state->v2.ike_exchanges) {
			if ((*e)->type == md->hdr.isa_xchg) {
				exchange = (*e);
				break;
			}
		}
		if (exchange == NULL) {
			enum_buf xb;
			llog(RC_LOG, ike->sa.logger, "unexpected %s request; message dropped",
			     str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb));
			return false;
		}
		ldbg_ft(ike->sa.logger, "plausible; exchange type matches responder %s exchange",
		     exchange->subplot);
		break;
	case MESSAGE_RESPONSE:
		exchange = ike->sa.st_v2_msgid_windows.initiator.exchange;
		if (PBAD(ike->sa.logger, exchange == NULL)) {
			return false;
		}
		if (exchange->type != md->hdr.isa_xchg) {
			enum_buf xb, eb;
			llog(RC_LOG, ike->sa.logger, "unexpected %s response, expecting %s (%s); message dropped",
			     str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
			     str_enum_short(&ikev2_exchange_names, exchange->type, &eb),
			     exchange->subplot);
			return false;
		}
		ldbg_ft(ike->sa.logger, "plausible; exchange type matches outstanding %s exchange",
		     exchange->subplot);
		break;
	}

	/*
	 * Double check that the matching exchange is secured.
	 */
	if (!exchange->secured) {
		enum_buf rb;
		enum_buf xb;
		llog_pexpect(ike->sa.logger, HERE, "%s %s (%s) exchange should be secured",
			     str_enum_short(&ikev2_exchange_names, exchange->type, &xb),
			     str_enum_short(&message_role_names, role, &rb),
			     exchange->subplot);
		return false;
	}

	return true;
}

/*
 * report problems - but less so when OE
 */

void log_v2_payload_errors(struct logger *logger, struct msg_digest *md,
			   const struct ikev2_payload_errors *errors)
{
	enum stream log_stream;
	if (suppress_log(logger)) {
		if (DBGP(DBG_BASE)) {
			log_stream = DEBUG_STREAM;
		} else {
			/*
			 * presumably the responder so tone things
			 * down
			 */
			return;
		}
	} else {
		log_stream = ALL_STREAMS;
	}

	LLOG_JAMBUF(RC_LOG | log_stream, logger, buf) {
		const enum ikev2_exchange ix = md->hdr.isa_xchg;
		jam(buf, "dropping unexpected ");
		jam_enum_short(buf, &ikev2_exchange_names, ix);
		jam(buf, " message");
		/* we want to print and log the first notify payload */
		struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N];
		if (ntfy != NULL) {
			jam(buf, " containing ");
			jam_enum_short(buf, &v2_notification_names,
				       ntfy->payload.v2n.isan_type);
			if (ntfy->next != NULL) {
				jam(buf, "...");
			}
			jam(buf, " notification");
		}
		if (md->message_payloads.parsed) {
			jam(buf, "; message payloads: ");
			jam_lset_short(buf, &ikev2_payload_names, ",",
				       md->message_payloads.present);
		}
		if (md->encrypted_payloads.parsed) {
			jam(buf, "; encrypted payloads: ");
			jam_lset_short(buf, &ikev2_payload_names, ",",
				       md->encrypted_payloads.present);
		}
		if (errors->missing != LEMPTY) {
			jam(buf, "; missing payloads: ");
			jam_lset_short(buf, &ikev2_payload_names, ",",
				       errors->missing);
		}
		if (errors->unexpected != LEMPTY) {
			jam(buf, "; unexpected payloads: ");
			jam_lset_short(buf, &ikev2_payload_names, ",",
				       errors->unexpected);
		}
		if (errors->excessive != LEMPTY) {
			jam(buf, "; excessive payloads: ");
			jam_lset_short(buf, &ikev2_payload_names, ",",
				       errors->excessive);
		}
		if (errors->notification != v2N_NOTHING_WRONG) {
			jam(buf, "; missing notification ");
			jam_enum_short(buf, &v2_notification_names,
				       errors->notification);
		}
	}
}

static void ldbg_transition(struct logger *logger, const char *indent,
			    const struct v2_transition *t)
{
	if (DBGP(DBG_BASE)) {

		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam_string(buf, indent);
			jam_string(buf, "-> ");
			jam_string(buf, (t->to == NULL ? "<NULL>" :
					 t->to->short_name));
			jam_string(buf, "; ");
			jam_enum_short(buf, &event_type_names, t->timeout_event);
		}

		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam_string(buf, indent);
			jam_string(buf, "   ");
			switch (t->recv_role) {
			case NO_MESSAGE:
				/* reverse polarity */
				jam_string(buf, "initiate");
				break;
			case MESSAGE_REQUEST:
				jam_string(buf, "respond");
				break;
			case MESSAGE_RESPONSE:
				jam_string(buf, "response");
				break;
			default:
				bad_case(t->recv_role);
			}
			jam_string(buf, ": ");
			jam_enum_short(buf, &ikev2_exchange_names, t->exchange);
			jam_string(buf, "; ");
			jam_string(buf, "payloads: ");
			FOR_EACH_THING(payloads, &t->message_payloads, &t->encrypted_payloads) {
				if (payloads->required == LEMPTY &&
				    payloads->optional == LEMPTY) {
					continue;
				}
				bool encrypted = (payloads == &t->encrypted_payloads);
				/* assumes SK is last!!! */
				if (encrypted) {
					jam_string(buf, " {");
				}
				const char *sep = "";
				FOR_EACH_THING(payload, &payloads->required, &payloads->optional) {
					if (*payload == LEMPTY) continue;
					bool optional = (payload == &payloads->optional);
					jam_string(buf, sep); sep = " ";
					if (optional) jam(buf, "[");
					jam_lset_short(buf, &ikev2_payload_names, optional ? "] [" : " ", *payload);
					if (optional) jam(buf, "]");
				}
				if (payloads->notification != 0) {
					jam(buf, " N(");
					jam_enum_short(buf, &v2_notification_names, payloads->notification);
					jam(buf, ")");
				}
				if (encrypted) {
					jam(buf, "}");
				}
			}
		}

		DBG_log("%s   story: %s", indent, t->story);
	}
}

static void validate_state_child_transition(struct logger *logger,
					    const struct finite_state *from,
					    const struct v2_transition *t)
{
	bool found_from = false;
	FOR_EACH_ELEMENT(f, t->from) {
		if (*f == from) {
			found_from = true;
		}
	}
	passert(found_from);

	const struct finite_state *to = t->to;
	passert(to != NULL);
	passert(to->kind >= STATE_IKEv2_FLOOR);
	passert(to->kind < STATE_IKEv2_ROOF);
	passert(to->ike_version == IKEv2);
	ldbg_transition(logger, "     ", t);
	FOR_EACH_THING(payloads, &t->message_payloads, &t->encrypted_payloads) {
		passert(payloads->notification == 0);
		passert(payloads->required == LEMPTY);
		passert(payloads->optional == LEMPTY);
	}
	passert(t->exchange != 0);
	passert(t->recv_role == 0);
	passert(t->processor == NULL);
	passert(t->llog_success == NULL);
}

static void validate_state_exchange(struct logger *logger,
				    const struct finite_state *from,
				    const struct v2_exchange *exchange)
{
	enum_buf ixb;
	ldbg(logger, "     => %s (%s); secured: %s",
	     str_enum_short(&ikev2_exchange_names, exchange->type, &ixb),
	     (exchange->subplot == NULL ? "<subplot>" : exchange->subplot),
	     bool_str(exchange->secured));

	if (exchange->initiate != NULL) {
		ldbg(logger, "        => initiator");
		ldbg_transition(logger, "           ", exchange->initiate);
	}

	if (exchange->responder != NULL) {
		ldbg(logger, "        => responder");
		FOR_EACH_ITEM(t, exchange->responder) {
			ldbg_transition(logger, "           ", t);
			PASSERT(logger, t->exchange == exchange->type);
			PASSERT(logger, t->recv_role == MESSAGE_REQUEST);
		}
	}

	if (exchange->response != NULL) {
		ldbg(logger, "        => response");
		FOR_EACH_ITEM(t, exchange->response) {
			ldbg_transition(logger, "           ", t);
		}
	}

	PASSERT(logger, exchange->subplot != NULL);
	PASSERT(logger, from->v2.secured == exchange->secured);

	/* does the exchange appear in the state's transitions? */
	bool found_transition = false;
	FOR_EACH_ITEM(t, exchange->responder) {
		if (t->exchange == exchange->type) {
			found_transition = true;
			break;
		}
	}
	PASSERT(logger, found_transition);
}

static void validate_state(struct logger *logger, const struct finite_state *from)
{
	if (DBGP(DBG_BASE)) {
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam(buf, "  ");
			jam_finite_state(buf, from);
		}
	}

	/*
	 * Validate transitions XOR exchanges.  Can have at most one.
	 */

	PASSERT(logger, ((from->v2.child_transition == NULL) ||
			 (from->v2.ike_exchanges == NULL)));

	if (from->v2.child_transition != NULL) {
		validate_state_child_transition(logger, from, from->v2.child_transition);
	}

	FOR_EACH_ITEM(exchange, from->v2.ike_exchanges) {
		validate_state_exchange(logger, from, *exchange);
	}
}

void init_ikev2_states(struct logger *logger)
{
	ldbg(logger, "checking IKEv2 state table");
	/* XXX: debug this using <<--selftest --debug-all --stderrlog>> */

	/*
	 * Fill in FINITE_STATES[].
	 *
	 * This is a hack until each finite-state is a separate object
	 * with corresponding edges (aka microcodes).
	 *
	 * XXX: Long term goal is to have a constant FINITE_STATES[]
	 * contain constant pointers and this static writeable array
	 * to just go away.
	 */
	for (enum state_kind kind = STATE_IKEv2_FLOOR; kind < STATE_IKEv2_ROOF; kind++) {
		/* fill in using static struct */
		const struct finite_state *fs = v2_states[kind - STATE_IKEv2_FLOOR];
		if (fs == NULL) {
			llog_passert(logger, HERE, "entry %d is NULL", kind);
		}
		passert(fs->kind == kind);
		passert(fs->ike_version == IKEv2);
		passert(finite_states[kind] == NULL);
		finite_states[kind] = fs;
	}

	/*
	 * Iterate over the state transitions filling in missing bits
	 * and checking for consistency.
	 *
	 * XXX: this misses magic state transitions, such as
	 * v2_liveness_probe, that are not directly attached to a
	 * state.
	 */

	for (enum state_kind kind = STATE_IKEv2_FLOOR; kind < STATE_IKEv2_ROOF; kind++) {
		/* fill in using static struct */
		const struct finite_state *from = finite_states[kind];
		validate_state(logger, from);

	}

}
