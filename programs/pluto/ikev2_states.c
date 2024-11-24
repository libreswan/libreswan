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

#define vdbg_ft(FORMAT, ...)			\
	vdbg("ft: "FORMAT, ##__VA_ARGS__)

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
#include "ikev2_liveness.h"
#include "ikev2_cookie.h"
#include "ikev2_redirect.h"
#include "ikev2_eap.h"
#include "ikev2_create_child_sa.h"
#include "ikev2_delete.h"
#include "log_limiter.h"		/* for payload_errors_log_limiter; */
#include "verbose.h"

struct ikev2_payload_errors {
	bool bad;
	lset_t excessive;
	lset_t missing;
	lset_t unexpected;
	v2_notification_t notification;
};

static void llog_v2_payload_errors(struct logger *logger, const struct msg_digest *md,
				   const struct ikev2_payload_errors *errors);

static void jam_v2_payload_errors(struct jambuf *buf, const struct msg_digest *md,
				  const struct ikev2_payload_errors *errors);

static struct ikev2_payload_errors ikev2_verify_payloads(const struct msg_digest *md,
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

static void jam_expected_payloads(struct jambuf *buf,
				  const struct ikev2_expected_payloads *payloads)
{
	jam_string(buf, "(");
	jam_lset_short(buf, &ikev2_payload_names, "+",
		       payloads->required);
	jam_string(buf, ")[");
	jam_lset_short(buf, &ikev2_payload_names, "_",
		       payloads->optional);
	jam_string(buf, "]");
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
	 /*
	  * Informational.  Order is important.
	  *
	  * The liveness probe, which strictly matches an empty
	  * message must be before the generic informational exchange.
	  * Otherwise the generic exchange, which can accept an empty
	  * message, would do the processing.
	  */
	 &v2_INFORMATIONAL_v2DELETE_exchange,
	 &v2_INFORMATIONAL_v2N_REDIRECT_exchange,
	 &v2_INFORMATIONAL_liveness_exchange,
	 &v2_INFORMATIONAL_exchange, /* last; matches mobike! */
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

struct ikev2_payload_errors ikev2_verify_payloads(const struct msg_digest *md,
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

	/*
	 * LIVENESS really does want to only match an empty message
	 * and, hence, does not want everywhere_payloads in the
	 * responder.
	 */
	lset_t opt_payloads = (payloads->exact_match ? payloads->optional :
			       payloads->optional | everywhere_payloads);
	lset_t req_payloads = payloads->required;

	struct ikev2_payload_errors errors = {
		.bad = false,
		.excessive = summary->repeated & ~repeatable_payloads,
		.missing = req_payloads & ~seen,
		.unexpected = seen & ~req_payloads & ~opt_payloads,
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

static const struct v2_transition *find_v2_transition(struct verbose verbose,
						      const struct msg_digest *md,
						      const struct v2_transitions *transitions,
						      struct ikev2_payload_errors *message_payload_status,
						      struct ikev2_payload_errors *encrypted_payload_status)
{
	const unsigned level = verbose.level;
	enum message_role role = v2_msg_role(md);

	FOR_EACH_ITEM(transition, transitions) {

		verbose.level = level;
		vdbg_ft("trying %s ...", transition->story);
		verbose.level++;

		/* message type? */
		if (transition->exchange != md->hdr.isa_xchg) {
			enum_buf xb;
			vdbg_ft("exchange type does not match %s",
				str_enum_short(&ikev2_exchange_names, transition->exchange, &xb));
			continue;
		}

		/* role? */
		if (transition->recv_role != role) {
			enum_buf rb;
			vdbg_ft("message role does not match %s",
				str_enum_short(&message_role_names, transition->recv_role, &rb));
			continue;
		}

		/* message payloads */
		if (!vexpect(md->message_payloads.parsed)) {
			return NULL;
		}
		struct ikev2_payload_errors message_payload_errors
			= ikev2_verify_payloads(md, &md->message_payloads,
						&transition->message_payloads);
		if (message_payload_errors.bad) {
			LDBGP_JAMBUF(DBG_BASE, verbose.logger, buf) {
				jam(buf, PRI_VERBOSE, pri_verbose);
				jam(buf, "message payloads do not match ");
				jam_expected_payloads(buf, &transition->message_payloads);
			}
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
			vexpect((transition->message_payloads.required & v2P(SK)) == LEMPTY);
			LDBGP_JAMBUF(DBG_BASE, verbose.logger, buf) {
				jam(buf, PRI_VERBOSE, pri_verbose);
				jam(buf, "unsecured message matched ");
				jam_expected_payloads(buf, &transition->message_payloads);
			}
			return transition;
		}

		/*
		 * Since SK{} payloads are expected, the caller should
		 * have parsed them.
		 */
		if (!vexpect((transition->message_payloads.required & v2P(SK)) != LEMPTY)) {
			continue;
		}
		if (!vexpect(md->encrypted_payloads.parsed)) {
			return NULL;
		}

		struct ikev2_payload_errors encrypted_payload_errors
			= ikev2_verify_payloads(md, &md->encrypted_payloads,
						&transition->encrypted_payloads);
		if (encrypted_payload_errors.bad) {
			LDBGP_JAMBUF(DBG_BASE, verbose.logger, buf) {
				jam(buf, PRI_VERBOSE, pri_verbose);
				jam_string(buf, "secured payloads do not match ");
				jam_expected_payloads(buf, &transition->encrypted_payloads);
			}
			/* save error for last pattern!?! */
			*encrypted_payload_status = encrypted_payload_errors;
			continue;
		}

		LDBGP_JAMBUF(DBG_BASE, verbose.logger, buf) {
			jam(buf, PRI_VERBOSE, pri_verbose);
			jam_string(buf, "secured message matched ");
			jam_expected_payloads(buf, &transition->message_payloads);
			jam_string(buf, " ");
			jam_expected_payloads(buf, &transition->encrypted_payloads);
		}
		return transition;
	}

	return NULL;
}

const struct v2_transition *find_v2_secured_transition(struct ike_sa *ike,
						       const struct msg_digest *md,
						       bool *secured_payload_failed)
{
	enum message_role role = v2_msg_role(md);

	enum_buf xb, rb;
	VERBOSE_DBGP(DBG_BASE, ike->sa.logger,
		     "looking for secured transition matching exchange %s %s ...",
		     str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
		     str_enum_short(&message_role_names, role, &rb));
	vassert(secured_payload_failed != NULL);

	struct ikev2_payload_errors message_payload_status = { .bad = false };
	struct ikev2_payload_errors encrypted_payload_status = { .bad = false };

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
		const unsigned level = verbose.level;
		FOR_EACH_ITEM(exchangep, ike->sa.st_state->v2.ike_exchanges) {
			const struct v2_exchange *exchange = (*exchangep);

			verbose.level = level;
			vdbg_ft("trying exchange %s ...", exchange->subplot);
			verbose.level++;

			if (exchange->type != md->hdr.isa_xchg) {
				vdbg_ft("wrong exchange type");
				continue;
			}
			const struct v2_transition *t =
				find_v2_transition(verbose, md,
						   exchange->responder,
						   &message_payload_status,
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
		vassert(exchange != NULL);
		const struct v2_transition *t =
			find_v2_transition(verbose, md,
					   exchange->response,
					   &message_payload_status,
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
		llog_v2_payload_errors(ike->sa.logger, md,
				       &message_payload_status);
		return NULL;
	}

	if (encrypted_payload_status.bad) {
		llog_v2_payload_errors(ike->sa.logger, md,
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

diag_t find_v2_unsecured_transition(struct logger *logger,
				    const struct v2_transitions *transitions,
				    const struct msg_digest *md,
				    const struct v2_transition **transition)
{
	enum message_role role = v2_msg_role(md);

	enum_buf xb, rb;
	VERBOSE_DBGP(DBG_BASE, logger,
		     "looking for an unsecured transition matching exchange %s %s ...",
		     str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
		     str_enum_short(&message_role_names, role, &rb));

	struct ikev2_payload_errors message_payload_status = { .bad = false };
	(*transition) = find_v2_transition(verbose, md, transitions,
					   &message_payload_status, NULL);
	if (*transition != NULL) {
		return NULL;
	}

	/*
	 * A very messed up message - none of the state
	 * transitions recognized it!.
	 */
	diag_t d = NULL;
	JAMBUF(buf) {
		jam_v2_payload_errors(buf, md, &message_payload_status);
		d = diag_jambuf(buf);
	}
	return d;
}

bool is_plausible_secured_v2_exchange(struct ike_sa *ike, struct msg_digest *md)
{
	enum message_role role = v2_msg_role(md);

	enum_buf xb, rb;
	VERBOSE_DBGP(DBG_BASE, ike->sa.logger,
		     "looking for plausible secured exchange matching %s %s ...",
		     str_enum_short(&ikev2_exchange_names, md->hdr.isa_xchg, &xb),
		     str_enum_short(&message_role_names, role, &rb));

	/*
	 * See if the decrypted message payloads include the secured
	 * SK|SKF payload.
	 *
	 * At this point, only the message payloads have been parsed.
	 */
	vassert(md->message_payloads.parsed);
	vassert(!md->encrypted_payloads.parsed);
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
		vdbg_ft("plausible; exchange type matches responder %s exchange",
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
		vdbg_ft("plausible; exchange type matches outstanding %s exchange",
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

void llog_v2_payload_errors(struct logger *logger,
			    const struct msg_digest *md,
			    const struct ikev2_payload_errors *errors)
{
	lset_t rc_flags = log_limiter_rc_flags(logger, PAYLOAD_ERRORS_LOG_LIMITER);
	if (rc_flags == LEMPTY) {
		return;
	}

	LLOG_JAMBUF(rc_flags, logger, buf) {
		jam_v2_payload_errors(buf, md, errors);
	}
}

void jam_v2_payload_errors(struct jambuf *buf, const struct msg_digest *md,
			   const struct ikev2_payload_errors *errors)
{
	/*
	 * Ignore .bad; who is this function to judge that the message
	 * is at fault (invalid or unexpected) when, in truth, the
	 * cause is a gap in the state machine.
	 */
	const enum ikev2_exchange ix = md->hdr.isa_xchg;
	jam_enum_short(buf, &ikev2_exchange_names, ix);
	jam_string(buf, " ");
	jam_enum_human(buf, &message_role_names, v2_msg_role(md));
	/* we want to print and log the first notify payload */
	struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N];
	if (ntfy != NULL) {
		jam_string(buf, " containing ");
		jam_enum_short(buf, &v2_notification_names,
			       ntfy->payload.v2n.isan_type);
		if (ntfy->next != NULL) {
			jam_string(buf, "...");
		}
		jam_string(buf, " notification");
	}
	jam(buf, " (Message ID %u", md->hdr.isa_msgid);
	if (md->message_payloads.parsed) {
		jam_string(buf, ";");
		if (md->message_payloads.present == LEMPTY) {
			jam_string(buf, " no payloads");
		} else {
			jam_string(buf, " message payloads ");
			jam_lset_short(buf, &ikev2_payload_names, ",",
				       md->message_payloads.present);
		}
		if (md->encrypted_payloads.present != LEMPTY) {
			jam_string(buf, ", encrypted payloads ");
			jam_lset_short(buf, &ikev2_payload_names, ",",
				       md->encrypted_payloads.present);
		}
		if (errors->missing != LEMPTY) {
			jam_string(buf, ", missing ");
			jam_lset_short(buf, &ikev2_payload_names, ",",
				       errors->missing);
		}
		if (errors->unexpected != LEMPTY) {
			jam_string(buf, ", unexpected ");
			jam_lset_short(buf, &ikev2_payload_names, ",",
				       errors->unexpected);
		}
		if (errors->excessive != LEMPTY) {
			jam_string(buf, ", excessive ");
			jam_lset_short(buf, &ikev2_payload_names, ",",
				       errors->excessive);
		}
		if (errors->notification != v2N_NOTHING_WRONG) {
			jam_string(buf, ", no ");
			jam_enum_short(buf, &v2_notification_names,
				       errors->notification);
			jam_string(buf, " notification");
		}
	}
	jam_string(buf, ")");
}

static void vdbg_transition(struct verbose verbose,
			    const struct v2_transition *t)
{
	if (DBGP(DBG_BASE)) {

		LLOG_JAMBUF(DEBUG_STREAM, verbose.logger, buf) {
			jam(buf, PRI_VERBOSE, pri_verbose);
			jam_string(buf, "->");
			jam_enum_short(buf, &ikev2_exchange_names, t->exchange);
			jam_string(buf, "; ");
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

		verbose.level++;

		if (t->from[0] != NULL) {
			LLOG_JAMBUF(DEBUG_STREAM, verbose.logger, buf) {
				jam(buf, PRI_VERBOSE, pri_verbose);
				jam_string(buf, "from:");
				FOR_EACH_ELEMENT(f, t->from) {
					if ((*f) == NULL) {
						break;
					}
					jam_string(buf, " ");
					jam_string(buf, (*f)->short_name);
				}
			}
		}

		LDBG_log(verbose.logger, PRI_VERBOSE"%s", pri_verbose, t->story);

		LLOG_JAMBUF(DEBUG_STREAM, verbose.logger, buf) {
			jam(buf, PRI_VERBOSE, pri_verbose);
			jam_string(buf, "->");
			jam_string(buf, (t->to == NULL ? "<NULL>" :
					 t->to->short_name));
			jam_string(buf, "; ");
			jam_enum_short(buf, &event_type_names, t->timeout_event);
		}


	}
}

static void validate_state_child_transition(struct verbose verbose,
					    const struct finite_state *from,
					    const struct v2_transition *t)
{
	bool found_from = false;
	FOR_EACH_ELEMENT(f, t->from) {
		if (*f == from) {
			found_from = true;
		}
	}
	vassert(found_from);

	const struct finite_state *to = t->to;
	vassert(to != NULL);
	vassert(to->kind >= STATE_IKEv2_FLOOR);
	vassert(to->kind < STATE_IKEv2_ROOF);
	vassert(to->ike_version == IKEv2);
	vdbg_transition(verbose, t);
	FOR_EACH_THING(payloads, &t->message_payloads, &t->encrypted_payloads) {
		vassert(payloads->notification == 0);
		vassert(payloads->required == LEMPTY);
		vassert(payloads->optional == LEMPTY);
	}
	vassert(t->exchange != 0);
	vassert(t->recv_role == 0);
	vassert(t->processor == NULL);
	vassert(t->llog_success == NULL);
}

static void validate_state_exchange_transition(struct verbose verbose,
					       const struct v2_transition *transition,
					       enum message_role recv_role,
					       const struct v2_exchange *exchange)
{
	vdbg_transition(verbose, transition);
	vassert(transition->llog_success != NULL);
	vassert(transition->recv_role == recv_role);
	vassert(transition->exchange == exchange->type);
	vassert(transition->from[0] == NULL);
}

static void validate_state_exchange(struct verbose verbose,
				    const struct finite_state *from,
				    const struct v2_exchange *exchange)
{
	enum_buf ixb;
	vdbg("=>%s (%s); secured: %s",
	     str_enum_short(&ikev2_exchange_names, exchange->type, &ixb),
	     (exchange->subplot == NULL ? "<subplot>" : exchange->subplot),
	     bool_str(exchange->secured));
	const unsigned level = ++verbose.level;

	verbose.level = level;
	if (verbose.rc_flags != 0) {
		LLOG_JAMBUF(verbose.rc_flags, verbose.logger, buf) {
			jam(buf, PRI_VERBOSE, pri_verbose);
			jam_string(buf, "from:");
			FOR_EACH_ELEMENT(f, exchange->initiate.from) {
				if ((*f) == NULL) {
					break;
				}
				jam_string(buf, " ");
				jam_string(buf, (*f)->short_name);
			}
		}
	}

	verbose.level = level;
	if (exchange->initiate.transition != NULL) {
		vdbg("initiator:");
		verbose.level++;
		validate_state_exchange_transition(verbose, exchange->initiate.transition, NO_MESSAGE, exchange);
	}

	verbose.level = level;
	if (exchange->responder != NULL) {
		vdbg("responder:");
		verbose.level++;
		FOR_EACH_ITEM(t, exchange->responder) {
			validate_state_exchange_transition(verbose, t, MESSAGE_REQUEST, exchange);
		}
	}

	verbose.level = level;
	if (exchange->response != NULL) {
		vdbg("response:");
		verbose.level++;
		FOR_EACH_ITEM(t, exchange->response) {
			validate_state_exchange_transition(verbose, t, MESSAGE_RESPONSE, exchange);
		}
	}

	verbose.level = level;
	vassert(exchange->subplot != NULL);
	vassert(from->v2.secured == exchange->secured);

	/* does the exchange appear in the state's transitions? */
	bool found_transition = false;
	FOR_EACH_ITEM(t, exchange->responder) {
		if (t->exchange == exchange->type) {
			found_transition = true;
			break;
		}
	}
	vassert(found_transition);
}

static void validate_state(struct verbose verbose, const struct finite_state *from)
{
	if (DBGP(DBG_BASE)) {
		LLOG_JAMBUF(DEBUG_STREAM, verbose.logger, buf) {
			jam(buf, PRI_VERBOSE, pri_verbose);
			jam_finite_state(buf, from);
		}
	}
	const unsigned level = ++verbose.level;

	/*
	 * Validate transitions XOR exchanges.  Can have at most one.
	 */

	vassert((from->v2.child_transition == NULL) ||
		(from->v2.ike_exchanges == NULL));

	if (from->v2.child_transition != NULL) {
		verbose.level = level;
		vdbg("child transition:");
		verbose.level++;
		validate_state_child_transition(verbose, from, from->v2.child_transition);
	}

	verbose.level = level;
	vdbg("exchanges:");
	verbose.level++;
	FOR_EACH_ITEM(exchange, from->v2.ike_exchanges) {
		validate_state_exchange(verbose, from, *exchange);
	}
}

void init_ikev2_states(struct logger *logger)
{
	VERBOSE_DBGP(DBG_BASE, logger, "checking IKEv2 state table");
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
			llog_passert(verbose.logger, HERE, "entry %d is NULL", kind);
		}
		vassert(fs->kind == kind);
		vassert(fs->ike_version == IKEv2);
		vassert(finite_states[kind] == NULL);
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
		validate_state(verbose, from);
	}

}
