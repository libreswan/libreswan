/* demultiplex incoming IKE messages
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Simon Deziel <simon@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2011-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015 Andrew Cagney <andrew.cagney@gmail.com>
 * Copyright (C) 2016 Antony Antony <appu@phenome.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "cookie.h"
#include "id.h"
#include "x509.h"
#include "pluto_x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "ike_alg.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */
#include "ikev2.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "timer.h"
#include "whack.h"      /* requires connections.h */
#include "server.h"
#include "spdb.h"
#include "nat_traversal.h"
#include "vendor.h"
#include "pluto_crypt.h"	/* just for log_crypto_workers() */

#include "alg_info.h" /* for ALG_INFO_IKE_FOREACH */

#include "ietf_constants.h"

#include "plutoalg.h" /* for default_ike_groups */

enum smf2_flags {
	/*
	 * Check the value of the IKE_I flag in the header.
	 *
	 * The original initiator receives packets with the IKE_I bit
	 * clear, while the original resonder receives packets with
	 * the bit set.  Confused?
	 *
	 * The initial IKE_I value should also be saved in "struct
	 * state" so it can be later validated.  Unfortunately there
	 * is no such field so, instead, the value is implicitly
	 * verified by the by the state machine being split into
	 * original initiator and original responder halves.
	 *
	 * Don't assume this flag is present.  If initiator and
	 * responder share states then this value will absent.
	 *
	 * Do not use this to determine ORIGINAL_INITIATOR vs ORIGINAL_RESPONDER.
	 * Instead use either md->original_role or st->st_original_role field.
	 *
	 * Arguably, this could be made a separate 3 state variable.
	 */
	SMF2_IKE_I_SET = LELEM(1),
	SMF2_IKE_I_CLEAR = LELEM(2),

	SMF2_SEND = LELEM(3),

	/*
	 * Is the MSG_R bit set.
	 *
	 * Requests have the bit clear, and responses have it set.
	 *
	 * Don't assume one of these flags are present.  Some state
	 * processors internally deal with both the request and the
	 * reply.
	 *
	 * In general, the relationship MSG_R != IKE_I does not hold
	 * (it just holds during the initial exchange).
	 */
	SMF2_MSG_R_SET = LELEM(5),
	SMF2_MSG_R_CLEAR = LELEM(6),

	/*
	 * Should the SK (secured-by-key) payload be unpacked and
	 * verified?
	 *
	 * The original responder, in R2 state isn't able to decrypt
	 * incomming messages.
	 *
	 * Some state transition processes do their own decryption.
	 */
	SMF2_UNPACK_SK = LELEM(7),
};

/*
 * IKEv2 has slightly different states than IKEv1.
 *
 * IKEv2 puts all the responsability for retransmission on the end that
 * wants to do something, usually, that the initiator. (But, not always
 * the original initiator, of the responder decides it needs to rekey first)
 *
 * Each exchange has a bit that indicates if it is an Initiator message,
 * or if it is a response.  The Responder never retransmits its messages
 * except in response to an Initiator retransmission.
 *
 * The message ID is *NOT* used in the cryptographic state at all, but instead
 * serves the role of a sequence number.  This makes the state machine far
 * simpler, and there really are no exceptions.
 *
 * The upper level state machine is therefore much simpler.
 * The lower level takes care of retransmissions, and the upper layer state
 * machine just has to worry about whether it needs to go into cookie mode,
 * etc.
 *
 * Like IKEv1, IKEv2 can have multiple child SAs.  Like IKEv1, each one of
 * the child SAs ("Phase 2") will get their own state. Unlike IKEv1,
 * an implementation may negotiate multiple CHILD_SAs at the same time
 * using different MessageIDs.  This is enabled by an option (a notify)
 * that the responder sends to the initiator.  The initiator may only
 * do concurrent negotiations if it sees the notify.
 *
 * XXX This implementation does not support concurrency, but it shouldn't be
 *     that hard to do.  The most difficult part will be to map the message IDs
 *     to the right state. Some CHILD_SAs may take multiple round trips,
 *     and each one will have to be mapped to the same state.
 *
 * The IKEv2 state values are chosen from the same state space as IKEv1.
 *
 */


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
 * Convert a payload type into a set index.
 */
#define PINDEX(N) ((N) - ISAKMP_v2PAYLOAD_TYPE_BASE)

/* Short forms for building payload type sets */

#define PT(n) ISAKMP_NEXT_v2 ## n
#define P(N) LELEM(PINDEX(PT(N)))

/* From RFC 5996:
 *
 * 3.10 "Notify Payload": N payload may appear in any message
 *	??? should encryption be required?
 *
 * 3.11 "Delete Payload": multiple D payloads may appear in an
 *	Informational exchange
 *
 * 3.12 "Vendor ID Payload": (multiple) may appear in any message
 *	??? should encryption be required?
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
static const lset_t repeatable_payloads = P(N) | P(D) | P(CP) | P(V);	/* if one can appear, many can appear */

/* microcode to parent first initiator state: not associated with an input packet */
const struct state_v2_microcode ikev2_parent_firststate_microcode =
	/* no state:   --> I1
	 * HDR, SAi1, KEi, Ni -->
	 */
	{ .story      = "initiate IKE_SA_INIT",
	  .state      = STATE_UNDEFINED,
	  .next_state = STATE_PARENT_I1,
	  .flags      = SMF2_IKE_I_CLEAR | SMF2_MSG_R_SET | SMF2_SEND,
	  .processor  = NULL,
	  .timeout_event = EVENT_v2_RETRANSMIT, };

/* microcode for input packet processing */
static const struct state_v2_microcode v2_state_microcode_table[] = {

	/* STATE_PARENT_I1: R1B --> I1B
	 *                     <--  HDR, N
	 * HDR, N, SAi1, KEi, Ni -->
	 */
	{ .story      = "Initiator: process anti-spoofing cookie",
	  .state      = STATE_PARENT_I1,
	  .next_state = STATE_PARENT_I1,
	  .flags = SMF2_IKE_I_CLEAR | SMF2_MSG_R_SET | SMF2_SEND,
	  .req_clear_payloads = P(N),
	  .opt_clear_payloads = LEMPTY,
	  .processor  = ikev2parent_inR1BoutI1B,
	  .recv_type  = ISAKMP_v2_SA_INIT,
	  .timeout_event = EVENT_RETAIN, },

	/* STATE_PARENT_I1: R1 --> I2
	 *                     <--  HDR, SAr1, KEr, Nr, [CERTREQ]
	 * HDR, SK {IDi, [CERT,] [CERTREQ,]
	 *      [IDr,] AUTH, SAi2,
	 *      TSi, TSr}      -->
	 */
	{ .story      = "Initiator: process IKE_SA_INIT reply, initiate IKE_AUTH",
	  .state      = STATE_PARENT_I1,
	  .next_state = STATE_PARENT_I2,
	  .flags = SMF2_IKE_I_CLEAR | SMF2_MSG_R_SET | SMF2_SEND,
	  .req_clear_payloads = P(SA) | P(KE) | P(Nr),
	  .opt_clear_payloads = P(CERTREQ),
	  .processor  = ikev2parent_inR1outI2,
	  .recv_type  = ISAKMP_v2_SA_INIT,
	  .timeout_event = EVENT_v2_RETRANSMIT, },

	/* STATE_PARENT_I2: R2 -->
	 *                     <--  HDR, SK {IDr, [CERT,] AUTH,
	 *                               SAr2, TSi, TSr}
	 * [Parent SA established]
	 */
	{ .story      = "Initiator: process IKE_AUTH response",
	  .state      = STATE_PARENT_I2,
	  .next_state = STATE_PARENT_I3,
	  .flags = SMF2_IKE_I_CLEAR | SMF2_MSG_R_SET,
	  .req_clear_payloads = P(SK),
	  .req_enc_payloads = P(IDr) | P(AUTH) | P(SA) | P(TSi) | P(TSr),
	  .opt_enc_payloads = P(CERT)|P(CP),
	  .processor  = ikev2parent_inR2,
	  .recv_type  = ISAKMP_v2_AUTH,
	  .timeout_event = EVENT_SA_REPLACE, },

	/* no state: none I1 --> R1
	 *                <-- HDR, SAi1, KEi, Ni
	 * HDR, SAr1, KEr, Nr, [CERTREQ] -->
	 */
	{ .story      = "Respond to IKE_SA_INIT",
	  .state      = STATE_UNDEFINED,
	  .next_state = STATE_PARENT_R1,
	  .flags = SMF2_IKE_I_SET | SMF2_MSG_R_CLEAR | SMF2_SEND,
	  .req_clear_payloads = P(SA) | P(KE) | P(Ni),
	  .processor  = ikev2parent_inI1outR1,
	  .recv_type  = ISAKMP_v2_SA_INIT,
	  .timeout_event = EVENT_v2_RESPONDER_TIMEOUT, },

	/* STATE_PARENT_R1: I2 --> R2
	 *                  <-- HDR, SK {IDi, [CERT,] [CERTREQ,]
	 *                             [IDr,] AUTH, SAi2,
	 *                             TSi, TSr}
	 * HDR, SK {IDr, [CERT,] AUTH,
	 *      SAr2, TSi, TSr} -->
	 *
	 * [Parent SA established]
	 */
	{ .story      = "respond to IKE_AUTH",
	  .state      = STATE_PARENT_R1,
	  .next_state = STATE_PARENT_R2,
	  .flags = SMF2_IKE_I_SET | SMF2_MSG_R_CLEAR | SMF2_SEND,
	  .req_clear_payloads = P(SK),
	  .req_enc_payloads = P(IDi) | P(AUTH) | P(SA) | P(TSi) | P(TSr),
	  .opt_enc_payloads = P(CERT) | P(CERTREQ) | P(IDr) | P(CP),
	  .processor  = ikev2parent_inI2outR2,
	  .recv_type  = ISAKMP_v2_AUTH,
	  .timeout_event = EVENT_SA_REPLACE, },

	/*
	 * There are three different CREATE_CHILD_SA's invocations,
	 * this is the combined write up (not in RFC). See above for
	 * individual cases from RFC
	 *
	 * HDR, SK {SA, Ni, [KEi], [N(REKEY_SA)], [TSi, TSr]} -->
	 *                <-- HDR, SK {N}
	 *                <-- HDR, SK {SA, Nr, [KEr], [TSi, TSr]}
	 */

	/* Create Child SA Exchange */
	{ .story      = "I3: CREATE_CHILD_SA",
	  .state      = STATE_PARENT_I3,
	  .next_state = STATE_PARENT_I3,
	  .flags = SMF2_IKE_I_CLEAR | SMF2_MSG_R_CLEAR | SMF2_SEND,
	  .req_clear_payloads = P(SK),
	  .req_enc_payloads = P(SA) | P(Ni),
	  .opt_enc_payloads = P(KE) | P(N) | P(TSi) | P(TSr),
	  .processor  = ikev2_child_inIoutR,
	  .recv_type  = ISAKMP_v2_CREATE_CHILD_SA,
	  .timeout_event = EVENT_SA_REPLACE, },

	/* Create Child SA Exchange */
	{ .story      = "R2: CREATE_CHILD_SA",
	  .state      = STATE_PARENT_R2,
	  .next_state = STATE_PARENT_R2,
	  .flags = SMF2_IKE_I_SET | SMF2_MSG_R_CLEAR | SMF2_SEND,
	  .req_clear_payloads = P(SK),
	  .req_enc_payloads = P(SA) | P(Ni),
	  .opt_enc_payloads = P(KE) | P(N) | P(TSi) | P(TSr),
	  .processor  = ikev2_child_inIoutR,
	  .recv_type  = ISAKMP_v2_CREATE_CHILD_SA,
	  .timeout_event = EVENT_SA_REPLACE, },

	/* Informational Exchange */

	/* RFC 5996 1.4 "The INFORMATIONAL Exchange"
	 *
	 * HDR, SK {[N,] [D,] [CP,] ...}  -->
	 *   <--  HDR, SK {[N,] [D,] [CP], ...}
	 */

	{ .story      = "I3: INFORMATIONAL",
	  .state      = STATE_PARENT_I3,
	  .next_state = STATE_PARENT_I3,
	  .flags      = SMF2_IKE_I_CLEAR,
	  .req_clear_payloads = P(SK),
	  .opt_enc_payloads = P(N) | P(D) | P(CP),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_RETAIN, },

	{ .story      = "R2: process INFORMATIONAL",
	  .state      = STATE_PARENT_R2,
	  .next_state = STATE_PARENT_R2,
	  .flags      = SMF2_IKE_I_SET,
	  .req_clear_payloads = P(SK),
	  .opt_enc_payloads = P(N) | P(D) | P(CP),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_RETAIN, },

	{ .story      = "IKE_SA_DEL: process INFORMATIONAL",
	  .state      = STATE_IKESA_DEL,
	  .next_state = STATE_IKESA_DEL,
	  .flags      = 0,
	  .req_clear_payloads = P(SK),
	  .opt_enc_payloads = P(N) | P(D) | P(CP),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_RETAIN, },

	/* last entry */
	{ .story      = "roof",
	  .state      = STATE_IKEv2_ROOF }
};

#undef P
#undef PT

/*
 * split an incoming message into payloads
 */
struct ikev2_payloads_summary ikev2_decode_payloads(struct msg_digest *md,
						    pb_stream    *in_pbs,
						    enum next_payload_types_ikev2 np)
{
	struct payload_digest *pd = md->digest_roof;
	struct ikev2_payloads_summary summary = {
		.status = STF_OK,
		.seen = LEMPTY,
		.repeated = LEMPTY,
	};

	/*
	 * ??? zero out the digest descriptors -- might nuke
	 * ISAKMP_NEXT_v2SK digest!
	 */

	while (np != ISAKMP_NEXT_v2NONE) {
		DBG(DBG_CONTROL,
		    DBG_log("Now let's proceed with payload (%s)",
			    enum_show(&ikev2_payload_names, np)));

		if (pd == &md->digest[PAYLIMIT]) {
			loglog(RC_LOG_SERIOUS,
			       "more than %d payloads in message; ignored",
			       PAYLIMIT);
			summary.status = STF_FAIL + v2N_INVALID_SYNTAX;
			break;
		}
		zero(pd);	/* ??? is this needed? */

		struct_desc *sd = v2_payload_desc(np);

		if (sd == NULL) {
			/*
			 * This payload is unknown to us.  RFCs 4306
			 * and 5996 2.5 say that if the payload has
			 * the Critical Bit, we should be upset but if
			 * it does not, we should just ignore it.
			 */
			if (!in_struct(&pd->payload, &ikev2_generic_desc, in_pbs, &pd->pbs)) {
				loglog(RC_LOG_SERIOUS, "malformed payload in packet");
				summary.status = STF_FAIL + v2N_INVALID_SYNTAX;
				break;
			}
			if (pd->payload.v2gen.isag_critical & ISAKMP_PAYLOAD_CRITICAL) {
				/*
				 * It was critical.  See RFC 5996 1.5
				 * "Version Numbers and Forward
				 * Compatibility" ??? we are supposed
				 * to send the offending np byte back
				 * in the notify payload.
				 */
				loglog(RC_LOG_SERIOUS,
				       "critical payload (%s) was not understood. Message dropped.",
				       enum_show(&ikev2_payload_names, np));
				summary.status = STF_FAIL + v2N_UNSUPPORTED_CRITICAL_PAYLOAD;
				break;
			}
			loglog(RC_COMMENT,
				"non-critical payload ignored because it contains an unknown or unexpected payload type (%s) at the outermost level",
				enum_show(&ikev2_payload_names, np));
			np = pd->payload.generic.isag_np;
			continue;
		}

		passert(PINDEX(np) < LELEM_ROOF);
		summary.repeated |= summary.seen & LELEM(PINDEX(np));
		summary.seen |= LELEM(PINDEX(np));

		if (!in_struct(&pd->payload, sd, in_pbs, &pd->pbs)) {
			loglog(RC_LOG_SERIOUS, "malformed payload in packet");
			summary.status = STF_FAIL + v2N_INVALID_SYNTAX;
			break;
		}

		DBG(DBG_PARSING,
		    DBG_log("processing payload: %s (len=%u)",
			    enum_show(&ikev2_payload_names, np),
			    pd->payload.generic.isag_length));

		/* place this payload at the end of the chain for this type */
		{
			struct payload_digest **p;

			for (p = &md->chain[np]; *p != NULL;
			     p = &(*p)->next)
				;
			*p = pd;
			pd->next = NULL;
		}

		switch (np) {
		case ISAKMP_NEXT_v2SK:
		case ISAKMP_NEXT_v2SKF:
			/* RFC 5996 2.14 "Encrypted Payload":
			 *
			 * Next Payload - The payload type of the
			 * first embedded payload.  Note that this is
			 * an exception in the standard header format,
			 * since the Encrypted payload is the last
			 * payload in the message and therefore the
			 * Next Payload field would normally be zero.
			 * But because the content of this payload is
			 * embedded payloads and there was no natural
			 * place to put the type of the first one,
			 * that type is placed here.
			 */
			np = ISAKMP_NEXT_v2NONE;
			break;

		default:
			np = pd->payload.generic.isag_np;
			break;
		}

		pd++;
	}

	md->digest_roof = pd;
	return summary;
}

struct ikev2_payload_errors ikev2_verify_payloads(struct ikev2_payloads_summary summary,
						  const struct state_v2_microcode *svm, bool enc)
{
	lset_t req_payloads = enc ? svm->req_enc_payloads : svm->req_clear_payloads;
	lset_t opt_payloads = enc ? svm->opt_enc_payloads : svm->opt_clear_payloads;
	struct ikev2_payload_errors errors = {
		.status = STF_OK,
		.bad_repeat = summary.repeated & ~repeatable_payloads,
		.missing = req_payloads & ~summary.seen,
		.unexpected = summary.seen & ~req_payloads & ~opt_payloads & ~everywhere_payloads,
	};

	if ((errors.bad_repeat | errors.missing | errors.unexpected) != LEMPTY) {
		errors.status = STF_FAIL + v2N_INVALID_SYNTAX;
	}
	return errors;
}

/* report problems - but less so when OE */
void ikev2_log_payload_errors(struct ikev2_payload_errors errors, struct state *st)
{
	if (!st && !DBGP(DBG_OPPO))
		return;

	else if (st != NULL && st->st_connection != NULL &&
		(st->st_connection->policy & POLICY_OPPORTUNISTIC) && !DBGP(DBG_OPPO)) {
			return;
	}

	if (errors.missing != LEMPTY) {
		loglog(RC_LOG_SERIOUS,
		       "missing payload(s) (%s). Message dropped.",
		       bitnamesof(payload_name_ikev2_main,
				  errors.missing));
	}
	if (errors.unexpected != LEMPTY) {
		loglog(RC_LOG_SERIOUS,
		       "payload(s) (%s) unexpected. Message dropped.",
		       bitnamesof(payload_name_ikev2_main,
				  errors.unexpected));
	}
	if (errors.bad_repeat != LEMPTY) {
		loglog(RC_LOG_SERIOUS,
		       "payload(s) (%s) unexpectedly repeated. Message dropped.",
		       bitnamesof(payload_name_ikev2_main,
				  errors.bad_repeat));
	}
}

static bool ikev2_check_fragment(struct msg_digest *md)
{
	struct state *st = md->st;
	struct ikev2_skf *skf = &md->chain[ISAKMP_NEXT_v2SKF]->payload.v2skf;
	struct ikev2_frag *i;

	/* ??? CLANG 3.5 thinks st might be NULL */
	if (!(st->st_connection->policy & POLICY_IKE_FRAG_ALLOW)) {
		DBG(DBG_CONTROL, DBG_log(
			"discarding IKE encrypted fragment - fragmentation not allowed by local policy (ike_frag=no)"));
		return FALSE;
	}

	DBG(DBG_CONTROL, DBG_log(
		"received IKE encrypted fragment number '%u', total number '%u', next payload '%u'",
		    skf->isaskf_number, skf->isaskf_total, skf->isaskf_np));

	/*
	 * Sanity check:
	 * fragment number must be 1 or greater (not 0)
	 * fragment number must be no greater than the total number of fragments
	 * total number of fragments must be no more than MAX_IKE_FRAGMENTS
	 * first fragment's next payload must not be ISAKMP_NEXT_v2NONE.
	 * later fragments' next payload must be ISAKMP_NEXT_v2NONE.
	 */
	if (!(skf->isaskf_number != 0 &&
	      skf->isaskf_number <= skf->isaskf_total &&
	      skf->isaskf_total <= MAX_IKE_FRAGMENTS &&
	      (skf->isaskf_number == 1) != (skf->isaskf_np == ISAKMP_NEXT_v2NONE)))
	{
		DBG(DBG_CONTROL, DBG_log(
			"ignoring invalid IKE encrypted fragment"));
		return FALSE;
	}

	i = st->ikev2_frags;

	if (i != NULL && skf->isaskf_total != i->total) {
		/*
		 * total number of fragments changed.
		 * Either this fragment is wrong or all the
		 * stored fragments are wrong or superseded.
		 * The only reason the other end would have
		 * started over with a different number of fragments
		 * is because it decided to ratchet down the packet size
		 * (and thus increase total).
		 * OK: skf->isaskf_total > i->total
		 * Bad: skf->isaskf_total < i->total
		 */
		if (skf->isaskf_total > i->total) {
			DBG(DBG_CONTROL, DBG_log(
				"discarding saved fragments because this fragment has larger total"));
			do {
				st->ikev2_frags = i->next;
				freeanychunk(i->cipher);
				pfree(i);
				i = st->ikev2_frags;
			} while (i != NULL);
			return TRUE;
		} else {
			DBG(DBG_CONTROL, DBG_log(
				"ignoring odd IKE encrypted fragment (total shrank)"));
			return FALSE;
		}
	}

	for (; i != NULL; i = i->next) {
		if (i->index == skf->isaskf_number) {
			DBG(DBG_CONTROL, DBG_log(
				"ignoring duplicate IKE encrypted fragment"));
			return FALSE;
		}
	}

	return TRUE;
}

static bool ikev2_collect_fragment(struct msg_digest *md)
{
	struct state *st = md->st;
	struct ikev2_skf *skf = &md->chain[ISAKMP_NEXT_v2SKF]->payload.v2skf;
	pb_stream *e_pbs = &md->chain[ISAKMP_NEXT_v2SKF]->pbs;
	struct ikev2_frag *frag, **i;
	int num_frags;

	if (!ikev2_check_fragment(md))
		return FALSE;

	frag = alloc_thing(struct ikev2_frag, "ikev2_frag");
	frag->np = skf->isaskf_np;
	frag->index = skf->isaskf_number;
	frag->total = skf->isaskf_total;
	frag->iv = e_pbs->cur - md->packet_pbs.start;
	clonetochunk(frag->cipher, md->packet_pbs.start,
		     e_pbs->roof - md->packet_pbs.start,
		     "IKEv2 encrypted fragment");

	/*
	 * Loop for two purposes:
	 * - Add frag into ordered linked list
	 * - set num_frags to lenght ot the list
	 */
	num_frags = 0;
	for (i = &st->ikev2_frags; ; i = &(*i)->next) {
		if (frag != NULL) {
			/* Still looking for a place to insert frag */
			if (*i == NULL || (*i)->index > frag->index) {
				frag->next = *i;
				*i = frag;
				frag = NULL;
			}
		}

		if (*i == NULL)
			break;

		num_frags++;
	}

	if (num_frags < skf->isaskf_total)
		return FALSE;

	/* if receiving fragments, respond with fragments too */
	st->st_seen_fragments = TRUE;

	DBG(DBG_CONTROL,
	    DBG_log(" updated IKE fragment state to respond using fragments without waiting for re-transmits"));

	return TRUE;
}

/*
 * process an input packet, possibly generating a reply.
 *
 * If all goes well, this routine eventually calls a state-specific
 * transition function.
 *
 * This routine will not release_any_md(mdp).  It is expected that its
 * caller will do this.  In fact, it will zap *mdp to NULL if it thinks
 * **mdp should not be freed.  So the caller should be prepared for
 * *mdp being set to NULL.
 */
void process_v2_packet(struct msg_digest **mdp)
{
	struct msg_digest *md = *mdp;
	const struct state_v2_microcode *svm;
	struct state *st;

	/* Look for an state which matches the various things we know:
	 *
	 * 1) exchange type received?
	 * 2) is it initiator or not?
	 */

	md->msgid_received = ntohl(md->hdr.isa_msgid);
	const enum isakmp_xchg_types ix = md->hdr.isa_xchg;
	const bool msg_r = (md->hdr.isa_flags & ISAKMP_FLAGS_v2_MSG_R) != 0;
	const bool ike_i = (md->hdr.isa_flags & ISAKMP_FLAGS_v2_IKE_I) != 0;

	DBG(DBG_CONTROL, {
		if (msg_r)
			DBG_log("I am receiving an IKE Response");
		else
			DBG_log("I am receiving an IKE Request");
	});

	if (ike_i) {
		DBG(DBG_CONTROL, DBG_log("I am the IKE SA Original Responder"));
		md->original_role = ORIGINAL_RESPONDER;
	} else {
		DBG(DBG_CONTROL, DBG_log("I am the IKE SA Original Initiator"));
		md->original_role = ORIGINAL_INITIATOR;
	}

	/*
	 * Find the corresponding state
	 */
	if (ix == ISAKMP_v2_SA_INIT) {
		/*
		 * For INIT messages, need to lookup using the ICOOKIE
		 * and the expected state.  The RCOOKIE probably won't
		 * match.
		 *
		 * An INIT-request has RCOOKIE=0.  In the case of a
		 * re-transmit, where the original responder is in
		 * state STATE_PARENT_R1 and has set its RCOOKIE to
		 * something non-zero, that won't match.
		 *
		 * An INIT-response as RCOOKIE!=0 (lets ignore
		 * INVALID_KE).  Since the original responder, which
		 * is in state STATE_PARENT_i1, still has RCOOKIE=0
		 * that won't match.
		 */
		enum state_kind expected_state = (ike_i ? STATE_PARENT_R1 : STATE_PARENT_I1);
		st = find_state_ikev2_parent_init(md->hdr.isa_icookie,
						  expected_state);
		if (st != NULL && md->original_role == ORIGINAL_INITIATOR) {
			/*
			 * Responder provided a cookie, record it.
			 *
			 * XXX: This is being done far too early.  The
			 * packet should first get some validation.
			 * It also might be an INVALID_KE in which
			 * case the cookie shouldn't be updated at
			 * all.
			 */
			rehash_state(st, md->hdr.isa_rcookie);
		}

		/*
		 * We need to check if this IKE_INIT is a retransmit
		 */
		if (st != NULL && md->original_role == ORIGINAL_RESPONDER) {
			if (st->st_msgid_lastrecv == md->msgid_received) {
				/* this is a recent retransmit. */
				set_cur_state(st);
				DBG(DBG_CONTROLMORE, DBG_log(
					"duplicate IKE_INIT_I message received, retransmiting previous packet"));
				if (st->st_suspended_md != NULL) {
					libreswan_log("IKE_INIT_I retransmission ignored: we're still working on the previous one");
				} else {
					send_ike_msg(st, "ikev2-responder-retransmit IKE_INIT_I");
				}
				return;
			}
			/* update lastrecv later on */

		}

		/*
		 * If this exchange request is not an IKE_INIT
		 * or IKE_AUTH, ensure we have an established IKE SA
		 */
		if ((ix != ISAKMP_v2_SA_INIT && ix != ISAKMP_v2_AUTH) &&
		    !IS_IKE_SA_ESTABLISHED(st)) {
			libreswan_log("Ignoring %s Exchange as IKE SA for %s has not yet been authenticated",
				enum_show(&state_names, st->st_state), st->st_connection->name);
			return;
		}
	} else if (!msg_r) {
		/*
		 * A request; send it to the parent.
		 */
		st = find_state_ikev2_parent(md->hdr.isa_icookie,
					     md->hdr.isa_rcookie);
		if (st != NULL) {
			/*
			 * XXX: This solution is broken. If two exchanges (after the
			 * initial exchange) are interleaved, we ignore the first
			 * This is https://bugs.libreswan.org/show_bug.cgi?id=185
			 *
			 * Beware of unsigned arrithmetic.
			 */
			if (st->st_msgid_lastrecv != v2_INVALID_MSGID &&
			    st->st_msgid_lastrecv > md->msgid_received) {
				/* this is an OLD retransmit. we can't do anything */
				set_cur_state(st);
				libreswan_log(
					"received too old retransmit: %u < %u",
					md->msgid_received,
					st->st_msgid_lastrecv);
				return;
			}
			if (st->st_msgid_lastrecv == md->msgid_received) {
				/* this is a recent retransmit. */
				set_cur_state(st);
				if (st->st_suspended_md != NULL) {
					libreswan_log("retransmission ignored: we're still working on the previous one");
				} else {
					send_ike_msg(st, "ikev2-responder-retransmit");
				}
				return;
			}
			/* update lastrecv later on */
		}
	} else {
		/*
		 * A reply; find the child that made the request and
		 * send it to that.
		 */
		st = find_state_ikev2_child(md->hdr.isa_icookie,
					    md->hdr.isa_rcookie,
					    md->hdr.isa_msgid); /* PAUL: really? not md->msgid_received */
		if (st == NULL) {
			/*
			 * Didn't find a child waiting on that message
			 * ID so presumably it isn't valid.
			 */
			st = find_state_ikev2_parent(md->hdr.isa_icookie,
						     md->hdr.isa_rcookie);
			if (st != NULL) {
				/*
				 * Check if it's an old packet being
				 * returned, and if so, drop it.
				 * NOTE: in_struct() changed the byte
				 * order.  *
				 *
				 * Beware of unsigned arrithmetic.
				 */

				if (md->hdr.isa_flags & ISAKMP_FLAGS_v2_MSG_R) {
					/* Response to our request */
					if (st->st_msgid_lastack != v2_INVALID_MSGID &&
					    st->st_msgid_lastack > md->msgid_received)
					{
						DBG(DBG_CONTROL, DBG_log(
							"dropping retransmitted response with msgid %u from peer - we already processed %u.",
						    md->msgid_received, st->st_msgid_lastack));
						return;
					}
					if (st->st_msgid_nextuse != v2_INVALID_MSGID &&
					    md->msgid_received >= st->st_msgid_nextuse) {
						/*
						 * A reply for an unknown request.  Huh!
						 */
						DBG(DBG_CONTROL, DBG_log(
							"dropping unasked response with msgid %u from peer (our last used msgid is %u)",
						      md->msgid_received,
						      st->st_msgid_nextuse - 1));
						return;
					}

				} else {
					/* We always need to respond to peer's request - else retransmits */
				}
			}
		}
	}

	/*
	 * Is the original role correct?
	 */
	if (st != NULL && st->st_original_role != md->original_role) {
		DBG(DBG_CONTROL,
		    DBG_log("state and md roles conflict; dropping packet"));
		return;
	}

	/*
	 * There is no "struct state" object if-and-only-if we're in
	 * the start-state (STATE_UNDEFINED).  The start-state
	 * transition will, likely, create the object.
	 *
	 * But what about when pluto, as the initial responder, is
	 * fending of an attack attack by sending back and requiring
	 * cookies - won't the cookie need a "struct state"?
	 * According to the RFC: no.  Instead a small table of
	 * constants can be used to generate cookies on the fly.
	 */
	const enum state_kind from_state =
		st == NULL ? STATE_UNDEFINED : st->st_state;
	DBG(DBG_CONTROL,
	    if (st != NULL) {
		    DBG_log("found state #%lu", st->st_serialno);
	    }
	    DBG_log("from_state is %s", enum_show(&state_names, from_state)));

	passert((st == NULL) == (from_state == STATE_UNDEFINED));

	struct ikev2_payloads_summary clear_payload_summary = { .status = STF_IGNORE };
	struct ikev2_payload_errors clear_payload_status = { .status = STF_OK };

	for (svm = v2_state_microcode_table; svm->state != STATE_IKEv2_ROOF;
	     svm++) {
		if (svm->state != from_state)
			continue;
		if (svm->recv_type != ix)
			continue;
		/*
		 * Does the original initiator flag match?
		 */
		if ((svm->flags & SMF2_IKE_I_SET) && !ike_i)
			continue;
		if ((svm->flags & SMF2_IKE_I_CLEAR) && ike_i)
			continue;
		/*
		 * Does the message reply flag match?
		 */
		if ((svm->flags & SMF2_MSG_R_SET) && !msg_r)
			continue;
		if ((svm->flags & SMF2_MSG_R_CLEAR) && msg_r)
			continue;
		/*
		 * Since there's a state that, at least, looks like it
		 * will accept the packet, unpack the clear payload
		 * and continue matching.
		 */
		if (clear_payload_summary.status != STF_OK) {
			DBG(DBG_CONTROL, DBG_log("Unpacking clear payload for svm: %s", svm->story));
			clear_payload_summary = ikev2_decode_payloads(md, &md->message_pbs,
								      md->hdr.isa_np);
			if (clear_payload_summary.status != STF_OK) {
				complete_v2_state_transition(mdp, clear_payload_summary.status);
				return;
			}

			if (clear_payload_summary.seen &
			    LELEM(PINDEX(ISAKMP_NEXT_v2SKF)))
				clear_payload_summary.seen ^=
					LELEM(PINDEX(ISAKMP_NEXT_v2SK)) |
					LELEM(PINDEX(ISAKMP_NEXT_v2SKF));
			if (clear_payload_summary.repeated &
			    LELEM(PINDEX(ISAKMP_NEXT_v2SKF)))
				clear_payload_summary.repeated ^=
					LELEM(PINDEX(ISAKMP_NEXT_v2SK)) |
					LELEM(PINDEX(ISAKMP_NEXT_v2SKF));
		}
		struct ikev2_payload_errors clear_payload_errors
			= ikev2_verify_payloads(clear_payload_summary, svm, FALSE);
		if (clear_payload_errors.status != STF_OK) {
			/* Save this failure for later logging. */
			clear_payload_status = clear_payload_errors;
			continue;
		}
		/* must be the right state machine entry */
		break;
	}

	DBG(DBG_CONTROL, DBG_log("selected state microcode %s", svm->story));
	if (st != NULL)
		set_cur_state(st);
	md->from_state = from_state;
	md->st = st;
	md->svm = svm;

	if (svm->state == STATE_IKEv2_ROOF) {
		DBG(DBG_CONTROL, DBG_log("no useful state microcode entry found"));
		/* no useful state microcode entry */
		if (clear_payload_status.status != STF_OK) {
			ikev2_log_payload_errors(clear_payload_status, st);
			complete_v2_state_transition(mdp, clear_payload_status.status);
		} else if (!(md->hdr.isa_flags & ISAKMP_FLAGS_v2_MSG_R)) {
			/*
			 * We are the responder to this message so
			 * return something.
			 *
			 * XXX: Returning INVALID_MESSAGE_ID seems
			 * pretty bogus.
			 */
			SEND_V2_NOTIFICATION(v2N_INVALID_MESSAGE_ID);
		}
		return;
	}

	if (state_busy(st))
		return;

	if (md->chain[ISAKMP_NEXT_v2SKF] != NULL && !ikev2_collect_fragment(md))
		return;

	DBG(DBG_PARSING, {
		    if (pbs_left(&md->message_pbs) != 0)
			    DBG_log("removing %d bytes of padding",
				    (int) pbs_left(&md->message_pbs));
	    });

	md->message_pbs.roof = md->message_pbs.cur;	/* trim padding (not actually legit) */

	DBG(DBG_CONTROL,
	    DBG_log("Now lets proceed with state specific processing"));

	DBG(DBG_CONTROL,
	    DBG_log("calling processor %s", svm->story));
	complete_v2_state_transition(mdp, (svm->processor)(md));
	/* our caller with release_any_md(mdp) */
}

bool ikev2_decode_peer_id_and_certs(struct msg_digest *md)
{
	bool initiator = md->hdr.isa_flags & ISAKMP_FLAGS_v2_MSG_R;

	unsigned int hisID = initiator ? ISAKMP_NEXT_v2IDr : ISAKMP_NEXT_v2IDi;
	struct state *const st = md->st;
	struct payload_digest *const id_him = md->chain[hisID];
	struct connection *c = md->st->st_connection;
	const pb_stream *id_pbs;
	struct ikev2_id *v2id;
	struct id peer;

	if (id_him == NULL) {
		libreswan_log("IKEv2 mode no peer ID (hisID)");
		return FALSE;
	}

	id_pbs = &id_him->pbs;
	v2id = &id_him->payload.v2id;
	peer.kind = v2id->isai_type;

	if (!extract_peer_id(&peer, id_pbs)) {
		libreswan_log("IKEv2 mode peer ID extraction failed");
		return FALSE;
	}

	if (!ikev2_decode_cert(md))
		return FALSE;

	/* process any CERTREQ payloads */
	ikev2_decode_cr(md);

	/*
	 * Now that we've decoded the ID payload, let's see if we
	 * need to switch connections.
	 * We must not switch horses if we initiated:
	 * - if the initiation was explicit, we'd be ignoring user's intent
	 * - if opportunistic, we'll lose our HOLD info
	 */
	if (initiator) {
		if (!same_id(&st->st_connection->spd.that.id, &peer) &&
			id_kind(&st->st_connection->spd.that.id) !=
			ID_FROMCERT) {

			char expect[IDTOA_BUF],
			     found[IDTOA_BUF];

			idtoa(&st->st_connection->spd.that.id, expect,
				sizeof(expect));
			idtoa(&peer, found, sizeof(found));
			loglog(RC_LOG_SERIOUS,
				"we require IKEv2 peer to have ID '%s', but peer declares '%s'",
				expect, found);
			return FALSE;
		} else if (id_kind(&st->st_connection->spd.that.id) == ID_FROMCERT) {
			if (id_kind(&peer) != ID_DER_ASN1_DN) {
				loglog(RC_LOG_SERIOUS, "peer ID is not a certificate type");
				return FALSE;
			}
			duplicate_id(&st->st_connection->spd.that.id, &peer);
		}
	} else {
		bool fromcert = FALSE;
		uint16_t auth = md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type;
		lset_t auth_policy = LEMPTY;

		switch (auth) {
		case IKEv2_AUTH_RSA:
			auth_policy = POLICY_RSASIG;
			break;
		case IKEv2_AUTH_PSK:
			auth_policy = POLICY_PSK;
			break;
		case IKEv2_AUTH_NULL:
			/* we cannot switch, parts of SKEYSEED are used as PSK */
			break;
		case IKEv2_AUTH_NONE:
		default:
			DBG(DBG_CONTROL, DBG_log("ikev2 skipping refine_host_connection due to unknown policy"));
		}

		if (auth_policy != LEMPTY) {
			/* should really return c if no better match found */
			struct connection *r = refine_host_connection(
				md->st, &peer, FALSE /*initiator*/,
				auth_policy, &fromcert);

			if (r == NULL) {
				char buf[IDTOA_BUF];

				idtoa(&peer, buf, sizeof(buf));
				DBG(DBG_CONTROL, DBG_log(
					"no refined connection for peer '%s'", buf));
				r = c; /* ??? is this safe? */
			}

			if (r != c) {
				char b1[CONN_INST_BUF];
				char b2[CONN_INST_BUF];

				/* apparently, r is an improvement on c -- replace */

				libreswan_log("switched from \"%s\"%s to \"%s\"%s",
					c->name,
					fmt_conn_instance(c, b1),
					r->name,
					fmt_conn_instance(r, b2));
				if (r->kind == CK_TEMPLATE || r->kind == CK_GROUP) {
					/* instantiate it, filling in peer's ID */
					r = rw_instantiate(r, &c->spd.that.host_addr,
						   NULL, &peer);
				}

				update_state_connection(md->st, r);
				c = r;
			} else if (c->spd.that.has_id_wildcards) {
				duplicate_id(&c->spd.that.id, &peer);
				c->spd.that.has_id_wildcards = FALSE;
			} else if (fromcert) {
				DBG(DBG_CONTROL, DBG_log("copying ID for fromcert"));
				duplicate_id(&c->spd.that.id, &peer);
			}
		}
	}

	char idbuf[IDTOA_BUF];

	DBG(DBG_CONTROL, {
		dntoa_or_null(idbuf, IDTOA_BUF, c->spd.this.ca, "%none");
		DBG_log("offered CA: '%s'", idbuf);
	});

	idtoa(&peer, idbuf, sizeof(idbuf));

	if (!(c->policy & POLICY_OPPORTUNISTIC)) {
		libreswan_log("IKEv2 mode peer ID is %s: '%s'",
			enum_show(&ikev2_idtype_names, v2id->isai_type),
			idbuf);
	} else {
		DBG(DBG_OPPO, DBG_log("IKEv2 mode peer ID is %s: '%s'",
			enum_show(&ikev2_idtype_names, v2id->isai_type),
			idbuf));
	}

	return TRUE;
}

/*
 * this logs to the main log (including peerlog!) the authentication
 * and encryption keys for an IKEv2 SA.  This is done in a format that
 * is compatible with tcpdump 4.0's -E option.
 *
 * The peerlog will be perfect, the syslog will require that a cut
 * command is used to remove the initial text.
 *
 */
/* ??? this is kind of odd: regular control flow only selecting DBG output */
void ikev2_log_parentSA(struct state *st)
{
	if (DBGP(DBG_CRYPT)) {
		const char *authalgo;
		char encalgo[128];

		if (st->st_oakley.integ_hasher == NULL ||
		    st->st_oakley.encrypter == NULL)
			return;

		authalgo = st->st_oakley.integ_hasher->common.officname;

		if (st->st_oakley.enckeylen != 0) {
			/* 3des will use '3des', while aes becomes 'aes128' */
			snprintf(encalgo, sizeof(encalgo), "%s%u",
				 st->st_oakley.encrypter->common.officname,
				 st->st_oakley.enckeylen);
		} else {
			snprintf(encalgo, sizeof(encalgo), "%s",
				st->st_oakley.encrypter->common.officname);
		}
		DBG_log("ikev2 I 0x%02x%02x%02x%02x%02x%02x%02x%02x 0x%02x%02x%02x%02x%02x%02x%02x%02x %s %s",
			st->st_icookie[0], st->st_icookie[1],
			st->st_icookie[2], st->st_icookie[3],
			st->st_icookie[4], st->st_icookie[5],
			st->st_icookie[6], st->st_icookie[7],
			st->st_rcookie[0], st->st_rcookie[1],
			st->st_rcookie[2], st->st_rcookie[3],
			st->st_rcookie[4], st->st_rcookie[5],
			st->st_rcookie[6], st->st_rcookie[7],
			authalgo,
			encalgo);

		DBG_log("ikev2 R 0x%02x%02x%02x%02x%02x%02x%02x%02x 0x%02x%02x%02x%02x%02x%02x%02x%02x %s %s",
			st->st_icookie[0], st->st_icookie[1],
			st->st_icookie[2], st->st_icookie[3],
			st->st_icookie[4], st->st_icookie[5],
			st->st_icookie[6], st->st_icookie[7],
			st->st_rcookie[0], st->st_rcookie[1],
			st->st_rcookie[2], st->st_rcookie[3],
			st->st_rcookie[4], st->st_rcookie[5],
			st->st_rcookie[6], st->st_rcookie[7],
			authalgo,
			encalgo);
	}
}

void send_v2_notification_invalid_ke(struct msg_digest *md,
				     const struct oakley_group_desc *group)
{
	DBG(DBG_CONTROL,
	    DBG_log("sending INVALID_KE back with %s(%d)",
		    strip_prefix(enum_show(&oakley_group_names, group->group),
				 "OAKLEY_GROUP_"),
		    group->group));
	/* convert group to a raw buffer */
	const u_int16_t gr = htons(group->group);
	chunk_t nd;
	setchunk(nd, (void*)&gr, sizeof(gr));

	send_v2_notification_from_md(md, v2N_INVALID_KE_PAYLOAD, &nd);
}

void send_v2_notification_from_state(struct state *st,
				     v2_notification_t type,
				     chunk_t *data)
{
	send_v2_notification(st, type, NULL, st->st_icookie, st->st_rcookie,
			     data);
}

void send_v2_notification_from_md(struct msg_digest *md,
				  v2_notification_t type,
				  chunk_t *data)
{
	/*
	 * Note: send_notification_from_md and send_v2_notification_from_md
	 * share code (and bugs).  Any fix to one should be done to both.
	 *
	 * Create a fake state object to be able to use send_notification.
	 * This is somewhat dangerous: the fake state must not be deleted
	 * or have almost any other operation performed on it.
	 * Ditto for fake connection.
	 *
	 * ??? how can we be sure to have faked all salient fields correctly?
	 *
	 * Most details must be left blank (eg. pointers
	 * set to NULL).  struct initialization is good at this.
	 *
	 * We need to set [??? we don't -- is this still true?]:
	 *   st_connection->that.host_addr
	 *   st_connection->that.host_port
	 *   st_connection->interface
	 */
	struct connection fake_connection = {
		.interface = md->iface,
		.addr_family = addrtypeof(&md->sender),	/* for ikev2_record_fragments() */
	};

	struct state fake_state = {
		.st_serialno = SOS_NOBODY,
		.st_connection = &fake_connection,
	};

	passert(md != NULL);

	update_ike_endpoints(&fake_state, md);

	send_v2_notification(&fake_state, type, NULL,
			     md->hdr.isa_icookie, md->hdr.isa_rcookie, data);
}

void ikev2_update_msgid_counters(struct msg_digest *md)
{
	struct state *st = md->st;
	struct state *ikesa;

	if (st == NULL) {
		/* current processer deleted the state, nothing to update */
		return;
	}

	ikesa = IS_CHILD_SA(st) ?  state_with_serialno(st->st_clonedfrom) : st;

	if (md->hdr.isa_flags & ISAKMP_FLAGS_v2_MSG_R) {
		/* we were initiator for this message exchange */
		ikesa->st_msgid_lastack = md->msgid_received;
		if (ikesa->st_msgid_lastack <= ikesa->st_msgid_nextuse)
			ikesa->st_msgid_nextuse = ikesa->st_msgid_lastack + 1;
	} else {
		/* we were responder for this message exchange */
		if (md->msgid_received > ikesa->st_msgid_lastrecv)
			ikesa->st_msgid_lastrecv = md->msgid_received;
	}
}

time_t ikev2_replace_delay(struct state *st, enum event_type *pkind,
		enum original_role role)
{
	enum event_type kind = *pkind;
	time_t delay;   /* unwrapped deltatime_t */
	struct connection *c = st->st_connection;

	if (IS_PARENT_SA(st)) /* workaround for child appearing as parent */
	{
		/* Note: we will defer to the "negotiated" (dictated)
		 * lifetime if we are POLICY_DONT_REKEY.
		 * This allows the other side to dictate
		 * a time we would not otherwise accept
		 * but it prevents us from having to initiate
		 * rekeying.  The negative consequences seem
		 * minor.
		 *
		 * We cleanup halfopen IKE SAs fast, could be spoofed packets
		 */
		if (IS_IKE_SA_ESTABLISHED(st)) {
			delay = deltasecs(c->sa_ike_life_seconds);
			DBG(DBG_LIFECYCLE, DBG_log("ikev2_replace_delay() picked up estalibhsed ike_life:%lu", delay));
		} else {
			delay = PLUTO_HALFOPEN_SA_LIFE;
			DBG(DBG_LIFECYCLE, DBG_log("ikev2_replace_delay() picked up half-open SA ike_life:%lu", delay));
		}
	} else {
		/* Delay is what the user said, no negotiation. */
		delay = deltasecs(c->sa_ipsec_life_seconds);
		DBG(DBG_LIFECYCLE, DBG_log("ikev2_replace_delay() picked up salifetime=%lu", delay));
	}

	/* By default, we plan to rekey.
	 *
	 * If there isn't enough time to rekey, plan to
	 * expire.
	 *
	 * If we are --dontrekey, a lot more rules apply.
	 * If we are the Initiator, use REPLACE_IF_USED.
	 * If we are the Responder, and the dictated time
	 * was unacceptable (too large), plan to REPLACE
	 * (the only way to ratchet down the time).
	 * If we are the Responder, and the dictated time
	 * is acceptable, plan to EXPIRE.
	 *
	 * Important policy lies buried here.
	 * For example, we favour the initiator over the
	 * responder by making the initiator start rekeying
	 * sooner.  Also, fuzz is only added to the
	 * initiator's margin.
	 *
	 * Note: for ISAKMP SA, we let the negotiated
	 * time stand (implemented by earlier logic).
	 */
	if (kind != EVENT_SA_EXPIRE) {
		/* unwrapped deltatime_t */
		time_t marg = deltasecs(c->sa_rekey_margin);

		if (role == ORIGINAL_INITIATOR) {
			marg += marg *
				c->sa_rekey_fuzz / 100.E0 *
				(rand() / (RAND_MAX + 1.E0));
		} else {
			marg /= 2;
		}

		if (delay > marg) {
			delay -= marg;
			st->st_margin = deltatime(marg);
		} else {
			*pkind = kind = EVENT_SA_EXPIRE;
		}

		if (c->policy & POLICY_OPPORTUNISTIC) {
			if (st->st_connection->spd.that.has_lease) {
				*pkind = kind = EVENT_SA_EXPIRE;
			} else if (IS_PARENT_SA_ESTABLISHED(st)) {
				*pkind = kind = EVENT_v2_SA_REPLACE_IF_USED_IKE;
			} else if (IS_CHILD_SA_ESTABLISHED(st)) {
				*pkind = kind = EVENT_v2_SA_REPLACE_IF_USED;
			}
		} else if (c->policy & POLICY_DONT_REKEY) {
			*pkind = kind = EVENT_SA_EXPIRE;
		}
	}
	return delay;
}

static void success_v2_state_transition(struct msg_digest *md)
{
	const struct state_v2_microcode *svm = md->svm;
	enum state_kind from_state = md->from_state;
	struct state *st = md->st;
	struct connection *c = st->st_connection;
	enum rc_type w;

	if (from_state != svm->next_state) {
		DBG(DBG_CONTROL, DBG_log("transition from state %s to state %s",
			      enum_name(&state_names, from_state),
			      enum_name(&state_names, svm->next_state)));
	}

	change_state(st, svm->next_state);
	w = RC_NEW_STATE + st->st_state;

	ikev2_update_msgid_counters(md);

	/* tell whack and log of progress, if we are actually advancing */
	if (from_state != svm->next_state) {
		char sadetails[512];

		passert(st->st_state >= STATE_IKEv2_BASE);
		passert(st->st_state <  STATE_IKEv2_ROOF);

		sadetails[0] = '\0';

		/* document IPsec SA details for admin's pleasure */
		if (IS_CHILD_SA_ESTABLISHED(st)) {
			ipstr_buf bul, buh, bhl, bhh;

			/* but if this is the parent st, this information is not set! you need to check the child sa! */
			libreswan_log(
				"negotiated connection [%s,%s:%d-%d %d] -> [%s,%s:%d-%d %d]",
				ipstr(&st->st_ts_this.low, &bul),
				ipstr(&st->st_ts_this.high, &buh),
				st->st_ts_this.startport, st->st_ts_this.endport, st->st_ts_this.ipprotoid,
				ipstr(&st->st_ts_that.low, &bhl),
				ipstr(&st->st_ts_that.high, &bhh),
				st->st_ts_that.startport, st->st_ts_that.endport,
				st->st_ts_that.ipprotoid);

			fmt_ipsec_sa_established(st, sadetails,
						 sizeof(sadetails));
			/* log our success */
			w = RC_SUCCESS;
		} else if (st->st_state == STATE_PARENT_I2 || st->st_state == STATE_PARENT_R1) {
			fmt_isakmp_sa_established(st, sadetails,
						  sizeof(sadetails));
		}

		/* tell whack and logs our progress - unless OE, then be quiet*/
		if (c == NULL || (c->policy & POLICY_OPPORTUNISTIC) == LEMPTY)
			loglog(w, "%s: %s%s",
				enum_name(&state_names, st->st_state),
				enum_name(&state_stories, st->st_state),
				sadetails);
	}

	/* if requested, send the new reply packet */
	if (svm->flags & SMF2_SEND) {
		/*
		 * Adjust NAT but not for initial state
		 *
		 * STATE_IKEv2_BASE is used when an md is invented
		 * for an initial outbound message that is not a response.
		 * ??? why should STATE_PARENT_I1 be excluded?
		 */
		if (nat_traversal_enabled &&
		    from_state != STATE_IKEv2_BASE &&
		    from_state != STATE_PARENT_I1) {
			/* adjust our destination port if necessary */
			nat_traversal_change_port_lookup(md, st);
		}

		DBG(DBG_CONTROL, {
			    ipstr_buf b;
			    DBG_log("sending V2 reply packet to %s:%u (from port %u)",
				    ipstr(&st->st_remoteaddr, &b),
				    st->st_remoteport,
				    st->st_interface->port);
		    });

		send_ike_msg(st, enum_name(&state_names, from_state));
	}

	if (w == RC_SUCCESS) {
		DBG(DBG_CONTROL, DBG_log("releasing whack for #%lu (sock=%d)",
			st->st_serialno, st->st_whack_sock));
		release_whack(st);

		/* XXX should call unpend again on parent SA */
		if (IS_CHILD_SA(st)) {
			/* with failed child sa, we end up here with an orphan?? */
			struct state *pst = state_with_serialno(st->st_clonedfrom);

			DBG(DBG_CONTROL, DBG_log("releasing whack and unpending for parent #%lu",
				pst->st_serialno));
			unpend(pst);
			release_whack(pst);
		}
	}

	/* Schedule for whatever timeout is specified */
	{
		time_t delay;   /* unwrapped deltatime_t */
		enum event_type kind = svm->timeout_event;
		struct connection *c = st->st_connection;

		switch (kind) {
		case EVENT_v2_RETRANSMIT:
			delete_event(st);
			if (DBGP(IMPAIR_RETRANSMITS)) {
				libreswan_log("supressing retransmit because IMPAIR_RETRANSMITS is set.");
				if (st->st_rel_whack_event != NULL) {
					pfreeany(st->st_rel_whack_event);
					st->st_rel_whack_event = NULL;
				}
				event_schedule(EVENT_v2_RELEASE_WHACK,
						EVENT_RELEASE_WHACK_DELAY, st);
				kind = EVENT_SA_REPLACE;
				delay = ikev2_replace_delay(st, &kind, md->original_role);
				DBG(DBG_LIFECYCLE, DBG_log("ikev2 case EVENT_v2_RETRANSMIT: for %lu seconds", delay));
				event_schedule(kind, delay, st);

			}  else {
				DBG(DBG_LIFECYCLE,DBG_log(
					"success_v2_state_transition scheduling EVENT_v2_RETRANSMIT of c->r_interval=%lu",
					c->r_interval));
				event_schedule_ms(EVENT_v2_RETRANSMIT,
						c->r_interval, st);
			}
			break;
		case EVENT_SA_REPLACE: /* IKE or IPsec SA replacement event */
			delay = ikev2_replace_delay(st, &kind, md->original_role);
			DBG(DBG_LIFECYCLE, DBG_log("ikev2 case EVENT_SA_REPLACE for %s state for %lu seconds",
				IS_IKE_SA(st) ? "parent" : "child", delay));
			delete_event(st);
			event_schedule(kind, delay, st);
			break;

		case EVENT_v2_RESPONDER_TIMEOUT:
			delete_event(st);
			event_schedule(kind, MAXIMUM_RESPONDER_WAIT, st);
			break;

		case EVENT_NULL:
			/*
			 * Is there really no case where we want to set no  timer?
			 * more likely an accident?
			 */
			DBG_log("V2 microcode entry (%s) has unspecified timeout_event",
					svm->story);
			break;

		case EVENT_RETAIN:
			/* the previous event is retained */
			break;

		default:
			bad_case(kind);
		}
		/* start liveness checks if set, making sure we only schedule once when moving
		 * from I2->I3 or R1->R2
		 */
		if (st->st_state != from_state &&
			st->st_state != STATE_UNDEFINED &&
			IS_V2_ESTABLISHED(st->st_state) &&
			dpd_active_locally(st)) {
			DBG(DBG_DPD,
			    DBG_log("dpd enabled, scheduling ikev2 liveness checks"));
			event_schedule(EVENT_v2_LIVENESS,
				       deltasecs(c->dpd_delay) >= MIN_LIVENESS ?
					deltasecs(c->dpd_delay) : MIN_LIVENESS,
				       st);
		}
	}
}

/* complete job started by the state-specific state transition function
 *
 * This routine requires a valid non-NULL *mdp unless result is STF_INLINE.
 * So, for example, it does not make sense for state transitions that are
 * not provoked by a packet.
 *
 * This routine will not release_any_md(mdp).  It is expected that its
 * caller will do this.  In fact, it will zap *mdp to NULL if it thinks
 * **mdp should not be freed.  So the caller should be prepared for
 * *mdp being set to NULL.
 *
 * md is used to:
 * - find st
 * - success_v2_state_transition(md);
 *   - for svm:
 *     - svm->next_state,
 *     - svm->flags & SMF2_SEND,
 *     - svm->timeout_event,
 *     -svm->flags, story
 *   - find from_state (st might be gone)
 *   - ikev2_update_msgid_counters(md);
 *   - nat_traversal_change_port_lookup(md, st)
 * - !(md->hdr.isa_flags & ISAKMP_FLAGS_v2_MSG_R) to gate Notify payloads/exchanges [WRONG]
 * - find note for STF_INTERNAL_ERROR
 * - find note for STF_FAIL (might not be part of result (STF_FAIL+note))
 *
 * We don't use these but complete_v1_state_transition does:
 * - record md->event_already_set
 * - remember_received_packet(st, md);
 * - fragvid, dpd, nortel
 */
void complete_v2_state_transition(struct msg_digest **mdp,
				  stf_status result)
{
	struct msg_digest *md = *mdp;
	struct state *st;
	const char *from_state_name;

	/* handle oddball/meta results now */

	switch (result) {
	case STF_SUSPEND:
		cur_state = md->st;	/* might have changed */
		/* FALL THROUGH */
	case STF_INLINE:	/* all done, including release_any_md */
		*mdp = NULL;	/* take md away from parent */
		/* FALL THROUGH */
	case STF_IGNORE:
		DBG(DBG_CONTROL,
		    DBG_log("complete v2 state transition with %s",
			    enum_show(&stfstatus_name, result)));
		return;

	default:
		break;
	}

	/* safe to refer to *md */

	st = md->st;
	from_state_name = enum_name(&state_names,
		st == NULL ? STATE_UNDEFINED : st->st_state);

	cur_state = st; /* might have changed */

	/*
	 * XXX/SML:  There is no need to abort here in all cases where st is
	 * null, so moved this precondition to where it's needed.  Some previous
	 * logic appears to have been tooled to handle null state, and state might
	 * be null legitimately in certain failure cases (STF_FAIL + xxx).
	 *
	 * One condition for null state is when a new connection request packet
	 * arrives and there is no suitable matching configuration.  For example,
	 * ikev2parent_inI1outR1() will return (STF_FAIL + NO_PROPOSAL_CHOSEN) but
	 * no state in this case.  While other failures may be better caught before
	 * this function is called, we should be graceful here.  And for this
	 * particular case, and similar failure cases, we want SEND_NOTIFICATION
	 * (below) to let the peer know why we've rejected the request.
	 *
	 * Another case of null state is return from ikev2parent_inR1BoutI1B
	 * which returns STF_IGNORE.
	 *
	 * Another case occurs when we finish an Informational Exchange message
	 * that causes us to delete the IKE state.  In fact, that can be an
	 * STF_OK and yet have no remaining state object at this point.
	 */

	DBG(DBG_CONTROL,
	    DBG_log("#%lu complete v2 state transition from %s with %s",
		    (st == NULL ? SOS_NOBODY : st->st_serialno),
		    from_state_name,
		    (result > STF_FAIL
		     ? enum_name(&ikev2_notify_names, result - STF_FAIL)
		     : enum_name(&stfstatus_name, result))));

	switch (result) {
	case STF_OK:
		if (st == NULL) {
			DBG(DBG_CONTROL, DBG_log("STF_OK but no state object remains"));
		} else {
			/* advance the state */
			success_v2_state_transition(md);
		}
		break;

	case STF_INTERNAL_ERROR:
		whack_log(RC_INTERNALERR + md->note, "%s: internal error",
			  from_state_name);

		DBG(DBG_CONTROL,
		    DBG_log("state transition function for %s had internal error",
			    from_state_name));
		break;

	case STF_TOOMUCHCRYPTO:
		passert(st != NULL);
		unset_suspended(st);
		pexpect(!st->st_calculating);
		libreswan_log("message in state %s ignored due to cryptographic overload",
			      from_state_name);
		log_crypto_workers();
		/*
		 * ??? this used to FALL THROUGH to case STF_FATAL.
		 *
		 * Effectively we ignore this state transition
		 * but keep the original state.
		 *
		 * ??? Perhaps we have half-computed crypto and perhaps
		 * that is a problem if we try to advance the state later.
		 */
		break;

	case STF_DROP:
		/* be vewy vewy quiet */
		if (st != NULL) {
			delete_state(st);
			md->st = st = NULL;
		}
		break;

	case STF_FATAL:
		passert(st != NULL);
		whack_log(RC_FATAL,
			  "encountered fatal error in state %s",
			  from_state_name);
		release_whack(st);
		if (IS_CHILD_SA(st)) {
			struct state *pst = state_with_serialno(st->st_clonedfrom);

			release_whack(pst);
		}
		release_pending_whacks(st, "fatal error");
		delete_state(st);
		md->st = st = NULL;
		break;

	default: /* a shortcut to STF_FAIL, setting md->note */
		passert(result > STF_FAIL);
		md->note = result - STF_FAIL;
		/* FALL THROUGH ... */
	case STF_FAIL:
		whack_log(RC_NOTIFICATION + md->note,
			  "%s: %s",
			  from_state_name,
			  enum_name(&ikev2_notify_names, md->note));

		if (md->note != NOTHING_WRONG) {
			if (!(md->hdr.isa_flags & ISAKMP_FLAGS_v2_MSG_R)) {
				/* We are the exchange responder */
				DBG(DBG_CONTROL, DBG_log("sending a notification reply"));
				SEND_V2_NOTIFICATION(md->note);

				if (st != NULL) {
					if (md->hdr.isa_xchg == ISAKMP_v2_SA_INIT) {
						delete_state(st);
					} else {
						delete_event(st);
						event_schedule(EVENT_v2_RESPONDER_TIMEOUT, MAXIMUM_RESPONDER_WAIT, st);
					}
				}
			} else {
				/* We are the exchange initiator */
				pexpect(st !=  NULL && st->st_event != NULL &&
						st->st_event->ev_type == EVENT_v2_RETRANSMIT);
			}
		}

		DBG(DBG_CONTROL,
		    DBG_log("state transition function for %s failed: %s",
			    from_state_name,
			    md->note == NOTHING_WRONG ?
				"<no reason given>" :
				enum_name(&ikev2_notify_names, md->note)));
		break;
	}
}

v2_notification_t accept_v2_nonce(struct msg_digest *md,
				chunk_t *dest,
				const char *name)
{
	/*
	 * note ISAKMP_NEXT_v2Ni == ISAKMP_NEXT_v2Nr
	 * so when we refer to ISAKMP_NEXT_v2Ni, it might be ISAKMP_NEXT_v2Nr
	 */
	pb_stream *nonce_pbs;
	size_t len;

	nonce_pbs = &md->chain[ISAKMP_NEXT_v2Ni]->pbs;
	len = pbs_left(nonce_pbs);

	/*
	 * RFC 7296 Section 2.10:
	 * Nonces used in IKEv2 MUST be randomly chosen, MUST be at least 128
	 * bits in size, and MUST be at least half the key size of the
	 * negotiated pseudorandom function (PRF).  However, the initiator
	 * chooses the nonce before the outcome of the negotiation is known.
	 * Because of that, the nonce has to be long enough for all the PRFs
	 * being proposed.
	 *
	 * We will check for a minimum/maximum here. Once the PRF is selected,
	 * we verify the nonce is big enough.
	 */

	if (len < IKEv2_MINIMUM_NONCE_SIZE || len > IKEv2_MAXIMUM_NONCE_SIZE) {
		loglog(RC_LOG_SERIOUS, "%s length %zu not between %d and %d",
			name, len, IKEv2_MINIMUM_NONCE_SIZE, IKEv2_MAXIMUM_NONCE_SIZE);
		return v2N_INVALID_SYNTAX; /* ??? */
	}
	clonereplacechunk(*dest, nonce_pbs->cur, len, "nonce");
	return v2N_NOTHING_WRONG;
}
