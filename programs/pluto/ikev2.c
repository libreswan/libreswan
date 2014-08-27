/* demultiplex incoming IKE messages
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

#include "xauth.h"

#include "nat_traversal.h"
#include "vendor.h"

#include "pluto_crypt.h"	/* just for log_crypto_workers() */

#define SEND_NOTIFICATION(t) { \
		if (st != NULL) \
			send_v2_notification_from_state(st, t, \
							NULL); \
		else \
			send_v2_notification_from_md(md, t, NULL); }

struct state_v2_microcode {
	const char *const story;
	enum state_kind state, next_state;
	enum isakmp_xchg_types recv_type;
	lset_t flags;
	lset_t req_clear_payloads;  /* required unencrypted payloads (allows just one) for received packet */
	lset_t opt_clear_payloads;  /* optional unencrypted payloads (none or one) for received packet */
	lset_t req_enc_payloads;  /* required encrypted payloads (allows just one) for received packet */
	lset_t opt_enc_payloads;  /* optional encrypted payloads (none or one) for received packet */
	enum event_type timeout_event;
	state_transition_fn *processor;
};

enum smf2_flags {
	SMF2_INITIATOR = LELEM(1),
	SMF2_STATENEEDED = LELEM(2),
	SMF2_REPLY = LELEM(3),
	SMF2_CONTINUE_MATCH = LELEM(4)	/* multiple SMC entries for this state: try the next if payloads don't work */
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

/* Short forms for building payload type sets */

#define PT(n) ISAKMP_NEXT_v2 ## n
#define P(n) LELEM(PT(n) - ISAKMP_v2PAYLOAD_TYPE_BASE)

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
	  .flags      = SMF2_INITIATOR,
	  .processor  = NULL,
	  .timeout_event = EVENT_NULL, };

/* microcode for input packet processing */
static const struct state_v2_microcode v2_state_microcode_table[] = {

	/* STATE_PARENT_I1: R1B --> I1B
	 *                     <--  HDR, N
	 * HDR, N, SAi1, KEi, Ni -->
	 */
	{ .story      = "Initiator: process anti-spoofing cookie",
	  .state      = STATE_PARENT_I1,
	  .next_state = STATE_PARENT_I1,
	  .flags = SMF2_INITIATOR | SMF2_STATENEEDED | SMF2_REPLY | SMF2_CONTINUE_MATCH,
	  .req_clear_payloads = P(N),
	  .opt_clear_payloads = LEMPTY,
	  .processor  = ikev2parent_inR1BoutI1B,
	  .recv_type  = ISAKMP_v2_SA_INIT,
	  .timeout_event = EVENT_NULL, },

	/* STATE_PARENT_I1: R1 --> I2
	 *                     <--  HDR, SAr1, KEr, Nr, [CERTREQ]
	 * HDR, SK {IDi, [CERT,] [CERTREQ,]
	 *      [IDr,] AUTH, SAi2,
	 *      TSi, TSr}      -->
	 */
	{ .story      = "Initiator: process IKE_SA_INIT reply, initiate IKE_AUTH",
	  .state      = STATE_PARENT_I1,
	  .next_state = STATE_PARENT_I2,
	  .flags = SMF2_INITIATOR | SMF2_STATENEEDED | SMF2_REPLY,
	  .req_clear_payloads = P(SA) | P(KE) | P(Nr),
	  .opt_clear_payloads = P(CERTREQ),
	  .processor  = ikev2parent_inR1outI2,
	  .recv_type  = ISAKMP_v2_SA_INIT,
	  .timeout_event = EVENT_NULL, },

	/* STATE_PARENT_I2: R2 -->
	 *                     <--  HDR, SK {IDr, [CERT,] AUTH,
	 *                               SAr2, TSi, TSr}
	 * [Parent SA established]
	 */
	{ .story      = "Initiator: process IKE_AUTH response",
	  .state      = STATE_PARENT_I2,
	  .next_state = STATE_PARENT_I3,
	  .flags = SMF2_INITIATOR | SMF2_STATENEEDED,
	  .req_clear_payloads = P(E),
	  .req_enc_payloads = P(IDr) | P(AUTH) | P(SA) | P(TSi) | P(TSr),
	  .opt_enc_payloads = P(CERT),
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
	  .flags =  /* not SMF2_INITIATOR, not SMF2_STATENEEDED */ SMF2_REPLY,
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
	  .flags =  /* not SMF2_INITIATOR */ SMF2_STATENEEDED | SMF2_REPLY,
	  .req_clear_payloads = P(E),
	  .req_enc_payloads = P(IDi) | P(AUTH) | P(SA) | P(TSi) | P(TSr),
	  .opt_enc_payloads = P(CERT) | P(CERTREQ) | P(IDr),
	  .processor  = ikev2parent_inI2outR2,
	  .recv_type  = ISAKMP_v2_AUTH,
	  .timeout_event = EVENT_SA_REPLACE, },

	/* Informational Exchange*/

	/* RFC 5996 1.4 "The INFORMATIONAL Exchange"
	 *
	 * HDR, SK {[N,] [D,] [CP,] ...}  -->
	 *   <--  HDR, SK {[N,] [D,] [CP], ...}
	 */

	{ .story      = "I2: process INFORMATIONAL",
	  .state      = STATE_PARENT_I2,
	  .next_state = STATE_PARENT_I2,
	  .flags      = SMF2_STATENEEDED,
	  .req_clear_payloads = P(E),
	  .opt_enc_payloads = P(N) | P(D) | P(CP),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_NULL, },

	/* Informational Exchange*/
	{ .story      = "R1: process INFORMATIONAL",
	  .state      = STATE_PARENT_R1,
	  .next_state = STATE_PARENT_R1,
	  .flags      = SMF2_STATENEEDED,
	  .req_clear_payloads = P(E),
	  .opt_enc_payloads = P(N) | P(D) | P(CP),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_NULL, },

	/* Informational Exchange*/
	{ .story      = "I3: INFORMATIONAL",
	  .state      = STATE_PARENT_I3,
	  .next_state = STATE_PARENT_I3,
	  .flags      = SMF2_STATENEEDED,
	  .req_clear_payloads = P(E),
	  .opt_enc_payloads = P(N) | P(D) | P(CP),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_NULL, },

	/*
	 * There are three different CREATE_CHILD_SA's invocations,
	 * this is the combined write up (not in RFC). See above for
	 * individual cases from RFC
	 *
	 * HDR, SK {SA, Ni, [KEi], [N(REKEY_SA)], [TSi, TSr]} -->
	 *                <-- HDR, SK {N}
	 *                <-- HDR, SK {SA, Nr, [KEr], [TSi, TSr]}
	 */

	/* Create Child SA Exchange*/
	{ .story      = "I3: CREATE_CHILD_SA",
	  .state      = STATE_PARENT_I3,
	  .next_state = STATE_PARENT_I3,
	  .flags = SMF2_STATENEEDED | SMF2_REPLY,
	  .req_clear_payloads = P(E),
	  .req_enc_payloads = P(SA) | P(Ni),
	  .opt_enc_payloads = P(KE) | P(N) | P(TSi) | P(TSr),
	  .processor  = ikev2_create_child_sa_in,
	  .recv_type  = ISAKMP_v2_CREATE_CHILD_SA,
	  .timeout_event = EVENT_SA_REPLACE, },

	/* Create Child SA Exchange*/
	{ .story      = "R2: CREATE_CHILD_SA",
	  .state      = STATE_PARENT_R2,
	  .next_state = STATE_PARENT_R2,
	  .flags = SMF2_STATENEEDED | SMF2_REPLY,
	  .req_clear_payloads = P(E),
	  .req_enc_payloads = P(SA) | P(Ni),
	  .opt_enc_payloads = P(KE) | P(N) | P(TSi) | P(TSr),
	  .processor  = ikev2_create_child_sa_in,
	  .recv_type  = ISAKMP_v2_CREATE_CHILD_SA,
	  .timeout_event = EVENT_SA_REPLACE, },

	/* Informational Exchange*/
	{ .story      = "R2: process INFORMATIONAL",
	  .state      = STATE_PARENT_R2,
	  .next_state = STATE_PARENT_R2,
	  .flags      = SMF2_STATENEEDED,
	  .req_clear_payloads = P(E),
	  .opt_enc_payloads = P(N) | P(D) | P(CP),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_NULL, },

	/* Informational Exchange*/
	{ .story      = "IKE_SA_DEL: process INFORMATIONAL",
	  .state      = STATE_IKESA_DEL,
	  .next_state = STATE_IKESA_DEL,
	  .flags      = SMF2_STATENEEDED,
	  .req_clear_payloads = P(E),
	  .opt_enc_payloads = P(N) | P(D) | P(CP),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_NULL, },

	/* last entry */
	{ .story      = "roof",
	  .state      = STATE_IKEv2_ROOF }
};

#undef P
#undef PT

/*
 * split up an incoming message into payloads
 *
 * Warning: may change md->svm based on payload matching.
 */
stf_status ikev2_process_payloads(struct msg_digest *md,
				  pb_stream    *in_pbs,
				  enum next_payload_types_ikev2 np,
				  bool enc)
{
	struct payload_digest *pd = md->digest_roof;
	const struct state_v2_microcode *svm = md->svm;
	lset_t seen = LEMPTY;
	lset_t repeated = LEMPTY;

	/* ??? zero out the digest descriptors -- might nuke ISAKMP_NEXT_v2E digest! */

	while (np != ISAKMP_NEXT_v2NONE) {
		struct_desc *sd = payload_desc(np);

		DBG(DBG_CONTROL,
		    DBG_log("Now let's proceed with payload (%s)",
			    enum_show(&ikev2_payload_names, np)));

		if (pd == &md->digest[PAYLIMIT]) {
			loglog(RC_LOG_SERIOUS,
			       "more than %d payloads in message; ignored",
			       PAYLIMIT);
			return STF_FAIL + v2N_INVALID_SYNTAX;
		}

		zero(pd);	/* ??? is this needed? */

		if (sd == NULL || np < ISAKMP_v2PAYLOAD_TYPE_BASE) {
			/* This payload is unknown to us.
			 * RFCs 4306 and 5996 2.5 say that if the payload
			 * has the Critical Bit, we should be upset
			 * but if it does not, we should just ignore it.
			 */
			if (!in_struct(&pd->payload, &ikev2_generic_desc, in_pbs, &pd->pbs)) {
				loglog(RC_LOG_SERIOUS, "malformed payload in packet");
				return STF_FAIL + v2N_INVALID_SYNTAX;
			}
			if (pd->payload.v2gen.isag_critical & ISAKMP_PAYLOAD_CRITICAL) {
				/* It was critical.
				 * See RFC 5996 1.5 "Version Numbers and Forward Compatibility"
				 * ??? we are supposed to send the offending np byte back in the
				 * notify payload.
				 */
				loglog(RC_LOG_SERIOUS,
				       "critical payload (%s) was not understood. Message dropped.",
				       enum_show(&ikev2_payload_names, np));
				return STF_FAIL + v2N_UNSUPPORTED_CRITICAL_PAYLOAD;
			}
			loglog(RC_COMMENT, "non-critical payload ignored because it contains an unknown or"
			       " unexpected payload type (%s) at the outermost level",
			       enum_show(&ikev2_payload_names, np));
			np = pd->payload.generic.isag_np;
			continue;
		}

		passert(np - ISAKMP_v2PAYLOAD_TYPE_BASE < LELEM_ROOF);

		{
			lset_t s = LELEM(np - ISAKMP_v2PAYLOAD_TYPE_BASE);

			repeated |= seen & s;
			seen |= s;
		}

		if (!in_struct(&pd->payload, sd, in_pbs, &pd->pbs)) {
			loglog(RC_LOG_SERIOUS, "malformed payload in packet");
			return STF_FAIL + v2N_INVALID_SYNTAX;
		}

		DBG(DBG_PARSING,
		    DBG_log("processing payload: %s (len=%u)\n",
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
		case ISAKMP_NEXT_v2E:
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

	for (;;) {
		lset_t req_payloads = enc ? svm->req_enc_payloads : svm->req_clear_payloads;
		lset_t opt_payloads = enc ? svm->opt_enc_payloads : svm->opt_clear_payloads;
		lset_t bad_repeat = repeated & ~repeatable_payloads;
		lset_t missing = req_payloads & ~seen;
		lset_t unexpected = seen & ~req_payloads & ~opt_payloads & ~everywhere_payloads;

		if ((bad_repeat | missing | unexpected) == LEMPTY)
			break;	/* all good */

		if (svm->flags & SMF2_CONTINUE_MATCH) {
			/* try the next microcode entry */
			svm++;
			DBG(DBG_CONTROL,
				DBG_log("ikev2_process_payload trying next svm: %s",
					svm->story));
			continue;
		}

		/* report problems */
		if (missing) {
			loglog(RC_LOG_SERIOUS,
			       "missing payload(s) (%s). Message dropped.",
			       bitnamesof(payload_name_ikev2_main, missing));
		}
		if (unexpected) {
			loglog(RC_LOG_SERIOUS,
			       "payload(s) (%s) unexpected. Message dropped.",
			       bitnamesof(payload_name_ikev2_main, unexpected));
		}
		if (bad_repeat) {
			loglog(RC_LOG_SERIOUS,
				"payload(s) (%s) unexpectedly repeated. Message dropped.",
				bitnamesof(payload_name_ikev2_main, bad_repeat));
		}
		return STF_FAIL + v2N_INVALID_SYNTAX;
	}

	md->svm = svm;	/* might have changed! */

	md->digest_roof = pd;
	return STF_OK;
}

/*
 * process an input packet, possibly generating a reply.
 *
 * If all goes well, this routine eventually calls a state-specific
 * transition function.
 */
void process_v2_packet(struct msg_digest **mdp)
{
	struct msg_digest *md = *mdp;
	struct state *st = NULL;
	enum state_kind from_state = STATE_UNDEFINED; /* state we started in */
	const struct state_v2_microcode *svm;
	enum isakmp_xchg_types ix;

	/* Look for an state which matches the various things we know:
	 *
	 * 1) exchange type received?
	 * 2) is it initiator or not?
	 */

	md->msgid_received = ntohl(md->hdr.isa_msgid);

	if (md->hdr.isa_flags & ISAKMP_FLAGS_MSG_R)
		DBG(DBG_CONTROL, DBG_log("I am receiving an IKE Response"));
	else
		DBG(DBG_CONTROL, DBG_log("I am receiving an IKE Request"));

	if (md->hdr.isa_flags & ISAKMP_FLAGS_IKE_I) {
		DBG(DBG_CONTROL, DBG_log("I am the IKE SA Original Responder"));
		md->role = O_RESPONDER;

		st = find_state_ikev2_parent(md->hdr.isa_icookie,
					     md->hdr.isa_rcookie);

		if (st == NULL) {
			/* first time for this cookie, it's a new state! */
			st = find_state_ikev2_parent_init(md->hdr.isa_icookie);
		}

		if (st != NULL) {
			/*
			 * XXX: This solution is broken. If two exchanges (after the
			 * initial exchange) are interleaved, we ignore the first
			 * This is https://bugs.libreswan.org/show_bug.cgi?id=185
			 */
			if (st->st_msgid_lastrecv != v2_INVALID_MSGID &&
			    st->st_msgid_lastrecv > md->msgid_received) {
				/* this is an OLD retransmit. we can't do anything */
				libreswan_log(
					"received too old retransmit: %u < %u",
					md->msgid_received,
					st->st_msgid_lastrecv);
				return;
			}
			if (st->st_msgid_lastrecv == md->msgid_received) {
				/* this is a recent retransmit. */
				send_ike_msg(st, "ikev2-responder-retransmit");
				return;
			}
			/* update lastrecv later on */
		}
	} else {
		DBG(DBG_CONTROL, DBG_log("I am the IKE SA Original Initiator"));
		md->role = O_INITIATOR;

		if (md->msgid_received == v2_INITIAL_MSGID) {
			st = find_state_ikev2_parent(md->hdr.isa_icookie,
						     md->hdr.isa_rcookie);
			if (st == NULL) {
				st = find_state_ikev2_parent(
					md->hdr.isa_icookie, zero_cookie);
				if (st != NULL) {
					/* responder inserted its cookie, record it */
					unhash_state(st);
					memcpy(st->st_rcookie,
					       md->hdr.isa_rcookie,
					       COOKIE_SIZE);
					insert_state(st);
				}
			}
		} else {
			st = find_state_ikev2_child(md->hdr.isa_icookie,
						    md->hdr.isa_rcookie,
						    md->hdr.isa_msgid); /* PAUL: really? not md->msgid_received */

			if (st != NULL) {
				/* found this child state, so we'll use it */
				/* note we update the st->st_msgid_lastack *AFTER* decryption*/
			} else {
				/*
				 * didn't find something with the msgid, so maybe it's
				 * not valid?
				 */
				st = find_state_ikev2_parent(
					md->hdr.isa_icookie,
					md->hdr.isa_rcookie);
			}
		}

		if (st != NULL) {
			/*
			 * then there is something wrong with the msgid, so
			 * maybe they retransmitted for some reason.
			 * Check if it's an old packet being returned, and
			 * if so, drop it.
			 * NOTE: in_struct() changed the byte order.
			 */
			if (st->st_msgid_lastack != v2_INVALID_MSGID &&
			    st->st_msgid_lastrecv != v2_INVALID_MSGID &&
			    md->msgid_received <= st->st_msgid_lastack) {
				/* it's fine, it's just a retransmit */
				DBG(DBG_CONTROL,
				    DBG_log("responding peer retransmitted msgid %u",
					    md->msgid_received));
				return;
			}
#if 0
			libreswan_log("last msgid ack is %u, received: %u",
				      st->st_msgid_lastack,
				      md->msgid_received);
			return;

#endif
		}
	}

	ix = md->hdr.isa_xchg;
	if (st != NULL) {
		from_state = st->st_state;
		DBG(DBG_CONTROL,
		    DBG_log("state found and its state is %s",
			    enum_show(&state_names, from_state)));
	}

	for (svm = v2_state_microcode_table; svm->state != STATE_IKEv2_ROOF;
	     svm++) {
		if (svm->flags & SMF2_STATENEEDED) {
			if (st == NULL)
				continue;
		} else {
			if (st != NULL)
				continue;
		}
		if (svm->state != from_state)
			continue;

		if (svm->recv_type != ix)
			continue;

		/* ??? not sure that this is necessary, but it ought to be correct */
		/* This check cannot apply for an informational exchange since one
		 * can be initiated by the initial responder.
		 */
		if (ix != ISAKMP_v2_INFORMATIONAL &&
		    (((svm->flags&SMF2_INITIATOR) != 0) != ((md->hdr.isa_flags & ISAKMP_FLAGS_MSG_R) != 0)))
			continue;

		/* must be the right state machine entry */
		break;
	}

	DBG(DBG_CONTROL, DBG_log("selected state microcode %s", svm->story));

	if (svm->state == STATE_IKEv2_ROOF) {
		DBG(DBG_CONTROL, DBG_log("ended up with STATE_IKEv2_ROOF"));

		/* no useful state microcode entry */
		if (!(md->hdr.isa_flags & ISAKMP_FLAGS_MSG_R)) {
			/* We are responder for this message exchange */
			SEND_NOTIFICATION(v2N_INVALID_MESSAGE_ID);
		}
		return;
	}

	if (state_busy(st))
		return;

	if (st != NULL)
		set_cur_state(st);
	md->svm = svm;
	md->from_state = from_state;
	md->st = st;

	{
		stf_status stf = ikev2_process_payloads(md, &md->message_pbs,
			md->hdr.isa_np, FALSE);

		svm = md->svm;	/* ikev2_process_payloads updates */

		if (stf != STF_OK) {
			complete_v2_state_transition(mdp, stf);
			return;
		}
	}

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
}

bool ikev2_decode_peer_id(struct msg_digest *md, enum phase1_role role)
{
	unsigned int hisID = role == O_INITIATOR ?
			     ISAKMP_NEXT_v2IDr : ISAKMP_NEXT_v2IDi;
	struct payload_digest *const id_him = md->chain[hisID];
	const pb_stream * id_pbs;
	struct ikev2_id * id;
	struct id peer;

	if (!id_him) {
		libreswan_log("IKEv2 mode no peer ID (hisID)");
		return FALSE;
	}

	id_pbs = &id_him->pbs;
	id = &id_him->payload.v2id;
	peer.kind = id->isai_type;

	if (!extract_peer_id(&peer, id_pbs)) {
		libreswan_log("IKEv2 mode peer ID extraction failed");
		return FALSE;
	}

	{
		char buf[IDTOA_BUF];

		idtoa(&peer, buf, sizeof(buf));
		libreswan_log("IKEv2 mode peer ID is %s: '%s'",
			      enum_show(&ikev2_idtype_names, id->isai_type), buf);
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
	struct state st;
	struct connection cnx;

	/**
	 * Create a dummy state to be able to use send_ike_msg in
	 * send_notification
	 *
	 * we need to set:
	 *   st_connection->that.host_addr
	 *   st_connection->that.host_port
	 *   st_connection->interface
	 */
	passert(md != NULL);

	zero(&st);
	zero(&cnx);
	st.st_connection = &cnx;
	st.st_remoteaddr = md->sender;
	st.st_remoteport = md->sender_port;
	st.st_localaddr  = md->iface->ip_addr;
	st.st_localport  = md->iface->port;
	cnx.interface = md->iface;
	st.st_interface = md->iface;

	send_v2_notification(&st, type, NULL,
			     md->hdr.isa_icookie, md->hdr.isa_rcookie, data);
}

void ikev2_update_counters(struct msg_digest *md)
{
	struct state *st = md->st;
	struct state *ikesa = IS_CHILD_SA(st) ?
		state_with_serialno(st->st_clonedfrom) : st;

	if (md->hdr.isa_flags & ISAKMP_FLAGS_MSG_R) {
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
		enum phase1_role role)
{
	enum event_type kind = *pkind;
	time_t delay;   /* unwrapped deltatime_t */
	struct connection *c = st->st_connection;

	if (IS_PARENT_SA(st)) {
		/* Note: we will defer to the "negotiated" (dictated)
		 * lifetime if we are POLICY_DONT_REKEY.
		 * This allows the other side to dictate
		 * a time we would not otherwise accept
		 * but it prevents us from having to initiate
		 * rekeying.  The negative consequences seem
		 * minor.
		 */
		delay = deltasecs(c->sa_ike_life_seconds);
	} else {
		/* Delay is what the user said, no negotiation. */
		delay = deltasecs(c->sa_ipsec_life_seconds);
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

		if (role == O_INITIATOR) {
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
	}
	return delay;
}

static void success_v2_state_transition(struct msg_digest **mdp)
{
	struct msg_digest *md = *mdp;
	const struct state_v2_microcode *svm = md->svm;
	enum state_kind from_state = md->from_state;
	struct state *st = md->st;
	enum rc_type w;

	if (from_state != svm->next_state) {
		libreswan_log("transition from state %s to state %s",
			      enum_name(&state_names, from_state),
			      enum_name(&state_names, svm->next_state));
	}

	change_state(st, svm->next_state);
	w = RC_NEW_STATE + st->st_state;

	ikev2_update_counters(md);

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
				"negotiated tunnel [%s,%s:%d-%d %d] -> [%s,%s:%d-%d %d]",
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
		} else if (IS_PARENT_SA_ESTABLISHED(st->st_state)) {
			fmt_isakmp_sa_established(st, sadetails,
						  sizeof(sadetails));
		}

		/* tell whack and logs our progress */
		loglog(w,
		       "%s: %s%s",
		       enum_name(&state_names, st->st_state),
		       enum_name(&state_stories, st->st_state),
		       sadetails);
	}

	/* if requested, send the new reply packet */
	if (svm->flags & SMF2_REPLY) {
		/* free previously transmitted packet */
		freeanychunk(st->st_tpacket);

		if (nat_traversal_enabled && from_state != STATE_PARENT_I1) {
			/* adjust our destination port if necessary */
			nat_traversal_change_port_lookup(md, st);
		}

		DBG(DBG_CONTROL, {
			    ipstr_buf b;
			    DBG_log("sending reply packet to %s:%u (from port %u)",
				    ipstr(&st->st_remoteaddr, &b),
				    st->st_remoteport,
				    st->st_interface->port);
		    });

		close_output_pbs(&reply_stream); /* good form, but actually a no-op */

		clonetochunk(st->st_tpacket, reply_stream.start,
			     pbs_offset(&reply_stream), "reply packet");

		/* actually send the packet
		 * Note: this is a great place to implement "impairments"
		 * for testing purposes.  Suppress or duplicate the
		 * send_ike_msg call depending on st->st_state.
		 */

		send_ike_msg(st, enum_name(&state_names, from_state));
	}

	if (w == RC_SUCCESS) {
		DBG_log("releasing whack for #%lu (sock=%d)",
			st->st_serialno, st->st_whack_sock);
		release_whack(st);

		/* XXX should call unpend again on parent SA */
		if (IS_CHILD_SA(st)) {
			/* with failed child sa, we end up here with an orphan?? */
			struct state *pst = state_with_serialno(st->st_clonedfrom);

			DBG_log("releasing whack and unpending for parent #%lu",
				pst->st_serialno);
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
		case EVENT_SA_REPLACE: /* SA replacement event */
			delay = ikev2_replace_delay(st, &kind,
					(svm->flags & SMF2_INITIATOR) ?
					O_INITIATOR : O_RESPONDER);
			delete_event(st);
			event_schedule(kind, delay, st);
			break;

		case EVENT_v2_RESPONDER_TIMEOUT:
			delete_event(st);
			event_schedule(kind,
				MAXIMUM_RETRANSMISSIONS_INITIAL *
					EVENT_RETRANSMIT_DELAY_0,
				st);
			break;

		case EVENT_NULL:
			/* XXX: Is there really no case where we want to set no timer? */
			/* dos_cookie is one 'valid' event, but it is used more? */
			DBG_log("V2 microcode entry (%s) has unspecified timeout_event",
				svm->story);
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

void complete_v2_state_transition(struct msg_digest **mdp,
				  stf_status result)
{
	struct msg_digest *md = *mdp;
	/* const struct state_v2_microcode *svm=md->svm; */
	struct state *st;
	enum state_kind from_state = STATE_UNDEFINED;
	const char *from_state_name;

	cur_state = st = md->st; /* might have changed */

	pexpect(st != NULL);   /*  STF_TOOMUCH_CRYPTO used to call delete_state(st); hitting this*/
	/*
	 * XXX/SML:  There is no need to abort here in all cases if state is
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
	 * Another case of null state is retrun from ikev2parent_inR1BoutI1B
	 * Which returns STF_IGNORE.
	 */
	if (st != NULL) {
		from_state = st->st_state;
		from_state_name = enum_name(&state_names, from_state);
	} else {
		from_state_name = "no-state";
	}

	/* advance the state */
	DBG(DBG_CONTROL,
	    DBG_log("complete v2 state transition with %s",
		    enum_name(&stfstatus_name,
			      result > STF_FAIL ? STF_FAIL : result)));

	switch (result) {
	case STF_IGNORE:
		break;

	case STF_INLINE:
		/*
		 * this is second time through complete state transition,
		 * so the MD has already been freed.
		 * ??? This comment is not true.
		* This has been proven by passert(md == NULL) failing.
		*/
		*mdp = NULL;
		break;

	case STF_SUSPEND:
		/* update the previous packet history */
		/* IKEv2 XXX */ /* update_retransmit_history(st, md); */

		/* the stf didn't complete its job: don't relase md */
		*mdp = NULL;
		break;

	case STF_OK:
		/* advance the state */
		passert(st != NULL);
		success_v2_state_transition(mdp);
		break;

	case STF_INTERNAL_ERROR:
		/* update the previous packet history */
		/* TODO: fix: update_retransmit_history(st, md); */

		whack_log(RC_INTERNALERR + md->note,
			  "%s: internal error",
			  enum_name(&state_names, st->st_state));

		DBG(DBG_CONTROL,
		    DBG_log("state transition function for %s had internal error",
			    enum_name(&state_names, from_state)));
		break;

	case STF_TOOMUCHCRYPTO:
		unset_suspended(st);
		pexpect(!st->st_calculating);
		libreswan_log("message in state %s ignored due to cryptographic overload",
			      from_state_name);
		log_crypto_workers();
		/* ??? why does the ikev1.c version break and the ikev2.c version FALL THROUGH? */
		/* FALL THROUGH */
	case STF_FATAL:
		/* update the previous packet history */
		/* update_retransmit_history(st, md); */

		passert(st != NULL);
		whack_log(RC_FATAL,
			  "encountered fatal error in state %s",
			  from_state_name);
		delete_event(st);
		release_whack(st);
		if (IS_CHILD_SA(st)) {
			struct state *pst = state_with_serialno(st->st_clonedfrom);

			release_whack(pst);
		}
		release_pending_whacks(st, "fatal error");
		delete_state(st);
		break;

	default: /* a shortcut to STF_FAIL, setting md->note */
		passert(result > STF_FAIL);
		md->note = result - STF_FAIL;
		result = STF_FAIL;	/* not actually used */
		/* FALL THROUGH ... */
	case STF_FAIL:
		whack_log(RC_NOTIFICATION + md->note,
			  "%s: %s",
			  from_state_name,
			  enum_name(&ikev2_notify_names, md->note));

		if (md->note != NOTHING_WRONG) {
			/*
			 * only send a notify is this packet was a request,
			 * not if it was a reply
			 */
			/* ??? is this a reasonable choice? */
			if (!(md->hdr.isa_flags & ISAKMP_FLAGS_MSG_R))
				SEND_NOTIFICATION(md->note);
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

	if (len < MINIMUM_NONCE_SIZE || MAXIMUM_NONCE_SIZE < len) {
		loglog(RC_LOG_SERIOUS, "%s length not between %d and %d",
			name, MINIMUM_NONCE_SIZE, MAXIMUM_NONCE_SIZE);
		return v2N_INVALID_SYNTAX; /* ??? */
	}
	clonereplacechunk(*dest, nonce_pbs->cur, len, "nonce");
	return v2N_NOTHING_WRONG;
}
