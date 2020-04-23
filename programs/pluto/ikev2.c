/* demultiplex incoming IKE messages
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

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "id.h"
#include "x509.h"
#include "pluto_x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "crypto.h"
#include "crypt_symkey.h"
#include "ike_alg.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */
#include "pluto_crypt.h"  /* for pluto_crypto_req & pluto_crypto_req_cont */
#include "ikev2.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "timer.h"
#include "whack.h"      /* requires connections.h */
#include "server.h"
#include "spdb.h"
#include "nat_traversal.h"
#include "vendor.h"
#include "ip_address.h"
#include "ikev2_send.h"
#include "state_db.h"
#include "ietf_constants.h"
#include "ikev2_cookie.h"
#include "plutoalg.h" /* for default_ike_groups */
#include "ikev2_message.h"	/* for ikev2_decrypt_msg() */
#include "pluto_stats.h"
#include "keywords.h"
#include "ikev2_msgid.h"
#include "ikev2_states.h"
#include "ip_endpoint.h"
#include "hostpair.h"		/* for find_v2_host_connection() */
#include "kernel.h"


static void v2_dispatch(struct ike_sa *ike, struct state *st,
			struct msg_digest **mdp,
			const struct state_v2_microcode *transition);

/*
 * IKEv2 has slightly different states than IKEv1.
 *
 * IKEv2 puts all the responsibility for retransmission on the end that
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

#define P(N) LELEM(ISAKMP_NEXT_v2##N)

/*
 * IKEv2 State transitions (aka microcodes).
 *
 * This table contains all possible state transitions, some of which
 * involve a message.
 *
 * During initialization this table parsed populating the
 * corresponding IKEv2 finite states.  While not the most efficient,
 * it seems to work.
 */

static /*const*/ struct state_v2_microcode v2_state_microcode_table[] = {

	/* no state:   --> CREATE_CHILD IKE Rekey Request
	 * HDR, SAi, KEi, Ni -->
	 */

	{ .story      = "Initiate CREATE_CHILD_SA IKE Rekey",
	  .state      = STATE_V2_REKEY_IKE_I0,
	  .next_state = STATE_V2_REKEY_IKE_I,
	  .flags      = SMF2_MESSAGE_RESPONSE,
	  .send = MESSAGE_REQUEST,
	  .processor  = NULL,
	  .timeout_event = EVENT_RETRANSMIT, },

	/* no state:   --> CREATE IPsec Rekey Request
	 * HDR, SAi1, N(REKEY_SA), {KEi,} Ni TSi TSr -->
	 */
	{ .story      = "Initiate CREATE_CHILD_SA IPsec Rekey SA",
	  .state      = STATE_V2_REKEY_CHILD_I0,
	  .next_state = STATE_V2_REKEY_CHILD_I,
	  .flags =      SMF2_MESSAGE_RESPONSE,
	  .send = MESSAGE_REQUEST,
	  .processor  = NULL,
	  .timeout_event = EVENT_RETRANSMIT, },

	/* no state:   --> CREATE IPsec Child Request
	 * HDR, SAi1, {KEi,} Ni TSi TSr -->
	 */
	{ .story      = "Initiate CREATE_CHILD_SA IPsec SA",
	  .state      = STATE_V2_CREATE_I0,
	  .next_state = STATE_V2_CREATE_I,
	  .flags =      SMF2_MESSAGE_RESPONSE,
	  .send = MESSAGE_REQUEST,
	  .processor  = NULL,
	  .timeout_event = EVENT_RETRANSMIT, },

	/* no state:   --> I1
	 * HDR, SAi1, KEi, Ni -->
	 */
	{ .story      = "initiate IKE_SA_INIT",
	  .state      = STATE_PARENT_I0,
	  .next_state = STATE_PARENT_I1,
	  .flags      = SMF2_MESSAGE_RESPONSE,
	  .send = MESSAGE_REQUEST,
	  .processor  = NULL,
	  .timeout_event = EVENT_RETRANSMIT, },

	/* STATE_PARENT_I1: R1B --> I1B
	 *                     <--  HDR, N
	 * HDR, N, SAi1, KEi, Ni -->
	 */
	{ .story      = "Initiator: process SA_INIT reply notification",
	  .state      = STATE_PARENT_I1,
	  .next_state = STATE_PARENT_I1,
	  .flags = SMF2_MESSAGE_RESPONSE,
	  .send = MESSAGE_REQUEST,
	  .req_clear_payloads = P(N),
	  .opt_clear_payloads = LEMPTY,
	  .processor = ikev2_IKE_SA_process_SA_INIT_response_notification,
	  .recv_type  = ISAKMP_v2_IKE_SA_INIT,
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
	  .flags = SMF2_MESSAGE_RESPONSE,
	  .send = MESSAGE_REQUEST,
	  .req_clear_payloads = P(SA) | P(KE) | P(Nr),
	  .opt_clear_payloads = P(CERTREQ),
	  .processor  = ikev2_parent_inR1outI2,
	  .recv_type  = ISAKMP_v2_IKE_SA_INIT,
	  .timeout_event = EVENT_RETRANSMIT, },

	/* STATE_PARENT_I2: R2 -->
	 *                     <--  HDR, SK {IDr, [CERT,] AUTH,
	 *                               SAr2, TSi, TSr}
	 * [Parent SA established]
	 */
	{ .story      = "Initiator: process INVALID_SYNTAX AUTH notification",
	  .state      = STATE_PARENT_I2, .next_state = STATE_PARENT_I2,
	  .flags = SMF2_MESSAGE_RESPONSE,
	  .message_payloads = { .required = P(SK), },
	  .encrypted_payloads = { .required = P(N), .notification = v2N_INVALID_SYNTAX, },
	  .processor  = ikev2_auth_initiator_process_failure_notification,
	  .recv_type  = ISAKMP_v2_IKE_AUTH, },
	{ .story      = "Initiator: process AUTHENTICATION_FAILED AUTH notification",
	  .state      = STATE_PARENT_I2, .next_state = STATE_PARENT_I2,
	  .flags = SMF2_MESSAGE_RESPONSE,
	  .message_payloads = { .required = P(SK), },
	  .encrypted_payloads = { .required = P(N), .notification = v2N_AUTHENTICATION_FAILED, },
	  .processor  = ikev2_auth_initiator_process_failure_notification,
	  .recv_type  = ISAKMP_v2_IKE_AUTH, },
	{ .story      = "Initiator: process UNSUPPORTED_CRITICAL_PAYLOAD AUTH notification",
	  .state      = STATE_PARENT_I2, .next_state = STATE_PARENT_I2,
	  .flags = SMF2_MESSAGE_RESPONSE,
	  .message_payloads = { .required = P(SK), },
	  .encrypted_payloads = { .required = P(N), .notification = v2N_UNSUPPORTED_CRITICAL_PAYLOAD, },
	  .processor  = ikev2_auth_initiator_process_failure_notification,
	  .recv_type  = ISAKMP_v2_IKE_AUTH, },
	/*
	 * XXX: Danger! This state transition mashes the IKE SA's
	 * initial state and the CHILD SA's final state.  There should
	 * instead be two separate state transitions: IKE SA:
	 * STATE_PARENT_I2 -> STATE_PARENT_I3; CHILD SA: ??? ->
	 * STATE_V2_IPSEC_I->???.  The IKE SA could then initiate the
	 * CHILD SA's transaction.
	 */
	{ .story      = "Initiator: process IKE_AUTH response",
	  .state      = STATE_PARENT_I2,
	  .next_state = STATE_V2_IPSEC_I,
	  .flags = SMF2_MESSAGE_RESPONSE | SMF2_ESTABLISHED,
	  .req_clear_payloads = P(SK),
	  .req_enc_payloads = P(IDr) | P(AUTH) | P(SA) | P(TSi) | P(TSr),
	  .opt_enc_payloads = P(CERT)|P(CP),
	  .processor  = ikev2_parent_inR2,
	  .recv_type  = ISAKMP_v2_IKE_AUTH,
	  .timeout_event = EVENT_SA_REPLACE, },
	{ .story      = "IKE SA: process IKE_AUTH response containing unknown notification",
	  .state      = STATE_PARENT_I2, .next_state = STATE_PARENT_I2,
	  .flags = SMF2_MESSAGE_RESPONSE,
	  .message_payloads = { .required = P(SK), },
	  .encrypted_payloads = { .required = P(N), },
	  .processor  = ikev2_auth_initiator_process_unknown_notification,
	  .recv_type  = ISAKMP_v2_IKE_AUTH, },

	/* no state: none I1 --> R1
	 *                <-- HDR, SAi1, KEi, Ni
	 * HDR, SAr1, KEr, Nr, [CERTREQ] -->
	 */
	{ .story      = "Respond to IKE_SA_INIT",
	  .state      = STATE_PARENT_R0,
	  .next_state = STATE_PARENT_R1,
	  .flags = SMF2_MESSAGE_REQUEST,
	  .send = MESSAGE_RESPONSE,
	  .req_clear_payloads = P(SA) | P(KE) | P(Ni),
	  .processor  = ikev2_parent_inI1outR1,
	  .recv_type  = ISAKMP_v2_IKE_SA_INIT,
	  .timeout_event = EVENT_SO_DISCARD, },

	/* STATE_PARENT_R1: I2 --> R2
	 *                  <-- HDR, SK {IDi, [CERT,] [CERTREQ,]
	 *                             [IDr,] AUTH, SAi2,
	 *                             TSi, TSr}
	 * HDR, SK {IDr, [CERT,] AUTH,
	 *      SAr2, TSi, TSr} -->
	 *
	 * [Parent SA established]
	 */
	{ .story      = "Responder: process IKE_AUTH request (no SKEYSEED)",
	  .state      = STATE_PARENT_R1,
	  .next_state = STATE_PARENT_R1,
	  .flags = SMF2_MESSAGE_REQUEST | SMF2_NO_SKEYSEED,
	  .send = MESSAGE_RESPONSE,
	  .req_clear_payloads = P(SK),
	  .req_enc_payloads = LEMPTY,
	  .opt_enc_payloads = LEMPTY,
	  .processor  = ikev2_ike_sa_process_auth_request_no_skeyid,
	  .recv_type  = ISAKMP_v2_IKE_AUTH,
	  .timeout_event = EVENT_SA_REPLACE, },
	/*
	 * XXX: Danger! This state transition mashes the IKE SA's
	 * initial state and the CHILD SA's final state.  There should
	 * instead be two separate state transitions: IKE SA:
	 * STATE_PARENT_R1->STATE_PARENT_R2; CHILD SA::
	 * ???->STATE_V2_IPSEC_R.  The IKE SA could then initiate the
	 * CHILD SA's transaction.
	 */
	{ .story      = "Responder: process IKE_AUTH request",
	  .state      = STATE_PARENT_R1,
	  .next_state = STATE_V2_IPSEC_R,
	  .flags = SMF2_MESSAGE_REQUEST | SMF2_ESTABLISHED,
	  .send = MESSAGE_RESPONSE,
	  .req_clear_payloads = P(SK),
	  .req_enc_payloads = P(IDi) | P(AUTH) | P(SA) | P(TSi) | P(TSr),
	  .opt_enc_payloads = P(CERT) | P(CERTREQ) | P(IDr) | P(CP),
	  .processor  = ikev2_ike_sa_process_auth_request,
	  .recv_type  = ISAKMP_v2_IKE_AUTH,
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

	/*
	 * Create Child SA Exchange to rekey IKE SA
	 * no state:   --> REKEY_IKE_R
	 * HDR, SAi1, KEi, Ni -->
	 *		<-- HDR, SAr1, KEr, Nr
	 */
	{ .story      = "Respond to CREATE_CHILD_SA IKE Rekey",
	  .state      = STATE_V2_REKEY_IKE_R,
	  .next_state = STATE_PARENT_R2,
	  .flags      = SMF2_MESSAGE_REQUEST,
	  .send = MESSAGE_RESPONSE,
	  .req_clear_payloads = P(SK),
	  .req_enc_payloads = P(SA) | P(Ni) | P(KE),
	  .opt_enc_payloads = P(N),
	  .processor  = ikev2_child_ike_inIoutR,
	  .recv_type  = ISAKMP_v2_CREATE_CHILD_SA,
	  .timeout_event = EVENT_SA_REPLACE },

	{ .story      = "Process CREATE_CHILD_SA IKE Rekey Response",
	  .state      = STATE_V2_REKEY_IKE_I,
	  .next_state = STATE_PARENT_I3,
	  .flags      = SMF2_MESSAGE_RESPONSE,
	  .req_clear_payloads = P(SK),
	  .req_enc_payloads = P(SA) | P(Ni) |  P(KE),
	  .opt_enc_payloads = P(N),
	  .processor  = ikev2_child_ike_inR,
	  .recv_type  = ISAKMP_v2_CREATE_CHILD_SA,
	  .timeout_event = EVENT_SA_REPLACE, },

	/*
	 * request --> [N(REKEY_SA),]
	 * [CP(CFG_REQUEST),]
	 * [N(IPCOMP_SUPPORTED)+,]
	 * [N(USE_TRANSPORT_MODE),]
	 * [N(ESP_TFC_PADDING_NOT_SUPPORTED),]
	 * [N(NON_FIRST_FRAGMENTS_ALSO),]
	 * SA, Ni, [KEi,] TSi, TSr,
	 * [V+][N+]
	 */
	{ .story      = "Process CREATE_CHILD_SA IPsec SA Response",
	  .state      = STATE_V2_CREATE_I,
	  .next_state = STATE_V2_IPSEC_I,
	  .flags      = SMF2_MESSAGE_RESPONSE | SMF2_ESTABLISHED,
	  .req_clear_payloads = P(SK),
	  .req_enc_payloads = P(SA) | P(Ni) | P(TSi) | P(TSr),
	  .opt_enc_payloads = P(KE) | P(N) | P(CP),
	  .processor  = ikev2_child_inR,
	  .recv_type  = ISAKMP_v2_CREATE_CHILD_SA,
	  .timeout_event = EVENT_SA_REPLACE, },

	{ .story      = "Respond to CREATE_CHILD_SA IPsec SA Request",
	  .state      = STATE_V2_CREATE_R,
	  .next_state = STATE_V2_IPSEC_R,
	  .flags      = SMF2_MESSAGE_REQUEST | SMF2_ESTABLISHED,
	  .send = MESSAGE_RESPONSE,
	  .req_clear_payloads = P(SK),
	  .req_enc_payloads = P(SA) | P(Ni) | P(TSi) | P(TSr),
	  .opt_enc_payloads = P(KE) | P(N) | P(CP),
	  .processor  = ikev2_child_inIoutR,
	  .recv_type  = ISAKMP_v2_CREATE_CHILD_SA,
	  .timeout_event = EVENT_SA_REPLACE, },

	/* Informational Exchange */

	/* RFC 5996 1.4 "The INFORMATIONAL Exchange"
	 *
	 * HDR, SK {[N,] [D,] [CP,] ...}  -->
	 *   <--  HDR, SK {[N,] [D,] [CP], ...}
	*
	 * A liveness exchange is a special empty message.
	 *
	 * XXX: since these just generate an empty response, they
	 * might as well have a dedicated liveness function.
	 *
	 * XXX: rather than all this transition duplication, the
	 * established states should share common transition stored
	 * outside of this table.
	 */

	{ .story      = "I3: Informational Request",
	  .state      = STATE_PARENT_I3,
	  .next_state = STATE_PARENT_I3,
	  .flags      = SMF2_SUPPRESS_SUCCESS_LOG,
	  .message_payloads.required = P(SK),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_RETAIN, },

	{ .story      = "I3: Informational Response",
	  .state      = STATE_PARENT_I3,
	  .next_state = STATE_PARENT_I3,
	  .flags      = SMF2_SUPPRESS_SUCCESS_LOG,
	  .message_payloads.required = P(SK),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_RETAIN, },

	{ .story      = "I3: INFORMATIONAL Request",
	  .state      = STATE_PARENT_I3,
	  .next_state = STATE_PARENT_I3,
	  .flags      = LEMPTY,
	  .req_clear_payloads = P(SK),
	  .opt_enc_payloads = P(N) | P(D) | P(CP),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_RETAIN, },

	{ .story      = "I3: INFORMATIONAL Response",
	  .state      = STATE_PARENT_I3,
	  .next_state = STATE_PARENT_I3,
	  .flags      = LEMPTY,
	  .req_clear_payloads = P(SK),
	  .opt_enc_payloads = P(N) | P(D) | P(CP),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_RETAIN, },

	{ .story      = "R2: process Informational Request",
	  .state      = STATE_PARENT_R2,
	  .next_state = STATE_PARENT_R2,
	  .flags      = SMF2_SUPPRESS_SUCCESS_LOG,
	  .message_payloads.required = P(SK),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_RETAIN, },

	{ .story      = "R2: process Informational Response",
	  .state      = STATE_PARENT_R2,
	  .next_state = STATE_PARENT_R2,
	  .flags      = SMF2_SUPPRESS_SUCCESS_LOG,
	  .message_payloads.required = P(SK),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_RETAIN, },

	{ .story      = "R2: process INFORMATIONAL Request",
	  .state      = STATE_PARENT_R2,
	  .next_state = STATE_PARENT_R2,
	  .flags      = LEMPTY,
	  .req_clear_payloads = P(SK),
	  .opt_enc_payloads = P(N) | P(D) | P(CP),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_RETAIN, },

	{ .story      = "R2: process INFORMATIONAL Response",
	  .state      = STATE_PARENT_R2,
	  .next_state = STATE_PARENT_R2,
	  .flags      = LEMPTY,
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

void init_ikev2(void)
{
	dbg("checking IKEv2 state table");

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
		const struct finite_state *fs = &v2_states[kind - STATE_IKEv2_FLOOR];
		passert(fs->kind == kind);
		passert(finite_states[kind] == NULL);
		finite_states[kind] = fs;
	}

	/*
	 * Iterate over the state transitions filling in missing bits
	 * and checking for consistency.
	 */
	for (struct state_v2_microcode *t = v2_state_microcode_table;
	     t->state < STATE_IKEv2_ROOF; t++) {

		passert(t->state >= STATE_IKEv2_FLOOR);
		passert(t->state < STATE_IKEv2_ROOF);
		struct finite_state *from = &v2_states[t->state - STATE_IKEv2_FLOOR];

		passert(t->next_state >= STATE_IKEv2_FLOOR);
		passert(t->next_state < STATE_IKEv2_ROOF);
		const struct finite_state *to = finite_states[t->next_state];
		passert(to != NULL);

		if (DBGP(DBG_BASE)) {
			if (from->nr_transitions == 0) {
				LSWLOG_DEBUG(buf) {
					jam(buf, "  ");
					lswlog_finite_state(buf, from);
					jam(buf, ":");
				}
			}
			const char *send;
			switch (t->send) {
			case NO_MESSAGE: send = ""; break;
			case MESSAGE_REQUEST: send = " send-request"; break;
			case MESSAGE_RESPONSE: send = " send-response"; break;
			default: bad_case(t->send);
			}
			DBG_log("    -> %s %s%s (%s)", to->short_name,
				enum_short_name(&timer_event_names,
						t->timeout_event),
				send, t->story);
		}

		/*
		 * Point .fs_v2_microcode at the first transition for
		 * the from state.  All other transitions for the from
		 * state should follow immediately after (or to put it
		 * another way, previous should match).
		 */
		if (from->v2_transitions == NULL) {
			/* start of the next state */
			passert(from->nr_transitions == 0);
			from->v2_transitions = t;
		} else {
			passert(t[-1].state == t->state);
		}
		from->nr_transitions++;


		/*
		 * Pack expected payloads et.al. into a structure.
		 *
		 * XXX: should be adding everywhere payloads here?!?
		 */
		if (t->req_clear_payloads != LEMPTY) {
			t->message_payloads.required = t->req_clear_payloads;
		}
		if (t->opt_clear_payloads != LEMPTY) {
			t->message_payloads.optional = t->opt_clear_payloads;
		}
		if (t->req_enc_payloads != LEMPTY) {
			t->encrypted_payloads.required = t->req_enc_payloads;
		}
		if (t->opt_enc_payloads != LEMPTY) {
			t->encrypted_payloads.optional = t->opt_enc_payloads;
		}

	}
}

/*
 * split an incoming message into payloads
 */
static struct payload_summary ikev2_decode_payloads(struct state *st,
						    struct msg_digest *md,
						    pb_stream *in_pbs,
						    enum next_payload_types_ikev2 np)
{
	struct payload_summary summary = {
		.parsed = true,
		.n = v2N_NOTHING_WRONG,
	};

	/*
	 * ??? zero out the digest descriptors -- might nuke
	 * ISAKMP_NEXT_v2SK digest!
	 *
	 * XXX: and v2SKF? Safer to leave them as is and just use new
	 * ones - always add to MD, never take away.
	 */

	/*
	 * XXX: Currently, when a message containing an SK payload is
	 * decoded, the encrypted payloads get appended to the
	 * previously decoded non-encrypted payloads.  For instance,
	 * given a message containing two notifications:
	 *
	 *     N(1), SK{ N(2) }
	 *
	 * The notification digest would contain both the unencrypted
	 * N(1) and encrypted N(2).  Since the unencrypted value is
	 * protected, while not very good, isn't really dangerous.
	 */

	while (np != ISAKMP_NEXT_v2NONE) {
		dbg("Now let's proceed with payload (%s)",
		    enum_show(&ikev2_payload_names, np));

		if (md->digest_roof >= elemsof(md->digest)) {
			log_message(RC_LOG_SERIOUS, st, md,
				    "more than %zu payloads in message; ignored",
				    elemsof(md->digest));
			summary.n = v2N_INVALID_SYNTAX;
			break;
		}

		/*
		 * *pd is the payload digest for this payload.
		 * It has three fields:
		 *	pbs is filled in by in_struct
		 *	payload is filled in by in_struct
		 *	next is filled in by list linking logic
		 */
		struct payload_digest *const pd = md->digest + md->digest_roof;

		/* map the payload onto a way to decode it */
		const struct_desc *sd = v2_payload_desc(np);

		if (sd == NULL) {
			/*
			 * This payload is unknown to us.  RFCs 4306
			 * and 5996 2.5 say that if the payload has
			 * the Critical Bit, we should be upset but if
			 * it does not, we should just ignore it.
			 */
			if (!in_struct(&pd->payload, &ikev2_generic_desc, in_pbs, &pd->pbs)) {
				log_message(RC_LOG_SERIOUS, st, md,
					    "malformed payload in packet");
				summary.n = v2N_INVALID_SYNTAX;
				break;
			}
			if (pd->payload.v2gen.isag_critical & ISAKMP_PAYLOAD_CRITICAL) {
				/*
				 * It was critical.  See RFC 5996 1.5
				 * "Version Numbers and Forward
				 * Compatibility"
				 */
				const char *role;
				switch (v2_msg_role(md)) {
				case MESSAGE_REQUEST:
					role = "request";
					break;
				case MESSAGE_RESPONSE:
					role = "response";
					break;
				default:
					bad_case(v2_msg_role(md));
				}
				log_message(RC_LOG_SERIOUS, st, md,
					    "message %s contained an unknown critical payload type (%s)",
					    role, enum_show(&ikev2_payload_names, np));
				summary.n = v2N_UNSUPPORTED_CRITICAL_PAYLOAD;
				summary.data[0] = np;
				summary.data_size = 1;
				break;
			}
			struct esb_buf eb;
			log_message(RC_COMMENT, st, md,
				    "non-critical payload ignored because it contains an unknown or unexpected payload type (%s) at the outermost level",
				    enum_showb(&ikev2_payload_names, np, &eb));
			np = pd->payload.generic.isag_np;
			continue;
		}

		if (np >= LELEM_ROOF) {
			dbg("huge next-payload %u", np);
			summary.n = v2N_INVALID_SYNTAX;
			break;
		}
		summary.repeated |= (summary.present & LELEM(np));
		summary.present |= LELEM(np);

		/*
		 * Read in the payload recording what type it should
		 * be.
		 */
		pd->payload_type = np;
		if (!in_struct(&pd->payload, sd, in_pbs, &pd->pbs)) {
			log_message(RC_LOG_SERIOUS,  st, md,
				    "malformed payload in packet");
			summary.n = v2N_INVALID_SYNTAX;
			break;
		}

		dbg("processing payload: %s (len=%zu)",
		    enum_show(&ikev2_payload_names, np),
		    pbs_left(&pd->pbs));

		/*
		 * Place payload at the end of the chain for this type.
		 * This code appears in ikev1.c and ikev2.c.
		 */
		{
			/* np is a proper subscript for chain[] */
			passert(np < elemsof(md->chain));
			struct payload_digest **p = &md->chain[np];

			while (*p != NULL)
				p = &(*p)->next;
			*p = pd;
			pd->next = NULL;
		}

		/*
		 * XXX: should this do 'deeper' analysis of packets.
		 * For instance checking the SPI of a notification
		 * payload?  Probably not as the value may be ignored.
		 */

		/*
		 * Advance next payload.
		 */
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

		md->digest_roof++;
	}

	return summary;
}

static bool ikev2_check_fragment(struct msg_digest *md, struct state *st)
{
	struct ikev2_skf *skf = &md->chain[ISAKMP_NEXT_v2SKF]->payload.v2skf;

	/* ??? CLANG 3.5 thinks st might be NULL */
	if (!(st->st_connection->policy & POLICY_IKE_FRAG_ALLOW)) {
		DBG(DBG_CONTROL, DBG_log(
			"discarding IKE encrypted fragment - fragmentation not allowed by local policy (ike_frag=no)"));
		return FALSE;
	}

	if (!(st->st_seen_fragvid)) {
		DBG(DBG_CONTROL, DBG_log(
			    "discarding IKE encrypted fragment - remote never proposed fragmentation"));
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

	if (st->st_v2_rfrags == NULL) {
		/* first fragment: must be good */
		return TRUE;
	}

	if (skf->isaskf_total != st->st_v2_rfrags->total) {
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
		if (skf->isaskf_total > st->st_v2_rfrags->total) {
			DBG(DBG_CONTROL, DBG_log(
				"discarding saved fragments because this fragment has larger total"));
			release_fragments(st);
			return TRUE;
		} else {
			DBG(DBG_CONTROL, DBG_log(
				"ignoring odd IKE encrypted fragment (total shrank)"));
			return FALSE;
		}
	} else if (st->st_v2_rfrags->frags[skf->isaskf_number].cipher.ptr != NULL) {
		/* retain earlier fragment with same index */
		DBG(DBG_CONTROL, DBG_log(
			    "ignoring repeated IKE encrypted fragment"));
		return FALSE;
	} else {
		return TRUE;
	}
}

static bool ikev2_collect_fragment(struct msg_digest *md, struct state *st)
{
	struct ikev2_skf *skf = &md->chain[ISAKMP_NEXT_v2SKF]->payload.v2skf;
	pb_stream *e_pbs = &md->chain[ISAKMP_NEXT_v2SKF]->pbs;

	if (!st->st_seen_fragvid) {
		DBG(DBG_CONTROL,
                    DBG_log(" fragments claiming to be from peer while peer did not signal fragmentation support - dropped"));
		return FALSE;
	}

	if (!ikev2_check_fragment(md, st)) {
		return FALSE;
	}

	/* if receiving fragments, respond with fragments too */
	if (!st->st_seen_fragments) {
		st->st_seen_fragments = TRUE;
		DBG(DBG_CONTROL,
		    DBG_log(" updated IKE fragment state to respond using fragments without waiting for re-transmits"));
	}

	/*
	 * Since the fragment check above can result in all fragments
	 * so-far being discarded; always check/fix frags.
	 */
	if (st->st_v2_rfrags == NULL) {
		st->st_v2_rfrags = alloc_thing(struct v2_ike_rfrags, "incoming v2_ike_rfrags");
		st->st_v2_rfrags->total = skf->isaskf_total;
	}

	passert(skf->isaskf_number < elemsof(st->st_v2_rfrags->frags));
	struct v2_ike_rfrag *frag = &st->st_v2_rfrags->frags[skf->isaskf_number];
	passert(frag->cipher.ptr == NULL);
	frag->iv = e_pbs->cur - md->packet_pbs.start;
	frag->cipher = clone_bytes_as_chunk(md->packet_pbs.start,
					    e_pbs->roof - md->packet_pbs.start,
					    "incoming IKEv2 encrypted fragment");

	if (skf->isaskf_number == 1) {
		st->st_v2_rfrags->first_np = skf->isaskf_np;
	}

	passert(st->st_v2_rfrags->count < st->st_v2_rfrags->total);
	st->st_v2_rfrags->count++;
	return st->st_v2_rfrags->count == st->st_v2_rfrags->total;
}

static struct child_sa *process_v2_child_ix(struct ike_sa *ike,
					    const struct state_v2_microcode *svm)
{
	/* for log */
	const char *what;
	const char *why = "";

	struct child_sa *child; /* to-be-determined */
	if (svm->state == STATE_V2_CREATE_R) {
		what = "Child SA Request";
		child = ikev2_duplicate_state(ike, IPSEC_SA,
					      SA_RESPONDER,
					      null_fd);
		change_state(&child->sa, STATE_V2_CREATE_R);
	} else {
		what = "IKE Rekey Request";
		child = ikev2_duplicate_state(ike, IKE_SA,
					      SA_RESPONDER,
					      null_fd);
		change_state(&child->sa, STATE_V2_REKEY_IKE_R); /* start with this */
	}

	binlog_refresh_state(&child->sa);

	connection_buf ibuf;
	connection_buf cbuf;
	dbg(PRI_CONNECTION" #%lu received %s CREATE_CHILD_SA%s Child "PRI_CONNECTION" #%lu in %s will process it further",
	    pri_connection(ike->sa.st_connection, &ibuf),
	    ike->sa.st_serialno,
	    what, why,
	    pri_connection(child->sa.st_connection, &cbuf),
	    child->sa.st_serialno, child->sa.st_state->name);

	return child;
}

/*
 * Find the SA (IKE or CHILD), within IKE's family, that is initiated
 * or is responding to Message ID.
 *
 * XXX: There's overlap between this and the is_duplicate_*() code.
 * For instance, there's little point in looking for a state when the
 * IKE SA's window shows it too old (at least if we ignore
 * record'n'send bugs).
 */

struct wip_filter {
	msgid_t msgid;
};

static bool v2_sa_by_initiator_wip_p(struct state *st, void *context)
{
	const struct wip_filter *filter = context;
	return st->st_v2_msgid_wip.initiator == filter->msgid;
}

static struct state *find_v2_sa_by_initiator_wip(struct ike_sa *ike, const msgid_t msgid)
{
	/*
	 * XXX: Would a linked list of CHILD SAs work better, would
	 * mean reference counting?  Should this also check that MSGID
	 * is within the IKE SA's window?
	 */
	struct wip_filter filter = {
		.msgid = msgid,
	};
	struct state *st;
	if (v2_sa_by_initiator_wip_p(&ike->sa, &filter)) {
		st = &ike->sa;
	} else {
		st = state_by_ike_spis(IKEv2,
				       NULL/*ignore clonedfrom*/,
				       NULL/*ignore v1 msgid*/,
				       NULL/*ignore role*/,
				       &ike->sa.st_ike_spis,
				       v2_sa_by_initiator_wip_p, &filter, __func__);
	}
	pexpect(st == NULL ||
		st->st_clonedfrom == SOS_NOBODY ||
		st->st_clonedfrom == ike->sa.st_serialno);
	return st;
}

static bool v2_sa_by_responder_wip_p(struct state *st, void *context)
{
	const struct wip_filter *filter = context;
	return st->st_v2_msgid_wip.responder == filter->msgid;
}

static struct state *find_v2_sa_by_responder_wip(struct ike_sa *ike, const msgid_t msgid)
{
	/*
	 * XXX: Would a linked list of CHILD SAs work better, would
	 * mean reference counting?  Should this also check that MSGID
	 * is within the IKE SA's window?
	 */
	struct wip_filter filter = {
		.msgid = msgid,
	};
	struct state *st;
	if (v2_sa_by_responder_wip_p(&ike->sa, &filter)) {
		st = &ike->sa;
	} else {
		st = state_by_ike_spis(IKEv2,
				       NULL/*ignore clonedfrom*/,
				       NULL/*ignore v1 msgid*/,
				       NULL/*ignore role*/,
				       &ike->sa.st_ike_spis,
				       v2_sa_by_responder_wip_p, &filter, __func__);
	}
	pexpect(st == NULL ||
		st->st_clonedfrom == SOS_NOBODY ||
		st->st_clonedfrom == ike->sa.st_serialno);
	return st;
}

/*
 * Is this a duplicate message?
 *
 * XXX:
 *
 * record'n'send bypassing the send queue can result in pluto having
 * more outstanding messages then the negotiated window size.
 *
 * This and the find_v2_sa_by_*_wip() have some overlap.  For
 * instance, little point in searching for a state when the IKE SA's
 * window shows the Message ID is too old (only record'n'send breakage
 * means it might still have a message, argh!).
 *
 * This code should use an explicit log function.  libreswan_log() is
 * at the mercy of the caller so the messages might be logged against
 * ST and might be logged against IKE.  This is one thing that
 * prevents find_v2_sa_by_*_wip() and this code being better
 * organized.
 */

/*
 * A duplicate request could be:
 *
 * - the request still being processed (for instance waiting on
 *   crypto), which can be tossed
 *
 * - the request last processed, which should trigger a retransmit of
 *   the response
 *
 * - an older request which can be tossed
 *
 * But if it is a fragment, much of this is skipped.
 */
static bool is_duplicate_request(struct ike_sa *ike,
				 struct msg_digest *md)
{
	passert(v2_msg_role(md) == MESSAGE_REQUEST);
	intmax_t msgid = md->hdr.isa_msgid;

	/* lie to keep test results happy */
	dbg("#%lu st.st_msgid_lastrecv %jd md.hdr.isa_msgid %08jx",
	    ike->sa.st_serialno, ike->sa.st_v2_msgid_windows.responder.recv, msgid);

	/* the sliding window is really small?!? */
	pexpect(ike->sa.st_v2_msgid_windows.responder.recv ==
		ike->sa.st_v2_msgid_windows.responder.sent);

	if (msgid < ike->sa.st_v2_msgid_windows.responder.sent) {
		/*
		 * this is an OLD retransmit and out sliding window
		 * holds only the most recent response. we can't do
		 * anything
		 */
		log_state(RC_LOG, &ike->sa,
			  "received too old retransmit: %jd < %jd",
			  msgid, ike->sa.st_v2_msgid_windows.responder.sent);
		return true;
	} else if (msgid == ike->sa.st_v2_msgid_windows.responder.sent) {
		/*
		 * This was the last request processed and,
		 * presumably, a response was sent.  Retransmit the
		 * saved response (the response was saved right?).
		 */
		if (ike->sa.st_tpacket.len == 0 && ike->sa.st_v2_tfrags == NULL) {
			FAIL_V2_MSGID(ike, &ike->sa,
				      "retransmission for messsage %jd exchange %s failed responder.sent %jd - there is no stored message or fragments to retransmit",
				      msgid, enum_name(&ikev2_exchange_names, md->hdr.isa_xchg),
				      ike->sa.st_v2_msgid_windows.responder.sent);
			return true;
		}
		/*
		 * If things are fragmented, only respond to the first
		 * fragment.
		 */
		unsigned fragment = 0;
		if (md->hdr.isa_np == ISAKMP_NEXT_v2SKF) {
			struct ikev2_skf skf;
			pb_stream in_pbs = md->message_pbs; /* copy */
			if (!in_struct(&skf, &ikev2_skf_desc, &in_pbs, NULL)) {
				return true;
			}
			fragment = skf.isaskf_number;
		}
		if (fragment == 0) {
			log_state(RC_LOG, &ike->sa,
				  "received duplicate %s message request (Message ID %jd); retransmitting response",
				  enum_short_name(&ikev2_exchange_names, md->hdr.isa_xchg),
				  msgid);
			send_recorded_v2_ike_msg(&ike->sa, "ikev2-responder-retransmit");
		} else if (fragment == 1) {
			log_state(RC_LOG, &ike->sa,
				  "received duplicate %s message request (Message ID %jd, fragment %u); retransmitting response",
				  enum_short_name(&ikev2_exchange_names, md->hdr.isa_xchg),
				  msgid, fragment);
			send_recorded_v2_ike_msg(&ike->sa, "ikev2-responder-retransmt (fragment 1)");
		} else {
			dbg_v2_msgid(ike, &ike->sa,
				     "received duplicate %s message request (Message ID %jd, fragment %u); discarded as not fragment 1",
				     enum_short_name(&ikev2_exchange_names, md->hdr.isa_xchg),
				     msgid, fragment);
		}
		return true;
	} else {
		/* all that is left */
		pexpect(msgid > ike->sa.st_v2_msgid_windows.responder.sent);
	}

	/*
	 * Is something already processing this request?
	 *
	 * Processing only starts for real once a responder has
	 * accumulated all fragments and obtained KEYMAT.
	 */
	{
		struct state *responder = find_v2_sa_by_responder_wip(ike, md->hdr.isa_msgid);
		/* only a true responder */
		pexpect(responder == NULL ||
			responder->st_v2_msgid_wip.responder == msgid);
		if (responder != NULL) {
			/* this generates the log message */
			pexpect(verbose_state_busy(responder));
			return true;
		}
	}

	/*
	 * The IKE SA responder, having accumulated all the fragments
	 * for the IKE_AUTH request, is computing the SKEYSEED.  When
	 * SKEYSEED finishes .st_v2_rfrags is wiped and the Message
	 * IDs updated to flag that the message as work-in-progress
	 * (so above check will have succeeded).
	 */
	if (state_is_busy(&ike->sa)) {
		/*
		 * To keep tests happy, try to output text matching
		 * verbose_state_busy(); but with some extra detail.
		 */
#if 0
		/*
		 * XXX: hang onto this code for now - it shows how to
		 * lightly unpack fragments.  Will be useful when
		 * fragmentation code is moved out of the state lookup
		 * code.
		 */
		unsigned fragment = 0;
		if (md->hdr.isa_np == ISAKMP_NEXT_v2SKF) {
			struct ikev2_skf skf;
			pb_stream in_pbs = md->message_pbs; /* copy */
			if (!in_struct(&skf, &ikev2_skf_desc, &in_pbs, NULL)) {
				return true;
			}
			fragment = skf.isaskf_number;
		}
		if (fragment == 0) {
			log_state(RC_LOG, &ike->sa,
				  "discarding packet received during asynchronous work (DNS or crypto) in %s",
				  ike->sa.st_state->name);
		} else if (fragment == 1) {
			log_state(RC_LOG, &ike->sa,
				  "discarding fragments received during asynchronous work (DNS or crypto) in %s",
				  ike->sa.st_state->name);
		} else {
			dbg_v2_msgid(ike, &ike->sa,
				     "discarding fragment %u received during asynchronous work (DNS or crypto) in %s",
				     fragment, ike->sa.st_state->name);
		}
#else
		log_state(RC_LOG, &ike->sa,
			  "discarding packet received during asynchronous work (DNS or crypto) in %s",
			  ike->sa.st_state->name);
#endif
		return true;
	}

	if (ike->sa.st_v2_rfrags != NULL) {
		pexpect(ike->sa.st_v2_rfrags->count < ike->sa.st_v2_rfrags->total);
		dbg_v2_msgid(ike, &ike->sa,
			     "not a duplicate - responder is accumulating fragments for message request %jd",
			     msgid);
	} else {
		dbg_v2_msgid(ike, &ike->sa,
			     "not a duplicate - message request %jd is new",
			     msgid);
	}

	return false;
}

/*
 * A duplicate response could be:
 *
 * - for an old request where there's no longer an initiator waiting,
 *   and can be dropped
 *
 * - the initiator is busy, presumably because this response is a
 *   duplicate and the initiator is waiting on crypto to complete so
 *   it can decrypt the response
 */
static bool is_duplicate_response(struct ike_sa *ike,
				  struct state *initiator,
				  struct msg_digest *md)
{
	passert(v2_msg_role(md) == MESSAGE_RESPONSE);
	intmax_t msgid = md->hdr.isa_msgid;

	/* only a true initiator */
	pexpect(initiator == NULL ||
		initiator->st_v2_msgid_wip.initiator == msgid);

	/* the sliding window is really small?!? */
	pexpect(ike->sa.st_v2_msgid_windows.responder.recv ==
		ike->sa.st_v2_msgid_windows.responder.sent);

	if (msgid <= ike->sa.st_v2_msgid_windows.initiator.recv) {
		/*
		 * Processing of the response was completed so drop as
		 * too old.
		 *
		 * XXX: Should be rate_log() but that shows up in the
		 * whack output.  While "correct" it messes with test
		 * output.  The old log line didn't show up because
		 * current-state wasn't set.
		 *
		 * Here's roughly why INITIATOR can be non-NULL:
		 *
		 * - west.#8 needs a rekey, so west.#11 is created and
		 * it sends a CREATE_CHILD_SA with Message ID 3.
		 *
		 * - west.#8 gives up on the re-key so it forces a
		 * delete request (aka record'n'send), sending a
		 * second message with ID 4
		 *
		 * West has two outstanding messages yet its window
		 * size of 1!
		 *
		 * - east receives the rekey with ID 3, creates
		 * east.#11 and and sends it off for further
		 * processing
		 *
		 * - east receives the delete with ID 4, forces a
		 * message ID update and sends an ID 4 response
		 * confirming the delete
		 *
		 * - east.#11 finishes its crypto so east sends back
		 * its response with Message ID 3 for a re-keyed SA it
		 * just deleted?!?!
		 *
		 * East has responded with two out-of-order messages
		 * (if the window size was 2 this would be ok but it
		 * isn't).
		 *
		 * - west receives the ID 4 response, tries to delete
		 * the IKE SA but can't because west.#11 is lurking;
		 * but regardless the ID window is forced 2->4
		 *
		 * - west receives the ID 3 response, which is clearly
		 * to-old so doesn't expect there to be a matching
		 * initiator, arrg
		 */
		if (initiator != NULL) {
			dbg_v2_msgid(ike, initiator, "XXX: expecting initiator==NULL - suspect record'n'send with an out-of-order wrong packet response; discarding packet");
		} else {
			dbg_v2_msgid(ike, initiator, "already processed response %jd (%s); discarding packet",
				     msgid, enum_short_name(&ikev2_exchange_names, md->hdr.isa_xchg));
		}
		return true;
	}

	if (initiator == NULL) {
		/*
		 * While there's an IKE SA matching the IKE SPIs,
		 * there's no corresponding initiator for the message.
		 *
		 * XXX: rate_log() sends to whack which, while making
		 * sense, but churns the test output.
		 */
		log_state(RC_LOG, &ike->sa,
			  "%s message response with Message ID %jd has no matching SA",
			  enum_name(&ikev2_exchange_names, md->hdr.isa_xchg), msgid);
		return true;
	}

	/*
	 * Sanity check the MSGID and initiator against the IKE SA
	 * Message ID window.
	 */

	if (msgid > ike->sa.st_v2_msgid_windows.initiator.sent) {
		/*
		 * There was an initiator waiting for a message that,
		 * according to the IKE SA, has yet to be sent?!?
		 */
		FAIL_V2_MSGID(ike, initiator,
			      "dropping response with Message ID %jd which is from the future - last request sent was %jd",
			      msgid, ike->sa.st_v2_msgid_windows.initiator.sent);
		return true;
	}

	/*
	 * If the state is busy, presumably doing something like
	 * crypto, skip further processing.
	 *
	 * For fragments, things only go busy once all fragments have
	 * been received (and re-transmitted fragments are ignored).
	 * If this changes then a lot more than this code will need to
	 * be moved.
	 *
	 * XXX: Is there a better way to handle this?
	 */
	if (verbose_state_busy(initiator)) {
		return true;
	}

	return false;
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
 *
 * Start by looking for (or creating) the IKE SA responsible for the
 * IKE SPIs group .....
 */

static void ike_process_packet(struct msg_digest **mdp, struct ike_sa *ike);

void ikev2_process_packet(struct msg_digest **mdp)
{
	struct msg_digest *md = *mdp;

	/* Look for an state that matches the various things we know:
	 *
	 * 1) exchange type received?
	 * 2) is it initiator or not?
	 */
	const enum isakmp_xchg_types ix = md->hdr.isa_xchg;

	/*
	 * If the IKE SA initiator sent the message then this end is
	 * looking for the IKE SA responder (and vice versa).
	 */
	enum sa_role expected_local_ike_role = (md->hdr.isa_flags & ISAKMP_FLAGS_v2_IKE_I) ? SA_RESPONDER : SA_INITIATOR;

	/*
	 * Dump what the message says, once a state has been found
	 * this can be checked against what is.
	 */
	LSWDBGP(DBG_BASE, buf) {
		switch (expected_local_ike_role) {
		case SA_RESPONDER:
			jam(buf, "I am the IKE SA Original Responder");
			break;
		case SA_INITIATOR:
			jam(buf, "I am the IKE SA Original Initiator");
			break;
		default:
			bad_case(expected_local_ike_role);
		}
		jam(buf, " receiving an IKEv2 ");
		lswlog_enum_short(buf, &ikev2_exchange_names, ix);
		switch (v2_msg_role(md)) {
		case MESSAGE_RESPONSE:
			jam(buf, " response ");
			break;
		case MESSAGE_REQUEST:
			jam(buf, " request ");
			break;
		default:
			bad_case(v2_msg_role(md));
		}
	}

	/*
	 * Find the IKE SA that is looking after this IKE SPI family.
	 *
	 * If it's a new IKE_SA_INIT request (or previously discarded
	 * request due to cookies) then a new IKE SA is created.
	 */

	struct ike_sa *ike;
	if (ix == ISAKMP_v2_IKE_SA_INIT) {
		/*
		 * The message ID of the initial exchange is always
		 * zero.
		 */
		if (md->hdr.isa_msgid != 0) {
			rate_log(md, "dropping IKE_SA_INIT message containing non-zero message ID");
			return;
		}
		/*
		 * Now try to find the state
		 */
		switch (v2_msg_role(md)) {
		case MESSAGE_REQUEST:
			/* The initiator must send: IKE_I && !MSG_R */
			if (expected_local_ike_role != SA_RESPONDER) {
				rate_log(md, "dropping IKE_SA_INIT request with conflicting IKE initiator flag");
				return;
			}
			/*
			 * 3.1.  The IKE Header: This [SPIr] value
			 * MUST be zero in the first message of an IKE
			 * initial exchange (including repeats of that
			 * message including a cookie).
			 */
			if (!ike_spi_is_zero(&md->hdr.isa_ike_responder_spi)) {
				rate_log(md, "dropping IKE_SA_INIT request with non-zero SPIr");
				return;
			}
			/*
			 * Look for a pre-existing IKE SA responder
			 * state using just the SPIi (SPIr in the
			 * message is zero so can't be used).
			 *
			 * If the lookup succeeds then there are
			 * several possibilities:
			 *
			 * State has Message ID == 0:
			 *
			 * Either it really is a duplicate; or it's a
			 * second (fake?) intiator sending the same
			 * SPIi at exactly the same time as the first
			 * (wow, what are the odds, it must be our
			 * lucky day!).
			 *
			 * Either way, the duplicate code needs to
			 * compare packets and decide if a retransmit
			 * or drop is required.  If the second
			 * initiator is real, then it will timeout and
			 * then retry with a new SPIi.
			 *
			 * State has Message ID > 0:
			 *
			 * Either it is an old duplicate; or, again,
			 * it's a second intiator sending the same
			 * SPIi only slightly later (again, what are
			 * the odds!).
			 *
			 * Several choices: let the duplicate code
			 * drop the packet, which is correct for an
			 * old duplicate message; or ignore the
			 * existing state and create a new one, which
			 * is good for the second initiator but not so
			 * good for an old duplicate.  Given an old
			 * duplicate is far more likely, handle that
			 * cleenly - let the duplicate code drop the
			 * packet.
			 */
			ike = find_v2_ike_sa_by_initiator_spi(&md->hdr.isa_ike_initiator_spi,
							      expected_local_ike_role);
			if (ike != NULL) {
				/*
				 * Set ST to the state that is
				 * currently processing the message,
				 * if it exists.  Pretty easy as it is
				 * the IKE SA or nothing at all.
				 *
				 * let duplicate message code below
				 * decide what to do
				 */
				dbg("received what looks like a duplicate IKE_SA_INIT for #%lu",
				    ike->sa.st_serialno);
				pexpect(md->hdr.isa_msgid == 0); /* per above */
			} else if (drop_new_exchanges()) {
				/* only log for debug to prevent disk filling up */
				dbg("pluto is overloaded with half-open IKE SAs; dropping new exchange");
				return;
			} else {
				/*
				 * Always check for cookies! XXX: why?
				 *
				 * Because the v2N_COOKIE payload is
				 * first, parsing and verifying it
				 * should be relatively quick and
				 * cheap, right?
				 *
				 * No.  The equation uses v2Ni forcing
				 * the entire payload to be parsed.
				 *
				 * The error notification is probably
				 * INVALID_SYNTAX, but could be
				 * v2N_UNSUPPORTED_CRITICAL_PAYLOAD.
				 */
				pexpect(!md->message_payloads.parsed);
				md->message_payloads = ikev2_decode_payloads(NULL, md,
									     &md->message_pbs,
									     md->hdr.isa_np);
				if (md->message_payloads.n != v2N_NOTHING_WRONG) {
					if (require_ddos_cookies()) {
						dbg("DDOS so not responding to invalid packet");
					} else {
						chunk_t data = chunk(md->message_payloads.data,
								     md->message_payloads.data_size);
						send_v2N_response_from_md(md, md->message_payloads.n,
									  &data);
					}
					return;
				}
				if (v2_rejected_initiator_cookie(md, require_ddos_cookies())) {
					dbg("pluto is overloaded and demanding cookies; dropping new exchange");
					return;
				}
				/*
				 * Check if we would drop the packet
				 * based on VID before we create a
				 * state. Move this to ikev2_oppo.c:
				 * drop_oppo_requests()?
				 */
				for (struct payload_digest *p = md->chain[ISAKMP_NEXT_v2V]; p != NULL; p = p->next) {
					if (vid_is_oppo((char *)p->pbs.cur, pbs_left(&p->pbs))) {
						if (pluto_drop_oppo_null) {
							DBG(DBG_OPPO, DBG_log("Dropped IKE request for Opportunistic IPsec by global policy"));
							return;
						}
						DBG(DBG_OPPO | DBG_CONTROLMORE, DBG_log("Processing IKE request for Opportunistic IPsec"));
						break;
					}
				}
				/* else - create a draft state here? */
				lset_t policy = LEMPTY;
				bool send_reject_response = true;
				struct connection *c = find_v2_host_pair_connection(md, &policy,
										    &send_reject_response);
				if (c == NULL) {
					if (send_reject_response) {
						/*
						 * NO_PROPOSAL_CHOSEN
						 * is used when the
						 * list of proposals
						 * is empty, like when
						 * we did not find any
						 * connection to use.
						 *
						 * INVALID_SYNTAX is
						 * for errors that a
						 * configuration
						 * change could not
						 * fix.
						 */
						send_v2N_response_from_md(md, v2N_NO_PROPOSAL_CHOSEN, NULL);
					}
					return;
				}
				/*
				 * We've committed to creating a state
				 * and, presumably, dedicating real
				 * resources to the connection.
				 */
				ike = new_v2_state(STATE_PARENT_R0, SA_RESPONDER,
						   md->hdr.isa_ike_spis.initiator,
						   ike_responder_spi(&md->sender),
						   c, policy, 0, null_fd);
				pexpect(md->hdr.isa_msgid == 0); /* per above */
			}
			/* update lastrecv later on */
			break;
		case MESSAGE_RESPONSE:
			/* The responder must send: !IKE_I && MSG_R. */
			if (expected_local_ike_role != SA_INITIATOR) {
				rate_log(md, "dropping IKE_SA_INIT response with conflicting IKE initiator flag");
				return;
			}
			/*
			 * 2.6.  IKE SA SPIs and Cookies: When the
			 * IKE_SA_INIT exchange does not result in the
			 * creation of an IKE SA due to
			 * INVALID_KE_PAYLOAD, NO_PROPOSAL_CHOSEN, or
			 * COOKIE, the responder's SPI will be zero
			 * also in the response message.  However, if
			 * the responder sends a non-zero responder
			 * SPI, the initiator should not reject the
			 * response for only that reason.
			 *
			 * i.e., can't check response for non-zero
			 * SPIr.
			 */
			/*
			 * Look for a pre-existing IKE SA responder
			 * state using just the SPIi (SPIr in the
			 * message isn't known so can't be used).
			 *
			 * An IKE_SA_INIT error notification response
			 * (INVALID_KE, COOKIE) should contain a zero
			 * SPIr (it must be ignored).
			 *
			 * An IKE_SA_INIT success response will
			 * contain an as yet unknown but non-zero SPIr
			 * so looking for it won't work.
			 */
			ike = find_v2_ike_sa_by_initiator_spi(&md->hdr.isa_ike_initiator_spi,
							      expected_local_ike_role);
			if (ike == NULL) {
				/*
				 * There should be a state matching
				 * the original initiator's cookie.
				 * Since there isn't someone's playing
				 * games.  Drop the packet.
				 */
				rate_log(md, "no matching state for IKE_SA_INIT response; discarding packet");
				return;
			}
			/*
			 * Set ST to the state that is currently
			 * processing the message, if it exists.
			 * Pretty easy as it is the IKE SA or nothing
			 * at all.
			 */
			pexpect(md->hdr.isa_msgid == 0); /* per above */
			break;
		default:
			bad_case(v2_msg_role(md));
		}
	} else if (v2_msg_role(md) == MESSAGE_REQUEST) {
		/*
		 * A (possibly new) request; start with the IKE SA
		 * with matching SPIs.  If it is a new CHILD SA
		 * request then the state machine will will morph ST
		 * into a child state before dispatching.
		 *
		 * XXX: what about a request that's already
		 * in-progress?
		 */
		ike = find_v2_ike_sa(&md->hdr.isa_ike_spis,
				     expected_local_ike_role);
		if (ike == NULL) {
			struct esb_buf ixb;
			rate_log(md, "%s message request has no corresponding IKE SA",
				 enum_show_shortb(&ikev2_exchange_names,
						  ix, &ixb));
			return;
		}
	} else if (v2_msg_role(md) == MESSAGE_RESPONSE) {
		/*
		 * A response to this ends request.  First find the
		 * IKE SA and then, within that group, find the
		 * initiator (it might also be the IKE SA but it might
		 * not).
		 */
		ike = find_v2_ike_sa(&md->hdr.isa_ike_spis,
				     expected_local_ike_role);
		if (ike == NULL) {
			/* technically IKE or CHILD SA */
			rate_log(md, "%s message response has no matching IKE SA",
				 enum_name(&ikev2_exchange_names, ix));
			return;
		}
	} else {
		PASSERT_FAIL("message role %d invalid", v2_msg_role(md));
	}

	/*
	 * There's at least an IKE SA, and possibly ST willing to
	 * process the message.  Backdate billing to when the message
	 * first arrived.
	 */
	passert(ike != NULL);

	/*
	 * Re-check ST's IKE SA's role against the I(Initiator) flag
	 * in the headers.  Since above searches will only find an IKE
	 * SA when the IKE SA's role is correct, this should always
	 * work.
	 */
	if (!pexpect(ike->sa.st_sa_role == expected_local_ike_role)) {
		return;
	}

	/*
	 * Since there's an IKE SA start billing and logging against
	 * it.
	 */
	statetime_t start = statetime_backdate(&ike->sa, &md->md_inception);
	so_serial_t old = push_cur_state(&ike->sa);
	ike_process_packet(mdp, ike);
	pop_cur_state(old);
	statetime_stop(&start, "%s()", __func__);
}

/*
 * The IKE SA for the message has been found (or created).  Continue
 * verification, and identify the state (ST) that the message should
 * be sent to.
 */

static void ike_process_packet(struct msg_digest **mdp, struct ike_sa *ike)
{
	struct msg_digest *md = *mdp;

	/*
	 * Deal with duplicate messages and busy states.
	 */
	struct state *st;
	switch (v2_msg_role(md)) {
	case MESSAGE_REQUEST:
		/*
		 * The IKE SA always processes requests.
		 *
		 * XXX: except further down where the code creates a
		 * new state when CREATE_CHILD_SA and switches to
		 * that.
		 *
		 * The other quirk is with fragments; but the only
		 * case that matters it when the IKE SA accumulating
		 * them.
		 */
		if (md->fake_clone) {
			log_state(RC_LOG, &ike->sa, "IMPAIR: processing a fake (cloned) message");
		}
		/*
		 * Is this duplicate?
		 *
		 * If MD is a fragment then it isn't considered a
		 * duplicate.
		 */
		if (is_duplicate_request(ike, md)) {
			return;
		}
		st = &ike->sa;
		break;
	case MESSAGE_RESPONSE:
		/*
		 * This is the response to an earlier request; use the
		 * IKE SA to find the state that initiated the
		 * exchange (sent that request).
		 *
		 * If the response is a fragment then ST will be
		 * non-NULL; is_duplicate_state() gets to figure out
		 * if the fragments are complete or need to wait
		 * longer.
		 */
		st = find_v2_sa_by_initiator_wip(ike, md->hdr.isa_msgid);
		if (md->fake_clone) {
			log_state(RC_LOG, st != NULL ? st : &ike->sa,
				  "IMPAIR: processing a fake (cloned) message");
		}
		if (is_duplicate_response(ike, st, md)) {
			return;
		}
		pexpect(st != NULL);
		break;
	default:
		bad_case(v2_msg_role(md));
	}

	/*
	 * Now that the state that is to process the message has been
	 * selected, switch logging to it.
	 *
	 * XXX: why the need to constantly pick a single winner and
	 * switch to it?  Because tests expect messages to be logged
	 * against a specific state.  It would be better of that code
	 * specified that state as a parameter.
	 */
	passert(st != NULL);
	/* XXX: debug-logging this is redundant */
	push_cur_state(st);

	/*
	 * If not already done above in the IKE_SA_INIT responder code
	 * path, decode the packet now.
	 */
	if (!md->message_payloads.parsed) {
		dbg("unpacking clear payload");
		pexpect(v2_msg_role(md) == MESSAGE_RESPONSE ||
			md->hdr.isa_xchg != ISAKMP_v2_IKE_SA_INIT);
		md->message_payloads =
			ikev2_decode_payloads(st, md, &md->message_pbs,
					      md->hdr.isa_np);
		if (md->message_payloads.n != v2N_NOTHING_WRONG) {
			/*
			 * Should only respond when the message is an
			 * IKE_SA_INIT request.  But that was handled
			 * above when dealing with cookies so here,
			 * there's zero reason to respond.
			 *
			 * decode calls packet code and that logs
			 * errors on the spot
			 */
			return;
		}
	}

	ikev2_process_state_packet(ike, st, mdp);
}

/*
 * The SA the message is intended for has also been identified.
 * Continue ...
 *
 * XXX: Well except for a CREATE_CHILD_SA request where, after further
 * processing the SA may get created.  Should this message instead be
 * sent to the IKE SA, which can then create a WIP child?
 */

void ikev2_process_state_packet(struct ike_sa *ike, struct state *st,
				struct msg_digest **mdp)
{
	struct msg_digest *md = *mdp;
	passert(ike != NULL);
	passert(st != NULL);

	/*
	 * There is no "struct state" object if-and-only-if we're
	 * responding to a shiny new SA_INIT message.  The start-state
	 * transition will (probably) create the object.
	 *
	 * But what about when pluto, as the initial responder, is
	 * fending of an attack attack by sending back and requiring
	 * cookies - won't the cookie need a "struct state"?
	 * According to the RFC: no.  Instead a small table of
	 * constants can be used to generate cookies on the fly.
	 */
	const struct finite_state *from_state = st->st_state;
	dbg("#%lu in state %s: %s", st->st_serialno,
	    from_state->short_name, from_state->story);

	struct ikev2_payload_errors message_payload_status = { .bad = false };
	struct ikev2_payload_errors encrypted_payload_status = { .bad = false };

	const enum isakmp_xchg_types ix = (*mdp)->hdr.isa_xchg;

	/*
	 * XXX: Unlike find_v2_state_transition(), the below scans
	 * every single state transition and then, in the case of a
	 * CREATE_CHILD_SA, ignores the "from" state.
	 *
	 * XXX: Unlike find_v2_state_transition(), this code detects
	 * and decrypts packets and fragments in the middle of the
	 * lookup.  Being more agressive with decrypting fragments
	 * will likely force that logic to be moved to before this
	 * lookup.
	 */

	const struct state_v2_microcode *svm;
	for (svm = v2_state_microcode_table; svm->state != STATE_IKEv2_ROOF;
	     svm++) {
		/*
		 * For CREATE_CHILD_SA exchanges, the from_state is
		 * ignored.  See further down.
		 */
		if (svm->state != from_state->kind && ix != ISAKMP_v2_CREATE_CHILD_SA)
			continue;
		if (svm->recv_type != ix)
			continue;

		/*
		 * Does the message role match the state transition?
		 */
		if (svm->flags & SMF2_MESSAGE_RESPONSE) {
			if (v2_msg_role(md) != MESSAGE_RESPONSE) {
				continue;
			}
		}
		if (svm->flags & SMF2_MESSAGE_REQUEST) {
			if (v2_msg_role(md) != MESSAGE_REQUEST) {
				continue;
			}
		}

		/*
		 * Check the message payloads are as expected.
		 */
		pexpect(md->message_payloads.parsed);
		struct ikev2_payload_errors message_payload_errors
			= ikev2_verify_payloads(md, &md->message_payloads,
						&svm->message_payloads);
		if (message_payload_errors.bad) {
			/* Save this failure for later logging. */
			message_payload_status = message_payload_errors;
			continue;
		}

		/*
		 * If there is no SK (or SKF) payload then checking is
		 * complete and things have matched.
		 *
		 * (.seen&(P(SK)|P(SKF))!=0 is equivalent.
		 */
		if (!(svm->message_payloads.required & P(SK))) {
			break;
		}

		/*
		 * Since the encrypted payload appears plausible, deal
		 * with fragmentation.
		 */
		if (!md->encrypted_payloads.parsed) {
			/*
			 * Deal with fragmentation.  The function
			 * returns FALSE either when there are more
			 * fragments, the fragment is corrupt, the
			 * fragment is a duplicate, or the fragment
			 * count changed (it also drops all
			 * fragments).  Either way stop processing.
			 *
			 * Only upon _first_ arrival of the last
			 * fragment, does the function return TRUE.
			 * The the processing flow below can then
			 * continue to the SKEYSEED check.
			 *
			 * However, if SKEYSEED (g^{xy}) needed to be
			 * computed then this code will be re-entered
			 * with all fragments present (so "the"
			 * function should not be called).
			 */
			bool have_all_fragments =
				(st->st_v2_rfrags != NULL &&
				 st->st_v2_rfrags->count == st->st_v2_rfrags->total);
			/*
			 * XXX: Because fragments are only checked
			 * all-at-once after they have all arrived, a
			 * single corrupt fragment will cause all
			 * fragments being thrown away, and the entire
			 * process re-start (Is this tested?)
			 *
			 * XXX: This code should instead check
			 * fragments as they arrive.  That means
			 * kicking off the g^{xy} calculation in the
			 * background (if it were in the forground,
			 * the fragments would be dropped).  Later.
			 */
			if (md->message_payloads.present & P(SKF)) {
				if (have_all_fragments) {
					DBG(DBG_CONTROL,
					    DBG_log("already have all fragments, skipping fragment collection"));
				} else if (!ikev2_collect_fragment(md, st)) {
					return;
				}
			}
			/*
			 * For this state transition, does it only
			 * apply when there's no SKEYSEED?  If so, and
			 * SKEYSEED is missing, then things match; else
			 * things can't match.
			 */
			if (svm->flags & SMF2_NO_SKEYSEED) {
				if (ike->sa.hidden_variables.st_skeyid_calculated) {
					continue;
				} else {
					break;
				}
			}
			/*
			 * XXX: Shouldn't reach this point without
			 * SKEYSEED so bail if somehow that hasn't
			 * happened.  No point in even calling
			 * ikev2_decrypt_msg() (it will also fail).
			 *
			 * Suspect it would be cleaner if the state
			 * machine included an explicit SMF2_SKEYSEED
			 * flag and all states requiring integrity
			 * were marked with that. Currently P(SK) and
			 * P(SKF) imply this.
			 */
			if (!pexpect(ike->sa.hidden_variables.st_skeyid_calculated)) {
				return;
			}
			/*
			 * Decrypt the packet, checking it for
			 * integrity.  Anything lacking integrity is
			 * dropped.
			 */
			if (!ikev2_decrypt_msg(st, md)) {
				log_state(RC_LOG, st, "encrypted payload seems to be corrupt; dropping packet");
				return;
			}
			/*
			 * The message is protected - the integrity
			 * check passed - so it was definitly sent by
			 * the other end of the secured IKE SA.
			 *
			 * However, for an AUTH packet, the other end
			 * hasn't yet been authenticated (and an
			 * INFORMATIONAL exchange immediately
			 * following AUTH be due to failed
			 * authentication).
			 *
			 * If there's something wrong with the message
			 * contents, then the IKE SA gets abandoned,
			 * but a new new one may be initiated.
			 *
			 * See "2.21.2.  Error Handling in IKE_AUTH"
			 * and "2.21.3.  Error Handling after IKE SA
			 * is Authenticated".
			 *
			 * For UNSUPPORTED_CRITICAL_PAYLOAD, while the
			 * RFC clearly states that for the initial
			 * exchanges and an INFORMATIONAL exchange
			 * immediately following, the notification
			 * causes a delete, it says nothing for
			 * exchanges that follow.
			 *
			 * For moment treat it the same.  Given the
			 * PAYLOAD ID that should identify the problem
			 * isn't being returned this is the least of
			 * our problems.
			 */
			struct payload_digest *sk = md->chain[ISAKMP_NEXT_v2SK];
			md->encrypted_payloads = ikev2_decode_payloads(st, md, &sk->pbs,
								       sk->payload.generic.isag_np);
			if (md->encrypted_payloads.n != v2N_NOTHING_WRONG) {
				switch (v2_msg_role(md)) {
				case MESSAGE_REQUEST:
				{
					/*
					 * Send back a protected error
					 * response.  Need to first
					 * put the IKE SA into
					 * responder mode.
					 */
					v2_msgid_start_responder(ike, &ike->sa, md);
					chunk_t data = chunk(md->encrypted_payloads.data,
							     md->encrypted_payloads.data_size);
					send_v2N_response_from_state(ike, *mdp,
								     md->encrypted_payloads.n,
								     &data);
					break;
				}
				case MESSAGE_RESPONSE:
					/*
					 * Can't respond so kill the
					 * IKE SA.  The secured
					 * message contained crap so
					 * there's little that can be
					 * done.
					 */
					break;
				default:
					bad_case(v2_msg_role(md));
				}
				complete_v2_state_transition(st, mdp, STF_FATAL);
				return;
			}
		} /* else { go ahead } */
		struct ikev2_payload_errors encrypted_payload_errors
			= ikev2_verify_payloads(md, &md->encrypted_payloads,
						&svm->encrypted_payloads);
		if (encrypted_payload_errors.bad) {
			/* Save this failure for later logging. */
			encrypted_payload_status = encrypted_payload_errors;
			continue;
		}

		if (svm->state != from_state->kind && ix == ISAKMP_v2_CREATE_CHILD_SA) {
			/*
			 * The IKE SA is receiving a CREATE_CHILD_SA
			 * request.  Unlike STATE_PARENT_R0 (and the
			 * initial responder) the R0 state isn't
			 * obvious - rekey IKE SA, rekey CHILD SA, and
			 * create CHILD SA are all slightly different.
			 *
			 * The code deals with this by ignoring the
			 * from_state, and then later, forcing MD's
			 * from state to values in the table.
			 */
			dbg("state #%lu forced to match CREATE_CHILD_SA from %s->%s by ignoring from state",
			    st->st_serialno,
			    finite_states[svm->state]->name,
			    finite_states[svm->next_state]->name);
		}

		/* must be the right state machine entry */
		break;
	}

	DBG(DBG_CONTROL, DBG_log("selected state microcode %s", svm->story));

	/* no useful state microcode entry? */
	if (svm->state == STATE_IKEv2_ROOF) {
		/* count all the error notifications */
		for (struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N];
		     ntfy != NULL; ntfy = ntfy->next) {
			pstat(ikev2_recv_notifies_e, ntfy->payload.v2n.isan_type);
		}
		/*
		 * All branches: log error, [complete transition]
		 * (why), return so first error wins.
		 */
		if (message_payload_status.bad) {
			/*
			 * A very messed up message.  Should only
			 * consider responding when IKE_SA_INIT
			 * request?  Code above should have rejected
			 * any message with invalid integrity.
			 *
			 * XXX: how can one complete a state
			 * transition on something that was never
			 * started?  because the state may need
			 * deleting.
			 */
			log_v2_payload_errors(st, md, &message_payload_status);
			if (md->hdr.isa_xchg == ISAKMP_v2_IKE_SA_INIT &&
			    md->hdr.isa_msgid == 0 &&
			    v2_msg_role(md) == MESSAGE_REQUEST) {
				pexpect(st->st_v2_msgid_wip.responder == -1);
				send_v2N_response_from_md(md, v2N_INVALID_SYNTAX, NULL);
				/* XXX: calls delete_state() */
				complete_v2_state_transition(st, mdp, STF_FATAL);
			}
			return;
		}
		if (encrypted_payload_status.bad) {
			/*
			 * Payload decrypted and integrity was ok but
			 * contents weren't valid.
			 *
			 * XXX: According to "2.21.2.  Error Handling
			 * in IKE_AUTH" and "2.21.3.  Error Handling
			 * after IKE SA is Authenticated" this should
			 * be fatal, killing the IKE SA.  Oops.
			 *
			 * XXX: how can one complete a state
			 * transition on something that was never
			 * started?  Since this is fatal, the state
			 * needs to be deleted.
			 *
			 * XXX: an alternative would be to treat this
			 * like some new but as-of-yet not supported
			 * message combination so just ignore it (but
			 * update Message IDs).
			 */
			log_v2_payload_errors(st, md, &encrypted_payload_status);
			if (v2_msg_role(md) == MESSAGE_REQUEST) {
				pexpect(ike->sa.st_v2_msgid_wip.responder == -1);
				v2_msgid_start_responder(ike, &ike->sa, md);
				send_v2N_response_from_state(ike, md, v2N_INVALID_SYNTAX, NULL);
			}
			/* XXX: calls delete_state() */
			complete_v2_state_transition(st, mdp, STF_FATAL);
			return;
		}
		/*
		 * Presumably things are pretty messed up.  While
		 * there might be a state there probably isn't an
		 * established IKE SA (so don't even consider trying
		 * to send an encrypted response), for instance:
		 *
		 * - instead of an IKE_AUTH request, the initiator
		 * sends something totally unexpected (such as an
		 * informational) and things end up here
		 *
		 * - when an IKE_AUTH request's IKE SA succeeeds but
		 * CHILD SA fails (and pluto screws up the IKE SA by
		 * updating its state but not its Message ID and not
		 * responding), the re-transmitted IKE_AUTH ends up
		 * here
		 *
		 * If a request, should it send an un-encrypted
		 * v2N_INVALID_SYNTAX?
		 */
		libreswan_log("no useful state microcode entry found for incoming packet");
		/* "dropping message with no matching microcode" */
		return;
	}

	if (ix == ISAKMP_v2_CREATE_CHILD_SA) {
		/*
		 * XXX: This code was embedded in the end of the FSM
		 * search loop.  Since it was always executed when the
		 * state matches, move it out of the loop.  Suspect
		 * this, and the code below, really belong in the
		 * state transition function proper.
		 */
		/* going to switch to child st. before that update parent */
		if (!LHAS(ike->sa.hidden_variables.st_nat_traversal, NATED_HOST))
			update_ike_endpoints(ike, md);

		/* bit further processing of create CREATE_CHILD_SA exchange */

		/*
		 * let's get a child state either new or existing to
		 * proceed
		 */
		struct child_sa *child;
		if (v2_msg_role(md) == MESSAGE_RESPONSE) {
			child = pexpect_child_sa(st);
		} else {
			pexpect(IS_IKE_SA(st));
			child = process_v2_child_ix(ike, svm);
		}

		/*
		 * Switch to child state (possibly from the same child
		 * state, see above)
		 */
		dbg("forcing ST #%lu to CHILD #%lu.#%lu in FSM processor",
		    st->st_serialno, ike->sa.st_serialno, child->sa.st_serialno);
		st = &child->sa;
	}

	v2_dispatch(ike, st, mdp, svm);
}

static void v2_dispatch(struct ike_sa *ike, struct state *st,
			struct msg_digest **mdp,
			const struct state_v2_microcode *svm)
{
	struct msg_digest *md = *mdp;
	md->st = st;
	md->svm = svm;

	/*
	 * For the responder, update the work-in-progress Message ID
	 * window (since work has commenced).
	 *
	 * Exclude the SKEYSEED calculation - the message has yet to
	 * be decrypted so true work on the message is yet to comence.
	 */
	if (v2_msg_role(md) == MESSAGE_REQUEST &&
	    !(svm->flags & SMF2_NO_SKEYSEED)) {
		v2_msgid_start_responder(ike, st, md);
	}

	DBG(DBG_PARSING, {
		    if (pbs_left(&md->message_pbs) != 0)
			    DBG_log("removing %d bytes of padding",
				    (int) pbs_left(&md->message_pbs));
	    });

	md->message_pbs.roof = md->message_pbs.cur;	/* trim padding (not actually legit) */

	DBG(DBG_CONTROL,
	    DBG_log("calling processor %s", svm->story));

	statetime_t start = statetime_start(st);
	/*
	 * XXX: for now pass in the possibly NULL child; suspect a
	 * better model is to drop the child and instead have the IKE
	 * SA run a nested state machine for the child.
	 *
	 * For instance, when a CREATE_CHILD_SA request arrives, pass
	 * that to the IKE SA and then let it do all the create child
	 * magic.
	 */
	struct child_sa *child = IS_CHILD_SA(st) ? pexpect_child_sa(st) : NULL;
	stf_status e = svm->processor(ike, child, md);
	statetime_stop(&start, "processing: %s in %s()", svm->story, __func__);

	/*
	 * Processor may screw around with md->st, for instance
	 * switching it to the CHILD SA, or a newly created state.
	 * Hence use that version for now.
	 */

	/* replace (*mdp)->st with st ... */
	complete_v2_state_transition((*mdp)->st, mdp, e);
	/* our caller with release_any_md(mdp) */
}

static bool decode_peer_id_counted(struct ike_sa *ike,
				   struct msg_digest *md, int depth)
{
	if (depth > 10) {
		/* should not happen, but it would be nice to survive */
		libreswan_log("decoding IKEv2 peer ID failed due to confusion");
		return FALSE;
	}
	bool initiator = (md->hdr.isa_flags & ISAKMP_FLAGS_v2_MSG_R) != 0;
	bool must_switch = FALSE;

	struct payload_digest *const id_him = initiator ?
		md->chain[ISAKMP_NEXT_v2IDr] : md->chain[ISAKMP_NEXT_v2IDi];

	if (id_him == NULL) {
		libreswan_log("IKEv2 mode no peer ID (hisID)");
		return FALSE;
	}

	enum ike_id_type hik = id_him->payload.v2id.isai_type;	/* His Id Kind */

	struct id peer_id;

	if (!extract_peer_id(hik, &peer_id, &id_him->pbs)) {
		libreswan_log("IKEv2 mode peer ID extraction failed");
		return FALSE;
	}

	/* You Tarzan, me Jane? */
	struct id tarzan_id;	/* may be unset */
	struct id *tip = NULL;	/* tarzan ID pointer (or NULL) */

	{
		const struct payload_digest *const tarzan_pld = md->chain[ISAKMP_NEXT_v2IDr];

		if (!initiator && tarzan_pld != NULL) {
			/*
			 * ??? problem with diagnostics: what we're calling "peer ID"
			 * is really our "peer's peer ID", in other words us!
			 */
			DBGF(DBG_CONTROL, "received IDr payload - extracting our alleged ID");
			if (!extract_peer_id(tarzan_pld->payload.v2id.isai_type,
					&tarzan_id, &tarzan_pld->pbs))
			{
				libreswan_log("Peer IDr payload extraction failed");
				return FALSE;
			}
			tip = &tarzan_id;
		}
	}

	/* start considering connection */

	struct connection *c = ike->sa.st_connection;

	/*
	 * If there are certs, try re-running the id check.
	 */
	if (!ike->sa.st_peer_alt_id &&
		ike->sa.st_remote_certs.verified != NULL) {
		if (match_certs_id(ike->sa.st_remote_certs.verified,
				   &c->spd.that.id /*ID_FROMCERT => updated*/)) {
			dbg("X509: CERT and ID matches current connection");
			ike->sa.st_peer_alt_id = true;
		} else {
			libreswan_log("Peer CERT payload SubjectAltName does not match peer ID for this connection");
			if (!LIN(POLICY_ALLOW_NO_SAN, c->policy)) {
				libreswan_log("X509: connection failed due to unmatched IKE ID in certificate SAN");
				if (initiator)
					return FALSE; /* cannot switch but switching required */
				must_switch = TRUE;
			} else {
				libreswan_log("X509: connection allows unmatched IKE ID and certificate SAN");
			}
		}
	}

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
		if (!ike->sa.st_peer_alt_id &&
		    !same_id(&c->spd.that.id, &peer_id) &&
		    c->spd.that.id.kind != ID_FROMCERT) {
			id_buf expect, found;

			loglog(RC_LOG_SERIOUS,
				"we require IKEv2 peer to have ID '%s', but peer declares '%s'",
				str_id(&c->spd.that.id, &expect),
				str_id(&peer_id, &found));
			return FALSE;
		} else if (c->spd.that.id.kind == ID_FROMCERT) {
			if (peer_id.kind != ID_DER_ASN1_DN) {
				loglog(RC_LOG_SERIOUS, "peer ID is not a certificate type");
				return FALSE;
			}
			duplicate_id(&c->spd.that.id, &peer_id);
		}
	} else {
		/* why should refine_host_connection() update this? We pulled it from their packet */
		bool fromcert = peer_id.kind == ID_DER_ASN1_DN;
		uint16_t auth = md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2auth.isaa_type;
		enum keyword_authby authby = AUTH_NEVER;

		switch (auth) {
		case IKEv2_AUTH_RSA:
			authby = AUTH_RSASIG;
			break;
		case IKEv2_AUTH_PSK:
			authby = AUTH_PSK;
			break;
		case IKEv2_AUTH_NULL:
			authby = AUTH_NULL;
			break;
		case IKEv2_AUTH_DIGSIG:
			if (c->policy & POLICY_RSASIG) {
				authby = AUTH_RSASIG;
				break;
			}
			if (c->policy & POLICY_ECDSA) {
				authby = AUTH_ECDSA;
				break;
			}
			/* FALL THROUGH */
		case IKEv2_AUTH_NONE:
		default:
			DBG(DBG_CONTROL, DBG_log("ikev2 skipping refine_host_connection due to unknown policy"));
		}

		if (authby != AUTH_NEVER) {
			struct connection *r = NULL;
			id_buf peer_str;

			if (authby != AUTH_NULL) {
				r = refine_host_connection(
					md->st, &peer_id, tip, FALSE /*initiator*/,
					LEMPTY /* auth_policy */, authby, &fromcert);
			}

			if (r == NULL) {
				/* no "improvement" on c found */
				if (DBGP(DBG_BASE)) {
					id_buf peer_str;
					DBG_log("no suitable connection for peer '%s'",
						str_id(&peer_id, &peer_str));
				}
				/* can we continue with what we had? */
				if (must_switch) {
					loglog(RC_LOG_SERIOUS, "Peer ID '%s' is not specified on the certificate SubjectAltName (SAN) and no better connection found",
					      str_id(&peer_id, &peer_str));
					return FALSE;
				}
				/* if X.509, we should have valid peer/san */
				if (ike->sa.st_remote_certs.verified != NULL && ike->sa.st_peer_alt_id == FALSE) {
					loglog(RC_LOG_SERIOUS, "Peer ID '%s' is not specified on the certificate SubjectAltName (SAN) and no better connection found",
					      str_id(&peer_id, &peer_str));
					return FALSE;
				}
				if (!ike->sa.st_peer_alt_id &&
				    !same_id(&c->spd.that.id, &peer_id) &&
				    c->spd.that.id.kind != ID_FROMCERT)
				{
					if (LIN(POLICY_AUTH_NULL, c->policy) &&
					    tip != NULL && tip->kind == ID_NULL) {
						libreswan_log("Peer ID '%s' expects us to have ID_NULL and connection allows AUTH_NULL - allowing",
							      str_id(&peer_id, &peer_str));
						ike->sa.st_peer_wants_null = TRUE;
					} else {
						id_buf peer_str;
						loglog(RC_LOG_SERIOUS, "Peer ID '%s' mismatched on first found connection and no better connection found",
							      str_id(&peer_id, &peer_str));
						return FALSE;
					}
				} else {
					DBGF(DBG_CONTROL, "Peer ID matches and no better connection found - continuing with existing connection");
				}
			} else if (r != c) {
				/* r is an improvement on c -- replace */

				char b1[CONN_INST_BUF];
				char b2[CONN_INST_BUF];

				libreswan_log("switched from \"%s\"%s to \"%s\"%s",
					c->name,
					fmt_conn_instance(c, b1),
					r->name,
					fmt_conn_instance(r, b2));
				if (r->kind == CK_TEMPLATE || r->kind == CK_GROUP) {
					/* instantiate it, filling in peer's ID */
					r = rw_instantiate(r, &c->spd.that.host_addr,
						   NULL, &peer_id);
				}

				update_state_connection(md->st, r);
				/* redo from scratch so we read and check CERT payload */
				DBGF(DBG_X509, "retrying ikev2_decode_peer_id_and_certs() with new conn");
				return decode_peer_id_counted(ike, md, depth + 1);
			} else if (must_switch) {
					id_buf peer_str;
					loglog(RC_LOG_SERIOUS, "Peer ID '%s' mismatched on first found connection and no better connection found",
							      str_id(&peer_id, &peer_str));
					return FALSE;
			}

			if (c->spd.that.has_id_wildcards) {
				duplicate_id(&c->spd.that.id, &peer_id);
				c->spd.that.has_id_wildcards = FALSE;
			} else if (fromcert) {
				DBGF(DBG_X509, "copying ID for fromcert");
				duplicate_id(&c->spd.that.id, &peer_id);
			}
		}
	}

	if (DBGP(DBG_BASE)) {
		dn_buf b;
		DBG_log("offered CA: '%s'",
			str_dn_or_null(c->spd.this.ca, "%none", &b));
	}

	if (!(c->policy & POLICY_OPPORTUNISTIC)) {
		id_buf idbuf;
		libreswan_log("IKEv2 mode peer ID is %s: '%s'",
			      enum_show(&ikev2_idtype_names, hik),
			      str_id(&peer_id, &idbuf));
	} else if (DBGP(DBG_BASE)) {
		id_buf idbuf;
		DBG_log("IKEv2 mode peer ID is %s: '%s'",
			enum_show(&ikev2_idtype_names, hik),
			str_id(&peer_id, &idbuf));
	}

	return TRUE;
}

bool ikev2_decode_peer_id(struct msg_digest *md)
{
	return decode_peer_id_counted(ike_sa(md->st), md, 0);
}

/*
 * This logs to the main log (including peerlog!) the authentication
 * and encryption keys for an IKEv2 SA.  This is done in a format that
 * is compatible with tcpdump 4.0's -E option.
 *
 * The peerlog will be perfect.  The syslog will require that a cut
 * command is used to remove the initial text.
 * DANGER: this intentionally leaks cryptographic secrets.
 */
void ikev2_log_parentSA(const struct state *st)
{
	DBG(DBG_PRIVATE,
	{
		if (st->st_oakley.ta_integ == NULL ||
		    st->st_oakley.ta_encrypt == NULL)
			return;

		/* format initiator SPI */
		char tispi[3 + 2*IKE_SA_SPI_SIZE];
		(void)datatot(st->st_ike_spis.initiator.bytes, sizeof(st->st_ike_spis.initiator.bytes),
			'x',
			tispi, sizeof(tispi));

		/* format responder SPI */
		char trspi[3 + 2*IKE_SA_SPI_SIZE];
		(void)datatot(st->st_ike_spis.responder.bytes, sizeof(st->st_ike_spis.responder.bytes),
			'x',
			trspi, sizeof(trspi));

		const char *authalgo = st->st_oakley.ta_integ->integ_tcpdump_name;
		const char *encalgo = st->st_oakley.ta_encrypt->encrypt_tcpdump_name;

		/*
		 * Text of encryption key length (suffix for encalgo).
		 * No more than 3 digits, but compiler fears it might be 5.
		 */
		char tekl[6] = "";
		if (st->st_oakley.enckeylen != 0)
			snprintf(tekl, sizeof(tekl), "%u",
				 st->st_oakley.enckeylen);

		/* v2 IKE authentication key for initiator (256 bit bound) */
		chunk_t ai = chunk_from_symkey("ai", st->st_skey_ai_nss);
		char tai[3 + 2 * BYTES_FOR_BITS(256)] = "";
		(void)datatot(ai.ptr, ai.len, 'x', tai, sizeof(tai));
		free_chunk_content(&ai);

		/* v2 IKE encryption key for initiator (256 bit bound) */
		chunk_t ei = chunk_from_symkey("ei", st->st_skey_ei_nss);
		char tei[3 + 2 * BYTES_FOR_BITS(256)] = "";
		(void)datatot(ei.ptr, ei.len, 'x', tei, sizeof(tei));
		free_chunk_content(&ei);

		DBG_log("ikev2 I %s %s %s:%s %s%s:%s",
			tispi, trspi,
			authalgo, tai,
			encalgo, tekl, tei);

		/* v2 IKE authentication key for responder (256 bit bound) */
		chunk_t ar = chunk_from_symkey("ar", st->st_skey_ar_nss);
		char tar[3 + 2 * BYTES_FOR_BITS(256)] = "";
		(void)datatot(ar.ptr, ar.len, 'x', tar, sizeof(tar));
		free_chunk_content(&ar);

		/* v2 IKE encryption key for responder (256 bit bound) */
		chunk_t er = chunk_from_symkey("er", st->st_skey_er_nss);
		char ter[3 + 2 * BYTES_FOR_BITS(256)] = "";
		(void)datatot(er.ptr, er.len, 'x', ter, sizeof(ter));
		free_chunk_content(&er);

		DBG_log("ikev2 R %s %s %s:%s %s%s:%s",
			tispi, trspi,
			authalgo, tar,
			encalgo, tekl, ter);
	}
	);
}

void log_ipsec_sa_established(const char *m, const struct state *st)
{
	/* log Child SA Traffic Selector details for admin's pleasure */
	const struct traffic_selector *a = &st->st_ts_this;
	const struct traffic_selector *b = &st->st_ts_that;
	range_buf ba, bb;
	libreswan_log("%s [%s:%d-%d %d] -> [%s:%d-%d %d]",
			m,
		      str_range(&a->net, &ba),
			a->startport,
			a->endport,
			a->ipprotoid,
		      str_range(&b->net, &bb),
			b->startport,
			b->endport,
			b->ipprotoid);
}

static void ikev2_child_emancipate(struct ike_sa *from, struct child_sa *to,
				   const struct state_v2_microcode *transition)
{
	/* initialze the the new IKE SA. reset and message ID */
	to->sa.st_clonedfrom = SOS_NOBODY;
	v2_msgid_init_ike(pexpect_ike_sa(&to->sa));

	/* Switch to the new IKE SPIs */
	to->sa.st_ike_spis = to->sa.st_ike_rekey_spis;
	rehash_state_cookies_in_db(&to->sa);

	/* TO has correct IKE_SPI so can migrate */
	v2_migrate_children(from, to);

	/* child is now a parent */
	ikev2_ike_sa_established(pexpect_ike_sa(&to->sa),
				 transition, transition->next_state);
}

static void success_v2_state_transition(struct state *st, struct msg_digest *md,
					const struct state_v2_microcode *transition)
{
	/*
	 * XXX: the transition's from state can lie - it may be
	 * different to the ST's state!
	 */
	enum state_kind from_state = transition->state;
	struct connection *c = st->st_connection;
	enum rc_type w;
	struct ike_sa *ike = ike_sa(st);

	if (from_state != transition->next_state) {
		dbg("transitioning from state %s to state %s",
		    finite_states[from_state]->name,
		    finite_states[transition->next_state]->name);
	}

	/*
	 * XXX: When should the Message IDs be updated when a response
	 * is 'valid' (as in integrity checked out ok so wasn't
	 * forged) but the contents aren't as desired?  For instance a
	 * rekey response of INVALID_KE.  The old code updates early
	 * (but redundantly when success), the new code updates late
	 * (so will get this case wrong).
	 */
	if (from_state == STATE_V2_REKEY_IKE_R ||
	    from_state == STATE_V2_REKEY_IKE_I) {
		/*
		 * XXX: need to update ST's IKE SA's msgids before ST
		 * itself becomes its own IKE SA (making the operation
		 * futile).
		 */
		dbg("Message ID: updating counters for #%lu before emancipating",
		    st->st_serialno);
		v2_msgid_update_recv(ike_sa(st), st, md);
		v2_msgid_update_sent(ike_sa(st), st, md, transition->send);
		/*
		 * XXX: should this be merged with the code sending
		 * with transitions message?  And do this before ST
		 * turns into its own IKE.
		 */
		v2_msgid_schedule_next_initiator(ike);
		ikev2_child_emancipate(ike, pexpect_child_sa(st),
				       transition);
	} else  {
		/*
		 * XXX: need to change state before updating Message
		 * IDs as that is what the update function expects
		 * (this is not a good reason).
		 */
		change_state(st, transition->next_state);
		dbg("Message ID: updating counters for #%lu after switching state ...",
		    st->st_serialno);
		v2_msgid_update_recv(ike_sa(st), st, md);
		v2_msgid_update_sent(ike_sa(st), st, md, transition->send);
		/*
		 * XXX: should this be merged with the code sending
		 * this transitions message?
		 */
		v2_msgid_schedule_next_initiator(ike);
	}

	w = RC_NEW_V2_STATE + st->st_state->kind;

	/*
	 * tell whack and log of progress; successful state
	 * transitions always advance (even when they go round to the
	 * same state).
	 */
	passert(st->st_state->kind >= STATE_IKEv2_FLOOR);
	passert(st->st_state->kind <  STATE_IKEv2_ROOF);

	if (transition->flags & SMF2_ESTABLISHED) {
		/*
		 * Count successful transition into an established state.
		 *
		 * Because IKE SAs and CHILD SAs share some state transitions
		 * this only works for CHILD SAs.  IKE SAs are accounted for
		 * separately.
		 */
		pstat_sa_established(st);
	}

	void (*log_details)(struct lswlog *buf, struct state *st);
	if (IS_CHILD_SA_ESTABLISHED(st)) {
		log_ipsec_sa_established("negotiated connection", st);
		log_details = lswlog_child_sa_established;
		/* log our success and trigger detach */
		w = RC_SUCCESS;
	} else if (st->st_state->kind == STATE_PARENT_I2 || st->st_state->kind == STATE_PARENT_R1) {
		log_details = lswlog_ike_sa_established;
	} else {
		log_details = NULL;
	}

	/*
	 * Tell whack and logs our progress - unless OE or a state
	 * transition we're not telling anyone about, then be quiet.
	 */
	if ((transition->flags & SMF2_SUPPRESS_SUCCESS_LOG) ||
	    (c != NULL && (c->policy & POLICY_OPPORTUNISTIC))) {
		LSWDBGP(DBG_BASE, buf) {
			lswlogf(buf, "%s: %s", st->st_state->name,
				st->st_state->story);
			/* document SA details for admin's pleasure */
			if (log_details != NULL) {
				log_details(buf, st);
			}
		}
	} else {
		LSWLOG_RC(w, buf) {
			lswlogf(buf, "%s: %s", st->st_state->name,
				st->st_state->story);
			/* document SA details for admin's pleasure */
			if (log_details != NULL) {
				log_details(buf, st);
			}
		}
	}

	/* if requested, send the new reply packet */
	if (transition->send != NO_MESSAGE) {
		/*
		 * Adjust NAT but not for initial state (initial
		 * outbound message?).
		 *
		 * ??? why should STATE_PARENT_I1 be excluded?  XXX:
		 * and why, for that state, does ikev2_natd_lookup()
		 * call it.
		 *
		 * XXX: STATE_PARENT_I1 is special in that, per the
		 * RFC, it must switch the local and remote ports to
		 * :4500.
		 *
		 * XXX: The "initial outbound message" check was first
		 * added by commit "pluto: various fixups associated
		 * with RFC 7383 code".  At the time a fake MD
		 * (created when an initiator initiates) had the magic
		 * state STATE_IKEv2_BASE and so it checked for that.
		 * What isn't clear is if the check was intended to
		 * block just an IKE SA initiating, or also block a
		 * CHILD SA initiate.
		 *
		 * XXX: STATE_PARENT_R1 (AUTH responder), in addition
		 * to the below, will also call nat*() explicitly.
		 * Perhaps multiple calls are benign?
		 *
		 * XXX: This is getting silly:
		 *
		 * - check for MD != NULL - while initial initiators
		 * don't have an incomming message it gets twarted by
		 * fake_md()
		 *
		 * - delete the call - IKE state transition code is
		 * already somewhat doing this and why would nat need
		 * to be updated during a child exchange
		 *
		 * - or what about an STF flag on the state?
		 *
		 * XXX: it would appear this is only for secure
		 * responder states.
		 *
		 * XXX: It's a hack trying to implement the below:
		 *
		 * - the correct check for this end not being behind a
		 *   NAT is !NATED_HOST && NATED_PEER
		 *
		 * - the state checks wrongly assume the responder
		 *   isn't behind a NAT; and will completely fail if,
		 *   after a REKEY, the initiator and responder roles
		 *   switch
		 *
		 * - ikev2_parent_inI2outR2_continue_tail()'s call can
		 *   be merged; suspect the thing to do is move the
		 *   code to after the message is decrypted?
		 *
		 * - is MOBIKE mutually excluded through policy flag
		 *   checks?
		 *
		 * 2.23.  NAT Traversal
		 *
		 * There are cases where a NAT box decides to remove
		 * mappings that are still alive (for example, the
		 * keepalive interval is too long, or the NAT box is
		 * rebooted).  This will be apparent to a host if it
		 * receives a packet whose integrity protection
		 * validates, but has a different port, address, or
		 * both from the one that was associated with the SA
		 * in the validated packet.  When such a validated
		 * packet is found, a host that does not support other
		 * methods of recovery such as IKEv2 Mobility and
		 * Multihoming (MOBIKE) [MOBIKE], and that is not
		 * behind a NAT, SHOULD send all packets (including
		 * retransmission packets) to the IP address and port
		 * in the validated packet, and SHOULD store this as
		 * the new address and port combination for the SA
		 * (that is, they SHOULD dynamically update the
		 * address).  A host behind a NAT SHOULD NOT do this
		 * type of dynamic address update if a validated
		 * packet has different port and/or address values
		 * because it opens a possible DoS attack (such as
		 * allowing an attacker to break the connection with a
		 * single packet).  Also, dynamic address update
		 * should only be done in response to a new packet;
		 * otherwise, an attacker can revert the addresses
		 * with old replayed packets.  Because of this,
		 * dynamic updates can only be done safely if replay
		 * protection is enabled.  When IKEv2 is used with
		 * MOBIKE, dynamically updating the addresses
		 * described above interferes with MOBIKE's way of
		 * recovering from the same situation.  See Section
		 * 3.8 of [MOBIKE] for more information.
		 */
		if (nat_traversal_enabled &&
		    from_state != STATE_PARENT_I0 &&
		    from_state != STATE_V2_CREATE_I0 &&
		    from_state != STATE_V2_REKEY_CHILD_I0 &&
		    from_state != STATE_V2_REKEY_IKE_I0 &&
		    from_state != STATE_PARENT_R0 &&
		    from_state != STATE_PARENT_I1) {
			/* from_state = STATE_PARENT_R1 */
			/* from_state = STATE_CREATE_R */
			/* from_state = STATE_REKEY_IKE_R */
			/* from_state = ??? */
			/* adjust our destination port if necessary */
			nat_traversal_change_port_lookup(md, &ike->sa);
		}

		endpoint_buf b;
		endpoint_buf b2;
		pexpect_st_local_endpoint(st);
		dbg("sending V2 %s packet to %s (from %s)",
		    v2_msg_role(md) == MESSAGE_REQUEST ? "new request" : "reply",
		    str_endpoint(&st->st_remote_endpoint, &b),
		    str_endpoint(&st->st_interface->local_endpoint, &b2));

		send_recorded_v2_ike_msg(&ike->sa, finite_states[from_state]->name);
	}

	if (w == RC_SUCCESS) {
		release_any_whack(st, HERE, "IKEv2 transitions finished");

		/* XXX should call unpend again on parent SA */
		if (IS_CHILD_SA(st)) {
			/* with failed child sa, we end up here with an orphan?? */
			struct ike_sa *ike = ike_sa(st);
			dbg("unpending #%lu's IKE SA #%lu", st->st_serialno,
			    ike->sa.st_serialno);
			/* a better call unpend in ikev2_ike_sa_established? */
			unpend(ike, c);

			/*
			 * If this was an OE connection, check for removing a potential
			 * matching bare shunt entry - bare shunts are always a %pass or
			 * %hold SPI but are found regardless of whether we passed in
			 * SPI_PASS or SPI_HOLD ?
			 */
			if (LIN(POLICY_OPPORTUNISTIC, c->policy)) {
				struct spd_route *sr = &c->spd;
				struct bare_shunt **bs = bare_shunt_ptr(&sr->this.client, &sr->that.client, sr->this.protocol);

				if (bs != NULL) {
					dbg("deleting old bare shunt");
					if (!delete_bare_shunt(&c->spd.this.host_addr,
						&c->spd.that.host_addr,
						c->spd.this.protocol,
						SPI_PASS /* else its not bare */,
						/* this text is used to signal the low level :/ */
						"IGNORE_ON_XFRM: installed IPsec SA replaced old bare shunt")) {
							loglog(RC_LOG_SERIOUS, "Failed to delete old bare shunt");
					}
				}
			}
			release_any_whack(&ike->sa, HERE, "IKEv2 transitions finished so releaseing IKE SA");
		}
	}

	/* Schedule for whatever timeout is specified */
	{
		enum event_type kind = transition->timeout_event;
		struct connection *c = st->st_connection;

		switch (kind) {
		case EVENT_RETRANSMIT:
			delete_event(st);
			dbg("success_v2_state_transition scheduling EVENT_RETRANSMIT of c->r_interval=%jdms",
			    deltamillisecs(c->r_interval));
			start_retransmits(st);
			break;

		case EVENT_SA_REPLACE: /* IKE or Child SA replacement event */
			v2_schedule_replace_event(st);
			break;

		case EVENT_SO_DISCARD:
			delete_event(st);
			event_schedule_s(kind, MAXIMUM_RESPONDER_WAIT, st);
			break;

		case EVENT_NULL:
			/*
			 * Is there really no case where we want to set no  timer?
			 * more likely an accident?
			 */
			LOG_PEXPECT("V2 microcode entry (%s) has unspecified timeout_event",
				    transition->story);
			break;

		case EVENT_RETAIN:
			/* the previous event is retained */
			break;

		default:
			bad_case(kind);
		}
		/*
		 * start liveness checks if set, making sure we only
		 * schedule once when moving from I2->I3 or R1->R2
		 */
		if (st->st_state->kind != from_state &&
			st->st_state->kind != STATE_UNDEFINED &&
			IS_CHILD_SA_ESTABLISHED(st) &&
			dpd_active_locally(st)) {
			DBG(DBG_DPD,
			    DBG_log("dpd enabled, scheduling ikev2 liveness checks"));
			deltatime_t delay = deltatime_max(c->dpd_delay, deltatime(MIN_LIVENESS));
			event_schedule(EVENT_v2_LIVENESS, delay, st);
		}
	}
}

static void log_stf_suspend(struct state *st, stf_status result)
{
	char b[CONN_INST_BUF];

	set_cur_state(st);      /* might have changed */

	fmt_conn_instance(st->st_connection, b);
	LSWDBGP(DBG_CONTROL, buf) {
		lswlogf(buf, "\"%s\"%s #%lu complete v2 state %s transition with ",
			st->st_connection->name, b, st->st_serialno,
			st->st_state->name);
		lswlog_v2_stf_status(buf, result);
		lswlogf(buf, " suspended from %s:%d",
			st->st_suspended_md_func,
			st->st_suspended_md_line);
	}
}

/*
 * Dependant on RESULT, either complete, suspend, abandon, or abort
 * (delete state) the state transition started by the state-specific
 * state transition function.
 *
 * Since this is function is meaningless without a state, ST really
 * should be non-NULL.
 *
 * XXX: A broken exception is when responding to an IKE_SA_INIT
 * request - the state machine calls the state transition function
 * with no state (trusting that the transition function will do the
 * job, but that isn't always true).  The fix is to create the state
 * before calling the state transition function (like is done for the
 * CHILD_SA code).
 *
 * Since, when initiating an exchange there is no message, code can't
 * assume that (*MDP) is non-NULL.
 *
 * XXX: Some state transition functions switch state part way (see
 * AUTH child code) and then tunnel the new state to this code via
 * (*MDP)->st (hence fake_md() and some callers passing in
 * (*MDP)->st).  The fix is for the AUTH code to handle the CHILD SA
 * as a nested or separate transition.
 *
 * XXX: The state transition structure (microcode) is stored in (*MDP)
 * forcing that structure to be created.  The fix is to store the
 * state's transition in the state.  As a bonus this makes determining
 * if a state is busy really really easy - if there's a
 * state-transition then it must be.
 *
 * This routine does not free (*MDP) (using release_any_md(mdp)).
 * However, when suspending a state transition, it will save it in ST
 * and zap (*MDP) so that the caller can't free it.  Hence, the caller
 * must be prepared for (*MDP) being set to NULL.
 *
 * XXX: At some point (*MDP) was being used for:
 *
 * - find st
 * - success_v2_state_transition(st, md);
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
void complete_v2_state_transition(struct state *st,
				  struct msg_digest **mdp,
				  stf_status result)
{
	/* statistics */
	/* this really depends on the type of error whether it is an IKE or IPsec fail */
	if (result > STF_FAIL) {
		pstats(ike_stf, STF_FAIL);
	} else {
		pstats(ike_stf, result);
	}

	/*
	 * XXX: If MD and MD.ST are non-NULL, expect MD.ST to point to
	 * ST.
	 *
	 * An exchange initiator doesn't have an MD but code insists
	 * that it should be and creates one (look for fake_md()).
	 * This is presumably because MD / MD.ST are being used to:
	 *
	 * - store the state transition; but that information really
             belongs in ST
	 *
	 * - store the CHILD SA when created midway through a state
         *   transition (see IKE_AUTH); but that should be either a
         *   nested or separate transition
	 *
	 * - signal that the SA was deleted mid-transition by clearing
	 *   MD.ST (so presumably it was previously set); but that
	 *   should be handled by returning an STF_deleteme and having
	 *   this code delete the SA.
	 */
	passert(mdp != NULL);
	struct msg_digest *md = *mdp;
	if (md != NULL) {
		if (md->st != NULL) {
			if (st == NULL) {
				/* can't happen, both must be null */
				LOG_PEXPECT("MD.ST contains the unknown %s SA #%lu; expecting NULL",
					    IS_CHILD_SA(md->st) ? "CHILD" : "IKE",
					    md->st->st_serialno);
			} else if (md->st != st) {
				/* can't happen, must match */
				LOG_PEXPECT("MD.ST contains the unknown %s SA #%lu; expecting the %s SA #%lu",
					    IS_CHILD_SA(md->st) ? "CHILD" : "IKE",
					    md->st->st_serialno,
					    IS_CHILD_SA(st) ? "CHILD" : "IKE",
					    st->st_serialno);
			} else {
				dbg("MD.ST contains the %s SA #%lu",
				    IS_CHILD_SA(st) ? "CHILD" : "IKE",
				    st->st_serialno);
			}
		} else if (st != NULL) {
			dbg("MD.ST contains NULL and ST is %s SA #%lu",
			    IS_CHILD_SA(st) ? "CHILD" : "IKE",
			    st->st_serialno);
		} else {
			dbg("MD.ST contains NULL and ST is NULL");
		}
	} else if (st != NULL) {
		dbg("MD.ST does not exist and ST is %s #%lu",
		    IS_CHILD_SA(st) ? "CHILD" : "IKE",
		    st->st_serialno);
	} else {
		dbg("MD.ST does not exist and ST is NULL");
	}

	/*
	 * XXX: yes, ST can be NULL.
	 *
	 * What happens is code deletes ST part way through a state
	 * transition and then tries to signal this by setting MD.ST
	 * to NULL (presumably it was previously set to ST).  This
	 * function is then called with MD.ST instead of simply ST.
	 *
	 * Of course all the intervening code still has references to
	 * the now-defunct state in local ST et.al. variables.  What
	 * could possibly go wrong .....
	 *
	 * The relevant code should instead return STF_deleteme
	 * (STF_ZOMBIFY?)  so that the delete can be performed here.
	 *
	 * XXX/SML:  There is no need to abort here in all cases where st is
	 * null, so moved this precondition to where it's needed.  Some previous
	 * logic appears to have been tooled to handle null state, and state might
	 * be null legitimately in certain failure cases (STF_FAIL + xxx).
	 *
	 * One condition for null state is when a new connection request packet
	 * arrives and there is no suitable matching configuration.  For example,
	 * ikev2_parent_inI1outR1() will return (STF_FAIL + NO_PROPOSAL_CHOSEN) but
	 * no state in this case.  While other failures may be better caught before
	 * this function is called, we should be graceful here.  And for this
	 * particular case, and similar failure cases, we want SEND_NOTIFICATION
	 * (below) to let the peer know why we've rejected the request.
	 *
	 * Another case of null state is return from ikev2_parent_inR1BoutI1B
	 * which returns STF_IGNORE.
	 *
	 * Another case occurs when we finish an Informational Exchange message
	 * that causes us to delete the IKE state.  In fact, that can be an
	 * STF_OK and yet have no remaining state object at this point.
	 */
	if (st == NULL) {
		/* see above */
		pexpect(md == NULL || md->st == NULL);
		if (result == STF_OK) {
			/*
			 * For instance, the successful transition of
			 * STATE_IKESA_DEL.
			 */
			dbg("STF_OK but no state object remains");
		} else if (result == STF_FAIL) {
			/* already logged by "delete" */
			dbg("STF_FAIL but no state object remains");
		} else if (result > STF_FAIL) {
			v2_notification_t notification = result - STF_FAIL;
			/* already logged by "delete" */
			dbg("STF_FAIL+%s but no state object remains",
			    enum_name(&ikev2_notify_names, notification));
			if (v2_msg_role(md) == MESSAGE_REQUEST) {
				/* will log? */
				send_v2N_response_from_md(md, notification, NULL);
			}
		} else {
			LSWLOG_PEXPECT(buf) {
				jam(buf, "NULL ST has unexpected status ");
				lswlog_v2_stf_status(buf, result);
			}
		}
		return;
	}

	struct ike_sa *ike = ike_sa(st);
	/* struct child_sa *child = IS_CHILD_SA(st) ? pexpect_child_sa(st) : NULL; */
	set_cur_state(st); /* might have changed */ /* XXX: huh? */
	const char *from_state_name = st->st_state->short_name;

	/*
	 * Try to get the transition that is being completed ...
	 *
	 * For the moment this comes from the (presumably non-NULL)
	 * MD.SVM.
	 *
	 * XXX: However, when a packet is bad and no transition is
	 * selected, this code is still called:
	 *
	 * STF_IGNORE: to undo the v2_msgid_start_responder() call;
	 * better would probably be to move that call to after a
	 * transition has been found (but fragmentation makes this
	 * messy).
	 *
	 * STF_FATAL: to discard a state in response to a bad exchange
	 * (for instance a protected packet's contents are bogus).
	 *
	 * Long term, this value should be extracted from the state
	 * and .st_v2_state_transition - it just isn't possible to
	 * squeeze both the IKE and CHILD transitions into MD.ST.
	 */
	const struct state_v2_microcode *transition = md != NULL ? md->svm : NULL;
	static const struct state_v2_microcode undefined_transition = {
		.story = "suspect message",
		.state = STATE_UNDEFINED,
		.next_state = STATE_UNDEFINED,
	};
	if (transition == NULL) {
		if (result != STF_FATAL && result != STF_IGNORE) {
			LOG_PEXPECT("state #%lu has no transition", st->st_serialno);
		} else {
			dbg("no transition for FATAL or IGNORE");
		}
		transition = &undefined_transition;
	}

	LSWDBGP(DBG_BASE, buf) {
		jam(buf, "#%lu complete_v2_state_transition()", st->st_serialno);
		jam(buf, " %s -> %s", from_state_name,
		    finite_states[transition->next_state]->short_name);
		jam(buf, " with status ");
		lswlog_v2_stf_status(buf, result);
		/* also dump any divergence */
		if (md == NULL) {
			jam(buf, "; md=NULL");
		} else if (md->svm == NULL) {
			jam(buf, "; md.svm=NULL");
		} else if (md->svm != transition) {
			jam(buf, "; md.svm=%s->%s",
			    finite_states[transition->state]->short_name,
			    finite_states[transition->next_state]->short_name);
		}
		if (transition->state != st->st_state->kind) {
			jam(buf, "; transition.[from]state=%s",
			    finite_states[transition->state]->short_name);
		}
	}

	/* audit log failures - success is audit logged in ikev2_ike_sa_established() */
	if (result > STF_OK) {
		linux_audit_conn(st, IS_IKE_SA_ESTABLISHED(st) ? LAK_CHILD_FAIL : LAK_PARENT_FAIL);
	}

	switch (result) {

	case STF_SUSPEND:
		/*
		 * If this transition was triggered by an
		 * incoming packet, save it.
		 *
		 * XXX: some initiator code creates a fake MD
		 * (there isn't a real one); save that as
		 * well.
		 */
		if (*mdp != NULL) {
			suspend_md(st, mdp);
			passert(*mdp == NULL); /* ownership transferred */
		}
		log_stf_suspend(st, result);
		return;

	case STF_IGNORE:
		/*
		 * logged above
		 *
		 * XXX: really?  Suspect this means to say logged
		 * where STF_IGNORE is returned.
		 *
		 * XXX: even when a packet is invalid and no
		 * transition is selected (TRANSITION==NULL) this code
		 * is executed - caller needs to cancel the responder
		 * processing the message.
		 */
		if (v2_msg_role(md) == MESSAGE_REQUEST) {
			v2_msgid_cancel_responder(ike, st, md);
		}
		return;

	case STF_OK:
		/* advance the state */
		success_v2_state_transition(st, md, transition);
		break;

	case STF_INTERNAL_ERROR:
		log_state(RC_INTERNALERR, st, "state transition function for %s had internal error",
			  st->st_state->name);
		release_pending_whacks(st, "internal error");
		break;

	case STF_FATAL:
		/*
		 * XXX: even when a packet is invalid and no
		 * transition is selected (TRANSITION==NULL) this code
		 * is executed - caller needs to kill the state.
		 */
		log_state(RC_FATAL, st, "encountered fatal error in state %s",
			  st->st_state->name);
		switch (v2_msg_role(md)) {
		case MESSAGE_RESPONSE:
			dbg("Message ID: forcing a response received update");
			v2_msgid_update_recv(ike, NULL, md);
			break;
		case MESSAGE_REQUEST:
			dbg("Message ID: exchange zombie as no response?");
			break;
		case NO_MESSAGE:
			break;
		}
		release_pending_whacks(st, "fatal error");
		delete_state(st);
		/* kill all st pointers */
		st = NULL; ike = NULL; if (md != NULL) md->st = NULL;
		break;

	case STF_FAIL:
		log_state(RC_NOTIFICATION, st, "state transition '%s' failed",
			  transition->story);
		break;

	default: /* STF_FAIL+notification */
		passert(result > STF_FAIL);
		/*
		 * XXX: For IKEv2, this code path isn't sufficient - a
		 * message request can result in a response that
		 * contains both a success and a fail.  Better to
		 * record the responses and and then return
		 * STF_ZOMBIFY signaling both that the message should
		 * be sent and the state deleted.
		 */
		v2_notification_t notification = result - STF_FAIL;
		/* Only the responder sends a notification */
		if (v2_msg_role(md) == MESSAGE_REQUEST) {
			dbg("sending a notification reply");
			send_v2N_response_from_state(ike, md,
						     notification,
						     NULL/*no data*/);
			if (md->hdr.isa_xchg == ISAKMP_v2_IKE_SA_INIT) {
				delete_state(st);
				/* kill all st pointers */
				st = NULL; ike = NULL; md->st = NULL;
			} else {
				dbg("forcing #%lu to a discard event",
				    st->st_serialno);
				delete_event(st);
				event_schedule_s(EVENT_SO_DISCARD,
						 MAXIMUM_RESPONDER_WAIT,
						 st);
			}
		} else {
			log_state(RC_NOTIFICATION+notification, st,
				  "state transition '%s' failed with %s",
				  transition->story, enum_name(&ikev2_notify_names, notification));
		}
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
	pb_stream *nonce_pbs = &md->chain[ISAKMP_NEXT_v2Ni]->pbs;
	size_t len = pbs_left(nonce_pbs);

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
	free_chunk_content(dest);
	*dest = clone_hunk(pbs_in_left_as_shunk(nonce_pbs), "nonce");
	passert(len == dest->len);
	return v2N_NOTHING_WRONG;
}

void lswlog_v2_stf_status(struct lswlog *buf, unsigned status)
{
	if (status <= STF_FAIL) {
		lswlog_enum(buf, &stf_status_names, status);
	} else {
		lswlogs(buf, "STF_FAIL+");
		lswlog_enum(buf, &ikev2_notify_names, status - STF_FAIL);
	}
}

/* used by parent and child to emit v2N_IPCOMP_SUPPORTED if appropriate */
bool emit_v2N_compression(struct state *cst,
			bool OK,
			pb_stream *s)
{
	const struct connection *c = cst->st_connection;

	if ((c->policy & POLICY_COMPRESS) && OK) {
		uint16_t c_spi;

		DBG(DBG_CONTROL, DBG_log("Initiator child policy is compress=yes, sending v2N_IPCOMP_SUPPORTED for DEFLATE"));

		/* calculate and keep our CPI */
		if (cst->st_ipcomp.our_spi == 0) {
			/* CPI is stored in network low order end of an ipsec_spi_t */
			cst->st_ipcomp.our_spi = get_my_cpi(&c->spd, LIN(POLICY_TUNNEL, c->policy));
			c_spi = (uint16_t)ntohl(cst->st_ipcomp.our_spi);
			if (c_spi < IPCOMP_FIRST_NEGOTIATED) {
				/* get_my_cpi() failed */
				loglog(RC_LOG_SERIOUS, "kernel failed to calculate compression CPI (CPI=%d)", c_spi);
				return false;
			}
			DBG(DBG_CONTROL, DBG_log("Calculated compression CPI=%d", c_spi));
		} else {
			c_spi = (uint16_t)ntohl(cst->st_ipcomp.our_spi);
		}

		struct ikev2_notify_ipcomp_data d = {
			.ikev2_cpi = c_spi,
			.ikev2_notify_ipcomp_trans = IPCOMP_DEFLATE,
		};
		pb_stream d_pbs;

		bool r =
			emit_v2Npl(v2N_IPCOMP_SUPPORTED, s, &d_pbs) &&
			out_struct(&d, &ikev2notify_ipcomp_data_desc, &d_pbs, NULL);
		close_output_pbs(&d_pbs);
		return r;
	} else {
		DBG(DBG_CONTROL, DBG_log("Initiator child policy is compress=no, NOT sending v2N_IPCOMP_SUPPORTED"));
		return true;
	}
}
