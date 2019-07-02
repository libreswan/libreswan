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
#include "ip_endpoint.h"
#include "hostpair.h"		/* for find_v2_host_connection() */

enum smf2_flags {
	/*
	 * Check the value of the I(Initiator) (IKE_I) flag in the
	 * header.
	 *
	 * The original initiator receives packets with the
	 * I(Initiator) bit clear, while the original resonder
	 * receives packets with the I(Initiator) bit set.
	 *
	 * The bit is used to identify the IKE SA initiator and
	 * responder SPIs (cookies) in the header (see 2.6. IKE SA
	 * SPIs and Cookies).  For incoming messages, the I(Initiator)
	 * flag in the header is used; for outgoing messages, the
	 * I(Initiator) flag is set according to ike.sa.st_sa_role.
	 *
	 * Arguably, this could be made a separate 3 state variable.
	 */
	SMF2_IKE_I_SET = LELEM(1),
	SMF2_IKE_I_CLEAR = LELEM(2),

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
	 * Should the SK (secured-by-key) decryption and verification
	 * be skipped?
	 *
	 * The original responder, when it receives the encrypted AUTH
	 * payload, isn't yet ready to decrypt it - receiving the
	 * packet is what triggers the DH calculation needed before
	 * encryption can occur.
	 */
	SMF2_NO_SKEYSEED = LELEM(7),

	/*
	 * Suppress logging of a successful state transition.
	 *
	 * This is here simply to stop liveness check transitions
	 * filling up the log file.
	 */
	SMF2_SUPPRESS_SUCCESS_LOG = LELEM(8),

	/*
	 * If this state transition is successful then the SA is
	 * encrypted and authenticated.
	 *
	 * XXX: The flag currently works for CHILD SAs but not IKE SAs
	 * (but it should).  This is because IKE SAs currently bypass
	 * the complete state transition code when establishing.  See
	 * also danger note below.
	 */
	SMF2_ESTABLISHED = LELEM(9),
};

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
	  .flags      = SMF2_IKE_I_CLEAR | SMF2_MSG_R_SET,
	  .send = MESSAGE_REQUEST,
	  .processor  = NULL,
	  .timeout_event = EVENT_RETRANSMIT, },

	/* no state:   --> CREATE IPsec Rekey Request
	 * HDR, SAi1, N(REKEY_SA), {KEi,} Ni TSi TSr -->
	 */
	{ .story      = "Initiate CREATE_CHILD_SA IPsec Rekey SA",
	  .state      = STATE_V2_REKEY_CHILD_I0,
	  .next_state = STATE_V2_REKEY_CHILD_I,
	  .flags =      SMF2_IKE_I_CLEAR | SMF2_MSG_R_SET,
	  .send = MESSAGE_REQUEST,
	  .processor  = NULL,
	  .timeout_event = EVENT_RETRANSMIT, },

	/* no state:   --> CREATE IPsec Child Request
	 * HDR, SAi1, {KEi,} Ni TSi TSr -->
	 */
	{ .story      = "Initiate CREATE_CHILD_SA IPsec SA",
	  .state      = STATE_V2_CREATE_I0,
	  .next_state = STATE_V2_CREATE_I,
	  .flags =      SMF2_IKE_I_CLEAR | SMF2_MSG_R_SET,
	  .send = MESSAGE_REQUEST,
	  .processor  = NULL,
	  .timeout_event = EVENT_RETRANSMIT, },

	/* no state:   --> I1
	 * HDR, SAi1, KEi, Ni -->
	 */
	{ .story      = "initiate IKE_SA_INIT",
	  .state      = STATE_PARENT_I0,
	  .next_state = STATE_PARENT_I1,
	  .flags      = SMF2_IKE_I_CLEAR | SMF2_MSG_R_SET,
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
	  .flags = SMF2_IKE_I_CLEAR | SMF2_MSG_R_SET,
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
	  .flags = SMF2_IKE_I_CLEAR | SMF2_MSG_R_SET,
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
	  .flags = SMF2_IKE_I_CLEAR | SMF2_MSG_R_SET,
	  .message_payloads = { .required = P(SK), },
	  .encrypted_payloads = { .required = P(N), .notification = v2N_INVALID_SYNTAX, },
	  .processor  = ikev2_auth_initiator_process_failure_notification,
	  .recv_type  = ISAKMP_v2_IKE_AUTH, },
	{ .story      = "Initiator: process AUTHENTICATION_FAILED AUTH notification",
	  .state      = STATE_PARENT_I2, .next_state = STATE_PARENT_I2,
	  .flags = SMF2_IKE_I_CLEAR | SMF2_MSG_R_SET,
	  .message_payloads = { .required = P(SK), },
	  .encrypted_payloads = { .required = P(N), .notification = v2N_AUTHENTICATION_FAILED, },
	  .processor  = ikev2_auth_initiator_process_failure_notification,
	  .recv_type  = ISAKMP_v2_IKE_AUTH, },
	{ .story      = "Initiator: process UNSUPPORTED_CRITICAL_PAYLOAD AUTH notification",
	  .state      = STATE_PARENT_I2, .next_state = STATE_PARENT_I2,
	  .flags = SMF2_IKE_I_CLEAR | SMF2_MSG_R_SET,
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
	  .flags = SMF2_IKE_I_CLEAR | SMF2_MSG_R_SET | SMF2_ESTABLISHED,
	  .req_clear_payloads = P(SK),
	  .req_enc_payloads = P(IDr) | P(AUTH) | P(SA) | P(TSi) | P(TSr),
	  .opt_enc_payloads = P(CERT)|P(CP),
	  .processor  = ikev2_parent_inR2,
	  .recv_type  = ISAKMP_v2_IKE_AUTH,
	  .timeout_event = EVENT_SA_REPLACE, },
	{ .story      = "IKE SA: process IKE_AUTH response containing unknown notification",
	  .state      = STATE_PARENT_I2, .next_state = STATE_PARENT_I2,
	  .flags = SMF2_IKE_I_CLEAR | SMF2_MSG_R_SET,
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
	  .flags = SMF2_IKE_I_SET | SMF2_MSG_R_CLEAR,
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
	  .flags = SMF2_IKE_I_SET | SMF2_MSG_R_CLEAR | SMF2_NO_SKEYSEED,
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
	  .flags = SMF2_IKE_I_SET | SMF2_MSG_R_CLEAR | SMF2_ESTABLISHED,
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
	  .flags      = SMF2_MSG_R_CLEAR,
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
	  .flags      = SMF2_MSG_R_SET,
	  .req_clear_payloads = P(SK),
	  .req_enc_payloads = P(SA) | P(Ni) |  P(KE),
	  .opt_enc_payloads = P(N),
	  .processor  = ikev2_child_ike_inR,
	  .recv_type  = ISAKMP_v2_CREATE_CHILD_SA,
	  .timeout_event = EVENT_SA_REPLACE, },

	{ .story      = "Process CREATE_CHILD_SA IPsec SA Response",
	  .state      = STATE_V2_CREATE_I,
	  .next_state = STATE_V2_IPSEC_I,
	  .flags      = SMF2_MSG_R_SET | SMF2_ESTABLISHED,
	  .req_clear_payloads = P(SK),
	  .req_enc_payloads = P(SA) | P(Ni) | P(TSi) | P(TSr),
	  .opt_enc_payloads = P(KE) | P(N),
	  .processor  = ikev2_child_inR,
	  .recv_type  = ISAKMP_v2_CREATE_CHILD_SA,
	  .timeout_event = EVENT_SA_REPLACE, },

	{ .story      = "Respond to CREATE_CHILD_SA IPsec SA Request",
	  .state      = STATE_V2_CREATE_R,
	  .next_state = STATE_V2_IPSEC_R,
	  .flags      = SMF2_MSG_R_CLEAR | SMF2_ESTABLISHED,
	  .send = MESSAGE_RESPONSE,
	  .req_clear_payloads = P(SK),
	  .req_enc_payloads = P(SA) | P(Ni) | P(TSi) | P(TSr),
	  .opt_enc_payloads = P(KE) | P(N),
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
	  .flags      = SMF2_IKE_I_SET | SMF2_SUPPRESS_SUCCESS_LOG,
	  .message_payloads.required = P(SK),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_RETAIN, },

	{ .story      = "I3: Informational Response",
	  .state      = STATE_PARENT_I3,
	  .next_state = STATE_PARENT_I3,
	  .flags      = SMF2_IKE_I_CLEAR | SMF2_SUPPRESS_SUCCESS_LOG,
	  .message_payloads.required = P(SK),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_RETAIN, },

	{ .story      = "I3: INFORMATIONAL Request",
	  .state      = STATE_PARENT_I3,
	  .next_state = STATE_PARENT_I3,
	  .flags      = SMF2_IKE_I_SET,
	  .req_clear_payloads = P(SK),
	  .opt_enc_payloads = P(N) | P(D) | P(CP),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_RETAIN, },

	{ .story      = "I3: INFORMATIONAL Response",
	  .state      = STATE_PARENT_I3,
	  .next_state = STATE_PARENT_I3,
	  .flags      = SMF2_IKE_I_CLEAR,
	  .req_clear_payloads = P(SK),
	  .opt_enc_payloads = P(N) | P(D) | P(CP),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_RETAIN, },

	{ .story      = "R2: process Informational Request",
	  .state      = STATE_PARENT_R2,
	  .next_state = STATE_PARENT_R2,
	  .flags      = SMF2_IKE_I_SET | SMF2_SUPPRESS_SUCCESS_LOG,
	  .message_payloads.required = P(SK),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_RETAIN, },

	{ .story      = "R2: process Informational Response",
	  .state      = STATE_PARENT_R2,
	  .next_state = STATE_PARENT_R2,
	  .flags      = SMF2_IKE_I_CLEAR | SMF2_SUPPRESS_SUCCESS_LOG,
	  .message_payloads.required = P(SK),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_RETAIN, },

	{ .story      = "R2: process INFORMATIONAL Request",
	  .state      = STATE_PARENT_R2,
	  .next_state = STATE_PARENT_R2,
	  .flags      = SMF2_IKE_I_SET,
	  .req_clear_payloads = P(SK),
	  .opt_enc_payloads = P(N) | P(D) | P(CP),
	  .processor  = process_encrypted_informational_ikev2,
	  .recv_type  = ISAKMP_v2_INFORMATIONAL,
	  .timeout_event = EVENT_RETAIN, },

	{ .story      = "R2: process INFORMATIONAL Response",
	  .state      = STATE_PARENT_R2,
	  .next_state = STATE_PARENT_R2,
	  .flags      = SMF2_IKE_I_CLEAR,
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
	 * Fill in the states.
	 *
	 * This is a hack until each finite-state is a separate object
	 * with corresponding edges (aka microcodes).
	 *
	 * XXX: Long term goal is to have a constant finite_states[]
	 * contain constant pointers and this writeable array to just
	 * go away.
	 */
	static struct finite_state v2_states[STATE_IKEv2_ROOF - STATE_IKEv2_FLOOR];
	for (enum state_kind kind = STATE_IKEv2_FLOOR; kind < STATE_IKEv2_ROOF; kind++) {

		/* skip hardwired states */
		if (finite_states[kind] != NULL) {
			continue;
		}

		/* fill in using static struct */
		struct finite_state *fs = &v2_states[kind - STATE_IKEv2_FLOOR];
		fs->kind = kind;
		finite_states[kind] = fs;

		fs->name = enum_name(&state_names, fs->kind);
		fs->short_name = enum_short_name(&state_names, fs->kind);
		fs->story = enum_name(&state_stories, fs->kind);

		/*
		 * Initialize .fs_category
		 *
		 * If/when struct finite_state is converted to a static
		 * structure, this all goes away.
		 */
		enum state_category cat;
		switch (fs->kind) {

		case STATE_PARENT_I0:
			/*
			 * IKEv2 IKE SA initiator, while the the SA_INIT
			 * packet is being constructed, are in state.  Only
			 * once the packet has been sent out does it
			 * transition to STATE_PARENT_I1 and start being
			 * counted as half-open.
			 */
			cat = CAT_IGNORE;
			break;

		case STATE_PARENT_I1:
		case STATE_PARENT_R0:
		case STATE_PARENT_R1:
			/*
			 * Count I1 as half-open too because with ondemand,
			 * a plaintext packet (that is spoofed) will
			 * trigger an outgoing IKE SA.
			 */
			cat = CAT_HALF_OPEN_IKE_SA;
			break;

		case STATE_PARENT_I2:
			/*
			 * All IKEv1 MAIN modes except the first
			 * (half-open) and last ones are not
			 * authenticated.
			 */
			cat = CAT_OPEN_IKE_SA;
			break;

		case STATE_V2_CREATE_I0: /* isn't this an ipsec state */
		case STATE_V2_CREATE_I: /* isn't this an ipsec state */
		case STATE_V2_REKEY_IKE_I0:
		case STATE_V2_REKEY_IKE_I:
		case STATE_V2_REKEY_CHILD_I0: /* isn't this an ipsec state */
		case STATE_V2_REKEY_CHILD_I: /* isn't this an ipsec state */
		case STATE_V2_CREATE_R:
		case STATE_V2_REKEY_IKE_R:
		case STATE_V2_REKEY_CHILD_R:
			/*
			 * IKEv1 established states.
			 *
			 * XAUTH, seems to a second level of authentication
			 * performed after the connection is established and
			 * authenticated.
			 */
			cat = CAT_ESTABLISHED_IKE_SA;
			break;

		case STATE_PARENT_I3:
		case STATE_PARENT_R2:
			/*
			 * IKEv2 established states.
			 */
			cat = CAT_ESTABLISHED_IKE_SA;
			break;

		case STATE_V2_IPSEC_I:
		case STATE_V2_IPSEC_R:
			cat = CAT_ESTABLISHED_CHILD_SA;
			break;

		case STATE_IKESA_DEL:
			cat = CAT_ESTABLISHED_IKE_SA;
			break;

		case STATE_CHILDSA_DEL:
			cat = CAT_INFORMATIONAL;
			break;

		default:
			bad_case(fs->kind);
		}
		fs->category = cat;
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

		DBGF(DBG_TMI, "processing IKEv2 state transition %s -> %s (%s)",
		     from->short_name, to->short_name, t->story);

		/*
		 * Point .fs_v2_microcode at the first transition.
		 * All other microcodes for that state should follow
		 * immediately after (or to put it another way,
		 * previous should match).
		 */
		if (from->v2_transitions == NULL) {
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

	/*
	 * Finally list/verify the states.
	 */
	if (DBGP(DBG_BASE)) {
		for (enum state_kind kind = STATE_IKEv2_FLOOR; kind < STATE_IKEv2_ROOF; kind++) {
			const struct finite_state *from = finite_states[kind];
			passert(from != NULL);
			LSWLOG_DEBUG(buf) {
				jam(buf, "  ");
				lswlog_finite_state(buf, from);
				jam(buf, ":");
				if (from->nr_transitions == 0) {
					lswlogs(buf, " <none>");
				}
			}
			for (unsigned ti = 0; ti < from->nr_transitions; ti++) {
				const struct state_v2_microcode *t = &from->v2_transitions[ti];
				const struct finite_state *to = finite_states[t->next_state];
				const char *send;
				switch (t->send) {
				case NO_MESSAGE: send = ""; break;
				case MESSAGE_REQUEST: send = " send-request"; break;
				case MESSAGE_RESPONSE: send = " send-request"; break;
				default: bad_case(t->send);
				}
				DBG_log("    -> %s %s%s (%s)", to->short_name,
					enum_short_name(&timer_event_names,
							t->timeout_event),
					send, t->story);
			}
		}
	}
}

/*
 * split an incoming message into payloads
 */
static struct payload_summary ikev2_decode_payloads(struct msg_digest *md,
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
		DBG(DBG_CONTROL,
		    DBG_log("Now let's proceed with payload (%s)",
			    enum_show(&ikev2_payload_names, np)));

		if (md->digest_roof >= elemsof(md->digest)) {
			loglog(RC_LOG_SERIOUS,
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
				loglog(RC_LOG_SERIOUS, "malformed payload in packet");
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
				loglog(RC_LOG_SERIOUS,
				       "message %s contained an unknown critical payload type (%s)",
				       role, enum_show(&ikev2_payload_names, np));
				summary.n = v2N_UNSUPPORTED_CRITICAL_PAYLOAD;
				summary.data[0] = np;
				summary.data_size = 1;
				break;
			}
			loglog(RC_COMMENT,
				"non-critical payload ignored because it contains an unknown or unexpected payload type (%s) at the outermost level",
				enum_show(&ikev2_payload_names, np));
			np = pd->payload.generic.isag_np;
			continue;
		}

		if (np >= LELEM_ROOF) {
			DBG(DBG_CONTROL, DBG_log("huge next-payload %u", np));
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
			loglog(RC_LOG_SERIOUS, "malformed payload in packet");
			summary.n = v2N_INVALID_SYNTAX;
			break;
		}

		DBG(DBG_PARSING,
		    DBG_log("processing payload: %s (len=%zu)",
			    enum_show(&ikev2_payload_names, np),
			    pbs_left(&pd->pbs)));

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

static struct ikev2_payload_errors ikev2_verify_payloads(struct msg_digest *md,
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

/* report problems - but less so when OE */
static void log_v2_payload_errors(struct state *st, struct msg_digest *md,
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

	LSWLOG_RC(RC_LOG_SERIOUS, buf) {
		const enum isakmp_xchg_types ix = md->hdr.isa_xchg;
		lswlogs(buf, "dropping unexpected ");
		lswlog_enum_short(buf, &ikev2_exchange_names, ix);
		lswlogs(buf, " message");
		/* we want to print and log the first notify payload */
		struct payload_digest *ntfy = md->chain[ISAKMP_NEXT_v2N];
		if (ntfy != NULL) {
			lswlogs(buf, " containing ");
			lswlog_enum_short(buf, &ikev2_notify_names,
					  ntfy->payload.v2n.isan_type);
			if (ntfy->next != NULL) {
				lswlogs(buf, "...");
			}
			lswlogs(buf, " notification");
		}
		if (md->message_payloads.parsed) {
			lswlogf(buf, "; message payloads: ");
			lswlog_enum_lset_short(buf, &ikev2_payload_names, ",",
					       md->message_payloads.present);
		}
		if (md->encrypted_payloads.parsed) {
			lswlogf(buf, "; encrypted payloads: ");
			lswlog_enum_lset_short(buf, &ikev2_payload_names, ",",
					       md->encrypted_payloads.present);
		}
		if (errors->missing != LEMPTY) {
			lswlogf(buf, "; missing payloads: ");
			lswlog_enum_lset_short(buf, &ikev2_payload_names, ",",
					       errors->missing);
		}
		if (errors->unexpected != LEMPTY) {
			lswlogf(buf, "; unexpected payloads: ");
			lswlog_enum_lset_short(buf, &ikev2_payload_names, ",",
					       errors->unexpected);
		}
		if (errors->excessive != LEMPTY) {
			lswlogf(buf, "; excessive payloads: ");
			lswlog_enum_lset_short(buf, &ikev2_payload_names, ",",
					       errors->excessive);
		}
		if (errors->notification != v2N_NOTHING_WRONG) {
			lswlogs(buf, "; missing notification ");
			lswlog_enum_short(buf, &ikev2_notify_names,
					  errors->notification);
		}
	}
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
	clonetochunk(frag->cipher, md->packet_pbs.start,
		     e_pbs->roof - md->packet_pbs.start,
		     "incoming IKEv2 encrypted fragment");

	if (skf->isaskf_number == 1) {
		st->st_v2_rfrags->first_np = skf->isaskf_np;
	}

	passert(st->st_v2_rfrags->count < st->st_v2_rfrags->total);
	st->st_v2_rfrags->count++;
	return st->st_v2_rfrags->count == st->st_v2_rfrags->total;
}

static struct child_sa *process_v2_child_ix(struct msg_digest *md,
					    struct ike_sa *ike)
{
	/* for log */
	const char *what;
	const char *why = "";

	/* this an IKE request and not a response */
	pexpect(v2_msg_role(md) == MESSAGE_REQUEST);

	struct child_sa *child; /* to-be-determined */
	if (md->from_state == STATE_V2_CREATE_R) {
		what = "Child SA Request";
		child = ikev2_duplicate_state(ike, IPSEC_SA,
					      SA_RESPONDER);
		change_state(&child->sa, STATE_V2_CREATE_R);
	} else {
		what = "IKE Rekey Request";
		child = ikev2_duplicate_state(ike, IKE_SA,
					      SA_RESPONDER);
		change_state(&child->sa, STATE_V2_REKEY_IKE_R); /* start with this */
	}

	binlog_refresh_state(&child->sa);

	LSWDBGP(DBG_BASE, buf) {
		jam_connection(buf, ike->sa.st_connection);
		jam(buf, " #%lu received %s CREATE_CHILD_SA%s from ",
		    ike->sa.st_serialno,
		    what, why);
		jam_endpoint(buf, &md->sender);
		jam(buf, " Child ");
		jam_connection(buf, child->sa.st_connection);
		jam(buf, " #%lu in %s will process it further",
		    child->sa.st_serialno, child->sa.st_state->name);
	}

	return child;
}

/*
 * Find the SA (IKE or CHILD), within IKE's family, that is initiated
 * or is responding to Message ID.
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
 * Is this a duplicate request:
 *
 * - an old message which can be tossed
 *
 * - the most recent completed request, which should trigger a
 *   retransmit of the response
 *
 * - the currently being processed request, which can also be tossed
 *
 * XXX: This solution is broken. If two exchanges (after the
 * initial exchange) are interleaved, we ignore the first.
 * This is https://bugs.libreswan.org/show_bug.cgi?id=185
 *
 * XXX: Is this still true?
 */

static bool is_duplicate_request(struct ike_sa *ike,
				 struct state *responder,
				 struct msg_digest *md)
{
	passert(v2_msg_role(md) == MESSAGE_REQUEST);
	intmax_t msgid = md->hdr.isa_msgid;

	/* lie to keep test results happy */
	dbg("#%lu st.st_msgid_lastrecv %jd md.hdr.isa_msgid %08jx",
	    ike->sa.st_serialno, ike->sa.st_v2_msgid_windows.responder.recv, msgid);

	/* only a true responder */
	pexpect(responder == NULL ||
		responder->st_v2_msgid_wip.responder == msgid);

	/* the sliding window is really small?!? */
	pexpect(ike->sa.st_v2_msgid_windows.responder.recv ==
		ike->sa.st_v2_msgid_windows.responder.sent);

	if (msgid < ike->sa.st_v2_msgid_windows.responder.recv) {
		/*
		 * this is an OLD retransmit. we can't do anything
		 */
		pexpect(responder == NULL);
		libreswan_log("received too old retransmit: %jd < %jd",
			      msgid, ike->sa.st_v2_msgid_windows.responder.recv);
		return true;
	}

	if (msgid == ike->sa.st_v2_msgid_windows.responder.sent) {
		/*
		 * This was the last request processed and,
		 * presumably, a response was sent.  Retransmit the
		 * saved response (the response was saved right?).
		 */
		if (ike->sa.st_tpacket.len == 0 && ike->sa.st_v2_tfrags == NULL) {
			FAIL_V2_MSGID(ike, responder,
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
			libreswan_log("received duplicate %s message request (Message ID %jd); retransmitting response",
				      enum_short_name(&ikev2_exchange_names, md->hdr.isa_xchg),
				      msgid);
			send_recorded_v2_ike_msg(&ike->sa, "ikev2-responder-retransmit");
		} else if (fragment == 1) {
			libreswan_log("received duplicate %s message request (Message ID %jd, fragment %u); retransmitting response",
				      enum_short_name(&ikev2_exchange_names, md->hdr.isa_xchg),
				      msgid, fragment);
			send_recorded_v2_ike_msg(&ike->sa, "ikev2-responder-retransmt (fragment 1)");
		} else {
			dbg_v2_msgid(ike, responder,
				     "received duplicate %s message request (Message ID %jd, fragment %u); discarded as not fragment 1",
				     enum_short_name(&ikev2_exchange_names, md->hdr.isa_xchg),
				     msgid, fragment);
		}
		return true;
	}

	/* all that is left */
	pexpect(msgid > ike->sa.st_v2_msgid_windows.responder.sent);

	if (responder != NULL && responder->st_v2_rfrags == NULL) {
		/*
		 * Packet currently being processed.  Having
		 * .st_v2_rfrag==NULL could mean either that all the
		 * fragments have been re-assembled, or there were
		 * never any fragments.
		 *
		 * To keep tests happy, try to output text matching
		 * verbose_state_busy().
		 *
		 * If things are fragmented, only log the first
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
			libreswan_log("discarding packet received during asynchronous work (DNS or crypto) in %s",
				      responder->st_state->name);
		} else if (fragment <= 1) {
			libreswan_log("discarding fragments received during asynchronous work (DNS or crypto) in %s",
				      responder->st_state->name);
		} else {
			dbg_v2_msgid(ike, responder, "discarding fragments received during asynchronous work (DNS or crypto) in %s",
				     responder->st_state->name);
		}
		return true;
	}

	/*
	 * For instance, the IKE SA initiator, having accumulated all
	 * the fragments for the IKE_AUTH response, is computing the
	 * SKEYSEED (which needs to happen before the fragments can be
	 * decrypted and merged into a single message).
	 */
	if (responder != NULL &&
	    responder->st_v2_rfrags != NULL &&
	    responder->st_v2_rfrags->count == responder->st_v2_rfrags->total) {
		/* bogus message to keep test results happy */
		libreswan_log("discarding packet received during asynchronous work (DNS or crypto) in %s",
			      responder->st_state->name);
		return true;
	}

	/*
	 * Since the above has detected and rejected a request that is
	 * already been processed, can this happen?
	 */
	if (responder != NULL && verbose_state_busy(responder)) {
		return true;
	}

	if (responder != NULL) {
		pexpect(responder->st_v2_rfrags != NULL &&
			responder->st_v2_rfrags->count < responder->st_v2_rfrags->total);
		dbg_v2_msgid(ike, responder, "not a duplicate - responder is accumulating fragments");
	} else {
		dbg_v2_msgid(ike, responder, "not a duplicate - message is new");
	}

	return false;
}

/*
 * Is this a duplicate response?
 *
 * - there's no initiator waiting for it so it can be dropped
 *
 * - the initiator is busy, presumably because this is a duplicate
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
		libreswan_log("%s message response with Message ID %jd has no matching SA",
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
 */

static void ike_process_packet(struct msg_digest **mdp, enum sa_role local_ike_role,
			       struct ike_sa *ike, struct state *st);

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
	 *
	 * XXX: local_ike_role -> expected_ike_role
	 */
	enum sa_role local_ike_role = (md->hdr.isa_flags & ISAKMP_FLAGS_v2_IKE_I) ? SA_RESPONDER : SA_INITIATOR;

	/*
	 * Dump what the message says, once a state has been found
	 * this can be checked against what is.
	 */
	LSWDBGP(DBG_BASE, buf) {
		switch (local_ike_role) {
		case SA_RESPONDER:
			jam(buf, "I am the IKE SA Original Responder");
			break;
		case SA_INITIATOR:
			jam(buf, "I am the IKE SA Original Initiator");
			break;
		default:
			bad_case(local_ike_role);
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
	 * Find one or two SAs:
	 *
	 * - IKE: the IKE SA that is looking after this IKE SPI family
	 *
	 *   If it's a new IKE_SA_INIT request (or previously
	 *   discarded request due to cookies) this will be NULL.
	 *
	 * - ST: the IKE/CHILD SA that will process (or is already
         *   processing) the message
	 *
	 *   If there's no existing state to handle the message then
	 *   this will be NULL.
	 */

	struct state *st;
	struct ike_sa *ike;
	if (ix == ISAKMP_v2_IKE_SA_INIT) {
		/*
		 * The message ID of the initial exchange is always
		 * zero.
		 */
		if (md->hdr.isa_msgid != 0) {
			libreswan_log("dropping IKE_SA_INIT message containing non-zero message ID");
			return;
		}
		/*
		 * Now try to find the state
		 */
		switch (v2_msg_role(md)) {
		case MESSAGE_REQUEST:
			/* The initiator must send: IKE_I && !MSG_R */
			if (local_ike_role != SA_RESPONDER) {
				libreswan_log("dropping IKE_SA_INIT request with conflicting IKE initiator flag");
				return;
			}
			/*
			 * 3.1.  The IKE Header: This [SPIr] value
			 * MUST be zero in the first message of an IKE
			 * initial exchange (including repeats of that
			 * message including a cookie).
			 */
			if (!ike_spi_is_zero(&md->hdr.isa_ike_responder_spi)) {
				libreswan_log("dropping IKE_SA_INIT request with non-zero SPIr");
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
							      local_ike_role);
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
				st =find_v2_sa_by_responder_wip(ike, md->hdr.isa_msgid);
				pexpect(st == NULL || st == &ike->sa);
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
				md->message_payloads = ikev2_decode_payloads(md,
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
				struct connection *c = find_v2_host_pair_connection(md, &policy);
				if (c == NULL) {
					/*
					 * NO_PROPOSAL_CHOSEN is used
					 * when the list of proposals
					 * is empty, like when we did
					 * not find any connection to
					 * use.
					 *
					 * INVALID_SYNTAX is for
					 * errors that a configuration
					 * change could not fix.
					 */
					send_v2N_response_from_md(md, v2N_NO_PROPOSAL_CHOSEN, NULL);
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
				st = find_v2_sa_by_responder_wip(ike, md->hdr.isa_msgid);
				pexpect(st == NULL || st == &ike->sa);
			}
			/* update lastrecv later on */
			break;
		case MESSAGE_RESPONSE:
			/* The responder must send: !IKE_I && MSG_R. */
			if (local_ike_role != SA_INITIATOR) {
				libreswan_log("dropping IKE_SA_INIT response with conflicting IKE initiator flag");
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
							      local_ike_role);
			if (ike == NULL) {
				/*
				 * There should be a state matching
				 * the original initiator's cookie.
				 * Since there isn't someone's playing
				 * games.  Drop the packet.
				 */
				libreswan_log("no matching state for IKE_SA_INIT response; discarding packet");
				return;
			}
			/*
			 * Set ST to the state that is currently
			 * processing the message, if it exists.
			 * Pretty easy as it is the IKE SA or nothing
			 * at all.
			 */
			pexpect(md->hdr.isa_msgid == 0); /* per above */
			st = find_v2_sa_by_initiator_wip(ike, md->hdr.isa_msgid);
			pexpect(st == NULL || st == &ike->sa);
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
				     local_ike_role);
		if (ike == NULL) {
			struct esb_buf ixb;
			rate_log(md, "%s message request has no corresponding IKE SA",
				 enum_show_shortb(&ikev2_exchange_names,
						  ix, &ixb));
			return;
		}
		/*
		 * As well as WIP this can also find something still
		 * accumulating fragments.  duplicate() gets to sort
		 * out the mess.
		 */
		st = find_v2_sa_by_responder_wip(ike, md->hdr.isa_msgid);
	} else if (v2_msg_role(md) == MESSAGE_RESPONSE) {
		/*
		 * A response to this ends request.  First find the
		 * IKE SA and then, within that group, find the
		 * initiator (it might also be the IKE SA but it might
		 * not).
		 */
		ike = find_v2_ike_sa(&md->hdr.isa_ike_spis,
				     local_ike_role);
		if (ike == NULL) {
			/* technically IKE or CHILD SA */
			rate_log(md, "%s message response has no matching IKE SA",
				 enum_name(&ikev2_exchange_names, ix));
			return;
		}
		st = find_v2_sa_by_initiator_wip(ike, md->hdr.isa_msgid);
	} else {
		PASSERT_FAIL("message role %d invalid", v2_msg_role(md));
	}

	/*
	 * There's at least an IKE SA, and possibly ST willing to
	 * process the message.  Backdate billing to when the message
	 * first arrived.
	 */
	passert(ike != NULL);

	statetime_t start = statetime_backdate(&ike->sa, &md->md_inception);
	ike_process_packet(mdp, local_ike_role, ike, st);
	statetime_stop(&start, "%s()", __func__);
}

/*
 * The IKE SA for the message has been found (or created).  Continue
 * verification, and identify the state (ST) that the message should
 * be sent to.
 *
 * XXX: should the find_v2_sa_by_*_wip() be moved to here, it is
 * pretty generic.
 */

static void ike_process_packet(struct msg_digest **mdp, enum sa_role local_ike_role,
			       struct ike_sa *ike, struct state *st)
{
	struct msg_digest *md = *mdp;
	/*
	 * If there's a state, attribute all further logging to that
	 * state.
	 */
	if (st != NULL) {
		/* XXX: debug-logging here is redundant */
		push_cur_state(st);
	} else if (ike != NULL) {
		push_cur_state(&ike->sa);
	}

	/*
	 * Now that cur-state has been set for logging, log if this
	 * packet is really bogus.
	 */
	if (md->fake_clone) {
		libreswan_log("IMPAIR: processing a fake (cloned) message");
	}

	/*
	 * Check ST's IKE SA's role against the I(Initiator) flag in
	 * the headers.  Since above searches require the correct IKE
	 * role, this should always work.
	 */
	if (ike != NULL && !pexpect(ike->sa.st_sa_role == local_ike_role)) {
		return;
	}

	/*
	 * Deal with duplicate messages and busy states.  Update ST so
	 * it points at the state that will process the message.
	 */
	if (ike != NULL) {
		switch (v2_msg_role(md)) {
		case MESSAGE_REQUEST:
			/*
			 * If ST!=NULL then there is a state
			 * processing MSGID and the message should be
			 * dropped.  But if ST is accumulating
			 * fragments, then things need to keep going.
			 */
			if (is_duplicate_request(ike, st, md)) {
				return;
			}
			/* The IKE SA always processes requests. */
			st = &ike->sa;
			break;
		case MESSAGE_RESPONSE:
			if (is_duplicate_response(ike, st, md)) {
				return;
			}
			break;
		default:
			bad_case(v2_msg_role(md));
		}
	}

	/*
	 * If not already done above in the IKE_SA_INIT responder code
	 * path, decode the packet now.
	 */
	if (!md->message_payloads.parsed) {
		dbg("unpacking clear payload");
		pexpect(v2_msg_role(md) == MESSAGE_RESPONSE ||
			md->hdr.isa_xchg != ISAKMP_v2_IKE_SA_INIT);
		md->message_payloads =
			ikev2_decode_payloads(md, &md->message_pbs,
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

	if (md->hdr.isa_xchg == ISAKMP_v2_IKE_SA_INIT &&
	    v2_msg_role(md) == MESSAGE_RESPONSE) {
		if (pexpect(md->hdr.isa_msgid == 0) &&
		    pexpect(ike != NULL)) {
			/*
			 * Responder provided a cookie, record it.
			 *
			 * XXX: This is being done far too early.  The
			 * packet should first get some validation.
			 * It might also be an INVALID_KE or COOKIE
			 * response in which case SPIr shouldn't be
			 * updated at all.
			 *
			 * XXX: Previously this was being done even
			 * earlier - as part of the code above looking
			 * for IKE SA initiator.  At least by moving
			 * it here it is delayed until after other
			 * processing has completed.
			 */
			rehash_state(&ike->sa, &md->hdr.isa_ike_responder_spi);
		}
	}

	/*
	 * Flag the state as responding to a request.
	 *
	 * The processing completes once the response has been sent
	 * out, or things die and the state is deleted, or there's an
	 * STF_IGNORE and the response is cancelled (for instance an
	 * encrypted packet is corrupt).
	 *
	 * If the state is collecting fragments then it will have been
	 * here before.  Hence the extra filter.  Is there something
	 * better?
	 */
	if (st != NULL && v2_msg_role(md) == MESSAGE_REQUEST &&
	    st->st_v2_rfrags == NULL) {
		v2_msgid_start_responder(ike, st, md);
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
	const struct finite_state *from_state =
		st == NULL ? finite_states[STATE_PARENT_R0] : st->st_state;
	dbg("#%lu in state %s: %s",
	     st != NULL ? st->st_serialno : 0,
	     from_state->short_name, from_state->story);

	struct ikev2_payload_errors message_payload_status = { .bad = false };
	struct ikev2_payload_errors encrypted_payload_status = { .bad = false };

	const enum isakmp_xchg_types ix = (*mdp)->hdr.isa_xchg;

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
		 * Does the original [ike] initiator flag match?
		 */
		if (svm->flags & SMF2_IKE_I_SET) {
			if ((md->hdr.isa_flags & ISAKMP_FLAGS_v2_IKE_I) == 0)
				/* opps, clear */
				continue;
		}
		if (svm->flags & SMF2_IKE_I_CLEAR) {
			if ((md->hdr.isa_flags & ISAKMP_FLAGS_v2_IKE_I) != 0)
				/* opps, set */
				continue;
		}
		/*
		 * Does the message reply flag match?
		 */
		if (svm->flags & SMF2_MSG_R_SET) {
			if ((md->hdr.isa_flags & ISAKMP_FLAGS_v2_MSG_R) == 0)
				/* oops, clear */
				continue;
		}
		if (svm->flags & SMF2_MSG_R_CLEAR) {
			if ((md->hdr.isa_flags & ISAKMP_FLAGS_v2_MSG_R) != 0)
				/* opps, set */
				continue;
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
		 * SK payloads require state.
		 */
		passert(st != NULL);

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
				libreswan_log("encrypted payload seems to be corrupt; dropping packet");
				/*
				 * XXX: Setting/clearing md->st is to
				 * prop up nested code needing ST but
				 * not having it as a parameter.
				 */
				md->st = st;
				/* replace (*mdp)->st with st ... */
				complete_v2_state_transition((*mdp)->st, mdp, STF_IGNORE);
				return;
			}
			/*
			 * Unpack the protected (but possibly not
			 * authenticated) contents.
			 *
			 * When unpacking an AUTH packet, the other
			 * end hasn't yet been authenticated (and an
			 * INFORMATIONAL exchange immediately
			 * following AUTH be due to failed
			 * authentication).
			 *
			 * If there's something wrong, then the IKE SA
			 * gets abandoned, but a new new one may be
			 * initiated.
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
			 * For moment treat it the same ?!?!?!.  Given
			 * the PAYLOAD ID that should identify the
			 * problem isn't being returned this is the
			 * least of our problems.
			 */
			struct payload_digest *sk = md->chain[ISAKMP_NEXT_v2SK];
			md->encrypted_payloads = ikev2_decode_payloads(md, &sk->pbs,
								       sk->payload.generic.isag_np);
			if (md->encrypted_payloads.n != v2N_NOTHING_WRONG) {
				switch (v2_msg_role(md)) {
				case MESSAGE_REQUEST:
				{
					chunk_t data = chunk(md->encrypted_payloads.data,
							     md->encrypted_payloads.data_size);
					send_v2N_response_from_state(ike_sa(st), *mdp,
								     md->encrypted_payloads.n,
								     &data);
					break;
				}
				case MESSAGE_RESPONSE:
					/* drop packet */
					break;
				default:
					bad_case(v2_msg_role(md));
				}
				/*
				 * XXX: Setting/clearing md->st is to
				 * prop up nested code needing ST but
				 * not having it as a parameter.
				 */
				md->st = st;
				/* replace (*mdp)->st with st ... */
				complete_v2_state_transition((*mdp)->st, mdp, STF_FATAL);
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
			    enum_short_name(&state_names, svm->state),
			    enum_short_name(&state_names, svm->next_state));
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
				pexpect(st == NULL || st->st_v2_msgid_wip.responder == 0);
				send_v2N_response_from_md(md, v2N_INVALID_SYNTAX, NULL);
				complete_v2_state_transition(st, mdp, STF_FATAL);
			} else {
				complete_v2_state_transition(st, mdp, STF_IGNORE);
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
			 */
			log_v2_payload_errors(st, md, &encrypted_payload_status);
			if (v2_msg_role(md) == MESSAGE_REQUEST) {
				send_v2N_response_from_state(ike, md, v2N_INVALID_SYNTAX, NULL);
			}
			complete_v2_state_transition(st, mdp, STF_FATAL);
			return;
		}
		if (st == NULL && v2_msg_role(md) == MESSAGE_REQUEST &&
		    md->hdr.isa_xchg != ISAKMP_v2_IKE_SA_INIT) {
			rate_log(md, "responding to message with unknown IKE SPI with INVALID_IKE_SPI");
			/*
			 * Lets assume "2.21.4.  Error Handling
			 * Outside IKE SA" - we MAY respond.
			 *
			 * XXX: how can one complete a state
			 * transition on something that was never
			 * started?
			 *
			 * XXX: is this ever reached?  All exchanges
			 * after IKE_SA_INIT _must_ find an IKE SA,
			 * else they get tossed much earlier in code
			 * above.
			 */
			send_v2N_response_from_md(md, v2N_INVALID_IKE_SPI,
						  NULL/*no data*/);
			return;
		}
		if (st != NULL) {
			/*
			 * Presumably things are pretty messed up.
			 * While there might be a state there probably
			 * isn't an established IKE SA (so don't even
			 * consider trying to send an encrypted
			 * response), for instance:
			 *
			 * - instead of an IKE_AUTH request, the
			 * initiator sends something totally
			 * unexpected (such as an informational) and
			 * things end up here
			 *
			 * - when an IKE_AUTH request's IKE SA
			 * succeeeds but CHILD SA fails (and pluto
			 * screws up the IKE SA by updating its state
			 * but not its Message ID and not responding),
			 * the re-transmitted IKE_AUTH ends up here
			 *
			 * If a request, should it send an
			 * un-encrypted v2N_INVALID_SYNTAX?
			 */
			libreswan_log("no useful state microcode entry found for incoming packet");
			/* "dropping message with no matching microcode" */
			complete_v2_state_transition(st, mdp, STF_IGNORE);
			return;
		}
		/* XXX: ever reached? */
		libreswan_log("no useful state microcode entry found for incoming packet");
		return;
	}

	md->from_state = svm->state;
	md->svm = svm;

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
			child = process_v2_child_ix(md, ike);
			v2_msgid_switch_responder(ike, child, md);
		}

		/*
		 * Switch to child state (possibly from the same child
		 * state, see above)
		 */
		dbg("forcing ST #%lu to CHILD #%lu.#%lu in FSM processor",
		    st->st_serialno, ike->sa.st_serialno, child->sa.st_serialno);
		st = &child->sa;
	}

	md->st = st;

	DBG(DBG_CONTROL,
	    DBG_log("Now let's proceed with state specific processing"));

	DBG(DBG_PARSING, {
		    if (pbs_left(&md->message_pbs) != 0)
			    DBG_log("removing %d bytes of padding",
				    (int) pbs_left(&md->message_pbs));
	    });

	md->message_pbs.roof = md->message_pbs.cur;	/* trim padding (not actually legit) */

	DBG(DBG_CONTROL,
	    DBG_log("calling processor %s", svm->story));

	/*
	 * XXX: the initial responder has ST==NULL!  But that's ok as
	 * statetime_start() will fudge up a statetime_t for the
	 * not-yet-created state.
	 */
	statetime_t start = statetime_start(st);
	stf_status e = svm->processor(st, md);
	statetime_stop(&start, "processing: %s", svm->story);

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
			if (initiator) {
				/* cannot switch connection so fail */
				libreswan_log("X509: CERT payload does not match connection ID");
				return FALSE;
			} else {
				dbg("X509: CERT payload does not match connection ID");
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
			char expect[IDTOA_BUF],
			     found[IDTOA_BUF];

			idtoa(&c->spd.that.id, expect, sizeof(expect));
			idtoa(&peer_id, found, sizeof(found));
			loglog(RC_LOG_SERIOUS,
				"we require IKEv2 peer to have ID '%s', but peer declares '%s'",
				expect, found);
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
		uint16_t auth = md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2a.isaa_type;
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

			if (authby != AUTH_NULL) {
				r = refine_host_connection(
					md->st, &peer_id, tip, FALSE /*initiator*/,
					LEMPTY /* auth_policy */, authby, &fromcert);
			}

			if (r == NULL) {
				/* no "improvement" on c found */
				char buf[IDTOA_BUF];

				idtoa(&peer_id, buf, sizeof(buf));
				DBG(DBG_CONTROL, DBG_log(
					"no suitable connection for peer '%s'", buf));
				/* can we continue with what we had? */
				if (!ike->sa.st_peer_alt_id &&
				    !same_id(&c->spd.that.id, &peer_id) &&
				    c->spd.that.id.kind != ID_FROMCERT)
				{
					if (LIN(POLICY_AUTH_NULL, c->policy) &&
					    tip != NULL && tip->kind == ID_NULL) {
						libreswan_log("Peer ID '%s' expects us to have ID_NULL and connection allows AUTH_NULL - allowing",
							buf);
						ike->sa.st_peer_wants_null = TRUE;
					} else {
						libreswan_log("Peer ID '%s' mismatched on first found connection and no better connection found",
							buf);
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

	char idbuf[IDTOA_BUF];

	DBG(DBG_CONTROL, {
		dntoa_or_null(idbuf, IDTOA_BUF, c->spd.this.ca, "%none");
		DBG_log("offered CA: '%s'", idbuf);
	});

	idtoa(&peer_id, idbuf, sizeof(idbuf));

	if (!(c->policy & POLICY_OPPORTUNISTIC)) {
		libreswan_log("IKEv2 mode peer ID is %s: '%s'",
			enum_show(&ikev2_idtype_names, hik),
			idbuf);
	} else {
		DBG(DBG_OPPO, DBG_log("IKEv2 mode peer ID is %s: '%s'",
			enum_show(&ikev2_idtype_names, hik),
			idbuf));
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
		free_chunk_contents(&ai);

		/* v2 IKE encryption key for initiator (256 bit bound) */
		chunk_t ei = chunk_from_symkey("ei", st->st_skey_ei_nss);
		char tei[3 + 2 * BYTES_FOR_BITS(256)] = "";
		(void)datatot(ei.ptr, ei.len, 'x', tei, sizeof(tei));
		free_chunk_contents(&ei);

		DBG_log("ikev2 I %s %s %s:%s %s%s:%s",
			tispi, trspi,
			authalgo, tai,
			encalgo, tekl, tei);

		/* v2 IKE authentication key for responder (256 bit bound) */
		chunk_t ar = chunk_from_symkey("ar", st->st_skey_ar_nss);
		char tar[3 + 2 * BYTES_FOR_BITS(256)] = "";
		(void)datatot(ar.ptr, ar.len, 'x', tar, sizeof(tar));
		free_chunk_contents(&ar);

		/* v2 IKE encryption key for responder (256 bit bound) */
		chunk_t er = chunk_from_symkey("er", st->st_skey_er_nss);
		char ter[3 + 2 * BYTES_FOR_BITS(256)] = "";
		(void)datatot(er.ptr, er.len, 'x', ter, sizeof(ter));
		free_chunk_contents(&er);

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

static void ikev2_child_emancipate(struct msg_digest *md)
{
	/* st grow up to be an IKE parent. not child anymore.  */

	struct child_sa *to = pexpect_child_sa(md->st);
	struct ike_sa *from = ike_sa(md->st);

	/* initialze the the new IKE SA. reset and message ID */
	to->sa.st_clonedfrom = SOS_NOBODY;
	v2_msgid_init_ike(pexpect_ike_sa(&to->sa));

	/* Switch to the new IKE SPIs */
	to->sa.st_ike_spis = to->sa.st_ike_rekey_spis;
	rehash_state_cookies_in_db(&to->sa);

	/* TO has correct IKE_SPI so can migrate */
	v2_migrate_children(from, to);

	/* child is now a parent */
	ikev2_ike_sa_established(pexpect_ike_sa(&to->sa), md->svm,
				 md->svm->next_state);
}

static void success_v2_state_transition(struct state *st, struct msg_digest *md)
{
	const struct state_v2_microcode *svm = md->svm;
	enum state_kind from_state = md->from_state;
	struct connection *c = st->st_connection;
	struct state *pst;
	enum rc_type w;
	struct ike_sa *ike = ike_sa(st);

	pst = IS_CHILD_SA(st) ? state_with_serialno(st->st_clonedfrom) : st;

	if (from_state != svm->next_state) {
		DBG(DBG_CONTROL, DBG_log("IKEv2: transition from state %s to state %s",
			      enum_name(&state_names, from_state),
			      enum_name(&state_names, svm->next_state)));
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
		dbg("Message ID: updating counters for #%lu to "PRI_MSGID" before emancipating",
		    md->st->st_serialno, md->hdr.isa_msgid);
		v2_msgid_update_recv(ike_sa(st), st, md);
		v2_msgid_update_sent(ike_sa(st), st, md, svm->send);
		/*
		 * XXX: should this be merged with the code sending
		 * with transitions message?  And do this before ST
		 * turns into its own IKE.
		 */
		v2_msgid_schedule_next_initiator(ike);
		ikev2_child_emancipate(md);
	} else  {
		/*
		 * XXX: need to change state before updating Message
		 * IDs as that is what the update function expects
		 * (this is not a good reason).
		 */
		change_state(st, svm->next_state);
		dbg("Message ID: updating counters for #%lu to "PRI_MSGID" after switching state",
		    md->st->st_serialno, md->hdr.isa_msgid);
		v2_msgid_update_recv(ike_sa(st), st, md);
		v2_msgid_update_sent(ike_sa(st), st, md, svm->send);
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

	if (svm->flags & SMF2_ESTABLISHED) {
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
	if ((svm->flags & SMF2_SUPPRESS_SUCCESS_LOG) ||
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
	if (svm->send != NO_MESSAGE) {
		/*
		 * Adjust NAT but not for initial state (initial
		 * outbound message?).
		 *
		 * ??? why should STATE_PARENT_I1 be excluded?  XXX:
		 * and why, for that state, does ikev2_natd_lookup()
		 * call it.
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
		 */
		bool new_request = (from_state == STATE_PARENT_I0 ||
				    from_state == STATE_V2_CREATE_I0 ||
				    from_state == STATE_V2_REKEY_CHILD_I0 ||
				    from_state == STATE_V2_REKEY_IKE_I0);
		if (nat_traversal_enabled &&
		    !new_request &&
		    from_state != STATE_PARENT_R0 &&
		    from_state != STATE_PARENT_I1) {
			/* adjust our destination port if necessary */
			nat_traversal_change_port_lookup(md, pst);
		}

		ipstr_buf b;
		endpoint_buf b2;
		pexpect_iface_port(st->st_interface);
		dbg("sending V2 %s packet to %s:%u (from %s)",
		    new_request ? "new request" :
		    "reply", ipstr(&st->st_remoteaddr, &b),
		    st->st_remoteport,
		    str_endpoint(&st->st_interface->local_endpoint, &b2));

		send_recorded_v2_ike_msg(pst, enum_name(&state_names, from_state));
	}

	if (w == RC_SUCCESS) {
		DBG(DBG_CONTROL, DBG_log("releasing whack for #%lu (sock="PRI_FD")",
					 st->st_serialno, PRI_fd(st->st_whack_sock)));
		release_whack(st);

		/* XXX should call unpend again on parent SA */
		if (IS_CHILD_SA(st)) {
			/* with failed child sa, we end up here with an orphan?? */
			struct state *pst = state_with_serialno(st->st_clonedfrom);

			DBG(DBG_CONTROL, DBG_log("releasing whack and unpending for parent #%lu",
				pst->st_serialno));
			/* a better call unpend in ikev2_ike_sa_established? */
			unpend(pst, st->st_connection);
			release_whack(pst);
		}
	}

	/* Schedule for whatever timeout is specified */
	{
		enum event_type kind = svm->timeout_event;
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
			DBG_log("V2 microcode entry (%s) has unspecified timeout_event",
					svm->story);
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
	struct ike_sa *ike = ike_sa(st);

	/*
	 * XXX; If MD.ST is set, make certain it is consistent with
	 * ST.  Eventually .ST will become v1 only be deleted.
	 */
	pexpect(mdp == NULL ||
		*mdp == NULL ||
		(*mdp)->st == NULL ||
		(*mdp)->st == st);

	/* statistics */
	/* this really depends on the type of error whether it is an IKE or IPsec fail */
	if (result > STF_FAIL) {
		pstats(ike_stf, STF_FAIL);
	} else {
		pstats(ike_stf, result);
	}

	/*
	 * Since this is a state machine, there really should always
	 * be a state.
	 *
	 * Unfortunately #1: instead of always having a state and
	 * passing it round, state transition functions create the
	 * state locally and then try to tunnel it back using the
	 * received message's digest - *MDP->st.  The big offenders
	 * are IKE_SA_INIT and IKE_AUTH reponders
	 *
	 * Unfortunately #2: the initiator of an exchange doesn't have
	 * a received message's digest, but that's ok one is sometimes
	 * created using fake_md().
	 *
	 * Hence, expect any of MDP, *MDP, or *MDP->st to be NULL.
	 */
	struct msg_digest *md = (mdp != NULL ? (*mdp) /*NULL?*/ : NULL);
	set_cur_state(st); /* might have changed */ /* XXX: huh? */
	/* get the from state */
	const struct finite_state *from_state = (st != NULL ? st->st_state
						 : finite_states[STATE_UNDEFINED]);
	const char *from_state_name = from_state->name;

	/*
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

	LSWDBGP(DBG_BASE, buf) {
		lswlogf(buf, "#%lu complete_v2_state_transition()",
			(st == NULL ? SOS_NOBODY : st->st_serialno));
		if (md != NULL && md->from_state != STATE_UNDEFINED/*0?*/ &&
		    md->from_state != from_state->kind) {
			jam(buf, " md.from_state=");
			lswlog_enum_short(buf, &state_names, md->from_state);
		}
		if (md != NULL && md->svm != NULL &&
		    md->svm->state != from_state->kind) {
			jam(buf, " md.svm.state[from]=");
			lswlog_enum_short(buf, &state_names, md->svm->state);
		}
		jam(buf, " %s->", from_state->short_name);
		if (md != NULL && md->svm != NULL) {
			lswlog_enum_short(buf, &state_names, md->svm->next_state);
		} else {
			jam(buf, "NULL");
		}
		lswlogf(buf, " with status ");
		lswlog_v2_stf_status(buf, result);
	}

	/* audit log failures - success is audit logged in ikev2_ike_sa_established() */
	if (result > STF_OK) {
		pexpect(st != NULL); /* we really need this for logging details */
		if (st != NULL) {
			linux_audit_conn(st, IS_IKE_SA_ESTABLISHED(st) ? LAK_CHILD_FAIL : LAK_PARENT_FAIL);
		}
	}

	switch (result) {

	case STF_SUSPEND:
		if (pexpect(st != NULL)) {
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
		}
		return;

	case STF_IGNORE:
		/* logged above */
		if (pexpect(st != NULL) && pexpect(md != NULL)) {
			if (v2_msg_role(md) == MESSAGE_REQUEST) {
				v2_msgid_cancel_responder(ike, st, md);
			}
		}
		return;

	case STF_OK:
		if (st == NULL) {
			/* this happens for the successful transition of STATE_IKESA_DEL */
			DBG(DBG_CONTROL, DBG_log("STF_OK but no state object remains"));
		} else {
			/* advance the state */
			success_v2_state_transition(st, md);
		}
		break;

	case STF_INTERNAL_ERROR:
		whack_log(RC_INTERNALERR, "%s: internal error",
			  from_state_name);

		DBG(DBG_CONTROL,
		    DBG_log("state transition function for %s had internal error",
			    from_state_name));
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
		release_pending_whacks(st, "fatal error");
		delete_state(st);
		md->st = st = NULL;
		break;

	default:
		passert(result >= STF_FAIL);
		v2_notification_t notification = result > STF_FAIL ?
			result - STF_FAIL : v2N_NOTHING_WRONG;
		whack_log(RC_NOTIFICATION + notification,
			  "%s: %s",
			  from_state_name,
			  enum_name(&ikev2_notify_names, notification));

		if (notification != v2N_NOTHING_WRONG) {
			/*
			 * XXX: For IKEv2, this code path isn't
			 * sufficient - a message request can result
			 * in a response that contains both a success
			 * and a fail.  Better to respond directly; or
			 * better still, record the response and send
			 * using that - look for comments about
			 * STF_ZOMBIFY.
			 */
			/* Only the responder sends a notification */
			if (!(md->hdr.isa_flags & ISAKMP_FLAGS_v2_MSG_R)) {
				struct state *pst = st;

				DBG(DBG_CONTROL, DBG_log("sending a notification reply"));
				/* We are the exchange responder */
				if (st != NULL && IS_CHILD_SA(st)) {
					pst = state_with_serialno(
							st->st_clonedfrom);
				}

				if (st == NULL) {
					send_v2N_response_from_md(md, notification, NULL);
				} else {
					send_v2N_response_from_state(ike_sa(pst), md,
								     notification,
								     NULL/*no data*/);
					if (md->hdr.isa_xchg == ISAKMP_v2_IKE_SA_INIT) {
						delete_state(st);
					} else {
						dbg("forcing #%lu to a discard event",
						    st->st_serialno);
						delete_event(st);
						event_schedule_s(EVENT_SO_DISCARD,
								 MAXIMUM_RESPONDER_WAIT,
								 st);
					}
				}
			}
		}

		DBG(DBG_CONTROL,
		    DBG_log("state transition function for %s failed: %s",
			    from_state_name,
			    notification == v2N_NOTHING_WRONG ?
				"<no reason given>" :
				enum_name(&ikev2_notify_names, notification)));
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
	free_chunk_contents(dest);
	*dest = clone_in_pbs_left_as_chunk(nonce_pbs, "nonce");
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
#include "kernel.h"
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
