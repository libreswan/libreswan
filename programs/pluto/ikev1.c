/* State machine for IKEv1
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010,2013-2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2011 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2008 Hiren Joshi <joshihirenn@gmail.com>
 * Copyright (C) 2009 Anthony Tong <atong@TrustedCS.com>
 * Copyright (C) 2012-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

/* Ordering Constraints on Payloads
 *
 * rfc2409: The Internet Key Exchange (IKE)
 *
 * 5 Exchanges:
 *   "The SA payload MUST precede all other payloads in a phase 1 exchange."
 *
 *   "Except where otherwise noted, there are no requirements for ISAKMP
 *    payloads in any message to be in any particular order."
 *
 * 5.3 Phase 1 Authenticated With a Revised Mode of Public Key Encryption:
 *
 *   "If the HASH payload is sent it MUST be the first payload of the
 *    second message exchange and MUST be followed by the encrypted
 *    nonce. If the HASH payload is not sent, the first payload of the
 *    second message exchange MUST be the encrypted nonce."
 *
 *   "Save the requirements on the location of the optional HASH payload
 *    and the mandatory nonce payload there are no further payload
 *    requirements. All payloads-- in whatever order-- following the
 *    encrypted nonce MUST be encrypted with Ke_i or Ke_r depending on the
 *    direction."
 *
 * 5.5 Phase 2 - Quick Mode
 *
 *   "In Quick Mode, a HASH payload MUST immediately follow the ISAKMP
 *    header and a SA payload MUST immediately follow the HASH."
 *   [NOTE: there may be more than one SA payload, so this is not
 *    totally reasonable.  Probably all SAs should be so constrained.]
 *
 *   "If ISAKMP is acting as a client negotiator on behalf of another
 *    party, the identities of the parties MUST be passed as IDci and
 *    then IDcr."
 *
 *   "With the exception of the HASH, SA, and the optional ID payloads,
 *    there are no payload ordering restrictions on Quick Mode."
 */

/* Unfolding of Identity -- a central mystery
 *
 * This concerns Phase 1 identities, those of the IKE hosts.
 * These are the only ones that are authenticated.  Phase 2
 * identities are for IPsec SAs.
 *
 * There are three case of interest:
 *
 * (1) We initiate, based on a whack command specifying a Connection.
 *     We know the identity of the peer from the Connection.
 *
 * (2) (to be implemented) we initiate based on a flow from our client
 *     to some IP address.
 *     We immediately know one of the peer's client IP addresses from
 *     the flow.  We must use this to figure out the peer's IP address
 *     and Id.  To be solved.
 *
 * (3) We respond to an IKE negotiation.
 *     We immediately know the peer's IP address.
 *     We get an ID Payload in Main I2.
 *
 *     Unfortunately, this is too late for a number of things:
 *     - the ISAKMP SA proposals have already been made (Main I1)
 *       AND one accepted (Main R1)
 *     - the SA includes a specification of the type of ID
 *       authentication so this is negotiated without being told the ID.
 *     - with Preshared Key authentication, Main I2 is encrypted
 *       using the key, so it cannot be decoded to reveal the ID
 *       without knowing (or guessing) which key to use.
 *
 *     There are three reasonable choices here for the responder:
 *     + assume that the initiator is making wise offers since it
 *       knows the IDs involved.  We can balk later (but not gracefully)
 *       when we find the actual initiator ID
 *     + attempt to infer identity by IP address.  Again, we can balk
 *       when the true identity is revealed.  Actually, it is enough
 *       to infer properties of the identity (eg. SA properties and
 *       PSK, if needed).
 *     + make all properties universal so discrimination based on
 *       identity isn't required.  For example, always accept the same
 *       kinds of encryption.  Accept Public Key Id authentication
 *       since the Initiator presumably has our public key and thinks
 *       we must have / can find his.  This approach is weakest
 *       for preshared key since the actual key must be known to
 *       decrypt the Initiator's ID Payload.
 *     These choices can be blended.  For example, a class of Identities
 *     can be inferred, sufficient to select a preshared key but not
 *     sufficient to infer a unique identity.
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
#include "ikev1_msgid.h"
#include "packet.h"
#include "crypto.h"
#include "ike_alg.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */
#include "ikev1.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "ikev1_quick.h"
#include "timer.h"
#include "whack.h"      /* requires connections.h */
#include "server.h"
#include "send.h"
#include "ikev1_send.h"
#include "ikev1_xauth.h"
#include "retransmit.h"
#include "nat_traversal.h"
#include "vendor.h"
#include "ikev1_dpd.h"
#include "hostpair.h"
#include "ip_address.h"

#ifdef HAVE_NM
#include "kernel.h"
#endif

#include "pluto_stats.h"

/*
 * state_v1_microcode is a tuple of information parameterizing certain
 * centralized processing of a packet.  For example, it roughly
 * specifies what payloads are expected in this message.  The
 * microcode is selected primarily based on the state.  In Phase 1,
 * the payload structure often depends on the authentication
 * technique, so that too plays a part in selecting the
 * state_v1_microcode to use.
 */

struct state_v1_microcode {
	enum state_kind state, next_state;
	lset_t flags;
	lset_t req_payloads;    /* required payloads (allows just one) */
	lset_t opt_payloads;    /* optional payloads (any mumber) */
	enum event_type timeout_event;
	ikev1_state_transition_fn *processor;
};

/* State Microcode Flags, in several groups */

/* Oakley Auth values: to which auth values does this entry apply?
 * Most entries will use SMF_ALL_AUTH because they apply to all.
 * Note: SMF_ALL_AUTH matches 0 for those circumstances when no auth
 * has been set.
 */
#define SMF_ALL_AUTH    LRANGE(0, OAKLEY_AUTH_ROOF - 1)
#define SMF_PSK_AUTH    LELEM(OAKLEY_PRESHARED_KEY)
#define SMF_DS_AUTH     (LELEM(OAKLEY_DSS_SIG) | LELEM(OAKLEY_RSA_SIG))
#define SMF_PKE_AUTH    LELEM(OAKLEY_RSA_ENC)
#define SMF_RPKE_AUTH   LELEM(OAKLEY_RSA_REVISED_MODE)

/* misc flags */
#define SMF_INITIATOR   LELEM(OAKLEY_AUTH_ROOF + 0)
#define SMF_FIRST_ENCRYPTED_INPUT       LELEM(OAKLEY_AUTH_ROOF + 1)
#define SMF_INPUT_ENCRYPTED     LELEM(OAKLEY_AUTH_ROOF + 2)
#define SMF_OUTPUT_ENCRYPTED    LELEM(OAKLEY_AUTH_ROOF + 3)
#define SMF_RETRANSMIT_ON_DUPLICATE     LELEM(OAKLEY_AUTH_ROOF + 4)

#define SMF_ENCRYPTED (SMF_INPUT_ENCRYPTED | SMF_OUTPUT_ENCRYPTED)

/* this state generates a reply message */
#define SMF_REPLY   LELEM(OAKLEY_AUTH_ROOF + 5)

/* this state completes P1, so any pending P2 negotiations should start */
#define SMF_RELEASE_PENDING_P2  LELEM(OAKLEY_AUTH_ROOF + 6)

/* if we have canoncalized the authentication from XAUTH mode */
#define SMF_XAUTH_AUTH  LELEM(OAKLEY_AUTH_ROOF + 7)

/* end of flags */

static ikev1_state_transition_fn unexpected;      /* forward declaration */
static ikev1_state_transition_fn informational;      /* forward declaration */

/*
 * v1_state_microcode_table is a table of all state_v1_microcode
 * tuples.  It must be in order of state (the first element).  After
 * initialization, ike_microcode_index[s] points to the first entry in
 * v1_state_microcode_table for state s.  Remember that each state
 * name in Main or Quick Mode describes what has happened in the past,
 * not what this message is.
 */

static const struct state_v1_microcode v1_state_microcode_table[] = {

#define P(n) LELEM(ISAKMP_NEXT_ ##n)

	/***** Phase 1 Main Mode *****/

	/* No state for main_outI1: --> HDR, SA */

	/* STATE_MAIN_R0: I1 --> R1
	 * HDR, SA --> HDR, SA
	 */
	{ STATE_MAIN_R0, STATE_MAIN_R1,
	  SMF_ALL_AUTH | SMF_REPLY,
	  P(SA), P(VID) | P(CR),
	  EVENT_SO_DISCARD, main_inI1_outR1 },

	/* STATE_MAIN_I1: R1 --> I2
	 * HDR, SA --> auth dependent
	 * SMF_PSK_AUTH, SMF_DS_AUTH: --> HDR, KE, Ni
	 * SMF_PKE_AUTH:
	 *	--> HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
	 * SMF_RPKE_AUTH:
	 *	--> HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i, <IDi1_b>Ke_i [,<<Cert-I_b>Ke_i]
	 * Note: since we don't know auth at start, we cannot differentiate
	 * microcode entries based on it.
	 */
	{ STATE_MAIN_I1, STATE_MAIN_I2,
	  SMF_ALL_AUTH | SMF_INITIATOR | SMF_REPLY,
	  P(SA), P(VID) | P(CR),
	  EVENT_v1_RETRANSMIT, main_inR1_outI2 },

	/* STATE_MAIN_R1: I2 --> R2
	 * SMF_PSK_AUTH, SMF_DS_AUTH: HDR, KE, Ni --> HDR, KE, Nr
	 * SMF_PKE_AUTH: HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
	 *	    --> HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
	 * SMF_RPKE_AUTH:
	 *	    HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i, <IDi1_b>Ke_i [,<<Cert-I_b>Ke_i]
	 *	    --> HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r
	 */
	{ STATE_MAIN_R1, STATE_MAIN_R2,
	  SMF_PSK_AUTH | SMF_DS_AUTH | SMF_REPLY | SMF_RETRANSMIT_ON_DUPLICATE,
	  P(KE) | P(NONCE), P(VID) | P(CR) | P(NATD_RFC),
	  EVENT_v1_RETRANSMIT, main_inI2_outR2 },

	{ STATE_MAIN_R1, STATE_UNDEFINED,
	  SMF_PKE_AUTH | SMF_REPLY | SMF_RETRANSMIT_ON_DUPLICATE,
	  P(KE) | P(ID) | P(NONCE), P(VID) | P(CR) | P(HASH),
	  EVENT_v1_RETRANSMIT, unexpected /* ??? not yet implemented */ },

	{ STATE_MAIN_R1, STATE_UNDEFINED,
	  SMF_RPKE_AUTH | SMF_REPLY | SMF_RETRANSMIT_ON_DUPLICATE,
	  P(NONCE) | P(KE) | P(ID), P(VID) | P(CR) | P(HASH) | P(CERT),
	  EVENT_v1_RETRANSMIT, unexpected /* ??? not yet implemented */ },

	/* for states from here on, output message must be encrypted */

	/* STATE_MAIN_I2: R2 --> I3
	 * SMF_PSK_AUTH: HDR, KE, Nr --> HDR*, IDi1, HASH_I
	 * SMF_DS_AUTH: HDR, KE, Nr --> HDR*, IDi1, [ CERT, ] SIG_I
	 * SMF_PKE_AUTH: HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
	 *	    --> HDR*, HASH_I
	 * SMF_RPKE_AUTH: HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r
	 *	    --> HDR*, HASH_I
	 */
	{ STATE_MAIN_I2, STATE_MAIN_I3,
	  SMF_PSK_AUTH | SMF_DS_AUTH | SMF_INITIATOR | SMF_OUTPUT_ENCRYPTED | SMF_REPLY,
	  P(KE) | P(NONCE), P(VID) | P(CR) | P(NATD_RFC),
	  EVENT_v1_RETRANSMIT, main_inR2_outI3 },

	{ STATE_MAIN_I2, STATE_UNDEFINED,
	  SMF_PKE_AUTH | SMF_INITIATOR | SMF_OUTPUT_ENCRYPTED | SMF_REPLY,
	  P(KE) | P(ID) | P(NONCE), P(VID) | P(CR),
	  EVENT_v1_RETRANSMIT, unexpected /* ??? not yet implemented */ },

	{ STATE_MAIN_I2, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_INITIATOR | SMF_OUTPUT_ENCRYPTED | SMF_REPLY,
	  P(NONCE) | P(KE) | P(ID), P(VID) | P(CR),
	  EVENT_v1_RETRANSMIT, unexpected /* ??? not yet implemented */ },

	/* for states from here on, input message must be encrypted */

	/* STATE_MAIN_R2: I3 --> R3
	 * SMF_PSK_AUTH: HDR*, IDi1, HASH_I --> HDR*, IDr1, HASH_R
	 * SMF_DS_AUTH: HDR*, IDi1, [ CERT, ] SIG_I --> HDR*, IDr1, [ CERT, ] SIG_R
	 * SMF_PKE_AUTH, SMF_RPKE_AUTH: HDR*, HASH_I --> HDR*, HASH_R
	 */
	{ STATE_MAIN_R2, STATE_MAIN_R3,
	  SMF_PSK_AUTH | SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED |
		SMF_REPLY | SMF_RELEASE_PENDING_P2,
	  P(ID) | P(HASH), P(VID) | P(CR),
	  EVENT_SA_REPLACE, main_inI3_outR3 },

	{ STATE_MAIN_R2, STATE_MAIN_R3,
	  SMF_DS_AUTH | SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED |
		SMF_REPLY | SMF_RELEASE_PENDING_P2,
	  P(ID) | P(SIG), P(VID) | P(CR) | P(CERT),
	  EVENT_SA_REPLACE, main_inI3_outR3 },

	{ STATE_MAIN_R2, STATE_UNDEFINED,
	  SMF_PKE_AUTH | SMF_RPKE_AUTH | SMF_FIRST_ENCRYPTED_INPUT |
		SMF_ENCRYPTED |
		SMF_REPLY | SMF_RELEASE_PENDING_P2,
	  P(HASH), P(VID) | P(CR),
	  EVENT_SA_REPLACE, unexpected /* ??? not yet implemented */ },

	/* STATE_MAIN_I3: R3 --> done
	 * SMF_PSK_AUTH: HDR*, IDr1, HASH_R --> done
	 * SMF_DS_AUTH: HDR*, IDr1, [ CERT, ] SIG_R --> done
	 * SMF_PKE_AUTH, SMF_RPKE_AUTH: HDR*, HASH_R --> done
	 * May initiate quick mode by calling quick_outI1
	 */
	{ STATE_MAIN_I3, STATE_MAIN_I4,
	  SMF_PSK_AUTH | SMF_INITIATOR |
		SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED | SMF_RELEASE_PENDING_P2,
	  P(ID) | P(HASH), P(VID) | P(CR),
	  EVENT_SA_REPLACE, main_inR3 },

	{ STATE_MAIN_I3, STATE_MAIN_I4,
	  SMF_DS_AUTH | SMF_INITIATOR |
		SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED | SMF_RELEASE_PENDING_P2,
	  P(ID) | P(SIG), P(VID) | P(CR) | P(CERT),
	  EVENT_SA_REPLACE, main_inR3 },

	{ STATE_MAIN_I3, STATE_UNDEFINED,
	  SMF_PKE_AUTH | SMF_RPKE_AUTH | SMF_INITIATOR |
		SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED | SMF_RELEASE_PENDING_P2,
	  P(HASH), P(VID) | P(CR),
	  EVENT_SA_REPLACE, unexpected /* ??? not yet implemented */ },

	/* STATE_MAIN_R3: can only get here due to packet loss */
	{ STATE_MAIN_R3, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_RETRANSMIT_ON_DUPLICATE,
	  LEMPTY, LEMPTY,
	  EVENT_NULL, unexpected },

	/* STATE_MAIN_I4: can only get here due to packet loss */
	{ STATE_MAIN_I4, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_INITIATOR | SMF_ENCRYPTED,
	  LEMPTY, LEMPTY,
	  EVENT_NULL, unexpected },

	/***** Phase 1 Aggressive Mode *****/

	/* No initial state for aggr_outI1:
	 * SMF_DS_AUTH (RFC 2409 5.1) and SMF_PSK_AUTH (RFC 2409 5.4):
	 * -->HDR, SA, KE, Ni, IDii
	 *
	 * Not implemented:
	 * RFC 2409 5.2: --> HDR, SA, [ HASH(1),] KE, <IDii_b>Pubkey_r, <Ni_b>Pubkey_r
	 * RFC 2409 5.3: --> HDR, SA, [ HASH(1),] <Ni_b>Pubkey_r, <KE_b>Ke_i, <IDii_b>Ke_i [, <Cert-I_b>Ke_i ]
	 */

	/* STATE_AGGR_R0:
	 * SMF_PSK_AUTH: HDR, SA, KE, Ni, IDii
	 *           --> HDR, SA, KE, Nr, IDir, HASH_R
	 * SMF_DS_AUTH:  HDR, SA, KE, Nr, IDii
	 *           --> HDR, SA, KE, Nr, IDir, [CERT,] SIG_R
	 */
	{ STATE_AGGR_R0, STATE_AGGR_R1,
	  SMF_PSK_AUTH | SMF_DS_AUTH | SMF_REPLY,
	  P(SA) | P(KE) | P(NONCE) | P(ID), P(VID) | P(NATD_RFC),
	  EVENT_SO_DISCARD, aggr_inI1_outR1 },

	/* STATE_AGGR_I1:
	 * SMF_PSK_AUTH: HDR, SA, KE, Nr, IDir, HASH_R
	 *           --> HDR*, HASH_I
	 * SMF_DS_AUTH:  HDR, SA, KE, Nr, IDir, [CERT,] SIG_R
	 *           --> HDR*, [CERT,] SIG_I
	 */
	{ STATE_AGGR_I1, STATE_AGGR_I2,
	  SMF_PSK_AUTH | SMF_INITIATOR | SMF_OUTPUT_ENCRYPTED | SMF_REPLY |
		SMF_RELEASE_PENDING_P2,
	  P(SA) | P(KE) | P(NONCE) | P(ID) | P(HASH), P(VID) | P(NATD_RFC),
	  EVENT_SA_REPLACE, aggr_inR1_outI2 },

	{ STATE_AGGR_I1, STATE_AGGR_I2,
	  SMF_DS_AUTH | SMF_INITIATOR | SMF_OUTPUT_ENCRYPTED | SMF_REPLY |
		SMF_RELEASE_PENDING_P2,
	  P(SA) | P(KE) | P(NONCE) | P(ID) | P(SIG), P(VID) | P(NATD_RFC),
	  EVENT_SA_REPLACE, aggr_inR1_outI2 },

	/* STATE_AGGR_R1:
	 * SMF_PSK_AUTH: HDR*, HASH_I --> done
	 * SMF_DS_AUTH:  HDR*, SIG_I  --> done
	 */
	{ STATE_AGGR_R1, STATE_AGGR_R2,
	  SMF_PSK_AUTH | SMF_FIRST_ENCRYPTED_INPUT |
		SMF_ENCRYPTED | SMF_RELEASE_PENDING_P2 |
		SMF_RETRANSMIT_ON_DUPLICATE,
	  P(HASH), P(VID) | P(NATD_RFC),
	  EVENT_SA_REPLACE, aggr_inI2 },

	{ STATE_AGGR_R1, STATE_AGGR_R2,
	  SMF_DS_AUTH | SMF_FIRST_ENCRYPTED_INPUT |
		SMF_ENCRYPTED | SMF_RELEASE_PENDING_P2 |
		SMF_RETRANSMIT_ON_DUPLICATE,
	  P(SIG), P(VID) | P(NATD_RFC),
	  EVENT_SA_REPLACE, aggr_inI2 },

	/* STATE_AGGR_I2: can only get here due to packet loss */
	{ STATE_AGGR_I2, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_INITIATOR | SMF_RETRANSMIT_ON_DUPLICATE,
	  LEMPTY, LEMPTY, EVENT_NULL, unexpected },

	/* STATE_AGGR_R2: can only get here due to packet loss */
	{ STATE_AGGR_R2, STATE_UNDEFINED,
	  SMF_ALL_AUTH,
	  LEMPTY, LEMPTY, EVENT_NULL, unexpected },

	/***** Phase 2 Quick Mode *****/

	/* No state for quick_outI1:
	 * --> HDR*, HASH(1), SA, Nr [, KE ] [, IDci, IDcr ]
	 */

	/* STATE_QUICK_R0:
	 * HDR*, HASH(1), SA, Ni [, KE ] [, IDci, IDcr ] -->
	 * HDR*, HASH(2), SA, Nr [, KE ] [, IDci, IDcr ]
	 * Installs inbound IPsec SAs.
	 * Because it may suspend for asynchronous DNS, first_out_payload
	 * is set to NONE to suppress early emission of HDR*.
	 * ??? it is legal to have multiple SAs, but we don't support it yet.
	 */
	{ STATE_QUICK_R0, STATE_QUICK_R1,
	  SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_REPLY,
	  P(HASH) | P(SA) | P(NONCE), /* P(SA) | */ P(KE) | P(ID) | P(NATOA_RFC),
	  EVENT_v1_RETRANSMIT, quick_inI1_outR1 },

	/* STATE_QUICK_I1:
	 * HDR*, HASH(2), SA, Nr [, KE ] [, IDci, IDcr ] -->
	 * HDR*, HASH(3)
	 * Installs inbound and outbound IPsec SAs, routing, etc.
	 * ??? it is legal to have multiple SAs, but we don't support it yet.
	 */
	{ STATE_QUICK_I1, STATE_QUICK_I2,
	  SMF_ALL_AUTH | SMF_INITIATOR | SMF_ENCRYPTED | SMF_REPLY,
	  P(HASH) | P(SA) | P(NONCE), /* P(SA) | */ P(KE) | P(ID) | P(NATOA_RFC),
	  EVENT_SA_REPLACE, quick_inR1_outI2 },

	/* STATE_QUICK_R1: HDR*, HASH(3) --> done
	 * Installs outbound IPsec SAs, routing, etc.
	 */
	{ STATE_QUICK_R1, STATE_QUICK_R2,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  P(HASH), LEMPTY,
	  EVENT_SA_REPLACE, quick_inI2 },

	/* STATE_QUICK_I2: can only happen due to lost packet */
	{ STATE_QUICK_I2, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_INITIATOR | SMF_ENCRYPTED |
		SMF_RETRANSMIT_ON_DUPLICATE,
	  LEMPTY, LEMPTY,
	  EVENT_NULL, unexpected },

	/* STATE_QUICK_R2: can only happen due to lost packet */
	{ STATE_QUICK_R2, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  LEMPTY, LEMPTY,
	  EVENT_NULL, unexpected },

	/***** informational messages *****/

	/* Informational Exchange (RFC 2408 4.8):
	 * HDR N/D
	 * Unencrypted: must not occur after ISAKMP Phase 1 exchange of keying material.
	 */
	/* STATE_INFO: */
	{ STATE_INFO, STATE_UNDEFINED,
	  SMF_ALL_AUTH,
	  LEMPTY, LEMPTY,
	  EVENT_NULL, informational },

	/* Informational Exchange (RFC 2408 4.8):
	 * HDR* N/D
	 */
	/* STATE_INFO_PROTECTED: */
	{ STATE_INFO_PROTECTED, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  P(HASH), LEMPTY,
	  EVENT_NULL, informational },

	{ STATE_XAUTH_R0, STATE_XAUTH_R1,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  P(MCFG_ATTR) | P(HASH), P(VID),
	  EVENT_NULL, xauth_inR0 }, /* Re-transmit may be done by previous state */

	{ STATE_XAUTH_R1, STATE_MAIN_R3,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  P(MCFG_ATTR) | P(HASH), P(VID),
	  EVENT_SA_REPLACE, xauth_inR1 },

#if 0
	/* for situation where there is XAUTH + ModeCFG */
	{ STATE_XAUTH_R2, STATE_XAUTH_R3,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  P(MCFG_ATTR) | P(HASH), P(VID),
	  EVENT_SA_REPLACE, xauth_inR2 },

	{ STATE_XAUTH_R3, STATE_MAIN_R3,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  P(MCFG_ATTR) | P(HASH), P(VID),
	  EVENT_SA_REPLACE, xauth_inR3 },
#endif

/* MODE_CFG_x:
 * Case R0:  Responder	->	Initiator
 *			<-	Req(addr=0)
 *	    Reply(ad=x)	->
 *
 * Case R1: Set(addr=x)	->
 *			<-	Ack(ok)
 */

	{ STATE_MODE_CFG_R0, STATE_MODE_CFG_R1,
	  SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_REPLY,
	  P(MCFG_ATTR) | P(HASH), P(VID),
	  EVENT_SA_REPLACE, modecfg_inR0 },

	{ STATE_MODE_CFG_R1, STATE_MODE_CFG_R2,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  P(MCFG_ATTR) | P(HASH), P(VID),
	  EVENT_SA_REPLACE, modecfg_inR1 },

	{ STATE_MODE_CFG_R2, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  LEMPTY, LEMPTY,
	  EVENT_NULL, unexpected },

	{ STATE_MODE_CFG_I1, STATE_MAIN_I4,
	  SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_RELEASE_PENDING_P2,
	  P(MCFG_ATTR) | P(HASH), P(VID),
	  EVENT_SA_REPLACE, modecfg_inR1 },

	{ STATE_XAUTH_I0, STATE_XAUTH_I1,
	  SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_REPLY | SMF_RELEASE_PENDING_P2,
	  P(MCFG_ATTR) | P(HASH), P(VID),
	  EVENT_v1_RETRANSMIT, xauth_inI0 },

	{ STATE_XAUTH_I1, STATE_MAIN_I4,
	  SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_REPLY | SMF_RELEASE_PENDING_P2,
	  P(MCFG_ATTR) | P(HASH), P(VID),
	  EVENT_v1_RETRANSMIT, xauth_inI1 },

	{ STATE_IKEv1_ROOF, STATE_IKEv1_ROOF,
	  LEMPTY,
	  LEMPTY, LEMPTY,
	  EVENT_NULL, NULL },
#undef P
};

void init_ikev1(void)
{
	/*
	 * Fill in the states.  This is a hack until each finite-state
	 * is a stand-alone object with corresponding edges (aka
	 * microcodes).
	 */
	static struct finite_state v1_states[STATE_IKEv1_ROOF - STATE_IKEv1_FLOOR];
	for (unsigned k = 0; k < elemsof(v1_states); k++) {
		struct finite_state *fs = &v1_states[k];
		fs->fs_state = k + STATE_IKEv1_FLOOR;
		fs->fs_name = enum_name(&state_names, fs->fs_state);
		fs->fs_short_name = enum_short_name(&state_names, fs->fs_state);
		fs->fs_story = enum_name(&state_stories, fs->fs_state);
		finite_states[fs->fs_state] = fs;
	}

	/*
	 * Fill in .fs_microcode and .fs_flags; check that table is in
	 * order -- catch coding errors.
	 */
	const struct state_v1_microcode *t = v1_state_microcode_table;
	do {
		passert(STATE_IKEv1_FLOOR <= t->state &&
			t->state < STATE_IKEv1_ROOF);
		struct finite_state *fs = &v1_states[t->state - STATE_IKEv1_FLOOR];
		/*
		 * Point .fs_microcode to the first entry in
		 * v1_state_microcode_table for that state.  All other
		 * microcodes for that state should follow immediately
		 * after.
		 */
		fs->fs_microcode = t;
		/*
		 * Copy over the flags that apply to the state; and
		 * not the edge.
		 */
		fs->fs_flags = t->flags & SMF_RETRANSMIT_ON_DUPLICATE;
		do {
			t++;
		} while (t->state == fs->fs_state);
		passert(t->state > fs->fs_state);
	} while (t->state < STATE_IKEv1_ROOF);

	/*
	 * Try to fill in .fs_timeout_event.
	 *
	 * Since the timeout event, stored in the edge structure (aka
	 * microcode), is for the target state, .next_state is used.
	 */
	for (t = v1_state_microcode_table; t->state < STATE_IKEv1_ROOF; t++) {
		if (t->next_state != STATE_UNDEFINED) {
			passert(STATE_IKEv1_FLOOR <= t->next_state &&
				t->next_state < STATE_IKEv1_ROOF);
			struct finite_state *fs = &v1_states[t->next_state - STATE_IKEv1_FLOOR];
			if (fs->fs_timeout_event == 0) {
				fs->fs_timeout_event = t->timeout_event;
			} else if (fs->fs_timeout_event != t->timeout_event) {
				/*
				 * Annoyingly, a state can seemingly
				 * have multiple and inconsistent
				 * timeout_events.
				 *
				 * For instance, MAIN_I3->MAIN_I4 has
				 * SA_REPLACE while XAUTH_I1->MAIN_I4
				 * has RETRANSMIT.  This is arguably a
				 * bug caused by a skipped state.
				 */
				LSWDBGP(DBG_CONTROLMORE, buf) {
					lswlogs(buf, "ignoring microcode for ");
					lswlog_finite_state(buf, finite_states[t->state]);
					lswlogs(buf, " -> ");
					lswlog_finite_state(buf, fs);
					lswlogs(buf, " with event ");
					lswlog_enum_short(buf, &timer_event_names,
							  t->timeout_event);
				}
			}
		}
	}

	/*
	 * Finally list the states.
	 */
	DBG(DBG_CONTROLMORE,
	    for (unsigned s = STATE_IKEv1_FLOOR; s < STATE_IKEv1_ROOF; s++) {
		    const struct finite_state *fs = finite_states[s];
		    LSWLOG_DEBUG(buf) {
			    lswlog_finite_state(buf, fs);
		    }
	    });
}

static stf_status unexpected(struct state *st, struct msg_digest *md UNUSED)
{
	loglog(RC_LOG_SERIOUS, "unexpected message received in state %s",
	       st->st_state_name);
	return STF_IGNORE;
}

/*
 * RFC 2408 Section 4.6
 *
 *  #   Initiator  Direction Responder  NOTE
 * (1)  HDR*; N/D     =>                Error Notification or Deletion
 */
static stf_status informational(struct state *st, struct msg_digest *md)
{
	struct payload_digest *const n_pld = md->chain[ISAKMP_NEXT_N];

	/* If the Notification Payload is not null... */
	if (n_pld != NULL) {
		pb_stream *const n_pbs = &n_pld->pbs;
		struct isakmp_notification *const n =
			&n_pld->payload.notification;
		pexpect(st == md->st);
		st = md->st;    /* may be NULL */

		/* Switch on Notification Type (enum) */
		/* note that we _can_ get notification payloads unencrypted
		 * once we are at least in R3/I4.
		 * and that the handler is expected to treat them suspiciously.
		 */
		DBG(DBG_CONTROL, DBG_log("processing informational %s (%d)",
					 enum_name(&ikev1_notify_names,
						   n->isan_type),
					 n->isan_type));

		pstats(ikev1_recv_notifies_e, n->isan_type);

		switch (n->isan_type) {
		case R_U_THERE:
			if (st == NULL) {
				loglog(RC_LOG_SERIOUS,
				       "received bogus  R_U_THERE informational message");
				return STF_IGNORE;
			}
			return dpd_inI_outR(st, n, n_pbs);

		case R_U_THERE_ACK:
			if (st == NULL) {
				loglog(RC_LOG_SERIOUS,
				       "received bogus R_U_THERE_ACK informational message");
				return STF_IGNORE;
			}
			return dpd_inR(st, n, n_pbs);

		case PAYLOAD_MALFORMED:
			if (st != NULL) {
				st->hidden_variables.st_malformed_received++;

				libreswan_log(
					"received %u malformed payload notifies",
					st->hidden_variables.st_malformed_received);

				if (st->hidden_variables.st_malformed_sent >
				    MAXIMUM_MALFORMED_NOTIFY / 2 &&
				    ((st->hidden_variables.st_malformed_sent +
				      st->hidden_variables.
				      st_malformed_received) >
				     MAXIMUM_MALFORMED_NOTIFY)) {
					libreswan_log(
						"too many malformed payloads (we sent %u and received %u",
						st->hidden_variables.st_malformed_sent,
						st->hidden_variables.st_malformed_received);
					delete_state(st);
					md->st = st = NULL;
				}
			}

			return STF_IGNORE;

		case ISAKMP_N_CISCO_LOAD_BALANCE:
			/*
			 * ??? what the heck is in the payload?
			 * We take the peer's new IP address from the last 4 octets.
			 * Is anything else possible?  Expected?  Documented?
			 */
			if (st == NULL || !IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
				loglog(RC_LOG_SERIOUS,
					"ignoring ISAKMP_N_CISCO_LOAD_BALANCE Informational Message with for unestablished state.");
			} else if (pbs_left(n_pbs) < 4) {
				loglog(RC_LOG_SERIOUS,
					"ignoring ISAKMP_N_CISCO_LOAD_BALANCE Informational Message without IPv4 address");
			} else {
				ip_address new_peer;

				(void)initaddr(n_pbs->roof - 4, 4, AF_INET, &new_peer);

				if (isanyaddr(&new_peer)) {
					ipstr_buf b;

					loglog(RC_LOG_SERIOUS,
						"ignoring ISAKMP_N_CISCO_LOAD_BALANCE Informational Message with invalid IPv4 address %s",
						ipstr(&new_peer, &b));
					return FALSE;
				}

				/* Saving connection name and whack sock id */
				const char *tmp_name = st->st_connection->name;
				fd_t tmp_whack_sock = dup_any(st->st_whack_sock);

				/* deleting ISAKMP SA with the current remote peer */
				delete_state(st);
				md->st = st = NULL;

				/* to find and store the connection associated with tmp_name */
				/* ??? how do we know that tmp_name hasn't been freed? */
				struct connection *tmp_c = conn_by_name(tmp_name, FALSE, FALSE);

				DBG(DBG_PARSING, {
					ipstr_buf npb;
					DBG_log("new peer address: %s", ipstr(&new_peer, &npb));
				});

				/* Current remote peer info */
				{
					ipstr_buf b;
					const struct spd_route *tmp_spd =
						&tmp_c->spd;
					int count_spd = 0;

					do {
						DBG(DBG_CONTROLMORE,
						    DBG_log("spd route number: %d",
							    ++count_spd));

						/**that info**/
						DBG(DBG_CONTROLMORE,
						    DBG_log("that id kind: %d",
							    tmp_spd->that.id.kind));
						DBG(DBG_CONTROLMORE,
						    DBG_log("that id ipaddr: %s",
							    ipstr(&tmp_spd->that.id.ip_addr, &b)));
						if (tmp_spd->that.id.name.ptr
						    != NULL)
							DBG(DBG_CONTROLMORE,
							    DBG_dump_chunk(
								    "that id name",
								    tmp_spd->
								    that.id.
								    name));
						DBG(DBG_CONTROLMORE,
						    DBG_log("that host_addr: %s",
							    ipstr(&tmp_spd->that.host_addr, &b)));
						DBG(DBG_CONTROLMORE,
						    DBG_log("that nexthop: %s",
							    ipstr(&tmp_spd->that.host_nexthop, &b)));
						DBG(DBG_CONTROLMORE,
						    DBG_log("that srcip: %s",
							    ipstr(&tmp_spd->that.host_srcip, &b)));
						DBG(DBG_CONTROLMORE,
						    DBG_log("that client_addr: %s, maskbits:%d",
							    ipstr(&tmp_spd->that.client.addr, &b),
							    tmp_spd->that.
							    client.maskbits));
						DBG(DBG_CONTROLMORE,
						    DBG_log("that has_client: %d",
							    tmp_spd->that.
							    has_client));
						DBG(DBG_CONTROLMORE,
						    DBG_log("that has_client_wildcard: %d",
							    tmp_spd->that.
							    has_client_wildcard));
						DBG(DBG_CONTROLMORE,
						    DBG_log("that has_port_wildcard: %d",
							    tmp_spd->that.
							    has_port_wildcard));
						DBG(DBG_CONTROLMORE,
						    DBG_log("that has_id_wildcards: %d",
							    tmp_spd->that.
							    has_id_wildcards));

						tmp_spd = tmp_spd->spd_next;
					} while (tmp_spd != NULL);

					if (tmp_c->interface != NULL) {
						DBG(DBG_CONTROLMORE,
						    DBG_log("Current interface_addr: %s",
							    ipstr(&tmp_c->interface->ip_addr, &b)));
					}
				}

				/* save peer's old address for comparison purposes */
				ip_address old_addr = tmp_c->spd.that.host_addr;

				/* update peer's address */
				tmp_c->spd.that.host_addr = new_peer;

				/* Modifying connection info to store the redirected remote peer info */
				DBG(DBG_CONTROLMORE,
				    DBG_log("Old host_addr_name : %s",
					    tmp_c->spd.that.host_addr_name));
				tmp_c->spd.that.host_addr_name = NULL;

				/* ??? do we know the id.kind has an ip_addr? */
				tmp_c->spd.that.id.ip_addr = new_peer;

				/* update things that were the old peer */
				ipstr_buf b;
				if (sameaddr(&tmp_c->spd.this.host_nexthop,
					     &old_addr)) {
					DBG(DBG_CONTROLMORE, {
						DBG_log("this host's next hop %s was the same as the old remote addr",
							ipstr(&old_addr, &b));
						DBG_log("changing this host's next hop to %s",
							ipstr(&new_peer, &b));
					});
					tmp_c->spd.this.host_nexthop = new_peer;
				}

				if (sameaddr(&tmp_c->spd.that.host_srcip,
					     &old_addr)) {
					DBG(DBG_CONTROLMORE, {
						DBG_log("Old that host's srcip %s was the same as the old remote addr",
							ipstr(&old_addr, &b));
						DBG_log("changing that host's srcip to %s",
							ipstr(&new_peer, &b));
					});
					tmp_c->spd.that.host_srcip = new_peer;
				}

				if (sameaddr(&tmp_c->spd.that.client.addr,
					     &old_addr)) {
					DBG(DBG_CONTROLMORE, {
						DBG_log("Old that client ip %s was the same as the old remote address",
							ipstr(&old_addr, &b));
						DBG_log("changing that client's ip to %s",
							ipstr(&new_peer, &b));
					});
					tmp_c->spd.that.client.addr = new_peer;
				}

				/* ??? is this wise?  This may changes a lot of other connections. */
				tmp_c->host_pair->him.addr = new_peer;

				/* Initiating connection to the redirected peer */
				initiate_connection(tmp_name, tmp_whack_sock,
						    empty_lmod, empty_lmod, NULL);
			}
			return STF_IGNORE;
		default:
			loglog(RC_LOG_SERIOUS,
				"received and ignored notification payload: %s",
				enum_name(&ikev1_notify_names, n->isan_type));
			return STF_IGNORE;
		}
	} else {
		/* warn if we didn't find any Delete or Notify payload in packet */
		if (md->chain[ISAKMP_NEXT_D] == NULL) {
			loglog(RC_LOG_SERIOUS,
				"received and ignored empty informational notification payload");
		}
		return STF_IGNORE;
	}
}

/*
 * create output HDR as replica of input HDR - IKEv1 only; return the body
 */
void ikev1_init_out_pbs_echo_hdr(struct msg_digest *md, bool enc, uint8_t np,
				 pb_stream *output_stream, uint8_t *output_buffer,
				 size_t sizeof_output_buffer,
				 pb_stream *rbody)
{
	struct isakmp_hdr hdr = md->hdr; /* mostly same as incoming header */

	/* make sure we start with a clean buffer */
	init_out_pbs(output_stream, output_buffer, sizeof_output_buffer,
		     "reply packet");

	hdr.isa_flags = 0; /* zero all flags */
	if (enc)
		hdr.isa_flags |= ISAKMP_FLAGS_v1_ENCRYPTION;

	if (IMPAIR(SEND_BOGUS_ISAKMP_FLAG)) {
		hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
	}

	/* there is only one IKEv1 version, and no new one will ever come - no need to set version */
	hdr.isa_np = np;
	/* surely must have room and be well-formed */
	passert(out_struct(&hdr, &isakmp_hdr_desc, output_stream, rbody));
}

/*
 * Recognise and, if necesssary, respond to an IKEv1 duplicate.
 *
 * Use .st_finite_state, which is the real current state, and not
 * FROM_STATE (which is derived from some convoluted magic) when
 * determining if the duplicate should or should not get a response.
 */
static bool ikev1_duplicate(struct state *st, struct msg_digest *md)
{
	passert(st != NULL);
	if (st->st_rpacket.ptr != NULL &&
	    st->st_rpacket.len == pbs_room(&md->packet_pbs) &&
	    memeq(st->st_rpacket.ptr, md->packet_pbs.start,
		  st->st_rpacket.len)) {
		if (st->st_finite_state->fs_flags & SMF_RETRANSMIT_ON_DUPLICATE) {
			/*
			 * States with EVENT_SO_DISCARD always respond
			 * to re-transmits; else cap.
			 */
			if (st->st_finite_state->fs_timeout_event == EVENT_SO_DISCARD ||
			    count_duplicate(st, MAXIMUM_v1_ACCEPTED_DUPLICATES)) {
				loglog(RC_RETRANSMISSION,
				       "retransmitting in response to duplicate packet; already %s",
				       st->st_state_name);
				resend_recorded_v1_ike_msg(st, "retransmit in response to duplicate");
			} else {
				loglog(RC_LOG_SERIOUS,
				       "discarding duplicate packet -- exhausted retransmission; already %s",
				       st->st_state_name);
			}
		} else {
			LSWDBGP(DBG_CONTROLMORE, buf) {
				lswlog_log_prefix(buf);
				lswlogf(buf, "discarding duplicate packet; already %s",
				st->st_state_name);
			}
		}
		return true;
	}
	return false;
}

/* process an input packet, possibly generating a reply.
 *
 * If all goes well, this routine eventually calls a state-specific
 * transition function.
 *
 * This routine will not release_any_md(mdp).  It is expected that its
 * caller will do this.  In fact, it will zap *mdp to NULL if it thinks
 * **mdp should not be freed.  So the caller should be prepared for
 * *mdp being set to NULL.
 */
void process_v1_packet(struct msg_digest **mdp)
{
	struct msg_digest *md = *mdp;
	const struct state_v1_microcode *smc;
	bool new_iv_set = FALSE;
	struct state *st = NULL;
	enum state_kind from_state = STATE_UNDEFINED;   /* state we started in */

#define SEND_NOTIFICATION(t) { \
		pstats(ikev1_sent_notifies_e, t); \
		if (st != NULL) \
			send_notification_from_state(st, from_state, t); \
		else \
			send_notification_from_md(md, t); }

	switch (md->hdr.isa_xchg) {
#ifdef NOTYET
	case ISAKMP_XCHG_NONE:
	case ISAKMP_XCHG_BASE:
	case ISAKMP_XCHG_AO:
#endif

	case ISAKMP_XCHG_AGGR:
	case ISAKMP_XCHG_IDPROT: /* part of a Main Mode exchange */
		if (md->hdr.isa_msgid != v1_MAINMODE_MSGID) {
			libreswan_log(
				"Message ID was 0x%08" PRIx32 " but should be zero in phase 1",
				md->hdr.isa_msgid);
			SEND_NOTIFICATION(INVALID_MESSAGE_ID);
			return;
		}

		if (is_zero_cookie(md->hdr.isa_icookie)) {
			libreswan_log(
				"Initiator Cookie must not be zero in phase 1 message");
			SEND_NOTIFICATION(INVALID_COOKIE);
			return;
		}

		if (is_zero_cookie(md->hdr.isa_rcookie)) {
			/*
			 * initial message from initiator
			 */
			if (md->hdr.isa_flags & ISAKMP_FLAGS_v1_ENCRYPTION) {
				libreswan_log("initial phase 1 message is invalid: its Encrypted Flag is on");
				SEND_NOTIFICATION(INVALID_FLAGS);
				return;
			}

			/*
			 * If there is already an existing state with
			 * this ICOOKIE, asssume it is some sort of
			 * re-transmit.
			 */
			st = find_state_ikev1_init(md->hdr.isa_icookie,
						   md->hdr.isa_msgid);
			if (st != NULL) {
				so_serial_t old_state = push_cur_state(st);
				if (!ikev1_duplicate(st, md)) {
					/*
					 * Not a duplicate for the
					 * current state; assume that
					 * this a really old
					 * re-transmit for an earlier
					 * state that should be
					 * discarded.
					 */
					libreswan_log("discarding initial packet; already %s",
						      st->st_state_name);
				}
				pop_cur_state(old_state);
				return;
			}
			passert(st == NULL); /* new state needed */
			/* don't build a state until the message looks tasty */
			from_state = (md->hdr.isa_xchg == ISAKMP_XCHG_IDPROT ?
				      STATE_MAIN_R0 : STATE_AGGR_R0);
		} else {
			/* not an initial message */

			st = find_state_ikev1(md->hdr.isa_icookie,
					      md->hdr.isa_rcookie,
					      md->hdr.isa_msgid);

			if (st == NULL) {
				/*
				 * perhaps this is a first message
				 * from the responder and contains a
				 * responder cookie that we've not yet
				 * seen.
				 */
				st = find_state_ikev1_init(md->hdr.isa_icookie,
							   md->hdr.isa_msgid);

				if (st == NULL) {
					libreswan_log(
						"phase 1 message is part of an unknown exchange");
					/* XXX Could send notification back */
					return;
				}
			}
			set_cur_state(st);
			from_state = st->st_state;
		}
		break;

	case ISAKMP_XCHG_INFO:  /* an informational exchange */
		st = ikev1_find_info_state(md->hdr.isa_icookie, md->hdr.isa_rcookie,
				     &md->sender, v1_MAINMODE_MSGID);

		if (st == NULL) {
			/*
			 * might be an informational response to our
			 * first message, in which case, we don't know
			 * the rcookie yet.
			 */
			st = find_state_ikev1_init(md->hdr.isa_icookie,
						   v1_MAINMODE_MSGID);
		}

		if (st != NULL)
			set_cur_state(st);

		if (md->hdr.isa_flags & ISAKMP_FLAGS_v1_ENCRYPTION) {
			bool quiet = (st == NULL);

			if (st == NULL) {
				DBG(DBG_CONTROL, DBG_log(
						"Informational Exchange is for an unknown (expired?) SA with MSGID:0x%08" PRIx32,
							md->hdr.isa_msgid));

				/* Let's try to log some info about these to track them down */
				DBG(DBG_CONTROL, {
					    DBG_dump("- unknown SA's md->hdr.isa_icookie:",
						    md->hdr.isa_icookie,
						    COOKIE_SIZE);
					    DBG_dump("- unknown SA's md->hdr.isa_rcookie:",
						    md->hdr.isa_rcookie,
						    COOKIE_SIZE);
				    });

				/* XXX Could send notification back */
				return;
			}

			if (!IS_ISAKMP_ENCRYPTED(st->st_state)) {
				if (!quiet) {
					loglog(RC_LOG_SERIOUS, "encrypted Informational Exchange message is invalid because no key is known");
				}
				/* XXX Could send notification back */
				return;
			}

			if (md->hdr.isa_msgid == v1_MAINMODE_MSGID) {
				if (!quiet) {
					loglog(RC_LOG_SERIOUS, "Informational Exchange message is invalid because it has a Message ID of 0");
				}
				/* XXX Could send notification back */
				return;
			}

			if (!unique_msgid(st, md->hdr.isa_msgid)) {
				if (!quiet) {
					loglog(RC_LOG_SERIOUS,
						"Informational Exchange message is invalid because it has a previously used Message ID (0x%08" PRIx32 " )",
						md->hdr.isa_msgid);
				}
				/* XXX Could send notification back */
				return;
			}
			st->st_msgid_reserved = FALSE;

			init_phase2_iv(st, &md->hdr.isa_msgid);
			new_iv_set = TRUE;

			from_state = STATE_INFO_PROTECTED;
		} else {
			if (st != NULL &&
			    IS_ISAKMP_AUTHENTICATED(st->st_state)) {
				loglog(RC_LOG_SERIOUS, "Informational Exchange message must be encrypted");
				/* XXX Could send notification back */
				return;
			}
			from_state = STATE_INFO;
		}
		break;

	case ISAKMP_XCHG_QUICK: /* part of a Quick Mode exchange */

		if (is_zero_cookie(md->hdr.isa_icookie)) {
			DBG(DBG_CONTROL, DBG_log(
				"Quick Mode message is invalid because it has an Initiator Cookie of 0"));
			SEND_NOTIFICATION(INVALID_COOKIE);
			return;
		}

		if (is_zero_cookie(md->hdr.isa_rcookie)) {
			DBG(DBG_CONTROL, DBG_log(
				"Quick Mode message is invalid because it has a Responder Cookie of 0"));
			SEND_NOTIFICATION(INVALID_COOKIE);
			return;
		}

		if (md->hdr.isa_msgid == v1_MAINMODE_MSGID) {
			DBG(DBG_CONTROL, DBG_log(
				"Quick Mode message is invalid because it has a Message ID of 0"));
			SEND_NOTIFICATION(INVALID_MESSAGE_ID);
			return;
		}

		st = find_state_ikev1(md->hdr.isa_icookie, md->hdr.isa_rcookie,
				      md->hdr.isa_msgid);

		if (st == NULL) {
			/* No appropriate Quick Mode state.
			 * See if we have a Main Mode state.
			 * ??? what if this is a duplicate of another message?
			 */
			st = find_state_ikev1(md->hdr.isa_icookie,
					      md->hdr.isa_rcookie,
					      v1_MAINMODE_MSGID);

			if (st == NULL) {
				DBG(DBG_CONTROL, DBG_log(
					"Quick Mode message is for a non-existent (expired?) ISAKMP SA"));
				/* XXX Could send notification back */
				return;
			}

			if (st->st_oakley.doing_xauth) {
				DBG(DBG_CONTROL, DBG_log(
					"Cannot do Quick Mode until XAUTH done."));
				return;
			}

			/* Have we just given an IP address to peer? */
			if (st->st_state == STATE_MODE_CFG_R2) {
				/* ISAKMP is up... */
				change_state(st, STATE_MAIN_R3);
			}

#ifdef SOFTREMOTE_CLIENT_WORKAROUND
			/* See: http://popoludnica.pl/?id=10100110 */
			if (st->st_state == STATE_MODE_CFG_R1) {
				libreswan_log(
					"SoftRemote workaround: Cannot do Quick Mode until MODECFG done.");
				return;
			}
#endif

			set_cur_state(st);

			if (!IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
					loglog(RC_LOG_SERIOUS, "Quick Mode message is unacceptable because it is for an incomplete ISAKMP SA");
				SEND_NOTIFICATION(PAYLOAD_MALFORMED /* XXX ? */);
				return;
			}

			if (!unique_msgid(st, md->hdr.isa_msgid)) {
					loglog(RC_LOG_SERIOUS, "Quick Mode I1 message is unacceptable because it uses a previously used Message ID 0x%08" PRIx32 " (perhaps this is a duplicated packet)",
						md->hdr.isa_msgid);
				SEND_NOTIFICATION(INVALID_MESSAGE_ID);
				return;
			}
			st->st_msgid_reserved = FALSE;

			/* Quick Mode Initial IV */
			init_phase2_iv(st, &md->hdr.isa_msgid);
			new_iv_set = TRUE;

			from_state = STATE_QUICK_R0;
		} else {
			if (st->st_oakley.doing_xauth) {
				libreswan_log("Cannot do Quick Mode until XAUTH done.");
				return;
			}
			set_cur_state(st);
			from_state = st->st_state;
		}

		break;

	case ISAKMP_XCHG_MODE_CFG:
		if (is_zero_cookie(md->hdr.isa_icookie)) {
			DBG(DBG_CONTROL, DBG_log("Mode Config message is invalid because it has an Initiator Cookie of 0"));
			/* XXX Could send notification back */
			return;
		}

		if (is_zero_cookie(md->hdr.isa_rcookie)) {
			DBG(DBG_CONTROL, DBG_log("Mode Config message is invalid because it has a Responder Cookie of 0"));
			/* XXX Could send notification back */
			return;
		}

		if (md->hdr.isa_msgid == 0) {
			DBG(DBG_CONTROL, DBG_log("Mode Config message is invalid because it has a Message ID of 0"));
			/* XXX Could send notification back */
			return;
		}

		st = ikev1_find_info_state(md->hdr.isa_icookie, md->hdr.isa_rcookie,
				     &md->sender, md->hdr.isa_msgid);

		if (st == NULL) {
			/* No appropriate Mode Config state.
			 * See if we have a Main Mode state.
			 * ??? what if this is a duplicate of another message?
			 */
			DBG(DBG_CONTROL, DBG_log(
				"No appropriate Mode Config state yet. See if we have a Main Mode state"));

			st = ikev1_find_info_state(md->hdr.isa_icookie,
					     md->hdr.isa_rcookie,
					     &md->sender, 0);

			if (st == NULL) {
				DBG(DBG_CONTROL, DBG_log(
					"Mode Config message is for a non-existent (expired?) ISAKMP SA"));
				/* XXX Could send notification back */
				/* ??? ought to log something (not just DBG)? */
				return;
			}

			set_cur_state(st);

			DBG(DBG_CONTROLMORE,
				DBG_log(" processing received isakmp_xchg_type %s.",
					enum_show(&ikev1_exchange_names,
					md->hdr.isa_xchg)));
			DBG(DBG_CONTROLMORE, {
				const struct end *this =
					&st->st_connection->spd.this;

				DBG_log(" this is a%s%s%s%s",
					this->xauth_server ?
						" xauthserver" : "",
					this->xauth_client ?
						" xauthclient" : "",
					this->modecfg_server ?
						" modecfgserver" : "",
					this->modecfg_client ?
						" modecfgclient" : "");
			});

			if (!IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
				DBG(DBG_CONTROLMORE, DBG_log(
					"Mode Config message is unacceptable because it is for an incomplete ISAKMP SA (state=%s)",
					st->st_state_name));
				/* XXX Could send notification back */
				return;
			}
			DBG(DBG_CONTROLMORE, DBG_log(" call  init_phase2_iv"));
			init_phase2_iv(st, &md->hdr.isa_msgid);
			new_iv_set = TRUE;

			/*
			 * okay, now we have to figure out if we are receiving a bogus
			 * new message in an outstanding XAUTH server conversation
			 * (i.e. a reply to our challenge)
			 * (this occurs with some broken other implementations).
			 *
			 * or if receiving for the first time, an XAUTH challenge.
			 *
			 * or if we are getting a MODECFG request.
			 *
			 * we distinguish these states because we cannot both be an
			 * XAUTH server and client, and our policy tells us which
			 * one we are.
			 *
			 * to complicate further, it is normal to start a new msgid
			 * when going from one state to another, or when restarting
			 * the challenge.
			 *
			 */

			const struct end *this = &st->st_connection->spd.this;

			if (this->xauth_server &&
			    st->st_state == STATE_XAUTH_R1 &&
			    st->quirks.xauth_ack_msgid) {
				from_state = STATE_XAUTH_R1;
				DBG(DBG_CONTROLMORE, DBG_log(
					" set from_state to %s state is STATE_XAUTH_R1 and quirks.xauth_ack_msgid is TRUE",
					    enum_name(&state_names,
						      st->st_state
						      )));
			} else if (this->xauth_client &&
				   IS_PHASE1(st->st_state)) {
				from_state = STATE_XAUTH_I0;
				DBG(DBG_CONTROLMORE, DBG_log(
					" set from_state to %s this is xauthclient and IS_PHASE1() is TRUE",
					    enum_name(&state_names,
						      st->st_state
						      )));
			} else if (this->xauth_client &&
				   st->st_state == STATE_XAUTH_I1) {
				/*
				 * in this case, we got a new MODECFG message after I0, maybe
				 * because it wants to start over again.
				 */
				from_state = STATE_XAUTH_I0;
				DBG(DBG_CONTROLMORE, DBG_log(
					" set from_state to %s this is xauthclient and state == STATE_XAUTH_I1",
					    enum_name(&state_names,
						      st->st_state
						      )));
			} else if (this->modecfg_server &&
				   IS_PHASE1(st->st_state)) {
				from_state = STATE_MODE_CFG_R0;
				DBG(DBG_CONTROLMORE, DBG_log(
					" set from_state to %s this is modecfgserver and IS_PHASE1() is TRUE",
					    enum_name(&state_names,
						      st->st_state
						      )));
			} else if (this->modecfg_client &&
				   IS_PHASE1(st->st_state)) {
				from_state = STATE_MODE_CFG_R1;
				DBG(DBG_CONTROLMORE, DBG_log(
					" set from_state to %s this is modecfgclient and IS_PHASE1() is TRUE",
					    enum_name(&state_names,
						      st->st_state
						      )));
			} else {
				DBG(DBG_CONTROLMORE, DBG_log(
					"received isakmp_xchg_type %s",
					    enum_show(&ikev1_exchange_names,
						      md->hdr.isa_xchg)));
				DBG(DBG_CONTROLMORE, DBG_log(
					"this is a%s%s%s%s in state %s. Reply with UNSUPPORTED_EXCHANGE_TYPE",
					    st->st_connection
					    ->spd.this.xauth_server ?
					    " xauthserver" : "",
					    st->st_connection
					    ->spd.this.xauth_client ?
					    " xauthclient" : "",
					    st->st_connection
					    ->spd.this.modecfg_server ?
					    " modecfgserver" :
					    "",
					    st->st_connection
					    ->spd.this.modecfg_client  ?
					    " modecfgclient" :
					    "",
					    enum_name(&
						      state_names,
						      st->st_state)
					    ));
				return;
			}
		} else {
			if (st->st_connection->spd.this.xauth_server &&
			    IS_PHASE1(st->st_state)) {
				/* Switch from Phase1 to Mode Config */
				DBG(DBG_CONTROL, DBG_log(
					"We were in phase 1, with no state, so we went to XAUTH_R0"));
				change_state(st, STATE_XAUTH_R0);
			}

			/* otherwise, this is fine, we continue in the state we are in */
			set_cur_state(st);
			from_state = st->st_state;
		}

		break;

	case ISAKMP_XCHG_NGRP:
	default:
		DBG(DBG_CONTROL, DBG_log("unsupported exchange type %s in message",
			      enum_show(&ikev1_exchange_names, md->hdr.isa_xchg)));
		SEND_NOTIFICATION(UNSUPPORTED_EXCHANGE_TYPE);
		return;
	}

	/* We have found a from_state, and perhaps a state object.
	 * If we need to build a new state object,
	 * we wait until the packet has been sanity checked.
	 */

	/* We don't support the Commit Flag.  It is such a bad feature.
	 * It isn't protected -- neither encrypted nor authenticated.
	 * A man in the middle turns it on, leading to DoS.
	 * We just ignore it, with a warning.
	 */
	if (md->hdr.isa_flags & ISAKMP_FLAGS_v1_COMMIT)
		DBG(DBG_CONTROL, DBG_log(
			"IKE message has the Commit Flag set but Pluto doesn't implement this feature due to security concerns; ignoring flag"));

	/* Handle IKE fragmentation payloads */
	if (md->hdr.isa_np == ISAKMP_NEXT_IKE_FRAGMENTATION) {
		struct isakmp_ikefrag fraghdr;
		struct ike_frag *ike_frag, **i;
		int last_frag_index = 0;  /* index of the last fragment */
		pb_stream frag_pbs;

		if (st == NULL) {
			DBG(DBG_CONTROL, DBG_log(
				"received IKE fragment, but have no state. Ignoring packet."));
			return;
		}

		if ((st->st_connection->policy & POLICY_IKE_FRAG_ALLOW) == 0) {
			DBG(DBG_CONTROL, DBG_log(
			       "discarding IKE fragment packet - fragmentation not allowed by local policy (ike_frag=no)"));
			return;
		}

		if (!in_struct(&fraghdr, &isakmp_ikefrag_desc,
			       &md->message_pbs, &frag_pbs) ||
		    pbs_room(&frag_pbs) != fraghdr.isafrag_length ||
		    fraghdr.isafrag_np != ISAKMP_NEXT_NONE ||
		    fraghdr.isafrag_number == 0 ||
		    fraghdr.isafrag_number > 16) {
			SEND_NOTIFICATION(PAYLOAD_MALFORMED);
			return;
		}

		DBG(DBG_CONTROL,
		    DBG_log("received IKE fragment id '%d', number '%u'%s",
			    fraghdr.isafrag_id,
			    fraghdr.isafrag_number,
			    (fraghdr.isafrag_flags == 1) ? "(last)" : ""));

		ike_frag = alloc_thing(struct ike_frag, "ike_frag");
		ike_frag->md = md;
		ike_frag->index = fraghdr.isafrag_number;
		ike_frag->last = (fraghdr.isafrag_flags & 1);
		ike_frag->size = pbs_left(&frag_pbs);
		ike_frag->data = frag_pbs.cur;

#if 0
/* is this ever hit? It was wrongly checking one byte instead of 4 bytes of marker */
		/* Strip non-ESP marker from first fragment */
		if (md->iface->ike_float && ike_frag->index == 1 &&
		    (ike_frag->size >= NON_ESP_MARKER_SIZE &&
		     memeq(non_ESP_marker, ike_frag->data,
			    NON_ESP_MARKER_SIZE))) {
			ike_frag->data += NON_ESP_MARKER_SIZE;
			ike_frag->size -= NON_ESP_MARKER_SIZE;
		}
#endif

		/* Add the fragment to the state */
		i = &st->st_v1_rfrags;
		for (;;) {
			if (ike_frag != NULL) {
				/* Still looking for a place to insert ike_frag */
				if (*i == NULL ||
				    (*i)->index > ike_frag->index) {
					ike_frag->next = *i;
					*i = ike_frag;
					ike_frag = NULL;
				} else if ((*i)->index == ike_frag->index) {
					/* Replace fragment with same index */
					struct ike_frag *old = *i;

					ike_frag->next = old->next;
					*i = ike_frag;
					release_md(old->md);
					pfree(old);
					ike_frag = NULL;
				}
			}

			if (*i == NULL)
				break;

			if ((*i)->last)
				last_frag_index = (*i)->index;

			i = &(*i)->next;
		}

		/* We have the last fragment, reassemble if complete */
		if (last_frag_index != 0) {
			size_t size = 0;
			int prev_index = 0;
			struct ike_frag *frag;

			for (frag = st->st_v1_rfrags; frag; frag = frag->next) {
				size += frag->size;
				if (frag->index != ++prev_index) {
					break; /* fragment list incomplete */
				} else if (frag->index == last_frag_index) {
					struct msg_digest *whole_md = alloc_md("msg_digest by ikev1 fragment handler");
					uint8_t *buffer = alloc_bytes(size,
								       "IKE fragments buffer");
					size_t offset = 0;

					whole_md->iface = frag->md->iface;
					whole_md->sender = frag->md->sender;

					/* Reassemble fragments in buffer */
					frag = st->st_v1_rfrags;
					while (frag != NULL &&
					       frag->index <= last_frag_index)
					{
						passert(offset + frag->size <=
							size);
						memcpy(buffer + offset,
						       frag->data, frag->size);
						offset += frag->size;
						frag = frag->next;
					}

					init_pbs(&whole_md->packet_pbs, buffer, size,
						 "packet");

					process_packet(&whole_md);
					release_any_md(&whole_md);
					release_fragments(st);
					/* optimize: if receiving fragments, immediately respond with fragments too */
					st->st_seen_fragments = TRUE;
					DBG(DBG_CONTROL, DBG_log(
						" updated IKE fragment state to respond using fragments without waiting for re-transmits"));
					break;
				}
			}
		}

		/* Don't release the md, taken care of by the ike_frag code */
		/* ??? I'm not sure -- DHR */
		*mdp = NULL;
		return;
	}

	/* Set smc to describe this state's properties.
	 * Look up the appropriate microcode based on state and
	 * possibly Oakley Auth type.
	 */
	passert(STATE_IKEv1_FLOOR <= from_state && from_state < STATE_IKEv1_ROOF);
	const struct finite_state *fs = finite_states[from_state];
	passert(fs != NULL);
	smc = fs->fs_microcode;
	passert(smc != NULL);

	if (st != NULL) {
		oakley_auth_t baseauth =
			xauth_calcbaseauth(st->st_oakley.auth);

		while (!LHAS(smc->flags, baseauth)) {
			smc++;
			passert(smc->state == from_state);
		}
	}

	if (verbose_state_busy(st))
		return;

	/*
	 * Detect and handle duplicated packets.  This won't work for
	 * the initial packet of an exchange because we won't have a
	 * state object to remember it.  If we are in a non-receiving
	 * state (terminal), and the preceding state did transmit,
	 * then the duplicate may indicate that that transmission
	 * wasn't received -- retransmit it.  Otherwise, just discard
	 * it.  ??? Notification packets are like exchanges -- I hope
	 * that they are idempotent!
	 */
	if (st != NULL && ikev1_duplicate(st, md)) {
		return;
	}

	/* save values for use in resumption of processing below.
	 * (may be suspended due to crypto operation not yet complete)
	 */
	md->st = st;
	md->from_state = from_state;
	md->smc = smc;
	md->new_iv_set = new_iv_set;

	/*
	 * look for encrypt packets. We cannot handle them if we have not
	 * yet calculated the skeyids. We will just store the packet in
	 * the suspended state, since the calculation is likely underway.
	 *
	 * note that this differs from above, because skeyid is calculated
	 * in between states. (or will be, once DH is async)
	 *
	 */
	if ((md->hdr.isa_flags & ISAKMP_FLAGS_v1_ENCRYPTION) &&
	    st != NULL &&
	    !st->hidden_variables.st_skeyid_calculated) {
		DBG(DBG_CRYPT | DBG_CONTROL, {
			ipstr_buf b;
			DBG_log("received encrypted packet from %s:%u but exponentiation still in progress",
				ipstr(&md->sender, &b),
				(unsigned)hportof(&md->sender));
		});

		/*
		 * if there was a previous packet, let it go, and go
		 * with most recent one.
		 */
		if (st->st_suspended_md != NULL) {
			DBG(DBG_CONTROL,
			    DBG_log("releasing suspended operation before completion: %p",
				    st->st_suspended_md));
			release_any_md(&st->st_suspended_md);
		}
		suspend_md(st, mdp);
		return;
	}

	process_packet_tail(mdp);
	/* our caller will release_any_md(mdp); */
}

/*
 * This routine will not release_any_md(mdp).  It is expected that its
 * caller will do this.  In fact, it will zap *mdp to NULL if it thinks
 * **mdp should not be freed.  So the caller should be prepared for
 * *mdp being set to NULL.
 */
void process_packet_tail(struct msg_digest **mdp)
{
	struct msg_digest *md = *mdp;
	struct state *st = md->st;
	enum state_kind from_state = md->from_state;
	const struct state_v1_microcode *smc = md->smc;
	bool new_iv_set = md->new_iv_set;
	bool self_delete = FALSE;

	if (md->hdr.isa_flags & ISAKMP_FLAGS_v1_ENCRYPTION) {
		DBG(DBG_CRYPT, {
			ipstr_buf b;
			DBG_log("received encrypted packet from %s:%u",
				ipstr(&md->sender, &b),
				(unsigned)hportof(&md->sender));
		});

		if (st == NULL) {
			libreswan_log(
				"discarding encrypted message for an unknown ISAKMP SA");
			SEND_NOTIFICATION(PAYLOAD_MALFORMED /* XXX ? */);
			return;
		}
		if (st->st_skey_ei_nss == NULL) {
			loglog(RC_LOG_SERIOUS,
				"discarding encrypted message because we haven't yet negotiated keying material");
			SEND_NOTIFICATION(INVALID_FLAGS);
			return;
		}

		/* Mark as encrypted */
		md->encrypted = TRUE;

		DBG(DBG_CRYPT,
		    DBG_log("decrypting %u bytes using algorithm %s",
			    (unsigned) pbs_left(&md->message_pbs),
			    st->st_oakley.ta_encrypt->common.fqn));

		/* do the specified decryption
		 *
		 * IV is from st->st_iv or (if new_iv_set) st->st_new_iv.
		 * The new IV is placed in st->st_new_iv
		 *
		 * See RFC 2409 "IKE" Appendix B
		 *
		 * XXX The IV should only be updated really if the packet
		 * is successfully processed.
		 * We should keep this value, check for a success return
		 * value from the parsing routines and then replace.
		 *
		 * Each post phase 1 exchange generates IVs from
		 * the last phase 1 block, not the last block sent.
		 */
		{
			const struct encrypt_desc *e = st->st_oakley.ta_encrypt;

			if (pbs_left(&md->message_pbs) % e->enc_blocksize != 0)
			{
				loglog(RC_LOG_SERIOUS,
				       "malformed message: not a multiple of encryption blocksize");
				SEND_NOTIFICATION(PAYLOAD_MALFORMED);
				return;
			}

			/* XXX Detect weak keys */

			/* grab a copy of raw packet (for duplicate packet detection) */
			clonetochunk(md->raw_packet, md->packet_pbs.start,
				     pbs_room(&md->packet_pbs), "raw packet");

			/* Decrypt everything after header */
			if (!new_iv_set) {
				if (st->st_iv_len == 0) {
					init_phase2_iv(st, &md->hdr.isa_msgid);
				} else {
					/* use old IV */
					restore_new_iv(st, st->st_iv, st->st_iv_len);
				}
			}

			passert(st->st_new_iv_len >= e->enc_blocksize);
			st->st_new_iv_len = e->enc_blocksize;   /* truncate */
			e->encrypt_ops->do_crypt(e, md->message_pbs.cur,
						 pbs_left(&md->message_pbs),
						 st->st_enc_key_nss,
						 st->st_new_iv, FALSE);

		}

		DBG_cond_dump(DBG_CRYPT, "decrypted:\n", md->message_pbs.cur,
			      md->message_pbs.roof - md->message_pbs.cur);

		DBG_cond_dump(DBG_CRYPT, "next IV:",
			      st->st_new_iv, st->st_new_iv_len);
	} else {
		/* packet was not encryped -- should it have been? */

		if (smc->flags & SMF_INPUT_ENCRYPTED) {
			loglog(RC_LOG_SERIOUS,
			       "packet rejected: should have been encrypted");
			SEND_NOTIFICATION(INVALID_FLAGS);
			return;
		}
	}

	/* Digest the message.
	 * Padding must be removed to make hashing work.
	 * Padding comes from encryption (so this code must be after decryption).
	 * Padding rules are described before the definition of
	 * struct isakmp_hdr in packet.h.
	 */
	{
		enum next_payload_types_ikev1 np = md->hdr.isa_np;
		lset_t needed = smc->req_payloads;
		const char *excuse =
			LIN(SMF_PSK_AUTH | SMF_FIRST_ENCRYPTED_INPUT,
			    smc->flags) ?
			"probable authentication failure (mismatch of preshared secrets?): "
			:
			"";

		while (np != ISAKMP_NEXT_NONE) {
			struct_desc *sd = v1_payload_desc(np);

			if (md->digest_roof >= elemsof(md->digest)) {
				loglog(RC_LOG_SERIOUS,
				       "more than %zu payloads in message; ignored",
				       elemsof(md->digest));
				SEND_NOTIFICATION(PAYLOAD_MALFORMED);
				return;
			}
			struct payload_digest *const pd = md->digest + md->digest_roof;

			/*
			 * only do this in main mode. In aggressive mode, there
			 * is no negotiation of NAT-T method. Get it right.
			 */
			if (st != NULL && st->st_connection != NULL &&
			    (st->st_connection->policy & POLICY_AGGRESSIVE) == LEMPTY)
			{
				switch (np) {
				case ISAKMP_NEXT_NATD_RFC:
				case ISAKMP_NEXT_NATOA_RFC:
					if ((st->hidden_variables.st_nat_traversal & NAT_T_WITH_RFC_VALUES) == LEMPTY) {
						/*
						 * don't accept NAT-D/NAT-OA reloc directly in message,
						 * unless we're using NAT-T RFC
						 */
						DBG(DBG_NATT,
						    DBG_log("st_nat_traversal was: %s",
							    bitnamesof(natt_bit_names,
								       st->hidden_variables.st_nat_traversal)));
						sd = NULL;
					}
					break;
				default:
					break;
				}
			}

			if (sd == NULL) {
				/* payload type is out of range or requires special handling */
				switch (np) {
				case ISAKMP_NEXT_ID:
					/* ??? two kinds of ID payloads */
					sd = (IS_PHASE1(from_state) ||
					      IS_PHASE15(from_state)) ?
						&isakmp_identification_desc :
						&isakmp_ipsec_identification_desc;
					break;

				case ISAKMP_NEXT_NATD_DRAFTS: /* out of range */
					/*
					 * ISAKMP_NEXT_NATD_DRAFTS was a private use type before RFC-3947.
					 * Since it has the same format as ISAKMP_NEXT_NATD_RFC,
					 * just rewrite np and sd, and carry on.
					 */
					np = ISAKMP_NEXT_NATD_RFC;
					sd = &isakmp_nat_d_drafts;
					break;

				case ISAKMP_NEXT_NATOA_DRAFTS: /* out of range */
					/* NAT-OA was a private use type before RFC-3947 -- same format */
					np = ISAKMP_NEXT_NATOA_RFC;
					sd = &isakmp_nat_oa_drafts;
					break;

				case ISAKMP_NEXT_SAK: /* or ISAKMP_NEXT_NATD_BADDRAFTS */
					/*
					 * Official standards say that this is ISAKMP_NEXT_SAK,
					 * a part of Group DOI, something we don't implement.
					 * Old non-updated Cisco gear abused this number in ancient NAT drafts.
					 * We ignore (rather than reject) this in support of people
					 * with crufty Cisco machines.
					 */
					loglog(RC_LOG_SERIOUS,
						"%smessage with unsupported payload ISAKMP_NEXT_SAK (or ISAKMP_NEXT_NATD_BADDRAFTS) ignored",
						excuse);
					/*
					 * Hack to discard payload, whatever it was.
					 * Since we are skipping the rest of the loop
					 * body we must do some things ourself:
					 * - demarshall the payload
					 * - grab the next payload number (np)
					 * - don't keep payload (don't increment pd)
					 * - skip rest of loop body
					 */
					if (!in_struct(&pd->payload, &isakmp_ignore_desc, &md->message_pbs,
						       &pd->pbs)) {
						loglog(RC_LOG_SERIOUS,
						       "%smalformed payload in packet",
						       excuse);
						SEND_NOTIFICATION(PAYLOAD_MALFORMED);
						return;
					}
					np = pd->payload.generic.isag_np;
					/* NOTE: we do not increment pd! */
					continue;  /* skip rest of the loop */

				default:
					loglog(RC_LOG_SERIOUS,
						"%smessage ignored because it contains an unknown or unexpected payload type (%s) at the outermost level",
					       excuse,
					       enum_show(&ikev1_payload_names, np));
					SEND_NOTIFICATION(INVALID_PAYLOAD_TYPE);
					return;
				}
				passert(sd != NULL);
			}

			passert(np < LELEM_ROOF);

			{
				lset_t s = LELEM(np);

				if (LDISJOINT(s,
					      needed | smc->opt_payloads |
					      LELEM(ISAKMP_NEXT_VID) |
					      LELEM(ISAKMP_NEXT_N) |
					      LELEM(ISAKMP_NEXT_D) |
					      LELEM(ISAKMP_NEXT_CR) |
					      LELEM(ISAKMP_NEXT_CERT))) {
					loglog(RC_LOG_SERIOUS,
						"%smessage ignored because it contains a payload type (%s) unexpected by state %s",
						excuse,
						enum_show(&ikev1_payload_names, np),
						st->st_state_name);
					SEND_NOTIFICATION(INVALID_PAYLOAD_TYPE);
					return;
				}

				DBG(DBG_PARSING,
				    DBG_log("got payload 0x%" PRIxLSET"  (%s) needed: 0x%" PRIxLSET " opt: 0x%" PRIxLSET,
					    s, enum_show(&ikev1_payload_names, np),
					    needed, smc->opt_payloads));
				needed &= ~s;
			}

			if (!in_struct(&pd->payload, sd, &md->message_pbs,
				       &pd->pbs)) {
				loglog(RC_LOG_SERIOUS,
				       "%smalformed payload in packet",
				       excuse);
				SEND_NOTIFICATION(PAYLOAD_MALFORMED);
				return;
			}

			/* do payload-type specific debugging */
			switch (np) {
			case ISAKMP_NEXT_ID:
			case ISAKMP_NEXT_NATOA_RFC:
				/* dump ID section */
				DBG(DBG_PARSING,
				    DBG_dump("     obj: ", pd->pbs.cur,
					     pbs_left(&pd->pbs)));
				break;
			default:
				break;
			}


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

			np = pd->payload.generic.isag_np;
			md->digest_roof++;

			/* since we've digested one payload happily, it is probably
			 * the case that any decryption worked.  So we will not suggest
			 * encryption failure as an excuse for subsequent payload
			 * problems.
			 */
			excuse = "";
		}

		DBG(DBG_PARSING, {
			    if (pbs_left(&md->message_pbs) != 0)
				    DBG_log("removing %d bytes of padding",
					    (int) pbs_left(&md->message_pbs));
		    });

		md->message_pbs.roof = md->message_pbs.cur;

		/* check that all mandatory payloads appeared */

		if (needed != 0) {
			loglog(RC_LOG_SERIOUS,
			       "message for %s is missing payloads %s",
			       enum_name(&state_names, from_state),
			       bitnamesof(payload_name_ikev1, needed));
			SEND_NOTIFICATION(PAYLOAD_MALFORMED);
			return;
		}
	}

	/* more sanity checking: enforce most ordering constraints */

	if (IS_PHASE1(from_state) || IS_PHASE15(from_state)) {
		/* rfc2409: The Internet Key Exchange (IKE), 5 Exchanges:
		 * "The SA payload MUST precede all other payloads in a phase 1 exchange."
		 */
		if (md->chain[ISAKMP_NEXT_SA] != NULL &&
		    md->hdr.isa_np != ISAKMP_NEXT_SA) {
			loglog(RC_LOG_SERIOUS,
			       "malformed Phase 1 message: does not start with an SA payload");
			SEND_NOTIFICATION(PAYLOAD_MALFORMED);
			return;
		}
	} else if (IS_QUICK(from_state)) {
		/* rfc2409: The Internet Key Exchange (IKE), 5.5 Phase 2 - Quick Mode
		 *
		 * "In Quick Mode, a HASH payload MUST immediately follow the ISAKMP
		 *  header and a SA payload MUST immediately follow the HASH."
		 * [NOTE: there may be more than one SA payload, so this is not
		 *  totally reasonable.  Probably all SAs should be so constrained.]
		 *
		 * "If ISAKMP is acting as a client negotiator on behalf of another
		 *  party, the identities of the parties MUST be passed as IDci and
		 *  then IDcr."
		 *
		 * "With the exception of the HASH, SA, and the optional ID payloads,
		 *  there are no payload ordering restrictions on Quick Mode."
		 */

		if (md->hdr.isa_np != ISAKMP_NEXT_HASH) {
			loglog(RC_LOG_SERIOUS,
			       "malformed Quick Mode message: does not start with a HASH payload");
			SEND_NOTIFICATION(PAYLOAD_MALFORMED);
			return;
		}

		{
			struct payload_digest *p;
			int i;

			p = md->chain[ISAKMP_NEXT_SA];
			i = 1;
			while (p != NULL) {
				if (p != &md->digest[i]) {
					loglog(RC_LOG_SERIOUS,
					       "malformed Quick Mode message: SA payload is in wrong position");
					SEND_NOTIFICATION(PAYLOAD_MALFORMED);
					return;
				}
				p = p->next;
				i++;
			}
		}

		/* rfc2409: The Internet Key Exchange (IKE), 5.5 Phase 2 - Quick Mode:
		 * "If ISAKMP is acting as a client negotiator on behalf of another
		 *  party, the identities of the parties MUST be passed as IDci and
		 *  then IDcr."
		 */
		{
			struct payload_digest *id = md->chain[ISAKMP_NEXT_ID];

			if (id != NULL) {
				if (id->next == NULL ||
				    id->next->next != NULL) {
					loglog(RC_LOG_SERIOUS,
						"malformed Quick Mode message: if any ID payload is present, there must be exactly two");
					SEND_NOTIFICATION(PAYLOAD_MALFORMED);
					return;
				}
				if (id + 1 != id->next) {
					loglog(RC_LOG_SERIOUS,
						"malformed Quick Mode message: the ID payloads are not adjacent");
					SEND_NOTIFICATION(PAYLOAD_MALFORMED);
					return;
				}
			}
		}
	}

	/*
	 * Ignore payloads that we don't handle:
	 */
	/* XXX Handle Notifications */
	{
		struct payload_digest *p = md->chain[ISAKMP_NEXT_N];

		while (p != NULL) {
			switch (p->payload.notification.isan_type) {
			case R_U_THERE:
			case R_U_THERE_ACK:
			case ISAKMP_N_CISCO_LOAD_BALANCE:
			case PAYLOAD_MALFORMED:
			case INVALID_MESSAGE_ID:
			case IPSEC_RESPONDER_LIFETIME:
				if (md->hdr.isa_xchg == ISAKMP_XCHG_INFO) {
					/* these are handled later on in informational() */
					break;
				}
				/* FALL THROUGH */
			default:
				if (st == NULL) {
					DBG(DBG_CONTROL, DBG_log(
					       "ignoring informational payload %s, no corresponding state",
					       enum_show(& ikev1_notify_names,
							 p->payload.notification.isan_type)));
				} else {
					loglog(RC_LOG_SERIOUS,
					       "ignoring informational payload %s, msgid=%08" PRIx32 ", length=%d",
					       enum_show(&ikev1_notify_names,
							 p->payload.notification.isan_type),
					       st->st_msgid,
					       p->payload.notification.isan_length);
					DBG_dump_pbs(&p->pbs);
				}
			}
			DBG_cond_dump(DBG_PARSING, "info:", p->pbs.cur, pbs_left(
					      &p->pbs));

			p = p->next;
		}

		p = md->chain[ISAKMP_NEXT_D];
		while (p != NULL) {
			self_delete |= accept_delete(md, p);
			DBG_cond_dump(DBG_PARSING, "del:", p->pbs.cur, pbs_left(
					      &p->pbs));
			p = p->next;
		}

		p = md->chain[ISAKMP_NEXT_VID];
		while (p != NULL) {
			handle_vendorid(md, (char *)p->pbs.cur,
					pbs_left(&p->pbs), FALSE);
			p = p->next;
		}
	}

	if (self_delete) {
		accept_self_delete(md);
		st = md->st;
		/* note: st ought to be NULL from here on */
	}

	complete_v1_state_transition(mdp, smc->processor(st, md));
	/* our caller will release_any_md(mdp); */
}

/*
 * replace previous receive packet with latest, to update
 * our notion of a retransmitted packet. This is important
 * to do, even for failing transitions, and suspended transitions
 * because the sender may well retransmit their request.
 * We had better be idempotent since we can be called
 * multiple times in handling a packet due to crypto helper logic.
 */
static void remember_received_packet(struct state *st, struct msg_digest *md)
{
	if (md->encrypted) {
		/* if encrypted, duplication already done */
		if (md->raw_packet.ptr != NULL) {
			pfreeany(st->st_rpacket.ptr);
			st->st_rpacket = md->raw_packet;
			md->raw_packet.ptr = NULL;
		}
	} else {
		/* this may be a repeat, but it will work */
		pfreeany(st->st_rpacket.ptr);
		clonetochunk(st->st_rpacket,
			     md->packet_pbs.start,
			     pbs_room(&md->packet_pbs), "raw packet");
	}
}

/* complete job started by the state-specific state transition function
 *
 * This routine will not release_any_md(mdp).  It is expected that its
 * caller will do this.  In fact, it will zap *mdp to NULL if it thinks
 * **mdp should not be freed.  So the caller should be prepared for
 * *mdp being set to NULL.
 *
 * md is used to:
 * - find st
 * - find from_state (st might be gone)
 * - find note for STF_FAIL (might not be part of result (STF_FAIL+note))
 * - find note for STF_INTERNAL_ERROR
 * - record md->event_already_set
 * - remember_received_packet(st, md);
 * - nat_traversal_change_port_lookup(md, st);
 * - smc for smc->next_state
 * - smc for smc->flags & SMF_REPLY to trigger a reply
 * - smc for smc->timeout_event
 * - smc for !(smc->flags & SMF_INITIATOR) for Contivity mode
 * - smc for smc->flags & SMF_RELEASE_PENDING_P2 to trigger unpend call
 * - smc for smc->flags & SMF_INITIATOR to adjust retransmission
 * - fragvid, dpd, nortel
 */
void complete_v1_state_transition(struct msg_digest **mdp, stf_status result)
{
	struct msg_digest *md = *mdp;
	passert(md != NULL);

	/* handle oddball/meta results now */

	/*
	 * statistics; lump all FAILs together
	 *
	 * Fun fact: using min() stupidly fails (at least in GCC 8.1.1 with -Werror=sign-compare)
	 * error: comparison of integer expressions of different signedness: `stf_status' {aka `enum <anonymous>'} and `int'
	 */
	pstats(ike_stf, PMIN(result, STF_FAIL));

	DBG(DBG_CONTROL,
	    DBG_log("complete v1 state transition with %s",
		    result > STF_FAIL ?
		    enum_name(&ikev1_notify_names, result - STF_FAIL) :
		    enum_name(&stf_status_names, result)));

	switch (result) {
	case STF_SUSPEND:
		set_cur_state(md->st);	/* might have changed */
		if (*mdp != NULL) {
			/*
			 * If this transition was triggered by an
			 * incoming packet, save it.
			 *
			 * XXX: some initiator code creates a fake MD
			 * (there isn't a real one); save that as
			 * well.
			 */
			suspend_md(md->st, mdp);
			passert(*mdp == NULL); /* ownership transfered */
		}
		return;
	case STF_IGNORE:
		return;
	default:
		break;
	}

	/* safe to refer to *md */

	enum state_kind from_state = md->from_state;

	struct state *st = md->st;
	set_cur_state(st); /* might have changed */

	passert(st != NULL);
	pexpect(!state_is_busy(st));

	switch (result) {
	case STF_OK:
	{
		/* advance the state */
		const struct state_v1_microcode *smc = md->smc;

		DBG(DBG_CONTROL, DBG_log("doing_xauth:%s, t_xauth_client_done:%s",
			bool_str(st->st_oakley.doing_xauth),
			bool_str(st->hidden_variables.st_xauth_client_done)));

		/* accept info from VID because we accept this message */

		/* If state has FRAGMENTATION support, import it */
		if (md->fragvid) {
			DBG(DBG_CONTROLMORE, DBG_log("peer supports fragmentation"));
			st->st_seen_fragvid = TRUE;
		}

		/* If state has DPD support, import it */
		if (md->dpd &&
		    st->hidden_variables.st_peer_supports_dpd != md->dpd) {
			DBG(DBG_DPD, DBG_log("peer supports dpd"));
			st->hidden_variables.st_peer_supports_dpd = md->dpd;

			if (dpd_active_locally(st)) {
				DBG(DBG_DPD, DBG_log("dpd is active locally"));
			}
		}

		/* If state has VID_NORTEL, import it to activate workaround */
		if (md->nortel) {
			DBG(DBG_CONTROLMORE, DBG_log("peer requires Nortel Contivity workaround"));
			st->st_seen_nortel_vid = TRUE;
		}

		if (!st->st_msgid_reserved &&
		    IS_CHILD_SA(st) &&
		    st->st_msgid != v1_MAINMODE_MSGID) {
			struct state *p1st = state_with_serialno(
				st->st_clonedfrom);

			if (p1st != NULL) {
				/* do message ID reservation */
				reserve_msgid(p1st, st->st_msgid);
			}

			st->st_msgid_reserved = TRUE;
		}

		DBG(DBG_CONTROL, DBG_log("IKEv1: transition from state %s to state %s",
			      enum_name(&state_names, from_state),
			      enum_name(&state_names, smc->next_state)));

		change_state(st, smc->next_state);

		/*
		 * XAUTH negotiation without ModeCFG cannot follow the regular
		 * state machine change as it cannot be determined if the CFG
		 * payload is "XAUTH OK, no ModeCFG" or "XAUTH OK, expect
		 * ModeCFG". To the smc, these two cases look identical. So we
		 * have an ad hoc state change here for the case where
		 * we have XAUTH but not ModeCFG. We move it to the established
		 * state, so the regular state machine picks up the Quick Mode.
		 */
		if (st->st_connection->spd.this.xauth_client &&
		    st->hidden_variables.st_xauth_client_done &&
		    !st->st_connection->spd.this.modecfg_client &&
		    st->st_state == STATE_XAUTH_I1)
		{
			bool aggrmode = LHAS(st->st_connection->policy, POLICY_AGGRESSIVE_IX);

			libreswan_log("XAUTH completed; ModeCFG skipped as per configuration");
			change_state(st, aggrmode ? STATE_AGGR_I2 : STATE_MAIN_I4);
			st->st_msgid_phase15 = v1_MAINMODE_MSGID;
		}

		/* Schedule for whatever timeout is specified */
		if (!md->event_already_set) {
			/*
			 * This md variable is hardly ever set.
			 * Only deals with v1 <-> v2 switching
			 * which will be removed in the near future anyway
			 * (PW 2017 Oct 8)
			 */
			DBG(DBG_CONTROL, DBG_log("event_already_set, deleting event"));
			/*
			 * Delete previous retransmission event.
			 * New event will be scheduled below.
			 */
			delete_event(st);
		}

		/* Delete IKE fragments */
		release_fragments(st);

		/* scrub the previous packet exchange */
		freeanychunk(st->st_rpacket);
		freeanychunk(st->st_tpacket);

		/* in aggressive mode, there will be no reply packet in transition
		 * from STATE_AGGR_R1 to STATE_AGGR_R2
		 */
		if (nat_traversal_enabled && st->st_connection->ikev1_natt != NATT_NONE) {
			/* adjust our destination port if necessary */
			nat_traversal_change_port_lookup(md, st);
		}

		/* if requested, send the new reply packet */
		if (smc->flags & SMF_REPLY) {
			/*
			 * Since replying, save previous packet so
			 * that re-transmits can deal with it.
			 */
			remember_received_packet(st, md);
			DBG(DBG_CONTROL, {
				ipstr_buf b;
				DBG_log("sending reply packet to %s:%u (from port %u)",
					ipstr(&st->st_remoteaddr, &b),
					st->st_remoteport,
					st->st_interface->port);
			});

			close_output_pbs(&reply_stream); /* good form, but actually a no-op */

			if (st->st_state == STATE_MAIN_R2 &&
				IMPAIR(SEND_NO_MAIN_R2)) {
				/* record-only so we propely emulate packet drop */
				record_outbound_ike_msg(st, &reply_stream,
					enum_name(&state_names, from_state));
				libreswan_log("IMPAIR: Skipped sending STATE_MAIN_R2 response packet");
			} else {
				record_and_send_v1_ike_msg(st, &reply_stream,
					enum_name(&state_names, from_state));
			}
		}

		/* Schedule for whatever timeout is specified */
		if (!md->event_already_set) {
			DBG(DBG_CONTROL, DBG_log("!event_already_set at reschedule"));
			intmax_t delay_ms; /* delay is in milliseconds here */
			enum event_type kind = smc->timeout_event;
			bool agreed_time = FALSE;
			struct connection *c = st->st_connection;

			/* fixup in case of state machine jump for xauth without modecfg */
			if (c->spd.this.xauth_client &&
			    st->hidden_variables.st_xauth_client_done &&
			    !c->spd.this.modecfg_client &&
			    (st->st_state == STATE_MAIN_I4 || st->st_state == STATE_AGGR_I2))
			{
				DBG(DBG_CONTROL, DBG_log("fixup XAUTH without ModeCFG event from EVENT_v1_RETRANSMIT to EVENT_SA_REPLACE"));
				kind = EVENT_SA_REPLACE;
			}

			switch (kind) {
			case EVENT_v1_RETRANSMIT: /* Retransmit packet */
				start_retransmits(st, EVENT_v1_RETRANSMIT);
				break;

			case EVENT_SA_REPLACE: /* SA replacement event */
				if (IS_PHASE1(st->st_state) ||
				    IS_PHASE15(st->st_state )) {
					/* Note: we will defer to the "negotiated" (dictated)
					 * lifetime if we are POLICY_DONT_REKEY.
					 * This allows the other side to dictate
					 * a time we would not otherwise accept
					 * but it prevents us from having to initiate
					 * rekeying.  The negative consequences seem
					 * minor.
					 */
					delay_ms = deltamillisecs(c->sa_ike_life_seconds);
					if ((c->policy & POLICY_DONT_REKEY) ||
					    delay_ms >= deltamillisecs(st->st_oakley.life_seconds))
					{
						agreed_time = TRUE;
						delay_ms = deltamillisecs(st->st_oakley.life_seconds);
					}
				} else {
					/* Delay is min of up to four things:
					 * each can limit the lifetime.
					 */
					time_t delay = deltasecs(c->sa_ipsec_life_seconds);

#define clamp_delay(trans) { \
		if (st->trans.present && \
		    delay >= deltasecs(st->trans.attrs.life_seconds)) { \
			agreed_time = TRUE; \
			delay = deltasecs(st->trans.attrs.life_seconds); \
		} \
	}
					clamp_delay(st_ah);
					clamp_delay(st_esp);
					clamp_delay(st_ipcomp);
					delay_ms = delay * 1000;
#undef clamp_delay
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
				if (agreed_time &&
				    (c->policy & POLICY_DONT_REKEY)) {
					kind = (smc->flags & SMF_INITIATOR) ?
					       EVENT_SA_REPLACE_IF_USED :
					       EVENT_SA_EXPIRE;
				}
				if (kind != EVENT_SA_EXPIRE) {
					time_t marg =
						deltasecs(c->sa_rekey_margin);

					if (smc->flags & SMF_INITIATOR) {
						marg += marg *
							c->sa_rekey_fuzz /
							100.E0 *
							(rand() /
							 (RAND_MAX + 1.E0));
					} else {
						marg /= 2;
					}

					if (delay_ms > marg * 1000) {
						delay_ms -= marg * 1000;
						st->st_margin = deltatime(marg);
					} else {
						kind = EVENT_SA_EXPIRE;
					}
				}
				/* XXX: DELAY_MS should be a deltatime_t */
				event_schedule(kind, deltatime_ms(delay_ms), st);
				break;

			case EVENT_SO_DISCARD:
				event_schedule(EVENT_SO_DISCARD, c->r_timeout, st);
				break;

			default:
				bad_case(kind);
			}
		}

		/* tell whack and log of progress */
		{
			enum rc_type w;
			void (*log_details)(struct lswlog *buf, struct state *st);

			if (IS_IPSEC_SA_ESTABLISHED(st)) {
				log_details = lswlog_child_sa_established;
				w = RC_SUCCESS; /* log our success */
			} else if (IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
				log_details = lswlog_ike_sa_established;
				w = RC_SUCCESS; /* log our success */
			} else {
				log_details = NULL;
				w = RC_NEW_STATE + st->st_state;
			}

			passert(st->st_state < STATE_IKEv1_ROOF);

			/* tell whack and logs our progress */
			LSWLOG_RC(w, buf) {
				lswlogf(buf, "%s: %s", st->st_finite_state->fs_name,
					st->st_finite_state->fs_story);
				/* document SA details for admin's pleasure */
				if (log_details != NULL) {
					log_details(buf, st);
				}
			}
		}

		/*
		 * make sure that a DPD event gets created for a new phase 1
		 * SA.
		 */
		if (IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
			if (deltasecs(st->st_connection->dpd_delay) > 0 &&
			    deltasecs(st->st_connection->dpd_timeout) > 0) {
				/* don't ignore failure */
				/* ??? in fact, we do ignore this:
				 * result is NEVER used
				 * (clang 3.4 noticed this)
				 */
				stf_status s = dpd_init(st);

				if (!pexpect(s != STF_FAIL))
					result = STF_FAIL; /* ??? fall through !?! */
				/* ??? result not subsequently used. Looks bad! */
			}
		}

		/* Special case for XAUTH server */
		if (st->st_connection->spd.this.xauth_server) {
			if (st->st_oakley.doing_xauth &&
			    IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
				DBG(DBG_CONTROLMORE|DBG_XAUTH,
				    DBG_log("XAUTH: Sending XAUTH Login/Password Request"));
				event_schedule(EVENT_v1_SEND_XAUTH,
					       deltatime_ms(EVENT_v1_SEND_XAUTH_DELAY_MS),
					       st);
				break;
			}
		}

		/*
		 * for XAUTH client, we are also done, because we need to
		 * stay in this state, and let the server query us
		 */
		if (!IS_QUICK(st->st_state) &&
		    st->st_connection->spd.this.xauth_client &&
		    !st->hidden_variables.st_xauth_client_done) {
			DBG(DBG_CONTROL,
			    DBG_log("XAUTH client is not yet authenticated"));
			break;
		}

		/*
		 * when talking to some vendors, we need to initiate a mode
		 * cfg request to get challenged, but there is also an
		 * override in the form of a policy bit.
		 */
		DBG(DBG_CONTROL,
		    DBG_log("modecfg pull: %s policy:%s %s",
			    (st->quirks.modecfg_pull_mode ?
			     "quirk-poll" : "noquirk"),
			    (st->st_connection->policy & POLICY_MODECFG_PULL) ?
			    "pull" : "push",
			    (st->st_connection->spd.this.modecfg_client ?
			     "modecfg-client" : "not-client")));

		if (st->st_connection->spd.this.modecfg_client &&
		    IS_ISAKMP_SA_ESTABLISHED(st->st_state) &&
		    (st->quirks.modecfg_pull_mode ||
		     st->st_connection->policy & POLICY_MODECFG_PULL) &&
		    !st->hidden_variables.st_modecfg_started) {
			DBG(DBG_CONTROL,
			    DBG_log("modecfg client is starting due to %s",
				    st->quirks.modecfg_pull_mode ? "quirk" :
				    "policy"));
			modecfg_send_request(st);
			break;
		}

		/* Should we set the peer's IP address regardless? */
		if (st->st_connection->spd.this.modecfg_server &&
		    IS_ISAKMP_SA_ESTABLISHED(st->st_state) &&
		    !st->hidden_variables.st_modecfg_vars_set &&
		    !(st->st_connection->policy & POLICY_MODECFG_PULL)) {
			change_state(st, STATE_MODE_CFG_R1);
			set_cur_state(st);
			libreswan_log("Sending MODE CONFIG set");
			/*
			 * ??? we ignore the result of modecfg.
			 * But surely, if it fails, we ought to terminate this exchange.
			 * What do the RFCs say?
			 */
			modecfg_start_set(st);
			break;
		}

		/*
		 * If we are the responder and the client is in "Contivity mode",
		 * we need to initiate Quick mode
		 */
		if (!(smc->flags & SMF_INITIATOR) &&
		    IS_MODE_CFG_ESTABLISHED(st->st_state) &&
		    (st->st_seen_nortel_vid)) {
			libreswan_log("Nortel 'Contivity Mode' detected, starting Quick Mode");
			change_state(st, STATE_MAIN_R3); /* ISAKMP is up... */
			set_cur_state(st);
			quick_outI1(st->st_whack_sock, st, st->st_connection,
				    st->st_connection->policy, 1, SOS_NOBODY
#ifdef HAVE_LABELED_IPSEC
				    , NULL /* Setting NULL as this is responder and will not have sec ctx from a flow*/
#endif
				    );
			break;
		}

		/* wait for modecfg_set */
		if (st->st_connection->spd.this.modecfg_client &&
		    IS_ISAKMP_SA_ESTABLISHED(st->st_state) &&
		    !st->hidden_variables.st_modecfg_vars_set) {
			DBG(DBG_CONTROL,
			    DBG_log("waiting for modecfg set from server"));
			break;
		}

		if (st->st_rekeytov2) {
			DBG(DBG_CONTROL,
			    DBG_log("waiting for IKEv1 -> IKEv2 rekey"));
			break;
		}

		DBG(DBG_CONTROL,
		    DBG_log("phase 1 is done, looking for phase 2 to unpend"));

		if (smc->flags & SMF_RELEASE_PENDING_P2) {
			/* Initiate any Quick Mode negotiations that
			 * were waiting to piggyback on this Keying Channel.
			 *
			 * ??? there is a potential race condition
			 * if we are the responder: the initial Phase 2
			 * message might outrun the final Phase 1 message.
			 *
			 * so, instead of actually sending the traffic now,
			 * we schedule an event to do so.
			 *
			 * but, in fact, quick_mode will enqueue a cryptographic operation
			 * anyway, which will get done "later" anyway, so maybe it is just fine
			 * as it is.
			 *
			 */
			unpend(st, NULL);
		}

		if (IS_ISAKMP_SA_ESTABLISHED(st->st_state) ||
		    IS_IPSEC_SA_ESTABLISHED(st))
			release_whack(st);

		if (IS_QUICK(st->st_state))
			break;

		break;
	}

	case STF_INTERNAL_ERROR:
		/* update the previous packet history */
		remember_received_packet(st, md);

		whack_log(RC_INTERNALERR + md->v1_note,
			  "%s: internal error",
			  st->st_state_name);

		DBG(DBG_CONTROL,
		    DBG_log("state transition function for %s had internal error",
			    enum_name(&state_names, from_state)));
		break;

	case STF_FATAL:
		/* update the previous packet history */
		remember_received_packet(st, md);

		whack_log(RC_FATAL,
			  "encountered fatal error in state %s",
			  st->st_state_name);
#ifdef HAVE_NM
		if (st->st_connection->remotepeertype == CISCO &&
		    st->st_connection->nmconfigured) {
			if (!do_command(st->st_connection,
					&st->st_connection->spd,
					"disconnectNM", st))
				DBG(DBG_CONTROL,
				    DBG_log("sending disconnect to NM failed, you may need to do it manually"));
		}
#endif
		release_pending_whacks(st, "fatal error");
		delete_state(st);
		md->st = st = NULL;
		break;

	default:        /* a shortcut to STF_FAIL, setting md->note */
		passert(result > STF_FAIL);
		md->v1_note = result - STF_FAIL;
		/* FALL THROUGH */
	case STF_FAIL:
		/* As it is, we act as if this message never happened:
		 * whatever retrying was in place, remains in place.
		 */
		/*
		 * ??? why no call of remember_received_packet?
		 * Perhaps because the message hasn't been authenticated?
		 * But then then any duplicate would lose too, I would think.
		 */
		whack_log(RC_NOTIFICATION + md->v1_note,
			  "%s: %s", st->st_state_name,
			  enum_name(&ikev1_notify_names, md->v1_note));

		if (md->v1_note != NOTHING_WRONG)
			SEND_NOTIFICATION(md->v1_note);

		DBG(DBG_CONTROL,
		    DBG_log("state transition function for %s failed: %s",
			    enum_name(&state_names, from_state),
			    enum_name(&ikev1_notify_names, md->v1_note)));

#ifdef HAVE_NM
		if (st->st_connection->remotepeertype == CISCO &&
		    st->st_connection->nmconfigured) {
			if (!do_command(st->st_connection,
					&st->st_connection->spd,
					"disconnectNM", st))
				DBG(DBG_CONTROL,
				    DBG_log("sending disconnect to NM failed, you may need to do it manually"));
		}
#endif
		if (IS_QUICK(st->st_state)) {
			delete_state(st);
			/* wipe out dangling pointer to st */
			md->st = NULL;
		}
		break;
	}
}

/*
 * note: may change which connection is referenced by md->st->st_connection.
 * But only if we are a Main Mode Responder.
 */
bool ikev1_decode_peer_id(struct msg_digest *md, bool initiator, bool aggrmode)
{
	struct state *const st = md->st;
	struct connection *c = st->st_connection;
	const struct payload_digest *const id_pld = md->chain[ISAKMP_NEXT_ID];
	const struct isakmp_id *const id = &id_pld->payload.id;

	/*
	 * I think that RFC2407 (IPSEC DOI) 4.6.2 is confused.
	 * It talks about the protocol ID and Port fields of the ID
	 * Payload, but they don't exist as such in Phase 1.
	 * We use more appropriate names.
	 * isaid_doi_specific_a is in place of Protocol ID.
	 * isaid_doi_specific_b is in place of Port.
	 * Besides, there is no good reason for allowing these to be
	 * other than 0 in Phase 1.
	 */
	if (st->hidden_variables.st_nat_traversal != LEMPTY &&
	    id->isaid_doi_specific_a == IPPROTO_UDP &&
	    (id->isaid_doi_specific_b == 0 ||
	     id->isaid_doi_specific_b == pluto_nat_port)) {
		DBG_log("protocol/port in Phase 1 ID Payload is %d/%d. accepted with port_floating NAT-T",
			id->isaid_doi_specific_a, id->isaid_doi_specific_b);
	} else if (!(id->isaid_doi_specific_a == 0 &&
		     id->isaid_doi_specific_b == 0) &&
		   !(id->isaid_doi_specific_a == IPPROTO_UDP &&
		     id->isaid_doi_specific_b == pluto_port))
	{
		loglog(RC_LOG_SERIOUS,
			"protocol/port in Phase 1 ID Payload MUST be 0/0 or %d/%d but are %d/%d (attempting to continue)",
			IPPROTO_UDP, pluto_port,
			id->isaid_doi_specific_a,
			id->isaid_doi_specific_b);
		/*
		 * We have turned this into a warning because of bugs in other
		 * vendors' products. Specifically CISCO VPN3000.
		 */
		/* return FALSE; */
	}

	struct id peer;

	if (!extract_peer_id(id->isaid_idtype, &peer, &id_pld->pbs))
		return FALSE;

	if (c->spd.that.id.kind == ID_FROMCERT) {
		/* breaks API, connection modified by %fromcert */
		duplicate_id(&c->spd.that.id, &peer);
	}

	/*
	 * For interop with SoftRemote/aggressive mode we need to remember some
	 * things for checking the hash
	 */
	st->st_peeridentity_protocol = id->isaid_doi_specific_a;
	st->st_peeridentity_port = ntohs(id->isaid_doi_specific_b);

	{
		char buf[IDTOA_BUF];

		idtoa(&peer, buf, sizeof(buf));
		libreswan_log("Peer ID is %s: '%s'",
			enum_show(&ike_idtype_names, id->isaid_idtype), buf);
	}

	/* check for certificates */
	lsw_cert_ret ret = ike_decode_cert(md);
	switch (ret) {
	case LSW_CERT_NONE:
		DBG(DBG_X509, DBG_log("X509: no CERT payloads to process"));
		break;
	case LSW_CERT_BAD:
		libreswan_log("X509: CERT payload bogus or revoked");
		return FALSE;
	case LSW_CERT_MISMATCHED_ID:
		libreswan_log("X509: CERT payload does not match connection ID");
		if (initiator || aggrmode) {
			/* cannot switch connection so fail */
			return FALSE;
		}
		break;
	case LSW_CERT_ID_OK:
		DBG(DBG_X509, DBG_log("X509: CERT and ID matches current connection"));
		break;
	default:
		bad_case(ret);
	}

	/* check for certificate requests */
	ikev1_decode_cr(md);

	/*
	 * Now that we've decoded the ID payload, let's see if we
	 * need to switch connections.
	 * Aggressive mode cannot switch connections.
	 * We must not switch horses if we initiated:
	 * - if the initiation was explicit, we'd be ignoring user's intent
	 * - if opportunistic, we'll lose our HOLD info
	 */

	if (initiator) {
		if (!st->st_peer_alt_id &&
		    !same_id(&c->spd.that.id, &peer) &&
		    c->spd.that.id.kind != ID_FROMCERT) {
			char expect[IDTOA_BUF],
			     found[IDTOA_BUF];

			idtoa(&c->spd.that.id, expect, sizeof(expect));
			idtoa(&peer, found, sizeof(found));
			loglog(RC_LOG_SERIOUS,
			       "we require IKEv1 peer to have ID '%s', but peer declares '%s'",
			       expect, found);
			return FALSE;
		} else if (c->spd.that.id.kind == ID_FROMCERT) {
			if (peer.kind != ID_DER_ASN1_DN) {
				loglog(RC_LOG_SERIOUS,
				       "peer ID is not a certificate type");
				return FALSE;
			}
			duplicate_id(&c->spd.that.id, &peer);
		}
	} else if (!aggrmode) {
		/* Main Mode Responder */
		uint16_t auth = xauth_calcbaseauth(st->st_oakley.auth);
		lset_t auth_policy;

		switch (auth) {
		case OAKLEY_PRESHARED_KEY:
			auth_policy = POLICY_PSK;
			break;
		case OAKLEY_RSA_SIG:
			auth_policy = POLICY_RSASIG;
			break;
		/* Not implemented */
		case OAKLEY_DSS_SIG:
		case OAKLEY_RSA_ENC:
		case OAKLEY_RSA_REVISED_MODE:
		case OAKLEY_ECDSA_P256:
		case OAKLEY_ECDSA_P384:
		case OAKLEY_ECDSA_P521:
		default:
			DBG(DBG_CONTROL, DBG_log("ikev1 ike_decode_peer_id bad_case due to not supported policy"));
			return FALSE;
		}

		bool fromcert;
		struct connection *r =
			refine_host_connection(st, &peer,
				NULL, /* IKEv1 does not support 'you Tarzan, me Jane' */
				FALSE,	/* we are responder */
				auth_policy,
				AUTH_UNSET,	/* ikev2 only */
				&fromcert);

		if (r == NULL) {
			char buf[IDTOA_BUF];

			idtoa(&peer, buf, sizeof(buf));
			DBG(DBG_CONTROL, DBG_log(
			       "no more suitable connection for peer '%s'", buf));
			/* can we continue with what we had? */
			if (!md->st->st_peer_alt_id &&
			    !same_id(&c->spd.that.id, &peer) &&
			    c->spd.that.id.kind != ID_FROMCERT) {
					libreswan_log("Peer mismatch on first found connection and no better connection found");
					return FALSE;
			} else {
				DBG(DBG_CONTROL, DBG_log("Peer ID matches and no better connection found - continuing with existing connection"));
				r = c;
			}
		}

		DBG(DBG_CONTROL, {
			char buf[IDTOA_BUF];
			dntoa_or_null(buf, IDTOA_BUF, r->spd.this.ca,
				      "%none");
			DBG_log("offered CA: '%s'", buf);
		});

		if (r != c) {
			/*
			 * We are changing st->st_connection!
			 * Our caller might be surprised!
			 */
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
						   NULL,
						   &peer);
			}

			update_state_connection(st, r);
			c = r;	/* c not subsequently used */
			/* redo from scratch so we read and check CERT payload */
			DBG(DBG_CONTROL, DBG_log("retrying ike_decode_peer_id() with new conn"));
			passert(!initiator && !aggrmode);
			return ikev1_decode_peer_id(md, FALSE, FALSE);
		} else if (c->spd.that.has_id_wildcards) {
			duplicate_id(&c->spd.that.id, &peer);
			c->spd.that.has_id_wildcards = FALSE;
		} else if (fromcert) {
			DBG(DBG_CONTROL, DBG_log("copying ID for fromcert"));
			duplicate_id(&c->spd.that.id, &peer);
		}
	}

	return TRUE;
}

bool ikev1_ship_chain(chunk_t *chain, int n, pb_stream *outs,
					     uint8_t type,
					     uint8_t setnp)
{
	int i;
	uint8_t np;

	for (i = 0; i < n; i++) {
		/* set np for last cert, or another */
		np = i == n - 1 ? setnp : ISAKMP_NEXT_CERT;

		if (!ikev1_ship_CERT(type, chain[i], outs, np))
			return FALSE;
	}

	return TRUE;
}

void doi_log_cert_thinking(uint16_t auth,
				enum ike_cert_type certtype,
				enum certpolicy policy,
				bool gotcertrequest,
				bool send_cert,
				bool send_chain)
{
	DBG(DBG_CONTROL, {
		DBG_log("thinking about whether to send my certificate:");

		struct esb_buf oan;
		struct esb_buf ictn;

		DBG_log("  I have RSA key: %s cert.type: %s ",
			enum_showb(&oakley_auth_names, auth, &oan),
			enum_showb(&ike_cert_type_names, certtype, &ictn));

		struct esb_buf cptn;

		DBG_log("  sendcert: %s and I did%s get a certificate request ",
			enum_showb(&certpolicy_type_names, policy, &cptn),
			gotcertrequest ? "" : " not");

		DBG_log("  so %ssend cert.", send_cert ? "" : "do not ");

		if (!send_cert) {
			if (auth == OAKLEY_PRESHARED_KEY) {
				DBG_log("I did not send a certificate because digital signatures are not being used. (PSK)");
			} else if (certtype == CERT_NONE) {
				DBG_log("I did not send a certificate because I do not have one.");
			} else if (policy == CERT_SENDIFASKED) {
				DBG_log("I did not send my certificate because I was not asked to.");
			} else {
				DBG_log("INVALID AUTH SETTING: %d", auth);
			}
		}
		if (send_chain)
			DBG_log("Sending one or more authcerts");
	});
}
