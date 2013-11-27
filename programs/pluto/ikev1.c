/* State machine for IKEv1
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Hiren Joshi <joshihirenn@gmail.com>
 * Copyright (C) 2009 Anthony Tong <atong@TrustedCS.com>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
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
#include "ikev1.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "timer.h"
#include "whack.h"      /* requires connections.h */
#include "server.h"

#include "xauth.h"

#include "nat_traversal.h"
#include "vendor.h"
#include "dpd.h"
#include "udpfromto.h"
#include "hostpair.h"

/* state_microcode is a tuple of information parameterizing certain
 * centralized processing of a packet.  For example, it roughly
 * specifies what payloads are expected in this message.
 * The microcode is selected primarily based on the state.
 * In Phase 1, the payload structure often depends on the
 * authentication technique, so that too plays a part in selecting
 * the state_microcode to use.
 */

struct state_microcode {
	enum state_kind state, next_state;
	lset_t flags;
	lset_t req_payloads;    /* required payloads (allows just one) */
	lset_t opt_payloads;    /* optional payloads (any mumber) */
	/* if not ISAKMP_NEXT_NONE, process_packet will emit HDR with this as np */
	u_int8_t first_out_payload;
	enum event_type timeout_event;
	state_transition_fn *processor;
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
#define SMF_PKE_AUTH    (LELEM(OAKLEY_RSA_ENC) | LELEM(OAKLEY_ELGAMAL_ENC))
#define SMF_RPKE_AUTH   (LELEM(OAKLEY_RSA_ENC_REV) | \
			 LELEM(OAKLEY_ELGAMAL_ENC_REV))
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

static state_transition_fn      /* forward declaration */
	unexpected,
	informational;

/* state_microcode_table is a table of all state_microcode tuples.
 * It must be in order of state (the first element).
 * After initialization, ike_microcode_index[s] points to the
 * first entry in state_microcode_table for state s.
 * Remember that each state name in Main or Quick Mode describes
 * what has happened in the past, not what this message is.
 */

static const struct state_microcode
*ike_microcode_index[STATE_IKE_ROOF - STATE_IKE_FLOOR];

#define PHONY_STATE(X) \
	{ X, X \
	  , 0 \
	  , 0, P(VID) | P(CR), PT(NONE) \
	  , 0, NULL }

static const struct state_microcode state_microcode_table[] = {
#define PT(n) ISAKMP_NEXT_ ## n
#define P(n) LELEM(PT(n))

	/***** Phase 1 Main Mode *****/

	/* No state for main_outI1: --> HDR, SA */

	/* STATE_MAIN_R0: I1 --> R1
	 * HDR, SA --> HDR, SA
	 */
	{ STATE_MAIN_R0, STATE_MAIN_R1,
	  SMF_ALL_AUTH | SMF_REPLY,
	  P(SA), P(VID) | P(CR), PT(NONE),
	  EVENT_RETRANSMIT, main_inI1_outR1 },

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
	  P(SA), P(VID) | P(CR), PT(NONE), /* don't know yet */
	  EVENT_RETRANSMIT, main_inR1_outI2 },

	/* STATE_MAIN_R1: I2 --> R2
	 * SMF_PSK_AUTH, SMF_DS_AUTH: HDR, KE, Ni --> HDR, KE, Nr
	 * SMF_PKE_AUTH: HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
	 *	    --> HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
	 * SMF_RPKE_AUTH:
	 *	    HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i, <IDi1_b>Ke_i [,<<Cert-I_b>Ke_i]
	 *	    --> HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r
	 */
	{ STATE_MAIN_R1, STATE_MAIN_R2,
	  SMF_PSK_AUTH | SMF_DS_AUTH | SMF_REPLY
	  , P(KE) | P(NONCE), P(VID) | P(CR) | P(NATD_RFC), PT(NONE)
	  , EVENT_RETRANSMIT, main_inI2_outR2 },

	{ STATE_MAIN_R1, STATE_UNDEFINED,
	  SMF_PKE_AUTH | SMF_REPLY,
	  P(KE) | P(ID) | P(NONCE), P(VID) | P(CR) | P(HASH), PT(KE),
	  EVENT_RETRANSMIT, unexpected /* ??? not yet implemented */ },

	{ STATE_MAIN_R1, STATE_UNDEFINED,
	  SMF_RPKE_AUTH | SMF_REPLY,
	  P(NONCE) | P(KE) | P(ID), P(VID) | P(CR) | P(HASH) | P(CERT), PT(
		  NONCE),
	  EVENT_RETRANSMIT, unexpected /* ??? not yet implemented */ },

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
	  SMF_PSK_AUTH | SMF_DS_AUTH | SMF_INITIATOR | SMF_OUTPUT_ENCRYPTED |
	  SMF_REPLY
	  , P(KE) | P(NONCE), P(VID) | P(CR) | P(NATD_RFC), PT(ID)
	  , EVENT_RETRANSMIT, main_inR2_outI3 },

	{ STATE_MAIN_I2, STATE_UNDEFINED,
	  SMF_PKE_AUTH | SMF_INITIATOR | SMF_OUTPUT_ENCRYPTED | SMF_REPLY,
	  P(KE) | P(ID) | P(NONCE), P(VID) | P(CR), PT(HASH),
	  EVENT_RETRANSMIT, unexpected /* ??? not yet implemented */ },

	{ STATE_MAIN_I2, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_INITIATOR | SMF_OUTPUT_ENCRYPTED | SMF_REPLY,
	  P(NONCE) | P(KE) | P(ID), P(VID) | P(CR), PT(HASH),
	  EVENT_RETRANSMIT, unexpected /* ??? not yet implemented */ },

	/* for states from here on, input message must be encrypted */

	/* STATE_MAIN_R2: I3 --> R3
	 * SMF_PSK_AUTH: HDR*, IDi1, HASH_I --> HDR*, IDr1, HASH_R
	 * SMF_DS_AUTH: HDR*, IDi1, [ CERT, ] SIG_I --> HDR*, IDr1, [ CERT, ] SIG_R
	 * SMF_PKE_AUTH, SMF_RPKE_AUTH: HDR*, HASH_I --> HDR*, HASH_R
	 */
	{ STATE_MAIN_R2, STATE_MAIN_R3,
	  SMF_PSK_AUTH | SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED |
	  SMF_REPLY | SMF_RELEASE_PENDING_P2,
	  P(ID) | P(HASH), P(VID) | P(CR), PT(NONE),
	  EVENT_SA_REPLACE, main_inI3_outR3 },

	{ STATE_MAIN_R2, STATE_MAIN_R3,
	  SMF_DS_AUTH | SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED |
	  SMF_REPLY | SMF_RELEASE_PENDING_P2,
	  P(ID) | P(SIG), P(VID) | P(CR) | P(CERT), PT(NONE),
	  EVENT_SA_REPLACE, main_inI3_outR3 },

	{ STATE_MAIN_R2, STATE_UNDEFINED,
	  SMF_PKE_AUTH | SMF_RPKE_AUTH | SMF_FIRST_ENCRYPTED_INPUT |
	  SMF_ENCRYPTED |
	  SMF_REPLY | SMF_RELEASE_PENDING_P2,
	  P(HASH), P(VID) | P(CR), PT(NONE),
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
	  P(ID) | P(HASH), P(VID) | P(CR), PT(NONE),
	  EVENT_SA_REPLACE, main_inR3 },

	{ STATE_MAIN_I3, STATE_MAIN_I4,
	  SMF_DS_AUTH | SMF_INITIATOR |
	  SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED | SMF_RELEASE_PENDING_P2,
	  P(ID) | P(SIG), P(VID) | P(CR) | P(CERT), PT(NONE),
	  EVENT_SA_REPLACE, main_inR3 },

	{ STATE_MAIN_I3, STATE_UNDEFINED,
	  SMF_PKE_AUTH | SMF_RPKE_AUTH | SMF_INITIATOR |
	  SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED | SMF_RELEASE_PENDING_P2,
	  P(HASH), P(VID) | P(CR), PT(NONE),
	  EVENT_SA_REPLACE, unexpected /* ??? not yet implemented */ },

	/* STATE_MAIN_R3: can only get here due to packet loss */
	{ STATE_MAIN_R3, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_RETRANSMIT_ON_DUPLICATE,
	  LEMPTY, LEMPTY,
	  PT(NONE), EVENT_NULL, unexpected },

	/* STATE_MAIN_I4: can only get here due to packet loss */
	{ STATE_MAIN_I4, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_INITIATOR | SMF_ENCRYPTED,
	  LEMPTY, LEMPTY,
	  PT(NONE), EVENT_NULL, unexpected },

	/***** Phase 1 Aggressive Mode *****/

	/* No state for aggr_outI1: -->HDR, SA, KE, Ni, IDii */

	/* STATE_AGGR_R0:
	 * SMF_PSK_AUTH: HDR, SA, KE, Ni, IDii
	 *                -->  HDR, SA, KE, Nr, IDir, HASH_R
	 * SMF_DS_AUTH:  HDR, KE, Nr, SIG --> HDR*, IDi1, HASH_I
	 */
	{ STATE_AGGR_R0, STATE_AGGR_R1,
	  SMF_PSK_AUTH | SMF_REPLY,
	  P(SA) | P(KE) | P(NONCE) | P(ID), P(VID) | P(NATD_RFC), PT(NONE),
	  EVENT_RETRANSMIT, aggr_inI1_outR1_psk },

	{ STATE_AGGR_R0, STATE_AGGR_R1,
	  SMF_DS_AUTH | SMF_REPLY,
	  P(SA) | P(KE) | P(NONCE) | P(ID), P(VID) | P(NATD_RFC), PT(NONE),
	  EVENT_RETRANSMIT, aggr_inI1_outR1_rsasig },

	/* STATE_AGGR_I1:
	 * SMF_PSK_AUTH: HDR, SA, KE, Nr, IDir, HASH_R
	 *                                 --> HDR*, HASH_I
	 * SMF_DS_AUTH: HDR, SA, KE, Nr, IDir, SIG_R
	 *                                 --> HDR*, SIG_I
	 */
	{ STATE_AGGR_I1, STATE_AGGR_I2,
	  SMF_PSK_AUTH | SMF_INITIATOR | SMF_OUTPUT_ENCRYPTED | SMF_REPLY |
	  SMF_RELEASE_PENDING_P2,
	  P(SA) | P(KE) | P(NONCE) | P(ID) | P(HASH), P(VID) | P(NATD_RFC), PT(
		  NONE),
	  EVENT_SA_REPLACE, aggr_inR1_outI2 },

	{ STATE_AGGR_I1, STATE_AGGR_I2,
	  SMF_DS_AUTH | SMF_INITIATOR | SMF_OUTPUT_ENCRYPTED | SMF_REPLY |
	  SMF_RELEASE_PENDING_P2,
	  P(SA) | P(KE) | P(NONCE) | P(ID) | P(SIG), P(VID) | P(NATD_RFC), PT(
		  NONE),
	  EVENT_SA_REPLACE, aggr_inR1_outI2 },

	/* STATE_AGGR_R1:
	 * SMF_PSK_AUTH: HDR*, HASH_I --> done
	 * SMF_DS_AUTH: HDR*, SIG_I   --> done
	 */
	{ STATE_AGGR_R1, STATE_AGGR_R2,
	  SMF_PSK_AUTH | SMF_FIRST_ENCRYPTED_INPUT |
	  SMF_ENCRYPTED | SMF_RELEASE_PENDING_P2,
	  P(HASH), P(VID) | P(NATD_RFC), PT(NONE),
	  EVENT_SA_REPLACE, aggr_inI2 },

	/* STATE_AGGR_R1: HDR*, HASH_I --> done */
	{ STATE_AGGR_R1, STATE_AGGR_R2,
	  SMF_DS_AUTH | SMF_FIRST_ENCRYPTED_INPUT |
	  SMF_ENCRYPTED | SMF_RELEASE_PENDING_P2,
	  P(SIG), P(VID) | P(NATD_RFC), PT(NONE),
	  EVENT_SA_REPLACE, aggr_inI2 },

	/* STATE_AGGR_I2: can only get here due to packet loss */
	{ STATE_AGGR_I2, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_INITIATOR | SMF_RETRANSMIT_ON_DUPLICATE,
	  LEMPTY, LEMPTY, PT(NONE), EVENT_NULL, unexpected },

	/* STATE_AGGR_R2: can only get here due to packet loss */
	{ STATE_AGGR_R2, STATE_UNDEFINED,
	  SMF_ALL_AUTH,
	  LEMPTY, LEMPTY, PT(NONE), EVENT_NULL, unexpected },

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
	  SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_REPLY
	  , P(HASH) | P(SA) | P(NONCE), /* P(SA) | */ P(KE) | P(ID) | P(
		  NATOA_RFC), PT(NONE)
	  , EVENT_RETRANSMIT, quick_inI1_outR1 },

	/* STATE_QUICK_I1:
	 * HDR*, HASH(2), SA, Nr [, KE ] [, IDci, IDcr ] -->
	 * HDR*, HASH(3)
	 * Installs inbound and outbound IPsec SAs, routing, etc.
	 * ??? it is legal to have multiple SAs, but we don't support it yet.
	 */
	{ STATE_QUICK_I1, STATE_QUICK_I2,
	  SMF_ALL_AUTH | SMF_INITIATOR | SMF_ENCRYPTED | SMF_REPLY
	  , P(HASH) | P(SA) | P(NONCE), /* P(SA) | */ P(KE) | P(ID) | P(
		  NATOA_RFC), PT(HASH)
	  , EVENT_SA_REPLACE, quick_inR1_outI2 },

	/* STATE_QUICK_R1: HDR*, HASH(3) --> done
	 * Installs outbound IPsec SAs, routing, etc.
	 */
	{ STATE_QUICK_R1, STATE_QUICK_R2,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  P(HASH), LEMPTY, PT(NONE),
	  EVENT_SA_REPLACE, quick_inI2 },

	/* STATE_QUICK_I2: can only happen due to lost packet */
	{ STATE_QUICK_I2, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_INITIATOR | SMF_ENCRYPTED |
	  SMF_RETRANSMIT_ON_DUPLICATE,
	  LEMPTY, LEMPTY, PT(NONE),
	  EVENT_NULL, unexpected },

	/* STATE_QUICK_R2: can only happen due to lost packet */
	{ STATE_QUICK_R2, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  LEMPTY, LEMPTY, PT(NONE),
	  EVENT_NULL, unexpected },

	/***** informational messages *****/

	/* Informational Exchange (RFC 2408 4.8):
	 * HDR N/D
	 * Unencrypted: must not occur after ISAKMP Phase 1 exchange of keying material.
	 */
	/* STATE_INFO: */
	{ STATE_INFO, STATE_UNDEFINED,
	  SMF_ALL_AUTH,
	  LEMPTY, LEMPTY, PT(NONE),
	  EVENT_NULL, informational },

	/* Informational Exchange (RFC 2408 4.8):
	 * HDR* N/D
	 */
	/* STATE_INFO_PROTECTED: */
	{ STATE_INFO_PROTECTED, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  P(HASH), LEMPTY, PT(NONE),
	  EVENT_NULL, informational },

	{ STATE_XAUTH_R0, STATE_XAUTH_R1,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  P(MCFG_ATTR) | P(HASH), P(VID), PT(NONE),
	  EVENT_NULL, xauth_inR0 }, /*Re-transmit may be done by previous state*/

	{ STATE_XAUTH_R1, STATE_MAIN_R3,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  P(MCFG_ATTR) | P(HASH), P(VID), PT(NONE),
	  EVENT_SA_REPLACE, xauth_inR1 },

#if 0
	/* for situation where there is XAUTH + ModeCFG */
	{ STATE_XAUTH_R2, STATE_XAUTH_R3,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  P(MCFG_ATTR) | P(HASH), P(VID), PT(NONE),
	  EVENT_SA_REPLACE, xauth_inR2 },

	{ STATE_XAUTH_R3, STATE_MAIN_R3,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  P(MCFG_ATTR) | P(HASH), P(VID), PT(NONE),
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
	  P(MCFG_ATTR) | P(HASH), P(VID), PT(HASH),
	  EVENT_SA_REPLACE, modecfg_inR0 },

	{ STATE_MODE_CFG_R1, STATE_MODE_CFG_R2,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  P(MCFG_ATTR) | P(HASH), P(VID), PT(HASH),
	  EVENT_SA_REPLACE, modecfg_inR1 },

	{ STATE_MODE_CFG_R2, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  LEMPTY, LEMPTY, PT(NONE),
	  EVENT_NULL, unexpected },

	{ STATE_MODE_CFG_I1, STATE_MAIN_I4,
	  SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_RELEASE_PENDING_P2,
	  P(MCFG_ATTR) | P(HASH), P(VID), PT(HASH),
	  EVENT_SA_REPLACE, modecfg_inR1 },

	{ STATE_XAUTH_I0, STATE_XAUTH_I1,
	  SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_REPLY | SMF_RELEASE_PENDING_P2,
	  P(MCFG_ATTR) | P(HASH), P(VID), PT(HASH),
	  EVENT_SA_REPLACE, xauth_inI0 },

	{ STATE_XAUTH_I1, STATE_MAIN_I4,
	  SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_REPLY | SMF_RELEASE_PENDING_P2,
	  P(MCFG_ATTR) | P(HASH), P(VID), PT(HASH),
	  EVENT_SA_REPLACE, xauth_inI1 },

#undef P
#undef PT
};

void init_demux(void)
{
	/* fill ike_microcode_index:
	 * make ike_microcode_index[s] point to first entry in
	 * state_microcode_table for state s (backward scan makes this easier).
	 * Check that table is in order -- catch coding errors.
	 * For what it's worth, this routine is idempotent.
	 */
	const struct state_microcode *t;

	for (t = &state_microcode_table[elemsof(state_microcode_table) - 1];;
	     ) {
		passert(
			STATE_IKE_FLOOR <= t->state && t->state <
			STATE_IKE_ROOF);
		ike_microcode_index[t->state - STATE_IKE_FLOOR] = t;
		if (t == state_microcode_table)
			break;
		t--;
		passert(t[0].state <= t[1].state);
	}
}

static stf_status unexpected(struct msg_digest *md)
{
	loglog(RC_LOG_SERIOUS, "unexpected message received in state %s",
	       enum_name(&state_names, md->st->st_state));
	return STF_IGNORE;
}

/*
 * RFC 2408 Section 4.6 
 *
 *  #   Initiator  Direction Responder  NOTE
 * (1)  HDR*; N/D     =>                Error Notification or Deletion
 */
static stf_status informational(struct msg_digest *md)
{
	struct payload_digest *const n_pld = md->chain[ISAKMP_NEXT_N];

	/* If the Notification Payload is not null... */
	if (n_pld != NULL) {
		pb_stream *const n_pbs = &n_pld->pbs;
		struct isakmp_notification *const n =
			&n_pld->payload.notification;
		struct state *st = md->st;    /* may be NULL */

		/* Switch on Notification Type (enum) */
		/* note that we _can_ get notification payloads unencrypted
		 * once we are at least in R3/I4.
		 * and that the handler is expected to treat them suspiciously.
		 */
		DBG(DBG_CONTROL, DBG_log("processing informational %s (%d)",
					 enum_name(&ikev1_notify_names,
						   n->isan_type),
					 n->isan_type));

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
			if (st) {
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
				}
			}
			return STF_IGNORE;

		case ISAKMP_N_CISCO_LOAD_BALANCE:
			if (st && IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
				char *tmp_name;
				int tmp_whack_sock;
				struct connection *tmp_c;
				ip_address old_addr;

				/* Saving connection name and whack sock id*/
				tmp_name = st->st_connection->name;
				tmp_whack_sock = dup_any(st->st_whack_sock);

				/* deleting ISAKMP SA with the current remote peer*/
				delete_state(st);

				/* to find and store the connection associated with tmp_name*/
				tmp_c = con_by_name(tmp_name, FALSE);

				DBG_cond_dump(DBG_PARSING,
					      "redirected remote end info:", n_pbs->cur + pbs_left(
						      n_pbs) - 4, 4);

#ifdef DEBUG
				/*Current remote peer info*/
				{

					char buftest[ADDRTOT_BUF];
					struct spd_route *tmp_spd =
						&tmp_c->spd;
					int count_spd = 0;

					do {
						DBG(DBG_CONTROLMORE,
						    DBG_log(
							    "spd route number: %d",
							    ++count_spd));

						/**that info**/
						DBG(DBG_CONTROLMORE,
						    DBG_log("that id kind: %d",
							    tmp_spd->that.id.
							    kind));
						DBG(DBG_CONTROLMORE,
						    DBG_log(
							    "that id ipaddr: %s",
							    (addrtot(&tmp_spd->
								     that.id.
								     ip_addr,
								     0,
								     buftest,
								     sizeof(
									     buftest)),
							     buftest)));
						if (tmp_spd->that.id.name.ptr
						    !=
						    NULL)
							DBG(DBG_CONTROLMORE, DBG_dump_chunk(
								    "that id name",
								    tmp_spd->
								    that.id.
								    name));
						DBG(DBG_CONTROLMORE,
						    DBG_log(
							    "that host_addr: %s",
							    (addrtot(&tmp_spd->
								     that.
								     host_addr,
								     0,
								     buftest,
								     sizeof(
									     buftest)),
							     buftest)));
						DBG(DBG_CONTROLMORE,
						    DBG_log("that nexthop: %s",
							    (addrtot(&tmp_spd->
								     that.
								     host_nexthop,
								     0,
								     buftest,
								     sizeof(
									     buftest)),
							     buftest)));
						DBG(DBG_CONTROLMORE,
						    DBG_log("that srcip: %s",
							    (addrtot(&tmp_spd->
								     that.
								     host_srcip,
								     0,
								     buftest,
								     sizeof(
									     buftest)),
							     buftest)));
						DBG(DBG_CONTROLMORE,
						    DBG_log(
							    "that client_addr: %s, maskbits:%d",
							    (
								    addrtot(&
									    tmp_spd
									    ->
									    that
									    .
									    client
									    .
									    addr,
									    0,
									    buftest,
									    sizeof(
										    buftest)),
								    buftest),
							    tmp_spd->that.
							    client.maskbits));
						DBG(DBG_CONTROLMORE,
						    DBG_log(
							    "that has_client: %d",
							    tmp_spd->that.
							    has_client));
						DBG(DBG_CONTROLMORE,
						    DBG_log(
							    "that has_client_wildcard: %d",
							    tmp_spd->that.
							    has_client_wildcard));
						DBG(DBG_CONTROLMORE,
						    DBG_log(
							    "that has_port_wildcard: %d",
							    tmp_spd->that.
							    has_port_wildcard));
						DBG(DBG_CONTROLMORE,
						    DBG_log(
							    "that has_id_wildcards: %d",
							    tmp_spd->that.
							    has_id_wildcards));

						tmp_spd = tmp_spd->next;
					} while (tmp_spd != NULL);

					if (tmp_c->interface != NULL) {
						DBG(DBG_CONTROLMORE,
						    DBG_log(
							    "Current interface_addr: %s",
							    (addrtot(&tmp_c->
								     interface
								     ->
								     ip_addr,
								     0,
								     buftest,
								     sizeof(
									     buftest)),
							     buftest)));
					}

					if (tmp_c->gw_info != NULL) {
						DBG(DBG_CONTROLMORE, {
							    DBG_log(
								    "Current gw_client_addr: %s",
								    (addrtot(&
									     tmp_c
									     ->
									     gw_info
									     ->
									     client_id
									     .
									     ip_addr,
									     0,
									     buftest,
									     sizeof(
										     buftest)),
								     buftest));
							    DBG_log(
								    "Current gw_gw_addr: %s",
								    (addrtot(&
									     tmp_c
									     ->
									     gw_info
									     ->
									     gw_id
									     .
									     ip_addr,
									     0,
									     buftest,
									     sizeof(
										     buftest)),
								     buftest));
						    });
					}

				}
#endif
				/*storing old address for comparison purposes*/
				old_addr = tmp_c->spd.that.host_addr;

				/*Decoding remote peer address info where connection has to be redirected to*/
				memcpy(
					&tmp_c->spd.that.host_addr.u.v4.sin_addr.s_addr,
					(u_int32_t *)(n_pbs->cur +
						      pbs_left(n_pbs) - 4),
					sizeof(tmp_c->spd.that.host_addr.u.v4.
					       sin_addr.
					       s_addr));

				/*Modifying connection info to store the redirected remote peer info*/
				DBG(DBG_CONTROLMORE,
				    DBG_log("Old host_addr_name : %s",
					    tmp_c->spd.that.host_addr_name));
				tmp_c->spd.that.host_addr_name = NULL;
				tmp_c->spd.that.id.ip_addr =
					tmp_c->spd.that.host_addr;

				DBG(DBG_CONTROLMORE, {
					    char buftest[ADDRTOT_BUF];
					    if (sameaddr(&tmp_c->spd.this.
							 host_nexthop,
							 &old_addr)) {
						    DBG_log(
							    "Old remote addr %s",
							    (addrtot(&old_addr,
								     0,
								     buftest,
								     sizeof(
									     buftest)),
							     buftest));
						    DBG_log(
							    "Old this host next hop %s",
							    (addrtot(&tmp_c->
								     spd.this.
								     host_nexthop,
								     0,
								     buftest,
								     sizeof(
									     buftest)),
							     buftest));
						    tmp_c->spd.this.host_nexthop = tmp_c->spd.that.host_addr;
						    DBG_log(
							    "New this host next hop %s",
							    (addrtot(&tmp_c->
								     spd.this.
								     host_nexthop,
								     0,
								     buftest,
								     sizeof(
									     buftest)),
							     buftest));
					    }

					    if (sameaddr(&tmp_c->spd.that.
							 host_srcip,
							 &old_addr)) {
						    DBG_log(
							    "Old that host srcip %s",
							    (addrtot(&tmp_c->
								     spd.that.
								     host_srcip,
								     0,
								     buftest,
								     sizeof(
									     buftest)),
							     buftest));
						    tmp_c->spd.that.host_srcip = tmp_c->spd.that.host_addr;
						    DBG_log(
							    "New that host srcip %s",
							    (addrtot(&tmp_c->
								     spd.that.
								     host_srcip,
								     0,
								     buftest,
								     sizeof(
									     buftest)),
							     buftest));
					    }

					    if (sameaddr(&tmp_c->spd.that.
							 client.addr,
							 &old_addr)) {
						    DBG_log(
							    "Old that client ip %s",
							    (addrtot(&tmp_c->
								     spd.that.
								     client.
								     addr, 0,
								     buftest,
								     sizeof(
									     buftest)),
							     buftest));
						    tmp_c->spd.that.client.addr = tmp_c->spd.that.host_addr;
						    DBG_log(
							    "New that client ip %s",
							    (addrtot(&tmp_c->
								     spd.that.
								     client.
								     addr, 0,
								     buftest,
								     sizeof(
									     buftest)),
							     buftest));
					    }
				    });

				tmp_c->host_pair->him.addr =
					tmp_c->spd.that.host_addr;

				/*Initiating connection to the redirected peer*/
				initiate_connection(tmp_name, tmp_whack_sock,
						    0, pcim_demand_crypto);
				return STF_IGNORE;
			}

		default:
#ifdef DEBUG
			if (st != NULL &&
			    st->st_connection->extra_debugging &
			    IMPAIR_DIE_ONINFO) {
				loglog(RC_LOG_SERIOUS,
				       "received unhandled informational notification payload %d: '%s'",
				       n->isan_type,
				       enum_name(&ikev1_notify_names,
						 n->isan_type));
				return STF_FATAL;
			}
#endif
			loglog(RC_LOG_SERIOUS,
			       "received and ignored informational message for unknown state");
			return STF_IGNORE;
		}
	}

	loglog(RC_LOG_SERIOUS,
	       "received and ignored empty informational notification payload");
	return STF_IGNORE;
}

/* process an input packet, possibly generating a reply.
 *
 * If all goes well, this routine eventually calls a state-specific
 * transition function.
 */
void process_v1_packet(struct msg_digest **mdp)
{
	struct msg_digest *md = *mdp;
	const struct state_microcode *smc;
	bool new_iv_set = FALSE;
	struct state *st = NULL;
	enum state_kind from_state = STATE_UNDEFINED;   /* state we started in */

#define SEND_NOTIFICATION(t) { \
		if (st) \
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
		if (md->hdr.isa_msgid != MAINMODE_MSGID) {
			libreswan_log(
				"Message ID was 0x%08lx but should be zero in phase 1",
				(unsigned long) md->hdr.isa_msgid);
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
			/* initial message from initiator
			 * ??? what if this is a duplicate of another message?
			 */
			if (md->hdr.isa_flags & ISAKMP_FLAG_ENCRYPTION) {
				libreswan_log("initial phase 1 message is invalid:"
					      " its Encrypted Flag is on");
				SEND_NOTIFICATION(INVALID_FLAGS);
				return;
			}

			/* don't build a state until the message looks tasty */
			from_state = (md->hdr.isa_xchg == ISAKMP_XCHG_IDPROT ?
				      STATE_MAIN_R0 : STATE_AGGR_R0);
		} else {
			/* not an initial message */

			st = find_state_ikev1(md->hdr.isa_icookie,
					      md->hdr.isa_rcookie,
					      md->hdr.isa_msgid);

#ifdef HAVE_LABELED_IPSEC
			if (st != NULL && st->st_connection->loopback) {
				DBG(DBG_CONTROL,
				    DBG_log(
					    "loopback scenario: verifying if this is really a correct state, if not, find the correct state"));

				st = find_state_ikev1_loopback(
					md->hdr.isa_icookie,
					md->hdr.isa_rcookie, md->hdr.isa_msgid,
					md);
				if (st != NULL)
					DBG(DBG_CONTROL,
					    DBG_log(
						    "loopback scenario: found a correct state for the received message"));


				else
					DBG(DBG_CONTROL,
					    DBG_log(
						    "loopback scenario: did not found any state, perhaps a first message from the responder"));


			}
#endif

			if (st == NULL) {
				/* perhaps this is a first message from the responder
				 * and contains a responder cookie that we've not yet seen.
				 */
				st = find_state_ikev1(md->hdr.isa_icookie,
						      zero_cookie,
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
		st = find_info_state(md->hdr.isa_icookie, md->hdr.isa_rcookie,
				     &md->sender, MAINMODE_MSGID);

		if (st == NULL) {
			/*
			 * might be an informational response to our first
			 * message, in which case, we don't know the rcookie yet.
			 */
			st = find_state_ikev1(md->hdr.isa_icookie, zero_cookie,
					      MAINMODE_MSGID);
		}

		if (st != NULL)
			set_cur_state(st);

		if (md->hdr.isa_flags & ISAKMP_FLAG_ENCRYPTION) {
			if (st == NULL) {
				libreswan_log(
					"Informational Exchange is for an unknown (expired?) SA with MSGID:0x%08lx",
					(unsigned long)md->hdr.isa_msgid);
				/* Let's try and log some info about these to track them down */
				DBG(DBG_PARSING, {
					    DBG_dump(
						    "- unknown SA's md->hdr.isa_icookie:",
						    md->hdr.isa_icookie,
						    COOKIE_SIZE);
					    DBG_dump(
						    "- unknown SA's md->hdr.isa_rcookie:",
						    md->hdr.isa_rcookie,
						    COOKIE_SIZE);
				    });

				/* XXX Could send notification back */
				return;
			}

			if (!IS_ISAKMP_ENCRYPTED(st->st_state)) {
				loglog(RC_LOG_SERIOUS, "encrypted Informational Exchange message is invalid"
				       " because no key is known");
				/* XXX Could send notification back */
				return;
			}

			if (md->hdr.isa_msgid == MAINMODE_MSGID) {
				loglog(RC_LOG_SERIOUS, "Informational Exchange message is invalid because"
				       " it has a Message ID of 0");
				/* XXX Could send notification back */
				return;
			}

			if (!unique_msgid(st, md->hdr.isa_msgid)) {
				loglog(RC_LOG_SERIOUS, "Informational Exchange message is invalid because"
				       " it has a previously used Message ID (0x%08lx)",
				       (unsigned long)md->hdr.isa_msgid);
				/* XXX Could send notification back */
				return;
			}
			st->st_reserve_msgid = FALSE;

			init_phase2_iv(st, &md->hdr.isa_msgid);
			new_iv_set = TRUE;

			from_state = STATE_INFO_PROTECTED;
		} else {
			if (st != NULL &&
			    (IS_ISAKMP_AUTHENTICATED(st->st_state))) {
				loglog(RC_LOG_SERIOUS, "Informational Exchange message"
				       " must be encrypted");
				/* XXX Could send notification back */
				return;
			}
			from_state = STATE_INFO;
		}
		break;

	case ISAKMP_XCHG_QUICK: /* part of a Quick Mode exchange */
		if (is_zero_cookie(md->hdr.isa_icookie)) {
			libreswan_log("Quick Mode message is invalid because"
				      " it has an Initiator Cookie of 0");
			SEND_NOTIFICATION(INVALID_COOKIE);
			return;
		}

		if (is_zero_cookie(md->hdr.isa_rcookie)) {
			libreswan_log("Quick Mode message is invalid because"
				      " it has a Responder Cookie of 0");
			SEND_NOTIFICATION(INVALID_COOKIE);
			return;
		}

		if (md->hdr.isa_msgid == MAINMODE_MSGID) {
			libreswan_log("Quick Mode message is invalid because"
				      " it has a Message ID of 0");
			SEND_NOTIFICATION(INVALID_MESSAGE_ID);
			return;
		}

		st = find_state_ikev1(md->hdr.isa_icookie, md->hdr.isa_rcookie,
				      md->hdr.isa_msgid);

#ifdef HAVE_LABELED_IPSEC
		if (st != NULL && st->st_connection->loopback) {
			DBG(DBG_CONTROL,
			    DBG_log(
				    "loopback scenario: verifying if this is really a correct state, if not, find the correct state"));

			st = find_state_ikev1_loopback(md->hdr.isa_icookie,
						       md->hdr.isa_rcookie,
						       md->hdr.isa_msgid, md);

			if (st != NULL)
				DBG(DBG_CONTROL,
				    DBG_log(
					    "loopback scenario: found a correct state for the received message"));


			else
				DBG(DBG_CONTROL,
				    DBG_log(
					    "loopback scenario: did not found any state, perhaps a first message from the responder"));


		}
#endif
		if (st == NULL) {
			/* No appropriate Quick Mode state.
			 * See if we have a Main Mode state.
			 * ??? what if this is a duplicate of another message?
			 */
			st = find_state_ikev1(md->hdr.isa_icookie,
					      md->hdr.isa_rcookie,
					      MAINMODE_MSGID);

			if (st == NULL) {
				libreswan_log("Quick Mode message is for a non-existent (expired?)"
					      " ISAKMP SA");
				/* XXX Could send notification back */
				return;
			}

			if (st->st_oakley.doing_xauth) {
				libreswan_log(
					"Cannot do Quick Mode until XAUTH done.");
				return;
			}

			if (st->st_state ==
			    STATE_MODE_CFG_R2)                          /* Have we just given an IP address to peer? */
				change_state(st, STATE_MAIN_R3);        /* ISAKMP is up... */

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
				loglog(RC_LOG_SERIOUS, "Quick Mode message is unacceptable because"
				       " it is for an incomplete ISAKMP SA");
				SEND_NOTIFICATION(PAYLOAD_MALFORMED /* XXX ? */);
				return;
			}

			if (!unique_msgid(st, md->hdr.isa_msgid)) {
				loglog(RC_LOG_SERIOUS, "Quick Mode I1 message is unacceptable because"
				       " it uses a previously used Message ID 0x%08lx"
				       " (perhaps this is a duplicated packet)",
				       (unsigned long) md->hdr.isa_msgid);
				SEND_NOTIFICATION(INVALID_MESSAGE_ID);
				return;
			}

			/* note that we need to reserve this message ID */
			st->st_reserve_msgid = FALSE;

			/* Quick Mode Initial IV */
			init_phase2_iv(st, &md->hdr.isa_msgid);
			new_iv_set = TRUE;

			from_state = STATE_QUICK_R0;
		} else {
			if (st->st_oakley.doing_xauth) {
				libreswan_log(
					"Cannot do Quick Mode until XAUTH done.");
				return;
			}
			set_cur_state(st);
			from_state = st->st_state;
		}

		break;

	case ISAKMP_XCHG_MODE_CFG:
		if (is_zero_cookie(md->hdr.isa_icookie)) {
			libreswan_log("Mode Config message is invalid because"
				      " it has an Initiator Cookie of 0");
			/* XXX Could send notification back */
			return;
		}

		if (is_zero_cookie(md->hdr.isa_rcookie)) {
			libreswan_log("Mode Config message is invalid because"
				      " it has a Responder Cookie of 0");
			/* XXX Could send notification back */
			return;
		}

		if (md->hdr.isa_msgid == 0) {
			libreswan_log("Mode Config message is invalid because"
				      " it has a Message ID of 0");
			/* XXX Could send notification back */
			return;
		}

		st = find_info_state(md->hdr.isa_icookie, md->hdr.isa_rcookie,
				     &md->sender, md->hdr.isa_msgid);

		if (st == NULL) {
			DBG(DBG_CONTROLMORE,
			    DBG_log(
				    " in %s:%d No appropriate Mode Config state yet."
				    "See if we have a Main Mode state",
				    __func__, __LINE__));
			/* No appropriate Mode Config state.
			 * See if we have a Main Mode state.
			 * ??? what if this is a duplicate of another message?
			 */
			st = find_info_state(md->hdr.isa_icookie,
					     md->hdr.isa_rcookie,
					     &md->sender, 0);

			if (st == NULL) {
				libreswan_log("Mode Config message is for a non-existent (expired?)"
					      " ISAKMP SA");
				/* XXX Could send notification back */
				return;
			}

			set_cur_state(st);

			DBG(DBG_CONTROLMORE, DBG_log(" processing received "
						     "isakmp_xchg_type %s.",
						     enum_show(&exchange_names_ikev1,
							       md->hdr.isa_xchg)));
			DBG(DBG_CONTROLMORE, DBG_log(" this is a%s%s%s%s",
						     st->st_connection->spd.
						     this.xauth_server ?
						     " xauthserver" : "",
						     st->st_connection->spd.
						     this.xauth_client ?
						     " xauthclient" : "",
						     st->st_connection->spd.
						     this.modecfg_server ?
						     " modecfgserver" : "",
						     st->st_connection->spd.
						     this.modecfg_client  ?
						     " modecfgclient" : ""
						     ));

			if (!IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
				loglog(RC_LOG_SERIOUS, "Mode Config message is unacceptable because"
				       " it is for an incomplete ISAKMP SA (state=%s)",
				       enum_name(&state_names, st->st_state));
				/* XXX Could send notification back */
				return;
			}
			DBG(DBG_CONTROLMORE, DBG_log(" call  init_phase2_iv"));
			init_phase2_iv(st, &md->hdr.isa_msgid);
			new_iv_set = TRUE;

			/*
			 * okay, now we have to figure out if we are receiving a bogus
			 * new message in an oustanding XAUTH server conversation
			 * (i.e. a reply to our challenge)
			 * (this occurs with some broken other implementations).
			 *
			 * or if receiving for the first time, an XAUTH challenge.
			 *
			 * or if we are getting a MODECFG request.
			 *
			 * we distinguish these states because we can not both be an
			 * XAUTH server and client, and our policy tells us which
			 * one we are.
			 *
			 * to complicate further, it is normal to start a new msgid
			 * when going from one state to another, or when restarting
			 * the challenge.
			 *
			 */

			if (st->st_connection->spd.this.xauth_server &&
			    st->st_state == STATE_XAUTH_R1 &&
			    st->quirks.xauth_ack_msgid) {
				from_state = STATE_XAUTH_R1;
				DBG(DBG_CONTROLMORE,
				    DBG_log(" set from_state to %s "
					    "state is STATE_XAUTH_R1 and quirks.xauth_ack_msgid==TRUE",
					    enum_name(&state_names,
						      st->st_state
						      )));
			} else if (st->st_connection->spd.this.xauth_client
				   &&
				   IS_PHASE1(st->st_state)) {
				from_state = STATE_XAUTH_I0;
				DBG(DBG_CONTROLMORE,
				    DBG_log(" set from_state to %s "
					    "this is xauthclient and IS_PHASE1() == TRUE",
					    enum_name(&state_names,
						      st->st_state
						      )));
			} else if (st->st_connection->spd.this.xauth_client
				   &&
				   st->st_state == STATE_XAUTH_I1) {
				/*
				 * in this case, we got a new MODECFG message after I0, maybe
				 * because it wants to start over again.
				 */
				from_state = STATE_XAUTH_I0;
				DBG(DBG_CONTROLMORE,
				    DBG_log(" set from_state to %s "
					    "this is xauthclient and state == STATE_XAUTH_I1",
					    enum_name(&state_names,
						      st->st_state
						      )));
			} else if (st->st_connection->spd.this.modecfg_server
				   &&
				   IS_PHASE1(st->st_state)) {
				from_state = STATE_MODE_CFG_R0;
				DBG(DBG_CONTROLMORE,
				    DBG_log(" set from_state to %s "
					    "this is modecfgserver and IS_PHASE1() == TRUE",
					    enum_name(&state_names,
						      st->st_state
						      )));
			} else if (st->st_connection->spd.this.modecfg_client
				   &&
				   IS_PHASE1(st->st_state)) {
				from_state = STATE_MODE_CFG_R1;
				DBG(DBG_CONTROLMORE,
				    DBG_log(" set from_state to %s "
					    "this is modecfgclient and IS_PHASE1() == TRUE",
					    enum_name(&state_names,
						      st->st_state
						      )));
			} else {
				DBG(DBG_CONTROLMORE,
				    DBG_log("in %s:%d processed received "
					    "isakmp_xchg_type %s.",
					    __func__,
					    __LINE__,
					    enum_show(&
						      exchange_names_ikev1,
						      md->hdr.isa_xchg)));
				DBG(DBG_CONTROLMORE,
				    DBG_log("this is a%s%s%s%s in state %s. "
					    "Reply with UNSUPPORTED_EXCHANGE_TYPE",
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
				/* after iphone tests disabled
				   libreswan_log("in state %s isakmp_xchg_types %s not supported."
				   "reply UNSUPPORTED_EXCHANGE_TYPE"
				   , enum_name(&state_names, st->st_state)
				   , enum_show(&exchange_names_ikev1, md->hdr.isa_xchg));
				   SEND_NOTIFICATION(UNSUPPORTED_EXCHANGE_TYPE);
				 */
				return;
			}
		} else {
			if (st->st_connection->spd.this.xauth_server &&
			    IS_PHASE1(st->st_state)) { /* Switch from Phase1 to Mode Config */
				libreswan_log(
					"We were in phase 1, with no state, so we went to XAUTH_R0");
				change_state(st, STATE_XAUTH_R0);
			}

			/* otherweise, this is fine, we continue in the state we are in */
			set_cur_state(st);
			from_state = st->st_state;
		}

		break;

	case ISAKMP_XCHG_NGRP:
	default:
		libreswan_log("unsupported exchange type %s in message",
			      enum_show(&exchange_names_ikev1, md->hdr.isa_xchg));
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
	 * By placing the check here, we could easily add a policy bit
	 * to a connection to suppress the warning.  This might be useful
	 * because the Commit Flag is expected from some peers.
	 */
	if (md->hdr.isa_flags & ISAKMP_FLAG_COMMIT)
		libreswan_log(
			"IKE message has the Commit Flag set but Pluto doesn't implement this feature due to security concerns; ignoring flag");


	/* Handle IKE fragmentation payloads */
	if (md->hdr.isa_np == ISAKMP_NEXT_IKE_FRAGMENTATION) {
		struct isakmp_ikefrag fraghdr;
		struct ike_frag *ike_frag, **i;
		int last_frag_index = 0;  /* index of the last fragment */
		pb_stream frag_pbs;

		if (st == NULL) {
			plog(
				"received IKE fragment, but have no state. Ignoring packet.");
			return;
		}

		if ((st->st_connection->policy & POLICY_IKE_FRAG_ALLOW) == 0) {
			loglog(RC_LOG,
			       "discarding IKE fragment packet - fragmentation not allowed by local policy (ike_frag=no)");
			return;
		}

		if (!in_struct(&fraghdr, &isakmp_ikefrag_desc,
			       &md->message_pbs, &frag_pbs) ||
		    pbs_room(&frag_pbs) != fraghdr.isafrag_length ||
		    fraghdr.isafrag_np != 0 ||
		    fraghdr.isafrag_number == 0 || fraghdr.isafrag_number >
		    16) {
			SEND_NOTIFICATION(PAYLOAD_MALFORMED);
			return;
		}

		DBG(DBG_CONTROL,
		    DBG_log("received IKE fragment id '%d', number '%u'%s",
			    fraghdr.isafrag_id,
			    fraghdr.isafrag_number,
			    (fraghdr.isafrag_flags ==
			     1) ? "(last)" : ""));

		ike_frag = alloc_thing(struct ike_frag, "ike_frag");
		if (ike_frag == NULL)
			return;

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
		     memcmp(non_ESP_marker, ike_frag->data,
			    NON_ESP_MARKER_SIZE) == 0)) {
			ike_frag->data += NON_ESP_MARKER_SIZE;
			ike_frag->size -= NON_ESP_MARKER_SIZE;
		}
#endif

		/* Add the fragment to the state */
		i = &st->ike_frags;
		while (1) {
			if (ike_frag) {
				/* Still looking for a place to insert ike_frag */
				if (*i == NULL || (*i)->index >
				    ike_frag->index) {
					ike_frag->next = *i;
					*i = ike_frag;
					ike_frag = NULL;
				} else if ((*i)->index == ike_frag->index) {
					/* Replace fragment with same index */
					struct ike_frag *old = *i;
					ike_frag->next = old->next;
					*i = ike_frag;
					release_md(old->md);
					free(old);
					ike_frag = NULL;
				}
			}

			if (*i == NULL)
				break;
			else if ((*i)->last)
				last_frag_index = (*i)->index;

			i = &(*i)->next;
		}

		/* We have the last fragment, reassemble if complete */
		if (last_frag_index) {
			size_t size = 0;
			int prev_index = 0;
			struct ike_frag *frag;
			for (frag = st->ike_frags; frag; frag = frag->next) {
				size += frag->size;
				if (frag->index != ++prev_index) {
					break; /* fragment list incomplete */
				} else if (frag->index == last_frag_index) {
					struct msg_digest *md = alloc_md();
					u_int8_t *buffer = alloc_bytes(size,
								       "IKE fragments buffer");
					size_t offset = 0;

					md->iface = frag->md->iface;
					md->sender = frag->md->sender;
					md->sender_port =
						frag->md->sender_port;

					/* Reassemble fragments in buffer */
					frag = st->ike_frags;
					while (frag && frag->index <=
					       last_frag_index) {
						passert(
							offset + frag->size <=
							size);
						memcpy(buffer + offset,
						       frag->data, frag->size);
						offset += frag->size;
						frag = frag->next;
					}

					init_pbs(&md->packet_pbs, buffer, size,
						 "packet");

					process_packet(&md);
					if (md != NULL)
						release_md(md);
					release_fragments(st);
					/* optimize: if receiving fragments, immediately respond with fragments too */
					st->st_seen_fragments = TRUE;
					DBG(DBG_CONTROL,
					    DBG_log(
						    " updated IKE fragment state to respond using fragments without waiting for re-transmits"));
					break;
				}
			}
		}

		/* Don't release the md, taken care of by the ike_frag code */
		*mdp = NULL;
		return;
	}

	/* Set smc to describe this state's properties.
	 * Look up the appropriate microcode based on state and
	 * possibly Oakley Auth type.
	 */
	passert(STATE_IKE_FLOOR <= from_state && from_state <= STATE_IKE_ROOF);
	smc = ike_microcode_index[from_state - STATE_IKE_FLOOR];

	if (st != NULL) {
		oakley_auth_t baseauth =
			xauth_calcbaseauth(st->st_oakley.auth);

		while (!LHAS(smc->flags, baseauth)) {
			smc++;
			passert(smc->state == from_state);
		}
	}

	/* Ignore a packet if the state has a suspended state transition
	 * Probably a duplicated packet but the original packet is not yet
	 * recorded in st->st_rpacket, so duplicate checking won't catch.
	 * ??? Should the packet be recorded earlier to improve diagnosis?
	 */
	if (st != NULL && st->st_suspended_md != NULL) {
		loglog(RC_LOG,
		       "discarding packet received during asynchronous work (DNS or crypto) in %s",
		       enum_name(&state_names, st->st_state));
		return;
	}

	/*
	 * if this state is busy calculating in between state transitions,
	 * (there will be no suspended state), then we silently ignore the
	 * packet, as there is nothing we can do right now.
	 */
	if (st != NULL && st->st_calculating) {
		libreswan_log("message received while calculating. Ignored.");
		return;
	}

	/* Detect and handle duplicated packets.
	 * This won't work for the initial packet of an exchange
	 * because we won't have a state object to remember it.
	 * If we are in a non-receiving state (terminal), and the preceding
	 * state did transmit, then the duplicate may indicate that that
	 * transmission wasn't received -- retransmit it.
	 * Otherwise, just discard it.
	 * ??? Notification packets are like exchanges -- I hope that
	 * they are idempotent!
	 */
	if (st != NULL &&
	    st->st_rpacket.ptr != NULL &&
	    st->st_rpacket.len == pbs_room(&md->packet_pbs) &&
	    memcmp(st->st_rpacket.ptr, md->packet_pbs.start,
		   st->st_rpacket.len) == 0) {
		if (smc->flags & SMF_RETRANSMIT_ON_DUPLICATE) {
			if (st->st_retransmit < MAXIMUM_RETRANSMISSIONS) {
				st->st_retransmit++;
				loglog(RC_RETRANSMISSION,
				       "retransmitting in response to duplicate packet; already %s",
				       enum_name(&state_names, st->st_state));
				resend_ike_v1_msg(st,
						  "retransmit in response to duplicate");
			} else {
				loglog(RC_LOG_SERIOUS,
				       "discarding duplicate packet -- exhausted retransmission; already %s",
				       enum_name(&state_names, st->st_state));
			}
		} else {
			loglog(RC_LOG_SERIOUS,
			       "discarding duplicate packet; already %s",
			       enum_name(&state_names, st->st_state));
		}
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
	 * look for encrypt packets. We can not handle them if we have not
	 * yet calculated the skeyids. We will just store the packet in
	 * the suspended state, since the calculation is likely underway.
	 *
	 * note that this differs from above, because skeyid is calculated
	 * in between states. (or will be, once DH is async)
	 *
	 */
	if ((md->hdr.isa_flags & ISAKMP_FLAG_ENCRYPTION) &&
	    st != NULL && !st->hidden_variables.st_skeyid_calculated ) {
		DBG(DBG_CRYPT | DBG_CONTROL,
		    DBG_log(
			    "received encrypted packet from %s:%u but exponentiation still in progress",
			    ip_str(&md->sender), (unsigned)md->sender_port));

		/* if there was a previous packet, let it go, and go with most
		 * recent one.
		 */
		if (st->st_suspended_md) {
			DBG(DBG_CONTROL,
			    DBG_log(
				    "releasing suspended operation before completion: %p",
				    st->st_suspended_md));
			release_md(st->st_suspended_md);
		}

		set_suspended(st, md);
		*mdp = NULL;
		return;
	}

	process_packet_tail(mdp);
}

void process_packet_tail(struct msg_digest **mdp)
{
	struct msg_digest *md = *mdp;
	struct state *st = md->st;
	enum state_kind from_state = md->from_state;
	const struct state_microcode *smc = md->smc;
	bool new_iv_set = md->new_iv_set;

	if (md->hdr.isa_flags & ISAKMP_FLAG_ENCRYPTION) {
		DBG(DBG_CRYPT, DBG_log("received encrypted packet from %s:%u",
				       ip_str(&md->sender),
				       (unsigned)md->sender_port));

		if (st == NULL) {
			libreswan_log(
				"discarding encrypted message for an unknown ISAKMP SA");
			SEND_NOTIFICATION(PAYLOAD_MALFORMED /* XXX ? */);
			return;
		}
		if (st->st_skey_ei.ptr == (u_char *) NULL) {
			loglog(RC_LOG_SERIOUS, "discarding encrypted message"
			       " because we haven't yet negotiated keying material");
			SEND_NOTIFICATION(INVALID_FLAGS);
			return;
		}

		/* Mark as encrypted */
		md->encrypted = TRUE;

		DBG(DBG_CRYPT,
		    DBG_log("decrypting %u bytes using algorithm %s",
			    (unsigned) pbs_left(&md->message_pbs),
			    enum_show(&oakley_enc_names,
				      st->st_oakley.encrypt)));

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
			const struct encrypt_desc *e = st->st_oakley.encrypter;

			if (pbs_left(&md->message_pbs) % e->enc_blocksize !=
			    0) {
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
					passert(st->st_iv_len <=
						sizeof(st->st_new_iv));
					st->st_new_iv_len = st->st_iv_len;
					init_new_iv(st);
				}
			}

			crypto_cbc_encrypt(e, FALSE, md->message_pbs.cur,
					   pbs_left(&md->message_pbs), st);

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
		struct payload_digest *pd = md->digest;
		volatile int np = md->hdr.isa_np;
		lset_t needed = smc->req_payloads;
		const char *excuse =
			LIN(SMF_PSK_AUTH | SMF_FIRST_ENCRYPTED_INPUT,
			    smc->flags) ?
			"probable authentication failure (mismatch of preshared secrets?): "
			:
			"";

		while (np != ISAKMP_NEXT_NONE) {
			struct_desc *sd = np <
					  ISAKMP_NEXT_ROOF ? payload_descs[np]
					  :
					  NULL;

			if (pd == &md->digest[PAYLIMIT]) {
				loglog(RC_LOG_SERIOUS,
				       "more than %d payloads in message; ignored",
				       PAYLIMIT);
				SEND_NOTIFICATION(PAYLOAD_MALFORMED);
				return;
			}

			/*
			 * only do this in main mode. In aggressive mode, there
			 * is no negotiation of NAT-T method. Get it right.
			 */
			if (st != NULL && st->st_connection != NULL &&
			    (st->st_connection->policy & POLICY_AGGRESSIVE) ==
			    0) {
				switch (np) {
				case ISAKMP_NEXT_NATD_RFC:
				case ISAKMP_NEXT_NATOA_RFC:
					if ((!st) ||
					    (!(st->hidden_variables.
					       st_nat_traversal &
					       NAT_T_WITH_RFC_VALUES))) {
						/*
						 * don't accept NAT-D/NAT-OA reloc directly in message,
						 * unless we're using NAT-T RFC
						 */
						DBG_log(
							"st_nat_traversal was: %u\n",
							st->hidden_variables.st_nat_traversal);
						sd = NULL;
					}
					break;
				}
			}

			if (sd == NULL) {
				/* payload type is out of range or requires special handling */
				switch (np) {
				case ISAKMP_NEXT_ID:
					sd =
						(IS_PHASE1(from_state) ||
						 IS_PHASE15(from_state)) ?
						&isakmp_identification_desc : &
						isakmp_ipsec_identification_desc;
					break;

				case ISAKMP_NEXT_NATD_DRAFTS:
					np = ISAKMP_NEXT_NATD_RFC; /* NAT-D was a private use type before RFC-3947 */
					sd = payload_descs[np];
					break;

				case ISAKMP_NEXT_NATOA_DRAFTS:
					np = ISAKMP_NEXT_NATOA_RFC; /* NAT-OA was a private use type before RFC-3947 */
					sd = payload_descs[np];
					break;

				default:
					loglog(RC_LOG_SERIOUS, "%smessage ignored because it contains an unknown or"
					       " unexpected payload type (%s) at the outermost level",
					       excuse,
					       enum_show(&payload_names_ikev1, np));
					SEND_NOTIFICATION(INVALID_PAYLOAD_TYPE);
					return;
				}
			}

			{
				lset_t s = LELEM(np);

				if (LDISJOINT(s,
					      needed | smc->opt_payloads |
					      LELEM(ISAKMP_NEXT_VID) |
					      LELEM(ISAKMP_NEXT_N) |
					      LELEM(ISAKMP_NEXT_D) |
					      LELEM(ISAKMP_NEXT_CR) |
					      LELEM(ISAKMP_NEXT_CERT))) {
					loglog(RC_LOG_SERIOUS, "%smessage ignored because it "
					       "contains an unexpected payload type (%s)",
					       excuse,
					       enum_show(&payload_names_ikev1, np));
					SEND_NOTIFICATION(INVALID_PAYLOAD_TYPE);
					return;
				}

				DBG(DBG_PARSING,
				    DBG_log(
					    "got payload 0x%" PRIxLSET"  (%s) needed: 0x%" PRIxLSET "opt: 0x%" PRIxLSET,
					    s, enum_show(&payload_names_ikev1, np),
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
			}

			/* place this payload at the end of the chain for this type */
			{
				struct payload_digest **p;

				for (p = &md->chain[np]; *p != NULL;
				     p = &(*p)->next)
					;
				*p = pd;
				pd->next = NULL;
			}

			np = pd->payload.generic.isag_np;
			pd++;

			/* since we've digested one payload happily, it is probably
			 * the case that any decryption worked.  So we will not suggest
			 * encryption failure as an excuse for subsequent payload
			 * problems.
			 */
			excuse = "";
		}

		md->digest_roof = pd;

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
			       enum_show(&state_names, from_state),
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
				if (id->next == NULL || id->next->next !=
				    NULL) {
					loglog(RC_LOG_SERIOUS, "malformed Quick Mode message:"
					       " if any ID payload is present,"
					       " there must be exactly two");
					SEND_NOTIFICATION(PAYLOAD_MALFORMED);
					return;
				}
				if (id + 1 != id->next) {
					loglog(RC_LOG_SERIOUS, "malformed Quick Mode message:"
					       " the ID payloads are not adjacent");
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
				/* fall through */
			default:
				if (st == NULL) {
					loglog(RC_LOG_SERIOUS,
					       "ignoring informational payload %s, no corresponding state",
					       enum_show(&
							 ikev1_notify_names,
							 p->payload.
							 notification.isan_type));
				} else {
					loglog(RC_LOG_SERIOUS,
					       "ignoring informational payload %s, msgid=%08x, length=%d",
					       enum_show(&ikev1_notify_names,
							 p->payload.
							 notification.isan_type),
					       st->st_msgid,
					       p->payload.notification.isan_length);
					DBG_dump_pbs(&p->pbs);
				}
#ifdef DEBUG
				if (st != NULL &&
				    st->st_connection->extra_debugging &
				    IMPAIR_DIE_ONINFO) {
					loglog(RC_LOG_SERIOUS,
					       "received and failed on unknown informational message");
					complete_v1_state_transition(mdp,
								     STF_FATAL);
					return;
				}
#endif
			}
			DBG_cond_dump(DBG_PARSING, "info:", p->pbs.cur, pbs_left(
					      &p->pbs));

			p = p->next;

		}

		p = md->chain[ISAKMP_NEXT_D];
		while (p != NULL) {
			accept_delete(st, md, p);
			DBG_cond_dump(DBG_PARSING, "del:", p->pbs.cur, pbs_left(
					      &p->pbs));
			p = p->next;
		}

		p = md->chain[ISAKMP_NEXT_VID];
		while (p != NULL) {
			handle_vendorid(md, (char *)p->pbs.cur,
					pbs_left(&p->pbs), st);
			p = p->next;
		}
	}

#if 0
	/* this does not seem to be right */

	/* VERIFY that we only accept NAT-D/NAT-OE when they sent us the VID */
	if ((md->chain[ISAKMP_NEXT_NATD_RFC] != NULL ||
	     md->chain[ISAKMP_NEXT_NATOA_RFC] != NULL) &&
	    !(st->hidden_variables.st_nat_traversal & NAT_T_WITH_RFC_VALUES)) {
		/*
		 * don't accept NAT-D/NAT-OA reloc directly in message,
		 * unless we're using NAT-T RFC
		 */
		loglog(RC_LOG_SERIOUS,
		       "message ignored because it contains a NAT payload, when we did not receive the appropriate VendorID");
		return;
	}
#endif

	/* possibly fill in hdr */
	if (smc->first_out_payload != ISAKMP_NEXT_NONE)
		echo_hdr(md, (smc->flags & SMF_OUTPUT_ENCRYPTED) != 0,
			 smc->first_out_payload);

	complete_v1_state_transition(mdp, smc->processor(md));
}

static void update_retransmit_history(struct state *st, struct msg_digest *md)
{
	/*
	 * replace previous receive packet with latest, to update
	 * our notion of a retransmitted packet. This is important
	 * to do, even for failing transitions, and suspended transitions
	 * because the sender may well retransmit their request.
	 */
	pfreeany(st->st_rpacket.ptr);

	if (md->encrypted) {
		/* if encrypted, duplication already done */
		st->st_rpacket = md->raw_packet;
		md->raw_packet.ptr = NULL;
	} else {
		clonetochunk(st->st_rpacket,
			     md->packet_pbs.start,
			     pbs_room(&md->packet_pbs), "raw packet");
	}
}

/* complete job started by the state-specific state transition function */
void complete_v1_state_transition(struct msg_digest **mdp, stf_status result)
{
	struct msg_digest *md = *mdp;
	const struct state_microcode *smc = md->smc;
	enum state_kind from_state = md->from_state;
	struct state *st;

	cur_state = st = md->st; /* might have changed */

	md->result = result;
	result = md->result;

	/* If state has FRAGMENTATION support, import it */
	if ( st && md->fragvid) {
		DBG(DBG_CONTROLMORE, DBG_log("peer supports fragmentation"));
		st->st_seen_fragvid = TRUE;
	}
	/* If state has DPD support, import it */
	if ( st && md->dpd && st->hidden_variables.st_dpd != md->dpd) {
		DBG(DBG_DPD, DBG_log("peer supports dpd"));
		st->hidden_variables.st_dpd = md->dpd;

		if (st->st_connection->dpd_delay &&
		    st->st_connection->dpd_timeout) {
			/* Set local policy for DPD to be on */
			st->hidden_variables.st_dpd_local = 1;
			DBG(DBG_DPD, DBG_log("enabling sending dpd"));
		}
	}
	/* If state has VID_NORTEL, import it to activate workaround */
	if (st && md->nortel) {
		DBG(DBG_CONTROLMORE, DBG_log("peer requires nortel contivity workaround"));
		st->st_seen_nortel_vid = TRUE;
	}

	/* advance the state */
	DBG(DBG_CONTROL,
	    DBG_log("complete state transition with %s",
		    enum_name(&stfstatus_name, result)));

	/*
	 * we can only be in calculating state if state is ignore,
	 * or suspended.
	 */
	passert(
		result == STF_INLINE || result == STF_IGNORE || result == STF_SUSPEND || st->st_calculating ==
		FALSE);

	switch (result) {
	case STF_IGNORE:
		break;

	case STF_INLINE:         /* this is second time through complete
		                  * state transition, so the MD has already
		                  * been freed.
		                  */
		*mdp = NULL;
		break;

	case STF_SUSPEND:
		/* update the previous packet history */
		update_retransmit_history(st, md);

		/* the stf didn't complete its job: don't relase md */
		*mdp = NULL;
		break;

	case STF_OK:
		/* advance the state */

		libreswan_log("transition from state %s to state %s",
			      enum_name(&state_names, from_state),
			      enum_name(&state_names, smc->next_state));

		if (st->st_reserve_msgid == FALSE && st->st_clonedfrom !=
		    SOS_NOBODY && st->st_msgid != 0) {
			struct state *p1st = state_with_serialno(
				st->st_clonedfrom);

			if (p1st) {
				/* do message ID reservation */
				reserve_msgid(p1st, st->st_msgid);
			}

			st->st_reserve_msgid = TRUE;
		}

		change_state(st, smc->next_state);

		/* XAUTH negotiation withOUT modecfg ends in STATE_XAUTH_I1
		 * which is wrong and creates issues further in several places
		 * As per libreswan design, it seems every phase 1 negotiation
		 * including xauth/modecfg must end with STATE_MAIN_I4 to mark
		 * actual end of phase 1. With modecfg, negotiation ends with
		 * STATE_MAIN_I4 already.
		 */
		/*if(st->st_connection->spd.this.xauth_client
		    && st->hidden_variables.st_xauth_client_done
		    && !st->st_connection->spd.this.modecfg_client
		    && st->st_state == STATE_XAUTH_I1) {
		    DBG(DBG_CONTROL, DBG_log("As XAUTH is done and modecfg is not configured,
		                                    so Phase 1 neogtiation finishes successfully"));
		    change_state(st, STATE_MAIN_I4);
		   }*/

		/* Schedule for whatever timeout is specified */
		if (!md->event_already_set) {
			/* Delete previous retransmission event.
			 * New event will be scheduled below.
			 */
			delete_event(st);
		}

		/* Delete IKE fragments */
		release_fragments(st);

		/* update the previous packet history */
		update_retransmit_history(st, md);

		/* free previous transmit packet */
		freeanychunk(st->st_tpacket);

		/* in aggressive mode, there will be no reply packet in transition
		 * from STATE_AGGR_R1 to STATE_AGGR_R2 */
		if (nat_traversal_enabled) {
			/* adjust our destination port if necessary */
			nat_traversal_change_port_lookup(md, st);
		}

		/* if requested, send the new reply packet */
		if (smc->flags & SMF_REPLY) {

			DBG(DBG_CONTROL, {
				    char buf[ADDRTOT_BUF];
				    DBG_log(
					    "sending reply packet to %s:%u (from port %u)",
					    (addrtot(&st->st_remoteaddr,
						     0, buf,
						     sizeof(buf)), buf),
					    st->st_remoteport,
					    st->st_interface->port);
			    });

			close_output_pbs(&reply_stream); /* good form, but actually a no-op */

			clonetochunk(st->st_tpacket, reply_stream.start,
				     pbs_offset(&reply_stream),
				     "reply packet");

			/* actually send the packet
			 * Note: this is a great place to implement "impairments"
			 * for testing purposes.  Suppress or duplicate the
			 * send_ike_msg call depending on st->st_state.
			 */

			send_ike_msg(st, enum_name(&state_names, from_state));
		}

		/* Schedule for whatever timeout is specified */
		if (!md->event_already_set) {
			time_t delay;
			enum event_type kind = smc->timeout_event;
			bool agreed_time = FALSE;
			struct connection *c = st->st_connection;

			switch (kind) {
			case EVENT_RETRANSMIT: /* Retransmit packet */
				delay = EVENT_RETRANSMIT_DELAY_0;
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
					delay = c->sa_ike_life_seconds;
					if ((c->policy & POLICY_DONT_REKEY) ||
					    delay >=
					    st->st_oakley.life_seconds) {
						agreed_time = TRUE;
						delay =
							st->st_oakley.
							life_seconds;
					}
				} else {
					/* Delay is min of up to four things:
					 * each can limit the lifetime.
					 */
					delay = c->sa_ipsec_life_seconds;
					if (st->st_ah.present &&
					    delay >=
					    st->st_ah.attrs.life_seconds) {
						agreed_time = TRUE;
						delay =
							st->st_ah.attrs.
							life_seconds;
					}
					if (st->st_esp.present &&
					    delay >=
					    st->st_esp.attrs.life_seconds) {
						agreed_time = TRUE;
						delay =
							st->st_esp.attrs.
							life_seconds;
					}
					if (st->st_ipcomp.present &&
					    delay >=
					    st->st_ipcomp.attrs.life_seconds) {
						agreed_time = TRUE;
						delay =
							st->st_ipcomp.attrs.
							life_seconds;
					}
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
					unsigned long marg =
						c->sa_rekey_margin;

					if (smc->flags & SMF_INITIATOR) {
						marg += marg *
							c->sa_rekey_fuzz /
							100.E0 *
							(rand() /
							 (RAND_MAX + 1.E0));
					} else {
						marg /= 2;
					}

					if ((unsigned long)delay > marg) {
						delay -= marg;
						st->st_margin = marg;
					} else {
						kind = EVENT_SA_EXPIRE;
					}
				}
				break;

			case EVENT_NULL:                /* non-event */
			case EVENT_REINIT_SECRET:       /* Refresh cookie secret */
			default:
				bad_case(kind);
			}
			event_schedule(kind, delay, st);
		}

		/* tell whack and log of progress */
		{
			const char *story = enum_name(&state_stories,
						      st->st_state);
			enum rc_type w = RC_NEW_STATE + st->st_state;
			char sadetails[512];

			passert(st->st_state < STATE_IKE_ROOF);

			sadetails[0] = '\0';

			/* document IPsec SA details for admin's pleasure */
			if (IS_IPSEC_SA_ESTABLISHED(st->st_state)) {
				fmt_ipsec_sa_established(st, sadetails,
							 sizeof(sadetails));

			} else if (IS_ISAKMP_SA_ESTABLISHED(st->st_state) &&
				   !st->hidden_variables.st_logged_p1algos) {
				fmt_isakmp_sa_established(st, sadetails,
							  sizeof(sadetails));
			}

			if (IS_ISAKMP_SA_ESTABLISHED(st->st_state) ||
			    IS_IPSEC_SA_ESTABLISHED(st->st_state)) {
				/* log our success */
				w = RC_SUCCESS;
			}

			/* tell whack and logs our progress */
			loglog(w,
			       "%s: %s%s",
			       enum_name(&state_names, st->st_state),
			       story,
			       sadetails);
		}

		/*
		 * make sure that a DPD event gets created for a new phase 1
		 * SA.
		 */
		if (IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
			if (st->st_connection->dpd_delay > 0 &&
			    st->st_connection->dpd_timeout > 0) {
				/* don't ignore failure */
				if (dpd_init(st) == STF_FAIL)
					result = STF_FAIL; /* fall through */
			}
		}

		/* Special case for XAUTH server */
		if (st->st_connection->spd.this.xauth_server) {
			if (st->st_oakley.doing_xauth &&
			    IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
				libreswan_log(
					"XAUTH: Sending XAUTH Login/Password Request");
				xauth_send_request(st);
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
			modecfg_start_set(st);
			break;
		}

		/* If we are the responder and the client is in "Contivity mode",
		   we need to initiate Quick mode */
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
			 * so, instead of actualling sending the traffic now,
			 * we schedule an event to do so.
			 *
			 * but, in fact, quick_mode will enqueue a cryptographic operation
			 * anyway, which will get done "later" anyway, so make it is just fine
			 * as it is.
			 *
			 */
			unpend(st);
		}

		if (IS_ISAKMP_SA_ESTABLISHED(st->st_state) ||
		    IS_IPSEC_SA_ESTABLISHED(st->st_state))
			release_whack(st);

		if (IS_QUICK(st->st_state))
			break;

		break;

	case STF_INTERNAL_ERROR:
		/* update the previous packet history */
		update_retransmit_history(st, md);

		whack_log(RC_INTERNALERR + md->note,
			  "%s: internal error",
			  enum_name(&state_names, st->st_state));

		DBG(DBG_CONTROL,
		    DBG_log(
			    "state transition function for %s had internal error",
			    enum_name(&state_names, from_state)));
		break;

	case STF_TOOMUCHCRYPTO:
		/* well, this should never happen during a whack, since
		 * a whack will always force crypto.
		 */
		set_suspended(st, NULL);
		pexpect(st->st_calculating == FALSE);
		libreswan_log(
			"message in state %s ignored due to cryptographic overload",
			enum_name(&state_names, from_state));
		break;

	case STF_FATAL:
		/* update the previous packet history */
		update_retransmit_history(st, md);

		whack_log(RC_FATAL,
			  "encountered fatal error in state %s",
			  enum_name(&state_names, st->st_state));
#ifdef HAVE_NM
		if (st->st_connection->remotepeertype == CISCO &&
		    st->st_connection->nmconfigured) {
			if (!do_command(st->st_connection,
					&st->st_connection->spd,
					"disconnectNM", st))
				DBG(DBG_CONTROL,
				    DBG_log(
					    "sending disconnect to NM failed, you may need to do it manually"));


		}
#endif
		delete_event(st);
		release_pending_whacks(st, "fatal error");
		delete_state(st);
		break;

	default:        /* a shortcut to STF_FAIL, setting md->note */
		passert(result > STF_FAIL);
		md->note = result - STF_FAIL;
		result = STF_FAIL;
	/* FALL THROUGH ... */

	case STF_FAIL:
		/* As it is, we act as if this message never happened:
		 * whatever retrying was in place, remains in place.
		 */
		whack_log(RC_NOTIFICATION + md->note,
			  "%s: %s", enum_name(&state_names, st->st_state),
			  enum_name(&ikev1_notify_names, md->note));

		if (md->note > 0)
			SEND_NOTIFICATION(md->note);

		DBG(DBG_CONTROL,
		    DBG_log("state transition function for %s failed: %s",
			    enum_name(&state_names, from_state),
			    enum_name(&ikev1_notify_names, md->note)));
#ifdef HAVE_NM
		if (st->st_connection->remotepeertype == CISCO &&
		    st->st_connection->nmconfigured) {
			if (!do_command(st->st_connection,
					&st->st_connection->spd,
					"disconnectNM", st))
				DBG(DBG_CONTROL,
				    DBG_log(
					    "sending disconnect to NM failed, you may need to do it manually"));


		}
#endif
		if (st != NULL && IS_PHASE1_INIT(st->st_state)) {
			delete_event(st);
			release_whack(st);
		}
		if (st != NULL && IS_QUICK(st->st_state))
			delete_state(st);
		break;
	}

}
