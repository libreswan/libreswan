/* IKEv2 state machine, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010,2013-2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2011 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2008 Hiren Joshi <joshihirenn@gmail.com>
 * Copyright (C) 2009 Anthony Tong <atong@TrustedCS.com>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2019-2019 Andrew Cagney <cagney@gnu.org>
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
#include "ikev1_states.h"
#include "ikev1_xauth.h"
#include "log.h"

#define S(KIND, STORY, CAT) \
	struct finite_state state_v1_##KIND = {				\
		.kind = STATE_##KIND,					\
		.name = "STATE_"#KIND,					\
		/* Not using #KIND + 6 because of clang's -Wstring-plus-int */ \
		.short_name = #KIND,					\
		.story = STORY,						\
		.category = CAT,					\
		.ike_version = IKEv1,					\
	}

/*
 * Count I1 as half-open too because with ondemand, a
 * plaintext packet (that is spoofed) will trigger an outgoing
 * ISAKMP (IKE) SA.
 */

S(AGGR_R0, "expecting Aggressive Mode request", CAT_HALF_OPEN_IKE_SA);
S(AGGR_I1, "sent Aggressive Mode request", CAT_HALF_OPEN_IKE_SA);
S(MAIN_R0, "expecting Main Mode request", CAT_HALF_OPEN_IKE_SA);
S(MAIN_I1, "sent Main Mode request", CAT_HALF_OPEN_IKE_SA);

/*
 * All IKEv1 MAIN modes except the first (half-open) and last
 * ones are not authenticated.
 *
 * These exchanges don't have any userfriendly name, like we used
 * elsewhere (request, response, confirmation)
 */

S(MAIN_R1, "sent Main Mode R1", CAT_OPEN_IKE_SA);
S(MAIN_R2, "sent Main Mode R2", CAT_OPEN_IKE_SA);
S(MAIN_I2, "sent Main Mode I2", CAT_OPEN_IKE_SA);
S(MAIN_I3, "sent Main Mode I3", CAT_OPEN_IKE_SA);
S(AGGR_R1, "sent Aggressive Mode response, expecting confirmation", CAT_OPEN_IKE_SA);

/*
 * IKEv1 established states.
 *
 * XAUTH, seems to a second level of authentication performed
 * after the connection is established and authenticated.
 */

S(MAIN_I4, "ISAKMP SA established", CAT_ESTABLISHED_IKE_SA);
S(MAIN_R3, "ISAKMP SA established", CAT_ESTABLISHED_IKE_SA);
S(AGGR_I2, "ISAKMP SA established", CAT_ESTABLISHED_IKE_SA);
S(AGGR_R2, "ISAKMP SA established", CAT_ESTABLISHED_IKE_SA);
S(XAUTH_I0, "XAUTH client - possibly awaiting CFG_request", CAT_ESTABLISHED_IKE_SA);
S(XAUTH_I1, "XAUTH client - possibly awaiting CFG_set", CAT_ESTABLISHED_IKE_SA);
S(XAUTH_R0, "XAUTH responder - optional CFG exchange", CAT_ESTABLISHED_IKE_SA);
S(XAUTH_R1, "XAUTH status sent, expecting Ack", CAT_ESTABLISHED_IKE_SA);

/*
 * IKEv1: QUICK is for child connections children.
 *        Initiator                        Responder
 *       -----------                      -----------
 *        HDR*, HASH(1), SA, Ni
 *          [, KE ] [, IDci, IDcr ] -->
 *                                  <--    HDR*, HASH(2), SA, Nr
 *                                               [, KE ] [, IDci, IDcr ]
 *        HDR*, HASH(3)             -->
 */

/* this is not established yet */
S(QUICK_I1, "sent Quick Mode request", CAT_ESTABLISHED_CHILD_SA);
S(QUICK_I2, "IPsec SA established", CAT_ESTABLISHED_CHILD_SA);
/* shouldn't we cat_ignore this? */
S(QUICK_R0, "expecting Quick Mode request", CAT_ESTABLISHED_CHILD_SA);
S(QUICK_R1, "sent Quick Mode reply, inbound IPsec SA installed, expecting confirmation", CAT_ESTABLISHED_CHILD_SA);
S(QUICK_R2, "IPsec SA established", CAT_ESTABLISHED_CHILD_SA);

/*
 * IKEv1: Post established negotiation.
 */

S(MODE_CFG_I1, "sent ModeCfg request", CAT_ESTABLISHED_IKE_SA);
S(MODE_CFG_R1, "sent ModeCfg reply, expecting Ack", CAT_ESTABLISHED_IKE_SA);
S(MODE_CFG_R2, "received ModeCfg Ack", CAT_ESTABLISHED_IKE_SA);

S(INFO, "received unencrypted Informational Exchange message", CAT_INFORMATIONAL);
S(INFO_PROTECTED, "received encrypted Informational Exchange message", CAT_INFORMATIONAL);
S(MODE_CFG_R0, "received ModeCfg request, reply sent", CAT_INFORMATIONAL);
S(MODE_CFG_CLIENT_RESPONDING, "non-pull client received MODE_CFG", CAT_INFORMATIONAL);
S(MODE_CFG_SERVER_WAITING_FOR_ACK, "server sent MODE_CFG SET, waiting for MODE_CFG ACK", CAT_INFORMATIONAL);

#undef S

struct finite_state *v1_states[] = {
#define S(KIND) [STATE_##KIND - STATE_IKEv1_FLOOR] = &state_v1_##KIND
	S(AGGR_R0),
	S(AGGR_I1),
	S(MAIN_R0),
	S(MAIN_I1),
	S(MAIN_R1),
	S(MAIN_R2),
	S(MAIN_I2),
	S(MAIN_I3),
	S(AGGR_R1),
	S(MAIN_I4),
	S(MAIN_R3),
	S(AGGR_I2),
	S(AGGR_R2),
	S(XAUTH_I0),
	S(XAUTH_I1),
	S(XAUTH_R0),
	S(XAUTH_R1),
	S(QUICK_I1),
	S(QUICK_I2),
	S(QUICK_R0),
	S(QUICK_R1),
	S(QUICK_R2),
	S(MODE_CFG_I1),
	S(MODE_CFG_R1),
	S(MODE_CFG_R2),
	S(INFO),
	S(INFO_PROTECTED),
	S(MODE_CFG_R0),
	S(MODE_CFG_CLIENT_RESPONDING),
	S(MODE_CFG_SERVER_WAITING_FOR_ACK),
#undef S
};

/*
 * v1_state_microcode_table is a table of all state_v1_microcode
 * tuples.  It must be in order of state (the first element).  After
 * initialization, ike_microcode_index[s] points to the first entry in
 * v1_state_microcode_table for state s.  Remember that each state
 * name in Main or Quick Mode describes what has happened in the past,
 * not what this message is.
 */

static const struct state_v1_microcode v1_state_microcode_table[] = {

#define FM(F) .processor = F, .message = #F

	/***** Phase 1 Main Mode *****/

	/* No state for main_outI1: --> HDR, SA */

	/* STATE_MAIN_R0: I1 --> R1
	 * HDR, SA --> HDR, SA
	 */
	{ STATE_MAIN_R0, STATE_MAIN_R1,
	  SMF_ALL_AUTH | SMF_REPLY,
	  v1P(SA), v1P(VID) | v1P(CR),
	  EVENT_v1_DISCARD,
	  FM(main_inI1_outR1),
	  .hash_type = V1_HASH_NONE, },

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
	  v1P(SA), v1P(VID) | v1P(CR),
	  EVENT_v1_RETRANSMIT,
	  FM(main_inR1_outI2),
	  .hash_type = V1_HASH_NONE, },

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
	  v1P(KE) | v1P(NONCE), v1P(VID) | v1P(CR) | v1P(NATD_RFC),
	  EVENT_v1_RETRANSMIT,
	  FM(main_inI2_outR2),
	  .hash_type = V1_HASH_NONE, },

	{ STATE_MAIN_R1, STATE_UNDEFINED,
	  SMF_PKE_AUTH | SMF_REPLY | SMF_RETRANSMIT_ON_DUPLICATE,
	  v1P(KE) | v1P(ID) | v1P(NONCE), v1P(VID) | v1P(CR) | v1P(HASH),
	  EVENT_v1_RETRANSMIT,
	  FM(unexpected) /* ??? not yet implemented */,
	  .hash_type = V1_HASH_NONE, },

	{ STATE_MAIN_R1, STATE_UNDEFINED,
	  SMF_RPKE_AUTH | SMF_REPLY | SMF_RETRANSMIT_ON_DUPLICATE,
	  v1P(NONCE) | v1P(KE) | v1P(ID), v1P(VID) | v1P(CR) | v1P(HASH) | v1P(CERT),
	  EVENT_v1_RETRANSMIT,
	  FM(unexpected) /* ??? not yet implemented */,
	  .hash_type = V1_HASH_NONE, },

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
	  v1P(KE) | v1P(NONCE), v1P(VID) | v1P(CR) | v1P(NATD_RFC),
	  EVENT_v1_RETRANSMIT,
	  FM(main_inR2_outI3),
	  /* calls main_mode_hash() after DH */
	  .hash_type = V1_HASH_NONE, },

	{ STATE_MAIN_I2, STATE_UNDEFINED,
	  SMF_PKE_AUTH | SMF_INITIATOR | SMF_OUTPUT_ENCRYPTED | SMF_REPLY,
	  v1P(KE) | v1P(ID) | v1P(NONCE), v1P(VID) | v1P(CR),
	  EVENT_v1_RETRANSMIT,
	  FM(unexpected) /* ??? not yet implemented */,
	  .hash_type = V1_HASH_NONE, },

	{ STATE_MAIN_I2, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_INITIATOR | SMF_OUTPUT_ENCRYPTED | SMF_REPLY,
	  v1P(NONCE) | v1P(KE) | v1P(ID), v1P(VID) | v1P(CR),
	  EVENT_v1_RETRANSMIT,
	  FM(unexpected) /* ??? not yet implemented */,
	  .hash_type = V1_HASH_NONE, },

	/* for states from here on, input message must be encrypted */

	/* STATE_MAIN_R2: I3 --> R3
	 * SMF_PSK_AUTH: HDR*, IDi1, HASH_I --> HDR*, IDr1, HASH_R
	 * SMF_DS_AUTH: HDR*, IDi1, [ CERT, ] SIG_I --> HDR*, IDr1, [ CERT, ] SIG_R
	 * SMF_PKE_AUTH, SMF_RPKE_AUTH: HDR*, HASH_I --> HDR*, HASH_R
	 */
	{ STATE_MAIN_R2, STATE_MAIN_R3,
	  SMF_PSK_AUTH | SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED |
		SMF_REPLY | SMF_RELEASE_PENDING_P2,
	  v1P(ID) | v1P(HASH), v1P(VID) | v1P(CR),
	  EVENT_v1_REPLACE,
	  FM(main_inI3_outR3),
	  /* calls oakley_auth() which calls main_mode_hash() */
	  /* RFC 2409: 5. Exchanges & 5.2 Phase 1 Authenticated With Public Key Encryption
	     HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b ) */
	  .hash_type = V1_HASH_NONE, },

	{ STATE_MAIN_R2, STATE_MAIN_R3,
	  SMF_DS_AUTH | SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED |
		SMF_REPLY | SMF_RELEASE_PENDING_P2,
	  v1P(ID) | v1P(SIG), v1P(VID) | v1P(CR) | v1P(CERT),
	  EVENT_v1_REPLACE,
	  FM(main_inI3_outR3),
	  /* calls oakley_auth() which calls main_mode_hash() */
	  /* RFC 2409: 5. Exchanges & 5.1 IKE Phase 1 Authenticated With Signatures
	     HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b )
	     SIG_I = SIGN(HASH_I) *",
	     SIG_I = SIGN(HASH_I) */
	  .hash_type = V1_HASH_NONE, },

	{ STATE_MAIN_R2, STATE_UNDEFINED,
	  SMF_PKE_AUTH | SMF_RPKE_AUTH | SMF_FIRST_ENCRYPTED_INPUT |
		SMF_ENCRYPTED |
		SMF_REPLY | SMF_RELEASE_PENDING_P2,
	  v1P(HASH), v1P(VID) | v1P(CR),
	  EVENT_v1_REPLACE,
	  FM(unexpected) /* ??? not yet implemented */,
	  .hash_type = V1_HASH_NONE, },

	/* STATE_MAIN_I3: R3 --> done
	 * SMF_PSK_AUTH: HDR*, IDr1, HASH_R --> done
	 * SMF_DS_AUTH: HDR*, IDr1, [ CERT, ] SIG_R --> done
	 * SMF_PKE_AUTH, SMF_RPKE_AUTH: HDR*, HASH_R --> done
	 * May initiate quick mode by calling quick_outI1
	 */
	{ STATE_MAIN_I3, STATE_MAIN_I4,
	  SMF_PSK_AUTH | SMF_INITIATOR |
		SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED | SMF_RELEASE_PENDING_P2,
	  v1P(ID) | v1P(HASH), v1P(VID) | v1P(CR),
	  EVENT_v1_REPLACE,
	  FM(main_inR3),
	  /* calls oakley_auth() which calls main_mode_hash() */
	  /* RFC 2409: 5. Exchanges & 5.2 Phase 1 Authenticated With Public Key Encryption
	     HASH_R = prf(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b ) */
	  .hash_type = V1_HASH_NONE, },

	{ STATE_MAIN_I3, STATE_MAIN_I4,
	  SMF_DS_AUTH | SMF_INITIATOR |
		SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED | SMF_RELEASE_PENDING_P2,
	  v1P(ID) | v1P(SIG), v1P(VID) | v1P(CR) | v1P(CERT),
	  EVENT_v1_REPLACE,
	  FM(main_inR3),
	  /* calls oakley_auth() which calls main_mode_hash() */
	  /* RFC 2409: 5. Exchanges & 5.1 IKE Phase 1 Authenticated With Signatures
	     HASH_R = prf(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b )
	     SIG_R = SIGN(HASH_R) */
	  .hash_type = V1_HASH_NONE, },

	{ STATE_MAIN_I3, STATE_UNDEFINED,
	  SMF_PKE_AUTH | SMF_RPKE_AUTH | SMF_INITIATOR |
		SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED | SMF_RELEASE_PENDING_P2,
	  v1P(HASH), v1P(VID) | v1P(CR),
	  EVENT_v1_REPLACE,
	  FM(unexpected) /* ??? not yet implemented */,
	  .hash_type = V1_HASH_NONE, },

	/* STATE_MAIN_R3: can only get here due to packet loss */
	{ STATE_MAIN_R3, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_RETRANSMIT_ON_DUPLICATE,
	  LEMPTY, LEMPTY,
	  EVENT_NULL,
	  FM(unexpected),
	  .hash_type = V1_HASH_NONE, },

	/* STATE_MAIN_I4: can only get here due to packet loss */
	{ STATE_MAIN_I4, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_INITIATOR | SMF_ENCRYPTED,
	  LEMPTY, LEMPTY,
	  EVENT_NULL,
	  FM(unexpected),
	  .hash_type = V1_HASH_NONE, },

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
	  v1P(SA) | v1P(KE) | v1P(NONCE) | v1P(ID), v1P(VID) | v1P(NATD_RFC),
	  EVENT_v1_DISCARD,
	  FM(aggr_inI1_outR1),
	  /* N/A */
	  .hash_type = V1_HASH_NONE, },

	/* STATE_AGGR_I1:
	 * SMF_PSK_AUTH: HDR, SA, KE, Nr, IDir, HASH_R
	 *           --> HDR*, HASH_I
	 * SMF_DS_AUTH:  HDR, SA, KE, Nr, IDir, [CERT,] SIG_R
	 *           --> HDR*, [CERT,] SIG_I
	 */
	{ STATE_AGGR_I1, STATE_AGGR_I2,
	  SMF_PSK_AUTH | SMF_INITIATOR | SMF_OUTPUT_ENCRYPTED | SMF_REPLY |
		SMF_RELEASE_PENDING_P2,
	  v1P(SA) | v1P(KE) | v1P(NONCE) | v1P(ID) | v1P(HASH), v1P(VID) | v1P(NATD_RFC),
	  EVENT_v1_REPLACE,
	  FM(aggr_inR1_outI2),
	  /* after DH calls oakley_auth() which calls main_mode_hash() */
	  /* RFC 2409: 5. Exchanges & 5.2 Phase 1 Authenticated With Public Key Encryption
	     HASH_R = prf(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b ) */
	  .hash_type = V1_HASH_NONE, },

	{ STATE_AGGR_I1, STATE_AGGR_I2,
	  SMF_DS_AUTH | SMF_INITIATOR | SMF_OUTPUT_ENCRYPTED | SMF_REPLY |
		SMF_RELEASE_PENDING_P2,
	  v1P(SA) | v1P(KE) | v1P(NONCE) | v1P(ID) | v1P(SIG), v1P(VID) | v1P(NATD_RFC),
	  EVENT_v1_REPLACE,
	  FM(aggr_inR1_outI2),
	  /* after DH calls oakley_auth() which calls main_mode_hash() */
	  /* RFC 2409: 5. Exchanges & 5.1 IKE Phase 1 Authenticated With Signatures
	     HASH_R = prf(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b )
	     SIG_R = SIGN(HASH_R) */
	  .hash_type = V1_HASH_NONE, },

	/* STATE_AGGR_R1:
	 * SMF_PSK_AUTH: HDR*, HASH_I --> done
	 * SMF_DS_AUTH:  HDR*, SIG_I  --> done
	 */
	{ STATE_AGGR_R1, STATE_AGGR_R2,
	  SMF_PSK_AUTH | SMF_FIRST_ENCRYPTED_INPUT |
		SMF_OUTPUT_ENCRYPTED | SMF_RELEASE_PENDING_P2 |
		SMF_RETRANSMIT_ON_DUPLICATE,
	  v1P(HASH), v1P(VID) | v1P(NATD_RFC),
	  EVENT_v1_REPLACE,
	  FM(aggr_inI2),
	  /* calls oakley_auth() which calls main_mode_hash() */
	  /* RFC 2409: 5. Exchanges & 5.2 Phase 1 Authenticated With Public Key Encryption
	     HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b ) */
	  .hash_type = V1_HASH_NONE, },

	{ STATE_AGGR_R1, STATE_AGGR_R2,
	  SMF_DS_AUTH | SMF_FIRST_ENCRYPTED_INPUT |
		SMF_OUTPUT_ENCRYPTED | SMF_RELEASE_PENDING_P2 |
		SMF_RETRANSMIT_ON_DUPLICATE,
	  v1P(SIG), v1P(VID) | v1P(NATD_RFC),
	  EVENT_v1_REPLACE,
	  FM(aggr_inI2),
	  /* calls oakley_auth() which calls main_mode_hash() */
	  /* RFC 2409: 5. Exchanges & 5.1 IKE Phase 1 Authenticated With Signatures
	     HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b )
	     SIG_I = SIGN(HASH_I) */
	  .hash_type = V1_HASH_NONE, },

	/* STATE_AGGR_I2: can only get here due to packet loss */
	{ STATE_AGGR_I2, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_INITIATOR | SMF_RETRANSMIT_ON_DUPLICATE,
	  LEMPTY, LEMPTY, EVENT_NULL,
	  FM(unexpected),
	  .hash_type = V1_HASH_NONE, },

	/* STATE_AGGR_R2: can only get here due to packet loss */
	{ STATE_AGGR_R2, STATE_UNDEFINED,
	  SMF_ALL_AUTH,
	  LEMPTY, LEMPTY, EVENT_NULL,
	  FM(unexpected),
	  .hash_type = V1_HASH_NONE, },

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
	  v1P(HASH) | v1P(SA) | v1P(NONCE), /* v1P(SA) | */ v1P(KE) | v1P(ID) | v1P(NATOA_RFC),
	  EVENT_v1_RETRANSMIT,
	  FM(quick_inI1_outR1),
	  /* RFC 2409: 5.5 Phase 2 - Quick Mode:
	     HASH(1) = prf(SKEYID_a, M-ID | <rest>) */
	  .hash_type = V1_HASH_1, },

	/* STATE_QUICK_I1:
	 * HDR*, HASH(2), SA, Nr [, KE ] [, IDci, IDcr ] -->
	 * HDR*, HASH(3)
	 * Installs inbound and outbound IPsec SAs, routing, etc.
	 * ??? it is legal to have multiple SAs, but we don't support it yet.
	 */
	{ STATE_QUICK_I1, STATE_QUICK_I2,
	  SMF_ALL_AUTH | SMF_INITIATOR | SMF_ENCRYPTED | SMF_REPLY,
	  v1P(HASH) | v1P(SA) | v1P(NONCE), /* v1P(SA) | */ v1P(KE) | v1P(ID) | v1P(NATOA_RFC),
	  EVENT_v1_REPLACE,
	  FM(quick_inR1_outI2),
	  /* RFC 2409: 5.5 Phase 2 - Quick Mode:
	     HASH(2) = prf(SKEYID_a, M-ID | Ni_b | <rest>) */
	  .hash_type = V1_HASH_2, },

	/* STATE_QUICK_R1: HDR*, HASH(3) --> done
	 * Installs outbound IPsec SAs, routing, etc.
	 */
	{ STATE_QUICK_R1, STATE_QUICK_R2,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  v1P(HASH), LEMPTY,
	  EVENT_v1_REPLACE,
	  FM(quick_inI2),
	  /* RFC 2409: 5.5 Phase 2 - Quick Mode:
	     HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b) */
	  .hash_type = V1_HASH_3, },

	/* STATE_QUICK_I2: can only happen due to lost packet */
	{ STATE_QUICK_I2, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_INITIATOR | SMF_ENCRYPTED |
		SMF_RETRANSMIT_ON_DUPLICATE,
	  LEMPTY, LEMPTY,
	  EVENT_NULL,
	  FM(unexpected),
	  .hash_type = V1_HASH_NONE, },

	/* STATE_QUICK_R2: can only happen due to lost packet */
	{ STATE_QUICK_R2, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  LEMPTY, LEMPTY,
	  EVENT_NULL,
	  FM(unexpected),
	  .hash_type = V1_HASH_NONE, },

	/***** informational messages *****/

	/* Informational Exchange (RFC 2408 4.8):
	 * HDR N/D
	 * Unencrypted: must not occur after ISAKMP Phase 1 exchange of keying material.
	 */
	/* STATE_INFO: */
	{ STATE_INFO, STATE_UNDEFINED,
	  SMF_ALL_AUTH,
	  LEMPTY, LEMPTY,
	  EVENT_NULL,
	  FM(informational),
	  .hash_type = V1_HASH_NONE, },

	/* Informational Exchange (RFC 2408 4.8):
	 * HDR* N/D
	 */
	/* STATE_INFO_PROTECTED: */
	{ STATE_INFO_PROTECTED, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  v1P(HASH), LEMPTY,
	  EVENT_NULL,
	  FM(informational),
	  /* RFC 2409: 5.7 ISAKMP Informational Exchanges:
	     HASH(1) = prf(SKEYID_a, M-ID | N/D) */
	  .hash_type = V1_HASH_1, },

	{ STATE_XAUTH_R0, STATE_XAUTH_R1,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  v1P(MODECFG) | v1P(HASH), v1P(VID),
	  EVENT_NULL,
	  FM(xauth_inR0),
	  /* RFC ????: */
	  .hash_type = V1_HASH_1, }, /* Re-transmit may be done by previous state */

	{ STATE_XAUTH_R1, STATE_MAIN_R3,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  v1P(MODECFG) | v1P(HASH), v1P(VID),
	  EVENT_v1_REPLACE,
	  FM(xauth_inR1),
	  /* RFC ????: */
	  .hash_type = V1_HASH_1, },

#if 0
	/* for situation where there is XAUTH + ModeCFG */
	{ STATE_XAUTH_R2, STATE_XAUTH_R3,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  v1P(MODECFG) | v1P(HASH), v1P(VID),
	  EVENT_v1_REPLACE,
	  FM(xauth_inR2), },

	{ STATE_XAUTH_R3, STATE_MAIN_R3,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  v1P(MODECFG) | v1P(HASH), v1P(VID),
	  EVENT_v1_REPLACE,
	  FM(xauth_inR3), },
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
	  SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_RETRANSMIT_ON_DUPLICATE,
	  v1P(MODECFG) | v1P(HASH), v1P(VID),
	  EVENT_v1_REPLACE,
	  FM(modecfg_inR0),
	  /* RFC ????: */
	  .hash_type = V1_HASH_1, },

	{ STATE_MODE_CFG_SERVER_WAITING_FOR_ACK, STATE_MAIN_R3,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  v1P(MODECFG) | v1P(HASH), v1P(VID),
	  EVENT_v1_REPLACE,
	  FM(modecfg_server_inACK),
	  /* RFC ????: */
	  .hash_type = V1_HASH_1, },

	{ STATE_MODE_CFG_R1, STATE_MODE_CFG_R2,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  v1P(MODECFG) | v1P(HASH), v1P(VID),
	  EVENT_v1_REPLACE,
	  FM(modecfg_inR1),
	  /* RFC ????: */
	  .hash_type = V1_HASH_1, },

	{ STATE_MODE_CFG_R2, STATE_UNDEFINED,
	  SMF_ALL_AUTH | SMF_ENCRYPTED,
	  LEMPTY, LEMPTY,
	  EVENT_NULL,
	  FM(unexpected),
	  .hash_type = V1_HASH_NONE, },

	{ STATE_MODE_CFG_CLIENT_RESPONDING, STATE_MAIN_I4,
	  SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_RETRANSMIT_ON_DUPLICATE | SMF_RELEASE_PENDING_P2,
	  v1P(MODECFG) | v1P(HASH), v1P(VID),
	  EVENT_v1_REPLACE,
	  FM(modecfg_client_inSET),
	  /* RFC ????: */
	  .hash_type = V1_HASH_1, },

	{ STATE_MODE_CFG_I1, STATE_MAIN_I4,
	  SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_RELEASE_PENDING_P2,
	  v1P(MODECFG) | v1P(HASH), v1P(VID),
	  EVENT_v1_REPLACE,
	  FM(modecfg_inR1),
	  /* RFC ????: */
	  .hash_type = V1_HASH_1, },

	{ STATE_XAUTH_I0, STATE_XAUTH_I1,
	  SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_REPLY | SMF_RELEASE_PENDING_P2,
	  v1P(MODECFG) | v1P(HASH), v1P(VID),
	  EVENT_v1_RETRANSMIT,
	  FM(xauth_inI0),
	  /* RFC ????: */
	  .hash_type = V1_HASH_1, },

	{ STATE_XAUTH_I1, STATE_MAIN_I4,
	  SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_REPLY | SMF_RELEASE_PENDING_P2,
	  v1P(MODECFG) | v1P(HASH), v1P(VID),
	  EVENT_v1_RETRANSMIT,
	  FM(xauth_inI1),
	  /* RFC ????: */
	  .hash_type = V1_HASH_1, },

	{ STATE_IKEv1_ROOF, STATE_IKEv1_ROOF,
	  LEMPTY,
	  LEMPTY, LEMPTY,
	  EVENT_NULL, NULL,
	  .hash_type = V1_HASH_NONE, },

#undef FM
#undef P
};

void init_ikev1_states(struct logger *logger)
{
	ldbg(logger, "checking IKEv1 state table");

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
	for (enum state_kind kind = STATE_IKEv1_FLOOR; kind < STATE_IKEv1_ROOF; kind++) {
		/* fill in using static struct */
		const struct finite_state *fs = v1_states[kind - STATE_IKEv1_FLOOR];
		passert(fs->kind == kind);
		passert(finite_states[kind] == NULL);
		finite_states[kind] = fs;
	}

	/*
	 * Go through the state transition table filling in details
	 * and checking for inconsistencies.
	 */
	for (const struct state_v1_microcode *t = v1_state_microcode_table;
	     t->state < STATE_IKEv1_ROOF; t++) {

		passert(t->state >= STATE_IKEv1_FLOOR);
		passert(t->state < STATE_IKEv1_ROOF);

		struct finite_state *from = v1_states[t->state - STATE_IKEv1_FLOOR];
		passert(from->kind == t->state);
		passert(from->ike_version == IKEv1);

		/*
		 * Deal with next_state == STATE_UNDEFINED.
		 *
		 * XXX: STATE_UNDEFINED is used when a state
		 * transitions back to the same state; such
		 * transitions should instead explicitly specify that
		 * same state.
		 */
		enum state_kind next_state = (t->next_state == STATE_UNDEFINED ?
					      t->state : t->next_state);
		passert(STATE_IKEv1_FLOOR <= next_state &&
			next_state < STATE_IKEv1_ROOF);
		const struct finite_state *to = finite_states[next_state];
		passert(to != NULL);

		if (LDBGP(DBG_BASE, logger)) {
			if (from->v1.nr_transitions == 0) {
				LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
					jam_string(buf, "  ");
					jam_finite_state(buf, from);
					jam_string(buf, ":");
				}
			}
			name_buf eb;
			LDBG_log(logger, "    -> %s %s (%s)", to->short_name,
				 str_enum_short(&event_type_names, t->timeout_event, &eb),
				 t->message);
		}

		/*
		 * Point .fs_v1.transitions at to the first entry in
		 * v1_state_microcode_table for that state.  All other
		 * transitions for that state should follow
		 * immediately after (or to put it another way, the
		 * previous transition's state should be the same as
		 * this).
		 */
		if (from->v1.transitions == NULL) {
			from->v1.transitions = t;
		} else {
			passert(t[-1].state == t->state);
		}
		from->v1.nr_transitions++;

		if (t->message == NULL) {
			llog_pexpect(logger, HERE, "transition %s -> %s missing .message",
				     from->short_name, to->short_name);
		}

		/*
		 * Copy (actually merge) the flags that apply to the
		 * state; and not the state transition.
		 *
		 * The original code used something like state
		 * .microcode .flags after the state transition had
		 * completed.  I.e., use the flags from a
		 * not-yet-taken potential future state transition and
		 * not the previous one.
		 *
		 * This is just trying to extract them and
		 * check they are consistent.
		 *
		 * XXX: this is confusing
		 *
		 * Should fs_flags and SMF_RETRANSMIT_ON_DUPLICATE
		 * should be replaced by SMF_RESPONDING in the
		 * transition flags?
		 *
		 * Or is this more like .fs_timeout_event which is
		 * always true of a state?
		 */
		if ((t->flags & from->v1.flags) != from->v1.flags) {
			ldbgf(DBG_BASE, logger, "transition %s -> %s (%s) missing flags 0x"PRI_LSET,
			      from->short_name, to->short_name,
			      t->message, from->v1.flags);
		}
		from->v1.flags |= t->flags & SMF_RETRANSMIT_ON_DUPLICATE;

		if (!(t->flags & SMF_FIRST_ENCRYPTED_INPUT) &&
		    (t->flags & SMF_INPUT_ENCRYPTED) &&
		    t->processor != unexpected) {
			/*
			 * The first encrypted message carries
			 * authentication information so isn't
			 * applicable.  Other encrypted messages
			 * require integrity via the HASH payload.
			 */
			if (!(t->req_payloads & LELEM(ISAKMP_NEXT_HASH))) {
				llog_pexpect(logger, HERE,
					     "transition %s -> %s (%s) missing HASH payload",
					     from->short_name, to->short_name,
					     t->message);
			}
			if (t->hash_type == V1_HASH_NONE) {
				llog_pexpect(logger, HERE,
					     "transition %s -> %s (%s) missing HASH protection",
					     from->short_name, to->short_name,
					     t->message);
			}
		}
	}
}
