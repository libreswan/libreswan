/* IKEv2 state machine, for libreswan
 *
 * Copyright (C) 2019 Andrew Cagney
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

#ifndef IKEV2_STATE_H
#define IKEV2_STATE_H

struct ikev2_expected_payloads;
struct payload_summary;

extern struct finite_state v2_states[STATE_IKEv2_ROOF - STATE_IKEv2_FLOOR];

enum smf2_flags {
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

	/*
	 * Should whack be released?
	 */
	SMF2_RELEASE_WHACK = LELEM(10),
};

struct ikev2_payload_errors ikev2_verify_payloads(struct msg_digest *md,
						  const struct payload_summary *summary,
						  const struct ikev2_expected_payloads *payloads);

const struct state_v2_microcode *find_v2_state_transition(struct logger *logger,
							  const struct finite_state *state,
							  struct msg_digest *md);

void log_v2_payload_errors(struct logger *logger, struct msg_digest *md,
			   const struct ikev2_payload_errors *errors);

#endif
