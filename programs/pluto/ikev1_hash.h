/* IKEv1 HASH payload weirdness, for Libreswan
 *
 * Copyright (C) 2019  Andrew Cagney
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

#ifndef IKEV1_HASH_H
#define IKEV1_HASH_H

#include <stdint.h>
#include <stdbool.h>

#include "chunk.h"
#include "defs.h"	/* for msgid_t */
#include "impair.h"

struct state;
struct msg_digest;

/*
 * RFC 2409: 5.5 Phase 2 - Quick Mode
 *
 * HASH(1) = prf(SKEYID_a, M-ID | SA | Ni [ | KE ] [ | IDci | IDcr )
 * aka HASH(1) = prf(SKEYID_a, M-ID | payload )
 *
 * HASH(2) = prf(SKEYID_a, M-ID | Ni_b | SA | Nr [ | KE ] [ | IDci | IDcr )
 * aka HASH(2) = prf(SKEYID_a, M-ID | Ni_b | payload )
 *
 * HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)
 */

enum v1_hash_type {
	V1_HASH_NONE,
	V1_HASH_1 = 1,
	V1_HASH_2 = 2,
	V1_HASH_3 = 3,
};

/*
 * Emit (saving where it is) and fixup (a previously saved) v1 HASH
 * payload.
 */

struct v1_hash_fixup {
	chunk_t hash_data;
	const uint8_t *body;
	const char *what;
	enum impair_emit impair;
	enum v1_hash_type hash_type;
	struct logger *logger;
};

bool emit_v1_HASH(enum v1_hash_type type, const char *what,
		  enum impair_v1_exchange exchange, struct state *st,
		  struct v1_hash_fixup *hash_fixup, struct pbs_out *out_pbs);

void fixup_v1_HASH(struct state *st, const struct v1_hash_fixup *data,
		   msgid_t msgid, const uint8_t *roof);

/*
 * Based on TYPE, check the IKEv1 HASH payload.
 *
 * TYPE includes no-hash, for instance on the first message when there
 * isn't yet a state.
 *
 * IKEv1 generates a new hash for each exchange.  Hence ST is either
 * an IKE SA or Child SA as the Quick Mode exchange (creating a Child
 * SA), it's the Child SA that contains the exchanges hash.
 */

bool check_v1_HASH(enum v1_hash_type type, const char *what,
		   struct state *st_or_null, struct msg_digest *md);

#endif
