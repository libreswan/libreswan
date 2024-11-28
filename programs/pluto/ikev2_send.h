/* IKEv2 send packet routines, for Libreswan
 *
 * Copyright (C) 2018-202- Andrew Cagney
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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
 */

#ifndef IKEV2_SEND_H
#define IKEV2_SEND_H

#include "chunk.h"

#include "connections.h"

struct msg_digest;
struct dh_desc;
struct ike_sa;
struct child_sa;
enum payload_security;
struct impair_unsigned;
struct v2_payload_errors;

struct v2_incoming_fragment {
	chunk_t text;		/* cipher or plain - decrypt in place */
	shunk_t plain;		/* read-only; points into decrypted plain text */
	size_t iv_offset;	/* into text */
};

struct v2_incoming_fragments {
	unsigned total;
	unsigned count;
	enum ikev2_exchange xchg;
	/*
	 * A fragment.
	 *
	 * - initially it contains the first fragment to arrive (which
	 *   may not be fragment 1)
	 *
	 *   on the responder, should there be a problem during
	 *   SKEYSEED then the saved message is used to construct the
	 *   headers for the un-protected error response
	 *
	 * - when fragment 1 arrives, it replaces any previously saved
         *   fragment
	 *
	 *   once all fragments have arrived, fragment 1 with its
	 *   protected, but not encrypted, payloads, is used to
	 *   reconstitute the message
	 *
	 * Additionally:
	 *
	 * - on the responder, while waiting for SKEYSEED to be
         *   calculated, it can contain the first secured message
         *   (instead of a fragment)
	 *
	 * Note: until all fragments have arrived and been decrypted,
	 * the saved fragment should not be trusted.
	 */
	struct msg_digest *md;
	/*
	 * Next-Payload from first fragment.
	 */
	int first_np;
	/*
	 * For simplicity, index by fragment number which is 1-based;
	 * leaving element 0 empty.
	 */
	struct v2_incoming_fragment frags[MAX_IKE_FRAGMENTS + 1];
};

struct v2_outgoing_fragment {
	struct v2_outgoing_fragment *next;
	/* hunk like */
	size_t len;
	uint8_t ptr[]; /* can be bigger */
};

/*
 * Should the payload be encrypted/protected (don't confuse this with
 * authenticated)?
 */

bool send_recorded_v2_message(struct ike_sa *ike, const char *where,
			      struct v2_outgoing_fragment *frags);

struct emit_v2_response_context;
typedef bool emit_v2_response_fn(struct pbs_out *pbs, struct emit_v2_response_context *context);

bool send_v2_response_from_md(struct msg_digest *md, const char *what,
			      emit_v2_response_fn *emit_v2_response,
			      struct emit_v2_response_context *context);

void record_v2_outgoing_fragment(struct pbs_out *pbs,
				 const char *what,
				 struct v2_outgoing_fragment **frags);
void record_v2_message(struct pbs_out *msg,
		       const char *what,
		       struct v2_outgoing_fragment **outgoing_fragments);

void free_v2_message_queues(struct state *st);
void free_v2_incoming_fragments(struct v2_incoming_fragments **frags);
void free_v2_outgoing_fragments(struct v2_outgoing_fragment **frags);

/*
 * Emit an IKEv2 payload.
 *
 * Like the out_*() primitives, these have struct pbs_out for emission
 * as the last parameter (or second last if the last one is the struct
 * pbs_out for the sub-payload).
 */

bool emit_v2UNKNOWN(const char *victim,
		    enum ikev2_exchange exchange_type,
		    const struct impair_unsigned *impair,
		    struct pbs_out *outs);

#endif
