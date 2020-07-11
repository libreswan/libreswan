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

#include "packet.h"		/* for pb_stream */

struct msg_digest;
struct dh_desc;
struct ike_sa;
struct v2_outgoing_fragment;
struct v2_incomming_fragments;

/*
 * Should the payload be encrypted/protected (don't confuse this with
 * authenticated)?
 */

enum payload_security {
	ENCRYPTED_PAYLOAD = 1,
	UNENCRYPTED_PAYLOAD,
};

void record_v2N_response(struct logger *logger,
			 struct ike_sa *ike,
			 struct msg_digest *md,
			 v2_notification_t type,
			 const chunk_t *data /* optional */,
			 enum payload_security security);

void record_v2N_spi_response(struct logger *logger,
			     struct ike_sa *st,
			     struct msg_digest *md,
			     enum ikev2_sec_proto_id protoid,
			     ipsec_spi_t *spi,
			     v2_notification_t type,
			     const chunk_t *data /* optional */,
			     enum payload_security security);

bool send_recorded_v2_message(struct ike_sa *ike, const char *where,
			      enum message_role role);

void send_v2N_response_from_md(struct msg_digest *md,
			       v2_notification_t type,
			       const chunk_t *data);

typedef bool payload_emitter_fn(struct state *st, pb_stream *pbs);

extern stf_status record_v2_informational_request(const char *name,
						  struct ike_sa *owner,
						  struct state *sender,
						  payload_emitter_fn *emit_payloads);
void record_v2_outgoing_fragment(struct pbs_out *pbs,
				 const char *what,
				 struct v2_outgoing_fragment **frags);
void record_v2_message(struct ike_sa *ike,
		       struct pbs_out *msg,
		       const char *what,
		       enum message_role message);

void free_v2_message_queues(struct state *st);
void free_v2_incomming_fragments(struct v2_incomming_fragments **frags);
void free_v2_outgoing_fragments(struct v2_outgoing_fragment **frags);

/*
 * Emit an IKEv2 payload.
 *
 * Like the out_*() primitives, these have the pb_stream for emission as
 * the last parameter (or second last if the last one is the pb_stream
 * for the sub-payload).
 */

bool emit_v2UNKNOWN(const char *victim, enum isakmp_xchg_types exchange_type,
		    struct pbs_out *outs);

/* emit a v2 Notification payload, with optional SA and optional sub-payload */
bool emit_v2Nsa_pl(v2_notification_t ntype,
		enum ikev2_sec_proto_id protoid,
		const ipsec_spi_t *spi, /* optional */
		pb_stream *outs,
		pb_stream *payload_pbs /* optional */);

/* emit a v2 Notification payload, with optional sub-payload */
/* i.e., emit header then open a containing payload? */
bool emit_v2Npl(v2_notification_t ntype,
		pb_stream *outs,
		pb_stream *payload_pbs /* optional */);

/* emit a v2 Notification payload, with optional hunk as sub-payload */
bool emit_v2N_bytes(v2_notification_t ntype,
		   const void *bytes, size_t size,
		   pb_stream *outs);
#define emit_v2N_hunk(NTYPE, HUNK, OUTS)	emit_v2N_bytes(NTYPE, (HUNK).ptr, (HUNK).len, OUTS)

/* output a v2 simple Notification payload */
bool emit_v2N(v2_notification_t ntype,
	       pb_stream *outs);

bool emit_v2V(const char *string, pb_stream *outs);

bool emit_v2N_signature_hash_algorithms(lset_t sighash_policy,
					pb_stream *outs);

#endif
