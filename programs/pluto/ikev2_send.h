/* IKEv2 send packet routines, for Libreswan
 *
 * Copyright (C) 2018-2019 Andrew Cagney
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
struct oakley_group_desc;
struct ike_sa;

bool send_recorded_v2_ike_msg(struct state *st, const char *where);

void send_v2N_spi_response_from_state(struct ike_sa *st,
				      struct msg_digest *md,
				      enum ikev2_sec_proto_id protoid,
				      ipsec_spi_t *spi,
				      v2_notification_t type,
				      const chunk_t *data /* optional */);

void send_v2N_response_from_state(struct ike_sa *st,
				  struct msg_digest *md,
				  v2_notification_t type,
				  const chunk_t *data /* optional */);

void send_v2N_response_from_md(struct msg_digest *md,
			       v2_notification_t type,
			       const chunk_t *data);

void record_v2_delete(struct state *st);

typedef bool payload_master_t(struct state *st, pb_stream *pbs);

extern stf_status record_v2_informational_request(const char *name,
						  struct ike_sa *owner,
						  struct state *sender,
						  payload_master_t *payloads);

/*
 * Emit an IKEv2 payload.
 *
 * Like the out_*() primitives, these have the pb_stream for emission as
 * the last parameter (or second last if the last one is the pb_stream
 * for the sub-payload).
 */

bool emit_v2UNKNOWN(const char *victim, pb_stream *outs);

/* emit a v2 Notification payload, with optional SA and optional sub-payload */
bool emit_v2Nsa_pl(v2_notification_t ntype,
		enum ikev2_sec_proto_id protoid,
		const ipsec_spi_t *spi, /* optional */
		pb_stream *outs,
		pb_stream *payload_pbs /* optional */);

/* emit a v2 Notification payload, with optional sub-payload */
bool emit_v2Npl(v2_notification_t ntype,
		pb_stream *outs,
		pb_stream *payload_pbs /* optional */);

/* emit a v2 Notification payload, with optional chunk as sub-payload */
bool emit_v2Nchunk(v2_notification_t ntype,
		const chunk_t *ndata, /* optional */
		pb_stream *outs);

/* output a v2 simple Notification payload */
bool emit_v2N(v2_notification_t ntype,
	       pb_stream *outs);

bool emit_v2V(const char *string, pb_stream *outs);

bool emit_v2N_signature_hash_algorithms(lset_t sighash_policy,
					pb_stream *outs);

#endif
