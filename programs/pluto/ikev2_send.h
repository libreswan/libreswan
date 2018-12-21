/* IKEv2 send packet routines, for Libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
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

bool record_and_send_v2_ike_msg(struct state *st, pb_stream *pbs,
				const char *what);

bool send_recorded_v2_ike_msg(struct state *st, const char *where);

void send_v2N_spi_response_from_state(struct ike_sa *st,
				      struct msg_digest *md,
				      enum ikev2_sec_proto_id protoid,
				      ipsec_spi_t *spi,
				      v2_notification_t type,
				      const chunk_t *data);
void send_v2N_response_from_state(struct ike_sa *st,
				  struct msg_digest *md,
				  v2_notification_t type,
				  const chunk_t *data);
void send_v2N_response_from_md(struct msg_digest *md,
			       v2_notification_t type,
			       const chunk_t *data);

void send_v2_delete(struct state *st);

extern stf_status send_v2_informational_request(const char *name,
						struct state *st,
						struct ike_sa *ike,
						stf_status (*payloads)(struct state *st,
								       pb_stream *pbs));

/*
 * Emit an IKEv2 payload.
 *
 * Like the out_*() primitives, these have the pb_stream as the last
 * parameter.
 */

bool emit_v2UNKNOWN(const char *victim, pb_stream *outs);

bool emit_v2N(enum ikev2_sec_proto_id protoid,
	      const ipsec_spi_t *spi,
	      v2_notification_t ntype,
	      const chunk_t *ndata,
	      pb_stream *outs);

bool emit_v2Ntd(v2_notification_t ntype,
		const chunk_t *ndata,
		pb_stream *outs);

bool emit_v2Nt(v2_notification_t ntype,
	       pb_stream *outs);

bool emit_v2V(const char *string, pb_stream *outs);

bool emit_v2N_signature_hash_algorithms(lset_t sighash_policy,
					pb_stream *outs);

#endif
