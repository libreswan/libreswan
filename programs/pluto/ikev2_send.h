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


void send_v2_notification_from_state(struct state *st, struct msg_digest *md,
				     v2_notification_t type,
				     chunk_t *data);
void send_v2_notification_from_md(struct msg_digest *md,
				  v2_notification_t type,
				  chunk_t *data);
void send_v2_notification_invalid_ke(struct msg_digest *md,
				     const struct oakley_group_desc *group);
void send_v2_delete(struct state *st);

extern stf_status send_v2_informational_request(const char *name,
						struct state *st,
						struct ike_sa *ike,
						stf_status (*payloads)(struct state *st,
								       pb_stream *pbs));

/*
 * XXX: Where does the name ship_v2*() come from?  Is for when a
 * function writes an entire payload into the PBS?  emit_v2*() might
 * be more meaningful?
 */
bool ship_v2UNKNOWN(pb_stream *outs, const char *victim);

bool ship_v2N(enum next_payload_types_ikev2 np,
	      uint8_t critical,
	      enum ikev2_sec_proto_id protoid,
	      const chunk_t *spi,
	      v2_notification_t type,
	      const chunk_t *n_data,
	      pb_stream *rbody);

bool ship_v2Nsp(enum next_payload_types_ikev2 np,
	      v2_notification_t type,
	      const chunk_t *n_data,
	      pb_stream *rbody);

bool ship_v2Ns(enum next_payload_types_ikev2 np,
	      v2_notification_t type,
	      pb_stream *rbody);

bool ship_v2V(pb_stream *outs, enum next_payload_types_ikev2 np,
	      const char *string);

#endif
