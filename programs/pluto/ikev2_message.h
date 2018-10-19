/* IKEv2 message routines, for Libreswan
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

#ifndef IKEV2_MESSAGE_H
#define IKEV2_MESSAGE_H

#include "chunk.h"

#include "packet.h"		/* for pb_stream */

struct msg_digest;
struct oakley_group_desc;
struct ike_sa;
struct state;

pb_stream open_v2_message(pb_stream *reply,
			  struct ike_sa *ike, struct msg_digest *md,
			  enum isakmp_xchg_types exchange_type);

typedef struct {
	struct ike_sa *ike;
	pb_stream pbs; /* within SK */
	/* pointers into SK header+contents */
	chunk_t payload; /* header+iv+cleartext+padding+integrity */
	/* chunk_t header; */
	chunk_t iv;
	chunk_t cleartext;
	/* chunk_t padding; */
	chunk_t integrity;
} v2SK_payload_t;

v2SK_payload_t open_v2SK_payload(pb_stream *container,
				 struct ike_sa *st);
bool close_v2SK_payload(v2SK_payload_t *sk);

stf_status encrypt_v2SK_payload(v2SK_payload_t *sk);

stf_status record_outbound_v2SK_msg(struct state *msg_sa,
				    struct msg_digest *md,
				    pb_stream *msg,
				    v2SK_payload_t *sk,
				    const char *what);

uint8_t build_ikev2_critical(bool impair);

bool ikev2_decrypt_msg(struct state *st, struct msg_digest *md);

#endif
