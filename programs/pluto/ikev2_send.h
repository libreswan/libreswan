/* IKEv1 send, for libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
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
 */

#ifndef IKEV2_SEND_H
#define IKEV2_SEND_H

#include "chunk.h"

#include "packet.h"		/* for pb_stream */

struct msg_digest;
struct oakley_group_desc;

bool record_and_send_v2_ike_msg(struct state *st, pb_stream *pbs,
				const char *what);

bool send_recorded_v2_ike_msg(struct state *st, const char *where);


void send_v2_notification_from_state(struct state *st,
				     v2_notification_t type,
				     chunk_t *data);
void send_v2_notification_from_md(struct msg_digest *md,
				  v2_notification_t type,
				  chunk_t *data);
void send_v2_notification_invalid_ke(struct msg_digest *md,
				     const struct oakley_group_desc *group);

/* parameters in the same order has the packet */
pb_stream open_v2_message(pb_stream *reply,
			  uint8_t *icookie, uint8_t *rcookie, /* aka SPI */
			  enum next_payload_types_ikev2 next_payload,
			  enum isakmp_xchg_types exchange_type,
			  lset_t flags, int message_id);

typedef struct v2sk_stream {
	struct ike_sa *ike;
	pb_stream payload;
	/* pointers into payload */
	uint8_t *iv;
	uint8_t *cleartext; /* where cleartext starts */
	uint8_t *integrity;
	const char *name;
} v2sk_stream_t;

v2sk_stream_t ikev2_open_encrypted_payload(pb_stream *container,
					   enum next_payload_types_ikev2 np,
					   struct ike_sa *st,
					   const char *name);

bool ikev2_close_encrypted_payload(v2sk_stream_t *sk);

stf_status ikev2_encrypt_payload(v2sk_stream_t *sk);

/*
 * XXX: Is the name ship_v2*() for where a function writes an entire
 * payload into the PBS.
 */
bool ship_v2N(enum next_payload_types_ikev2 np,
	      u_int8_t critical,
	      enum ikev2_sec_proto_id protoid,
	      const chunk_t *spi,
	      v2_notification_t type,
	      const chunk_t *n_data,
	      pb_stream *rbody);
bool ship_v2V(pb_stream *outs, enum next_payload_types_ikev2 np,
	      const char *string);

/* XXX: should be local to ikev2_send.c? */
int build_ikev2_version(void);

#endif
