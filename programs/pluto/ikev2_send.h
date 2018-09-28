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

pb_stream open_v2_message(pb_stream *reply,
			  struct ike_sa *ike, struct msg_digest *md,
			  enum isakmp_xchg_types exchange_type);

typedef struct v2sk_payload {
	struct ike_sa *ike;
	pb_stream pbs;
	/* pointers into payload buffer (not .payload) */
	uint8_t *iv;
	uint8_t *cleartext; /* where cleartext starts */
	uint8_t *integrity;
} v2sk_payload_t;

v2sk_payload_t open_v2sk_payload(pb_stream *container,
				 struct ike_sa *st);
bool close_v2sk_payload(v2sk_payload_t *sk);

stf_status encrypt_v2sk_payload(v2sk_payload_t *sk);

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

/*
 * XXX: should be local to ikev2_send.c
 */
uint8_t build_ikev2_version(void);
uint8_t build_ikev2_critical(bool impair);
bool emit_wire_iv(const struct state *st, pb_stream *pbs);
uint8_t *ikev2_authloc(const struct state *st,
		       pb_stream *e_pbs);
stf_status ikev2_encrypt_msg(struct ike_sa *ike,
			     uint8_t *auth_start,
			     uint8_t *wire_iv_start,
			     uint8_t *enc_start,
			     uint8_t *integ_start);

#endif
