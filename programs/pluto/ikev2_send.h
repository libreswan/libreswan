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

#include "packet.h"

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

/* XXX: should be local to ikev2_send.c? */
bool ship_v2N(enum next_payload_types_ikev2 np,
	      u_int8_t critical,
	      u_int8_t protoid,
	      const chunk_t *spi,
	      v2_notification_t type,
	      const chunk_t *n_data,
	      pb_stream *rbody);
int build_ikev2_version(void);

#endif
