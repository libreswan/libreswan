/* IKEv1 send, for libreswan
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

#ifndef IKEV1_SEND_H
#define IKEV1_SEND_H

#include "shunk.h"

struct state;

struct v1_ike_rfrag {
	struct v1_ike_rfrag *next;
	struct msg_digest *md;
	int index;
	int last;
	shunk_t data;
};

void record_outbound_v1_ike_msg(struct state *st, struct pbs_out *pbs, const char *what);
bool record_and_send_v1_ike_msg(struct state *st, struct pbs_out *pbs,
				const char *what);

bool resend_recorded_v1_ike_msg(struct state *st, const char *where);

void free_v1_message_queues(struct state *st);

extern monotime_t last_v1N_PAYLOAD_MALFORMED;

extern void send_v1_notification_from_state(struct state *st,
					    enum state_kind from_state,
					    v1_notification_t type);
extern void send_v1_notification_from_md(struct msg_digest *md,
					 v1_notification_t type);
#endif
