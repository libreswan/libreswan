/* IKEv2 Message ID tracking, for libreswan
 *
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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
 *
 */

#ifndef IKEV2_MSGID_H
#define IKEV2_MSGID_H

#include <stdint.h>		/* for intmax_t */

struct state;
struct ike_sa;
struct msg_digest;
enum message_role;

/*
 * The type INTMAX_T is chosen so that SEND and RECV are sufficiently
 * big to hold both MSGID_T (unmodified) and -1 (the initial value).
 * As a bonus intmax_t can easily be printed using %jd.
 *
 * An additional bonus is that the old v2_INVALID_MSGID ((uint32_t)-1)
 * will not match -1 - cross checking code should only compare valid
 * MSGIDs.
 */

struct v2_window {
	intmax_t sent;
	intmax_t recv;
};

struct v2_msgids {
	/* IKE and CHILD */
	intmax_t current_request;
	/* IKE only */
	struct v2_window initiator;
	struct v2_window responder;
};

void v2_msgid_init(struct ike_sa *ike);
void v2_msgid_update_recv(struct ike_sa *ike, struct state *receiver,
			  struct msg_digest *md);
void v2_msgid_update_sent(struct ike_sa *ike, struct state *sender,
			  struct msg_digest *md, enum message_role sending);
bool v2_msgid_ok(struct ike_sa *ike, enum message_role incomming, msgid_t msgid);

void schedule_next_send(struct state *st);
stf_status add_st_to_ike_sa_send_list(struct state *st, struct ike_sa *ike);

#endif
