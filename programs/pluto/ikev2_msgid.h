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

#include "monotime.h"

struct state;
struct ike_sa;
struct msg_digest;
struct state_v2_microcode;
enum message_role;

/*
 * The type INTMAX_T is chosen so that SEND and RECV are sufficiently
 * big to hold both MSGID_T (unmodified) and -1 (the initial value).
 * As a bonus intmax_t can easily be printed using %jd.
 *
 * An additional bonus is that the old v2_INVALID_MSGID ((uint32_t)-1)
 * will not match -1 - cross checking code should only compare valid
 * MSGIDs.
 *
 * While .PENDING - the list of states waiting for an open window - is
 * probably only used by the initiator code, store it in the window so
 * that struct contains everything.
 */

typedef stf_status v2_msgid_pending_cb(struct ike_sa *ike,
				       struct state *st,
				       struct msg_digest *md);

struct v2_msgid_window {
	monotime_t last_contact;  /* received a message */
	intmax_t sent;
	intmax_t recv;
	struct v2_msgid_pending *pending;
};

struct v2_msgid_windows {
	struct v2_msgid_window initiator;
	struct v2_msgid_window responder;
};

/*
 * The Message ID for the state's in-progress exchanges.  If no
 * exchange is in progress then it's value is -1.
 *
 * The INITIATOR Message ID is valid from the time the request is sent
 * (earlier?) through to when the response is received.  Lookups then
 * use this to route the response to the state waiting for it.
 *
 * The RESPONDER Message ID is valid for the period that the state is
 * processing the request.
 *
 * XXX: should the also be {start,cancel}_initiator()?
 */

struct v2_msgid_wip {
	intmax_t initiator;
	intmax_t responder;
};

void v2_msgid_init_ike(struct ike_sa *ike);
void v2_msgid_init_child(struct ike_sa *ike, struct child_sa *child);
void v2_msgid_free(struct state *st);

void v2_msgid_start_responder(struct ike_sa *ike, struct state *responder,
			      const struct msg_digest *md);

void v2_msgid_switch_responder_to_child(struct ike_sa *ike, struct child_sa *child,
					struct msg_digest *md, where_t where);
void v2_msgid_switch_responder_from_aborted_child(struct ike_sa *ike, struct child_sa **child,
						  struct msg_digest *md, where_t where);

void v2_msgid_switch_initiator(struct ike_sa *ike, struct child_sa *child,
			       const struct msg_digest *md);

void v2_msgid_cancel_responder(struct ike_sa *ike, struct state *responder,
			       const struct msg_digest *md);

bool v2_msgid_request_outstanding(struct ike_sa *ike);
bool v2_msgid_request_pending(struct ike_sa *ike);

/*
 * Processing has finished - recv's accepted or sent is on its way -
 * update window.{recv,sent} and wip.{initiator,responder}.
 *
 * XXX: Should these interfaces be revamped so that they are more like
 * the above?
 *
 * In complete_v2_state_transition(), update_recv() and update_send
 * are first called so that all windows are up-to-date, and then
 * schedule_next_initiator() is called to schedule any waiting
 * initiators.  It could probably be simpler, but probably only after
 * record 'n' send has been eliminated.
 */
void v2_msgid_update_recv(struct ike_sa *ike, struct state *receiver,
			  struct msg_digest *md);
void v2_msgid_update_sent(struct ike_sa *ike, struct state *sender,
			  struct msg_digest *md, enum message_role sending);

/*
 * Handle multiple initiators trying to send simultaneously.
 *
 * XXX: Suspect this code is broken.
 *
 * For this to work all initiators need to route their requests
 * through queue_initiator(), and due to record 'n' send at least,
 * this isn't true.
 *
 * Complicating this is how each individual initiate code path needs
 * to be modified so that delays calling queue_initiator() until it is
 * ready to actually send (and a message id can be assigned).  Would
 * it be simpler if there was a gate keeper that assigned request
 * message id up front, but only when one was available?
 */
void v2_msgid_queue_initiator(struct ike_sa *ike, struct state *st,
			      enum isakmp_xchg_types ix,
			      const struct state_v2_microcode *transition,
			      v2_msgid_pending_cb *callback);
void v2_msgid_schedule_next_initiator(struct ike_sa *ike);

void dbg_v2_msgid(struct ike_sa *ike, struct state *st, const char *msg, ...) PRINTF_LIKE(3);
void fail_v2_msgid(where_t where, struct ike_sa *ike, struct state *st,
		   const char *fmt, ...) PRINTF_LIKE(4);
#define FAIL_V2_MSGID(IKE, ST, FMT, ...) fail_v2_msgid(HERE, IKE, ST, FMT,##__VA_ARGS__)

#endif
