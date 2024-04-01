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
struct v2_state_transition;
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

struct v2_msgid_window {
	monotime_t last_sent;  /* sent a message */
	monotime_t last_recv;  /* received a message */
	/*
	 * .sent: last outbound message sent
	 * .recv: last inbound message processed
	 * .wip: message being processed; or -1
	 *
	 * Initiator:
	 *
	 * Idle:       .sent:N   .recv:N   .wip:-1   .state=_IRn?
	 * Initiating: .sent:N   .recv:N   .wip:N+1  .state=_IRn?
	 * Initiated:  .sent:N+1 .recv:N   .wip:-1   .state=_In+1
	 *
	 * Responder:
	 *
	 * Idle:       .sent:N   .recv:N   .wip:-1   .state=_Rn?
	 * Responding: .sent:N   .recv:N   .wip:N+1  .state=_Rn?
	 * Responded:  .sent:N+1 .recv:N+1 .wip:N+1  .state=_Rn+1
	 *
	 * Initiator:
	 *
	 * Response:   .sent:N+1 .recv:N   .wip:N+1  .state=_In+1
	 * (after packet has been assembled)
	 * Idle    :   .sent:N+1 .recv:N+1 .wip:-1   .state=_IRn+1
	 *
	 * XXX: should .wip be set _while_ protected and verified
	 * fragments are being accumulated.
	 *
	 * When retransmitting a response, the RFC says to also check
	 * that the fragments match.  Hence .recv_frags which
	 * out-lives the .incomming_fragments field.
	 */
	intmax_t sent;		/* starts with -1 */
	intmax_t recv;		/* starts with -1 */
	unsigned recv_frags;	/* number of fragments in last .recv */
	intmax_t wip;		/* >=0 when busy */
	/*
	 * Fragments:
	 *
	 * Incoming fragments are accumulated and then re-assembled
	 * into a single message.  Once assembled the structure is
	 * deleted.  Note that this all happens before .recv and
	 * .recv_frags (used to detect the need to retransmit a
	 * response) are set.
	 *
	 * Outgoing fragments are used when retransmitting.  A todo is
	 * to delete them after a few minutes.
	 */
	struct v2_incoming_fragments *incoming_fragments;
	struct v2_outgoing_fragment *outgoing_fragments;
	/*
	 * The SA being worked on by the exchange.
	 *
	 * For instance, the larval Child SA being established by an
	 * IKE_AUTH; larval IKE or Child SA being established or
	 * rekeyd by a CREATE_CHILD_SA exchange.
	 */
	struct child_sa *wip_sa;
};

struct v2_msgid_windows {
	monotime_t last_sent;  /* sent a message */
	monotime_t last_recv;  /* received a message */
	struct v2_msgid_window initiator;
	struct v2_msgid_window responder;
	struct v2_msgid_pending *pending_requests;
};

void v2_msgid_init_ike(struct ike_sa *ike);
void v2_msgid_free(struct state *st);

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

void v2_msgid_start(struct ike_sa *ike, const struct msg_digest *md);
void v2_msgid_cancel(struct ike_sa *ike, const struct msg_digest *md);
void v2_msgid_finish(struct ike_sa *ike, const struct msg_digest *md);

/*
 * This is a hack for code that forces sending an additional request
 * even though the request window is full.
 */

void v2_msgid_start_record_n_send(struct ike_sa *ike);

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

void v2_msgid_queue_initiator(struct ike_sa *ike, struct child_sa *child/*optional*/,
			      const struct v2_state_transition *transition);

void v2_msgid_migrate_queue(struct ike_sa *from, struct child_sa *to);

void v2_msgid_schedule_next_initiator(struct ike_sa *ike);

void dbg_v2_msgid(struct ike_sa *ike, const char *msg, ...) PRINTF_LIKE(2);
void fail_v2_msgid_where(where_t where, struct ike_sa *ike, const char *fmt, ...) PRINTF_LIKE(3);
#define pexpect_v2_msgid(IKE, ROLE, COND)				\
	({								\
		bool cond_ = COND; /* eval once, no paren */		\
		if (!cond_) {						\
		enum_buf eb;						\
			fail_v2_msgid(IKE, "%s %s",			\
				      str_enum_short(&message_role_names, ROLE, &eb), \
				      #COND);				\
		}							\
	})
#define fail_v2_msgid(IKE, FMT, ...) fail_v2_msgid_where(HERE, IKE, FMT,##__VA_ARGS__)

struct v2_msgid_window *v2_msgid_window(struct ike_sa *ike, enum message_role message_role);

#endif
