/* IKEv2 Message ID tracking, for libreswan
 *
 * Copyright (C) 2019-2022 Andrew Cagney <cagney@gnu.org>
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

#include "defs.h"
#include "state.h"
#include "demux.h"
#include "connections.h"
#include "ikev2_msgid.h"
#include "log.h"
#include "ikev2.h"		/* for complete_v2_state_transition() */

static callback_cb initiate_next;		/* type assertion */

/*
 * Logging.
 */

static const char *jam_prefix(struct jambuf *buf, struct ike_sa *ike, struct state *wip_sa)
{
	jam(buf, "Message ID: ");
	const char *who;
	if (wip_sa == NULL) {
		who = "lost";
		jam(buf, "CHILD #%lu.#LOST", ike->sa.st_serialno);
	} else if (IS_CHILD_SA(wip_sa)) {
		who = "child";
		jam(buf, "CHILD #%lu.#%lu", ike->sa.st_serialno, wip_sa->st_serialno);
	} else {
		who = "ike";
		jam(buf, "IKE #%lu", ike->sa.st_serialno);
	}
	return who;
}

static void jam_old_new_monotime(struct jambuf *buf, const char *what,
				 monotime_t old, monotime_t new)
{
	monotime_buf mb;
	jam(buf, " %s=%s", what, str_monotime(old, &mb));
	if (monotime_cmp(old, !=, new)) {
		jam(buf, "->%s", str_monotime(new, &mb));
	}
}
static void jam_old_new_intmax(struct jambuf *buf, const char *what,
			       intmax_t old, intmax_t new)
{
	jam(buf, " %s=%jd", what, old);
	if (old != new) {
		jam(buf, "->%jd", new);
	}
}

static void jam_ike_window(struct jambuf *buf, const char *what,
			   const struct v2_msgid_window *old,
			   const struct v2_msgid_window *new)
{
	jam(buf, " ike.%s", what);
	jam_old_new_intmax(buf, ".sent", old->sent, new->sent);
	jam_old_new_intmax(buf, ".recv", old->recv, new->recv);
	jam_old_new_intmax(buf, ".recv_frags", old->recv_frags, new->recv_frags);
	if (old->recv_wip > -1 || new->recv_wip > -1) {
		jam_old_new_intmax(buf, ".recv_wip", old->recv_wip, new->recv_wip);
	}
	jam_old_new_monotime(buf, ".last_sent", old->last_sent, new->last_sent);
	jam_old_new_monotime(buf, ".last_recv", old->last_recv, new->last_recv);
}

static void jam_ike_windows(struct jambuf *buf,
			    const struct v2_msgid_windows *old,
			    const struct v2_msgid_windows *new)
{
	jam_ike_window(buf, "initiator", &old->initiator, &new->initiator);
	jam_ike_window(buf, "responder", &old->responder, &new->responder);
}

static void jam_wip_sa(struct jambuf *buf, const char *who,
		       const struct v2_msgid_wip *old,
		       const struct v2_msgid_wip *new)
{
	jam(buf, " %s.wip.initiator=%jd", who, old->initiator);
	if (old->initiator != new->initiator) {
		jam(buf, "->%jd", new->initiator);
	}
}

static void jam_window_details(struct jambuf *buf,
			       const char *who,
			       struct ike_sa *ike, const struct v2_msgid_windows *old_windows,
			       struct state *wip_sa, const struct v2_msgid_wip *old_wip)
{
	jam_string(buf, " (");

	jam_ike_windows(buf,
			old_windows != NULL ? old_windows : &ike->sa.st_v2_msgid_windows,
			&ike->sa.st_v2_msgid_windows);
	if (wip_sa != NULL) {
		jam_wip_sa(buf, who,
			   old_wip != NULL ? old_wip : &wip_sa->st_v2_msgid_wip,
			   &wip_sa->st_v2_msgid_wip);
	}
}

VPRINTF_LIKE(4)
static void jam_v2_msgid(struct jambuf *buf,
			 struct ike_sa *ike, struct state *wip_sa,
			 const char *fmt, va_list ap)
{
	const char *who = jam_prefix(buf, ike, wip_sa);
	jam(buf, " ");
	jam_va_list(buf, fmt, ap);
	jam_window_details(buf, who, ike, NULL, wip_sa, NULL);
}

void dbg_v2_msgid(struct ike_sa *ike, struct state *wip_sa,
		  const char *fmt, ...)
{
	LSWDBGP(DBG_BASE, buf) {
		va_list ap;
		va_start(ap, fmt);
		jam_v2_msgid(buf, ike, wip_sa, fmt, ap);
		va_end(ap);
	}
}

void fail_v2_msgid(where_t where, struct ike_sa *ike, struct state *wip_sa,
		   const char *fmt, ...)
{
	JAMBUF(buf) {
		va_list ap;
		va_start(ap, fmt);
		jam_v2_msgid(buf, ike, wip_sa, fmt, ap);
		va_end(ap);
		/* XXX: hack - double copy */
		pexpect_fail(ike->sa.st_logger, where, PRI_SHUNK, pri_shunk(jambuf_as_shunk(buf)));
	}
}

/*
 * Dump the MSGIDs along with any changes.
 *
 * Why not just dump the one that changed in the calling function?
 * Because MSGIDs have this strange habit of mysteriously changing
 * between calls.
 */

static void dbg_msgids_update(const char *what,
			      enum message_role message, intmax_t msgid,
			      struct ike_sa *ike, const struct v2_msgid_windows *old_windows,
			      struct state *wip_sa, const struct v2_msgid_wip *old_wip)
{
	if (DBGP(DBG_BASE)) {
		LSWLOG_DEBUG(buf) {
			const char *who = jam_prefix(buf, ike, wip_sa);
			jam(buf, " %s", what);

			switch (message) {
			case MESSAGE_REQUEST: jam(buf, " message request %jd", msgid); break;
			case MESSAGE_RESPONSE: jam(buf, " message response %jd", msgid); break;
			case NO_MESSAGE: break;
			default: bad_case(message);
			}
			jam_window_details(buf, who, ike, old_windows, wip_sa, old_wip);
		}
	}
}

/*
 * Maintain or reset Message IDs.
 *
 * When resetting, need to fudge things up sufficient to fool
 * ikev2_update_msgid_counters(() into thinking that this is a shiny
 * new init request.
 */

static const struct v2_msgid_windows empty_v2_msgid_windows = {
	.initiator = {
		.sent = -1,
		.recv = -1,
		.recv_wip = -1,
	},
	.responder = {
		.sent = -1,
		.recv = -1,
		.recv_wip = -1,
	},
};

static const struct v2_msgid_wip empty_v2_msgid_wip = {
	.initiator = -1,
};

void v2_msgid_init_ike(struct ike_sa *ike)
{
	monotime_t now = mononow();
	struct v2_msgid_windows old_windows = ike->sa.st_v2_msgid_windows;
	ike->sa.st_v2_msgid_windows = empty_v2_msgid_windows;
	ike->sa.st_v2_msgid_windows.last_sent = now;
	ike->sa.st_v2_msgid_windows.last_recv = now;
	ike->sa.st_v2_msgid_windows.responder.last_sent = now;
	ike->sa.st_v2_msgid_windows.responder.last_recv = now;
	ike->sa.st_v2_msgid_windows.initiator.last_sent = now;
	ike->sa.st_v2_msgid_windows.initiator.last_recv = now;
	struct v2_msgid_wip old_wip = ike->sa.st_v2_msgid_wip;
	ike->sa.st_v2_msgid_wip = empty_v2_msgid_wip;
	/* pretend there's a sender */
	dbg_msgids_update("initializing (IKE SA)", NO_MESSAGE, -1,
			  ike, &old_windows,
			  &ike->sa, &old_wip);
}

void v2_msgid_init_child(struct ike_sa *ike, struct child_sa *child)
{
	child->sa.st_v2_msgid_windows = empty_v2_msgid_windows;
	struct v2_msgid_wip old_child = child->sa.st_v2_msgid_wip;
	child->sa.st_v2_msgid_wip = empty_v2_msgid_wip;
	/* pretend there's a sender */
	dbg_msgids_update("initializing (CHILD SA)", NO_MESSAGE, -1,
			  ike, &ike->sa.st_v2_msgid_windows, /* unchanged */
			  &child->sa, &old_child);
}

void v2_msgid_start_responder(struct ike_sa *ike, const struct msg_digest *md)
{
	enum message_role role = v2_msg_role(md);
	if (!pexpect(role == MESSAGE_REQUEST)) {
		return;
	}
	/* extend msgid */
	intmax_t msgid = md->hdr.isa_msgid;

	if (DBGP(DBG_BASE) &&
	    ike->sa.st_v2_msgid_windows.responder.recv_wip != -1) {
		FAIL_V2_MSGID(ike, &ike->sa,
			      "ike->sa.st_v2_msgid_windows.responder.recv_wip == -1 (was %jd)",
			      ike->sa.st_v2_msgid_windows.responder.recv_wip);
	}
	ike->sa.st_v2_msgid_windows.responder.recv_wip = msgid;
	dbg_msgids_update("responder starting", role, msgid,
			  ike, &ike->sa.st_v2_msgid_windows,
			  &ike->sa, &ike->sa.st_v2_msgid_wip);
}

void v2_msgid_cancel_responder(struct ike_sa *ike, const struct msg_digest *md)
{
	enum message_role msg_role = v2_msg_role(md);
	if (!pexpect(msg_role == MESSAGE_REQUEST)) {
		return;
	}
	/* extend msgid */
	intmax_t msgid = md->hdr.isa_msgid;

	/*
	 * If an encrypted message is corrupt things bail before
	 * start_responder() but then STF_IGNORE tries to clear it.
	 */
	if (DBGP(DBG_BASE) &&
	    ike->sa.st_v2_msgid_windows.responder.recv_wip != msgid) {
		FAIL_V2_MSGID(ike, &ike->sa,
			      "ike->sa.st_v2_msgid_windows.responder.recv_wip == %jd(msgid) (was %jd)",
			      msgid, ike->sa.st_v2_msgid_windows.responder.recv_wip);
	}
	ike->sa.st_v2_msgid_windows.responder.recv_wip = -1;
	dbg_msgids_update("cancelling responder", msg_role, msgid,
			  ike, &ike->sa.st_v2_msgid_windows,
			  &ike->sa, &ike->sa.st_v2_msgid_wip);
}

void v2_msgid_update_recv(struct ike_sa *ike, struct state *receiver,
			  struct msg_digest *md)
{
	/* save old value, and add shortcut to new */
	const struct v2_msgid_windows old = ike->sa.st_v2_msgid_windows;
	struct v2_msgid_windows *new = &ike->sa.st_v2_msgid_windows;

	/*
	 * If the receiver is known, save a copy of the old values.
	 *
	 * The receiver (CHILD SA) gets lost (deleted) when processing
	 * an IKE_AUTH response and authentication fails.  When this
	 * happens all that matters is that the IKE SA is updated.
	 */
	const struct v2_msgid_wip old_receiver =
		receiver != NULL ? receiver->st_v2_msgid_wip : empty_v2_msgid_wip;

	enum message_role receiving = v2_msg_role(md);
	intmax_t msgid;
	struct v2_msgid_window *update;
	const char *update_received_story;

	switch (receiving) {
	case MESSAGE_REQUEST:
		update_received_story = "updating responder received";
		/*
		 * Processing request finished.  Scrub it as wip.
		 *
		 * XXX: should this done in update_sent() since it is
		 * when sending the response that things really
		 * finish?
		 */
		msgid = md->hdr.isa_msgid; /* zero-extended */
		if (receiver != NULL) {
			if (DBGP(DBG_BASE) &&
			    receiver->st_v2_msgid_windows.responder.recv_wip != msgid) {
				FAIL_V2_MSGID(ike, receiver,
					      "windows.responder.recv_wip == %jd(msgid) (was %jd)",
					      msgid, receiver->st_v2_msgid_windows.responder.recv_wip);
			}
			receiver->st_v2_msgid_windows.responder.recv_wip = -1;
		} else {
			FAIL_V2_MSGID(ike, NULL, "XXX: message request receiver lost!?!");
		}
		/* update responder's last request received */
		update = &new->responder;
		break;
	case MESSAGE_RESPONSE:
		update_received_story = "updating initiator received";
		/*
		 * Since the response has been successfully processed,
		 * clear WIP.INITIATOR.  This way duplicate
		 * responses get discarded as there is no receiving
		 * state.
		 *
		 * XXX: Unfortunately the record 'n' send code throws
		 * a spanner in the works.  It calls update_send()
		 * before update_recv() breaking the assumption that
		 * WIP.INITIATOR is the old MSGID.
		 */
		msgid = md->hdr.isa_msgid; /* zero-extended */
		if (receiver != NULL) {
			if (old_receiver.initiator > msgid) {
				/*
				 * Hack around record 'n' send calling
				 * update_sent() (setting
				 * WIP.INITIATOR to the next request)
				 * midway through processing.
				 *
				 * Getting rid of record 'n' send will
				 * fix this hack.
				 */
				dbg_v2_msgid(ike, receiver,
					     "XXX: receiver.wip.initiator %jd != receiver.msgid %jd - suspect record'n'called update_sent() before update_recv()",
					     old_receiver.initiator, msgid);
			} else {
				if (DBGP(DBG_BASE) && old_receiver.initiator != msgid) {
					FAIL_V2_MSGID(ike, receiver,
						      "receiver.wip.initiator == %jd(msgid) (was %jd)",
						      msgid, old_receiver.initiator);
				}
				receiver->st_v2_msgid_wip.initiator = -1;
			}
			/* this is what matters */
			pexpect(receiver->st_v2_msgid_wip.initiator != msgid);
			/*
			 * clear the retransmits for the old message
			 *
			 * XXX: Because the IKE_AUTH initiator
			 * switches states from IKE->CHILD part way
			 * through, this code can end up clearing the
			 * child's retransmits when what is needed is
			 * to clear the IKE SA's retransmits.
			 */
			if (ike->sa.st_retransmit_event != NULL) {
				dbg_v2_msgid(ike, receiver,
					     "clearing EVENT_RETRANSMIT as response received");
				clear_retransmits(&ike->sa);
			} else {
				dbg_v2_msgid(ike, receiver,
					     "XXX: no EVENT_RETRANSMIT to clear, suspect IKE->CHILD switch");
			}
		} else {
			/*
			 * For instance, the IKE_AUTH response is
			 * rejected and the child (which was the
			 * receiver) is deleted before this code is
			 * called.
			 *
			 * XXX: if the IKE SA is made the receiver
			 * this problem goes away.
			 */
			dbg("Message ID: IKE #%lu XXX: message response receiver lost, probably a deleted child",
			    ike->sa.st_serialno);
		}
		/* update initiator's last response received */
		update = &new->initiator;
		break;
	case NO_MESSAGE:
		dbg("Message ID: IKE #%lu skipping update_recv as MD is fake",
		    ike->sa.st_serialno);
		return;
	default:
		bad_case(receiving);
	}

	update->recv = msgid;
	update->recv_frags = md->v2_frags_total;
	new->last_recv = update->last_recv = mononow(); /* not strictly correct */

	dbg_msgids_update(update_received_story, receiving, msgid,
			  ike, &old, receiver, &old_receiver);
}

void v2_msgid_update_sent(struct ike_sa *ike, struct state *sender,
			  struct msg_digest *md, enum message_role sending)
{
	struct v2_msgid_windows old = ike->sa.st_v2_msgid_windows;
	struct v2_msgid_windows *new = &ike->sa.st_v2_msgid_windows;
	struct v2_msgid_wip old_sender = sender->st_v2_msgid_wip;

	/* tbd */
	intmax_t msgid;
	struct v2_msgid_window *update;
	const char *update_sent_story;

	switch (sending) {
	case MESSAGE_REQUEST:
		/*
		 * pluto is initiating a new exchange.
		 *
		 * Use the next Message ID (which should be what was
		 * used by the code emitting the message request)
		 */
		update_sent_story = "updating initiator sent";
		update = &new->initiator;
		msgid = update->sent + 1;
		sender->st_v2_msgid_wip.initiator = msgid;
#if 0
		/*
		 * XXX: The record 'n' send code calls update_send()
		 * before update_recv() breaking WIP.INITIATOR's
		 * expected sequence OLD-MSGID -> -1 -> NEW-MSGID.
		 */
		if (DBGP(DBG_BASE) && old_sender.initiator != -1) {
			FAIL_V2_MSGID(ike, sender,
				      "sender.wip.initiator == -1 (was %jd)",
				      old_sender.initiator);
		}
#else
		if (old_sender.initiator != -1) {
			dbg_v2_msgid(ike, sender,
				     "XXX: expecting sender.wip.initiator %jd == -1 - suspect record'n'send out-of-order?)",
				     old_sender.initiator);
		}
#endif
		if (ike->sa.st_retransmit_event == NULL) {
			dbg_v2_msgid(ike, sender,
				     "scheduling EVENT_RETRANSMIT");
			start_retransmits(&ike->sa);
		} else {
			dbg_v2_msgid(ike, sender,
				     "XXX: EVENT_RETRANSMIT already scheduled -- suspect record'n'send");
		}
		break;
	case MESSAGE_RESPONSE:
		/*
		 * pluto is responding to MD.
		 *
		 * Since this is a response, the MD's Message ID
		 * trumps what ever is in responder.sent.  This way,
		 * when messages are lost, the counter jumps forward
		 * to the most recent received.
		 */
		update_sent_story = "updating responder sent";
		update = &new->responder;
		passert(md != NULL);
		pexpect(v2_msg_role(md) == MESSAGE_REQUEST);
		/* extend isa_msgid */
		msgid = md->hdr.isa_msgid;
		break;
	case NO_MESSAGE:
		dbg_v2_msgid(ike, sender,
			     "skipping update_send as nothing to send");
		return;
	default:
		bad_case(sending);
	}

	update->sent = msgid;
	new->last_sent = update->last_sent = mononow(); /* close enough */

	dbg_msgids_update(update_sent_story, sending, msgid,
			  ike, &old, sender, &old_sender);
}

struct v2_msgid_pending {
	so_serial_t child;
	so_serial_t who_for; /* for logging; either IKE or Child */
	const struct v2_state_transition *transition;
	struct v2_msgid_pending *next;
};

void v2_msgid_free(struct state *st)
{
	/* find the end; small list? */
	struct v2_msgid_pending **pp = &st->st_v2_msgid_windows.initiator.pending;
	while (*pp != NULL) {
		struct v2_msgid_pending *tbd = *pp;
		*pp = tbd->next;
		pfree(tbd);
	}
}

bool v2_msgid_request_outstanding(struct ike_sa *ike)
{
	struct v2_msgid_window *initiator = &ike->sa.st_v2_msgid_windows.initiator;
	intmax_t unack = (initiator->sent - initiator->recv);
	return (unack != 0); /* well >0 */
}

bool v2_msgid_request_pending(struct ike_sa *ike)
{
	struct v2_msgid_window *initiator = &ike->sa.st_v2_msgid_windows.initiator;
	return initiator->pending != NULL;
}

void v2_msgid_queue_initiator(struct ike_sa *ike, struct child_sa *child,
			      const struct v2_state_transition *transition)
{
	struct v2_msgid_window *initiator = &ike->sa.st_v2_msgid_windows.initiator;
	/* for logging */
	so_serial_t who_for = (child != NULL ? child->sa.st_serialno : ike->sa.st_serialno);
	/*
	 * Find the insertion point; small list?
	 *
	 * The queue has a simple priority order: informational
	 * exchanges (presumably either a delete or error
	 * notification) are put at the front before anything else
	 * (namely CREATE_CHILD_SA).
	 */
	struct v2_msgid_pending **pp = &initiator->pending;
	while (*pp != NULL) {
		if (transition->exchange == ISAKMP_v2_INFORMATIONAL
		    && (*pp)->transition->exchange != ISAKMP_v2_INFORMATIONAL) {
			dbg("inserting informational exchange for #%lu before #%lu's %s exchange",
			    who_for, (*pp)->who_for,
			    enum_name(&isakmp_xchg_type_names, (*pp)->transition->exchange));
			break;
		}
		pp = &(*pp)->next;
	}
	/* append */
	struct v2_msgid_pending new = {
		.child = child != NULL ? child->sa.st_serialno : SOS_NOBODY,
		.who_for = who_for,
		.transition = transition,
		.next = (*pp),
	};
	*pp = clone_thing(new, "struct initiate_list");
	v2_msgid_schedule_next_initiator(ike);
}

void v2_msgid_migrate_queue(struct ike_sa *from, struct child_sa *to)
{
	pexpect(to->sa.st_v2_msgid_windows.initiator.pending == NULL);
	to->sa.st_v2_msgid_windows.initiator.pending = from->sa.st_v2_msgid_windows.initiator.pending;
	from->sa.st_v2_msgid_windows.initiator.pending = NULL;
	for (struct v2_msgid_pending *pending = to->sa.st_v2_msgid_windows.initiator.pending; pending != NULL;
	     pending = pending->next) {
		if (pending->who_for == from->sa.st_serialno) {
			pending->who_for = to->sa.st_serialno;
		}
	}
}

static void initiate_next(const char *story, struct state *ike_sa, void *context UNUSED)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		dbg("IKE SA with pending initiates disappeared (%s)", story);
		return;
	}
	struct v2_msgid_window *initiator = &ike->sa.st_v2_msgid_windows.initiator;
	for (intmax_t unack = (initiator->sent - initiator->recv);
	     unack < ike->sa.st_connection->ike_window && initiator->pending != NULL;
	     unack++) {
		/*
		 * Make a copy of head, removing it from list.
		 */
		struct v2_msgid_pending pending = *initiator->pending;
		pfree(initiator->pending);
		initiator->pending = pending.next;

		struct child_sa *child = child_sa_by_serialno(pending.child);
		if (pending.child != SOS_NOBODY && child == NULL) {
			dbg_v2_msgid(ike, NULL,
				     "cannot initiate %s exchange for #%lu as Child SA disappeared (unack %jd)",
				     enum_name(&isakmp_xchg_type_names, pending.transition->exchange),
				     pending.child, unack);
			continue;
		}

		struct state *who_for = (child != NULL ? &child->sa : &ike->sa);
		pexpect(who_for->st_serialno == pending.who_for);
		dbg_v2_msgid(ike, who_for, "resuming SA using IKE SA (unack %jd)", unack);

		/*
		 * try to check that the transition still applies ...
		 */
		if (pending.transition->state != ike->sa.st_state->kind) {
			log_state(RC_LOG, who_for,
				  "dropping transition %s; IKE SA is not in state %s",
				  pending.transition->story,
				  finite_states[pending.transition->state]->short_name);
		} else {
			set_v2_transition(&ike->sa, pending.transition, HERE);
			stf_status status = pending.transition->processor(ike, child, NULL);
			complete_v2_state_transition(&ike->sa, NULL/*initiate so no md*/, status);
		}
	}
}

void v2_msgid_schedule_next_initiator(struct ike_sa *ike)
{
	struct v2_msgid_window *initiator = &ike->sa.st_v2_msgid_windows.initiator;
	/*
	 * If there appears to be space and there's a pending
	 * initiate, poke the IKE SA so it tries to initiate things.
	 */
	if (initiator->pending != NULL) {
		intmax_t unack = (initiator->sent - initiator->recv);
		/* if this returns NULL, that's ok; will log "LOST" */
		struct state *who_for = state_by_serialno(initiator->pending->who_for);
		if (unack < ike->sa.st_connection->ike_window) {
			dbg_v2_msgid(ike, who_for,
				     "wakeing IKE SA for next initiator (unack %jd)",
				     unack);
			schedule_callback("next initiator", ike->sa.st_serialno, initiate_next, NULL);
		} else {
			dbg_v2_msgid(ike, who_for,
				     "next initiator blocked by outstanding response (unack %jd)",
				     unack);
		}
	} else {
		dbg_v2_msgid(ike, &ike->sa,
			     "no pending message initiators to schedule");
	}
}
