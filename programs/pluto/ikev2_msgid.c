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

static void jam_msgid_prefix(struct jambuf *buf, struct ike_sa *ike)
{
	jam_string(buf, "Message ID: ");
	jam(buf, "IKE #%lu", ike->sa.st_serialno);
}

static void jam_old_new_monotime(struct jambuf *buf,
				 const char **prefix, const char *what,
				 const monotime_t *old, const monotime_t *new)
{
	if (old == new || monotime_cmp(*old, !=, *new)) {
		jam_string(buf, *prefix);
		*prefix = "";
		monotime_buf mb;
		jam(buf, " %s=%s", what, str_monotime(*old, &mb));
		if (old != new) {
			jam(buf, "->%s", str_monotime(*new, &mb));
		}
	}
}

static void jam_old_new_intmax(struct jambuf *buf,
				 const char **prefix, const char *what,
			       const intmax_t *old, const intmax_t *new)
{
	if (old == new || *old != *new) {
		jam_string(buf, *prefix);
		*prefix = "";
		jam(buf, " %s=%jd", what, *old);
		if (old != new) {
			jam(buf, "->%jd", *new);
		}
	}
}

static void jam_old_new_unsigned(struct jambuf *buf,
				 const char **prefix, const char *what,
				 const unsigned *old, const unsigned *new)
{
	if (old == new || *old != *new) {
		jam_string(buf, *prefix);
		*prefix = "";
		jam(buf, " %s=%u", what, *old);
		if (old != new) {
			jam(buf, "->%u", *new);
		}
	}
}

static void jam_ike_window(struct jambuf *buf,
			   const char *prefix,
			   const struct v2_msgid_window *old,
			   const struct v2_msgid_window *new)
{
	jam_old_new_intmax(buf, &prefix, ".sent", &old->sent, &new->sent);
	jam_old_new_intmax(buf, &prefix, ".recv", &old->recv, &new->recv);
	jam_old_new_unsigned(buf, &prefix, ".recv_frags", &old->recv_frags, &new->recv_frags);
	jam_old_new_intmax(buf, &prefix, ".wip", &old->wip, &new->wip);
	jam_old_new_monotime(buf, &prefix, ".last_sent", &old->last_sent, &new->last_sent);
	jam_old_new_monotime(buf, &prefix, ".last_recv", &old->last_recv, &new->last_recv);
}

static void jam_ike_windows(struct jambuf *buf,
			    const struct v2_msgid_windows *old,
			    const struct v2_msgid_windows *new)
{
	jam_ike_window(buf, "; initiator", &old->initiator, &new->initiator);
	jam_ike_window(buf, "; responder", &old->responder, &new->responder);
}

static void jam_window_details(struct jambuf *buf,
			       struct ike_sa *ike,
			       const struct v2_msgid_windows *old_windows)
{
	jam_ike_windows(buf,
			old_windows != NULL ? old_windows : &ike->sa.st_v2_msgid_windows,
			&ike->sa.st_v2_msgid_windows);
}

VPRINTF_LIKE(3)
static void jam_v2_msgid(struct jambuf *buf,
			 struct ike_sa *ike,
			 const char *fmt, va_list ap)
{
	jam_msgid_prefix(buf, ike);
	jam(buf, " ");
	jam_va_list(buf, fmt, ap);
	jam_window_details(buf, ike, NULL);
}

void dbg_v2_msgid(struct ike_sa *ike, const char *fmt, ...)
{
	LDBGP_JAMBUF(DBG_BASE, ike->sa.logger, buf) {
		va_list ap;
		va_start(ap, fmt);
		jam_v2_msgid(buf, ike, fmt, ap);
		va_end(ap);
	}
}

void fail_v2_msgid_where(where_t where, struct ike_sa *ike, const char *fmt, ...)
{
	LLOG_PEXPECT_JAMBUF(ike->sa.logger, where, buf) {
		va_list ap;
		va_start(ap, fmt);
		jam_v2_msgid(buf, ike, fmt, ap);
		va_end(ap);
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
			      struct ike_sa *ike, const struct v2_msgid_windows *old_windows)
{
	LDBGP_JAMBUF(DBG_BASE, ike->sa.logger, buf) {
		jam_msgid_prefix(buf, ike);
		jam(buf, " %s", what);
		switch (message) {
		case MESSAGE_REQUEST: jam(buf, " request %jd", msgid); break;
		case MESSAGE_RESPONSE: jam(buf, " response %jd", msgid); break;
		case NO_MESSAGE: break;
		default: bad_case(message);
		}
		jam_window_details(buf, ike, old_windows);
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
		.wip = -1,
	},
	.responder = {
		.sent = -1,
		.recv = -1,
		.wip = -1,
	},
};

void v2_msgid_init_ike(struct ike_sa *ike)
{
	const monotime_t now = mononow();
	const struct v2_msgid_windows old = ike->sa.st_v2_msgid_windows;
	struct v2_msgid_windows *new = &ike->sa.st_v2_msgid_windows;
	*new = empty_v2_msgid_windows;
	new->last_sent = now;
	new->last_recv = now;
	new->responder.last_sent = now;
	new->responder.last_recv = now;
	new->initiator.last_sent = now;
	new->initiator.last_recv = now;
	/* pretend there's a sender */
	dbg_msgids_update("initializing", NO_MESSAGE, -1, ike, &old);
}

void v2_msgid_start_record_n_send(struct ike_sa *ike)
{
	const struct v2_msgid_windows old = ike->sa.st_v2_msgid_windows;
	struct v2_msgid_windows *new = &ike->sa.st_v2_msgid_windows;
	/*
	 * Make things look like the last exchange finished (even
	 * though it didn't).
	 */
	intmax_t msgid = new->initiator.recv = old.initiator.sent;
	new->initiator.wip = -1;
	dbg_msgids_update("initiator record'n'send", NO_MESSAGE, msgid, ike, &old);
}

void v2_msgid_start(struct ike_sa *ike, const struct msg_digest *md)
{
	const struct v2_msgid_windows old = ike->sa.st_v2_msgid_windows;
	struct v2_msgid_windows *new = &ike->sa.st_v2_msgid_windows;

	enum message_role role = v2_msg_role(md);
	switch (role) {
	case NO_MESSAGE:
	{
		intmax_t msgid = old.initiator.sent + 1;
		pexpect_v2_msgid(ike, role, old.initiator.recv+1 == msgid);
		pexpect_v2_msgid(ike, role, old.initiator.sent+1 == msgid);
#if 0
		/*
		 * XXX: apparently, even this isn't always true!.
		 */
		pexpect_v2_msgid(ike, role, old.initiator.wip == -1);
#endif
#if 0
		/*
		 * XXX: v2_msgid_start() isn't called when starting a
		 * new exchange!  It should be ...
		 */
		new->initiator.wip = msgid;
#endif
		dbg_msgids_update("initiator starting", role, msgid, ike, &old);
		break;
	}
	case MESSAGE_REQUEST:
	{
		/* extend msgid */
		intmax_t msgid = md->hdr.isa_msgid;
		pexpect_v2_msgid(ike, role, old.responder.wip == -1);
		pexpect_v2_msgid(ike, role, old.responder.sent+1 == msgid);
		pexpect_v2_msgid(ike, role, old.responder.recv+1 == msgid);
		new->responder.wip = msgid;
		dbg_msgids_update("responder starting", role, msgid, ike, &old);
		break;
	}
	case MESSAGE_RESPONSE:
	{
		intmax_t msgid = md->hdr.isa_msgid;
#if 0
		/*
		 * XXX: v2_msgid_start() isn't called when starting a
		 * new exchange!  It should be ...
		 */
		pexpect_v2_msgid(ike, role, old.initiator.wip == -1);
#else
		pexpect_v2_msgid(ike, role, old.initiator.wip == msgid);
#endif
		pexpect_v2_msgid(ike, role, old.initiator.sent == msgid);
		pexpect_v2_msgid(ike, role, old.initiator.recv+1 == msgid);
		new->initiator.wip = msgid;
		dbg_msgids_update("initiator response", role, msgid, ike, &old);
		break;
	}
	}
}

void v2_msgid_cancel(struct ike_sa *ike, const struct msg_digest *md)
{
	enum message_role msg_role = v2_msg_role(md);
	switch (msg_role) {
	case NO_MESSAGE:
		dbg_v2_msgid(ike, "initiator canceling new exchange");
		break;
	case MESSAGE_REQUEST:
	{
		/* extend msgid */
		intmax_t msgid = md->hdr.isa_msgid;
		if (ike->sa.st_v2_msgid_windows.responder.wip != msgid) {
			fail_v2_msgid(ike,
				      "responder.wip should be %jd, was %jd",
				      msgid, ike->sa.st_v2_msgid_windows.responder.wip);
		}
		ike->sa.st_v2_msgid_windows.responder.wip = -1;
		dbg_msgids_update("responder cancelling", msg_role, msgid,
				  ike, &ike->sa.st_v2_msgid_windows);
		break;
	}
	case MESSAGE_RESPONSE:
		dbg_v2_msgid(ike, "initiator canceling processing of response to existing exchange");
		break;
	}
}

static void v2_msgid_update_recv(struct ike_sa *ike, const struct msg_digest *md)
{
	/* save old value, and add shortcut to new */
	const struct v2_msgid_windows old = ike->sa.st_v2_msgid_windows;
	struct v2_msgid_windows *new = &ike->sa.st_v2_msgid_windows;

	enum message_role receiving = v2_msg_role(md);
	intmax_t msgid;
	struct v2_msgid_window *update;
	const char *update_received_story;

	switch (receiving) {
	case MESSAGE_REQUEST:
	{
		update_received_story = "updating responder received";
		/* update responder's last request received */
		struct v2_msgid_window *responder = &ike->sa.st_v2_msgid_windows.responder;
		update = responder;
		/*
		 * Processing request finished.  Scrub it as wip.
		 *
		 * XXX: should this be done in update_sent() since it
		 * is when sending the response signifying that things
		 * really finish?
		 */
		msgid = md->hdr.isa_msgid; /* zero-extended */
		if (DBGP(DBG_BASE) && responder->wip != msgid) {
			fail_v2_msgid(ike,
				      "windows.responder.wip == %jd(msgid) (was %jd)",
				      msgid, responder->wip);
		}
		responder->wip = -1;
		break;
	}
	case MESSAGE_RESPONSE:
	{
		update_received_story = "updating initiator received";
		/* update initiator's last response received */
		struct v2_msgid_window *initiator = &ike->sa.st_v2_msgid_windows.initiator;
		update = initiator;
		/*
		 * Since the response has been successfully processed,
		 * clear WIP.INITIATOR.  This way duplicate responses
		 * get discarded as there is no receiving state.
		 *
		 * XXX: Unfortunately the record 'n' send code throws
		 * a spanner in the works.  It calls update_sent()
		 * before update_recv() breaking the assumption that
		 * WIP.INITIATOR is the old MSGID.
		 */
		msgid = md->hdr.isa_msgid; /* zero-extended */
		if (old.initiator.wip > msgid) {
			/*
			 * Hack around record 'n' send calling
			 * update_sent() (setting WIP.INITIATOR to the
			 * next request) midway through processing.
			 *
			 * Getting rid of record 'n' send will fix
			 * this hack.
			 */
			dbg_v2_msgid(ike,
				     "XXX: receiver.wip.initiator %jd != receiver.msgid %jd - suspect record'n'called update_sent() before update_recv()",
				     old.initiator.wip, msgid);
		} else {
			if (DBGP(DBG_BASE) && old.initiator.wip != msgid) {
				fail_v2_msgid(ike,
					      "receiver.wip.initiator == %jd(msgid) (was %jd)",
					      msgid, old.initiator.wip);
			}
			new->initiator.wip = -1;
		}
		/* this is what matters */
		pexpect(new->initiator.wip != msgid);
		/*
		 * Clear the retransmits for the old message.
		 */
		dbg_v2_msgid(ike, "clearing EVENT_RETRANSMIT as response received");
		clear_retransmits(&ike->sa);
		break;
	}
	case NO_MESSAGE:
		dbg_v2_msgid(ike, "skipping update_recv as no message (presumably initiator)");
		return;
	default:
		bad_case(receiving);
	}

	update->recv = msgid;
	update->recv_frags = md->v2_frags_total;
	new->last_recv = update->last_recv = mononow(); /* not strictly correct */

	dbg_msgids_update(update_received_story, receiving, msgid, ike, &old);
}

static void v2_msgid_update_sent(struct ike_sa *ike, const struct msg_digest *md, enum message_role sending)
{
	struct v2_msgid_windows old = ike->sa.st_v2_msgid_windows;
	struct v2_msgid_windows *new = &ike->sa.st_v2_msgid_windows;

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
		new->initiator.wip = msgid;
#if 0
		/*
		 * XXX: The record 'n' send code calls update_sent()
		 * before update_recv() breaking WIP.INITIATOR's
		 * expected sequence OLD-MSGID -> -1 -> NEW-MSGID.
		 */
		if (DBGP(DBG_BASE) && old.initiator.wip != -1) {
			fail_v2_msgid(ike,
				      "sender.wip.initiator == -1 (was %jd)",
				      old.initiator.wip);
		}
#else
		if (old.initiator.wip != -1) {
			dbg_v2_msgid(ike,
				     "XXX: expecting sender.wip.initiator %jd == -1 - suspect record'n'send out-of-order?)",
				     old.initiator.wip);
		}
#endif
		if (ike->sa.st_retransmit_event == NULL) {
			dbg_v2_msgid(ike, "scheduling EVENT_RETRANSMIT");
			start_retransmits(&ike->sa);
		} else {
			dbg_v2_msgid(ike, "XXX: EVENT_RETRANSMIT already scheduled -- suspect record'n'send");
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
		dbg_v2_msgid(ike, "skipping update_send as nothing to send (presumably initiator receiving a response)");
		return;
	default:
		bad_case(sending);
	}

	update->sent = msgid;
	new->last_sent = update->last_sent = mononow(); /* close enough */

	dbg_msgids_update(update_sent_story, sending, msgid, ike, &old);
}

void v2_msgid_finish(struct ike_sa *ike, const struct msg_digest *md)
{
	v2_msgid_update_recv(ike, md);
	/*
	 * XXX: If possible, avoid relying on .st_v2_transition.  When
	 * record'n'send is forcing an initiate, .st_v2_transition is
	 * bogus.  When record'n'send goes away so does this hack.
	 */
	v2_msgid_update_sent(ike, md,
			     (md == NULL ? MESSAGE_REQUEST :
			      ike->sa.st_v2_transition->send_role));
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
	struct v2_msgid_pending **pp = &st->st_v2_msgid_windows.pending_requests;
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
	return ike->sa.st_v2_msgid_windows.pending_requests != NULL;
}

void v2_msgid_queue_initiator(struct ike_sa *ike, struct child_sa *child,
			      const struct v2_state_transition *transition)
{
	/* for logging */
	so_serial_t who_for = (child != NULL ? child->sa.st_serialno : ike->sa.st_serialno);
	struct logger *logger = (child != NULL ? child->sa.logger : ike->sa.logger);
	/*
	 * Find the insertion point; small list?
	 *
	 * The queue has a simple priority order: informational
	 * exchanges (presumably either a delete or error
	 * notification) are put at the front before anything else
	 * (namely CREATE_CHILD_SA).
	 */
	unsigned ranking = 0;
	struct v2_msgid_pending **pp = &ike->sa.st_v2_msgid_windows.pending_requests;
	while (*pp != NULL) {
		if (transition->exchange == ISAKMP_v2_INFORMATIONAL
		    && (*pp)->transition->exchange != ISAKMP_v2_INFORMATIONAL) {
			break;
		}
		ranking++;
		pp = &(*pp)->next;
	}
	/*
	 * Full log when the exchange is blocked.  That is waiting on
	 * another exchange (ranking>0) or an exchange in progress.
	 */
	enum stream stream = (ranking > 0 ? LOG_STREAM :
			      v2_msgid_request_outstanding(ike) ? LOG_STREAM :
			      DBGP(DBG_BASE) ? DEBUG_STREAM :
			      NO_STREAM);
	if (stream != NO_STREAM) {
		LLOG_JAMBUF(stream, logger, buf) {
			jam(buf, "adding %s request to IKE SA "PRI_SO"'s message queue",
			    enum_name_short(&isakmp_xchg_type_names, transition->exchange),
			    pri_so(ike->sa.st_serialno));
			if (ranking > 0) {
				jam(buf, " at position %u", ranking);
			}
			if ((*pp) != NULL) {
				jam(buf, "; before "PRI_SO"'s %s exchange",
				    pri_so((*pp)->who_for),
				    enum_name_short(&isakmp_xchg_type_names, (*pp)->transition->exchange));
			}
		}
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
	pexpect(to->sa.st_v2_msgid_windows.pending_requests == NULL);
	to->sa.st_v2_msgid_windows.pending_requests = from->sa.st_v2_msgid_windows.pending_requests;
	from->sa.st_v2_msgid_windows.pending_requests = NULL;
	for (struct v2_msgid_pending *pending = to->sa.st_v2_msgid_windows.pending_requests; pending != NULL;
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
	     unack < ike->sa.st_connection->config->ike_window
		     && ike->sa.st_v2_msgid_windows.pending_requests != NULL;
	     unack++) {

		/*
		 * Make a copy of the pending exchange, and then
		 * release it.
		 */
		struct v2_msgid_pending pending = *ike->sa.st_v2_msgid_windows.pending_requests;
		pfree(ike->sa.st_v2_msgid_windows.pending_requests);
		ike->sa.st_v2_msgid_windows.pending_requests = pending.next;

		struct child_sa *child = child_sa_by_serialno(pending.child);
		if (pending.child != SOS_NOBODY && child == NULL) {
			dbg_v2_msgid(ike,
				     "cannot initiate %s exchange for #%lu as Child SA disappeared (unack %jd)",
				     enum_name(&isakmp_xchg_type_names, pending.transition->exchange),
				     pending.child, unack);
			continue;
		}

		struct state *who_for = (child != NULL ? &child->sa : &ike->sa);
		pexpect(who_for->st_serialno == pending.who_for);
		dbg_v2_msgid(ike, "resuming IKE SA for "PRI_SO" (unack %jd)",
			     pri_so(pending.who_for), unack);

		/*
		 * try to check that the transition still applies ...
		 */
		if (pending.transition->state != ike->sa.st_state->kind) {
			log_state(RC_LOG, who_for,
				  "dropping transition %s; IKE SA is not in state %s",
				  pending.transition->story,
				  finite_states[pending.transition->state]->short_name);
			continue;
		}

		/*
		 * The Message ID / open window will only be assigned
		 * to the request when the state transition finishes
		 * and the message is sent (which could be several
		 * events down the road).
		 *
		 * This is "ok" as this function is only re-called
		 * when the response has been received and the
		 * exchange has finished.
		 *
		 * XXX: this should this instead pre-assign the
		 * Message ID / open window to the exchange (and
		 * unassign it if the exchange is abandoned)?
		 */

		start_v2_transition(ike, pending.transition, /*md*/NULL, HERE);

		/* pexpect(initiator->wip_sa == NULL); */
		initiator->wip_sa = child;
		stf_status status = pending.transition->processor(ike, child, NULL);
		complete_v2_state_transition(ike, NULL/*initiate so no md*/, status);
	}
}

void v2_msgid_schedule_next_initiator(struct ike_sa *ike)
{
	const struct v2_msgid_window *initiator = &ike->sa.st_v2_msgid_windows.initiator;
	const struct v2_msgid_pending *pending = ike->sa.st_v2_msgid_windows.pending_requests;
	/*
	 * If there appears to be space and there's a pending
	 * initiate, poke the IKE SA so it tries to initiate things.
	 */
	if (pending != NULL) {
		/* if this returns NULL, that's ok; will log "LOST" */
		intmax_t unack = (initiator->sent - initiator->recv);
		if (unack < ike->sa.st_connection->config->ike_window) {
			dbg_v2_msgid(ike,
				     "wakeing IKE SA for next initiator "PRI_SO", (unack %jd)",
				     pri_so(pending->who_for), unack);
			schedule_callback("next initiator", deltatime(0),
					  ike->sa.st_serialno, initiate_next, NULL);
		} else {
			dbg_v2_msgid(ike,
				     "next initiator "PRI_SO" blocked by outstanding response (unack %jd)",
				     pri_so(pending->who_for), unack);
		}
	} else {
		dbg_v2_msgid(ike,
			     "no pending message initiators to schedule");
	}
}

/*
 * XXX: only handles 1 window!
 */
struct v2_msgid_window *v2_msgid_window(struct ike_sa *ike, enum message_role message_role)
{
	switch (message_role) {
	case MESSAGE_REQUEST: return &ike->sa.st_v2_msgid_windows.responder;
	case MESSAGE_RESPONSE: return &ike->sa.st_v2_msgid_windows.initiator;
	case NO_MESSAGE: break;
	}
	bad_enum(ike->sa.logger, &message_role_names, message_role);
}
