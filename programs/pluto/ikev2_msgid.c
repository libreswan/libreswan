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

#define pexpect_v2_msgid(COND)			\
	({								\
		bool cond_ = COND; /* eval once, no paren */		\
		if (!cond_) {						\
			enum_buf eb;					\
			llog_pexpect_v2_msgid_where(where, ike,		\
						    "%s %jd: %s",	\
						    str_enum_short(&message_role_names, role, &eb), \
						    msgid, #COND);	\
		}							\
	})

static callback_cb initiate_next;		/* type assertion */

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

/*
 * Logging.
 */

static void jam_old_new_prefix(struct jambuf *buf,
			       const char **prefix, const char *what)
{
	jam_string(buf, *prefix);
	*prefix = "";
	jam_string(buf, " ");
	jam_string(buf, what);
	jam_string(buf, "=");
}

static void jam_old_new_exchange(struct jambuf *buf,
				 const char **prefix, const char *what,
				 const struct v2_exchange *const *old,
				 const struct v2_exchange *const *new)
{
	if (old == new || (*old) != (*new)) {
		jam_old_new_prefix(buf, prefix, what);
		if (*old != NULL) {
			jam_string(buf, (*old)->initiate->story);
		}
		if (old != new) {
			jam_string(buf, "->");
			if (*new != NULL) {
				jam_string(buf, (*new)->initiate->story);
			}
		}
	}
}

static void jam_old_new_monotime(struct jambuf *buf,
				 const char **prefix, const char *what,
				 const monotime_t *old, const monotime_t *new)
{
	if (old == new || monotime_cmp(*old, !=, *new)) {
		jam_old_new_prefix(buf, prefix, what);
		jam_monotime(buf, *old);
		if (old != new) {
			jam_string(buf, "->");
			jam_monotime(buf, *new);
		}
	}
}

static void jam_old_new_intmax(struct jambuf *buf,
				 const char **prefix, const char *what,
			       const intmax_t *old, const intmax_t *new)
{
	if (old == new || *old != *new) {
		jam_old_new_prefix(buf, prefix, what);
		jam(buf, "%jd", *old);
		if (old != new) {
			jam_string(buf, "->");
			jam(buf, "%jd", *new);
		}
	}
}

static void jam_old_new_unsigned(struct jambuf *buf,
				 const char **prefix, const char *what,
				 const unsigned *old, const unsigned *new)
{
	if (old == new || *old != *new) {
		jam_old_new_prefix(buf, prefix, what);
		jam(buf, "%u", *old);
		if (old != new) {
			jam_string(buf, "->");
			jam(buf, "%u", *new);
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
	jam_old_new_exchange(buf, &prefix, ".exchange", &old->exchange, &new->exchange);
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
			       const struct v2_msgid_windows *old)
{
	jam_ike_windows(buf, old, &ike->sa.st_v2_msgid_windows);
}

VPRINTF_LIKE(4)
static void jam_v2_msgid(struct jambuf *buf,
			 struct ike_sa *ike,
			 const struct v2_msgid_windows *old,
			 const char *fmt, va_list ap)
{
	jam(buf, "Message ID: ");
	jam_va_list(buf, fmt, ap);
	jam_window_details(buf, ike, old);
}

void dbg_v2_msgid(struct ike_sa *ike, const char *fmt, ...)
{
	if (DBGP(DBG_BASE)) {
		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, ike->sa.logger, buf) {
			va_list ap;
			va_start(ap, fmt);
			/* dump non-default values */
			jam_v2_msgid(buf, ike, &empty_v2_msgid_windows, fmt, ap);
			va_end(ap);
		}
	}
}

void llog_pexpect_v2_msgid_where(where_t where, struct ike_sa *ike, const char *fmt, ...)
{
	LLOG_PEXPECT_JAMBUF(ike->sa.logger, where, buf) {
		va_list ap;
		va_start(ap, fmt);
		/* dump all values */
		jam_v2_msgid(buf, ike, &ike->sa.st_v2_msgid_windows, fmt, ap);
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

static void dbg_msgid_update(const char *what,
			     enum message_role message, intmax_t msgid,
			     struct ike_sa *ike, const struct v2_msgid_windows *old)
{
	if (DBGP(DBG_BASE)) {
		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, ike->sa.logger, buf) {
			jam(buf, "Message ID: %s", what);
			switch (message) {
			case MESSAGE_REQUEST: jam(buf, " request %jd", msgid); break;
			case MESSAGE_RESPONSE: jam(buf, " response %jd", msgid); break;
			case NO_MESSAGE: break;
			default: bad_case(message);
			}
			jam_window_details(buf, ike, old);
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
	dbg_msgid_update("initializing", NO_MESSAGE, -1, ike, &old);
}

void v2_msgid_start_record_n_send(struct ike_sa *ike, const struct v2_exchange *exchange)
{
	const struct v2_msgid_windows old = ike->sa.st_v2_msgid_windows;
	struct v2_msgid_windows *new = &ike->sa.st_v2_msgid_windows;
	/*
	 * Make things look like the last exchange finished (even
	 * though it didn't).
	 */
	intmax_t msgid = new->initiator.recv = old.initiator.sent;
	new->initiator.wip = msgid + 1;
	new->initiator.exchange = exchange;
	dbg_msgid_update("initiator record'n'send", NO_MESSAGE, msgid, ike, &old);
}

void v2_msgid_start(struct ike_sa *ike,
		    const struct v2_exchange *exchange,
		    const struct msg_digest *md,
		    where_t where)
{
	const struct v2_msgid_windows old = ike->sa.st_v2_msgid_windows;
	struct v2_msgid_windows *new = &ike->sa.st_v2_msgid_windows;

	const char *update_story;
	intmax_t msgid;
	enum message_role role = v2_msg_role(md);
	switch (role) {
	case NO_MESSAGE:
	{
		update_story = "initiator starting";
		msgid = old.initiator.sent + 1;
		pexpect_v2_msgid(old.initiator.recv+1 == msgid);
		pexpect_v2_msgid(old.initiator.sent+1 == msgid);
		pexpect_v2_msgid(old.initiator.wip == -1);
		pexpect_v2_msgid(old.initiator.exchange == NULL);
		pexpect_v2_msgid(exchange != NULL);
		new->initiator.wip = msgid;
		new->initiator.exchange = exchange;
		break;
	}
	case MESSAGE_REQUEST:
	{
		/* extend msgid */
		update_story = "responder starting";
		msgid = md->hdr.isa_msgid;
		pexpect_v2_msgid(old.responder.wip == -1);
		pexpect_v2_msgid(old.responder.sent+1 == msgid);
		pexpect_v2_msgid(old.responder.recv+1 == msgid);
		new->responder.wip = msgid;
		break;
	}
	case MESSAGE_RESPONSE:
	{
		update_story = "initiator starting";
		msgid = md->hdr.isa_msgid;
		pexpect_v2_msgid(old.initiator.wip == -1);
		pexpect_v2_msgid(old.initiator.sent == msgid);
		pexpect_v2_msgid(old.initiator.recv+1 == msgid);
		pexpect_v2_msgid(old.initiator.exchange != NULL);
		new->initiator.wip = msgid;
		break;
	}
	default:
		bad_case(role);
	}
	dbg_msgid_update(update_story, role, msgid, ike, &old);
}

void v2_msgid_cancel(struct ike_sa *ike, const struct msg_digest *md, where_t where)
{
	enum message_role role = v2_msg_role(md);
	switch (role) {
	case NO_MESSAGE:
		dbg_v2_msgid(ike, "initiator canceling new exchange");
		break;
	case MESSAGE_REQUEST:
	{
		/* extend msgid */
		intmax_t msgid = md->hdr.isa_msgid;
		pexpect_v2_msgid(ike->sa.st_v2_msgid_windows.responder.wip == msgid);
		ike->sa.st_v2_msgid_windows.responder.wip = -1;
		dbg_msgid_update("responder cancelling", role, msgid,
				 ike, &ike->sa.st_v2_msgid_windows);
		break;
	}
	case MESSAGE_RESPONSE:
		dbg_v2_msgid(ike, "initiator canceling processing of response to existing exchange");
		break;
	}
}

void v2_msgid_finish(struct ike_sa *ike, const struct msg_digest *md, where_t where)
{
	struct v2_msgid_windows old = ike->sa.st_v2_msgid_windows;
	struct v2_msgid_windows *new = &ike->sa.st_v2_msgid_windows;
	enum message_role role = v2_msg_role(md);

	intmax_t msgid;
	const char *update_story;
	struct v2_msgid_window *update;

	switch (role) {
	case NO_MESSAGE:
	{
		/*
		 * pluto is initiating a new exchange.
		 *
		 * Use the next Message ID (which should be what was
		 * used by the code emitting the message request).
		 */
		msgid = old.initiator.sent + 1;
		update_story = "initiator finishing";
		pexpect_v2_msgid(old.initiator.wip == msgid);
		pexpect_v2_msgid(old.initiator.exchange != NULL);
		update = &new->initiator;
		new->initiator.wip = -1;
		new->initiator.sent = msgid;
		if (ike->sa.st_retransmit_event == NULL) {
			dbg_v2_msgid(ike, "scheduling EVENT_RETRANSMIT");
			start_retransmits(&ike->sa);
		} else {
			dbg_v2_msgid(ike, "XXX: EVENT_RETRANSMIT already scheduled -- suspect record'n'send");
		}
		break;
	}
	case MESSAGE_REQUEST:
	{
		/*
		 * Finished responding to MD.
		 *
		 * Since this is a response, the MD's Message ID
		 * trumps what ever is in responder.sent.  This way,
		 * when messages are lost, the counter jumps forward
		 * to the most recent received.
		 *
		 * The retransmit code uses both .recv and
		 * .recv_frags.  Both need to match.
		 */
		update_story = "responder finishing";
		msgid = md->hdr.isa_msgid;
		pexpect_v2_msgid(old.responder.wip == msgid);
		update = &new->responder;
		new->responder.wip = -1;
		/* for duplicate detection */
		new->responder.recv = msgid;
		new->responder.recv_frags = md->v2_frags_total;
		new->responder.sent = msgid;
		break;
	}
	case MESSAGE_RESPONSE:
	{
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
		update_story = "initiator finishing";
		msgid = md->hdr.isa_msgid;
		update = &new->initiator;
		pexpect_v2_msgid(old.initiator.wip == msgid);
		pexpect_v2_msgid(old.initiator.exchange != NULL);
		new->initiator.exchange = NULL;
		new->initiator.recv = msgid;
		new->initiator.wip = -1;
		/*
		 * Clear the retransmits for the old message.
		 */
		dbg_v2_msgid(ike, "clearing EVENT_RETRANSMIT as response received");
		clear_retransmits(&ike->sa);
		break;
	}
	default:
		bad_case(role);
	}

	/* should be backdated to when the message arrives? */
	new->last_recv = update->last_recv = mononow(); /* close enough */
	dbg_msgid_update(update_story, role, msgid, ike, &old);
}

struct v2_msgid_pending {
	so_serial_t child;
	so_serial_t who_for; /* for logging; either IKE or Child */
	const struct v2_exchange *exchange;
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

void v2_msgid_queue_exchange(struct ike_sa *ike, struct child_sa *child/*could-be-null*/,
			     const struct v2_exchange *exchange)
{
	/* for logging */
	so_serial_t who_for = (child != NULL ? child->sa.st_serialno : ike->sa.st_serialno);
	struct logger *logger = (child != NULL ? child->sa.logger : ike->sa.logger);
	bool crossing_stream =
		(child != NULL && child->sa.st_connection != ike->sa.st_connection);

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
		if (exchange->initiate->exchange == ISAKMP_v2_INFORMATIONAL
		    && (*pp)->exchange->initiate->exchange != ISAKMP_v2_INFORMATIONAL) {
			break;
		}
		ranking++;
		pp = &(*pp)->next;
	}

	/*
	 * Log when the exchange is blocked by some other task.
	 *
	 * That is there is something in front of the task on the
	 * queue (ranking>0) or when there's a crossing stream.
	 *
	 * Log to the file as there can be long gaps between the
	 * "initiating", adding, and sending messages.  Don't log to
	 * whack they are always adjacent.
	 *
	 * Should the initiate code assign the window?
	 */
	enum stream stream = (ranking > 0 ? LOG_STREAM :
			      crossing_stream ? LOG_STREAM :
			      DBGP(DBG_BASE) ? DEBUG_STREAM|ADD_PREFIX :
			      NO_STREAM);
	if (stream != NO_STREAM) {
		LLOG_JAMBUF(stream, logger, buf) {
			jam(buf, "adding %s request to IKE SA "PRI_SO"'s message queue",
			    enum_name_short(&isakmp_xchg_type_names,
					    exchange->initiate->exchange),
			    pri_so(ike->sa.st_serialno));
			if (ranking > 0) {
				jam(buf, " at position %u", ranking);
			}
			if ((*pp) != NULL) {
				jam(buf, "; before "PRI_SO"'s %s exchange",
				    pri_so((*pp)->who_for),
				    enum_name_short(&isakmp_xchg_type_names,
						    (*pp)->exchange->initiate->exchange));
			}
		}
	}

	/* append */
	struct v2_msgid_pending new = {
		.child = child != NULL ? child->sa.st_serialno : SOS_NOBODY,
		.who_for = who_for,
		.exchange = exchange,
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
		 * Make an on-stack copy of the pending exchange, and
		 * then release the allocated memory.
		 */
		struct v2_msgid_pending pending = *ike->sa.st_v2_msgid_windows.pending_requests;
		pfree(ike->sa.st_v2_msgid_windows.pending_requests);
		ike->sa.st_v2_msgid_windows.pending_requests = pending.next;

		struct child_sa *child = child_sa_by_serialno(pending.child);
		if (pending.child != SOS_NOBODY && child == NULL) {
			dbg_v2_msgid(ike,
				     "cannot initiate %s exchange for "PRI_SO" as Child SA disappeared (unack %jd)",
				     enum_name(&isakmp_xchg_type_names,
					       pending.exchange->initiate->exchange),
				     pri_so(pending.child), unack);
			continue;
		}

		struct state *who_for = (child != NULL ? &child->sa : &ike->sa);
		pexpect(who_for->st_serialno == pending.who_for);
		dbg_v2_msgid(ike, "resuming IKE SA for "PRI_SO" (unack %jd)",
			     pri_so(pending.who_for), unack);

		/*
		 * try to check that the transition still applies ...
		 */
		if (!v2_transition_from(pending.exchange->initiate, ike->sa.st_state)) {
			LLOG_JAMBUF(RC_LOG, who_for->logger, buf) {
				jam(buf, "dropping transition ");
				jam_v2_transition(buf, pending.exchange->initiate);
				jam(buf, " as IKE SA is in state %s",
				    ike->sa.st_state->short_name);
			}
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

		start_v2_exchange(ike, pending.exchange, HERE);
		/* pexpect(initiator->wip_sa == NULL); */
		initiator->wip_sa = child;
		stf_status status = pending.exchange->initiate->processor(ike, child, NULL);
		complete_v2_state_transition(ike, NULL/*initiate so no md*/, status);

		/*
		 * Get out of Dodge!
		 *
		 * complete_v2_state_transition can delete the IKE SA!
		 * OTOH, if there's still a pending exchange then
		 * success_v2_state_transition() will schedule a call
		 * back to this function.
		 */
		return;

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

const struct v2_transitions *v2_msgid_transitions(struct ike_sa *ike,
						  const struct msg_digest *md)
{
	switch (v2_msg_role(md)) {
	case NO_MESSAGE:
		break;
	case MESSAGE_REQUEST:
		return ike->sa.st_state->v2.transitions;
	case MESSAGE_RESPONSE:
	{
		const struct v2_exchange *exchange = ike->sa.st_v2_msgid_windows.initiator.exchange;
		PASSERT(ike->sa.logger, exchange != NULL);
		const struct finite_state *state = exchange->initiate->to;
		/* for now, but for how long? */
		if (PBAD(ike->sa.logger, state == NULL)) {
			return ike->sa.st_state->v2.transitions;
		}
		if (PBAD(ike->sa.logger, state != ike->sa.st_state)) {
			return ike->sa.st_state->v2.transitions;
		}
		if (PBAD(ike->sa.logger, state->v2.transitions != exchange->response)) {
			return ike->sa.st_state->v2.transitions;
		}
		return exchange->response;
	}
	}
	bad_case(v2_msg_role(md));
}
