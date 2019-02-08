/* IKEv2 Message ID tracking, for libreswan
 *
 * Copyright (C) 2019 Andrew Cagney
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

#include "lswlog.h"
#include "defs.h"
#include "state.h"
#include "demux.h"
#include "connections.h"
#include "ikev2_msgid.h"

/*
 * Dump the MSGIDs along with any changes.
 *
 * Why not just dump the one that changed in the calling function?
 * Because MSGIDs have this strange habbit of mysteriously changing
 * between calls.
 */

static void fmt_msgids(struct lswlog *buf,
		       const char *what, enum message_role message, intmax_t msgid,
		       struct ike_sa *ike, const struct v2_msgids *old)

{
	lswlogf(buf, "Message ID: IKE #%lu %s",
		ike->sa.st_serialno,
		ike->sa.st_finite_state->fs_short_name);

	lswlogf(buf, "; %s ", what);
	switch (message) {
	case MESSAGE_REQUEST: lswlogf(buf, "request"); break;
	case MESSAGE_RESPONSE: lswlogf(buf, "response"); break;
	case NO_MESSAGE: lswlogf(buf, "no-message"); break;
	default: bad_case(message);
	}
	lswlogf(buf, " msgid=%jd", msgid);

	lswlogf(buf, "; initiator:");
	lswlogf(buf, " sent=%jd", old->initiator.sent);
	if (old->initiator.sent != ike->sa.st_v2_msgids.initiator.sent) {
		lswlogf(buf, "->%jd", ike->sa.st_v2_msgids.initiator.sent);
	}
	lswlogf(buf, " recv=%jd", old->initiator.recv);
	if (old->initiator.recv != ike->sa.st_v2_msgids.initiator.recv) {
		lswlogf(buf, "->%jd", ike->sa.st_v2_msgids.initiator.recv);
	}

	lswlogf(buf, "; responder:");
	lswlogf(buf, " sent=%jd", old->responder.sent);
	if (old->responder.sent != ike->sa.st_v2_msgids.responder.sent) {
		lswlogf(buf, "->%jd", ike->sa.st_v2_msgids.responder.sent);
	}
	lswlogf(buf, " recv=%jd", old->responder.recv);
	if (old->responder.recv != ike->sa.st_v2_msgids.responder.recv) {
		lswlogf(buf, "->%jd", ike->sa.st_v2_msgids.responder.recv);
	}
}

/*
 * Maintain or reset Message IDs.
 *
 * When resetting, need to fudge things up sufficient to fool
 * ikev2_update_msgid_counters(() into thinking that this is a shiny
 * new init request.
 */

void v2_msgid_init(struct ike_sa *ike)
{
	intmax_t old_request = ike->sa.st_v2_msgids.current_request;
	struct v2_msgids old = ike->sa.st_v2_msgids;
	static const struct v2_msgids empty_v2_msgids = {
		.current_request = -1,
		.initiator = {
			.sent = -1,
			.recv = -1,
		},
		.responder = {
			.sent = -1,
			.recv = -1,
		},
	};
	ike->sa.st_v2_msgids = empty_v2_msgids;
	if (DBGP(DBG_BASE)) {
		LSWLOG_DEBUG(buf) {
			/* pretend there's a sender */
			fmt_msgids(buf, "initializing", NO_MESSAGE, -1, ike, &old);
			fmt(buf, "; current_request=%jd", old_request);
			if (old_request != ike->sa.st_v2_msgids.current_request) {
				fmt(buf, "->%jd", ike->sa.st_v2_msgids.current_request);
			}
		}
	}
}

#if 0
static void schedule_next_send(struct ike_sa *ike)
{
	msgid_t unack = (ike->sa.st_v2_msgids.initiator.sent -
			 ike->sa.st_v2_msgids.initiator.recv);
	while (unack < ike->sa.st_connection->ike_window) {
		if (ike->sa.send_next_ix == NULL) {
			break;
		}
		/* get next from list */
		so_serial_t child_so = ike->sa.send_next_ix->st_serialno;
		{
			struct initiate_list *p = ike->sa.send_next_ix;
			ike->sa.send_next_ix = p->next;
			pfree(p);
		}
		struct state *child = state_with_serialno(child_so);
		if (child == NULL) {
			dbg("can't send for #%lu using parent #%lu as it disappeared",
			    child_so, ike->sa.st_serialno);
			continue;
		}
		dbg("scheduling CHILD SA #%lu send using IKE SA #%lu next message id="PRI_MSGID", unack="PRI_MSGID,
		    child->st_serialno, ike->sa.st_serialno,
		    ike->sa.st_v2_msgids.initiator.sent + 1,
		    unack);
		event_force(EVENT_v2_SEND_NEXT_IKE, child);
		unack++;
	}
}
#endif

void v2_msgid_update_recv(struct ike_sa *ike, struct state *receiver,
			  struct msg_digest *md)
{
	/* extend msgid */
	intmax_t msgid = md->hdr.isa_msgid;
	struct v2_msgids old = ike->sa.st_v2_msgids;
	struct v2_msgids *new = &ike->sa.st_v2_msgids;
	intmax_t old_receiver_request = receiver->st_v2_msgids.current_request;

	enum message_role role = v2_msg_role(md);

	switch (role) {
	case MESSAGE_REQUEST:
		/* last request we received */
		new->responder.recv = msgid;
		/* extend st_msgid_lastrecv */
		if (ike->sa.st_msgid_lastrecv != new->responder.recv) {
			dbg("Message ID: IKE #%lu lastrecv "PRI_MSGID" == responder.recv %jd",
			    ike->sa.st_serialno,
			    ike->sa.st_msgid_lastrecv,
			    new->responder.recv);
		}
		break;
	case MESSAGE_RESPONSE:
		/* last response we received */
		new->initiator.recv = msgid;
		/* extend st_msgid_lastack */
		if (DBGP(DBG_BASE) && ike->sa.st_msgid_lastack != new->initiator.recv) {
			PEXPECT_LOG("Message ID: IKE #%lu lastack "PRI_MSGID" == initiator.recv %jd",
				    ike->sa.st_serialno,
				    ike->sa.st_msgid_lastack,
				    new->initiator.recv);
		}
		/*
		 * Since the response has been successfully processed,
		 * clear CURRENT_REQUEST.  This way duplicate
		 * responses get discarded as there is no receiving
		 * state.
		 *
		 * XXX: Unfortunately the record 'n' send code throws
		 * a spanner in the works.  It calls update_send()
		 * before update_recv() breaking the assumption that
		 * CURRENT_REQUEST is the old MSGID.
		 */
		if (old_receiver_request > msgid) {
			/*
			 * Hack around record 'n' send calling
			 * update_sent() (setting CURRENT_REQUEST to
			 * the next request) midway through
			 * processing.
			 *
			 * Getting rid of record 'n' send will fix
			 * this hack.
			 */
			dbg("Message ID: XXX: IKE #%lu receiver #%lu: expecting current_request %jd == msgid %jd but record 'n' called update_sent() before update_recv()",
			    ike->sa.st_serialno, receiver->st_serialno,
			    old_receiver_request, msgid);
		} else {
			if (DBGP(DBG_BASE) && old_receiver_request != msgid) {
				PEXPECT_LOG("Message ID: IKE #%lu receiver #%lu: current_request %jd == msgid %jd",
					    ike->sa.st_serialno, receiver->st_serialno,
					    old_receiver_request, msgid);
			}
			receiver->st_v2_msgids.current_request = -1;
		}
		/* this is what matters */
		pexpect(receiver->st_v2_msgids.current_request != msgid);
		break;
	case NO_MESSAGE:
		dbg("Message ID: IKE #%lu skipping update_recv as MD is fake",
		    ike->sa.st_serialno);
		return;
	default:
		bad_case(role);
	}

	if (DBGP(DBG_BASE)) {
		LSWLOG_DEBUG(buf) {
			fmt_msgids(buf, "receiving", role, msgid, ike, &old);
			if (old_receiver_request != receiver->st_v2_msgids.current_request) {
				fmt(buf, "; receiver #%lu current_request=%jd->%jd",
				    receiver->st_serialno, old_receiver_request,
				    receiver->st_v2_msgids.current_request);
			}
		}
	}
}

void v2_msgid_update_sent(struct ike_sa *ike, struct state *sender,
			  struct msg_digest *md, enum message_role sending)
{
	struct v2_msgids old = ike->sa.st_v2_msgids;
	struct v2_msgids *new = &ike->sa.st_v2_msgids;
	intmax_t old_sender_request = sender->st_v2_msgids.current_request;
	intmax_t msgid;
	switch (sending) {
	case MESSAGE_REQUEST:
		/*
		 * pluto is initiating a new exchange.
		 *
		 * Use the next Message ID (which should be what was
		 * used by the code emitting the message request)
		 */
		msgid = new->initiator.sent + 1;
		sender->st_v2_msgids.current_request = new->initiator.sent = msgid;
		/* extend st_msgid */
		if (DBGP(DBG_BASE) && sender->st_msgid != sender->st_v2_msgids.current_request) {
			PEXPECT_LOG("Message ID: sender #%lu st_msgid "PRI_MSGID" == current_request %jd",
				    sender->st_serialno,
				    sender->st_msgid,
				    sender->st_v2_msgids.current_request);
		}
		/* extend st_msgid_nextuse */
		if (DBGP(DBG_BASE) && ike->sa.st_msgid_nextuse != new->initiator.sent + 1) {
			PEXPECT_LOG("Message ID: IKE #%lu nextuse "PRI_MSGID" == initiator.sent %jd+1",
				    ike->sa.st_serialno,
				    ike->sa.st_msgid_nextuse,
				    new->initiator.sent);
		}
#if 0
		/*
		 * XXX: The record 'n' send code calls update_send()
		 * before update_recv() breaking CURRENT_REQUEST's
		 * expected sequence OLD-MSGID -> -1 -> NEW-MSGID.
		 */
		if (DBGP(DBG_BASE) && old_sender_request != -1) {
			PEXPECT_LOG("Message ID: IKE #%lu sender #%lu current_request %jd == -1",
				    ike->sa.st_serialno, sender->st_serialno,
				    old_sender_request);
		}
#else
		if (old_sender_request != -1) {
			dbg("Message ID: XXX: IKE #%lu sender #%lu expecting current_request %jd == -1 but record 'n' send out-of-order",
			    ike->sa.st_serialno, sender->st_serialno,
			    old_sender_request);
		}
#endif
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
		passert(md != NULL);
		pexpect(v2_msg_role(md) == MESSAGE_REQUEST);
		/* extend isa_msgid */
		msgid = md->hdr.isa_msgid;
		new->responder.sent = msgid;
		/* extend st_msgid_lastreplied */
		if (DBGP(DBG_BASE) && ike->sa.st_msgid_lastreplied != new->responder.sent) {
			PEXPECT_LOG("Message ID: IKE #%lu lastreplied "PRI_MSGID" == responder.sent %jd",
				    ike->sa.st_serialno,
				    ike->sa.st_msgid_lastreplied,
				    new->responder.sent);
		}
		break;
	case NO_MESSAGE:
		dbg("Message ID: IKE #%lu sender #%lu skipping update_send as nothing to send",
		    ike->sa.st_serialno, sender->st_serialno);
		return;
	default:
		bad_case(sending);
	}

	if (DBGP(DBG_BASE)) {
		LSWLOG_DEBUG(buf) {
			fmt_msgids(buf, "sending", sending, msgid, ike, &old);
			if (old_sender_request != sender->st_v2_msgids.current_request) {
				fmt(buf, "; sender #%lu current_request=%jd->%jd",
				    sender->st_serialno, old_sender_request,
				    sender->st_v2_msgids.current_request);
			}
		}
	}
}
