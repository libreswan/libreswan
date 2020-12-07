/* impair message send/recv, for libreswan
 *
 * Copyright (C) 2020  Andrew Cagney
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

#include "impair.h"
#include "lswalloc.h"
#include "passert.h"
#include "lswlog.h"

#include "chunk.h"

#include "defs.h"
#include "demux.h"
#include "impair_message.h"
#include "state.h"
#include "state_db.h"		/* for FOR_EACH_STATE */

/*
 * Track each unique message.
 */

struct message {
	chunk_t body;
	struct message *next;
};

static unsigned message_nr(shunk_t message, struct message **messages)
{
	unsigned nr = 0;
	struct message **mp = messages;
	for (; (*mp) != NULL; mp = &(*mp)->next) {
		nr++;
		struct message *m = (*mp);
		if (hunk_eq(m->body, message)) {
			if (DBGP(DBG_BASE)) {
				DBG_log("matching %u", nr);
				DBG_dump_hunk(NULL, m->body);
			}
			return nr;
		}
	}
	/* append new */
	nr++;
	struct message *m = alloc_thing(struct message, "message");
	m->body = clone_hunk(message, "message-body");
	*mp = m;
	if (DBGP(DBG_BASE)) {
		DBG_log("adding %u", nr);
		DBG_dump_hunk(NULL, m->body);
	}
	return nr;
}

static void free_messages(struct message **messages)
{
	while (*messages != NULL) {
		struct message *m = (*messages);
		*messages = m->next;
		free_chunk_content(&m->body);
		pfree(m);
	}
}

/*
 * Track messages to impair.
 */

struct message_impairment {
	unsigned message_nr;
	struct message_impairment *next;
};

struct direction_impairment {
	struct message_impairment *impairments;
	struct message *messages;
	const char *name;
};

static struct direction_impairment outgoing_impairments = {
	.name = "outgoing",
};

static struct direction_impairment incoming_impairments = {
	.name = "incoming",
};

void add_message_impairment(unsigned nr, enum impair_action action, struct logger *logger)
{
	struct direction_impairment *direction;
	switch (action) {
	case CALL_IMPAIR_DROP_INCOMING:
		direction = &incoming_impairments;
		break;
	case CALL_IMPAIR_DROP_OUTGOING:
		direction = &outgoing_impairments;
		break;
	default:
		bad_case(action);
	}
	llog(RC_LOG, logger, "IMPAIR: will drop %s message %u",
		    direction->name, nr);
	struct message_impairment *m = alloc_thing(struct message_impairment, "impair message");
	m->message_nr = nr;
	m->next = direction->impairments;
	direction->impairments = m;
}

static bool impair_message(shunk_t message, struct direction_impairment *direction,
			   struct message_impairment *impairment,
			   struct logger *logger)
{
	if (direction->impairments == NULL) {
		return false;
	}
	unsigned nr = message_nr(message, &direction->messages);
	dbg("%s message nr is %u", direction->name, nr);
	for (struct message_impairment **mp = &direction->impairments; (*mp) != NULL; mp = &(*mp)->next) {
		struct message_impairment *m = (*mp);
		if (m->message_nr == nr) {
			llog(RC_LOG, logger, "IMPAIR: dropping %s message %u",
				    direction->name, nr);
			/* return details */
			(*impairment) = *m;
			(*impairment).next = NULL;
			/*
			 * Delete each impairment as it is consumed.
			 * This way, at the end of a successful test
			 * no impairments are left.
			 */
			*mp = m->next;
			pfree(m);
			return true;
		}
	}
	return false;
}

bool impair_incoming_message(struct msg_digest *md)
{
	struct message_impairment impairment;
	bool impair = impair_message(pbs_in_as_shunk(&md->packet_pbs),
				     &incoming_impairments, &impairment,
				     md->md_logger);
	if (!impair) {
		return false;
	}

	/* hack to also log to whack */
	struct state *st;
	FOR_EACH_STATE_NEW2OLD(st) {
		if (st->st_logger->object_whackfd != NULL) {
			llog(RC_LOG, st->st_logger, "IMPAIR: drop incoming message %u",
				    impairment.message_nr);
		}
	}
	return true;
}

bool impair_outgoing_message(shunk_t message, struct logger *logger)
{
	struct message_impairment impairment; /*ignored*/
	return impair_message(message, &outgoing_impairments, &impairment, logger);
}

static void free_direction(struct direction_impairment *direction, struct logger *logger)
{
	/*
	 * XXX: free the messages but NOT the impairments.  At the end
	 * of a test run all the impairments should have been consumed
	 * so leaking them acts as an additional red flag.
	 */
	free_messages(&direction->messages);
	if (direction->impairments != NULL) {
		llog(RC_LOG, logger, "IMPAIR: outstanding %s impairment",
			direction->name);
	}
}

void free_impair_message(struct logger *logger)
{
	free_direction(&incoming_impairments, logger);
	free_direction(&outgoing_impairments, logger);
}
