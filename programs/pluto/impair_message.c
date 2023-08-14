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

static struct direction_impairment outbound_impairments = {
	.name = "outbound",
};

static struct direction_impairment inbound_impairments = {
	.name = "inbound",
};

struct direction_impairment *const message_impairments[] = {
	[IMPAIR_INBOUND_MESSAGE] = &inbound_impairments,
	[IMPAIR_OUTBOUND_MESSAGE] = &outbound_impairments,
};

void add_message_impairment(enum impair_action impair_action,
			    enum impair_message_direction impair_direction,
			    unsigned nr, struct logger *logger)
{
	PASSERT(logger, impair_direction < elemsof(message_impairments));
	struct direction_impairment *direction = message_impairments[impair_direction];
	switch (impair_action) {
	case CALL_IMPAIR_MESSAGE_DROP:
		break;
	default:
		bad_case(impair_action);
	}
	PASSERT(logger, direction != NULL);
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

static bool impair_inbound_message(struct msg_digest *md)
{
	struct message_impairment impairment;
	bool impair = impair_message(pbs_in_all(&md->packet_pbs),
				     &inbound_impairments, &impairment,
				     md->md_logger);
	if (!impair) {
		return false;
	}

	/* hack to also log to whack */

	struct state_filter sf = { .where = HERE, };
	while (next_state_new2old(&sf)) {
		struct state *st = sf.st;
		if (st->st_logger->object_whackfd != NULL ||
		    st->st_logger->global_whackfd != NULL) {
			llog(RC_LOG, st->st_logger, "IMPAIR: drop inbound message %u",
				    impairment.message_nr);
		}
	}
	return true;
}

bool impair_outbound_message(shunk_t message, struct logger *logger)
{
	struct message_impairment impairment; /*ignored*/
	return impair_message(message, &outbound_impairments, &impairment, logger);
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

/*
 * Impair pluto by replaying packets.
 *
 * To make things easier, all packets received are saved, in-order, in
 * a list and then various impair operations iterate over this list.
 *
 * For instance, IKEv1 sends back-to-back packets (see XAUTH).  By
 * replaying them (and everything else) this can simulate what happens
 * when the remote starts re-transmitting them.
 */

static void process_md_clone(struct msg_digest *orig, const char *fmt, ...) PRINTF_LIKE(2);
static void process_md_clone(struct msg_digest *orig, const char *fmt, ...)
{
	/* not whack FD yet is expected to be reset! */
	struct msg_digest *md = clone_raw_md(orig, HERE);

	LLOG_JAMBUF(RC_LOG, md->md_logger, buf) {
		jam_string(buf, "IMPAIR: start processing ");
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);
		jam(buf, " (%d bytes)", (int)pbs_room(&md->packet_pbs));
	}
	if (DBGP(DBG_BASE)) {
		DBG_dump(NULL, md->packet_pbs.start, pbs_room(&md->packet_pbs));
	}

	process_md(md);

	LLOG_JAMBUF(RC_LOG, md->md_logger, buf) {
		jam(buf, "IMPAIR: stop processing ");
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);
	}

	md_delref(&md);
	pexpect(md == NULL);
}

static unsigned long replay_count;

struct replay_entry {
	struct list_entry entry;
	struct msg_digest *md;
	unsigned long nr;
};

static void jam_replay_entry(struct jambuf *buf, const struct replay_entry *r)
{
	jam(buf, "replay packet %lu", r == NULL ? 0L : r->nr);
}

LIST_INFO(replay_entry, entry, replay_info, jam_replay_entry);

static struct list_head replay_packets = INIT_LIST_HEAD(&replay_packets, &replay_info);

static void save_md_for_replay(bool already_impaired, struct msg_digest *md)
{
	if (!already_impaired) {
		struct replay_entry *e = alloc_thing(struct replay_entry, "replay");
		e->md = clone_raw_md(md, HERE);
		e->nr = ++replay_count; /* yes; pre-increment */
		init_list_entry(&replay_info, e, &e->entry); /* back-link */
		insert_list_entry(&replay_packets, &e->entry);
	}
}

bool impair_inbound(struct msg_digest *md)
{
	if (impair_inbound_message(md)) {
		return true;
	}
	bool impaired = false;
	if (impair.replay_duplicates) {
		save_md_for_replay(impaired, md);
		/* MD is the most recent entry */
		struct replay_entry *e = NULL;
		FOR_EACH_LIST_ENTRY_NEW2OLD(e, &replay_packets) {
			process_md_clone(e->md, "original packet");
			process_md_clone(e->md, "duplicate packet");
			break;
		}
		impaired = true;
	}
	if (impair.replay_forward) {
		save_md_for_replay(impaired, md);
		struct replay_entry *e = NULL;
		FOR_EACH_LIST_ENTRY_OLD2NEW(e, &replay_packets) {
			process_md_clone(e->md, "replay forward: packet %lu of %lu",
					 e->nr, replay_count);
		}
		impaired = true;
	}
	if (impair.replay_backward) {
		save_md_for_replay(impaired, md);
		struct replay_entry *e = NULL;
		FOR_EACH_LIST_ENTRY_NEW2OLD(e, &replay_packets) {
			process_md_clone(e->md, "start replay backward: packet %lu of %lu",
					 e->nr, replay_count);
		}
		impaired = true;
	}
	return impaired;
}

void shutdown_impair_message(struct logger *logger)
{
	free_direction(&inbound_impairments, logger);
	free_direction(&outbound_impairments, logger);

	struct replay_entry *e = NULL;
	FOR_EACH_LIST_ENTRY_NEW2OLD(e, &replay_packets) {
		md_delref(&e->md);
		remove_list_entry(&e->entry);
		pfreeany(e);
	}
}
