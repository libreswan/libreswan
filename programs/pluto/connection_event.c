/* connection events, for libreswan
 *
 * Copyright (C) 2023 Andrew Cagney
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

#include "enum_names.h"

#include "defs.h"

#include "log.h"
#include "server.h"
#include "connections.h"
#include "connection_event.h"
#include "revival.h"			/* for revive_connection() */
#include "list_entry.h"

static void connection_event_handler(void *arg, const struct timer_event *event);

static const char *connection_event_name[] = {
#define S(E) [E] = #E
	S(CONNECTION_NONEVENT),
	S(CONNECTION_REVIVAL),
#undef S
};

const struct enum_names connection_event_names = {
	CONNECTION_NONEVENT, CONNECTION_REVIVAL,
	ARRAY_REF(connection_event_name),
	"CONNECTION_", NULL,
};

struct event_connection {
	struct list_entry entry;
	enum connection_event event;
	struct connection *connection;
	const char *subplot;
	struct timeout *timeout;
	struct logger *logger;
};

static size_t jam_event_connection(struct jambuf *buf, const struct event_connection *event)
{
	return jam(buf, PRI_CO" %s", pri_connection_co(event->connection),
		   enum_name_short(&connection_event_names, event->event));
}

LIST_INFO(event_connection, entry, event_connection_info, jam_event_connection);
static struct list_head connection_events =
	INIT_LIST_HEAD(&connection_events, &event_connection_info);

void schedule_connection_event(struct connection *c,
			       enum connection_event event, const char *subplot,
			       deltatime_t delay,
			       const char *impair, struct logger *logger)
{
	struct event_connection *d = alloc_thing(struct event_connection, "data");
	connection_buf cb;
	d->logger = string_logger(null_fd, HERE, "event %s for "PRI_CONNECTION": ",
				  enum_name(&connection_event_names, event),
				  pri_connection(c, &cb));
	d->event = event;
	d->subplot = subplot;
	d->connection = connection_addref(c, d->logger);
	init_list_entry(&event_connection_info, d, &d->entry);
	insert_list_entry(&connection_events, &d->entry);

	if (impair != NULL) {
		llog(RC_LOG, logger,
		     "IMPAIR: %s: skip scheduling %s event",
		     impair, impair);
		return;
	}

	schedule_timeout(enum_name(&connection_event_names, event),
			 &d->timeout, delay,
			 connection_event_handler, d);
}

static void discard_connection_event(struct event_connection **e)
{
	/*
	 * When impaired, .timeout is NULL but destroy_timeout()
	 * handles that.
	 */
	destroy_timeout(&(*e)->timeout);
	connection_delref(&(*e)->connection, (*e)->logger);
	free_logger(&(*e)->logger, HERE);
	pfree(*e);
	*e = NULL;
}

static void delete_connection_event(struct event_connection **e)
{
	remove_list_entry(&(*e)->entry);
	discard_connection_event(e);
}

void connection_event_handler(void *arg, const struct timer_event *event)
{
	/* save event details*/
	struct event_connection *e = arg;

	ldbg(e->logger, "dispatching");

	/* make it invisible */
	remove_list_entry(&e->entry);

	switch (e->event) {
	case CONNECTION_NONEVENT:
		break;
	case CONNECTION_REVIVAL:
		revive_connection(e->connection, e->subplot, event);
		break;
	}

	discard_connection_event(&e);
}

bool connection_event_is_scheduled(const struct connection *c,
				   enum connection_event event)
{
	struct event_connection *e;
	FOR_EACH_LIST_ENTRY_OLD2NEW(e, &connection_events) {
		if (e->connection == c &&
		    e->event == event) {
			return true;
		}
	}
	return false;
}

bool flush_connection_event(const struct connection *c,
			    enum connection_event event)
{
	bool flushed = false;
	struct event_connection *e;
	FOR_EACH_LIST_ENTRY_OLD2NEW(e, &connection_events) {
		if (e->connection == c &&
		    e->event == event) {
			delete_connection_event(&e);
			flushed = true;
		}
	}
	return flushed;
}

void flush_connection_events(const struct connection *c)
{
	struct event_connection *e;
	FOR_EACH_LIST_ENTRY_OLD2NEW(e, &connection_events) {
		if (e->connection == c) {
			delete_connection_event(&e);
		}
	}
}
