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

struct connection_event_event {
	enum connection_event event;
	struct connection *connection;
	const char *subplot;
	struct timeout *timeout;
	struct logger *logger;
};

void schedule_connection_event(struct connection *c,
			       enum connection_event event, const char *subplot,
			       deltatime_t delay,
			       const char *impair, struct logger *logger)
{
	struct connection_event_event *d = alloc_thing(struct connection_event_event, "data");
	connection_buf cb;
	d->logger = string_logger(HERE, "event %s for "PRI_CONNECTION,
				  enum_name(&connection_event_names, event),
				  pri_connection(c, &cb));
	d->event = event;
	d->subplot = subplot;
	d->connection = connection_addref(c, d->logger);
	c->events[event] = d;

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

static void discard_connection_event(struct connection_event_event **e)
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

static void delete_connection_event(struct connection_event_event **e)
{
	discard_connection_event(e);
}

static void dispatch_connection_event(struct connection_event_event *e,
				      const threadtime_t *inception)
{
	ldbg(e->logger, "dispatching");

	/* make it invisible */
	e->connection->events[e->event] = NULL;

	switch (e->event) {
	case CONNECTION_REVIVAL:
		revive_connection(e->connection, e->subplot, inception);
		break;
	}

	discard_connection_event(&e);
}

void connection_event_handler(void *arg, const struct timer_event *event)
{
	dispatch_connection_event(arg, &event->inception);
}

void whack_impair_call_connection_event_handler(struct connection *c,
						enum connection_event event,
						struct logger *logger)
{
	struct connection_event_event *e = c->events[event];
	if (e != NULL) {
		threadtime_t inception = threadtime_start();
		enum_buf eb;
		llog(RC_COMMENT, logger, "IMPAIR: dispatch %s event",
		     str_enum_short(&connection_event_names, event, &eb));
		/* dispatch will delete */
		dispatch_connection_event(e, &inception);
		return;
	}
	enum_buf eb;
	llog(RC_COMMENT, logger, "IMPAIR: no %s event for connection found",
	     str_enum_short(&connection_event_names, event, &eb));
}

bool connection_event_is_scheduled(const struct connection *c,
				   enum connection_event event)
{
	return (c->events[event] != NULL);
}

bool flush_connection_event(struct connection *c,
			    enum connection_event event)
{
	if (c->events[event] != NULL) {
		delete_connection_event(&c->events[event]);
		return true;
	}
	return false;
}

bool flush_connection_events(struct connection *c)
{
	bool flushed = false;
	for (enum connection_event e = 0; e < CONNECTION_EVENT_ROOF; e++) {
		flushed |= flush_connection_event(c, e);

	}
	return flushed;
}
