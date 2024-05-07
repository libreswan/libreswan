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
#include "iface.h"			/* for struct iface_endpoint */

static void connection_event_handler(void *arg, const struct timer_event *event);

struct connection_event {
	enum connection_event_kind kind;
	struct connection *connection;
	const char *subplot;
	struct timeout *timeout;
	struct logger *logger;
};

static void jam_connection_event(struct jambuf *buf, const struct connection_event *event)
{
	const struct connection *c = event->connection;
	/* currently only one */
	jam_string(buf, " ");
	jam_enum_short(buf, &connection_event_kind_names, event->kind);
	switch (event->kind) {
	case CONNECTION_REVIVAL:
		if (c->redirect.attempt > 0) {
			jam_string(buf, "; redirect");
			jam(buf, " attempt %u", c->redirect.attempt);
			jam_string(buf, " from ");
			jam_address_sensitive(buf, &c->redirect.old_gw_address);
			jam_string(buf, " to ");
			jam_address_sensitive(buf, &c->redirect.ip);
		}
		if (c->revival.attempt > 0) {
			jam(buf, "; attempt %u", c->revival.attempt);
			jam_string(buf, " next in ");
			jam_deltatime(buf, c->revival.delay);
			jam_string(buf, "s");
			if (c->revival.remote.is_set) {
				jam_string(buf, " to ");
				jam_endpoint_sensitive(buf, &c->revival.remote);
			}
			if (c->revival.local != NULL) {
				jam_string(buf, " via ");
				jam_endpoint_sensitive(buf, &c->revival.local->local_endpoint);
			}
		}
		break;
	}
	jam_string(buf, "; ");
	jam_string(buf, event->subplot);
}

void schedule_connection_event(struct connection *c,
			       enum connection_event_kind event_kind,
			       const char *subplot,
			       deltatime_t delay,
			       const char *impair, struct logger *logger)
{
	struct connection_event *d = alloc_thing(struct connection_event, "data");
	connection_buf cb;
	enum_buf kb;
	d->logger = string_logger(HERE, "event %s for "PRI_CONNECTION,
				  str_enum(&connection_event_kind_names, event_kind, &kb),
				  pri_connection(c, &cb));
	d->kind = event_kind;
	d->subplot = subplot;
	d->connection = connection_addref(c, d->logger);
	c->events[event_kind] = d;

	if (impair != NULL) {
		llog(RC_LOG, logger,
		     "IMPAIR: %s: skip scheduling %s event",
		     impair, impair);
		return;
	}

	schedule_timeout(str_enum(&connection_event_kind_names, event_kind, &kb),
			 &d->timeout, delay,
			 connection_event_handler, d);
}

static void discard_connection_event(struct connection_event **e)
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

static void delete_connection_event(struct connection_event **e)
{
	discard_connection_event(e);
}

static void dispatch_connection_event(struct connection_event *e,
				      const threadtime_t *inception)
{
	ldbg(e->logger, "dispatching");

	/* make it invisible */
	e->connection->events[e->kind] = NULL;

	switch (e->kind) {
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
						enum connection_event_kind event_kind,
						struct logger *logger)
{
	struct connection_event *event = c->events[event_kind];
	if (event != NULL) {
		threadtime_t inception = threadtime_start();
		LLOG_JAMBUF(RC_LOG, logger, buf) {
			jam_string(buf, "IMPAIR: dispatch");
			jam_connection_event(buf, event);
		}
		/* dispatch will delete */
		dispatch_connection_event(event, &inception);
		return;
	}
	enum_buf eb;
	llog(RC_COMMENT, logger, "IMPAIR: no %s event for connection found",
	     str_enum_short(&connection_event_kind_names, event_kind, &eb));
}

bool connection_event_is_scheduled(const struct connection *c,
				   enum connection_event_kind event)
{
	return (c->events[event] != NULL);
}

bool flush_connection_event(struct connection *c,
			    enum connection_event_kind event_kind)
{
	if (c->events[event_kind] != NULL) {
		delete_connection_event(&c->events[event_kind]);
		return true;
	}
	return false;
}

bool flush_connection_events(struct connection *c)
{
	bool flushed = false;
	for (enum connection_event_kind e = 0; e < CONNECTION_EVENT_KIND_ROOF; e++) {
		flushed |= flush_connection_event(c, e);

	}
	return flushed;
}
