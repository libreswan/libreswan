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

static timeout_cb connection_event_handler;

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
	co_serial_t serialno;
	const char *subplot;
	struct timeout *timeout;
};

static void jam_event_connection(struct jambuf *buf, const struct event_connection *event)
{
	jam(buf, PRI_CO" %s", pri_co(event->serialno),
	    enum_name_short(&connection_event_names, event->event));
}

LIST_INFO(event_connection, entry, event_connection_info, jam_event_connection);
static struct list_head connection_events =
	INIT_LIST_HEAD(&connection_events, &event_connection_info);

void schedule_connection_event(const struct connection *c,
			       enum connection_event event, const char *subplot,
			       deltatime_t delay)
{
	struct event_connection *d = alloc_thing(struct event_connection, "data");
	d->serialno = c->serialno;
	d->event = event;
	d->subplot = subplot;
	init_list_entry(&event_connection_info, d, &d->entry);
	insert_list_entry(&connection_events, &d->entry);
	schedule_timeout(enum_name(&connection_event_names, event),
			 &d->timeout, delay,
			 connection_event_handler, d);
}

void connection_event_handler(void *arg, struct logger *logger)
{
	/* save event details*/
	struct event_connection *tmp = arg;
	remove_list_entry(&tmp->entry);
	enum connection_event event = tmp->event;
	co_serial_t serialno = tmp->serialno;
	const char *subplot = tmp->subplot;
	passert(tmp->timeout != NULL);
	destroy_timeout(&tmp->timeout);
	pfree(tmp); tmp = NULL;

	/* is connection still around? */
	struct connection *c = connection_by_serialno(serialno);
	if (c == NULL) {
		llog_pexpect(logger, HERE, PRI_CO" no longer exists",
			     pri_co(serialno));
		return;
	}

	ldbg(logger, "%s() dispatching %s to "PRI_CO,
	     __func__,
	     enum_name_short(&connection_event_names, event),
	     pri_co(serialno));

	switch (event) {
	case CONNECTION_NONEVENT:
		break;
	case CONNECTION_REVIVAL:
		revive_connection(c, subplot, logger);
		break;
	}
}

bool connection_event_is_scheduled(const struct connection *c,
				   enum connection_event event)
{
	struct event_connection *e;
	FOR_EACH_LIST_ENTRY_OLD2NEW(e, &connection_events) {
		if (e->serialno == c->serialno &&
		    e->event == event) {
			return true;
		}
	}
	return false;
}

void flush_connection_event(const struct connection *c,
			    enum connection_event event)
{

	struct event_connection *e;
	FOR_EACH_LIST_ENTRY_OLD2NEW(e, &connection_events) {
		if (e->serialno == c->serialno &&
		    e->event == event) {
			remove_list_entry(&e->entry);
			destroy_timeout(&e->timeout);
			pfree(e);
		}
	}
}
