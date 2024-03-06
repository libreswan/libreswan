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

#ifndef CONNECTION_EVENT_H
#define CONNECTION_EVENT_H

#include <stdbool.h>

#include "deltatime.h"

struct connection;
enum connection_event_kind;
struct connection_event;

/*
 * Connection based events and timers.
 */

bool connection_event_is_scheduled(const struct connection *c,
				   enum connection_event_kind event);

void schedule_connection_event(struct connection *c,
			       enum connection_event_kind event,
			       const char *subplot,
			       deltatime_t delay,
			       const char *impair,
			       struct logger *logger);

bool flush_connection_event(struct connection *c,
			    enum connection_event_kind event);
bool flush_connection_events(struct connection *c);

void whack_impair_call_connection_event_handler(struct connection *c,
						enum connection_event_kind event,
						struct logger *logger);

#endif
