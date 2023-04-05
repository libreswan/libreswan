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

/*
 * Connection based events and timers.
 */

enum connection_event {
	CONNECTION_NONEVENT,
	CONNECTION_REVIVAL,
};

extern const struct enum_names connection_event_names;

bool connection_event_is_scheduled(const struct connection *c,
				   enum connection_event event);

void schedule_connection_event(const struct connection *c,
			       enum connection_event event, const char *subplot,
			       deltatime_t delay);

void flush_connection_event(const struct connection *c,
			    enum connection_event event);

#endif
