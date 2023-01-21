/* connection routing, for libreswan
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

#ifndef CONNECTION_ROUTING_H
#define CONNECTION_ROUTING_H

struct connection;
struct state;

enum connection_action {
	CONNECTION_RETRY,
	/*CONNECTION_REVIVE*/
	CONNECTION_FAIL,
};

extern const struct enum_names connection_action_names;

enum connection_action connection_timeout(struct connection *c, unsigned tries_so_far,
					  struct logger *logger);

#endif
