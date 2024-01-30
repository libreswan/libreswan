/* route connections, for libreswan
 *
 * Copyright (C) 2023  Andrew Cagney
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

#include <stdbool.h>

#include "whack_route.h"
#include "connections.h"
#include "server.h"		/* for listen; */
#include "show.h"
#include "log.h"
#include "whack_connection.h"

static unsigned whack_route_connection(const struct whack_message *m UNUSED,
				       struct show *s,
				       struct connection *c)
{
	connection_attach(c, show_logger(s));
	if (kernel_route_installed(c)) {
		whack_log(RC_FATAL, s, "connection is already routed (ondemand)");
		connection_detach(c, show_logger(s));
		return 0;
	}
	connection_route(c, HERE);
	connection_detach(c, show_logger(s));
	return 1; /* the connection counts */
}

void whack_route(const struct whack_message *m, struct show *s)
{
	if (!listening) {
		whack_log(RC_DEAF, s,
			  "need --listen before --route");
		return;
	}

	if (m->name == NULL) {
		/* leave bread crumb */
		whack_log(RC_FATAL, s,
			  "received command to route connection, but did not receive the connection name - ignored");
		return;
	}

	whack_connections_bottom_up(m, s, whack_route_connection,
				    (struct each) {
					    .log_unknown_name = true,
				    });
}
