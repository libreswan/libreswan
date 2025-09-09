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
#include "visit_connection.h"
#include "ipsec_interface.h"

static unsigned maybe_route_connection(struct connection *c)
{
	if (is_instance(c)) {
		ldbg(c->logger, "instances are not routed");
		return 0; /* not counted */
	}

	if (c->policy.route) {
		llog(RC_LOG, c->logger, "connection is already routed");
		return 0; /* not counted */
	}

	if (c->routing.state == RT_UNROUTED) {
		/* both install policy and route connection */
		connection_route(c, HERE);
		return 1; /* counted */
	}

	if (kernel_route_installed(c)) {
		/*
		 * Need to stop the connection unrouting.
		 *
		 * For instance, a connection in state ROUTED_TUNNEL
		 * and with -ROUTE will still have the kernel route
		 * and policy installed.  Add +ROUTE so that when the
		 * connection fails or is taken down, ondemand routing
		 * remains in place.
		 *
		 * Note that is includes states such as
		 * ROUTED_ONDEMAND which happens when a connection as
		 * +UP -ROUTE.
		 */
		add_policy(c, policy.route);
		llog(RC_LOG, c->logger, "connection will remain routed");
		return 1;
	}

	/*
	 * These are assumed to be in-flight connections.
	 */
	llog(RC_LOG, c->logger, "connection marked for routing");
	return 1;
}

static unsigned whack_route_connection(const struct whack_message *m UNUSED,
				       struct show *s,
				       struct connection *c,
				       struct connection_visitor_context *context UNUSED)
{
	connection_attach(c, show_logger(s));
	unsigned rc = maybe_route_connection(c);
	connection_detach(c, show_logger(s));
	return rc;
}

void whack_route(const struct whack_message *m, struct show *s)
{
	if (!listening) {
		show_rc(RC_DEAF, s,
			"need --listen before --route");
		return;
	}

	if (m->name == NULL) {
		/* leave bread crumb */
		show_rc(RC_FATAL, s,
			"received command to route connection, but did not receive the connection name - ignored");
		return;
	}

	whack_connection_trees(m, s, OLD2NEW,
			       whack_route_connection, NULL,
			       (struct each) {
				       .log_unknown_name = true,
			       });
}
