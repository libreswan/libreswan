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

#include "whack_unroute.h"
#include "connections.h"
#include "show.h"
#include "log.h"
#include "whack_connection.h"

static unsigned whack_unroute_connection(const struct whack_message *m UNUSED,
					 struct show *s,
					 struct connection *c)
{
	struct logger *logger = show_logger(s);
	switch (c->local->kind) {

	case CK_TEMPLATE:
	case CK_LABELED_TEMPLATE:
	case CK_PERMANENT:
		/*
		 * Let code know of intent.
		 *
		 * Functions such as connection_unroute() don't fiddle
		 * policy bits as they are called as part of
		 * unroute/route sequences.
		 */
		connection_attach(c, show_logger(s));
		del_policy(c, POLICY_ROUTE);
		connection_unroute(c, HERE);
		connection_detach(c, show_logger(s));
		return 1; /* the connection counts */

	case CK_LABELED_PARENT:
	case CK_LABELED_CHILD:
	case CK_INSTANCE:
		/*
		 * Skip instances, why?
		 *
		 * This assumes that an instance was routed by its
		 * template?  And hence only templates and permanents
		 * need unrouting?
		 */
		connection_attach(c, logger);
		llog(RC_LOG, c->logger, "cannot initiate");
		connection_detach(c, logger);
		return 0; /* the connection doesn't count */

	case CK_GROUP:
		return whack_connection_instances(m, s, c, whack_unroute_connection);

	case CK_INVALID:
		break;
	}
	bad_enum(show_logger(s), &connection_kind_names, c->local->kind);
}

void whack_unroute(const struct whack_message *m, struct show *s)
{
	if (m->name == NULL) {
		/* leave bread crumb */
		whack_log(RC_FATAL, s,
			  "received command to unroute connection, but did not receive the connection name - ignored");
		return;
	}

	whack_connection(m, s, whack_unroute_connection,
			 (struct each) {
				 .log_unknown_name = true,
			 });
}
