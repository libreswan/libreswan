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

static bool whack_unroute_connection(struct show *s, struct connection **cp,
				     const struct whack_message *m UNUSED)
{
	connection_attach((*cp), show_logger(s));
	/*
	 * Let code know of intent.
	 *
	 * Functions such as connection_unroute() don't fiddle policy
	 * bits as they are called as part of unroute/route sequences.
	 */
	del_policy((*cp), POLICY_ROUTE);
	connection_unroute((*cp), HERE);
	connection_detach((*cp), show_logger(s));
	return true; /* ok; keep going */
}


void whack_unroute(const struct whack_message *m, struct show *s)
{
	if (m->name == NULL) {
		/* leave bread crumb */
		whack_log(RC_FATAL, s,
			  "received command to unroute connection, but did not receive the connection name - ignored");
		return;
	}

	whack_each_connection(m, s, whack_unroute_connection,
			      (struct each) {
				      .log_unknown_name = true,
				      .skip_instances = true,
			      });
}
