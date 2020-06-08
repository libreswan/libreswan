/* <<ipsec suspend <connection> >>, for libreswan
 *
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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
 *
 */

#include "lswcdefs.h"

#include "show.h"
#include "connections.h"
#include "log.h"
#include "whack_suspend.h"
#include "whack_connection.h"
#include "terminate.h"

static unsigned whack_suspend_connection(const struct whack_message *m UNUSED,
					 struct show *s,
					 struct connection *c)
{
	if (c->session == NULL) {
		whack_log(RC_FATAL, s, "no stored ticket, cannot suspend connection");
		return 0; /*doesn't count*/
	}

	llog(RC_LOG, c->logger, "suspending connection - deleting states");
	/* terminate connection, but if an instance, don't delete ourselves */
	del_policy(c, policy.up);
	/* assume caller has a reference to stop C disappearing?!? */
	terminate_connection(c, HERE);
	return 1;
}

void whack_suspend(const struct whack_message *m, struct show *s)
{
	if (m->name == NULL) {
		whack_log(RC_FATAL, s,
			  "received command to suspend a connection, but did not receive the connection name - ignored");
		return;
	}

	/*
	 * This is old-to-new which means that aliases are processed
	 * before templates.
	 */
	whack_connection(m, s, whack_suspend_connection,
			 /*alias_order*/OLD2NEW,
			 (struct each) {0});
}
