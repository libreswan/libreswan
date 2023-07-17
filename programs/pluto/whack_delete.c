/* <<ipsec delete <connection> >>, for libreswan
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
 *
 */

#include "whack_connection.h"
#include "whack_delete.h"
#include "show.h"
#include "log.h"
#include "connections.h"
#include "pending.h"

/*
 * Terminate and then delete connections with the specified name.
 */

static bool whack_delete_connection(struct show *s, struct connection **c,
				   const struct whack_message *m UNUSED)
{
	struct logger *logger = show_logger(s);
	connection_attach(*c, logger);

	/*
	 * Let code know of intent.
	 *
	 * Functions such as connection_unroute() don't fiddle policy
	 * bits as they are called as part of unroute/route sequences.
	 */

	del_policy(*c, POLICY_UP);
	del_policy(*c, POLICY_ROUTE);

	if (never_negotiate(*c)) {
		ldbg((*c)->logger, "skipping as never-negotiate");
		PEXPECT(logger, (is_permanent(*c) || is_template(*c)));

		connection_unroute(*c, HERE);
		delete_connection(c);
		return false;
	}

	switch ((*c)->local->kind) {

	case CK_PERMANENT:
		llog(RC_LOG, (*c)->logger, "terminating SAs using this connection");

		remove_connection_from_pending(*c);
		delete_states_by_connection(*c);
		connection_unroute(*c, HERE);

		delete_connection(c);
		return true;

	case CK_GROUP:
		/* little left to do */
		connection_unroute(*c, HERE);
		delete_connection(c);
		return true;

	case CK_TEMPLATE:
		/* also need to unroute */
		connection_unroute(*c, HERE);
		delete_connection(c);
		return true;

	case CK_INSTANCE:
		/*
		 * For CK_INSTANCE, this could also delete the *C
		 * connection.
		 */
		llog(RC_LOG, (*c)->logger, "terminating SAs using this connection");

		remove_connection_from_pending(*c);
		delete_states_by_connection(*c);
		connection_unroute(*c, HERE);

		delete_connection(c);
		return true;

	case CK_LABELED_TEMPLATE:
		/* also need to unroute */

		remove_connection_from_pending(*c);
		delete_states_by_connection(*c);
		connection_unroute(*c, HERE);

		delete_connection(c);
		return true;

	case CK_LABELED_PARENT:
		llog(RC_LOG, (*c)->logger, "terminating SAs using this connection");

		remove_connection_from_pending(*c);
		delete_states_by_connection(*c);
		connection_unroute(*c, HERE);

		delete_connection(c);
		return true;

	case CK_LABELED_CHILD:
		/*
		 * Let the labeled parent, called later, terminate the
		 * entire IKE SA and unroute everything.
		 *
		 * XXX: does this need to stop delete_connection()
		 * deleting the child?
		 */
		PEXPECT(logger, (*c)->config->ike_version == IKEv2);

		remove_connection_from_pending(*c);
		delete_states_by_connection(*c);
		connection_unroute(*c, HERE);

		delete_connection(c);
		return true;

	case CK_INVALID:
		break;
	}
	bad_case((*c)->local->kind);
}

void whack_delete(const struct whack_message *m, struct show *s)
{
	if (m->name == NULL) {
		whack_log(RC_FATAL, s,
			  "received command to delete a connection, but did not receive the connection name - ignored");
		return;
	}

	/*
	 * This is new-to-old which means that instances are processed
	 * before templates.
	 */
	whack_connections_bottom_up(m, s, whack_delete_connection,
				    (struct each) {
					    .log_unknown_name = false,
				    });
}
