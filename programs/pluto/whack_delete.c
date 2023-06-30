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

#include "rcv_whack.h"
#include "whack_delete.h"
#include "show.h"
#include "log.h"
#include "connections.h"
#include "pending.h"

/*
 * Terminate and then delete connections with the specified name.
 */

static void terminate_connection(struct connection **c, struct logger *logger)
{
	connection_attach(*c, logger);

	llog(RC_LOG, (*c)->logger, "terminating SAs using this connection");
	del_policy(*c, POLICY_UP);
	remove_connection_from_pending(*c);

	/*
	 * For CK_INSTANCE, this could also delete the *C connection.
	 */
	delete_states_by_connection(c);

	connection_detach(*c, logger);
}

static void terminate_connections(struct connection **c, struct logger *logger, where_t where)
{
	switch ((*c)->local->kind) {
	case CK_PERMANENT:
	case CK_INSTANCE:
	case CK_LABELED_PARENT:
	case CK_LABELED_CHILD:
		terminate_connection(c, logger); /* could delete C! */
		return;
	case CK_TEMPLATE:
	case CK_GROUP:
	case CK_LABELED_TEMPLATE:
	{
		struct connection_filter cq = {
			.clonedfrom = *c,
			.where = HERE,
		};
		while (next_connection_old2new(&cq)) {
			terminate_connections(&cq.c, logger, where);
		}
		return;
	}
	case CK_INVALID:
		break;
	}
	bad_case((*c)->local->kind);
}

static bool whack_delete_connection(struct show *s, struct connection **c,
				   const struct whack_message *m UNUSED)
{
	terminate_connections(c, show_logger(s), HERE);
	if (*c != NULL) {
		connection_attach(*c, show_logger(s));
		delete_connection(c);
	}
	return true;
}

void whack_delete(const struct whack_message *m, struct show *s)
{
	if (m->name == NULL) {
		whack_log(RC_FATAL, s,
			  "received whack command to delete a connection, but did not receive the connection name - ignored");
		return;
	}

	whack_each_connection(m, s, whack_delete_connection,
			      (struct each) {
				      .log_unknown_name = false,
				      .skip_instances = true,
			      });
}
