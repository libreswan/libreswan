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
#include "ikev2_delete.h"
#include "ikev1.h"		/* for send_v1_delete() */
#include "connection_event.h"

/*
 * Terminate and then delete connections with the specified name.
 */

static bool whack_delete_connection(struct show *s, struct connection *c,
				    const struct whack_message *m UNUSED)
{
	struct logger *logger = show_logger(s);
	connection_attach(c, logger);

	/*
	 * Let code know of intent.
	 *
	 * Functions such as connection_unroute() don't fiddle policy
	 * bits as they are called as part of unroute/route sequences.
	 */
	del_policy(c, POLICY_UP);
	del_policy(c, POLICY_ROUTE);

	switch (c->local->kind) {

	case CK_PERMANENT:
		if (never_negotiate(c)) {
			ldbg(c->logger, "skipping as never-negotiate");
			break;
		}
		llog(RC_LOG, c->logger, "terminating SAs using this connection");
		remove_connection_from_pending(c);
		whack_connection_delete_states(c, HERE);
		break;

	case CK_INSTANCE:
	case CK_LABELED_PARENT:
		llog(RC_LOG, c->logger, "terminating SAs using this connection");
		remove_connection_from_pending(c);
		whack_connection_delete_states(c, HERE);
		break;

	case CK_GROUP:
	case CK_TEMPLATE:
	case CK_LABELED_TEMPLATE:
	case CK_LABELED_CHILD:
		break;

	case CK_INVALID:
		bad_case(c->local->kind);
	}

	connection_unroute(c, HERE); /* some times redundant */

	/*
	 * Flush any lurking revivals.
	 *
	 * Work-around github/1255 and ikev2-delete-02 where:
	 *
	 * teardown_ipsec_kernel_policies() doesn't schedule a revival
	 * for the Child SA but should.
	 *
	 * a later delete_ike schedules a revival but shouldn't.
	 */
	if (flush_connection_events(c)) {
		ldbg(logger, "flushed bogus pending events");
	}

	struct connection *cc = c; /* hack part #1 */
	if (!is_instance(cc)) {
		/*
		 * A non-instance connection has a floating reference;
		 * need to delete that so that caller's delref deletes
		 * the connection.
		 */
		connection_delref(&cc, cc->logger);
	}

	/*
	 * hack part #2; caller is left with the only reference.
	 */
	PEXPECT(c->logger, refcnt_peek(&c->refcnt) == 1);
	return true;
}

void whack_delete(const struct whack_message *m, struct show *s,
		  bool log_unknown_name)
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
					    .log_unknown_name = log_unknown_name,
				    });
}
