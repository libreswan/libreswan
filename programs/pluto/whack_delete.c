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
#include "ikev1.h"			/* for established_isakmp_for_state() */
#include "ikev1_delete.h"		/* for llog_n_maybe_send_v1_delete() */
#include "connection_event.h"
#include "terminate.h"			/* for terminate_connection_states() */

/*
 * Terminate and then delete connections with the specified name.
 */

static unsigned whack_delete_one_connection(const struct whack_message *m UNUSED,
					    struct show *s,
					    struct connection *c)
{
	struct logger *logger = show_logger(s);
	connection_attach(c, logger);

	/*
	 * Let code know of intent.
	 *
	 * Functions such as connection_unroute() don't fiddle policy
	 * bits as they are called as part of unroute/route sequences.
	 */
	del_policy(c, policy.up);
	del_policy(c, policy.route);

	if (never_negotiate(c)) {
		ldbg(c->logger, "skipping as never-negotiate");
		connection_unroute(c, HERE); /* some times redundant */
	} else {
		/* announce the change */
		switch (c->local->kind) {
		case CK_INSTANCE:
		case CK_PERMANENT:
		case CK_LABELED_PARENT:
			llog(RC_LOG, c->logger, "terminating SAs using this connection");
			break;
		default:
			break;
		}

		/* flush things */
		switch (c->local->kind) {
		case CK_PERMANENT:
		case CK_INSTANCE:
		case CK_LABELED_PARENT:
		case CK_LABELED_CHILD:
			remove_connection_from_pending(c);
			terminate_all_connection_states(c, HERE);
			break;
		default:
			break;
		}

		/*
		 * Above remove from pending and delete connection
		 * states calls, and below flush event call, should be
		 * folded into connection_unroute().
		 *
		 * See github/1197
		 */
		connection_unroute(c, HERE); /* some times redundant */

		/*
		 * Flush any lurking revivals.
		 *
		 * Work-around github/1255 and ikev2-delete-02 where:
		 *
		 * teardown_ipsec_kernel_policies() doesn't schedule a
		 * revival for the Child SA but should, and then a
		 * later delete_ike schedules a revival but shouldn't
		 * (revival is tied to the Child SA not the IKE SA).
		 */
		switch (c->local->kind) {
		case CK_PERMANENT:
		case CK_INSTANCE:
			if (flush_connection_events(c)) {
				ldbg(logger, "flushed bogus pending events");
			}
			break;
		default:
			break;
		}
	}

	/*
	 * A non-instance connection has a floating reference; need to
	 * delete that so that the caller is left with the only
	 * reference to the connection.
	 */
	struct connection *cc = c;
	if (!is_instance(cc)) {
		connection_delref(&cc, cc->logger);
	}
	PEXPECT(c->logger, refcnt_peek(&c->refcnt) == 1);
	return 1; /* the connection counts */
}

void whack_delete_connection(struct connection **cp, struct logger *logger)
{
	/*
	 * If it's a connection instance, grap a reference so
	 * that this function holds the last reference
	 * (permanent connections have a free reference).
	 */

	struct connection *c =
		(is_instance(*cp) ? connection_addref(*cp, logger) :
		 *cp);

	del_policy((*cp), policy.route)
	del_policy((*cp), policy.up)

	terminate_all_connection_states(c, HERE);
	connection_unroute(c, HERE); /* should be redundant */
	remove_connection_from_pending(c);
	flush_connection_events(c);

	delete_connection(&c);
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
	whack_connections_bottom_up(m, s, whack_delete_one_connection,
				    (struct each) {
					    .log_unknown_name = log_unknown_name,
				    });
}
