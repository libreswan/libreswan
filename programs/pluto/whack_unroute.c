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

static whack_connection_visitor_cb whack_unroute_connection;

static unsigned unroute_connection(struct connection *c, struct show *s)
{
	connection_attach(c, show_logger(s));
	connection_unroute(c, HERE);
	connection_detach(c, show_logger(s));
	return 1; /* the connection counts */
}

static unsigned unroute_instances(const struct whack_message *m,
				  struct connection *c, struct show *s)
{
	return whack_connection_instance_new2old(m, s, c, whack_unroute_connection);
}

static unsigned whack_unroute_connection(const struct whack_message *m,
					 struct show *s,
					 struct connection *c)
{
	unsigned nr = 0;

	/*
	 * Let code know of intent.
	 *
	 * Functions such as connection_unroute() don't fiddle policy
	 * bits as they are called as part of unroute/route sequences.
	 */
	del_policy(c, policy.route);

	switch (c->local->kind) {

	case CK_PERMANENT:
		nr += unroute_connection(c, s);
		return nr;

	case CK_TEMPLATE:
	case CK_LABELED_TEMPLATE:
		/*
		 * Both the template and the instance may have been
		 * routed separately (for instance by manual initiate,
		 * narrowing, ...).  Hence, regardless of template,
		 * also callback to unroute instances.
		 */
		nr += unroute_instances(m, c, s);
		nr += unroute_connection(c, s);
		return nr;

	case CK_LABELED_CHILD:
		/*
		 * Labeled children are routed/unrouted by their
		 * parent.
		 */
		llog(RC_LOG, show_logger(s), "cannot unroute");
		return 0;

	case CK_LABELED_PARENT:
	case CK_INSTANCE:
		nr += unroute_connection(c, s);
		return nr;

	case CK_GROUP:
		del_policy(c, policy.route);
		nr += unroute_instances(m, c, s);
		return nr;

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
