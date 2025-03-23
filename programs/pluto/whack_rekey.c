/* rekey connections: IKEv2
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 Antony Antony <antony@phenome.org>
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

#include "defs.h"
#include "log.h"
#include "connections.h"
#include "state.h"
#include "timer.h"
#include "whack_rekey.h"
#include "show.h"
#include "whack_connection.h"

static bool rekey_state(const struct whack_message *m, struct show *s,
			struct connection *c, enum sa_kind sa_kind, so_serial_t so)
{
	struct logger *logger = show_logger(s);

	struct state *st = state_by_serialno(so);
	if (st == NULL) {
		connection_attach(c, logger);
		llog(RC_LOG, c->logger, "connection does not have %s",
		     connection_sa_name(c, sa_kind));
		connection_detach(c, logger);
		return 0; /* the connection doesn't count */
	}

	if (!m->whack_async) {
		state_attach(st, logger);
	}

	if (IS_CHILD_SA(st)) {
		struct child_sa *child = pexpect_child_sa(st);
		struct ike_sa *parent = parent_sa(child);
		if (parent == NULL) {
			llog_sa(RC_LOG, child,
				"can't rekey, %s has no %s",
				st->st_connection->config->ike_info->child_sa_name,
				st->st_connection->config->ike_info->parent_sa_name);
			return 0; /* the connection doesn't count */
		}
		if (!m->whack_async) {
			state_attach(&parent->sa, logger);
		}
	}

	ldbg(logger, "rekeying "PRI_SO, pri_so(so));
	event_force(EVENT_v2_REKEY, st);
	return 1; /* the connection counts */
}

static unsigned whack_rekey_ike(const struct whack_message *m,
				struct show *s,
				struct connection *c)
{
	struct logger *logger = show_logger(s);

	if (!can_have_sa(c, IKE_SA)) {
		/* silently skip */
		connection_buf cb;
		ldbg(logger, "skipping non-parent connection "PRI_CONNECTION,
		     pri_connection(c, &cb));
		return 0; /* the connection doesn't count */
	}

	return rekey_state(m, s, c, IKE_SA, c->established_ike_sa);
}

static unsigned whack_rekey_child(const struct whack_message *m,
				  struct show *s,
				  struct connection *c)
{
	struct logger *logger = show_logger(s);

	if (!can_have_sa(c, CHILD_SA)) {
		/* silently skip */
		connection_buf cb;
		ldbg(logger, "skipping non-child connection "PRI_CONNECTION,
		     pri_connection(c, &cb));
		return 0; /* the connection doesn't count */
	}

	return rekey_state(m, s, c, CHILD_SA, c->established_child_sa);
}

void whack_rekey(const struct whack_message *m, struct show *s, enum sa_kind sa_kind)
{
	struct logger *logger = show_logger(s);
	if (m->name == NULL) {
		/* leave bread crumb */
		llog(RC_FATAL, logger,
		     "received command to rekey connection, but did not receive the connection name - ignored");
		return;
	}

	switch (sa_kind) {
	case IKE_SA:
		whack_connections_bottom_up(m, s, whack_rekey_ike,
					    (struct each) {
						    .log_unknown_name = true,
					    });
		return;
	case CHILD_SA:
		whack_connections_bottom_up(m, s, whack_rekey_child,
					    (struct each) {
						    .log_unknown_name = true,
					    });
		return;
	}
	bad_case(sa_kind);
}
