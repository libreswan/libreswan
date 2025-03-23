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
#include "whack_sa.h"
#include "show.h"
#include "visit_connection.h"
#include "ikev2_delete.h"

static unsigned whack_connection_sa(const struct whack_message *m,
				    struct show *s,
				    struct connection *c)
{
	enum sa_kind sa_kind = whack_sa_kind(m->whack_command);
	struct logger *logger = show_logger(s);

	if (!can_have_sa(c, sa_kind)) {
		/* silently skip */
		connection_attach(c, logger);
		ldbg(logger, "skipping non-%s connection",
		     connection_sa_name(c, sa_kind));
		connection_detach(c, logger);
		return 0;
	}

	so_serial_t so = SOS_NOBODY;
	switch (sa_kind) {
	case IKE_SA: so = c->established_ike_sa; break;
	case CHILD_SA: so = c->established_child_sa; break;
	}

	if (so == SOS_NOBODY) {
		connection_attach(c, logger);
		llog(RC_LOG, c->logger, "connection does not have an established %s",
		     connection_sa_name(c, sa_kind));
		connection_detach(c, logger);
		return 0; /* the connection doesn't count */
	}

	struct state *st = state_by_serialno(so);
	if (st == NULL) {
		connection_attach(c, logger);
		llog(RC_LOG, c->logger, "connection established %s "PRI_SO" missing",
		     connection_sa_name(c, sa_kind), pri_so(so));
		connection_detach(c, logger);
		return 0; /* the connection doesn't count */
	}

	if (!m->whack_async) {
		state_attach(st, logger);
	}

	/* find and attach to the IKE SA */
	if (IS_CHILD_SA(st)) {
		struct child_sa *child = pexpect_child_sa(st);
		struct ike_sa *parent = parent_sa(child);
		if (parent == NULL) {
			llog_sa(RC_LOG, child,
				"%s has no %s",
				st->st_connection->config->ike_info->child_sa_name,
				st->st_connection->config->ike_info->parent_sa_name);
			return 0; /* the connection doesn't count */
		}
		if (!m->whack_async) {
			state_attach(&parent->sa, logger);
		}
	}

	switch (m->whack_command) {
	case WHACK_REKEY_IKE:
	case WHACK_REKEY_CHILD:
		event_force(EVENT_v2_REKEY, st);
		return true; /* the connection counts */
	case WHACK_DELETE_IKE:
		submit_v2_delete_exchange(pexpect_ike_sa(st), NULL);
		return true; /* the connection counts */
	case WHACK_DELETE_CHILD:
		submit_v2_delete_exchange(ike_sa(st, HERE), pexpect_child_sa(st));
		return true; /* the connection counts */
	case WHACK_DOWN_IKE:
		del_policy(c, policy.up);
		submit_v2_delete_exchange(pexpect_ike_sa(st), NULL);
		return true; /* the connection counts */
	case WHACK_DOWN_CHILD:
		del_policy(c, policy.up);
		submit_v2_delete_exchange(ike_sa(st, HERE), pexpect_child_sa(st));
		return true; /* the connection counts */
	default:
		bad_case(m->whack_command);
	}

}


void whack_sa(const struct whack_message *m, struct show *s)
{
	struct logger *logger = show_logger(s);
	if (m->name == NULL) {
		/* leave bread crumb */
		enum_buf stb;
		llog(RC_FATAL, logger,
		     "received command to %s connection %s, but did not receive the connection name",
		     whack_sa_name(m->whack_command),
		     str_enum(&sa_kind_names, whack_sa_kind(m->whack_command), &stb));
		return;
	}

	whack_connections_bottom_up(m, s, whack_connection_sa,
				    (struct each) {
					    .log_unknown_name = true,
				    });
}
