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
#include "whack_connection.h"
#include "ikev2_delete.h"

static struct state *connection_state(const struct whack_message *m,
				      struct show *s,
				      struct connection *c,
				      enum sa_type sa_type,
				      so_serial_t so)
{
	struct logger *logger = show_logger(s);

	if (!can_have_sa(c, sa_type)) {
		/* silently skip */
		connection_buf cb;
		ldbg(logger, "skipping non-%s connection "PRI_CONNECTION,
		     connection_sa_name(c, sa_type),
		     pri_connection(c, &cb));
		return NULL; /* the connection doesn't count */
	}

	struct state *st = state_by_serialno(so);
	if (st == NULL) {
		connection_attach(c, logger);
		llog(RC_LOG, c->logger, "connection does not have %s",
		     connection_sa_name(c, sa_type));
		connection_detach(c, logger);
		return NULL; /* the connection doesn't count */
	}

	if (!m->whack_async) {
		state_attach(st, logger);
	}

	if (IS_CHILD_SA(st)) {
		struct child_sa *child = pexpect_child_sa(st);
		struct ike_sa *parent = parent_sa(child);
		if (parent == NULL) {
			llog_sa(RC_LOG, child,
				"%s has no %s",
				st->st_connection->config->ike_info->child_sa_name,
				st->st_connection->config->ike_info->parent_sa_name);
			return NULL; /* the connection doesn't count */
		}
		if (!m->whack_async) {
			state_attach(&parent->sa, logger);
		}
	}

	return st;
}

static void whack_connection_sa(const struct whack_message *m,
				struct show *s,
				const char *op,
				whack_connection_visitor_cb *whack_connection_sa_visitor)
{
	struct logger *logger = show_logger(s);
	if (m->name == NULL) {
		/* leave bread crumb */
		llog(RC_FATAL, logger,
		     "received command to %s connection, but did not receive the connection name", op);
		return;
	}

	whack_connections_bottom_up(m, s, whack_connection_sa_visitor,
				    (struct each) {
					    .log_unknown_name = true,
				    });
}

static bool whack_rekey_connection_sa(const struct whack_message *m,
				      struct show *s,
				      struct connection *c,
				      enum sa_type sa_type,
				      so_serial_t so)
{
	struct state *st = connection_state(m, s, c, sa_type, so);
	if (st == NULL) {
		/* already logged */
		return false;
	}

	pdbg(st->logger, "rekeying");
	event_force(EVENT_v2_REKEY, st);
	return true; /* the connection counts */
}

static unsigned whack_rekey_connection_ike_sa(const struct whack_message *m,
					      struct show *s,
					      struct connection *c)
{
	return whack_rekey_connection_sa(m, s, c, IKE_SA, c->established_ike_sa);
}

static unsigned whack_rekey_connection_child_sa(const struct whack_message *m,
						struct show *s,
						struct connection *c)
{
	return whack_rekey_connection_sa(m, s, c, CHILD_SA, c->newest_ipsec_sa);
}

void whack_rekey_ike(const struct whack_message *m, struct show *s)
{
	whack_connection_sa(m, s, "rekey IKE SA", whack_rekey_connection_ike_sa);
}

void whack_rekey_child(const struct whack_message *m, struct show *s)
{
	whack_connection_sa(m, s, "rekey Child SA", whack_rekey_connection_child_sa);
}

static bool whack_delete_connection_sa(const struct whack_message *m,
				       struct show *s,
				       struct connection *c,
				       enum sa_type sa_type,
				       so_serial_t so)
{
	struct state *st = connection_state(m, s, c, sa_type, so);
	if (st == NULL) {
		/* already logged */
		return false;
	}

	pdbg(st->logger, "deleting");
	switch (sa_type) {
	case IKE_SA:
		submit_v2_delete_exchange(pexpect_ike_sa(st), NULL);
		return true; /* the connection counts */
	case CHILD_SA:
		submit_v2_delete_exchange(ike_sa(st, HERE), pexpect_child_sa(st));
		return true; /* the connection counts */
	}
	bad_case(sa_type);
}

static unsigned whack_delete_connection_ike_sa(const struct whack_message *m,
					      struct show *s,
					      struct connection *c)
{
	return whack_delete_connection_sa(m, s, c, IKE_SA, c->established_ike_sa);
}

static unsigned whack_delete_connection_child_sa(const struct whack_message *m,
						struct show *s,
						struct connection *c)
{
	return whack_delete_connection_sa(m, s, c, CHILD_SA, c->newest_ipsec_sa);
}

void whack_delete_ike(const struct whack_message *m, struct show *s)
{
	whack_connection_sa(m, s, "delete IKE SA", whack_delete_connection_ike_sa);
}

void whack_delete_child(const struct whack_message *m, struct show *s)
{
	whack_connection_sa(m, s, "delete Child SA", whack_delete_connection_child_sa);
}
