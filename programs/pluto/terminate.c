/* shutdown connections: IKEv1/IKEv2
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2019-2023 Andrew Cagney <cagney@gnu.org>
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

#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sysdep.h"
#include "constants.h"
#include "lswalloc.h"
#include "id.h"
#include "x509.h"
#include "certs.h"

#include "defs.h"
#include "connections.h"        /* needs id.h */
#include "pending.h"
#include "foodgroups.h"
#include "demux.h"      /* needs packet.h */
#include "state.h"
#include "timer.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "server.h"
#include "kernel.h"     /* needs connections.h */
#include "log.h"
#include "keys.h"
#include "whack.h"
#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "nat_traversal.h"

#include "terminate.h"
#ifdef USE_IKEv1
#include "ikev1_terminate.h"
#endif
#include "ikev2_terminate.h"

#include "visit_connection.h"		/* for whack_connection() */
#include "ikev2_delete.h"
#include "pluto_stats.h"
#include "revival.h"
#include "connection_event.h"

void terminate_all_connection_states(struct connection *c, where_t where)
{
	switch (c->config->ike_version) {
#ifdef USE_IKEv1
	case IKEv1:
		terminate_all_ikev1_connection_states(c, where);
		pmemory(c);
		return;
#endif
	case IKEv2:
		terminate_all_ikev2_connection_states(c, where);
		pmemory(c);
		return;
	}
	/* caller must hold a reference */
	bad_case(c->config->ike_version);
}

/*
 * Caller must hold a reference; hence all the pmemory(C) calls.
 *
 * Caller must have stripped the +UP and +KEEP bits; else revival will
 * happen only to then be stomped on.
 */

void terminate_connection(struct connection *c, where_t where)
{
	if (never_negotiate(c)) {
		/*
		 * Suppress message as there are no SAs; only unroute
		 * is really needed.
		 */
		PEXPECT(c->logger, c->local->kind == CK_PERMANENT);
		ldbg(c->logger, "terminating and downing never-negotiate connection");
	} else {
		ldbg(c->logger, "terminating SAs using this connection");
	}

	/* see callers */
	PEXPECT(c->logger, (c->local->kind == CK_INSTANCE ||
			    c->local->kind == CK_PERMANENT ||
			    c->local->kind == CK_LABELED_PARENT));

	PEXPECT(c->logger, !c->policy.up);
	PEXPECT(c->logger, !c->policy.keep);

	/*
	 * If there are states, delete them.
	 *
	 * Since the +UP and +KEEP bits have been stripped, deleting
	 * states won't trigger a revival.  However, when there are no
	 * states, the connection may already be on the revival queue.
	 * That is handled further down.
	 */
	terminate_all_connection_states(c, HERE);
	pmemory(c); /* should not disappear; caller holds ref */

	/*
	 * Remove any kernel policy.
	 *
	 * For instance, a connection with no states that is on the
	 * pending or revival queue can have on-demand or negotiating
	 * kernel policy installed (else this call is a no-op).
	 */
	connection_unroute(c, where);
	pmemory(c); /* should not disappear; caller holds ref */

	/*
	 * Remove connection from revival queue.
	 */
	flush_unrouted_revival(c);
	pmemory(c); /* should not disappear; caller holds ref */

	/*
	 * Remove the connection from the pending queue.
	 *
	 * For instance, conn/1x1 and conn/1x2 where the latter is on
	 * the former's pending queue (i.e., no states).
	 */
	remove_connection_from_pending(c);

	pmemory(c); /* should not disappear; caller holds ref */
}

static void terminate_and_down_and_unroute_connection(struct connection *c, where_t where)
{
	/*
	 * Strip the +UP bit so that the connection (when its state is
	 * deleted say) doesn't end up on the revival queue.
	 *
	 * Note that the connection could already be lurking on the
	 * pending / revival queue.  That's handled once the states
	 * are deleted (although the order shouldn't matter)..
	 */
	del_policy(c, policy.up);
	del_policy(c, policy.keep);
	del_policy(c, policy.route);

	/*
	 * Remove pending DDNS.
	 *
	 * For instance, a disoriented connection trying to resolve or
	 * orient being deleted.
	 *
	 * Running "down" on a dis-oriented connection will also loose
	 * the CHECK_DDNS event.  But "up" should put it back.  Pluto
	 * needs a way to indicate that a connection is "idle" -
	 * igoring everything.
	 */
	flush_connection_event(c, CONNECTION_CHECK_DDNS);

	terminate_connection(c, where);
}

void terminate_and_down_and_unroute_connections(struct connection *c, where_t where)
{
	switch (c->local->kind) {
	case CK_INSTANCE:
	case CK_PERMANENT:
	case CK_LABELED_PARENT:
		/* caller holds ref; whack already attached */
		terminate_and_down_and_unroute_connection(c, where);
		pmemory(c); /* should not disappear; caller holds ref */
		return;

	case CK_TEMPLATE:
	case CK_LABELED_TEMPLATE:
	{
		/*
		 * Template should remaining, however, terminating and
		 * downing instances will make them go away.
		 *
		 * Worse, terminating and downing an IKE cuckold could
		 * cause Child SA cuckoo connection to be deleted.
		 * Hence, the loop picks away at the first instance.
		 */
		del_policy(c, policy.up);
		/*
		 * Pick away at instances.
		 */
		const struct connection *last = NULL;
		while (true) {
			struct connection_filter cq = {
				.clonedfrom = c,
				.ike_version = c->config->ike_version,
				.search = {
					.order = OLD2NEW,
					.verbose.logger = c->logger,
					.where = where,
				},
			};
			if (!next_connection(&cq)) {
				break;
			}
			/* log first actual delete */
			if (last == NULL) {
				llog(RC_LOG, c->logger, "deleting template instances");
			}
			/* always going forward */
			PASSERT(c->logger, last != cq.c);
			last = cq.c;
			/* stop it disappearing */
			connection_addref(cq.c, c->logger);
			whack_attach(cq.c, c->logger);
			terminate_and_down_and_unroute_connection(cq.c, where);
			/* leave whack attached during death */
			connection_delref(&cq.c, c->logger);
		}
		pmemory(c); /* should not disappear */
		/* to be sure */
		connection_unroute(c, where);
		/*
		 * Remove pending DDNS.  For instance, a template
		 * needing DNS resolution, and nence never made it to
		 * orient.
		 */
		flush_connection_event(c, CONNECTION_CHECK_DDNS);
		return;
	}

	case CK_GROUP:
	{
		/* should not disappear */
		del_policy(c, policy.up);
		struct connection_filter cq = {
			.clonedfrom = c,
			.ike_version = c->config->ike_version,
			.search = {
				.order = OLD2NEW,
				.verbose.logger = c->logger,
				.where = where,
			},
		};
		if (next_connection(&cq)) {
			llog(RC_LOG, c->logger, "terminating group instances");
			do {
				whack_attach(cq.c, c->logger); /* propagate whack */
				terminate_and_down_and_unroute_connections(cq.c, where);
				pmemory(cq.c); /* should not disappear */
				whack_detach(cq.c, c->logger); /* propagate whack */
			} while (next_connection(&cq));
		}
		/*
		 * Remove pending DDNS.  For instance, a template
		 * needing DNS resolution, and nence never made it to
		 * orient.
		 */
		flush_connection_event(c, CONNECTION_CHECK_DDNS);
		pmemory(c); /* should not disappear */
		return;
	}

	case CK_LABELED_CHILD: /* should not happen? */
	case CK_INVALID:
		break;
	}
	bad_enum(c->logger, &connection_kind_names, c->local->kind);
}

void terminate_and_delete_connections(struct connection *c,
				      struct logger *logger,
				      where_t where)
{
	PEXPECT(logger, refcnt_peek(c, logger) > 1);

	switch (c->local->kind) {
	case CK_LABELED_PARENT:
	case CK_PERMANENT:
	case CK_TEMPLATE:
	case CK_LABELED_TEMPLATE:
		/*
		 * Template should remaining, however, terminating and
		 * downing instances will make them go away.
		 *
		 * Worse, terminating and downing an IKE cuckold could
		 * cause Child SA cuckoo connection to be deleted.
		 * Hence, the keep getting first loop.
		 */
		whack_attach(c, logger);
		terminate_and_down_and_unroute_connections(c, where);
		/* leave whack attached during death */
		connection_delref(&c, logger);
		return;

	case CK_GROUP:
	{
		/* should not disappear */
		whack_attach(c, logger);
		struct connection_filter cq = {
			.clonedfrom = c,
			.ike_version = c->config->ike_version,
			.search = {
				.order = OLD2NEW,
				.verbose.logger = logger,
				.where = where,
			},
		};
		if (next_connection(&cq)) {
			llog(RC_LOG, c->logger, "deleting group instances");
			do {
				connection_addref(cq.c, logger);
				terminate_and_delete_connections(cq.c, logger, where);
				connection_delref(&cq.c, logger);
			} while (next_connection(&cq));
		}
		pmemory(c); /* should not disappear */
		/* leave whack attached during death */
		connection_delref(&c, logger);
		return;
	}

	case CK_LABELED_CHILD: /* should not happen? */
	case CK_INSTANCE:
	case CK_INVALID:
		break;
	}
	bad_enum(c->logger, &connection_kind_names, c->local->kind);
}
