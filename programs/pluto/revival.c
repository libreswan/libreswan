/* routines for reviving connections, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001, 2013-2017 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009, 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2012 Bram <bram-bcrafjna-erqzvar@spam.wizbit.be>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2015-2018 Antony Antony <antony@phenome.org>
 * Copyright (C) 2015-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017 Richard Guy Briggs <rgb@tricolour.ca>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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
 */

#include "connections.h"
#include "nat_traversal.h"		/* for NAT_T_DETECTED */
#include "state.h"
#include "log.h"
#include "iface.h"
#include "initiate.h"			/* for initiate_connection() */
#include "revival.h"
#include "state_db.h"
#include "pluto_shutdown.h"		/* for exiting_pluto */

/*
 * Revival mechanism: keep track of connections
 * that should be kept up, even though all their
 * states have been deleted.
 *
 * We record the connection names.
 * Each name is recorded only once.
 *
 * XXX: This functionality totally overlaps both "initiate" and
 * "pending" and should be merged (however, this simple code might
 * prove to be a better starting point).
 */

struct revival {
	co_serial_t serialno;
	struct revival *next;
};

static struct revival *revivals = NULL;

/*
 * XXX: Return connection C's revival object's link, if found.  If the
 * connection C can't be found, then the address of the revival list's
 * tail is returned.  Perhaps, exiting the loop and returning NULL
 * would be more obvious.
 */
static struct revival **find_revival(const struct connection *c)
{
	for (struct revival **rp = &revivals; ; rp = &(*rp)->next) {
		if (*rp == NULL || co_serial_cmp((*rp)->serialno, ==, c->serialno)) {
			return rp;
		}
	}
}

/*
 * XXX: In addition to freeing RP (and killing the pointer), this
 * "free" function has the side effect of unlinks RP from the revival
 * list.  Perhaps free*() isn't the best name.
 */
static void free_revival(struct revival **rp)
{
	struct revival *r = *rp;
	*rp = r->next;
	pfree(r);
}

void flush_revival(const struct connection *c)
{
	struct revival **rp = find_revival(c);

	if (*rp == NULL) {
		dbg("flush revival: connection '%s' with serial "PRI_CO" wasn't on the list",
		    c->name, pri_co(c->serialno));
	} else {
		dbg("flush revival: connection '%s' with serial "PRI_CO" revival flushed",
		    c->name, pri_co(c->serialno));
		free_revival(rp);
	}
}

void add_revival_if_needed(struct state *st)
{
	struct connection *c = st->st_connection;

	if (!IS_IKE_SA(st)) {
		dbg("skipping revival: not an IKE SA");
		return;
	}

	if ((c->policy & POLICY_UP) == LEMPTY) {
		dbg("skipping revival: POLICY_UP disabled");
		return;
	}

	if ((c->policy & POLICY_DONT_REKEY) != LEMPTY) {
		dbg("skipping revival: POLICY_DONT_REKEY enabled");
		return;
	}

	if (exiting_pluto) {
		dbg("skilling revival: pluto is going down");
		return;
	}

	so_serial_t newer_sa = get_newer_sa_from_connection(st);
	if (state_by_serialno(newer_sa) != NULL) {
		/*
		 * Presumably this is an old state that has either
		 * been rekeyed or replaced.
		 *
		 * XXX: Should not even be here though!  The old IKE
		 * SA should be going through delete state transition
		 * that, at the end, cleanly deletes it with none of
		 * this guff.
		 */
		dbg("skipping revival: IKE delete_state() for #%lu and connection '%s' that is supposed to remain up;  not a problem - have newer #%lu",
		    st->st_serialno, c->name, newer_sa);
		return;
	}

	if (impair.revival) {
		log_state(RC_LOG, st,
			  "IMPAIR: skipping revival of connection that is supposed to remain up");
		return;
	}

	if (*find_revival(c) != NULL) {
		log_state(RC_LOG, st, "deleting IKE SA but connection is supposed to remain up; EVENT_REVIVE_CONNS already scheduled");
		return;
	}

	log_state(RC_LOG, st, "deleting IKE SA but connection is supposed to remain up; schedule EVENT_REVIVE_CONNS");

	struct revival *r = alloc_thing(struct revival,
					"revival struct");
	r->serialno = c->serialno;
	r->next = revivals;
	revivals = r;
	int delay = c->temp_vars.revive_delay;
	dbg("add revival: connection '%s' (serial "PRI_CO") added to the list and scheduled for %d seconds",
	    c->name, pri_co(c->serialno), delay);
	c->temp_vars.revive_delay = min(delay + REVIVE_CONN_DELAY,
						REVIVE_CONN_DELAY_MAX);
	if (IS_IKE_SA_ESTABLISHED(st) &&
	    c->kind == CK_INSTANCE &&
	    LIN(POLICY_UP, c->policy)) {
		/*
		 * why isn't the host_port set by instantiation ?
		 *
		 * XXX: it is, but it is set to 500; better question
		 * is why isn't the host_port updated once things have
		 * established and nat has been detected.
		 */
		dbg("updating connection for remote port %d", st->st_remote_endpoint.hport);
		dbg("%s() %s.host_port: %u->%u (that)", __func__, c->spd.that.leftright,
		    c->spd.that.host_port, st->st_remote_endpoint.hport);
		c->spd.that.host_port = st->st_remote_endpoint.hport;
		/* need to force the encap port */
		c->spd.that.host_encap = (st->hidden_variables.st_nat_traversal & NAT_T_DETECTED ||
					  st->st_interface->protocol == &ip_protocol_tcp);
	}

	if (c->kind == CK_INSTANCE && c->sa_keying_tries == 0) {
		dbg("limiting instance revival attempts to 2 keyingtries");
		c->sa_keying_tries = 2;
	}
	/*
	 * XXX: Schedule the next revival using this connection's
	 * revival delay and not the most urgent connection's revival
	 * delay.  Trying to fix this here just is annoying and
	 * probably of marginal benefit: it is something better
	 * handled with a proper connection event so that the event
	 * loop deal with all the math (this code would then be
	 * deleted); and would encroach even further on "initiate" and
	 * "pending" functionality.
	 */
	schedule_oneshot_timer(EVENT_REVIVE_CONNS, deltatime(delay));
}

static void revive_conns(struct logger *logger)
{
	/*
	 * XXX: Revive all listed connections regardless of their
	 * DELAY.  See note above in add_revival().
	 *
	 * XXX: since this is called from the event loop, the global
	 * whack_log_fd is invalid so specifying RC isn't exactly
	 * useful.
	 */
	dbg("revive_conns() called");
	while (revivals != NULL) {
		struct connection *c = connection_by_serialno(revivals->serialno);
		if (c == NULL) {
			llog(RC_UNKNOWN_NAME, logger,
				    "failed to initiate connection "PRI_CO" which received a Delete/Notify but must remain up per local policy; connection no longer exists", pri_co(revivals->serialno));
		} else {
			llog(RC_LOG, c->logger,
			     "initiating connection '%s' with serial "PRI_CO" which received a Delete/Notify but must remain up per local policy",
			     c->name, pri_co(c->serialno));
			if (!initiate_connection(c, NULL, true/*background*/)) {
				llog(RC_FATAL, c->logger,
				     "failed to initiate connection");
			}
		}
		/*
		 * Danger! The free_revival() call removes head,
		 * replacing it with the next in the list.
		 */
		free_revival(&revivals);
	}
	dbg("revive_conns() done");
}

void init_revival(void)
{
	init_oneshot_timer(EVENT_REVIVE_CONNS, revive_conns);
}

void free_revivals(void)
{
	while (revivals != NULL) {
		free_revival(&revivals);
	}
}
