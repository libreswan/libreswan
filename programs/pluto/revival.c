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
#include "connection_event.h"
#include "nat_traversal.h"		/* for NAT_T_DETECTED */
#include "state.h"
#include "log.h"
#include "iface.h"
#include "initiate.h"			/* for initiate_connection() */
#include "revival.h"
#include "whack_shutdown.h"		/* for exiting_pluto; */
#include "ikev2_replace.h"
#include "orient.h"

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
 *
 * XXX: during shutdown delete_all_connections() should flush any
 * outstanding revivals; hence no need to free revivals.
 */

static void delete_revival(const struct connection *c)
{
	if (!flush_connection_event(c, CONNECTION_REVIVAL)) {
		if (impair.revival) {
#if 0
			/* XXX: should be log but messages with output */
			llog(RC_LOG, c->logger, "IMPAIR: revival: no event to delete");
#else
			ldbg(c->logger, "IMPAIR: revival: no event to delete");
#endif
			return;
		}

		if (exiting_pluto) {
			ldbg(c->logger, "revival: ignoring missing event, pluto is going down");
			return;
		}

		llog_pexpect(c->logger, HERE, "revival: no event to delete");
	}
}

void flush_routed_ondemand_revival(struct connection *c)
{
	PEXPECT(c->logger, c->child.routing == RT_ROUTED_ONDEMAND);
	if (c->temp_vars.revival.attempt > 0) {
		delete_revival(c);
	} else {
		PEXPECT(c->logger, !connection_event_is_scheduled(c, CONNECTION_REVIVAL));
	}
}

void flush_unrouted_revival(struct connection *c)
{
	PEXPECT(c->logger, c->child.routing == RT_UNROUTED);
	if (c->temp_vars.revival.attempt > 0) {
		delete_revival(c);
	} else {
		PEXPECT(c->logger, !connection_event_is_scheduled(c, CONNECTION_REVIVAL));
	}
}

static bool revival_plausable(struct connection *c, struct logger *logger)
{
	if (exiting_pluto) {
		ldbg(logger, "revival: skilling, pluto is going down");
		return false;
	}

	if ((c->policy & POLICY_UP) == LEMPTY) {
		ldbg(logger, "revival: skipping, POLICY_UP disabled");
		return false;
	}

	if (is_labeled(c)) {
		/* not supported for now */
		ldbg(logger, "revival: skipping, labeled IPsec is too hard");
		return false;
	}

	if (!oriented(c)) {
		/* e.x., interface deleted while up */
		ldbg(logger, "revival: skipping, not oriented");
		return false;
	}

	if (c->interface->ip_dev->ifd_change == IFD_DELETE) {
		/*
		 * The oriented() isn't sufficient.
		 *
		 * An interface is first marked as dead and then
		 * deleted.  As a result a connection will check for
		 * revival when the interface is attached but dead.
		 */
		ldbg(logger, "revival: skipping, interface being deleted");
		return false;
	}

	/*
	 * XXX: should this be a pexpect()?
	 */
	if (connection_event_is_scheduled(c, CONNECTION_REVIVAL)) {
		llog(RC_LOG, logger,
		     "event CONNECTION_REVIVAL already scheduled");
		return false;
	}

	/* not completely ruled out */
	return true;
}

bool should_revive(struct state *st)
{
	struct connection *c = st->st_connection;

	if (st->st_on_delete.skip_revival) {
		llog_pexpect(st->st_logger, HERE, "revival was handled earlier");
		return false;
	}

	/*
	 * XXX: now the weird ones.
	 */

	if (!IS_IKE_SA(st)) {
		ldbg(st->st_logger, "revival: skipping, not an IKE SA");
		return false;
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
		ldbg(st->st_logger, "revival: skipping, IKE delete_state() for #%lu and connection '%s' that is supposed to remain up;  not a problem - have newer #%lu",
		    st->st_serialno, c->name, newer_sa);
		return false;
	}

	if (!revival_plausable(c, st->st_logger)) {
		return false;
	}

	return true;
}

bool should_revive_child(struct child_sa *child)
{
	struct connection *c = child->sa.st_connection;

	if (c->newest_routing_sa > child->sa.st_serialno) {
		/*
		 * There's a newer SA playing with the routing.
		 * Presumably this is an old Child SA that is in the
		 * process of being rekeyed or replaced.
		 */
		ldbg_sa(child, "revival: skipping, newest routing SA "PRI_SO" is newer than this Child SA "PRI_SO,
			pri_so(c->newest_routing_sa), pri_so(child->sa.st_serialno));
		return false;
	}

	if (c->newest_ipsec_sa > child->sa.st_serialno) {
		/* should be covered by above */
		llog_pexpect(child->sa.st_logger, HERE,
			     "revival: skipping, newest IPsec SA "PRI_SO" is newer than this Child SA "PRI_SO,
			     pri_so(c->newest_ipsec_sa), pri_so(child->sa.st_serialno));
		return false;
	}

	if (!revival_plausable(c, child->sa.st_logger)) {
		return false;
	}

	return true;
}

bool should_revive_ike(struct ike_sa *ike)
{
	struct connection *c = ike->sa.st_connection;

	if (c->newest_ike_sa != SOS_NOBODY &&
	    c->newest_ike_sa != ike->sa.st_serialno) {
		/* should be covered by above */
		llog_pexpect(ike->sa.st_logger, HERE,
			     "revival: skipping, newest IKE SA "PRI_SO" is is not us",
			     pri_so(c->newest_ike_sa));
		return false;
	}

	return revival_plausable(c, ike->sa.st_logger);
}

static void update_remote_port(struct connection *c, struct state *st)
{
	/* XXX: check that IKE is for C? */
	if ((IS_IKE_SA_ESTABLISHED(st) ||
	     IS_V1_ISAKMP_SA_ESTABLISHED(st)) &&
	    is_instance(c)) {
		/*
		 * Why isn't the host_port set by instantiation?
		 *
		 * XXX: it is, but it is set to 500; better question
		 * is why isn't the host_port updated once things have
		 * established and nat has been detected.
		 */
		ldbg(st->st_logger, "revival: %s() %s.host_port: %u->%u (that)", __func__, c->remote->config->leftright,
		     c->remote->host.port, st->st_remote_endpoint.hport);
		c->remote->host.port = st->st_remote_endpoint.hport;
		/*
		 * Need to force the host to use the encap port.
		 */
		c->remote->host.encap =
			(st->hidden_variables.st_nat_traversal & NAT_T_DETECTED ||
			 st->st_interface->io->protocol == &ip_protocol_tcp);
	}
}

static void schedule_revival_event(struct connection *c, struct logger *logger, const char *subplot)
{
	deltatime_buf db;
	deltatime_t delay = c->temp_vars.revival.delay;

	c->temp_vars.revival.delay =
		deltatime_min(deltatime_add(delay, REVIVE_CONN_DELAY),
			      REVIVE_CONN_DELAY_MAX);
	c->temp_vars.revival.attempt++;

	llog(RC_LOG, logger,
	     "connection is supposed to remain up; revival attempt %u scheduled in %s seconds",
	     c->temp_vars.revival.attempt,
	     str_deltatime(delay, &db));

	schedule_connection_event(c, CONNECTION_REVIVAL, subplot, delay,
				  (impair.revival ? "revival" : NULL), logger);
}

void schedule_revival(struct state *st, const char *subplot)
{
	if (st->st_on_delete.skip_revival) {
		llog_pexpect(st->st_logger, HERE, "revival already scheduled");
		return;
	}
	on_delete(st, skip_revival);

	struct connection *c = st->st_connection;
	update_remote_port(c, st);
	schedule_revival_event(c, st->st_logger, subplot);
}

void schedule_child_revival(struct ike_sa *ike, struct child_sa *child, const char *subplot)
{
	struct connection *c = child->sa.st_connection;
	update_remote_port(c, &ike->sa);
	schedule_revival_event(c, child->sa.st_logger, subplot);
}

void schedule_ike_revival(struct ike_sa *ike, const char *subplot)
{
	struct connection *c = ike->sa.st_connection;
	update_remote_port(c, &ike->sa);
	schedule_revival_event(c, ike->sa.st_logger, subplot);
}

void revive_connection(struct connection *c, const char *subplot,
		       const threadtime_t *inception)
{
	llog(RC_LOG, c->logger,
	     "reviving connection which %s but must remain up per local policy (serial "PRI_CO")",
	     subplot, pri_co(c->serialno));

	/*
	 * See ikev2-removed-iface-01
	 *
	 * The established connection is loosing its interface which
	 * triggers a delete.  That in turn causes the connection to
	 * go onto the revival queue expecting to then initiate a
	 * connection via the interface that was just deleted.  Oh.
	 *
	 * What saves things from the inevitable core dump is
	 * initiate_connection() being sprinkled with oriented()
	 * checks.
	 *
	 * It should instead wait until the interface comes back and
	 * then, assuming UP, initiate.
	 */
	if (!PEXPECT(c->logger, oriented(c))) {
		return;
	}

	connection_revive(c, inception, HERE);
}
