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
#include "ikev1.h"	/* for established_isakmp_sa_for_state() */

/*
 * This code path can't tell if the flush is due to an initiate or a
 * revival (would need to pass bit into initiate).  Hence always
 * silently flush.
 */
void flush_routed_ondemand_revival(struct connection *c)
{
	PEXPECT(c->logger, c->child.routing == RT_ROUTED_ONDEMAND);
	flush_connection_event(c, CONNECTION_REVIVAL);
}

void flush_unrouted_revival(struct connection *c)
{
	PEXPECT(c->logger, c->child.routing == RT_UNROUTED);
	flush_connection_event(c, CONNECTION_REVIVAL);
}

static bool revival_plausable(struct connection *c, struct logger *logger)
{
	if (exiting_pluto) {
		ldbg(logger, "revival: skilling, pluto is going down");
		return false;
	}

	if (!c->policy.up) {
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

static void update_remote_port(struct state *st)
{
	struct connection *c = st->st_connection;

	/*
	 * Need to find the IKE/ISAKMP SA that is being used to
	 * exchange messages, and then extract its port.
	 *
	 * But first dismiss a few edge cases.
	 */

	if (!is_instance(c)) {
		ldbg(st->st_logger, "revival: skip %s(), not an instance", __func__);
		return;
	}

	if (!IS_PARENT_SA_ESTABLISHED(st) &&
	    !IS_IPSEC_SA_ESTABLISHED(st)) {
		ldbg(st->st_logger, "revival: skip %s(), not established",
		     __func__);
		return;
	}

	struct ike_sa *ike =
		(st->st_ike_version > IKEv1 ? ike_sa(st, HERE) :
		 established_isakmp_sa_for_state(st, /*viable-parent*/false));

	if (ike == NULL) {
		ldbg(st->st_logger, "revival: skip %s(), no %s",
		     __func__, c->config->ike_info->parent_sa_name);
		return;
	}

	if (!IS_PARENT_SA_ESTABLISHED(&ike->sa)) {
		/* should always be true? */
		ldbg(st->st_logger, "revival: skip %s(), %s is not established",
		     __func__, c->config->ike_info->parent_sa_name);
		return;
	}

	/*
	 * Why isn't the host_port set by instantiation?
	 *
	 * XXX: it is, but it is set to 500; better question
	 * is why isn't the host_port updated once things have
	 * established and nat has been detected.
	 */
	c->revival.remote = st->st_remote_endpoint;
	c->revival.local = iface_endpoint_addref(st->st_interface);

	endpoint_pair_buf eb;
	ldbg(st->st_logger, "revival: %s() %s",
	     __func__,
	     str_endpoint_pair(&c->revival.local->local_endpoint, &c->revival.remote, &eb));
}

static void schedule_revival_event(struct connection *c, struct logger *logger, const char *subplot)
{
	deltatime_buf db;
	deltatime_t delay = c->revival.delay;

	c->revival.delay =
		deltatime_min(deltatime_add(delay, REVIVE_CONN_DELAY),
			      REVIVE_CONN_DELAY_MAX);
	c->revival.attempt++;

	llog(RC_LOG, logger,
	     "connection is supposed to remain up; revival attempt %u scheduled in %s seconds",
	     c->revival.attempt,
	     str_deltatime(delay, &db));

	schedule_connection_event(c, CONNECTION_REVIVAL, subplot, delay,
				  (impair.revival ? "revival" : NULL), logger);
}

bool scheduled_connection_revival(struct connection *c, const char *subplot, struct logger *logger)
{
	if (!revival_plausable(c, logger)) {
		return false;
	}

	schedule_revival_event(c, logger, subplot);
	return true;
}

bool scheduled_child_revival(struct child_sa *child, const char *subplot)
{
	struct connection *c = child->sa.st_connection;

	if (c->newest_routing_sa > child->sa.st_serialno) {
		/*
		 * There's a newer SA playing with the routing.
		 * Presumably this is an old Child SA that is in the
		 * process of being rekeyed or replaced.
		 */
		llog_pexpect(child->sa.logger, HERE,
			     "revival: skipping, newest routing SA "PRI_SO" is newer than this Child SA "PRI_SO,
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

	update_remote_port(&child->sa);
	schedule_revival_event(c, child->sa.st_logger, subplot);
	return true;
}

bool scheduled_ike_revival(struct ike_sa *ike, const char *subplot)
{
	struct connection *c = ike->sa.st_connection;

	if (c->established_ike_sa != SOS_NOBODY &&
	    c->established_ike_sa != ike->sa.st_serialno) {
		/* should be covered by above */
		llog_pexpect(ike->sa.st_logger, HERE,
			     "revival: skipping, newest IKE SA "PRI_SO" is is not us",
			     pri_so(c->established_ike_sa));
		return false;
	}

	if (!revival_plausable(c, ike->sa.st_logger)) {
		return false;
	}

	update_remote_port(&ike->sa);
	schedule_revival_event(c, ike->sa.st_logger, subplot);
	return true;
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

	shunk_t sec_label = null_shunk;
	struct logger *logger = c->logger;
	so_serial_t replacing = SOS_NOBODY;
	lset_t policy = child_sa_policy(c);
	bool background = false;

	ipsecdoi_initiate(c, policy, replacing, inception,
			  sec_label, background, logger,
			  INITIATED_BY_REVIVE, HERE);
}
