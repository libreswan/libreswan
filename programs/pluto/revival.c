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
#include "pluto_shutdown.h"		/* for exiting_pluto */
#include "ikev2_replace.h"

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

void flush_revival(const struct connection *c)
{
	flush_connection_event(c, CONNECTION_REVIVAL);
}

void add_revival_if_needed(struct state *st)
{
	if (!should_revive(st)) {
		return;
	}
	schedule_revival(st);
}

bool should_revive(struct state *st)
{
	struct connection *c = st->st_connection;

	if (exiting_pluto) {
		dbg("skilling revival: pluto is going down");
		return false;
	}

	if (IS_CHILD_SA_ESTABLISHED(st) &&
	    c->newest_ipsec_sa == st->st_serialno &&
	    (c->policy & POLICY_UP)) {
		struct ike_sa *ike = ike_sa(st, HERE);
		llog_sa(RC_LOG_SERIOUS, ike,
			  "received Delete SA payload: replace CHILD SA #%lu now",
			  st->st_serialno);
		PASSERT(st->st_logger, st->st_ike_version == IKEv2);
		st->st_replace_margin = deltatime(0);
		ikev2_replace(st);
		return false;
	}

	if (!IS_IKE_SA(st)) {
		dbg("skipping revival: not an IKE SA");
		return false;
	}

	if ((c->policy & POLICY_UP) == LEMPTY) {
		dbg("skipping revival: POLICY_UP disabled");
		return false;
	}

	if ((c->policy & POLICY_DONT_REKEY) != LEMPTY) {
		dbg("skipping revival: POLICY_DONT_REKEY enabled");
		return false;
	}

	if (c->config->ike_version == IKEv2 && c->config->sec_label.len > 0) {
		dbg("skipped revival: childless IKE SA");
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
		dbg("skipping revival: IKE delete_state() for #%lu and connection '%s' that is supposed to remain up;  not a problem - have newer #%lu",
		    st->st_serialno, c->name, newer_sa);
		return false;
	}

	if (impair.revival) {
		log_state(RC_LOG, st,
			  "IMPAIR: skipping revival of connection that is supposed to remain up");
		return false;
	}

	if (connection_event_scheduled(c, CONNECTION_REVIVAL)) {
		log_state(RC_LOG, st,
			  "deleting %s but connection is supposed to remain up; EVENT_REVIVE_CONNS already scheduled",
			  c->config->ike_info->sa_type_name[IKE_SA]);
		return false;
	}

	return true;
}

void schedule_revival(struct state *st)
{
	struct connection *c = st->st_connection;
	log_state(RC_LOG, st,
		  "deleting %s but connection is supposed to remain up; schedule EVENT_REVIVE_CONNS",
		  c->config->ike_info->sa_type_name[IKE_SA]);

	int delay = c->temp_vars.revive_delay;
	dbg("add revival: connection '%s' (serial "PRI_CO") added to the list and scheduled for %d seconds",
	    c->name, pri_co(c->serialno), delay);
	c->temp_vars.revive_delay = min(delay + REVIVE_CONN_DELAY,
						REVIVE_CONN_DELAY_MAX);
	if ((IS_IKE_SA_ESTABLISHED(st) || IS_V1_ISAKMP_SA_ESTABLISHED(st)) &&
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
		dbg("%s() %s.host_port: %u->%u (that)", __func__, c->remote->config->leftright,
		    c->remote->host.port, st->st_remote_endpoint.hport);
		c->remote->host.port = st->st_remote_endpoint.hport;
		/*
		 * Need to force the host to use the encap port.
		 */
		c->remote->host.encap =
			(st->hidden_variables.st_nat_traversal & NAT_T_DETECTED ||
			 st->st_interface->io->protocol == &ip_protocol_tcp);
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
	schedule_connection_event(c, CONNECTION_REVIVAL, deltatime(delay));
}

void revive_connection(struct connection *c, struct logger *logger)
{
	llog(RC_LOG, c->logger,
	     "initiating connection '%s' with serial "PRI_CO" which received a Delete/Notify but must remain up per local policy",
	     c->name, pri_co(c->serialno));
	initiate_connection(c, /*remote-host-name*/NULL,
			    /*background*/true,
			    /*log-failure*/true,
			    logger);
}
