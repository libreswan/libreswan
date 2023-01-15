/*
 * timer event handling
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2005-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
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

#include "defs.h"
#include "state.h"
#include "ikev2_retransmit.h"
#include "passert.h"
#include "connections.h"
#include "log.h"
#include "pluto_stats.h"
#include "ikev2_send.h"
#include "pending.h"
#include "ikev2_replace.h"
#include "ikev2.h"		/* for ikev2_retry_establishing_ike_sa() */
#include "kernel.h"

void process_v2_ike_sa_established_request_timeout(struct ike_sa *ike, monotime_t now UNUSED)
{
	const char *kind_name = enum_name(&connection_kind_names,
					  ike->sa.st_connection->kind);

	switch (ike->sa.st_connection->config->dpd.action) {
	case DPD_ACTION_CLEAR:
	{
		/*
		 * Danger: delete_ike_family() can delete the IKE SA's
		 * connection.  Cover our bases by saving a handle.
		 */
		llog_sa(RC_LOG, ike,
			"liveness action - clearing connection kind %s",
			kind_name);
		co_serial_t co = ike->sa.st_connection->serialno;
		so_serial_t so = ike->sa.st_serialno;
		/* remove any partial negotiations that are failing */
		flush_pending_by_connection(ike->sa.st_connection);
		delete_ike_family(&ike, DONT_SEND_DELETE);
		pexpect(ike == NULL);
		struct connection *c = connection_by_serialno(co);
		if (c != NULL && c->newest_ike_sa == so) {
			dbg("unrouting connection kind %s",
			    kind_name);
			unroute_connection(c); /* --unroute */
		}
		break;
	}

	case DPD_ACTION_RESTART:
	{
		/*
		 * XXX: Danger! This connection call can end up
		 * deleting IKE.
		 *
		 * So that the logger is valid after IKE_TBD's been
		 * deleted, create a clone of IKE's logger and
		 * kill the IKE pointer.
		 *
		 * XXX: and how is this different to REVIVE?
		 */
		llog_sa(RC_LOG, ike,
			"liveness action - restarting all connections that share this peer");
		struct logger *logger = clone_logger(ike->sa.st_logger, HERE);
		struct connection *c = ike->sa.st_connection;
		ike = NULL;
		restart_connections_by_peer(c, logger);
		ike = NULL; /* potentially deleted */
		free_logger(&logger, HERE);
		break;
	}

	case DPD_ACTION_HOLD:
		llog_sa(RC_LOG, ike,
			"liveness action - putting connection into hold");
		if (ike->sa.st_connection->kind == CK_INSTANCE) {
			dbg("liveness warning: dpdaction=hold on instance futile - will be deleted");
		}
		delete_ike_family(&ike, DONT_SEND_DELETE);
		break;

	default:
		bad_case(ike->sa.st_connection->config->dpd.action);
	}
}

/*
 * XXX: it is the IKE SA that is responsible for all retransmits.
 */

void event_v2_retransmit(struct state *ike_sa, monotime_t now)
{
	passert(ike_sa != NULL);
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		return;
	}

	/* if this connection has a newer Child SA than this state
	 * this negotiation is not relevant any more.  would this
	 * cover if there are multiple CREATE_CHILD_SA pending on this
	 * IKE negotiation ???
	 *
	 * XXX: Suspect this is to handle a race where the other end
	 * brings up the connection first?  For that case, shouldn't
	 * this state have been deleted?
	 *
	 * NOTE: a larger serialno does not mean superseded. crossed
	 * streams could mean the lower serial established later and
	 * is the "newest". Should > be replaced with != ?
	 */

	struct connection *c = ike->sa.st_connection;
	if (!IS_IKE_SA_ESTABLISHED(&ike->sa) && c->newest_ike_sa > ike->sa.st_serialno) {
		llog_sa(RC_LOG, ike,
			  "suppressing retransmit because IKE SA was superseded #%lu try=%lu; drop this negotiation",
			  c->newest_ike_sa, ike->sa.st_try);
		pstat_sa_failed(&ike->sa, REASON_SUPERSEDED_BY_NEW_SA);
		delete_ike_family(&ike, DONT_SEND_DELETE);
		return;
	}

	switch (retransmit(&ike->sa)) {
	case RETRANSMIT_YES:
		send_recorded_v2_message(ike, "EVENT_RETRANSMIT",
					 MESSAGE_REQUEST);
		return;
	case RETRANSMIT_NO:
		return;
	case RETRANSMITS_TIMED_OUT:
		break;
	case DELETE_ON_RETRANSMIT:
		delete_ike_family(&ike, DONT_SEND_DELETE);
		return;
	}

	if (ike->sa.st_state->v2.request_timeout != NULL) {
		ike->sa.st_state->v2.request_timeout(ike, now);
		return;
	}

	/*
	 * XXX: This is looking at the failed to establish IKE SA.
	 * The retry is probably valid.  However, would it be easier
	 * to just let the replace code handle this?
	 */
	if (ikev2_retry_establishing_ike_sa(ike)) {
		return;
	}

	/*
	 * XXX: There might be a larval child.  Just use the biggest
	 * stick available.
	 */

	pstat_sa_failed(&ike->sa, REASON_TOO_MANY_RETRANSMITS);
	/* can't send delete as message window is full */
	delete_ike_family(&ike, DONT_SEND_DELETE);

	/* note: no md->st to clear */
}
