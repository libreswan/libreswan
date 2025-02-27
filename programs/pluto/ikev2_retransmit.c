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
#include "routing.h"
#include "revival.h"
#include "terminate.h"

/*
 * XXX: it is the IKE SA that is responsible for all retransmits.
 */

void event_v2_retransmit(struct state *ike_sa, monotime_t now UNUSED)
{
	passert(ike_sa != NULL);
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		return;
	}

	/*
	 * Handle IKE SAs crossing-streams.
	 *
	 * Note: can't assume the connection's Child SA as been
	 * established as peer's established IKE SA can connswitch the
	 * Child leaving this negotiation in limbo.
	 *
	 * terminate_ike_family() gets to handle this.
	 *
	 * Note: a larger serialno does not mean superseded.  Crossed
	 * streams could mean the lower serial established later and
	 * is the "newest".  Hence the equality check (and not >).
	 */

	struct connection *c = ike->sa.st_connection;
	if (!IS_IKE_SA_ESTABLISHED(&ike->sa) && c->established_ike_sa != SOS_NOBODY) {
		/*
		 * The connection is established, yet this IKE SA is
		 * not.  Presumably this means that the peer also
		 * initiated and established an IKE SA leaving this
		 * IKE SA in limbo.
		 *
		 * Note: since it isn't established it can't be the
		 * connection's established IKE SA.
		 *
		 * Note: this may also leave the Child SA for the
		 * connection in limbo.  Hopefully revival code will
		 * pick that up.
		 */
		PEXPECT(ike->sa.logger, c->established_ike_sa != ike->sa.st_serialno);
		llog(RC_LOG, ike->sa.logger,
		     "dropping negotiation as superseded by established IKE SA #%lu",
		     c->established_ike_sa);
		terminate_ike_family(&ike, REASON_SUPERSEDED_BY_NEW_SA, HERE);
		return;
	}

	enum retransmit_action retransmit_action = retransmit(&ike->sa);
	switch (retransmit_action) {

	case RETRANSMIT_YES:
		send_recorded_v2_message(ike, "EVENT_RETRANSMIT",
					 ike->sa.st_v2_msgid_windows.initiator.outgoing_fragments);
		return;

	case RETRANSMIT_NO:
		return;

	case RETRANSMIT_TIMEOUT:
	case TIMEOUT_ON_RETRANSMIT:
		/*
		 * Tell the connection so it can revive/retry if
		 * needed and then delete the state.
		 */
		terminate_ike_family(&ike, REASON_TOO_MANY_RETRANSMITS, HERE);
		return;

	}

	bad_case(retransmit_action);
}
