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
	if (!IS_IKE_SA_ESTABLISHED(&ike->sa) && c->established_ike_sa > ike->sa.st_serialno) {
		llog_sa(RC_LOG, ike,
			  "suppressing retransmit because IKE SA was superseded #%lu; drop this negotiation",
			  c->established_ike_sa);
		pstat_sa_failed(&ike->sa, REASON_SUPERSEDED_BY_NEW_SA);
		connection_delete_ike_family(&ike, HERE);
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
		connection_timeout_ike_family(&ike, HERE);
		return;

	}

	bad_case(retransmit_action);
}
