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
#include "ikev1_retransmit.h"
#include "connections.h"
#include "log.h"
#include "ikev1_send.h"
#include "pending.h"
#include "ikev1_replace.h"
#include "pluto_stats.h"
#include "revival.h"

#ifdef USE_IKEv1
/* Time to retransmit, or give up.
 *
 * Generally, we'll only try to send the message
 * MAXIMUM_RETRANSMISSIONS times.  Each time we double
 * our patience.
 *
 * As a special case, if this is the first initiating message
 * of a Main Mode exchange, and we have been directed to try
 * forever, we'll extend the number of retransmissions to
 * MAXIMUM_RETRANSMISSIONS_INITIAL times, with all these
 * extended attempts having the same patience.  The intention
 * is to reduce the bother when nobody is home.
 *
 * Since IKEv1 is not reliable for the Quick Mode responder,
 * we'll extend the number of retransmissions as well to
 * improve the reliability.
 */

void event_v1_retransmit(struct state *st, monotime_t now UNUSED)
{
	switch (retransmit(st)) {
	case RETRANSMIT_YES:
		resend_recorded_v1_ike_msg(st, "EVENT_RETRANSMIT");
		return;
	case RETRANSMIT_NO:
		return;
	case RETRANSMIT_TIMEOUT:
		break;
	case TIMEOUT_ON_RETRANSMIT:
		break;
	}

	pstat_sa_failed(st, REASON_TOO_MANY_RETRANSMITS);

	/* placed here because IKEv1 doesn't do a proper state change to STF_FAIL_v1N/STF_FATAL */
	linux_audit_conn(st, IS_IKE_SA(st) ? LAK_PARENT_FAIL : LAK_CHILD_FAIL);

	/*
	 * If policy dictates, try to keep the state's connection
	 * alive.  DONT_REKEY overrides UP.
	 */
	PEXPECT(st->st_logger, !st->st_on_delete.skip_revival);
	if (should_revive(st)) {
		/*
		 * No clue as to why the state is being deleted so
		 * make something up.  Caller, such as the IKEv1
		 * timeout should have scheduled the revival already.
		 */
		schedule_revival(st, "retransmit timeout");
		/*
		 * Hack so that the code deleting a connection knows
		 * that it needs to delete the revival.
		 *
		 * XXX: Should be sending event to the routing code,
		 * but this is IKEv1.
		 */
		if (st->st_ike_version == IKEv1) {
			enum routing new_rt;
			switch (st->st_connection->child.routing) {
			case RT_UNROUTED:
			case RT_UNROUTED_NEGOTIATION:
				new_rt = RT_UNROUTED_REVIVAL;
				break;
			case RT_ROUTED_NEGOTIATION:
				new_rt = RT_ROUTED_ONDEMAND;
				break;
			default:
				new_rt = 0;
			}
			if (new_rt != 0) {
				set_routing((IS_IKE_SA(st) ? CONNECTION_TIMEOUT_IKE :
					     CONNECTION_TIMEOUT_CHILD),
					    st->st_connection,
					    new_rt, NULL, HERE);
			}
		}
	}

	delete_state(st);
	/* note: no md->st to clear */
}
#endif
