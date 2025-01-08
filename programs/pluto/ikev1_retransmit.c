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
#include "terminate.h"

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

	/* placed here because IKEv1 doesn't do a proper state change
	 * to STF_FAIL_v1N/STF_FATAL */
	linux_audit_conn(st, IS_IKE_SA(st) ? LAK_PARENT_FAIL : LAK_CHILD_FAIL);

	if (IS_V1_ISAKMP_SA(st)) {
		struct ike_sa *ike = pexpect_ike_sa(st);
		terminate_ike_family(&ike, REASON_TOO_MANY_RETRANSMITS, HERE);
		return;
	}

	struct child_sa *child = pexpect_child_sa(st);
	pstat_sa_failed(&child->sa, REASON_TOO_MANY_RETRANSMITS);
	connection_teardown_child(&child, REASON_TOO_MANY_RETRANSMITS, HERE);
	/* note: no md->st to clear */
}
#endif
