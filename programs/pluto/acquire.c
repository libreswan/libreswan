/* handle acquire (ondemand) from kernel, for libreswan
 *
 * Copyright (C) 1998-2010,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2009 Stefan Arentz <stefan@arentz.ca>
 * Copyright (C) 2009-2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2007-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Panagiotis Tamtamis <tamtamis@gmail.com>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
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

#include "defs.h"
#include "acquire.h"

#include "log.h"
#include "kernel.h"
#include "orient.h"
#include "instantiate.h"
#include "initiate.h"

/* (Possibly) Opportunistic Initiation:
 *
 * Knowing clients (single IP addresses), try to build a tunnel.  This
 * may involve discovering a gateway and instantiating an
 * Opportunistic connection.  Called when a packet is caught by a
 * %trap, or when whack --oppohere --oppothere is used.  It may turn
 * out that an existing or non-opporunistic connection can handle the
 * traffic.
 *
 * Most of the code will be restarted if an ADNS request is made to
 * discover the gateway.  The only difference between the first and
 * second entry is whether gateways_from_dns is NULL or not.
 *
 *	initiate_opportunistic: initial entrypoint
 *	continue_oppo: where we pickup when ADNS result arrives
 *	initiate_opportunistic_body: main body shared by above routines
 *	cannot_ondemand: a helper function to log a diagnostic
 *
 * This structure repeats a lot of code when the ADNS result arrives.
 * This seems like a waste, but anything learned the first time
 * through may no longer be true!
 *
 * After the first IKE message is sent, the regular state machinery
 * carries negotiation forward.
 */

static void cannot_ondemand(lset_t rc_flags, const struct kernel_acquire *b, const char *ughmsg)
{
	LLOG_JAMBUF(rc_flags, b->logger, buf) {
		jam(buf, "cannot ");
		jam_kernel_acquire(buf, b);
		jam(buf, ": %s", ughmsg);
	}

	if (b->by_acquire) {
		ldbg(b->logger, "initiate from acquire so kernel policy is assumed to already expire");
	} else {
		ldbg(b->logger, "initiate from whack so nothing to kernel policy to expire");
	}
}

void initiate_ondemand(const struct kernel_acquire *b)
{
	threadtime_t inception = threadtime_start();

	if (impair.cannot_ondemand) {
		llog(RC_LOG, b->logger, "IMPAIR: cannot ondemand forced");
		return;
	}

	/*
	 * What connection shall we use?  First try for one that
	 * explicitly handles the clients.
	 */

	if (!b->packet.ip.is_set) {
		cannot_ondemand(RC_OPPOFAILURE, b, "impossible IP address");
		return;
	}

	/* XXX: shouldn't this have happened earlier? */
	if (thingeq(b->packet.src.bytes, b->packet.dst.bytes)) {
		/*
		 * NETKEY gives us acquires for our own IP. This code
		 * does not handle talking to ourselves on another ip.
		 */
		cannot_ondemand(RC_OPPOFAILURE, b, "acquire for our own IP address");
		return;
	}

	struct connection *c = find_connection_for_packet(b->packet,
							  b->sec_label,
							  b->logger);
	if (c == NULL) {
		/*
		 * No connection explicitly handles the clients and
		 * there are no Opportunistic connections -- whine and
		 * give up.  The failure policy cannot be gotten from
		 * a connection; we pick %pass.
		 */
		cannot_ondemand(RC_OPPOFAILURE, b, "no routed template covers this pair");
		return;
	}

	/* else C would not have been found */
	if (!PEXPECT(b->logger, oriented(c))) {
		return;
	}

	/*
	 * addref() or instantiate() C creating CP.  CP must be
	 * delref()ed.
	 */

	struct connection *cp =
		(is_labeled_template(c) ? labeled_template_instantiate(c, (c)->remote->host.addr, HERE) :
		 is_opportunistic_template(c) ? oppo_initiator_instantiate(c, b->packet, HERE) :
		 is_permanent(c) ? connection_addref(c, b->logger) :
		 is_instance(c) ? connection_addref(c, b->logger) /*valid?!?*/:
		 NULL);

	if (cp == NULL) {
		connection_attach(c, b->logger);
		LLOG_PEXPECT_JAMBUF(c->logger, HERE, buf) {
			jam_string(buf, "can't acquire (on-demand): ");
			jam_kernel_acquire(buf, b);
		}
		connection_detach(c, b->logger);
		return;
	}

	connection_attach(cp, b->logger);
	LLOG_JAMBUF(RC_LOG, cp->logger, buf) {
		jam_kernel_acquire(buf, b);
	}

	const struct child_policy policy = child_sa_policy(cp);
	initiate(cp, &policy, SOS_NOBODY,
		 &inception, b->sec_label,
		 b->background, cp->logger,
		 INITIATED_BY_ACQUIRE,
		 HERE);

	connection_detach(cp, b->logger);
	connection_delref(&cp, b->logger);

}
