/* whack communicating routines, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013-2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2011 Mika Ilmaranta <ilmis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2014-2020 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2014-2017 Antony Antony <antony@phenome.org>
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
 */

#include "whack_crash.h"

#include "defs.h"
#include "state.h"
#include "log.h"
#include "show.h"
#include "connections.h"
#include "ikev1_replace.h"
#include "ikev2_replace.h"
#include "timer.h"

/*
 * Walk through the state table, and delete each state whose phase 1 (IKE)
 * peer is among those given.
 * This function is only called for ipsec whack --crash peer
 */

static void delete_states_by_peer(struct show *s, const ip_address *peer)
{
	/* note: peer_buf and peerstr at same scope */
	address_buf peer_buf;
	const char *peerstr = str_address(peer, &peer_buf);
	struct logger *logger = show_logger(s);

	show(s, "restarting peer %s", peerstr);

	/* first restart the phase1s */
	for (int ph1 = 0; ph1 < 2; ph1++) {
		struct state_filter sf = {
			.search = {
				.order = NEW2OLD,
				.verbose.logger = &global_logger,
				.where = HERE,
			},
		};
		while (next_state(&sf)) {
			struct state *st = sf.st;
			const struct connection *c = st->st_connection;
			endpoint_buf b;
			ldbg(logger, "comparing %s to %s",
			     str_endpoint(&st->st_remote_endpoint, &b),
			     peerstr);

			if (peer != NULL /* ever false? */ &&
			    endpoint_address_eq_address(st->st_remote_endpoint, *peer)) {
				if (ph1 == 0 && IS_IKE_SA(st)) {
					show(s, "peer %s for connection %s crashed; replacing",
					     peerstr, c->name);
					switch (st->st_ike_version) {
#ifdef USE_IKEv1
					case IKEv1:
						ikev1_replace(st);
						break;
#endif
					case IKEv2:
						ikev2_replace(st, /*background*/false);
						break;
					}
				} else {
					event_force(c->config->ike_info->replace_event, st);
				}
			}
		}
	}
}

void whack_crash(const struct whack_message *m, struct show *s)
{
	delete_states_by_peer(s, &m->whack_crash_peer);
}
