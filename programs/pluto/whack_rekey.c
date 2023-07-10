/* rekey connections: IKEv2
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 Antony Antony <antony@phenome.org>
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
#include "log.h"
#include "connections.h"
#include "state.h"
#include "timer.h"
#include "whack_rekey.h"
#include "show.h"
#include "whack_connection.h"

static bool rekey_state(const struct whack_message *m, struct show *s,
			struct connection *c, enum sa_type sa_type, so_serial_t so)
{
	struct logger *logger = show_logger(s);

	if (!is_permanent(c) && !is_instance(c)) {
		/* silently skip */
		connection_buf cb;
		ldbg(logger, "skipping !permanent/!instance connection "PRI_CONNECTION,
		     pri_connection(c, &cb));
		return false;
	}

	struct state *st = state_by_serialno(so);
	if (st == NULL) {
		connection_attach(c, logger);
		llog(RC_LOG, c->logger, "connection does not have %s",
		     sa_name(c->config->ike_version, sa_type));
		connection_detach(c, logger);
		return false;
	}

	if (!m->whack_async) {
		state_attach(st, logger);
		if (IS_CHILD_SA(st)) {
			struct ike_sa *ike = ike_sa(st, HERE);
			state_attach(&ike->sa, logger);
		}
	}

	ldbg(logger, "rekeying "PRI_SO, pri_so(so));
	event_force(EVENT_v2_REKEY, st);
	return true;
}

static bool whack_rekey_ike(struct show *s,
			    struct connection **c,
			    const struct whack_message *m)
{
	return rekey_state(m, s, *c, IKE_SA, (*c)->newest_ike_sa);
}

static bool whack_rekey_child(struct show *s,
			      struct connection **c,
			      const struct whack_message *m)
{
	return rekey_state(m, s, *c, IPSEC_SA, (*c)->newest_ipsec_sa);
}

void whack_rekey(const struct whack_message *m, struct show *s, enum sa_type sa_type)
{
	struct logger *logger = show_logger(s);
	if (m->name == NULL) {
		/* leave bread crumb */
		llog(RC_FATAL, logger,
		     "received command to rekey connection, but did not receive the connection name - ignored");
		return;
	}

	switch (sa_type) {
	case IKE_SA:
		whack_each_connection(m, s, whack_rekey_ike,
				      (struct each) {
					      .log_unknown_name = true,
					      .skip_instances = false,
				      });
		return;
	case IPSEC_SA:
		whack_each_connection(m, s, whack_rekey_child,
				      (struct each) {
					      .log_unknown_name = true,
					      .skip_instances = false,
				      });
		return;
	}
	bad_case(sa_type);
}
