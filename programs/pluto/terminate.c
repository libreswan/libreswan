/* shutdown connections: IKEv1/IKEv2
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 Paul Wouters <pwouters@redhat.com>
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

#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sysdep.h"
#include "constants.h"
#include "lswalloc.h"
#include "id.h"
#include "x509.h"
#include "certs.h"

#include "defs.h"
#include "connections.h"        /* needs id.h */
#include "pending.h"
#include "foodgroups.h"
#include "packet.h"
#include "demux.h"      /* needs packet.h */
#include "state.h"
#include "timer.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "server.h"
#include "kernel.h"     /* needs connections.h */
#include "log.h"
#include "keys.h"
#include "whack.h"
#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "ikev1_xauth.h"
#include "nat_traversal.h"
#include "terminate.h"
#include "host_pair.h"

static void terminate_connection(struct connection *c)
{
	llog(RC_LOG, c->logger, "terminating SAs using this connection");

	del_policy(c, POLICY_UP);

	/*
	 * XXX: see ikev2-removed-iface-01
	 *
	 * Extra output appears because of the unroute:
	 *
	 * +002 "test2": connection no longer oriented - system interface change?
	 * +002 "test2": unroute-host output: Device "NULL" does not exist.
	 */
	remove_connection_from_pending(c);
	delete_states_by_connection(c);
	connection_unroute(c, HERE);
}

void terminate_connections(struct connection **c, struct logger *logger, where_t where)
{
	switch ((*c)->local->kind) {
	case CK_INSTANCE:
	case CK_LABELED_CHILD: /* should not happen? */
		connection_attach(*c, logger);
		terminate_connection(*c);
		delete_connection(c);
		return;

	case CK_PERMANENT:
	case CK_LABELED_PARENT:
		connection_attach(*c, logger);
		terminate_connection(*c);
		connection_detach(*c, logger);
		return;

	case CK_TEMPLATE:
	case CK_GROUP:
	case CK_LABELED_TEMPLATE:
	{
		struct connection_filter cq = {
			.clonedfrom = *c,
			.where = HERE,
		};
		while (next_connection_old2new(&cq)) {
			terminate_connections(&cq.c, logger, where);
		}
		return;
	}
	case CK_INVALID:
		break;
	}
	bad_case((*c)->local->kind);
}
