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
#include "whack_connection.h"		/* for whack_connection() */
#include "ikev1_delete.h"
#include "ikev2_delete.h"

static void delete_v1_states(struct connection *c,
			     struct ike_sa **ike,
			     struct child_sa **child,
			     enum whack_state whacamole)
{
	switch (whacamole) {
	case WHACK_START_IKE:
		/*
		 * IKEv1 announces the death of the ISAKMP SA after
		 * all the children have gone (reverse of IKEv2).
		 */
		state_attach(&(*ike)->sa, c->logger);
		(*ike)->sa.st_viable_parent = false;
		return;
	case WHACK_LURKING_CHILD:
		state_attach(&(*child)->sa, c->logger);
		delete_child_sa(child);
		return;
	case WHACK_LURKING_IKE:
		state_attach(&(*ike)->sa, c->logger);
		delete_ike_sa(ike);
		return;
	case WHACK_CHILD:
	case WHACK_CUCKOO:
	{
		/*
		 * Can't always assume IKE is suitable for sending
		 * deletes: for CHILD it probably is; and for CUCKOO
		 * it is NULL.
		 *
		 * Hence just always re-compute it.
		 */
		state_attach(&(*child)->sa, c->logger);
		struct ike_sa *isakmp = /* could be NULL */
			established_isakmp_sa_for_state(&(*child)->sa, /*viable-parent*/false);
		/* IKEv1 has cuckoos */
		llog_n_maybe_send_v1_delete(isakmp, &(*child)->sa, HERE);
		connection_delete_child(child, HERE);
		return;
	}
	case WHACK_ORPHAN:
		/* IKEv1 has orphans */
		state_attach(&(*child)->sa, c->logger);
		PEXPECT(c->logger, ike == NULL);
		connection_delete_child(child, HERE);
		return;
	case WHACK_SIBLING:
		/*
		 * When IKEv1 deletes an IKE SA any siblings are
		 * orphaned.
		 */
		return;
	case WHACK_IKE:
		/*
		 * When IKEv1 deletes an IKE SA it always sends a
		 * delete notify; hence handle this in WHACK_STOP_IKE.
		 */
		return;
	case WHACK_STOP_IKE:
	{
		struct ike_sa *isakmp =
			established_isakmp_sa_for_state(&(*ike)->sa, /*viable-parent*/false);
		llog_n_maybe_send_v1_delete(isakmp, &(*ike)->sa, HERE);
		connection_delete_ike(ike, HERE);
		return;
	}
	}
	bad_case(whacamole);
}

static void delete_v2_states(struct connection *c,
			     struct ike_sa **ike,
			     struct child_sa **child,
			     enum whack_state whacamole)
{
	switch (whacamole) {
	case WHACK_START_IKE:
		/* announce to the world */
		state_attach(&(*ike)->sa, c->logger);
		(*ike)->sa.st_viable_parent = false;
		record_n_send_n_log_v2_delete(*ike, HERE);
		return;
	case WHACK_LURKING_CHILD:
		state_attach(&(*child)->sa, c->logger);
		delete_child_sa(child);
		return;
	case WHACK_LURKING_IKE:
		state_attach(&(*ike)->sa, c->logger);
		delete_ike_sa(ike);
		return;
	case WHACK_CHILD:
		state_attach(&(*child)->sa, c->logger);
		connection_delete_child(child, HERE);
		return;
	case WHACK_CUCKOO:
		state_attach(&(*child)->sa, c->logger);
		PEXPECT(c->logger, ike == NULL);
		connection_delete_child(child, HERE);
		return;
	case WHACK_ORPHAN:
		state_attach(&(*child)->sa, c->logger);
		llog_pexpect(c->logger, HERE, "unexpected orphan Child SA "PRI_SO,
			     (*child)->sa.st_serialno);
		PEXPECT(c->logger, ike == NULL);
		delete_child_sa(child);
		return;
	case WHACK_SIBLING:
		state_attach(&(*child)->sa, c->logger);
		connection_delete_child(child, HERE);
		return;
	case WHACK_IKE:
		connection_delete_ike_family(ike, HERE);
		return;
	case WHACK_STOP_IKE:
		delete_ike_sa(ike);
		return;
	}
	bad_case(whacamole);
}

static void delete_states(struct connection *c,
			  struct ike_sa **ike,
			  struct child_sa **child,
			  enum whack_state whacamole)
{
	switch (c->config->ike_version) {
	case IKEv1:
		delete_v1_states(c, ike, child, whacamole);
		return;
	case IKEv2:
		delete_v2_states(c, ike, child, whacamole);
		return;
	}
	bad_case(c->config->ike_version);
}

void terminate_all_connection_states(struct connection *c, where_t where)
{
	whack_connection_states(c, delete_states, where);
}

static void terminate_and_down_connection(struct connection *c, struct logger *logger)
{
	llog(RC_LOG, c->logger, "terminating SAs using this connection");
	del_policy(c, policy.up);

	/*
	 * XXX: see ikev2-removed-iface-01
	 *
	 * Extra output appears because of the unroute:
	 *
	 * +002 "test2": connection no longer oriented - system interface change?
	 * +002 "test2": unroute-host output: Device "NULL" does not exist.
	 */
	c = connection_addref(c, logger);
	terminate_all_connection_states(c, HERE);
	connection_delref(&c, logger);
}

void terminate_and_down_connections(struct connection **cp, struct logger *logger, where_t where)
{
	switch ((*cp)->local->kind) {
	case CK_INSTANCE:
	case CK_LABELED_CHILD: /* should not happen? */
		connection_attach((*cp), logger);
		terminate_and_down_connection((*cp), logger);
		delete_connection(cp);
		return;

	case CK_PERMANENT:
	case CK_LABELED_PARENT:
		connection_attach((*cp), logger);
		terminate_and_down_connection((*cp), logger);
		connection_detach((*cp), logger);
		return;

	case CK_TEMPLATE:
	case CK_GROUP:
	case CK_LABELED_TEMPLATE:
	{
		struct connection_filter cq = {
			.clonedfrom = (*cp),
			.where = HERE,
		};
		while (next_connection_old2new(&cq)) {
			terminate_and_down_connections(&cq.c, logger, where);
		}
		return;
	}
	case CK_INVALID:
		break;
	}
	bad_case((*cp)->local->kind);
}
