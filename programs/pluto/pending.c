/* information about connections between hosts and clients
 *
 * Copyright (C) 1998-2002,2013,2015 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2011 Anthony Tong <atong@TrustedCS.com>
 * Copyright (C) 2017-2018 Antony Antony <antony@phenome.org>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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
#include <arpa/nameser.h>       /* missing from <resolv.h> on old systems */
#include <errno.h>


#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "pending.h"
#include "log.h"
#include "state.h"
#include "packet.h"
#include "demux.h"
#include "ikev1_quick.h"
#include "timer.h"
#include "ikev2.h"
#include "ip_address.h"
#include "ikev2_create_child_sa.h"		/* for initiate_v2_CREATE_CHILD_SA_create_child() */
#include "initiate.h"
#include "show.h"

/*
 * queue an IPsec SA negotiation pending completion of a
 * suitable phase 1 (IKE SA)
 */

void append_pending(struct ike_sa *ike,
		    struct connection *c,
		    lset_t policy,
		    so_serial_t replacing,
		    const shunk_t sec_label,
		    bool part_of_initiating_ike_sa,
		    bool detach_whack)
{
	if (c->pending != NULL) {
		address_buf b;
		connection_buf cib;
		bool duplicate = (c->pending->ike == ike);
		ldbg_sa(ike, "connection "PRI_CONNECTION" is already pending: waiting on IKE SA #%lu connecting to %s; %s",
			pri_connection(c, &cib),
			c->pending->ike->sa.st_serialno,
			str_address(&c->remote->host.addr, &b),
			duplicate ? "ignoring duplicate" : "this IKE SA is different");
		if (duplicate) {
			return;
		}
	}

	struct pending *p = alloc_thing(struct pending, "struct pending");
	c->pending = p;

	/*
	 * Clone C's logger but strip it of any whack attached by the
	 * caller (initiate_connection() say) that will be detached
	 * after this code returns.
	 */
	p->logger = clone_logger(c->logger, HERE);
	if (detach_whack) {
		release_whack(p->logger, HERE);
	}

	p->ike = ike;
	p->connection = connection_addref(c, p->logger); /* no pending logger */
	p->policy = policy;
	p->replacing = replacing;
	p->pend_time = mononow();
	p->sec_label = sec_label;

	/*
	 * If this is part of an initiate then there's already enough
	 * going on; no need to log this action.
	 */
	enum stream only = (!part_of_initiating_ike_sa ? ALL_STREAMS :
			    DBGP(DBG_BASE) ? DEBUG_STREAM :
			    NO_STREAM);

	if (only != NO_STREAM) {
		address_buf b;
		state_buf sab;
		llog(only | RC_COMMENT, p->logger,
		     "queue %s; waiting on %s "PRI_STATE" negotiating with %s",
		     /* "Child SA" or "IPsec SA" */
		     c->config->ike_info->child_sa_name,
		     /* "IKE SA" or "ISAKMP SA" */
		     c->config->ike_info->parent_sa_name,
		     pri_state(&ike->sa, &sab),
		     ipstr(&c->remote->host.addr, &b));
	}

	/*
	 * Hopefully the list is short.
	 *
	 * Append SAs as they arrive so that things are processed
	 * first-in first-out.
	 *
	 * Since, for the IKE SA, the first child is immediately
	 * added, the IKE SA's connection's Child SA is always first.
	 */
	struct pending **end = &ike->sa.st_pending;
	while ((*end) != NULL) {
		end = &(*end)->next;
	}
	*end = p;

	ldbg_sa(ike, "pending: %s() ike %p pending %p connection %p ike %p",
		__func__, ike, p, p->connection, p->ike);
}

/*
 * Release all the whacks awaiting the completion of this state.  This
 * is accomplished by closing all the whack socket file descriptors.
 * We go to some trouble to tell each whack, but to not tell it twice.
 */

void release_pending_whacks(struct state *st, err_t story)
{
	if (!whack_attached(st->logger)) {
		pdbg(st->logger, "%s: state has no whack fd", __func__);
		return;
	}

	/*
	 * Check for the SA's parent and if that needs to disconnect.
	 *
	 * For instance, when the IKE_SA establishes but the first
	 * CHILD_SA fails with a timeout then this code will be called
	 * with the CHILD_SA.
	 *
	 * XXX: Since this is meant to release pending whacks, should
	 * this check for, and release the whacks for any pending
	 * CHILD_SA attached to this ST's IKE SA?
	 */
	struct ike_sa *ike_with_same_whack = NULL;
	if (IS_CHILD_SA(st)) {
		struct ike_sa *ike = ike_sa(st, HERE);
		if (ike == NULL || !same_whack(st->logger, ike->sa.logger)) {
			release_whack(st->logger, HERE);
			return;
		}

		ike_with_same_whack = ike;
		release_whack(ike->sa.logger, HERE);
	} else {
		ike_with_same_whack = pexpect_ike_sa(st);
	}
	pexpect(ike_with_same_whack != NULL);

	/*
	 * Now go through pending children and close the whack socket
	 * of any that are going to be assigned this ST as the parent.
	 *
	 * XXX: Is this because the parent is dying so anything
	 * waiting on it should be detached.
	 *
	 * SAME_FD() is used to identify whack sockets that are
	 * different to ST - when found a further release message is
	 * printed.
	 */

	for (struct pending *p = st->st_pending; p != NULL; p = p->next) {

		ldbg(st->logger, "pending: %s() ike %p pending %p connection %p ike %p",
		     __func__, st, p, p->connection, p->ike);

		bool has_whack = whack_attached(p->logger);

		pdbg(p->logger,
		     "pending: %s: %s SA "PRI_SO" "PRI_LOGGER" has %s SA with whack "PRI_LOGGER,
		     __func__,
		     p->ike->sa.st_connection->config->ike_info->parent_name,
		     pri_so(p->ike->sa.st_serialno),
		     pri_logger(p->ike->sa.logger),
		     p->ike->sa.st_connection->config->ike_info->parent_name,
		     pri_logger(p->logger));

		if (p->ike != ike_with_same_whack) {
			/* none of our business */
			continue;
		}

		if (!has_whack) {
			/* nothing to do */
			continue;
		}

		if (!same_whack(st->logger, p->logger)) {
			/* XXX: why not the log file? */
			llog(WHACK_STREAM|RC_COMMENT, p->logger,
			     "%s for IKE SA, but releasing whack for pending %s",
			     story,
			     /* "IPsec SA" or "CHILD SA" */
			     p->connection->config->ike_info->child_sa_name);
		}
		release_whack(p->logger, HERE);
	}

	/* last gasp */
	release_whack(st->logger, HERE);
}

/*
 * Remove a pending from a linked list.
 *
 * pp points to the link to the entry.
 * *pp will be updated to point to the successor to the original *pp.
 * In effect, we advance *pp.
 *
 * Note: If you are traversing a linked list and deleting some
 * entries, you should not advance pp after calling delete_pending.
 */

static void delete_pending(struct pending **pp, const char *what)
{
	/* remove from list */
	struct pending *p = *pp;
	*pp = p->next;
	struct connection *c = p->connection;
	c->pending = NULL;

	connection_buf cib;
	ldbg(c->logger,
	     "pending: %s pending [%p] %s connection "PRI_CONNECTION" [%p]",
	     what, p, (c->config->ike_version == IKEv2 ? "Child SA" : "Quick Mode"),
	     pri_connection(c, &cib), c);

	connection_delref(&p->connection, &global_logger);
	free_logger(&p->logger, HERE);
	pfree(p);
}

/*
 * Look for phase2s that were waiting for a phase 1.
 *
 * XXX instead of doing this work NOW, we should simply create an event
 *     in zero future time to unpend the state.
 * YYY but, in fact, quick_mode will enqueue a cryptographic operation
 *     anyway, which will get done "later" anyway, so make it is just fine
 *     as it is.
 *     In IKEv2 it called when AUTH is complete, child is established.
 *     Established child get removed not unpend.
 */

void unpend(struct ike_sa *ike, struct connection *cc)
{
	if (cc == NULL) {
		ldbg_sa(ike, "pending: unpending state %p #%lu pending %p",
			ike, ike->sa.st_serialno, ike->sa.st_pending);
	} else {
		connection_buf cib;
		ldbg_sa(ike, "pending: unpending state #%lu connection "PRI_CONNECTION"",
			ike->sa.st_serialno, pri_connection(cc, &cib));
	}

	struct pending **pp = &ike->sa.st_pending;
	while ((*pp) != NULL) {

		struct pending *p = (*pp);

		ldbg_sa(ike, "pending: %s() ike %p pending %p connection %p ike %p",
			__func__, ike, p, p->connection, p->ike);

		p->pend_time = mononow();
		char *what ="unqueuing";
		switch (ike->sa.st_ike_version) {
		case IKEv2:
			if (cc == p->connection) {
				/*
				 * IKEv2 AUTH negotiation
				 * include child.  nothing to
				 * upend, like in IKEv1,
				 * delete it
				 */
				what = "delete from";
			} else if (!already_has_larval_v2_child(ike, p->connection)) {
				connection_attach(p->connection, p->logger);
				submit_v2_CREATE_CHILD_SA_new_child(ike, p->connection,
								    p->policy,
								    /*detach_whack*/false);
				connection_detach(p->connection, p->logger);
			}
			break;
		case IKEv1:
#ifdef USE_IKEv1
			connection_attach(p->connection, p->logger);
			quick_outI1(ike, p->connection,
				    p->policy,
				    p->replacing);
			connection_detach(p->connection, p->logger);
#endif
			break;
		default:
			bad_case(ike->sa.st_ike_version);
		}

		delete_pending(pp, what);	/* in effect, advances pp */
	}
}

struct connection *first_pending(const struct ike_sa *ike)
{
	struct pending *p = ike->sa.st_pending;
	if (p != NULL) {
		connection_attach(p->connection, p->logger);
		ldbg_sa(ike, "pending: %s() ike %p pending %p connection %p ike %p",
			__func__, ike, p, p->connection, p->ike);
		return p->connection;
	}
	ldbg_sa(ike, "pending: no first pending from state");
	return NULL;
}

/* a IKE SA negotiation has been replaced; update any pending */

void move_pending(struct ike_sa *old, struct ike_sa *new)
{
	if (pbad(old == NULL)) {
		return;
	}

	if (pbad(old == new)) {
		return;
	}

	ldbg(old->sa.logger, "pending: update ike %p pending %p -> ike %p pending %p",
	     old, old->sa.st_pending,
	     new, new->sa.st_pending);

	struct pending **pp = &new->sa.st_pending;
	while ((*pp) != NULL) {
		pp = &(*pp)->next;
	}

	(*pp) = old->sa.st_pending;
	old->sa.st_pending = NULL;
}

/*
 * An IKE SA negotiation has failed; discard any pending.
 *
 * Danger: this code deletes connections.
 */
void flush_pending_by_state(struct ike_sa *ike)
{
	ldbg(ike->sa.logger, "pending: %s() ike %p pending %p",
	     __func__, ike, ike->sa.st_pending);

	struct pending **pp = &ike->sa.st_pending;
	while ((*pp) != NULL) {
		struct pending *p = (*pp);

		ldbg_sa(ike, "pending: %s() ike %p pending %p connection %p ike %p",
			__func__, ike, p, p->connection, p->ike);

		/*
		 * We don't have to worry about deref to
		 * free'ed *pp, because delete_pending updates
		 * pp to point to the next element before it
		 * frees *pp
		 *
		 * We don't need to worry about delrefing
		 * .connection because delete_pending() will
		 * do it for us.
		 */
		if ((*pp)->connection != ike->sa.st_connection) {
			/*
			 * Find another IKE SA willing to care
			 * for the CUCKOO, or initiate our
			 * own.
			 */
			connection_reschedule((*pp)->connection, (*pp)->logger, HERE);
		}
		delete_pending(pp, "flush");	/* in effect, advances pp */
	}
}

/*
 * A connection is been deleted; look for and remove the connection
 * from the host-pair pending list.
 *
 * The host-pair pending list contains all connections waiting for an
 * IKE SA to establish between the two ends.
 *
 * Note: this code DOES NOT delete the connection (ya!).
 */

void remove_connection_from_pending(const struct connection *c)
{
	if (c->pending == NULL) {
		return;
	}

	struct ike_sa *ike = c->pending->ike;
	ldbg_sa(ike, "pending: %s() ike %p pending %p connection %p connection %p",
		__func__, ike, c->pending, c->pending->connection, c);

	struct pending **pp = &c->pending->ike->sa.st_pending;
	while ((*pp) != NULL && (*pp) != c->pending) {
		pp = &(*pp)->next;
	}

	/* should have been found */
	if (PBAD(c->logger, (*pp) == NULL)) {
		return;
	}

	delete_pending(pp, "flush");
}

bool connection_is_pending(const struct connection *c)
{
	return (c->pending != NULL);
}
