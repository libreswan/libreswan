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
#include "pluto_crypt.h"  /* for pluto_crypto_req & pluto_crypto_req_cont */
#include "ikev2.h"
#include "ip_address.h"
#include "hostpair.h"

/*
 * queue an IPsec SA negotiation pending completion of a
 * suitable phase 1 (IKE SA)
 */
void add_pending(struct fd *whack_sock,
		 struct ike_sa *ike,
		 struct connection *c,
		 lset_t policy,
		 unsigned long try,
		 so_serial_t replacing,
		 struct xfrm_user_sec_ctx_ike *uctx,
		 bool part_of_initiate)
{
	struct pending *p, **pp;

	/* look for duplicate pending IPsec SA's, skip add operation */
	pp = host_pair_first_pending(c);

	for (p = pp ? *pp : NULL; p != NULL; p = p->next) {
		if (p->connection == c && p->ike == ike) {
			address_buf b;
			connection_buf cib;
			dbg("Ignored already queued up pending IPsec SA negotiation with %s "PRI_CONNECTION"",
			    str_address(&c->spd.that.host_addr, &b),
			    pri_connection(c, &cib));
			return;
		}
	}

	p = alloc_thing(struct pending, "struct pending");
	p->whack_sock = dup_any(whack_sock); /*on heap*/
	p->ike = ike;
	p->connection = c;
	p->policy = policy;
	p->try = try;
	p->replacing = replacing;
	p->pend_time = mononow();
	p->part_of_initiate = part_of_initiate; /* useful */
	p->uctx = NULL;
	if (uctx != NULL) {
		p->uctx = clone_thing(*uctx, "pending security context");
		dbg("pending IPsec SA negotiation with security context %s, %d",
		    p->uctx->sec_ctx_value,
		    p->uctx->ctx.ctx_len);
	}

	/*
	 * If this is part of an initiate then there's already enough
	 * going on; no need to log this action.
	 */
	enum stream only = part_of_initiate ? (DBGP(DBG_BASE) ? DEBUG_STREAM : NO_STREAM) : ALL_STREAMS;
	if (only != NO_STREAM) {
		address_buf b;
		connection_buf cibb;
		struct connection *cb = ike->sa.st_connection;
		log_pending(only | RC_COMMENT, p,
			    "queuing pending IPsec SA negotiating with %s IKE SA #%lu "PRI_CONNECTION"",
			    ipstr(&c->spd.that.host_addr, &b),
			    ike->sa.st_serialno, pri_connection(cb, &cibb));
	}
	host_pair_enqueue_pending(c, p, &p->next);
}

/*
 * Release all the whacks awaiting the completion of this state.  This
 * is accomplished by closing all the whack socket file descriptors.
 * We go to some trouble to tell each whack, but to not tell it twice.
 */

void release_pending_whacks(struct state *st, err_t story)
{
	/*
	 * Use fstat() to uniquely identify the whack connection -
	 * multiple sockets to the same whack will have similar
	 * 'struct stat' values.
	 *
	 * If the socket is valid, close it.
	 */
	if (!fd_p(st->st_whack_sock)) {
		dbg("%s: state #%lu has no whack fd",
		     __func__, st->st_serialno);
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
		if (same_fd(st->st_whack_sock, ike->sa.st_whack_sock)) {
			ike_with_same_whack = ike;
			release_any_whack(&ike->sa, HERE, "release pending whacks state's IKE SA");
		} else {
			release_any_whack(st, HERE, "releasing isolated child");
			return;
		}
	} else {
		ike_with_same_whack = pexpect_ike_sa(st);
	}
	pexpect(ike_with_same_whack != NULL);

	/*
	 * Now go through pending children and close the whack socket
	 * of any that are going to be assigned this ST as the parent.
	 * XXX: Is this because the parent is dying so anything
	 * waiting on it should be deleted.
	 *
	 * SAME_FD() is used to identify whack sockets that are
	 * different to ST - when found a further release message is
	 * printed.
	 */

	struct pending **pp = host_pair_first_pending(st->st_connection);
	if (pp == NULL)
		return;
	for (struct pending *p = *pp; p != NULL; p = p->next) {
		dbg("%s: IKE SA #%lu "PRI_FD" has pending CHILD SA with socket "PRI_FD,
		    __func__, p->ike->sa.st_serialno,
		    pri_fd(p->ike->sa.st_whack_sock),
		    pri_fd(p->whack_sock));
		if (p->ike == ike_with_same_whack && fd_p(p->whack_sock)) {
			if (!same_fd(st->st_whack_sock, p->whack_sock)) {
				/* XXX: why not the log file? */
				log_pending(WHACK_STREAM|RC_COMMENT, p,
					    "%s for IKE SA, but releasing whack for pending %s",
					    story,
					    /* IPsec SA or CHILD SA */
					    enum_enum_name(&sa_type_names,
							   p->connection->ike_version,
							   IPSEC_SA));
			}
			close_any(&p->whack_sock);/*on-heap*/
		}
	}
	release_any_whack(st, HERE, "releasing child");
}

/*
 * remove a pending from a linked list.
 *
 * pp points to the link to the entry.
 * *pp will be updated to point to the successor to the original *pp.
 * In effect, we advance *pp.
 * Note: If you are traversing a linked list and deleting some entries,
 * you should not advance pp after calling delete_pending.
 */
static void delete_pending(struct pending **pp)
{
	struct pending *p = *pp;

	*pp = p->next;
	if (p->connection != NULL)
		connection_discard(p->connection);
	close_any(&p->whack_sock); /*on-heap*/

	if (DBGP(DBG_BASE)) {
		if (p->connection == NULL) {
			/* ??? when does this happen? */
			DBG_log("removing pending policy for no connection {%p}", p);
		} else {
			connection_buf cib;
			DBG_log("removing pending policy for "PRI_CONNECTION" {%p}",
				pri_connection(p->connection, &cib), p);
		}
	}

	pfreeany(p->uctx);
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
	struct pending **pp, *p;
	char *what ="unqueuing";

	if (cc == NULL) {
		dbg("unpending state #%lu", ike->sa.st_serialno);
	} else {
		connection_buf cib;
		dbg("unpending state #%lu connection "PRI_CONNECTION"",
		    ike->sa.st_serialno, pri_connection(cc, &cib));
	}

	for (pp = host_pair_first_pending(ike->sa.st_connection);
	     (p = *pp) != NULL; )
	{
		if (p->ike == ike) {
			p->pend_time = mononow();
			switch (ike->sa.st_ike_version) {
			case IKEv2:
				if (cc != p->connection) {
					ikev2_initiate_child_sa(p);
				} else {
					/*
					 * IKEv2 AUTH negotiation
					 * include child.  nothing to
					 * upend, like in IKEv1,
					 * delete it
					 */
					what = "delete from";
				}
				break;
			case IKEv1:
				quick_outI1(p->whack_sock, &ike->sa, p->connection,
					    p->policy,
					    p->try, p->replacing
					    , p->uctx
					    );
				break;
			default:
				bad_case(ike->sa.st_ike_version);
			}
			address_buf b;
			connection_buf cib;
			dbg("%s pending %s with %s "PRI_CONNECTION"",
			    what,
			    (ike->sa.st_ike_version == IKEv2) ? "Child SA" : "Quick Mode",
			    str_address(&p->connection->spd.that.host_addr, &b),
			    pri_connection(p->connection, &cib));

			p->connection = NULL;           /* ownership transferred */
			delete_pending(pp);	/* in effect, advances pp */
		} else {
			pp = &p->next;
		}
	}
}

struct connection *first_pending(const struct ike_sa *ike,
				 lset_t *policy,
				 struct fd **p_whack_sock)
{
	struct pending **pp, *p;

	dbg("getting first pending from state #%lu", ike->sa.st_serialno);

	for (pp = host_pair_first_pending(ike->sa.st_connection);
	     (p = *pp) != NULL; pp = &p->next)
	{
		if (p->ike == ike) {
			close_any(p_whack_sock); /*on-heap*/
			*p_whack_sock = dup_any(p->whack_sock); /*on-heap*/
			*policy = p->policy;
			return p->connection;
		}
	}
	return NULL;
}

/*
 * Look for phase2s that were waiting for a phase 1.  If the time that we
 * have been pending exceeds a DPD timeout that was set, then we call the
 * dpd_timeout() on this state.  We hope this kills the pending state.
 */
bool pending_check_timeout(const struct connection *c)
{
	struct pending **pp, *p;

	for (pp = host_pair_first_pending(c); (p = *pp) != NULL; ) {
		deltatime_t waited = monotimediff(mononow(), p->pend_time);
		connection_buf cib;
		dbg("checking connection "PRI_CONNECTION" for stuck phase 2s (waited %jd, patience 3*%jd)",
		    pri_connection(c, &cib), deltasecs(waited),
		    deltasecs(c->dpd_timeout));
		if (deltasecs(c->dpd_timeout) > 0) {
			if (!monobefore(mononow(),
				monotime_add(p->pend_time,
					deltatimescale(3, 1, c->dpd_timeout)))) {
				connection_buf cib;
				dbg("connection "PRI_CONNECTION" stuck, restarting",
				    pri_connection(c, &cib));
				return TRUE;
			}
		}
		pp = &p->next;
	}
	return FALSE;
}

/* a Main Mode negotiation has been replaced; update any pending */
void update_pending(struct ike_sa *old_ike, struct ike_sa *new_ike)
{
	struct pending *p, **pp;

	pp = host_pair_first_pending(old_ike->sa.st_connection);
	if (pp == NULL)
		return;

	for (p = *pp; p != NULL; p = p->next)
		if (p->ike == old_ike)
			p->ike = new_ike;
}

/* a Main Mode negotiation has failed; discard any pending */
void flush_pending_by_state(struct ike_sa *ike)
{
	struct pending **pp, *p;

	pp = host_pair_first_pending(ike->sa.st_connection);
	if (pp == NULL)
		return;

	while ((p = *pp) != NULL) {
		if (p->ike == ike) {
			/* we don't have to worry about deref to free'ed
			 * *pp, because delete_pending updates pp to
			 * point to the next element before it frees *pp
			 */
			delete_pending(pp);	/* in effect, advances pp */
		} else {
			pp = &p->next;
		}
	}
}

/* a connection has been deleted; discard any related pending */
void flush_pending_by_connection(const struct connection *c)
{
	struct pending **pp, *p;

	pp = host_pair_first_pending(c);
	if (pp == NULL)
		return;

	while ((p = *pp) != NULL) {
		if (p->connection == c) {
			p->connection = NULL; /* prevent delete_pending from releasing */
			delete_pending(pp);	/* in effect, advances pp */
		} else {
			pp = &p->next;
		}
	}
}

void show_pending_phase2(struct show *s,
			 const struct connection *c,
			 const struct ike_sa *ike)
{
	struct pending **pp, *p;

	pp = host_pair_first_pending(c);
	if (pp == NULL)
		return;

	for (p = *pp; p != NULL; p = p->next) {
		if (p->ike == ike) {
			/* connection-name state-number [replacing state-number] */
			WHACK_LOG(RC_COMMENT, show_fd(s), buf) {
				jam(buf, "#%lu: pending ", p->ike->sa.st_serialno);
				jam_string(buf, (ike->sa.st_ike_version == IKEv2) ? "CHILD SA" : "Phase 2");
				jam(buf, " for ");
				jam_connection(buf, c);
				if (p->replacing != SOS_NOBODY) {
					lswlogf(buf, " replacing #%lu", p->replacing);
				}
			}
		}
	}
}

bool in_pending_use(const struct connection *c)
{
	/* see if it is being used by a pending */
	struct pending **pp, *p;

	pp = host_pair_first_pending(c);
	if (pp == NULL)
		return FALSE;

	for (p = *pp; p != NULL; p = p->next)
		if (p->connection == c)
			return TRUE; /* in use, so we're done */

	return FALSE;
}
