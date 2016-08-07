/* information about connections between hosts and clients
 *
 * Copyright (C) 1998-2002,2013,2015 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2011 Anthony Tong <atong@TrustedCS.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
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

#include <libreswan.h>
#include "kameipsec.h"

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

/* struct pending, the structure representing IPsec SA
 * negotiations delayed until a Keying Channel has been negotiated.
 * Essentially, a pending call to quick_outI1.
 */

struct pending {
	int whack_sock;
	struct state *isakmp_sa;
	struct connection *connection;
	lset_t policy;
	unsigned long try;
	so_serial_t replacing;
	monotime_t pend_time;
#ifdef HAVE_LABELED_IPSEC
	struct xfrm_user_sec_ctx_ike *uctx;
#endif

	struct pending *next;
};

/*
 * queue an IPsec SA negotiation pending completion of a
 * suitable phase 1 (IKE SA)
 */
void add_pending(int whack_sock,
		 struct state *isakmp_sa,
		 struct connection *c,
		 lset_t policy,
		 unsigned long try,
		 so_serial_t replacing
#ifdef HAVE_LABELED_IPSEC
		 , struct xfrm_user_sec_ctx_ike *uctx
#endif
		 )
{
	struct pending *p, **pp;

	/* look for duplicate pending IPsec SA's, skip add operation */
	pp = host_pair_first_pending(c);

	for (p = pp ? *pp : NULL; p != NULL; p = p->next) {
		if (p->connection == c && p->isakmp_sa == isakmp_sa) {
			DBG(DBG_CONTROL, {
				ipstr_buf b;
				char cib[CONN_INST_BUF];
				DBG_log("Ignored already queued up pending IPsec SA negotiation with %s \"%s\"%s",
					ipstr(&c->spd.that.host_addr, &b),
					c->name, fmt_conn_instance(c, cib));
			});
			return;
		}
	}

	DBG(DBG_CONTROL, {
		ipstr_buf b;
		char cib[CONN_INST_BUF];
		DBG_log("Queuing pending IPsec SA negotiating with %s \"%s\"%s",
			ipstr(&c->spd.that.host_addr, &b),
			c->name, fmt_conn_instance(c, cib));
	});

	p = alloc_thing(struct pending, "struct pending");
	p->whack_sock = whack_sock;
	p->isakmp_sa = isakmp_sa;
	p->connection = c;
	p->policy = policy;
	p->try = try;
	p->replacing = replacing;
	p->pend_time = mononow();
#ifdef HAVE_LABELED_IPSEC
	p->uctx = NULL;
	if (uctx != NULL) {
		p->uctx = clone_thing(*uctx, "pending security context");
		DBG(DBG_CONTROL,
		    DBG_log("pending IPsec SA negotiation with security context %s, %d",
			    p->uctx->sec_ctx_value,
			    p->uctx->ctx.ctx_len));
	}
#endif

	host_pair_enqueue_pending(c, p, &p->next);
}

/* Release all the whacks awaiting the completion of this state.
 * This is accomplished by closing all the whack socket file descriptors.
 * We go to a lot of trouble to tell each whack, but to not tell it twice.
 */
void release_pending_whacks(struct state *st, err_t story)
{
	struct pending *p, **pp;
	struct stat stst;

	if (st->st_whack_sock == NULL_FD ||
	    fstat(st->st_whack_sock, &stst) != 0) {
		/* resulting st_dev/st_ino ought to be distinct */
		zero(&stst);	/* OK: no pointer fields */
	}

	release_whack(st);

	pp = host_pair_first_pending(st->st_connection);
	if (pp == NULL)
		return;

	for (p = *pp;
	     p != NULL;
	     p = p->next) {
		if (p->isakmp_sa == st && p->whack_sock != NULL_FD) {
			struct stat pst;

			if (fstat(p->whack_sock, &pst) == 0 &&
			    (stst.st_dev != pst.st_dev ||
			     stst.st_ino != pst.st_ino)) {
				passert(whack_log_fd == NULL_FD);
				whack_log_fd = p->whack_sock;
				whack_log(RC_COMMENT,
					  "%s for IKE SA, but releasing whack for pending IPSEC SA",
					  story);
				whack_log_fd = NULL_FD;
			}
			close(p->whack_sock);
			p->whack_sock = NULL_FD;
		}
	}
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
	close_any(p->whack_sock);

	DBG(DBG_DPD, {
		if (p->connection == NULL) {
			/* ??? when does this happen? */
			DBG_log("removing pending policy for no connection {%p}",
				p);
		} else {
			char cib[CONN_INST_BUF];
			DBG_log("removing pending policy for \"%s\"%s {%p}",
				p->connection->name,
				fmt_conn_instance(p->connection, cib),
				p);
		}
	});

#ifdef HAVE_LABELED_IPSEC
	pfreeany(p->uctx);
#endif

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
 */
void unpend(struct state *st)
{
	struct pending **pp, *p;

	DBG(DBG_DPD,
	    DBG_log("unpending state #%lu", st->st_serialno));

	for (pp = host_pair_first_pending(st->st_connection);
	     (p = *pp) != NULL; )
	{
		if (p->isakmp_sa == st) {
			DBG(DBG_CONTROL, {
				ipstr_buf b;
				char cib[CONN_INST_BUF];
				DBG_log("unqueuing pending %s with %s \"%s\"%s %s",
					st->st_ikev2 ? "Child SA" : "Quick Mode",
					ipstr(&p->connection->spd.that.host_addr, &b),
					p->connection->name,
					fmt_conn_instance(p->connection, cib),
					enum_name(&pluto_cryptoimportance_names,
						  st->st_import));
			});

			p->pend_time = mononow();
			if (!st->st_ikev2) {
				(void) quick_outI1(p->whack_sock, st, p->connection,
						   p->policy,
						   p->try, p->replacing
#ifdef HAVE_LABELED_IPSEC
						   , p->uctx
#endif
						   );
			}
			p->whack_sock = NULL_FD;        /* ownership transferred */
			p->connection = NULL;           /* ownership transferred */
			delete_pending(pp);	/* in effect, advances pp */
		} else {
			pp = &p->next;
		}
	}
}

struct connection *first_pending(const struct state *st,
				 lset_t *policy,
				 int *p_whack_sock)
{
	struct pending **pp, *p;

	DBG(DBG_DPD,
	    DBG_log("getting first pending from state #%lu", st->st_serialno));

	for (pp = host_pair_first_pending(st->st_connection);
	     (p = *pp) != NULL; pp = &p->next)
	{
		if (p->isakmp_sa == st) {
			*p_whack_sock = p->whack_sock;
			*policy = p->policy;
			return p->connection;
		}
	}
	return NULL;
}

/*
 * Look for phase2s that were waiting for a phase 1.  If the time that we
 * have been pending exceeds a DPD timeout that was set, then we call the
 * dpd_timeout() on this state, which hopefully kills this pending state.
 */
bool pending_check_timeout(const struct connection *c)
{
	struct pending **pp, *p;

	for (pp = host_pair_first_pending(c); (p = *pp) != NULL; ) {
		DBG(DBG_DPD, {
			deltatime_t waited = monotimediff(mononow(), p->pend_time);
			char cib[CONN_INST_BUF];
			DBG_log("checking connection \"%s\"%s for stuck phase 2s (waited %lds, patience 3*%lds)",
				c->name,
				fmt_conn_instance(c, cib),
				(long) deltasecs(waited),
				(long) deltasecs(c->dpd_timeout));
			});

		if (deltasecs(c->dpd_timeout) > 0) {
			if (!monobefore(mononow(),
				monotimesum(p->pend_time,
					deltatimescale(3, 1, c->dpd_timeout)))) {
				DBG(DBG_DPD, {
					char cib[CONN_INST_BUF];
					DBG_log("connection \"%s\"%s stuck, restarting",
						c->name, fmt_conn_instance(c, cib));
				});
				return TRUE;
			}
		}
		pp = &p->next;
	}
	return FALSE;
}

/* a Main Mode negotiation has been replaced; update any pending */
void update_pending(struct state *os, struct state *ns)
{
	struct pending *p, **pp;

	pp = host_pair_first_pending(os->st_connection);
	if (pp == NULL)
		return;

	for (p = *pp; p != NULL; p = p->next)
		if (p->isakmp_sa == os)
			p->isakmp_sa = ns;
}

/* a Main Mode negotiation has failed; discard any pending */
void flush_pending_by_state(struct state *st)
{
	struct pending **pp, *p;

	pp = host_pair_first_pending(st->st_connection);
	if (pp == NULL)
		return;

	while ((p = *pp) != NULL) {
		if (p->isakmp_sa == st) {
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

void show_pending_phase2(const struct connection *c, const struct state *st)
{
	struct pending **pp, *p;

	pp = host_pair_first_pending(c);
	if (pp == NULL)
		return;

	for (p = *pp; p != NULL; p = p->next) {
		if (p->isakmp_sa == st) {
			/* connection-name state-number [replacing state-number] */
			char cip[CONN_INST_BUF];

			fmt_conn_instance(p->connection, cip);
			whack_log(RC_COMMENT,
				  "#%lu: pending Phase 2 for \"%s\"%s replacing #%lu",
				  p->isakmp_sa->st_serialno,
				  p->connection->name,
				  cip,
				  p->replacing);
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
