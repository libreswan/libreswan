/* information about connections between hosts and clients
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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
 *
 * RCSID $Id: pending.c,v 1.5 2005/03/27 20:18:13 mcr Exp $
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
#include <resolv.h>
#include <arpa/nameser.h>	/* missing from <resolv.h> on old systems */
#include <sys/queue.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>
#include "kameipsec.h"

#include "constants.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "ac.h"
#include "smartcard.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "connections.h"	/* needs id.h */
#include "pending.h"
#include "log.h"
#include "state.h"
#include "packet.h"
#include "demux.h"
#include "ikev1_quick.h"
#include "timer.h"

/* struct pending, the structure representing Quick Mode
 * negotiations delayed until a Keying Channel has been negotiated.
 * Essentially, a pending call to quick_outI1.
 */

struct pending {
    int           whack_sock;
    struct state *isakmp_sa;
    struct connection *connection;
    lset_t        policy;
    unsigned long try;
    so_serial_t   replacing;
    time_t        pend_time;

    struct pending *next;
};

/* queue a Quick Mode negotiation pending completion of a suitable Main Mode */
void
add_pending(int whack_sock
, struct state *isakmp_sa
, struct connection *c
, lset_t policy
, unsigned long try
, so_serial_t replacing)
{
    struct pending *p = alloc_thing(struct pending, "struct pending");

    DBG(DBG_CONTROL, DBG_log("Queuing pending Quick Mode with %s \"%s\""
	, ip_str(&c->spd.that.host_addr)
	, c->name));
    p->whack_sock = whack_sock;
    p->isakmp_sa = isakmp_sa;
    p->connection = c;
    p->policy = policy;
    p->try = try;
    p->replacing = replacing;
    p->pend_time = time(NULL);

    host_pair_enqueue_pending(c, p, &p->next);
}

/* Release all the whacks awaiting the completion of this state.
 * This is accomplished by closing all the whack socket file descriptors.
 * We go to a lot of trouble to tell each whack, but to not tell it twice.
 */
void
release_pending_whacks(struct state *st, err_t story)
{
    struct pending *p, **pp;
    struct stat stst;

    if (st->st_whack_sock == NULL_FD || fstat(st->st_whack_sock, &stst) != 0)
	zero(&stst);	/* resulting st_dev/st_ino ought to be distinct */

    release_whack(st);

    pp = host_pair_first_pending(st->st_connection);
    if(pp == NULL) return;

    for (p = *pp;
	 p != NULL;
	 p = p->next)
    {
	if (p->isakmp_sa == st && p->whack_sock != NULL_FD)
	{
	    struct stat pst;

	    if (fstat(p->whack_sock, &pst) == 0
	    && (stst.st_dev != pst.st_dev || stst.st_ino != pst.st_ino))
	    {
		passert(whack_log_fd == NULL_FD);
		whack_log_fd = p->whack_sock;
		whack_log(RC_COMMENT
		    , "%s for ISAKMP SA, but releasing whack for pending IPSEC SA"
		    , story);
		whack_log_fd = NULL_FD;
	    }
	    close(p->whack_sock);
	    p->whack_sock = NULL_FD;
	}
    }
}

static void
delete_pending(struct pending **pp)
{
    struct pending *p = *pp;

    *pp = p->next;
    if (p->connection != NULL)
	connection_discard(p->connection);
    close_any(p->whack_sock);

    DBG(DBG_DPD,
	DBG_log("removing pending policy for \"%s\" {%p}",
		p->connection ? p->connection->name : "none", p));

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
void
unpend(struct state *st)
{
    struct pending **pp
	, *p;

    DBG(DBG_DPD,
	DBG_log("unpending state #%lu", st->st_serialno));

    for (pp = host_pair_first_pending(st->st_connection); (p = *pp) != NULL; )
    {
	if (p->isakmp_sa == st)
	{
	    DBG(DBG_CONTROL
		, DBG_log("unqueuing pending Quick Mode with %s \"%s\""
			  , ip_str(&p->connection->spd.that.host_addr)
			  , p->connection->name));

	    p->pend_time = time(NULL);
	    (void) quick_outI1(p->whack_sock, st, p->connection, p->policy
		, p->try, p->replacing);
	    p->whack_sock = NULL_FD;	/* ownership transferred */
	    p->connection = NULL;	/* ownership transferred */
	    delete_pending(pp);
	}
	else
	{
	    pp = &p->next;
	}
    }
}

/*
 * Look for phase2s that were waiting for a phase 1.  If the time that we
 * have been pending exceeds a DPD timeout that was set, then we call the
 * dpd_timeout() on this state, which hopefully kills this pending state.
 */
bool pending_check_timeout(struct connection *c)
{
    struct pending **pp, *p;
    time_t n = time(NULL);
    bool restart = FALSE;

    for (pp = host_pair_first_pending(c); (p = *pp) != NULL; )
    {
	DBG(DBG_DPD,
	    DBG_log("checking connection \"%s\" for stuck phase 2s %lu+%lu <= %lu"
		    , c->name
		    , (unsigned long)p->pend_time
		    , (unsigned long)c->dpd_timeout
		    , (unsigned long)n));
		    
	if(c->dpd_timeout > 0) {
	    if((p->pend_time + c->dpd_timeout*3) <= n) {
		restart = TRUE;
	    }
	}
	pp = &p->next;
    }
    return restart;
}

/* a Main Mode negotiation has been replaced; update any pending */
void
update_pending(struct state *os, struct state *ns)
{
    struct pending *p, **pp;

    pp = host_pair_first_pending(os->st_connection);
    if(pp == NULL) return;

    for (p = *pp;
	 p != NULL;
	 p = p->next) {
	if (p->isakmp_sa == os)
	    p->isakmp_sa = ns;
    }	    
}

/* a Main Mode negotiation has failed; discard any pending */
void
flush_pending_by_state(struct state *st)
{
    struct pending **pp
	, *p;
    
    pp = host_pair_first_pending(st->st_connection);
    if(pp == NULL) return;

    while((p = *pp) != NULL) {
	if (p->isakmp_sa == st) {
	    /* we don't have to worry about deref to free'ed
	     * *pp, because delete_pending updates pp to
	     * point to the next element before it frees *pp
	     */
	    delete_pending(pp);
	}
	else 
	    pp = &p->next;
    }
}

/* a connection has been deleted; discard any related pending */
void
flush_pending_by_connection(struct connection *c)
{
    struct pending **pp
	, *p;
    
    pp = host_pair_first_pending(c);
    if(pp == NULL) return;

    while((p = *pp) != NULL) {
	if (p->connection == c)
	    {
		p->connection = NULL;	/* prevent delete_pending from releasing */
		delete_pending(pp);
	    }
	else
	    {
		pp = &p->next;
	    }
    }
}

void
show_pending_phase2(const struct connection *c, const struct state *st)
{
    struct pending **pp
	, *p;
    
    pp = host_pair_first_pending(c);
    if(pp == NULL) return;

    for (p = *pp; p != NULL; p = p->next)
    {
	if (p->isakmp_sa == st)
	{
	    /* connection-name state-number [replacing state-number] */
	    char cip[CONN_INST_BUF];

	    fmt_conn_instance(p->connection, cip);
	    whack_log(RC_COMMENT, "#%lu: pending Phase 2 for \"%s\"%s replacing #%lu"
		, p->isakmp_sa->st_serialno
		, p->connection->name
		, cip
		, p->replacing);
	}
    }
}

bool in_pending_use(struct connection *c)
{
    /* see if it is being used by a pending */
    struct pending **pp, *p;
    
    pp = host_pair_first_pending(c);
    if(pp == NULL) return FALSE;

    for (p = *pp; p != NULL; p = p->next)
	if (p->connection == c)
		return TRUE;	/* in use, so we're done */

    return FALSE;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
