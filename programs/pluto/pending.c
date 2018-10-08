/* information about connections between hosts and clients
 *
 * Copyright (C) 1998-2002,2013,2015 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2011 Anthony Tong <atong@TrustedCS.com>
 * Copyright (C) 2017-2018 Antony Antony <antony@phenome.org>
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

#include <libreswan.h>

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

/*
 * queue an IPsec SA negotiation pending completion of a
 * suitable phase 1 (IKE SA)
 */
void add_pending(fd_t whack_sock,
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
			close_any(&whack_sock);
			return;
		}
	}

	DBG(DBG_CONTROL, {
		ipstr_buf b;
		char ciba[CONN_INST_BUF];
		char cibb[CONN_INST_BUF];
		struct connection *cb = isakmp_sa->st_connection;
		DBG_log("Queuing pending IPsec SA negotiating with %s \"%s\"%s IKE SA #%lu \"%s\"%s",
			ipstr(&c->spd.that.host_addr, &b),
			c->name, fmt_conn_instance(c, ciba),
			isakmp_sa->st_serialno,
			cb->name, fmt_conn_instance(cb, cibb));
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

/*
 * Release all the whacks awaiting the completion of this state.  This
 * is accomplished by closing all the whack socket file descriptors.
 * We go to some trouble to tell each whack, but to not tell it twice.
 */

static bool same_fd(const struct stat *stst, fd_t fd)
{
	struct stat pst;
	if (!fd_p(fd)) {
		return false;
	} else if (fstat(fd.fd, &pst) != 0) {
		return false;
	} else {
		return (stst->st_dev == pst.st_dev &&
			stst->st_ino == pst.st_ino);
	}
}

void release_pending_whacks(struct state *st, err_t story)
{
	/*
	 * Use fstat() to uniquely identify the whack connection -
	 * multiple sockets to the same whack will have similar
	 * 'struct stat' values.
	 *
	 * If the socket is valid, close it.
	 */
	struct stat stst;
	if (!fd_p(st->st_whack_sock)) {
		DBGF(DBG_CONTROL, "%s: state #%lu has no whack fd",
		     __func__, st->st_serialno);
		zero(&stst);
	} else if (fstat(st->st_whack_sock.fd, &stst) != 0) {
		int e = errno;
		LSWDBGP(DBG_CONTROL, buf) {
			lswlogf(buf, "%s: state #%lu stat("PRI_FD") failed ",
				__func__, st->st_serialno, PRI_fd(st->st_whack_sock));
			lswlog_errno(buf, e);
		}
		/* presumably dead */
		st->st_whack_sock = null_fd;
		zero(&stst);
	} else {
		DBGF(DBG_CONTROL, "%s: state #%lu "PRI_FD" .st_dev=%lu .st_ino=%lu",
		     __func__, st->st_serialno, PRI_fd(st->st_whack_sock),
		     (unsigned long)stst.st_dev, (unsigned long)stst.st_ino);
		release_whack(st);
	}

	/*
	 * Check for the SA's parent and if that needs to disconnect.
	 *
	 * For instance, when the IKE_SA establishes but the first
	 * CHILD_SA fails with a timeout then this code will be called
	 * with the CHILD_SA.
	 *
	 * XXX: Since this is ment to release pending whacks, should
	 * this check for, and release the whacks for any pending
	 * CHILD_SA attached to this ST's IKE SA?
	 */
	if (IS_CHILD_SA(st)) {
		struct ike_sa *ike = ike_sa(st);
		if (same_fd(&stst, ike->sa.st_whack_sock)) {
			release_whack(&ike->sa);
		}
	}

	/*
	 * Now go through pending children and close the whack socket
	 * of any that are going to be assigned this ST as the parent.
	 * XXX: Is this because the parent is dying so anything
	 * waiting on it should be deleted.
	 *
	 * SAME_FD() is used to identify whack sockets that are
	 * differnt to ST - when found a further release message is
	 * printed.
	 *
	 * XXX: but what if this is a child?  Presumably the loop
	 * becomes redundant or does IKEv1 confuse things?
	 */

	struct pending **pp = host_pair_first_pending(st->st_connection);
	if (pp == NULL)
		return;
	for (struct pending *p = *pp; p != NULL; p = p->next) {
		DBGF(DBG_CONTROL,
		     "%s: IKE SA #%lu "PRI_FD" has pending CHILD SA with socket "PRI_FD,
		     __func__, p->isakmp_sa->st_serialno,
		     PRI_fd(p->isakmp_sa->st_whack_sock),
		     PRI_fd(p->whack_sock));
		if (p->isakmp_sa == st && fd_p(p->whack_sock)) {
			if (!same_fd(&stst, p->whack_sock)) {
				passert(!fd_p(whack_log_fd));
				whack_log_fd = p->whack_sock;
				whack_log(RC_COMMENT,
					  "%s for IKE SA, but releasing whack for pending IPSEC SA",
					  story);
				whack_log_fd = null_fd;
			}
			close_any(&p->whack_sock);
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
	close_any(&p->whack_sock);

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
 *     In IKEv2 it called when AUTH is complete, child is established.
 *     Established child get removed not unpend.
 */
void unpend(struct state *st, struct connection *cc)
{
	struct pending **pp, *p;
	char *what ="unqueuing";

	if (cc == NULL) {
		DBG(DBG_CONTROL, DBG_log("unpending state #%lu",
					st->st_serialno));
	} else {
		char cib[CONN_INST_BUF];
		DBG(DBG_CONTROL,
			DBG_log("unpending state #%lu connection \"%s\"%s",
				st->st_serialno, cc->name,
				fmt_conn_instance(cc, cib)));
	}

	for (pp = host_pair_first_pending(st->st_connection);
	     (p = *pp) != NULL; )
	{
		if (p->isakmp_sa == st) {
			p->pend_time = mononow();
			if (st->st_ikev2 && cc != p->connection) {
				ikev2_initiate_child_sa(p);

			} else if (!st->st_ikev2) {
				quick_outI1(p->whack_sock, st, p->connection,
					    p->policy,
					    p->try, p->replacing
#ifdef HAVE_LABELED_IPSEC
					    , p->uctx
#endif
					    );
			} else {
				/*
				 * IKEv2 AUTH negotiation include child.
				 * nothing to upend, like in IKEv1, delete it
				 */
				 what = "delete from";
			}
			DBG(DBG_CONTROL, {
				ipstr_buf b;
				char cib[CONN_INST_BUF];
				DBG_log("%s pending %s with %s \"%s\"%s",
					what,
					st->st_ikev2 ? "Child SA" : "Quick Mode",
					ipstr(&p->connection->spd.that.host_addr, &b),
					p->connection->name,
					fmt_conn_instance(p->connection, cib));
			});

			p->whack_sock = null_fd;        /* ownership transferred */
			p->connection = NULL;           /* ownership transferred */
			delete_pending(pp);	/* in effect, advances pp */
		} else {
			pp = &p->next;
		}
	}
}

struct connection *first_pending(const struct state *st,
				 lset_t *policy,
				 fd_t *p_whack_sock)
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
 * dpd_timeout() on this state.  We hope this kills the pending state.
 */
bool pending_check_timeout(const struct connection *c)
{
	struct pending **pp, *p;

	for (pp = host_pair_first_pending(c); (p = *pp) != NULL; ) {
		DBG(DBG_DPD, {
			deltatime_t waited = monotimediff(mononow(), p->pend_time);
			char cib[CONN_INST_BUF];
			DBG_log("checking connection \"%s\"%s for stuck phase 2s (waited %jd, patience 3*%jd)",
				c->name,
				fmt_conn_instance(c, cib),
				deltasecs(waited),
				deltasecs(c->dpd_timeout));
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

			LSWLOG_WHACK(RC_COMMENT, buf) {
				lswlogf(buf, "#%lu: pending ", p->isakmp_sa->st_serialno);
				lswlogs(buf, st->st_ikev2 ? "CHILD SA" : "Phase 2");
				lswlogf(buf, " for \"%s\"%s", p->connection->name,
					cip);
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
