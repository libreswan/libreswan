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
#include "host_pair.h"
#include "ikev2_create_child_sa.h"		/* for initiate_v2_CREATE_CHILD_SA_create_child() */
#include "initiate.h"
#include "show.h"

/*
 * queue an IPsec SA negotiation pending completion of a
 * suitable phase 1 (IKE SA)
 */

static void add_pending(struct fd *whack_sock,
			struct ike_sa *ike,
			struct connection *c,
			lset_t policy,
			so_serial_t replacing,
			const shunk_t sec_label,
			bool part_of_initiate)
{
	/* look for duplicate pending IPsec SA's, skip add operation */
	for (struct pending *p, **pp = host_pair_first_pending(c);
	     pp != NULL && (p = *pp) != NULL; pp = &p->next) {
		if (p->connection == c) {
			address_buf b;
			connection_buf cib;
			bool duplicate = (p->ike == ike);
			dbg("connection "PRI_CONNECTION" is already pending: waiting on IKE SA #%lu connecting to %s; %s",
			    pri_connection(c, &cib),
			    p->ike->sa.st_serialno,
			    str_address(&c->remote->host.addr, &b),
			    duplicate ? "ignoring duplicate" : "this IKE SA is different");
			if (duplicate) {
				return;
			}
		}
	}

	struct pending *p = alloc_thing(struct pending, "struct pending");
	p->whack_sock = fd_addref(whack_sock); /*on heap*/
	p->ike = ike;
	p->connection = c;
	p->policy = policy;
	p->replacing = replacing;
	p->pend_time = mononow();
	p->part_of_initiate = part_of_initiate; /* useful */
	p->sec_label = sec_label;

	/*
	 * If this is part of an initiate then there's already enough
	 * going on; no need to log this action.
	 */
	enum stream only = part_of_initiate ? (DBGP(DBG_BASE) ? DEBUG_STREAM : NO_STREAM) : ALL_STREAMS;
	if (only != NO_STREAM) {
		address_buf b;
		state_buf sab;
		log_pending(only | RC_COMMENT, p,
			    "queue %s; waiting on %s "PRI_STATE" negotiating with %s",
			    /* "Child SA" or "IPsec SA" */
			    p->connection->config->ike_info->child_sa_name,
			    /* "IKE SA" or "ISAKMP SA" */
			    p->connection->config->ike_info->ike_sa_name,
			    pri_state(&ike->sa, &sab),
			    ipstr(&c->remote->host.addr, &b));
	}
	host_pair_enqueue_pending(c, p);
}

void add_v1_pending(struct fd *whackfd,
		    struct ike_sa *ike,
		    struct connection *c,
		    lset_t policy,
		    so_serial_t replacing,
		    const shunk_t sec_label,
		    bool part_of_initiate)
{
	passert(ike->sa.st_ike_version == IKEv1);
	add_pending(whackfd, ike, c, policy, replacing, sec_label, part_of_initiate);
}

void add_v2_pending(struct fd *whackfd,
		    struct ike_sa *ike,
		    struct connection *c,
		    lset_t policy,
		    so_serial_t replacing,
		    const shunk_t sec_label,
		    bool part_of_initiate)
{
	passert(ike->sa.st_ike_version == IKEv2);
	add_pending(whackfd, ike, c, policy, replacing, sec_label, part_of_initiate);
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
	if (!fd_p(st->st_logger->object_whackfd)) {
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
		if (same_fd(st->st_logger->object_whackfd, ike->sa.st_logger->object_whackfd)) {
			ike_with_same_whack = ike;
			release_whack(ike->sa.st_logger, HERE);
		} else {
			release_whack(st->st_logger, HERE);
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

	for (struct pending *p, **pp = host_pair_first_pending(st->st_connection);
	     pp != NULL && (p = *pp) != NULL; pp = &p->next) {
		dbg("%s: IKE SA #%lu "PRI_FD" has pending CHILD SA with socket "PRI_FD,
		    __func__, p->ike->sa.st_serialno,
		    pri_fd(p->ike->sa.st_logger->object_whackfd),
		    pri_fd(p->whack_sock));
		if (p->ike == ike_with_same_whack && fd_p(p->whack_sock)) {
			if (!same_fd(st->st_logger->object_whackfd, p->whack_sock)) {
				/* XXX: why not the log file? */
				log_pending(WHACK_STREAM|RC_COMMENT, p,
					    "%s for IKE SA, but releasing whack for pending %s",
					    story,
					    /* "IPsec SA" or "CHILD SA" */
					    p->connection->config->ike_info->child_sa_name);
			}
			fd_delref(&p->whack_sock);/*on-heap*/
		}
	}
	release_whack(st->st_logger, HERE);
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
	const struct connection *c = (*pp)->connection;
	connection_buf cib;
	ldbg(c->logger,
	     "%s removing pending {%p} %s connection "PRI_CONNECTION"",
	     what, (*pp), (c->config->ike_version == IKEv2 ? "Child SA" : "Quick Mode"),
	     pri_connection(c, &cib));

	/* remove from list */
	struct pending *p = *pp;
	*pp = p->next;

	fd_delref(&p->whack_sock); /*on-heap*/
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
		dbg("unpending state #%lu", ike->sa.st_serialno);
	} else {
		connection_buf cib;
		dbg("unpending state #%lu connection "PRI_CONNECTION"",
		    ike->sa.st_serialno, pri_connection(cc, &cib));
	}

	for (struct pending *p, **pp = host_pair_first_pending(ike->sa.st_connection);
	     pp != NULL && (p = *pp) != NULL; /*see-below*/) {
		if (p->ike == ike) {
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
					submit_v2_CREATE_CHILD_SA_new_child(ike, p->connection,
									    p->policy,
									    p->whack_sock);
				}
				break;
			case IKEv1:
#ifdef USE_IKEv1
				quick_outI1(p->whack_sock, &ike->sa, p->connection,
					    p->policy,
					    p->replacing,
					    null_shunk);
#endif
				break;
			default:
				bad_case(ike->sa.st_ike_version);
			}
			delete_pending(pp, what);	/* in effect, advances pp */
		} else {
			pp = &p->next;
		}
	}
}

struct connection *first_pending(const struct ike_sa *ike,
				 lset_t *policy,
				 struct fd **p_whack_sock)
{
	dbg("getting first pending from state #%lu", ike->sa.st_serialno);

	for (struct pending *p, **pp = host_pair_first_pending(ike->sa.st_connection);
	     pp != NULL && (p = *pp) != NULL; pp = &p->next) {
		if (p->ike == ike) {
			fd_delref(p_whack_sock); /*on-heap*/
			*p_whack_sock = fd_addref(p->whack_sock); /*on-heap*/
			*policy = p->policy;
			return p->connection;
		}
	}
	return NULL;
}

/*
 * Look for phase2s that were waiting for a phase 1.  If the time that
 * we have been pending exceeds a DPD timeout that was set, then we
 * call the dpd_timeout() on this state.  We hope this kills the
 * pending state.
 */

static bool pending_check_timeout(const struct connection *c)
{
	const monotime_t now = mononow();
	for (struct pending *p, **pp = host_pair_first_pending(c);
	     pp != NULL && (p = *pp) != NULL; /*see-below*/) {
		deltatime_t waited = monotimediff(mononow(), p->pend_time);
		connection_buf cib;
		dbg("checking connection "PRI_CONNECTION" for stuck phase 2s (waited %jd, patience 3*%jd)",
		    pri_connection(c, &cib), deltasecs(waited),
		    deltasecs(c->config->dpd.timeout));
		if (deltasecs(c->config->dpd.timeout) > 0) {
			/* patience = 3 * c->config->dpd.timeout */
			deltatime_t patience = deltatime_scale(c->config->dpd.timeout, 3, 1);
			monotime_t pending_patience = monotime_add(p->pend_time, patience);
			/* run out of patience? */
			if (monotime_cmp(now, >=, pending_patience)) {
				connection_buf cib;
				dbg("connection "PRI_CONNECTION" stuck, restarting",
				    pri_connection(c, &cib));
				return true;
			}
		}
		pp = &p->next;
	}
	return false;
}

/* time between scans of pending phase2 */
#define PENDING_PHASE2_INTERVAL (2 * secs_per_minute)

/*
 * Call connection_check_phase2 periodically to check to see if pending
 * phase2s ever got unstuck, and if not, perform DPD action.
 */
void connection_check_phase2(struct logger *logger)
{
	struct connection_filter cf = { .where = HERE, };
	while (next_connection_new2old(&cf)) {
		struct connection *c = cf.c;

		if (never_negotiate(c)) {
			connection_buf cib;
			dbg("pending review: connection "PRI_CONNECTION" has no negotiated policy, skipped",
			    pri_connection(c, &cib));
			continue;
		}

		if (!(c->policy & POLICY_UP)) {
			connection_buf cib;
			dbg("pending review: connection "PRI_CONNECTION" was not up, skipped",
			    pri_connection(c, &cib));
			continue;
		}

		if (!pending_check_timeout(c)) {
			connection_buf cib;
			dbg("pending review: connection "PRI_CONNECTION" has no timed out pending connections, skipped",
			    pri_connection(c, &cib));
			continue;
		}

		/* XXX: push/pop LOGGER's WHACK? */
		address_buf ab;
		llog(RC_LOG, c->logger,
		     "%s negotiating with %s took too long -- replacing",
		     c->config->ike_info->ike_sa_name,
		     str_address_sensitive(&c->remote->host.addr, &ab));

		struct state *p1st;
		switch (c->config->ike_version) {
#ifdef USE_IKEv1
		case IKEv1:
			p1st = find_phase1_state(c,
						 (V1_ISAKMP_SA_ESTABLISHED_STATES |
						  V1_PHASE1_INITIATOR_STATES));
			break;
#endif
		case IKEv2:
			p1st = find_phase1_state(c, IKEV2_ISAKMP_INITIATOR_STATES);
			break;
		default:
			bad_case(c->config->ike_version);
		}

		if (p1st != NULL) {
			/* arrange to rekey the phase 1, if there was one. */
			if (c->config->dnshostname != NULL) {
				restart_connections_by_peer(c, logger);
			} else {
				event_force(c->config->ike_info->replace_event, p1st);
			}
		} else {
			/* start a new connection. Something wanted it up */
			initiate_connection(c, /*remote-host-name*/NULL,
					    /*background*/true,
					    logger);
		}
	}
}

/* a IKE SA negotiation has been replaced; update any pending */
void update_pending(struct ike_sa *old_ike, struct ike_sa *new_ike)
{
	pexpect(old_ike != NULL);
	if (old_ike == NULL)
		return;

	for (struct pending *p, **pp = host_pair_first_pending(old_ike->sa.st_connection);
	     pp != NULL && (p = *pp) != NULL; pp = &p->next) {
		if (p->ike == old_ike)
			p->ike = new_ike;
	}
}

/*
 * An IKE SA negotiation has failed; discard any pending.
 *
 * Danger: this code deletes connections.
 */
void flush_pending_by_state(struct ike_sa *ike)
{
	for (struct pending *p, **pp = host_pair_first_pending(ike->sa.st_connection);
	     pp != NULL && (p = *pp) != NULL; /*see-below*/ ) {
		if (p->ike == ike) {
			/* we don't have to worry about deref to free'ed
			 * *pp, because delete_pending updates pp to
			 * point to the next element before it frees *pp
			 */
			struct connection *c = p->connection;
			delete_pending(pp, "flush");	/* in effect, advances pp */
			/* above unlink means C is no longer pending */
			pexpect(!connection_is_pending(c));
			connection_delete_unused_instance(&c,
							  /*old-state*/NULL,
							  null_fd/*XXX: p->whack_sock?*/);
		} else {
			pp = &p->next;
		}
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
	unsigned found = 0;	/* should appear at most once */
	for (struct pending *p, **pp = host_pair_first_pending(c);
	     pp != NULL && (p = *pp) != NULL; /*see-below*/) {
		if (p->connection == c) {
			found++;
			delete_pending(pp, "flush");	/* in effect, advances pp */
		} else {
			pp = &p->next;
		}
	}
	PEXPECT(c->logger, found <= 1);
}

void show_pending_child_details(struct show *s,
				const struct connection *c,
				const struct ike_sa *ike)
{
	for (struct pending *p, **pp = host_pair_first_pending(c);
	     pp != NULL && (p = *pp) != NULL; pp = &p->next) {
		if (p->ike == ike) {
			/* connection-name state-number [replacing state-number] */
			SHOW_JAMBUF(RC_COMMENT, s, buf) {
				jam(buf, "#%lu: pending ", p->ike->sa.st_serialno);
				jam_string(buf, (ike->sa.st_ike_version == IKEv2) ? "CHILD SA" : "Phase 2");
				jam(buf, " for ");
				jam_connection(buf, c);
				if (p->replacing != SOS_NOBODY) {
					jam(buf, " replacing #%lu", p->replacing);
				}
			}
		}
	}
}

bool connection_is_pending(const struct connection *c)
{
	/* see if it is being used by a pending */
	for (struct pending *p, **pp = host_pair_first_pending(c);
	     pp != NULL && (p = *pp) != NULL; pp = &p->next) {
		if (p->connection == c)
			return true; /* in use, so we're done */
	}

	return false;
}

void init_pending(void)
{
	enable_periodic_timer(EVENT_PENDING_PHASE2, connection_check_phase2,
			      deltatime(PENDING_PHASE2_INTERVAL));
}
