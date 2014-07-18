/*
 * Cryptographic helper function.
 * Copyright (C) 2004-2007 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2004-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2006 Luis F. Ortiz <lfo@polyad.org>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2008 Anthony Tong <atong@TrustedCS.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009 Stefan Arentz <stefan@arentz.ca>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
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
 * This code was developed with the support of IXIA communications.
 *
 */

#include <pthread.h>    /* Must be the first include file */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#if defined(macintosh) || (defined(__MACH__) && defined(__APPLE__))
#include <sys/sysctl.h>
#endif

#include <signal.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "enum_names.h"
#include "defs.h"
#include "packet.h"
#include "demux.h"
#include "lswlog.h"
#include "log.h"
#include "state.h"
#include "demux.h"
#include "rnd.h"
#include "pluto_crypt.h"
#include "timer.h"

#include <nss.h>
#include "lswconf.h"

#include "lsw_select.h"

TAILQ_HEAD(req_queue, pluto_crypto_req_cont);

/*
 * Note: this per-helper struct is never modified in a helper thread
 *
 * Life cycle:
 * - array of nhelpers pointers to this struct created by init_crypto_helpers
 *   Each is initialized by init_crypto_helper (and thread is created):
 *	pcw_work = 0
 *	pcw_dead = FALSE (TRUE if thread creation failed)
 *	pcw_active some kind of queue
 *
 * - cleanup_crypto_helper.
 *   Called by send_crypto_helper_request (if worker is dead and reaped)
 *   Called by handle_helper_answer on EOF if reaped (set dead)
 *	pcw_work = 0
 *	pcw_dead = FALSE (marking as not dead -- lets it live again)
 *
 * - kill_helper does a pthread_cancel.
 *   It is called if the main program's handle_helper_answer cannot
 *   read correctly from helper.
 *	pcw_dead = TRUE
 *
 * - handle_helper_answer reads from helper
 *   + calls kill_helper on read error
 *	pcw_dead = TRUE on EOF
 *
 * pcw_work:
 * - send_crypto_helper_request increments it at end
 * - crypto_send_backlog increments it at end
 * - handle_helper_answer decrements it after reading
 */
struct pluto_crypto_worker {
	int pcw_helpernum;
	pthread_t pcw_pid;

	/* socketpair's file descriptors
	 * Each socket is bidirectional and they are cross-connected.
	 */
	int pcw_master_fd;	/* master's fd (-1 if none) */
	int pcw_helper_fd;	/* helper's fd */

	int pcw_maxbasicwork;   /* how many basic things can be queued */
	int pcw_maxcritwork;    /* how many critical things can be queued */
	bool pcw_dead;          /* worker is dead */
	/*TAILQ_HEAD*/ struct req_queue pcw_active;	/* queue of tasks for this worker */
	int pcw_work;           /* how many items in pcw_active */
};

static /*TAILQ_HEAD*/ struct req_queue backlog;
static int backlogqueue_len = 0;

static void init_crypto_helper(struct pluto_crypto_worker *w, int n);

static void *pluto_helper_thread(void *w);	/* forward */

/* may be NULL if we are to do all the work ourselves */
static struct pluto_crypto_worker *pc_workers = NULL;

static int pc_workers_cnt = 0;	/* number of workers threads */
static pcr_req_id pcw_id;	/* counter for generating unique request IDs */

/* pluto crypto operations */
static const char *const pluto_cryptoop_strings[] = {
	"build_kenonce",	/* calculate g^i and nonce */
	"build_nonce",	/* just fetch a new nonce */
	"compute dh+iv (V1 Phase 1)",	/* (g^x)(g^y) and skeyids for Phase 1 DH + prf */
	"compute dh (V1 Phase 2 PFS)",	/* perform (g^x)(g^y) for Phase 2 PFS */
	"compute dh (V2)",	/* perform IKEv2 PARENT SA calculation, create SKEYSEED */
};

static enum_names pluto_cryptoop_names =
	{ pcr_build_kenonce, pcr_compute_dh_v2, pluto_cryptoop_strings, NULL };

/* initializers for pluto_crypto_request continuations */

static void pcr_init(struct pluto_crypto_req *r,
			    enum pluto_crypto_requests pcr_type,
			    enum crypto_importance pcr_pcim)
{
	zero(r);
	r->pcr_len  = sizeof(struct pluto_crypto_req);
	r->pcr_type = pcr_type;
	r->pcr_pcim = pcr_pcim;
}


void pcr_nonce_init(struct pluto_crypto_req *r,
			    enum pluto_crypto_requests pcr_type,
			    enum crypto_importance pcr_pcim)
{
	pcr_init(r, pcr_type, pcr_pcim);

	INIT_WIRE_ARENA(r->pcr_d.kn);
}

void pcr_dh_init(struct pluto_crypto_req *r,
			enum pluto_crypto_requests pcr_type,
			enum crypto_importance pcr_pcim)
{
	pcr_init(r, pcr_type, pcr_pcim);

	INIT_WIRE_ARENA(r->pcr_d.dhq);
}

/* If there are any helper threads, this code is always executed IN A HELPER THREAD.
 * Otherwise it is executed in the main (only) thread.
 */
static void pluto_do_crypto_op(struct pluto_crypto_req *r, int helpernum)
{
	DBG(DBG_CONTROL,
	    DBG_log("crypto helper %d doing %s; request ID %u",
		    helpernum,
		    enum_show(&pluto_cryptoop_names, r->pcr_type),
		    r->pcr_id));
	{
		const char *d = getenv("PLUTO_CRYPTO_HELPER_DELAY");

		if (d != NULL) {
			unsigned long delay;
			err_t ugh = ttoulb(d, 0, 0, secs_per_hour, &delay);

			if (ugh != NULL) {
				libreswan_log("$PLUTO_CRYPTO_HELPER_DELAY malformed: %s", ugh);
			} else {
				DBG_log("crypto helper is pausing for %lu seconds", delay);
				sleep(delay);
			}
		}
	}

	/* now we have the entire request in the buffer, process it */
	switch (r->pcr_type) {
	case pcr_build_kenonce:
		calc_ke(r);
		calc_nonce(r);
		break;

	case pcr_build_nonce:
		calc_nonce(r);
		break;

	case pcr_compute_dh_iv:
		calc_dh_iv(r);
		break;

	case pcr_compute_dh:
		calc_dh(r);
		break;

	case pcr_compute_dh_v2:
		calc_dh_v2(r);
		break;
	}
}

/* IN A HELPER THREAD */
static void pluto_crypto_helper(int helper_fd, int helpernum)
{
	FILE *in = fdopen(helper_fd, "rb");
	FILE *out = fdopen(helper_fd, "wb");
	struct pluto_crypto_req req;

	/* OS X does not have pthread_setschedprio */
#if !(defined(macintosh) || (defined(__MACH__) && defined(__APPLE__)))
	int status = pthread_setschedprio(pthread_self(), 10);

	DBG(DBG_CONTROL,
	    DBG_log("status value returned by setting the priority of this thread (crypto helper %d) %d",
		    helpernum, status));
#endif

	DBG(DBG_CONTROL, DBG_log("crypto helper %d waiting on fd %d",
				 helpernum, fileno(in)));

	passert(offsetof(struct pluto_crypto_req, pcr_len) == 0);

	for (;;) {
		size_t sz;

		zero(&req);

		errno = 0;
		sz = fread(&req, sizeof(char), sizeof(req), in);

		if (sz == 0 && feof(in)) {
			loglog(RC_LOG_SERIOUS,
			       "pluto_crypto_helper: crypto helper %d normal exit (EOF)\n",
			       helpernum);
			break;
		} else if (sz != sizeof(req)) {
			if (ferror(in) != 0) {
				/* ??? is strerror(ferror(in)) correct? */
				char errbuf[100];	/* ??? how big is big enough? */

				strerror_r(errno, errbuf, sizeof(errbuf));
				loglog(RC_LOG_SERIOUS,
				       "pluto_crypto_helper: crypto helper %d got read error: %s\n",
				       helpernum, errbuf);
			} else {
				/* short read -- fatal */
				loglog(RC_LOG_SERIOUS,
				       "pluto_crypto_helper: crypto helper %d got a short read error: %zu instead of %zu\n",
				       helpernum, sz, sizeof(req));
			}
			break;
		}

		passert(req.pcr_len == sizeof(req));

		DBG(DBG_CONTROL, DBG_log("crypto helper %d read fd: %d",
					 helpernum,
					 fileno(in)));

		pluto_do_crypto_op(&req, helpernum);

		passert(req.pcr_len == sizeof(req));

		errno = 0;
		sz = fwrite(&req, sizeof(char), sizeof(req), out);
		fflush(out);

		if (sz != sizeof(req)) {
			if (ferror(out) != 0) {
				/* ??? is strerror(ferror(out)) correct? */
				char errbuf[100];	/* ??? how big is big enough? */

				strerror_r(errno, errbuf, sizeof(errbuf));
				loglog(RC_LOG_SERIOUS,
				       "crypto helper %d failed to write answer: %s",
				       helpernum, errbuf);
			} else {
				/* short write -- fatal */
				loglog(RC_LOG_SERIOUS,
				       "pluto_crypto_helper error: crypto helper %d write truncated: %zu instead of %zu\n",
				       helpernum, sz, sizeof(req));
			}
			break;
		}
	}

	/* We have no way to report this thread's success or failure. */

	fclose(in);
	fclose(out);
	/*pthread_exit();*/
}

/* send the request, make sure it all goes down. */
static bool crypto_write_request(struct pluto_crypto_worker *w,
				 const struct pluto_crypto_req *r)
{
	const unsigned char *wdat = (unsigned char *)r;
	size_t wlen = r->pcr_len;

	passert(wlen == sizeof(*r));

	DBG(DBG_CONTROL,
	    DBG_log("asking crypto helper %d to do %s; request ID %u (len=%zu, pcw_work=%d)",
		    w->pcw_helpernum,
		    enum_show(&pluto_cryptoop_names, r->pcr_type),
		    r->pcr_id, r->pcr_len, w->pcw_work));

	while (wlen > 0) {
		ssize_t cnt = write(w->pcw_master_fd, wdat, wlen);

		if (cnt < 0) {
			libreswan_log(
				"write to crypto helper %d failed: cnt=%d err=%s",
				w->pcw_helpernum, (int)cnt, strerror(errno));
			return FALSE;
		}

		if (cnt == 0) {
			/* Not clear why this would happen.  Socket full? */
			libreswan_log(
				"write to crypto helper %d failed to write any bytes",
				w->pcw_helpernum);
			return FALSE;
		}

		if ((size_t)cnt != wlen) {
			libreswan_log("short write to crypto helper %d (%zu of %zu bytes); will continue",
				w->pcw_helpernum, (size_t)cnt, wlen);
		}

		wlen -= cnt;
		wdat += cnt;
	}

	return TRUE;
}

/*
 * send_crypto_helper_request is called with a request to do some
 * cryptographic operations along with a continuation structure,
 * which will be used to deal with the response.
 *
 * r: a local variable in the caller.  Its content must be relocatable since
 *    it gets sent down a notional wire (or copied for the backlog queue)
 *
 * cn: heap-allocated.  The caller transfers ownership (i.e responsibility
 *     to free) to us.  We pass that on if we can (STF_SUSPEND result)
 *     and otherwise free it.  NOTE: we don't free any md held in the
 *     cn.  If STF_SUSPEND happens, the continuation will.  Otherwise
 *     responsibility remains with the caller (and its callers).
 *     (??? is this discipline followed?)
 *
 * This function may fail if there is no worker that can take
 * more work items.
 *
 * Return values:
 *	STF_INLINE: computation and continuation done.
 *	STF_FAIL: failure; message logged
 *	STF_SUSPEND: computation queued for later completion
 *	STF_TOOMUCHCRYPTO: queue overloaded: we won't do this; message logged
 *
 * ??? note that the struct pluto_crypto_req in the request is not
 * the same as in the response.  That makes using the continuation
 * to handle failure cases a little dodgy.  Besides, none of the
 * continuation functions handles a non-NULL ugh parameter.
 * On the other hand, the continuation is in a better position to
 * provide context in a diagnostic message.
 * The parameter ought to be removed or used.
 */

stf_status send_crypto_helper_request(struct pluto_crypto_req *r,
				 struct pluto_crypto_req_cont *cn)
{
	static int pc_worker_num = 0;	/* index of last worker assigned work */
	struct pluto_crypto_worker *w;	/* best worker for task */
	struct pluto_crypto_worker *c;	/* candidate worker */
	struct state *st = cur_state;	/* TRANSITIONAL */

	/* Transitional: caller may have set pcrc_serialno.
	 * If so, it ought to be right.
	 */
	passert(cn->pcrc_serialno == st->st_serialno);

	passert(st->st_serialno != SOS_NOBODY && st != NULL);
	cn->pcrc_serialno = st->st_serialno;

	/* do it all ourselves? */
	if (pc_workers == NULL) {
		reset_cur_state();

		pluto_do_crypto_op(r, -1);
		/* call the continuation */
		(*cn->pcrc_func)(cn, r, NULL);

		pfree(cn);	/* ownership transferred from caller */

		/* indicate that we completed the work */
		return STF_INLINE;
	}

	/* attempt to send to a worker thread */

	/* set up the id */
	r->pcr_id = pcw_id++;
	cn->pcrc_id = r->pcr_id;
	cn->pcrc_pcr = r;

	/* Find the first of the least-busy workers (if any) */

	w = NULL;
	for (c = pc_workers; c != &pc_workers[pc_workers_cnt]; c++) {
		DBG(DBG_CONTROL,
		    DBG_log("crypto helper %d%s: pcw_work: %d",
			    pc_worker_num,
			    c->pcw_dead? " DEAD" : "",
			    c->pcw_work));

		if (!c->pcw_dead && (w == NULL || c->pcw_work < w->pcw_work)) {
			w = c;	/* c is the best so far */
			if (c->pcw_work == 0)
				break;	/* early out: cannot do better */
		}
	}

	if (w != NULL &&
	    (w->pcw_work < w->pcw_maxbasicwork ||
	      (w->pcw_work < w->pcw_maxcritwork && r->pcr_pcim > pcim_ongoing_crypto)))
	{
		/* allocate task to worker w */

		/* link it to the worker's active list
		 * cn transferred from caller
		 */
		TAILQ_INSERT_TAIL(&w->pcw_active, cn, pcrc_list);

		passert(w->pcw_master_fd != -1);

		cn->pcrc_reply_stream = reply_stream;
		if (pbs_offset(&reply_stream) != 0) {
			/* copy partially built reply stream to heap
			 * IMPORTANT: don't leak this.
			 */
			cn->pcrc_reply_buffer =
				clone_bytes(reply_stream.start,
					    pbs_offset(&reply_stream),
						       "saved reply buffer");
		}

		if (!crypto_write_request(w, r)) {
			/* free the heap space */
			if (pbs_offset(&cn->pcrc_reply_stream) != 0)
				pfree(cn->pcrc_reply_buffer);
			cn->pcrc_reply_buffer = NULL;
			loglog(RC_LOG_SERIOUS, "cannot start crypto helper %d: failed to write",
				w->pcw_helpernum);
			return STF_FAIL;
		}

		w->pcw_work++;
	} else if (r->pcr_pcim >= pcim_demand_crypto) {
		/* Task is important: put it all on the backlog queue for later */

		/* cn transferred from caller */
		TAILQ_INSERT_TAIL(&backlog, cn, pcrc_list);

		/* copy the request */
		r = clone_bytes(r, r->pcr_len, "saved crypto request");
		cn->pcrc_pcr = r;

		cn->pcrc_reply_stream = reply_stream;
		if (pbs_offset(&reply_stream) != 0) {
			/* copy partially built reply stream to heap
			 * IMPORTANT: don't leak this.
			 */
			cn->pcrc_reply_buffer =
				clone_bytes(reply_stream.start,
					    pbs_offset(&reply_stream),
					    "saved reply buffer");
		}

		backlogqueue_len++;
		DBG(DBG_CONTROL,
		    DBG_log("critical demand crypto operation queued on backlog as %dth item; request ID %u",
			    backlogqueue_len, r->pcr_id));
	} else {
		/* didn't find any available workers */
		DBG(DBG_CONTROL,
		    DBG_log("failed to find any available crypto worker (import=%s)",
			    enum_name(&pluto_cryptoimportance_names,
				      r->pcr_pcim)));

		loglog(RC_LOG_SERIOUS, "can not start crypto helper: failed to find any available worker");

		pfree(cn);	/* ownership transferred from caller */
		return STF_TOOMUCHCRYPTO;
	}

	/* cn ownership transferred on to backlog */

	st->st_calculating = TRUE;
	delete_event(st);
	event_schedule(EVENT_CRYPTO_FAILED, EVENT_CRYPTO_FAILED_DELAY, st);

	return STF_SUSPEND;
}

/*
 * send 1 unit of backlog, if any, to indicated worker.
 */
static void crypto_send_backlog(struct pluto_crypto_worker *w)
{
	if (backlogqueue_len > 0) {
		struct pluto_crypto_req_cont *cn = backlog.tqh_first;
		struct pluto_crypto_req *r;

		passert(cn != NULL);
		TAILQ_REMOVE(&backlog, cn, pcrc_list);

		backlogqueue_len--;

		r = cn->pcrc_pcr;

		DBG(DBG_CONTROL,
		    DBG_log("removing request ID %u from crypto backlog queue; %d left",
			    r->pcr_id, backlogqueue_len));

		/* w points to a worker. Make sure it is live */
		if (w->pcw_dead) {
			init_crypto_helper(w, w->pcw_helpernum);
			if (w->pcw_dead) {
				DBG(DBG_CONTROL,
				    DBG_log("found only a dead crypto helper %d, and failed to restart it",
					w->pcw_helpernum));
				/* discard request ??? is this the best action? */
				/* XXX invoke callback with failure */
				passert(FALSE);
				if (pbs_offset(&cn->pcrc_reply_stream) != 0) {
					pfree(cn->pcrc_reply_buffer);
					cn->pcrc_reply_buffer = NULL;
				}
				return;
			}
		}

		/* link it to the active worker list */
		TAILQ_INSERT_TAIL(&w->pcw_active, cn, pcrc_list);

		passert(w->pcw_master_fd != -1);
		passert(w->pcw_work > 0);

		/* send the request, and then mark the worker as having more work */
		if (!crypto_write_request(w, r)) {
			/* XXX invoke callback with failure */
			passert(FALSE);
			if (pbs_offset(&cn->pcrc_reply_stream) != 0)
				pfree(cn->pcrc_reply_buffer);
			cn->pcrc_reply_buffer = NULL;
			return;
		}

		/* if it was on the backlog, it was saved, free it */
		pfree(r);
		cn->pcrc_pcr = NULL;

		w->pcw_work++;
	}
}

/*
 * look for any states attached to continuations
 * also check the backlog
 */
static void scrap_crypto_cont(/*TAILQ_HEAD*/ struct req_queue *qh,
			      struct pluto_crypto_req_cont *cn,
			      const char *what)
{
	DBG(DBG_CONTROL,
	    DBG_log("scrapping crypto request ID%u for #%lu from %s",
		    cn->pcrc_id, cn->pcrc_serialno, what));
	TAILQ_REMOVE(qh, cn, pcrc_list);
	if (pbs_offset(&cn->pcrc_reply_stream) != 0) {
		pfree(cn->pcrc_reply_buffer);
		cn->pcrc_reply_buffer = NULL;
	}
	pfree(cn);
}

void delete_cryptographic_continuation(struct state *st)
{
	int i;

	passert(st->st_serialno != SOS_NOBODY);

	/* check backlog queue */
	if (backlogqueue_len > 0) {
		struct pluto_crypto_req_cont *cn, *next_cn;

		passert(backlog.tqh_first != NULL);

		for (cn = backlog.tqh_first; cn != NULL; cn = next_cn) {
			next_cn = cn->pcrc_list.tqe_next;	/* grab before cn is freed */

			if (st->st_serialno == cn->pcrc_serialno) {
				backlogqueue_len--;
				/* iff it was on the backlog, cn->pcrc_pcr was malloced, free it */
				pfree(cn->pcrc_pcr);
				cn->pcrc_pcr = NULL;
				scrap_crypto_cont(&backlog, cn, "backlog");
			}
		}
	}

	/*
	 * Check each worker's queue.
	 * We cannot delete an in-flight computation, but we can mark it as
	 * no longer of interest.
	 */
	for (i = 0; i < pc_workers_cnt; i++) {
		struct pluto_crypto_worker *w = &pc_workers[i];
		struct pluto_crypto_req_cont *cn;

		for (cn = w->pcw_active.tqh_first; cn != NULL; cn = cn->pcrc_list.tqe_next) {
			if (st->st_serialno == cn->pcrc_serialno) {
				DBG(DBG_CONTROL,
					DBG_log("we will ignore result of crypto request ID%u for #%lu from crypto helper %d",
						cn->pcrc_id, cn->pcrc_serialno, i));
				cn->pcrc_serialno = SOS_NOBODY;
			}
		}
	}
}

static void kill_helper(struct pluto_crypto_worker *w)
{
	pthread_cancel(w->pcw_pid);
	w->pcw_dead = TRUE;
}

/*
 * This function is called when there is socketpair input from a helper.
 * This is the answer from the helper.
 * We read the request from the socketpair, and find the associated continuation,
 * and dispatch to that continuation.
 *
 * This function should process only a single answer, and then go back
 * to the select call to get called again. This is not most efficient,
 * but is is most fair.
 *
 */
static void handle_helper_answer(struct pluto_crypto_worker *w)
{
	struct pluto_crypto_req rr;
	ssize_t actlen;
	struct pluto_crypto_req_cont *cn;

	DBG(DBG_CRYPT | DBG_CONTROL,
	    DBG_log("crypto helper %d has finished work (pcw_work now %d)",
		    w->pcw_helpernum,
		    w->pcw_work));

	/* read from the socketpair in one gulp */

	zero(&rr);

	actlen = read(w->pcw_master_fd, (void *)&rr, sizeof(rr));

	if (actlen != sizeof(rr)) {
		if (actlen == -1) {
			loglog(RC_LOG_SERIOUS,
			       "read from crypto helper %d failed: %s.  Killing helper.",
			       w->pcw_helpernum, strerror(errno));
			kill_helper(w);
		} else if (actlen == 0) {
			/* EOF: mark worker as dead. */
			w->pcw_dead = TRUE;
		} else {
			loglog(RC_LOG_SERIOUS,
			       "read from crypto helper %d failed with short length %zd of %zu.  Killing helper.",
			       w->pcw_helpernum, actlen, sizeof(rr));
			kill_helper(w);
		}
		return;
	}

	if (rr.pcr_len != sizeof(rr)) {
		loglog(RC_LOG_SERIOUS,
		       "crypto helper %d screwed up length: %zu != %zu; killing it",
		       w->pcw_helpernum,
		       rr.pcr_len, sizeof(rr));
		kill_helper(w);
		return;
	}

	DBG(DBG_CRYPT | DBG_CONTROL, DBG_log("crypto helper %d replies to request ID %u",
					     w->pcw_helpernum,
					     rr.pcr_id));

	/* worker w can accept more work now that we have read from its socketpair */
	w->pcw_work--;

	/*
	 * if there is work queued, then send it off after reading, since this
	 * avoids the most deadlocks
	 */
	crypto_send_backlog(w);

	/* now match up request to continuation, and invoke it */
	for (cn = w->pcw_active.tqh_first;
	     cn != NULL && rr.pcr_id != cn->pcrc_id;
	     cn = cn->pcrc_list.tqe_next)
		;

	if (cn == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "failed to find crypto continuation associated with request ID %u performed by crypto helper %d\n",
		       rr.pcr_id,
		       w->pcw_helpernum);
		return;
	}

	/* unlink it */
	TAILQ_REMOVE(&w->pcw_active, cn, pcrc_list);

	passert(cn->pcrc_func != NULL);

	DBG(DBG_CRYPT, DBG_log("calling continuation function %p",
			       cn->pcrc_func));

	reply_stream = cn->pcrc_reply_stream;
	if (pbs_offset(&reply_stream) != 0) {
		memcpy(reply_stream.start, cn->pcrc_reply_buffer,
		       pbs_offset(&reply_stream));
		pfree(cn->pcrc_reply_buffer);
	}
	cn->pcrc_reply_buffer = NULL;

	/* call the continuation (skip if suppressed) */
	cn->pcrc_pcr = &rr;
	reset_cur_state();
	if (cn->pcrc_serialno != SOS_NOBODY)
		(*cn->pcrc_func)(cn, &rr, NULL);

	/* now free up the continuation */
	pfree(cn);
}

/*
 * initialize a helper.
 */
static void init_crypto_helper(struct pluto_crypto_worker *w, int n)
{
	int fds[2];
	int thread_status;

	/* reset this */
	w->pcw_master_fd = -1;
	w->pcw_helpernum = n;

	if (socketpair(PF_UNIX, SOCK_STREAM, 0, fds) != 0) {
		loglog(RC_LOG_SERIOUS,
		       "could not create socketpair for crypto helper %d: %s",
		       n, strerror(errno));
		return;
	}

	w->pcw_master_fd = fds[0];
	w->pcw_helper_fd = fds[1];
	w->pcw_maxbasicwork = 2;
	w->pcw_maxcritwork = 4;
	w->pcw_work = 0;
	w->pcw_dead = FALSE;
	TAILQ_INIT(&w->pcw_active);

	/* set the send/received queue length to be at least maxcritwork
	 * times sizeof(pluto_crypto_req) in size
	 */
	{
		int qlen = w->pcw_maxcritwork *
			   sizeof(struct pluto_crypto_req);

		if (setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &qlen,
			       sizeof(qlen)) == -1 ||
		    setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &qlen,
			       sizeof(qlen)) == -1 ||
		    setsockopt(fds[0], SOL_SOCKET, SO_RCVBUF, &qlen,
			       sizeof(qlen)) == -1 ||
		    setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &qlen,
			       sizeof(qlen)) == -1) {
			loglog(RC_LOG_SERIOUS,
			       "could not set socket queue to %d for crypto helper %d",
			       qlen, n);
			return;
		}
	}

	thread_status = pthread_create(&w->pcw_pid, NULL,
				       pluto_helper_thread, (void *)w);
	if (thread_status != 0) {
		loglog(RC_LOG_SERIOUS, "failed to start child thread for crypto helper %d, error = %d",
		       n, thread_status);
		close(fds[1]);
		close(fds[0]);
		w->pcw_master_fd = -1;
		w->pcw_dead = TRUE;
	} else {
		libreswan_log("started thread for crypto helper %d (master fd %d)",
			      n, w->pcw_master_fd);
	}
}

/* IN A HELPER THREAD */
static void *pluto_helper_thread(void *w)
{
	const struct pluto_crypto_worker *helper;

	helper = (struct pluto_crypto_worker *)w;
	pluto_crypto_helper(helper->pcw_helper_fd, helper->pcw_helpernum);
	return NULL;	/* end of thread */
}

/*
 * initialize the helpers.
 *
 * Later we will have to make provisions for helpers that have hardware
 * underneath them, in which case, they may be able to accept many
 * more requests than average.
 *
 */
void init_crypto_helpers(int nhelpers)
{
	int i;

	pc_workers = NULL;
	pc_workers_cnt = 0;
	pcw_id = 1;

	TAILQ_INIT(&backlog);

	/* find out how many CPUs there are, if nhelpers is -1 */
	/* if nhelpers == 0, then we do all the work ourselves */
	if (nhelpers == -1) {
		int ncpu_online;
#if !(defined(macintosh) || (defined(__MACH__) && defined(__APPLE__)))
		ncpu_online = sysconf(_SC_NPROCESSORS_ONLN);
#else
		int mib[2], numcpu;
		size_t len;

		mib[0] = CTL_HW;
		mib[1] = HW_NCPU;
		len = sizeof(numcpu);
		ncpu_online = sysctl(mib, 2, &numcpu, &len, NULL, 0);
#endif

		if (ncpu_online > 2) {
			nhelpers = ncpu_online - 1;
		} else {
			/*
			 * if we have 2 CPUs or less, then create 1 helper, since
			 * we still want to deal with head-of-queue problem.
			 */
			nhelpers = 1;
		}
	}

	if (nhelpers > 0) {
		libreswan_log("starting up %d crypto helpers",
			      nhelpers);
		pc_workers = alloc_bytes(sizeof(*pc_workers) * nhelpers,
					 "pluto crypto helpers");
		pc_workers_cnt = nhelpers;

		for (i = 0; i < nhelpers; i++)
			init_crypto_helper(&pc_workers[i], i);
	} else {
		libreswan_log(
			"no crypto helpers will be started; all cryptographic operations will be done inline");
	}
}

void enumerate_crypto_helper_response_sockets(lsw_fd_set *readfds)
{
	int cnt;
	struct pluto_crypto_worker *w = pc_workers;

	for (cnt = 0; cnt < pc_workers_cnt; cnt++, w++) {
		if (!w->pcw_dead) {
			passert(w->pcw_master_fd > 0);

			LSW_FD_SET(w->pcw_master_fd, readfds);
		}
	}
}

int pluto_crypto_helper_response_ready(lsw_fd_set *readfds)
{
	int cnt;
	struct pluto_crypto_worker *w = pc_workers;
	int ndes;

	ndes = 0;

	for (cnt = 0; cnt < pc_workers_cnt; cnt++, w++) {
		if (!w->pcw_dead) {
			passert(w->pcw_master_fd > 0);

			if (LSW_FD_ISSET(w->pcw_master_fd, readfds)) {
				handle_helper_answer(w);
				ndes++;
			}
		}
	}

	return ndes;
}
