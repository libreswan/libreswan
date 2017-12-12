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
 * Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
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
#include <event2/event.h>
#include <event2/event_struct.h>

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
#include  "server.h"
#include "ikev2_prf.h"
#include "crypt_dh.h"
#include "ikev1_prf.h"
#include "state_db.h"

#ifdef HAVE_SECCOMP
# include "pluto_seccomp.h"
#endif

static void handle_helper_answer(void *arg);

struct pluto_crypto_req_cont *new_pcrc(
	crypto_req_cont_func fn,
	const char *name,
	struct state *st,
	struct msg_digest *md)
{
	struct pluto_crypto_req_cont *r = alloc_thing(struct pluto_crypto_req_cont, name);

	r->pcrc_func = fn;
	r->pcrc_serialno = st->st_serialno;
	r->pcrc_md = md;
	r->pcrc_name = name;

	passert(md == NULL || md->st == st);
	passert(st->st_suspended_md == NULL);

	/*
	 * There is almost always a non-NULL md.
	 * Exception: main_inI2_outR2_tail initiates DH calculation
	 * in parallel with normal processing that needs the md exclusively.
	 */
	if (md != NULL)
		set_suspended(st, md);
	return r;
}

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
 *
 * pcw_work:
 * - send_crypto_helper_request increments it at end
 * - crypto_send_backlog increments it at end
 * - handle_helper_answer decrements it after reading
 */
struct pluto_crypto_worker {
	int pcw_helpernum;
	pthread_t pcw_pid;

	/*
	 * socketpair's file descriptors
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
static int backlog_queue_len = 0;

static void init_crypto_helper(struct pluto_crypto_worker *w, int n);

static void *pluto_helper_thread(void *w);	/* forward */

/* may be NULL if we are to do all the work ourselves */
static struct pluto_crypto_worker *pc_workers = NULL;

static int pc_workers_cnt = 0;	/* number of workers threads */
static pcr_req_id pcw_id;	/* counter for generating unique request IDs */

/* pluto crypto operations */
static const char *const pluto_cryptoop_strings[] = {
	"build KE and nonce",	/* calculate g^i and generate a nonce */
	"build nonce",	/* generate a nonce */
	"compute dh+iv (V1 Phase 1)",	/* calculate (g^x)(g^y) and skeyids for Phase 1 DH + prf */
	"compute dh (V1 Phase 2 PFS)",	/* calculate (g^x)(g^y) for Phase 2 PFS */
	"compute dh (V2)",	/* perform IKEv2 PARENT SA calculation, create SKEYSEED */
};

static enum_names pluto_cryptoop_names = {
	pcr_build_ke_and_nonce, pcr_compute_dh_v2,
	ARRAY_REF(pluto_cryptoop_strings),
	NULL, /* prefix */
	NULL
};

/* initializers for pluto_crypto_request continuations */

static void pcr_init(struct pluto_crypto_req *r,
		     enum pluto_crypto_requests pcr_type,
		     enum crypto_importance pcr_pcim)
{
	zero(r);
	r->pcr_type = pcr_type;
	r->pcr_pcim = pcr_pcim;
}

/*
 * Release the contents of R.
 *
 * For at least DH what part of the union is in use is depdent on the
 * release being performed pre- or post- crypto.  Ewwww!
 */

static void pcrc_release_request(struct pluto_crypto_req_cont *cn)
{
	struct pluto_crypto_req *r = &cn->pcrc_pcr;
	switch (r->pcr_type) {
	case pcr_build_ke_and_nonce:
	case pcr_build_nonce:
		cancelled_ke_and_nonce(&r->pcr_d.kn);
		break;
	case pcr_compute_dh_iv:
	case pcr_compute_dh:
	case pcr_compute_dh_v2:
		/*
		 * XXX: everything needs to be freed!
		 */
		DBG(DBG_CONTROL, DBG_log("missing pre-crypto release code"));
		break;
	}
	/* free the heap space */
	pfreeany(cn->pcrc_reply_buffer);
	pfree(cn);
}

static void pcr_release_crypto_response(struct pluto_crypto_req *r)
{
	switch (r->pcr_type) {
	case pcr_build_ke_and_nonce:
	case pcr_build_nonce:
		cancelled_ke_and_nonce(&r->pcr_d.kn);
		break;
	case pcr_compute_dh_iv:
	case pcr_compute_dh:
	case pcr_compute_dh_v2:
		/*
		 * XXX: everything needs to be freed!
		 */
		DBG(DBG_CONTROL, DBG_log("missing post-crypto release code"));
		break;
	}
}

void pcr_kenonce_init(struct pluto_crypto_req_cont *cn,
		      enum pluto_crypto_requests pcr_type,
		      enum crypto_importance pcr_pcim,
		      const struct oakley_group_desc *dh)
{
	struct pluto_crypto_req *r = &cn->pcrc_pcr;
	pcr_init(r, pcr_type, pcr_pcim);
	r->pcr_d.kn.group = dh;
}

struct pcr_skeyid_q *pcr_dh_init(struct pluto_crypto_req_cont *cn,
				 enum pluto_crypto_requests pcr_type,
				 enum crypto_importance pcr_pcim)
{
	struct pluto_crypto_req *r = &cn->pcrc_pcr;
	pcr_init(r, pcr_type, pcr_pcim);

	struct pcr_skeyid_q *dhq = &r->pcr_d.dhq;
	INIT_WIRE_ARENA(*dhq);
	return dhq;
}

/*
 * If there are any helper threads, this code is always executed IN A HELPER
 * THREAD. Otherwise it is executed in the main (only) thread.
 */

static int crypto_helper_delay;

static void pluto_do_crypto_op(struct pluto_crypto_req *r, int helpernum)
{
	struct timeval tv0;
	gettimeofday(&tv0, NULL);

	DBG(DBG_CONTROL,
	    DBG_log("crypto helper %d doing %s; request ID %u",
		    helpernum,
		    enum_show(&pluto_cryptoop_names, r->pcr_type),
		    r->pcr_id));
	if (crypto_helper_delay > 0) {
		DBG_log("crypto helper is pausing for %u seconds",
			crypto_helper_delay);
		sleep(crypto_helper_delay);
	}

	/* now we have the entire request in the buffer, process it */
	switch (r->pcr_type) {

	case pcr_build_ke_and_nonce:
		calc_ke(&r->pcr_d.kn);
		calc_nonce(&r->pcr_d.kn);
		break;

	case pcr_build_nonce:
		calc_nonce(&r->pcr_d.kn);
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

	DBG(DBG_CONTROL, {
			struct timeval tv1;
			unsigned long tv_diff;
			gettimeofday(&tv1, NULL);
			tv_diff = (tv1.tv_sec  - tv0.tv_sec) * 1000000 + (tv1.tv_usec - tv0.tv_usec);
			DBG_log("crypto helper %d finished %s; request ID %u time elapsed %ld usec",
					helpernum,
					enum_show(&pluto_cryptoop_names, r->pcr_type),
					r->pcr_id, tv_diff));
	}

}

/* IN A HELPER THREAD */
static void pluto_crypto_helper(int helper_fd, int helpernum)
{
	FILE *in = fdopen(helper_fd, "rb");
#ifdef HAVE_SECCOMP
	switch (pluto_seccomp_mode) {
	case SECCOMP_ENABLED:
		init_seccomp_cryptohelper(SCMP_ACT_KILL);
		break;
	case SECCOMP_TOLERANT:
		init_seccomp_cryptohelper(SCMP_ACT_TRAP);
		break;
	case SECCOMP_DISABLED:
		break;
	default:
		bad_case(pluto_seccomp_mode);
	}
#else
        libreswan_log("seccomp security for crypto helper not supported");
#endif
#if 0
	pid_t testpid = getsid(0);
	if (testpid == -1)
		loglog(RC_LOG_SERIOUS, "Success: seccomp security was tolerant and the rogue syscall was blocked");
	else
		loglog(RC_LOG_SERIOUS, "Failure: seccomp security was disabled or failed to block the rogue syscall");
#endif
	/* OS X does not have pthread_setschedprio */
#if USE_PTHREAD_SETSCHEDPRIO
	int status = pthread_setschedprio(pthread_self(), 10);

	DBG(DBG_CONTROL,
	    DBG_log("status value returned by setting the priority of this thread (crypto helper %d) %d",
		    helpernum, status));
#endif

	DBG(DBG_CONTROL, DBG_log("crypto helper %d waiting on fd %d",
				 helpernum, fileno(in)));

	for (;;) {
		size_t sz;

		errno = 0;
		struct pluto_crypto_req_cont *cn;
		sz = fread(&cn, sizeof(char), sizeof(cn), in);

		if (sz == 0 && feof(in)) {
			loglog(RC_LOG_SERIOUS,
			       "pluto_crypto_helper: crypto helper %d normal exit (EOF)",
			       helpernum);
			break;
		} else if (sz != sizeof(cn)) {
			/*
			 * XXX: since CN is smaller than a page, this
			 * should never happen?
			 */
			if (ferror(in) != 0) {
				/* ??? is strerror(ferror(in)) correct? */
				char errbuf[100];	/* ??? how big is big enough? */

				strerror_r(errno, errbuf, sizeof(errbuf));
				loglog(RC_LOG_SERIOUS,
				       "pluto_crypto_helper: crypto helper %d got read error: %s",
				       helpernum, errbuf);
			} else {
				/* short read -- fatal */
				loglog(RC_LOG_SERIOUS,
				       "pluto_crypto_helper: crypto helper %d got a short read error: %zu instead of %zu",
				       helpernum, sz, sizeof(cn));
			}
			break;
		}

		DBG(DBG_CONTROL, DBG_log("crypto helper %d read fd: %d",
					 helpernum,
					 fileno(in)));

		pluto_do_crypto_op(&cn->pcrc_pcr, helpernum);

		pluto_event_now("sending helper answer", handle_helper_answer, cn);
	}

	/* We have no way to report this thread's success or failure. */

	fclose(in);
	/*pthread_exit();*/
}

/* send the request, make sure it all goes down. */
static bool crypto_write_request(struct pluto_crypto_worker *w,
				 struct pluto_crypto_req_cont *cn)
{
	DBG(DBG_CONTROL,
	    DBG_log("asking crypto helper %d to do %s; request ID %u (pcw_work=%d)",
		    w->pcw_helpernum,
		    enum_show(&pluto_cryptoop_names, cn->pcrc_pcr.pcr_type),
		    cn->pcrc_pcr.pcr_id, w->pcw_work));
	cn->pcrc_worker = w; /* helper assigned */

	const unsigned char *wdat = (unsigned char*)&cn;
	size_t wlen = sizeof(cn);
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
			/*
			 * XXX: since CN is smaller than a page, this
			 * should never happen?
			 */
			libreswan_log("short write to crypto helper %d (%zu of %zu bytes); will continue",
				w->pcw_helpernum, (size_t)cnt, wlen);
		}

		wlen -= cnt;
		wdat += cnt;
	}

	return TRUE;
}

/*
 * Do the work 'inline' which really means on the event queue.
 *
 * Given threads are assumed, this has not been tested.
 */

static void inline_worker(void *arg)
{
	struct pluto_crypto_req_cont *cn = arg;
	struct state *st = state_by_serialno(cn->pcrc_serialno);
	if (st == NULL) {
		pcrc_release_request(cn);
	} else {
		pluto_do_crypto_op(&cn->pcrc_pcr, -1);

		reply_stream = cn->pcrc_reply_stream;
		if (cn->pcrc_reply_buffer != NULL) {
			memcpy(reply_stream.start, cn->pcrc_reply_buffer,
			       pbs_offset(&reply_stream));
			pfree(cn->pcrc_reply_buffer);
		}
		cn->pcrc_reply_buffer = NULL;

		/* call the continuation */
#if 0
		so_serial_t old_state = push_cur_state(st);
#endif
		(*cn->pcrc_func)(st, cn->pcrc_md, cn, &cn->pcrc_pcr);
#if 0
		pop_cur_state(old_state);
#endif

		pfree(cn);
	}
}

/*
 * send_crypto_helper_request is called with a request to do some
 * cryptographic operations along with a continuation structure,
 * which will be used to deal with the response.
 *
 * See also comments prefixing the typedef for crypto_req_cont_func.
 *
 * struct pluto_crypto_req *r:
 *	points to a auto variable in the caller.  Its content must be
 *	relocatable since it gets sent down a notional wire (or copied
 *	for the backlog queue).  Our caller need not worry about allocation.
 *
 * struct pluto_crypto_req_cont *cn:
 *	Points to a heap-allocated struct.  The caller transfers ownership
 *	(i.e responsibility to free) to us.  (We or our allies will free it
 *	after the continuation function is called or failure is determined.)
 *
 * NOTE: we don't free any resources held in the cn (eg. a msg_digest).
 *	If the continuation function is called (STF_SUSPEND),
 *	the continuation function must deal with such resources,
 *	directly or indirectly.
 *	Otherwise (STF_FAIL, STF_TOOMUCHCRYPTO) this responsibility remains
 *	with the caller of send_crypto_helper_request (and its callers).
 *	(??? is this discipline followed?)
 *
 * If a state is deleted, and that state's serial number is in a queued
 * cn->pcrc_serialno, that cn->pcrc_serialno will be set to SOS_NOBODY
 * signifying that that continuation is a lame duck.  Computation will
 * still be done but the continuation should discard the result.
 * This is a bit of a fudge so much of the implementation is marked
 * with the comment TRANSITIONAL.
 *
 * Return values:
 *
 *	STF_FAIL: failure; message already logged.
 *		STF not called.
 *
 *	STF_SUSPEND: computation queued for later completion.
 *		STF will be called in the indefinite future.
 *		Resources must be preserved until then.
 *
 *	STF_TOOMUCHCRYPTO: queue overloaded: we won't do this; message logged.
 *		STF not called.
 *
 * Suggested life-cycle of a resource like a msg_digest:
 *
 * - Note: not implemented by this mechanism, just a convention
 *   for the callers.
 *
 * - resource should be preserved in the case of STF_SUSPEND since
 *   it will be needed in the future.
 *
 * - normally complete_v?_state_transition frees these resources.
 *
 * Note that the struct pluto_crypto_req in the request is not
 * the same as in the response.
 */

stf_status send_crypto_helper_request(struct state *st,
				      struct pluto_crypto_req_cont *cn)
{
	static int pc_worker_num = 0;	/* index of last worker assigned work */
	struct pluto_crypto_worker *w;	/* best worker for task */
	struct pluto_crypto_worker *c;	/* candidate worker */

	/*
	 * transitional: caller must have set pcrc_serialno.
	 * It ought to match cur_state->st_serialno.
	 */
	passert(cn->pcrc_serialno == st->st_serialno);
	passert(st->st_serialno != SOS_NOBODY);

	passert(cn->pcrc_func != NULL);

	/* attempt to send to a worker thread */

	/* set up the id */
	cn->pcrc_id = cn->pcrc_pcr.pcr_id = pcw_id++;

	/* copy partially built reply stream to heap */
	cn->pcrc_reply_stream = reply_stream;
	if (pbs_offset(&reply_stream) == 0) {
		cn->pcrc_reply_buffer = NULL;
	} else {
		cn->pcrc_reply_buffer = clone_bytes(reply_stream.start,
						    pbs_offset(&reply_stream),
						    "saved reply buffer");
	}

	/*
	 * do it all ourselves?
	 */
	if (pc_workers == NULL) {
		pluto_event_now("inline crypto", inline_worker, cn);
		return STF_SUSPEND;
	}

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
	      (w->pcw_work < w->pcw_maxcritwork &&
	       cn->pcrc_pcr.pcr_pcim > pcim_ongoing_crypto)))
	{
		/* allocate task to worker w */

		/* link it to the worker's active list
		 * cn transferred from caller
		 */
		TAILQ_INSERT_TAIL(&w->pcw_active, cn, pcrc_list);

		passert(w->pcw_master_fd != -1);

		if (!crypto_write_request(w, cn)) {
			loglog(RC_LOG_SERIOUS, "cannot start crypto helper %d: failed to write",
				w->pcw_helpernum);
			pcrc_release_request(cn);	/* ownership transferred from caller */
			return STF_FAIL;
		}

		w->pcw_work++;
	} else if (cn->pcrc_pcr.pcr_pcim >= pcim_demand_crypto) {
		/* Task is important: put it all on the backlog queue for later */

		/* cn transferred from caller */
		TAILQ_INSERT_TAIL(&backlog, cn, pcrc_list);

		backlog_queue_len++;
		DBG(DBG_CONTROL,
		    DBG_log("critical demand crypto operation queued on backlog as %dth item; request ID %u",
			    backlog_queue_len, cn->pcrc_pcr.pcr_id));
	} else {
		/* didn't find any available workers */
		DBG(DBG_CONTROL,
		    DBG_log("failed to find any available crypto worker (import=%s)",
			    enum_name(&pluto_cryptoimportance_names,
				      cn->pcrc_pcr.pcr_pcim)));

		loglog(RC_LOG_SERIOUS, "cannot start crypto helper: failed to find any available worker");
		pcrc_release_request(cn);	/* ownership transferred from caller */
		return STF_TOOMUCHCRYPTO;
	}

	/* cn ownership transferred on to backlog */

	DBG(DBG_CONTROLMORE, DBG_log("#%lu %s:%u st->st_calculating = TRUE;", st->st_serialno, __FUNCTION__, __LINE__));
	st->st_calculating = TRUE;
	delete_event(st);
	event_schedule_s(EVENT_CRYPTO_TIMEOUT, EVENT_CRYPTO_TIMEOUT_DELAY, st);

	return STF_SUSPEND;
}

/*
 * send 1 unit of backlog, if any, to indicated worker.
 */
static void crypto_send_backlog(struct pluto_crypto_worker *w)
{
	if (backlog_queue_len > 0) {
		struct pluto_crypto_req_cont *cn = backlog.tqh_first;

		passert(cn != NULL);
		TAILQ_REMOVE(&backlog, cn, pcrc_list);

		backlog_queue_len--;

		DBG(DBG_CONTROL,
		    DBG_log("removing request ID %u from crypto backlog queue; %d left",
			    cn->pcrc_pcr.pcr_id, backlog_queue_len));

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
				pcrc_release_request(cn);
				return;
			}
		}

		/* link it to the active worker list */
		TAILQ_INSERT_TAIL(&w->pcw_active, cn, pcrc_list);

		passert(w->pcw_master_fd != -1);
		passert(w->pcw_work > 0);

		/* send the request, and then mark the worker as having more work */
		if (!crypto_write_request(w, cn)) {
			/* XXX invoke callback with failure */
			passert(FALSE);
			pcrc_release_request(cn);
			return;
		}

		w->pcw_work++;
	}
}

void delete_cryptographic_continuation(struct state *st)
{
	int i;

	passert(st->st_serialno != SOS_NOBODY);

	/* check backlog queue */
	if (backlog_queue_len > 0) {
		struct pluto_crypto_req_cont *cn, *next_cn;

		passert(backlog.tqh_first != NULL);

		for (cn = backlog.tqh_first; cn != NULL; cn = next_cn) {
			next_cn = cn->pcrc_list.tqe_next;	/* grab before cn is freed */

			if (st->st_serialno == cn->pcrc_serialno) {
				backlog_queue_len--;
				DBG(DBG_CONTROL,
				    DBG_log("scrapping crypto request ID%u for #%lu from backlog",
					    cn->pcrc_id, cn->pcrc_serialno));
				TAILQ_REMOVE(&backlog, cn, pcrc_list);
				pcrc_release_request(cn);
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
				cn->pcrc_serialno = SOS_NOBODY;	/* no longer of interest */
			}
		}
	}
}

void log_crypto_workers(void) {
	static bool first_time = TRUE;
	int i;

	if (!first_time)
		return;

	first_time = FALSE;

	for (i = 0; i < pc_workers_cnt; i++) {
		struct pluto_crypto_worker *w = &pc_workers[i];
		struct pluto_crypto_req_cont *cn;

		for (cn = w->pcw_active.tqh_first; cn != NULL; cn = cn->pcrc_list.tqe_next) {
			libreswan_log("crypto queue: request ID %u for #%lu assigned to %scrypto helper %d",
					cn->pcrc_id, cn->pcrc_serialno,
					w->pcw_dead ? "dead " : "", i);
		}
	}
}

/*
 * This function is called when a helper passes work back to the main
 * thread using the event loop.
 *
 */
static void handle_helper_answer(void *arg)
{
	struct pluto_crypto_req_cont *cn = arg;
	struct pluto_crypto_worker *w = cn->pcrc_worker;

	DBG(DBG_CONTROL,
		DBG_log("crypto helper %d replies to request ID %u",
			w->pcw_helpernum, cn->pcrc_pcr.pcr_id));

	/* worker w can accept more work now that we have read from its socketpair */
	w->pcw_work--;

	/*
	 * if there is work queued, then send it off after reading, since this
	 * avoids the most deadlocks
	 */
	crypto_send_backlog(w);

	/* unlink it */
	TAILQ_REMOVE(&w->pcw_active, cn, pcrc_list);

	passert(cn->pcrc_func != NULL);

	DBG(DBG_CONTROL,
		DBG_log("calling continuation function %p",
			cn->pcrc_func));

	reply_stream = cn->pcrc_reply_stream;
	if (cn->pcrc_reply_buffer != NULL) {
		memcpy(reply_stream.start, cn->pcrc_reply_buffer,
		       pbs_offset(&reply_stream));
		pfree(cn->pcrc_reply_buffer);
	}
	cn->pcrc_reply_buffer = NULL;

	/*
	 * call the continuation (skip if suppressed)
	 */
	reset_cur_state();
	struct state *st = state_by_serialno(cn->pcrc_serialno);
	if (st == NULL) {
		if (cn->pcrc_serialno == SOS_NOBODY) {
			/* suppressed */
			DBG(DBG_CONTROL, DBG_log("state #%lu crypto result suppressed",
						 cn->pcrc_serialno));
		} else {
			/* oops, the state disappeared! */
			PEXPECT_LOG("state #%lu for crypto callback disappeared!",
				    cn->pcrc_serialno);
		}
		pcr_release_crypto_response(&cn->pcrc_pcr);
	} else {
		/*
		 * XXX:
		 *
		 * TODO: enable push/pop.
		 *
		 * Current each individual .pcrc_func handles this in
		 * their own special way.
		 *
		 * TODO: delete individual ST/PCRC_SERIALNO checks.
		 *
		 * Currently each individual .pcrc_func contains its
		 * own redundant checks.
		 *
		 * TODO: delete md?
		 *
		 * Currently each individual .pcrc_func contains its
		 * own, probably dead, code for deleting MD et.al.
		 */
#if 0
		so_serial_t old_state = push_cur_state(st);
#endif
		(*cn->pcrc_func)(st, cn->pcrc_md, cn, &cn->pcrc_pcr);
#if 0
		pop_cur_state(old_state);
#endif
	}

	/* now free up the continuation */
	pfree(cn);
}

#define MAX_HELPER_BASIC_WORK 200
#define MAX_HELPER_CRIT_WORK 400

/*
 * initialize a helper.
 */
static void init_crypto_helper(struct pluto_crypto_worker *w, int n)
{
	int fds[2];
	int thread_status;

	/* reset this */
	w->pcw_master_fd = -1;
	w->pcw_helper_fd = -1;
	w->pcw_helpernum = n;

	/*
	 * XXX: socketpar() is total overkill.  pipe() is sufficient.
	 * But then, so would an in-memory queue.
	 */
	if (socketpair(PF_UNIX, SOCK_STREAM, 0, fds) != 0) {
		loglog(RC_LOG_SERIOUS,
		       "could not create socketpair for crypto helper %d: %s",
		       n, strerror(errno));
		return;
	}

	w->pcw_master_fd = fds[0];
	w->pcw_helper_fd = fds[1];
	w->pcw_maxbasicwork = MAX_HELPER_BASIC_WORK;
	w->pcw_maxcritwork = MAX_HELPER_CRIT_WORK;
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
 * Initialize crypto helper debug delay value from environment variable.
 * This function is NOT thread safe (getenv).
 */
static void init_crypto_helper_delay(void)
{
	const char *envdelay;
	unsigned long delay;
	err_t error;

	envdelay = getenv("PLUTO_CRYPTO_HELPER_DELAY");
	if (envdelay == NULL)
		return;

	error = ttoulb(envdelay, 0, 0, secs_per_hour, &delay);
	if (error != NULL)
		libreswan_log("$PLUTO_CRYPTO_HELPER_DELAY malformed: %s",
			error);
	else
		crypto_helper_delay = (int)delay;
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

	init_crypto_helper_delay();

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

		/* magic numbers from experience */
		if (ncpu_online > 2) {
			nhelpers = ncpu_online - 1;
		} else {
			nhelpers = ncpu_online * 2;
		}
	}

	if (nhelpers > 0) {
		libreswan_log("starting up %d crypto helpers",
			      nhelpers);
		pc_workers = alloc_bytes(sizeof(*pc_workers) * nhelpers,
					 "pluto crypto helpers (ignore)");
		pc_workers_cnt = nhelpers;

		for (i = 0; i < nhelpers; i++)
			init_crypto_helper(&pc_workers[i], i);
	} else {
		libreswan_log(
			"no crypto helpers will be started; all cryptographic operations will be done inline");
	}
}
