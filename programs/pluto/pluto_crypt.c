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
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
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
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "enum_names.h"
#include "defs.h"
#include "lswlog.h"
#include "log.h"
#include "state.h"
#include "demux.h"
#include "pluto_crypt.h"
#include "timer.h"

#include "server.h"
#include "ikev2_prf.h"
#include "crypt_dh.h"
#include "ikev1_prf.h"
#include "state_db.h"

#ifdef HAVE_SECCOMP
# include "pluto_seccomp.h"
#endif

/*
 * The crypto continuation structure
 *
 * Pluto is an event-driven transaction system.
 * Each transaction must take a very small slice of time.
 * Those that cannot, must be broken into multiple
 * transactions and the state carried between them
 * cannot be on the stack or in simple global variables.
 * A continuation is used to hold such state.
 *
 * A struct pluto_crypto_req_cont is heap-allocated
 * by code that wants to delegate cryptographic work.  It fills
 * in parts of the struct, and "fires and forgets" the work.
 * Unless the firing fails, a case that must be handled.
 * This struct stays on the master side: it isn't sent to the helper.
 * It is used to keep track of in-process work and what to do
 * when the work is complete.
 *
 * Used for:
 *	IKEv1 Quick Mode Key Exchange
 *	Other Key Exchange
 *	Diffie-Hellman computation
 */

struct pluto_crypto_req_cont {
	crypto_req_cont_func *pcrc_func;	/* function to continue with */
	struct list_entry pcrc_backlog;
	so_serial_t pcrc_serialno;	/* sponsoring state's serial number */
	bool pcrc_cancelled;
	const char *pcrc_name;
	struct pluto_crypto_req pcrc_pcr;
	pcr_req_id pcrc_id;
	int pcrc_helpernum;
};

/*
 * The work queue.  Accesses must be locked.
 */

static size_t log_backlog(struct lswlog *buf, void *data)
{
	size_t size = 0;
	if (data == NULL) {
		size += lswlogf(buf, "no work-order");
	} else {
		struct pluto_crypto_req_cont *cn = data;
		size += lswlogf(buf, "work-order %ju", (uintmax_t)cn->pcrc_id);
		if (cn->pcrc_serialno != SOS_NOBODY) {
			size += lswlogf(buf, " state #%lu", cn->pcrc_serialno);
		}
		if (cn->pcrc_helpernum != 0) {
			size += lswlogf(buf, " helper %u", cn->pcrc_helpernum);
		}
		if (cn->pcrc_cancelled) {
			size += lswlogf(buf, " cancelled");
		}
	}
	return size;
}

struct list_info backlog_info = {
	.debug = DBG_CONTROLMORE,
	.name = "backlog",
	.log = log_backlog,
};

static pthread_mutex_t backlog_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t backlog_cond = PTHREAD_COND_INITIALIZER;

struct list_head backlog;
static int backlog_queue_len = 0;

/*
 * Create the pluto crypto request object.
 */

static pluto_event_now_cb handle_helper_answer;	/* type assertion */

struct pluto_crypto_req_cont *new_pcrc(crypto_req_cont_func fn,
				       const char *name)
{
	passert(fn != NULL);
	struct pluto_crypto_req_cont *r = alloc_thing(struct pluto_crypto_req_cont, name);
	r->pcrc_func = fn;
	r->pcrc_cancelled = false;
	r->pcrc_name = name;
	r->pcrc_backlog = list_entry(&backlog_info, r);
	r->pcrc_serialno = SOS_NOBODY;
	return r;
}

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
	bool pcw_dead;
	pcr_req_id pcw_pcrc_id;
	so_serial_t pcw_pcrc_serialno;
};

static void init_crypto_helper(struct pluto_crypto_worker *w, int n);

/* may be NULL if we are to do all the work ourselves */
static struct pluto_crypto_worker *pc_workers = NULL;

static int pc_workers_cnt = 0;	/* number of workers threads */

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
		     enum pluto_crypto_requests pcr_type)
{
	zero(r);
	r->pcr_type = pcr_type;
}

/*
 * Release the contents of R.
 *
 * For at least DH what part of the union is in use is depdent on the
 * release being performed pre- or post- crypto.  Ewwww!
 */

static void pcr_release(struct pluto_crypto_req *r)
{
	switch (r->pcr_type) {
	case pcr_build_ke_and_nonce:
	case pcr_build_nonce:
		cancelled_ke_and_nonce(&r->pcr_d.kn);
		break;
	case pcr_compute_dh_v2:
		cancelled_dh_v2(&r->pcr_d.dh_v2);
		break;
	case pcr_compute_dh_iv:
	case pcr_compute_dh:
		cancelled_v1_dh(&r->pcr_d.v1_dh);
		break;
	}
}

static void pcrc_release_request(struct pluto_crypto_req_cont *cn)
{
	pcr_release(&cn->pcrc_pcr);
	/* free the heap space */
	pfree(cn);
}

void pcr_kenonce_init(struct pluto_crypto_req_cont *cn,
		      enum pluto_crypto_requests pcr_type,
		      const struct oakley_group_desc *dh)
{
	struct pluto_crypto_req *r = &cn->pcrc_pcr;
	pcr_init(r, pcr_type);
	r->pcr_d.kn.group = dh;
}

struct pcr_v1_dh *pcr_v1_dh_init(struct pluto_crypto_req_cont *cn,
				 enum pluto_crypto_requests pcr_type)
{
	struct pluto_crypto_req *r = &cn->pcrc_pcr;
	pcr_init(r, pcr_type);

	struct pcr_v1_dh *dhq = &r->pcr_d.v1_dh;
	INIT_WIRE_ARENA(*dhq);
	return dhq;
}

struct pcr_dh_v2 *pcr_dh_v2_init(struct pluto_crypto_req_cont *cn)
{
	struct pluto_crypto_req *r = &cn->pcrc_pcr;
	pcr_init(r, pcr_compute_dh_v2);
	struct pcr_dh_v2 *dhq = &r->pcr_d.dh_v2;
	INIT_WIRE_ARENA(*dhq);
	return dhq;
}

/*
 * If there are any helper threads, this code is always executed IN A HELPER
 * THREAD. Otherwise it is executed in the main (only) thread.
 */

static int crypto_helper_delay;

static void pluto_do_crypto_op(struct pluto_crypto_req_cont *cn, int helpernum)
{
	realtime_t tv0 = realnow();
	struct pluto_crypto_req *r = &cn->pcrc_pcr;

	DBG(DBG_CONTROL,
	    DBG_log("crypto helper %d doing %s; request ID %u",
		    helpernum,
		    enum_show(&pluto_cryptoop_names, r->pcr_type),
		    cn->pcrc_id));
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
		calc_dh_iv(&r->pcr_d.v1_dh);
		break;

	case pcr_compute_dh:
		calc_dh(&r->pcr_d.v1_dh);
		break;

	case pcr_compute_dh_v2:
		calc_dh_v2(r);
		break;
	}

	LSWDBGP(DBG_CONTROL, buf) {
		realtime_t tv1 = realnow();
		deltatime_t tv_diff = realtimediff(tv1, tv0);
		lswlogf(buf, "crypto helper %d finished %s; request ID %u time elapsed ",
			helpernum,
			enum_show(&pluto_cryptoop_names, r->pcr_type),
			cn->pcrc_id);
		lswlog_deltatime(buf, tv_diff);
		lswlogs(buf, " seconds");
	}

}

/* IN A HELPER THREAD */
static void *pluto_crypto_helper_thread(void *arg)
{
	struct pluto_crypto_worker *w = arg;
	DBGF(DBG_CONTROL, "starting up helper thread %d", w->pcw_helpernum);

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

	/* OS X does not have pthread_setschedprio */
#if USE_PTHREAD_SETSCHEDPRIO
	int status = pthread_setschedprio(pthread_self(), 10);
	DBG(DBG_CONTROL,
	    DBG_log("status value returned by setting the priority of this thread (crypto helper %d) %d",
		    w->pcw_helpernum, status));
#endif

	while(!exiting_pluto) {
		w->pcw_pcrc_id = 0;
		w->pcw_pcrc_serialno = SOS_NOBODY;
		struct pluto_crypto_req_cont *cn = NULL;
		pthread_mutex_lock(&backlog_mutex);
		{
			/*
			 * Search the backlog[] for something to do.
			 * If needed sleep.
			 */
			for (;;) {
				/* get oldest; if any */
				FOR_EACH_LIST_ENTRY_OLD2NEW(&backlog, cn) {
					/* CN is the first entry */
					goto found_work;
				}
				DBG(DBG_CONTROL, DBG_log("crypto helper %d waiting (nothing to do)",
							 w->pcw_helpernum));
				pthread_cond_wait(&backlog_cond, &backlog_mutex);
				DBG(DBG_CONTROL, DBG_log("crypto helper %d resuming",
							 w->pcw_helpernum));
			}
		found_work:
			/*
			 * Assign the entry to this thread, removing
			 * it from the backlog.
			 */
			remove_list_entry(&cn->pcrc_backlog);
			cn->pcrc_helpernum = w->pcw_helpernum;
			w->pcw_pcrc_id = cn->pcrc_id;
			w->pcw_pcrc_serialno = cn->pcrc_serialno;
		}
		pthread_mutex_unlock(&backlog_mutex);
		if (!cn->pcrc_cancelled) {
			DBG(DBG_CONTROL,
			    DBG_log("crypto helper %d starting work-order %u for state #%lu",
				    w->pcw_helpernum, w->pcw_pcrc_id,
				    w->pcw_pcrc_serialno));
			pluto_do_crypto_op(cn, w->pcw_helpernum);
		}
		DBG(DBG_CONTROL,
		    DBG_log("crypto helper %d sending results from work-order %u for state #%lu to event queue",
			    w->pcw_helpernum, w->pcw_pcrc_id,
			    w->pcw_pcrc_serialno));
		pluto_event_now("sending helper answer", w->pcw_pcrc_serialno,
				handle_helper_answer, cn);
	}
	DBGF(DBG_CONTROL, "shutting down helper thread %d", w->pcw_helpernum);
	return NULL;
}

/*
 * Do the work 'inline' which really means on the event queue.
 */

static pluto_event_now_cb inline_worker; /* type assertion */

static void inline_worker(struct state *st,
			  struct msg_digest **mdp,
			  void *arg)
{
	struct pluto_crypto_req_cont *cn = arg;
	if (!cn->pcrc_cancelled) {
		pexpect(st != NULL);
		pluto_do_crypto_op(cn, -1);
	}
	handle_helper_answer(st, mdp, arg);
}

/*
 * send_crypto_helper_request is called with a request to do some
 * cryptographic operations along with a continuation structure,
 * which will be used to deal with the response.
 *
 * See also comments prefixing the typedef for crypto_req_cont_func.
 *
 * struct pluto_crypto_req_cont *cn:
 *
 *	Points to a heap-allocated struct.  The caller transfers
 *	ownership (i.e responsibility to free) to us.  (We or our
 *	allies will free it after the continuation function is called
 *	or failure is determined.)
 *
 * If a state is deleted (which will cancel any outstanding crypto
 * request), then cn->pcrc_cancelled will be set true.
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
 * Suggested life-cycle of a resource like a msg_digest:
 *
 * - Note: not implemented by this mechanism, just a convention
 *   for the callers.
 *
 * - resource should be preserved in the case of STF_SUSPEND since
 *   it will be needed in the future.
 *
 */

void send_crypto_helper_request(struct state *st,
				struct pluto_crypto_req_cont *cn)
{
	passert(st->st_serialno != SOS_NOBODY);
	passert(cn->pcrc_serialno == SOS_NOBODY);
	cn->pcrc_serialno = st->st_serialno;

	/* set up the id */
	static pcr_req_id pcw_id;	/* counter for generating unique request IDs */
	cn->pcrc_id = ++pcw_id;

	/*
	 * Save in case it needs to be cancelled.
	 */
	pexpect(st->st_offloaded_task == NULL);
	st->st_offloaded_task = cn;
	st->st_v1_offloaded_task_in_background = false;

	/*
	 * do it all ourselves?
	 */
	if (pc_workers == NULL) {
		pluto_event_now("inline crypto", st->st_serialno,
				inline_worker, cn);
	} else {
		DBG(DBG_CONTROLMORE,
		    DBG_log("adding %s work-order %u for state #%lu",
			    cn->pcrc_name, cn->pcrc_id,
			    cn->pcrc_serialno));
		delete_event(st);
		event_schedule_s(EVENT_CRYPTO_TIMEOUT, EVENT_CRYPTO_TIMEOUT_DELAY, st);
		/* add to backlog */
		pthread_mutex_lock(&backlog_mutex);
		{
			insert_list_entry(&backlog, &cn->pcrc_backlog);
			backlog_queue_len++;
			/* wake up threads waiting for work */
			pthread_cond_signal(&backlog_cond);
		}
		pthread_mutex_unlock(&backlog_mutex);
	}
}

void delete_cryptographic_continuation(struct state *st)
{
	passert(st->st_serialno != SOS_NOBODY);
	struct pluto_crypto_req_cont *cn = st->st_offloaded_task;
	if (cn == NULL) {
		return;
	}
	/* shut it down */
	cn->pcrc_cancelled = true;
	st->st_offloaded_task = NULL;
	/* remove it from any queue */
	if (pc_workers != NULL) {
		/* remove it from any queue */
		pthread_mutex_lock(&backlog_mutex);
		if (remove_list_entry(&cn->pcrc_backlog)) {
			backlog_queue_len--;
		} else {
			/*
			 * Already grabbed by the helper thread so
			 * can't delete it here.
			 */
			cn = NULL;
		}
		pthread_mutex_unlock(&backlog_mutex);
		if (cn != NULL) {
			pcrc_release_request(cn);
		}
	}
}

/*
 * This function is called when a helper passes work back to the main
 * thread using the event loop.
 *
 */
static void handle_helper_answer(struct state *st,
				 struct msg_digest **mdp,
				 void *arg)
{
	struct pluto_crypto_req_cont *cn = arg;

	DBG(DBG_CONTROL,
		DBG_log("crypto helper %d replies to request ID %u",
			cn->pcrc_helpernum, cn->pcrc_id));

	passert(cn->pcrc_func != NULL);

	DBG(DBG_CONTROL,
		DBG_log("calling continuation function %p",
			cn->pcrc_func));

	/*
	 * call the continuation (skip if suppressed)
	 */
	if (cn->pcrc_cancelled) {
		/* suppressed */
		DBG(DBG_CONTROL, DBG_log("work-order %u state #%lu crypto result suppressed",
					 cn->pcrc_id, cn->pcrc_serialno));
		pexpect(st == NULL || st->st_offloaded_task == NULL);
		pcr_release(&cn->pcrc_pcr);
	} else if (st == NULL) {
		/* oops, the state disappeared! */
		LSWLOG_PEXPECT(buf) {
			lswlogf(buf, "work-order %u state #%lu disappeared!",
				cn->pcrc_id, cn->pcrc_serialno);
		}
		pcr_release(&cn->pcrc_pcr);
	} else {
		st->st_offloaded_task = NULL;
		st->st_v1_offloaded_task_in_background = false;
		(*cn->pcrc_func)(st, mdp, &cn->pcrc_pcr);
	}

	/* now free up the continuation */
	pfree(cn);
}

/*
 * initialize a helper.
 */
static void init_crypto_helper(struct pluto_crypto_worker *w, int n)
{
	int thread_status;

	w->pcw_helpernum = n;

	thread_status = pthread_create(&w->pcw_pid, NULL,
				       pluto_crypto_helper_thread, (void *)w);
	if (thread_status != 0) {
		loglog(RC_LOG_SERIOUS, "failed to start child thread for crypto helper %d, error = %d",
		       n, thread_status);
		w->pcw_dead = TRUE;
	} else {
		libreswan_log("started thread for crypto helper %d", n);
	}
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

	init_list(&backlog_info, &backlog);
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
