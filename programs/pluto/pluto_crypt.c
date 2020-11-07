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
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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
#include <unistd.h>		/* for pipe2() */
#include <fcntl.h>		/* for fcntl() et.al. */

#include "sysdep.h"
#include "constants.h"
#include "enum_names.h"
#include "defs.h"
#include "log.h"
#include "state.h"
#include "connections.h"
#include "demux.h"
#include "pluto_crypt.h"
#include "timer.h"

#include "server.h"
#include "ikev2_prf.h"
#include "crypt_dh.h"
#include "ikev1_prf.h"
#include "state_db.h"
#include "pluto_shutdown.h"		/* for exiting_pluto */

#include "ikev1.h"	/* for complete_v1_state_transition() */
#include "ikev2.h"	/* for complete_v2_state_transition() */

#ifdef HAVE_SECCOMP
# include "pluto_seccomp.h"
#endif

static void helper_thread_stopped_callback(struct state *st, void *arg);

/*
 * Hack to keep old PCR based code working.
 */
struct crypto_task {
	struct pluto_crypto_req_cont *cn;
};

static resume_cb handle_helper_answer;
static crypto_compute_fn pcr_compute;
static crypto_completed_cb pcr_completed;
static crypto_cancelled_cb pcr_cancelled;

static const struct crypto_handler pcr_handler = {
	.name = "pcr",
	.compute_fn = pcr_compute,
	.completed_cb = pcr_completed,
	.cancelled_cb = pcr_cancelled,
};

/*
 * The crypto continuation structure
 *
 * Pluto is an event-driven transaction system.
 * Each transaction must take a very small slice of time.
 * Those that cannot, must be broken into multiple
 * transactions and the state carried between them
 * cannot be on the stack or in simple global variables.
 * A continuation is used to hold such state.
 */

typedef unsigned int job_id;

struct pluto_crypto_req_cont {
	struct crypto_task *pcrc_task;
	const struct crypto_handler *pcrc_handler;
	struct list_entry pcrc_backlog;
	so_serial_t pcrc_so_serialno;		/* sponsoring state-object's serial number */
	bool pcrc_cancelled;
	const char *pcrc_name;
	job_id pcrc_job_id;
	int pcrc_helpernum;
	struct cpu_usage pcrc_time_used;

	/* where to send messages */
	struct logger *logger;

	/* old way */
	struct pluto_crypto_req pcrc_pcr;
	crypto_req_cont_func *pcrc_func;	/* function to continue with */
};

#define dbg_job(JOB, FMT, ...)						\
	dbg("job %u for #%lu: %s (%s): "FMT,				\
	    JOB->pcrc_job_id, JOB->pcrc_so_serialno,		\
	    JOB->pcrc_name,						\
	    (JOB->pcrc_pcr.pcr_type == pcr_crypto ? JOB->pcrc_handler->name : \
	     enum_show(&pluto_cryptoop_names, JOB->pcrc_pcr.pcr_type)), \
	    ##__VA_ARGS__)

/*
 * The work queue.  Accesses must be locked.
 */

static void jam_backlog(struct jambuf *buf, const void *data)
{
	if (data == NULL) {
		jam(buf, "no job");
	} else {
		const struct pluto_crypto_req_cont *cn = data;
		jam(buf, "job %ju", (uintmax_t)cn->pcrc_job_id);
		if (cn->pcrc_so_serialno != SOS_NOBODY) {
			jam(buf, " state #%lu", cn->pcrc_so_serialno);
		}
		if (cn->pcrc_helpernum != 0) {
			jam(buf, " helper %u", cn->pcrc_helpernum);
		}
		if (cn->pcrc_cancelled) {
			jam(buf, " cancelled");
		}
		if (cn->pcrc_name != NULL) {
			jam(buf, " %s", cn->pcrc_name);
		}
		if (cn->pcrc_handler != NULL) {
			jam(buf, " (%s)", cn->pcrc_handler->name);
		}
	}
}

static const struct list_info backlog_info = {
	.name = "backlog",
	.jam = jam_backlog,
};

static pthread_mutex_t backlog_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t backlog_cond = PTHREAD_COND_INITIALIZER;

struct list_head backlog = INIT_LIST_HEAD(&backlog, &backlog_info);
static int backlog_queue_len = 0;

static void message_helpers(struct pluto_crypto_req_cont *cn)
{
	pthread_mutex_lock(&backlog_mutex);
	if (cn != NULL) {
		insert_list_entry(&backlog, &cn->pcrc_backlog);
		backlog_queue_len++;
	}
	/* wake up threads waiting for work */
	pthread_cond_signal(&backlog_cond);
	pthread_mutex_unlock(&backlog_mutex);
}

/*
 * Create the pluto crypto request object.
 */

struct pluto_crypto_req_cont *new_pcrc(crypto_req_cont_func fn,
				       const char *name)
{
	struct pluto_crypto_req_cont *r = alloc_thing(struct pluto_crypto_req_cont, name);
	r->pcrc_func = fn; /* may be NULL */
	r->pcrc_cancelled = false;
	r->pcrc_name = name;
	r->pcrc_backlog = list_entry(&backlog_info, r);
	r->pcrc_so_serialno = SOS_NOBODY;
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
};

/* may be NULL if we are to do all the work ourselves */
static struct pluto_crypto_worker *pc_workers = NULL;

static int nr_helper_threads = 0;

/* pluto crypto operations */
static const char *const pluto_cryptoop_strings[] = {
	"crypto",		/* generic crypto */
	"build KE and nonce",	/* calculate g^i and generate a nonce */
	"build nonce",	/* generate a nonce */
	"compute dh+iv (V1 Phase 1)",	/* calculate (g^x)(g^y) and skeyids for Phase 1 DH + prf */
	"compute dh (V1 Phase 2 PFS)",	/* calculate (g^x)(g^y) for Phase 2 PFS */
	"compute dh (V2)",	/* perform IKEv2 PARENT SA calculation, create SKEYSEED */
};

static enum_names pluto_cryptoop_names = {
	0, elemsof(pluto_cryptoop_strings)-1,
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

static void pcr_cancelled(struct crypto_task **task)
{
	struct pluto_crypto_req *r = &(*task)->cn->pcrc_pcr;
	switch (r->pcr_type) {
	case pcr_build_ke_and_nonce:
	case pcr_build_nonce:
		cancelled_ke_and_nonce(&r->pcr_d.kn);
		break;
	case pcr_compute_v2_dh_shared_secret:
		cancelled_v2_dh_shared_secret(&r->pcr_d.dh_v2);
		break;
#ifdef USE_IKEv1
	case pcr_compute_v1_dh_shared_secret_and_iv:
	case pcr_compute_v1_dh_shared_secret:
		cancelled_v1_dh_shared_secret(&r->pcr_d.v1_dh);
		break;
#endif
	case pcr_crypto:
	default:
		bad_case(r->pcr_type);
	}
	pfreeany(*task);
}

void pcr_kenonce_init(struct pluto_crypto_req_cont *cn,
		      enum pluto_crypto_requests pcr_type,
		      const struct dh_desc *dh)
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
	pcr_init(r, pcr_compute_v2_dh_shared_secret);
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
	if (cn->pcrc_cancelled) {
		dbg_job(cn, "helper %d skipping job as cancelled", helpernum);
		return;
	}

	logtime_t start = logtime_start(cn->logger);

	dbg_job(cn, "helper %d starting job", helpernum);
	if (crypto_helper_delay > 0) {
		DBG_log("helper %d is pausing for %u seconds",
			helpernum, crypto_helper_delay);
		sleep(crypto_helper_delay);
	}

	cn->pcrc_handler->compute_fn(cn->logger, cn->pcrc_task, helpernum);

	cn->pcrc_time_used =
		logtime_stop(&start,
			     "helper %d processing job %u for state #%lu: %s (%s)",
			     helpernum, cn->pcrc_job_id, cn->pcrc_so_serialno,
			     cn->pcrc_name, cn->pcrc_handler->name);
}

static void pcr_compute(struct logger *logger,
			struct crypto_task *task,
			int unused_helpernum UNUSED)
{
	struct pluto_crypto_req_cont *cn = task->cn;
	struct pluto_crypto_req *r = &cn->pcrc_pcr;

	/* now we have the entire request in the buffer, process it */
	switch (r->pcr_type) {
	case pcr_build_ke_and_nonce:
		calc_ke(&r->pcr_d.kn, logger);
		calc_nonce(&r->pcr_d.kn);
		break;

	case pcr_build_nonce:
		calc_nonce(&r->pcr_d.kn);
		break;

#ifdef USE_IKEv1
	case pcr_compute_v1_dh_shared_secret_and_iv:
		calc_v1_dh_shared_secret_and_iv(&r->pcr_d.v1_dh, logger);
		break;
	case pcr_compute_v1_dh_shared_secret:
		calc_v1_dh_shared_secret(&r->pcr_d.v1_dh, logger);
		break;
#endif

	case pcr_compute_v2_dh_shared_secret:
		calc_v2_dh_shared_secret(r, logger);
		break;

	case pcr_crypto:
	default:
		bad_case(r->pcr_type);
	}
}

/* IN A HELPER THREAD */
static void *pluto_crypto_helper_thread(void *arg)
{
	struct logger logger[1] = { GLOBAL_LOGGER(null_fd), };
	const struct pluto_crypto_worker *w = arg;

	dbg("starting helper thread %d", w->pcw_helpernum);

#ifdef HAVE_SECCOMP
	init_seccomp_cryptohelper(w->pcw_helpernum, logger);
#else
	log_message(RC_LOG, logger, "seccomp security for helper not supported");
#endif

	/* OS X does not have pthread_setschedprio */
#if USE_PTHREAD_SETSCHEDPRIO
	int status = pthread_setschedprio(pthread_self(), 10);
	dbg("status value returned by setting the priority of this helper thread %d: %d",
	    w->pcw_helpernum, status);
#endif

	while (true) {
		struct pluto_crypto_req_cont *cn = NULL;
		pthread_mutex_lock(&backlog_mutex);
		{
			/*
			 * Search the backlog[] for something to do.
			 * If needed wait.
			 */
			pexpect(cn == NULL);
			while (!exiting_pluto) {
				/* grab the next entry, if there is one */
				pexpect(cn == NULL);
				FOR_EACH_LIST_ENTRY_OLD2NEW(&backlog, cn) { break; }
				if (cn != NULL) {
					/*
					 * Assign the entry to this
					 * thread, removing it from
					 * the backlog.
					 */
					remove_list_entry(&cn->pcrc_backlog);
					cn->pcrc_helpernum = w->pcw_helpernum;
					break;
				}
				dbg("helper thread %d has nothing to do",
				    w->pcw_helpernum);
				pthread_cond_wait(&backlog_cond, &backlog_mutex);
			}
			if (cn == NULL) {
				/*
				 * No CN implies pluto is exiting but
				 * not reverse - could grab a CN in
				 * parallel to pluto starting to exit.
				 */
				pexpect(exiting_pluto);
			}
		}
		pthread_mutex_unlock(&backlog_mutex);
		if (cn == NULL) {
			/* per above, must be shutting down */
			break;
		}
		/* might be cancelled */
		pluto_do_crypto_op(cn, w->pcw_helpernum);
		dbg_job(cn, "helper thread %d sending result back to state",
			w->pcw_helpernum);
		schedule_resume("sending helper answer back to state",
				cn->pcrc_so_serialno,
				handle_helper_answer, cn);
	}
	dbg("telling main thread that the helper thread %d is done", w->pcw_helpernum);
	schedule_callback("helper stopped", SOS_NOBODY,
			  helper_thread_stopped_callback, NULL);
	return NULL;
}

/*
 * Do the work 'inline' which really means on the event queue.
 *
 * Step one is to perform the crypto in a state-free context (just
 * like for a worker thread); and step two is to resume the thread
 * with the possibly cancelled result.
 */

static callback_cb inline_worker; /* type assertion */

static void inline_worker(struct state *unused_st UNUSED,
			  void *arg)
{
	struct pluto_crypto_req_cont *cn = arg;
	/* might be cancelled */
	pluto_do_crypto_op(cn, -1);
	schedule_resume("inline worker sending helper answer",
			cn->pcrc_so_serialno,
			handle_helper_answer, cn);
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

static void submit_crypto_request(struct pluto_crypto_req_cont *cn,
				  const struct logger *logger,
				  struct state *st,
				  struct crypto_task *task,
				  const struct crypto_handler *handler)
{
	passert(st->st_serialno != SOS_NOBODY);
	passert(cn->pcrc_so_serialno == SOS_NOBODY);
	cn->pcrc_so_serialno = st->st_serialno;

	/* set up the id */
	static job_id pcw_job_id = 0;	/* counter for generating unique request IDs */
	cn->pcrc_job_id = ++pcw_job_id;
	cn->pcrc_handler = handler;
	cn->pcrc_task = task;

	/*
	 * Save in case it needs to be cancelled.
	 */
	pexpect(st->st_offloaded_task == NULL);
	st->st_offloaded_task = cn;
	st->st_v1_offloaded_task_in_background = false;
	cn->logger = clone_logger(logger);
	dbg_job(cn, "adding job to queue");

	/*
	 * do it all ourselves?
	 */
	if (pc_workers == NULL) {
		/*
		 * Invoke the inline worker as if it is on a separate
		 * thread - no resume (aka unsuspend) and no state
		 * (hence SOS_NOBODY).
		 */
		schedule_callback("inline crypto", SOS_NOBODY, inline_worker, cn);
	} else {
		/*
		 * XXX: Danger:
		 *
		 * Clearing retransmits here is wrong, for instance
		 * when crypto is being run in the background.
		 */
		delete_event(st);
		clear_retransmits(st);
		event_schedule(EVENT_CRYPTO_TIMEOUT, EVENT_CRYPTO_TIMEOUT_DELAY, st);
		/* add to backlog */
		message_helpers(cn);
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
		if (detached_list_entry(&cn->pcrc_backlog)) {
			/*
			 * Already grabbed by the helper thread so
			 * can't delete it here.
			 */
			cn = NULL;
		} else {
			remove_list_entry(&cn->pcrc_backlog);
			backlog_queue_len--;
		}
		pthread_mutex_unlock(&backlog_mutex);
		if (cn != NULL) {
			cn->pcrc_handler->cancelled_cb(&cn->pcrc_task);
			pexpect(cn->pcrc_task == NULL); /* did their job */
			/* free the heap space */
			free_logger(&cn->logger, HERE);
			pfree(cn);
		}
	}
}

/*
 * This function is called when a helper passes work back to the main
 * thread using the event loop.
 *
 */
static stf_status handle_helper_answer(struct state *st,
				       struct msg_digest *md,
				       void *arg)
{
	struct pluto_crypto_req_cont *cn = arg;
	dbg_job(cn, "processing response from helper %d", cn->pcrc_helpernum);

	const struct crypto_handler *h = cn->pcrc_handler;
	passert(h != NULL);

	/*
	 * call the continuation (skip if suppressed)
	 */
	stf_status status;
	if (cn->pcrc_cancelled) {
		/* suppressed */
		dbg_job(cn, "was cancelled; ignoring respose");
		pexpect(st == NULL || st->st_offloaded_task == NULL);
		h->cancelled_cb(&cn->pcrc_task);
		pexpect(cn->pcrc_task == NULL); /* did your job */
		status = STF_SKIP_COMPLETE_STATE_TRANSITION;
	} else if (st == NULL) {
		/* oops, the state disappeared! */
		pexpect_fail(cn->logger, HERE,
			     "state #%lu for job %u disappeared!",
			     cn->pcrc_so_serialno, cn->pcrc_job_id);
		h->cancelled_cb(&cn->pcrc_task);
		pexpect(cn->pcrc_task == NULL); /* did your job */
		status = STF_SKIP_COMPLETE_STATE_TRANSITION;
	} else {
		pexpect(st->st_offloaded_task == cn);
		st->st_offloaded_task = NULL;
		st->st_v1_offloaded_task_in_background = false;
		/* bill the thread time */
		cpu_usage_add(st->st_timing.helper_usage, cn->pcrc_time_used);
		/* wall clock time not billed */
		/* run the callback */
		dbg_job(cn, "calling continuation function %p", h->completed_cb);
		status = h->completed_cb(st, md, &cn->pcrc_task);
		pexpect(cn->pcrc_task == NULL); /* did your job */
	}
	pexpect(cn->pcrc_task == NULL); /* cross check - re-check */
	/* now free up the continuation */
	free_logger(&cn->logger, HERE);
	pfree(cn);
	return status;
}

stf_status pcr_completed(struct state *st,
			 struct msg_digest *md,
			 struct crypto_task **task)
{
	struct pluto_crypto_req_cont *cn = (*task)->cn;
	passert(cn->pcrc_func != NULL);
	pexpect(cn->pcrc_pcr.pcr_type != pcr_crypto);
	(*cn->pcrc_func)(st, md, &cn->pcrc_pcr);
	switch (cn->pcrc_pcr.pcr_type) {
	case pcr_build_ke_and_nonce:
		cancelled_ke_and_nonce(&cn->pcrc_pcr.pcr_d.kn);
		break;
	default:
		break;
	}
	pfree(*task);
	*task = NULL;
	return STF_SKIP_COMPLETE_STATE_TRANSITION;
}

/*
 * Initialize helper debug delay value from environment variable.
 * This function is NOT thread safe (getenv).
 */
static void init_crypto_helper_delay(struct logger *logger)
{
	const char *envdelay;
	unsigned long delay;
	err_t error;

	envdelay = getenv("PLUTO_CRYPTO_HELPER_DELAY");
	if (envdelay == NULL)
		return;

	error = ttoulb(envdelay, 0, 0, secs_per_hour, &delay);
	if (error != NULL)
		log_message(RC_LOG, logger,
			    "$PLUTO_CRYPTO_HELPER_DELAY malformed: %s",
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
void start_crypto_helpers(int nhelpers, struct logger *logger)
{
	pc_workers = NULL;
	nr_helper_threads = 0;

	init_crypto_helper_delay(logger);

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
		log_message(RC_LOG, logger, "%d CPU cores online", ncpu_online);
		if (ncpu_online < 4)
			nhelpers = ncpu_online;
		else
			nhelpers = ncpu_online - 1;
	}

	if (nhelpers > 0) {
		log_message(RC_LOG, logger, "starting up %d helper threads", nhelpers);

		/*
		 * create the threads.  Set nr_helpers_started after
		 * the threads have been created so that shutdown code
		 * only tries to run when there really are threads.
		 */
		pc_workers = alloc_things(struct pluto_crypto_worker, nhelpers,
					  "pluto helpers");
		for (int n = 0; n < nhelpers; n++) {
			struct pluto_crypto_worker *w = &pc_workers[n];
			w->pcw_helpernum = n + 1; /* i.e., not 0 */
			int thread_status = pthread_create(&w->pcw_pid, NULL,
							   pluto_crypto_helper_thread, (void *)w);
			if (thread_status != 0) {
				log_message(RC_LOG_SERIOUS, logger,
					    "failed to start child thread for helper %d, error = %d",
					    n, thread_status);
				w->pcw_dead = true;
			} else {
				log_message(RC_LOG, logger, "started thread for helper %d", n);
			}
		}
		nr_helper_threads = nhelpers;
	} else {
		log_message(RC_LOG, logger,
			    "no helpers will be started; all cryptographic operations will be done inline");
	}
}

/*
 * Repeatedly nudge the helper threads until they all exit.
 *
 * Note that pthread_join() doesn't work here: an any-thread join may
 * end up joining an unrelated thread (for instance the CRL helper);
 * and a specific thread join may block waiting for the wrong thread.
 */

static void helper_thread_stopped_callback(struct state *st UNUSED, void *context UNUSED)
{
	nr_helper_threads--;
	dbg("helper thread exited, %u remaining", nr_helper_threads);

	/* wait for more? */
	if (nr_helper_threads > 0) {
		/* poke threads waiting for work */
		message_helpers(NULL);
		return;
	}

	/*
	 * Finish things using a callback so this code can cleanup all
	 * its allocated data.
	 */
	pfreeany(pc_workers);
	schedule_callback("all helper threads stopped", SOS_NOBODY,
			  helper_threads_stopped_callback, NULL);
}

void stop_helper_threads(void)
{
	if (nr_helper_threads > 0) {
		/* poke threads waiting for work */
		message_helpers(NULL);
	} else {
		dbg("no helper threads to shutdown");
		pexpect(pc_workers == NULL);
		schedule_callback("no helpers to stop", SOS_NOBODY,
				  helper_threads_stopped_callback, NULL);
	}
}

void send_crypto_helper_request(struct state *st,
				struct pluto_crypto_req_cont *cn)
{
	passert(cn->pcrc_func != NULL);
	passert(cn->pcrc_pcr.pcr_type != pcr_crypto);
	struct crypto_task *task = alloc_thing(struct crypto_task, "pcr_task");
	task->cn = cn;
	submit_crypto_request(cn, st->st_logger, st,
			      task, &pcr_handler);
}

void submit_crypto(const struct logger *logger,
		   struct state *st,
		   struct crypto_task *task,
		   const struct crypto_handler *handler,
		   const char *name)
{
	struct pluto_crypto_req_cont *cn = new_pcrc(NULL, name);
	pcr_init(&cn->pcrc_pcr, pcr_crypto);
	submit_crypto_request(cn, logger, st, task, handler);
}
