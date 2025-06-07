/* Pluto's helper thread pool, for libreswan
 *
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
#include <unistd.h>	/* for sleep() */
#include <limits.h>	/* for UINT_MAX, ULONG_MAX */

#include "ttodata.h"
#include "refcnt.h"

#include "defs.h"
#include "log.h"
#include "state.h"
#include "server.h"
#include "whack_shutdown.h"		/* for exiting_pluto; */
#include "server_pool.h"
#include "list_entry.h"
#include "pluto_timing.h"
#include "connections.h"
#include "demux.h"			/* for md_addref() md_delref() */

#ifdef USE_SECCOMP
# include "pluto_seccomp.h"
#endif

static callback_cb helper_thread_stopped_callback;	/* type assertion */
static resume_cb handle_helper_answer;			/* type assertion */
static callback_cb inline_worker;			/* type assertion */
static callback_cb call_server_helpers_stopped_callback; /* type assertion */
/*
 * The job structure
 *
 * Pluto is an event-driven transaction system.  Each transaction must
 * take a very small slice of time.  Those that cannot, must be broken
 * into multiple transactions and the state carried between them
 * cannot be on the stack or in simple global variables.
 *
 * A job is used to hold such state.
 *
 * XXX:
 *
 * Define job_id_t and helper_id_t as enums so that GCC 10 will detect
 * and complain when code attempts to assign the wrong type.

 * An enum's size is always an <<int>.  Presumably this is so that the
 * size of the declaration <<enum foo;>> (i.e., with no other
 * information) is always known - this means the upper bound is always
 * UINT_MAX.  See note further down on overflow.
 */

typedef enum { JOB_ID_MIN = 1, JOB_ID_MAX = UINT_MAX, } job_id_t;
typedef enum { HELPER_ID_MIN = 1, HELPER_ID_MAX = UINT_MAX, } helper_id_t;

struct job {
	struct task *task;
	const struct task_handler *handler;
	struct list_entry backlog;
	so_serial_t callback_so;		/* sponsoring state-object's serial number */
	so_serial_t task_so;			/* sponsoring state-object's serial number */
	struct msg_digest *md;
	bool cancelled;
	where_t where;
	job_id_t job_id;
	helper_id_t helper_id;
	struct cpu_usage time_used;

	/* where to send messages */
	struct logger *logger;
};

#define PRI_JOB "job %u helper %u "PRI_SO"/"PRI_SO" %s (%s)"
#define pri_job(JOB)							\
	JOB->job_id,							\
		JOB->helper_id,						\
		pri_so(JOB->callback_so),				\
		pri_so(JOB->task_so),					\
		JOB->where->func,					\
		JOB->handler->name

/*
 * The work queue.  Accesses must be locked.
 */

static size_t jam_backlog(struct jambuf *buf, const void *data)
{
	if (data == NULL) {
		return jam(buf, "no job");
	}

	size_t s = 0;
	const struct job *job = data;
	s += jam(buf, "job %ju", (uintmax_t)job->job_id);
	if (job->callback_so != SOS_NOBODY) {
		s += jam(buf, " state "PRI_SO, pri_so(job->callback_so));
	}
	if (job->task_so != SOS_NOBODY && job->task_so != job->callback_so) {
		s += jam(buf, " state #%lu", pri_so(job->task_so));
	}
	if (job->helper_id != 0) {
		s += jam(buf, " helper %u", job->helper_id);
	}
	if (job->cancelled) {
		s += jam(buf, " cancelled");
	}
	if (job->where != NULL) {
		s += jam(buf, " %s", job->where->func);
	}
	if (job->handler != NULL) {
		s += jam(buf, " (%s)", job->handler->name);
	}
	return s;
}

LIST_INFO(job, backlog, backlog_info, jam_backlog);

static pthread_mutex_t backlog_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t backlog_cond = PTHREAD_COND_INITIALIZER;

struct list_head backlog = INIT_LIST_HEAD(&backlog, &backlog_info);
static int backlog_queue_len = 0;

static void message_helpers(struct job *job)
{
	pthread_mutex_lock(&backlog_mutex);
	if (job != NULL) {
		insert_list_entry(&backlog, &job->backlog);
		backlog_queue_len++;
	}
	/* wake up threads waiting for work */
	pthread_cond_signal(&backlog_cond);
	pthread_mutex_unlock(&backlog_mutex);
}

/*
 * Note: this per-helper struct is never modified in a helper thread
 */

struct helper_thread {
	struct logger *logger;
	helper_id_t helper_id;
	pthread_t pid;
};

/* may be NULL if we are to do all the work ourselves */

static struct helper_thread *helper_threads = NULL;
static unsigned helper_threads_started = 0;
static unsigned helper_threads_stopped = 0;

unsigned server_nhelpers(void)
{
	return (helper_threads_started - helper_threads_stopped);
}

/*
 * If there are any helper threads, this code is always executed IN A HELPER
 * THREAD. Otherwise it is executed in the main (only) thread.
 */

static void do_job(struct job *job, helper_id_t helper_id)
{
	logtime_t start = logtime_start(job->logger);

	if (job->cancelled) {
		ldbg(job->logger, PRI_JOB": skipping as cancelled", pri_job(job));
	} else {
		ldbg(job->logger, PRI_JOB": started", pri_job(job));
		job->handler->computer_fn(job->logger, job->task, helper_id);
		ldbg(job->logger, PRI_JOB": finished", pri_job(job));
	}

	job->time_used = logtime_stop(&start, PRI_JOB, pri_job(job));
	schedule_resume("sending job back to main thread",
			job->callback_so, &job->md/*stolen*/,
			handle_helper_answer, job);
}

/* IN A HELPER THREAD */
static void *helper_thread(void *arg)
{
	const struct helper_thread *w = arg;
	ldbg(w->logger, "starting thread");

#ifdef USE_SECCOMP
	init_seccomp_cryptohelper(w->helper_id, w->logger);
#else
	llog(RC_LOG, w->logger, "seccomp security for helper not supported");
#endif

	/* OS X does not have pthread_setschedprio */
#if USE_PTHREAD_SETSCHEDPRIO
	int status = pthread_setschedprio(pthread_self(), 10);
	ldbg(w->logger, "status value returned by setting the priority of this thread: %d", status);
#endif

	while (true) {
		struct job *job = NULL;
		pthread_mutex_lock(&backlog_mutex);
		{
			/*
			 * Search the backlog[] for something to do.
			 * If needed wait.
			 */
			pexpect(job == NULL);
			while (!exiting_pluto) {
				/* grab the next entry, if there is one */
				pexpect(job == NULL);
				FOR_EACH_LIST_ENTRY_OLD2NEW(job, &backlog) { break; }
				if (job != NULL) {
					/*
					 * Assign the entry to this
					 * thread, removing it from
					 * the backlog.
					 *
					 * XXX: logged when job
					 * started.
					 */
					remove_list_entry(&job->backlog);
					job->helper_id = w->helper_id;
					break;
				}
				dbg("helper %u: waiting for work", w->helper_id);
				pthread_cond_wait(&backlog_cond, &backlog_mutex);
			}
			if (job == NULL) {
				/*
				 * No JOB implies pluto is exiting but
				 * not reverse - could grab a JOB in
				 * parallel to pluto starting to exit.
				 */
				pexpect(exiting_pluto);
			}
		}
		pthread_mutex_unlock(&backlog_mutex);
		if (job == NULL) {
			/* per above, must be shutting down */
			break;
		}
		/* might be cancelled */
		if (impair.helper_thread_delay.enabled) {
			llog(RC_LOG, job->logger,
			     "IMPAIR: "PRI_JOB": helper is pausing for %u seconds",
			     pri_job(job), impair.helper_thread_delay.value);
			sleep(impair.helper_thread_delay.value);
		}
		do_job(job, w->helper_id);
	}

	dbg("helper %u: telling main thread that it is exiting", w->helper_id);
	schedule_callback("helper stopped", deltatime(0), SOS_NOBODY,
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

static void inline_worker(const char *story UNUSED, struct state *unused_st UNUSED, void *arg)
{
	struct job *job = arg;
	/* might be cancelled */
	do_job(job, -1);
}

/*
 * send_crypto_helper_request is called with a request to do some
 * cryptographic operations along with a continuation structure,
 * which will be used to deal with the response.
 *
 * See also comments prefixing the typedef for crypto_req_cont_func.
 *
 * struct job *j:
 *
 *	Points to a heap-allocated struct.  The caller transfers
 *	ownership (i.e responsibility to free) to us.  (We or our
 *	allies will free it after the continuation function is called
 *	or failure is determined.)
 *
 * If a state is deleted (which will cancel any outstanding crypto
 * request), then job->cancelled will be set true.
 *
 * Return values:
 *
 *	STF_FAIL_v1N: failure; message already logged.
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

void submit_task(struct state *callback_sa,
		 struct state *task_sa,
		 struct msg_digest *md,
		 bool detach_whack,
		 struct task *task,
		 const struct task_handler *handler,
		 where_t where)
{
	if (callback_sa->st_offloaded_task != NULL) {
		llog_pexpect(callback_sa->logger, where,
			     "state already has outstanding crypto ["PRI_WHERE"]",
			     pri_where(callback_sa->st_offloaded_task->where));
		return;
	}

	struct job *job = alloc_thing(struct job, where->func);
	ldbg_alloc(&global_logger, "job", job, HERE);
	job->cancelled = false;
	job->where = where;
	init_list_entry(&backlog_info, job, &job->backlog);
	job->callback_so = callback_sa->st_serialno;
	job->task_so = task_sa->st_serialno;

	/*
	 * set up the id
	 *
	 * XXX: job_id is used as a short lifetime identifier so
	 * rolling (after several years of up-time) isn't a concern.
	 */
	static job_id_t job_id = 0;	/* counter for generating unique request IDs */
	job->job_id = ++job_id;

	job->handler = handler;
	job->task = task;

	/*
	 * Save in case it needs to be cancelled.
	 */
	task_sa->st_offloaded_task = job;
	job->logger = clone_logger(task_sa->logger, HERE);
	job->md = md_addref(md);
	ldbg(job->logger, PRI_JOB": added to pending queue", pri_job(job));

	if (callback_sa->st_ike_version == IKEv1) {
		/*
		 * IKEv1: schedule a timeout event to cap the suspend
		 * time.  STF_SUSPEND will be looking for this.
		 *
		 * IKEv2: While initiating and processing a message
		 * there's the TIMEOUT_INITIATOR, TIMEOUT_RESPONDER,
		 * or TIMEOUT_RESPONSE timer running, hence no need
		 * for this additional timer.  When calculating crypto
		 * in the background (for instance when assembling
		 * fragments), there's a DISCARD timer running.
		 */
		delete_v1_event(callback_sa);
		event_schedule(EVENT_v1_CRYPTO_TIMEOUT, EVENT_CRYPTO_TIMEOUT_DELAY, callback_sa);
	}

	/*
	 * do it all ourselves?
	 */
	if (helper_threads == NULL) {
		/*
		 * Invoke the inline worker as if it is on a separate
		 * thread - no resume (aka unsuspend) and no state
		 * (hence SOS_NOBODY).  Caller will return
		 * STF_SUSPEND, and then the event-loop will invoke
		 * the callback.
		 */
		deltatime_t delay = deltatime(0);
		if (impair.helper_thread_delay.enabled) {
			if (impair.helper_thread_delay.value == 0) {
				static uint64_t warp = 0;
				delay = deltatime_from_milliseconds(++warp);
				llog(RC_LOG, job->logger, "IMPAIR: "PRI_JOB": helper is warped by %ju milliseconds",
				     pri_job(job), warp);
			} else {
				delay = deltatime(impair.helper_thread_delay.value);
				llog(RC_LOG, job->logger, "IMPAIR: "PRI_JOB": helper is pausing for %ju seconds",
				     pri_job(job), deltasecs(delay));
			}
		}

		if (detach_whack) {
			whack_detach(job->logger, task_sa->logger);
		}

		schedule_callback("inline crypto", delay,
				  SOS_NOBODY, inline_worker, job);
		return;
	}

	if (detach_whack) {
		whack_detach(job->logger, task_sa->logger);
	}

	/* add to backlog */
	message_helpers(job);
}

void delete_cryptographic_continuation(struct state *st)
{
	passert(in_main_thread());
	passert(st->st_serialno != SOS_NOBODY);
	struct job *job = st->st_offloaded_task;
	if (job == NULL) {
		return;
	}
	pmemory(job);
	/* shut it down */
	job->cancelled = true;
	st->st_offloaded_task = NULL;
	/* thread pool will throw the task back for cleanup */
}

/*
 * This function is called when a helper passes work back to the main
 * thread using the event loop.
 *
 */

static void free_job(struct job **jobp)
{
	struct job *job = *jobp;
	passert(job->handler->cleanup_cb != NULL);
	job->handler->cleanup_cb(&job->task);
	pexpect(job->task == NULL); /* did your job */
	md_delref(&job->md);
	/* now free up the continuation */
	free_logger(&job->logger, HERE);
	ldbg_free(&global_logger, "job", job, HERE);
	pfree(job);
	*jobp = NULL;
}

static stf_status handle_helper_answer(struct state *callback_sa,
				       struct msg_digest *md,
				       void *arg)
{
	passert(in_main_thread());
	struct job *job = arg;
	passert(job->handler != NULL);
	struct state *task_sa = state_by_serialno(job->task_so);

	/*
	 * call the continuation (skip if suppressed)
	 */
	stf_status status;
	if (job->cancelled) {
		/* suppressed */
		ldbg(job->logger, PRI_JOB": job cancelled!", pri_job(job));
		PEXPECT(job->logger, task_sa == NULL || task_sa->st_offloaded_task == NULL);
		status = STF_SKIP_COMPLETE_STATE_TRANSITION;
	} else if (callback_sa == NULL) {
		/* oops, the callback state disappeared! */
		llog_pexpect(job->logger, HERE, PRI_JOB": callback disappeared!", pri_job(job));
		status = STF_SKIP_COMPLETE_STATE_TRANSITION;
	} else if (task_sa == NULL) {
		/* oops, the task state disappeared! */
		llog_pexpect(job->logger, HERE, PRI_JOB": task disappeared!", pri_job(job));
		status = STF_SKIP_COMPLETE_STATE_TRANSITION;
	} else {
		ldbg(job->logger, PRI_JOB": calling state's callback function", pri_job(job));
		PEXPECT(job->logger, task_sa->st_offloaded_task == job);
		task_sa->st_offloaded_task = NULL;
		/* bill the thread time */
		cpu_usage_add(task_sa->st_timing.helper_usage, job->time_used);
		/* wall clock time not billed */
		/* run the callback */
		PASSERT(job->logger, job->handler->completed_cb != NULL);
		status = job->handler->completed_cb(callback_sa, md, job->task);
	}
	name_buf buf;
	ldbg(job->logger, PRI_JOB": final status %s; cleaning up",
	     pri_job(job), str_enum_long(&stf_status_names, status, &buf));
	free_job(&job);
	return status;
}

/*
 * initialize the helpers.
 *
 * Later we will have to make provisions for helpers that have hardware
 * underneath them, in which case, they may be able to accept many
 * more requests than average.
 *
 */
void start_server_helpers(uintmax_t nhelpers, struct logger *logger)
{
	/* redundant */
	helper_threads = NULL;
	helper_threads_started = 0;
	helper_threads_stopped = 0;

	/*
	 * When nhelpers==-1 (aka MAX), find out how many CPUs there
	 * are.  When nhelpers=0, everything is done on the main
	 * thread.
	 */

	if (nhelpers > 1000/*arbitrary*/ && nhelpers < UINTMAX_MAX) {
		llog(RC_LOG, logger, "warning: nhelpers=%ju is huge, limiting to number of CPUs", nhelpers);
		nhelpers = UINTMAX_MAX;
	}

	if (nhelpers == UINTMAX_MAX) {
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
		/* The theory is reserve one CPU for the event loop */
		llog(RC_LOG, logger, "%d CPU cores online", ncpu_online);
		if (ncpu_online < 4)
			nhelpers = ncpu_online;
		else
			nhelpers = ncpu_online - 1;
	}

	if (nhelpers > 0) {
		llog(RC_LOG, logger, "starting up %ju helper threads", nhelpers);

		/*
		 * create the threads.  Set nr_helpers_started after
		 * the threads have been created so that shutdown code
		 * only tries to run when there really are threads.
		 */
		helper_threads = alloc_things(struct helper_thread, nhelpers,
					      "pluto helpers");
		for (unsigned n = 0; n < nhelpers; n++) {
			struct helper_thread *w = &helper_threads[n];
			w->helper_id = n + 1; /* i.e., not 0 */
			w->logger = string_logger(HERE, "helper(%d)", w->helper_id);
			int thread_status = pthread_create(&w->pid, NULL,
							   helper_thread, (void *)w);
			if (thread_status != 0) {
				llog(RC_LOG, logger,
					    "failed to start child thread for helper %d, error = %d",
					    n, thread_status);
			} else {
				llog(RC_LOG, logger, "started thread for helper %d", n);
			}
		}
		helper_threads_started = nhelpers;
	} else {
		llog(RC_LOG, logger,
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

static void (*server_helpers_stopped_callback)(void);

static void helper_thread_stopped_callback(const char *story UNUSED,
					   struct state *st UNUSED,
					   void *context UNUSED)
{
	helper_threads_stopped++;
	dbg("one helper thread exited, %u remaining",
	    helper_threads_started-helper_threads_stopped);

	/* wait for more? */
	if (helper_threads_started > helper_threads_stopped) {
		/* poke threads waiting for work */
		message_helpers(NULL);
		return;
	}

	/* all done; cleanup */
	for (unsigned h = 0; h < helper_threads_started; h++) {
		struct helper_thread *w = &helper_threads[h];
		free_logger(&w->logger, HERE);
	}

	pfreeany(helper_threads);
	helper_threads = NULL;
	server_helpers_stopped_callback();
}

static void call_server_helpers_stopped_callback(const char *story UNUSED,
						 struct state *st UNUSED,
						 void *context UNUSED)
{
	server_helpers_stopped_callback();
}

void stop_server_helpers(void (*server_helpers_stopped_cb)(void))
{
	server_helpers_stopped_callback = server_helpers_stopped_cb;
	if (helper_threads_started > 0) {
		/* poke threads waiting for work */
		message_helpers(NULL);
	} else {
		/*
		 * Always finish things using a callback so this call stack
		 * can cleanup all its allocated data.
		 */
		dbg("no helper threads to shutdown");
		pexpect(helper_threads == NULL);
		schedule_callback("no helpers to stop", deltatime(0), SOS_NOBODY,
				  call_server_helpers_stopped_callback, NULL);
	}
}

void free_server_helper_jobs(struct logger *logger)
{
	if (helper_threads_started == helper_threads_stopped) {
		passert(helper_threads == NULL);
		struct job *job = NULL;
		FOR_EACH_LIST_ENTRY_OLD2NEW(job, &backlog) {
			remove_list_entry(&job->backlog);
			free_job(&job);
		}
	} else {
		llog(RC_LOG, logger, "WARNING: helper threads still running");
	}
}
