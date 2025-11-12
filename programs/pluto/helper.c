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

#include "defs.h"
#include "log.h"
#include "server.h"
#include "whack_shutdown.h"		/* for exiting_pluto; */
#include "helper.h"
#include "list_entry.h"
#include "pluto_timing.h"

#ifdef USE_SECCOMP
# include "pluto_seccomp.h"
#endif

static callback_cb helper_stopped_callback;		/* type assertion */
static callback_cb resume_main_thread;		/* type assertion */
static callback_cb inline_helper;			/* type assertion */
static callback_cb call_helpers_stopped_callback;	/* type assertion */

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
 * Define request_id_t and helper_id_t as enums so that GCC 10 will detect
 * and complain when code attempts to assign the wrong type.

 * An enum's size is always an <<int>.  Presumably this is so that the
 * size of the declaration <<enum foo;>> (i.e., with no other
 * information) is always known - this means the upper bound is always
 * UINT_MAX.  See note further down on overflow.
 */

enum request_id { REQUEST_ID_MIN = 1, REQUEST_ID_MAX = UINT_MAX, };

struct job {
	struct list_entry backlog;
	where_t where;
	enum request_id request_id;
	enum helper_id helper_id;
	helper_fn *helper;
	helper_cb *callback;
	struct refcnt *request;
	/* where to send messages */
	struct logger *logger;
};

#define PRI_JOB "%s, request %u"
#define pri_job(JOB)							\
	(JOB)->request->base->what,					\
		(JOB)->request_id

#define PRI_JOB_HELPER PRI_JOB", helper %d"
#define pri_job_helper(JOB) pri_job(JOB), JOB->helper_id

/*
 * The work queue.  Accesses must be locked.
 */

static size_t jam_helper_backlog(struct jambuf *buf, const void *data)
{
	if (data == NULL) {
		return jam(buf, "no job");
	}

	size_t s = 0;
	const struct job *job = data;
	s += jam(buf, "job %ju", (uintmax_t)job->request_id);
	if (job->helper_id != 0) {
		s += jam(buf, " helper %d", job->helper_id);
	}
	if (job->where != NULL) {
		s += jam(buf, " %s", job->where->func);
	}
	if (job->request != NULL && job->request->base->what != NULL) {
		s += jam(buf, " (%s)", job->request->base->what);
	}
	return s;
}

LIST_INFO(job, backlog, helper_backlog_info, jam_helper_backlog);

static pthread_mutex_t helper_backlog_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t helper_backlog_cond = PTHREAD_COND_INITIALIZER;

struct list_head helper_backlog = INIT_LIST_HEAD(&helper_backlog, &helper_backlog_info);

static void message_helpers(struct job *job)
{
	pthread_mutex_lock(&helper_backlog_mutex);
	if (job != NULL) {
		insert_list_entry(&helper_backlog, &job->backlog);
	}
	/* wake up threads waiting for work */
	pthread_cond_signal(&helper_backlog_cond);
	pthread_mutex_unlock(&helper_backlog_mutex);
}

/*
 * Note: this per-helper struct is never modified in a helper thread
 */

struct helper {
	struct logger *logger;
	enum helper_id id;
	pthread_t pid;
};

/* may be NULL if we are to do all the work ourselves */

static struct helper *helpers = NULL;
static unsigned helpers_started = 0;
static unsigned helpers_stopped = 0;

unsigned nhelpers(void)
{
	return (helpers_started - helpers_stopped);
}

/*
 * If there are any helper threads, this code is always executed IN A HELPER
 * THREAD. Otherwise it is executed in the main (only) thread.
 */

static void do_job(struct job *job)
{
	ldbg(job->logger, PRI_JOB_HELPER": request started",
	     pri_job_helper(job));
	job->callback = job->helper((struct help_request*) job->request,
				    job->logger, job->helper_id);
	ldbg(job->logger, PRI_JOB_HELPER": request %s",
	     pri_job_helper(job),
	     (job->callback == NULL ? "failed" : "succeeded"));

	schedule_callback("helper finished",
			  deltatime(0), SOS_NOBODY,
			  resume_main_thread, job,
			  job->logger);
}

/* IN A HELPER THREAD */
static void *helper(void *arg)
{
	const struct helper *h = arg;
	ldbg(h->logger, "starting thread");

#ifdef USE_SECCOMP
	init_seccomp_helper(h->logger);
#else
	llog(RC_LOG, h->logger, "seccomp security for helper not supported");
#endif

	/* OS X does not have pthread_setschedprio */
#if USE_PTHREAD_SETSCHEDPRIO
	int status = pthread_setschedprio(pthread_self(), 10);
	ldbg(h->logger, "status value returned by setting the priority of this thread: %d", status);
#endif

	while (true) {
		struct job *job = NULL;
		pthread_mutex_lock(&helper_backlog_mutex);
		{
			/*
			 * Search the backlog[] for something to do.
			 * If needed wait.
			 */
			pexpect(job == NULL);
			while (!exiting_pluto) {
				/* grab the next entry, if there is one */
				pexpect(job == NULL);
				FOR_EACH_LIST_ENTRY_OLD2NEW(job, &helper_backlog) { break; }
				if (job != NULL) {
					/*
					 * Assign the entry to this
					 * helper, removing it from
					 * the backlog.
					 *
					 * XXX: logged when job
					 * started.
					 */
					remove_list_entry(&job->backlog);
					job->helper_id = h->id;
					ldbg(job->logger, PRI_JOB_HELPER": assigned",
					     pri_job_helper(job));
					break;
				}
				ldbg(h->logger, "waiting for work");
				pthread_cond_wait(&helper_backlog_cond, &helper_backlog_mutex);
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
		pthread_mutex_unlock(&helper_backlog_mutex);
		if (job == NULL) {
			/* per above, must be shutting down */
			break;
		}

		/* cancelled, handled by do_job() */

		do_job(job);
	}

	ldbg(h->logger, "helper %u: telling main thread that it is exiting", h->id);
	schedule_callback("helper exiting", deltatime(0), SOS_NOBODY,
			  helper_stopped_callback,
			  /*w-but-rw*/arg, h->logger);

	/*
	 * Danger.  This isn't the end.
	 *
	 * NSS still has stuff in thread-exit handlers to execute and
	 * there's no clean way of forcing its execution (and if it
	 * isn't allowed to run NSS crashes!).  Hence, the main thread
	 * will need to wait for this thread to exit.
	 *
	 * But wait, there's more.  The main thread also needs to keep
	 * the event loop running while these threads are exiting so
	 * ptread_join() needs to be called with care.
	 *
	 * See: Race condition in helper_thread_stopped_callback() #2461
	 * See: PR_Cleanup() doesn't wait for pthread_create() threads
	 * https://bugzilla.mozilla.org/show_bug.cgi?id=1992272
	 */

	return NULL;
}

/*
 * Do the work 'inline' which really means on the event queue.
 *
 * Step one is to perform the work in a state-free context (just like
 * for a worker thread); and step two is to resume the thread with the
 * possibly cancelled result.
 */

static void inline_helper(const char *story UNUSED, struct state *st, void *arg)
{
	struct job *job = arg;
	struct logger *logger = job->logger;
	PEXPECT(logger, st == NULL);
	job->helper_id = INLINE_HELPER_ID;
	do_job(job);
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

void request_help_where(struct refcnt *request,
			helper_fn *helper,
			struct logger *logger,
			where_t where)
{
	struct job *job = alloc_thing(struct job, where->func);
	ldbg_newref(&global_logger, job);
	job->where = where;
	job->helper = helper;
	job->request = request;
	job->logger = clone_logger(logger, HERE);

	init_list_entry(&helper_backlog_info, job, &job->backlog);

	/*
	 * set up the id
	 *
	 * XXX: request_id is used as a short lifetime identifier so
	 * rolling (after several years of up-time) isn't a concern.
	 */
	static enum request_id request_id = 0;	/* counter for generating unique request IDs */
	job->request_id = ++request_id;

	/*
	 * do it all ourselves?
	 */
	if (helpers == NULL) {
		/*
		 * Invoke the inline_helper() as if it is on a
		 * separate thread.  It's put onto the event queue so
		 * that the existing stack can first unwind.
		 */
		ldbg(logger, PRI_JOB": adding to event queue", pri_job(job));

		schedule_callback("inline helper",
				  deltatime(0),
				  SOS_NOBODY,
				  inline_helper, job,
				  job->logger);
		return;
	}

	/* add to backlog */
	ldbg(logger, PRI_JOB": adding to helper queue", pri_job(job));
	message_helpers(job);
}

/*
 * This function is called when a helper passes work back to the main
 * thread using the event loop.
 */

static void free_job(struct job **jobp)
{
	struct job *job = *jobp;
	void * r = refcnt_delref_where("helper", job->request, job->logger, HERE);
	PASSERT(job->logger, r == NULL);
	/* now free up the continuation */
	free_logger(&job->logger, HERE);
	ldbg_delref(&global_logger, job);
	pfree(job);
	*jobp = NULL;
}

static void resume_main_thread(const char *story,
			       struct state *st,
			       void *arg)
{
	struct job *job = arg;
	PASSERT(job->logger, in_main_thread());
	PEXPECT(job->logger, st == NULL);

	/*
	 * call the continuation (skip if suppressed)
	 */
	if (job->callback != NULL) {
		ldbg(job->logger, PRI_JOB_HELPER": %s: resuming",
		     pri_job_helper(job), story);
		job->callback((struct help_request *)job->request, job->logger);
	} else {
		/* should already be logged */
		ldbg(job->logger, PRI_JOB_HELPER": %s: aborted",
		     pri_job_helper(job), story);
	}

	free_job(&job);
}

/*
 * initialize the helpers.
 *
 * Later we will have to make provisions for helpers that have hardware
 * underneath them, in which case, they may be able to accept many
 * more requests than average.
 *
 */
void start_helpers(uintmax_t nhelpers, struct logger *logger)
{
	/* redundant */
	helpers = NULL;
	helpers_started = 0;
	helpers_stopped = 0;

	/*
	 * When nhelpers==-1 (aka MAX), find out how many CPUs there
	 * are.  When nhelpers=0, everything is done on the main
	 * thread.
	 */

	if (nhelpers > 1000/*arbitrary*/ && nhelpers < UINTMAX_MAX) {
		llog(WARNING_STREAM, logger, "nhelpers=%ju is huge, limiting to number of CPUs", nhelpers);
		nhelpers = UINTMAX_MAX;
	}

	if (nhelpers == UINTMAX_MAX) {
		int ncpu_online = nr_processors_online();
		/* The theory is reserve one CPU for the event loop */
		llog(RC_LOG, logger, "%d CPU cores online", ncpu_online);
		if (ncpu_online < 4)
			nhelpers = ncpu_online;
		else
			nhelpers = ncpu_online - 1;
	}

	if (nhelpers > 0) {
		llog(RC_LOG, logger, "starting %ju helpers", nhelpers);

		/*
		 * create the threads.  Set nr_helpers_started after
		 * the threads have been created so that shutdown code
		 * only tries to run when there really are threads.
		 */
		helpers = alloc_things(struct helper, nhelpers, "helper");
		for (unsigned n = 0; n < nhelpers; n++) {
			struct helper *h = &helpers[n];
			h->id = n + 1; /* i.e., not 0 */
			h->logger = string_logger(HERE, "helper %d", h->id);
			int thread_status = pthread_create(&h->pid, NULL, helper, (void *)h);
			if (thread_status != 0) {
				llog_errno(WARNING_STREAM, h->logger, thread_status, "failed to start, ");
			} else {
				llog(RC_LOG, h->logger, "started");
			}
		}
		helpers_started = nhelpers;
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

static void (*helpers_stopped_callback)(void);

static void helper_stopped_callback(const char *story UNUSED,
				    struct state *st UNUSED,
				    void *context)
{
	pexpect(st == NULL);
	struct helper *h = context;

	helpers_stopped++;
	ldbg(h->logger, "exiting, %u helpers remaining",
	     helpers_started-helpers_stopped);

	/*
	 * Danger:
	 *
	 * Delay joining W.pid until all helper threads have exited.
	 * This way the event-loop is kept running.
	 *
	 * Even though W is on the exit path it still needs to execute
	 * NSS's thread exit code - who knows what that is doing and
	 * how long it will take -
	 */

	if (helpers_started > helpers_stopped) {
		/* poke threads waiting for work */
		message_helpers(NULL);
		return;
	}

	 /*
	  * All done; cleanup
	  *
	  * All helper threads are on the exit war-path so, hopefully,
	  * this join will not block (but no telling what NSS did).
	  */

	for (unsigned n = 0; n < helpers_started; n++) {
		struct helper *h = &helpers[n];
		ldbg(h->logger, "joining helper");
		pthread_join(h->pid, NULL);
		free_logger(&h->logger, HERE);
	}

	pfreeany(helpers);
	helpers = NULL;
	helpers_stopped_callback();
}

static void call_helpers_stopped_callback(const char *story UNUSED,
					  struct state *st UNUSED,
					  void *context UNUSED)
{
	helpers_stopped_callback();
}

void stop_helpers(void (*helpers_stopped_cb)(void), struct logger *logger)
{
	helpers_stopped_callback = helpers_stopped_cb;
	if (helpers_started == 0) {
		/*
		 * Always finish things using a callback so this call
		 * stack can cleanup all its allocated data.
		 */
		ldbg(logger, "no helpers to shutdown");
		pexpect(helpers == NULL);
		schedule_callback("no helpers to stop",
				  deltatime(0), SOS_NOBODY,
				  call_helpers_stopped_callback, /*context*/NULL,
				  logger);
		return;
	}
	/* poke threads waiting for work */
	message_helpers(NULL);
	/* return to the event loop */
}

void free_help_requests(struct logger *logger)
{
	if (helpers_started == helpers_stopped) {
		passert(helpers == NULL);
		struct job *job = NULL;
		FOR_EACH_LIST_ENTRY_OLD2NEW(job, &helper_backlog) {
			remove_list_entry(&job->backlog);
			free_job(&job);
		}
	} else {
		llog(RC_LOG, logger, "WARNING: helper threads still running");
	}
}
