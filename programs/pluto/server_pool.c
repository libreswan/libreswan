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

#include <unistd.h>	/* for sleep() */

#include "refcnt.h"

#include "defs.h"
#include "log.h"
#include "state.h"
#include "server_pool.h"
#include "pluto_timing.h"
#include "connections.h"
#include "demux.h"			/* for md_addref() md_delref() */
#include "helper.h"

static callback_cb delayed_help_request;

static helper_fn server_pool_helper;			/* type assertion */
static helper_cb server_pool_callback;

static refcnt_discard_content_fn discard_server_pool_help_request_content;

/*
 * The job structure
 *
 * Pluto is an event-driven transaction system.  Each transaction must
 * take a very small slice of time.  Those that cannot, must be broken
 * into multiple transactions and the state carried between them
 * cannot be on the stack or in simple global variables.
 *
 * A job is used to hold such state.
 */

struct help_request {
	struct refcnt refcnt;
	bool cancelled;
	struct msg_digest *md;
	so_serial_t callback_so;	/* state to notify when crypto
					 * completed; for IKEv2 this
					 * is the IKE SA */
	where_t where;
	struct cpu_usage time_used;

	unsigned task_nr;
	so_serial_t task_so;		/* state requiring crypto; for
					 * IKEv2 this is either IKE or
					 * Child SA */
	struct task *task;
	const struct task_handler *handler;
	struct logger *task_logger;
};

/* .task_logger will add the #state prefix */
#define PRI_REQUEST "task %u, %s for %s()"
#define pri_request(REQUEST)			\
	(REQUEST)->task_nr,			\
		(REQUEST)->handler->name,	\
		(REQUEST)->where->func

void discard_server_pool_help_request_content(void *pointer,
					      const struct logger *owner UNUSED,
					      where_t where)
{
	struct help_request *request = pointer;
	ldbg(request->task_logger,
	     PRI_REQUEST": discarding request content "PRI_WHERE,
	     pri_request(request), pri_where(where));

	md_delref(&request->md);
	passert(request->handler->cleanup_cb != NULL);
	request->handler->cleanup_cb(&request->task, request->task_logger);
	pexpect(request->task == NULL); /* did your job */
	/* now free up the continuation */
	free_logger(&request->task_logger, HERE);
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
	if (task_sa->st_offloaded_task != NULL) {
		llog_pexpect(task_sa->logger, where,
			     "state already has outstanding crypto %p",
			     task_sa->st_offloaded_task);
		return;
	}

	struct help_request *request = alloc_help_request("crypto",
							  &discard_server_pool_help_request_content,
							  task_sa->logger);
	static unsigned task_nr;
	request->where = where;
	request->md = md_addref(md);
	request->callback_so = callback_sa->st_serialno;
	request->handler = handler;
	request->task = task;
	request->task_nr = ++task_nr;
	request->task_so = task_sa->st_serialno;
	request->task_logger = clone_logger(task_sa->logger, HERE);
	task_sa->st_offloaded_task = refcnt_addref(request, task_sa->logger, HERE);

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
		ldbg(task_sa->logger, PRI_REQUEST": scheduling crtpto-timeout of callback sa "PRI_SO,
		     pri_request(request), pri_so(callback_sa->st_serialno));
		delete_v1_event(callback_sa);
		event_schedule(EVENT_v1_CRYPTO_TIMEOUT, EVENT_CRYPTO_TIMEOUT_DELAY, callback_sa);
	}

	deltatime_t delay = deltatime(0);
	if (nhelpers() == 0) {
		if (impair.helper_thread_delay.enabled) {
			if (impair.helper_thread_delay.value == 0) {
				static uint64_t warp = 0;
				delay = deltatime(++warp);
				llog(IMPAIR_STREAM, task_sa->logger,
				     PRI_REQUEST": helper is warped by %ju seconds",
				     pri_request(request), warp);
			} else {
				delay = deltatime(impair.helper_thread_delay.value);
				llog(IMPAIR_STREAM, task_sa->logger,
				     PRI_REQUEST": helper is pausing for %ju seconds",
				     pri_request(request), deltasecs(delay));
			}
		}
	}

	/*
	 * Do the detach after the IMPAIR log so the impair appears on
	 * the console.
	 */
	if (detach_whack) {
		whack_detach_where(request->task_logger, task_sa->logger, HERE);
	}

	/*
	 * Stall the crypto without locking up the event queue (which
	 * is what sleep() will do).
	 */

	if (deltatime_cmp(delay, >, deltatime(0))) {
		schedule_callback("delayed crypto", delay,
				  SOS_NOBODY,
				  delayed_help_request,
				  request,
				  task_sa->logger);
		return;
	}

	request_help(request, server_pool_helper, task_sa->logger);
}

void delayed_help_request(const char *story UNUSED,
			  struct state *st,
			  void *context)
{
	struct help_request *request = context;
	PEXPECT(request->task_logger, st == NULL);
	request_help(request, server_pool_helper, request->task_logger);
}

helper_cb *server_pool_helper(struct help_request *request,
			      struct verbose verbose, /*task*/
			      enum helper_id helper_id)
{
	/* might be cancelled */
	if (nhelpers() > 0) {
		if (impair.helper_thread_delay.enabled) {
			llog(IMPAIR_STREAM, verbose.logger,
			     PRI_REQUEST": helper is pausing for %u seconds",
			     pri_request(request), impair.helper_thread_delay.value);
			sleep(impair.helper_thread_delay.value);
		}
	}

	if (request->cancelled) {
		/*
		 * Callback must be called so that state can be
		 * cleaned up.
		 */
		return server_pool_callback;
	}

	vtime_t start = vdbg_start("%d", helper_id);
	request->handler->computer_fn(request->task_logger, request->task, helper_id);
	request->time_used = vdbg_stop(&start, "%d", helper_id);

	return server_pool_callback;
}

void delete_cryptographic_continuation(struct state *st)
{
	passert(in_main_thread());
	passert(st->st_serialno != SOS_NOBODY);
	struct help_request *request = st->st_offloaded_task;
	if (request == NULL) {
		return;
	}
	pmemory(request);
	/* shut it down */
	request->cancelled = true;
	refcnt_delref(&st->st_offloaded_task, st->logger, HERE);
}

void server_pool_callback(struct help_request *request,
			  struct verbose verbose/*task*/)
{
	struct state *callback_sa = state_by_serialno(request->callback_so);
	if (callback_sa == NULL) {
		vdbg(PRI_REQUEST": callback sa "PRI_SO" disappeared",
		     pri_request(request),
		     pri_so(request->callback_so));
		/* Cancelling is part of deleting the SA. */
		vexpect(request->cancelled);
		return;
	}

	struct state *task_sa = state_by_serialno(request->task_so);
	if (task_sa == NULL) {
		/* oops, the task state disappeared! */
		llog_pexpect(verbose.logger, HERE,
			     PRI_REQUEST": task sa disappeared",
			     pri_request(request));
		vexpect(request->cancelled);
		return;
	}

	if (request->cancelled) {
		vdbg(PRI_REQUEST": request cancelled", pri_request(request));
		vexpect(task_sa->st_offloaded_task == NULL);
		return;
	}

	if (task_sa->st_offloaded_task != request) {
		llog_pexpect(verbose.logger, HERE,
			     PRI_REQUEST": .st_offloaded_task @%p does not match request @%p",
			     pri_request(request),
			     task_sa->st_offloaded_task,
			     request);
		/* probably bad! */
		return;
	}

	refcnt_delref(&task_sa->st_offloaded_task, verbose.logger, HERE);

	/* add the helper's time to the bill */
	cpu_usage_add(task_sa->st_timing.helper_usage, request->time_used);

	statetime_t start = statetime_start(callback_sa);
	{
		/* run the callback */
		vassert(request->handler != NULL);
		vassert(request->handler->completed_cb != NULL);
		stf_status status = request->handler->completed_cb(callback_sa, request->md, request->task);
		if (status == STF_SKIP_COMPLETE_STATE_TRANSITION) {
			/* ST may have been freed! */
			vdbg(PRI_REQUEST": resume suppressed by complete_state_transition()",
			     pri_request(request));
		} else {
			complete_state_transition(callback_sa, request->md, status);
		}

	}
	statetime_stop(&start, "resume");
}
