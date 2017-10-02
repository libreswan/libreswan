/* XAUTH handling, for libreswan.
 *
 * Copyright (C) 2017 Andrew Cagney
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
 */

#include <pthread.h> /* Must be the first include file */

#include <stdlib.h>

#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "xauth.h"
#include "pam_conv.h"
#include "event.h"
#include "state.h"
#include "server.h"
#include "id.h"
#include "pluto_stats.h"

pthread_t main_thread;

struct xauth {
	const char *method;
	so_serial_t serialno;
	void *arg;
	char *name;
	struct timeval tv0;
	bool (*authenticate)(void *arg, volatile bool *abort);
	void (*cleanup)(void *arg);
	void (*callback)(struct state *st, const char *name,
			 bool aborted, bool success);
	bool success;
	volatile bool abort;
	pthread_t thread;
};

/*
 * Abort the transaction, disconnecting it from state.
 *
 * Need to pass in serialno so that something sane can be logged when
 * the xauth request has already been deleted.  Need to pass in
 * st_callback, but only when it needs to notify an abort.
 */
void xauth_abort(so_serial_t serialno, struct xauth **xauthp,
		 struct state *st_callback)
{
	passert(pthread_equal(main_thread, pthread_self()));

	passert(xauthp != NULL);
	struct xauth *xauth = *xauthp;
	*xauthp = NULL;

	if (xauth == NULL) {
		PEXPECT_LOG("XAUTH: #%lu: main-thread: no thread to abort (already aborted?)",
			    serialno);
	} else {
		pstats_xauth_aborted++;
		passert(!xauth->abort);
		passert(xauth->serialno == serialno);
		libreswan_log("XAUTH: #%lu: main-thread: aborting authentication %s-thread for '%s'",
			      serialno, xauth->method, xauth->name);
		xauth->abort = true;
		if (st_callback != NULL) {
			DBG(DBG_CONTROL,
			    DBG_log("XAUTH: #%lu: main-thread: notifying callback for user '%s'",
				    serialno, xauth->name));
			xauth->callback(st_callback, xauth->name, true, false);
		}
	}
}

/*
 * On the main thread; notify the state (if it is present) of the
 * xauth result, and then release everything.
 */
static void xauth_cleanup_callback(evutil_socket_t socket UNUSED,
				   const short event UNUSED,
				   void *arg)
{
	pstats_xauth_stopped++;
	passert(pthread_equal(main_thread, pthread_self()));

	struct xauth *xauth = arg;
	DBG(DBG_CONTROL, {
			struct timeval tv1;
			unsigned long tv_diff;

			gettimeofday(&tv1, NULL);
			tv_diff = (tv1.tv_sec  - xauth->tv0.tv_sec) * 1000000 +
				  (tv1.tv_usec - xauth->tv0.tv_usec);
			DBG_log("XAUTH: #%lu: main-thread cleaning up %s-thread for user '%s' result %s time elapsed %ld usec%s.",
				xauth->serialno,
				xauth->method, xauth->name,
				xauth->success ? "SUCCESS" : "FAILURE",
				tv_diff,
				xauth->abort ? " ABORTED" : "");
			});

	/*
	 * Try to find the corresponding state.
	 *
	 * Since this is running on the main thread, it and
	 * Xauth_abort() can't get into a race.
	 */
	if (xauth->abort) {
		/* ST may or may not exist, don't try */
		libreswan_log("XAUTH: #%lu: aborted for user '%s'",
			      xauth->serialno, xauth->name);
	} else {
		struct state *st = state_with_serialno(xauth->serialno);
		passert(st != NULL);
		st->st_xauth = NULL; /* all done */
		xauth->callback(st, xauth->name, false, xauth->success);
	}
	xauth->cleanup(xauth->arg);
	pfree(xauth->name);
	pfree(xauth);
}

/*
 * First create a cleanup (it will transfer control to the main thread
 * and that will do the real cleanup); and then perform the
 * authorization.
 */
static void *xauth_thread(void *arg)
{
	struct xauth *xauth = arg;

	passert(!pthread_equal(main_thread, pthread_self()));
	DBG(DBG_CONTROLMORE,
	    DBG_log("XAUTH: #%lu: %s-thread authenticating user '%s'",
		    xauth->serialno, xauth->method,
		    xauth->name));
	xauth->success = xauth->authenticate(xauth->arg, &xauth->abort);

	/*
	 * Schedule xauth_cleanup_callback() to run on the main
	 * thread, and then let this thread die.
	 *
	 * Given xauth->abort is volatile and updated by the main
	 * thread, logging it here is just a hint.
	 */
	DBG(DBG_CONTROLMORE,
	    DBG_log("XAUTH: #%lu: %s-thread queueing cleanup for user '%s' with result %s%s",
		    xauth->serialno, xauth->method, xauth->name,
		    xauth->success ? "SUCCESS" : "FAILURE",
		    xauth->abort ? " ABORTED" : ""));
	const struct timeval delay = { 0, 0 };
	pluto_event_add(NULL_FD, EV_TIMEOUT, xauth_cleanup_callback, arg,
			&delay, "xauth_cleanup_callback");

	return NULL;
}

static struct xauth *xauth_alloc(const char *method,
				 const char *name,
				 so_serial_t serialno,
				 void *arg,
				 bool (*authenticate)(void *arg, volatile bool *abort),
				 void (*cleanup)(void *arg),
				 void (*callback)(struct state *st,
						  const char *name,
						  bool aborted,
						  bool success))
{
	struct xauth *xauth = alloc_thing(struct xauth, "xauth arg");
	xauth->method = method;
	xauth->name = clone_str(name, "xauth name");
	xauth->arg = arg;
	xauth->callback = callback;
	xauth->success = FALSE;
	xauth->serialno = serialno;
	xauth->authenticate = authenticate;
	xauth->cleanup = cleanup;
	xauth->callback = callback;
	gettimeofday(&xauth->tv0, NULL);
	return xauth;
}

static void xauth_start_thread(struct xauth **xauthp,
			       const char *method,
			       const char *name,
			       so_serial_t serialno,
			       void *arg,
			       bool (*authenticate)(void *arg, volatile bool *abort),
			       void (*cleanup)(void *arg),
			       void (*callback)(struct state *st,
						const char *name,
						bool aborted,
						bool success))
{
	passert(pthread_equal(main_thread, pthread_self()));

	struct xauth *xauth = xauth_alloc(method, name, serialno, arg,
					  authenticate, cleanup, callback);

	pthread_attr_t thread_attr;
	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);

	DBG(DBG_CONTROLMORE,
	    DBG_log("XAUTH: #%lu: main-thread starting %s-thread for authenticating user '%s'",
		    xauth->serialno, xauth->method, xauth->name));
	int error = pthread_create(&xauth->thread, &thread_attr,
				   xauth_thread, xauth);

	pthread_attr_destroy(&thread_attr);

	if (error) {
		LOG_ERRNO(error, "XAUTH: #%lu: creation of %s-thread for user '%s' failed",
			  xauth->serialno, xauth->method, xauth->name);
		*xauthp = NULL;
		pfree(xauth->name);
		pfree(xauth);
		return;
	}
	*xauthp = xauth;
	pstats_xauth_started++;
};

#ifdef XAUTH_HAVE_PAM

static bool xauth_pam_thread(void *arg, volatile bool *abort)
{
	return do_pam_authentication((struct pam_thread_arg*)arg, abort);
}

static void xauth_pam_cleanup(void *arg)
{
	struct pam_thread_arg *pam = arg;
	pfree(pam->name);
	pfree(pam->password);
	pfree(pam->c_name);
	pfree(pam->ra);
	pfree(pam);
}

void xauth_start_pam_thread(struct xauth **xauthp,
			    const char *name,
			    const char *password,
			    const char *connection_name,
			    const ip_address *remoteaddr,
			    so_serial_t serialno,
			    unsigned long instance_serial,
			    const char *atype,
			    void (*callback)(struct state *st,
					     const char *name,
					     bool aborted,
					     bool success))
{
	struct pam_thread_arg *pam = alloc_thing(struct pam_thread_arg, "xauth pam param");

	pam->name = clone_str(name, "pam name");

	pam->password = clone_str(password, "pam password");
	pam->c_name = clone_str(connection_name, "pam connection name");

	ipstr_buf ra;
	pam->ra = clone_str(ipstr(remoteaddr, &ra), "pam remoteaddr");
	pam->st_serialno = serialno;
	pam->c_instance_serial = instance_serial;
	pam->atype = atype;

	return xauth_start_thread(xauthp, "PAM", name, serialno, pam,
				  xauth_pam_thread,
				  xauth_pam_cleanup, callback);
}

#endif

static void cleanup_xauth_now(void *arg UNUSED)
{
}

/*
 * Schedule the XAUTH callback for NOW so it is (hopefully) run next.
 *
 * The callers (both IKEv1) can probably be written to not do this.
 * Later.
 */
void xauth_next(struct xauth **xauthp,
		const char *method, const char *name,
		so_serial_t serialno, bool success,
		void (*callback)(struct state *st,
				 const char *name,
				 bool aborted,
				 bool success))
{
	passert(pthread_equal(main_thread, pthread_self()));
	struct xauth *xauth = xauth_alloc(method, name, serialno,
					  NULL, NULL,
					  cleanup_xauth_now,
					  callback);
	xauth->success = success;
	*xauthp = xauth;
	const struct timeval delay = { 0, 0 };
	pluto_event_add(NULL_FD, EV_TIMEOUT, xauth_cleanup_callback, xauth,
			&delay, "xauth_now_callback");
}
