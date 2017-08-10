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

pthread_t main_thread;

void xauth_cancel(so_serial_t serialno, pthread_t *thread)
{
	passert(pthread_equal(main_thread, pthread_self()));
	if (pthread_equal(*thread, main_thread)) {
		DBG(DBG_CONTROLMORE,
		    DBG_log("XAUTH: #%lu: no thread to cancel", serialno));
	} else {
		libreswan_log("XAUTH: #%lu: cancelling authentication thread",
			      serialno);
		pthread_cancel(*thread);
		*thread = main_thread;
	}
}

struct xauth {
	const char *method;
	so_serial_t serialno;
	void *arg;
	char *name;
	bool (*authenticate)(void *arg);
	void (*cleanup)(void *arg);
	void (*callback)(struct state *st, const char *name, bool success);
	bool success;
};

/*
 * Read this code bottom up!
 */

/*
 * On the main thread; notify the state (if it is present) of the
 * xauth result, and then release everything.
 */
static void xauth_cleanup_callback(evutil_socket_t socket UNUSED,
				   const short event UNUSED,
				   void *arg)
{
	passert(pthread_equal(main_thread, pthread_self()));
	struct xauth *xauth = arg;
	DBG(DBG_CONTROLMORE,
	    DBG_log("XAUTH: #%lu: main-thread cleaning up %s-thread for user '%s' result %s",
		    xauth->serialno, xauth->method, xauth->name,
		    xauth->success ? "SUCCESS" : "FAILURE"));
	/*
	 * Try to find the corresponding state.
	 *
	 * Since this is running on the main thread, it and
	 * xauth_cancel() can't get into a race a state being deleted.
	 */
	struct state *st = state_with_serialno(xauth->serialno);
	if (st == NULL) {
		libreswan_log("XAUTH: #%lu: cancelled for user '%s' - state no longer exists",
			      xauth->serialno, xauth->name);
	} else {
		st->st_xauth_thread = main_thread; /* all done */
		xauth->callback(st, xauth->name, xauth->success);
	}
	xauth->cleanup(xauth->arg);
	pfree(xauth->name);
	pfree(xauth);
}

/*
 * Schedule xauth_cleanup_callback() to run on the main thread, and
 * then let this thread die.
 */
static void xauth_thread_cleanup(void *arg)
{
	passert(!pthread_equal(main_thread, pthread_self()));
	struct xauth *xauth = arg;
	DBG(DBG_CONTROLMORE,
	    DBG_log("XAUTH: #%lu: %s-thread queueing cleanup for user '%s' with result %s",
		    xauth->serialno, xauth->method, xauth->name,
		    xauth->success ? "SUCCESS" : "FAILURE"));
	const struct timeval delay = { 0, 0 };
	pluto_event_new(NULL_FD, EV_TIMEOUT, xauth_cleanup_callback, arg, &delay);
}

/*
 * First create a cleanup (it will transfer control to the main thread
 * and that will do the real cleanup); and then perform the
 * authorization.
 */
static void *xauth_thread(void *arg)
{
	/*
	 * Start with CANCEL disabled so that "I will survive" message
	 * can be logged.  Presumably pthread_setcancelstate(DISABLED)
	 * can't be cancelled?
	 */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

	passert(!pthread_equal(main_thread, pthread_self()));
	struct xauth *xauth = arg;
	DBG(DBG_CONTROLMORE,
	    DBG_log("XAUTH: #%lu: %s-thread authenticating user '%s'",
		    xauth->serialno, xauth->method,
		    xauth->name));

	pthread_cleanup_push(xauth_thread_cleanup, arg);

	/*
	 * Systems go, enable CANCEL and do the authentication.
	 *
	 * The call setcanceltype(DEFERED) is redundant as it should
	 * already be the default.
	 */
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

	xauth->success = xauth->authenticate(xauth->arg);

	/*
	 * Ensure the cleanup function is always runs by disabling
	 * cancel.  Can pthread_cleanup_pop(TRUE) can be canceled
	 * while running the cancel function?
	 */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	pthread_cleanup_pop(TRUE);

	return NULL;
}

static void xauth_start_thread(pthread_t *thread,
			       const char *method,
			       const char *name,
			       so_serial_t serialno,
			       void *arg,
			       bool (*authenticate)(void *arg),
			       void (*cleanup)(void *arg),
			       void (*callback)(struct state *st,
						const char *name,
						bool success))
{
	passert(pthread_equal(main_thread, pthread_self()));
	// set thread to non-cancelable;
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

	/*
	 * For moment don't try to "join" the thread (could do it in
	 * xauth_cleanup_callback()?)
	 */
	pthread_attr_t thread_attr;
	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);

	int error = pthread_create(thread, &thread_attr,
				   xauth_thread, xauth);

	pthread_attr_destroy(&thread_attr);

	if (error) {
		LOG_ERRNO(error, "XAUTH: #%lu: creation of %s-thread for user '%s' failed",
			  xauth->serialno, xauth->method, xauth->name);
		*thread = main_thread;
		return;
	}

	DBG(DBG_CONTROLMORE,
	    DBG_log("XAUTH: #%lu: main-thread started %s-thread for authenticating user '%s'",
		    xauth->serialno, xauth->method, xauth->name));
};

#ifdef XAUTH_HAVE_PAM

static bool xauth_pam_thread(void *arg)
{
	return do_pam_authentication((struct pam_thread_arg*)arg);
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

void xauth_start_pam_thread(pthread_t *thread,
			    const char *name,
			    const char *password,
			    const char *connection_name,
			    const ip_address *remoteaddr,
			    so_serial_t serialno,
			    unsigned long instance_serial,
			    const char *atype,
			    void (*callback)(struct state *st,
					     const char *name,
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

	return xauth_start_thread(thread, "PAM", name, serialno, pam,
				  xauth_pam_thread,
				  xauth_pam_cleanup, callback);
}

#endif

static bool xauth_always_thread(void *arg)
{
	return arg != NULL;
}

static void xauth_always_cleanup(void *arg UNUSED)
{
	return;
}

void xauth_start_always_thread(pthread_t *thread,
			       const char *method, const char *name,
			       so_serial_t serialno, bool success,
			       void (*callback)(struct state *st,
						const char *name,
						bool success))
{
	return xauth_start_thread(thread, method, name, serialno,
				  success ? &main_thread : NULL,
				  xauth_always_thread, xauth_always_cleanup,
				  callback);
}
