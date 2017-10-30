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
#include "log.h"

#include "defs.h"
#include "xauth.h"
#include "pam_conv.h"
#include "event.h"
#include "state.h"
#include "server.h"
#include "id.h"
#include "pluto_stats.h"
#include "log.h"

pthread_t main_thread;

struct xauth {
	const char *method;
	so_serial_t serialno;
	void *arg;
	char *name;
	struct timeval tv0;
	bool (*authenticate)(void *arg);
	void (*callback)(struct state *st, const char *name,
			 bool aborted, bool success);
	void (*cleanup)(void *arg);
	bool abort;
	pid_t child;
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
	passert(xauthp != NULL);
	struct xauth *xauth = *xauthp;
	*xauthp = NULL;

	if (xauth == NULL) {
		PEXPECT_LOG("XAUTH: #%lu: main-process: no thread to abort (already aborted?)",
			    serialno);
	} else {
		pstats_xauth_aborted++;
		passert(!xauth->abort);
		passert(xauth->serialno == serialno);
		libreswan_log("XAUTH: #%lu: main-process: aborting authentication %s-process for '%s'",
			      serialno, xauth->method, xauth->name);
		xauth->abort = true;
		/*
		 * Don't hold back.
		 *
		 * XXX: need to fix child so that more friendly
		 * SIGTERM is handled - currently the forked process
		 * has it blocked by libvent.
		 */
		kill(xauth->child, SIGKILL);
		if (st_callback != NULL) {
			DBG(DBG_CONTROL,
			    DBG_log("XAUTH: #%lu: main-process: notifying callback for user '%s'",
				    serialno, xauth->name));
			xauth->callback(st_callback, xauth->name, true, false);
		}
	}
}

/*
 * On the main thread; notify the state (if it is present) of the
 * xauth result, and then release everything.
 */
static void xauth_cleanup(int status, void *arg)
{
	pstats_xauth_stopped++;

	struct xauth *xauth = arg;
	bool success = WIFEXITED(status) && WEXITSTATUS(status) == 0;

	DBG(DBG_CONTROL, {
			struct timeval tv1;
			unsigned long tv_diff;

			gettimeofday(&tv1, NULL);
			tv_diff = (tv1.tv_sec  - xauth->tv0.tv_sec) * 1000000 +
				  (tv1.tv_usec - xauth->tv0.tv_usec);
			DBG_log("XAUTH: #%lu: main-process cleaning up %s-process for user '%s' result %s time elapsed %ld usec%s.",
				xauth->serialno,
				xauth->method, xauth->name,
				success ? "SUCCESS" : "FAILURE",
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
		set_cur_state(st);
		libreswan_log("XAUTH: #%lu: completed for user '%s' with status %s",
			      xauth->serialno, xauth->name,
			      success ? "SUCCESSS" : "FAILURE");
		xauth->callback(st, xauth->name, false, success);
		reset_cur_state();
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
static int xauth_child(void *arg)
{
	struct xauth *xauth = arg;

	DBG(DBG_CONTROLMORE,
	    DBG_log("XAUTH: #%lu: %s-process authenticating user '%s'",
		    xauth->serialno, xauth->method,
		    xauth->name));
	bool success = xauth->authenticate(xauth->arg);

	/*
	 * Schedule xauth_cleanup_callback() to run on the main
	 * thread, and then let this thread die.
	 *
	 * Given xauth->abort is volatile and updated by the main
	 * thread, logging it here is just a hint.
	 */
	libreswan_log("XAUTH: #%lu: %s-process completed for user '%s' with result %s%s",
		      xauth->serialno, xauth->method, xauth->name,
		      success ? "SUCCESS" : "FAILURE",
		      xauth->abort ? " ABORTED" : "");
	return success ? 0 : 1;
}

static struct xauth *xauth_alloc(const char *method,
				 const char *name,
				 so_serial_t serialno,
				 void *arg,
				 bool (*authenticate)(void *arg),
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
	xauth->serialno = serialno;
	xauth->authenticate = authenticate;
	xauth->cleanup = cleanup;
	xauth->callback = callback;
	gettimeofday(&xauth->tv0, NULL);
	return xauth;
}

static void xauth_start_child(struct xauth **xauthp,
			      const char *method,
			      const char *name,
			      so_serial_t serialno,
			      void *arg,
			      bool (*authenticate)(void *arg),
			      void (*cleanup)(void *arg),
			      void (*callback)(struct state *st,
					       const char *name,
					       bool aborted,
					       bool success))
{
	passert(pthread_equal(main_thread, pthread_self()));

	struct xauth *xauth = xauth_alloc(method, name, serialno, arg,
					  authenticate, cleanup, callback);

	DBG(DBG_CONTROLMORE,
	    DBG_log("XAUTH: #%lu: main-process starting %s-process for authenticating user '%s'",
		    xauth->serialno, xauth->method, xauth->name));
	xauth->child = pluto_fork(xauth_child, xauth_cleanup, xauth);
	if (xauth->child < 0) {
		libreswan_log("XAUTH: #%lu: creation of %s-process for user '%s' failed",
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

	return xauth_start_child(xauthp, "PAM", name, serialno, pam,
				 xauth_pam_thread,
				 xauth_pam_cleanup, callback);
}

#endif
