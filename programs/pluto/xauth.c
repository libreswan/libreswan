/* XAUTH PAM handling
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

#ifdef XAUTH_HAVE_PAM

#include <pthread.h> /* Must be the first include file */

#include <stdlib.h>

#include "constants.h"
#include "lswlog.h"
#include "defs.h"
#include "log.h"
#include "xauth.h"
#include "pam_conv.h"
#include "event.h"
#include "state.h"
#include "connections.h"
#include "server.h"
#include "id.h"
#include "pluto_stats.h"
#include "log.h"
#include "ip_address.h"

/* information for tracking xauth PAM work in flight */

struct xauth {
	so_serial_t serialno;
	struct pam_thread_arg ptarg;
	struct timeval tv0;
	xauth_callback_t *callback;
	bool abort;
	pid_t child;
};

static void pfree_xauth(struct xauth *x)
{
	pfree(x->ptarg.name);
	pfree(x->ptarg.password);
	pfree(x->ptarg.c_name);
	pfree(x->ptarg.ra);

	pfree(x);
}

/*
 * Abort the transaction, disconnecting it from state.
 *
 * Need to pass in serialno so that something sane can be logged when
 * the xauth request has already been deleted.  Need to pass in
 * st_callback, but only when it needs to notify an abort.
 */
void xauth_pam_abort(struct state *st, bool call_callback)
{
	struct xauth *xauth = st->st_xauth;

	if (xauth == NULL) {
		PEXPECT_LOG("XAUTH: #%lu: main-process: no thread to abort (already aborted?)",
			    st->st_serialno);
	} else {
		st->st_xauth = NULL;
		pstats_xauth_aborted++;
		passert(!xauth->abort);
		passert(xauth->serialno == st->st_serialno);
		libreswan_log("XAUTH: #%lu: main-process: aborting authentication PAM-process for '%s'",
			      st->st_serialno, xauth->ptarg.name);
		xauth->abort = true;
		/*
		 * Don't hold back.
		 *
		 * XXX: need to fix child so that more friendly
		 * SIGTERM is handled - currently the forked process
		 * has it blocked by libvent.
		 */
		kill(xauth->child, SIGKILL);
		if (call_callback) {
			DBG(DBG_XAUTH,
			    DBG_log("XAUTH: #%lu: main-process: notifying callback for user '%s'",
				    st->st_serialno, xauth->ptarg.name));
			xauth->callback(st, xauth->ptarg.name, false);
		} else {
			pfree_xauth(xauth);
		}
	}
}

/*
 * This is the callback from pluto_fork when the process dies.
 * On the main thread; notify the state (if it is present) of the
 * xauth result, and then release everything.
 */
static void xauth_pam_child_cleanup(int status, void *arg)
{
	struct xauth *xauth = arg;

	pstats_xauth_stopped++;

	bool success = WIFEXITED(status) && WEXITSTATUS(status) == 0;

	DBG(DBG_XAUTH, {
			struct timeval tv1;
			unsigned long tv_diff;

			gettimeofday(&tv1, NULL);
			tv_diff = (tv1.tv_sec  - xauth->tv0.tv_sec) * 1000000 +
				  (tv1.tv_usec - xauth->tv0.tv_usec);
			DBG_log("XAUTH: #%lu: main-process cleaning up PAM-process for user '%s' result %s time elapsed %ld usec%s.",
				xauth->serialno,
				xauth->ptarg.name,
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
			      xauth->serialno, xauth->ptarg.name);
	} else {
		struct state *st = state_with_serialno(xauth->serialno);
		passert(st != NULL);
		st->st_xauth = NULL; /* all done */
		so_serial_t old_state = push_cur_state(st);
		libreswan_log("XAUTH: #%lu: completed for user '%s' with status %s",
			      xauth->serialno, xauth->ptarg.name,
			      success ? "SUCCESSS" : "FAILURE");
		xauth->callback(st, xauth->ptarg.name, success);
		pop_cur_state(old_state);
	}

	pfree_xauth(xauth);
}

static bool xauth_pam_thread(void *arg)
{
	return do_pam_authentication((struct pam_thread_arg*)arg);
}

/*
 * First create a cleanup (it will transfer control to the main thread
 * and that will do the real cleanup); and then perform the
 * authorization.
 */
static int xauth_child(void *arg)
{
	struct xauth *xauth = arg;

	DBG(DBG_XAUTH,
	    DBG_log("XAUTH: #%lu: PAM-process authenticating user '%s'",
		    xauth->serialno,
		    xauth->ptarg.name));
	bool success = xauth_pam_thread(&xauth->ptarg);
	DBG(DBG_XAUTH,
	    DBG_log("XAUTH: #%lu: PAM-process completed for user '%s' with result %s%s",
		    xauth->serialno, xauth->ptarg.name,
		    success ? "SUCCESS" : "FAILURE",
		    xauth->abort ? " ABORTED" : ""));
	return success ? 0 : 1;
}

void xauth_start_pam_thread(struct state *st,
			    const char *name,
			    const char *password,
			    const char *atype,
			    xauth_callback_t *callback)
{
	so_serial_t serialno = st->st_serialno;

	/* now start the xauth child process */

	passert(pthread_equal(main_thread, pthread_self()));

	struct xauth *xauth = alloc_thing(struct xauth, "xauth arg");

	xauth->callback = callback;
	xauth->serialno = serialno;
	gettimeofday(&xauth->tv0, NULL);

	/* fill in pam_thread_arg with info for the child process */

	xauth->ptarg.name = clone_str(name, "pam name");

	xauth->ptarg.password = clone_str(password, "pam password");
	xauth->ptarg.c_name = clone_str(st->st_connection->name, "pam connection name");

	ipstr_buf ra;
	xauth->ptarg.ra = clone_str(ipstr(&st->st_remoteaddr, &ra), "pam remoteaddr");
	xauth->ptarg.st_serialno = serialno;
	xauth->ptarg.c_instance_serial = st->st_connection->instance_serial;
	xauth->ptarg.atype = atype;

	DBG(DBG_XAUTH,
	    DBG_log("XAUTH: #%lu: main-process starting PAM-process for authenticating user '%s'",
		    xauth->serialno, xauth->ptarg.name));
	xauth->child = pluto_fork(xauth_child, xauth_pam_child_cleanup, xauth);
	if (xauth->child < 0) {
		libreswan_log("XAUTH: #%lu: creation of PAM-process for user '%s' failed",
			      xauth->serialno, xauth->ptarg.name);
		pfree_xauth(xauth);
		return;
	}

	st->st_xauth = xauth;
	pstats_xauth_started++;
}

#endif
