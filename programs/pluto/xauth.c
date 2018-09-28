/* XAUTH PAM handling
 *
 * Copyright (C) 2017 Andrew Cagney
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
 */

#include <stdlib.h>
#include <sys/wait.h>		/* for WIFEXITED() et.al. */

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
#include "demux.h"
#include "deltatime.h"
#include "monotime.h"

/* information for tracking xauth PAM work in flight */

struct xauth {
	so_serial_t serialno;
	struct pam_thread_arg ptarg;
	monotime_t start_time;
	xauth_callback_t *callback;
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
void xauth_pam_abort(struct state *st)
{
	struct xauth *xauth = st->st_xauth;

	if (xauth == NULL) {
		PEXPECT_LOG("PAM: #%lu: main-process: no process to abort (already aborted?)",
			    st->st_serialno);
	} else {
		st->st_xauth = NULL; /* aborted */
		pstats_xauth_aborted++;
		passert(xauth->serialno == st->st_serialno);
		libreswan_log("PAM: #%lu: main-process: aborting authentication PAM-process for '%s'",
			      st->st_serialno, xauth->ptarg.name);
		/*
		 * Don't hold back.
		 *
		 * XXX: need to fix child so that more friendly
		 * SIGTERM is handled - currently the forked process
		 * has it blocked by libvent.
		 */
		kill(xauth->child, SIGKILL);
		/*
		 * xauth is deleted by xauth_pam_callback() _after_
		 * the process exits and the callback has been called.
		 */
	}
}

/*
 * This is the callback from pluto_fork when the process dies.
 * On the main thread; notify the state (if it is present) of the
 * xauth result, and then release everything.
 */

static pluto_fork_cb pam_callback; /* type assertion */

static void pam_callback(struct state *st,
			 struct msg_digest **mdp,
			 int status, void *arg)
{
	struct xauth *xauth = arg;

	pstats_xauth_stopped++;

	bool success = WIFEXITED(status) && WEXITSTATUS(status) == 0;
	LSWDBGP(DBG_XAUTH, buf) {
		lswlogf(buf, "PAM: #%lu: main-process cleaning up PAM-process for user '%s' result %s time elapsed ",
			xauth->serialno,
			xauth->ptarg.name,
			success ? "SUCCESS" : "FAILURE");
		lswlog_deltatime(buf, monotimediff(mononow(), xauth->start_time));
		if (st == NULL) {
			lswlogs(buf, " (state deleted)");
		} else if (st->st_xauth == NULL) {
			lswlogs(buf, " (aborted)");
		}
	}

	/*
	 * Try to find the corresponding state.
	 *
	 * Since this is running on the main thread, it and
	 * Xauth_abort() can't get into a race.
	 */
	if (st != NULL) {
		st->st_xauth = NULL; /* all done */
		libreswan_log("PAM: #%lu: completed for user '%s' with status %s",
			      xauth->serialno, xauth->ptarg.name,
			      success ? "SUCCESSS" : "FAILURE");
		xauth->callback(st, mdp, xauth->ptarg.name, success);
	}

	pfree_xauth(xauth);
}

/*
 * Perform the authentication in the child process.
 */
static int pam_child(void *arg)
{
	struct xauth *xauth = arg;

	DBG(DBG_XAUTH,
	    DBG_log("PAM: #%lu: PAM-process authenticating user '%s'",
		    xauth->serialno,
		    xauth->ptarg.name));
	bool success = do_pam_authentication(&xauth->ptarg);
	DBG(DBG_XAUTH,
	    DBG_log("PAM: #%lu: PAM-process completed for user '%s' with result %s",
		    xauth->serialno, xauth->ptarg.name,
		    success ? "SUCCESS" : "FAILURE"));
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

	struct xauth *xauth = alloc_thing(struct xauth, "xauth arg");

	xauth->callback = callback;
	xauth->serialno = serialno;
	xauth->start_time = mononow();

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
	    DBG_log("PAM: #%lu: main-process starting PAM-process for authenticating user '%s'",
		    xauth->serialno, xauth->ptarg.name));
	xauth->child = pluto_fork("xauth", xauth->serialno,
				  pam_child, pam_callback, xauth);
	if (xauth->child < 0) {
		libreswan_log("PAM: #%lu: creation of PAM-process for user '%s' failed",
			      xauth->serialno, xauth->ptarg.name);
		pfree_xauth(xauth);
		return;
	}

	st->st_xauth = xauth;
	pstats_xauth_started++;
}
