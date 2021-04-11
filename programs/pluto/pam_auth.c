/* AUTH PAM handling
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
#include <signal.h>		/* for kill() and signals in general */

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "pam_auth.h"
#include "pam_conv.h"
#include "event.h"
#include "state.h"
#include "connections.h"
#include "id.h"
#include "pluto_stats.h"
#include "log.h"
#include "ip_address.h"
#include "demux.h"
#include "deltatime.h"
#include "monotime.h"
#include "server_fork.h"

/* information for tracking pamauth PAM work in flight */

struct pamauth {
	so_serial_t serialno;
	struct pam_thread_arg ptarg;
	monotime_t start_time;
	pamauth_callback_t *callback;
	pid_t child;
};

static void pfree_pamauth(struct pamauth *x)
{
	pfree(x->ptarg.name);
	pfree(x->ptarg.password);
	pfree(x->ptarg.c_name);
	pfree(x);
}

/*
 * Abort the transaction, disconnecting it from state.
 *
 * Need to pass in serialno so that something sane can be logged when
 * the pamauth request has already been deleted.  Need to pass in
 * st_callback, but only when it needs to notify an abort.
 */
void pamauth_abort(struct state *st)
{
	struct pamauth *pamauth = st->st_pamauth;

	if (pamauth == NULL) {
		pexpect_fail(st->st_logger, HERE,
			     "PAM: #%lu: main-process: no process to abort (already aborted?)",
			     st->st_serialno);
	} else {
		st->st_pamauth = NULL; /* aborted */
		pstats_pamauth_aborted++;
		passert(pamauth->serialno == st->st_serialno);
		log_state(RC_LOG, st, "PAM: #%lu: main-process: aborting authentication PAM-process for '%s'",
			      st->st_serialno, pamauth->ptarg.name);
		/*
		 * Don't hold back.
		 *
		 * XXX: need to fix child so that more friendly
		 * SIGTERM is handled - currently the forked process
		 * has it blocked by libvent.
		 */
		kill(pamauth->child, SIGKILL);
		/*
		 * pamauth is deleted by pamauth_pam_callback() _after_
		 * the process exits and the callback has been called.
		 */
	}
}

/*
 * This is the callback from server_fork() when the process dies.
 *
 * On the main thread; notify the state (if it is present) of the
 * pamauth result, and then release everything.
 */

static server_fork_cb pam_callback; /* type assertion */

static void pam_callback(struct state *st,
			 struct msg_digest *md,
			 int status, void *arg,
			 struct logger *logger)
{
	struct pamauth *pamauth = arg;

	pstats_pamauth_stopped++;

	bool success = WIFEXITED(status) && WEXITSTATUS(status) == 0;
	deltatime_buf db;
	dbg("PAM: #%lu: main-process cleaning up PAM-process for user '%s' result %s time elapsed %s seconds%s",
	    pamauth->serialno,
	    pamauth->ptarg.name,
	    success ? "SUCCESS" : "FAILURE",
	    str_deltatime(monotimediff(mononow(), pamauth->start_time), &db),
	    (st == NULL ? " (state deleted)" :
	     st->st_pamauth == NULL ? " (aborted)" :
	     ""));

	/*
	 * Try to find the corresponding state.
	 *
	 * Since this is running on the main thread, it and
	 * Xauth_abort() can't get into a race.
	 */
	if (st != NULL) {
		st->st_pamauth = NULL; /* all done */
		llog(RC_LOG, logger,
			    "PAM: #%lu: completed for user '%s' with status %s",
			    pamauth->serialno, pamauth->ptarg.name,
			    success ? "SUCCESS" : "FAILURE");
		pamauth->callback(st, md, pamauth->ptarg.name, success);
	}

	pfree_pamauth(pamauth);
}

/*
 * Perform the authentication in the child process.
 */
static int pam_child(void *arg, struct logger *logger)
{
	struct pamauth *pamauth = arg;

	dbg("PAM: #%lu: PAM-process authenticating user '%s'",
	    pamauth->serialno,
	    pamauth->ptarg.name);
	bool success = do_pam_authentication(&pamauth->ptarg, logger);
	dbg("PAM: #%lu: PAM-process completed for user '%s' with result %s",
	    pamauth->serialno, pamauth->ptarg.name,
	    success ? "SUCCESS" : "FAILURE");
	return success ? 0 : 1;
}

void auth_fork_pam_process(struct state *st,
			     const char *name,
			     const char *password,
			     const char *atype,
			     pamauth_callback_t *callback)
{
	so_serial_t serialno = st->st_serialno;

	/* now start the pamauth child process */

	struct pamauth *pamauth = alloc_thing(struct pamauth, "pamauth arg");

	pamauth->callback = callback;
	pamauth->serialno = serialno;
	pamauth->start_time = mononow();

	/* fill in pam_thread_arg with info for the child process */

	pamauth->ptarg.name = clone_str(name, "pam name");

	pamauth->ptarg.password = clone_str(password, "pam password");
	pamauth->ptarg.c_name = clone_str(st->st_connection->name, "pam connection name");
	pamauth->ptarg.rhost = endpoint_address(st->st_remote_endpoint);
	pamauth->ptarg.st_serialno = serialno;
	pamauth->ptarg.c_instance_serial = st->st_connection->instance_serial;
	pamauth->ptarg.atype = atype;

	dbg("PAM: #%lu: main-process starting PAM-process for authenticating user '%s'",
	    pamauth->serialno, pamauth->ptarg.name);
	pamauth->child = server_fork("pamauth", pamauth->serialno,
				     pam_child, pam_callback, pamauth,
				     st->st_logger);
	if (pamauth->child < 0) {
		log_state(RC_LOG, st, "PAM: #%lu: creation of PAM-process for user '%s' failed",
			      pamauth->serialno, pamauth->ptarg.name);
		pfree_pamauth(pamauth);
		return;
	}

	st->st_pamauth = pamauth;
	pstats_pamauth_started++;
}
