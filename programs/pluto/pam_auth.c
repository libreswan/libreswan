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

struct pam_auth {
	so_serial_t serialno;
	struct pam_thread_arg ptarg;
	monotime_t start_time;
	pam_auth_callback_fn *callback;
	pid_t child;
	const char *aborted;
};

static void pam_auth_free(struct pam_auth **p)
{
	struct pam_auth *x = *p;
	*p = NULL;
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
void pam_auth_abort(struct state *st, const char *story)
{
	struct pam_auth *pamauth = st->st_pam_auth;

	if (pamauth == NULL) {
		pexpect_fail(st->st_logger, HERE,
			     "PAM: %s while authenticating yet no PAM process to abort",
			     story);
		return;
	}

	pstats_pamauth_aborted++;
	passert(pamauth->serialno == st->st_serialno);
	pamauth->aborted = story;
	dbg("PAM: #%lu: %s while authenticating '%s'; aborting PAM",
	    pamauth->serialno, story, pamauth->ptarg.name);

	/*
	 * Don't hold back.
	 *
	 * XXX: need to fix child so that more friendly SIGTERM is
	 * handled - currently the forked process has it blocked by
	 * libevent.
	 */
	kill(pamauth->child, SIGKILL);
	/*
	 * PAMAUTH is deleted by pam_auth_callback() _after_ the
	 * process exits and the callback has been called.
	 *
	 * Free ST of any responsibility for releasing .st_pam_auth
	 * (the fork handler will do that later).
	 */
	st->st_pam_auth = NULL; /* aborted */

}

/*
 * This is the callback from server_fork() when the process dies.
 *
 * On the main thread; notify the state (if it is present) of the
 * pamauth result, and then release everything.
 */

static server_fork_cb pam_callback; /* type assertion */

static stf_status pam_callback(struct state *st,
			       struct msg_digest *md,
			       int status, void *arg,
			       struct logger *logger)
{
	struct pam_auth *pamauth = arg;

	pstats_pamauth_stopped++;

	bool success = (pamauth->aborted == NULL &&
			WIFEXITED(status) &&
			WEXITSTATUS(status) == 0);

	LLOG_JAMBUF(RC_LOG, logger, buf) {
		jam(buf, "PAM: authentication of user '%s' ", pamauth->ptarg.name);
		if (success) {
			jam(buf, "SUCCEEDED");
		} else if (pamauth->aborted == NULL) {
			jam(buf, "FAILED");
		} else {
			jam(buf, "ABORTED (%s)", pamauth->aborted);
		}
		jam(buf, " after ");
		jam_deltatime(buf, monotimediff(mononow(), pamauth->start_time));
		jam(buf, " seconds");
	}

	/*
	 * If there is still a state, notify it.  Since this is
	 * running on the main thread, it and pam_auth_abort() can't
	 * get into a race.
	 */

	stf_status ret = STF_OK;
	if (st != NULL) {
		st->st_pam_auth = NULL; /* all done */
		ret = pamauth->callback(st, md, pamauth->ptarg.name, success);
	}

	pam_auth_free(&pamauth);
	return ret;
}

/*
 * Perform the authentication in the child process.
 */
static int pam_child(void *arg, struct logger *logger)
{
	struct pam_auth *pamauth = arg;

	dbg("PAM: #%lu: PAM-process authenticating user '%s'",
	    pamauth->serialno,
	    pamauth->ptarg.name);
	bool success = do_pam_authentication(&pamauth->ptarg, logger);
	dbg("PAM: #%lu: PAM-process completed for user '%s' with result %s",
	    pamauth->serialno, pamauth->ptarg.name,
	    success ? "SUCCESS" : "FAILURE");
	return success ? 0 : 1;
}

bool pam_auth_fork_request(struct state *st,
			   const char *name,
			   const char *password,
			   const char *atype,
			   pam_auth_callback_fn *callback)
{
	so_serial_t serialno = st->st_serialno;

	/* now start the pamauth child process */

	struct pam_auth *pamauth = alloc_thing(struct pam_auth, "pamauth arg");

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
		log_state(RC_LOG, st,
			  "PAM: creation of PAM authentication process for user '%s' failed",
			  pamauth->ptarg.name);
		pam_auth_free(&pamauth);
		return false;
	}

	st->st_pam_auth = pamauth;
	pstats_pamauth_started++;
	return true;
}
