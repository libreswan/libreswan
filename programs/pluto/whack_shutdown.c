/* shutdown pluto, for libreswan
 *
 * Copyright (C) 1997      Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009-2016 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2016 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2012 Philippe Vouters <Philippe.Vouters@laposte.net>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2016-2024 Andrew Cagney
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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

#include <unistd.h>		/* for exit(2) */

#include "whack_shutdown.h"

#include "constants.h"
#include "lswnss.h"		/* for lsw_nss_shutdown() */
#include "lswalloc.h"		/* for report_leaks() et.al. */

#include "defs.h"		/* for so_serial_t */
#include "log.h"		/* for close_log() et.al. */

#include "lock_file.h"		/* for delete_lock_file() */
#include "server_pool.h"	/* for stop_crypto_helpers() */
#include "pluto_sd.h"		/* for pluto_sd() */
#include "root_certs.h"		/* for free_root_certs() */
#include "keys.h"		/* for free_preshared_secrets() */
#include "connections.h"
#include "x509_crl.h"		/* for free_crl_queue() */
#include "iface.h"		/* for shutdown_ifaces() */
#include "kernel.h"		/* for kernel_ops.shutdown() and free_kernel() */
#include "virtual_ip.h"		/* for free_virtual_ip() */
#include "server.h"		/* for free_server() */
#include "revival.h"		/* for free_revivals() */
#ifdef USE_DNSSEC
#include "dnssec.h"		/* for unbound_ctx_free() */
#endif
#include "demux.h"		/* for free_demux() */
#include "impair_message.h"	/* for free_impair_message() */
#include "state_db.h"		/* for check_state_db() */
#include "connection_db.h"	/* for check_connection_db() */
#include "ikev2_ike_session_resume.h"	/* for shutdown_ike_session_resume() */
#include "spd_db.h"	/* for check_spd_db() */
#include "server_fork.h"	/* for check_server_fork() */
#include "pending.h"
#include "connection_event.h"
#include "terminate.h"

server_stopped_cb server_stopped_callback NEVER_RETURNS;

volatile bool exiting_pluto = false;
static enum pluto_exit_code pluto_exit_code;
static bool pluto_leave_state;

/*
 * leave pluto, with status.
 * Once child is launched, parent must not exit this way because
 * the lock would be released.
 *
 *  0 OK
 *  1 general discomfort
 * 10 lock file exists
 */

static void exit_prologue(enum pluto_exit_code code, struct logger *logger);
static void exit_epilogue(struct logger *logger) NEVER_RETURNS;
static void server_helpers_stopped_callback(void);

void libreswan_exit(enum pluto_exit_code exit_code)
{
	struct logger *logger = &global_logger;
	exit_prologue(exit_code, logger);
	exit_epilogue(logger);
}

static void exit_prologue(enum pluto_exit_code exit_code, struct logger *logger UNUSED/*sometimes*/)
{
	/*
	 * Tell the world, well actually all the threads, that pluto
	 * is exiting and they should quit.  Even if pthread_cancel()
	 * weren't buggy, using it correctly would be hard, so use
	 * this instead.
	 */
	exiting_pluto = true;
	pluto_exit_code = exit_code;

	/* needed because we may be called in odd state */
 #ifdef USE_SYSTEMD_WATCHDOG
	pluto_sd(PLUTO_SD_STOPPING, exit_code, logger);
 #endif
}

static void delete_every_connection(struct logger *logger)
{
	/*
	 * Keep deleting the oldest connection until there isn't one.
	 *
	 * Picking away at the queue avoids the posability of a
	 * cascading delete deleting the next entry in the list.
	 */
	const struct connection *last = NULL;
	while (true) {
		struct connection_filter cq = {
			.search = {
				.order = OLD2NEW,
				.verbose.logger = logger,
				.where = HERE,
			},
		};
		if (!next_connection(&cq)) {
			break;
		}

		/*
		 * Always going forward, never in reverse.
		 */
		PASSERT(logger, last != cq.c);
		last = cq.c;

		/*
		 * Only expect root connections; the terminate call
		 * wipes out anything else.
		 */

		connection_attach(cq.c, logger);
		PEXPECT(cq.c->logger, (cq.c->local->kind == CK_GROUP ||
				       cq.c->local->kind == CK_PERMANENT ||
				       cq.c->local->kind == CK_TEMPLATE ||
				       cq.c->local->kind == CK_LABELED_TEMPLATE));
		terminate_and_delete_connections(&cq.c, logger, HERE);
	}
}

void exit_epilogue(struct logger *logger)
{
	if (pluto_leave_state) {
		shutdown_nss();
		free_preshared_secrets(logger);
		delete_lock_file();	/* delete any lock files */
		close_log();	/* close the logfiles */
#ifdef USE_SYSTEMD_WATCHDOG
		pluto_sd(PLUTO_SD_EXIT, pluto_exit_code, logger);
#endif
		exit(pluto_exit_code);
	}

	/*
	 * Before ripping everything down; check internal state.
	 */
	state_db_check(logger, HERE);
	connection_db_check(logger, HERE);
	spd_db_check(logger, HERE);
	check_server_fork(logger, HERE); /*pid_entry_db_check()*/

	/*
	 * This wipes out pretty much everything: connections, states,
	 * revivals, ...
	 */
	delete_every_connection(logger);

	free_server_helper_jobs(logger);

	free_root_certs(logger);
	free_preshared_secrets(logger);
	free_remembered_public_keys();
	/*
	 * free memory allocated by initialization routines.  Please don't
	 * forget to do this.
	 */

#if defined(USE_LIBCURL) || defined(USE_LDAP)
	/*
	 * free the crl requests that are waiting to be picked and
	 * processed by the fetch-helper.
	 */
	shutdown_x509_crl_queue(logger);
#endif

	/*
	 * The impair_message code has pointers to to msg_digest
	 * which, in turn has pointers to iface.  Hence it must be
	 * shutdown (and links released) before the interfaces.
	 */
	shutdown_impair_message(logger);

	shutdown_ifaces(logger);	/* free interface list from memory */
	shutdown_kernel(logger);
	shutdown_ike_session_resume(logger); /* before NSS! */
	shutdown_nss();
	delete_lock_file();	/* delete any lock files */
#ifdef USE_DNSSEC
	unbound_ctx_free();	/* needs event-loop aka server */
#endif

	/*
	 * No libevent events beyond this point.
	 */
	free_server(logger);

	free_virtual_ip();	/* virtual_private= */
	free_pluto_main();	/* our static chars */

	/* report memory leaks now, after all free_* calls */
	if (leak_detective) {
		report_leaks(logger);
	}
	close_log();	/* close the logfiles */
#ifdef USE_SYSTEMD_WATCHDOG
	pluto_sd(PLUTO_SD_EXIT, pluto_exit_code, logger);
#endif
	exit(pluto_exit_code);	/* exit, with our error code */
}

void whack_shutdown(struct logger *logger, bool leave_state)
{
	pluto_leave_state = leave_state;
	llog(RC_LOG, logger, "Pluto is shutting down%s", (leave_state ? " (leaving state)" : ""));

	/*
	 * Leak (unlink but don't close aka delref) the currently
	 * attached whackfd.
	 *
	 * Unlinking the whackfd from the logger stops any further log
	 * messages reaching the attached whack (the entire exit
	 * process is radio silent).
	 *
	 * Leaving whackfd open means that whack will remain attached
	 * until pluto exits.
	 *
	 * See also whack_handle_cb() sets whackfd[0] to the current
	 * whack's FD before, indirectly, calling this function.
	 */
	fd_leak(logger->whackfd[0], logger, HERE);

	/*
	 * Start the shutdown process.
	 *
	 * Flag that things are going down and delete anything that
	 * isn't asynchronous (or depends on something asynchronous).
	 */
	exit_prologue(PLUTO_EXIT_OK, logger);

	/*
	 * Wait for the crypto-helper threads to notice EXITING_PLUTO
	 * and exit (if necessary, wake any sleeping helpers from
	 * their slumber).  Without this any helper using NSS after
	 * the code below has shutdown the NSS DB will crash.
	 *
	 * This does not try to delete any tasks left waiting on the
	 * helper queue.  Instead, code further down deleting
	 * connections (which in turn deletes states) should clean
	 * that up?
	 *
	 * This also does not try to delete any completed tasks
	 * waiting on the event loop.  One theory is for the helper
	 * code to be changed so that helper tasks can be "cancelled"
	 * after the've completed?
	 */
	stop_server_helpers(server_helpers_stopped_callback, logger);

	/*
	 * helper_threads_stopped_callback() is called once both all
	 * helper-threads have exited, and all helper-thread events
	 * lurking in the event-queue have been processed).
	 */
}

void server_helpers_stopped_callback(void)
{
	/*
	 * As libevent to shutdown the event-loop, once completed
	 * SERVER_STOPPED_CALLBACK is called.
	 *
	 * XXX: don't hardwire the callback - passing it in as an
	 * explicit parameter hopefully makes following the code flow
	 * a little easier(?).
	 */
	stop_server(server_stopped_callback);
	/*
	 * server_stopped() is called once the event-loop exits.
	 */
}

void server_stopped_callback(int r, struct logger *logger)
{
	ldbg(logger, "event loop exited: %s",
	     r < 0 ? "an error occurred" :
	     r > 0 ? "no pending or active events" :
	     "success");

	exit_epilogue(logger);
}
