/* whack communicating routines, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013-2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2011 Mika Ilmaranta <ilmis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2014-2020 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2014-2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2019-2023 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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

#include <unistd.h>			/* for getsid() */

#include "connections.h"
#include "rcv_whack.h"
#include "log.h"
#include "fips_mode.h"
#include "show.h"
#include "kernel.h"
#ifdef USE_SECCOMP
#include "pluto_seccomp.h"
#endif

#include "initiate.h"			/* for initiate_connection() */
#include "acquire.h"			/* for initiate_ondemand() */
#include "keys.h"			/* for load_preshared_secrets() */
#include "x509_crl.h"			/* for list_crl_fetch_requests() */
#include "nss_cert_reread.h"		/* for reread_cert_connections() */
#include "root_certs.h"			/* for free_root_certs() */
#include "server.h"			/* for listening; */
#include "ikev2_liveness.h"		/* for submit_v2_liveness_exchange() */
#include "impair_message.h"		/* for add_message_impairment() */
#include "pluto_sd.h"			/* for pluto_sd() */
#include "ipsec_interface.h"
#include "iface.h"			/* for find_ifaces() */
#include "foodgroups.h"			/* for load_groups() */
#include "ikev2_delete.h"		/* for submit_v2_delete_exchange() */
#include "ikev2_redirect.h"		/* for find_and_active_redirect_states() */
#include "addresspool.h"		/* for show_addresspool_status() */
#include "pluto_stats.h"		/* for whack_clear_stats() et.al. */
#include "server_fork.h"		/* for show_process_status() */
#include "ddns.h"			/* for connection_check_ddns() */
#include "visit_connection.h"
#include "whack_add.h"
#include "whack_briefconnectionstatus.h"
#include "whack_connectionstatus.h"
#include "whack_crash.h"
#include "whack_debug.h"
#include "whack_delete.h"
#include "whack_deleteid.h"
#include "whack_deletestate.h"
#include "whack_deleteuser.h"
#include "whack_down.h"
#include "whack_impair.h"
#include "whack_initiate.h"
#include "whack_pubkey.h"
#include "whack_route.h"
#include "whack_sa.h"
#include "whack_showstates.h"
#include "whack_shutdown.h"
#include "whack_status.h"
#include "whack_suspend.h"
#include "whack_trafficstatus.h"
#include "whack_unroute.h"
#include "config_setup.h"
#include "ddos.h"

static void whack_unlisten(const struct whack_message *wm UNUSED, struct show *s)
{
	struct logger *logger = show_logger(s);
	llog(RC_LOG, logger, "no longer listening for IKE messages");
	listening = false;
}

static void whack_rereadsecrets(const struct whack_message *wm UNUSED, struct show *s)
{
	load_preshared_secrets(show_logger(s));
}

static void whack_rereadcerts(const struct whack_message *wm UNUSED, struct show *s)
{
	reread_cert_connections(show_logger(s));
	free_root_certs(show_logger(s));
}

static void whack_fetchcrls(const struct whack_message *wm UNUSED, struct show *s)
{
	fetch_x509_crls(s);
}

static void whack_rereadall(const struct whack_message *wm UNUSED, struct show *s)
{
	whack_rereadsecrets(wm, s);
	whack_rereadcerts(wm, s);
	whack_fetchcrls(wm, s);
}

static void whack_listcacerts(struct show *s)
{
	struct root_certs *roots = root_certs_addref(show_logger(s));
	list_cacerts(s, roots);
	root_certs_delref(&roots, show_logger(s));
}

static void whack_fipsstatus(const struct whack_message *wm UNUSED, struct show *s)
{
	bool fips = is_fips_mode();
	show(s, "FIPS mode %s", !fips ?
		"disabled" :
		impair.force_fips ? "enabled [forced]" : "enabled");
}

static void whack_showstates(const struct whack_message *wm UNUSED, struct show *s)
{
	show_states(s, mononow());
}

static void jam_whack_name(struct jambuf *buf, const struct whack_message *wm)
{
	jam_string(buf, "name=");
	if (wm->name == NULL) {
		jam_string(buf, "<none>");
	} else {
		jam_string(buf, wm->name);
	}
}

static void jam_whack_deletestateno(struct jambuf *buf, const struct whack_message *wm)
{
	jam_so(buf, wm->whack_deletestateno);
}

static void jam_whack_crash_peer(struct jambuf *buf, const struct whack_message *wm)
{
	jam_address(buf, &wm->whack_crash_peer);
}

static void jam_whack_initiate(struct jambuf *buf, const struct whack_message *wm)
{
	jam(buf, "initiate: start: name='%s' remote='%s' async=%s",
	    (wm->name == NULL ? "<null>" : wm->name),
	    (wm->remote_host != NULL ? wm->remote_host : "<null>"),
	    bool_str(wm->whack_async));
}

PRINTF_LIKE(2)
static void dbg_whack(struct show *s, const char *fmt, ...)
{
	if (DBGP(DBG_BASE)) {
		struct logger *logger = show_logger(s);
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam(buf, "whack: ");
			va_list ap;
			va_start(ap, fmt);
			jam_va_list(buf, fmt, ap);
			va_end(ap);
			jam(buf, " ("PRI_LOGGER")", pri_logger(logger));
		}
	}
}

static void whack_listen(const struct whack_message *wm, struct show *s)
{
	struct logger *logger = show_logger(s);
	const struct whack_listen *wl = &wm->whack.listen;

	/* first extract current values from config */

	const struct config_setup *oco = config_setup_singleton();
	pluto_ike_socket_errqueue = config_setup_yn(oco, KYN_IKE_SOCKET_ERRQUEUE);
	pluto_ike_socket_bufsize = config_setup_option(oco, KBF_IKE_SOCKET_BUFSIZE);

	/* Update MSG_ERRQUEUE settings before listen. */

	bool errqueue_set = false;
	if (wl->ike_socket_errqueue_toggle) {
		errqueue_set = true;
		pluto_ike_socket_errqueue = !pluto_ike_socket_errqueue;
	}

	switch (wl->ike_socket_errqueue) {
	case YN_YES:
		errqueue_set = true;
		pluto_ike_socket_errqueue = true;
		break;
	case YN_NO:
		errqueue_set = true;
		pluto_ike_socket_errqueue = false;
		break;
	case YN_UNSET:
		break;
	}

	if (errqueue_set) {
		llog(RC_LOG, logger, "%s IKE socket MSG_ERRQUEUEs",
		     (pluto_ike_socket_errqueue ? "enabling" : "disabling"));
	}

	/* Update MSG buffer size before listen */

	if (wl->ike_socket_bufsize != 0) {
		pluto_ike_socket_bufsize = wl->ike_socket_bufsize;
		llog(RC_LOG, logger, "set IKE socket buffer to %u", pluto_ike_socket_bufsize);
	}

	/* now put values back into config_setup */
	update_setup_yn(KYN_IKE_SOCKET_ERRQUEUE, (pluto_ike_socket_errqueue ? YN_YES : YN_NO));
	update_setup_option(KBF_IKE_SOCKET_BUFSIZE, pluto_ike_socket_bufsize);

	/* do the deed */

#ifdef USE_SYSTEMD_WATCHDOG
	pluto_sd(PLUTO_SD_RELOADING, SD_REPORT_NO_STATUS);
#endif
	llog(RC_LOG, logger, "listening for IKE messages");
	listening = true;
	find_ifaces(true /* remove dead interfaces */, logger);

	load_preshared_secrets(logger);
	load_groups(logger);
#ifdef USE_SYSTEMD_WATCHDOG
	pluto_sd(PLUTO_SD_READY, SD_REPORT_NO_STATUS);
#endif
}

static void jam_redirect(struct jambuf *buf, const struct whack_message *wm)
{
	if (wm->redirect_to != NULL) {
		jam_string(buf, " redirect-to=");
		jam_string(buf, wm->redirect_to);
	}
	if (wm->global_redirect != 0) {
		jam_string(buf, " redirect_to=");
		jam_sparse_long(buf, &yna_option_names, wm->global_redirect);
	}
}

static void whack_active_redirect(const struct whack_message *wm, struct show *s)
{
	struct logger *logger = show_logger(s);
	/*
	 * We are redirecting all peers of one or all connections.
	 *
	 * Whack's --redirect-to is ambitious - is it part of an ADD
	 * or a global op?  Checking .whack_add.
	 */
	find_and_active_redirect_states(wm->name, wm->redirect_to, logger);
}

static void whack_checkpubkeys(const struct whack_message *wm, struct show *s)
{
	show_pubkeys(s, wm->whack_utc, SHOW_EXPIRED_KEYS);
}

static void whack_shutdown_leave_state(const struct whack_message *wm UNUSED, struct show *s)
{
	whack_shutdown(show_logger(s), true);
}

static void whack_list(const struct whack_message *wm, struct show *s)
{
	monotime_t now = mononow();

	if (wm->whack_list & LELEM(LIST_PUBKEYS)) {
		dbg_whack(s, "listpubkeys: start:");
		show_pubkeys(s, wm->whack_utc, SHOW_ALL_KEYS);
		dbg_whack(s, "listpubkeys: stop:");
	}

	if (wm->whack_list & LELEM(LIST_PSKS)) {
		dbg_whack(s, "list & LIST_PSKS: start:");
		list_psks(s);
		dbg_whack(s, "list & LIST_PSKS: stop:");
	}

	if (wm->whack_list & LELEM(LIST_CERTS)) {
		dbg_whack(s, "listcerts: start:");
		list_certs(s);
		dbg_whack(s, "listcerts: stop:");
	}

	if (wm->whack_list & LELEM(LIST_CACERTS)) {
		dbg_whack(s, "listcacerts: start");
		whack_listcacerts(s);
		dbg_whack(s, "listcacerts: stop:");
	}

	if (wm->whack_list & LELEM(LIST_CRLS)) {
		dbg_whack(s, "listcrls: start:");
		list_crls(s);
#if defined(USE_LIBCURL) || defined(USE_LDAP)
		list_crl_fetch_requests(s, wm->whack_utc);
#endif
		dbg_whack(s, "listcrls: stop:");
	}

	if (wm->whack_list & LELEM(LIST_EVENTS)) {
		dbg_whack(s, "listevents: start:");
		list_timers(s, now);
		list_state_events(s, now);
		dbg_whack(s, "listevents: stop:");
	}
}

static void dispatch_command(const struct whack_message *const wm, struct show *s)
{
	static const struct command {
		const char *name;
		void (*jam)(struct jambuf *buf, const struct whack_message *wm);
		void (*op)(const struct whack_message *wm, struct show *s);
	} commands[] = {
		[WHACK_FETCHCRLS] = {
			.name = "fetchcrls",
			.op = whack_fetchcrls,
		},
		[WHACK_REREADALL] = {
			.name = "rereadall",
			.op = whack_rereadall,
		},
		[WHACK_REREADSECRETS] = {
			.name = "rereadsecrets",
			.op = whack_rereadsecrets,
		},
		[WHACK_REREADCERTS] = {
			.name = "rereadcerts",
			.op = whack_rereadcerts,
		},
		[WHACK_GLOBALSTATUS] = {
			.name = "globalstatus",
			.op = whack_globalstatus,
		},
		[WHACK_TRAFFICSTATUS] = {
			.name = "trafficstatus",
			.op = whack_trafficstatus,
		},
		[WHACK_SHUNTSTATUS] = {
			.name = "shuntstatus",
			.op = whack_shuntstatus,
		},
		[WHACK_FIPSSTATUS] = {
			.name = "fipsstatus",
			.op = whack_fipsstatus,
		},
		[WHACK_BRIEFSTATUS] = {
			.name = "briefstatus",
			.op = whack_briefstatus,
		},
		[WHACK_PROCESSSTATUS] = {
			.name = "processstatus",
			.op = whack_processstatus,
		},
		[WHACK_ADDRESSPOOLSTATUS] = {
			.name = "addresspoolstatus",
			.op = whack_addresspoolstatus,
		},
		[WHACK_CONNECTIONSTATUS] = {
			.name = "connectionstatus",
			.op = whack_connectionstatus,
		},
		[WHACK_BRIEFCONNECTIONSTATUS] = {
			.name = "briefconnectionstatus",
			.op = whack_briefconnectionstatus,
		},
		/**/
		[WHACK_DELETE] = {
			.name = "delete",
			.op = whack_delete,
			.jam = jam_whack_name,
		},
		[WHACK_ADD] = {
			.name = "add",
			.op = whack_add,
			.jam = jam_whack_name,
		},
		[WHACK_ROUTE] = {
			.name = "route",
			.op = whack_route,
			.jam = jam_whack_name,
		},
		[WHACK_UNROUTE] = {
			.name = "unroute",
			.op = whack_unroute,
			.jam = jam_whack_name,
		},
		[WHACK_INITIATE] = {
			.name = "initiate",
			.op = whack_initiate,
			.jam = jam_whack_initiate,
		},
		[WHACK_SUSPEND] = {
			.name = "suspend",
			.op = whack_suspend,
			.jam = jam_whack_name,
		},
		[WHACK_ACQUIRE] = {
			.name = "acquire",
			.op = whack_acquire,
		},
		[WHACK_DOWN] = {
			.name = "down",
			.op = whack_down,
			.jam = jam_whack_name,
		},
		/**/
		[WHACK_DELETEUSER] = {
			.name = "deleteuser",
			.op = whack_deleteuser,
			.jam = jam_whack_name,
		},
		[WHACK_DELETEID] = {
			.name = "deleteid",
			.op = whack_deleteid,
			.jam = jam_whack_name,
		},
		[WHACK_DELETESTATE] = {
			.name = "deletestate",
			.op = whack_deletestate,
			.jam = jam_whack_deletestateno,
		},
		/**/
		[WHACK_CRASH] = {
			.name = "crash",
			.op = whack_crash,
			.jam = jam_whack_crash_peer,
		},
		[WHACK_DDNS] = {
			.name = "ddns",
			.op = whack_ddns,
		},
		[WHACK_PURGEOCSP] = {
			.name = "purgeocsp",
			.op = whack_purgeocsp,
		},
		[WHACK_CLEARSTATS] = {
			.name = "clearstats",
			.op = whack_clearstats,
		},
		[WHACK_SHOWSTATES] = {
			.name = "showstates",
			.op = whack_showstates,
		},
		/**/
		[WHACK_REKEY_IKE] = {
			.name = "rekey-ike",
			.op = whack_sa,
			.jam = jam_whack_name,
		},
		[WHACK_REKEY_CHILD] = {
			.name = "rekey-child",
			.op = whack_sa,
			.jam = jam_whack_name,
		},
		[WHACK_DELETE_IKE] = {
			.name = "delete-ike",
			.op = whack_sa,
			.jam = jam_whack_name,
		},
		[WHACK_DELETE_CHILD] = {
			.name = "delete-child",
			.op = whack_sa,
			.jam = jam_whack_name,
		},
		[WHACK_DOWN_IKE] = {
			.name = "down-ike",
			.op = whack_sa,
			.jam = jam_whack_name,
		},
		[WHACK_DOWN_CHILD] = {
			.name = "down-child",
			.op = whack_sa,
			.jam = jam_whack_name,
		},
		[WHACK_DDOS] = {
			.name = "ddos",
			.op = whack_ddos,
		},
		[WHACK_CHECKPUBKEYS] = {
			.name = "checkpubkeys",
			.op = whack_checkpubkeys,
		},
		[WHACK_LIST] = {
			.name = "list",
			.op = whack_list,
		},
#ifdef USE_SECCOMP
		[WHACK_SECCOMP_CRASHTEST] {
			.name = "seccomp-crashtest",
			.op = whack_seccomp_crashtest,
		},
#endif
		[WHACK_SHUTDOWN_LEAVE_STATE] = {
			.name = "shutdown(leave-state)",
			.op = whack_shutdown_leave_state,
		},
		[WHACK_GLOBAL_REDIRECT] = {
			.jam = jam_redirect,
			.name = "global-redirect",
			.op = whack_global_redirect,
		},
		[WHACK_ACTIVE_REDIRECT] = {
			.jam = jam_redirect,
			.name = "active-redirect",
			.op = whack_active_redirect,
		},
		/**/
		[WHACK_LISTEN] = {
			.name = "listen",
			.op = whack_listen,
		},
		[WHACK_UNLISTEN] = {
			.name = "unlisten",
			.op = whack_unlisten,
		},
	};

	struct logger *logger = show_logger(s);
	PASSERT(logger, wm->whack_command < elemsof(commands));
	const struct command *command = &commands[wm->whack_command];

	if (PBAD(logger, command->name == NULL) ||
	    PBAD(logger, command->op == NULL)) {
		return;
	}

	if (DBGP(DBG_BASE)) {
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam_string(buf, "whack: ");
			jam_string(buf, "start: ");
			jam_string(buf, command->name);
			if (command->jam != NULL) {
				jam_string(buf, ": ");
				command->jam(buf, wm);
			}
			jam(buf, " ("PRI_LOGGER")", pri_logger(logger));
		}
	}

	command->op(wm, s);

	if (DBGP(DBG_BASE)) {
		struct logger *logger = show_logger(s);
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam_string(buf, "whack: ");
			jam_string(buf, "stop: ");
			jam_string(buf, command->name);
			if (command->jam != NULL) {
				jam_string(buf, ": ");
				command->jam(buf, wm);
			}
			jam(buf, " ("PRI_LOGGER")", pri_logger(logger));
		}
	}
}

/*
 * handle a whack message.
 */

static void whack_process(const struct whack_message *const m, struct show *s)
{
	/*
	 * XXX: keep code below compiling.
	 *
	 * Suspect logging code should either:
	 *
	 * => use llog() (or log_show() wrapper?) so failing
	 * whack requests leave a breadcrumb in the main whack log.
	 *
	 * => use show_*() because the good output is for whack
	 */
	struct logger *logger = show_logger(s);
	ldbg(logger, "processing message from %s",
	     (m->whack_from == WHACK_FROM_WHACK ? "whack" :
	      m->whack_from == WHACK_FROM_ADDCONN ? "addconn" :
	      "???"));

	/*
	 * May be needed in future:
	 * const struct lsw_conf_options *oco = lsw_init_options();
	 *
	 * XXX: why?
	 */

	if (!lmod_empty(m->whack_debugging)) {
		lmod_buf lb;
		dbg_whack(s, "debugging: start: %s", str_lmod(&debug_names, m->whack_debugging, &lb));
		whack_debug(m, s);
		dbg_whack(s, "debugging: stop: %s", str_lmod(&debug_names, m->whack_debugging, &lb));
	}

	if (m->impairments.len > 0) {
		dbg_whack(s, "impair: start: %d impairments", m->impairments.len);
		whack_impair(m, s);
		dbg_whack(s, "impair: stop: %d impairments", m->impairments.len);
	}

	/*
	 * Most commands go here.
	 */

	if (m->whack_command != 0) {
		dispatch_command(m, s);
	}

	if (m->whack_key) {
		dbg_whack(s, "key: start:");
		/* add a public key */
		key_add_request(m, show_logger(s));
		dbg_whack(s, "key: stop:");
	}

	return;
}

static void whack_handle(struct fd *whackfd, struct logger *whack_logger);

void whack_handle_cb(int fd, void *arg UNUSED, struct logger *global_logger)
{
	threadtime_t start = threadtime_start();
	{
		struct fd *whackfd = fd_accept(fd, HERE, global_logger);
		if (whackfd == NULL) {
			/* already logged */
			return;
		}

		/*
		 * Hack to get the whack fd attached to the initial
		 * event handler logger.  With this done, everything
		 * from here on can use attach_whack() et.al.
		 *
		 * See also whack_shutdown() which deliberately leaks
		 * this fd.
		 */
		struct logger whack_logger = *global_logger;
		whack_logger.whackfd[0] = whackfd;
		whack_logger.where = HERE;

		whack_handle(whackfd, &whack_logger);

		fd_delref(&whackfd);
	}
	threadtime_stop(&start, SOS_NOBODY, "whack");
}

/*
 * Handle a whack request.
 */

static void whack_handle(struct fd *whackfd, struct logger *whack_logger)
{
	/*
	 * properly initialize msg - needed because short reads are
	 * sometimes OK
	 */
	struct whack_message msg = {0};

	ssize_t n = fd_read(whackfd, &msg, sizeof(msg));
	if (n <= 0) {
		llog_error(whack_logger, -(int)n,
			   "read() failed in whack_handle()");
		return;
	}

	static uintmax_t msgnum;
	ldbgf(DBG_TMI, whack_logger, "whack message %ju; size=%zd", msgnum++, n);

	/*
	 * Try to unpack the message.  Will reject anything with
	 * neither WHACK_BASIC_MAGIC nor whack_magic().
	 */

	struct whackpacker wp = {
		.msg = &msg,
		.n = n,
	};

	if (!unpack_whack_msg(&wp, whack_logger)) {
		/* already logged */
		return; /* don't shutdown */
	}

	/*
	 * Handle basic commands here.
	 */

	if (msg.basic.whack_shutdown) {
		whack_shutdown(whack_logger, false);
		return; /* force shutting down */
	}

	if (msg.basic.whack_status) {
		struct show *s = alloc_show(whack_logger);
		whack_status(s, mononow());
		free_show(&s);
		/* bail early, but without complaint */
		return; /* don't shutdown */
	}

	struct show *s = alloc_show(whack_logger);
	whack_process(&msg, s);
	free_show(&s);
}
