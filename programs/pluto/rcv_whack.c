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

#include "sparse_names.h"
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
#include "sparse_names.h"

#include "whack_add.h"
#include "whack_briefconnectionstatus.h"
#include "visit_connection.h"
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
#include "whack_sa.h"
#include "whack_route.h"
#include "whack_shutdown.h"
#include "whack_status.h"
#include "whack_trafficstatus.h"
#include "whack_unroute.h"
#include "whack_showstates.h"
#include "whack_suspend.h"

static void whack_ddos(const struct whack_message *wm, struct show *s)
{
	set_whack_pluto_ddos(wm->whack_ddos, show_logger(s));
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

static void do_whacklisten(struct logger *logger)
{
	fflush(stderr);
	fflush(stdout);
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

/*
 * Handle: whack --keyid <id> [--addkey] [--pubkeyrsa <key>]\n"
 *
 *                                               key  addkey pubkey
 * whack --keyid <id>                             y      n      n
 *     delete <id> key
 * whack --keyid <id> --pubkeyrsa ...             y      n      y
 *     replace <id> key
 * whack --keyid <id> --addkey --pubkeyrsa ...    y      y      y
 *     add <id> key (keeping any old key)
 * whack --keyid <id> --addkey
 *     invalid as public key is missing (keyval.len is 0)
 */
static void key_add_request(const struct whack_message *msg, struct logger *logger)
{
	bool given_key = msg->keyval.len > 0;

	/*
	 * Figure out the key type.
	 */

	const struct pubkey_type *type;
	switch (msg->pubkey_alg) {
	case IPSECKEY_ALGORITHM_RSA:
		type = &pubkey_type_rsa;
		break;
	case IPSECKEY_ALGORITHM_ECDSA:
		type = &pubkey_type_ecdsa;
		break;
	case IPSECKEY_ALGORITHM_X_PUBKEY:
		type = NULL;
		break;
	default:
		if (msg->pubkey_alg != 0) {
			llog_pexpect(logger, HERE, "unrecognized algorithm type %u", msg->pubkey_alg);
			return;
		}
		type = NULL;
	}

	enum_buf pkb;
	dbg("processing key=%s addkey=%s given_key=%s alg=%s(%d)",
	    bool_str(msg->whack_key),
	    bool_str(msg->whack_addkey),
	    bool_str(given_key),
	    str_enum(&ipseckey_algorithm_config_names, msg->pubkey_alg, &pkb),
	    msg->pubkey_alg);

	/*
	 * Adding must have a public key.
	 */
	if (msg->whack_addkey && !given_key) {
		llog(RC_LOG, logger,
		     "error: key to add is empty (needs DNS lookup?)");
		return;
	}

	struct id keyid; /* must free keyid */
	err_t ugh = atoid(msg->keyid, &keyid); /* must free keyid */
	if (ugh != NULL) {
		llog(RC_BADID, logger,
		     "bad --keyid \"%s\": %s", msg->keyid, ugh);
		return;
	}

	/*
	 * Delete any old key.
	 *
	 * No --addkey just means that is no existing key to delete.
	 * For instance !add with a key means replace.
	 */
	if (!msg->whack_addkey) {
		if (!given_key) {
			/* XXX: this gets called by "add" so be silent */
			llog(LOG_STREAM/*not-whack*/, logger,
			     "delete keyid %s", msg->keyid);
		}
		delete_public_keys(&pluto_pubkeys, &keyid, type);
		/* XXX: what about private keys; suspect not easy as not 1:1? */
	}

	/*
	 * Add the new key.
	 *
	 * No --addkey with a key means replace.
	 */
 	if (given_key) {

		/*
		 * A key was given: add it.
		 *
		 * XXX: this gets called by "add" so be silent.
		 */
		llog(LOG_STREAM/*not-whack*/, logger,
		     "add keyid %s", msg->keyid);
		if (DBGP(DBG_BASE)) {
			DBG_dump_hunk(NULL, msg->keyval);
		}

		/* add the public key */
		struct pubkey *pubkey = NULL; /* must-delref */
		diag_t d = unpack_dns_ipseckey(&keyid, PUBKEY_LOCAL, msg->pubkey_alg,
					       /*install_time*/realnow(),
					       /*until_time*/realtime_epoch,
					       /*ttl*/0,
					       HUNK_AS_SHUNK(msg->keyval),
					       &pubkey/*new-public-key:must-delref*/,
					       &pluto_pubkeys);
		if (d != NULL) {
			llog(RC_LOG, logger, "%s", str_diag(d));
			pfree_diag(&d);
			free_id_content(&keyid);
			return;
		}

		/* try to pre-load the private key */
		bool load_needed;
		const ckaid_t *ckaid = pubkey_ckaid(pubkey);
		pubkey_delref(&pubkey);
		err_t err = preload_private_key_by_ckaid(ckaid, &load_needed, logger);
		if (err != NULL) {
			dbg("no private key: %s", err);
		} else if (load_needed) {
			ckaid_buf ckb;
			llog(LOG_STREAM/*not-whack-for-now*/, logger,
				    "loaded private key matching CKAID %s",
				    str_ckaid(ckaid, &ckb));
		}
	}
	free_id_content(&keyid);
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

static void jam_redirect(struct jambuf *buf, const struct whack_message *wm)
{
	if (wm->redirect_to != NULL) {
		jam_string(buf, " redirect-to=");
		jam_string(buf, wm->redirect_to);
	}
	if (wm->global_redirect != 0) {
		jam_string(buf, " redirect_to=");
		jam_sparse(buf, &yna_option_names, wm->global_redirect);
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

static void whack_global_redirect(const struct whack_message *wm, struct show *s)
{
	struct logger *logger = show_logger(s);
	if (wm->redirect_to != NULL) {
		if (streq(wm->redirect_to, "")) {
			set_global_redirect_dests("");
			global_redirect = GLOBAL_REDIRECT_NO;
			llog(RC_LOG, logger,
			     "cleared global redirect targets and disabled global redirects");
		} else {
			set_global_redirect_dests(wm->redirect_to);
			llog(RC_LOG, logger,
			     "set global redirect target to %s", global_redirect_to());
		}
	}

	switch (wm->global_redirect) {
	case GLOBAL_REDIRECT_NO:
		global_redirect = GLOBAL_REDIRECT_NO;
		llog(RC_LOG, logger, "set global redirect to 'no'");
		break;
	case GLOBAL_REDIRECT_YES:
	case GLOBAL_REDIRECT_AUTO:
		if (strlen(global_redirect_to()) == 0) {
			llog(RC_LOG, logger,
			     "ipsec whack: --global-redirect set to no as there are no active redirect targets");
			global_redirect = GLOBAL_REDIRECT_NO;
		} else {
			global_redirect = wm->global_redirect;
			enum_buf rn;
			llog(RC_LOG, logger,
			     "set global redirect to %s",
			     str_sparse(&global_redirect_names, global_redirect, &rn));
		}
		break;
	}
}

#ifdef USE_SECCOMP
static void whack_seccomp_crashtest(const struct whack_message *wm UNUSED, struct show *s)
{
	struct logger *logger = show_logger(s);
	/*
	 * This is a SECCOMP test, it CAN KILL pluto if successful!
	 *
	 * Basically, we call a syscall that pluto does not use and
	 * that is not on the whitelist. Currently we use getsid()
	 *
	 * With seccomp=enabled, pluto will be killed by the kernel
	 * With seccomp=tolerant or seccomp=disabled, pluto will
	 * report the test results.
	 */
	if (pluto_seccomp_mode == SECCOMP_ENABLED)
		llog(RC_LOG, logger,
		     "pluto is running with seccomp=enabled! pluto is expected to die!");
	llog(RC_LOG, logger, "Performing seccomp security test using getsid() syscall");
	pid_t testpid = getsid(0);

	/* We did not get shot by the kernel seccomp protection */
	if (testpid == -1) {
		llog(RC_LOG, logger,
		     "pluto: seccomp test syscall was blocked");
		switch (pluto_seccomp_mode) {
		case SECCOMP_TOLERANT:
			llog(RC_LOG, logger,
			     "OK: seccomp security was tolerant; the rogue syscall was blocked and pluto was not terminated");
			break;
		case SECCOMP_DISABLED:
			llog(RC_LOG, logger,
			     "OK: seccomp security was not enabled and the rogue syscall was blocked");
			break;
		case SECCOMP_ENABLED:
			llog_error(logger, 0/*no-errno*/,
				   "pluto seccomp was enabled but the rogue syscall did not terminate pluto!");
			break;
		default:
			bad_case(pluto_seccomp_mode);
		}
	} else {
		llog(RC_LOG, logger,
		     "pluto: seccomp test syscall was not blocked");
		switch (pluto_seccomp_mode) {
		case SECCOMP_TOLERANT:
			llog_error(logger, 0/*no-errno*/,
				   "pluto seccomp was tolerant but the rogue syscall was not blocked!");
			break;
		case SECCOMP_DISABLED:
			llog(RC_LOG, logger,
			     "OK: pluto seccomp was disabled and the rogue syscall was not blocked");
			break;
		case SECCOMP_ENABLED:
			llog_error(logger, 0/*no-errno*/,
				   "pluto seccomp was enabled but the rogue syscall was not blocked!");
			break;
		default:
			bad_case(pluto_seccomp_mode);
		}
	}
}
#endif

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
		[WHACK_OPPO_INITIATE] = {
			.name = "oppo-initiate",
			.op = whack_oppo_initiate,
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

	if (!lmod_empty(m->debugging)) {
		lmod_buf lb;
		dbg_whack(s, "debugging: start: %s", str_lmod(&debug_names, m->debugging, &lb));
		whack_debug(m, s);
		dbg_whack(s, "debugging: stop: %s", str_lmod(&debug_names, m->debugging, &lb));
	}

	if (m->impairments.len > 0) {
		dbg_whack(s, "impair: start: %d impairments", m->impairments.len);
		whack_impair(m, s);
		dbg_whack(s, "impair: stop: %d impairments", m->impairments.len);
	}

	/* update MSG_ERRQUEUE setting before size before calling listen */
	if (m->ike_sock_err_toggle) {
		dbg_whack(s, "ike_sock_err_toggle: start: !%s", bool_str(pluto_sock_errqueue));
		pluto_sock_errqueue = !pluto_sock_errqueue;
		llog(RC_LOG, logger,
			    "%s IKE socket MSG_ERRQUEUEs",
			    pluto_sock_errqueue ? "enabling" : "disabling");
		dbg_whack(s, "ike_sock_err_toggle: stop: !%s", bool_str(pluto_sock_errqueue));
	}

	/* process "listen" before any operation that could require it */
	if (m->whack_listen) {
		dbg_whack(s, "listen: start:");
		do_whacklisten(logger);
		dbg_whack(s, "listen: stop:");
	}

	if (m->whack_unlisten) {
		dbg_whack(s, "unlisten: start:");
		llog(RC_LOG, logger, "no longer listening for IKE messages");
		listening = false;
		dbg_whack(s, "unlisten: stop:");
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
