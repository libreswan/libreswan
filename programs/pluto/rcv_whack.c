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
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <fcntl.h>
#include <unistd.h>		/* for gethostname() */

#include <event2/event.h>
#include <event2/event_struct.h>

#include "lswconf.h"
#include "constants.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "pluto_x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "foodgroups.h"
#include "whack.h"              /* needs connections.h */
#include "packet.h"
#include "demux.h"              /* needs packet.h */
#include "state.h"
#include "ipsec_doi.h"          /* needs demux.h and state.h */
#include "kernel.h"             /* needs connections.h */
#include "rcv_whack.h"
#include "log.h"
#include "lswfips.h"
#include "keys.h"
#include "secrets.h"
#include "server.h"
#include "fetch.h"
#include "timer.h"
#include "ikev2.h"
#include "ikev2_redirect.h"
#include "ikev2_delete.h"
#include "ikev2_liveness.h"
#include "server.h" /* for pluto_seccomp */
#include "kernel_alg.h"
#include "ike_alg.h"
#include "ip_address.h" /* for setportof() */
#include "crl_queue.h"
#include "pluto_sd.h"
#include "initiate.h"
#include "iface.h"
#include "show.h"
#include "impair_message.h"
#ifdef HAVE_SECCOMP
#include "pluto_seccomp.h"
#endif
#include "server_fork.h"		/* for show_process_status() */

#ifdef USE_XFRM_INTERFACE
# include "kernel_xfrm_interface.h"
#endif
#include "addresspool.h"

#include "pluto_stats.h"

#include "nss_cert_reread.h"
#include "send.h"			/* for impair: send_keepalive() */
#include "pluto_shutdown.h"		/* for shutdown_pluto() */
#include "orient.h"
#include "ikev2_create_child_sa.h"	/* for submit_v2_CREATE_CHILD_SA_*() */

static struct state *find_impaired_state(unsigned biased_what,
					 struct logger *logger)
{
	if (biased_what == 0) {
		llog(RC_COMMENT, logger, "state 'no' is not valid");
		return NULL;
	}
	so_serial_t so = biased_what - 1; /* unbias */
	struct state *st = state_by_serialno(so);
	if (st == NULL) {
		llog(RC_COMMENT, logger, "state #%lu not found", so);
		return NULL;
	}
	return st;
}

static struct logger merge_loggers(struct state *st, bool background, struct logger *logger)
{
	/* so errors go to whack and file regardless of BACKGROUND */
	struct logger loggers = *st->st_logger;
	loggers.global_whackfd = logger->global_whackfd;
	if (!background) {
		/* XXX: something better */
		fd_delref(&st->st_logger->object_whackfd);
		st->st_logger->object_whackfd = fd_addref(logger->global_whackfd);
	}
	return loggers;
}

static void whack_impair_action(enum impair_action impairment_action,
				unsigned impairment_param,
				unsigned biased_value,
				bool background, struct logger *logger)
{
	switch (impairment_action) {
	case CALL_IMPAIR_UPDATE:
		/* err... */
		break;
	case CALL_GLOBAL_EVENT_HANDLER:
	{
		passert(biased_value > 0);
		call_global_event_inline(biased_value, logger);
		break;
	}
	case CALL_STATE_EVENT_HANDLER:
	{
		struct state *st = find_impaired_state(biased_value, logger);
		if (st == NULL) {
			/* already logged */
			return;
		}
		/* will log */
		struct logger loggers = merge_loggers(st, background, logger);
		call_state_event_handler(&loggers, st, (enum event_type)impairment_param);
		break;
	}
	case CALL_INITIATE_v2_LIVENESS:
	{
		struct state *st = find_impaired_state(biased_value, logger);
		if (st == NULL) {
			/* already logged */
			return;
		}
		/* will log */
		struct ike_sa *ike = ike_sa(st, HERE);
		if (ike == NULL) {
			/* already logged */
			return;
		}
		merge_loggers(&ike->sa, background, logger);
		llog_sa(RC_COMMENT, ike, "initiating liveness for #%lu", st->st_serialno);
		submit_v2_liveness_exchange(ike, st->st_serialno);
		break;
	}
	case CALL_SEND_KEEPALIVE:
	{
		struct state *st = find_impaired_state(biased_value, logger);
		if (st == NULL) {
			/* already logged */
			return;
		}
		/* will log */
		struct logger loggers = merge_loggers(st, true/*background*/, logger);
		llog(RC_COMMENT, &loggers, "sending keepalive");
		send_keepalive_using_state(st, "inject keep-alive");
		break;
	}
	case CALL_IMPAIR_DROP_INCOMING:
	case CALL_IMPAIR_DROP_OUTGOING:
		add_message_impairment(biased_value - 1, impairment_action, logger);
	}
}

static int whack_route_connection(struct connection *c,
				  void *unused_arg UNUSED,
				  struct logger *logger)
{
	/* XXX: something better? */
	fd_delref(&c->logger->global_whackfd);
	c->logger->global_whackfd = fd_addref(logger->global_whackfd);

	if (!oriented(c)) {
		/* XXX: why whack only? */
		llog(WHACK_STREAM|RC_ORIENT, c->logger,
		     "we cannot identify ourselves with either end of this connection");
	} else if (c->policy & POLICY_GROUP) {
		route_group(c);
	} else if (!trap_connection(c)) {
		/* XXX: why whack only? */
		llog(WHACK_STREAM|RC_ROUTE, c->logger,
		     "could not route");
	}

	/* XXX: something better? */
	fd_delref(&c->logger->global_whackfd);

	return 1;
}

static int whack_unroute_connection(struct connection *c,
				    void *unused_arg UNUSED,
				    struct logger *logger)
{
	const struct spd_route *sr;
	int fail = 0;

	passert(c != NULL);

	for (sr = &c->spd; sr != NULL; sr = sr->spd_next) {
		if (sr->routing >= RT_ROUTED_TUNNEL)
			fail++;
	}
	if (fail > 0) {
		llog(WHACK_STREAM|RC_RTBUSY, logger, "cannot unroute: route busy");
	} else if (c->policy & POLICY_GROUP) {
		unroute_group(c);
	} else {
		unroute_connection(c);
	}

	return 1;
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
#ifdef USE_XFRM_INTERFACE
	stale_xfrmi_interfaces(logger);
#endif
	load_preshared_secrets(logger);
	load_groups(logger);
#ifdef USE_SYSTEMD_WATCHDOG
	pluto_sd(PLUTO_SD_READY, SD_REPORT_NO_STATUS);
#endif
}

/*
 * Handle: whack --keyid <id> [--addkey] [--pubkeyrsa <key>]\n"
 *
 * whack --keyid <id>
 *     delete <id> key
 * whack --keyid <id> --pubkeyrsa ...
 *     replace <id> key
 * whack --keyid <id> --addkey --pubkeyrsa ...
 *     add <id> key (keeping any old key)
 * whack --keyid <id> --addkey
 *     invalid as public key is missing (keyval.len is 0)
 */
static void key_add_request(const struct whack_message *msg, struct logger *logger)
{
	/* A (public) key requires a (key) type and a type requires a key */

	const struct pubkey_type *type = pubkey_alg_type(msg->pubkey_alg);
	bool given_key = type != NULL;	/* were we given a key by the whack command? */

	passert(given_key == (msg->keyval.len != 0));

	/* --addkey always requires a key */
	if (msg->whack_addkey && !given_key) {
		llog(RC_LOG_SERIOUS, logger,
			    "error: key to add is empty (needs DNS lookup?)");
		return;
	}

	struct id keyid;
	err_t ugh = atoid(msg->keyid, &keyid); /* must free keyid */
	if (ugh != NULL) {
		llog(RC_BADID, logger,
			    "bad --keyid \"%s\": %s", msg->keyid, ugh);
		return;
	}

	/* if no --addkey: delete any preexisting keys */
	if (!msg->whack_addkey) {
		if (!given_key) {
			/* XXX: this gets called by "add" so be silent */
			llog(LOG_STREAM/*not-whack*/, logger,
				    "delete keyid %s", msg->keyid);
		}
		delete_public_keys(&pluto_pubkeys, &keyid, type);
		/* XXX: what about private keys; suspect not easy as not 1:1? */
	}

	/* if a key was given: add it */
	if (given_key) {
		/* XXX: this gets called by "add" so be silent */
		llog(LOG_STREAM/*not-whack*/, logger,
			    "add keyid %s", msg->keyid);
		DBG_dump_hunk(NULL, msg->keyval);

		/* add the public key */
		struct pubkey *pubkey = NULL; /* must-delref */
		err_t ugh = add_public_key(&keyid, PUBKEY_LOCAL, type,
					   /*install_time*/realnow(),
					   /*until_time*/realtime_epoch,
					   /*ttl*/0,
					   &msg->keyval,
					   &pubkey/*new-public-key:must-delref*/,
					   &pluto_pubkeys);
		if (ugh != NULL) {
			llog(RC_LOG_SERIOUS, logger, "%s", ugh);
			free_id_content(&keyid);
			return;
		}

		/* try to pre-load the private key */
		bool load_needed;
		const ckaid_t *ckaid = pubkey_ckaid(pubkey);
		pubkey_delref(&pubkey, HERE);
		err_t err = preload_private_key_by_ckaid(ckaid, &load_needed, logger);
		if (err != NULL) {
			dbg("no private key: %s", err);
		} else if (load_needed) {
			ckaid_buf ckb;
			llog(RC_LOG|LOG_STREAM/*not-whack-for-now*/, logger,
				    "loaded private key matching CKAID %s",
				    str_ckaid(ckaid, &ckb));
		}
	}
	free_id_content(&keyid);
}

static void dbg_whack(struct show *s, const char *fmt, ...) PRINTF_LIKE(2);
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
			jam(buf, " ("PRI_FD")", logger->global_whackfd);
		}
	}
}

/*
 * handle a whack message.
 */

static void whack_process(const struct whack_message *const m, struct show *s)
{
	const monotime_t now = mononow();

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
	struct fd *whackfd = logger->global_whackfd;

	/*
	 * May be needed in future:
	 * const struct lsw_conf_options *oco = lsw_init_options();
	 *
	 * XXX: why?
	 */
	if (m->whack_options) {
		dbg_whack(s, "start: options (impair|debug)");
		switch (m->opt_set) {
		case WHACK_ADJUSTOPTIONS:
			if (libreswan_fipsmode()) {
				if (lmod_is_set(m->debugging, DBG_PRIVATE)) {
					whack_log(RC_FATAL, whackfd,
						  "FIPS: --debug private is not allowed in FIPS mode, aborted");
					return; /*don't shutdown*/
				}
				if (lmod_is_set(m->debugging, DBG_CRYPT)) {
					whack_log(RC_FATAL, whackfd,
						  "FIPS: --debug crypt is not allowed in FIPS mode, aborted");
					return; /*don't shutdown*/
				}
			}
			if (m->name == NULL) {
				/*
				 * This is done in two two-steps so
				 * that if either old or new would
				 * cause a debug message to print, it
				 * will be printed.
				 *
				 * XXX: why not unconditionally send
				 * what was changed back to whack?
				 */
				lset_t old_debugging = cur_debugging & DBG_MASK;
				lset_t new_debugging = lmod(old_debugging, m->debugging);
				set_debugging(cur_debugging | new_debugging);
				LSWDBGP(DBG_BASE, buf) {
					jam(buf, "old debugging ");
					jam_lset_short(buf, &debug_names,
						       "+", old_debugging);
					jam(buf, " + ");
					jam_lmod(buf, &debug_names, "+", m->debugging);
				}
				LSWDBGP(DBG_BASE, buf) {
					jam(buf, "new debugging = ");
					jam_lset_short(buf, &debug_names,
						       "+", new_debugging);
				}
				set_debugging(new_debugging);
				for (unsigned i = 0; i < m->nr_impairments; i++) {
					/* ??? what should we do with return value? */
					process_impair(&m->impairments[i],
						       whack_impair_action,
						       m->whack_async/*background*/,
						       logger);
				}
			} else if (!m->whack_connection) {
				struct connection *c = conn_by_name(m->name, true/*strict*/);
				if (c == NULL) {
					whack_log(RC_UNKNOWN_NAME, whackfd,
						  "no connection named \"%s\"", m->name);
				} else if (c != NULL) {
					c->extra_debugging = m->debugging;
					LSWDBGP(DBG_BASE, buf) {
						jam(buf, "\"%s\" extra_debugging = ",
						    c->name);
						jam_lmod(buf, &debug_names,
							 "+", c->extra_debugging);
					}
				}
			}
			break;

		case WHACK_SETDUMPDIR:
			/* XXX */
			break;

		}
		dbg_whack(s, "stop: options (impair|debug)");
	}

	if (m->whack_rekey_ike) {
		dbg_whack(s, "start: rekey_ike '%s'", m->name == NULL ? "NULL" : m->name);
		if (m->name == NULL) {
			/* leave bread crumb */
			llog(RC_FATAL, logger,
			     "received whack command to rekey IKE SA of connection, but did not receive the connection name or state number - ignored");
		} else {
			rekey_now(m->name, IKE_SA, m->whack_async/*background*/, logger);
		}
		dbg_whack(s, "stop: rekey_ike '%s'", m->name == NULL ? "NULL" : m->name);
	}

	if (m->whack_rekey_ipsec) {
		dbg_whack(s, "start: rekey_ipsec '%s'", m->name == NULL ? "NULL" : m->name);
		if (m->name == NULL) {
			/* leave bread crumb */
			llog(RC_FATAL, logger,
			     "received whack command to rekey IPsec SA of connection, but did not receive the connection name or state number - ignored");
		} else {
			rekey_now(m->name, IPSEC_SA, m->whack_async/*background*/, logger);
		}
		dbg_whack(s, "stop: rekey_ipsec '%s'", m->name == NULL ? "NULL" : m->name);
	}

	/* Deleting combined with adding a connection works as replace.
	 * To make this more useful, in only this combination,
	 * delete will silently ignore the lack of the connection.
	 */
	if (m->whack_delete) {
		dbg_whack(s, "start: delete '%s'", m->name == NULL ? "NULL" : m->name);
		if (m->name == NULL) {
			whack_log(RC_FATAL, whackfd,
				  "received whack command to delete a connection, but did not receive the connection name - ignored");
		} else {
			terminate_connections_by_name(m->name, /*quiet?*/true, logger);
			delete_connections_by_name(m->name, !m->whack_connection, logger);
		}
		dbg_whack(s, "stop: delete '%s'", m->name == NULL ? "NULL" : m->name);
	}

	if (m->whack_deleteuser) {
		dbg_whack(s, "start: deleteuser '%s'", m->name == NULL ? "NULL" : m->name);
		if (m->name == NULL ) {
			whack_log(RC_FATAL, whackfd,
				  "received whack command to delete a connection by username, but did not receive the username - ignored");
		} else {
			llog(LOG_STREAM, logger,
			     "received whack to delete connection by user %s", m->name);
			struct state_filter sf = { .where = HERE, };
			while (next_state_new2old(&sf)) {
				v1_delete_state_by_username(sf.st, m->name);
			}
		}
		dbg_whack(s, "stop: deleteuser '%s'", m->name == NULL ? "NULL" : m->name);
	}

	if (m->whack_deleteid) {
		dbg_whack(s, "start: deleteid '%s'", m->name == NULL ? "NULL" : m->name);
		if (m->name == NULL ) {
			whack_log(RC_FATAL, whackfd,
				  "received whack command to delete a connection by id, but did not receive the id - ignored");
		} else {
			llog(LOG_STREAM, logger,
			     "received whack to delete connection by id %s", m->name);
			struct state_filter sf = { .where = HERE, };
			while (next_state_new2old(&sf)) {
				delete_state_by_id_name(sf.st, m->name);
			}
		}
		dbg_whack(s, "stop: deleteid '%s'", m->name == NULL ? "NULL" : m->name);
	}

	if (m->whack_deletestate) {
		dbg_whack(s, "start: deletestate #%lu", m->whack_deletestateno);
		struct state *st = state_by_serialno(m->whack_deletestateno);

		if (st == NULL) {
			llog(RC_UNKNOWN_NAME, logger, "no state #%lu to delete",
			     m->whack_deletestateno);
		} else {
			merge_loggers(st, m->whack_async/*background*/, logger);
			llog(LOG_STREAM/*not-whack*/, st->st_logger,
			     "received whack to delete %s state #%lu %s",
			     st->st_connection->config->ike_info->version_name,
			     st->st_serialno, st->st_state->name);

			switch (st->st_ike_version) {
			case IKEv1:
				delete_state(st);
				st = NULL;
				break;
			case IKEv2:
				submit_v2_delete_exchange(ike_sa(st, HERE),
							  IS_CHILD_SA(st) ? pexpect_child_sa(st) : NULL);
				break;
			}
		}
		dbg_whack(s, "stop: deletestate #%lu", m->whack_deletestateno);
	}

	if (m->whack_crash) {
		address_buf pb;
		dbg_whack(s, "start: crash %s", str_address(&m->whack_crash_peer, &pb));
		delete_states_by_peer(whackfd, &m->whack_crash_peer);
		dbg_whack(s, "stop: crash %s", str_address(&m->whack_crash_peer, &pb));
	}

	if (m->whack_connection) {
		dbg_whack(s, "start: add-connection '%s'", m->name == NULL ? "NULL" : m->name);
		add_connection(m, logger);
		dbg_whack(s, "stop: add-connection '%s'", m->name == NULL ? "NULL" : m->name);
	}

	if (m->active_redirect_dests != NULL) {
		dbg_whack(s, "start: active_redirect_dests '%s'", m->name == NULL ? "NULL" : m->name);
		/*
		 * we are redirecting all peers of one or all connections
		 */
		find_and_active_redirect_states(m->name, m->active_redirect_dests, logger);
		dbg_whack(s, "stop: active_redirect_dests '%s'", m->name == NULL ? "NULL" : m->name);
	}

	if (m->global_redirect_to) {
		dbg_whack(s, "start: global_redirect_to %s", m->global_redirect_to);
		if (streq(m->global_redirect_to, "<none>")) {
			set_global_redirect_dests("");
			global_redirect = GLOBAL_REDIRECT_NO;
			llog(RC_LOG, logger,
				"cleared global redirect targets and disabled global redirects");
		} else {
			set_global_redirect_dests(m->global_redirect_to);
			llog(RC_LOG, logger,
				"set global redirect target to %s", global_redirect_to());
		}
		dbg_whack(s, "stop: global_redirect_to %s", m->global_redirect_to);
	}

	if (m->global_redirect) {
		dbg_whack(s, "start: global_redirect %d", m->global_redirect);
		if (m->global_redirect != GLOBAL_REDIRECT_NO && strlen(global_redirect_to()) == 0) {
			llog(RC_LOG_SERIOUS, logger,
			    "ipsec whack: --global-redirect set to no as there are no active redirect targets");
			global_redirect = GLOBAL_REDIRECT_NO;
		} else {
			global_redirect = m->global_redirect;
			llog(RC_LOG, logger,
				"set global redirect to %s",
				enum_name(&allow_global_redirect_names, global_redirect));
		}
		dbg_whack(s, "stop: global_redirect %d", m->global_redirect);
	}

	/* update any socket buffer size before calling listen */
	if (m->ike_buf_size != 0) {
		dbg_whack(s, "start: ike_buf_size %lu", m->ike_buf_size);
		pluto_sock_bufsize = m->ike_buf_size;
		llog(RC_LOG, logger,
			    "set IKE socket buffer to %d", pluto_sock_bufsize);
		dbg_whack(s, "stop: ike_buf_size %lu", m->ike_buf_size);
	}

	/* update MSG_ERRQUEUE setting before size before calling listen */
	if (m->ike_sock_err_toggle) {
		dbg_whack(s, "start: ike_sock_err_toggle !%s", bool_str(pluto_sock_errqueue));
		pluto_sock_errqueue = !pluto_sock_errqueue;
		llog(RC_LOG, logger,
			    "%s IKE socket MSG_ERRQUEUEs",
			    pluto_sock_errqueue ? "enabling" : "disabling");
		dbg_whack(s, "stop: ike_sock_err_toggle !%s", bool_str(pluto_sock_errqueue));
	}

	/* process "listen" before any operation that could require it */
	if (m->whack_listen) {
		dbg_whack(s, "start: listen");
		do_whacklisten(logger);
		dbg_whack(s, "stop: listen");
	}

	if (m->whack_unlisten) {
		dbg_whack(s, "start: unlisten");
		llog(RC_LOG, logger, "no longer listening for IKE messages");
		listening = false;
		dbg_whack(s, "stop: unlisten");
	}

	if (m->whack_ddos != DDOS_undefined) {
		dbg_whack(s, "start: ddos %d", m->whack_ddos);
		set_whack_pluto_ddos(m->whack_ddos, logger);
		dbg_whack(s, "stop: ddos %d", m->whack_ddos);
	}

	if (m->whack_ddns) {
		dbg_whack(s, "start: ddns %d", m->whack_ddns);
		llog(RC_LOG, logger, "updating pending dns lookups");
		connection_check_ddns(show_logger(s));
		dbg_whack(s, "stop: ddns %d", m->whack_ddns);
	}

	if (m->whack_reread & REREAD_SECRETS) {
		dbg_whack(s, "start: reread & REREAD_SECRETS");
		load_preshared_secrets(show_logger(s));
		dbg_whack(s, "stop: reread & REREAD_SECRETS");
	}

	if (m->whack_listpubkeys) {
		dbg_whack(s, "start: listpubkeys");
		show_pubkeys(s, m->whack_utc, SHOW_ALL_KEYS);
		dbg_whack(s, "stop: list & LIST_PUBKEYS");
	}

	if (m->whack_checkpubkeys) {
		dbg_whack(s, "start: checkpubkeys");
		show_pubkeys(s, m->whack_utc, SHOW_EXPIRED_KEYS);
		dbg_whack(s, "stop: check_pubkeys");
	}

	if (m->whack_purgeocsp) {
		dbg_whack(s, "start: purgeocsp");
		clear_ocsp_cache();
		dbg_whack(s, "stop: purgeocsp");
	}

	if (m->whack_reread & REREAD_CRLS) {
		llog(RC_LOG_SERIOUS, logger,
		     "ipsec whack: rereadcrls command obsoleted did you mean ipsec whack --fetchcrls");
	}

#if defined(LIBCURL) || defined(LIBLDAP)
	if (m->whack_reread & REREAD_FETCH) {
		dbg_whack(s, "start: reread & REREAD_FETCH");
		submit_crl_fetch_requests(NULL, logger);
		dbg_whack(s, "stop: reread & REREAD_FETCH");
	}
#endif

	if (m->whack_reread & REREAD_CERTS) {
		dbg_whack(s, "start: reread & REREAD_CERTS");
		reread_cert_connections(logger);
		dbg_whack(s, "stop: reread & REREAD_CERTS");
	}

	if (m->whack_list & LIST_PSKS) {
		dbg_whack(s, "start: list & LIST_PSKS");
		list_psks(s);
		dbg_whack(s, "stop: list & LIST_PSKS");
	}

	if (m->whack_list & LIST_CERTS) {
		dbg_whack(s, "start: list & LIST_CERTS");
		list_certs(s);
		dbg_whack(s, "stop: list & LIST_CERTS");
	}

	if (m->whack_list & LIST_CACERTS) {
		dbg_whack(s, "start: list & LIST_CACERTS");
		list_authcerts(s);
		dbg_whack(s, "stop: list & LIST_CACERTS");
	}

	if (m->whack_list & LIST_CRLS) {
		dbg_whack(s, "start: list & LIST_CRLS");
		list_crls(s);
#if defined(LIBCURL) || defined(LIBLDAP)
		list_crl_fetch_requests(s, m->whack_utc);
#endif
		dbg_whack(s, "stop: list & LIST_CRLS");
	}

	if (m->whack_list & LIST_EVENTS) {
		dbg_whack(s, "start: list & LIST_EVENTS");
		list_timers(s, now);
		list_state_events(s, now);
		dbg_whack(s, "stop: list & LIST_EVENTS");
	}

	if (m->whack_key) {
		dbg_whack(s, "start: key");
		/* add a public key */
		key_add_request(m, show_logger(s));
		dbg_whack(s, "stop: key");
	}

	if (m->whack_route) {
		dbg_whack(s, "start: route");
		if (!listening) {
			whack_log(RC_DEAF, whackfd,
				  "need --listen before --route");
		} else {
			struct connection *c = conn_by_name(m->name, true/*strict*/);

			if (c != NULL) {
				whack_route_connection(c, NULL, logger);
			} else if (0 == foreach_connection_by_alias(m->name, whack_route_connection,
								    NULL, logger)) {
				whack_log(RC_ROUTE, whackfd,
					  "no connection or alias '%s'",
					  m->name);
			}
		}
		dbg_whack(s, "stop: route");
	}

	if (m->whack_unroute) {
		dbg_whack(s, "start: unroute");
		passert(m->name != NULL);

		struct connection *c = conn_by_name(m->name, true/*strict*/);
		if (c != NULL) {
			whack_unroute_connection(c, whackfd, NULL);
		} else if (0 == foreach_connection_by_alias(m->name, whack_unroute_connection,
							    NULL, logger)) {
			whack_log(RC_ROUTE, whackfd,
				  "no connection or alias '%s'",
				  m->name);
		}
		dbg_whack(s, "stop: unroute");
	}

	if (m->whack_initiate) {
		dbg_whack(s, "start: initiate name='%s' remote='%s' async=%s",
			  m->name != NULL ? m->name : "<null>",
			  m->remote_host != NULL ? m->remote_host : "<null>",
			  bool_str(m->whack_async));
		if (!listening) {
			whack_log(RC_DEAF, whackfd,
				  "need --listen before --initiate");
		} else {
			ip_address testip;
			const char *oops;
			bool pass_remote = false;

			if (m->remote_host != NULL) {
				oops = ttoaddress_dns(shunk1(m->remote_host), NULL/*UNSPEC*/, &testip);

				if (oops != NULL) {
					whack_log(RC_NOPEERIP, whackfd,
						  "remote host IP address '%s' is invalid: %s",
						  m->remote_host, oops);
				} else {
					pass_remote = true;
				}
			}
			initiate_connections_by_name(m->name, pass_remote ? m->remote_host : NULL,
						     m->whack_async, logger);
		}
		dbg_whack(s, "stop: initiate");
	}

	if (m->whack_oppo_initiate) {
		dbg_whack(s, "start: oppo_initiate");
		if (!listening) {
			whack_log(RC_DEAF, whackfd,
				  "need --listen before opportunistic initiation");
		} else {
			const ip_protocol *protocol = protocol_by_ipproto(m->oppo.ipproto);
			ip_packet packet = packet_from_raw(HERE,
							   address_type(&m->oppo.local.address),
							   &m->oppo.local.address.bytes,
							   &m->oppo.remote.address.bytes,
							   protocol,
							   m->oppo.local.port,
							   m->oppo.remote.port);
			initiate_ondemand(&packet,
					  /*by_acquire*/false,
					  /*background*/m->whack_async,
					  null_shunk, logger);
		}
		dbg_whack(s, "stop: oppo_initiate");
	}

	if (m->whack_terminate) {
		dbg_whack(s, "start: terminate");
		passert(m->name != NULL);
		terminate_connections_by_name(m->name, /*quiet?*/true, logger);
		dbg_whack(s, "stop: terminate");
	}

	if (m->whack_status) {
		dbg_whack(s, "start: status");
		show_status(s);
		dbg_whack(s, "stop: status");
	}

	if (m->whack_global_status) {
		dbg_whack(s, "start: globalstatus");
		show_global_status(s);
		dbg_whack(s, "stop: globalstatus");
	}

	if (m->whack_clear_stats) {
		dbg_whack(s, "start: clearstats");
		clear_pluto_stats();
		dbg_whack(s, "stop: clearstats");
	}

	if (m->whack_traffic_status) {
		dbg_whack(s, "start: trafficstatus");
		show_traffic_status(s, m->name);
		dbg_whack(s, "stop: trafficstatus");
	}

	if (m->whack_shunt_status) {
		dbg_whack(s, "start: shuntstatus");
		show_shunt_status(s);
		dbg_whack(s, "stop: shuntstatus");
	}

	if (m->whack_fips_status) {
		dbg_whack(s, "start: fipsstatus");
		show_fips_status(s);
		dbg_whack(s, "stop: fipsstatus");
	}

	if (m->whack_brief_status) {
		dbg_whack(s, "start: briefstatus");
		show_brief_status(s);
		dbg_whack(s, "stop: briefstatus");
	}

	if (m->whack_process_status) {
		dbg_whack(s, "processstatus...");
		show_process_status(s);
		dbg_whack(s, "...processstatus");
	}

	if (m->whack_addresspool_status) {
		dbg_whack(s, "start: addresspoolstatus");
		show_addresspool_status(s);
		dbg_whack(s, "stop: addresspoolstatus");
	}

	if (m->whack_show_states) {
		dbg_whack(s, "start: showstates");
		show_states(s);
		dbg_whack(s, "stop: showstates");
	}

#ifdef HAVE_SECCOMP
	if (m->whack_seccomp_crashtest) {
		dbg_whack(s, "start: seccomp_crashtest");
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
			llog(RC_LOG_SERIOUS, logger,
				    "pluto is running with seccomp=enabled! pluto is expected to die!");
		llog(RC_LOG_SERIOUS, logger, "Performing seccomp security test using getsid() syscall");
		pid_t testpid = getsid(0);

		/* We did not get shot by the kernel seccomp protection */
		if (testpid == -1) {
			llog(RC_LOG_SERIOUS, logger,
				    "pluto: seccomp test syscall was blocked");
			switch (pluto_seccomp_mode) {
			case SECCOMP_TOLERANT:
				llog(RC_LOG_SERIOUS, logger,
					    "OK: seccomp security was tolerant; the rogue syscall was blocked and pluto was not terminated");
				break;
			case SECCOMP_DISABLED:
				llog(RC_LOG_SERIOUS, logger,
					    "OK: seccomp security was not enabled and the rogue syscall was blocked");
				break;
			case SECCOMP_ENABLED:
				llog(RC_LOG_SERIOUS, logger,
					    "ERROR: pluto seccomp was enabled but the rogue syscall did not terminate pluto!");
				break;
			default:
				bad_case(pluto_seccomp_mode);
			}
		} else {
			llog(RC_LOG_SERIOUS, logger,
				    "pluto: seccomp test syscall was not blocked");
			switch (pluto_seccomp_mode) {
			case SECCOMP_TOLERANT:
				llog(RC_LOG_SERIOUS, logger,
					    "ERROR: pluto seccomp was tolerant but the rogue syscall was not blocked!");
				break;
			case SECCOMP_DISABLED:
				llog(RC_LOG_SERIOUS, logger,
					    "OK: pluto seccomp was disabled and the rogue syscall was not blocked");
				break;
			case SECCOMP_ENABLED:
				llog(RC_LOG_SERIOUS, logger,
					    "ERROR: pluto seccomp was enabled but the rogue syscall was not blocked!");
				break;
			default:
				bad_case(pluto_seccomp_mode);
			}
		}
		dbg_whack(s, "stop: seccomp_crashtest");
	}
#endif

	/* luckly last !?! */
	if (m->whack_shutdown) {
		dbg_whack(s, "start: shutdown");
		shutdown_pluto(logger, m->whack_leave_state ? PLUTO_EXIT_LEAVE_STATE : PLUTO_EXIT_OK);
		dbg_whack(s, "stop: shutdown");
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

		/* XXX: something better? */
		struct logger whack_logger = *global_logger;
		whack_logger.global_whackfd = whackfd;
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
	struct whack_message msg = { .magic = 0, };

	ssize_t n = fd_read(whackfd, &msg, sizeof(msg));
	if (n <= 0) {
		log_errno(whack_logger, -(int)n,
			  "read() failed in whack_handle()");
		return;
	}

	static uintmax_t msgnum;
	DBGF(DBG_TMI, "whack message %ju; size=%zd", msgnum++, n);

	/* sanity check message */
	if ((size_t)n < offsetof(struct whack_message, whack_shutdown) + sizeof(msg.whack_shutdown)) {
		llog(RC_BADWHACKMESSAGE, whack_logger,
			    "ignoring runt message from whack: got %zd bytes", n);
		return;
	}

	/*
	 * XXX:
	 *
	 * I'm guessing to ensure upgrades work and a new whack can
	 * shutdown an old pluto, the code below reads .whack_shutdown
	 * regardless of the value of .magic.
	 *
	 * The assumption seems to be that the opening stanza of
	 * struct whack_message doesn't change so reading the
	 * .whack_shutdown field is robust.
	 *
	 * Except it isn't.
	 *
	 * The opening stanza of struct whack_message has changed (for
	 * instance adding FIPS status et.al.) moving
	 * .whack_shutdown's offset.  There's even a comment in
	 * comment in whack.h ("If you change anything earlier in this
	 * struct, update WHACK_BASIC_MAGIC.").  So if .magic isn't
	 * WHACK_MAGIC, .whack_shutdown is probably wrong, and when it
	 * also isn't WHACK_BASIC_MAGIC, it is definitely wrong.
	 */

	if (msg.magic != WHACK_MAGIC) {

		if (msg.whack_shutdown) {
			llog(RC_LOG, whack_logger, "shutting down%s",
				    (msg.magic != WHACK_BASIC_MAGIC) ?  " despite whacky magic" : "");
			/* magic invalid; msg.whack_leave_state is untouchable */
			shutdown_pluto(whack_logger, PLUTO_EXIT_OK);
			return; /* force shutting down */
		}

		if (msg.magic == WHACK_BASIC_MAGIC) {
			/* Only basic commands.  Simpler inter-version compatibility. */
			if (msg.whack_status) {
				struct show *s = alloc_show(whack_logger);
				show_status(s);
				free_show(&s);
			}
			/* bail early, but without complaint */
			return; /* don't shutdown */
		}

		llog(RC_BADWHACKMESSAGE, whack_logger,
			    "ignoring message from whack with bad magic %d; should be %d; Mismatched versions of userland tools.",
			    msg.magic, WHACK_MAGIC);
		return; /* bail (but don't shutdown) */
	}

	struct whackpacker wp = {
		.msg = &msg,
		.n = n,
		.str_next = msg.string,
		.str_roof = (unsigned char *)&msg + n,
	};

	if (!unpack_whack_msg(&wp, whack_logger)) {
		/* already logged */
		return; /* don't shutdown */
	}

	struct show *s = alloc_show(whack_logger);
	whack_process(&msg, s);
	free_show(&s);
}
