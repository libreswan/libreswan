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
#include "pluto_crypt.h"  /* for pluto_crypto_req & pluto_crypto_req_cont */
#include "ikev2.h"
#include "ikev2_redirect.h"
#include "ikev2_delete.h"
#include "ikev2_liveness.h"
#include "ikev2_rekey.h"
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

#ifdef USE_XFRM_INTERFACE
# include "kernel_xfrm_interface.h"
#endif
#include "addresspool.h"

#include "pluto_stats.h"
#include "state_db.h"

#include "nss_cert_reread.h"
#include "send.h"			/* for impair: send_keepalive() */
#include "pluto_shutdown.h"		/* for exit_pluto() */

static struct state *find_impaired_state(unsigned biased_what, struct fd *whackfd)
{
	if (biased_what == 0) {
		log_global(RC_COMMENT, whackfd,
			   "state 'no' is not valid");
		return NULL;
	}
	so_serial_t so = biased_what - 1; /* unbias */
	struct state *st = state_by_serialno(so);
	if (st == NULL) {
		log_global(RC_COMMENT, whackfd,
			   "state #%lu not found", so);
		return NULL;
	}
	return st;
}

static struct logger attach_logger(struct state *st, bool background, struct fd *whackfd)
{
	/* so errors go to whack and file regardless of BACKGROUND */
	struct logger logger = *st->st_logger;
	logger.global_whackfd = whackfd;
	if (!background) {
		/* XXX: something better */
		close_any(&st->st_logger->object_whackfd);
		st->st_logger->object_whackfd = dup_any(whackfd);
	}
	return logger;
}

static void whack_impair_action(enum impair_action action, unsigned event,
				unsigned biased_what, bool background, struct fd *whackfd)
{
	switch (action) {
	case CALL_IMPAIR_UPDATE:
		/* err... */
		break;
	case CALL_GLOBAL_EVENT:
		call_global_event_inline(event, whackfd);
		break;
	case CALL_STATE_EVENT:
	{
		struct state *st = find_impaired_state(biased_what, whackfd);
		if (st == NULL) {
			/* already logged */
			return;
		}
		/* will log */
		struct logger logger = attach_logger(st, background, whackfd);
		call_state_event_inline(&logger, st, event);
		break;
	}
	case CALL_INITIATE_v2_LIVENESS:
	{
		struct state *st = find_impaired_state(biased_what, whackfd);
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
		struct logger logger = attach_logger(&ike->sa, background, whackfd);
		log_message(RC_COMMENT, &logger, "initiating liveness");
		initiate_v2_liveness(&logger, ike);
		break;
	}
	case CALL_INITIATE_v2_DELETE:
	{
		struct state *st = find_impaired_state(biased_what, whackfd);
		if (st == NULL) {
			/* already logged */
			return;
		}
		/* will log */
		attach_logger(st, background, whackfd);
		initiate_v2_delete(ike_sa(st, HERE), st);
		break;
	}
	case CALL_INITIATE_v2_REKEY:
	{
		struct state *st = find_impaired_state(biased_what, whackfd);
		if (st == NULL) {
			/* already logged */
			return;
		}
		/* will log */
		attach_logger(st, background, whackfd);
		initiate_v2_rekey(ike_sa(st, HERE), st);
		break;
	}
	case CALL_SEND_KEEPALIVE:
	{
		struct state *st = find_impaired_state(biased_what, whackfd);
		if (st == NULL) {
			/* already logged */
			return;
		}
		/* will log */
		struct logger logger = attach_logger(st, true/*background*/, whackfd);
		log_message(RC_COMMENT, &logger, "sending keepalive");
		send_keepalive(st, "inject keep-alive");
		break;
	}
	case CALL_IMPAIR_DROP_INCOMING:
	case CALL_IMPAIR_DROP_OUTGOING:
	{
		struct logger logger = GLOBAL_LOGGER(whackfd);
		/* will log */
		add_message_impairment(biased_what - 1, action, &logger);
		break;
	}
	}
}

static int whack_route_connection(struct connection *c,
				  struct fd *whackfd,
				  void *unused_arg UNUSED)
{
	if (!oriented(*c)) {
		/* XXX: why whack only? */
		log_connection(RC_ORIENT|WHACK_STREAM, whackfd, c,
			       "we cannot identify ourselves with either end of this connection");
	} else if (c->policy & POLICY_GROUP) {
		route_group(whackfd, c);
	} else if (!trap_connection(c, whackfd)) {
		/* XXX: why whack only? */
		log_connection(RC_ROUTE|WHACK_STREAM, whackfd, c, "could not route");
	}
	return 1;
}

static int whack_unroute_connection(struct connection *c,
				    struct fd *whackfd,
				    void *unused_arg UNUSED)
{
	const struct spd_route *sr;
	int fail = 0;

	passert(c != NULL);

	for (sr = &c->spd; sr != NULL; sr = sr->spd_next) {
		if (sr->routing >= RT_ROUTED_TUNNEL)
			fail++;
	}
	if (fail > 0) {
		whack_log(RC_RTBUSY, whackfd,
			  "cannot unroute: route busy");
	} else if (c->policy & POLICY_GROUP) {
		unroute_group(c);
	} else {
		unroute_connection(c);
	}

	return 1;
}

static void do_whacklisten(struct fd *whackfd)
{
	struct logger logger[1] = { GLOBAL_LOGGER(whackfd), };
	fflush(stderr);
	fflush(stdout);
#ifdef USE_SYSTEMD_WATCHDOG
	pluto_sd(PLUTO_SD_RELOADING, SD_REPORT_NO_STATUS);
#endif
	log_message(RC_LOG, logger, "listening for IKE messages");
	listening = true;
	find_ifaces(true /* remove dead interfaces */, whackfd);
#ifdef USE_XFRM_INTERFACE
	stale_xfrmi_interfaces(logger);
#endif
	load_preshared_secrets(logger);
	load_groups(whackfd);
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
		log_message(RC_LOG_SERIOUS, logger,
			    "error: key to add is empty (needs DNS lookup?)");
		return;
	}

	struct id keyid;
	err_t ugh = atoid(msg->keyid, &keyid); /* must free keyid */
	if (ugh != NULL) {
		log_message(RC_BADID, logger, "bad --keyid \"%s\": %s", msg->keyid, ugh);
		return;
	}

	/* if no --addkey: delete any preexisting keys */
	if (!msg->whack_addkey) {
		if (!given_key) {
			/* XXX: this gets called by "add" so be silent */
			log_message(LOG_STREAM/*not-whack*/,
				    logger, "delete keyid %s", msg->keyid);
		}
		delete_public_keys(&pluto_pubkeys, &keyid, type);
		/* XXX: what about private keys; suspect not easy as not 1:1? */
	}

	/* if a key was given: add it */
	if (given_key) {
		/* XXX: this gets called by "add" so be silent */
		log_message(LOG_STREAM/*not-whack*/, logger,
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
			log_message(RC_LOG_SERIOUS, logger, "%s", ugh);
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
			log_message(RC_LOG|LOG_STREAM/*not-whack-for-now*/, logger,
				    "loaded private key matching CKAID %s",
				    str_ckaid(ckaid, &ckb));
		}
	}
	free_id_content(&keyid);
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
	 * => use log_message() (or log_show() wrapper?) so failing
	 * whack requests leave a breadcrumb in the main whack log.
	 *
	 * => use show_*() because the good output is for whack
	 */
	struct fd *whackfd = show_logger(s)->global_whackfd;

	/*
	 * May be needed in future:
	 * const struct lsw_conf_options *oco = lsw_init_options();
	 *
	 * XXX: why?
	 */
	if (m->whack_options) {
		dbg("whack: options (impair|debug)");
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
					jam_enum_lset_short(buf, &debug_names,
							    "+", old_debugging);
					jam(buf, " + ");
					jam_lmod(buf, &debug_names, "+", m->debugging);
				}
				LSWDBGP(DBG_BASE, buf) {
					jam(buf, "new debugging = ");
					jam_enum_lset_short(buf, &debug_names,
							    "+", new_debugging);
				}
				set_debugging(new_debugging);
				struct logger global_logger = GLOBAL_LOGGER(whackfd);
				for (unsigned i = 0; i < m->nr_impairments; i++) {
					process_impair(&m->impairments[i],
						       whack_impair_action,
						       m->whack_async/*background*/,
						       whackfd, &global_logger);
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
	}

	if (m->whack_rekey_ike) {
		dbg("whack: rekey_ike '%s'", m->name == NULL ? "NULL" : m->name);
		if (m->name == NULL) {
			/* leave bread crumb */
			log_global(RC_FATAL, whackfd,
				   "received whack command to rekey IKE SA of connection, but did not receive the connection name or state number - ignored");
		} else {
			rekey_now(m->name, IKE_SA, whackfd,
				  m->whack_async/*background*/);
		}
	}

	if (m->whack_rekey_ipsec) {
		dbg("whack: rekey_ipsec '%s'", m->name == NULL ? "NULL" : m->name);
		if (m->name == NULL) {
			/* leave bread crumb */
			log_global(RC_FATAL, whackfd,
				   "received whack command to rekey IPsec SA of connection, but did not receive the connection name or state number - ignored");
		} else {
			rekey_now(m->name, IPSEC_SA, whackfd,
				  m->whack_async/*background*/);
		}
	}

	/* Deleting combined with adding a connection works as replace.
	 * To make this more useful, in only this combination,
	 * delete will silently ignore the lack of the connection.
	 */
	if (m->whack_delete) {
		dbg("whack: delete '%s'", m->name == NULL ? "NULL" : m->name);
		if (m->name == NULL) {
			whack_log(RC_FATAL, whackfd,
				  "received whack command to delete a connection, but did not receive the connection name - ignored");
		} else {
			terminate_connection(m->name, true, whackfd);
			delete_connections_by_name(m->name, !m->whack_connection, whackfd);
		}
	}

	if (m->whack_deleteuser) {
		dbg("whack: deleteuser '%s'", m->name == NULL ? "NULL" : m->name);
		if (m->name == NULL ) {
			whack_log(RC_FATAL, whackfd,
				  "received whack command to delete a connection by username, but did not receive the username - ignored");
		} else {
			plog_global("received whack to delete connection by user %s",
				    m->name);
			for_each_state(v1_delete_state_by_username, m->name,
				       __func__);
		}
	}

	if (m->whack_deleteid) {
		dbg("whack: deleteid '%s'", m->name == NULL ? "NULL" : m->name);
		if (m->name == NULL ) {
			whack_log(RC_FATAL, whackfd,
				  "received whack command to delete a connection by id, but did not receive the id - ignored");
		} else {
			plog_global("received whack to delete connection by id %s",
				    m->name);
			for_each_state(delete_state_by_id_name, m->name, __func__);
		}
	}

	if (m->whack_deletestate) {
		dbg("whack: deletestate #%lu", m->whack_deletestateno);
		struct state *st =
			state_with_serialno(m->whack_deletestateno);

		if (st == NULL) {
			log_global(RC_UNKNOWN_NAME, whackfd, "no state #%lu to delete",
				   m->whack_deletestateno);
		} else {
			set_cur_state(st);
			/* needs an abstraction */
			close_any(&st->st_logger->global_whackfd);
			st->st_logger->global_whackfd = dup_any(whackfd);
			log_state(LOG_STREAM/*not-whack*/, st,
				  "received whack to delete %s state #%lu %s",
				  enum_name(&ike_version_names, st->st_ike_version),
				  st->st_serialno,
				  st->st_state->name);

			if ((st->st_ike_version == IKEv2) && !IS_CHILD_SA(st)) {
				log_state(LOG_STREAM/*not-whack*/, st,
					  "Also deleting any corresponding CHILD_SAs");
				delete_ike_family(pexpect_ike_sa(st),
						  PROBABLY_SEND_DELETE);
				st = NULL;
				/* note: no md->st to clear */
			} else {
				delete_state(st);
				st = NULL;
				/* note: no md->st to clear */
			}
		}
	}

	if (m->whack_crash) {
		address_buf pb;
		dbg("whack: crash %s", str_address(&m->whack_crash_peer, &pb));
		delete_states_by_peer(whackfd, &m->whack_crash_peer);
	}

	if (m->whack_connection) {
		dbg("whack: connection '%s'", m->name == NULL ? "NULL" : m->name);
		add_connection(whackfd, m);
	}

	if (m->active_redirect_dests != NULL) {
		dbg("whack: active_redirect_dests '%s'", m->name == NULL ? "NULL" : m->name);
		/*
		 * we are redirecting all peers of one or all connections
		 */
		find_states_and_redirect(m->name, m->active_redirect_dests, whackfd);
	}

	/* update any socket buffer size before calling listen */
	if (m->ike_buf_size != 0) {
		dbg("whack: ike_buf_size %lu", m->ike_buf_size);
		pluto_sock_bufsize = m->ike_buf_size;
		libreswan_log("Set IKE socket buffer to %d", pluto_sock_bufsize);
	}

	/* update MSG_ERRQUEUE setting before size before calling listen */
	if (m->ike_sock_err_toggle) {
		dbg("whack: ike_sock_err_toggle !%s", bool_str(pluto_sock_errqueue));
		pluto_sock_errqueue = !pluto_sock_errqueue;
		libreswan_log("%s IKE socket MSG_ERRQUEUEs",
			pluto_sock_errqueue ? "Enabling" : "Disabling");
	}

	/* process "listen" before any operation that could require it */
	if (m->whack_listen) {
		dbg("whack: listen");
		do_whacklisten(whackfd);
	}

	if (m->whack_unlisten) {
		dbg("whack: unlisten");
		libreswan_log("no longer listening for IKE messages");
		listening = FALSE;
	}

	if (m->whack_ddos != DDOS_undefined) {
		dbg("whack: ddos %d", m->whack_ddos);
		set_whack_pluto_ddos(m->whack_ddos);
	}

	if (m->whack_ddns) {
		dbg("whack: ddns %d", m->whack_ddns);
		libreswan_log("updating pending dns lookups");
		connection_check_ddns(whackfd);
	}

	if (m->whack_reread & REREAD_SECRETS) {
		dbg("whack: ddns");
		load_preshared_secrets(show_logger(s));
	}

	if (m->whack_list & LIST_PUBKEYS) {
		dbg("whack: list");
		list_public_keys(s, m->whack_utc,
				 m->whack_check_pub_keys);
	}

	if (m->whack_purgeocsp) {
		dbg("whack: purgeocsp");
		clear_ocsp_cache();
	}

	if (m->whack_reread & REREAD_CRLS) {
		loglog(RC_LOG_SERIOUS, "ipsec whack: rereadcrls command obsoleted did you mean ipsec whack --fetchcrls");
	}

#if defined(LIBCURL) || defined(LIBLDAP)
	if (m->whack_reread & REREAD_FETCH) {
		dbg("whack: reread & FETCH");
		add_crl_fetch_requests(NULL);
	}
#endif

	if (m->whack_reread & REREAD_CERTS) {
		dbg("whack: reread & CERTS");
		reread_cert_connections(whackfd);
	}

	if (m->whack_list & LIST_PSKS) {
		dbg("whack: list & PSKS");
		list_psks(s);
	}

	if (m->whack_list & LIST_CERTS) {
		dbg("whack: list & CERTS");
		list_certs(s);
	}

	if (m->whack_list & LIST_CACERTS) {
		dbg("whack: list & CACERTS");
		list_authcerts(s);
	}

	if (m->whack_list & LIST_CRLS) {
		dbg("whack: list & CRLS");
		list_crls(whackfd);
#if defined(LIBCURL) || defined(LIBLDAP)
		list_crl_fetch_requests(whackfd, m->whack_utc);
#endif
	}

	if (m->whack_list & LIST_EVENTS) {
		dbg("whack: list & EVENTS");
		list_timers(s, now);
		list_state_events(s, now);
	}

	if (m->whack_key) {
		dbg("whack: key");
		/* add a public key */
		key_add_request(m, show_logger(s));
	}

	if (m->whack_route) {
		dbg("whack: route");
		if (!listening) {
			whack_log(RC_DEAF, whackfd,
				  "need --listen before --route");
		} else {
			struct connection *c = conn_by_name(m->name, true/*strict*/);

			if (c != NULL) {
				whack_route_connection(c, whackfd, NULL);
			} else if (0 == foreach_connection_by_alias(m->name, whackfd,
								    whack_route_connection,
								    NULL)) {
				whack_log(RC_ROUTE, whackfd,
					  "no connection or alias '%s'",
					  m->name);
			}
		}
	}

	if (m->whack_unroute) {
		dbg("whack: unroute");
		passert(m->name != NULL);

		struct connection *c = conn_by_name(m->name, true/*strict*/);
		if (c != NULL) {
			whack_unroute_connection(c, whackfd, NULL);
		} else if (0 == foreach_connection_by_alias(m->name, whackfd,
							    whack_unroute_connection,
							    NULL)) {
			whack_log(RC_ROUTE, whackfd,
				  "no connection or alias '%s'",
				  m->name);
		}
	}

	if (m->whack_initiate) {
		dbg("whack: initiate");
		if (!listening) {
			whack_log(RC_DEAF, whackfd,
				  "need --listen before --initiate");
		} else {
			ip_address testip;
			const char *oops;
			bool pass_remote = FALSE;

			if (m->remote_host != NULL) {
				oops = ttoaddr(m->remote_host, 0, AF_UNSPEC, &testip);

				if (oops != NULL) {
					whack_log(RC_NOPEERIP, whackfd,
						  "remote host IP address '%s' is invalid: %s",
						  m->remote_host, oops);
				} else {
					pass_remote = TRUE;
				}
			}
			initiate_connections_by_name(m->name, pass_remote ? m->remote_host : NULL,
						     whackfd, m->whack_async);
		}
	}

	if (m->whack_oppo_initiate) {
		dbg("whack: oppo_initiate");
		if (!listening) {
			whack_log(RC_DEAF, whackfd,
				  "need --listen before opportunistic initiation");
		} else {
			initiate_ondemand(&m->oppo_my_client,
					  &m->oppo_peer_client, m->oppo_proto,
					  FALSE, whackfd, m->whack_async,
					  NULL, "whack");
		}
	}

	if (m->whack_terminate) {
		dbg("whack: terminate");
		passert(m->name != NULL);
		terminate_connection(m->name, true, whackfd);
	}

	if (m->whack_status) {
		dbg("whack: status");
		show_status(s);
	}

	if (m->whack_global_status) {
		dbg("whack: global_status");
		show_global_status(s);
	}

	if (m->whack_clear_stats) {
		dbg("whack: clear_stats");
		clear_pluto_stats();
	}

	if (m->whack_traffic_status) {
		dbg("whack: traffic_status");
		show_traffic_status(s, m->name);
	}

	if (m->whack_shunt_status) {
		dbg("whack: shunt_status");
		show_shunt_status(s);
	}

	if (m->whack_fips_status) {
		dbg("whack: fips_status");
		show_fips_status(s);
	}

	if (m->whack_brief_status) {
		dbg("whack: brief_status");
		show_brief_status(s);
	}
	if (m->whack_addresspool_status) {
		dbg("whack: addresspool_status");
		show_addresspool_status(s);
	}

	if (m->whack_show_states) {
		dbg("whack: show_states");
		show_states(s);
	}

#ifdef HAVE_SECCOMP
	if (m->whack_seccomp_crashtest) {
		dbg("whack: seccomp_crashtest");
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
			loglog(RC_LOG_SERIOUS, "pluto is running with seccomp=enabled! pluto is expected to die!");
		loglog(RC_LOG_SERIOUS, "Performing seccomp security test using getsid() syscall");
		pid_t testpid = getsid(0);

		/* We did not get shot by the kernel seccomp protection */
		if (testpid == -1) {
			loglog(RC_LOG_SERIOUS, "pluto: seccomp test syscall was blocked");
			switch (pluto_seccomp_mode) {
			case SECCOMP_TOLERANT:
				loglog(RC_LOG_SERIOUS, "OK: seccomp security was tolerant; the rogue syscall was blocked and pluto was not terminated");
				break;
			case SECCOMP_DISABLED:
				loglog(RC_LOG_SERIOUS, "OK: seccomp security was not enabled and the rogue syscall was blocked");
				break;
			case SECCOMP_ENABLED:
				loglog(RC_LOG_SERIOUS, "ERROR: pluto seccomp was enabled but the rogue syscall did not terminate pluto!");
				break;
			default:
				bad_case(pluto_seccomp_mode);
			}
		} else {
			loglog(RC_LOG_SERIOUS, "pluto: seccomp test syscall was not blocked");
			switch (pluto_seccomp_mode) {
			case SECCOMP_TOLERANT:
				loglog(RC_LOG_SERIOUS, "ERROR: pluto seccomp was tolerant but the rogue syscall was not blocked!");
				break;
			case SECCOMP_DISABLED:
				loglog(RC_LOG_SERIOUS, "OK: pluto seccomp was disabled and the rogue syscall was not blocked");
				break;
			case SECCOMP_ENABLED:
				loglog(RC_LOG_SERIOUS, "ERROR: pluto seccomp was enabled but the rogue syscall was not blocked!");
				break;
			default:
				bad_case(pluto_seccomp_mode);
			}
		}
	}
#endif

	if (m->whack_shutdown) {
		libreswan_log("shutting down");
		shutdown_pluto(whackfd, PLUTO_EXIT_OK);
		return; /* shutting down */
	}

	return; /* don't shut down */
}

static void whack_handle(struct fd *whackfd, struct logger *whack_logger);

void whack_handle_cb(evutil_socket_t fd, const short event UNUSED,
		     void *arg UNUSED)
{
	threadtime_t start = threadtime_start();
	{
		struct logger global_logger = GLOBAL_LOGGER(null_fd); /*no whack*/
		struct fd *whackfd = fd_accept(fd, HERE, &global_logger);
		if (whackfd == NULL) {
			/* already logged */
			return;
		}

		whack_log_fd = whackfd;
		struct logger whack_logger[1] = { GLOBAL_LOGGER(whackfd), };
		whack_handle(whackfd, whack_logger);
		whack_log_fd = null_fd;
		close_any(&whackfd);
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
		LOG_ERRNO(-(int)n, "read() failed in whack_handle()");
		return;
	}

	static uintmax_t msgnum;
	DBGF(DBG_TMI, "whack message %ju; size=%zd", msgnum++, n);

	/* sanity check message */
	if ((size_t)n < offsetof(struct whack_message, whack_shutdown) + sizeof(msg.whack_shutdown)) {
		log_message(RC_BADWHACKMESSAGE, whack_logger,
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
			log_message(RC_LOG, whack_logger, "shutting down%s",
				    (msg.magic != WHACK_BASIC_MAGIC) ?  " despite whacky magic" : "");
			shutdown_pluto(whackfd, PLUTO_EXIT_OK);
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

		log_message(RC_BADWHACKMESSAGE, whack_logger,
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
