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
 * Copyright (C) 2014-2019 Paul Wouters <pwouters@redhat.com>
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

#include "libreswan/pfkeyv2.h"

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
#include "peerlog.h"
#include "lswfips.h"
#include "keys.h"
#include "secrets.h"
#include "server.h"
#include "fetch.h"
#include "timer.h"
#include "pluto_crypt.h"  /* for pluto_crypto_req & pluto_crypto_req_cont */
#include "ikev2.h"
#include "ikev2_redirect.h"
#include "server.h" /* for pluto_seccomp */
#include "kernel_alg.h"
#include "ike_alg.h"
#include "ip_address.h" /* for setportof() */
#include "crl_queue.h"
#include "pluto_sd.h"
#include "initiate.h"

#ifdef USE_XFRM_INTERFACE
# include "xfrm_interface.h"
#endif

#include "pluto_stats.h"

/* bits loading keys from asynchronous DNS */

enum key_add_attempt {
	ka_TXT,
#ifdef USE_KEYRR
	ka_KEY,
#endif
	ka_roof /* largest value + 1 */
};

struct key_add_common {
	int refCount;
	char *diag[ka_roof];
	int whack_fd;
	bool success;
};

struct key_add_continuation {
	struct key_add_common *common;  /* common data */
	enum key_add_attempt lookingfor;
};

static int whack_route_connection(struct connection *c,
				  UNUSED void *arg)
{
	struct connection *old = push_cur_connection(c);

	if (!oriented(*c)) {
		/* XXX: why whack only? */
		log_connection(RC_ORIENT|WHACK_STREAM, c,
			       "we cannot identify ourselves with either end of this connection");
	} else if (c->policy & POLICY_GROUP) {
		route_group(c);
	} else if (!trap_connection(c)) {
		/* XXX: why whack only? */
		log_connection(RC_ROUTE|WHACK_STREAM, c, "could not route");
	}
	pop_cur_connection(old);
	return 1;
}

static int whack_unroute_connection(struct connection *c,
				    UNUSED void *arg)
{
	const struct spd_route *sr;
	int fail = 0;

	passert(c != NULL);
	set_cur_connection(c);

	for (sr = &c->spd; sr != NULL; sr = sr->spd_next) {
		if (sr->routing >= RT_ROUTED_TUNNEL)
			fail++;
	}
	if (fail > 0) {
		whack_log(RC_RTBUSY,
			"cannot unroute: route busy");
	} else if (c->policy & POLICY_GROUP) {
		unroute_group(c);
	} else {
		unroute_connection(c);
	}

	reset_cur_connection();
	return 1;
}

static void do_whacklisten(void)
{
	fflush(stderr);
	fflush(stdout);
	peerlog_close();    /* close any open per-peer logs */
#ifdef USE_SYSTEMD_WATCHDOG
	pluto_sd(PLUTO_SD_RELOADING, SD_REPORT_NO_STATUS);
#endif
	libreswan_log("listening for IKE messages");
	listening = TRUE;
	find_ifaces(TRUE /* remove dead interfaces */);
#ifdef USE_XFRM_INTERFACE
	stale_xfrmi_interfaces();
#endif
	load_preshared_secrets();
	load_groups();
#ifdef USE_SYSTEMD_WATCHDOG
	pluto_sd(PLUTO_SD_READY, SD_REPORT_NO_STATUS);
#endif
}

static void key_add_request(const struct whack_message *msg)
{
	plog_global("add keyid %s", msg->keyid);
	struct id keyid;
	err_t ugh = atoid(msg->keyid, &keyid, FALSE);

	if (ugh != NULL) {
		loglog(RC_BADID, "bad --keyid \"%s\": %s", msg->keyid, ugh);
	} else {
		if (!msg->whack_addkey)
			delete_public_keys(&pluto_pubkeys, &keyid,
					   pubkey_alg_type(msg->pubkey_alg));

		if (msg->keyval.len != 0) {
			DBG_dump_hunk("add pubkey", msg->keyval);
			ugh = add_public_key(&keyid, PUBKEY_LOCAL,
					     pubkey_alg_type(msg->pubkey_alg),
					     &msg->keyval, &pluto_pubkeys);
			if (ugh != NULL)
				loglog(RC_LOG_SERIOUS, "%s", ugh);
		} else {
				loglog(RC_LOG_SERIOUS, "error: Key without keylength from whack not added to key list (needs DNS lookup?)");
		}
	}
}

/*
 * handle a whack message.
 */
static bool whack_process(struct fd *whackfd, const struct whack_message *const m)
{
	/*
	 * May be needed in future:
	 * const struct lsw_conf_options *oco = lsw_init_options();
	 */
	if (m->whack_options) {
		switch (m->opt_set) {
		case WHACK_ADJUSTOPTIONS:
#ifdef FIPS_CHECK
			if (libreswan_fipsmode()) {
				if (lmod_is_set(m->debugging, DBG_PRIVATE)) {
					whack_log(RC_FATAL, "FIPS: --debug-private is not allowed in FIPS mode, aborted");
					return false; /*don't shutdown*/
				}
			}
#endif
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
				lset_t old_impairing = cur_debugging & IMPAIR_MASK;
				lset_t new_impairing = lmod(old_impairing, m->impairing);
				set_debugging(cur_debugging | new_debugging);
				LSWDBGP(DBG_CONTROL, buf) {
					lswlogs(buf, "old debugging ");
					lswlog_enum_lset_short(buf, &debug_names,
							       "+", old_debugging);
					lswlogs(buf, " + ");
					lswlog_lmod(buf, &debug_names,
						    "+", m->debugging);
				}
				LSWDBGP(DBG_CONTROL, buf) {
					lswlogs(buf, "new debugging = ");
					lswlog_enum_lset_short(buf, &debug_names,
							       "+", new_debugging);
				}
				LSWDBGP(DBG_CONTROL, buf) {
					lswlogs(buf, "old impairing ");
					lswlog_enum_lset_short(buf, &impair_names,
							       "+", old_impairing);
					lswlogs(buf, " + ");
					lswlog_lmod(buf, &impair_names,
						    "+", m->impairing);
				}
				LSWDBGP(DBG_CONTROL, buf) {
					lswlogs(buf, "new impairing = ");
					lswlog_enum_lset_short(buf, &impair_names,
							       "+", new_impairing);
				}
				set_debugging(new_debugging | new_impairing);
				process_impair(&m->impairment);
			} else if (!m->whack_connection) {
				struct connection *c = conn_by_name(m->name,
								   TRUE, FALSE);

				if (c != NULL) {
					c->extra_debugging = m->debugging;
					LSWDBGP(DBG_CONTROL, buf) {
						lswlogf(buf, "\"%s\" extra_debugging = ",
							c->name);
						lswlog_lmod(buf, &debug_names,
							    "+", c->extra_debugging);
					}
					c->extra_impairing = m->impairing;
					LSWDBGP(DBG_CONTROL, buf) {
						lswlogf(buf, "\"%s\" extra_impairing = ",
							c->name);
						lswlog_lmod(buf, &impair_names,
							    "+", c->extra_impairing);
					}
					process_impair(&m->impairment);
				}
			}
			break;

		case WHACK_SETDUMPDIR:
			/* XXX */
			break;

		}
	}

	if (m->whack_rekey_ike) {
		if (m->name == NULL)
			whack_log(RC_FATAL, "received whack command to rekey IKE SA of connection, but did not receive the connection name or state number - ignored");
		else
			rekey_now(m->name, IKE_SA);
	}

	if (m->whack_rekey_ipsec) {
		if (m->name == NULL)
			whack_log(RC_FATAL, "received whack command to rekey IPsec SA of connection, but did not receive the connection name or state number - ignored");
		else
			rekey_now(m->name, IPSEC_SA);
	}

	/* Deleting combined with adding a connection works as replace.
	 * To make this more useful, in only this combination,
	 * delete will silently ignore the lack of the connection.
	 */
	if (m->whack_delete) {
		if (m->name == NULL) {
			whack_log(RC_FATAL, "received whack command to delete a connection, but did not receive the connection name - ignored");
		} else {
			terminate_connection(m->name, TRUE);
			delete_connections_by_name(m->name, !m->whack_connection);
		}
	}

	if (m->whack_deleteuser) {
		if (m->name == NULL ) {
			whack_log(RC_FATAL, "received whack command to delete a connection by username, but did not receive the username - ignored");
		} else {
			plog_global("received whack to delete connection by user %s",
				    m->name);
			for_each_state(v1_delete_state_by_username, m->name,
				       __func__);
		}
	}

	if (m->whack_deleteid) {
		if (m->name == NULL ) {
			whack_log(RC_FATAL, "received whack command to delete a connection by id, but did not receive the id - ignored");
		} else {
			plog_global("received whack to delete connection by id %s",
				    m->name);
			for_each_state(delete_state_by_id_name, m->name, __func__);
		}
	}

	if (m->whack_deletestate) {
		struct state *st =
			state_with_serialno(m->whack_deletestateno);

		if (st == NULL) {
			loglog(RC_UNKNOWN_NAME, "no state #%lu to delete",
					m->whack_deletestateno);
		} else {
			set_cur_state(st);
			plog_state(st, "received whack to delete %s state #%lu %s",
				   enum_name(&ike_version_names, st->st_ike_version),
				   st->st_serialno,
				   st->st_state->name);

			if ((st->st_ike_version == IKEv2) && !IS_CHILD_SA(st)) {
				plog_state(st, "Also deleting any corresponding CHILD_SAs");
				delete_my_family(st, FALSE);
				/* note: no md->st to clear */
			} else {
				delete_state(st);
				/* note: no md->st to clear */
			}
		}
	}

	if (m->whack_crash)
		delete_states_by_peer(&m->whack_crash_peer);

	if (m->whack_connection) {
		add_connection(m);
	}

	if (m->active_redirect) {
		ipstr_buf b;
		char *redirect_gw;

		redirect_gw = clone_str(ipstr(&m->active_redirect_gw, &b),
				"active redirect gw ip");

		if (!isanyaddr(&m->active_redirect_peer)) {
			/* if we are redirecting one specific peer */
			find_states_and_redirect(NULL, m->active_redirect_peer, redirect_gw);
		} else {
			/* we are redirecting all peers of one connection */
			find_states_and_redirect(m->name, m->active_redirect_peer, redirect_gw);
		}
	}

	/* update any socket buffer size before calling listen */
	if (m->ike_buf_size != 0) {
		pluto_sock_bufsize = m->ike_buf_size;
		libreswan_log("Set IKE socket buffer to %d", pluto_sock_bufsize);
	}

	/* update MSG_ERRQUEUE setting before size before calling listen */
	if (m->ike_sock_err_toggle) {
		pluto_sock_errqueue = !pluto_sock_errqueue;
		libreswan_log("%s IKE socket MSG_ERRQUEUEs",
			pluto_sock_errqueue ? "Enabling" : "Disabling");
	}

	/* process "listen" before any operation that could require it */
	if (m->whack_listen)
		do_whacklisten();

	if (m->whack_unlisten) {
		libreswan_log("no longer listening for IKE messages");
		listening = FALSE;
	}

	if (m->whack_ddos != DDOS_undefined)
		set_whack_pluto_ddos(m->whack_ddos);

	if (m->whack_ddns) {
		libreswan_log("updating pending dns lookups");
		connection_check_ddns();
	}

	if (m->whack_reread & REREAD_SECRETS)
		load_preshared_secrets();

	if (m->whack_list & LIST_PUBKEYS)
		list_public_keys(whackfd, m->whack_utc,
				 m->whack_check_pub_keys);

	if (m->whack_purgeocsp)
		clear_ocsp_cache();

	if (m->whack_reread & REREAD_CRLS)
		loglog(RC_LOG_SERIOUS, "ipsec whack: rereadcrls command obsoleted did you mean ipsec whack --fetchcrls");

#if defined(LIBCURL) || defined(LIBLDAP)
	if (m->whack_reread & REREAD_FETCH)
		add_crl_fetch_requests(NULL);
#endif

	if (m->whack_list & LIST_PSKS)
		list_psks(whackfd);

	if (m->whack_list & LIST_CERTS)
		list_certs(whackfd);

	if (m->whack_list & LIST_CACERTS)
		list_authcerts(whackfd);

	if (m->whack_list & LIST_CRLS) {
		list_crls(whackfd);
#if defined(LIBCURL) || defined(LIBLDAP)
		list_crl_fetch_requests(whackfd, m->whack_utc);
#endif
	}

	if (m->whack_list & LIST_EVENTS)
		timer_list(whackfd);

	if (m->whack_key) {
		/* add a public key */
		key_add_request(m);
	}

	if (m->whack_route) {
		if (!listening) {
			whack_log(RC_DEAF, "need --listen before --route");
		} else {
			struct connection *c = conn_by_name(m->name,
							TRUE, TRUE);

			if (c != NULL) {
				whack_route_connection(c, NULL);
			} else if (0 == foreach_connection_by_alias(m->name,
						whack_route_connection,
						NULL)) {
				whack_log(RC_ROUTE,
					"no connection or alias '%s'",
					m->name);
			}
		}
	}

	if (m->whack_unroute) {
		passert(m->name != NULL);

		struct connection *c = conn_by_name(m->name, TRUE, TRUE);

		if (c != NULL) {
			whack_unroute_connection(c, NULL);
		} else if (0 == foreach_connection_by_alias(m->name,
						whack_unroute_connection,
						NULL)) {
			whack_log(RC_ROUTE,
				"no connection or alias '%s'",
				m->name);
		}
	}

	if (m->whack_initiate) {
		if (!listening) {
			whack_log(RC_DEAF, "need --listen before --initiate");
		} else {
			ip_address testip;
			const char *oops;
			bool pass_remote = FALSE;

			if (m->remote_host != NULL) {
				oops = ttoaddr(m->remote_host, 0, AF_UNSPEC, &testip);

				if (oops != NULL) {
					whack_log(RC_NOPEERIP, "remote host IP address '%s' is invalid: %s",
						m->remote_host, oops);
				} else {
					pass_remote = TRUE;
				}
			}
			initiate_connections_by_name(m->name, (m->whack_async ? null_fd : whackfd),
						     pass_remote ? m->remote_host : NULL);
		}
	}

	if (m->whack_oppo_initiate) {
		if (!listening) {
			whack_log(RC_DEAF,
				  "need --listen before opportunistic initiation");
		} else {
			initiate_ondemand(&m->oppo_my_client,
						&m->oppo_peer_client, m->oppo_proto,
						FALSE,
					  (m->whack_async ? null_fd : whackfd),
						NULL,
						"whack");
		}
	}

	if (m->whack_terminate) {
		passert(m->name != NULL);
		terminate_connection(m->name, TRUE);
	}

	if (m->whack_status)
		show_status(whackfd);

	if (m->whack_global_status)
		show_global_status(whackfd);

	if (m->whack_clear_stats)
		clear_pluto_stats();

	if (m->whack_traffic_status)
		show_traffic_status(m->name);

	if (m->whack_shunt_status)
		show_shunt_status(whackfd);

	if (m->whack_fips_status)
		show_fips_status(whackfd);

	if (m->whack_brief_status)
		show_states_status(whackfd, TRUE);

#ifdef HAVE_SECCOMP
	if (m->whack_seccomp_crashtest) {
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
		return true; /* shutting down */
	}

	return false; /* don't shut down */
}

static bool whack_handle(struct fd *whackfd);

void whack_handle_cb(evutil_socket_t fd, const short event UNUSED,
		     void *arg UNUSED)
{
	threadtime_t start = threadtime_start();
	{
		struct fd *whackfd = fd_accept(fd, HERE);
		if (whackfd == NULL) {
			/* already logged */
			return;
		}
		whack_log_fd = whackfd;
		bool shutdown = whack_handle(whackfd);
		whack_log_fd = null_fd;
		if (shutdown) {
			/*
			 * Leak the whack FD, when pluto finally exits
			 * it will be closed and whack released.
			 *
			 * Note that the above killed off whack_log_fd
			 * which means that the entire exit process is
			 * radio silent.
			 */
			fd_leak(&whackfd, HERE);
			/* XXX: shutdown the event loop */
			exit_pluto(PLUTO_EXIT_OK);
		} else {
			close_any(&whackfd);
		}
	}
	threadtime_stop(&start, SOS_NOBODY, "whack");
}

/*
 * Handle a whack request.
 */
static bool whack_handle(struct fd *whackfd)
{
	/*
	 * properly initialize msg - needed because short reads are
	 * sometimes OK
	 */
	struct whack_message msg = { .magic = 0, };

	ssize_t n = fd_read(whackfd, &msg, sizeof(msg), HERE);
	if (n <= 0) {
		LOG_ERRNO(errno, "read() failed in whack_handle()");
		return false; /* don't shutdown */
	}

	/* DBG_log("msg %d size=%u", ++msgnum, n); */

	/* sanity check message */
	{
		if ((size_t)n < offsetof(struct whack_message,
					 whack_shutdown) + sizeof(msg.whack_shutdown)) {
			loglog(RC_BADWHACKMESSAGE, "ignoring runt message from whack: got %zd bytes", n);
			return false; /* don't shutdown */
		}

		if (msg.magic != WHACK_MAGIC) {

			if (msg.whack_shutdown) {
				libreswan_log("shutting down%s",
				    (msg.magic != WHACK_BASIC_MAGIC) ?  " despite whacky magic" : "");
				return true; /* force shutting down */
			}

			if (msg.magic == WHACK_BASIC_MAGIC) {
				/* Only basic commands.  Simpler inter-version compatibility. */
				if (msg.whack_status)
					show_status(whackfd);
				/* bail early, but without complaint */
				return false; /* don't shutdown */
			}

			loglog(RC_BADWHACKMESSAGE, "ignoring message from whack with bad magic %d; should be %d; Mismatched versions of userland tools.",
			       msg.magic, WHACK_MAGIC);
			return false; /* bail (but don't shutdown) */
		}
	}

	struct whackpacker wp = {
		.msg = &msg,
		.n = n,
		.str_next = msg.string,
		.str_roof = (unsigned char *)&msg + n,
	};
	const char *ugh = unpack_whack_msg(&wp);
	if (ugh != NULL) {
		if (*ugh != '\0')
			loglog(RC_BADWHACKMESSAGE, "%s", ugh);
		return false; /* don't shutdown */
	}

	return whack_process(whackfd, &msg);
}
