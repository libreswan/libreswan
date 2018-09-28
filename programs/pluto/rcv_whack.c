
/*
 * hack communicating routines
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013-2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2011 Mika Ilmaranta <ilmis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2014-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2014-2017 Antony Antony <antony@phenome.org>
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

#include <libreswan.h>
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
#include "server.h" /* for pluto_seccomp */
#include "kernel_alg.h"
#include "ike_alg.h"
#include "ip_address.h" /* for setportof() */
#include "crl_queue.h"
#include "pluto_sd.h"

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
	set_cur_connection(c);

	if (!oriented(*c))
		whack_log(RC_ORIENT,
			"we cannot identify ourselves with either end of this connection");
	else if (c->policy & POLICY_GROUP)
		route_group(c);
	else if (!trap_connection(c))
		whack_log(RC_ROUTE, "could not route");

	reset_cur_connection();
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
	load_preshared_secrets();
	load_groups();
#ifdef USE_SYSTEMD_WATCHDOG
	pluto_sd(PLUTO_SD_READY, SD_REPORT_NO_STATUS);
#endif
}

static void key_add_request(const struct whack_message *msg)
{
	DBG_log("add keyid %s", msg->keyid);
	struct id keyid;
	err_t ugh = atoid(msg->keyid, &keyid, FALSE);

	if (ugh != NULL) {
		loglog(RC_BADID, "bad --keyid \"%s\": %s", msg->keyid, ugh);
	} else {
		if (!msg->whack_addkey)
			delete_public_keys(&pluto_pubkeys, &keyid,
					   msg->pubkey_alg);

		if (msg->keyval.len != 0) {
			DBG_dump_chunk("add pubkey", msg->keyval);
			ugh = add_public_key(&keyid, PUBKEY_LOCAL,
					     msg->pubkey_alg,
					     &msg->keyval, &pluto_pubkeys);
			if (ugh != NULL)
				loglog(RC_LOG_SERIOUS, "%s", ugh);
		} else {
				loglog(RC_LOG_SERIOUS, "error: Key without keylength from whack not added to key list (needs DNS lookup?)");
		}
	}
}
static char whackrecordname[PATH_MAX];
static FILE *whackrecordfile = NULL;

/*
 * writewhackrecord must match readwhackmsg.
 * Writes out 64 bits for time, even if we only have 32-bit time_t.
 */
static bool writewhackrecord(char *buf, size_t buflen)
{
	uint32_t header[3];	/* length, high time, low time */
	time_t now = time(NULL);

	/* round up buffer length */
	size_t abuflen = (buflen + sizeof(header[0]) - 1) & ~(sizeof(header[0]) - 1);

	/* bail if we aren't writing anything */
	if (whackrecordfile == NULL)
		return TRUE;

	header[0] = buflen + sizeof(header);
	header[1] = (now >> 16) >> 16;	/* >> 32 not legal on 32-bit systems */
	header[2] = now;	/* bottom 32 bits */

	/* DBG_log("buflen: %zu abuflen: %zu", buflen, abuflen); */

	if (fwrite(header, sizeof(header), 1, whackrecordfile) < 1)
		DBG_log("writewhackrecord: fwrite error when writing header");

	if (fwrite(buf, abuflen, 1, whackrecordfile) < 1)
		DBG_log("writewhackrecord: fwrite error when writing buf");

	return TRUE;
}

/*
 * we write out an empty record with the right WHACK magic.
 * this should permit a later mechanism to figure out the
 * endianness of the file, since we will get records from
 * other systems for analysis eventually.
 */
static bool openwhackrecordfile(char *file)
{
	char when[256];
	char FQDN[SWAN_MAX_DOMAIN_LEN];
	const uint32_t magic = WHACK_BASIC_MAGIC;

	strcpy(FQDN, "unknown host");
	gethostname(FQDN, sizeof(FQDN));

	jam_str(whackrecordname, sizeof(whackrecordname), file);
	whackrecordfile = fopen(whackrecordname, "w");
	if (whackrecordfile == NULL) {
		libreswan_log("Failed to open whack record file: '%s'",
			      whackrecordname);
		return FALSE;
	}

	struct realtm now = local_realtime(realnow());
	strftime(when, sizeof(when), "%F %T", &now.tm);

	fprintf(whackrecordfile, "#!-pluto-whack-file- recorded on %s on %s",
		FQDN, when);

	writewhackrecord((char *)&magic, sizeof(magic));

	DBG(DBG_CONTROL,
	    DBG_log("started recording whack messages to %s",
		    whackrecordname));
	return TRUE;
}


/*
 * handle a whack message.
 */
void whack_process(fd_t whackfd, const struct whack_message *const m)
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
					goto done;
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
					lswlogs(buf, "base debugging = ");
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
					lswlogs(buf, "base impairing = ");
					lswlog_enum_lset_short(buf, &impair_names,
							       "+", new_impairing);
				}
				base_debugging = new_debugging | new_impairing;
				set_debugging(base_debugging);
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

		case WHACK_STARTWHACKRECORD:
			/* close old filename */
			if (whackrecordfile != NULL) {
				DBG(DBG_CONTROL,
				    DBG_log("stopped recording whack messages to %s",
					    whackrecordname));
				fclose(whackrecordfile);
			}
			whackrecordfile = NULL;

			openwhackrecordfile(m->string1);

			/* do not do any other processing for these */
			goto done;

		case WHACK_STOPWHACKRECORD:
			if (whackrecordfile != NULL) {
				DBG(DBG_CONTROL,
				    DBG_log("stopped recording whack messages to %s",
					    whackrecordname));
				fclose(whackrecordfile);
			}
			whackrecordfile = NULL;
			/* do not do any other processing for these */
			goto done;
		}
	}

	/* Deleting combined with adding a connection works as replace.
	 * To make this more useful, in only this combination,
	 * delete will silently ignore the lack of the connection.
	 */
	if (m->whack_delete)
		delete_connections_by_name(m->name, !m->whack_connection);

	if (m->whack_deleteuser) {
		DBG_log("received whack to delete connection by user %s",
				m->name);
		for_each_state(v1_delete_state_by_username, m->name);
	}

	if (m->whack_deleteid) {
		DBG_log("received whack to delete connection by id %s",
				m->name);
		for_each_state(delete_state_by_id_name, m->name);
	}

	if (m->whack_deletestate) {
		struct state *st =
			state_with_serialno(m->whack_deletestateno);

		if (st == NULL) {
			loglog(RC_UNKNOWN_NAME, "no state #%lu to delete",
					m->whack_deletestateno);
		} else {
			set_cur_state(st);
			DBG_log("received whack to delete %s state #%lu %s",
				st->st_ikev2 ? "IKEv2" : "IKEv1",
				st->st_serialno,
				st->st_state_name);

			if (st->st_ikev2 && !IS_CHILD_SA(st)) {
				DBG_log("Also deleting any corresponding CHILD_SAs");
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

	if (m->whack_reread & REREAD_SECRETS)
		load_preshared_secrets();

	if (m->whack_list & LIST_PUBKEYS)
		list_public_keys(m->whack_utc, m->whack_check_pub_keys);

	if (m->whack_purgeocsp)
		clear_ocsp_cache();

	if (m->whack_reread & REREAD_CRLS)
		loglog(RC_LOG_SERIOUS, "ipsec whack: rereadcrls command obsoleted did you mean ipsec whack --fetchcrls");

#if defined(LIBCURL) || defined(LIBLDAP)
	if (m->whack_reread & REREAD_FETCH)
		add_crl_fetch_requests(NULL);
#endif

	if (m->whack_list & LIST_PSKS)
		list_psks();

	if (m->whack_list & LIST_CERTS)
		list_certs();

	if (m->whack_list & LIST_CACERTS)
		list_authcerts();

	if (m->whack_list & LIST_CRLS) {
		list_crls();
#if defined(LIBCURL) || defined(LIBLDAP)
		list_crl_fetch_requests(m->whack_utc);
#endif
	}

	if (m->whack_list & LIST_EVENTS)
		timer_list();

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
			initiate_connection(m->name,
					    (m->whack_async ?
					     null_fd :
					     dup_any(whackfd)),
					    m->debugging,
					    m->impairing,
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
						m->whack_async ?
						  null_fd :
						  dup_any(whackfd),
#ifdef HAVE_LABELED_IPSEC
						NULL,
#endif
						"whack");
		}
	}

	if (m->whack_terminate) {
		passert(m->name != NULL);
		terminate_connection(m->name);
	}

	if (m->whack_status)
		show_status();

	if (m->whack_global_status)
		show_global_status();

	if (m->whack_clear_stats)
		clear_pluto_stats();

	if (m->whack_traffic_status)
		show_traffic_status(m->name);

	if (m->whack_shunt_status)
		show_shunt_status();

	if (m->whack_fips_status)
		show_fips_status();

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
		exit_pluto(PLUTO_EXIT_OK); /* delete lock and leave, with 0 status */
	}

done:
	whack_log_fd = null_fd;
	close_any(&whackfd);
}

static void whack_handle(int kernelfd);

void whack_handle_cb(evutil_socket_t fd, const short event UNUSED,
		void *arg UNUSED)
{
		whack_handle(fd);
}

/*
 * Handle a whack request.
 */
static void whack_handle(int whackctlfd)
{
	struct whack_message msg, msg_saved;
	struct sockaddr_un whackaddr;
	socklen_t whackaddrlen = sizeof(whackaddr);
	fd_t whackfd = NEW_FD(accept(whackctlfd, (struct sockaddr *)&whackaddr,
				     &whackaddrlen));
	/* Note: actual value in n should fit in int.  To print, cast to int. */
	ssize_t n;

	/* static int msgnum=0; */

	if (!fd_p(whackfd)) {
		LOG_ERRNO(errno, "accept() failed in whack_handle()");
		return;
	}
	if (fcntl(whackfd.fd, F_SETFD, FD_CLOEXEC) < 0) {
		LOG_ERRNO(errno, "failed to set CLOEXEC in whack_handle()");
		close_any(&whackfd);
		return;
	}

	/*
	 * properly initialize msg
	 *
	 * - needed because short reads are sometimes OK
	 *
	 * - although struct whack_msg has pointer fields
	 *   they don't appear on the wire so zero() should work.
	 */
	zero(&msg);

	n = read(whackfd.fd, &msg, sizeof(msg));
	if (n <= 0) {
		LOG_ERRNO(errno, "read() failed in whack_handle()");
		close_any(&whackfd);
		return;
	}

	whack_log_fd = whackfd;

	msg_saved = msg;

	/* DBG_log("msg %d size=%u", ++msgnum, n); */

	/* sanity check message */
	{
		err_t ugh = NULL;
		struct whackpacker wp;

		wp.msg = &msg;
		wp.n   = n;
		wp.str_next = msg.string;
		wp.str_roof = (unsigned char *)&msg + n;

		if ((size_t)n <
		    offsetof(struct whack_message,
			     whack_shutdown) + sizeof(msg.whack_shutdown)) {
			ugh = builddiag(
				"ignoring runt message from whack: got %d bytes",
				(int)n);
		} else if (msg.magic != WHACK_MAGIC) {
			if (msg.whack_shutdown) {
				libreswan_log("shutting down%s",
				    (msg.magic != WHACK_BASIC_MAGIC) ?  " despite whacky magic" : "");
				exit_pluto(PLUTO_EXIT_OK);  /* delete lock and leave, with 0 status */
			}
			if (msg.magic == WHACK_BASIC_MAGIC) {
				/* Only basic commands.  Simpler inter-version compatibility. */
				if (msg.whack_status)
					show_status();

				ugh = "";               /* bail early, but without complaint */
			} else {
				ugh = builddiag(
					"ignoring message from whack with bad magic %d; should be %d; Mismatched versions of userland tools.",
					msg.magic, WHACK_MAGIC);
			}
		} else {
			ugh = unpack_whack_msg(&wp);
		}

		if (ugh != NULL) {
			if (*ugh != '\0')
				loglog(RC_BADWHACKMESSAGE, "%s", ugh);
			whack_log_fd = null_fd;
			close_any(&whackfd);
			return;
		}
	}

	/* dump record if necessary */
	writewhackrecord((char *)&msg_saved, n);

	whack_process(whackfd, &msg);
}

/*
 * interactive input from the whack user, using current whack_fd
 */
bool whack_prompt_for(fd_t whackfd,
		      const char *prompt1,
		      const char *prompt2,
		      bool echo,
		      char *ansbuf, size_t ansbuf_len)
{
	fd_t savewfd = whack_log_fd;
	ssize_t n;

	whack_log_fd = whackfd;

	DBG(DBG_CONTROLMORE, DBG_log("prompting for %s:", prompt2));

	whack_log(echo ? RC_USERPROMPT : RC_ENTERSECRET,
		  "%s prompt for %s:",
		  prompt1, prompt2);

	whack_log_fd = savewfd;

	n = read(whackfd.fd, ansbuf, ansbuf_len);

	if (n == -1) {
		whack_log(RC_LOG_SERIOUS, "read(whackfd) failed: %s",
			  strerror(errno));
		return FALSE;
	}

	if (n == 0) {
		whack_log(RC_LOG_SERIOUS, "no %s entered, aborted", prompt2);
		return FALSE;
	}

	ansbuf[ansbuf_len - 1] = '\0'; /* ensure buffer is NULL terminated */

	return TRUE;
}
