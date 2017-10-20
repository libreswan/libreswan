/* error logging functions
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2005-2007 Michael Richardson
 * Copyright (C) 2006-2010 Bart Trojanowski
 * Copyright (C) 2008-2012 Paul Wouters
 * Copyright (C) 2008-2010 David McCullough.
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013,2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include <pthread.h>    /* Must be the first include file */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>     /* used only if MSG_NOSIGNAL not defined */
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <libreswan.h>
#include "libreswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "lswconf.h"
#include "lswfips.h"
#include "lswlog.h"

#include "defs.h"
#include "log.h"
#include "peerlog.h"
#include "server.h"
#include "state.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "kernel.h"             /* needs connections.h */
#include "whack.h"              /* needs connections.h */
#include "timer.h"
#include "kernel_alg.h"
#include "ike_alg.h"
#include "ike_alg_null.h"
#include "plutoalg.h"
/* for show_virtual_private: */
#include "virtual.h"	/* needs connections.h */
#include "crypto.h"

#ifndef NO_DB_OPS_STATS
#define NO_DB_CONTEXT
#include "db_ops.h"
#endif

#include "pluto_stats.h"

bool
	log_to_stderr = TRUE,		/* should log go to stderr? */
	log_to_syslog = TRUE,		/* should log go to syslog? */
	log_with_timestamp = TRUE,	/* testsuite requires no timestamps */
	log_append = TRUE,
	log_ip = TRUE;

/* should we complain when we find no local id */
bool
	logged_myid_fqdn_txt_warning = FALSE,
	logged_myid_ip_txt_warning   = FALSE;

char *pluto_log_file = NULL;	/* pathname */
static FILE *pluto_log_fp = NULL;

char *pluto_stats_binary = NULL;

/* Context for logging.
 *
 * Global variables: must be carefully adjusted at transaction boundaries!
 * If the context provides a whack file descriptor, messages
 * should be copied to it -- see whack_log()
 */
int whack_log_fd = NULL_FD;                     /* only set during whack_handle() */
struct state *cur_state = NULL;                 /* current state, for diagnostics */
struct connection *cur_connection = NULL;       /* current connection, for diagnostics */
const ip_address *cur_from = NULL;              /* source of current current message */
u_int16_t cur_from_port;                        /* host order */

void pluto_init_log(void)
{
	set_alloc_exit_log_func(exit_log);
	if (log_to_stderr)
		setbuf(stderr, NULL);

	if (pluto_log_file != NULL) {
		pluto_log_fp = fopen(pluto_log_file,
			log_append ? "a" : "w");
		if (pluto_log_fp == NULL) {
			fprintf(stderr,
				"Cannot open logfile '%s': %s\n",
				pluto_log_file, strerror(errno));
		} else {
			/*
			 * buffer by line:
			 * should be faster that no buffering
			 * and yet safe since each message is probably a line.
			 */
			setvbuf(pluto_log_fp, NULL, _IOLBF, 0);
		}
	}

	if (log_to_syslog)
		openlog("pluto", LOG_CONS | LOG_NDELAY | LOG_PID,
			LOG_AUTHPRIV);

	peerlog_init();
}

/*
 * Add just the WHACK or STATE (or connection) prefix.
 *
 * Callers need to pick and choose.  For instance, WHACK output some
 * times suppress the whack prefix; and there is no point adding the
 * STATE prefix when it was added earlier.
 */

static void add_whack_rc_prefix(struct lswlog *buf, enum rc_type rc)
{
	lswlogf(buf, "%03d ", rc);
}

static void add_state_prefix(struct lswlog *buf)
{
	if (!pthread_equal(pthread_self(), main_thread)) {
		return;
	}

	struct connection *c = cur_state != NULL ? cur_state->st_connection :
		cur_connection;

	if (c != NULL) {
		lswlogf(buf, "\"%s\"", c->name);
		/* if it fits, put in any connection instance information */
		char inst[CONN_INST_BUF];
		fmt_conn_instance(c, inst);
		lswlogs(buf, inst);
		if (cur_state != NULL) {
			/* state number */
			lswlogf(buf, " #%lu", cur_state->st_serialno);
		}
		lswlogs(buf, ": ");
	} else if (cur_from != NULL) {
		/* peer's IP address */
		ipstr_buf b;
		lswlogf(buf, "packet from %s:%u: ",
			log_ip ? ipstr(cur_from, &b) : "<ip address>",
			(unsigned)cur_from_port);
	}
}

/*
 * Wrap up the logic to decide if a particular output should occure.
 * The compiler will likely inline these.
 */

static void stdlog_raw(char *b)
{
	if (log_to_stderr || pluto_log_fp != NULL) {
		char now[34] = "";

		if (log_with_timestamp)
			prettynow(now, sizeof(now), "%b %e %T: ");
		fprintf(log_to_stderr ? stderr : pluto_log_fp,
			"%s%s\n", now, b);
	}
}

static void syslog_raw(int severity, char *b)
{
	if (log_to_syslog)
		syslog(severity, "%s", b);
}

static void peerlog_raw(char *b)
{
	if (log_to_perpeer) {
		peerlog(b);
	}
}

static void whack_rc_raw(enum rc_type rc, char *b)
{
	/*
	 * Only whack-log when the main thread.
	 *
	 * Helper threads, which are asynchronous, shouldn't be trying
	 * to directly emit whack output.
	 */
	if (pthread_equal(pthread_self(), main_thread)) {
		if (whack_log_p()) {
			/*
			 * On the assumption that logging to whack is
			 * rare and slow anyway, don't try to tune
			 * this code path.
			 */
			LSWBUF(buf) {
				add_whack_rc_prefix(buf, rc);
				/* add_state_prefix() - done by caller */
				lswlogs(buf, b);
				lswlog_to_whack_stream(buf);
			}
		}
	}
}

static void lswlog_log_raw(struct lswlog *buf, enum rc_type rc, int severity)
{
	stdlog_raw(buf->array);
	syslog_raw(severity, buf->array);
	peerlog_raw(buf->array);
	whack_rc_raw(rc, buf->array);
}

void lswlog_pre(struct lswlog *buf)
{
	add_state_prefix(buf);
}

void lswlog_to_logger_stream(struct lswlog *buf, enum rc_type rc)
{
	lswlog_log_raw(buf, rc, LOG_WARNING);
}

void close_log(void)
{
	if (log_to_syslog)
		closelog();

	if (pluto_log_fp != NULL) {
		(void)fclose(pluto_log_fp);
		pluto_log_fp = NULL;
	}

	peerlog_close();
}

void prettynow(char *buf, size_t buflen, const char *fmt)
{
	realtime_t n = realnow();
	struct tm tm1;
	struct tm *t = localtime_r(&n.real_secs, &tm1);

	/* the cast suppresses a warning: <http://gcc.gnu.org/bugzilla/show_bug.cgi?id=39438> */
	((size_t (*)(char *, size_t, const char *, const struct tm *))strftime)(buf, buflen, fmt, t);
}

/* thread locks added until all non re-entrant functions it uses have been fixed */
void libreswan_vloglog(enum rc_type rc, const char *message, va_list args)
{
	LSWBUF(buf) {
		add_state_prefix(buf);
		lswlogvf(buf, message, args);
		lswlog_log_raw(buf, rc, LOG_WARNING);
	}
}

void lswlog_to_error_stream(struct lswlog *buf)
{
	lswlog_log_raw(buf, RC_LOG_SERIOUS, LOG_ERR);
}

void lswlog_log_errno(int e, const char *prefix, const char *message, ...)
{
	LSWBUF(buf) {
		/* <prefix><state#N...><message>.Errno %d: <strerror> */
		lswlogs(buf, prefix);
		add_state_prefix(buf);
		va_list args;
		va_start(args, message);
		lswlogvf(buf, message, args);
		va_end(args);
		lswlogs(buf, ".");
		lswlog_errno(buf, e);
		lswlog_to_error_stream(buf);
	}
}

void exit_log(const char *message, ...)
{
	LSWBUF(buf) {
		/* FATAL ERROR: <state...><message> */
		lswlogs(buf, "FATAL ERROR: ");
		add_state_prefix(buf);
		va_list args;
		va_start(args, message);
		lswlogvf(buf, message, args);
		va_end(args);
		lswlog_to_error_stream(buf);
	}
	exit_pluto(PLUTO_EXIT_FAIL);
}

void lswlog_exit(enum rc_type rc)
{
	exit_pluto(rc);
}

void whack_log_pre(enum rc_type rc, struct lswlog *buf)
{
	passert(pthread_equal(pthread_self(), main_thread));
	add_whack_rc_prefix(buf, rc);
	add_state_prefix(buf);
}

void lswlog_to_whack_stream(struct lswlog *buf)
{
	passert(pthread_equal(pthread_self(), main_thread));

	int wfd = whack_log_fd != NULL_FD ? whack_log_fd :
	      cur_state != NULL ? cur_state->st_whack_sock :
	      NULL_FD;

	passert(wfd != NULL_FD);

	char *m = buf->array;
	size_t len = buf->len;

	/* write to whack socket, but suppress possible SIGPIPE */
#ifdef MSG_NOSIGNAL                     /* depends on version of glibc??? */
	m[len] = '\n';  /* don't need NUL, do need NL */
	(void) send(wfd, m, len + 1, MSG_NOSIGNAL);
#else /* !MSG_NOSIGNAL */
	int r;
	struct sigaction act, oldact;

	m[len] = '\n'; /* don't need NUL, do need NL */
	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0; /* no nothing */
	r = sigaction(SIGPIPE, &act, &oldact);
	passert(r == 0);

	(void) write(wfd, m, len + 1);

	r = sigaction(SIGPIPE, &oldact, NULL);
	passert(r == 0);
#endif /* !MSG_NOSIGNAL */
}

bool whack_log_p(void)
{
	if (!pthread_equal(pthread_self(), main_thread)) {
		PEXPECT_LOG("%s", "whack_log*() must be called from the main thread");
		return false;
	}

	int wfd = whack_log_fd != NULL_FD ? whack_log_fd :
	      cur_state != NULL ? cur_state->st_whack_sock :
	      NULL_FD;

	return wfd != NULL_FD;
}

/* emit message to whack.
 * form is "ddd statename text" where
 * - ddd is a decimal status code (RC_*) as described in whack.h
 * - text is a human-readable annotation
 */

void whack_log(enum rc_type rc, const char *message, ...)
{
	if (whack_log_p()) {
		LSWBUF(buf) {
			add_whack_rc_prefix(buf, rc);
			add_state_prefix(buf);
			va_list args;
			va_start(args, message);
			lswlogvf(buf, message, args);
			va_end(args);
			lswlog_to_whack_stream(buf);
		}
	}
}

void whack_log_comment(const char *message, ...)
{
	if (whack_log_p()) {
		LSWBUF(buf) {
			/* add_whack_rc_prefix() - skipped */
			add_state_prefix(buf);
			va_list args;
			va_start(args, message);
			lswlogvf(buf, message, args);
			va_end(args);
			lswlog_to_whack_stream(buf);
		}
	}
}

lset_t base_debugging = DBG_NONE; /* default to reporting nothing */

void extra_debugging(const struct connection *c)
{
	if (c == NULL) {
		reset_debugging();
		return;
	}

	if (c->extra_debugging != 0) {
		LSWLOG(buf) {
			lswlogs(buf, "extra debugging enabled for connection: ");
			lswlog_enum_lset_short(buf, &debug_and_impair_names,
					       c->extra_debugging & ~cur_debugging);
		}
		set_debugging(cur_debugging | c->extra_debugging);
	}

	/*
	 * if any debugging is on, make sure that we log the connection
	 * we are processing, because it may not be clear in later debugging.
	 */
	DBG(~LEMPTY, {
		char buf[CONN_INST_BUF] =  "";
		char b1[CONN_INST_BUF];
		ipstr_buf ra;
		/* fmt_conn_instance include the same if  POLICY_OPPORTUNISTIC */
		if (cur_state != NULL && !(c->policy & POLICY_OPPORTUNISTIC)) {
			snprintf(buf, sizeof(buf), " #%lu %s",
				cur_state->st_serialno,
				ipstr(&cur_state->st_remoteaddr, &ra));
		}
		DBG_log("processing connection \"%s\"%s%s",
			c->name, fmt_conn_instance(c, b1), buf);
	});

}

void set_debugging(lset_t deb)
{
	cur_debugging = deb;

	if (kernel_ops != NULL && kernel_ops->set_debug != NULL)
		(*kernel_ops->set_debug)(cur_debugging, DBG_log,
					 libreswan_log);
}

void lswlog_to_debug_stream(struct lswlog *buf)
{
	sanitize_string(buf->array, buf->roof);
	stdlog_raw(buf->array);
	syslog_raw(LOG_DEBUG, buf->array);
	peerlog_raw(buf->array);
	/* not whack */
}

static void show_system_security(void)
{
	int selinux = libreswan_selinux();
#ifdef FIPS_CHECK
	bool fips = libreswan_fipsmode();
#else
	int fips = FALSE;
#endif

	whack_log(RC_COMMENT, " ");     /* spacer */

	whack_log(RC_COMMENT, "fips mode=%s;", fips ? "enabled" : "disabled");

	whack_log(RC_COMMENT, "SElinux=%s",
		selinux == 0 ? "disabled" : selinux == 1 ? "enabled" : "indeterminate");
#ifdef HAVE_SECCOMP
	whack_log(RC_COMMENT, "seccomp=%s",
		pluto_seccomp_mode == SECCOMP_ENABLED ? "enabled" :
			pluto_seccomp_mode == SECCOMP_TOLERANT ? "tolerant" : "disabled");
#else
	whack_log(RC_COMMENT, "seccomp=unsupported");
#endif
	whack_log(RC_COMMENT, " ");     /* spacer */

}

void show_global_status(void)
{
	show_globalstate_status();
	show_pluto_stats();
}

void show_status(void)
{
	show_kernel_interface();
	show_ifaces_status();
	show_system_security();
	show_setup_plutomain();
	show_myid_status();
	show_debug_status();
	show_setup_natt();
	show_virtual_private();
	kernel_alg_show_status();
	ike_alg_show_status();
#ifndef NO_DB_OPS_STATS
	db_ops_show_status();
#endif
	show_connections_status();
	show_states_status();
#ifdef KLIPS
	show_shunt_status();
#endif
}

/*
 * a routine that attempts to schedule itself daily.
 *
 */

void daily_log_reset(void)
{
	logged_myid_fqdn_txt_warning = FALSE;
	logged_myid_ip_txt_warning   = FALSE;
}

void daily_log_event(void)
{
	struct tm tm1, *ltime;
	time_t interval;
	realtime_t n = realnow();

	/* schedule event for midnight, local time */
	tzset();
	ltime = localtime_r(&n.real_secs, &tm1);
	interval = secs_per_day -
		   (ltime->tm_sec +
		    ltime->tm_min * secs_per_minute +
		    ltime->tm_hour * secs_per_hour);

	/* this might happen during a leap second */
	if (interval <= 0)
		interval = secs_per_day;

	event_schedule(EVENT_LOG_DAILY, interval, NULL);

	daily_log_reset();
}

/*
 * We store runtime info for stats/status this way.
 * You may be able to do something similar using these hooks.
 */

struct log_conn_info {
	struct connection *conn;
	struct state *ignore;           /* ignore this state */

	/* best completed state of connection */

	enum {
		tun_down=0,
		tun_phase1,
		tun_phase1up,
		tun_phase15,
		tun_phase2,
		tun_up
	} tunnel;

	/* best uncompleted state info for each phase */

	enum {
		p1_none=0,
		p1_init,
		p1_encrypt,
		p1_auth,
		p1_up,
		p1_down
	} phase1;

	enum {
		p2_none=0,
		p2_neg,
		p2_up,
	} phase2;
};

/*
 * we need to make sure we do not saturate the stats daemon
 * so we track what we have told it in a long (triple)
 */
#define LOG_CONN_STATSVAL(lci) \
	((lci)->tunnel | ((lci)->phase1 << 4) | ((lci)->phase2 << 8))

static void connection_state(struct state *st, void *data)
{
	struct log_conn_info *lc = data;

	if (st == NULL || st == lc->ignore ||
	    st->st_connection == NULL || lc->conn == NULL)
		return;

	if (st->st_connection != lc->conn) {
		if (lc->conn->host_pair != st->st_connection->host_pair ||
		    !same_peer_ids(lc->conn, st->st_connection, NULL))
			return;
		/* phase1 is shared with another connnection */
	}

	/* ignore undefined states (i.e. just deleted) */
	if (st->st_state == STATE_UNDEFINED)
		return;

	if (IS_IKE_SA(st)) {
		if (lc->tunnel < tun_phase1)
			lc->tunnel = tun_phase1;
		if (IS_IKE_SA_ESTABLISHED(st)) {
			if (lc->tunnel < tun_phase1up)
				lc->tunnel = tun_phase1up;
			lc->phase1 = p1_up;
		} else {
			if (lc->phase1 < p1_init)
				lc->phase1 = p1_init;
			if (IS_ISAKMP_ENCRYPTED(st->st_state) &&
			    lc->phase1 < p1_encrypt)
				lc->phase1 = p1_encrypt;
			if (IS_ISAKMP_AUTHENTICATED(st->st_state) &&
			    lc->phase1 < p1_auth)
				lc->phase1 = p1_auth;
		}
	} else {
		lc->phase1 = p1_down;
	}

	/* only phase one shares across connections, so we can quit now */
	if (st->st_connection != lc->conn)
		return;

	if (IS_PHASE15(st->st_state)) {
		if (lc->tunnel < tun_phase15)
			lc->tunnel = tun_phase15;
	}

	if (IS_QUICK(st->st_state)) {
		if (lc->tunnel < tun_phase2)
			lc->tunnel = tun_phase2;
		if (IS_IPSEC_SA_ESTABLISHED(st->st_state)) {
			if (lc->tunnel < tun_up)
				lc->tunnel = tun_up;
			lc->phase2 = p2_up;
		} else {
			if (lc->phase2 < p2_neg)
				lc->phase2 = p2_neg;
		}
	}
}

void log_state(struct state *st, enum state_kind new_state)
{
	char buf[1024];
	struct log_conn_info lc;
	struct connection *conn;
	const char *tun = NULL, *p1 = NULL, *p2 = NULL;
	enum state_kind save_state;

	if (pluto_stats_binary == NULL)
		return;

	if (st == NULL) {
		DBG(DBG_CONTROLMORE, DBG_log(
			    "log_state() called without state"));
		return;
	}

	conn = st->st_connection;
	if (conn == NULL || st->st_connection->name == NULL) {
		DBG(DBG_CONTROLMORE,
		    DBG_log("log_state() called without st->st_connection or without st->st_connection->name"));
		return;
	}

	DBG(DBG_CONTROLMORE,
	    DBG_log("log_state called for state update for connection %s ",
		    conn->name));
	zero(&lc);	/* OK: the two pointer fields handled below */
	lc.conn = conn;
	lc.ignore = NULL;

	save_state = st->st_state;
	st->st_state = new_state;
	for_each_state(connection_state, &lc);
	st->st_state = save_state;

	if (conn->statsval ==
	    (IPsecSAref2NFmark(st->st_ref) | LOG_CONN_STATSVAL(&lc))) {
		DBG(DBG_CONTROLMORE,
		    DBG_log("log_state for connection %s state change signature (%d) matches last one - skip logging",
			    conn->name, conn->statsval));
		return;
	}
	conn->statsval = IPsecSAref2NFmark(st->st_ref) |
			 LOG_CONN_STATSVAL(&lc);
	DBG(DBG_CONTROLMORE,
	    DBG_log("log_state set state change signature for connection %s to %d",
		    conn->name, conn->statsval));

	switch (lc.tunnel) {
	case tun_phase1:
		tun = "phase1";
		break;
	case tun_phase1up:
		tun = "phase1up";
		break;
	case tun_phase15:
		tun = "phase15";
		break;
	case tun_phase2:
		tun = "phase2";
		break;
	case tun_up:
		tun = "up";
		break;
	case tun_down:
		tun = "down";
		break;
	default:
		tun = "unchanged";
		break;
	}

	switch (lc.phase1) {
	case p1_init:     p1 = "init";
		break;
	case p1_encrypt:  p1 = "encrypt";
		break;
	case p1_auth:     p1 = "auth";
		break;
	case p1_up:       p1 = "up";
		break;
	case p1_down:       p1 = "down";
		break;
	default:          p1 = "unchanged";
		break;
	}

	switch (lc.phase2) {
	case p2_neg:      p2 = "neg";
		break;
	case p2_up:       p2 = "up";
		break;
	default:          p2 = "down";
		break;
	}
	DBG(DBG_CONTROLMORE,
	    DBG_log("log_state calling %s for connection %s with tunnel(%s) phase1(%s) phase2(%s)",
		    pluto_stats_binary, conn->name, tun, p1, p2));

	snprintf(buf, sizeof(buf), "%s "
		 "%s ipsec-tunnel-%s if_stats /proc/net/dev/%s \\; "
		 "%s ipsec-tunnel-%s tunnel %s \\; "
		 "%s ipsec-tunnel-%s phase1 %s \\; "
		 "%s ipsec-tunnel-%s phase2 %s \\; "
		 "%s ipsec-tunnel-%s nfmark-me/him 0x%x/0x%x",

		 pluto_stats_binary,
		 conn->interface ? "push" : "drop", conn->name,
		 conn->interface ? conn->interface->ip_dev->id_vname : "",
		 tun ? "push" : "drop", conn->name, tun ? tun : "",
		 p1  ? "push" : "drop", conn->name, p1  ? p1  : "",
		 p2  ? "push" : "drop", conn->name, p2  ? p2  : "",
		 (st->st_ref || st->st_refhim) ? "push" : "drop", conn->name,
		 st->st_ref == IPSEC_SAREF_NA ? IPSEC_SAREF_NA :
		 st->st_ref == IPSEC_SAREF_NULL ? 0u :
		 IPsecSAref2NFmark(st->st_ref) | IPSEC_NFMARK_IS_SAREF_BIT
		 ,
		 st->st_refhim == IPSEC_SAREF_NA ? IPSEC_SAREF_NA :
		 st->st_refhim == IPSEC_SAREF_NULL ? 0u :
		 IPsecSAref2NFmark(st->st_refhim) | IPSEC_NFMARK_IS_SAREF_BIT);
	if (system(buf) == -1) {
		loglog(RC_LOG_SERIOUS,"statsbin= failed to send status update notification");
	}
	DBG(DBG_CONTROLMORE,
	    DBG_log("log_state for connection %s completed", conn->name));
}
