/* error logging functions, for libreswan
 *
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

#include <pthread.h>    /* Must be the first include file; XXX: why? */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "defs.h"
#include "lswlog.h"
#include "log.h"
#include "peerlog.h"

#include "connections.h"
#include "state.h"
#include "kernel.h"	/* for kernel_ops */
#include "timer.h"

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

/*
 * Wrap up the logic to decide if a particular output should occure.
 * The compiler will likely inline these.
 */

static void stdlog_raw(char *b)
{
	if (log_to_stderr || pluto_log_fp != NULL) {
		FILE *out = log_to_stderr ? stderr : pluto_log_fp;

		if (log_with_timestamp) {
			char now[34] = "";
			struct realtm t = local_realtime(realnow());
			strftime(now, sizeof(now), "%b %e %T", &t.tm);
			fprintf(out, "%s.%06ld: %s\n", now, t.microsec, b);
		} else {
			fprintf(out, "%s\n", b);
		}
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

static void whack_raw(struct lswlog *b, enum rc_type rc)
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
				lswlogl(buf, b);
				lswlog_to_whack_stream(buf);
			}
		}
	}
}

void lswlog_log_prefix(struct lswlog *buf)
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
			/* state name */
			if (DBGP(DBG_ADD_PREFIX)) {
				lswlogf(buf, " ");
				lswlog_enum_short(buf, &state_names,
						  cur_state->st_state);
			}
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

static void log_raw(struct lswlog *buf, int severity)
{
	stdlog_raw(buf->array);
	syslog_raw(severity, buf->array);
	peerlog_raw(buf->array);
	/* not whack */
}

void lswlog_to_debug_stream(struct lswlog *buf)
{
	sanitize_string(buf->array, buf->roof); /* needed? */
	log_raw(buf, LOG_DEBUG);
	/* not whack */
}

void lswlog_to_error_stream(struct lswlog *buf)
{
	log_raw(buf, LOG_ERR);
	whack_raw(buf, RC_LOG_SERIOUS);
}

void lswlog_to_log_stream(struct lswlog *buf)
{
	log_raw(buf, LOG_WARNING);
	/* not whack */
}

void lswlog_to_logwhack_stream(struct lswlog *buf, enum rc_type rc)
{
	log_raw(buf, LOG_WARNING);
	whack_raw(buf, rc);
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

void libreswan_log_errno(int e, const char *prefix, const char *message, ...)
{
	LSWBUF(buf) {
		/* <prefix><state#N...><message>.Errno %d: <strerror> */
		lswlogs(buf, prefix);
		lswlog_log_prefix(buf);
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
		lswlog_log_prefix(buf);
		va_list args;
		va_start(args, message);
		lswlogvf(buf, message, args);
		va_end(args);
		lswlog_to_error_stream(buf);
	}
	exit_pluto(PLUTO_EXIT_FAIL);
}

void libreswan_exit(enum rc_type rc)
{
	exit_pluto(rc);
}

void whack_log_pre(enum rc_type rc, struct lswlog *buf)
{
	passert(pthread_equal(pthread_self(), main_thread));
	add_whack_rc_prefix(buf, rc);
	lswlog_log_prefix(buf);
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
			lswlog_log_prefix(buf);
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
			lswlog_log_prefix(buf);
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

	if (!lmod_empty(c->extra_debugging)) {
		lset_t old_debugging = cur_debugging & DBG_MASK;
		lset_t new_debugging = lmod(old_debugging, c->extra_debugging);
		LSWLOG(buf) {
			lswlogs(buf, "extra debugging enabled for connection: ");
			lswlog_enum_lset_short(buf, &debug_names, "+",
					       new_debugging & ~old_debugging);
			/* XXX: doesn't log cleared */
		}
		set_debugging(new_debugging | (cur_debugging & IMPAIR_MASK));
	}

	if (!lmod_empty(c->extra_impairing)) {
		lset_t old_impairing = cur_debugging & IMPAIR_MASK;
		lset_t new_impairing = lmod(old_impairing, c->extra_impairing);
		LSWLOG(buf) {
			lswlogs(buf, "extra impairing enabled for connection: ");
			lswlog_enum_lset_short(buf, &impair_names, "+",
					       new_impairing & ~old_impairing);
			/* XXX: doesn't log cleared */
		}
		set_debugging(new_impairing | (cur_debugging & DBG_MASK));
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
	time_t interval;
	realtime_t n = realnow();

	/* schedule event for midnight, local time */
	tzset();
	struct realtm t = local_realtime(n);
	interval = secs_per_day -
		   (t.tm.tm_sec +
		    t.tm.tm_min * secs_per_minute +
		    t.tm.tm_hour * secs_per_hour);

	/* this might happen during a leap second */
	if (interval <= 0)
		interval = secs_per_day;

	event_schedule(EVENT_LOG_DAILY, interval, NULL);

	daily_log_reset();
}
