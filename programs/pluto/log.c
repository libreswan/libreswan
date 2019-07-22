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
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
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
 *
 */

#include <pthread.h>    /* Must be the first include file; XXX: why? */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

#include "defs.h"
#include "lswlog.h"
#include "log.h"
#include "peerlog.h"
#include "state_db.h"
#include "connections.h"
#include "state.h"
#include "kernel.h"	/* for kernel_ops */
#include "timer.h"
#include "ip_endpoint.h"
#include "impair.h"
#include "demux.h"	/* for struct msg_digest */

bool
	log_to_stderr = TRUE,		/* should log go to stderr? */
	log_to_syslog = TRUE,		/* should log go to syslog? */
	log_with_timestamp = TRUE,	/* testsuite requires no timestamps */
	log_append = TRUE,
	log_to_audit = FALSE;

char *pluto_log_file = NULL;	/* pathname */
static FILE *pluto_log_fp = NULL;

char *pluto_stats_binary = NULL;

/*
 * If valid, wack and log_whack streams write to this.
 *
 * (apparently) If the context provides a whack file descriptor,
 * messages should be copied to it -- see whack_log()
 */
fd_t whack_log_fd = { .fd = NULL_FD, };      /* only set during whack_handle() */

/*
 * Context for logging.
 *
 * CUR_FROM, CUR_CONNECTION and CUR_STATE work something like a stack.
 * lswlog_log_prefix() will use the first of CUR_STATE, CUR_CONNECTION
 * and CUR_FROM when looking for the context to use with a prefix.
 * Operations then "push" and "pop" (or clear all) contexts.
 *
 * For instance, setting CUR_STATE will hide CUR_CONNECTION, and
 * resetting CUR_STATE will re-expose CUR_CONNECTION.
 *
 * Surely it would be easier to explicitly specify the context with
 * something like LSWLOG_RC_STATE()?
 *
 * Global variables: must be carefully adjusted at transaction
 * boundaries!
 */
static struct state *cur_state = NULL;                 /* current state, for diagnostics */
static struct connection *cur_connection = NULL;       /* current connection, for diagnostics */
static ip_address cur_from;				/* source of current current message */

static void update_extra(const char *what, enum_names *names,
			 lmod_t extra, lset_t mask)
{
	if (!lmod_empty(extra)) {
		lset_t old = base_debugging & mask;
		lset_t new = lmod(old, extra);
		if (new != old) {
			LSWLOG(buf) {
				lswlogf(buf, "extra %s enabled for connection: ", what);
				lswlog_enum_lset_short(buf, names, "+", new & ~old);
				/* XXX: doesn't log cleared */
			}
			set_debugging(new | (base_debugging & ~mask));
		}
	}
}

static void update_debugging(void)
{
	struct connection *c = cur_state != NULL ? cur_state->st_connection : cur_connection;
	if (c == NULL) {
		set_debugging(base_debugging);
	} else {
		update_extra("debugging", &debug_names,
			     c->extra_debugging, DBG_MASK);
		update_extra("impairing", &impair_names,
			     c->extra_impairing, IMPAIR_MASK);
	}
}

/*
 * if any debugging is on, make sure that we log the connection we are
 * processing, because it may not be clear in later debugging.
 */

enum processing {
	START = 1,
	STOP,
	RESTART,
	SUSPEND,
	RESUME,
	RESET,
};

static void log_processing(enum processing processing, bool current,
			   struct state *st, struct connection *c,
			   const ip_address *from,
			   where_t where)
{
	pexpect(((st != NULL) + (c != NULL) + (from != NULL)) == 1);	/* exactly 1 */
	LSWDBGP(DBG_BASE, buf) {
		switch (processing) {
		case START: jam(buf, "start"); break;
		case STOP: jam(buf, "stop"); break;
		case RESTART: jam(buf, "[RE]START"); break;
		case SUSPEND: jam(buf, "suspend"); break;
		case RESUME: jam(buf, "resume"); break;
		case RESET: jam(buf, "RESET"); break;
		}
		jam(buf, " processing:");
		if (st != NULL) {
			jam(buf, " state #%lu", st->st_serialno);
			/* also include connection/from */
			c = st->st_connection;
			from = &st->st_remoteaddr;
		}
		if (c != NULL) {
			jam_string(buf, " connection ");
			jam_connection(buf, c);
		}
		if (from != NULL) {
			lswlogf(buf, " from ");
			jam_endpoint(buf, from);
		}
		if (!current) {
			jam(buf, " (BACKGROUND)");
		}
		jam(buf, " "PRI_WHERE, pri_where(where));
	}
}

/*
 * XXX:
 *
 * Given code should be using matching push/pop operations on each
 * field, this global 'blat' looks like some sort of - we've lost
 * track - hack.  Especially since the reset_globals() call is often
 * followed by passert(globals_are_reset()).
 *
 * Is this leaking the whack_log_fd?
 *
 * For instance, the IKEv1/IKEv2 specific initiate code calls
 * reset_globals() when it probably should be calling pop_cur_state().
 * Luckily, whack_log_fd isn't the real value (that seems to be stored
 * elsewhere?) and, for as long as the whack connection is up, code
 * keeps setting it back.
 */
void log_reset_globals(where_t where)
{
	if (fd_p(whack_log_fd)) {
		dbg("processing: RESET whack log_fd (was "PRI_FD") "PRI_WHERE,
		    PRI_fd(whack_log_fd), pri_where(where));
		whack_log_fd = null_fd;
	}
	if (cur_state != NULL) {
		log_processing(RESET, true, cur_state, NULL, NULL, where);
		cur_state = NULL;
	}
	if (cur_connection != NULL) {
		log_processing(RESET, true, NULL, cur_connection, NULL, where);
		cur_connection = NULL;
	}
	if (address_is_valid(&cur_from)) {
		/* peer's IP address */
		log_processing(RESET, true, NULL, NULL, &cur_from, where);
		zero(&cur_from);
	}
	if (cur_debugging != base_debugging) {
		dbg("processing: RESET cur_debugging (was "PRI_LSET") "PRI_WHERE,
		    cur_debugging, pri_where(where));
		cur_debugging = base_debugging;
	}
}

void log_pexpect_reset_globals(where_t where)
{
	if (fd_p(whack_log_fd)) {
		log_pexpect(where, "processing: unexpected whack_log_fd "PRI_FD" should be "PRI_FD,
			    PRI_fd(whack_log_fd), PRI_fd(null_fd));
		whack_log_fd = null_fd;
	}
	if (cur_state != NULL) {
		log_pexpect(where, "processing: unexpected cur_state #%lu should be #0",
			    cur_state->st_serialno);
		cur_state = NULL;
	}
	if (cur_connection != NULL) {
		log_pexpect(where, "processing: unexpected cur_connection %s should be NULL",
			    cur_connection->name);
		cur_connection = NULL;
	}
	if (address_is_valid(&cur_from)) {
		endpoint_buf buf;
		log_pexpect(where, "processing: unexpected cur_from %s should be NULL",
			    str_sensitive_endpoint(&cur_from, &buf));
		zero(&cur_from);
	}
	if (cur_debugging != base_debugging) {
		log_pexpect(where, "processing: unexpected cur_debugging "PRI_LSET" should be "PRI_LSET,
			    cur_debugging, base_debugging);
		cur_debugging = base_debugging;
	}
}

struct connection *log_push_connection(struct connection *new_connection,
				       where_t where)
{
	bool current = (cur_state == NULL); /* not hidden by state? */
	struct connection *old_connection = cur_connection;

	if (old_connection != NULL &&
	    old_connection != new_connection) {
		log_processing(SUSPEND, current,
			       NULL, old_connection, NULL, where);
	}

	cur_connection = new_connection;
	update_debugging();

	if (new_connection == NULL) {
		dbg("start processing: connection NULL "PRI_WHERE,
		    pri_where(where));
	} else if (old_connection == new_connection) {
		log_processing(RESTART, current,
			       NULL, new_connection, NULL, where);
	} else {
		log_processing(START, current,
			       NULL, new_connection, NULL, where);
	}

	return old_connection;
}

void log_pop_connection(struct connection *c, where_t where)
{
	bool current = (cur_state == NULL); /* not hidden by state? */
	if (cur_connection != NULL) {
		log_processing(STOP, current /* current? */,
			       NULL, cur_connection, NULL, where);
	} else {
		dbg("processing: STOP connection NULL "PRI_WHERE,
		    pri_where(where));
	}
	cur_connection = c;
	update_debugging();
	if (cur_connection != NULL) {
		log_processing(RESUME, current /* current? */,
			       NULL, cur_connection, NULL, where);
	}
}

bool is_cur_connection(const struct connection *c)
{
	return cur_connection == c;
}

so_serial_t log_push_state(struct state *new_state, where_t where)
{
	struct state *old_state = cur_state;

	if (old_state != NULL) {
		if (old_state != new_state) {
			log_processing(SUSPEND, true /* must be current */,
				       cur_state, NULL, NULL, where);
		}
	} else if (cur_connection != NULL && new_state != NULL) {
		log_processing(SUSPEND, true /* current for now */,
			       NULL, cur_connection, NULL, where);
	}

	cur_state = new_state;
	update_debugging();

	if (new_state == NULL) {
		dbg("skip start processing: state #0 "PRI_WHERE,
		    pri_where(where));
	} else if (old_state == new_state) {
		log_processing(RESTART, true /* must be current */,
			       new_state, NULL, NULL, where);
	} else {
		log_processing(START, true /* must be current */,
			       new_state, NULL, NULL, where);
	}
	return old_state != NULL ? old_state->st_serialno : SOS_NOBODY;
}

void log_pop_state(so_serial_t serialno, where_t where)
{
	if (cur_state != NULL) {
		log_processing(STOP, true, /* must be current */
			       cur_state, NULL, NULL, where);
	} else {
		dbg("processing: STOP state #0 "PRI_WHERE,
		    pri_where(where));
	}
	cur_state = state_by_serialno(serialno);
	update_debugging();
	if (cur_state != NULL) {
		log_processing(RESUME, true, /* must be current */
			       cur_state, NULL, NULL, where);
	} else if (cur_connection != NULL) {
		log_processing(RESUME, true, /* now current */
			       NULL, cur_connection, NULL, where);
	}
}

extern ip_address log_push_from(ip_address new_from, where_t where)
{
	bool current = (cur_state == NULL && cur_connection == NULL);
	ip_address old_from = cur_from;
	if (address_is_valid(&old_from)) {
		log_processing(SUSPEND, current,
			       NULL, NULL, &old_from, where);
	}
	cur_from = new_from;
	if (address_is_valid(&cur_from)) {
		log_processing(START, current,
			       NULL, NULL, &cur_from, where);
	}
	return old_from;
}

extern void log_pop_from(ip_address old_from, where_t where)
{
	bool current = (cur_state == NULL && cur_connection == NULL);
	if (address_is_valid(&cur_from)) {
		log_processing(STOP, current,
			       NULL, NULL, &cur_from, where);
	}
	if (address_is_valid(&old_from)) {
		log_processing(RESUME, current,
			       NULL, NULL, &old_from, where);
	}
	cur_from = old_from;
}


/*
 * Initialization.
 */

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
 * Wrap up the logic to decide if a particular output should occur.
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
		peerlog(cur_connection, b);
	}
}

static void whack_raw(struct lswlog *buf, enum rc_type rc)
{
	/*
	 * Using globals so never from a helper thread
	 */
	passert(in_main_thread());
	/* aka whack_log_p() */
	fd_t wfd = (fd_p(whack_log_fd) ? whack_log_fd :
		    cur_state != NULL ? cur_state->st_whack_sock :
		    null_fd);
	if (!fd_p(wfd)) {
		return;
	}

	/*
	 * XXX: use iovec as it's easier than trying to deal with
	 * truncation while still ensuring that the message is
	 * terminated with a '\n' (this isn't a performance thing, it
	 * just replaces local memory moves with kernel equivalent).
	 */

	/* 'NNN ' */
	char prefix[10];/*65535+200*/
	int prefix_len = snprintf(prefix, sizeof(prefix), "%03u ", rc);
	passert(prefix_len >= 0 && (unsigned) prefix_len < sizeof(prefix));

	/* message, not including trailing '\0' */
	shunk_t message = jambuf_as_shunk(buf);

	/* NL */
	char nl = '\n';

	struct iovec iov[] = {
		{ .iov_base = prefix, .iov_len = prefix_len, },
		/* need to cast away const :-( */
		{ .iov_base = (void*)message.ptr, .iov_len = message.len, },
		{ .iov_base = &nl, .iov_len = sizeof(nl), },
	};
	struct msghdr msg = {
		.msg_iov = iov,
		.msg_iovlen = elemsof(iov),
	};

	/* write to whack socket, but suppress possible SIGPIPE */
	sendmsg(wfd.fd, &msg, MSG_NOSIGNAL);
}

static void lswlog_cur_prefix(struct lswlog *buf,
			      const struct state *cur_state,
			      const struct connection *cur_connection,
			      const ip_address *cur_from)
{
	if (!in_main_thread()) {
		return;
	}

	const struct connection *c = cur_state != NULL ? cur_state->st_connection :
		cur_connection;

	if (c != NULL) {
		jam_connection(buf, c);
		if (cur_state != NULL) {
			/* state number */
			lswlogf(buf, " #%lu", cur_state->st_serialno);
			/* state name */
			if (DBGP(DBG_ADD_PREFIX)) {
				lswlogf(buf, " ");
				lswlogs(buf, cur_state->st_state->short_name);
			}
		}
		lswlogs(buf, ": ");
	} else if (cur_from != NULL && address_is_valid(cur_from)) {
		/* peer's IP address */
		lswlogs(buf, "packet from ");
		jam_sensitive_endpoint(buf, cur_from);
		lswlogs(buf, ": ");
	}
}

void lswlog_log_prefix(struct lswlog *buf)
{
	lswlog_cur_prefix(buf, cur_state, cur_connection, &cur_from);
}

/*
 * This needs to mimic both lswlog_log_prefix() and
 * lswlog_dbg_prefix().
 */

void log_prefix(struct lswlog *buf, bool debug,
		struct state *st, struct connection *c)
{
	if (debug) {
		lswlogs(buf, DEBUG_PREFIX);
	}
	if (!debug || DBGP(DBG_ADD_PREFIX)) {
		lswlog_cur_prefix(buf, st, c, &cur_from);
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
	if (in_main_thread()) {
		/* don't whack-log from helper threads */
		whack_raw(buf, RC_LOG_SERIOUS);
	}
}

void lswlog_to_log_stream(struct lswlog *buf)
{
	log_raw(buf, LOG_WARNING);
	/* not whack */
}

void lswlog_to_default_streams(struct lswlog *buf, enum rc_type rc)
{
	log_raw(buf, LOG_WARNING);
	if (in_main_thread()) {
		/* don't whack-log from helper threads */
		whack_raw(buf, rc);
	}
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

/* <prefix><state#N...><message>. Errno %d: <strerror> */

void lswlog_errno_prefix(struct lswlog *buf, const char *prefix)
{
	lswlogs(buf, prefix);
	lswlog_log_prefix(buf);
}

void lswlog_errno_suffix(struct lswlog *buf, int e)
{
	lswlogs(buf, ".");
	jam(buf, " "PRI_ERRNO, pri_errno(e));
	lswlog_to_error_stream(buf);
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

void lswlog_to_whack_stream(struct lswlog *buf, enum rc_type rc)
{
	pexpect(whack_log_p());
	whack_raw(buf, rc);
}

bool whack_log_p(void)
{
	if (!in_main_thread()) {
		PEXPECT_LOG("%s", "whack_log*() must be called from the main thread");
		return false;
	}

	fd_t wfd = fd_p(whack_log_fd) ? whack_log_fd :
	      cur_state != NULL ? cur_state->st_whack_sock :
	      null_fd;

	return fd_p(wfd);
}

/* emit message to whack.
 * form is "ddd statename text\n" where
 * - ddd is a decimal status code (RC_*) as described in whack.h
 * - text is a human-readable annotation
 */

void whack_log(enum rc_type rc, const char *message, ...)
{
	if (whack_log_p()) {
		LSWBUF(buf) {
			lswlog_log_prefix(buf);
			va_list args;
			va_start(args, message);
			lswlogvf(buf, message, args);
			va_end(args);
			lswlog_to_whack_stream(buf, rc);
		}
	}
}

lset_t base_debugging = DBG_NONE; /* default to reporting nothing */

void set_debugging(lset_t deb)
{
	cur_debugging = deb;
}

void reset_debugging(void)
{
	set_debugging(base_debugging);
}

void plog_raw(enum rc_type unused_rc UNUSED,
	      const struct state *st,
	      const struct connection *c,
	      const ip_endpoint *from,
	      const char *message, ...)
{
	LSWBUF(buf) {
		lswlog_cur_prefix(buf, st, c, from);
		va_list ap;
		va_start(ap, message);
		jam_va_list(buf, message, ap);
		va_end(ap);
		lswlog_to_log_stream(buf);
	}
}

void loglog_raw(enum rc_type rc,
		const struct state *st,
		const struct connection *c,
		const ip_endpoint *from,
		const char *message, ...)
{
	LSWBUF(buf) {
		lswlog_cur_prefix(buf, st, c, from);
		va_list ap;
		va_start(ap, message);
		jam_va_list(buf, message, ap);
		va_end(ap);
		lswlog_to_log_stream(buf);
		if (whack_log_p()) {
			lswlog_to_whack_stream(buf, rc);
		}
	}
}

void DBG_raw(enum rc_type unused_rc UNUSED,
	     const struct state *st,
	     const struct connection *c,
	     const ip_endpoint *from,
	     const char *message, ...)
{
	LSWBUF(buf) {
		jam(buf, DEBUG_PREFIX);
		if (DBGP(DBG_ADD_PREFIX)) {
			lswlog_cur_prefix(buf, st, c, from);
		}
		va_list ap;
		va_start(ap, message);
		jam_va_list(buf, message, ap);
		va_end(ap);
		lswlog_to_log_stream(buf);
	}
}

#define RATE_LIMIT 1000
static unsigned nr_rate_limited_logs;

static unsigned log_limit(void)
{
	if (impair_log_rate_limit == 0) {
		/* --impair log-rate-limit:no */
		return RATE_LIMIT;
	} else {
		/* --impair log-rate-limit:yes */
		/* --impair log-rate-limit:NNN */
		return impair_log_rate_limit;
	}
}

void rate_log(const struct msg_digest *md,
	      const char *message, ...)
{
	unsigned limit = log_limit();
	if (nr_rate_limited_logs == limit) {
		plog_global("rate limited log reached limit of %u entries", limit);
	} else if (nr_rate_limited_logs > limit) {
		LSWDBGP(DBG_BASE, buf) {
			va_list ap;
			va_start(ap, message);
			lswlogvf(buf, message, ap);
			va_end(ap);
		}
		return;
	}
	nr_rate_limited_logs++;
	LSWBUF(buf) {
		lswlog_cur_prefix(buf, NULL/*st*/, NULL/*c*/, &md->sender);
		va_list ap;
		va_start(ap, message);
		jam_va_list(buf, message, ap);
		va_end(ap);
		lswlog_to_log_stream(buf);
	}
}

static void reset_log_rate_limit(void)
{
	if (nr_rate_limited_logs > log_limit()) {
		plog_global("rate limited log reset");
	}
	nr_rate_limited_logs = 0;
}

void init_rate_log(void)
{
	enable_periodic_timer(EVENT_RESET_LOG_RATE_LIMIT,
			      reset_log_rate_limit,
			      RESET_LOG_RATE_LIMIT);
}
