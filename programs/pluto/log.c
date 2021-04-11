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
 * Copyright (C) 2017-2020 Andrew Cagney <cagney@gnu.org>
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
#include "log.h"
#include "state_db.h"
#include "connections.h"
#include "state.h"
#include "kernel.h"	/* for kernel_ops */
#include "timer.h"
#include "ip_endpoint.h"
#include "impair.h"
#include "demux.h"	/* for struct msg_digest */
#include "pending.h"

static void log_raw(int severity, const char *prefix, struct jambuf *buf);

struct logger failsafe_logger = {
	.where = { .basename = "<global>", .func = "<global>", },
	.object = NULL,
	.object_vec = &logger_global_vec,
};

const struct log_param default_log_param = {
	.log_with_timestamp = true,	/* but testsuite requires no timestamps */
};

static struct log_param log_param = {
	.log_with_timestamp = false,	/* initial logger to stderr requires no timestamp */
};

bool
	log_to_stderr = TRUE,		/* should log go to stderr? */
	log_to_syslog = TRUE,		/* should log go to syslog? */
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
struct fd *whack_log_fd = NULL;      /* only set during whack_handle() */

/*
 * Initialization.
 */

void pluto_init_log(struct log_param param)
{
	log_param = param;

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
}

/*
 * Wrap up the logic to decide if a particular output should occur.
 * The compiler will likely inline these.
 */

static void stdlog_raw(const char *prefix, char *message, const struct realtm *t)
{
	if (log_to_stderr || pluto_log_fp != NULL) {
		FILE *out = log_to_stderr ? stderr : pluto_log_fp;

		if (log_param.log_with_timestamp) {
			char now[34] = "";
			strftime(now, sizeof(now), "%b %e %T", &t->tm);
			fprintf(out, "%s.%06ld: %s%s\n", now, t->microsec, prefix, message);
		} else {
			fprintf(out, "%s%s\n", prefix, message);
		}
	}
}

static void syslog_raw(int severity, const char *prefix, char *message)
{
	if (log_to_syslog)
		syslog(severity, "%s%s", prefix, message);
}

static void jambuf_to_whack(struct jambuf *buf, const struct fd *whackfd, enum rc_type rc)
{
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
	ssize_t s = fd_sendmsg(whackfd, &msg, MSG_NOSIGNAL);
	if (s < 0) {
		/* probably the other end hit cntrl-c */
		JAMBUF(buf) {
			jam(buf, "whack error: "PRI_ERRNO, pri_errno(-(int)s));
			/* not whack */
			log_raw(LOG_WARNING, "", buf);
		}
	}
}

/*
 * interactive input from the whack user, using current whack_fd
 */
bool whack_prompt_for(struct state *st, const char *prompt,
		      bool echo, char *ansbuf, size_t ansbuf_len)
{
	dbg("prompting whack for %s", prompt);

	/*
	 * XXX: This includes the connection name twice: first from
	 * the state prefix; and second explicitly.  Only reason is so
	 * that tests are happy.
	 */
	JAMBUF(buf) {
		/* XXX: one of these is redundant */
		jam_logger_prefix(buf, st->st_logger);
		jam(buf, "%s ", st->st_connection->name);
		/* the real message */
		jam(buf, "prompt for %s:", prompt);
		jambuf_to_whack(buf, st->st_logger->object_whackfd,
				echo ? RC_USERPROMPT : RC_ENTERSECRET);
	}

	ssize_t n = fd_read(st->st_logger->object_whackfd, ansbuf, ansbuf_len);
	if (n < 0) {
		log_state(RC_LOG_SERIOUS, st, "read(whackfd) failed: "PRI_ERRNO,
			  pri_errno(-(int)n));
		return false;
	}

	if (n == 0) {
		log_state(RC_LOG_SERIOUS, st, "no %s entered, aborted", prompt);
		return false;
	}

	ansbuf[ansbuf_len - 1] = '\0'; /* ensure buffer is NULL terminated */
	return true;
}

static void log_raw(int severity, const char *prefix, struct jambuf *buf)
{
	/* assume there's a logging prefix; normally there is */
	struct realtm t = local_realtime(realnow());
	stdlog_raw(prefix, buf->array, &t);
	syslog_raw(severity, prefix, buf->array);
	/* not whack */
}

void jambuf_to_error_stream(struct jambuf *buf)
{
	log_raw(LOG_ERR, "", buf);
	if (in_main_thread() && fd_p(whack_log_fd)) {
		/* don't whack-log from helper threads */
		jambuf_to_whack(buf, whack_log_fd, RC_LOG_SERIOUS);
	}
}

void jambuf_to_debug_stream(struct jambuf *buf)
{
	log_raw(LOG_DEBUG, DEBUG_PREFIX, buf);
}

void jambuf_to_default_streams(struct jambuf *buf, enum rc_type rc)
{
	log_raw(LOG_WARNING, "", buf);
	if (in_main_thread() && fd_p(whack_log_fd)) {
		/* don't whack-log from helper threads */
		jambuf_to_whack(buf, whack_log_fd, rc);
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
}

/* emit message to whack.
 * form is "ddd statename text\n" where
 * - ddd is a decimal status code (RC_*) as described in whack.h
 * - text is a human-readable annotation
 */

static void whack_va_list(enum rc_type rc, const struct fd *whackfd,
			  const char *message, va_list args) PRINTF_LIKE_VA(3);
static void whack_va_list(enum rc_type rc, const struct fd *whackfd,
			  const char *message, va_list args)
{
	/* no-prefix: RC added by jambuf_to_whack() below */
	JAMBUF(buf) {
		/* always get the message out */
		if (!in_main_thread()) {
			jam_string(buf, "[EXPECTATION FAILED: on main thread]: ");
		}
		if (!fd_p(whackfd)) {
			jam_string(buf, "[EXPECTATION FAILED: whackfd valid]: ");
		}
		{
			jam_va_list(buf, message, args);
		}
		if (!in_main_thread() || !fd_p(whackfd)) {
			log_raw(LOG_ERR, "", buf);
		} else {
			jambuf_to_whack(buf, whackfd, rc);
		}
	}
}

void whack_log(enum rc_type rc, const struct fd *whackfd, const char *message, ...)
{
	va_list args;
	va_start(args, message);
	whack_va_list(rc, whackfd, message, args);
	va_end(args);
}

void whack_comment(const struct fd *whackfd, const char *message, ...)
{
	va_list args;
	va_start(args, message);
	whack_va_list(RC_COMMENT, whackfd, message, args);
	va_end(args);
}

void set_debugging(lset_t deb)
{
	cur_debugging = deb;
}

#define RATE_LIMIT 1000
static unsigned nr_rate_limited_logs;

static unsigned log_limit(void)
{
	if (impair.log_rate_limit == 0) {
		/* --impair log-rate-limit:no */
		return RATE_LIMIT;
	} else {
		/* --impair log-rate-limit:yes */
		/* --impair log-rate-limit:NNN */
		return impair.log_rate_limit;
	}
}

PRINTF_LIKE_VA(3)
static void rate_log_raw(const char *prefix,
			 struct logger *logger,
			 const char *message,
			 va_list ap)
{
	JAMBUF(buf) {
		jam_string(buf, prefix);
		jam_logger_prefix(buf, logger);
		jam_va_list(buf, message, ap);
		jambuf_to_logger(buf, logger, LOG_STREAM);
	}
}

void rate_log(const struct msg_digest *md,
	      const char *message, ...)
{
	unsigned limit = log_limit();
	va_list ap;
	va_start(ap, message);
	if (nr_rate_limited_logs < limit) {
		rate_log_raw("", md->md_logger, message, ap);
	} else if (nr_rate_limited_logs == limit) {
		rate_log_raw("", md->md_logger, message, ap);
		log_global(LOG_STREAM, null_fd,
			   "rate limited log reached limit of %u entries", limit);
	} else if (DBGP(DBG_BASE)) {
		rate_log_raw(DEBUG_PREFIX, md->md_logger, message, ap);
	}
	va_end(ap);
	nr_rate_limited_logs++;
}

static global_timer_cb reset_log_rate_limit;

static void reset_log_rate_limit(struct logger *logger)
{
	if (nr_rate_limited_logs > log_limit()) {
		llog(RC_LOG, logger, "rate limited log reset");
	}
	nr_rate_limited_logs = 0;
}

void init_rate_log(void)
{
	enable_periodic_timer(EVENT_RESET_LOG_RATE_LIMIT,
			      reset_log_rate_limit,
			      RESET_LOG_RATE_LIMIT);
}

static void log_whacks(enum rc_type rc, const struct fd *global_whackfd,
		       const struct fd *object_whackfd, struct jambuf *buf)
{
	if (fd_p(object_whackfd)) {
		jambuf_to_whack(buf, object_whackfd, rc);
	}
	if (fd_p(global_whackfd) &&
	    !same_fd(object_whackfd, global_whackfd)) {
		jambuf_to_whack(buf, global_whackfd, rc);
	}
}

void jambuf_to_logger(struct jambuf *buf, const struct logger *logger, lset_t rc_flags)
{
	enum rc_type rc = rc_flags & RC_MASK;
	enum stream only = rc_flags & STREAM_MASK;
	switch (only) {
	case DEBUG_STREAM:
		log_raw(LOG_DEBUG, DEBUG_PREFIX, buf);
		break;
	case ALL_STREAMS:
		log_raw(LOG_WARNING, "", buf);
		log_whacks(rc, logger->global_whackfd, logger->object_whackfd, buf);
		break;
	case LOG_STREAM:
		log_raw(LOG_WARNING, "", buf);
		break;
	case WHACK_STREAM:
		log_whacks(rc, logger->global_whackfd, logger->object_whackfd, buf);
		break;
	case ERROR_STREAM:
		log_raw(LOG_ERR, "", buf);
		log_whacks(rc, logger->global_whackfd, logger->object_whackfd, buf);
		break;
	case NO_STREAM:
		/*
		 * XXX: Like writing to /dev/null - go through the
		 * motions but with no result.  Code really really
		 * should not call this function with this flag.
		 */
		break;
	default:
		bad_case(only);
	}
}

static bool always_suppress_log(const void *object UNUSED)
{
	return true;
}

static bool never_suppress_log(const void *object UNUSED)
{
	return false;
}

static size_t jam_global_prefix(struct jambuf *unused_buf UNUSED,
			      const void *unused_object UNUSED)
{
	/* jam(buf, "") - nothing to add */
	return 0;
}

const struct logger_object_vec logger_global_vec = {
	.name = "global",
	.suppress_object_log = never_suppress_log,
	.jam_object_prefix = jam_global_prefix,
	.free_object = false,
};

struct logger logger_from(struct logger *global, const ip_endpoint *from)
{
	struct logger logger = {
		.where = HERE,
		.global_whackfd = global->global_whackfd,
		.object = from,
		.object_vec = &logger_from_vec,
	};
	return logger;
}

static size_t jam_from_prefix(struct jambuf *buf, const void *object)
{
	size_t s = 0;
	if (!in_main_thread()) {
		s += jam(buf, "EXPECTATION FAILED: %s in main thread: ", __func__);
	} else if (object == NULL) {
		s += jam(buf, "EXPECTATION FAILED: %s NULL: ", __func__);
	} else {
		const ip_endpoint *from = object;
		/* peer's IP address */
		if (endpoint_protocol(*from) == &ip_protocol_tcp) {
			s += jam(buf, "connection from ");
		} else {
			s += jam(buf, "packet from ");
		}
		s += jam_endpoint_sensitive(buf, from);
		s += jam(buf, ": ");
	}
	return s;
}

const struct logger_object_vec logger_from_vec = {
	.name = "from",
	.suppress_object_log = always_suppress_log,
	.jam_object_prefix = jam_from_prefix,
	.free_object = false,
};

static size_t jam_message_prefix(struct jambuf *buf, const void *object)
{
	size_t s = 0;
	if (!in_main_thread()) {
		s += jam(buf, "EXPECTATION FAILED: %s in main thread: ", __func__);
	} else if (object == NULL) {
		s += jam(buf, "EXPECTATION FAILED: %s NULL: ", __func__);
	} else {
		const struct msg_digest *md = object;
		s += jam_from_prefix(buf, &md->sender);
	}
	return s;
}

const struct logger_object_vec logger_message_vec = {
	.name = "message",
	.suppress_object_log = always_suppress_log,
	.jam_object_prefix = jam_message_prefix,
	.free_object = false,
};

static size_t jam_connection_prefix(struct jambuf *buf, const void *object)
{
	size_t s = 0;
	if (!in_main_thread()) {
		s += jam(buf, "EXPECTATION FAILED: %s in main thread: ",
			 __func__);
	} else if (object == NULL) {
		s += jam(buf, "EXPECTATION FAILED: %s NULL: ", __func__);
	} else {
		const struct connection *c = object;
		s += jam_connection(buf, c);
		s += jam(buf, ": ");
	}
	return s;
}

static bool suppress_connection_log(const void *object)
{
	const struct connection *connection = object;
	return connection->policy & POLICY_OPPORTUNISTIC;
}

const struct logger_object_vec logger_connection_vec = {
	.name = "connection",
	.suppress_object_log = suppress_connection_log,
	.jam_object_prefix = jam_connection_prefix,
	.free_object = false,
};

static size_t jam_state_prefix(struct jambuf *buf, const void *object)
{
	size_t s = 0;
	if (!in_main_thread()) {
		s += jam(buf, "EXPECTATION FAILED: %s in main thread: ", __func__);
	} else if (object == NULL) {
		s += jam(buf, "EXPECTATION FAILED: %s NULL: ", __func__);
	} else {
		const struct state *st = object;
		/*
		 * XXX: When delete state() triggers a delete
		 * connection, this can be NULL.
		 */
		if (st->st_connection != NULL) {
			s += jam_connection(buf, st->st_connection);
		}
		/* state number */
		s += jam(buf, " #%lu", st->st_serialno);
		/* state name */
		if (DBGP(DBG_ADD_PREFIX)) {
			s += jam(buf, " ");
			s += jam_string(buf, st->st_state->short_name);
		}
		s += jam(buf, ": ");
	}
	return s;
}

static bool suppress_state_log(const void *object)
{
	const struct state *state = object;
	return state->st_connection->policy & POLICY_OPPORTUNISTIC;
}

const struct logger_object_vec logger_state_vec = {
	.name = "state",
	.suppress_object_log = suppress_state_log,
	.jam_object_prefix = jam_state_prefix,
	.free_object = false,
};

static size_t jam_string_prefix(struct jambuf *buf, const void *object)
{
	const char *string = object;
	return jam_string(buf, string);
}

const struct logger_object_vec logger_string_vec = {
	.name = "string(never-suppress)",
	.suppress_object_log = never_suppress_log,
	.jam_object_prefix = jam_string_prefix,
	.free_object = true,
};

struct logger *alloc_logger(void *object, const struct logger_object_vec *vec, where_t where)
{
	struct logger logger = {
		.object = object,
		.object_vec = vec,
		.where = where,
	};
	struct logger *l = clone_thing(logger, "logger");
	dbg_alloc("alloc logger", l, where);
	return l;
}

struct logger *clone_logger(const struct logger *stack, where_t where)
{
	/*
	 * Convert the dynamicically generated OBJECT prefix into an
	 * unchanging string.  This way the prefix can be safely
	 * accessed on a helper thread.
	 */
	char prefix[LOG_WIDTH];
	struct jambuf prefix_buf = ARRAY_AS_JAMBUF(prefix);
	jam_logger_prefix(&prefix_buf, stack);
	/*
	 * choose a logger object vec with a hardwired suppress.
	 */
	const struct logger_object_vec *object_vec;
	if (suppress_log(stack)) {
		static const struct logger_object_vec always_suppress_vec = {
			.name = "string(always-suppressed)",
			.suppress_object_log = always_suppress_log,
			.jam_object_prefix = jam_string_prefix,
			.free_object = true,
		};
		object_vec = &always_suppress_vec;
	} else {
		object_vec = &logger_string_vec;
	}
	/* construct the clone */
	struct logger heap = {
		.global_whackfd = dup_any(stack->global_whackfd),
		.object_whackfd = dup_any(stack->object_whackfd),
		.where = stack->where,
		.object_vec = object_vec,
		.object = clone_str(prefix, "heap logger prefix"),
	};
	/* and clone it */
	struct logger *l = clone_thing(heap, "heap logger");
	dbg_alloc("clone logger", l, where);
	return l;
}

struct logger *string_logger(struct fd *whackfd, where_t where, const char *fmt, ...)
{
	/*
	 * Convert the dynamicically generated OBJECT prefix into an
	 * unchanging string.  This way the prefix can be safely
	 * accessed on a helper thread.
	 */
	char prefix[LOG_WIDTH];
	{
		struct jambuf prefix_buf = ARRAY_AS_JAMBUF(prefix);
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(&prefix_buf, fmt, ap);
		va_end(ap);
	}
	/* construct the clone */
	struct logger logger = {
		.global_whackfd = dup_any(whackfd),
		.object_whackfd = null_fd,
		.where = where,
		.object_vec = &logger_string_vec,
		.object = clone_str(prefix, "string logger prefix"),
	};
	/* and clone it */
	struct logger *l = clone_thing(logger, "string logger");
	dbg_alloc("string logger", l, where);
	return l;
}

void free_logger(struct logger **logp, where_t where)
{
	dbg_free("logger", *logp, where);
	close_any(&(*logp)->global_whackfd);
	close_any(&(*logp)->object_whackfd);
	/*
	 * For instance the string allocated by clone_logger().  More
	 * complex objects are freed by other means.
	 */
	if ((*logp)->object_vec->free_object) {
		pfree((void*) (*logp)->object);
	}
	/* done */
	pfree(*logp);
	*logp = NULL;
}

/*
 * XXX: these were macros only older GCC's, seeing for some code
 * paths, OBJECT was always non-NULL and pexpect(OBJECT!=NULL) was
 * constant, would generate a -Werror=address:
 *
 * error: the comparison will always evaluate as 'true' for the
 * address of 'stack_md' will never be NULL [-Werror=address]
 */

void log_pending(lset_t rc_flags, const struct pending *p, const char *msg, ...)
{
	passert(in_main_thread());
	passert(p != NULL);
	struct logger logger = {
		.where = HERE,
		.global_whackfd = whack_log_fd,
		.object_whackfd = p->whack_sock,
		.object = p->connection,
		.object_vec = &logger_connection_vec,
	};
	va_list ap;
	va_start(ap, msg);
	llog_va_list(rc_flags, &logger, msg, ap);
	va_end(ap);
}

void log_state(lset_t rc_flags, const struct state *st,
	       const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	if (pexpect((st) != NULL) &&
	    pexpect(in_main_thread())) {
		struct logger logger = *(st->st_logger);
		/*
		 * XXX: the state logger still needs to pick up the
		 * global whack FD :-(
		 */
		if (whack_log_fd != NULL) {
			logger.global_whackfd = whack_log_fd;
		}
		llog_va_list(rc_flags, &logger, msg, ap);
	} else {
		/* still get the message out */
		llog_va_list(rc_flags, &failsafe_logger, msg, ap);

	}
	va_end(ap);
}
