/* logging declarations, for libreswan's pluto
 *
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2004 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
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

#ifndef _PLUTO_LOG_H
#define _PLUTO_LOG_H

#include <libreswan.h>

#include "lswcdefs.h"
#include "lswlog.h"
#include "fd.h"
#include "ip_endpoint.h"

struct state;
struct connection;
struct msg_digest;
struct pending;
struct show;

/* moved common code to library file */
#include "passert.h"

struct log_param {
	bool log_with_timestamp;	/* testsuite requires no timestamps */
};

/* start with this before parsing options */
extern const struct log_param default_log_param;

/*
 * Log 'cur' directly (without setting it first).
 */

extern void pluto_init_log(struct log_param);
void init_rate_log(void);
extern void close_log(void);

extern bool log_to_audit;
extern bool log_append;
extern bool log_to_syslog;          /* should log go to syslog? */
extern char *pluto_log_file;
extern char *pluto_stats_binary;

/* Context for logging.
 *
 * Global variables: must be carefully adjusted at transaction boundaries!
 * All are to be left in RESET condition and will be checked.
 * There are several pairs of routines to set and reset them.
 * If the context provides a whack file descriptor, messages
 * should be copied to it -- see whack_log()
 */
extern struct fd *whack_log_fd;           /* only set during whack_handle() */

extern bool whack_prompt_for(struct state *st, const char *prompt,
			     bool echo, char *ansbuf, size_t ansbuf_len);

/* for pushing state to other subsystems */
#define binlog_refresh_state(st) binlog_state((st), (st)->st_state->kind)
#define binlog_fake_state(st, new_state) binlog_state((st), (new_state))
extern void binlog_state(struct state *st, enum state_kind state);

extern void set_debugging(lset_t deb);

extern const struct logger_object_vec logger_global_vec;
extern const struct logger_object_vec logger_from_vec;
extern const struct logger_object_vec logger_message_vec;
extern const struct logger_object_vec logger_connection_vec;
extern const struct logger_object_vec logger_state_vec;
extern const struct logger_object_vec logger_string_vec;

extern struct logger failsafe_logger;

struct logger *string_logger(struct fd *whackfd, where_t where, const char *fmt, ...)
	PRINTF_LIKE(3) MUST_USE_RESULT; /* must free */

#define GLOBAL_LOGGER(WHACKFD) (struct logger)			\
	{							\
		.where = HERE,					\
		.global_whackfd = WHACKFD,			\
		.object = NULL,					\
		.object_vec = &logger_global_vec,		\
	}
struct logger logger_from(struct logger *outer, const ip_endpoint *endpoint); /*on-stack*/
struct logger *alloc_logger(void *object, const struct logger_object_vec *vec, where_t where);
struct logger *clone_logger(const struct logger *stack, where_t where);
void free_logger(struct logger **logp, where_t where);

#define log_verbose(RC_FLAGS, LOGGER, FORMAT, ...)			\
	{								\
		if (suppress_log(LOGGER)) {				\
			dbg(FORMAT, ##__VA_ARGS__);			\
		} else {						\
			llog(RC_FLAGS, LOGGER, FORMAT,		\
				    ##__VA_ARGS__);			\
		}							\
	}

/*
 * Log with no context.
 */

#define log_global(RC, WHACKFD, MESSAGE, ...)				\
	{								\
		struct logger log_ = GLOBAL_LOGGER(WHACKFD);		\
		llog(RC,	&log_,					\
			    MESSAGE,##__VA_ARGS__);			\
	}

/*
 * Log with a connection context.
 *
 * Unlike state and pending, connections do not have an attached
 * WHACKFD.  Instead connection operations only log to whack when
 * being called by the whack event handler (where WHACKFD is passed
 * down).  If whack needs to remain attached after the whack event
 * handler returns then the WHACKFD parameter is duped into to either
 * a state or pending struct.
 */

void log_pending(lset_t rc_flags, const struct pending *p,
		 const char *msg, ...) PRINTF_LIKE(3);

/*
 * log the state; notice how it still needs to pick up the global
 * whackfd.
 */

void log_state(lset_t rc_flags, const struct state *st,
	       const char *msg, ...) PRINTF_LIKE(3);

/*
 * Wrappers.
 *
 * XXX: do these help or hinder - would calling log_state() directly
 * be better (if slightly more text)?  For the moment stick with the
 * wrappers so changing the underlying implementation is easier.
 *
 * XXX: what about whack_log()?  That only sends messages to the
 * global whack (and never the objects whack).  Likely easier to stick
 * with whack_log() and manually add the prefix as needed.
 */

/*
 * rate limited logging
 */
void rate_log(const struct msg_digest *md,
	      const char *message, ...) PRINTF_LIKE(2);

/*
 * Whack only logging.
 *
 * None of these functions add a context prefix (such as connection
 * name).  If that's really really needed then use
 * log_*(WHACK_STREAM,...) above.
 *
 * whack_comment() output includes the '000 ' prefix (RC_COMMENT).  It
 * also requires a valid whackfd.  It should only be used by show
 * commands.
 */

void whack_log(enum rc_type rc, const struct fd *whackfd, const char *message, ...) PRINTF_LIKE(3);
void whack_comment(const struct fd *whackfd, const char *message, ...) PRINTF_LIKE(2);

extern void show_status(struct show *s);
extern void show_setup_plutomain(struct show *s);
extern void show_setup_natt(struct show *s);
extern void show_global_status(struct show *s);

enum linux_audit_kind {
	LAK_PARENT_START,
	LAK_CHILD_START,
	LAK_PARENT_DESTROY,
	LAK_CHILD_DESTROY,
	LAK_PARENT_FAIL,
	LAK_CHILD_FAIL
};
extern void linux_audit_conn(const struct state *st, enum linux_audit_kind);

#ifdef USE_LINUX_AUDIT
extern void linux_audit_init(int do_audit, struct logger *logger);
# include <libaudit.h>	/* from audit-libs devel */
# define AUDIT_LOG_SIZE 256
/* should really be in libaudit.h */
# define AUDIT_RESULT_FAIL 0
# define AUDIT_RESULT_OK 1
# ifndef AUDIT_CRYPTO_IKE_SA
#  define AUDIT_CRYPTO_IKE_SA 2408
# endif
# ifndef AUDIT_CRYPTO_IPSEC_SA
#  define AUDIT_CRYPTO_IPSEC_SA 2409
# endif
#endif

void jambuf_to_default_streams(struct jambuf *buf, enum rc_type rc);

#define LSWLOG_DEBUG(BUF)					\
	JAMBUF(BUF)						\
		/* no-prefix */					\
		for (; BUF != NULL;				\
		     jambuf_to_debug_stream(BUF), BUF = NULL)

#define LSWDBGP(DEBUG, BUF)						\
	for (bool lswlog_p = DBGP(DEBUG); lswlog_p; lswlog_p = false)	\
		JAMBUF(BUF)						\
			/* no-prefix */					\
			for (; BUF != NULL;				\
			     jambuf_to_debug_stream(BUF), BUF = NULL)

#endif /* _PLUTO_LOG_H */
