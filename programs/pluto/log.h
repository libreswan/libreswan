/* logging declarations
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

/* moved common code to library file */
#include "libreswan/passert.h"

extern bool
	log_with_timestamp,     /* prefix timestamp */
	log_append,
	log_to_audit;

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
extern fd_t whack_log_fd;                        /* only set during whack_handle() */

extern bool whack_prompt_for(fd_t whackfd,
			     const char *prompt1,
			     const char *prompt2,
			     bool echo,
			     char *ansbuf, size_t ansbuf_len);

/* for pushing state to other subsystems */
#define binlog_refresh_state(st) binlog_state((st), (st)->st_state->kind)
#define binlog_fake_state(st, new_state) binlog_state((st), (new_state))
extern void binlog_state(struct state *st, enum state_kind state);

extern void set_debugging(lset_t deb);

extern void log_reset_globals(where_t where);
#define reset_globals() log_reset_globals(HERE)

extern void log_pexpect_reset_globals(where_t where);
#define pexpect_reset_globals() log_pexpect_reset_globals(HERE)

struct connection *log_push_connection(struct connection *c, where_t where);
void log_pop_connection(struct connection *c, where_t where);

#define push_cur_connection(C) log_push_connection(C, HERE)
#define pop_cur_connection(C) log_pop_connection(C, HERE)

so_serial_t log_push_state(struct state *st, where_t where);
void log_pop_state(so_serial_t serialno, where_t where);

#define push_cur_state(ST) log_push_state(ST, HERE)
#define pop_cur_state(ST) log_pop_state(ST, HERE)

#define set_cur_connection(C) push_cur_connection(C)
#define reset_cur_connection() pop_cur_connection(NULL)
bool is_cur_connection(const struct connection *c);
#define set_cur_state(ST) push_cur_state(ST)
#define reset_cur_state() pop_cur_state(SOS_NOBODY)

extern ip_address log_push_from(ip_address new_from, where_t where);
extern void log_pop_from(ip_address old_from, where_t where);

#define push_cur_from(NEW) log_push_from(NEW, HERE)
#define pop_cur_from(OLD) log_pop_from(OLD, HERE)

/*
 * Broadcast a log message.
 *
 * By default send it to the log file and any attached whacks (both
 * globally and the object).
 *
 * If any *_STREAM flag is specified then only send the message to
 * that stream.
 *
 * XXX:
 *
 * - how should this handle the error stream (i.e., the log stream
 *   with severity LOG_ERR)
 *
 * - what about having debug logging's prefix (this currently uses the
 *   same prefix as for normal logging).
 *
 * - this can't replace whack_log() which _only_ sends messages to the
 *   global whack
 *
 * - should these be made bits so they can be combined?
 */

enum stream {
	/*
	 * This means that a simple RC_* code will go to both whack
	 * and and the log files.
	 */
	/* Mask the whack RC; max value is 64435+200 */
	RC_MASK		= 0x0fffff,
	/*                                 Severity     Whack Prefix */
	ALL_STREAMS     = 0x000000,	/* LOG_WARNING   yes         */
	LOG_STREAM	= 0x100000,	/* LOG_WARNING   no          */
	DEBUG_STREAM	= 0x200000,	/* LOG_DEBUG     no    "| "  */
	WHACK_STREAM	= 0x300000,	/*    N/A        yes         */
	ERROR_STREAM	= 0x400000,	/* LOG_ERR       no          */
	NO_STREAM	= 0xf00000,	/* n/a */
};

void log_message(lset_t rc_flags,
		 const struct state *st,
		 const struct connection *c,
		 const ip_address *from,
		 const char *format, ...) PRINTF_LIKE(5);

void log_pending(lset_t rc_flags,
		 const struct pending *pending,
		 const char *format, ...) PRINTF_LIKE(3);

void log_state(lset_t rc_flags,
	       const struct state *st,
	       const char *format, ...)	PRINTF_LIKE(3);

/*
 * Wrappers.
 *
 * XXX: do these help or hinder - would calling log_state() directly
 * be better (if slightly more text)?  For the moment stick with the
 * wrappers so changing the underlying implementation is easier.
 *
 * XXX: what about dbg_state() et.al.?  Since these always add a
 * prefix the debate is open.  However, when cur_state is deleted
 * (sure ...), the debug-prefix macro will break.
 *
 * XXX: what about whack_log()?  That only sends messages to the
 * global whack (and never the objects whack).  Likely easier to stick
 * with whack_log() and manually add the prefix as needed.
 */

#define PLOG_RAW(STATE, CONNECTION, FROM, BUF)				\
	LSWLOG_(true, BUF,						\
		jam_log_prefix(BUF, STATE, CONNECTION, FROM),		\
		lswlog_to_log_stream(BUF))

#define plog_global(MESSAGE, ...) log_message(LOG_STREAM, NULL, NULL, NULL, MESSAGE,##__VA_ARGS__);
#define plog_from(FROM, MESSAGE, ...) log_message(LOG_STREAM, NULL, NULL, FROM, MESSAGE,##__VA_ARGS__);
#define plog_md(MD, MESSAGE, ...) log_message(LOG_STREAM, NULL, NULL, &(MD)->sender, MESSAGE,##__VA_ARGS__);
#define plog_connection(C, MESSAGE, ...) log_message(LOG_STREAM, NULL, C, NULL, MESSAGE,##__VA_ARGS__);
#define plog_state(ST, MESSAGE, ...) log_state(LOG_STREAM, ST, MESSAGE,##__VA_ARGS__);

/*
 * rate limited logging
 */
void rate_log(const struct msg_digest *md,
	      const char *message, ...) PRINTF_LIKE(2);

/*
 * Log 'cur' directly (without setting it first).
 */

void jam_log_prefix(struct lswlog *buf,
		    const struct state *st,
		    const struct connection *c,
		    const ip_address *from);

extern void pluto_init_log(void);
void init_rate_log(void);
extern void close_log(void);
extern void exit_log(const char *message, ...) PRINTF_LIKE(1) NEVER_RETURNS;


/*
 * struct lswlog primitives
 */
bool whack_log_p(void);

void whack_log(enum rc_type rc, const char *message, ...) PRINTF_LIKE(2);
/*
 * Like whack_log(RC_COMMENT, ...) but suppress the 'NNN ' prefix.
 *
 * XXX: whack_log_comment() -> whack_print().
 */
#define whack_log_comment(FMT, ...) whack_log(RC_PRINT, FMT,##__VA_ARGS__)

/* show status, usually on whack log */
extern void show_status(void);

extern void show_setup_plutomain(void);
extern void show_setup_natt(void);
extern void show_global_status(void);

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
extern void linux_audit_init(int do_audit);
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

#endif /* _PLUTO_LOG_H */
