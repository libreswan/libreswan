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
extern void reset_debugging(void);

extern lset_t base_debugging;	/* bits selecting what to report */

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
 * Direct a log message, possibly prefix with the supplied context
 * (ST, C, MD, FROM), to either log file, whack, or debug stream; or
 * some combination of those three :-/
 *
 * Todays proposed naming convention:
 *
 *   {plog,loglog,wlog,dbg}_{global,from,md,c,st,raw}()
 *
 * {plog,loglog,wlog,dbg} -> plog: write to pluto's log file (but not
 * whack); wlog: write to whack (but not pluto's log file); loglog:
 * write to both; dbg: a debug log record to pluto's log file (but not
 * whack).
 *
 * {global,from,md,c,st} -> global: no context prefix; from: endpoint
 * as prefix; md: endpoint from md as prefix; c: connection+instance
 * as prefix; st: state+connection as prefix; raw: takes all
 * parameters with the most detailed non-NULL value being prefered.
 *
 * XXX:
 *
 * - many of the above combinations are meaningless
 *
 * - As a way of encouraging the use of log functions that include the
 *   context, the context free log function is given the annoyngly
 *   long name plog_global() and not the shorter plog().
 *
 * - instead of a custom whack+pluto logging function, should whack
 *   logging be decided by a flag in 'c' and/or 'st'?  Suspect that is
 *   how things have largely managed to work, and if whack is
 *   monitoring a state or connection then all messages for that state
 *   or connection should be sent there
 *
 * - in addition there is rate_log(md), should it send to whack when
 *   available?  Or should this be merged with above.
 */

typedef void (log_raw_fn)(enum rc_type,
			  const struct state *st,
			  const struct connection *c,
			  const ip_endpoint *from,
			  const char *message, ...) PRINTF_LIKE(5);

log_raw_fn plog_raw;

#define plog_global(MESSAGE, ...) plog_raw(RC_COMMENT, NULL, NULL, NULL, MESSAGE,##__VA_ARGS__);
#define plog_from(FROM, MESSAGE, ...) plog_raw(RC_COMMENT, NULL, NULL, FROM, MESSAGE,##__VA_ARGS__);
#define plog_md(MD, MESSAGE, ...) plog_raw(RC_COMMENT, NULL, NULL, &(MD)->sender, MESSAGE,##__VA_ARGS__);
#define plog_c(C, MESSAGE, ...) plog_raw(RC_COMMENT, NULL, C, NULL, MESSAGE,##__VA_ARGS__);
#define plog_st(ST, MESSAGE, ...) plog_raw(RC_COMMENT, ST, NULL, NULL, MESSAGE,##__VA_ARGS__);

log_raw_fn loglog_raw;

/* unconditional */
log_raw_fn DBG_raw;


/*
 * rate limited logging
 */
void rate_log(const struct msg_digest *md,
	      const char *message, ...) PRINTF_LIKE(2);

/*
 * Log 'cur' directly (without setting it first).
 */

void log_prefix(struct lswlog *buf, bool debug,
		struct state *st, struct connection *c);

#define LSWLOG_CONNECTION(CONNECTION, BUF)				\
	LSWLOG_(true, BUF,						\
		log_prefix(BUF, false, NULL, CONNECTION),		\
		lswlog_to_default_streams(BUF, RC_LOG))

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
