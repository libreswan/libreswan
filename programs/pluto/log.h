/* logging declarations
 *
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2004 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
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
#include "ip_address.h"

struct state;
struct connection;

/* moved common code to library file */
#include "libreswan/passert.h"

extern bool
	log_with_timestamp,     /* prefix timestamp */
	log_append;

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
extern void log_state(struct state *st, enum state_kind state);

extern void set_debugging(lset_t deb);
extern void reset_debugging(void);

extern lset_t base_debugging;	/* bits selecting what to report */

extern void log_reset_globals(const char *func, const char *file, long line);
#define reset_globals() log_reset_globals(__func__, PASSERT_BASENAME, __LINE__)

extern void log_pexpect_reset_globals(const char *func, const char *file, long line);
#define pexpect_reset_globals() log_pexpect_reset_globals(__func__, PASSERT_BASENAME, __LINE__)

struct connection *log_push_connection(struct connection *c, const char *func,
				       const char *file, long line);
void log_pop_connection(struct connection *c, const char *func,
			const char *file, long line);

#define push_cur_connection(C) log_push_connection(C, __func__, PASSERT_BASENAME, __LINE__)
#define pop_cur_connection(C) log_pop_connection(C, __func__, PASSERT_BASENAME, __LINE__)

so_serial_t log_push_state(struct state *st, const char *func,
			   const char *file, long line);
void log_pop_state(so_serial_t serialno, const char *func,
		   const char *file, long line);

#define push_cur_state(ST) log_push_state(ST, __func__, PASSERT_BASENAME, __LINE__)
#define pop_cur_state(ST) log_pop_state(ST, __func__, PASSERT_BASENAME, __LINE__)

#define set_cur_connection(C) push_cur_connection(C)
#define reset_cur_connection() pop_cur_connection(NULL)
#define set_cur_state(ST) push_cur_state(ST)
#define reset_cur_state() pop_cur_state(SOS_NOBODY)

extern ip_address log_push_from(ip_address new_from, const char *func,
				const char *file, long line);
extern void log_pop_from(ip_address old_from, const char *func,
			 const char *file, long line);

#define push_cur_from(NEW)					\
	log_push_from(NEW, __func__, PASSERT_BASENAME, __LINE__)
#define pop_cur_from(OLD)						\
	log_pop_from(OLD, __func__, PASSERT_BASENAME, __LINE__)


/*
 * Log 'cur' directly (without setting it first).
 */

void log_prefix(struct lswlog *buf, bool debug,
		struct state *st, struct connection *c);

#define LSWLOG_STATE(STATE, BUF)					\
	LSWLOG_(true, BUF,						\
		log_prefix(BUF, false, STATE, NULL),			\
		lswlog_to_default_streams(BUF, RC_LOG))

#define LSWLOG_CONNECTION(CONNECTION, BUF)				\
	LSWLOG_(true, BUF,						\
		log_prefix(BUF, true, NULL, CONNECTION),		\
		lswlog_to_default_streams(BUF, RC_LOG))

bool log_debugging(struct state *st, struct connection *c, lset_t predicate);

#define LSWDBGP_STATE(DEBUG, STATE, BUF)				\
	LSWLOG_(log_debugging(STATE, NULL, DEBUG), BUF,			\
		log_prefix(BUF, true, STATE, NULL),			\
		lswlog_to_debug_stream(BUF))

#define LSWDBGP_CONNECTION(DEBUG, CONNECTION, BUF)			\
	LSWLOG_(log_debugging(NULL, CONNECTION, DEBUG), BUF,		\
		log_prefix(BUF, true, NULL, CONNECTION),		\
		lswlog_to_debug_stream(BUF))

extern void pluto_init_log(void);
extern void close_log(void);
extern void exit_log(const char *message, ...) PRINTF_LIKE(1) NEVER_RETURNS;

/*
 * struct lswlog primitives
 */
bool whack_log_p(void);
void whack_log_pre(enum rc_type rc, struct lswlog *buf);

void whack_log(enum rc_type rc, const char *message, ...) PRINTF_LIKE(2);
/*
 * Like whack_log() but suppress the 'NNN ' prefix.
 */
void whack_log_comment(const char *message, ...) PRINTF_LIKE(1);

/* show status, usually on whack log */
extern void show_status(void);

extern void show_setup_plutomain(void);
extern void show_setup_natt(void);
extern void show_global_status(void);

#ifdef USE_LINUX_AUDIT
#include <libaudit.h>	/* from audit-libs devel */
#define AUDIT_LOG_SIZE 256
/* should really be in libaudit.h */
#define AUDIT_RESULT_FAIL 0
#define AUDIT_RESULT_OK 1
#ifndef AUDIT_CRYPTO_IKE_SA
# define AUDIT_CRYPTO_IKE_SA 2408
#endif
#ifndef AUDIT_CRYPTO_IPSEC_SA
# define AUDIT_CRYPTO_IPSEC_SA 2409
#endif

enum linux_audit_kind {
	LAK_PARENT_START,
	LAK_CHILD_START,
	LAK_PARENT_DESTROY,
	LAK_CHILD_DESTROY
};
extern void linux_audit_init(void);
extern void linux_audit(const int type, const char *message,
			const char *addr, const int result);
extern void linux_audit_conn(const struct state *st, enum linux_audit_kind);
#endif

#endif /* _PLUTO_LOG_H */
