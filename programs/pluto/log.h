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
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifndef _PLUTO_LOG_H
#define _PLUTO_LOG_H

#include <libreswan.h>

#include "lswlog.h"

#ifndef PERPERRLOGDIR
#define PERPERRLOGDIR "/var/log/pluto/peer"
#endif

/* moved common code to library file */
#include "libreswan/passert.h"

extern bool
	log_to_perpeer,         /* should log go to per-IP file? */
	log_to_audit,         /* audit logs for kernel/auditd */
	log_with_timestamp,     /* prefix timestamp */
	log_append;

extern char *base_perpeer_logdir;
extern char *pluto_log_file;
extern char *pluto_stats_binary;

/* used in some messages to distiguish
 * which pluto is which, when doing
 * unit testing
 */
extern const char *pluto_ifn_inst;

/* maximum number of files to keep open for per-peer log files */
#define MAX_PEERLOG_COUNT 16

/* Context for logging.
 *
 * Global variables: must be carefully adjusted at transaction boundaries!
 * All are to be left in RESET condition and will be checked.
 * There are several pairs of routines to set and reset them.
 * If the context provides a whack file descriptor, messages
 * should be copied to it -- see whack_log()
 */
extern int whack_log_fd;                        /* only set during whack_handle() */
extern struct state *cur_state;                 /* current state, for diagnostics */
extern struct connection *cur_connection;       /* current connection, for diagnostics */
extern const ip_address *cur_from;              /* source of current current message */
extern u_int16_t cur_from_port;                 /* host order */

extern bool whack_prompt_for(int whackfd,
			     const char *prompt1,
			     const char *prompt2,
			     bool echo,
			     char *ansbuf, size_t ansbuf_len);

extern void passert_fail(const char *pred_str,
			 const char *file_str,
			 unsigned long line_no) NEVER_RETURNS;

/* for pushing state to other subsystems */
extern void log_state(struct state *st, enum state_kind state);

extern void extra_debugging(const struct connection *c);

#define reset_debugging() { set_debugging(base_debugging); }

#define GLOBALS_ARE_RESET() (whack_log_fd == NULL_FD \
			      && cur_state == NULL \
			      && cur_connection == NULL \
			      && cur_from == NULL \
			      && cur_debugging == base_debugging)

#define reset_globals() { \
		whack_log_fd = NULL_FD; \
		cur_state = NULL; \
		cur_from = NULL; \
		reset_cur_connection(); \
}

#define set_cur_connection(c) { \
		cur_connection = (c); \
		extra_debugging(c); \
}

#define reset_cur_connection() { \
		cur_connection = NULL; \
		reset_debugging(); \
}

#define set_cur_state(s) { \
		cur_state = (s); \
		extra_debugging((s)->st_connection); \
}

#define reset_cur_state() { \
		cur_state = NULL; \
		reset_debugging(); \
}

extern void pluto_init_log(void);
extern void close_log(void);
extern void exit_log(const char *message, ...) PRINTF_LIKE(1) NEVER_RETURNS;

/* close of all per-peer logging */
extern void close_peerlog(void);

/* free all per-peer log resources */
extern void perpeer_logfree(struct connection *c);

extern void whack_log(int mess_no, const char *message, ...) PRINTF_LIKE(2);

/* show status, usually on whack log */
extern void show_status(void);

/*
 * call this routine to reset daily items.
 */
extern void daily_log_reset(void);
extern void daily_log_event(void);

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

/*
 * some events are to be logged only occasionally.
 */
extern bool logged_txt_warning;
extern bool logged_myid_ip_txt_warning;
extern bool logged_myid_fqdn_txt_warning;

#endif /* _PLUTO_LOG_H */
