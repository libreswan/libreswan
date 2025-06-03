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

#include "lswcdefs.h"
#include "lswlog.h"
#include "fd.h"
#include "ip_endpoint.h"
#include "monotime.h"

struct ike_sa;
struct state;
struct connection;
struct msg_digest;
struct pending;
struct show;
struct config_setup;

/* moved common code to library file */
#include "passert.h"

/*
 * Log 'cur' directly (without setting it first).
 */

struct logger *init_log(const char *progname);
void switch_log(const struct config_setup *oco, struct logger **logger);
void close_log(void);	/* call after report_leaks() */
void show_log(struct show *s);

extern bool whack_prompt_for(struct ike_sa *ike,
			     const char *prompt,
			     bool echo,
			     char *ansbuf,
			     size_t ansbuf_len);

void release_whack(struct logger *logger, where_t where);

bool whack_attached(const struct logger *logger);
bool same_whack(const struct logger *lhs, const struct logger *rhs);
void whack_attach_where(struct logger *dst, const struct logger *src, where_t where);
void whack_detach_where(struct logger *dst, const struct logger *src, where_t where);

#define whack_attach(DST, SRC) whack_attach_where(DST, SRC, HERE)
#define whack_detach(DST, SRC) whack_detach_where(DST, SRC, HERE)

void md_attach_where(struct msg_digest *md, const struct logger *src, where_t where);
void md_detach_where(struct msg_digest *md, const struct logger *src, where_t where);

#define md_attach(MD, SRC) md_attach_where(MD, SRC, HERE)
#define md_detach(MD, SRC) md_detach_where(MD, SRC, HERE)

void connection_attach_where(struct connection *c, const struct logger *src, where_t where);
void connection_detach_where(struct connection *c, const struct logger *src, where_t where);

#define connection_attach(C, SRC) connection_attach_where(C, SRC, HERE)
#define connection_detach(C, SRC) connection_detach_where(C, SRC, HERE)

void state_attach_where(struct state *st, const struct logger *src, where_t where);
void state_detach_where(struct state *st, const struct logger *src, where_t where);

#define state_attach(ST, SRC) state_attach_where(ST, SRC, HERE)
#define state_detach(ST, SRC) state_detach_where(ST, SRC, HERE)

/* for pushing state to other subsystems */
#define binlog_refresh_state(st) binlog_state((st), (st)->st_state->kind)
#define binlog_fake_state(st, new_state) binlog_state((st), (new_state))
extern void binlog_state(struct state *st, enum state_kind state);
void init_binlog(const struct config_setup *oco, struct logger *logger);

extern void set_debugging(lset_t deb);

extern const struct logger_object_vec logger_from_vec;
extern const struct logger_object_vec logger_message_vec;
extern const struct logger_object_vec logger_connection_vec;
extern const struct logger_object_vec logger_state_vec;

struct logger *string_logger(where_t where, const char *fmt, ...)
	PRINTF_LIKE(2) MUST_USE_RESULT; /* must free */

struct logger logger_from(struct logger *outer, const ip_endpoint *endpoint); /*on-stack*/
struct logger *alloc_logger(void *object, const struct logger_object_vec *vec,
			    lset_t debugging, where_t where);
struct logger *clone_logger(const struct logger *stack, where_t where);
void free_logger(struct logger **logp, where_t where);

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
 * Log the state.
 *
 * PRI_STATE() / PRI_SA() try to match the llog_sa() prefix.
 */

void log_state(lset_t rc_flags, const struct state *st,
	       const char *msg, ...) PRINTF_LIKE(3);
#define llog_sa(RC_FLAGS, SA, MSG, ...) llog(RC_FLAGS, (SA)->sa.logger, MSG, ##__VA_ARGS__)
#define ldbg_sa(SA, MSG, ...) ldbg((SA)->sa.logger, MSG, ##__VA_ARGS__)

#define state_buf connection_buf /* hack */
#define PRI_STATE PRI_CONNECTION" "PRI_SO
#define pri_state(ST, B) pri_connection((ST)->st_connection, B), pri_so((ST)->st_serialno)

size_t jam_state(struct jambuf *buf, const struct state *st);

extern void show_setup_plutomain(struct show *s);
extern void show_setup_natt(struct show *s);

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
extern bool linux_audit_init(bool do_audit, struct logger *logger);
extern bool linux_audit_enabled(void);
# include <libaudit.h>			/* from rpm:audit-libs-devel */
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
