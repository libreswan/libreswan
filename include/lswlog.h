/* logging declaratons
 *
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2004 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
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

#ifndef _LSWLOG_H_
#define _LSWLOG_H_

#include <libreswan.h>
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>

/* moved common code to library file */
#include "libreswan/passert.h"

/*
 * Everything goes through here.
 *
 * Like vprintf() this modifies AP; to preserve AP use C99's
 * va_copy().
 */
extern void libreswan_vloglog(int mess_no, const char *fmt, va_list ap);

/*
 * Log to both main log and whack log with MESS_NO.
 */
#define loglog	libreswan_loglog
extern void libreswan_loglog(int mess_no, const char *fmt, ...) PRINTF_LIKE(2);

/*
 * Log to both main log and whack log at level RC_LOG.
 */
#define plog	libreswan_log
extern int libreswan_log(const char *fmt, ...) PRINTF_LIKE(1);

#include "constants.h"

extern lset_t base_debugging;	/* bits selecting what to report */
extern lset_t cur_debugging;	/* current debugging level */
extern void set_debugging(lset_t deb);

#define DBGP(cond)	(cur_debugging & (cond))

/*
 * NOTE: DBG's action can be a { } block, but that block must not
 * contain commas that are outside quotes or parenthesis.
 * If it does, they will be interpreted by the C preprocesser
 * as macro argument separators.  This happens accidentally if
 * multiple variables are declared in one declaration.
 */
#define DBG(cond, action)	{ if (DBGP(cond)) { action; } }

#define DBG_log libreswan_DBG_log
#define DBG_dump libreswan_DBG_dump
extern int libreswan_DBG_log(const char *message, ...) PRINTF_LIKE(1);
extern void libreswan_DBG_dump(const char *label, const void *p, size_t len);

#define DBG_dump_chunk(label, ch) DBG_dump(label, (ch).ptr, (ch).len)

#define DBG_cond_dump(cond, label, p, len) DBG(cond, DBG_dump(label, p, len))
#define DBG_cond_dump_chunk(cond, label, ch) DBG(cond, DBG_dump_chunk(label, \
								      ch))

/* Build up a diagnostic in a static buffer -- NOT RE-ENTRANT.
 * Although this would be a generally useful function, it is very
 * hard to come up with a discipline that prevents different uses
 * from interfering.  It is intended that by limiting it to building
 * diagnostics, we will avoid this problem.
 * Juggling is performed to allow an argument to be a previous
 * result: the new string may safely depend on the old one.  This
 * restriction is not checked in any way: violators will produce
 * confusing results (without crashing!).
 */
#define LOG_WIDTH	((size_t)1024)	/* roof of number of chars in log line */

extern err_t builddiag(const char *fmt, ...) PRINTF_LIKE(1);	/* NOT RE-ENTRANT */

extern bool log_to_stderr;          /* should log go to stderr? */
extern bool log_to_syslog;          /* should log go to syslog? */

/*
 * For stand-alone tools.
 *
 * XXX: can "progname" be made private to lswlog.c?
 */
extern char *progname;
extern void tool_init_log(char *progname);
extern void tool_close_log(void);

/* Codes for status messages returned to whack.
 * These are 3 digit decimal numerals.  The structure
 * is inspired by section 4.2 of RFC959 (FTP).
 * Since these will end up as the exit status of whack, they
 * must be less than 256.
 * NOTE: ipsec_auto(8) knows about some of these numbers -- change carefully.
 */
enum rc_type {
	RC_COMMENT,		/* non-commital utterance (does not affect exit status) */
	RC_WHACK_PROBLEM,	/* whack-detected problem */
	RC_LOG,			/* message aimed at log (does not affect exit status) */
	RC_LOG_SERIOUS,		/* serious message aimed at log (does not affect exit status) */
	RC_SUCCESS,		/* success (exit status 0) */
	RC_INFORMATIONAL,	/* should get relayed to user - if there is one */
	RC_INFORMATIONAL_TRAFFIC, /* status of an established IPSEC (aka Phase 2) state */

	/* failure, but not definitive */
	RC_RETRANSMISSION = 10,

	/* improper request */
	RC_DUPNAME = 20,	/* attempt to reuse a connection name */
	RC_UNKNOWN_NAME,	/* connection name unknown or state number */
	RC_ORIENT,		/* cannot orient connection: neither end is us */
	RC_CLASH,		/* clash between two Road Warrior connections OVERLOADED */
	RC_DEAF,		/* need --listen before --initiate */
	RC_ROUTE,		/* cannot route */
	RC_RTBUSY,		/* cannot unroute: route busy */
	RC_BADID,		/* malformed --id */
	RC_NOKEY,		/* no key found through DNS */
	RC_NOPEERIP,		/* cannot initiate when peer IP is unknown */
	RC_INITSHUNT,		/* cannot initiate a shunt-oly connection */
	RC_WILDCARD,		/* cannot initiate when ID has wildcards */
	RC_CRLERROR,		/* CRL fetching disabled or obsolete reread cmd */

	/* permanent failure */
	RC_BADWHACKMESSAGE = 30,
	RC_NORETRANSMISSION,
	RC_INTERNALERR,
	RC_OPPOFAILURE,		/* Opportunism failed */
	RC_CRYPTOFAILED,	/* system too busy to perform required
				* cryptographic operations */
	RC_AGGRALGO,		/* multiple algorithms requested in phase 1 aggressive */
	RC_FATAL,		/* fatal error encountered, and negotiation aborted */

	/* entry of secrets */
	RC_ENTERSECRET = 40,
	RC_USERPROMPT = 41,

	/* progress: start of range for successful state transition.
	 * Actual value is RC_NEW_STATE plus the new state code.
	 */
	RC_NEW_STATE = 100,

	/* start of range for notification.
	 * Actual value is RC_NOTIFICATION plus code for notification
	 * that should be generated by this Pluto.
	 */
	RC_NOTIFICATION = 200	/* as per IKE notification messages */
};

/*
 * Wrap <message> in a prefix and suffix where the suffix contains
 * errno and message.  Since __VA_ARGS__ may alter ERRNO, it needs to
 * be saved.
 */

void lswlog_log_errno(int e, const char *prefix,
		      const char *message, ...) PRINTF_LIKE(3);
void lswlog_exit(int rc) NEVER_RETURNS;

#define LOG_ERRNO(ERRNO, ...)						\
	{								\
		int log_errno = ERRNO; /* save the value */		\
		lswlog_log_errno(log_errno, "ERROR: ", __VA_ARGS__);	\
	}

#define EXIT_LOG_ERRNO(ERRNO, ...)					\
	{								\
		int exit_log_errno = ERRNO; /* save the value */	\
		lswlog_log_errno(exit_log_errno, "FATAL ERROR: ", __VA_ARGS__); \
		lswlog_exit(PLUTO_EXIT_FAIL);				\
	}

/*
 * general utilities
 */

/* sanitize a string */
extern void sanitize_string(char *buf, size_t size);

/*
 * A generic buffer for accumulating log output.
 */

struct lswbuf {
	/*
	 * BUF contains the accumulated log output.  It is always NUL
	 * terminated (LEN specifes the location of the NUL).
	 *
	 * BUF can contain up to BOUND-1 characters of log output
	 * (i.e. LEN<BOUND).
	 *
	 * An attempt to accumulate more than BOUND-1 characters will
	 * cause the output to be truncated, and last few characters
	 * replaced by DOTS.
	 *
	 * A buffer containing truncated output is identified by LEN
	 * == BOUND.
	 */
	signed char parrot;
	char buf[LOG_WIDTH + 1]; /* extra NUL */
	signed char canary;
	size_t len;
};

extern const struct lswbuf empty_lswbuf;

struct lswlog {
#define LSWBUF_BUF(LOG) ((LOG)->buf->buf)
#define LSWBUF_LEN(LOG) ((LOG)->buf->len)
	struct lswbuf *buf;
	size_t bound; /* < sizeof(LSWBUF_BUF()) */
	const char *dots;
};

/*
 * To debug, set this to printf or similar.
 */
extern int (*lswlog_debugf)(const char *format, ...) PRINTF_LIKE(1);

#define LSWBUF_PARROT -1
#define LSWBUF_CANARY -2

#define PASSERT_LSWBUF(LOG)						\
	do {								\
		passert((LOG)->dots != NULL);				\
		/* LEN/BOUND well defined */				\
		passert((LOG)->buf->len <= (LOG)->bound);		\
		passert((LOG)->bound < sizeof((LOG)->buf->buf));	\
		/* passert((LOG)->len < sizeof((LOG)->buf)) */;		\
		/* always NUL terminated */				\
		passert((LOG)->buf->parrot == LSWBUF_PARROT);		\
		passert((LOG)->buf->buf[(LOG)->buf->len] == '\0');	\
		passert((LOG)->buf->canary == LSWBUF_CANARY);		\
	} while (false)

/*
 * Try to append the message to the end of the log buffer.
 *
 * If there is insufficient space, the output is truncated and "..."
 * is appended.
 *
 * Like C99 snprintf() et.al., always return the untruncated message
 * length.
 */
size_t lswlogvf(struct lswlog *log, const char *format, va_list ap);
size_t lswlogf(struct lswlog *log, const char *format, ...) PRINTF_LIKE(2);
size_t lswlogs(struct lswlog *log, const char *string);
size_t lswlogl(struct lswlog *log, struct lswlog *buf);

/*
 * A code wrapper that covers up the details of allocating,
 * initializing, logging, and de-allocating the 'struct lswbuf' and
 * 'struct lswlog' objects.  For instance:
 *
 *    LSWBUFP(RC_LOG, false, log) { lswlogf(log, "hello world"); }
 *
 * LOG, a variable name, is defined as a pointer to the log buffer.
 *
 * This implementation stores the 'struct lswlog' on the stack.
 *
 * An alternative would be to put it on the heap.
 *
 * Apparently chaining void function calls using a comma is valid C?
 */

#define EMPTY_LSWBUF(BUF) {						\
		.buf = (BUF),						\
		.bound = sizeof((BUF)->buf) - 1,			\
		.dots = "..."						\
	}

#define LSWBUF(LOG)							\
	for (bool lswbuf_p = true; lswbuf_p; lswbuf_p = false)		\
		for (struct lswbuf lswbuf = empty_lswbuf; lswbuf_p;)	\
			for (struct lswlog lswlog = EMPTY_LSWBUF(&lswbuf), *LOG = &lswlog; \
			     lswbuf_p; lswbuf_p = false)

/*
 * Like the above but further restrict the output to SIZE.
 *
 * For instance:
 *
 *    LSWBUFT(log, 5, "*", logt) {
 *      n += lswlogtf(t, "abc"); // 3
 *      n += lswlogtf(t, "def"); // 3
 *    }
 *
 * would would result in: abc++<nul>
 *
 * Like C99 snprintf() et.al, always return the untruncated message
 * length.
 */

#define LSWBUFT(LOG, WIDTH, DOTS, LOGT)					\
	for (bool lswbuft_p = true; lswbuft_p; )			\
		for (struct lswlog lswlogt = {				\
				.buf = (LOG)->buf,			\
				.bound = min((LOG)->buf->len + (WIDTH), (LOG)->bound), \
				.dots = ((LOG)->buf->len + (WIDTH) >= (LOG)->bound \
					 ? (LOG)->dots			\
					 : (DOTS)),			\
		      }, *LOGT = &lswlogt;				\
		     lswbuft_p; lswbuft_p = false)

/*
 * Wrapper macros to deal with the details of conditionally
 * allocating, logging, and deallocating the buffer.
 *
 * For the moment, not very efficient.
 */

#define LSWDBGP(DEBUG, LOG)						\
	for (bool lswdbgp_p = DBGP(DEBUG); lswdbgp_p; lswdbgp_p = false) \
		LSWBUF(LOG)						\
			for (; lswdbgp_p;				\
			     DBG_log("%s", LSWBUF_BUF(LOG)),		\
				     lswdbgp_p = false)

#define LSWLOG(LOG)							\
	for (bool lswlog_p = true; lswlog_p; lswlog_p = false)		\
		LSWBUF(LOG)						\
			for (; lswlog_p;				\
			     libreswan_log("%s", LSWBUF_BUF(LOG)),	\
				     lswlog_p = false)

#endif /* _LSWLOG_H_ */
