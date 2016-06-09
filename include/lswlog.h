/* logging declaratons
 *
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2004 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
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

/* moved common code to library file */
#include "libreswan/passert.h"

#define loglog	libreswan_loglog
#define plog	libreswan_log
extern int libreswan_log(const char *message, ...) PRINTF_LIKE(1);

/* Log to both main log and whack log
 * Much like log, actually, except for specifying mess_no.
 */
extern void libreswan_loglog(int mess_no, const char *message,
			     ...) PRINTF_LIKE(2);
extern void libreswan_log_abort(const char *file_str,
				int line_no) NEVER_RETURNS;
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

extern void tool_init_log(void);
extern void tool_close_log(void);

#define lsw_abort()	libreswan_log_abort(__FILE__, __LINE__)

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
#define LOG_WIDTH	1024	/* roof of number of chars in log line */

extern err_t builddiag(const char *fmt, ...) PRINTF_LIKE(1);	/* NOT RE-ENTRANT */

extern char *progname;
extern bool log_to_stderr;          /* should log go to stderr? */
extern bool log_to_syslog;          /* should log go to syslog? */

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
	RC_NOVALIDPIN,		/* cannot initiate without valid PIN */

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

/* the following routines do a dance to capture errno before it is changed
 * A call must doubly parenthesize the argument list (no varargs macros).
 * The first argument must be "e", the local variable that captures errno.
 */
#define log_errno(a) \
	{ \
		int e = errno; \
		libreswan_log_errno_routine a; \
	}

extern void libreswan_log_errno_routine(int e, const char *message,
					...) PRINTF_LIKE(2);
#define exit_log_errno(a) \
	{ \
		int e = errno; \
		libreswan_exit_log_errno_routine a; \
	}

extern void libreswan_exit_log_errno_routine(int e, const char *message,
					     ...) PRINTF_LIKE(2) NEVER_RETURNS;

/*
 * general utilities
 */

/* sanitize a string */
extern void sanitize_string(char *buf, size_t size);

#endif /* _LSWLOG_H_ */

