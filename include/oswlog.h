/* logging definitions
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2004       Michael Richardson <mcr@xelerance.com>
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
 * RCSID $Id: oswlog.h,v 1.11 2005/01/26 00:52:16 mcr Exp $
 */

#ifndef _OSWLOG_H_
#define _OSWLOG_H_

#include <openswan.h>
#include <stdarg.h>
#include <stdio.h>

/* moved common code to library file */
#include "openswan/passert.h"

#if !defined(NO_DEBUG)

#include "constants.h"

extern lset_t base_debugging;	/* bits selecting what to report */
extern lset_t cur_debugging;	/* current debugging level */

#define DBGP(cond)         (cur_debugging & (cond))
#define DBG(cond, action)   { if (DBGP(cond)) { action ; } }

#define DBG_log openswan_DBG_log
#define loglog  openswan_loglog
#define plog    openswan_log
#define DBG_dump openswan_DBG_dump
extern int openswan_DBG_log(const char *message, ...) PRINTF_LIKE(1);
extern void openswan_DBG_dump(const char *label, const void *p, size_t len);
extern int openswan_log(const char *message, ...) PRINTF_LIKE(1);
extern void openswan_loglog(int mess_no, const char *message, ...) PRINTF_LIKE(2);
extern void openswan_exit_log(const char *message, ...) PRINTF_LIKE(1);

#define DBG_dump_chunk(label, ch) DBG_dump(label, (ch).ptr, (ch).len)

extern void exit_tool(int);
extern void tool_init_log(void);
extern void tool_close_log(void);

#else /*!DEBUG*/

#define DBG(cond, action)	{ }	/* do nothing */

#endif /*!DEBUG*/

#define DBG_cond_dump(cond, label, p, len) DBG(cond, DBG_dump(label, p, len))
#define DBG_cond_dump_chunk(cond, label, ch) DBG(cond, DBG_dump_chunk(label, ch))

/*
 * function to log stuff from libraries that may be used in multiple
 * places.
 */
#ifndef OPENSWAN_KEYING_FUNCTION 
#define OPENSWAN_KEYING_FUNCTION 
typedef int (*openswan_keying_debug_func_t)(const char *message, ...);
#endif

/* Build up a diagnostic in a static buffer.
 * Although this would be a generally useful function, it is very
 * hard to come up with a discipline that prevents different uses
 * from interfering.  It is intended that by limiting it to building
 * diagnostics, we will avoid this problem.
 * Juggling is performed to allow an argument to be a previous
 * result: the new string may safely depend on the old one.  This
 * restriction is not checked in any way: violators will produce
 * confusing results (without crashing!).
 */
#define LOG_WIDTH   1024    /* roof of number of chars in log line */

extern char diag_space[LOG_WIDTH];	/* output buffer, but can be occupied at call */
extern err_t builddiag(const char *fmt, ...) PRINTF_LIKE(1);

extern char *progname;

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
    RC_LOG,		/* message aimed at log (does not affect exit status) */
    RC_LOG_SERIOUS,	/* serious message aimed at log (does not affect exit status) */
    RC_SUCCESS,		/* success (exit status 0) */

    /* failure, but not definitive */

    RC_RETRANSMISSION = 10,

    /* improper request */

    RC_DUPNAME = 20,	/* attempt to reuse a connection name */
    RC_UNKNOWN_NAME,	/* connection name unknown or state number */
    RC_ORIENT,	/* cannot orient connection: neither end is us */
    RC_CLASH,	/* clash between two Road Warrior connections OVERLOADED */
    RC_DEAF,	/* need --listen before --initiate */
    RC_ROUTE,	/* cannot route */
    RC_RTBUSY,	/* cannot unroute: route busy */
    RC_BADID,	/* malformed --id */
    RC_NOKEY,	/* no key found through DNS */
    RC_NOPEERIP,	/* cannot initiate when peer IP is unknown */
    RC_INITSHUNT,	/* cannot initiate a shunt-oly connection */
    RC_WILDCARD,	/* cannot initiate when ID has wildcards */
    RC_NOVALIDPIN,	/* cannot initiate without valid PIN */

    /* permanent failure */

    RC_BADWHACKMESSAGE = 30,
    RC_NORETRANSMISSION,
    RC_INTERNALERR,
    RC_OPPOFAILURE,	/* Opportunism failed */
    RC_NOALGO,          /* algorithm not supported */
    RC_CRYPTOFAILED,    /* system too busy to perform required
			 * cryptographic operations */
    RC_AGGRALGO,        /* multiple algorithms requested in phase 1 aggressive */
    RC_FATAL,           /* fatal error encountered, and negotiation aborted */

    /* entry of secrets */
    RC_ENTERSECRET = 40,
    RC_XAUTHPROMPT = 41,

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
#define log_errno(a) { int e = errno; openswan_log_errno_routine a; }
extern void openswan_log_errno_routine(int e, const char *message, ...) PRINTF_LIKE(2);
#define exit_log_errno(a) { int e = errno; openswan_exit_log_errno_routine a; }
extern void openswan_exit_log_errno_routine(int e, const char *message, ...) PRINTF_LIKE(2) NEVER_RETURNS NEVER_RETURNS;

/*
 * general utilities
 */

/* option pickup from files (userland only because of use of FILE) */
const char *optionsfrom(const char *filename, int *argcp, char ***argvp,
						int optind, FILE *errorreport);

/* sanitize a string */
extern size_t sanitize_string(char *buf, size_t size);

#endif /* _OSWLOG_H_ */

