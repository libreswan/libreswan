/* logging declarations
 *
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2004 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
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

#ifndef _LSWLOG_H_
#define _LSWLOG_H_

#include <stdarg.h>
#include <stdio.h>		/* for FILE */
#include <stddef.h>		/* for size_t */

#include "lset.h"
#include "lswcdefs.h"
#include "jambuf.h"
#include "passert.h"
#include "constants.h"		/* for DBG_... */
#include "where.h"		/* used by macros */
#include "fd.h"			/* for null_fd */
#include "impair.h"
#include "pexpect.h"
#include "fatal.h"

/*
 * Codes for status messages returned to whack.
 *
 * These are 3 digit decimal numerals.  The structure is inspired by
 * section 4.2 of RFC959 (FTP).  Since these will end up as the exit
 * status of whack, they must be less than 256.
 *
 * NOTE: ipsec_auto(8) knows about some of these numbers -- change
 * carefully.
 */

enum rc_type {

	/* entry of secrets */
	RC_ENTERSECRET = 10,
	RC_USERPROMPT = 11,

	RC_EXIT_FLOOR = 20,

	/* improper request */
	RC_DUPNAME = 20,	/* attempt to reuse a connection name */
	RC_UNKNOWN_NAME = 21,	/* connection name unknown or state number */
	RC_ORIENT = 22,		/* cannot orient connection: neither end is us */
	RC_CLASH = 23,		/* clash between two Road Warrior connections OVERLOADED */
	RC_DEAF = 24,		/* need --listen before --initiate */
	RC_ROUTE = 25,		/* cannot route */
	RC_RTBUSY = 26,		/* cannot unroute: route busy */
	RC_BADID = 27,		/* malformed --id */
	RC_NOKEY = 28,		/* no key found through DNS */
	RC_NOPEERIP = 29,	/* cannot initiate when peer IP is unknown */
	RC_INITSHUNT = 30,	/* cannot initiate a shunt-oly connection */
	RC_WILDCARD = 31,	/* cannot initiate when ID has wildcards */
	RC_CRLERROR = 32,	/* CRL fetching disabled or obsolete reread cmd */
	RC_WHACK_PROBLEM = 33,	/* whack-detected problem */

	/* permanent failure */
	RC_BADWHACKMESSAGE = 50,
	RC_NORETRANSMISSION = 51,
	RC_INTERNAL_ERROR = 52,
	RC_OPPOFAILURE = 53,	/* Opportunism failed */
	RC_CRYPTOFAILED = 54,	/* system too busy to perform required
				 * cryptographic operations */
	RC_AGGRALGO = 55,	/* multiple algorithms requested in
				 * phase 1 aggressive */
	RC_FATAL = 56,		/* fatal error encountered, and
				 * negotiation aborted */

	RC_EXIT_ROOF = 100,
};


/*
 * A generic buffer for accumulating unbounded output.
 *
 * The buffer's contents can be directed to various logging streams.
 */

struct jambuf;

/*
 * By default messages are broadcast (to both log files and whack),
 * mix-in one of these options to limit this.
 *
 * This means that a simple RC_* code will go to both whack and and
 * the log files.
 */

#define RC_MASK              0x00fffff	/* rc_type max is 64435+200 */
#define STREAM_MASK          0x0f00000
#define LOG_PREFIX_MASK	     0xf000000

enum log_prefix {
	AUTO_PREFIX =        0x0000000,
	NO_PREFIX =          0x1000000,
        ADD_PREFIX =         0x2000000,
};

enum stream {
	/*                                 syslog()                      */
	/*                                Severity  Whack  Tools  Prefix */
	ALL_STREAMS        = 0x0000000, /* WARNING   yes    err?   <o>   */
#define RC_LOG 2
	LOG_STREAM         = 0x0100000, /* WARNING    no    err?   <o>   */
	WHACK_STREAM       = 0x0200000, /*   N/A     yes    err    <o>   */
	DEBUG_STREAM       = 0x0300000, /*  DEBUG     no    err    | <o> */
	ERROR_STREAM       = 0x0400000, /*   ERR     yes    err    <o>   */
	PEXPECT_STREAM     = 0x0500000, /*   ERR     yes    err    EXPECTATION FAILED: <o> */
	PASSERT_STREAM     = 0x0600000, /*   ERR     yes    err    ABORT: ASSERTION_FAILED: <o> */
	FATAL_STREAM       = 0x0700000, /*   ERR     yes    err    FATAL ERROR: <o> */
	NO_STREAM          = 0x0f00000, /*   N/A     N/A                 */
	/*
	 * <o>: add prefix when object is available
	 *
	 * | <o>: add both "| " and prefix when object is available and
         * feature is enabled
	 *
	 * err?: write to stderr when enabled (tests log_to_stderr,
	 * typically via -v).  Used by tools such as whack.
	 */
};

/*
 * Broadcast a log message.
 *
 * By default send it to the log file and any attached whacks (both
 * globally and the object).
 *
 * If any *_STREAM flag is specified then only send the message to
 * that stream.
 *
 * llog() is a catch-all for code that may or may not have ST.
 * For instance a responder decoding a message may not yet have
 * created the state.  It will will use ST, MD, or nothing as the
 * prefix, and logs to ST's whackfd when possible.
 */

struct logger_object_vec {
	const char *name;
	bool free_object;
	size_t (*jam_object_prefix)(struct jambuf *buf, const void *object);
};

/* these omit ": " always */
typedef struct {
	char buf[100];/* completely made up size */
} prefix_buf;
const char *str_prefix(const struct logger *logger, prefix_buf *buf);
size_t jam_prefix(struct jambuf *buf, const struct logger *logger);

/* these include ": " when jam_prefix() is non-empty */
size_t jam_logger_prefix(struct jambuf *buf, const struct logger *logger);
void jam_logger_rc_prefix(struct jambuf *buf, const struct logger *logger, lset_t rc_flags);

size_t jam_object_prefix_none(struct jambuf *buf, const void *object);

struct logger {
	/* support up to two whacks */
	struct fd *whackfd[2];
	const void *object;
	const struct logger_object_vec *object_vec;
	where_t where;
	/* used by timing to nest its logging output */
	int timing_level;
	lset_t debugging;
};

#define PRI_LOGGER "logger@%p/"PRI_FD"/"PRI_FD
#define pri_logger(LOGGER)						\
	(LOGGER),							\
		pri_fd((LOGGER) == NULL ? NULL : (LOGGER)->whackfd[0]), \
		pri_fd((LOGGER) == NULL ? NULL : (LOGGER)->whackfd[1])

void llog(enum stream stream, const struct logger *log,
	  const char *format, ...) PRINTF_LIKE(3);

void llog_va_list(enum stream stream, const struct logger *logger,
		  const char *message, va_list ap) VPRINTF_LIKE(3);

void jambuf_to_logger(struct jambuf *buf, const struct logger *logger, lset_t rc_flags);

#define LLOG_JAMBUF(RC_FLAGS, LOGGER, BUF)				\
	/* create the buffer */						\
	for (struct logjam logjam_, *lbp_ = &logjam_;			\
	     lbp_ != NULL; lbp_ = NULL)					\
		/* create the jambuf */					\
		for (struct jambuf *BUF =				\
			     jambuf_from_logjam(&logjam_, LOGGER,	\
						0, NULL, RC_FLAGS);	\
		     BUF != NULL;					\
		     logjam_to_logger(&logjam_), BUF = NULL)

void llog_dump(enum stream stream,
	       const struct logger *log,
	       const void *p, size_t len);
#define llog_hunk(RC_FLAGS, LOGGER, HUNK)				\
	{								\
		const typeof(HUNK) *hunk_ = &(HUNK); /* evaluate once */ \
		llog_dump(RC_FLAGS, LOGGER, hunk_->ptr, hunk_->len);	\
	}
#define llog_thing(RC_FLAGS, LOGGER, THING)			\
	llog_dump(RC_FLAGS, LOGGER, &(THING), sizeof(THING))

void llog_base64_bytes(lset_t rc_flags,
		       const struct logger *log,
		       const void *p, size_t len);
#define llog_base64_hunk(RC_FLAGS, LOGGER, HUNK)			\
	{								\
		const typeof(HUNK) *hunk_ = &(HUNK); /* evaluate once */ \
		llog_base64_bytes(RC_FLAGS, LOGGER, hunk_->ptr, hunk_->len); \
	}

void llog_pem_bytes(lset_t rc_flags,
		    const struct logger *log,
		    const char *name,
		    const void *p, size_t len);
#define llog_pem_hunk(RC_FLAGS, LOGGER, NAME, HUNK)			\
	{								\
		const typeof(HUNK) *hunk_ = &(HUNK); /* evaluate once */ \
		llog_pem_bytes(RC_FLAGS, LOGGER, NAME, hunk_->ptr, hunk_->len); \
	}

/*
 * Wrap <message> in a prefix and suffix where the suffix contains
 * errno and message.
 *
 * Notes:
 *
 * Because __VA_ARGS__ may contain function calls that modify ERRNO,
 * errno's value is first saved.
 *
 * While these common-case macros are implemented as wrapper functions
 * so that backtrace will include the below function call and that
 * _includes_ the MESSAGE parameter - makes debugging much easier.
 */

void libreswan_exit(enum pluto_exit_code rc) NEVER_RETURNS;

/*
 * XXX: The message format is:
 *   ERROR: <log-prefix><message...>[: <strerr> (errno)]
 * and not:
 *   <log-prefix>ERROR: <message...>...
 */

void log_error(const struct logger *logger, int error,
	       const char *message, ...) PRINTF_LIKE(3);

#define llog_error(LOGGER, ERRNO, FMT, ...)			\
	{							\
		int e_ = ERRNO; /* save value across va args */	\
		log_error(LOGGER, e_, FMT, ##__VA_ARGS__);	\
	}

/*
 * Unlike llog_error(), there's no "ERROR: " prefix and no ": "
 * separator.
 */

void llog_errno(lset_t rc_flags, const struct logger *logger, int error,
		const char *message, ...) PRINTF_LIKE(4);

#define LDBG_errno(LOGGER, ERRNO, FMT, ...)				\
	{								\
		int e_ = ERRNO; /* save value across va args */		\
		llog_errno(DEBUG_STREAM, LOGGER, e_, FMT, ##__VA_ARGS__); \
	}

/*
 * Log debug messages to the main log stream, but not the WHACK log
 * stream.
 *
 * NOTE: DBG's action can be a { } block, but that block must not
 * contain commas that are outside quotes or parenthesis.
 * If it does, they will be interpreted by the C preprocessor
 * as macro argument separators.  This happens accidentally if
 * multiple variables are declared in one declaration.
 *
 * Naming: All LDBG_*(logger) prefixed functions send stuff to the
 * debug stream unconditionally.  Hence they should be wrapped in
 * LDBGP(logger).
 */

extern lset_t cur_debugging;	/* current debugging level */

#define LDBGP(COND, LOGGER) (COND & (cur_debugging | (LOGGER)->debugging))

#define dbg(MESSAGE, ...)						\
	{								\
		if (LDBGP(DBG_BASE, &global_logger)) {			\
			LDBG_log(&global_logger, MESSAGE, ##__VA_ARGS__); \
		}							\
	}

void ldbg(const struct logger *logger, const char *message, ...) PRINTF_LIKE(2);
void pdbg(const struct logger *logger, const char *message, ...) PRINTF_LIKE(2);

void ldbgf(lset_t cond, const struct logger *logger, const char *fmt, ...) PRINTF_LIKE(3);
void pdbgf(lset_t cond, const struct logger *logger, const char *fmt, ...) PRINTF_LIKE(3);

/* LDBG_JAMBUF() is ambiguous - LDBG_op() or ldbg() ucase? */

#define LDBGP_JAMBUF(COND, LOGGER, BUF)					\
	for (bool cond_ = LDBGP(COND, LOGGER); cond_; cond_ = false)	\
		LLOG_JAMBUF(DEBUG_STREAM, LOGGER, BUF)
#define PDBGP_JAMBUF(COND, LOGGER, BUF)					\
	for (bool cond_ = LDBGP(COND, LOGGER); cond_; cond_ = false)	\
		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, LOGGER, BUF)


/* DBG_*() are unconditional */

#define LDBG_log_hunk(LOGGER, LABEL, HUNK, ...)		\
	{						\
		LDBG_log(LOGGER, LABEL, ##__VA_ARGS__);	\
		LDBG_hunk(LOGGER, HUNK);		\
	}

#define LDBG_dump(LOGGER, DATA, LEN)			\
	llog_dump(DEBUG_STREAM, LOGGER, DATA, LEN)

#define LDBG_hunk(LOGGER, HUNK)				\
	llog_hunk(DEBUG_STREAM, LOGGER, HUNK);

#define LDBG_thing(LOGGER, THING)			\
	llog_thing(DEBUG_STREAM, LOGGER, THING);

#define ldbg_dump(LOGGER, DATA, LEN)			\
	{						\
		if (LDBGP(DBG_BASE, LOGGER)) {		\
			LDBG_dump(LOGGER, DATA, LEN);	\
		}					\
	}
#define ldbg_hunk(LOGGER, HUNK)				\
	{						\
		if (LDBGP(DBG_BASE, LOGGER)) {		\
			LDBG_hunk(LOGGER, HUNK);	\
		}					\
	}
#define ldbg_thing(LOGGER, THING)			\
	{						\
		if (LDBGP(DBG_BASE, LOGGER)) {		\
			LDBG_thing(LOGGER, THING);	\
		}					\
	}

/* LDBG_*(logger, ...) are unconditional wrappers */
#define LDBG_log(LOGGER, FMT, ...) llog(DEBUG_STREAM, LOGGER, FMT, ##__VA_ARGS__)
#define LDBG_va_list(LOGGER, FMT, AP) llog_va_list(DEBUG_STREAM, LOGGER, FMT, AP)

/*
 * Code wrappers that cover up the details of allocating,
 * initializing, de-allocating (and possibly logging) a 'struct
 * lswlog' buffer.
 *
 * BUF (a C variable name) is declared locally as a pointer to a
 * per-thread 'struct jambuf' buffer.
 *
 * Implementation notes:
 *
 * This implementation stores the output in an array on the thread's
 * stack.  It could just as easily use the heap (but that would
 * involve memory overheads) or even a per-thread static variable.
 * Since the BUF variable is a pointer the specifics of the
 * implementation are hidden.
 *
 * This implementation, unlike DBG(), does not have a code block
 * parameter.  Instead it uses a sequence of for-loops to set things
 * up for a code block.  This avoids problems with "," within macro
 * parameters confusing the parser.  It also permits a simple
 * consistent indentation style.
 *
 * The stack array is left largely uninitialized (just a few strategic
 * entries are set).  This avoids the need to zero LOG_WITH bytes.
 *
 * Apparently chaining void function calls using a comma is valid C?
 */

/*
 * Scratch buffer for accumulating extra output.
 *
 * XXX: case should be expanded to illustrate how to stuff a truncated
 * version of the output into the LOG buffer.
 *
 * For instance:
 */

#if 0
void lswbuf(struct jambuf *log)
{
	LSWBUF(buf) {
		jam(buf, "written to buf");
		lswlogl(log, buf); /* add to calling array */
	}
}
#endif

/*
 * For a switch statements
 */

void bad_case_where(const char *expression, long value, where_t where) NEVER_RETURNS;
#define bad_case(N) bad_case_where(#N, (N), HERE)

void bad_enum_where(const struct logger *logger,
		    const struct enum_names *en,
		    unsigned long val, where_t where) NEVER_RETURNS;
#define bad_enum(LOGGER, ENUM_NAMES, VALUE) bad_enum_where(LOGGER, ENUM_NAMES, VALUE, HERE)

void bad_sparse_where(const struct logger *logger,
		      const struct sparse_names *sn,
		      unsigned long val, where_t where) NEVER_RETURNS;
#define bad_sparse(LOGGER, SPARSE_NAMES, VALUE) bad_sparse_where(LOGGER, SPARSE_NAMES, VALUE, HERE)

#define impaired_passert(BEHAVIOUR, LOGGER, ASSERTION)			\
	{								\
		if (impair.BEHAVIOUR) {					\
			bool assertion_ = ASSERTION;			\
			if (!assertion_) {				\
				llog(RC_LOG, LOGGER,		\
					    "IMPAIR: assertion '%s' failed", \
					    #ASSERTION);		\
			}						\
		} else {						\
			passert(ASSERTION);				\
		}							\
	}

#endif /* _LSWLOG_H_ */
