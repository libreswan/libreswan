/* error logging functions
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2005-2007 Michael Richardson
 * Copyright (C) 2006-2010 Bart Trojanowski
 * Copyright (C) 2008-2012 Paul Wouters
 * Copyright (C) 2008-2010 David McCullough.
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013,2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
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

#include <pthread.h>    /* Must be the first include file */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>     /* used only if MSG_NOSIGNAL not defined */
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <libreswan.h>
#include "libreswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "lswconf.h"
#include "lswfips.h"
#include "lswlog.h"

#include "defs.h"
#include "log.h"
#include "server.h"
#include "state.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "kernel.h"             /* needs connections.h */
#include "whack.h"              /* needs connections.h */
#include "timer.h"
#include "kernel_alg.h"
#include "ike_alg.h"
#include "plutoalg.h"
/* for show_virtual_private: */
#include "virtual.h"	/* needs connections.h */

#ifdef USE_LINUX_AUDIT
# include <libaudit.h>
# include "crypto.h" /* for oakley_group_desc */
#endif

#ifndef NO_DB_OPS_STATS
#define NO_DB_CONTEXT
#include "db_ops.h"
#endif

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

/* close one per-peer log */
static void perpeer_logclose(struct connection *c);     /* forward */

bool
	log_to_stderr = TRUE,		/* should log go to stderr? */
	log_to_syslog = TRUE,		/* should log go to syslog? */
	log_to_perpeer = FALSE,		/* should log go to per-IP file? */
	log_with_timestamp = TRUE,	/* testsuite requires no timestamps */
	log_to_audit = FALSE,		/* audit log messages for kernel */
	log_append = TRUE;

bool
	logged_txt_warning = FALSE; /* should we complain about finding KEY? */

/* should we complain when we find no local id */
bool
	logged_myid_fqdn_txt_warning = FALSE,
	logged_myid_ip_txt_warning   = FALSE;

char *pluto_log_file = NULL;	/* pathname */
static FILE *pluto_log_fp = NULL;

char *base_perpeer_logdir = NULL;
char *pluto_stats_binary = NULL;
static int perpeer_count = 0;

/* what to put in front of debug output */
static const char debug_prefix = '|';

/*
 * used in some messages to distiguish
 * which pluto is which, when doing unit testing
 * gets set by "use_interface" in server.c, if it is going to be changed.
 * Is used by pluto_helpers in their process-title.
 * could be used by debug routines as well, but is not yet.
 */
const char *pluto_ifn_inst = "";

/* from sys/queue.h -> NOW private sysdep.h. */
static CIRCLEQ_HEAD(, connection) perpeer_list;

/* Context for logging.
 *
 * Global variables: must be carefully adjusted at transaction boundaries!
 * If the context provides a whack file descriptor, messages
 * should be copied to it -- see whack_log()
 */
int whack_log_fd = NULL_FD;                     /* only set during whack_handle() */
struct state *cur_state = NULL;                 /* current state, for diagnostics */
struct connection *cur_connection = NULL;       /* current connection, for diagnostics */
const ip_address *cur_from = NULL;              /* source of current current message */
u_int16_t cur_from_port;                        /* host order */

void pluto_init_log(void)
{
	set_alloc_exit_log_func(exit_log);
	if (log_to_stderr)
		setbuf(stderr, NULL);

	if (pluto_log_file != NULL) {
		pluto_log_fp = fopen(pluto_log_file,
			log_append ? "a" : "w");
		if (pluto_log_fp == NULL) {
			fprintf(stderr,
				"Cannot open logfile '%s': %s\n",
				pluto_log_file, strerror(errno));
		} else {
			/*
			 * buffer by line:
			 * should be faster that no buffering
			 * and yet safe since each message is probably a line.
			 */
			setvbuf(pluto_log_fp, NULL, _IOLBF, 0);
		}
	}

	if (log_to_syslog)
		openlog("pluto", LOG_CONS | LOG_NDELAY | LOG_PID,
			LOG_AUTHPRIV);

	CIRCLEQ_INIT(&perpeer_list);
}

/* format a string for the log, with suitable prefixes.
 * A format starting with ~ indicates that this is a reprocessing
 * of the message, so prefixing and quoting is suppressed.
 */
static void fmt_log(char *buf, size_t buf_len, const char *fmt, va_list ap)
{
	bool reproc = *fmt == '~';
	size_t ps;
	struct connection *c = cur_state != NULL ? cur_state->st_connection :
			       cur_connection;

	buf[0] = '\0';
	if (reproc) {
		fmt++; /* ~ at start of format suppresses this prefix */
	} else if (c != NULL) {
		/* start with name of connection */
		char *const be = buf + buf_len;
		char *bp = buf;

		snprintf(bp, be - bp, "\"%s\"", c->name);
		bp += strlen(bp);

		/* if it fits, put in any connection instance information */
		if (be - bp > CONN_INST_BUF) {
			fmt_conn_instance(c, bp);
			bp += strlen(bp);
		}

		if (cur_state != NULL) {
			/* state number */
			snprintf(bp, be - bp, " #%lu", cur_state->st_serialno);
			bp += strlen(bp);
		}
		snprintf(bp, be - bp, ": ");
	} else if (cur_from != NULL) {
		/* peer's IP address */
		ipstr_buf b;

		snprintf(buf, buf_len, "packet from %s:%u: ",
			 ipstr(cur_from, &b),
			 (unsigned)cur_from_port);
	}

	ps = strlen(buf);
	vsnprintf(buf + ps, buf_len - ps, fmt, ap);
	if (!reproc)
		sanitize_string(buf, buf_len);
}

void close_peerlog(void)
{
	/* exit if the circular queue has not been initialized */
	if (perpeer_list.cqh_first == NULL)
		return;

	/* end of circular queue is given by pointer to "HEAD" */
	while (perpeer_list.cqh_first != (void *)&perpeer_list)
		perpeer_logclose(perpeer_list.cqh_first);
}

void close_log(void)
{
	if (log_to_syslog)
		closelog();

	if (pluto_log_fp != NULL) {
		(void)fclose(pluto_log_fp);
		pluto_log_fp = NULL;
	}

	close_peerlog();
}

static void perpeer_logclose(struct connection *c)
{
	/* only free/close things if we had used them! */
	if (c->log_file != NULL) {
		passert(perpeer_count > 0);

		CIRCLEQ_REMOVE(&perpeer_list, c, log_link);
		perpeer_count--;
		fclose(c->log_file);
		c->log_file = NULL;
	}
}

void perpeer_logfree(struct connection *c)
{
	perpeer_logclose(c);
	if (c->log_file_name != NULL) {
		pfree(c->log_file_name);
		c->log_file_name = NULL;
		c->log_file_err = FALSE;
	}
}

/* attempt to arrange a writeable parent directory for <path>
 * Result indicates success.  Failure will be logged.
 *
 * NOTE: this routine must not call our own logging facilities to report
 * an error since those routines are not re-entrant and such a call
 * would be recursive.
 */
static bool ensure_writeable_parent_directory(char *path)
{
	/* NOTE: a / in the first char of a path is not like any other.
	 * That is why the strchr starts at path + 1.
	 */
	char *e = strrchr(path + 1, '/'); /* end of directory prefix */
	bool happy = TRUE;

	if (e != NULL) {
		/* path has an explicit directory prefix: deal with it */

		/* Treat a run of slashes as one.
		 * Remember that a / in the first char is different.
		 */
		while (e > path + 1 && e[-1] == '/')
			e--;

		*e = '\0'; /* carve off dirname part of path */

		if (access(path, W_OK) == 0) {
			/* mission accomplished, with no work */
		} else if (errno != ENOENT) {
			/* cannot write to this directory for some reason
			 * other than a missing directory
			 */
			syslog(LOG_CRIT, "cannot write to %s: %s", path, strerror(
				       errno));
			happy = FALSE;
		} else {
			/* missing directory: try to create one */
			happy = ensure_writeable_parent_directory(path);
			if (happy) {
				if (mkdir(path, 0750) != 0) {
					syslog(LOG_CRIT,
					       "cannot create dir %s: %s",
					       path, strerror(errno));
					happy = FALSE;
				}
			}
		}

		*e = '/'; /* restore path to original form */
	}
	return happy;
}

/* open the per-peer log
 *
 * NOTE: this routine must not call our own logging facilities to report
 * an error since those routines are not re-entrant and such a call
 * would be recursive.
 */
static void open_peerlog(struct connection *c)
{
	/* syslog(LOG_INFO, "opening log file for conn %s", c->name); */

	if (c->log_file_name == NULL) {
		char peername[ADDRTOT_BUF], dname[ADDRTOT_BUF];
		size_t peernamelen = addrtot(&c->spd.that.host_addr, 'Q', peername,
			sizeof(peername)) - 1;
		int lf_len;


		/* copy IP address, turning : and . into / */
		{
			char ch, *p, *q;

			p = peername;
			q = dname;
			do {
				ch = *p++;
				if (ch == '.' || ch == ':')
					ch = '/';
				*q++ = ch;
			} while (ch != '\0');
		}

		lf_len = peernamelen * 2 +
			 strlen(base_perpeer_logdir) +
			 sizeof("//.log") +
			 1;
		c->log_file_name =
			alloc_bytes(lf_len, "per-peer log file name");

#if 0
		fprintf(stderr, "base dir |%s| dname |%s| peername |%s|",
			base_perpeer_logdir, dname, peername);
#endif
		snprintf(c->log_file_name, lf_len, "%s/%s/%s.log",
			 base_perpeer_logdir, dname, peername);

		/* syslog(LOG_DEBUG, "conn %s logfile is %s", c->name, c->log_file_name); */
	}

	/* now open the file, creating directories if necessary */

	c->log_file_err = !ensure_writeable_parent_directory(c->log_file_name);
	if (c->log_file_err)
		return;

	c->log_file = fopen(c->log_file_name, "w");
	if (c->log_file == NULL) {
		if (c->log_file_err) {
			syslog(LOG_CRIT, "logging system cannot open %s: %s",
			       c->log_file_name, strerror(errno));
			c->log_file_err = TRUE;
		}
		return;
	}

	/* look for a connection to close! */
	while (perpeer_count >= MAX_PEERLOG_COUNT) {
		/* cannot be NULL because perpeer_count > 0 */
		passert(perpeer_list.cqh_last != (void *)&perpeer_list);

		perpeer_logclose(perpeer_list.cqh_last);
	}

	/* insert this into the list */
	CIRCLEQ_INSERT_HEAD(&perpeer_list, c, log_link);
	passert(c->log_file != NULL);
	perpeer_count++;
}

#ifdef GCC_LINT
static void prettynow(char *buf, size_t buflen, const char *fmt) __attribute__ ((format (__strftime__, 3, 0)));
#endif
static void prettynow(char *buf, size_t buflen, const char *fmt)
{
	realtime_t n = realnow();
	struct tm tm1;
	struct tm *t = localtime_r(&n.real_secs, &tm1);

	/* the cast suppresses a warning: <http://gcc.gnu.org/bugzilla/show_bug.cgi?id=39438> */
	((size_t (*)(char *, size_t, const char *, const struct tm *))strftime)(buf, buflen, fmt, t);
}

/* log a line to cur_connection's log */
static void peerlog(const char *prefix, const char *m)
{
	if (cur_connection == NULL) {
		/* we cannot log it in this case. Oh well. */
		return;
	}

	if (cur_connection->log_file == NULL)
		open_peerlog(cur_connection);

	/* despite our attempts above, we may not be able to open the file. */
	if (cur_connection->log_file != NULL) {
		char datebuf[32];

		prettynow(datebuf, sizeof(datebuf), "%Y-%m-%d %T");
		fprintf(cur_connection->log_file, "%s %s%s\n",
			datebuf, prefix, m);

		/* now move it to the front of the list */
		CIRCLEQ_REMOVE(&perpeer_list, cur_connection, log_link);
		CIRCLEQ_INSERT_HEAD(&perpeer_list, cur_connection, log_link);
	}
}

/* thread locks added until all non re-entrant functions it uses have been fixed */
int libreswan_log(const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH]; /* longer messages will be truncated */

	pthread_mutex_lock(&log_mutex);
	va_start(args, message);
	fmt_log(m, sizeof(m), message, args);
	va_end(args);

	if (log_to_stderr || pluto_log_fp != NULL) {
		char buf[34] = "";

		if (log_with_timestamp)
			prettynow(buf, sizeof(buf), "%b %e %T: ");
		fprintf(log_to_stderr ? stderr : pluto_log_fp,
			"%s%s\n", buf, m);
	}
	if (log_to_syslog)
		syslog(LOG_WARNING, "%s", m);
	if (log_to_perpeer)
		peerlog("", m);

	pthread_mutex_unlock(&log_mutex);
	whack_log(RC_LOG, "~%s", m);
	return 0;
}

/* thread locks added until all non re-entrant functions it uses have been fixed */
void loglog(int mess_no, const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH]; /* longer messages will be truncated */

	pthread_mutex_lock(&log_mutex);
	va_start(args, message);
	fmt_log(m, sizeof(m), message, args);
	va_end(args);

	if (log_to_stderr || pluto_log_fp != NULL) {
		char buf[34] = "";

		if (log_with_timestamp)
			prettynow(buf, sizeof(buf), "%b %e %T: ");
		fprintf(log_to_stderr ? stderr : pluto_log_fp,
			"%s%s\n", buf, m);
	}
	if (log_to_syslog)
		syslog(LOG_WARNING, "%s", m);
	if (log_to_perpeer)
		peerlog("", m);

	pthread_mutex_unlock(&log_mutex);
	whack_log(mess_no, "~%s", m);
}

void libreswan_log_errno_routine(int e, const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH]; /* longer messages will be truncated */

	va_start(args, message);
	fmt_log(m, sizeof(m), message, args);
	va_end(args);

	if (log_to_stderr || pluto_log_fp != NULL)
		fprintf(log_to_stderr ? stderr : pluto_log_fp,
			"ERROR: %s. Errno %d: %s\n", m, e, strerror(e));
	if (log_to_syslog)
		syslog(LOG_ERR, "ERROR: %s. Errno %d: %s", m, e, strerror(e));
	if (log_to_perpeer)
		peerlog(strerror(e), m);

	whack_log(RC_LOG_SERIOUS,
		  "~ERROR: %s. Errno %d: %s", m, e, strerror(e));
}

void exit_log(const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH]; /* longer messages will be truncated */

	va_start(args, message);
	fmt_log(m, sizeof(m), message, args);
	va_end(args);

	if (log_to_stderr || pluto_log_fp != NULL)
		fprintf(log_to_stderr ? stderr : pluto_log_fp,
			"FATAL ERROR: %s\n", m);
	if (log_to_syslog)
		syslog(LOG_ERR, "FATAL ERROR: %s", m);
	if (log_to_perpeer)
		peerlog("FATAL ERROR: ", m);

	whack_log(RC_LOG_SERIOUS, "~FATAL ERROR: %s", m);

	exit_pluto(PLUTO_EXIT_FAIL);
}

void libreswan_exit_log_errno_routine(int e, const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH]; /* longer messages will be truncated */

	va_start(args, message);
	fmt_log(m, sizeof(m), message, args);
	va_end(args);

	if (log_to_stderr || pluto_log_fp != NULL)
		fprintf(log_to_stderr ? stderr : pluto_log_fp,
			"FATAL ERROR: %s. Errno %d: %s\n", m, e, strerror(e));
	if (log_to_syslog)
		syslog(LOG_ERR, "FATAL ERROR: %s. Errno %d: %s", m, e, strerror(
			       e));
	if (log_to_perpeer)
		peerlog(strerror(e), m);

	whack_log(RC_LOG_SERIOUS,
		  "~FATAL ERROR: %s. Errno %d: %s", m, e, strerror(e));

	exit_pluto(PLUTO_EXIT_FAIL);
}

void libreswan_log_abort(const char *file_str, int line_no)
{
	loglog(RC_LOG_SERIOUS, "ABORT at %s:%d", file_str, line_no);
	abort();
}

/* emit message to whack.
 * form is "ddd statename text" where
 * - ddd is a decimal status code (RC_*) as described in whack.h
 * - text is a human-readable annotation
 */
static volatile sig_atomic_t dying_breath = FALSE;

void whack_log(int mess_no, const char *message, ...)
{
	int wfd;

	pthread_mutex_lock(&log_mutex);
	wfd = whack_log_fd != NULL_FD ? whack_log_fd :
	      cur_state != NULL ? cur_state->st_whack_sock :
	      NULL_FD;

	if (wfd != NULL_FD || dying_breath) {
		va_list args;
		char m[LOG_WIDTH]; /* longer messages will be truncated */
		int prelen = snprintf(m, sizeof(m), "%03d ", mess_no);

		passert(prelen >= 0);

		va_start(args, message);
		fmt_log(m + prelen, sizeof(m) - prelen, message, args);
		va_end(args);

		if (dying_breath) {
			/* status output copied to log */
			if (log_to_stderr || pluto_log_fp != NULL)
				fprintf(log_to_stderr ? stderr : pluto_log_fp,
					"%s\n", m + prelen);
			if (log_to_syslog)
				syslog(LOG_WARNING, "%s", m + prelen);
			if (log_to_perpeer)
				peerlog("", m);
		}

		if (wfd != NULL_FD) {
			/* write to whack socket, but suppress possible SIGPIPE */
			size_t len = strlen(m);
#ifdef MSG_NOSIGNAL                     /* depends on version of glibc??? */
			m[len] = '\n';  /* don't need NUL, do need NL */
			(void) send(wfd, m, len + 1, MSG_NOSIGNAL);
#else /* !MSG_NOSIGNAL */
			int r;
			struct sigaction act,
					 oldact;

			m[len] = '\n'; /* don't need NUL, do need NL */
			act.sa_handler = SIG_IGN;
			sigemptyset(&act.sa_mask);
			act.sa_flags = 0; /* no nothing */
			r = sigaction(SIGPIPE, &act, &oldact);
			passert(r == 0);

			(void) write(wfd, m, len + 1);

			r = sigaction(SIGPIPE, &oldact, NULL);
			passert(r == 0);
#endif                  /* !MSG_NOSIGNAL */
		}
	}
	pthread_mutex_unlock(&log_mutex);
}

/* Debugging message support */

void libreswan_switch_fail(int n, const char *file_str, unsigned long line_no)
{
	char buf[30];

	snprintf(buf, sizeof(buf), "case %d unexpected", n);
	passert_fail(buf, file_str, line_no);
	/* NOTREACHED */
}

void passert_fail(const char *pred_str, const char *file_str,
		  unsigned long line_no)
{
	/* we will get a possibly unplanned prefix.  Hope it works */
	loglog(RC_LOG_SERIOUS, "ASSERTION FAILED at %s:%lu: %s",
		file_str, line_no, pred_str);
	dying_breath = TRUE;
	/* exiting correctly doesn't always work */
	libreswan_log_abort(file_str, line_no);
}

void pexpect_log(const char *pred_str, const char *file_str,
		 unsigned long line_no)
{
	/* we will get a possibly unplanned prefix.  Hope it works */
	loglog(RC_LOG_SERIOUS, "EXPECTATION FAILED at %s:%lu: %s", file_str,
	       line_no, pred_str);
}

lset_t
	base_debugging = DBG_NONE, /* default to reporting nothing */
	cur_debugging =  DBG_NONE;

void extra_debugging(const struct connection *c)
{
	if (c == NULL) {
		reset_debugging();
		return;
	}

	if (c->extra_debugging != 0) {
		libreswan_log("extra debugging enabled for connection: %s",
			      bitnamesof(debug_bit_names, c->extra_debugging &
					 ~cur_debugging));
		set_debugging(cur_debugging | c->extra_debugging);
	}

	/*
	 * if any debugging is on, make sure that we log the connection
	 * we are processing, because it may not be clear in later debugging.
	 */
	DBG(~LEMPTY, {
		char b1[CONN_INST_BUF];
		DBG_log("processing connection \"%s\"%s",
			c->name, fmt_conn_instance(c, b1));
	});

}

void set_debugging(lset_t deb)
{
	cur_debugging = deb;

	if (kernel_ops != NULL && kernel_ops->set_debug != NULL)
		(*kernel_ops->set_debug)(cur_debugging, DBG_log,
					 libreswan_log);
}

/* log a debugging message (prefixed by "| ") */
/* thread locks added until all non re-entrant functions it uses have been fixed */
int DBG_log(const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH]; /* longer messages will be truncated */

	pthread_mutex_lock(&log_mutex);
	va_start(args, message);
	vsnprintf(m, sizeof(m), message, args);
	va_end(args);

	/* then sanitize anything else that is left. */
	sanitize_string(m, sizeof(m));

	if (log_to_stderr || pluto_log_fp != NULL) {
		char buf[34] = "";

		if (log_with_timestamp)
			prettynow(buf, sizeof(buf), "%b %e %T: ");
		fprintf(log_to_stderr ? stderr : pluto_log_fp,
			"%s%c %s\n", buf, debug_prefix, m);
	}
	if (log_to_syslog)
		syslog(LOG_DEBUG, "%c %s", debug_prefix, m);
	if (log_to_perpeer) {
		char prefix[3];
		prefix[0] = debug_prefix;
		prefix[1] = ' ';
		prefix[2] = '\n';
		peerlog(prefix, m);
	}

	pthread_mutex_unlock(&log_mutex);
	return 0;
}

/* dump raw bytes in hex to stderr (for lack of any better destination) */

void libreswan_DBG_dump(const char *label, const void *p, size_t len)
{
#define DUMP_LABEL_WIDTH 20  /* arbitrary modest boundary */
#define DUMP_WIDTH   (4 * (1 + 4 * 3) + 1)
	char buf[DUMP_LABEL_WIDTH + DUMP_WIDTH];
	char *bp, *bufstart;
	const unsigned char *cp = p;

	bufstart = buf;

	if (label != NULL && label[0] != '\0') {
		/* Handle the label.  Care must be taken to avoid buffer overrun. */
		size_t llen = strlen(label);

		if (llen + 1 > sizeof(buf)) {
			DBG_log("%s", label);
		} else {
			strcpy(buf, label);
			if (buf[llen - 1] == '\n') {
				buf[llen - 1] = '\0'; /* get rid of newline */
				DBG_log("%s", buf);
			} else if (llen < DUMP_LABEL_WIDTH) {
				bufstart = buf + llen;
			} else {
				DBG_log("%s", buf);
			}
		}
	}

	bp = bufstart;
	do {
		int i, j;

		for (i = 0; len != 0 && i != 4; i++) {
			*bp++ = ' ';
			for (j = 0; len != 0 && j != 4; len--, j++) {
				static const char hexdig[] =
					"0123456789abcdef";

				*bp++ = ' ';
				*bp++ = hexdig[(*cp >> 4) & 0xF];
				*bp++ = hexdig[*cp & 0xF];
				cp++;
			}
		}
		*bp = '\0';
		DBG_log("%s", buf);
		bp = bufstart;
	} while (len != 0);
#undef DUMP_LABEL_WIDTH
#undef DUMP_WIDTH
}

static void show_system_security(void)
{
	int selinux = libreswan_selinux();
#ifdef FIPS_CHECK
	bool fips = libreswan_fipsmode();
#else
	int fips = FALSE;
#endif

	whack_log(RC_COMMENT, " ");     /* spacer */

	whack_log(RC_COMMENT, "fips mode=%s;", fips ? "enabled" : "disabled");

	whack_log(RC_COMMENT, "SElinux=%s",
		selinux == 0 ? "disabled" : selinux == 1 ? "enabled" : "indeterminate");
	whack_log(RC_COMMENT, " ");     /* spacer */

}

void show_global_status(void)
{
	show_globalstate_status();
}

void show_status(void)
{
	show_kernel_interface();
	show_ifaces_status();
	show_system_security();
	show_setup_plutomain();
	show_myid_status();
	show_debug_status();
	show_setup_natt();
	show_virtual_private();
	kernel_alg_show_status();
	ike_alg_show_status();
#ifndef NO_DB_OPS_STATS
	db_ops_show_status();
#endif
	show_connections_status();
	show_states_status();
#ifdef KLIPS
	show_shunt_status();
#endif
}

/*
 * a routine that attempts to schedule itself daily.
 *
 */

void daily_log_reset(void)
{
	/* now perform actions */
	logged_txt_warning = FALSE;

	logged_myid_fqdn_txt_warning = FALSE;
	logged_myid_ip_txt_warning   = FALSE;
}

void daily_log_event(void)
{
	struct tm tm1, *ltime;
	time_t interval;
	realtime_t n = realnow();

	/* schedule event for midnight, local time */
	tzset();
	ltime = localtime_r(&n.real_secs, &tm1);
	interval = secs_per_day -
		   (ltime->tm_sec +
		    ltime->tm_min * secs_per_minute +
		    ltime->tm_hour * secs_per_hour);

	/* this might happen during a leap second */
	if (interval <= 0)
		interval = secs_per_day;

	event_schedule(EVENT_LOG_DAILY, interval, NULL);

	daily_log_reset();
}

/*
 * We store runtime info for stats/status this way.
 * You may be able to do something similar using these hooks.
 */

struct log_conn_info {
	struct connection *conn;
	struct state *ignore;           /* ignore this state */

	/* best completed state of connection */

	enum {
		tun_down=0,
		tun_phase1,
		tun_phase1up,
		tun_phase15,
		tun_phase2,
		tun_up
	} tunnel;

	/* best uncompleted state info for each phase */

	enum {
		p1_none=0,
		p1_init,
		p1_encrypt,
		p1_auth,
		p1_up,
		p1_down
	} phase1;

	enum {
		p2_none=0,
		p2_neg,
		p2_up,
	} phase2;
};

/*
 * we need to make sure we do not saturate the stats daemon
 * so we track what we have told it in a long (triple)
 */
#define LOG_CONN_STATSVAL(lci) \
	((lci)->tunnel | ((lci)->phase1 << 4) | ((lci)->phase2 << 8))

static void connection_state(struct state *st, void *data)
{
	struct log_conn_info *lc = data;

	if (st == NULL || st == lc->ignore ||
	    st->st_connection == NULL || lc->conn == NULL)
		return;

	if (st->st_connection != lc->conn) {
		if (lc->conn->host_pair != st->st_connection->host_pair ||
		    !same_peer_ids(lc->conn, st->st_connection, NULL))
			return;
		/* phase1 is shared with another connnection */
	}

	/* ignore undefined states (i.e. just deleted) */
	if (st->st_state == STATE_UNDEFINED)
		return;

	if (IS_IKE_SA(st)) {
		if (lc->tunnel < tun_phase1)
			lc->tunnel = tun_phase1;
		if (IS_IKE_SA_ESTABLISHED(st)) {
			if (lc->tunnel < tun_phase1up)
				lc->tunnel = tun_phase1up;
			lc->phase1 = p1_up;
		} else {
			if (lc->phase1 < p1_init)
				lc->phase1 = p1_init;
			if (IS_ISAKMP_ENCRYPTED(st->st_state) &&
			    lc->phase1 < p1_encrypt)
				lc->phase1 = p1_encrypt;
			if (IS_ISAKMP_AUTHENTICATED(st->st_state) &&
			    lc->phase1 < p1_auth)
				lc->phase1 = p1_auth;
		}
	} else {
		lc->phase1 = p1_down;
	}

	/* only phase one shares across connections, so we can quit now */
	if (st->st_connection != lc->conn)
		return;

	if (IS_PHASE15(st->st_state)) {
		if (lc->tunnel < tun_phase15)
			lc->tunnel = tun_phase15;
	}

	if (IS_QUICK(st->st_state)) {
		if (lc->tunnel < tun_phase2)
			lc->tunnel = tun_phase2;
		if (IS_IPSEC_SA_ESTABLISHED(st->st_state)) {
			if (lc->tunnel < tun_up)
				lc->tunnel = tun_up;
			lc->phase2 = p2_up;
		} else {
			if (lc->phase2 < p2_neg)
				lc->phase2 = p2_neg;
		}
	}
}

void log_state(struct state *st, enum state_kind new_state)
{
	char buf[1024];
	struct log_conn_info lc;
	struct connection *conn;
	const char *tun = NULL, *p1 = NULL, *p2 = NULL;
	enum state_kind save_state;

	if (pluto_stats_binary == NULL)
		return;

	if (st == NULL) {
		DBG(DBG_CONTROLMORE, DBG_log(
			    "log_state() called without state"));
		return;
	}

	conn = st->st_connection;
	if (conn == NULL || st->st_connection->name == NULL) {
		DBG(DBG_CONTROLMORE,
		    DBG_log("log_state() called without st->st_connection or without st->st_connection->name"));
		return;
	}

	DBG(DBG_CONTROLMORE,
	    DBG_log("log_state called for state update for connection %s ",
		    conn->name));
	zero(&lc);	/* OK: the two pointer fields handled below */
	lc.conn = conn;
	lc.ignore = NULL;

	save_state = st->st_state;
	st->st_state = new_state;
	for_each_state(connection_state, &lc);
	st->st_state = save_state;

	if (conn->statsval ==
	    (IPsecSAref2NFmark(st->st_ref) | LOG_CONN_STATSVAL(&lc))) {
		DBG(DBG_CONTROLMORE,
		    DBG_log("log_state for connection %s state change signature (%d) matches last one - skip logging",
			    conn->name, conn->statsval));
		return;
	}
	conn->statsval = IPsecSAref2NFmark(st->st_ref) |
			 LOG_CONN_STATSVAL(&lc);
	DBG(DBG_CONTROLMORE,
	    DBG_log("log_state set state change signature for connection %s to %d",
		    conn->name, conn->statsval));

	switch (lc.tunnel) {
	case tun_phase1:
		tun = "phase1";
		break;
	case tun_phase1up:
		tun = "phase1up";
		break;
	case tun_phase15:
		tun = "phase15";
		break;
	case tun_phase2:
		tun = "phase2";
		break;
	case tun_up:
		tun = "up";
		break;
	case tun_down:
		tun = "down";
		break;
	default:
		tun = "unchanged";
		break;
	}

	switch (lc.phase1) {
	case p1_init:     p1 = "init";
		break;
	case p1_encrypt:  p1 = "encrypt";
		break;
	case p1_auth:     p1 = "auth";
		break;
	case p1_up:       p1 = "up";
		break;
	case p1_down:       p1 = "down";
		break;
	default:          p1 = "unchanged";
		break;
	}

	switch (lc.phase2) {
	case p2_neg:      p2 = "neg";
		break;
	case p2_up:       p2 = "up";
		break;
	default:          p2 = "down";
		break;
	}
	DBG(DBG_CONTROLMORE,
	    DBG_log("log_state calling %s for connection %s with tunnel(%s) phase1(%s) phase2(%s)",
		    pluto_stats_binary, conn->name, tun, p1, p2));

	snprintf(buf, sizeof(buf), "%s "
		 "%s ipsec-tunnel-%s if_stats /proc/net/dev/%s \\; "
		 "%s ipsec-tunnel-%s tunnel %s \\; "
		 "%s ipsec-tunnel-%s phase1 %s \\; "
		 "%s ipsec-tunnel-%s phase2 %s \\; "
		 "%s ipsec-tunnel-%s nfmark-me/him 0x%x/0x%x",

		 pluto_stats_binary,
		 conn->interface ? "push" : "drop", conn->name,
		 conn->interface ? conn->interface->ip_dev->id_vname : "",
		 tun ? "push" : "drop", conn->name, tun ? tun : "",
		 p1  ? "push" : "drop", conn->name, p1  ? p1  : "",
		 p2  ? "push" : "drop", conn->name, p2  ? p2  : "",
		 (st->st_ref || st->st_refhim) ? "push" : "drop", conn->name,
		 st->st_ref == IPSEC_SAREF_NA ? IPSEC_SAREF_NA :
		 st->st_ref == IPSEC_SAREF_NULL ? 0u :
		 IPsecSAref2NFmark(st->st_ref) | IPSEC_NFMARK_IS_SAREF_BIT
		 ,
		 st->st_refhim == IPSEC_SAREF_NA ? IPSEC_SAREF_NA :
		 st->st_refhim == IPSEC_SAREF_NULL ? 0u :
		 IPsecSAref2NFmark(st->st_refhim) | IPSEC_NFMARK_IS_SAREF_BIT);
	if (system(buf) == -1) {
		loglog(RC_LOG_SERIOUS,"statsbin= failed to send status update notification");
	}
	DBG(DBG_CONTROLMORE,
	    DBG_log("log_state for connection %s completed", conn->name));
}

#ifdef USE_LINUX_AUDIT
void linux_audit_init(void)
{
	libreswan_log("Linux audit support [enabled]");
	/* test and log if audit is enabled on the system */
	int audit_fd;
	audit_fd = audit_open();
	if (audit_fd < 0) {
		if (errno == EINVAL || errno == EPROTONOSUPPORT ||
			errno == EAFNOSUPPORT) {
			loglog(RC_LOG_SERIOUS,
				"Warning: kernel has no audit support");
		} else {
			loglog(RC_LOG_SERIOUS,
				"FATAL: audit_open() failed : %s",
				strerror(errno));
			exit_pluto(PLUTO_EXIT_AUDIT_FAIL);
		}
	} else {
		log_to_audit = TRUE;
	}
	close(audit_fd);
	libreswan_log("Linux audit activated");
}

void linux_audit(const int type, const char *message, const char *addr,
		const int result)
{

	int audit_fd, rc;

	if (!log_to_audit)
		return;

	audit_fd = audit_open();
	if (audit_fd < 0) {
			loglog(RC_LOG_SERIOUS,
				"FATAL (SOON): audit_open() failed : %s",
				strerror(errno));
			exit_pluto(PLUTO_EXIT_AUDIT_FAIL);
	}

	/*
	 * audit_log_user_message() - log a general user message
	 *
	 * audit_fd - The fd returned by audit_open
	 * type - type of message, ex: AUDIT_USYS_CONFIG, AUDIT_USER_LOGIN
	 * message - the message text being sent
	 * hostname - the hostname if known, NULL if unknown
	 * addr - The network address of the user, NULL if unknown
	 * tty - The tty of the user, if NULL will attempt to figure out
	 * result - 1 is "success" and 0 is "failed"
	 *
	 * We log the remoteid instead of hostname
	 */

	rc = audit_log_user_message(audit_fd, type, message, NULL, addr, NULL, result);
	close(audit_fd);
	if (rc < 0) {
		loglog(RC_LOG_SERIOUS,
			"FATAL: audit log failed: %s",
			strerror(errno));
		exit_pluto(PLUTO_EXIT_AUDIT_FAIL);
	}
}

/*
 * any admin/network strings but go through audit_encode_nv_string()
 */
void linux_audit_conn(const struct state *st, enum linux_audit_kind op)
{
	char raddr[ADDRTOT_BUF];
	char laddr[ADDRTOT_BUF];
	char audit_str[AUDIT_LOG_SIZE];
	char cipher_str[AUDIT_LOG_SIZE];
	char spi_str[AUDIT_LOG_SIZE];
	struct connection *const c = st->st_connection;
	bool initiator = FALSE;
	char head[IDTOA_BUF];
	char integname[IDTOA_BUF];
	char prfname[IDTOA_BUF];
	struct esb_buf esb;
	/* we need to free() this */
	char *conn_encode = audit_encode_nv_string("conn-name",c->name,0);

	zero(&cipher_str);	/* OK: no pointer fields */
	zero(&spi_str);	/* OK: no pointer fields */

	switch (op) {
	case LAK_PARENT_START:
	case LAK_PARENT_DESTROY:
		initiator = (st->st_original_role == ORIGINAL_INITIATOR) || IS_PHASE1_INIT(st->st_state);
		snprintf(head, sizeof(head), "op=%s direction=%s %s connstate=%lu ike-version=%s auth=%s",
			op == LAK_PARENT_START ? "start" : "destroy",
			initiator ? "initiator" : "responder",
			conn_encode,
			st->st_serialno,
			st->st_ikev2 ? "2.0" : "1",
			st->st_ikev2 ? ((c->policy & POLICY_PSK) ? "PRESHARED_KEY" : "RSA_SIG") :
				strip_prefix(enum_show(&oakley_auth_names,
					st->st_oakley.auth), "OAKLEY_"));

		snprintf(prfname, sizeof(prfname), "%s",
			st->st_oakley.prf_hasher->common.officname);

		if (st->st_oakley.integ_hasher != NULL) {
			snprintf(integname, sizeof(integname), "%s_%zu",
				st->st_oakley.integ_hasher->common.officname,
				st->st_oakley.integ_hasher->hash_integ_len *
				BITS_PER_BYTE);
		} else {
			if (!st->st_ikev2) {
				/* ikev1 takes integ from prf, ecept of cause gcm */
				/* but we dont support gcm in ikev1 for now */
				jam_str(integname, sizeof(integname), prfname);
			} else {
				snprintf(integname, sizeof(integname), "none");
			}
		}

		snprintf(cipher_str, sizeof(cipher_str),
			"cipher=%s ksize=%d integ=%s prf=%s pfs=%s",
			st->st_oakley.encrypter->common.officname,
			st->st_oakley.enckeylen,
			integname, prfname,
			strip_prefix(enum_name(&oakley_group_names, st->st_oakley.group->group), "OAKLEY_GROUP_"));
		break;

	case LAK_CHILD_START:
	case LAK_CHILD_DESTROY:
		snprintf(head, sizeof(head), "op=%s %s connstate=%lu, satype=%s samode=%s",
			op == LAK_CHILD_START ? "start" : "destroy",
			conn_encode,
			st->st_serialno,
			st->st_esp.present ? "ipsec-esp" : (st->st_ah.present ? "ipsec-ah" : "ipsec-policy"),
			c->policy & POLICY_TUNNEL ? "tunnel" : "transport");

		snprintf(cipher_str, sizeof(cipher_str),
			"cipher=%s ksize=%d integ=%s",
			st->st_esp.present ?
				strip_prefix(enum_showb(&esp_transformid_names,
					st->st_esp.attrs.transattrs.encrypt, &esb), "ESP_") :
				"none",
			st->st_esp.present ?
				st->st_esp.attrs.transattrs.enckeylen :
				0,
			strip_prefix(enum_show(&auth_alg_names,
				st->st_esp.attrs.transattrs.integ_hash),
				"AUTH_ALGORITHM_"));

		snprintf(spi_str, sizeof(spi_str),
		"in-spi=%lu(0x%08lx) out-spi=%lu(0x%08lx) in-ipcomp=%lu(0x%08lx) out-ipcomp=%lu(0x%08lx)",
		st->st_esp.present ? (unsigned long)ntohl(st->st_esp.attrs.spi) :
			(unsigned long)ntohl(st->st_ah.attrs.spi),
		st->st_esp.present ? (unsigned long)ntohl(st->st_esp.attrs.spi) :
			(unsigned long)ntohl(st->st_ah.attrs.spi),
		st->st_esp.present ?  (unsigned long)ntohl(st->st_esp.our_spi) :
			(unsigned long)ntohl(st->st_ah.our_spi),
		st->st_esp.present ?  (unsigned long)ntohl(st->st_esp.our_spi) :
			(unsigned long)ntohl(st->st_ah.our_spi),
		st->st_ipcomp.present ?  (unsigned long)ntohl(st->st_ipcomp.attrs.spi) : (unsigned long)0,
		st->st_ipcomp.present ?  (unsigned long)ntohl(st->st_ipcomp.attrs.spi) : (unsigned long)0,
		st->st_ipcomp.present ? (unsigned long)ntohl(st->st_ipcomp.our_spi) : (unsigned long)0,
		st->st_ipcomp.present ? (unsigned long)ntohl(st->st_ipcomp.our_spi) : (unsigned long)0);
		break;
	default:
		bad_case(op);
	}
	free(conn_encode); /* allocated by audit_encode_nv_string() */

	addrtot(&c->spd.this.host_addr, 0, laddr, sizeof(laddr));
	addrtot(&c->spd.that.host_addr, 0, raddr, sizeof(raddr));

	snprintf(audit_str, sizeof(audit_str), "%s %s %s laddr=%s",
		head,
		cipher_str,
		spi_str,
		laddr);

	linux_audit((op == LAK_CHILD_START || op == LAK_CHILD_DESTROY) ?
			AUDIT_CRYPTO_IPSEC_SA : AUDIT_CRYPTO_IKE_SA,
		audit_str, raddr, AUDIT_RESULT_OK);
}
#endif
