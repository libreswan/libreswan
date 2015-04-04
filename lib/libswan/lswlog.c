/*
 * error logging functions
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2007-2010 Paul Wouters <paul@xelerance.com>
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
 */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>	/* used only if MSG_NOSIGNAL not defined */
#include <sys/queue.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <libreswan.h>

#include "constants.h"
#include "lswlog.h"
#include "libreswan/pfkey_debug.h"

bool
	log_to_stderr = TRUE,	/* should log go to stderr? */
	log_to_syslog = FALSE;	/* should log go to syslog? */

bool
	logged_txt_warning = FALSE;	/*
					 * should we complain about finding
					 * KEY?
					 */

static void libreswanlib_passert_fail(const char *pred_str,
				const char *file_str,
				unsigned long line_no) NEVER_RETURNS;

libreswan_passert_fail_t libreswan_passert_fail = libreswanlib_passert_fail;

void tool_init_log(void)
{
	if (log_to_stderr)
		setbuf(stderr, NULL);
	if (log_to_syslog)
		openlog(progname, LOG_CONS | LOG_NDELAY | LOG_PID,
			LOG_AUTHPRIV);

	pfkey_error_func = printf;
	pfkey_debug_func = printf;
}

void tool_close_log(void)
{
	if (log_to_syslog)
		closelog();
}

/*
 * format a string for the log, with suitable prefixes.
 * A format starting with ~ indicates that this is a reprocessing
 * of the message, so prefixing and quoting is suppressed.
 */
static void fmt_log(char *buf, size_t buf_len,
		const char *fmt, va_list ap)
{
	bool reproc = *fmt == '~';
	char *p = buf;

	buf[0] = '\0';
	if (reproc) {
		fmt++;	/* ~ at start of format suppresses this prefix */
	} else if (progname != NULL && (strlen(progname) + 1 + 1) < buf_len) {
		/* start with name of connection */
		p = add_str(buf, buf_len, jam_str(buf, buf_len, progname), " ");
	}
	vsnprintf(p, buf_len - (p - buf), fmt, ap);
	if (!reproc)
		sanitize_string(buf, buf_len);
}

int libreswan_log(const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH];	/* longer messages will be truncated */

	va_start(args, message);
	fmt_log(m, sizeof(m), message, args);
	va_end(args);

	if (log_to_stderr)
		fprintf(stderr, "%s\n", m);
	if (log_to_syslog)
		syslog(LOG_WARNING, "%s", m);

	return 0;
}

void libreswan_loglog(int mess_no UNUSED, const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH];	/* longer messages will be truncated */

	va_start(args, message);
	fmt_log(m, sizeof(m), message, args);
	va_end(args);

	if (log_to_stderr)
		fprintf(stderr, "%s\n", m);
	if (log_to_syslog)
		syslog(LOG_WARNING, "%s", m);
}

void libreswan_log_errno_routine(int e, const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH];	/* longer messages will be truncated */

	va_start(args, message);
	fmt_log(m, sizeof(m), message, args);
	va_end(args);

	if (log_to_stderr)
		fprintf(stderr, "ERROR: %s. Errno %d: %s\n", m, e,
			strerror(e));
	if (log_to_syslog)
		syslog(LOG_ERR, "ERROR: %s. Errno %d: %s", m, e, strerror(e));
}

void libreswan_exit_log_errno_routine(int e, const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH];	/* longer messages will be truncated */

	va_start(args, message);
	fmt_log(m, sizeof(m), message, args);
	va_end(args);

	if (log_to_stderr)
		fprintf(stderr, "FATAL ERROR: %s. Errno %d: %s\n",
			m, e, strerror(e));
	if (log_to_syslog)
		syslog(LOG_ERR, "FATAL ERROR: %s. Errno %d: %s",
			m, e, strerror(e));

	exit(1);
}

void libreswan_log_abort(const char *file_str, int line_no)
{
	libreswan_loglog(RC_LOG_SERIOUS, "ABORT at %s:%d", file_str, line_no);
	abort();
}

/* Debugging message support */
void libreswan_switch_fail(int n, const char *file_str, unsigned long line_no)
{
	char buf[30];

	snprintf(buf, sizeof(buf), "case %d unexpected", n);
	libreswan_passert_fail(buf, file_str, line_no);
}

static void libreswanlib_passert_fail(const char *pred_str,
				const char *file_str, unsigned long line_no)
{
	/* we will get a possibly unplanned prefix.  Hope it works */
	libreswan_loglog(RC_LOG_SERIOUS, "ASSERTION FAILED at %s:%lu: %s",
			file_str, line_no, pred_str);
	abort();	/* exiting correctly doesn't always work */
}

lset_t
	base_debugging = DBG_NONE,	/* default to reporting nothing */
	cur_debugging =  DBG_NONE;

void set_debugging(lset_t deb)
{
	cur_debugging = deb;

	pfkey_lib_debug = (cur_debugging & DBG_PFKEY ?
			PF_KEY_DEBUG_PARSE_MAX : PF_KEY_DEBUG_PARSE_NONE);
}

/* log a debugging message (prefixed by "| ") */

int libreswan_DBG_log(const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH];	/* longer messages will be truncated */

	va_start(args, message);
	vsnprintf(m, sizeof(m), message, args);
	va_end(args);

	/* then sanitize anything else that is left. */
	sanitize_string(m, sizeof(m));

	if (log_to_stderr)
		fprintf(stderr, "| %s\n", m);
	if (log_to_syslog)
		syslog(LOG_DEBUG, "| %s", m);

	return 0;
}

/* dump raw bytes in hex to stderr (for lack of any better destination) */
void libreswan_DBG_dump(const char *label, const void *p, size_t len)
{
#define DUMP_LABEL_WIDTH 20	/* arbitrary modest boundary */
#define DUMP_WIDTH   (4 * (1 + 4 * 3) + 1)
	char buf[DUMP_LABEL_WIDTH + DUMP_WIDTH];
	char *bp;
	const unsigned char *cp = p;

	bp = buf;

	if (label != NULL && label[0] != '\0') {
		/*
		 * Handle the label.
		 * Care must be taken to avoid buffer overrun.
		 */
		size_t llen = strlen(label);

		if (llen + 1 > sizeof(buf)) {
			DBG_log("%s", label);
		} else {
			strcpy(buf, label);
			if (buf[llen - 1] == '\n') {
				buf[llen - 1] = '\0';	/* get rid of newline */
				DBG_log("%s", buf);
			} else if (llen < DUMP_LABEL_WIDTH) {
				bp = buf + llen;
			} else {
				DBG_log("%s", buf);
			}
		}
	}

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
		bp = buf;
	} while (len != 0);
#   undef DUMP_LABEL_WIDTH
#   undef DUMP_WIDTH
}
