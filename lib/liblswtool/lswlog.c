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

bool log_to_stderr = TRUE;	/* should log go to stderr? */

char *progname = NULL;

void tool_init_log(char *name)
{
	progname = name;

	if (log_to_stderr)
		setbuf(stderr, NULL);

	pfkey_error_func = printf;
	pfkey_debug_func = printf;
}

/*
 * format a string for the log, with suitable prefixes.
 */
static void fmt_log(char *buf, size_t buf_len,
		const char *fmt, va_list ap)
{
	char *p = buf;
	buf[0] = '\0';
	if (progname != NULL && (strlen(progname) + 1 + 1) < buf_len) {
		/* start with name of connection */
		p = add_str(buf, buf_len, jam_str(buf, buf_len, progname), " ");
	}
	vsnprintf(p, buf_len - (p - buf), fmt, ap);
}

void libreswan_vloglog(int mess_no UNUSED, const char *fmt, va_list ap)
{
	char m[LOG_WIDTH];	/* longer messages will be truncated */

	fmt_log(m, sizeof(m), fmt, ap);

	if (log_to_stderr)
		fprintf(stderr, "%s\n", m);
}

void lswlog_log_errno(int e, const char *prefix, const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH];	/* longer messages will be truncated */

	va_start(args, message);
	fmt_log(m, sizeof(m), message, args);
	va_end(args);

	if (log_to_stderr)
		fprintf(stderr, "%s%s. Errno %d: %s\n",
			prefix, m, e, strerror(e));
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

void lswlog_dbg_raw(struct lswlog *buf)
{
	sanitize_string(buf->array, buf->roof);
	if (log_to_stderr)
		fprintf(stderr, "%s\n", buf->array);
}
