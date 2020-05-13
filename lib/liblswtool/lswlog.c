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
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
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
#include "lswtool.h"
#include "lswlog.h"

bool log_to_stderr = TRUE;	/* should log go to stderr? */

const char *progname;

static const char *prog_suffix = "";

void tool_init_log(const char *name)
{
	const char *last_slash = strrchr(name, '/');

	progname = last_slash == NULL ? name : last_slash + 1;
	prog_suffix = ": ";

	if (log_to_stderr)
		setbuf(stderr, NULL);
}

/* <prefix><PROGNAME>: <message>. Errno N: <errmess> */

void lswlog_errno_prefix(struct lswlog *buf, const char *prefix)
{
	lswlogs(buf, prefix);
	lswlogs(buf, progname);
	lswlogs(buf, prog_suffix);
}

void lswlog_errno_suffix(struct lswlog *buf, int e)
{
	lswlogs(buf, ".");
	jam(buf, " "PRI_ERRNO, pri_errno(e));
	if (log_to_stderr) {
		lswlog_to_file_stream(buf, stderr);
	}
}

void jam_cur_prefix(struct lswlog *buf)
{
	lswlogf(buf, "%s%s", progname, prog_suffix);
}

void jambuf_to_logger(jambuf_t *buf, const struct logger *logger UNUSED, lset_t rc_flags)
{
	enum stream only = rc_flags & ~RC_MASK;
	switch (only) {
	case DEBUG_STREAM:
		fprintf(stderr, "%s%s\n", DEBUG_PREFIX, buf->array);
		break;
	case ALL_STREAMS:
	case LOG_STREAM:
		if (log_to_stderr) {
			fprintf(stderr, "%s\n", buf->array);
		}
		break;
	case WHACK_STREAM:
		fprintf(stderr, "%s\n", buf->array);
		break;
	case ERROR_STREAM:
		fprintf(stderr, "%s\n", buf->array);
		break;
	case NO_STREAM:
		/*
		 * XXX: Like writing to /dev/null - go through the
		 * motions but with no result.  Code really really
		 * should not call this function with this flag.
		 */
		break;
	default:
		bad_case(only);
	}
}

void log_jambuf(lset_t rc_flags, struct fd *unused_object_fd UNUSED, jambuf_t *buf)
{
	jambuf_to_logger(buf, NULL, rc_flags);
}

void lswlog_to_error_stream(struct lswlog *buf)
{
	fprintf(stderr, "%s\n", buf->array);
}

void lswlog_to_default_streams(struct lswlog *buf, enum rc_type rc UNUSED)
{
	if (log_to_stderr) {
		fprintf(stderr, "%s\n", buf->array);
	}
}
