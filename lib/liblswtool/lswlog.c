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
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>	/* used only if MSG_NOSIGNAL not defined */
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <libreswan.h>

#include "constants.h"
#include "lswtool.h"
#include "lswlog.h"

bool log_to_stderr = true;	/* should log go to stderr? */

const char *progname;

static size_t jam_progname_prefix(struct jambuf *buf, const void *object UNUSED)
{
	const char *progname = object;
	if (progname != NULL) {
		return jam(buf, "%s: ", progname);
	}
	return 0;
}

static bool suppress_progname_log(const void *object UNUSED)
{
	return false;
}

const struct logger_object_vec progname_object_vec = {
	.name = "tool",
	.jam_object_prefix = jam_progname_prefix,
	.suppress_object_log = suppress_progname_log,
};

static struct logger progname_logger = {
	.object_vec = &progname_object_vec,
	.object = NULL, /* progname */
};

struct logger *tool_init_log(const char *name)
{
	const char *last_slash = strrchr(name, '/');
	progname_logger.object = progname = last_slash == NULL ? name : last_slash + 1;

	if (log_to_stderr) {
		setbuf(stderr, NULL);
	}
	return &progname_logger;
}

void jambuf_to_logger(struct jambuf *buf, const struct logger *logger UNUSED, lset_t rc_flags)
{
	enum stream only = rc_flags & STREAM_MASK;
	switch (only) {
	case DEBUG_STREAM:
		jambuf_to_debug_stream(buf);
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
		jambuf_to_error_stream(buf);
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

void jambuf_to_debug_stream(struct jambuf *buf)
{
	fprintf(stderr, "%s%s\n", DEBUG_PREFIX, buf->array);
}

void jambuf_to_error_stream(struct jambuf *buf)
{
	fprintf(stderr, "%s\n", buf->array);
}
