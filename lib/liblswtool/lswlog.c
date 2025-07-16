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

#include "constants.h"
#include "lswtool.h"
#include "lswlog.h"
#include "lswalloc.h"

bool log_to_stderr = true;	/* should log go to stderr? */

const char *progname;

static size_t jam_progname_prefix(struct jambuf *buf, const void *object UNUSED)
{
	const char *progname = object;
	if (progname != NULL) {
		return jam(buf, "%s", progname);
	}
	return 0;
}

const struct logger_object_vec progname_object_vec = {
	.name = "tool",
	.jam_object_prefix = jam_progname_prefix,
};

static struct logger progname_logger = {
	.object_vec = &progname_object_vec,
	.object = NULL, /* progname */
};

struct logger *tool_logger(int argc UNUSED, char *argv[])
{
	const char *last_slash = strrchr(argv[0], '/');
	const char *last_name = (last_slash == NULL ? argv[0] : last_slash + 1);

	/* need to allocate string then mark as never free */
	ssize_t name_size = sizeof("ipsec "/*includes \0*/) + strlen(last_name) + 1/*to be sure*/;
	char *name = alloc_things(char, name_size, "(ignore)progname");
	/* snprintf() returns length, not size */
	passert(name_size > snprintf(name, name_size, "ipsec %s", last_name));

	/*
	 * Also stop on ARGV[0]!
	 *
	 * This is a hack so that getopt() prints something reasonable
	 * as the prefix when reporting errors.
	 *
	 * Note: this does not affect PS.
	 */
	progname_logger.object = progname = argv[0] = name;

	/* redundant? */
	setbuf(stderr, NULL);

	return &progname_logger;
}

/* XXX: The message format is:
 *   FATAL ERROR: <log-prefix><message...><diag>
 *   EXPECTATION FAILED: <log-prefix><message...><diag>
 *   | <log-prefix><message...><diag>
 * and not:
 *   <log-prefix>FATAL ERROR: <message...><diag>
 *   <log-prefix>| <message...><diag>
 *   <log-prefix>EXPECTATION_FAILED: <message...><diag>
 * say
 */

void jam_stream_prefix(struct jambuf *buf, const struct logger *logger, enum stream stream)
{
	switch (stream) {
	case PRINTF_STREAM:
	case NO_STREAM:
		/* suppress all prefixes */
		return;
	case DEBUG_STREAM:
		jam_string(buf, DEBUG_PREFIX);
		/* add prefix when enabled */
		if (LDBGP(DBG_ADD_PREFIX, logger) ||
		    logger->debugging != LEMPTY) {
			jam_logger_prefix(buf, logger);
		}
		return;
	case PEXPECT_STREAM:
		jam_logger_prefix(buf, logger);
		jam_string(buf, PEXPECT_PREFIX);
		return;
	case PASSERT_STREAM:
		jam_logger_prefix(buf, logger);
		jam_string(buf, PASSERT_PREFIX);
		return;
	case WARNING_STREAM:
		jam_logger_prefix(buf, logger);
		jam_string(buf, WARNING_PREFIX);
		return;
	case ERROR_STREAM:
		jam_logger_prefix(buf, logger);
		jam_string(buf, ERROR_PREFIX);
		return;
	case FATAL_STREAM:
		jam_logger_prefix(buf, logger);
		jam_string(buf, FATAL_PREFIX);
		return;
	case ALL_STREAMS:
	case LOG_STREAM:
	case WHACK_STREAM:
		jam_logger_prefix(buf, logger);
		return;
	}

	abort(); /* not passert as goes recursive */
}

void jambuf_to_logger(struct jambuf *buf, const struct logger *logger UNUSED, enum stream stream)
{
	switch (stream) {
	case ALL_STREAMS:
	case LOG_STREAM:
		if (log_to_stderr) {
			fprintf(stderr, "%s\n", buf->array);
		}
		return;
	case PRINTF_STREAM:
	case WHACK_STREAM:
		/* AKA the console */
		fprintf(stdout, "%s\n", buf->array);
		return;
	case WARNING_STREAM:
	case FATAL_STREAM:
	case DEBUG_STREAM:
	case ERROR_STREAM:
	case PEXPECT_STREAM:
		fprintf(stderr, "%s\n", buf->array);
		return;
	case PASSERT_STREAM:
		fprintf(stderr, "%s\n", buf->array);
		return; /*abort();?*/
	case NO_STREAM:
		/*
		 * XXX: Like writing to /dev/null - go through the
		 * motions but with no result.  Code really really
		 * should not call this function with this flag.
		 */
		return;
	}
	fprintf(stderr, "bad stream %d", stream);
	abort(); /* not bad_case(stream) as recursive */
}
