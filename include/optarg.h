/* getopt parsing, for libreswan
 *
 * Copyright (C) 2023,2024 Andrew Cagney
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

#ifndef OPTARG_H

#include <getopt.h>

#include "deltatime.h"
#include "ip_address.h"
#include "ip_cidr.h"
#include "lmod.h"

struct logger;
enum timescale;

extern unsigned verbose;			/* defined by optarg.c */
extern int optarg_index;			/* defined by optarg.c */
extern const struct option optarg_options[]; 	/* defined by program */

/*
 * Wrap getopt_long() and dispense with common cases such as ':', '?',
 * and '\0'.
 *
 * Danger: this expect option strings to have the form:
 *    option\0[MAGIC]<arg>
 * see below.
 */

int optarg_getopt(struct logger *logger, int argc, char **argv, const char *options);

/*
 * Using OPTARG_OPTIONS[] table, which is assumed to contain METAOPT
 * suffixes, generate a usage message.
 *
 * Note: this function always writes to STDOUT.  This is so that:
 *    cmd -h | more
 * always works.
 *
 * Note: there are two hacks for forcing new lines and doing:
 *
 * - any option starting with METAOPT_HEADING
 *   don't tell anyone that --\r\a\n\t will match
 *   prefered for now
 *
 * - an empty option
 *   which seems to be ignored?
 *
 */

#define METAOPT_REPLACE   "\0>"		/* warn that option was replaced */
#define METAOPT_IGNORE "\0!"		/* warn, and ignore, option */
#define METAOPT_HEADING  "\r\a\n\t"	/* new line with heading */

#define REPLACE_OPT(OLD, NEW, RELEASE, ...)	OLD METAOPT_REPLACE NEW "\n" RELEASE
#define IGNORE_OPT(OLD, RELEASE, ...)		OLD METAOPT_IGNORE "\n" RELEASE
#define HEADING_OPT(HEADING)		{ METAOPT_HEADING HEADING, no_argument, NULL, 0, }
#define OPT(OPT, ...) 			OPT "\0" __VA_ARGS__

void optarg_usage(const char *progname, const char *arguments,
		  const char *details) NEVER_RETURNS;

NEVER_RETURNS PRINTF_LIKE(2) void optarg_fatal(const struct logger *logger,
					       const char *fmt, ...);

/* returns a non-empty string, or barfs */
const char *optarg_nonempty(const struct logger *logger);
/* returns a non-NULL string, or barfs */
const char *optarg_empty(const struct logger *logger);

deltatime_t optarg_deltatime(const struct logger *logger, enum timescale default_timescale);

uintmax_t optarg_uintmax(const struct logger *logger);

/* 0 or [1500..64k) */
uintmax_t optarg_udp_bufsize(const struct logger *logger);

/* non-zero OPTIONAL provides default */
uintmax_t optarg_sparse(const struct logger *logger, unsigned optional, const struct sparse_names *names);

enum yn_options optarg_yn(const struct logger *logger, enum yn_options optional);
enum yna_options optarg_yna(const struct logger *logger, enum yna_options optional);
enum yne_options optarg_yne(const struct logger *logger, enum yne_options optional);

/*
 * Adddres family dependent options.
 *
 * The struct keeps track of the selected value and which param
 * used/specified it so it can be logged when a conflict occurs.
 */

struct optarg_family {
	const char *used_by;
	const struct ip_info *type;
};

ip_address optarg_address_dns(const struct logger *logger, struct optarg_family *);
ip_cidr optarg_cidr_num(const struct logger *logger, struct optarg_family *);
void optarg_family(struct optarg_family *family, const struct ip_info *info);
ip_address optarg_any(struct optarg_family *family);

/*
 * Call optarg_verbose() whenever --verbose is encountered.
 *
 * Each call increments VERBOSE.
 *
 * When VERBOSE>=2 it also adds increasingly verbose debugging to
 * CUR_DEBUGGING.  As verbose increases, START (if non-LEMPTY),
 * DBG_BASE, DBG_ALL and DBG_TMI are each added in turn.
 */

void optarg_verbose(const struct logger *logger, lset_t start);

/*
 * parse --debug and --no-debug options.  The option may be followed
 * by an argument.
 *
 * First variant updates CUR_DEBUGGING; second maintains a set of
 * updates - see whack.c.
 */

enum optarg_debug {
	OPTARG_DEBUG_YES = 1,
	OPTARG_DEBUG_NO,
};

void optarg_debug(enum optarg_debug);
void optarg_debug_lmod(enum optarg_debug, lmod_t *debugging);

#endif
