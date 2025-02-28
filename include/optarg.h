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
 * Danger: at time of writing, only pluto had the correctly structured
 * table.
 *
 * Note: this function always writes to STDOUT.  This is so that:
 *    cmd -h | more
 * always works.
 */

#define METAOPT_RENAME "\0>"		/* warn that option was renamed */
#define METAOPT_OBSOLETE "\0!"		/* warn, and ignore, option */
#define METAOPT_NEWLINE "\0^"
/* heading: \0HEADING */
/* argument: \0<argument> */

void optarg_usage(const char *progname);

NEVER_RETURNS PRINTF_LIKE(2) void optarg_fatal(const struct logger *logger,
					       const char *fmt, ...);

deltatime_t optarg_deltatime(const struct logger *logger, enum timescale default_timescale);

uintmax_t optarg_uintmax(const struct logger *logger);

/* non-zero OPTIONAL provides default */
uintmax_t optarg_sparse(const struct logger *logger, unsigned optional, const struct sparse_names *names);

/*
 * Adddres family dependent options.
 *
 * The struct keeps track of the selected value and which param
 * used/specified it so it can be logged when a conflict occures.
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
 * parse --debug and --no-debug options
 *
 * First variant updates CUR_DEBUGGING; second maintains a set of
 * updates - see whack.c.
 */

void optarg_debug(bool enable);
void optarg_debug_lmod(bool enable, lmod_t *debugging);

#endif
