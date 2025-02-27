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

extern unsigned verbose;			/* defined by optarg.c */
extern int optarg_index;			/* defined by optarg.c */
extern const struct option optarg_options[]; 	/* defined by program */
enum timescale;

void optarg_init(const struct logger *logger);

deltatime_t optarg_deltatime(enum timescale default_timescale);

uintmax_t optarg_uintmax(void);
/* non-zero OPTIONAL provides default */
uintmax_t optarg_sparse(unsigned optional, const struct sparse_names *names);

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

ip_address optarg_address_dns(struct optarg_family *);
ip_cidr optarg_cidr_num(struct optarg_family *);
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

void optarg_verbose(lset_t start);

/*
 * parse --debug and --no-debug options
 *
 * First variant updates CUR_DEBUGGING; second maintains a set of
 * updates - see whack.c.
 */

void optarg_debug(bool enable);
void optarg_debug_lmod(bool enable, lmod_t *debugging);

#endif
