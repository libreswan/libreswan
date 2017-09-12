/* lset_t names for libreswan
 *
 * Copyright (C) 2017, Andrew Cagney <cagney@gnu.org>
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

#ifndef LSET_NAMES_H
#define LSET_NAMES_H

#include "constants.h" /* for typedef uint_fast64_t lset_t et.al. */

struct lswlog;

struct lelem_name {
	const char *name;
	const char *flag;
	lset_t lelem; /* redundant, but allows a cross check */
};

struct lset_names {
	const char *strip;
	size_t roof;
	/*
	 * Name of each lset element.
	 *
	 * [ROOF] is set to SENTINEL_LELEM_NAME so the array size can
	 * be checked.  It should not be accessed.
	 */
#define SENTINEL_LELEM LRANGE(0, LELEM_ROOF-1)
#define SENTINEL_LELEM_NAME { NULL, NULL, SENTINEL_LELEM, }
	struct lelem_name lelems[];
};

void lset_names_check(const struct lset_names *names);

size_t lswlog_lset_flags(struct lswlog *buf,
			 const struct lset_names *names,
			 lset_t bits);

#endif
