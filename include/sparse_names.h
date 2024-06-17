/* sparse_names, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2004-2008  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2004-2009  Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#ifndef SPARSE_NAMES_H
#define SPARSE_NAMES_H

#include <stddef.h>		/* for size_t */

#include "shunk.h"

struct jambuf;

/*
 * sparse_names is much like enum_names, except values are not known
 * to be contiguous or ordered.
 *
 * The array is NULL terminated, as in .name==NULL; but suggest using
 * SPARSE_NULL in case that needs to change.
 */

#define SPARSE_NULL { NULL, 0, NULL, }
#define SPARSE(N, V) { .name = N, .value = V, }

struct sparse_name {
	/* field order (backwards?) dictated by started() */
	const char *const name;
	unsigned long value;
	const char *help;
};

struct sparse_names {
	size_t roof; /* when non-zero, limit on value */
	struct sparse_name list[];
};

const struct sparse_name *sparse_lookup(const struct sparse_names *, shunk_t);

typedef struct {
	char buf[16];/*how big?*/
} sparse_buf;

const char *sparse_name(const struct sparse_names *sd, unsigned long val);
size_t jam_sparse(struct jambuf *buf, const struct sparse_names *sd, unsigned long val);
const char *str_sparse(const struct sparse_names *sd, unsigned long val, sparse_buf *buf);
size_t jam_sparse_names(struct jambuf *buf, const struct sparse_names *names, const char *separator);

/*
 * sparse_sparse_names is much like enum_enum_names, except, again the
 * values are neither assumed to be contingious or ordered.
 *
 * The array is terminated by a NULL entry.
 */

struct sparse_sparse_name {
	unsigned long value;
	const struct sparse_names *names;
};

struct sparse_sparse_names {
	size_t ignore_for_now;
	const struct sparse_sparse_name list[];
};

extern const char *sparse_sparse_name(const struct sparse_sparse_names *sd, unsigned long v1, unsigned long v2);

#endif /* _CONSTANTS_H_ */
