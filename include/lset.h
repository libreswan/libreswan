/* long set constants
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2004-2008  Michael Richardson <mcr@xelerance.com>
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
 *
 */

#ifndef LSET_H
#define LSET_H

#include <stddef.h>		/* for size_t */
#include <stdint.h>		/* for uint_fast64_t */
#include <stdbool.h>
#include <inttypes.h>		/* for PRI... */

struct enum_names;
struct jambuf;
struct sparse_names;

/*
 * set type with room for at least 64 elements for ALG opts (was 32 in
 * stock FS)
 */

typedef uint_fast64_t lset_t;
#define PRI_LSET "%"PRIxFAST64

#define LELEM_ROOF  64	/* all elements must be less than this */
#define LEMPTY ((lset_t)0)
#define LELEM(opt) ((lset_t)1 << (opt))
#define LRANGE(lwb, upb) LRANGES(LELEM(lwb), LELEM(upb))
#define LRANGES(first, last) (last - first + last)
#define LHAS(set, elem)  (((set) & LELEM(elem)) != LEMPTY)
#define LIN(subset, set)  (((subset) & (set)) == (subset))
#define LDISJOINT(a, b)  (((a) & (b)) == LEMPTY)
/* LFIRST: find first element of a set (tricky use of twos complement) */
#define LFIRST(s) ((s) & -(s))
#define LSINGLETON(s) ((s) != LEMPTY && LFIRST(s) == (s))

/*
 * Printing lset_t values:
 */

typedef struct {
	char buf[512]; /* arbitrary */
} lset_buf;

extern bool test_lset(const struct enum_names *table, lset_t val);

size_t jam_lset(struct jambuf *, const struct enum_names *sd, lset_t val);
const char *str_lset(const struct enum_names *sd, lset_t val, lset_buf *buf);
size_t jam_sparse_lset(struct jambuf *, const struct sparse_names *sd, lset_t val);

size_t jam_lset_short(struct jambuf *, const struct enum_names *sd,
		      const char *separator, lset_t val);
const char *str_lset_short(const struct enum_names *sd,
			   const char *separator, lset_t val,
			   lset_buf *buf);

#endif /* CONSTANTS_H */
