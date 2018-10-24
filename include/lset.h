/* long set constants
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2004-2008  Michael Richardson <mcr@xelerance.com>
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

struct enum_names;
struct lswlog;

/*
 * set type with room for at least 64 elements for ALG opts (was 32 in
 * stock FS)
 */

typedef uint_fast64_t lset_t;
#define PRIxLSET    PRIxFAST64
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

/* Printing lset_t values:
 *
 * These routines require a name table which is a NULL-terminated
 * sequence of strings.  That means that each bit in the set must
 * have a name.
 *
 * bitnamesof() formats a display of a set of named bits (in a static area -- NOT RE-ENTRANT)
 * bitnamesofb() formats into a caller-supplied buffer (re-entrant)
 *
 * lswlog_enum_lset_short() formats into a caller-supplied buffer -- only form
 */
extern bool testset(const char *const table[], lset_t val);
extern const char *bitnamesof(const char *const table[], lset_t val);	/* NOT RE-ENTRANT */
extern const char *bitnamesofb(const char *const table[],
			       lset_t val,
			       char *buf, size_t blen);

size_t lswlog_enum_lset_short(struct lswlog *, const struct enum_names *sd,
			      const char *separator, lset_t val);

#endif /* CONSTANTS_H */
