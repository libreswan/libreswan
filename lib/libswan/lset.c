/* lset_t routines, for libreswan
 *
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 1998-2002,2015  D. Hugh Redelmeier.
 * Copyright (C) 2016-2017 Andrew Cagney
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
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

#include "lset.h"

#include "lswlog.h"	/* for passert() */
#include "enum_names.h"
#include "sparse_names.h"

/* test a set by seeing if all bits have names */
bool test_lset(const struct enum_names *en, lset_t val)
{
	for (unsigned e = 0; val != 0; e++) {
		lset_t bit = LELEM(e);
		if (val & bit) {
			const char *n = enum_name(en, e);
			if (n == NULL) {
				return false;
			}
		}
		val &= ~bit;
	}
	return true;
}

static size_t jam_lset_pretty(struct jambuf *buf, enum_names *en, lset_t val,
			      const char *separator, bool shorten)
{
	if (val == LEMPTY) {
		return jam(buf, "none");
	}

	size_t s = 0;
	const char *sep = "";
	const struct enum_names *range = NULL;
	const char *prefix = NULL;
	for (unsigned e = 0; val != 0; e++) {
		lset_t bit = LELEM(e);
		if (val & bit) {
			/* range!=NULL implies e>=range->en_first */
			if (range == NULL || e > range->en_last) {
				/* try to find a new range */
				range = enum_range(en, e, &prefix);
			}
			s += jam_string(buf, sep);
			sep = separator;
			/* can handle range==NULL */
			const char *name = enum_range_name(range, e, prefix, shorten);
			if (name == NULL) {
				/* No name for this bit, use hex. */
				s += jam(buf, "0x" PRI_LSET, bit);
			} else {
				s += jam_string(buf, name);
			}
		}
		val &= ~bit;
	}
	return s;
}

#define LSET_SEPARATOR "+"

size_t jam_lset(struct jambuf *buf, enum_names *en, lset_t val)
{
	return jam_lset_pretty(buf, en, val, LSET_SEPARATOR, /*shorten?*/false);
}

const char *str_lset(enum_names *en, lset_t val, lset_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_lset(&buf, en, val);
	return out->buf;
}

size_t jam_lset_short(struct jambuf *buf, enum_names *en,
		      const char *separator, lset_t val)
{
	return jam_lset_pretty(buf, en, val, separator, /*shorten?*/true);
}

const char *str_lset_short(enum_names *en, const char *separator,
			   lset_t val, lset_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_lset_short(&buf, en, separator, val);
	return out->buf;
}

size_t jam_sparse_lset(struct jambuf *buf, const struct sparse_names *sd, lset_t val)
{
	if (val == LEMPTY) {
		return jam(buf, "none");
	}

	size_t s = 0;
	const char *sep = "";
	for (unsigned e = 0; val != 0; e++) {
		lset_t bit = LELEM(e);
		if (val & bit) {
			s += jam_string(buf, sep);
			sep = LSET_SEPARATOR;
			/* can return NULL */
			const char *name = sparse_name(sd, bit);
			if (name == NULL) {
				/* No name for this bit, use hex. */
				s += jam(buf, "0x" PRI_LSET, bit);
			} else {
				s += jam_string(buf, name);
			}
		}
		val &= ~bit;
	}
	return s;
}
