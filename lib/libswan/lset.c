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

/*
 * NOT RE-ENTRANT!
 */
const char *bitnamesof(const char *const table[], lset_t val)
{
	static char bitnamesbuf[8192]; /* I hope that it is big enough! */

	return bitnamesofb(table, val, bitnamesbuf, sizeof(bitnamesbuf));
}

/* test a set by seeing if all bits have names */
bool testset(const char *const table[], lset_t val)
{
	lset_t bit;
	const char *const *tp;

	for (tp = table, bit = 01; val != 0; bit <<= 1, tp++) {
		const char *n = *tp;

		if (n == NULL || ((val & bit) && *n == '\0'))
			return false;

		val &= ~bit;
	}
	return true;
}

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

/*
 * construct a string to name the bits on in a set
 *
 * Result of bitnamesof may be in STATIC buffer -- NOT RE-ENTRANT!
 * Note: prettypolicy depends on internal details of bitnamesofb.
 * binamesofb is re-entrant since the caller provides the buffer.
 */
const char *bitnamesofb(const char *const table[], lset_t val,
			char *b, size_t blen)
{
	char *const roof = b + blen;
	char *p = b;
	lset_t bit;
	const char *const *tp;

	passert(blen != 0); /* need room for NUL */

	/* if nothing gets filled in, default to "none" rather than "" */
	(void) jam_str(b, blen, "none");

	for (tp = table, bit = 01; val != 0; bit <<= 1) {
		if (val & bit) {
			const char *n = *tp;

			if (p != b)
				p = jam_str(p, (size_t)(roof - p), "+");

			if (n == NULL || *n == '\0') {
				/*
				 * No name for this bit, so use hex.
				 * if snprintf returns a different value from
				 * strlen, truncation happened
				 */
				(void)snprintf(p, (size_t)(roof - p),
					"0x%" PRIxLSET,
					bit);
				p += strlen(p);
			} else {
				p = jam_str(p, (size_t)(roof - p), n);
			}
			val -= bit;
		}
		/*
		 * Move on in the table, but not past end.
		 * This is a bit of a trick: while we are at stuck the end,
		 * the loop will print out the remaining bits in hex.
		 */
		if (*tp != NULL)
			tp++;
	}
	return b;
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
