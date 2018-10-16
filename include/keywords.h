/* manifest constants
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2004-2008  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2004-2009  Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
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

#ifndef KEYWORDS_H
#define KEYWORDS_H

#include <stddef.h>	/* for size_t */

#include "constants.h"	/* XXX: for elemsof() */
#include "shunk.h"

/*
 * NAME<>VALUE map (but with bonus .details)
 *
 * We've already got enum_names, struct keyword_enum_values, and
 * sparse_name so why yet another another one?
 *
 * The two key differences are:
 *
 * - the new .details field
 *
 * - lookups return the map
 *
 * This way code listing values can easily include additional
 * information.  For instance, a short description of each --impair
 * flag in help output.
 *
 * Once the dust has settled, this code can be merged with the other
 * name tables.
 *
 * For keyword_enum_values and sparse_names while things are straight
 * forward, it will churn the code - trying to add the new field to
 * the existing code resulted in lots of uninitialized field errors.
 *
 * For enum_names, things get more complex.  But again, there really
 * shouldn't be so many NAME<>VALUE maps.
 */

struct keyword {
	const char *name;
	const char *sname;
	unsigned value;
	const char *details;
};

struct keywords;

const struct keyword *keyword_by_value(const struct keywords *keywords,
				       unsigned value);

const struct keyword *keyword_by_name(const struct keywords *keywords,
				      shunk_t name);

const struct keyword *keyword_by_sname(const struct keywords *keywords,
				       shunk_t name);

/*
 * logging short-cuts
 */

size_t lswlog_keyname(struct lswlog *buf, const struct keywords *keywords, unsigned value);
size_t lswlog_keysname(struct lswlog *buf, const struct keywords *keywords, unsigned value);


/*
 * "private"
 */

typedef const struct keyword *(keyword_by_value_fn)(const struct keywords *, unsigned);

struct keywords {
	const struct keyword *values;
	size_t nr_values;
	keyword_by_value_fn *by_value;
	const char *name;
};

/*
 * direct map: values[I].value == I IFF values[I].name!=NULL
 *
 * Can contain holes where .name==NULL.  For instance, with an enum
 * starting at 1, values[0].name==NULL.
 */
keyword_by_value_fn keyword_by_value_direct;
#define DIRECT_KEYWORDS(NAME, VALUES) {					\
		.values = VALUES,					\
			.nr_values = elemsof(VALUES),			\
			.by_value = keyword_by_value_direct,		\
			.name = (NAME),					\
			}

/*
 * sorted map: binary search possible
 */
keyword_by_value_fn keyword_by_value_binary;
#define SORTED_KEYWORDS(NAME, VALUES) {					\
		.values = VALUES,					\
			.nr_values = elemsof(VALUES),			\
			.by_value = keyword_by_value_binary,		\
			.name = (NAME),					\
			}

/*
 * sparse map: linear search required
 */
keyword_by_value_fn keyword_by_value_linear;
#define SPARSE_KEYWORDS(NAME, VALUES) {					\
		.values = VALUES,					\
			.nr_values = elemsof(VALUES),			\
			.by_value = keyword_by_value_linear,		\
			.name = (NAME),					\
			}

#endif
