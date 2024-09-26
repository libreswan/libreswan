/*
 * tables of names for values defined in constants.h
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 1998-2002,2015  D. Hugh Redelmeier.
 * Copyright (C) 2016-2017 Andrew Cagney
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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

/*
 * Note that the array sizes are all specified; this is to enable range
 * checking by code that only includes constants.h.
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <netinet/in.h>

#include <ietf_constants.h>
#include "passert.h"

#include "constants.h"
#include "enum_names.h"
#include "lswlog.h"
#include "ip_said.h"		/* for SPI_PASS et.al. */
#include "secrets.h"		/* for enum privae_key_kind */

/*
 * Iterate over the enum_names returning all the valid indexes.
 *
 * Use -1 as the starting point / sentinel.
 *
 * XXX: Works fine provided we ignore the enum_names object that
 * contains negative values stored in unsigned fields!
 */

long next_enum(enum_names *en, long l)
{
	if (l < -1) {
		llog_passert(&global_logger, HERE, "%ld should be >= -1", l);
	}

	unsigned long e;

	/*
	 * Advance L by 1 giving a starting candidate.
	 */
	if (l < 0) {
		e = 0;
	} else {
		e = l+1;
	}

	while (true) {
		/*
		 * Find a range that puts an upper bound on E.  E may
		 * fall within the range, but could also fall short.
		 */
		const struct enum_names *b = NULL;
		for (const struct enum_names *p = en;
		     p != NULL; p = p->en_next_range) {

			if (p->en_last - p->en_first + 1 != p->en_checklen) {
				llog_passert(&global_logger, HERE,
					     "p->en_last(%lu) - p->en_first(%lu) + 1 == p->en_checklen(%zu)",
					     p->en_last, p->en_first, p->en_checklen);
			}

			if (e > p->en_last) {
				continue;
			}

			if (e >= p->en_first) {
				b = p;
				break;
			}

			/* e < .en_first; save when closer */
			if (b == NULL ||
			    b->en_first > p->en_first) {
				b = p;
			}
		}
		if (b == NULL) {
			return -1;
		}

		/*
		 * If E isn't yet within the range, make it so.
		 */
		if (e < b->en_first) {
			e = b->en_first;
		}

		/*
		 * Find the first valid name within the range; if this
		 * fails, iterate round looking for a new range.
		 */
		while (e <= b->en_last) {
			if (b->en_names[e - b->en_first] != NULL) {
				return e;
			}
			e++;
		}
	}
}

/*
 * the enum_name range containing VAL, or NULL.
 */
const struct enum_names *enum_range(const struct enum_names *en, unsigned long val, const char **prefix)
{
	*prefix = NULL;
	for (enum_names *p = en; p != NULL; p = p->en_next_range) {
		passert(p->en_last - p->en_first + 1 == p->en_checklen);
		/* return most recent prefix */
		if (p->en_prefix != NULL) {
			*prefix = p->en_prefix;
		}
		if (p->en_first <= val && val <= p->en_last) {
			return p;
		}
	}
	return NULL;
}

/*
 * The actual name for VAL, using RANGE; possibly shortened using
 * PREFIX.
 */
const char *enum_range_name(const struct enum_names *range, unsigned long val,
			    const char *prefix, bool shorten)
{
	if (range == NULL) {
		return NULL;
	}
	passert(range->en_first <= val && val <= range->en_last);
	/* can be NULL */
	const char *name = range->en_names[val - range->en_first];
	if (name != NULL && prefix != NULL && shorten) {
		/* grr: can't use eat() */
		size_t pl = strlen(prefix);
		return strneq(name, prefix, pl) ? name + pl : name;
	} else {
		return name;
	}
}

static const char *find_enum(const struct enum_names *en, unsigned long val, bool shorten)
{
	const char *prefix = NULL;
	/* can be NULL */
	const struct enum_names *range = enum_range(en, val, &prefix);
	/* can be NULL */
	return enum_range_name(range, val, prefix, shorten);
}

bool enum_long(enum_names *ed, unsigned long val, enum_buf *b)
{
	/* can be NULL; handled here */
	b->buf = find_enum(ed, val, /*shorten?*/false);
	if (b->buf == NULL) {
		bad_name(val, b);
		return false;
	}

	return true;
}

bool enum_short(enum_names *ed, unsigned long val, enum_buf *b)
{
	/* can be NULL; handled here */
	b->buf = find_enum(ed, val, /*shorten?*/true);
	if (b->buf == NULL) {
		bad_name(val, b);
		return false;
	}

	return true;
}

const char *str_enum_long(enum_names *ed, unsigned long val, enum_buf *b)
{
	enum_long(ed, val, b);
	return b->buf;
}

const char *str_enum_short(enum_names *ed, unsigned long val, enum_buf *b)
{
	enum_short(ed, val, b);
	return b->buf;
}

size_t jam_enum_long(struct jambuf *buf, enum_names *en, unsigned long val)
{
	const char *name = find_enum(en, val, /*shorten*/false);
	if (name != NULL) {
		return jam_string(buf, name);
	}
	return jam_bad(buf, en->en_prefix, val);
}

size_t jam_enum_short(struct jambuf *buf, enum_names *en, unsigned long val)
{
	/* can be NULL; handled here */
	const char *name = find_enum(en, val, /*shorten*/true);
	if (name != NULL) {
		return jam_string(buf, name);
	}
	return jam_bad(buf, en->en_prefix, val);
}

size_t jam_enum_human(struct jambuf *buf, enum_names *en, unsigned long val)
{
	/* can be NULL; handled here */
	const char *name = find_enum(en, val, /*shorten?*/true);
	if (name != NULL) {
		return jam_string_human(buf, name);
	}
	return jam_bad(buf, en->en_prefix, val);
}

/*
 * Find the value for a name in an enum_names table.  If not found, returns -1.
 *
 * Strings are compared without regard to case.
 *
 * ??? the table contains unsigned long values BUT the function returns an
 * int so there is some potential for overflow.
 */
int enum_search(enum_names *ed, const char *str)
{
	for (enum_names *p = ed; p != NULL; p = p->en_next_range) {
		passert(p->en_last - p->en_first + 1 == p->en_checklen);
		for (unsigned long en = p->en_first; en <= p->en_last; en++) {
			const char *ptr = p->en_names[en - p->en_first];

			if (ptr != NULL && strcaseeq(ptr, str)) {
				passert(en <= INT_MAX);
				return en;
			}
		}
	}
	return -1;
}

int enum_match(enum_names *ed, shunk_t string)
{
	const char *prefix = NULL;
	for (enum_names *p = ed; p != NULL; p = p->en_next_range) {
		passert(p->en_last - p->en_first + 1 == p->en_checklen);
		prefix = (p->en_prefix == NULL ? prefix : p->en_prefix);
		for (unsigned long en = p->en_first; en <= p->en_last; en++) {
			const char *name = p->en_names[en - p->en_first];

			if (name == NULL) {
				continue;
			}

			passert(en <= INT_MAX);

			/*
			 * try matching all four variants of name:
			 * with and without prefix en->en_prefix and
			 * with and without suffix '(...)'
			 */
			size_t name_len = strlen(name);
			size_t prefix_len = (prefix == NULL ? 0 : strlen(prefix));

			/* suffix must not and will not overlap prefix */
			const char *suffix = strchr(name + prefix_len, '(');

			size_t suffix_len = (suffix != NULL && name[name_len - 1] == ')' ?
					     &name[name_len] - suffix : 0);

#			define try(guard, f, b) ( \
				(guard) && \
				name_len - ((f) + (b)) == string.len && \
				strncaseeq(name + (f), string.ptr, string.len))

			if (try(true, 0, 0) ||
			    try(suffix_len > 0, 0, suffix_len) ||
			    try(prefix_len > 0, prefix_len, 0) ||
			    try(prefix_len > 0 && suffix_len > 0, prefix_len, suffix_len))
			{
				return en;
			}
#			undef try
		}
	}
	return -1;
}

/* choose table from struct enum_enum_names */
static const struct enum_names *enum_enum_table(enum_enum_names *een,
						unsigned long table)
{
	if (!(een->een_last - een->een_first + 1 == een->een_checklen)) {
		/* *_{last,first} are longs */
		llog_passert(&global_logger, HERE,
			     ".een_last=%lu - .een_first=%lu + 1 == .een_checklen=%zu",
			     een->een_last, een->een_first, een->een_checklen);
	}

	if (een->een_first <= table && table <= een->een_last) {
		return een->een_enum_name[table - een->een_first];
	}

	return NULL;
}

bool enum_enum_name(enum_enum_names *een, unsigned long table,
		    unsigned long val, enum_buf *b)
{
	enum_names *en = enum_enum_table(een, table);
	if (en == NULL) {
		snprintf(b->tmp, sizeof(b->tmp), "%lu.%lu", table, val);
		b->buf = b->tmp;
		return false;
	}

	return enum_name(en, val, b);
}

const char *str_enum_enum(enum_enum_names *een, unsigned long table,
			  unsigned long val, enum_buf *b)
{
	enum_enum_name(een, table, val, b);
	return b->buf;
}

const char *str_enum_enum_short(enum_enum_names *een, unsigned long table,
				unsigned long val, enum_buf *b)
{
	enum_names *en = enum_enum_table(een, table);
	if (en == NULL) {
		/* assume the log context implies the table name */
		snprintf(b->tmp, sizeof(b->tmp), "%lu.%lu", table, val);
		b->buf = b->tmp;
		return b->buf;
	}

	return str_enum_short(en, val, b);
}

size_t jam_enum_enum(struct jambuf *buf, enum_enum_names *een,
		     unsigned long table, unsigned long val)
{
	enum_names *en = enum_enum_table(een, table);
	if (en == NULL) {
		/* XXX: dump something more meaningful */
		return jam(buf, "%lu.%lu", table, val);
	}
	return jam_enum(buf, en, val);
}

size_t jam_enum_enum_short(struct jambuf *buf, enum_enum_names *een,
			   unsigned long table, unsigned long val)
{
	enum_names *en = enum_enum_table(een, table);
	if (en == NULL) {
		/* XXX: dump something more meaningful */
		return jam(buf, "%lu.%lu", table, val);
	}
	return jam_enum_short(buf, en, val);
}

void check_enum_names(const struct enum_names_check *checklist)
{
	/* check that enum_names are well-formed */
	for (const struct enum_names_check *c = checklist;
	     c->name != NULL && c->enum_names != NULL; c++) {
		/*
		 * enum_name will check all linked enum_names if given
		 * a value that isn't covered.  -42 is probably not
		 * covered.
		 */
		enum_buf b;
		enum_name(c->enum_names, -42UL, &b);
	}
}

void check_enum_enum_names(const struct enum_enum_names_check *checklist)
{
	/* check that enum_enum_names are well-formed */
	for (const struct enum_enum_names_check *c = checklist;
	     c->name != NULL && c->enum_enum_names != NULL; c++) {
		/* check v2_transform_ID_enums, the only enum_enum_names */
		enum_enum_table(c->enum_enum_names, -42UL);
	}
}

void init_enum_names(void)
{
	check_enum_names(enum_names_checklist);
	check_enum_enum_names(enum_enum_names_checklist);
}
