/* enums as names, for libreswan
 *
 * Copyright (C) 2025 Andrew Cagney
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

#ifndef NAMES_H
#define NAMES_H

#include <stdbool.h>

#include "shunk.h"

struct jambuf;
struct enum_names;
struct enum_enum_names;
struct sparse_names;
struct sparse_sparse_names;

/*
 * Printing names:
 *
 * The enum_names and sparse_names tables describes an enumeration (a
 * correspondence between integer values and names).
 */

/*
 * Caller-allocated buffer
 *
 * All these functions (ignoring jam*()) store the result in the
 * caller allocated NAME_BUF.
 *
 * After the call, the field .buf points into a static string (or
 * .tmp[] when the value is not known, see jam_bad()).
 *
 * DANGER: name_buf can't be struct-returned as that moves the struct
 * invalidating the internal pointer.
 *
 * .tmp[] is big enough for decimal rep of any unsigned long value.
 */

typedef struct name_buf {
	const char *buf;
	char tmp[((sizeof(unsigned long) * 241 + 99) / 100)*2 + sizeof("_??")];
} name_buf;

/*
 * Recommended for logging:
 *
 * str_enum_{short,long}() are identical to enum_{short,long}(),
 * except the value (stored in name_buf) is also returned.  Hence the
 * are used:
 *
 *   enum the_enum { THE_ENUM_FIRST_VALUE = 1, } the_enum;
 *   name_buf teb;
 *   ldbg(logger, "the_enum is %s",
 *        str_enum_short(the_enum_names, the_enum, &teb);
 *
 * jam_enum_{short,long}() instead append the value to the JAMBUF, or
 * a mashup of the standard prefix and the numeric value when unknown.
 *
 * jam_enum_human() transforms the value into something more friendly:
 *
 *    - any prefix is dropped
 *    - uppercase is converted to lower case
 *    - '_' is replaced by '-'
 *
 * For instance, "THE_ENUM_FIRST_VALUE" with prefix "THE_ENUM_",
 * becomes "first-value".
 */

const char *str_enum_long(const struct enum_names *en, unsigned long val, name_buf *b);
const char *str_enum_short(const struct enum_names *en, unsigned long val, name_buf *b);

const char *str_sparse_long(const struct sparse_names *sd, unsigned long val, name_buf *buf);
const char *str_sparse_short(const struct sparse_names *sd, unsigned long val, name_buf *buf);

size_t jam_enum_long(struct jambuf *, const struct enum_names *en, unsigned long val);
size_t jam_enum_short(struct jambuf *, const struct enum_names *en, unsigned long val);

size_t jam_sparse_long(struct jambuf *buf, const struct sparse_names *sd, unsigned long val);
size_t jam_sparse_short(struct jambuf *buf, const struct sparse_names *sd, unsigned long val);

/* drop prefix + transform [_A-Z]->[-a-z] */
size_t jam_enum_human(struct jambuf *, const struct enum_names *en, unsigned long val);

size_t jam_sparse_names(struct jambuf *buf, const struct sparse_names *names, const char *separator);

/*
 * Recommended for determining an enum's validity:
 *
 * When the numeric value is known, return TRUE and set name_buf.buf
 * to the name.
 *
 * When the numeric value is unknown, return FALSE and set
 * name_buf.buf to the decimal string representation of the numeric
 * value.
 *
 * Since enum_short() discards the name's prefix returning a shorter
 * string, it is prefered when logging.  Since enum_long() is
 * oh-so-slightly faster it prefered when the result is debug-logged.
 */

bool enum_long(const struct enum_names *en, unsigned long val, name_buf *b);
bool enum_short(const struct enum_names *en, unsigned long val, name_buf *b);

bool sparse_long(const struct sparse_names *sd, unsigned long val, name_buf *b);
bool sparse_short(const struct sparse_names *sd, unsigned long val, name_buf *b);

/*
 * iterator
 *
 * start with -1 -- we hope more immune to rounding
 * ??? how are integers subject to rounding?
 */
extern long next_enum(const struct enum_names *en, long last);

/*
 * Search ED for an enum matching STRING.  Return -1 if no match is
 * found.
 */
extern int enum_byname(const struct enum_names *ed, shunk_t string);

/*
 * primitives:
 *
 * Return the enum_names range containing VAL; and using its result,
 * the corresponding and adjusted name.
 */
const struct enum_names *enum_range(const struct enum_names *en, unsigned long val, const char **prefix);
const char *enum_range_name(const struct enum_names *range, unsigned long val, const char *prefix, bool shorten);

/*
 * Printing enum enums.
 *
 * An enum_enum_names table describes an enumeration first identified
 * by a TYPE and then identified by a VALUE.
 *
 * Like above:
 *
 * enum_enum_name() returns TABLE VAL's enum, or NULL.
 *
 * jam_enum_enum() appends TABLE VAL's enum name; if unnamed, append a
 * mashup of the standard prefix and the numeric value.
 *
 * jam_enum_enum_short() appends TABLE VAL's enum name with any
 * standard prefix removed; if unnamed, append a mashup of the
 * standard prefix and the numeric value.
 */

typedef const struct enum_enum_names enum_enum_names;

bool enum_enum_name(enum_enum_names *e, unsigned long table,
		    unsigned long val, name_buf *buf);

const char *str_enum_enum(enum_enum_names *e, unsigned long table,
			  unsigned long val, name_buf *buf);
const char *str_enum_enum_short(enum_enum_names *e, unsigned long table,
				unsigned long val, name_buf *buf);

size_t jam_enum_enum(struct jambuf *log, enum_enum_names *een,
		     unsigned long table, unsigned long val);
size_t jam_enum_enum_short(struct jambuf *log, enum_enum_names *een,
			   unsigned long table, unsigned long val);

const char *sparse_sparse_name(const struct sparse_sparse_names *sd, unsigned long v1, unsigned long v2);

/*
 * Used by KEYWORD lookup code to report renames et.al.
 *
 * It's assumed names are small and the upper bits can be used as
 * flags.  It's also assumed that enums are >=32-bit.
 */
enum name_flags {
	NAME_IMPLEMENTED_AS = (1<<30),
	NAME_RENAMED_TO,
#define NAME_FLAGS (0x3 <<30)
};

void bad_name(unsigned long val, name_buf *b);
size_t jam_bad(struct jambuf *buf, const char *prefix, unsigned long val);

typedef const struct enum_names enum_names; /*TBD?*/

#endif
