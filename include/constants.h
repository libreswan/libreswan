/*
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
 *
 */

#ifndef _CONSTANTS_H_
#define _CONSTANTS_H_

#include <stddef.h> /* for size_t */
#include <string.h>		/* for strcmp() */

#include "shunk.h"

struct jambuf;

/* Some constants code likes to use. Useful? */

enum {
	secs_per_minute = 60,
	secs_per_hour = 60 * secs_per_minute,
	secs_per_day = 24 * secs_per_hour
};

enum binary {
	binary_per_kilo = UINT64_C(1024),
	binary_per_mega = UINT64_C(1024) * binary_per_kilo,
	binary_per_giga = UINT64_C(1024) * binary_per_mega,
	binary_per_tera = UINT64_C(1024) * binary_per_giga,
	binary_per_peta = UINT64_C(1024) * binary_per_tera,
	binary_per_exa  = UINT64_C(1024) * binary_per_peta, /* 2^64 s 16 Exa */
};

/*
 * This file was split into internal constants (Libreswan/pluto related),
 * and external constants (defined by IETF, etc.)
 *
 * Constants that are kernel/IPsec related are in appropriate
 * libreswan / *.h files.
 *
 */

/*
 * NOTE:For debugging purposes, constants.c has tables to map
 * numbers back to names.
 * Any changes here should be reflected there.
 */

/*
 * min()/max() macros that also do
 * strict type-checking.. See the
 * "unnecessary" pointer comparison.
 * Note: re-evaluation is avoided.
 * Copied from include/linux/kernel.h
 * Copyright Torvalds et al.
 */
#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })

/*
 * Alternate MIN/MAX implementation.
 *
 * These have more macro-like behaviour (hence NAMING):
 * - if the arguments are compile-time constants, then so is the result
 *   so this can be used (for example) in array bound calculation.
 * - one of the arguments will be evaluated twice.
 * - type errors are probably not detected.
 * - does not depend on GCC extensions to C language
 *
 * The P prefix is required because <sys/param.h> defines MIN and MAX
 */

#define PMIN(x,y) ((x) <= (y) ? (x) : (y))
#define PMAX(x,y) ((x) >= (y) ? (x) : (y))

#define NULL_FD (-1)	/* NULL file descriptor */

/* octet_t / BITS_IN_OCTET anyone? */
#define BITS_IN_BYTE 8
#define BYTES_FOR_BITS(b)   (((b) + BITS_IN_BYTE - 1) / BITS_IN_BYTE)

/* clearer shorthand for *cmp functions */
#define streq(a, b) (strcmp((a), (b)) == 0)
#define strneq(a, b, c) (strncmp((a), (b), (c)) == 0)
#define startswith(a, b) strneq((a), (b), strlen(b))
#define eat(a, b) (startswith((a), (b))? ((a) += sizeof(b) - 1), true : false)
#define strcaseeq(a, b) (strcasecmp((a), (b)) == 0)
#define strncaseeq(a, b, n) (strncasecmp((a), (b), (n)) == 0)
#define memeq(a, b, n) (memcmp((a), (b), (n)) == 0)
#define thingeq(L, R)							\
	({								\
		/* check type compat by flipping types */		\
		const typeof(R) *l_ = &(L);/* type flip */		\
		const typeof(L) *r_ = &(R);/* type flip */		\
		memeq(l_, r_, sizeof(L));				\
	})

/*
 * Fill a string field, ensuring that it is padded and terminated with NUL
 * If termination isn't required, strncpy would do.
 * If filling isn't required, jam_str would do.
 */
#define fill_and_terminate(dest, src, len) { \
		strncpy((dest), (src), (len)-1); \
		(dest)[(len)-1] = '\0'; \
	}

/*
 * zero an object given a pointer to it.
 *
 * Note: this won't work on a pointer to the first element of an
 * array since sizeof() will only give the length of the first element.
 * Unfortunately, no compiler diagnostic will flag this.
 * Any array will have to be prefixed with an & to yield a pointer
 * to the whole array.  The normal representation for a string or pointer
 * to a raw buffer is a pointer to the first element, so they cannot be zeroed.
 *
 * Simple form of this rule:
 * The argument to zero must be prefixed by & unless it is a pointer
 * to the object you wish to zero.  A pointer to an object must be
 * a pointer to the whole object, not just the first element.
 *
 * Note also that zeroing a pointer is not guaranteed to make it NULL
 * (read the C standard).  This problem is mostly theoretical since
 * on almost all real architectures it works.
 * ??? there are many calls that are intended to set pointers to NULL.
 * ??? there are many calls to zero that are not needed and thus confusing.
 *     Often we would be better served if calls to messup were used:
 *     actual bugs might be detected.
 */
#define zero(x) memset((x), '\0', sizeof(*(x)))	/* zero all bytes */

/*
 * messup: set memory to a deterministic useless value
 *
 * Like zero macro, but sets object to likely wrong value.
 * The intent is that memory that is supposed to not be used
 * without further initialization will not accidentally have a
 * plausible value (eg. zero, or the previous value, or some
 * secret that might be leaked).
 */

#define messupn(x, n) memset((x), 0xFB, (n))	/* set n bytes to wrong value */
#define messup(x) messupn((x), sizeof(*(x)))	/* set all bytes to wrong value */

extern const char *bool_str(bool b);	/* bool -> string */
err_t ttobool(const char *t, bool *b);	/* string -> bool */

/* routines to copy C strings to fixed-length buffers */
extern char *jam_str(char *dest, size_t size, const char *src);
extern char *add_str(char *buf, size_t size, char *hint, const char *src);

/* Routines to check and display values.
 *
 * WARNING: Some of these routines are not re-entrant because
 * they use a static buffer.
 * When a non-re-entrant version is called, the buffer holding the result
 * may be overwritten by the next call.  Among other things, this means that
 * at most one call should appear in the argument list to a function call
 * (e.g. a call to a log function).
 */

/*
 * Printing Enums:
 *
 * An enum_names table describes an enumeration (a correspondence
 * between integer values and names).
 *
 * Recommended for determining an enum's validity:
 *
 *   enum_name*() returns true when known, and sets enum_buf to a
 *   non-NULL string.
 *
 * Recommended for logging:
 *
 *   str_enum*() is similar to enum_name, except it formats a numeric
 *   representation for any unnamed value in a caller-supplied buffer.
 *
 *   jam_enum() appends the name of an enum value; if unnamed, append
 *   a mashup of the standard prefix and the numeric value.
 *
 * {*}_short() same as for root, but with any standard prefix removed.
 *
 * Caller-allocated buffer
 *
 * Enough space for decimal rep of any unsigned long + "??"  sizeof
 * yields log-base-256 of maximum value.  Multiplying by 241/100
 * converts this to the number of decimal digits (the common log),
 * rounded up a little (instead of 2.40654...).  The addition of 99
 * ensures that the division rounds up to an integer rather than
 * truncates.
 *
 * The .name field points either at buf[] or some internal string.  It
 * is never NULL.  DANGER: enum_buf can't be returned as that moves
 * the struct invalidating the internal pointer.
 */

typedef struct {
	const char *buf;
	char tmp[(sizeof(unsigned long) * 241 + 99) / 100 + sizeof("??")];
} enum_buf;
typedef enum_buf esb_buf; /* XXX: TBD */

typedef const struct enum_names enum_names;

extern const char *enum_name(enum_names *ed, unsigned long val);
extern bool enum_name_short(enum_names *ed, unsigned long val, enum_buf *b);

size_t jam_enum_short(struct jambuf *, enum_names *en, unsigned long val);
size_t jam_enum_long(struct jambuf *, enum_names *en, unsigned long val);

#define jam_enum jam_enum_long
/* drop prefix + transform [_A-Z]->[-a-z] */
size_t jam_enum_human(struct jambuf *, enum_names *en, unsigned long val);


extern const char *str_enum_long(enum_names *ed, unsigned long val, enum_buf *);
extern const char *str_enum_short(enum_names *ed, unsigned long val, enum_buf *);

#define str_enum str_enum_long
#define enum_show str_enum_long /* XXX: TBD */

/*
 * iterator
 *
 * start with -1 -- we hope more immune to rounding
 * ??? how are integers subject to rounding?
 */
extern long next_enum(enum_names *en, long last);

extern int enum_search(enum_names *ed, const char *string);

/*
 * Search ED for an enum matching STRING.  Return -1 if no match is
 * found.
 *
 * Unlike enum_search() this compares strings both with and without
 * any prefix or suffix.  For instance, given the enum_name entry
 * "ESP_BLOWFISH(OBSOLETE)" with prefix "ESP_", any of
 * "esp_blowfish(obsolete)", "esp_blowfish" and "blowfish" will match.
 */
extern int enum_match(enum_names *ed, shunk_t string);

/*
 * primitives:
 *
 * Return the enum_names range containing VAL; and using its result,
 * the corresponding and adjusted name.
 */
const struct enum_names *enum_range(enum_names *en, unsigned long val, const char **prefix);
const char *enum_range_name(enum_names *range, unsigned long val, const char *prefix, bool shorten);

/*
 * Printing enum enums.
 *
 * An enum_enum_names table describes an enumeration first identified
 * by a TYPE and then identified by a VALUE.
 *
 * Like above:
 *
 * enum_enum_table() returns TABLE's enum_names, or NULL.
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

enum_names *enum_enum_table(enum_enum_names *e, unsigned long table);
const char *enum_enum_name(enum_enum_names *e, unsigned long table,
			   unsigned long val);

const char *str_enum_enum(enum_enum_names *e, unsigned long table,
			  unsigned long val, enum_buf *buf);
const char *str_enum_enum_short(enum_enum_names *e, unsigned long table,
				unsigned long val, enum_buf *buf);

size_t jam_enum_enum(struct jambuf *log, enum_enum_names *een,
		     unsigned long table, unsigned long val);
size_t jam_enum_enum_short(struct jambuf *log, enum_enum_names *een,
			   unsigned long table, unsigned long val);

/* XXX: assumes enums are 8-bits!?! */
#define LOOSE_ENUM_OTHER 255

extern void init_constants(void);

#include "ietf_constants.h"
#include "pluto_constants.h"
#include "names_constant.h"

#endif /* _CONSTANTS_H_ */
