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
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#ifndef _CONSTANTS_H_

/*
 * This file was split into internal contants (Libreswan/pluto related),
 * and external constants (defined by IETF, etc.)
 *
 * Constants which are kernel/IPsec related are in appropriate
 * libreswan / *.h files.
 *
 */

/*
 * NOTE:For debugging purposes, constants.c has tables to map
 * numbers back to names.
 * Any changes here should be reflected there.
 */

#define elemsof(array) (sizeof(array) / sizeof(*(array)))	/* number of elements in an array */


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

/* Many routines return only success or failure, but wish to describe
 * the failure in a message.  We use the convention that they return
 * a NULL on success and a pointer to constant string on failure.
 * The fact that the string is a constant is limiting, but it
 * avoids storage management issues: the recipient is allowed to assume
 * that the string will live "long enough" (usually forever).
 * <libreswan.h> defines err_t for this return type.
 */

/* you'd think this should be builtin to compiler... */
#ifndef TRUE
#  define TRUE 1
#  ifndef LIBRESWAN_COCOA_APP
typedef int bool;
#  endif
#endif

#ifndef FALSE
#  define FALSE 0
#endif

#define NULL_FD (-1)	/* NULL file descriptor */
#define dup_any(fd)  ((fd) == NULL_FD ? NULL_FD : dup((fd)))
#define close_any(fd)  { if ((fd) != NULL_FD) { close(fd); (fd) = NULL_FD; } }

#include <inttypes.h>

#include <prcpucfg.h>	/* from nspr4 devel */

#ifndef BITS_PER_BYTE
# define BITS_PER_BYTE  8
#endif
#define BYTES_FOR_BITS(b)   (((b) + BITS_PER_BYTE - 1) / BITS_PER_BYTE)

/* clearer shorthand for *cmp functions */
#define streq(a, b) (strcmp((a), (b)) == 0)
#define strneq(a, b, c) (strncmp((a), (b), (c)) == 0)
#define startswith(a, b) strneq((a), (b), sizeof(b)-1)	/* b must be literal! */
#define eat(a, b) (startswith((a), (b))? ((a) += sizeof(b) - 1), TRUE : FALSE)
#define strcaseeq(a, b) (strcasecmp((a), (b)) == 0)
#define strncaseeq(a, b, n) (strncasecmp((a), (b), (n)) == 0)
#define memeq(a, b, n) (memcmp((a), (b), (n)) == 0)


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
 * without futher initialization will not accidentally have a
 * plausible value (eg. zero, or the previous value, or some
 * secret that might be leaked).
 */

#define messupn(x, n) memset((x), 0xFB, (n))	/* set n bytes to wrong value */
#define messup(x) messupn((x), sizeof(*(x)))	/* set all bytes to wrong value */

/* routines to copy C strings to fixed-length buffers */
extern char *jam_str(char *dest, size_t size, const char *src);
extern char *add_str(char *buf, size_t size, char *hint, const char *src);

/* set type with room for at least 64 elements for ALG opts
 * (was 32 in stock FS)
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

/* Routines to check and display values.
 *
 * WARNING: Some of these routines are not re-entrant because
 * they use a static buffer.
 * When a non-re-entrant version is called, the buffer holding the result
 * may be overwritten by the next call.  Among other things, this means that
 * at most one call should appear in the argument list to a function call
 * (e.g. a call to a log function).
 */

/* Printing Enums:
 *
 * An enum_names table describes an enumeration (a correspondence
 * between integer values and names).
 *
 * enum_name() returns the name of an enum value, or NULL if unnamed.
 * enum_show() is like enum_name, except it formats a numeric representation
 *    for any unnamed value (in a static area -- NOT RE-ENTRANT)
 * enum_showb() is like enum_show() but uses a caller-supplied buffer
 *    for any unnamed value and thus is re-entrant.
 */

/* Printing lset_t values:
 *
 * bitnamesof() formats a display of a set of named bits (in a static area -- NOT RE-ENTRANT)
 * bitnamesofb() formats into a caller-supplied buffer (re-entrant)
 */

typedef const struct enum_names enum_names;

extern const char *enum_name(enum_names *ed, unsigned long val);

/* caller-allocated buffer for enum_showb */
struct esb_buf {
	/* enough space for any unsigned 32-bit + "??" */
	char buf[14];
};
extern const char *enum_showb(enum_names *ed, unsigned long val, struct esb_buf *);

extern const char *enum_show(enum_names *ed, unsigned long val);	/* NOT RE-ENTRANT */

/* sometimes the prefix gets annoying */
extern const char *strip_prefix(const char *s, const char *prefix);

extern int enum_search(enum_names *ed, const char *string);

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
 * enum_enum_showb() returns TABLE VAL's enum or %ld using BUF.
 */

typedef const struct enum_enum_names enum_enum_names;

enum_names *enum_enum_table(enum_enum_names *e, unsigned long table);
const char *enum_enum_name(enum_enum_names *e, unsigned long table,
			   unsigned long val);
const char *enum_enum_showb(enum_enum_names *e, unsigned long table,
			    unsigned long val, struct esb_buf *buf);


/* Printing lset_t values:
 *
 * These routines require a name table which is a NULL-terminated
 * sequence of strings.  That means that each bit in the set must
 * have a name.
 *
 * bitnamesof() formats a display of a set of named bits (in a static area -- NOT RE-ENTRANT)
 * bitnamesofb() formats into a caller-supplied buffer (re-entrant)
 */
extern bool testset(const char *const table[], lset_t val);
extern const char *bitnamesof(const char *const table[], lset_t val);	/* NOT RE-ENTRANT */
extern const char *bitnamesofb(const char *const table[],
			       lset_t val,
			       char *buf, size_t blen);

/*
 * The sparser_name should be transformed into keyword_enum_value
 *
 * keyword_enum_value is used by starter()
 *
 */

#define LOOSE_ENUM_OTHER 255

struct keyword_enum_value {
	const char *name;
	unsigned int value;
};

struct keyword_enum_values {
	const struct keyword_enum_value *values;
	size_t valuesize;
};

extern struct keyword_enum_values kw_host_list;

extern const char *keyword_name(struct keyword_enum_values *kevs,
				unsigned int value);

/* sparse_names is much like enum_names, except values are
 * not known to be contiguous or ordered.
 * The array of names is ended with one with the name sparse_end
 * (this avoids having to reserve a value to signify the end).
 * Often appropriate for enums defined by others.
 */
struct sparse_name {
	unsigned long val;
	const char *const name;
};

typedef const struct sparse_name sparse_names[];

extern const char *sparse_name(sparse_names sd, unsigned long val);
extern const char *sparse_val_show(sparse_names sd, unsigned long val); /* uses static buffer -- NOT RE-ENTRANT */
extern const char sparse_end[];

#define FULL_INET_ADDRESS_SIZE    6

extern void init_constants(void);

#include "ietf_constants.h"
#include "pluto_constants.h"
#include "names_constant.h"

#define _CONSTANTS_H_
#endif /* _CONSTANTS_H_ */
