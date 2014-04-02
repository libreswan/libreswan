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

#define elemsof(array) (sizeof(array) / sizeof(*(array)))       /* number of elements in an array */

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

#define NULL_FD (-1)    /* NULL file descriptor */
#define dup_any(fd) ((fd) == NULL_FD ? NULL_FD : dup(fd))
#define close_any(fd) do { if ((fd) != NULL_FD) { close(fd); (fd) = NULL_FD; \
			   } } while (0)

#include <inttypes.h>

#include <prcpucfg.h>

#ifndef BITS_PER_BYTE
# define BITS_PER_BYTE  8
#endif
#define BYTES_FOR_BITS(b)   (((b) + BITS_PER_BYTE - 1) / BITS_PER_BYTE)

#define streq(a, b) (strcmp((a), (b)) == 0)             /* clearer shorthand */
#define strcaseeq(a, b) (strcasecmp((a), (b)) == 0)     /* clearer shorthand */
#define memeq(a, b, n) (memcmp((a), (b), (n)) == 0)	/* clearer shorthand */

/* zero an object given a pointer to it.
 * Note: this won't work on an array without an explicit &
 * (it will appear to work but it will only zero the first element).
 */
#define zero(x) memset((x), '\0', sizeof(*(x)))	/* zero all bytes */

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

#define ENUM_SHOW_BUF_LEN	14	/* enough space for any unsigned 32-bit + "??" */
extern const char *enum_showb(enum_names *ed, unsigned long val, char *buf, size_t blen);

/* sometimes the prefix gets annoying */
extern const char *strip_prefix(const char *s, const char *prefix);

extern const char *enum_show(enum_names *ed, unsigned long val);        /* NOT RE-ENTRANT */

extern int enum_search(enum_names *ed, const char *string);

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
extern const char *bitnamesof(const char *const table[], lset_t val);   /* NOT RE-ENTRANT */
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

