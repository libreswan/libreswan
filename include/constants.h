/* manifest constants
 *
 * Copyright (C) 2004       Michael Richardson <mcr@xelerance.com>
 * COpyright (C) 1997       Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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
 * RCSID $Id: constants.h,v 1.3 2004/05/29 03:06:12 mcr Exp $
 */

#ifndef _CONSTANTS_H_

/*
 * This file was split into internal contants (Openswan/pluto related),
 * and external constants (defined by IETF, etc.)
 *
 * Constants which are kernel/IPsec related are in appropriate
 * openswan / *.h files. 
 *
 */

/*
 * NOTE:For debugging purposes, constants.c has tables to map
 * numbers back to names.
 * Any changes here should be reflected there.
 */

#define elemsof(array) (sizeof(array) / sizeof(*(array)))	/* number of elements in an array */

/* Many routines return only success or failure, but wish to describe
 * the failure in a message.  We use the convention that they return
 * a NULL on success and a pointer to constant string on failure.
 * The fact that the string is a constant is limiting, but it
 * avoids storage management issues: the recipient is allowed to assume
 * that the string will live "long enough" (usually forever).
 * <openswan.h> defines err_t for this return type.
 */

typedef int bool;
#define FALSE	0
#define TRUE	1

#define NULL_FD	(-1)	/* NULL file descriptor */
#define dup_any(fd) ((fd) == NULL_FD? NULL_FD : dup(fd))
#define close_any(fd) { if ((fd) != NULL_FD) { close(fd); (fd) = NULL_FD; } }

#define BITS_PER_BYTE	8
#define BYTES_FOR_BITS(b)   (((b) + BITS_PER_BYTE - 1) / BITS_PER_BYTE)

#define streq(a, b) (strcmp((a), (b)) == 0)	/* clearer shorthand */
#define strcaseeq(a, b) (strcasecmp((a), (b)) == 0)	/* clearer shorthand */

/* set type with room for at least 64 elements for ALG opts (was 32 in stock FS) */

typedef unsigned long long lset_t;
#define LEMPTY 0ULL
#define LELEM(opt) (1ULL << (opt))
#define LRANGE(lwb, upb) LRANGES(LELEM(lwb), LELEM(upb))
#define LRANGES(first, last) (last - first + last)
#define LHAS(set, elem)  ((LELEM(elem) & (set)) != LEMPTY)
#define LIN(subset, set)  (((subset) & (set)) == (subset))
#define LDISJOINT(a, b)  (((a) & (b)) == LEMPTY)

/* Routines to check and display values.
 *
 * An enum_names describes an enumeration.
 * enum_name() returns the name of an enum value, or NULL if invalid.
 * enum_show() is like enum_name, except it formats a numeric representation
 *    for any invalid value (in a static area!)
 *
 * bitnames() formats a display of a set of named bits (in a static area)
 */

typedef const struct enum_names enum_names;

extern const char *enum_name(enum_names *ed, unsigned long val);
extern const char *enum_show(enum_names *ed, unsigned long val);
extern int enum_search(enum_names *ed, const char *string);

extern bool testset(const char *const table[], lset_t val);
extern const char *bitnamesof(const char *const table[], lset_t val);
extern const char *bitnamesofb(const char *const table[]
			       , lset_t val
			       , char *buf, size_t blen);

/*
 * The sparser_name should be transformed into keyword_enum_value
 *
 * keyword_enum_value is used by starter()
 *
 */

#define LOOSE_ENUM_OTHER 255

struct keyword_enum_value {
    const unsigned char *name;
    unsigned int value;
};

struct keyword_enum_values {
    struct keyword_enum_value *values;
    size_t                     valuesize;
};

extern const char *keyword_name(struct keyword_enum_values *kevs, unsigned int value);

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
extern const char *sparse_val_show(sparse_names sd, unsigned long val);
extern const char sparse_end[];

#define FULL_INET_ADDRESS_SIZE    6

extern void init_constants(void);

#include "ietf_constants.h"
#include "pluto_constants.h"

#define _CONSTANTS_H_
#endif /* _CONSTANTS_H_ */


