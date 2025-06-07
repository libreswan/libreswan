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
#define strheq(a, b) hunk_heq(shunk1(a), shunk1(b))
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
extern char *add_str(char *buf, size_t size, const char *src);

/* XXX: assumes enums are 8-bits!?! */
#define LOOSE_ENUM_OTHER 255

#include "ietf_constants.h"
#include "pluto_constants.h"
#include "names_constant.h"

#endif /* _CONSTANTS_H_ */
