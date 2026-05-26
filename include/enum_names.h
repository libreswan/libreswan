/* table structure used by enum_{short,long}() and friends.
 *
 * Note: this structure is opaque to all files that don't define
 * tables for enum_{short,long}() and friends.
 *
 * To simplify initializing
 *	en_names, en_checklen
 *	een_enum_names, een_checklen
 * use ARRAY_REF()
 */

#ifndef ENUM_NAMES_H
#define ENUM_NAMES_H

#include <stddef.h>		/* for size_t */

#include "lswcdefs.h"		/* for COUNTED_BY_PTR(), ARRAY_PTR() */

struct enum_names {
	unsigned long en_first;                 /* first value in range */
	unsigned long en_last;                  /* last value in range (inclusive) */
	size_t en_checklen;		/* for checking: elemsof(en_names) == en_last-enfirst+1 */
	const char *const *en_names COUNTED_BY_PTR(en_checklen);
	const char *const en_prefix;	/* what to remove for short name */
	const struct enum_names *en_next_range; /* descriptor of next range */
};

struct enum_enum_names {
	unsigned long een_first;		/* first value in range */
	unsigned long een_last;			/* last value in range (inclusive) */
	size_t een_checklen;	/* for checking: elemsof(een_names) == een_last-enfirst+1 */
	const struct enum_names *const *const een_enum_name COUNTED_BY_PTR(een_checklen);	/* actual table to use, subscripted by previous enum */
};

/* arrays are null terminated */

struct enum_names_check {
	const char *name;
	const struct enum_names *enum_names;
};

extern const struct enum_names_check enum_names_checklist[]; /* NULL terminated*/

struct enum_enum_names_check {
	const char *name;
	const struct enum_enum_names *enum_enum_names;
};

extern const struct enum_enum_names_check enum_enum_names_checklist[]; /* NULL terminated*/

extern void check_enum_names(const struct enum_names_check *checklist);
extern void check_enum_enum_names(const struct enum_enum_names_check *checklist);

extern void init_enum_names(void);

#endif
