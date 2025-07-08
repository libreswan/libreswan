/* sys/cdefs.h like compiler macros, for libreswan
 *
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 */

#ifndef LSWCDEFS_H
#define LSWCDEFS_H

#define swap(L,R)				\
	{					\
		typeof(L) tmp_ = L;		\
		L = R;				\
		R = tmp_;			\
	}

/*
 * elemsof() returns the unsigned size_t.
 */
#define elemsof(array) (sizeof(array) / sizeof(*(array)))

/*
 * NOTE: this is by nature a scary macro because it is used to
 * initialized two fields.
 *
 * This has a hacky advantage: if you don't wish to count the last
 * element of the array (say, because it is a NULL there for
 * bitnamesof), just use ARRAY_REF()-1!
 */
#define ARRAY_REF(p) (p), elemsof(p)

/* GCC magic for use in function definitions! */
#ifdef GCC_LINT
# define NEVER_RETURNS		__attribute__ ((noreturn))
# define UNUSED			__attribute__ ((unused))
# define MUST_USE_RESULT	__attribute__ ((warn_unused_result))
# define NONNULL(ARG, ...)	__attribute__ ((nonnull(ARG, ##__VA_ARGS__)))
#else
# define NEVER_RETURNS		/* ignore */
# define UNUSED			/* ignore */
# define MUST_USE_RESULT	/* ignore */
# define NONNULL(ARG, ...)	/* ignore */
#endif

#ifdef COMPILER_HAS_NO_PRINTF_LIKE
# define PRINTF_LIKE(n)		/* ignore */
# define VPRINTF_LIKE(n)	/* ignore */
# define STRFTIME_LIKE(n)	/* ignore */
#else
# define PRINTF_LIKE(n)		__attribute__ ((format(printf, n, n + 1)))
# define VPRINTF_LIKE(n)	__attribute__ ((format(printf, n, 0)))
# define STRFTIME_LIKE(n)	__attribute__ ((format(strftime, n, 0)))
#endif

/*
 * A macro to iterate over a list-like structure.
 */

#define FOR_EACH_ITEM(ENTRY, LIST)					\
	for (typeof((LIST)->list[0]) *ENTRY =				\
		     (LIST) != NULL ? (LIST)->list : NULL;		\
	     ENTRY != NULL && ENTRY < (LIST)->list + (LIST)->len;	\
	     ENTRY++)

#define pfree_list(LIST) {			\
		typeof(LIST) list_ = LIST;	\
		pfreeany(list_->list);		\
		list_->len = 0;			\
	}

/* Remember, THING 1 and THING 2 are inseparable */
#define FOR_EACH_THING(THING, THING1, THING2, ...)			\
	for (typeof(THING1) things_[] = { THING1, THING2, ##__VA_ARGS__ }, \
		     *thingp_ = things_, THING;				\
	     thingp_ < things_ + elemsof(things_) ? (THING = *thingp_, true) : false; \
	     thingp_++)

#define FOR_EACH_ELEMENT(THING, ARRAY)			\
	for (typeof(&(ARRAY)[0]) THING = (ARRAY);	\
	     THING < (ARRAY) + elemsof(ARRAY);		\
	     THING++)

#define FOR_EACH_ELEMENT_FROM_1(THING, ARRAY)		\
	for (typeof(&(ARRAY)[1]) THING = &(ARRAY)[1];	\
	     THING < (ARRAY) + elemsof(ARRAY);		\
	     THING++)

/*
 * A macro to discard the const portion of a variable to avoid
 * otherwise unavoidable -Wcast-qual warnings.  USE WITH CAUTION and
 * only when you know it's safe to discard the const.
 */
#define DISCARD_CONST(VARTYPE, VARNAME)					\
	({								\
		const VARTYPE tmp = (VARNAME);				\
		(VARTYPE)tmp;						\
	})

#define is_set(POINTER_TO_THING) ((POINTER_TO_THING) != NULL && (POINTER_TO_THING)->is_set)
#define is_unset(POINTER_TO_THING) (!is_set(POINTER_TO_THING))

#endif
