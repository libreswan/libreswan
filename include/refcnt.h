/* reference counting macros
 *
 * Copyright (C) 2019 Andrew Cagney
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

#ifndef REFCNT_H
#define REFCNT_H

#include <stdbool.h>

#include "lswlog.h"		/* for pexpect(), for dbg() */
#include "lswcdefs.h"		/* for MUST_USE_RESULT */
#include "where.h"

struct refcnt_base {
	const char *what;
	void (*free)(void *object, const struct logger *logger, where_t where);
};

typedef struct refcnt {
	volatile unsigned count;
	const struct refcnt_base *base;
} refcnt_t;

/*
 * Initialize the refcnt.
 *
 * Note: the over-allocated memory is _NOT_ aligned.
 */

void refcnt_init(const void *pointer, struct refcnt *refcnt,
		 const struct refcnt_base *base, where_t where);

#define refcnt_overalloc(THING, EXTRA, FREE, WHERE)		       \
	({							       \
		static const struct refcnt_base b_ = {		       \
			.what = #THING,				       \
			.free = FREE,				       \
		};						       \
		THING *t_ = alloc_bytes(sizeof(THING) + (EXTRA), b_.what); \
		refcnt_init(t_, &t_->refcnt, &b_, WHERE);	       \
		t_;						       \
	})

#define refcnt_alloc(THING, FREE, WHERE)			       \
	refcnt_overalloc(THING, /*extra*/0, FREE, WHERE)

/* look at refcnt atomically */
unsigned refcnt_peek(const refcnt_t *refcnt);

/*
 * Add a reference.
 */

void refcnt_addref_where(const char *what, const void *pointer,
			 refcnt_t *refcnt, where_t where);

#define addref_where(OBJ, WHERE)					\
	({								\
		typeof(OBJ) o_ = OBJ; /* evaluate once */		\
		refcnt_addref_where(#OBJ, o_, o_ == NULL ? NULL : &o_->refcnt, WHERE); \
		o_; /* result */					\
	})

/*
 * Delete a reference.
 */

void refcnt_delref_where(const char *what, void *pointer,
			 struct refcnt *refcnt,
			 const struct logger *logger, where_t where);

#define delref_where(OBJ, LOGGER, WHERE)				\
	{								\
		typeof(OBJ) o_ = OBJ;					\
		refcnt_t *r_ = (*o_ == NULL ? NULL : &(*o_)->refcnt);	\
		refcnt_delref_where(#OBJ, *o_, r_, LOGGER, WHERE);	\
		*o_ = NULL; /*kill pointer */				\
	}

/* for code wanting to use refcnt for normal allocs */
void dbg_alloc(const char *what, const void *pointer, where_t where);
void dbg_free(const char *what, const void *pointer, where_t where);

#endif
