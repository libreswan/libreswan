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
#include <stdlib.h>		/* for size_t */

#include "lswcdefs.h"		/* for MUST_USE_RESULT et.al. */
#include "where.h"

struct jambuf;
struct logger;

typedef	void (refcnt_discard_content_fn)(void *pointer,
					 const struct logger *logger,
					 where_t where);
typedef size_t (refcnt_jam_fn)(struct jambuf *buf, const void *pointer);

struct refcnt_base {
	const char *what;
	refcnt_discard_content_fn *discard_content;
	refcnt_jam_fn *jam;
};

typedef struct refcnt {
	volatile unsigned count;
	const struct refcnt_base *base;
} refcnt_t;

/*
 * Allocate the structure (plus extra) initializing the refcnt.
 *
 * On return the object has a reference count of one and all other
 * fields are zero.
 *
 * Note: any over-allocated memory is _NOT_ aligned.
 */

void refcnt_init(const void *pointer,
		 struct refcnt *refcnt,
		 const struct refcnt_base *base,
		 const struct logger *owner,
		 where_t where)
	NONNULL(1,2,3,4,5);

#define refcnt_overalloc(THING, EXTRA, OWNER, WHERE)			\
	({								\
		static const struct refcnt_base b_ = {			\
			.what = #THING,					\
		};							\
		THING *t_ = overalloc_thing(THING, EXTRA);		\
		refcnt_init(t_, &t_->refcnt, &b_, OWNER, WHERE);	\
		t_;							\
	})

#define refcnt_alloc(THING, OWNER, WHERE)				\
	refcnt_overalloc(THING, /*extra*/0, OWNER, WHERE)

/* look at refcnt atomically */

unsigned refcnt_peek_where(const refcnt_t *refcnt,
			   const struct logger *owner,
			   where_t where)
	NONNULL(1,2,3);

#define refcnt_peek(OBJ, OWNER)						\
	({								\
		typeof(OBJ) o_ = OBJ; /* evaluate once */		\
		(o_ == NULL ? 0 : /* a NULL pointer has no references */ \
		 refcnt_peek_where(&o_->refcnt,				\
				   OWNER,				\
				   HERE));				\
	})

/*
 * Add a reference.
 */

void refcnt_addref_where(const char *what,
			 refcnt_t *refcnt,
			 const struct logger *owner,
			 where_t where)
	NONNULL(1,2,3,4);

#define refcnt_addref(OBJ, OWNER, WHERE)			\
	({							\
		typeof(OBJ) o_ = OBJ; /* evaluate once */	\
		if (o_ != NULL) {				\
			refcnt_addref_where(#OBJ,		\
					    &o_->refcnt,	\
					    OWNER, WHERE);	\
		}						\
		o_; /* result */				\
	})

/*
 * Delete a reference.
 *
 * Returns a non-NULL pointer to the object when it is the last
 * reference and needs to be pfree()ed.
 */

void *refcnt_delref_where(const char *what,
			  struct refcnt *refcnt,
			  const struct logger *owner,
			  where_t where)
	MUST_USE_RESULT
	NONNULL(1,2,3,4);

#define refcnt_delref(OBJP, OWNER, WHERE)				\
	({								\
		typeof(OBJP) op_ = OBJP;				\
		typeof(*OBJP) o_ = *op_;				\
		if (o_ != NULL) {					\
			o_ = refcnt_delref_where(#OBJP,			\
						 &o_->refcnt,		\
						 OWNER, WHERE);		\
		}							\
		*op_ = NULL; /* always kill pointer */			\
		o_; /* NULL or last OBJ */				\
	})

/*
 * For code wanting to use refcnt checks but with normal allocs; or
 * internal reference counting (e.g., NSS).
 */

void ldbg_newref_where(const struct logger *owner, const char *what,
		       const void *pointer, where_t where)
	NONNULL(1,2,4);

void ldbg_addref_where(const struct logger *owner, const char *what,
		       const void *pointer, where_t where)
	NONNULL(1,2,4);

void ldbg_delref_where(const struct logger *owner, const char *what,
		       const void *pointer, where_t where)
	NONNULL(1,2,4);

#define ldbg_newref(OWNER, POINTER) ldbg_newref_where(OWNER, #POINTER, POINTER, HERE)
#define ldbg_addref(OWNER, POINTER) ldbg_addref_where(OWNER, #POINTER, POINTER, HERE)
#define ldbg_delref(OWNER, POINTER) ldbg_delref_where(OWNER, #POINTER, POINTER, HERE)

#define vdbg_newref(POINTER) ldbg_newref_where(verbose.logger, #POINTER, POINTER, HERE)
#define vdbg_addref(POINTER) ldbg_addref_where(verbose.logger, #POINTER, POINTER, HERE)
#define vdbg_delref(POINTER) ldbg_delref_where(verbose.logger, #POINTER, POINTER, HERE)

#endif
