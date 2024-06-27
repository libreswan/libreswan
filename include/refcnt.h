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

#include "lswcdefs.h"		/* for MUST_USE_RESULT */
#include "where.h"

struct logger;

struct refcnt_base {
	const char *what;
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

void refcnt_init(const void *pointer, struct refcnt *refcnt,
		 const struct refcnt_base *base, where_t where);

#define refcnt_overalloc(THING, EXTRA, WHERE)			       \
	({							       \
		static const struct refcnt_base b_ = {		       \
			.what = #THING,				       \
		};						       \
		THING *t_ = alloc_bytes(sizeof(THING) + (EXTRA), b_.what); \
		refcnt_init(t_, &t_->refcnt, &b_, WHERE);	       \
		t_;						       \
	})

#define refcnt_alloc(THING, WHERE)			\
	refcnt_overalloc(THING, /*extra*/0, WHERE)

/* look at refcnt atomically */

unsigned refcnt_peek_where(const void *pointer,
			   const refcnt_t *refcnt,
			   struct logger *owner,
			   where_t where);
#define refcnt_peek(OBJ, OWNER)						\
	({								\
		typeof(OBJ) o_ = OBJ; /* evaluate once */		\
		(o_ == NULL ? 0 : /* a NULL pointer has no references */ \
		 refcnt_peek_where(o_, &o_->refcnt, OWNER, HERE));	\
	})

/*
 * Add a reference.
 */

void refcnt_addref_where(const char *what, const void *pointer,
			 refcnt_t *refcnt,
			 const struct logger *logger,
			 const struct logger *new_owner,
			 where_t where);

/* old */

#define addref_where(OBJ, WHERE)					\
	({								\
		typeof(OBJ) o_ = OBJ; /* evaluate once */		\
		if (o_ != NULL) {					\
			refcnt_addref_where(#OBJ, o_,			\
					    &o_->refcnt,		\
					    NULL, NULL, WHERE);		\
		}							\
		o_; /* result */					\
	})

/* new */

#define laddref_where(OBJ, OWNER, WHERE)				\
	({								\
		typeof(OBJ) o_ = OBJ; /* evaluate once */		\
		if (o_ != NULL) {					\
			refcnt_addref_where(#OBJ, o_,			\
					    &o_->refcnt,		\
					    o_->logger,			\
					    OWNER, WHERE);		\
		}							\
		o_; /* result */					\
	})

/*
 * Delete a reference.
 *
 * Returns a non-NULL pointer to the object when it is the last
 * reference and needs to be pfree()ed.
 */

void *refcnt_delref_where(const char *what, void *pointer,
			  struct refcnt *refcnt,
			  const struct logger *logger,
			  const struct logger *owner,
			  where_t where) MUST_USE_RESULT;

#define delref_where(OBJP, LOGGER, WHERE)				\
	({								\
		typeof(OBJP) op_ = OBJP;				\
		typeof(*OBJP) o_ = *op_;				\
		*op_ = NULL; /* always kill pointer; and early */	\
		if (o_ != NULL) {					\
			o_ = refcnt_delref_where(#OBJP, o_,		\
						 &o_->refcnt,		\
						 LOGGER, NULL, WHERE);	\
		}							\
		o_; /* NULL or last OBJ */				\
	})

#define ldelref_where(OBJP, OWNER, WHERE)				\
	({								\
		typeof(OBJP) op_ = OBJP;				\
		typeof(*OBJP) o_ = *op_;				\
		*op_ = NULL; /* always kill pointer; and early */	\
		if (o_ != NULL) {					\
			o_ = refcnt_delref_where(#OBJP, o_,		\
						 &o_->refcnt,		\
						 o_->logger,		\
						 OWNER, WHERE);		\
		}							\
		o_; /* NULL or last OBJ */				\
	})

/*
 * For code wanting to use refcnt checks but with normal allocs.
 */

void ldbg_alloc(const struct logger *logger, const char *what, const void *pointer, where_t where);
void ldbg_free(const struct logger *logger, const char *what, const void *pointer, where_t where);

void ldbg_addref_where(const struct logger *logger, const char *what, const void *pointer, where_t where);
void ldbg_delref_where(const struct logger *logger, const char *what, const void *pointer, where_t where);

void dbg_alloc(const char *what, const void *pointer, where_t where);
void dbg_free(const char *what, const void *pointer, where_t where);

#endif
