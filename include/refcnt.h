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

typedef struct {
	volatile unsigned count;
} refcnt_t;

/*
 * Initialize the refcnt.
 *
 * Note that ref_init(OBJ,HERE) breaks as HERE contains braces.
 */

void refcnt_init(const char *what, const void *pointer,
		 refcnt_t *refcnt, where_t where);

#define refcnt_alloc(THING, WHERE)				       \
	({							       \
		THING *t_ = alloc_bytes(sizeof(THING), (WHERE).func);  \
		refcnt_init(#THING, t_, &t_->refcnt, WHERE);	       \
		t_;						       \
	})

/* look at refcnt atomically */
unsigned refcnt_peek(refcnt_t *refcnt);

/*
 * Add a reference.
 *
 * Note that ref_add(OBJ,HERE) breaks as HERE contains braces.
 */

void refcnt_add(const char *what, const void *pointer,
		refcnt_t *refcnt, where_t where);

#define refcnt_addref(OBJ, WHERE)					\
	({								\
		if ((OBJ) == NULL) {					\
			dbg("addref "#OBJ"@NULL "PRI_WHERE"", pri_where(WHERE)); \
		} else {						\
			refcnt_add(#OBJ, (OBJ), &(OBJ)->refcnt, WHERE);	\
		}							\
		(OBJ); /* result */					\
	})

#define add_ref(OBJ)							\
	({								\
		where_t here_ = HERE;					\
		refcnt_addref((OBJ), here_);				\
	})

/*
 * Delete a reference.
 *
 * Note that ref_delete(OBJ,FREE,HERE) breaks as HERE contains braces.
 */

bool refcnt_delete(const char *what, const void *pointer,
		   refcnt_t *refcnt, where_t where) MUST_USE_RESULT;

#define refcnt_delref(OBJ, FREE, WHERE)					\
	{								\
		if (*(OBJ) == NULL) {					\
			dbg("delref "#OBJ"@NULL "PRI_WHERE"", pri_where(WHERE)); \
		} else if (refcnt_delete(#OBJ, *(OBJ), &(*(OBJ))->refcnt, \
					 WHERE)) {			\
			FREE((OBJ), WHERE);				\
			passert(*(OBJ) == NULL);			\
		} else {						\
			*(OBJ) = NULL; /* kill pointer */		\
		}							\
	}

#define delete_ref(OBJ, FREE)						\
	{								\
		where_t here_ = HERE;					\
		refcnt_delref((OBJ), FREE, here_);			\
	}

/*
 * Replace an existing reference.
 *
 * Note that ref_replace(OBJ,NEW,FREE,HERE) breaks as HERE contains
 * braces.
 */

#define refcnt_replace(OBJ, NEW, FREE, WHERE)				\
	{								\
		/* add new before deleting old */			\
		ref_add(NEW, WHERE);					\
		ref_delete((OBJ), FREE, WHERE);				\
		*(OBJ) = NEW;						\
	}

#define replace_ref(OBJ, NEW, FREE)					\
	{								\
		where_t here_ = HERE;					\
		/* add new before deleting old */			\
		refcnt_replace((OBJ), NEW, FREE, here_);		\
	}

/* for code wanting to use refcnt for normal allocs */
void dbg_alloc(const char *what, const void *pointer, where_t where);
void dbg_free(const char *what, const void *pointer, where_t where);

#endif
