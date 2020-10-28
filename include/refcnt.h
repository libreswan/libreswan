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
	unsigned count;
} refcnt_t;

/*
 * Initialize the refcnt.
 *
 * Note that ref_init(O,HERE) breaks as HERE contains braces.
 */

void refcnt_init(const char *what, const void *pointer,
		 refcnt_t *refcnt, where_t where);

#define refcnt_alloc(THING, WHERE)				       \
	({							       \
		THING *t_ = alloc_bytes(sizeof(THING), (WHERE).func);  \
		refcnt_init(#THING, t_, &t_->refcnt, WHERE);	       \
		t_;						       \
	})

/*
 * Add a reference.
 *
 * Note that ref_add(O,HERE) breaks as HERE contains braces.
 */

void refcnt_add(const char *what, const void *pointer,
		refcnt_t *refcnt, where_t where);

#define refcnt_addref(O, WHERE)						\
	({								\
		if ((O) == NULL) {					\
			dbg("addref "#O"@NULL "PRI_WHERE"", pri_where(WHERE)); \
		} else {						\
			refcnt_add(#O, O, &(O)->refcnt, WHERE);		\
		}							\
		(O); /* result */					\
	})

#define add_ref(O)							\
	({								\
		where_t here_ = HERE;					\
		refcnt_addref(O, here_);				\
	})

/*
 * Delete a reference.
 *
 * Note that ref_delete(O,FREE,HERE) breaks as HERE contains braces.
 */

bool refcnt_delete(const char *what, const void *pointer,
		   refcnt_t *refcnt, where_t where) MUST_USE_RESULT;

#define refcnt_delref(O, FREE, WHERE)					\
	{								\
		if (*(O) == NULL) {					\
			dbg("delref "#O"@NULL "PRI_WHERE"", pri_where(WHERE)); \
		} else if (refcnt_delete(#O, *(O), &(*(O))->refcnt,	\
					 WHERE)) {			\
			FREE(O, WHERE);					\
			passert(*(O) == NULL);				\
		} else {						\
			*(O) = NULL; /* kill pointer */			\
		}							\
	}

#define delete_ref(O, FREE)						\
	{								\
		where_t here_ = HERE;					\
		refcnt_delref(O, FREE, here_);				\
	}

/*
 * Replace an existing reference.
 *
 * Note that ref_replace(O,NEW,FREE,HERE) breaks as HERE contains
 * braces.
 */

#define refcnt_replace(O, NEW, FREE, WHERE)				\
	{								\
		/* add new before deleting old */			\
		ref_add(NEW, WHERE);					\
		ref_delete(O, FREE, WHERE);				\
		*(O) = NEW;						\
	}

#define replace_ref(O, NEW, FREE)					\
	{								\
		where_t here_ = HERE;					\
		/* add new before deleting old */			\
		refcnt_replace(O, NEW, FREE, here_);			\
	}

/* for code wanting to use refcnt for normal allocs */
void dbg_alloc(const char *what, const void *pointer, where_t where);
void dbg_free(const char *what, const void *pointer, where_t where);

#endif
