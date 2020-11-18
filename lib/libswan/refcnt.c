/* reference counting, for libreswan
 *
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
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
 */

#include "refcnt.h"

static void dbg_ref(const char *what, const void *pointer, where_t where,
		    int old_count, int new_count, const char *why)
{
	if (DBGP(DBG_REFCNT)) {
		DBG_log("%sref %s@%p(%u->%u) "PRI_WHERE"",
			why, what, pointer, old_count, new_count,
			pri_where(where));
	}
}

#define DEBUG_LOG(OLD_COUNT, WHY)				\
	dbg_ref(what, pointer, where, OLD_COUNT, refcnt->count, WHY)

/*
 * So existing code can use the refcnt tracer.
 */

void dbg_alloc(const char *what, const void *pointer, where_t where)
{
	dbg_ref(what, pointer, where, 0, 1, "new");
}

void dbg_free(const char *what, const void *pointer, where_t where)
{
	dbg_ref(what, pointer, where, 1, 0, "del");
}

/* -- */

void refcnt_init(const char *what, const void *pointer,
		 refcnt_t *refcnt, where_t where)
{
	/* on main thread */
	if (refcnt->count != 0) {
		log_pexpect(where, "refcnt for %s@%p should have been 0 initialized",
			    what, pointer);
	}
	unsigned old = refcnt->count++;
	DEBUG_LOG(old, "new");
}

void refcnt_add(const char *what, const void *pointer,
		refcnt_t *refcnt, where_t where)
{
	/* on main thread */
	if (refcnt->count == 0) {
		log_pexpect(where, "refcnt for %s@%p should have been non-0",
			    what, pointer);
	}
	unsigned old = refcnt->count++;
	DEBUG_LOG(old, "add");
}

bool refcnt_delete(const char *what, const void *pointer,
		   refcnt_t *refcnt, where_t where)
{
	/* on main thread */
	unsigned old;
	if (refcnt->count == 0) {
		log_pexpect(where, "refcnt for %s@%p should have been non-0",
			    what, pointer);
		old = 0;
	} else {
		old = refcnt->count--;
	}
	DEBUG_LOG(old, "del");
	return refcnt->count == 0;
}
