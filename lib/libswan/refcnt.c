/* reference counting, for libreswan
 *
 * Copyright (C) 2015-2025  Andrew Cagney
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

#include <pthread.h>

#include "refcnt.h"
#include "lswlog.h"		/* for DBG*() et.al. */

static pthread_mutex_t refcnt_mutex = PTHREAD_MUTEX_INITIALIZER;

NONNULL(1,2,3,4,5)
static void ldbg_ref(const struct logger *logger,
		     const struct logger *owner,
		     const char *why,
		     const char *what,
		     const void *pointer,
		     where_t where,
		     int old_count, int new_count)
{
	if (LDBGP(DBG_REFCNT, owner)) {
		LLOG_JAMBUF(DEBUG_STREAM, owner, buf) {
			jam_string(buf, why);
			jam_string(buf, " ");
			jam_string(buf, what);
			if (old_count == new_count) {
				jam(buf, "%s[%p](%u)", what, pointer, new_count);
			} else {
				jam(buf, " %s@%p(%u->%u)", what, pointer, old_count, new_count);
			}
			if (logger != &global_logger) {
				jam_string(buf, " ");
				jam_logger_prefix(buf, logger);
			}
			jam_string(buf, " ");
			jam_where(buf, where);
		}
	}
}

#define LDBG_REF(WHY)						\
	ldbg_ref(logger, owner, WHY, refcnt->base->what, refcnt, where, old, new)

/*
 * So existing code can use the refcnt tracer.
 */

void ldbg_newref_where(const struct logger *logger, const char *what,
		       const void *pointer, where_t where)
{
	if (LDBGP(DBG_REFCNT, logger)) {
		LDBG_log(logger, "newref %s@%p "PRI_WHERE,
			 what, pointer, pri_where(where));
	}
}

void ldbg_addref_where(const struct logger *logger, const char *what,
		       const void *pointer, where_t where)
{
	if (LDBGP(DBG_REFCNT, logger)) {
		LDBG_log(logger, "addref %s@%p "PRI_WHERE,
			 what, pointer, pri_where(where));
	}
}

void ldbg_delref_where(const struct logger *logger, const char *what,
		       const void *pointer, where_t where)
{
	if (LDBGP(DBG_REFCNT, logger)) {
		LDBG_log(logger, "delref %s@%p "PRI_WHERE,
			 what, pointer, pri_where(where));
	}
}

/* -- */

void refcnt_init(const void *pointer,
		 struct refcnt *refcnt,
		 const struct refcnt_base *base,
		 const struct logger *owner,
		 const struct where *where)
{
	const struct logger *logger = &global_logger;

	if (refcnt != pointer) {
		llog_passert(owner, where,
			     "%s() %s@%p should have been at the start of %p",
			     __func__, base->what, refcnt, pointer);
	}

	unsigned old, new;
	pthread_mutex_lock(&refcnt_mutex);
	{
		old = refcnt->count;
		refcnt->count++;
		refcnt->base = base;
		new = refcnt->count;
	}
	pthread_mutex_unlock(&refcnt_mutex);

	if (old != 0 || new != 1) {
		llog_passert(owner, where,
			     "%s() %s@%p should have been 0 initialized",
			     __func__, base->what, pointer);
	}

	LDBG_REF("newref");
}

void refcnt_addref_where(const char *what,
			 refcnt_t *refcnt,
			 const struct logger *logger,
			 const struct logger *owner,
			 where_t where)
{
	unsigned old, new;
	pthread_mutex_lock(&refcnt_mutex);
	{
		old = refcnt->count;
		refcnt->count++;
		new = refcnt->count;
	}
	pthread_mutex_unlock(&refcnt_mutex);

	if (old == 0) {
		llog_passert(logger, where,
			     "%s() refcnt for %s@%p should have been non-0",
			     __func__, what, refcnt);
	}

	LDBG_REF("addref");
}

/*
 * Look at refcnt atomically
 *
 * This is a bit slow but it is used rarely.
 */
unsigned refcnt_peek_where(const refcnt_t *refcnt,
			   const struct logger *logger,
			   const struct logger *owner,
			   where_t where)
{
	unsigned old, new;
	pthread_mutex_lock(&refcnt_mutex);
	{
		old = new = refcnt->count;
	}
	pthread_mutex_unlock(&refcnt_mutex);
	LDBG_REF("peek");
	return old;
}

void *refcnt_delref_where(const char *what,
			  struct refcnt *refcnt,
			  const struct logger *logger,
			  const struct logger *owner,
			  const struct where *where)
{
	/* on main thread */
	unsigned old, new;
	pthread_mutex_lock(&refcnt_mutex);
	{
		old = refcnt->count;
		if (old > 0) {
			refcnt->count--;
		}
		new = refcnt->count;
	}
	pthread_mutex_unlock(&refcnt_mutex);

	if (old == 0) {
		llog_passert(logger, where,
			     "%s() refcnt for %s@%p should have been non-0",
			     __func__, what, refcnt);
	}

	LDBG_REF("delref");

	if (new == 0) {
		return refcnt;
	}

	return NULL;
}
