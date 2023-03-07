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

#include <pthread.h>

#include "refcnt.h"

static pthread_mutex_t refcnt_mutex = PTHREAD_MUTEX_INITIALIZER;

static void dbg_ref(const char *why, const char *what,
		    const void *pointer, where_t where,
		    int old_count, int new_count)
{
	if (DBGP(DBG_REFCNT)) {
		DBG_log("%sref %s@%p(%u->%u) "PRI_WHERE"",
			why, what, pointer, old_count, new_count,
			pri_where(where));
	}
}

#define DEBUG_LOG(WHY)						\
	dbg_ref(WHY, refcnt->base->what, pointer, where, old, new)

/*
 * So existing code can use the refcnt tracer.
 */

void dbg_alloc(const char *what, const void *pointer, where_t where)
{
	dbg_ref("new", what, pointer, where, 0, 1);
}

void dbg_free(const char *what, const void *pointer, where_t where)
{
	dbg_ref("del", what, pointer, where, 1, 0);
}

/* -- */

void refcnt_init(const void *pointer, struct refcnt *refcnt,
		 const struct refcnt_base *base,
		 const struct where *where)
{
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
		llog_pexpect(&global_logger, where, "refcnt for %s@%p should have been 0 initialized",
			    base->what, pointer);
	}
	DEBUG_LOG("new");
}

void refcnt_addref_where(const char *what, const void *pointer,
			 refcnt_t *refcnt, where_t where)
{
	if (pointer == NULL) {
		dbg("addref %s@NULL "PRI_WHERE"", what, pri_where(where));
		return;
	}

	unsigned old, new;
	pthread_mutex_lock(&refcnt_mutex);
	{
		old = refcnt->count;
		refcnt->count++;
		new = refcnt->count;
	}
	pthread_mutex_unlock(&refcnt_mutex);
	if (old == 0) {
		llog_pexpect(&global_logger, where, "refcnt for %s@%p should have been non-0",
			    what, pointer);
	}
	DEBUG_LOG("add");
}

/*
 * look at refcnt atomically
 * This is a bit slow but it is used rarely.
 */
unsigned refcnt_peek(const refcnt_t *refcnt)
{
	unsigned val;
	pthread_mutex_lock(&refcnt_mutex);
	{
		val = refcnt->count;
	}
	pthread_mutex_unlock(&refcnt_mutex);
	return val;
}

void *refcnt_delref_where(const char *what, void *pointer,
			  struct refcnt *refcnt,
			  const struct logger *logger,
			  const struct where *where)
{
	if (pointer == NULL) {
		ldbg(logger, "delref %s@NULL "PRI_WHERE"", what, pri_where(where));
		return NULL;
	}

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
		llog_pexpect(logger, where, "refcnt for %s@%p should have been non-0",
			     what, pointer);
	}
	DEBUG_LOG("del");
	if (new == 0) {
		return pointer;
	}
	return NULL;
}
