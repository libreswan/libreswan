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
#include "lswlog.h"		/* for DBG*() et.al. */

static pthread_mutex_t refcnt_mutex = PTHREAD_MUTEX_INITIALIZER;

static void ldbg_ref(const struct logger *logger,
		     const struct logger *owner,
		     const char *why, const char *what,
		     const void *pointer, where_t where,
		     int old_count, int new_count)
{
	if (DBGP(DBG_REFCNT)) {
		LLOG_JAMBUF(DEBUG_STREAM, &global_logger, buf) {
			if (logger == NULL) {
				jam_string(buf, what);
				jam_string(buf, ": ");
			} else {
				jam_logger_prefix(buf, logger);
			}
			jam(buf, "%sref @%p(%u->%u)",
			    why, pointer, old_count, new_count);
			if (owner != NULL) {
				jam_string(buf, " ");
				jam_logger_prefix(buf, owner);
			}
			jam_string(buf, " ");
			jam_where(buf, where);
		}
	}
}

#define LDBG_REF(WHY)						\
	ldbg_ref(logger, owner, WHY, refcnt->base->what, pointer, where, old, new)

/*
 * So existing code can use the refcnt tracer.
 */

void ldbg_alloc(const struct logger *new_owner, const char *what, const void *pointer, where_t where)
{
	ldbg_ref(NULL, new_owner, "new", what, pointer, where, 0, 1);
}

void ldbg_free(const struct logger *logger, const char *what, const void *pointer, where_t where)
{
	ldbg_ref(logger, NULL, "del", what, pointer, where, 1, 0);
}

void dbg_alloc(const char *what, const void *pointer, where_t where)
{
	ldbg_alloc(NULL, what, pointer, where);
}

void dbg_free(const char *what, const void *pointer, where_t where)
{
	ldbg_free(NULL, what, pointer, where);
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
		llog_passert(&global_logger, where,
			     "%s() %s@%p should have been 0 initialized",
			     __func__, base->what, pointer);
	}
	ldbg_ref(NULL, NULL, "new", base->what, pointer, where, old, new);
}

void refcnt_addref_where(const char *what,
			 const void *pointer,
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
		llog_passert((logger == NULL ? &global_logger : logger), where,
			     "%s() refcnt for %s@%p should have been non-0",
			     __func__, what, pointer);
	}

	LDBG_REF("add");
}

/*
 * look at refcnt atomically
 * This is a bit slow but it is used rarely.
 */
unsigned refcnt_peek_where(const void *pointer,
			   const refcnt_t *refcnt,
			   struct logger *logger,
			   where_t where)
{
	unsigned val;
	pthread_mutex_lock(&refcnt_mutex);
	{
		val = refcnt->count;
	}
	pthread_mutex_unlock(&refcnt_mutex);
	ldbg_ref(logger, /*owner*/NULL, "peek", /*what*/NULL, pointer, where, val, val);
	return val;
}

void *refcnt_delref_where(const char *what, void *pointer,
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
		llog_passert((logger == NULL ? &global_logger : logger), where,
			     "%s() refcnt for %s@%p should have been non-0",
			     __func__, what, pointer);
	}

	LDBG_REF("del");

	if (new == 0) {
		return pointer;
	}

	return NULL;
}
