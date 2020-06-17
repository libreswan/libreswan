/*
 * Memory allocation routines
 * Header: "lswalloc.h"
 *
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
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

#include <pthread.h>	/* pthread.h must be first include file */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>


#include "constants.h"
#include "lswlog.h"

#include "lswalloc.h"

bool leak_detective = FALSE;	/* must not change after first alloc! */

/*
 * memory allocation
 *
 * --leak_detective puts a wrapper around each allocation and maintains
 * a list of live ones.  If a dead one is freed, an assertion MIGHT fail.
 * If the live list is corrupted, that will often be detected.
 * In the end, report_leaks() is called, and the names of remaining
 * live allocations are printed.  At the moment, it is hoped, not that
 * the list is empty, but that there will be no surprises.
 *
 * Accepted Leaks:
 * - "struct iface" and "device name" (for "discovered" net interfaces)
 * - "struct pluto_event in event_schedule()" (events not associated with states)
 * - "Pluto lock name" (one only, needed until end -- why bother?)
 */

/* this magic number is 3671129837 decimal (623837458 complemented) */
#define LEAK_MAGIC 0xDAD0FEEDul

union mhdr {
	struct {
		const char *name;
		union mhdr *older, *newer;
		unsigned long magic;
		unsigned long size;
	} i;	/* info */
	unsigned long long junk;	/* force maximal alignment */
};

/* protects updates to the leak-detective linked list */
static pthread_mutex_t leak_detective_mutex = PTHREAD_MUTEX_INITIALIZER;

static union mhdr *allocs = NULL;

static void install_allocation(union mhdr *p, size_t size, const char *name)
{
	p->i.name = name;
	p->i.size = size;
	p->i.magic = LEAK_MAGIC;
	p->i.newer = NULL;
	{
		pthread_mutex_lock(&leak_detective_mutex);
		p->i.older = allocs;
		if (allocs != NULL)
			allocs->i.newer = p;
		allocs = p;
		pthread_mutex_unlock(&leak_detective_mutex);
	}
}

static void remove_allocation(union mhdr *p)
{
	pthread_mutex_lock(&leak_detective_mutex);
	if (p->i.older != NULL) {
		passert(p->i.older->i.newer == p);
		p->i.older->i.newer = p->i.newer;
	}
	if (p->i.newer == NULL) {
		passert(p == allocs);
		allocs = p->i.older;
	} else {
		passert(p->i.newer->i.older == p);
		p->i.newer->i.older = p->i.older;
	}
	pthread_mutex_unlock(&leak_detective_mutex);
	p->i.magic = ~LEAK_MAGIC;
}

static void *allocate(void *(*alloc)(size_t), size_t size, const char *name)
{
	union mhdr *p;

	if (size == 0) {
		/* uclibc returns NULL on malloc(0) */
		size = 1;
	}

	if (leak_detective) {
		/* fail on overflow */
		if (sizeof(union mhdr) + size < size)
			return NULL;

		p = alloc(sizeof(union mhdr) + size);
	} else {
		p = alloc(size);
	}

	if (p == NULL) {
		PASSERT_FAIL("unable to allocate %zu bytes for %s", size, name);
	}

	if (leak_detective) {
		install_allocation(p, size, name);
		return p + 1;
	} else {
		return p;
	}
}

void *uninitialized_malloc(size_t size, const char *name)
{
	return allocate(malloc, size, name);
}

void pfree(void *ptr)
{
	if (leak_detective) {
		union mhdr *p;

		passert(ptr != NULL);

		p = ((union mhdr *)ptr) - 1;

		if (p->i.magic == ~LEAK_MAGIC) {
			PASSERT_FAIL("pointer %p invalid, possible double free (magic == ~LEAK_MAGIC)", ptr);
		} else if (p->i.magic != LEAK_MAGIC) {
			PASSERT_FAIL("pointer %p invalid, possible heap corruption or bad pointer (magic != LEAK_MAGIC or ~LEAK_MAGIC})", ptr);
		}

		remove_allocation(p);
		/* stomp on memory!   Is another byte value better? */
		memset(p, 0xEF, sizeof(union mhdr) + p->i.size);
		/* put back magic */
		p->i.magic = ~LEAK_MAGIC;
		free(p);
	} else {
		free(ptr);
	}
}

void report_leaks(void)
{
	union mhdr *p,
		*pprev = NULL;
	unsigned long n = 0;
	unsigned long numleaks = 0;
	unsigned long total = 0;

	pthread_mutex_lock(&leak_detective_mutex);
	p = allocs;
	while (p != NULL) {
		passert(p->i.magic == LEAK_MAGIC);
		passert(pprev == p->i.newer);
		pprev = p;
		p = p->i.older;
		n++;
		if (p == NULL ||
		    pprev->i.name != p->i.name ||
		    pprev->i.size != p->i.size) {
			/* filter out one-time leaks we prefer to not fix */
			if (strstr(pprev->i.name, "(ignore)") == NULL) {
				if (n != 1)
					libreswan_log("leak: %lu * %s, item size: %lu",
						n, pprev->i.name, pprev->i.size);
				else
					libreswan_log("leak: %s, item size: %lu",
						pprev->i.name, pprev->i.size);
				numleaks += n;
				total += pprev->i.size;
				n = 0;
			} else {
				n = 0;
			}
		}
	}
	pthread_mutex_unlock(&leak_detective_mutex);

	if (numleaks != 0)
		libreswan_log("leak detective found %lu leaks, total size %lu",
			numleaks, total);
	else
		libreswan_log("leak detective found no leaks");
}

static void *zalloc(size_t size)
{
	return calloc(1, size);
}

void *alloc_bytes(size_t size, const char *name)
{
	return allocate(zalloc, size, name);
}

/*
 * Note:
 * orig=NULL; size=0 -> NULL
 * orig=PTR; size=0 -> new PTR (for instance a shunk with PTR = "")
 * orig=PTR; size>0 -> new PTR
 */
void *clone_bytes(const void *orig, size_t size, const char *name)
{
	void *p;
	if (orig == NULL) {
		passert(size == 0);
		p = NULL;
	} else {
		/* even when size is 0, allocate something */
		p = uninitialized_malloc(size, name);
		memcpy(p, orig, size);
	}
	return p;
}

/*
 * Re-size something on the HEAP.
 *
 * Unlike the more traditional realloc() this code doesn't allow a
 * NULL pointer.  The caller, which is presumably implementing some
 * sort of realloc() wrapper, gets to handle this.  So as to avoid any
 * confusion, give this a different name and function signature.
 */

void *uninitialized_realloc(void *ptr, size_t new_size, const char *name)
{
	if (ptr == NULL) {
		return uninitialized_malloc(new_size, name);
	} else if (leak_detective) {
		union mhdr *p = ((union mhdr *)ptr) - 1;
		passert(p->i.magic == LEAK_MAGIC);
		remove_allocation(p);
		p = realloc(p, sizeof(union mhdr) + new_size);
		if (p == NULL) {
			PASSERT_FAIL("unable to reallocate %zu bytes for %s", new_size, name);
		}
		install_allocation(p, new_size, name);
		return p+1;
	} else {
		return realloc(ptr, new_size);
	}
}

void realloc_bytes(void **ptr, size_t old_size, size_t new_size, const char *name)
{
	if (*ptr == NULL) {
		passert(old_size == 0);
	} else if (leak_detective) {
		union mhdr *p = ((union mhdr *)*ptr) - 1;
		passert(p->i.magic == LEAK_MAGIC);
		passert(p->i.size == old_size);
	}
	*ptr = uninitialized_realloc(*ptr, new_size, name);
	/* XXX: old_size..new_size still uninitialized */
	if (new_size > old_size) {
		uint8_t *b = *ptr;
		memset(b + old_size, '\0', new_size - old_size);
	}
}
