/*
 * Memory allocation routines
 * Header: "lswalloc.h"
 *
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#include <libreswan.h>

#include "constants.h"
#include "lswlog.h"

/*
 * leave enabled so support functions are always in libswan, and
 * pluto can be recompiled with just the leak detective changes
 * ??? this seems dangerous and stupid
 */
#define LEAK_DETECTIVE
#include "lswalloc.h"

bool leak_detective = FALSE;	/* must not change after first alloc! */

const chunk_t empty_chunk = { NULL, 0 };

static exit_log_func_t exit_log_func = NULL;	/* allow for customer to customize */

void set_alloc_exit_log_func(exit_log_func_t func)
{
	exit_log_func = func;
}

/*
 * memory allocation
 *
 * LEAK_DETECTIVE puts a wrapper around each allocation and maintains
 * a list of live ones.  If a dead one is freed, an assertion MIGHT fail.
 * If the live list is currupted, that will often be detected.
 * In the end, report_leaks() is called, and the names of remaining
 * live allocations are printed.  At the moment, it is hoped, not that
 * the list is empty, but that there will be no surprises.
 *
 * Accepted Leaks:
 * - "struct iface" and "device name" (for "discovered" net interfaces)
 * - "struct event in event_schedule()" (events not associated with states)
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
	unsigned long junk;	/* force maximal alignment */
};

static union mhdr *allocs = NULL;

static void *alloc_bytes_raw(size_t size, const char *name)
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

		p = malloc(sizeof(union mhdr) + size);
	} else {
		p = malloc(size);
	}

	if (p == NULL) {
		if (exit_log_func != NULL) {
			(*exit_log_func)("unable to malloc %lu bytes for %s",
					(unsigned long) size, name);
		}
		abort();
	}

	if (leak_detective) {
		p->i.name = name;
		p->i.size = size;
		p->i.older = allocs;
		if (allocs != NULL)
			allocs->i.newer = p;
		allocs = p;
		p->i.newer = NULL;
		p->i.magic = LEAK_MAGIC;
		return p + 1;
	} else {
		return p;
	}

}

void pfree(void *ptr)
{
	union mhdr *p;

	if (leak_detective) {
		passert(ptr != NULL);
		p = ((union mhdr *)ptr) - 1;
		passert(p->i.magic == LEAK_MAGIC);
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
		p->i.magic = ~LEAK_MAGIC;
		free(p);
	} else {
		free(ptr);
	}
}

#ifdef LEAK_DETECTIVE
void report_leaks(void)
{
	union mhdr
	*p = allocs,
	*pprev = NULL;
	unsigned long n = 0;
	unsigned long numleaks = 0;
	unsigned long total = 0;

	while (p != NULL) {
		passert(p->i.magic == LEAK_MAGIC);
		passert(pprev == p->i.newer);
		pprev = p;
		p = p->i.older;
		n++;
		if (p == NULL || pprev->i.name != p->i.name) {
			if (n != 1)
				libreswan_log("leak: %lu * %s, item size: %lu",
					n, pprev->i.name, pprev->i.size);
			else
				libreswan_log("leak: %s, item size: %lu",
					pprev->i.name, pprev->i.size);
			numleaks += n;
			total += pprev->i.size;
			n = 0;
		}
	}
	if (numleaks != 0)
		libreswan_log("leak detective found %lu leaks, total size %lu",
			numleaks, total);
	else
		libreswan_log("leak detective found no leaks");

}
#endif	/* !LEAK_DETECTIVE */

void *alloc_bytes(size_t size, const char *name)
{
	void *p = alloc_bytes_raw(size, name);

	memset(p, '\0', size);
	return p;
}

void *clone_bytes(const void *orig, size_t size, const char *name)
{
	void *p = alloc_bytes_raw(size, name);

	memcpy(p, orig, size);
	return p;
}
