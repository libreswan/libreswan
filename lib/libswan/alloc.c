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

bool leak_detective = false;	/* must not change after first alloc! */

/*
 * memory allocation
 *
 * --leak_detective puts a wrapper around each allocation and maintains
 * a list of live ones.  If a dead one is freed, an assertion MIGHT fail.
 * If the live list is corrupted, that will often be detected.
 * In the end, report_leaks() is called, and the names of remaining
 * live allocations are printed.
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

/*
 * Detect and passert() an invalid memory address.
 *
 * With leak_detective, valid memory has .magic==LEAK_MAGIC, and just
 * pfree()d memory has .magic=~LEAK_DETECTIVE (and 0xFE scribbled over
 * the content).
 */

static union mhdr *pmhdr_where(void *ptr, where_t where)
{
#if 0
	/*
	 * Diagnose a pointer read from a pfree()'d struct.
	 *
	 * Since the pfree() memory contents had 0XEF scribbled on
	 * them, any pointers in that struct will have the value
	 * POINTER_MAGIC.
	 *
	 * This isn't enabled.  POINTER_MAGIC is misalligned and
	 * (presumably) invalid.  Accessing .i.magic should fail,
	 * SIGSEGVs or SIGBUS.
	 */
#ifdef INTPTR_MAX
# if INTPTR_MAX == INT32_C(0x7FFFFFFF)
#  define POINTER_T uint32_t
#  define POINTER_MAGIC UINT32_C(0xEFEFEFEF)
# elif INTPTR_MAX == INT64_C(0x7FFFFFFFFFFFFFFF)
#  define POINTER_T uint64_t
#  define POINTER_MAGIC UINT64_C(0xEFEFEFEFEFEFEFEF)
# else
#   error INTPTR_MAX not recognized
# endif
#else
# error INTPTR_MAX not defined
#endif
	if ((POINTER_T)ptr == POINTER_MAGIC) {
		llog_passert(&global_logger, where,
			     "pointer %p invalid, possible use after free (pointer == POINTER_MAGIC)", ptr);
	}
#endif
	union mhdr *p = ((union mhdr *)ptr) - 1;
	switch (p->i.magic) {
	case LEAK_MAGIC:
		break;
	case ~LEAK_MAGIC:
		/*
		 * Diagnose of a double free.
		 *
		 * Note: this won't detect a re-allocated pointer vis:
		 *
		 *    pfree(p);          // p == 1234
		 *    q = alloc_bytes(); // q == 1234
		 *    pfree(p)           // p == 1234
		 *
		 * Note: the testuite has EFENCE enabled (unmap and
		 * never reuse in free()) so just trying to access
		 * .i.magic will trigger a SEGV barf.
		 */
		llog_passert(&global_logger, where,
			     "pointer %p invalid, possible double free (magic == ~LEAK_MAGIC)", ptr);
	default:
		/*
		 * Diagnose an invalid pointer (possibly corrupt,
		 * possibly...).
		 */
		llog_passert(&global_logger, where,
			     "pointer %p invalid, possible heap corruption or bad pointer (magic != LEAK_MAGIC and ~LEAK_MAGIC})", ptr);
	}
	return p;
}

void pmemory_where(void *ptr, where_t where)
{
	passert(ptr != NULL);
	if (leak_detective) {
		pmhdr_where(ptr, where);
	}
}

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
		llog_passert(&global_logger, HERE,
			     "unable to allocate %zu bytes for %s", size, name);
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
		passert(ptr != NULL);
		union mhdr *p = pmhdr_where(ptr, HERE);
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

bool report_leaks(struct logger *logger)
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
					llog(RC_LOG, logger, "leak: %lu * %s, item size: %lu",
						    n, pprev->i.name, pprev->i.size);
				else
					llog(RC_LOG, logger, "leak: %s, item size: %lu",
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

	if (numleaks != 0) {
		llog(RC_LOG, logger, "leak detective found %lu leaks, total size %lu",
			    numleaks, total);
	} else {
		llog(RC_LOG, logger, "leak detective found no leaks");
	}

	return numleaks != 0;
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
	if (orig == NULL) {
		passert(size == 0);
		return NULL;
	}

	/*
	 * Even when size is 0, allocate something.
	 *
	 * Note: memcpy(DST,NULL,*) is undefined.  Since size>0
	 * implies !NULL use that (string code can end up with
	 * {!NULL,0}.
	 */
	void *p = uninitialized_malloc(size, name);
	if (size > 0) {
		passert(orig != NULL); /* per above */
		memcpy(p, orig, size);
	}
	return p;
}

void *clone_bytes_bytes(const void *lhs_ptr, size_t lhs_len,
			const void *rhs_ptr, size_t rhs_len,
			const char *name)
{
	if (lhs_ptr == NULL && rhs_ptr == NULL) {
		passert(lhs_len == 0);
		passert(rhs_len == 0);
		return NULL;
	}

	/*
	 * When at least one PTR is non-NULL allocate something (even
	 * though SIZE can be zero).
	 *
	 * Note: memcpy(DST,NULL,*) is undefined.  Since LEN>0 implies
	 * !NULL use that (string code can end up with {!NULL,0}.
	 */
	size_t size = lhs_len + rhs_len;
	void *new = uninitialized_malloc(size, name);
	if (lhs_len > 0) {
		passert(lhs_ptr != NULL);
		memcpy(new, lhs_ptr, lhs_len);
	}
	if (rhs_len > 0) {
		passert(rhs_ptr != NULL);
		memcpy(new + lhs_len, rhs_ptr, rhs_len);
	}
	return new;
}

char *clone_str(const char *str, const char *name)
{
	if (str == NULL) {
		return NULL;
	}

	return clone_bytes(str, strlen(str) + 1, name);
}

void append_str(char **sentence, const char *sep, const char *word)
{
	if (*sentence == NULL) {
		(*sentence) = clone_str(word, __func__);
	}

	char *ns = alloc_printf("%s%s%s", (*sentence), sep, word);
	pfree((*sentence));
	(*sentence) = ns;
}

/*
 * Re-size something on the HEAP.
 */

void *uninitialized_realloc(void *ptr, size_t new_size, const char *name)
{
	if (ptr == NULL) {
		return uninitialized_malloc(new_size, name);
	} else if (leak_detective) {
		union mhdr *p = pmhdr_where(ptr, HERE);
		remove_allocation(p);
		p = realloc(p, sizeof(union mhdr) + new_size);
		if (p == NULL) {
			llog_passert(&global_logger, HERE,
				     "unable to reallocate %zu bytes for %s", new_size, name);
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
		union mhdr *p = pmhdr_where(*ptr, HERE);
		passert(p->i.size == old_size);
	}
	*ptr = uninitialized_realloc(*ptr, new_size, name);
	/* XXX: old_size..new_size still uninitialized */
	if (new_size > old_size) {
		uint8_t *b = *ptr;
		memset(b + old_size, '\0', new_size - old_size);
	}
}
