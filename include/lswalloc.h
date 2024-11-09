/*
 * Misc. universal things
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001, 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#ifndef _LSW_ALLOC_H_
#define _LSW_ALLOC_H_

#include <sys/types.h>
#include <stdarg.h>

#include "constants.h"
#include "lswcdefs.h"

struct logger;

/* memory allocation */

extern void pfree(void *ptr);

/* Never returns NULL; allocates 0 bytes as 1-byte */
extern void *alloc_bytes(size_t size, const char *name);

/* verify allocation; PTR must be non-NULL */
void pmemory_where(void *ptr, where_t where);
#define pmemory(PTR) pmemory_where(PTR, HERE)

/* clone's NULL bytes as NULL bytes, not 1-byte */
void *clone_bytes(const void *orig, size_t size, const char *name);
void *clone_bytes_bytes(const void *lhs_ptr, size_t lhs_len,
			const void *rhs_ptr, size_t rhs_len, const char *name);

void realloc_bytes(void **ptr, size_t old_size, size_t new_size, const char *name);

extern bool leak_detective;
extern bool report_leaks(struct logger *logger); /* true is bad */

/*
 * Notes on __typeof__().
 *
 * The macro clone_thing(), for instance, uses __typeof__(THING) to
 * ensure that the type of the original THING and the returned clone
 * match.  Enforcing this flushed out a weird bug in the config
 * parser.
 *
 * While __typeof__() is a non-standard extension, it is widely
 * supported - GCC, LLVM, and even PCC include the feature.  MSVC
 * provides the alternative decltype(), and when someone tries to use
 * that compiler adding suitable #ifdefs should be straight forward.
 *
 * There is, however, one limitation.  If THING has the const
 * qualifier then the clone can't be assigned to a non-const variable.
 * For instance, this code gets a warning:
 *
 *    const char *p = ...;
 *    char *q = clone_thing(*p, "copy of p");
 *
 * One way round it would be to use another GCC extension ({}) and
 * change the macro to:
 *
 *    #define clone_thing(TYPE,THING,NAME) ({
 *            const (TYPE) *p = &(THING);
 *            (TYPE*) clone_bytes(p, sizeof(TYPE), (NAME);
 *       )}
 *
 * Another would be to use, er, C++'s remove_const<>.
 */

#define alloc_thing(thing, name) ((thing*) alloc_bytes(sizeof(thing), (name)))

/* XXX: No NAME parameter; get ready for implicit HERE */
#define overalloc_thing(THING, EXTRA)				\
	((THING*) alloc_bytes(sizeof(THING) + (EXTRA), #THING))

#define alloc_things(THING, COUNT, NAME)			\
	((THING*) alloc_bytes(sizeof(THING) * (COUNT), (NAME)))

#define overalloc_things(THING, COUNT, EXTRA)				\
	((THING*) alloc_bytes(sizeof(THING) * (COUNT) +  (EXTRA), #THING"s"))

#define realloc_things(THINGS, OLD_COUNT, NEW_COUNT, NAME)		\
	{								\
		void *things_ = THINGS;					\
		realloc_bytes(&things_,					\
			      (OLD_COUNT) * sizeof((THINGS)[0]),	\
			      (NEW_COUNT) * sizeof((THINGS)[0]),	\
			      NAME);					\
		THINGS = things_;					\
	}

#define zero_thing(THING) memset(&(THING), '\0', sizeof(THING))

#define clone_thing(orig, name)						\
	((__typeof__(&(orig))) clone_bytes((const void *)&(orig),	\
					   sizeof(orig), (name)))

#define clone_things(ORIG, COUNT, NAME)					\
	((__typeof__(&(ORIG[0]))) clone_bytes((ORIG), sizeof((ORIG)[0]) * (COUNT), (NAME)))

#define clone_const_thing(orig, name) clone_bytes((const void *)&(orig), \
					    sizeof(orig), (name))

#define clone_const_things(ORIG, COUNT, NAME) \
	clone_bytes((ORIG), (COUNT) * sizeof((ORIG)[0]), (NAME))

#define clone_str(str, name) \
	((str) == NULL ? NULL : clone_bytes((str), strlen((str)) + 1, (name)))

#define pfreeany(P) {				\
		typeof(P) *pp_ = &(P);		\
		if (*pp_ != NULL) {		\
			pfree(*pp_);		\
			*pp_ = NULL;		\
		}				\
	}

#define replace(p, q) { pfreeany(p); (p) = (q); }

/*
 * Memory primitives, should only be used by libevent.
 */
void *uninitialized_malloc(size_t size, const char *name);
void *uninitialized_realloc(void *ptr, size_t size, const char *name);

/* can't use vaprintf() as it calls malloc() directly */
char *alloc_printf(const char *fmt, ...) PRINTF_LIKE(1) MUST_USE_RESULT;
char *alloc_vprintf(const char *fmt, va_list ap)  VPRINTF_LIKE(1) MUST_USE_RESULT;

#endif /* _LSW_ALLOC_H_ */
