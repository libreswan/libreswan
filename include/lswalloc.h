/*
 * misc. universal things
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001, 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
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

#include "constants.h"
#include <sys/types.h>

/* memory allocation */

extern void pfree(void *ptr);
extern void *alloc_bytes(size_t size, const char *name);
extern void *clone_bytes(const void *orig, size_t size,
			  const char *name);

extern bool leak_detective;
extern void report_leaks(void);

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

#define alloc_things(THING, COUNT, NAME) ((THING*) alloc_bytes(sizeof(THING) * (COUNT), (NAME)))

#define clone_thing(orig, name)						\
	((__typeof__(&(orig))) clone_bytes((const void *)&(orig),	\
					   sizeof(orig), (name)))

#define clone_const_thing(orig, name) clone_bytes((const void *)&(orig), \
					    sizeof(orig), (name))

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

typedef void (*exit_log_func_t)(const char *message, ...);
extern void set_alloc_exit_log_func(exit_log_func_t func);

#endif /* _LSW_ALLOC_H_ */
