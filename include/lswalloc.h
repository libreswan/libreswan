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
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
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

#define alloc_thing(thing, name) (alloc_bytes(sizeof(thing), (name)))

#define clone_thing(orig, name) clone_bytes((const void *)&(orig), \
					    sizeof(orig), (name))
#define clone_str(str, name) \
	((str) == NULL ? NULL : clone_bytes((str), strlen((str)) + 1, (name)))

#define pfreeany(p) { if ((p) != NULL) pfree(p); }

#define replace(p, q) { pfreeany(p); (p) = (q); }

/* chunk is a simple pointer-and-size abstraction */

struct chunk {
	u_char *ptr;
	size_t len;
};

typedef struct chunk chunk_t;

#define setchunk(ch, addr, size) { (ch).ptr = (addr); (ch).len = (size); }

/* NOTE: freeanychunk, unlike pfreeany, NULLs .ptr */
#define freeanychunk(ch) { pfreeany((ch).ptr); (ch).ptr = NULL; }

#define clonetochunk(ch, addr, size, name) \
	{ (ch).ptr = clone_bytes((addr), (ch).len = (size), name); }

#define clonereplacechunk(ch, addr, size, name) \
	{ pfreeany((ch).ptr); clonetochunk(ch, addr, size, name); }

#define chunkcpy(dst, chunk) \
	{ memcpy(dst, chunk.ptr, chunk.len); dst += chunk.len; }

#define same_chunk(a, b) \
	((a).len == (b).len && memeq((a).ptr, (b).ptr, (b).len))

extern const chunk_t empty_chunk;

typedef void (*exit_log_func_t)(const char *message, ...);
extern void set_alloc_exit_log_func(exit_log_func_t func);

#endif /* _LSW_ALLOC_H_ */
