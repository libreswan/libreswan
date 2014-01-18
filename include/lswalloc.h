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

#define pfreeany(p) do { if ((p) != NULL) \
				 pfree(p); } while (0)
#define replace(p, q) do { pfreeany(p); (p) = (q); } while (0)

/* chunk is a simple pointer-and-size abstraction */

struct chunk {
	u_char *ptr;
	size_t len;
};
typedef struct chunk chunk_t;

#define setchunk(ch, addr, size) do { (ch).ptr = (addr); (ch).len = (size); \
} while (0)
/* NOTE: freeanychunk, unlike pfreeany, NULLs .ptr */
#define freeanychunk(ch) do { pfreeany((ch).ptr); (ch).ptr = NULL; } while (0)
#define clonetochunk(ch, addr, size, name) \
	do { (ch).ptr = clone_bytes((addr), (ch).len = (size), name); \
	} while (0)
#define clonereplacechunk(ch, addr, size, name) \
	do { pfreeany((ch).ptr); clonetochunk(ch, addr, size, name); \
	} while (0)
#define chunkcpy(dst, chunk) \
	do { memcpy(dst, chunk.ptr, chunk.len); dst += chunk.len; } while (0)
#define same_chunk(a, b) \
	((a).len == (b).len && memeq((a).ptr, (b).ptr, (b).len))

extern const chunk_t empty_chunk;

typedef void (*exit_log_func_t)(const char *message, ...);
extern void set_exit_log_func(exit_log_func_t func);

#ifdef DMALLOC
# include <dmalloc.h>
#endif

#define free_lsw_nss_symkey(ch)  \
	do { PK11SymKey *ptr = 0; \
	     if ((ch).ptr != NULL) { memcpy(&ptr, (ch).ptr, (ch).len); \
				     memset((ch).ptr, 0, (ch).len ); } \
	     if (ptr != NULL) { PK11_FreeSymKey(ptr); } } while (0)

#define dup_lsw_nss_symkey(ch)  \
	do { PK11SymKey *ptr = 0; \
	     if ((ch).ptr != NULL) { memcpy(&ptr, (ch).ptr, (ch).len); } \
	     if (ptr != NULL) { PK11_ReferenceSymKey(ptr); } } while (0)

#endif /* _LSW_ALLOC_H_ */
