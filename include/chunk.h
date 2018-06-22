/*
 * memory chunks, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001, 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2018 Andrew Cagney
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

#ifndef CHUNK_H
#define CHUNK_H

#include <stddef.h>	/* size_t */
#include <stdint.h>	/* uint8_t */

/* chunk is a simple pointer-and-size abstraction */

struct chunk {
	uint8_t *ptr;
	size_t len;
};

typedef struct chunk chunk_t;

chunk_t chunk(void *ptr, size_t len);

/* XXX: count can't have side effects. */
#define alloc_chunk(COUNT, NAME) (struct chunk) {			\
		.len = (COUNT),						\
		.ptr = alloc_things(u_int8_t, (COUNT), NAME),		\
	}

#define setchunk(ch, addr, size) { (ch).ptr = (addr); (ch).len = (size); }

/* NOTE: freeanychunk, unlike pfreeany, NULLs .ptr and zeros .len */
#define freeanychunk(CH) {					\
		chunk_t *chp_ = &(CH); /*eval once */		\
		pfreeany(chp_->ptr);				\
		*chp_ = (chunk_t) { .len = 0, .ptr = NULL, };	\
	}

#define clonetochunk(ch, addr, size, name) \
	{ (ch).ptr = clone_bytes((addr), (ch).len = (size), name); }

chunk_t clone_chunk(chunk_t old, const char *name);

/* note: the caller must free the result */
char *str_from_chunk(chunk_t c, const char *name);

#define clonereplacechunk(ch, addr, size, name) \
	{ pfreeany((ch).ptr); clonetochunk(ch, addr, size, name); }

/*
 * Concatenate the contents of a chunk onto a string.
 * The destination pointer is incremented by the length.
 * Pray that there is enough space.
 */
#define catchunk(dst, chunk) { \
		memcpy((dst), (chunk).ptr, (chunk).len); \
		(dst) += (chunk).len; \
	}

#define same_chunk(a, b) \
	((a).len == (b).len && memeq((a).ptr, (b).ptr, (b).len))

extern const chunk_t empty_chunk;

#endif
