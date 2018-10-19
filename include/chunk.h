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
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifndef CHUNK_H
#define CHUNK_H

#include <stdbool.h>	/* bool */
#include <stddef.h>	/* size_t */
#include <stdint.h>	/* uint8_t */

/*
 * chunk is a simple pointer-and-size abstraction
 *
 * It's for dealing with raw bytes, for strings see shunk_t.
 *
 * Where possible, implement using non-inline functions.  This way all
 * code is found in chunk.c.  And debugging doesn't run into grief
 * with either macros or badly inlined functions.
 */

typedef struct /*chunk*/ {
	uint8_t *ptr;
	size_t len;
} chunk_t;

chunk_t chunk(void *ptr, size_t len);
#define CHUNK(OBJECT) { .ptr = (OBJECT), .len = sizeof(OBJECT), }

chunk_t alloc_chunk(size_t count, const char *name);
void free_chunk_contents(chunk_t *chunk); /* blats *CHUNK */

chunk_t clone_chunk(chunk_t old, const char *name);

/* clone(first+second) */
chunk_t clone_chunk_chunk(chunk_t first, chunk_t second, const char *name);

/* always NUL terminated; NULL is NULL */
char *clone_chunk_as_string(chunk_t chunk, const char *name);

chunk_t clone_bytes_as_chunk(void *bytes, size_t sizeof_bytes, const char *name);

bool chunk_eq(chunk_t a, chunk_t b);

extern const chunk_t empty_chunk;

#define PRI_CHUNK "%p@%zu"
#define pri_chunk(CHUNK) (CHUNK).ptr, (CHUNK).len


/*
 * Old stuff that can go away.
 */

/* replaced by free_chunk_contents()? */
#define freeanychunk(CH) {					\
		chunk_t *chp_ = &(CH); /*eval once */		\
		pfreeany(chp_->ptr);				\
		*chp_ = (chunk_t) { .len = 0, .ptr = NULL, };	\
	}

/* replaced by chunk() */
#define setchunk(ch, addr, size) { (ch).ptr = (addr); (ch).len = (size); }

/* replaced by clone_chunk() */
#define clonetochunk(ch, addr, size, name) \
	{ (ch).ptr = clone_bytes((addr), (ch).len = (size), name); }

#endif
