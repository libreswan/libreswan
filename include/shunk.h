/*
 * string fragments, for libreswan
 *
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

#ifndef SHUNK_H
#define SHUNK_H

#include <stddef.h>	/* size_t */

/*
 * shunk_t is a rip of of chunk_t, but with a character pointer.  It
 * is intended for string slicing.
 */

struct shunk {
	const char *ptr;
	size_t len;
};

typedef struct shunk shunk_t;

extern const shunk_t empty_shunk;

shunk_t shunk1(const char *ptr); /* strlen() implied */
shunk_t shunk2(const char *ptr, int len);

/* like strsep()/strtok() */
shunk_t shunk_token(shunk_t *shunk, const char *delim);

/*
 * To print, use: printf(PRISHUNK, SHUNKF(shunk));
 */
#define PRISHUNK "%.*s"
#define SHUNKF(SHUNK) (int) (SHUNK).len, (SHUNK).ptr

#endif
