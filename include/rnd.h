/* randomness machinery
 *
 * Copyright (C) 1998, 1999  D. Hugh Redelmeier.
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

#ifndef PLUTO_RND_H
#define PLUTO_RND_H

#include <stdint.h>	/* for uintmax_t */
#include <stddef.h>	/* for size_t */

#include "chunk.h"

struct logger;

extern void fill_rnd_chunk(chunk_t chunk);
extern void get_rnd_bytes(void *buffer, size_t size);
extern uintmax_t get_rnd_uintmax(void);
extern chunk_t alloc_rnd_chunk(size_t size, const char *name);

#endif
