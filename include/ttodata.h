/*
 * header file for Libreswan library functions
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 */

#ifndef TTODATA_H
#define TTODATA_H    /* seen it, no need to see it again */

#include <stddef.h>		/* for size_t */

#include "err.h"
#include "lset.h"
#include "chunk.h"
#include "shunk.h"

/* text conversions */

#define ULTOT_BUF	((64+2)/3 + 1)  /* holds 64 bits in octal + NUL */

extern err_t ttodata(const char *src, size_t srclen, int base,
		     void *buf, size_t buflen, size_t *needed);

extern err_t ttochunk(shunk_t src, int base, chunk_t *chunk);

extern size_t datatot(const void *src, size_t srclen, int format,
		      char *buf, size_t buflen);

#endif
