/* Output base64 bytes, for libreswan
 *
 * Copyright (C) 2022 Andrew Cagney
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
 *
 */

#include "jambuf.h"
#include "chunk.h"
#include "ttodata.h"	/* for datatot() */
#include "passert.h"
#include "lswalloc.h"

size_t jam_base64_bytes(struct jambuf *buf, const void *ptr, size_t size)
{
	/*
	 * A byte is 8-bits, base64 uses 6-bits (2^6=64).  Plus some
	 * for \0.  Plus some extra for the trailing === and rounding.
	 */
	size_t base64_len = size * 8 / 6 + 1 + 10;
	char *base64_ptr = alloc_things(char, base64_len, "base64");
	size_t length = datatot(ptr, size, 64, base64_ptr, base64_len);
	passert(length < base64_len);
	jam_raw_bytes(buf, base64_ptr, length);
	pfree(base64_ptr);
	return length;
}
