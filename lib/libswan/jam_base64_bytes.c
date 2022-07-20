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

size_t jam_base64_bytes(struct jambuf *buf, const void *ptr, size_t size)
{
	/*
	 * A byte is 8-bits, base64 uses 6-bits (2^6=64).  Plus some
	 * for \0.  Plus some extra for the trailing === and rounding.
	 */
	chunk_t base64 = alloc_chunk(size * 8 / 6 + 1 + 10, "base64");
	size_t length = datatot(ptr, size, 64, (void*)base64.ptr, base64.len);
	passert(length < base64.len);
	jam_raw_bytes(buf, base64.ptr, length);
	free_chunk_content(&base64);
	return length;
}
