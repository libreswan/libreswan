/*
 * SECItem<>chunk conversions, for libreswan
 *
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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

#include "lswalloc.h"
#include "jambuf.h"
#include "lswnss.h"

SECItem same_bytes_as_secitem(void *bytes, size_t len, SECItemType type)
{
	SECItem si = {
		.type = type,
		.data = bytes,
		.len = len,
	};
	return si;
}

SECItem same_shunk_as_secitem(shunk_t shunk, SECItemType type)
{
	SECItem si = {
		.type = type,
		.data = DISCARD_CONST(uint8_t *, shunk.ptr),
		.len = shunk.len,
	};
	return si;
}

chunk_t same_secitem_as_chunk(SECItem si)
{
	return chunk2(si.data, si.len);
}

shunk_t same_secitem_as_shunk(SECItem si)
{
	return shunk2(si.data, si.len);
}

chunk_t clone_secitem_as_chunk(SECItem si, const char *name)
{
	chunk_t chunk = {
		.len = si.len,
		.ptr = clone_bytes(si.data, si.len, name),
	};
	return chunk;
}
