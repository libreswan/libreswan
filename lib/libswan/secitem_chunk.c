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

#include <libreswan.h>
#include <lswalloc.h>
#include "nss.h"
#include "secrets.h"

SECItem same_chunk_as_secitem(chunk_t chunk, SECItemType type)
{
	SECItem si = {
		.type = type,
		.data = chunk.ptr,
		.len = chunk.len,
	};
	return si;
}

chunk_t same_secitem_as_chunk(SECItem si)
{
	chunk_t chunk = {
		.ptr = si.data,
		.len = si.len,
	};
	return chunk;
}

chunk_t clone_secitem_as_chunk(SECItem si, const char *name)
{
	chunk_t chunk = {
		.len = si.len,
		.ptr = clone_bytes(si.data, si.len, name),
	};
	return chunk;
}

#if 0	/* not used (yet?) */
SECItem clone_chunk_as_secitem(chunk_t chunk, SECItemType type, const char *name)
{
	SECItem si = {
		.type = type,
		.len = chunk.len,
		.data = clone_bytes(chunk.ptr, chunk.len, name),
	};
	return si;
}
#endif
