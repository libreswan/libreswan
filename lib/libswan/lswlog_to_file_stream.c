/* Send LSWLOG to a file with implicit '\n', for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney
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

#include <stdio.h>

#include "lswlog.h"

size_t lswlog_to_file_stream(struct lswlog *buf, FILE *file)
{
	lswlogs(buf, "\n");
	/* out includes '\0', drop it */
	chunk_t out = fmtbuf_as_chunk(buf);
	return fwrite(out.ptr, out.len-1, 1, file);
}
