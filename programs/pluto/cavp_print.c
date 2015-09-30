/*
 * Parse CAVP test vectors, for libreswan
 *
 * Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
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

#include <stdio.h>
#include <stdlib.h>

#include "constants.h"
#include "lswalloc.h"
#include "crypt_dbg.h"
#include "cavp_print.h"

/*
 * The test vectors are CR-LF terminated, mimic this.
 */
static const char crlf[] = "\r\n";

void config_key(const char *key)
{
	fputs("[", stdout);
	fputs(key, stdout);
	fputs("]", stdout);
	fputs(crlf, stdout);
}

void config_number(const char *key, int number)
{
	printf("[%s = %d]%s", key, number, crlf);
}

void print_chunk(const char *prefix, chunk_t chunk, size_t binlen)
{
	printf("%s = ", prefix);
	size_t len = binlen == 0 ? chunk.len
		: binlen < chunk.len ? binlen
		: chunk.len;

	size_t i = 0;
	for (i = 0; i < len; i++) {
		printf("%02x", chunk.ptr[i]);
	}
	printf("%s", crlf);
}

void print_symkey(const char *prefix, PK11SymKey *key, size_t binlen)
{
	chunk_t chunk = chunk_from_symkey(prefix, key);
	print_chunk(prefix, chunk, binlen);
	freeanychunk(chunk);
}

void print_number(const char *prefix, int number)
{
	printf("%s = %d%s", prefix, number, crlf);
}

void print_line(const char *line)
{
	fputs(line, stdout);
	fputs(crlf, stdout);
}
