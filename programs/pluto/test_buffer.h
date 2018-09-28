/*
 * Copyright (C) 2014 Andrew Cagney <andrew.cagney@gmail.com>
 * Copyright (C) 2015 Andrew Cagney <andrew.cagney@gmail.com>
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

#include <stdbool.h>
#include <pk11pub.h>

#include "chunk.h"

chunk_t decode_hex_to_chunk(const char *original, const char *string);
chunk_t decode_to_chunk(const char *prefix, const char *string);
PK11SymKey *decode_hex_to_symkey(const char *prefix, const char *string);

bool verify_chunk(const char *desc,
		   chunk_t expected,
		   chunk_t actual);
bool verify_symkey(const char *desc,
		   chunk_t expected, PK11SymKey *actual);
bool verify_chunk_data(const char *desc,
		  chunk_t expected,
		  u_char *actual);

struct encrypt_desc;

PK11SymKey *decode_to_key(const struct encrypt_desc *encrypt_desc, const char *string);
