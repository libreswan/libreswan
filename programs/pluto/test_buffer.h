/*
 * Copyright (C) 2014 Andrew Cagney <andrew.cagney@gmail.com>
 * Copyright (C) 2015 Andrew Cagney <andrew.cagney@gmail.com>
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

chunk_t decode_hex_to_chunk(const char *original, const char *string);
chunk_t decode_to_chunk(const char *prefix, const char *string);
int compare_chunks(const char *prefix,
		   chunk_t expected,
		   chunk_t actual);
int compare_chunk(const char *prefix,
		  chunk_t expected,
		  u_char *actual);
chunk_t extract_chunk(const char *prefix, chunk_t input,
		      size_t offset, size_t length);

PK11SymKey *decode_to_key(CK_MECHANISM_TYPE cipher_mechanism, const char *string);
