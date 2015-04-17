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

struct hash_desc;

struct cavp_config {
	struct hash_desc *hasher;
} cavp_config;

struct cavp_data {
	chunk_t psk;
	chunk_t ni;
	chunk_t nr;
	chunk_t cky_i;
	chunk_t cky_r;
	PK11SymKey *g_xy;
} cavp_data;

void cavp_run(void);

void print_chunk(const char *prefix, chunk_t chunk, size_t binlen);
void print_symkey(const char *prefix, PK11SymKey *key, size_t binlen);
