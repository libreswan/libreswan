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

void config_number(const char *prefix, int number);
void config_key(const char *key);

void print_chunk(const char *prefix, chunk_t chunk, size_t binlen);
void print_symkey(const char *prefix, PK11SymKey *key, size_t binlen);
void print_number(const char *prefix, int number);
void print_line(const char *line);
