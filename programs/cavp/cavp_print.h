/*
 * Parse CAVP test vectors, for libreswan
 *
 * Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
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

#include <stdio.h>
#include <stdbool.h>

extern bool cavp_print_json;

void config_number(const char *prefix, int number);
void config_key(const char *key);

void fprint_chunk(FILE *, const char *prefix, const char *json,
		  chunk_t chunk, size_t binlen);
void fprint_symkey(FILE *, const char *prefix, const char *json,
		   PK11SymKey *key, size_t binlen);
void fprint_number(FILE *, const char *prefix, const char *json,
		   int number);
void fprint_line(FILE *, const char *line);
void fprint_begin(FILE *);
void fprint_end(FILE *);

void print_chunk(const char *prefix, const char *json,
		 chunk_t chunk, size_t binlen);
void print_symkey(const char *prefix, const char *json,
		 PK11SymKey *key, size_t binlen);
void print_number(const char *prefix, const char *json,
		  int number);
void print_line(const char *line);
void print_begin(void);
void print_end(void);
