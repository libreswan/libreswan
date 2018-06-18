/*
 * Parse CAVP test vectors, for libreswan
 *
 * Copyright (C) 2015,2017 Andrew Cagney <cagney@gnu.org>
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
#include "crypt_symkey.h"
#include "cavp_print.h"

bool cavp_print_json = false;

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

void fprint_number(FILE *file, const char *prefix, const char *json,
		   int number)
{
	if (!cavp_print_json) {
		fprintf(file, "%s = %d%s", prefix, number, crlf);
	} else if (json != NULL) {
		fprintf(file, "\"%s\": %d\n", json, number);
	}
}

void fprint_chunk(FILE *file, const char *prefix, const char *json,
		  chunk_t chunk, size_t binlen)
{
	if (!cavp_print_json) {
		fprintf(file, "%s = ", prefix);
		size_t len = binlen == 0 ? chunk.len
			: binlen < chunk.len ? binlen
			: chunk.len;
		for (size_t i = 0; i < len; i++) {
			fprintf(file, "%02x", chunk.ptr[i]);
		}
		fprintf(file, "%s", crlf);
	} else if (json != NULL) {
		fprintf(file, "\"%s\": \"", json);
		size_t len = binlen == 0 ? chunk.len
			: binlen < chunk.len ? binlen
			: chunk.len;
		for (size_t i = 0; i < len; i++) {
			fprintf(file, "%02x", chunk.ptr[i]);
		}
		fprintf(file, "\"\n");
	}
}

void fprint_symkey(FILE *file, const char *prefix, const char *json,
		   PK11SymKey *key, size_t binlen)
{
	chunk_t chunk = chunk_from_symkey(prefix, key);
	fprint_chunk(file, prefix, json, chunk, binlen);
	freeanychunk(chunk);
}

void fprint_line(FILE *file, const char *line)
{
	fputs(line, file);
	if (!cavp_print_json) {
		fputs(crlf, file);
	} else {
		fputs("\n", file);
	}
}

void print_chunk(const char *prefix, const char *json,
		 chunk_t chunk, size_t binlen)
{
	fprint_chunk(stdout, prefix, json, chunk, binlen);
}

void print_symkey(const char *prefix, const char *json,
		  PK11SymKey *key, size_t binlen)
{
	fprint_symkey(stdout, prefix, json, key, binlen);
}

void print_number(const char *prefix, const char *json,
		  int number)
{
	fprint_number(stdout, prefix, json, number);
}

void print_line(const char *line)
{
	fprint_line(stdout, line);
}
