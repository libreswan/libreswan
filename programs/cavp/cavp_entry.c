/* Parse CAVP test vectors, for libreswan (CAVP)
 *
 * Copyright (C) 2015-2018, Andrew Cagney
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

#include "test_buffer.h"
#include "crypt_symkey.h"
#include "cavp_entry.h"

void op_entry(const struct cavp_entry *entry,
	      const char *value UNUSED)
{
	*(entry->entry) = entry;
}

void op_chunk(const struct cavp_entry *entry,
	      const char *value)
{
	if (entry->chunk == NULL) {
		fprintf(stderr, "missing chunk for '%s'\n", entry->key);
		exit(1);
	}
	freeanychunk(*(entry->chunk));
	*(entry->chunk) = decode_hex_to_chunk(entry->key, value);
}

void op_symkey(const struct cavp_entry *entry,
	       const char *value)
{
	release_symkey(__func__, "entry", entry->symkey);
	chunk_t chunk = decode_hex_to_chunk(entry->key, value);
	*(entry->symkey) = symkey_from_chunk("symkey", chunk);
	freeanychunk(chunk);
}

void op_signed_long(const struct cavp_entry *entry,
		    const char *value)
{
	*(entry->signed_long) = strtol(value, NULL, 10);
}

void op_unsigned_long(const struct cavp_entry *entry,
		      const char *value)
{
	*(entry->unsigned_long) = strtoul(value, NULL, 10);
}

void op_ignore(const struct cavp_entry *entry UNUSED,
	       const char *value UNUSED)
{
}

const struct cavp_entry *cavp_entry_by_key(const struct cavp_entry *entries,
						  const char *key)
{
	const struct cavp_entry *entry;
	for (entry = entries; entry->key != NULL; entry++) {
		if (strcmp(entry->key, key) == 0) {
			return entry;
		}
	}
	return NULL;
}

const struct cavp_entry *cavp_entry_by_opt(const struct cavp_entry *entries, const char *opt)
{
	for (const struct cavp_entry *entry = entries; entry->key != NULL; entry++) {
		if (entry->opt != NULL && strcasecmp(entry->opt, opt) == 0) {
			return entry;
		}
	}
	return NULL;
}
