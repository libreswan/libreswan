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
	      const char *value_unused UNUSED,
	      struct logger *logger_unused UNUSED)
{
	*(entry->entry) = entry;
}

void op_chunk(const struct cavp_entry *entry,
	      const char *value,
	      struct logger *logger_unused UNUSED)
{
	if (entry->chunk == NULL) {
		fprintf(stderr, "missing chunk for '%s'\n", entry->key);
		exit(1);
	}
	free_chunk_content(entry->chunk);
	*entry->chunk = chunk_from_hex(value, entry->key);
}

void op_symkey(const struct cavp_entry *entry,
	       const char *value,
	       struct logger *logger)
{
	symkey_delref(logger, "entry", entry->symkey);
	chunk_t chunk = chunk_from_hex(value, entry->key);
	*(entry->symkey) = symkey_from_hunk("symkey", chunk, logger);
	free_chunk_content(&chunk);
}

void op_signed_long(const struct cavp_entry *entry,
		    const char *value,
		    struct logger *logger_unused UNUSED)
{
	*(entry->signed_long) = strtol(value, NULL, 10);
}

void op_unsigned_long(const struct cavp_entry *entry,
		      const char *value,
		      struct logger *logger_unused UNUSED)
{
	*(entry->unsigned_long) = strtoul(value, NULL, 10);
}

void op_ignore(const struct cavp_entry *entry UNUSED,
	       const char *value_unused UNUSED,
	       struct logger *logger_unused UNUSED)
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
