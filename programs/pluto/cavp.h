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

struct cavp_entry {
	const char *key;
	void (*op)(struct cavp_entry *key, const char *value);
	chunk_t *chunk;
	PK11SymKey **symkey;
	int *number;
	struct hash_desc **hasher;
	int value;
};

struct cavp {
	const char *alias;
	const char *description;
	void (*print_config)(void);
	void (*run)(void);
	struct cavp_entry *config;
	struct cavp_entry *data;
};

extern const struct hash_desc *hasher;
extern char hasher_name[];
void hash(struct cavp_entry *entry, const char *value);

void ignore(struct cavp_entry *entry, const char *value);
void chunk(struct cavp_entry *entry, const char *value);
void symkey(struct cavp_entry *entry, const char *value);
void number(struct cavp_entry *entry, const char *value);
