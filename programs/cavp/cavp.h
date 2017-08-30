/*
 * Parse CAVP test vectors, for libreswan
 *
 * Copyright (C) 2015-2016, Andrew Cagney <cagney@gnu.org>
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
	/* set by the below */
	chunk_t *chunk;
	PK11SymKey **symkey;
	signed long *signed_long;
	unsigned long *unsigned_long;
	struct cavp_entry **entry;
	/* constant values */
	int value;
	const struct encrypt_desc *encrypt;
	const struct hash_desc *hash;
	const struct prf_desc *prf;
	const struct integ_desc *integ;
};

struct cavp {
	const char *alias;
	const char *description;
	void (*print_config)(void);
	void (*run)(void);
	struct cavp_entry *config;
	struct cavp_entry *data;
	const char *match[];
};

/*
 * Select the given entry
 */
void op_entry(struct cavp_entry *entry, const char *value);
void op_ignore(struct cavp_entry *entry, const char *value);
void op_chunk(struct cavp_entry *entry, const char *value);
void op_symkey(struct cavp_entry *entry, const char *value);
void op_signed_long(struct cavp_entry *entry, const char *value);
void op_unsigned_long(struct cavp_entry *entry, const char *value);
void op_boolean(struct cavp_entry *entry, const char *value);
