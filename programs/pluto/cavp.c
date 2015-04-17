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

#include <stdio.h>
/* #include <stdbool.h> */
#include <string.h>
#include <stdlib.h>

#include "constants.h"
#include "lswalloc.h"
#include "ike_alg.h"
#include "crypto.h"
#include "crypt_symkey.h"
#include "test_buffer.h"

#include "cavp.h"

const char crlf[] = "\r\n";

struct cavp_entry {
	const char *key;
	void (*op)(struct cavp_entry *key, const char *value);
	chunk_t *chunk;
	PK11SymKey **symkey;
	int val;
};

static struct cavp_entry *lookup(struct cavp_entry *entries, const char *key)
{
	struct cavp_entry *entry;
	for (entry = entries; entry->op != NULL; entry++) {
		if (strcmp(entry->key, key) == 0) {
			return entry;
		}
	}
	return NULL;
}

enum what { INITIAL, BLANK, CONFIG, DATA, RUN, FINAL } state = INITIAL;

static void error_state(enum what state, enum what what)
{
	fprintf(stderr, "bad state %d what %d\n", state, what);
	exit(1);
}

static void next_state(enum what what)
{
	switch (state) {
	case INITIAL:
		switch (what) {
		case CONFIG:
			state = CONFIG;
			break;
		case BLANK:
			break;
		default:
			error_state(state, what);
		}
		break;
	case CONFIG:
		switch (what) {
		case CONFIG:
			break;
		case BLANK:
			state = DATA;
			break;
		default:
			error_state(state, what);
		}
		break;
	case DATA:
		switch (what) {
		case DATA:
			break;
		case BLANK:
			cavp_run();
			state = RUN;
			break;
		default:
			error_state(state, what);
		}
		break;
	case RUN:
		switch (what) {
		case CONFIG:
			state = CONFIG;
			break;
		case DATA:
			state = DATA;
			break;
		case BLANK:
			break;
		default:
			error_state(state, what);
		}
		break;
	default:
		error_state(state, what);
		break;
	}
}

static void print_config(struct cavp_entry *key,
			 const char *value)
{
	if (value) {
		printf("[%s = %s]%s", key->key, value, crlf);
	} else {
		printf("[%s]%s", key->key, crlf);
	}
}

static void hash(struct cavp_entry *entry,
		 const char *value UNUSED)
{
	cavp_config.hasher = ike_alg_get_hasher(entry->val);
	if (cavp_config.hasher != NULL) {
		printf("[%s]%s", entry->key, crlf);
	} else {
		fprintf(stderr, "hasher %s not found\n", entry->key);
	}
}

static struct cavp_entry config_entries[] = {
	{ .key = "SHA-1", .op = hash, .val = OAKLEY_SHA1 },
	{ .key = "SHA-224", .op = hash, .val = 0 },
	{ .key = "SHA-256", .op = hash, .val = OAKLEY_SHA2_256 },
	{ .key = "SHA-384", .op = hash, .val = OAKLEY_SHA2_384 },
	{ .key = "SHA-512", .op = hash, .val = OAKLEY_SHA2_512 },
	{ .key = "Ni length", .op = print_config },
	{ .key = "Nr length", .op = print_config },
	{ .key = "pre-shared-key length", .op = print_config },
	{ .key = "g^xy length", .op = print_config },
	{ .key = NULL }
};

static void print_data(struct cavp_entry *entry,
		       const char *value)
{
	printf("%s = %s%s", entry->key, value, crlf);
}

static void chunk(struct cavp_entry *entry,
		  const char *value)
{
	freeanychunk(*(entry->chunk));
	*(entry->chunk) = decode_hex_to_chunk(entry->key, value);
	print_chunk(entry->key, *(entry->chunk), 0);
}

static void symkey(struct cavp_entry *entry,
		   const char *value)
{
	if (*(entry->symkey) != NULL) {
		PK11_FreeSymKey(*(entry->symkey));
	}
	chunk_t chunk = decode_hex_to_chunk(entry->key, value);
	*(entry->symkey) = chunk_to_key(CKM_DH_PKCS_DERIVE, chunk);
	freeanychunk(chunk);
	print_symkey(entry->key, *(entry->symkey), 0);
}

static void ignore(struct cavp_entry *entry UNUSED,
		   const char *value UNUSED)
{
	fprintf(stderr, "'%s' = '%s'%s", entry->key, value, crlf);
}

static struct cavp_entry data_entries[] = {
	{ .key = "COUNT", .op = print_data },
	{ .key = "g^xy", .op = symkey, .symkey = &cavp_data.g_xy },
	{ .key = "Ni", .op = chunk, .chunk = &cavp_data.ni },
	{ .key = "Nr", .op = chunk, .chunk = &cavp_data.nr },
	{ .key = "CKY_I", .op = chunk, .chunk = &cavp_data.cky_i },
	{ .key = "CKY_R", .op = chunk, .chunk = &cavp_data.cky_r },
	{ .key = "pre-shared-key", .op = chunk, .chunk = &cavp_data.psk },
	{ .key = "SKEYID", .op = ignore },
	{ .key = "SKEYID_d", .op = ignore },
	{ .key = "SKEYID_a", .op = ignore },
	{ .key = "SKEYID_e", .op = ignore },
	{ .key = "SKEYID_", .op = ignore },
	{ .op = NULL }
};

static void cavp_parser()
{
	char line[2048];
	while (TRUE) {
		if (fgets(line, sizeof(line), stdin) == NULL) {
			int error = ferror(stdin);
			if (error) {
				fprintf(stderr, "Unexpected error: %s\n",
					strerror(error));
				exit(1);
			}
			break;
		}
		/* trim trailing cr/nl. */
		int last = strlen(line) - 1;
		while (last >= 0 && strchr(crlf, line[last]) != NULL) {
			last--;
		}
		line[last + 1] = '\0';
		/* break the line up */
		char *lparen = strchr(line, '[');
		char *eq = strchr(line, '=');
		char *rparen = strchr(line, ']');
		if (line[0] == '\0') {
			next_state(BLANK);
			/* blank */
			fputs(line, stdout);
			fputs(crlf, stdout);
		} else if (line[0] == '#') {
			/* # .... comment */
			fputs(line, stdout);
			fputs(crlf, stdout);
		} else if (lparen != NULL && rparen != NULL) {
			next_state(CONFIG);
			/* "[" <key> [ " = " <value> ] "]" */
			*rparen = '\0';
			char *key = lparen + 1;
			char *value;
			if (eq == NULL) {
				value = NULL;
			} else {
				value = eq + 2;
				*(eq - 1) = '\0';
			}
			struct cavp_entry *entry = lookup(config_entries, key);
			if (entry != NULL) {
				entry->op(entry, value);
			} else {
				fprintf(stderr, "['%s' = '%s']%s",
					key, value, crlf);
			}
		} else if (eq != NULL) {
			next_state(DATA);
			*(eq - 1) = '\0';
			char *key = line;
			char *value = eq + 2;
			struct cavp_entry *entry = lookup(data_entries, key);
			if (entry != NULL) {
				entry->op(entry, value);
			} else {
				fprintf(stderr, "'%s' = '%s'%s",
					key, value, crlf);
			}
		} else {
			fprintf(stderr, "bad line: '%s'\n", line);
		}
	}
}

void print_chunk(const char *prefix, chunk_t chunk, size_t binlen)
{
	printf("%s = ", prefix);
        size_t len = binlen == 0 ? chunk.len
                : binlen < chunk.len ? binlen
                : chunk.len;
        
        size_t i = 0;
        for (i = 0; i < len; i++) {
                printf("%02x", chunk.ptr[i]);
        }
        printf("%s", crlf);
}

void print_symkey(const char *prefix, PK11SymKey *key, size_t binlen)
{
        chunk_t chunk = chunk_from_symkey_bytes(prefix, key, 0,
                                                PK11_GetKeyLength(key));
	print_chunk(prefix, chunk, binlen);
        freeanychunk(chunk);
}

int main()
{
	setbuf(stdout, NULL);

	NSS_NoDB_Init(".");
        init_crypto();

	cavp_parser();
	return 0;
}
