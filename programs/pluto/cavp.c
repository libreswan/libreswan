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

#include <stdio.h>
/* #include <stdbool.h> */
#include <string.h>
#include <stdlib.h>

#include "constants.h"
#include "lswalloc.h"
#include "lswnss.h"
#include "ike_alg.h"
#include "crypto.h"
#include "crypt_dbg.h"
#include "crypt_symkey.h"
#include "test_buffer.h"

#include "cavp.h"
#include "cavp_print.h"
#include "cavp_ikev1.h"
#include "cavp_ikev2.h"


struct cavp *cavps[] = {
	&cavp_ikev1_sig,
	&cavp_ikev1_psk,
	&cavp_ikev2,
	NULL
};

#define BUF_SIZE 4096

static struct cavp_entry *lookup_entry(struct cavp_entry *entries, const char *key)
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

static struct cavp *cavp;

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
			cavp->print_config();
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
			cavp->run();
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

const struct hash_desc *hasher;
char hasher_name[BUF_SIZE];

void hash(struct cavp_entry *entry,
	  const char *value UNUSED)
{
	strcpy(hasher_name, entry->key);
	hasher = ike_alg_get_hasher(entry->value);
	if (hasher == NULL) {
		fprintf(stderr, "hasher %s not found\n", entry->key);
	}
}

void chunk(struct cavp_entry *entry,
	   const char *value)
{
	freeanychunk(*(entry->chunk));
	*(entry->chunk) = decode_hex_to_chunk(entry->key, value);
}

void symkey(struct cavp_entry *entry,
	    const char *value)
{
	free_any_symkey(__func__, entry->symkey);
	chunk_t chunk = decode_hex_to_chunk(entry->key, value);
	*(entry->symkey) = chunk_to_symkey(CKM_DH_PKCS_DERIVE, chunk);
	freeanychunk(chunk);
}

void number(struct cavp_entry *entry,
	    const char *value)
{
	*(entry->number) = atoi(value);
}

void ignore(struct cavp_entry *entry UNUSED,
	    const char *value UNUSED)
{
}

static void cavp_parser()
{
	char line[BUF_SIZE];
	for (;;) {
		if (fgets(line, sizeof(line), stdin) == NULL) {
			int error = ferror(stdin);
			if (error != 0) {
				fprintf(stderr, "Unexpected error: %s\n",
					strerror(error));
				exit(1);
			}
			break;
		}
		/* trim trailing cr/nl. */
		int last = strlen(line) - 1;
		while (last >= 0 && strchr("\r\n", line[last]) != NULL) {
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
			print_line(line);
		} else if (line[0] == '#') {
			/* # .... comment */
			if (cavp == NULL) {
				struct cavp **cavpp;
				for (cavpp = cavps; *cavpp != NULL; cavpp++) {
					if (strstr(line, (*cavpp)->description) != NULL) {
						cavp = *cavpp;
						fprintf(stderr, "\ntest: %s (guess)\n\n", cavp->description);
						break;
					}
				}
			}
			print_line(line);
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
			struct cavp_entry *entry = lookup_entry(cavp->config, key);
			if (entry == NULL) {
				fprintf(stderr, "unknown config entry: ['%s' = '%s']\n", key, value);
				exit(1);
			}
			entry->op(entry, value);
		} else if (eq != NULL) {
			next_state(DATA);
			*(eq - 1) = '\0';
			char *key = line;
			char *value = eq + 2;
			struct cavp_entry *entry = lookup_entry(cavp->data, key);
			if (entry == NULL) {
				fprintf(stderr, "unknown data entry: '%s' = '%s'\n", key, value);
				exit(1);
			}
			entry->op(entry, value);
		} else {
			fprintf(stderr, "bad line: '%s'\n", line);
		}
	}
}

static void usage(void)
{
	fprintf(stderr, "Usage: cavp [ -OPTION ] <test-vector>|-\n");
	struct cavp **cavpp;
	for (cavpp = cavps; *cavpp != NULL; cavpp++) {
		fprintf(stderr, "\t-%s\t%s\n", (*cavpp)->alias, (*cavpp)->description);
	}
}

int main(int argc, char *argv[])
{
	if (argc <= 1) {
		usage();
		exit(1);
	}
	char **argp = argv + 1;

	/* a -XXX option? */
	if ((*argp)[0] == '-' && (*argp)[1] != '\0') {
		struct cavp **cavpp;
		for (cavpp = cavps; *cavpp != NULL; cavpp++) {
			if (strcmp(argv[1]+1, (*cavpp)->alias) == 0) {
				cavp = *cavpp;
				fprintf(stderr, "test: %s\n", cavp->description);
				break;
			}
		}
		if (cavp == NULL) {
			fprintf(stderr, "Unknown test %s\n", argv[1]);
			usage();
			exit(1);
		}
		argp++;
	} else {
		fprintf(stderr, "Guessing test type ...\n");
	}

	if (*argp == NULL) {
		fprintf(stderr, "missing test file\n");
		usage();
		exit(1);
	}
	if (strcmp(*argp, "-") == 0) {
		fprintf(stderr, "Reading from stdin\n");
	} else {
		fprintf(stderr, "reading from %s\n", *argp);
		if (freopen(*argp, "r", stdin) == NULL) {
			perror("freopen");
			exit(1);
		}
	}
	argp++;

	if (*argp != NULL) {
		fprintf(stderr, "unexpected %s", *argp);
		usage();
		exit(1);
	}

	setbuf(stdout, NULL);

	lsw_nss_buf_t err;
	if (!lsw_nss_setup(NULL, 0, NULL, err)) {
		fprintf(stderr, "unexpected %s\n", err);
		exit(1);
	}

	init_crypto();

	cavp_parser();

	lsw_nss_shutdown();
	return 0;
}
