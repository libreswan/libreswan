/*
 * Parse CAVP test vectors, for libreswan
 *
 * Copyright (C) 2015-2017, Andrew Cagney <cagney@gnu.org>
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
#include <regex.h>

#include "constants.h"
#include "lswlog.h"
#include "lswalloc.h"
#include "lswnss.h"
#include "lswfips.h"
#include "ike_alg.h"
#include "crypt_symkey.h"
#include "test_buffer.h"

#include "cavp.h"
#include "cavp_print.h"
#include "cavp_ikev1.h"
#include "cavp_ikev2.h"
#include "cavp_sha.h"
#include "cavp_hmac.h"
#include "cavp_gcm.h"

struct cavp *cavps[] = {
	&cavp_ikev1_sig,
	&cavp_ikev1_psk,
	&cavp_ikev2,
	&cavp_sha_msg,
	&cavp_sha_monte,
	&cavp_hmac,
	&cavp_gcm,
	NULL
};

static struct cavp_entry *lookup_entry(struct cavp_entry *entries, const char *key)
{
	struct cavp_entry *entry;
	for (entry = entries; entry->key != NULL; entry++) {
		if (strcmp(entry->key, key) == 0) {
			break;
		}
	}
	return entry;
}

enum what { HEADER, BODY, BLANK, CONFIG, DATA, IDLE, END } state = HEADER;

const char *const whats[] = {
	"HEADER", "BODY", "BLANK", "CONFIG", "DATA", "IDLE", "END",
};

static void error_state(enum what state, enum what what,
			const char *message)
{
	fprintf(stderr, "\nbad state transition from %s(%d) to %s(%d)\n%s\n",
		whats[state], state, whats[what], what, message);
	exit(1);
}

static struct cavp *cavp;

static void next_state(enum what what)
{
	switch (state) {
	case HEADER:
		switch (what) {
		case BODY:
			state = what;
			break;
		default:
			error_state(state, what,
				    "expecting header containing file type");
		}
		break;
	case BODY:
		switch (what) {
		case CONFIG:
			state = CONFIG;
			break;
		case BLANK:
			break;
		default:
			error_state(state, what, "expecting config section");
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
			error_state(state, what, "expecting data section");
		}
		break;
	case DATA:
		switch (what) {
		case DATA:
			break;
		case BLANK:
			cavp->run();
			state = IDLE;
			break;
		case END:
			cavp->run();
			state = END;
			break;
		default:
			error_state(state, what, "expecting EOF or CONFIG section");
		}
		break;
	case IDLE:
		switch (what) {
		case CONFIG:
			state = CONFIG;
			break;
		case DATA:
			state = DATA;
			break;
		case END:
			state = END;
			break;
		case BLANK:
			break;
		default:
			error_state(state, what, "expecting config section");
		}
		break;
	default:
		error_state(state, what, "expecting the unexpected");
		break;
	}
}

const struct prf_desc *prf;
const char *prf_name;

void op_entry(struct cavp_entry *entry,
	      const char *value UNUSED)
{
	*(entry->entry) = entry;
}

void op_chunk(struct cavp_entry *entry,
	      const char *value)
{
	if (entry->chunk == NULL) {
		fprintf(stderr, "missing chunk for '%s'\n", entry->key);
		exit(1);
	}
	freeanychunk(*(entry->chunk));
	*(entry->chunk) = decode_hex_to_chunk(entry->key, value);
}

void op_symkey(struct cavp_entry *entry,
	       const char *value)
{
	release_symkey(__func__, "entry", entry->symkey);
	chunk_t chunk = decode_hex_to_chunk(entry->key, value);
	*(entry->symkey) = symkey_from_chunk("symkey", DBG_CRYPT,
					     chunk);
	freeanychunk(chunk);
}

void op_signed_long(struct cavp_entry *entry,
		    const char *value)
{
	*(entry->signed_long) = strtol(value, NULL, 10);
}

void op_unsigned_long(struct cavp_entry *entry,
		      const char *value)
{
	*(entry->unsigned_long) = strtoul(value, NULL, 10);
}

void op_ignore(struct cavp_entry *entry UNUSED,
	       const char *value UNUSED)
{
}

struct fields {
	char *key;
	char *value;
};

static struct fields parse_fields(char *line)
{
	struct fields fields = {
		.key = line,
	};
	char *eq = strchr(line, '=');
	if (eq != NULL) {
		char *ke = eq;
		while (ke > fields.key && ke[-1] == ' ') {
			ke--;
		}
		*ke = '\0';
	}
	if (eq == NULL) {
		fields.value = NULL;
	} else {
		fields.value = eq + 1;
		while (*fields.value == ' ') {
			fields.value++;
		}
	}
	return fields;
}

/* size is arbitrary */
static char line[65536];
static int line_nr;

static void cavp_parser()
{
	for (;;) {
		line_nr++;
		if (fgets(line, sizeof(line), stdin) == NULL) {
			int error = ferror(stdin);
			if (error != 0) {
				fprintf(stderr, "unexpected error at line %d: %s(%d)\n",
					line_nr, strerror(error), error);
				exit(1);
			}
			break;
		}
		if (strlen(line) >= sizeof(line) - 1) {
			fprintf(stderr, "line %d exceeded buffer length of %zu: %s\n",
				line_nr, sizeof(line), line);
			exit(1);
		}
		/* trim trailing cr/nl. */
		int last = strlen(line) - 1;
		while (last >= 0 && strchr("\r\n", line[last]) != NULL) {
			last--;
		}
		line[last + 1] = '\0';
		/* break the line up */
		if (line[0] == '\0') {
			next_state(BLANK);
			/* blank */
			print_line(line);
		} else if (line[0] == '#') {
			/* # .... comment */
			if (cavp == NULL) {
				for (struct cavp **cavpp = cavps;
				     cavp == NULL && *cavpp != NULL;
				     cavpp++) {
					for (const char **match = (*cavpp)->match;
					     cavp == NULL && *match != NULL;
					     match++) {
						regex_t regex;
						if (regcomp(&regex, *match, REG_EXTENDED)) {
							fprintf(stderr, "bad regex %s\n", *match);
							exit(1);
						}
						if (regexec(&regex, line, 0, NULL, 0) == 0) {
							cavp = *cavpp;
							fprintf(stderr, "\ntest: %s (header matched '%s')\n\n",
								cavp->description, *match);
							next_state(BODY);
						}
						regfree(&regex);
					}
				}
			}
			print_line(line);
		} else if (line[0] == '[') {
			next_state(CONFIG);
			/* "[" <key> [ " "* "=" " "* <value> ] "]" */
			char *rparen = strchr(line, ']');
			*rparen = '\0';
			struct fields fields = parse_fields(line + 1);
			struct cavp_entry *entry = lookup_entry(cavp->config, fields.key);
			if (entry->key == NULL) {
				fprintf(stderr, "unknown config entry: ['%s' = '%s']\n",
					fields.key, fields.value);
				exit(1);
			} else if (entry->op == NULL) {
				fprintf(stderr, "ignoring config entry: ['%s' = '%s']\n",
					fields.key, fields.value);
			} else {
				entry->op(entry, fields.value);
			}
		} else {
			next_state(DATA);
			struct fields fields = parse_fields(line);
			struct cavp_entry *entry = lookup_entry(cavp->data, fields.key);
			if (entry->key == NULL) {
				fprintf(stderr, "unknown data entry: '%s' = '%s'\n",
					fields.key, fields.value);
				exit(1);
			} else if (entry->op == NULL) {
				fprintf(stderr, "ignoring data entry: '%s' = '%s'\n",
					fields.key, fields.value);
			} else {
				entry->op(entry, fields.value);
			}
		}
	}
	next_state(END);
}

static void usage(void)
{
	fprintf(stderr, "Usage:\n\n");
	fprintf(stderr, "    cavp [ -TEST ] <test-vector>|-\n\n");
	fprintf(stderr, "Where -TEST specifies the test type:\n\n");
	for (struct cavp **cavpp = cavps; *cavpp != NULL; cavpp++) {
		fprintf(stderr, "    -%-8s %s\n",
			(*cavpp)->alias,
			(*cavpp)->description);
	}
	fprintf(stderr, "\n");
	fprintf(stderr, "If -TEST is omitted then the test type is determined from the\n");
	fprintf(stderr, "file header by matching one of the patterns:\n\n");
	for (struct cavp **cavpp = cavps; *cavpp != NULL; cavpp++) {
		const char *sep = (*cavpp)->alias;
		for (const char **matchp = (*cavpp)->match; *matchp; matchp++) {
			fprintf(stderr, "    %-8s  '%s'\n", sep, *matchp);
			sep = "";
		}
	}
}

int main(int argc, char *argv[])
{
	tool_init_log(argv[0]);

	if (argc <= 1) {
		usage();
		exit(1);
	}
	char **argp = argv + 1;

	/* a -XXX option? */
	while ((*argp)[0] == '-') {
		if (strcmp(*argp, "--") == 0) {
			argp++;
			break;
		} else if (strcmp(*argp, "-fips") == 0) {
			argp++;
			lsw_set_fips_mode(LSW_FIPS_ON);
		} else {
			struct cavp **cavpp;
			for (cavpp = cavps; *cavpp != NULL; cavpp++) {
				if (strcmp(argv[1]+1, (*cavpp)->alias) == 0) {
					cavp = *cavpp;
					next_state(BODY);
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
		}
	}
	if (cavp == NULL) {
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

	ike_alg_init();

	cavp_parser();

	lsw_nss_shutdown();
	exit(0);
}
