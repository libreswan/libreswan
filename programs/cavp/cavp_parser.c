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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>

#include "fips_mode.h"
#include "lswnss.h"

#include "cavp.h"
#include "cavps.h"
#include "cavp_entry.h"
#include "cavp_print.h"
#include "cavp_parser.h"

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

static void next_state(const struct cavp *cavp, enum what what, struct logger *logger)
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
			cavp->run_test(logger);
			state = IDLE;
			break;
		case END:
			cavp->run_test(logger);
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

void cavp_parser(const struct cavp *cavp, struct logger *logger)
{
	/* size is arbitrary */
	char line[65536] = "";
	int line_nr = 0;

	if (cavp != NULL) {
		next_state(cavp, BODY, logger);
	}

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
			next_state(cavp, BLANK, logger);
			/* blank */
			print_line(line);
		} else if (line[0] == '#') {
			/* # .... comment */
			if (cavp == NULL) {
				for (const struct cavp **cavpp = cavps;
				     cavp == NULL && *cavpp != NULL;
				     cavpp++) {
					for (const char *const *match = (*cavpp)->match;
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
							next_state(cavp, BODY, logger);
						}
						regfree(&regex);
					}
				}
			}
			print_line(line);
		} else if (line[0] == '[') {
			next_state(cavp, CONFIG, logger);
			/* "[" <key> [ " "* "=" " "* <value> ] "]" */
			char *rparen = strchr(line, ']');
			if (rparen == NULL) {
				fprintf(stderr, "unmatched \"[\" in line %d\n", line_nr);
				exit(1);
			}
			*rparen = '\0';
			struct fields fields = parse_fields(line + 1);
			const struct cavp_entry *entry = cavp_entry_by_key(cavp->config, fields.key);
			if (entry == NULL) {
				fprintf(stderr, "unknown config entry: ['%s' = '%s']\n",
					fields.key, fields.value);
				exit(1);
			} else if (entry->op == NULL) {
				fprintf(stderr, "ignoring config entry: ['%s' = '%s']\n",
					fields.key, fields.value);
			} else {
				entry->op(entry, fields.value, logger);
			}
		} else {
			next_state(cavp, DATA, logger);
			struct fields fields = parse_fields(line);
			const struct cavp_entry *entry = cavp_entry_by_key(cavp->data, fields.key);
			if (entry == NULL) {
				fprintf(stderr, "unknown data entry: '%s' = '%s'\n",
					fields.key, fields.value);
				exit(1);
			} else if (entry->op == NULL) {
				fprintf(stderr, "ignoring data entry: '%s' = '%s'\n",
					fields.key, fields.value);
			} else {
				entry->op(entry, fields.value, logger);
			}
		}
	}
	next_state(cavp, END, logger);
}
