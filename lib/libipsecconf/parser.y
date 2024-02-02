%{   /* -*- bison-mode -*- */
/* Libreswan config file parser (parser.y)
 * Copyright (C) 2001 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2004 Michael Richardson <mcr@sandelman.ottawa.on.ca>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Philippe Vouters <Philippe.Vouters@laposte.net>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#define YYDEBUG 1

#include "deltatime.h"
#include "timescale.h"
#include "binary-iec-60027-2.h"

#include "ipsecconf/keywords.h"
#include "ipsecconf/parser.h"	/* includes parser.tab.h" */
#include "ipsecconf/parser-flex.h"
#include "ipsecconf/confread.h"

#define YYERROR_VERBOSE
#define ERRSTRING_LEN	256

/**
 * Bison
 */
static char parser_errstring[ERRSTRING_LEN+1];

/**
 * Static Globals
 */
static bool save_errors;
static struct config_parsed *parser_cfg;
static struct kw_list **parser_kw, *parser_kw_last;
static void new_parser_kw(struct keyword *keyword, char *string, uintmax_t number, struct logger *logger);
static uintmax_t parser_unsigned(const char *yytext, struct logger *logger);
static uintmax_t parser_time(struct keyword *kw, const char *yytext, struct logger *logger);
static struct starter_comments_list *parser_comments;

/**
 * Functions
 */

%}

%parse-param {struct logger *logger}

%union {
	char *s;
	bool boolean;
	struct keyword k;
}
%token EQUAL FIRST_SPACES EOL CONFIG SETUP CONN INCLUDE VERSION
%token <s>      STRING
%token <boolean>   BOOLEAN
%token <k>      KEYWORD
%token <k>      BOOLWORD
%token <k>      PERCENTWORD
%token <k>      BINARYWORD
%token <k>      BYTEWORD
%token <k>      COMMENT
%%

/*
 * Config file
 */

config_file: blanklines versionstmt sections ;

/* check out the version number - this is optional (and we're phasing out its use) */
/* we have configs shipped with version 2 (UNSIGNED) and with version 2.0 (STRING, now  NUMBER/float was removed */

versionstmt: /* NULL */
	| VERSION STRING EOL blanklines
	;

blanklines: /* NULL */
	| blanklines EOL
	;

sections: /* NULL */
	| sections section_or_include blanklines
	;

section_or_include:
	CONFIG SETUP EOL {
		parser_kw = &parser_cfg->config_setup;
		parser_kw_last = NULL;
		parser_comments = &parser_cfg->comments;
		if (yydebug)
			fprintf(stderr, "\nconfig setup read\n");
	} kw_sections
	| CONN STRING EOL {
		struct section_list *section = malloc(sizeof(struct section_list));

		if (section == NULL) {
			parser_kw = NULL;
			parser_kw_last = NULL;
			yyerror(logger, "can't allocate memory in section_or_include/conn");
		} else {
			section->name = $2;
			section->kw = NULL;

			TAILQ_INSERT_TAIL(&parser_cfg->sections, section, link);

			/* setup keyword section to record values */
			parser_kw = &section->kw;
			parser_kw_last = NULL;

			/* and comments */
			TAILQ_INIT(&section->comments);
			parser_comments = &section->comments;

			if (yydebug)
				fprintf(stderr, "\nread conn %s\n", section->name);
		}
	} kw_sections
	| INCLUDE STRING EOL {
		parser_y_include($2, logger);
	}
	;

kw_sections: /* NULL */
	| kw_sections kw_section
	;

kw_section: FIRST_SPACES statement_kw EOL
	| FIRST_SPACES EOL;	/* kludge to ignore whitespace (without newline) at EOF */

statement_kw:
	KEYWORD EQUAL KEYWORD {
		struct keyword kw = $1;

		/* because the third argument was also a keyword, we dig up the string representation. */
		const char *value = $3.keydef->keyname;

		char *string = NULL;	/* neutral placeholding value */
		uintmax_t number = 0;	/* neutral placeholding value */

		switch (kw.keydef->type) {
		case kt_list:
			number = parser_enum_list(kw.keydef, value);
			break;
		case kt_lset:
			number = parser_lset(kw.keydef, value);	/* XXX: truncates! */
			break;
		case kt_enum:
			number = parser_enum(kw.keydef, value);
			break;
		case kt_pubkey:
		case kt_loose_enum:
			number = parser_loose_enum(&kw, value);
			break;
		case kt_string:
		case kt_appendstring:
		case kt_appendlist:
		case kt_filename:
		case kt_dirname:
		case kt_ipaddr:
		case kt_bitstring:
		case kt_idtype:
		case kt_range:
		case kt_subnet:
			string = strdup(value);
			break;

		case kt_bool:
		case kt_number:
		case kt_time:
		case kt_percent:
		case kt_binary:
		case kt_byte:
			yyerror(logger, "keyword value is a keyword, but type not a string");
			assert(kw.keydef->type != kt_bool);
			break;

		case kt_comment:
			break;

		case kt_obsolete:
		case kt_obsolete_quiet:
			break;
		}

		new_parser_kw(&kw, string, number, logger);
	}
	| COMMENT EQUAL STRING {
		struct starter_comments *new =
			malloc(sizeof(struct starter_comments));

		if (new == NULL) {
			yyerror(logger, "can't allocate memory in statement_kw");
		} else {
			new->x_comment = strdup($1.string);
			new->commentvalue = strdup($3);
			TAILQ_INSERT_TAIL(parser_comments, new, link);
		}
	}
	| KEYWORD EQUAL STRING {
		struct keyword kw = $1;

		char *string = NULL;	/* neutral placeholding value */
		uintmax_t number = 0;	/* neutral placeholding value */

		switch (kw.keydef->type) {
		case kt_list:
			number = parser_enum_list(kw.keydef, $3);
			break;
		case kt_lset:
			number = parser_lset(kw.keydef, $3); /* XXX: truncates! */
			break;
		case kt_enum:
			number = parser_enum(kw.keydef, $3);
			break;
		case kt_pubkey:
		case kt_loose_enum:
			number = parser_loose_enum(&kw, $3);
			break;
		case kt_string:
		case kt_appendstring:
		case kt_appendlist:
		case kt_filename:
		case kt_dirname:
		case kt_ipaddr:
		case kt_bitstring:
		case kt_idtype:
		case kt_range:
		case kt_subnet:
			string = $3;
			break;

		case kt_number:
			number = parser_unsigned($3, logger);
			break;

		case kt_time:
			number = parser_time(&$1, $3, logger);
			break;

		case kt_bool:
		case kt_percent:
		case kt_binary:
		case kt_byte:
			yyerror(logger, "valid keyword, but value is not a number");
			assert(kw.keydef->type != kt_bool);
			break;
		case kt_comment:
			break;
		case kt_obsolete:
		case kt_obsolete_quiet:
			break;
		}

		new_parser_kw(&kw, string, number, logger);
	}

	| BOOLWORD EQUAL BOOLEAN {
		new_parser_kw(&$1, NULL, $3, logger);
	}

	| PERCENTWORD EQUAL STRING {
		struct keyword kw = $1;
		const char *const str = $3;
		/*const*/ char *endptr;
		char buf[80];
		unsigned long val = (errno = 0, strtoul(str, &endptr, 10));

		if (endptr == str) {
			snprintf(buf, sizeof(buf),
				"malformed percentage %s=%s",
				kw.keydef->keyname, str);
			yyerror(logger, buf);
		} else if (!streq(endptr, "%")) {
			snprintf(buf, sizeof(buf),
				"bad percentage multiplier \"%s\" on %s",
				endptr, str);
			yyerror(logger, buf);
		} else if (errno != 0 || val > UINT_MAX) {
			snprintf(buf, sizeof(buf),
				"percentage way too large \"%s\"", str);
			yyerror(logger, buf);
		} else {
			new_parser_kw(&kw, NULL, (unsigned int)val, logger);
		}
	}
	| KEYWORD EQUAL BOOLEAN {
		new_parser_kw(&$1, NULL, $3, logger);
	}
	| KEYWORD EQUAL { /* this is meaningless, we ignore it */ }
	| BINARYWORD EQUAL STRING {
		struct keyword *kw = &$1;
		const char *const str = $3;
		uint64_t b;

		diag_t diag = ttobinary(str, &b, 0 /* no B prefix */);
		if (diag != NULL) {
			yyerror(logger, str_diag(diag));
			pfree_diag(&diag);
		} else {
			new_parser_kw(kw, NULL, b, logger);
		}
	}
	| BYTEWORD EQUAL STRING {
		struct keyword *kw = &$1;
		const char *const str = $3;
		uint64_t b;

		diag_t diag = ttobinary(str, &b, 1 /* with B prefix */);
		if (diag != NULL) {
			yyerror(logger, str_diag(diag));
			pfree_diag(&diag);
		} else {
			new_parser_kw(kw, NULL, b, logger);
		}
	}
	;
%%

void yyerror(struct logger *logger UNUSED, const char *s)
{
	if (save_errors)
		parser_y_error(parser_errstring, ERRSTRING_LEN, s);
}

struct config_parsed *parser_load_conf(const char *file,
				       starter_errors_t *perrl,
				       struct logger *logger)
{
	parser_errstring[0] = '\0';

	struct config_parsed *cfg = malloc(sizeof(struct config_parsed));

	if (cfg == NULL) {
		snprintf(parser_errstring, ERRSTRING_LEN, "can't allocate memory");
		goto err;
	}

	static const struct config_parsed empty_config_parsed;	/* zero or null everywhere */
	*cfg = empty_config_parsed;

	FILE *f = streq(file, "-") ?
		fdopen(STDIN_FILENO, "r") : fopen(file, "r");

	if (f == NULL) {
		snprintf(parser_errstring, ERRSTRING_LEN, "can't load file '%s'",
			 file);
		goto err;
	}

	yyin = f;
	parser_y_init(file, f);
	save_errors = true;
	TAILQ_INIT(&cfg->sections);
	TAILQ_INIT(&cfg->comments);
	parser_cfg = cfg;

	if (yyparse(logger) != 0) {
		if (parser_errstring[0] == '\0') {
			snprintf(parser_errstring, ERRSTRING_LEN,
				"Unknown error...");
		}
		save_errors = false;
		do {} while (yyparse(logger) != 0);
		goto err;
	}

	/* check all are kv_config */
	for (const struct kw_list *kw = parser_cfg->config_setup;
	     kw != NULL; kw = kw->next) {
		if (!(kw->keyword.keydef->validity & kv_config)) {
			snprintf(parser_errstring, sizeof(parser_errstring),
				 "unexpected keyword '%s' in section 'config setup'",
				 kw->keyword.keydef->keyname);
			goto err;
		}
	}

	/**
	 * Config valid
	 */
	return cfg;

err:
	starter_error_append(perrl, "%s", parser_errstring);

	if (cfg != NULL)
		parser_free_conf(cfg);

	return NULL;
}

static void parser_free_kwlist(struct kw_list *list)
{
	while (list != NULL) {
		struct kw_list *elt = list;

		list = list->next;
		if (elt->string != NULL)
			free(elt->string);
		free(elt);
	}
}

void parser_free_conf(struct config_parsed *cfg)
{
	if (cfg != NULL) {
		struct section_list *seci;

		parser_free_kwlist(cfg->config_setup);

		for (seci = cfg->sections.tqh_first; seci != NULL; ) {
			struct section_list *sec = seci;

			seci = seci->link.tqe_next;

			if (sec->name != NULL)
				free(sec->name);
			parser_free_kwlist(sec->kw);
			free(sec);
		}

		free(cfg);
	}
}

static void new_parser_kw(struct keyword *keyword, char *string, uintmax_t number,
			  struct logger *logger)
{
	struct kw_list *new = malloc(sizeof(struct kw_list));

	if (new == NULL) {
		yyerror(logger, "cannot allocate memory for a kw_list");
	} else {
		/*
		 * fill the values into new
		 * (either string or number might have a placeholder value
		 */
		new->keyword = *keyword;
		new->string = string;
		new->number = number;
		new->next = NULL;

		/* link the new kw_list into the list */

		if (*parser_kw == NULL)
			*parser_kw = new;	/* first in (some) list */

		/* connect to previous last on list */
		if (parser_kw_last != NULL)
			parser_kw_last->next = new;

		/* new is new last on list */
		parser_kw_last = new;
	}
}

uintmax_t parser_unsigned(const char *yytext, struct logger *logger)
{
	uintmax_t number;
	err_t err = shunk_to_uintmax(shunk1(yytext), NULL, /*base*/10, &number);
	if (err != NULL) {
		char ebuf[128];
		snprintf(ebuf, sizeof(ebuf),
			 "%s: %s", err, yytext);
		yyerror(logger, ebuf);
	}
	return number;
}

uintmax_t parser_time(struct keyword *kw, const char *str, struct logger *logger)
{
	const struct timescale *scale;
	if (kw->keydef->validity & kv_milliseconds) {
		scale = &timescale_milliseconds;
	} else {
		scale = &timescale_seconds;
	}
	deltatime_t d;
	diag_t diag = ttodeltatime(str, &d, scale);
	if (diag != NULL) {
		yyerror(logger, str_diag(diag));
		pfree_diag(&diag);
	}
	return deltamillisecs(d);
}
