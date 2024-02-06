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
#include "lswlog.h"

#define YYERROR_VERBOSE
#define ERRSTRING_LEN	256

/**
 * Static Globals
 */
static bool save_errors;

static struct parser {
	struct config_parsed *cfg;
	struct kw_list **kw;
	enum section { SECTION_CONFIG_SETUP, SECTION_CONN_DEFAULT, SECTION_CONN, } section;
	struct starter_comments_list *comments;
} parser;

static void parser_kw_warning(struct logger *logger, struct keyword *kw, const char *yytext,
			      const char *s, ...) PRINTF_LIKE(4);
static void new_parser_kw(struct keyword *keyword, const char *string, uintmax_t number, struct logger *logger);

static bool parser_kw_unsigned(struct keyword *kw, const char *yytext,
			       uintmax_t *number, struct logger *logger);
static bool parser_kw_bool(struct keyword *kw, const char *yytext,
			   uintmax_t *number, struct logger *logger);
static bool parser_kw_time(struct keyword *kw, const char *yytext,
			   uintmax_t *number, struct logger *logger);

/**
 * Functions
 */

%}

%param {struct logger *logger}

%union {
	char *s;
	bool boolean;
	struct keyword k;
}
%token EQUAL FIRST_SPACES EOL CONFIG SETUP CONN INCLUDE VERSION
%token <s>      STRING
%token <k>      KEYWORD
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
		parser.kw = &parser.cfg->config_setup;
		parser.section = SECTION_CONFIG_SETUP;
		parser.comments = &parser.cfg->comments;
		ldbg(logger, "%s", "");
		ldbg(logger, "reading config setup");
	} kw_sections
	| CONN STRING EOL {
		struct section_list *section = malloc(sizeof(struct section_list));
		PASSERT(logger, section != NULL);

		section->name = $2;
		section->kw = NULL;

		TAILQ_INSERT_TAIL(&parser.cfg->sections, section, link);

		/* setup keyword section to record values */
		parser.kw = &section->kw;
		parser.section = (streq(section->name, "%default") ? SECTION_CONN_DEFAULT :
				  SECTION_CONN);

		/* and comments */
		TAILQ_INIT(&section->comments);
		parser.comments = &section->comments;

		ldbg(logger, "%s", "");
		ldbg(logger, "reading conn %s", section->name);

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

		const char *string = NULL;	/* neutral placeholding value */
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
			string = value;
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
		case kt_obsolete:
			break;
		}

		new_parser_kw(&kw, string, number, logger);
	}
	| COMMENT EQUAL STRING {
		struct starter_comments *new =
			malloc(sizeof(struct starter_comments));
		PASSERT(logger, new != NULL);

		new->x_comment = strdup($1.string);
		new->commentvalue = strdup($3);
		TAILQ_INSERT_TAIL(parser.comments, new, link);
	}
	| KEYWORD EQUAL STRING {
		struct keyword kw = $1;

		const char *string = $3;	/* neutral placeholding value */
		uintmax_t number = 0;		/* neutral placeholding value */
		bool ok = true;

		switch (kw.keydef->type) {
		case kt_list:
			number = parser_enum_list(kw.keydef, string);
			break;
		case kt_lset:
			number = parser_lset(kw.keydef, string); /* XXX: truncates! */
			break;
		case kt_enum:
			number = parser_enum(kw.keydef, string);
			break;
		case kt_pubkey:
		case kt_loose_enum:
			number = parser_loose_enum(&kw, string);
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
			break;

		case kt_number:
			ok = parser_kw_unsigned(&kw, string, &number, logger);
			break;

		case kt_time:
			ok = parser_kw_time(&kw, string, &number, logger);
			break;

		case kt_bool:
			ok = parser_kw_bool(&kw, string, &number, logger);
			break;

		case kt_percent:
		case kt_binary:
		case kt_byte:
			yyerror(logger, "valid keyword, but value is not a number");
			break;

		case kt_comment:
		case kt_obsolete:
			break;
		}

		if (ok) {
			new_parser_kw(&kw, string, number, logger);
		}

	}

	| PERCENTWORD EQUAL STRING {
		struct keyword kw = $1;
		const char *const str = $3;
		/*const*/ char *endptr;
		unsigned long val = (errno = 0, strtoul(str, &endptr, 10));

		if (endptr == str) {
			yyerror(logger, "malformed percentage %s=%s",
				kw.keydef->keyname, str);
		} else if (!streq(endptr, "%")) {
			yyerror(logger, "bad percentage multiplier \"%s\" on %s",
				endptr, str);
		} else if (errno != 0 || val > UINT_MAX) {
			yyerror(logger, "percentage way too large \"%s\"", str);
		} else {
			new_parser_kw(&kw, NULL, (unsigned int)val, logger);
		}
	}
	| KEYWORD EQUAL { /* this is meaningless, we ignore it */ }
	| BINARYWORD EQUAL STRING {
		struct keyword *kw = &$1;
		const char *const str = $3;
		uint64_t b;

		diag_t diag = ttobinary(str, &b, 0 /* no B prefix */);
		if (diag != NULL) {
			yyerror(logger, "%s", str_diag(diag));
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
			yyerror(logger, "%s", str_diag(diag));
			pfree_diag(&diag);
		} else {
			new_parser_kw(kw, NULL, b, logger);
		}
	}
	;
%%

void parser_kw_warning(struct logger *logger, struct keyword *kw, const char *yytext,
		       const char *s, ...)
{
	if (save_errors) {
		LLOG_JAMBUF(RC_LOG, logger, buf) {
			jam(buf, "%s:%u: warning: ",
			    parser_cur_filename(),
			    parser_cur_line());
			va_list ap;
			va_start(ap, s);
			jam_va_list(buf, s, ap);
			va_end(ap);
			jam_string(buf, ": ");
			if (kw->keyleft && !kw->keyright) {
				jam_string(buf, "left");
			}
			if (!kw->keyleft && kw->keyright) {
				jam_string(buf, "right");
			}
			jam_string(buf, kw->keydef->keyname);
			jam_string(buf, "=");
			jam_string(buf, yytext);
		}
	}
}

void yyerror(struct logger *logger UNUSED, const char *s, ...)
{
	if (save_errors) {
		LLOG_JAMBUF(RC_LOG, logger, buf) {
			jam(buf, "%s:%u: ",
			    parser_cur_filename(),
			    parser_cur_line());
			va_list ap;
			va_start(ap, s);
			jam_va_list(buf, s, ap);
			va_end(ap);
		}
	}
}

struct config_parsed *parser_load_conf(const char *file,
				       struct logger *logger)
{
	parser.cfg = malloc(sizeof(struct config_parsed));
	PASSERT(logger, parser.cfg != NULL);

	FILE *f = streq(file, "-") ?
		fdopen(STDIN_FILENO, "r") : fopen(file, "r");

	if (f == NULL) {
		llog(RC_LOG, logger, "can't load file '%s'", file);
		goto err;
	}

	yyin = f;
	parser_y_init(file, f);
	save_errors = true;
	TAILQ_INIT(&parser.cfg->sections);
	TAILQ_INIT(&parser.cfg->comments);

	if (yyparse(logger) != 0) {
		save_errors = false;
		do {} while (yyparse(logger) != 0);
		goto err;
	}

	/**
	 * Config valid
	 */
	struct config_parsed *cfg = parser.cfg;
	parser.cfg = NULL;
	return cfg;

err:
	if (parser.cfg != NULL)
		parser_free_conf(parser.cfg);

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

static void new_parser_kw(struct keyword *keyword,
			  const char *string,
			  uintmax_t number,
			  struct logger *logger)
{
	/* both means no prefix */
	const char *leftright =
		(keyword->keyleft && keyword->keyright ? "" :
		 keyword->keyleft ? "left" :
		 keyword->keyright ? "right" :
		 "");
	const char *section = "???";
	const char *eqs = (string == NULL ? "" : "=");
	const char *value = (string == NULL ? "" : string);
	switch (parser.section) {
	case SECTION_CONFIG_SETUP:
		section = "'config setup'";
		if ((keyword->keydef->validity & kv_config) == LEMPTY) {
			yyerror(logger, "warning: invalid %s keyword ignored: %s%s%s%s",
				section, leftright, keyword->keydef->keyname, eqs, value);
			/* drop it on the floor */
			return;
		}
		break;
	case SECTION_CONN:
		section = "conn";
		if ((keyword->keydef->validity & kv_conn) == LEMPTY) {
			yyerror(logger, "warning: invalid %s keyword ignored: %s%s%s%s",
				section, leftright, keyword->keydef->keyname, eqs, value);
			/* drop it on the floor */
			return;
		}
		break;
	case SECTION_CONN_DEFAULT:
		section = "'conn %%default'";
		if ((keyword->keydef->validity & kv_conn) == LEMPTY ||
		    keyword->keydef->field == KSCF_ALSO) {
			yyerror(logger, "warning: invalid %s keyword ignored: %s%s%s%s",
				section, leftright, keyword->keydef->keyname, eqs, value);
			/* drop it on the floor */
			return;
		}
		break;
	}

	if (keyword->keydef->type == kt_obsolete) {
		yyerror(logger, "warning: obsolete %s keyword ignored: %s%s%s%s",
			section, leftright, keyword->keydef->keyname, eqs, value);
		/* drop it on the floor */
		return;
	}

	/* Find end, while looking for duplicates. */
	struct kw_list **end;
	for (end = parser.kw; (*end) != NULL; end = &(*end)->next) {
		if ((*end)->keyword.keydef != keyword->keydef) {
			continue;
		}
		if (((*end)->keyword.keyleft != keyword->keyleft) &&
		    ((*end)->keyword.keyright != keyword->keyright)) {
			continue;
		}
		if (keyword->keydef->validity & kv_duplicateok) {
			continue;
		}
		yyerror(logger, "warning: overriding earlier %s keyword: %s%s%s%s",
			section, leftright, keyword->keydef->keyname, eqs, value);
		/* ulgh; not pfree()/clone_str() */
		free((*end)->string);
		(*end)->string = (string != NULL ? strdup(string) : NULL);
		(*end)->number = number;
		return;
	}

	/*
	 * fill the values into new
	 * (either string or number might have a placeholder value
	 */
	struct kw_list *new = malloc(sizeof(struct kw_list));
	PASSERT(logger, new != NULL);
	(*new) = (struct kw_list) {
		.keyword = *keyword,
		.string = (string != NULL ? strdup(string) : NULL),
		.number = number,
	};

	/* append the new kw_list to the list */
	(*end) = new;
}

bool parser_kw_unsigned(struct keyword *kw, const char *yytext,
			uintmax_t *number, struct logger *logger)
{
	err_t err = shunk_to_uintmax(shunk1(yytext), NULL, /*base*/10, number);
	if (err != NULL) {
		parser_kw_warning(logger, kw, yytext, "%s, keyword ignored", err);
		return false;
	}
	return true;
}

bool parser_kw_bool(struct keyword *kw, const char *yytext,
		    uintmax_t *number, struct logger *logger)
{
	const struct sparse_name *name = sparse_lookup(yn_option_names, yytext);
	if (name == NULL) {
		parser_kw_warning(logger, kw, yytext, "invalid boolean, keyword ignored");
		return false;
	}
	enum yn_options yn = name->value;
	switch (yn) {
	case YN_YES:
		(*number) = true;
		return true;
	case YN_NO:
		(*number) = false;
		return true;
	case YN_UNSET:
		break;
	}
	bad_case(yn);
}

bool parser_kw_time(struct keyword *kw, const char *yytext,
		    uintmax_t *number, struct logger *logger)
{
	const struct timescale *scale;
	if (kw->keydef->validity & kv_milliseconds) {
		scale = &timescale_milliseconds;
	} else {
		scale = &timescale_seconds;
	}
	deltatime_t d;
	diag_t diag = ttodeltatime(yytext, &d, scale);
	if (diag != NULL) {
		parser_kw_warning(logger, kw, yytext, "%s, keyword ignored", str_diag(diag));
		pfree_diag(&diag);
		return false;
	}
	(*number) = deltamillisecs(d);
	return true;
}
