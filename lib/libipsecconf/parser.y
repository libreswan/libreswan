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
#include "lmod.h"

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

void parser_kw(struct keyword *kw, const char *string, struct logger *logger);

static void yyerror(struct logger *logger, const char *msg);
static void new_parser_kw(struct keyword *keyword, const char *string, uintmax_t number, struct logger *logger);

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
		/*
		 * Because the third argument was also a keyword, we
		 * dig up the string representation.
		 *
		 * There should be a way to stop the lexer converting
		 * the third field into a keyword.
		 */
		struct keyword kw = $1;
		const char *value = $3.keydef->keyname;
		parser_kw(&kw, value, logger);
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
		const char *string = $3;
		parser_kw(&kw, string, logger);
	}
	| KEYWORD EQUAL {
		struct keyword kw = $1;
		parser_kw(&kw, "", logger);
	}
	;
%%

void parser_warning(struct logger *logger, int error, const char *s, ...)
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
			if (error > 0) {
				jam_errno(buf, error);
			}
		}
	}
}

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

void yyerror(struct logger *logger, const char *s)
{
	if (save_errors) {
		LLOG_JAMBUF(RC_LOG, logger, buf) {
			jam(buf, "%s:%u: ",
			    parser_cur_filename(),
			    parser_cur_line());
			jam_string(buf, s);
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

static void new_parser_kw(struct keyword *kw,
			  const char *yytext,
			  uintmax_t number,
			  struct logger *logger)
{
	/* both means no prefix */
	const char *section = "???";
	switch (parser.section) {
	case SECTION_CONFIG_SETUP:
		section = "'config setup'";
		if ((kw->keydef->validity & kv_config) == LEMPTY) {
			parser_kw_warning(logger, kw, yytext,
					  "invalid %s keyword ignored",
					  section);
			/* drop it on the floor */
			return;
		}
		break;
	case SECTION_CONN:
		section = "conn";
		if ((kw->keydef->validity & kv_conn) == LEMPTY) {
			parser_kw_warning(logger, kw, yytext,
					  "invalid %s keyword ignored", section);
			/* drop it on the floor */
			return;
		}
		break;
	case SECTION_CONN_DEFAULT:
		section = "'conn %%default'";
		if ((kw->keydef->validity & kv_conn) == LEMPTY ||
		    kw->keydef->field == KSCF_ALSO) {
			parser_kw_warning(logger, kw, yytext,
					  "invalid %s keyword ignored", section);
			/* drop it on the floor */
			return;
		}
		break;
	}

	/* Find end, while looking for duplicates. */
	struct kw_list **end;
	for (end = parser.kw; (*end) != NULL; end = &(*end)->next) {
		if ((*end)->keyword.keydef != kw->keydef) {
			continue;
		}
		if (((*end)->keyword.keyleft != kw->keyleft) &&
		    ((*end)->keyword.keyright != kw->keyright)) {
			continue;
		}
		if (kw->keydef->validity & kv_duplicateok) {
			continue;
		}
		/* note the weird behaviour! */
		if (parser.section == SECTION_CONFIG_SETUP) {
			parser_kw_warning(logger, kw, yytext,
					  "overriding earlier %s keyword with new value", section);
			/* ulgh; not pfree()/clone_str() */
			free((*end)->string);
			(*end)->string = (yytext != NULL ? strdup(yytext) : NULL);
			(*end)->number = number;
			return;
		}
		parser_kw_warning(logger, kw, yytext, "ignoring duplicate %s keyword", section);
		return;
	}

	/*
	 * fill the values into new
	 * (either string or number might have a placeholder value
	 */
	struct kw_list *new = malloc(sizeof(struct kw_list));
	PASSERT(logger, new != NULL);
	(*new) = (struct kw_list) {
		.keyword = *kw,
		.string = (yytext != NULL ? strdup(yytext) : NULL),
		.number = number,
	};

	/* append the new kw_list to the list */
	(*end) = new;
}

static bool parser_kw_unsigned(struct keyword *kw, const char *yytext,
			       uintmax_t *number, struct logger *logger)
{
	err_t err = shunk_to_uintmax(shunk1(yytext), NULL, /*base*/10, number);
	if (err != NULL) {
		parser_kw_warning(logger, kw, yytext, "%s, keyword ignored", err);
		return false;
	}
	return true;
}

static bool parser_kw_bool(struct keyword *kw, const char *yytext,
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

static bool parser_kw_time(struct keyword *kw, const char *yytext,
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

static bool parser_kw_percent(struct keyword *kw, const char *yytext,
			      uintmax_t *number, struct logger *logger)
{
	shunk_t end;
	err_t err = shunk_to_uintmax(shunk1(yytext), &end, /*base*/10, number);
	if (err != NULL) {
		parser_kw_warning(logger, kw, yytext, "%s, percent keyword ignored", err);
		return false;
	}

	if (!hunk_streq(end, "%")) {
		parser_kw_warning(logger, kw, yytext,
				  "bad percentage multiplier \""PRI_SHUNK"\", keyword ignored",
				  pri_shunk(end));
		return false;
	}

	if ((*number) > UINT_MAX) {
		parser_kw_warning(logger, kw, yytext,
				  "percentage way too large, keyword ignored");
		return false;
	}

	return true;
}


static bool parser_kw_binary(struct keyword *kw, const char *yytext,
			     uintmax_t *number, struct logger *logger)
{
	diag_t diag = ttobinary(yytext, number, 0 /* no B prefix */);
	if (diag != NULL) {
		parser_kw_warning(logger, kw, yytext,
				  "%s, keyword ignored", str_diag(diag));
		pfree_diag(&diag);
		return false;
	}

	return true;
}

static bool parser_kw_byte(struct keyword *kw, const char *yytext,
			   uintmax_t *number, struct logger *logger)
{
	diag_t diag = ttobinary(yytext, number, 1 /* with B prefix */);
	if (diag != NULL) {
		parser_kw_warning(logger, kw, yytext,
				  "%s, keyword ignored", str_diag(diag));
		pfree_diag(&diag);
		return false;
	}

	return true;
}

static bool parser_kw_lset(struct keyword *kw, const char *yytext,
			   uintmax_t *number, struct logger *logger)
{
	lmod_t result = {0};

	/*
	 * Use lmod_args() since it both knows how to parse a comma
	 * separated list and can handle no-XXX (ex: all,no-xauth).
	 * The final set of enabled bits is returned in .set.
	 */
	if (!lmod_arg(&result, kw->keydef->info, yytext, true/*enable*/)) {
		/*
		 * If the lookup failed, complain.
		 *
		 * XXX: the error diagnostic is a little vague -
		 * should lmod_arg() instead return the error?
		 */
		parser_kw_warning(logger, kw, yytext, "invalid, keyword ignored");
		return false;
	}

	/* no truncation */
	PEXPECT(logger, sizeof(*number) == sizeof(result.set));
	(*number) = result.set;
	return true;
}

static bool parser_kw_sparse_name(struct keyword *kw, const char *yytext,
				  uintmax_t *number, struct logger *logger)
{
	PASSERT(logger, kw->keydef->sparse_name != NULL);

	const struct sparse_name *sn = sparse_lookup(kw->keydef->sparse_name, yytext);
	if (sn != NULL) {
		(*number) = sn->value;
		return true;
	}

	/*
	 * We didn't find anything, complain.
	 *
	 * XXX: call jam_sparse_names() to list what is valid?
	 */
	parser_kw_warning(logger, kw, yytext, "invalid, keyword ignored");
	return false;
}

static bool parser_kw_loose_sparse_name(struct keyword *kw, const char *yytext,
					uintmax_t *number, struct logger *logger)
{
	PASSERT(logger, (kw->keydef->type == kt_host ||
			 kw->keydef->type == kt_pubkey));
	PASSERT(logger, kw->keydef->sparse_name != NULL);

	const struct sparse_name *sn = sparse_lookup(kw->keydef->sparse_name, yytext);
	if (sn != NULL) {
		PASSERT(logger, sn->value != LOOSE_ENUM_OTHER);
		(*number) = sn->value;
		return true;
	}

	(*number) = LOOSE_ENUM_OTHER; /* i.e., use string value */
	return true;
}

void parser_kw(struct keyword *kw, const char *string, struct logger *logger)
{
	uintmax_t number = 0;		/* neutral placeholding value */
	bool ok = true;

	switch (kw->keydef->type) {
	case kt_lset:
		ok = parser_kw_lset(kw, string, &number, logger);
		break;
	case kt_sparse_name:
		ok = parser_kw_sparse_name(kw, string, &number, logger);
		break;
	case kt_pubkey:
	case kt_host:
		ok = parser_kw_loose_sparse_name(kw, string, &number, logger);
		break;
	case kt_string:
	case kt_also:
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

	case kt_unsigned:
		ok = parser_kw_unsigned(kw, string, &number, logger);
		break;

	case kt_time:
		ok = parser_kw_time(kw, string, &number, logger);
		break;

	case kt_bool:
		ok = parser_kw_bool(kw, string, &number, logger);
		break;

	case kt_percent:
		ok = parser_kw_percent(kw, string, &number, logger);
		break;

	case kt_binary:
		ok = parser_kw_binary(kw, string, &number, logger);
		break;

	case kt_byte:
		ok = parser_kw_byte(kw, string, &number, logger);
		break;

	case kt_obsolete:
		/* drop it on the floor */
		parser_kw_warning(logger, kw, string, "obsolete keyword ignored");
		ok = false;
		break;

	case kt_comment:
		break;

	}

	if (ok) {
		new_parser_kw(kw, string, number, logger);
	}
}
