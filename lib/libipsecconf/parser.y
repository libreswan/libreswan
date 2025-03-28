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
#include "sparse_names.h"
#include "lswalloc.h"

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
static void new_parser_kw(struct keyword *keyword, const char *string,
			  uintmax_t number, deltatime_t time,
			  struct logger *logger);

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
%token <s>      COMMENT
%%

/*
 * Config file
 */

config_file: blanklines versionstmt sections ;

/* check out the version number - this is optional (and we're phasing out its use) */
/* we have configs shipped with version 2 (UNSIGNED) and with version 2.0 (STRING, now  NUMBER/float was removed */

versionstmt: /* NULL */
	| VERSION STRING EOL blanklines {
		/* free strings allocated by lexer */
		pfreeany($2);
	}
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
		ldbg(logger, "reading config setup");
	} kw_sections
	| CONN STRING EOL {
		struct section_list *section = alloc_thing(struct section_list, "section list");
		PASSERT(logger, section != NULL);

		section->name = clone_str($2, "section->name");
		section->kw = NULL;

		TAILQ_INSERT_TAIL(&parser.cfg->sections, section, link);

		/* setup keyword section to record values */
		parser.kw = &section->kw;
		parser.section = (streq(section->name, "%default") ? SECTION_CONN_DEFAULT :
				  SECTION_CONN);

		ldbg(logger, "reading conn %s", section->name);

		/* free strings allocated by lexer */
		pfreeany($2);

	} kw_sections
	| INCLUDE STRING EOL {
		parser_y_include($2, logger);
		/* free strings allocated by lexer */
		pfreeany($2)
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
	| KEYWORD EQUAL STRING {
		struct keyword kw = $1;
		const char *string = $3;
		parser_kw(&kw, string, logger);
		/* free strings allocated by lexer */
		pfreeany($3);
	}
	| KEYWORD EQUAL {
		struct keyword kw = $1;
		parser_kw(&kw, "", logger);
	}

	| COMMENT EQUAL STRING {
		parser_warning(logger, 0/*error*/, "X- style comment ignored: %s=%s", $1, $3);
		/* free strings allocated by lexer */
		pfreeany($1);
		pfreeany($3);
	}
	| COMMENT EQUAL {
		parser_warning(logger, 0/*error*/, "X- style comment ignored: %s=", $1);
		/* free strings allocated by lexer */
		pfreeany($1);
	}
	| COMMENT {
		parser_warning(logger, 0/*error*/, "X- style comment ignored: %s", $1);
		/* free strings allocated by lexer */
		pfreeany($1);
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

void parser_fatal(struct logger *logger, int error, const char *s, ...)
{
        struct logjam logjam;
        struct jambuf *buf = jambuf_from_logjam(&logjam, logger, PLUTO_EXIT_FAIL,
                                                NULL/*where*/, FATAL_STREAM);
        {
		jam(buf, "%s:%u: ",
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
        fatal_logjam_to_logger(&logjam);
}

static const char *leftright(struct keyword *kw)
{
	if (kw->keyleft && !kw->keyright) {
		return "left";
	}
	if (!kw->keyleft && kw->keyright) {
		return "right";
	}
	return "";
}

void parser_kw_warning(struct logger *logger, struct keyword *kw, const char *yytext,
		       const char *s, ...)
{
	if (save_errors) {
		LLOG_JAMBUF(RC_LOG, logger, buf) {
			jam(buf, "%s:%u: warning: ",
			    parser_cur_filename(),
			    parser_cur_line());
			/* message */
			va_list ap;
			va_start(ap, s);
			jam_va_list(buf, s, ap);
			va_end(ap);
			/* what was specified */
			jam_string(buf, ": ");
			jam_string(buf, leftright(kw));
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
	parser.cfg = alloc_thing(struct config_parsed, __func__);
	PASSERT(logger, parser.cfg != NULL);
	ldbg(logger, "allocated config %p", parser.cfg);

	FILE *f = (streq(file, "-") ? fdopen(STDIN_FILENO, "r") :
		   fopen(file, "r"));

	if (f == NULL) {
		llog(RC_LOG, logger, "can't load file '%s'", file);
		goto err;
	}

	yyin = f;
	parser_y_init(file, f);
	save_errors = true;
	TAILQ_INIT(&parser.cfg->sections);

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
	ldbg(logger, "allocated config %p", cfg->conn_default.kw);
	return cfg;

err:
	parser_freeany_config_parsed(&parser.cfg);

	return NULL;
}

static void parser_free_kwlist(struct kw_list *list)
{
	while (list != NULL) {
		/* advance */
		struct kw_list *elt = list;
		list = list->next;
		/* free */
		pfreeany(elt->string);
		pfree(elt);
	}
}

void parser_freeany_config_parsed(struct config_parsed **cfgp)
{
	if ((*cfgp) != NULL) {
		struct config_parsed *cfg = (*cfgp);
		parser_free_kwlist(cfg->config_setup);

		for (struct section_list *seci = TAILQ_FIRST(&cfg->sections);
		     seci != NULL; ) {
			/* step off */
			struct section_list *sec = seci;
			seci = TAILQ_NEXT(seci, link);

			pfreeany(sec->name);
			parser_free_kwlist(sec->kw);
			pfree(sec);
		}

		pfreeany(*cfgp);
	}
}

static void new_parser_kw(struct keyword *kw,
			  const char *yytext,
			  uintmax_t number,
			  deltatime_t deltatime,
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
			pfreeany((*end)->string);
			(*end)->string = clone_str(yytext, "keyword.string"); /*handles NULL*/
			(*end)->number = number;
			(*end)->deltatime = deltatime;
			return;
		}
		parser_kw_warning(logger, kw, yytext, "ignoring duplicate %s keyword", section);
		return;
	}

	/*
	 * fill the values into new
	 * (either string or number might have a placeholder value
	 */
	struct kw_list *new = alloc_thing(struct kw_list, "kw_list");
	(*new) = (struct kw_list) {
		.keyword = *kw,
		.string = clone_str(yytext, "keyword.list"), /*handles NULL*/
		.number = number,
		.deltatime = deltatime,
	};

	ldbgf(DBG_TMI, logger, "  %s%s=%s number=%ju field=%u", kw->keydef->keyname,
	      leftright(kw), new->string, new->number,
	      kw->keydef->field);

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
	const struct sparse_name *name = sparse_lookup_by_name(&yn_option_names, shunk1(yytext));
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

static bool parser_kw_deltatime(struct keyword *kw, const char *yytext,
				enum timescale default_timescale,
				deltatime_t *deltatime,
				struct logger *logger)
{
	diag_t diag = ttodeltatime(yytext, deltatime, default_timescale);
	if (diag != NULL) {
		parser_kw_warning(logger, kw, yytext, "%s, keyword ignored", str_diag(diag));
		pfree_diag(&diag);
		return false;
	}
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
	const struct sparse_names *names = kw->keydef->sparse_names;
	PASSERT(logger, names != NULL);

	const struct sparse_name *sn = sparse_lookup_by_name(names, shunk1(yytext));
	if (sn == NULL) {
		/*
		 * We didn't find anything, complain.
		 *
		 * XXX: call jam_sparse_names() to list what is valid?
		 */
		parser_kw_warning(logger, kw, yytext, "invalid, keyword ignored");
		return false;
	}

	enum name_flags flags = (sn->value & NAME_FLAGS);
	(*number) = sn->value & ~NAME_FLAGS;
	name_buf new_name;

	switch (flags) {
	case NAME_IMPLEMENTED_AS:
		parser_kw_warning(logger, kw, yytext, "%s implemented as %s",
				  yytext, str_sparse_short(names, (*number), &new_name));
		return true;
	case NAME_RENAMED_TO:
		parser_kw_warning(logger, kw, yytext, "%s renamed to %s",
				  yytext, str_sparse_short(names, (*number), &new_name));
		return true;
	}

	return true;
}

static bool parser_kw_loose_sparse_name(struct keyword *kw, const char *yytext,
					uintmax_t *number, struct logger *logger)
{
	PASSERT(logger, (kw->keydef->type == kt_host ||
			 kw->keydef->type == kt_pubkey));
	PASSERT(logger, kw->keydef->sparse_names != NULL);

	const struct sparse_name *sn = sparse_lookup_by_name(kw->keydef->sparse_names,
							     shunk1(yytext));
	if (sn == NULL) {
		(*number) = LOOSE_ENUM_OTHER; /* i.e., use string value */
		return true;
	}

	PASSERT(logger, sn->value != LOOSE_ENUM_OTHER);
	(*number) = sn->value;
	return true;

}

void parser_kw(struct keyword *kw, const char *string, struct logger *logger)
{
	uintmax_t number = 0;		/* neutral placeholding value */
	deltatime_t deltatime = {.is_set = false, };
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

	case kt_seconds:
		ok = parser_kw_deltatime(kw, string, TIMESCALE_SECONDS,
					 &deltatime, logger);
		break;

	case kt_milliseconds:
		ok = parser_kw_deltatime(kw, string, TIMESCALE_MILLISECONDS,
					 &deltatime, logger);
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

	}

	if (ok) {
		new_parser_kw(kw, string, number, deltatime, logger);
	}
}
