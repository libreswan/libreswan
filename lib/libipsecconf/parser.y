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
#include "binaryscale-iec-60027-2.h"

#include "ipsecconf/keywords.h"
#include "ipsecconf/parser.h"	/* includes parser.tab.h" */
#include "ipsecconf/scanner.h"
#include "ipsecconf/confread.h"
#include "lswlog.h"
#include "lmod.h"
#include "sparse_names.h"
#include "lswalloc.h"

#define YYERROR_VERBOSE
#define ERRSTRING_LEN	256

static void parser_key_value_warning(struct parser *parser,
				     struct keyword *key,
				     shunk_t value,
				     const char *s, ...) PRINTF_LIKE(4);

void parse_key_value(struct parser *parser, enum end default_end,
		     shunk_t key, shunk_t value);

static void yyerror(struct parser *parser, const char *msg);
static void new_parser_key_value(struct parser *parser,
				 struct keyword *key, shunk_t value,
				 uintmax_t number, deltatime_t time);

/**
 * Functions
 */

%}

%param {struct parser *parser}

%union {
	char *s;
}
%token EQUAL FIRST_SPACES EOL CONFIG SETUP CONN INCLUDE VERSION
%token <s>      STRING
%token <s>      KEYWORD
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
		parser->kw = &parser->cfg->config_setup;
		parser->section = SECTION_CONFIG_SETUP;
		ldbg(parser->logger, "reading config setup");
	} kw_sections
	| CONN STRING EOL {
		struct section_list *section = alloc_thing(struct section_list, "section list");
		PASSERT(parser->logger, section != NULL);

		section->name = clone_str($2, "section->name");
		section->kw = NULL;

		TAILQ_INSERT_TAIL(&parser->cfg->sections, section, link);

		/* setup keyword section to record values */
		parser->kw = &section->kw;
		parser->section = (streq(section->name, "%default") ? SECTION_CONN_DEFAULT :
				  SECTION_CONN);

		ldbg(parser->logger, "reading conn %s", section->name);

		/* free strings allocated by lexer */
		pfreeany($2);

	} kw_sections
	| INCLUDE STRING EOL {
		scanner_include($2, parser);
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
		char *key = $1; /* must free? */
		char *value = $3; /* must free */
		parse_key_value(parser, END_ROOF, shunk1(key), shunk1(value));
		pfreeany(key);
		pfreeany(value);
	}
	| KEYWORD EQUAL STRING {
		char *key = $1;
		char *value = $3;
		parse_key_value(parser, END_ROOF, shunk1(key), shunk1(value));
		/* free strings allocated by lexer */
		pfreeany(key);
		pfreeany(value);
	}
	| KEYWORD EQUAL {
		char *key = $1;
		parse_key_value(parser, END_ROOF, shunk1(key), shunk1(""));
		pfreeany(key);
	}

	| COMMENT EQUAL STRING {
		parser_warning(parser, 0/*error*/, "X- style comment ignored: %s=%s", $1, $3);
		/* free strings allocated by lexer */
		pfreeany($1);
		pfreeany($3);
	}
	| COMMENT EQUAL {
		parser_warning(parser, 0/*error*/, "X- style comment ignored: %s=", $1);
		/* free strings allocated by lexer */
		pfreeany($1);
	}
	| COMMENT {
		parser_warning(parser, 0/*error*/, "X- style comment ignored: %s", $1);
		/* free strings allocated by lexer */
		pfreeany($1);
	}
	;
%%

void parser_warning(struct parser *parser, int error, const char *s, ...)
{
	if (parser->error_stream != NO_STREAM) {
		LLOG_JAMBUF(parser->error_stream, parser->logger, buf) {
			jam_scanner_file_line(buf, parser);
			jam_string(buf, "warning: ");
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

void parser_fatal(struct parser *parser, int error, const char *s, ...)
{
	LLOG_FATAL_JAMBUF(PLUTO_EXIT_FAIL, parser->logger, buf) {
		jam_scanner_file_line(buf, parser);
		va_list ap;
		va_start(ap, s);
		jam_va_list(buf, s, ap);
		va_end(ap);
		if (error > 0) {
			jam_errno(buf, error);
		}
        }
	abort(); /* gcc doesn't believe above always exits */
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

void parser_key_value_warning(struct parser *parser,
			      struct keyword *key,
			      shunk_t value,
			      const char *s, ...)
{
	if (parser->error_stream != NO_STREAM) {
		LLOG_JAMBUF(parser->error_stream, parser->logger, buf) {
			jam_scanner_file_line(buf, parser);
			jam_string(buf, "warning: ");
			/* message */
			va_list ap;
			va_start(ap, s);
			jam_va_list(buf, s, ap);
			va_end(ap);
			/* what was specified */
			jam_string(buf, ": ");
			jam_string(buf, leftright(key));
			jam_string(buf, key->keydef->keyname);
			jam_string(buf, "=");
			jam_shunk(buf, value);
		}
	}
}

void yyerror(struct parser *parser, const char *s)
{
	if (parser->error_stream != NO_STREAM) {
		LLOG_JAMBUF(parser->error_stream, parser->logger, buf) {
			jam_scanner_file_line(buf, parser);
			jam_string(buf, s);
		}
	}
}

static struct config_parsed *alloc_config_parsed(void)
{
	struct config_parsed *cfgp = alloc_thing(struct config_parsed, __func__);
	TAILQ_INIT(&cfgp->sections);
	return cfgp;
}

struct config_parsed *parser_load_conf(const char *file,
				       struct logger *logger,
				       bool setuponly,
				       unsigned verbosity)
{
	struct parser parser = {
		.logger = logger,
		.error_stream = ERROR_STREAM,
		.verbosity = verbosity,
		.setuponly = setuponly,
	};

	if (!scanner_open(&parser, file)) {
		return NULL;
	}

	/* i.e., parser_init() */
	parser.cfg = alloc_config_parsed(),
	ldbg(logger, "allocated config %p", parser.cfg);

	if (yyparse(&parser) != 0) {
		/* suppress errors */
		parser.error_stream = (LDBGP(DBG_BASE, logger) ? DEBUG_STREAM : NO_STREAM);
		do {} while (yyparse(&parser) != 0);
		goto err;
	}

	scanner_close(&parser);

	/**
	 * Config valid
	 */
	ldbg(logger, "allocated config %p", parser.cfg->conn_default.kw);
	return parser.cfg;

err:
	parser_freeany_config_parsed(&parser.cfg);
	scanner_close(&parser);

	return NULL;
}

struct config_parsed *parser_argv_conf(const char *name, char *argv[], int start,
				       struct logger *logger)
{
	struct config_parsed *cfgp = alloc_config_parsed();

	/* there's only one */
	struct section_list *section = alloc_thing(struct section_list, __func__);
	TAILQ_INSERT_TAIL(&cfgp->sections, section, link);
	section->name = clone_str(name, __func__);

	struct parser parser = {
		.cfg = cfgp,
		.section = SECTION_CONN,
		.kw = &section->kw,
		.logger = logger,
		.setuponly = false,
	};

	scanner_init(&parser, "argv", start);

	/* for options that should have an end, but don't */
	enum end default_end = LEFT_END;

	for (char **argp = argv + start; (*argp) != NULL; argp++) {

		const char *const arg = (*argp);
		shunk_t cursor = shunk1(arg);

		/* only whack options have -- */
		bool whack = hunk_streat(&cursor, "--");

		/*
		 * Parse simple whack --OPTIONs (remember leading "--"
		 * indicating a whack option was stripped and WHACK
		 * set).
		 */

		if (whack && hunk_streq(cursor, "to")) {
			default_end++;
			if (default_end >= END_ROOF) {
				llog(ERROR_STREAM, logger, "too many '--to's");
				parser_freeany_config_parsed(&cfgp);
				exit(1);
			}
			scanner_next_line(&parser);
			continue;
		}

		if (whack && hunk_streat(&cursor, "nego")) {
			parse_key_value(&parser, default_end,
					shunk1("negotiationshunt"),
					cursor);
			scanner_next_line(&parser);
			continue;
		}

		if (whack && hunk_streat(&cursor, "fail")) {
			parse_key_value(&parser, default_end,
					shunk1("failureshunt"),
					cursor);
			scanner_next_line(&parser);
			continue;
		}

		/*
		 * Parse KEY=VALUE (and --KEY=VALUE).  When whack,
		 * also allow --KEY VALUE.
		 */

		char sep;
		shunk_t key = shunk_token(&cursor, &sep, "=");
		shunk_t value;
		if (sep == '=') {
			value = cursor;
		} else if (whack) {
			/* only allow --KEY VALUE when whack compat */
			if (argp[1] == NULL) {
				llog(ERROR_STREAM, logger, "missing argument for %s", arg);
				parser_freeany_config_parsed(&cfgp);
				return NULL;
			}
			/* skip/use next arg */
			argp++;
			value = shunk1(*argp);
			scanner_next_line(&parser);
		} else {
			llog(ERROR_STREAM, logger, "missing '=' in %s", arg);
			parser_freeany_config_parsed(&cfgp);
			exit(1);
		}

		/*
		 * Handle whack --KEY=VALUE options by mapping the KEY
		 * onto the equivalent ipsec.conf KEY.
		 */

		if (whack && hunk_streq(key, "host")) {
			key = shunk1(default_end == LEFT_END ? "left" :
				     default_end == RIGHT_END ? "right" :
				     "???");
		}

		if (whack && hunk_streq(key, "authby")) {
			/* XXX: whack's authby semantics */
			key = shunk1("auth");
		}

		parse_key_value(&parser, default_end, key, value);
		scanner_next_line(&parser);
	}

	scanner_close(&parser);

	return cfgp;
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

		/* keep deleting the first entry */
		struct section_list *sec;
		while ((sec = TAILQ_FIRST(&cfg->sections)) != NULL) {
			TAILQ_REMOVE(&cfg->sections, sec, link);
			pfreeany(sec->name);
			parser_free_kwlist(sec->kw);
			pfree(sec);
		}

		pfreeany(*cfgp);
	}
}

void new_parser_key_value(struct parser *parser,
			  struct keyword *key,
			  shunk_t value,
			  uintmax_t number,
			  deltatime_t deltatime)
{
	/* both means no prefix */
	const char *section = "???";
	switch (parser->section) {
	case SECTION_CONFIG_SETUP:
		section = "'config setup'";
		if ((key->keydef->validity & kv_config) == LEMPTY) {
			parser_key_value_warning(parser, key, value,
						 "invalid %s keyword ignored",
						 section);
			/* drop it on the floor */
			return;
		}
		break;
	case SECTION_CONN:
		section = "conn";
		if ((key->keydef->validity & kv_conn) == LEMPTY) {
			parser_key_value_warning(parser, key, value,
						 "invalid %s keyword ignored", section);
			/* drop it on the floor */
			return;
		}
		break;
	case SECTION_CONN_DEFAULT:
		section = "'conn %%default'";
		if ((key->keydef->validity & kv_conn) == LEMPTY ||
		    key->keydef->field == KSCF_ALSO) {
			parser_key_value_warning(parser, key, value,
						 "invalid %s keyword ignored", section);
			/* drop it on the floor */
			return;
		}
		break;
	}

	/* Find end, while looking for duplicates. */
	struct kw_list **end;
	for (end = parser->kw; (*end) != NULL; end = &(*end)->next) {
		if ((*end)->keyword.keydef != key->keydef) {
			continue;
		}
		if (((*end)->keyword.keyleft != key->keyleft) &&
		    ((*end)->keyword.keyright != key->keyright)) {
			continue;
		}
		if (key->keydef->validity & kv_duplicateok) {
			continue;
		}
		/* note the weird behaviour! */
		if (parser->section == SECTION_CONFIG_SETUP) {
			parser_key_value_warning(parser, key, value,
						 "overriding earlier %s keyword with new value", section);
			pfreeany((*end)->string);
			(*end)->string = clone_hunk_as_string(value, "keyword.string"); /*handles NULL*/
			(*end)->number = number;
			(*end)->deltatime = deltatime;
			return;
		}
		parser_key_value_warning(parser, key, value,
					 "ignoring duplicate %s keyword", section);
		return;
	}

	/*
	 * fill the values into new
	 * (either string or number might have a placeholder value
	 */
	struct kw_list *new = alloc_thing(struct kw_list, "kw_list");
	(*new) = (struct kw_list) {
		.keyword = *key,
		.string = clone_hunk_as_string(value, "keyword.list"), /*handles NULL*/
		.number = number,
		.deltatime = deltatime,
	};

	ldbgf(DBG_TMI, parser->logger, "  %s%s=%s number=%ju field=%u", key->keydef->keyname,
	      leftright(key), new->string, new->number,
	      key->keydef->field);

	/* append the new kw_list to the list */
	(*end) = new;
}

static bool parse_kt_unsigned(struct keyword *key, shunk_t value,
			      uintmax_t *number, struct parser *parser)
{
	err_t err = shunk_to_uintmax(value, NULL, /*base*/10, number);
	if (err != NULL) {
		parser_key_value_warning(parser, key, value,
					 "%s, keyword ignored", err);
		return false;
	}
	return true;
}

static bool parse_kt_bool(struct keyword *key, shunk_t value,
			  uintmax_t *number, struct parser *parser)
{
	const struct sparse_name *name = sparse_lookup_by_name(&yn_option_names, value);
	if (name == NULL) {
		parser_key_value_warning(parser, key, value,
					 "invalid boolean, keyword ignored");
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

static bool parse_kt_deltatime(struct keyword *key, shunk_t value,
			       enum timescale default_timescale,
			       deltatime_t *deltatime,
			       struct parser *parser)
{
	diag_t diag = ttodeltatime(value, deltatime, default_timescale);
	if (diag != NULL) {
		parser_key_value_warning(parser, key, value,
					 "%s, keyword ignored", str_diag(diag));
		pfree_diag(&diag);
		return false;
	}
	return true;
}

static bool parse_kt_binary(struct keyword *key, shunk_t value,
			    uintmax_t *number, struct parser *parser)
{
	diag_t diag = tto_scaled_uintmax(value, number, &binary_scales);
	if (diag != NULL) {
		parser_key_value_warning(parser, key, value,
					 "%s, keyword ignored", str_diag(diag));
		pfree_diag(&diag);
		return false;
	}

	return true;
}

static bool parse_kt_lset(struct keyword *key, shunk_t value,
			  uintmax_t *number, struct parser *parser)
{
	lmod_t result = {0};

	/*
	 * Use lmod_args() since it both knows how to parse a comma
	 * separated list and can handle no-XXX (ex: all,no-xauth).
	 * The final set of enabled bits is returned in .set.
	 */
	if (!ttolmod(value, &result, key->keydef->info, true/*enable*/)) {
		/*
		 * If the lookup failed, complain.
		 *
		 * XXX: the error diagnostic is a little vague -
		 * should lmod_arg() instead return the error?
		 */
		parser_key_value_warning(parser, key, value,
					 "invalid, keyword ignored");
		return false;
	}

	/* no truncation */
	PEXPECT(parser->logger, sizeof(*number) == sizeof(result.set));
	(*number) = result.set;
	return true;
}

static bool parse_kt_sparse_name(struct keyword *key, shunk_t value,
				 uintmax_t *number, struct parser *parser)
{
	const struct sparse_names *names = key->keydef->sparse_names;
	PASSERT(parser->logger, names != NULL);

	const struct sparse_name *sn = sparse_lookup_by_name(names, value);
	if (sn == NULL) {
		/*
		 * We didn't find anything, complain.
		 *
		 * XXX: call jam_sparse_names() to list what is valid?
		 */
		parser_key_value_warning(parser, key, value,
					 "invalid, keyword ignored");
		return false;
	}

	enum name_flags flags = (sn->value & NAME_FLAGS);
	(*number) = sn->value & ~NAME_FLAGS;
	name_buf new_name;

	switch (flags) {
	case NAME_IMPLEMENTED_AS:
		parser_key_value_warning(parser, key, value,
					 PRI_SHUNK" implemented as %s",
					 pri_shunk(value), str_sparse_short(names, (*number), &new_name));
		return true;
	case NAME_RENAMED_TO:
		parser_key_value_warning(parser, key, value,
					 PRI_SHUNK" renamed to %s",
					 pri_shunk(value), str_sparse_short(names, (*number), &new_name));
		return true;
	}

	return true;
}

static bool parse_kt_loose_sparse_name(struct keyword *key, shunk_t value,
				       uintmax_t *number, struct parser *parser)
{
	PASSERT(parser->logger, (key->keydef->type == kt_host ||
				 key->keydef->type == kt_pubkey));
	PASSERT(parser->logger, key->keydef->sparse_names != NULL);

	const struct sparse_name *sn = sparse_lookup_by_name(key->keydef->sparse_names, value);
	if (sn == NULL) {
		(*number) = LOOSE_ENUM_OTHER; /* i.e., use string value */
		return true;
	}

	PASSERT(parser->logger, sn->value != LOOSE_ENUM_OTHER);
	(*number) = sn->value;
	return true;

}

/*
 * Look for one of the tokens, and set the value up right.
 */

static bool parse_leftright(shunk_t s,
			    const struct keyword_def *k,
			    const char *leftright)
{
	/* gobble up "left|right" */
	if (!hunk_strcaseeat(&s, leftright)) {
		return false;
	}

	/* if present and kw non-empty, gobble up "-" */
	if (strlen(k->keyname) > 0) {
		hunk_streat(&s, "-");
	}

	/* keyword matches? */
	if (!hunk_strcaseeq(s, k->keyname)) {
		return false;
	}

	/* success */
	return true;
}

/* type is really "token" type, which is actually int */
static bool parser_find_keyword(shunk_t s, enum end default_end,
				struct keyword *kw, struct parser *parser)
{
	bool left = false;
	bool right = false;

	zero(kw);

	const struct keyword_def *k;
	for (k = ipsec_conf_keywords; k->keyname != NULL; k++) {

		if (hunk_strcaseeq(s, k->keyname)) {

			/*
			 * Given a KEY with BOTH|LEFTRIGHT, BOTH
			 * trumps LEFTRIGHT.
			 *
			 * For instance:
			 *
			 *   --key=value --to ...
			 *
			 * sets left-key and right-key.  To only set
			 * one end, specify:
			 *
			 *   --right-key=value --to ...
			 *
			 */
			if (k->validity & kv_both) {
				left = true;
				right = true;
				break;
			}

			/*
			 * For instance --auth=... --to ...
			 */
			if (k->validity & kv_leftright) {
				if (default_end == LEFT_END) {
					left = true;
					break;
				}
				if (default_end == RIGHT_END) {
					right = true;
					break;
				}

#if 0 /* see github#663 */
				continue;
#else
				parser_warning(parser, 0, "%s= is being treated as right-%s=",
					       k->keyname, k->keyname);
				right = true;
#endif
			}
			break;
		}

		if (k->validity & kv_leftright) {
			left = parse_leftright(s, k, "left");
			if (left) {
				break;
			}
			right = parse_leftright(s, k, "right");
			if (right) {
				break;
			}
		}
	}

	/* if we still found nothing */
	if (k->keyname == NULL) {
#define FAIL(FUNC) FUNC(parser, /*errno*/0, "unrecognized '%s' keyword '"PRI_SHUNK"'", \
			str_parser_section(parser), pri_shunk(s))
		if (parser->section == SECTION_CONFIG_SETUP ||
		    !parser->setuponly) {
			FAIL(parser_fatal);
			/* never returns */
		}
		FAIL(parser_warning);
		/* never returns */
		return false;
#undef FAIL
	}

	/* else, set up llval.k to point, and return KEYWORD */
	kw->keydef = k;
	kw->keyleft = left;
	kw->keyright = right;
	return true;
}

void parse_key_value(struct parser *parser, enum end default_end,
		     shunk_t key, shunk_t value)
{
	struct keyword kw[1];
	if (!parser_find_keyword(key, default_end, kw, parser)) {
		return;
	}

	uintmax_t number = 0;		/* neutral placeholding value */
	deltatime_t deltatime = {.is_set = false, };
	bool ok = true;

	switch (kw->keydef->type) {
	case kt_lset:
		ok = parse_kt_lset(kw, value, &number, parser);
		break;
	case kt_sparse_name:
		ok = parse_kt_sparse_name(kw, value, &number, parser);
		break;
	case kt_pubkey:
	case kt_host:
		ok = parse_kt_loose_sparse_name(kw, value, &number, parser);
		break;
	case kt_string:
	case kt_also:
	case kt_appendstring:
	case kt_appendlist:
	case kt_ipaddr:
	case kt_idtype:
	case kt_range:
	case kt_subnet:
		break;

	case kt_unsigned:
		ok = parse_kt_unsigned(kw, value, &number, parser);
		break;

	case kt_seconds:
		ok = parse_kt_deltatime(kw, value, TIMESCALE_SECONDS,
					&deltatime, parser);
		break;

	case kt_milliseconds:
		ok = parse_kt_deltatime(kw, value, TIMESCALE_MILLISECONDS,
					&deltatime, parser);
		break;

	case kt_bool:
		ok = parse_kt_bool(kw, value, &number, parser);
		break;

	case kt_binary:
		ok = parse_kt_binary(kw, value, &number, parser);
		break;

	case kt_obsolete:
		/* drop it on the floor */
		parser_key_value_warning(parser, kw, value,
					 "obsolete keyword ignored");
		ok = false;
		break;

	}

	if (ok) {
		new_parser_key_value(parser, kw, value, number, deltatime);
	}
}
