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
				     const struct ipsec_conf_keyval *key,
				     shunk_t value,
				     const char *s, ...) PRINTF_LIKE(4);

void parse_keyval(struct parser *parser, enum end default_end,
		  shunk_t key, shunk_t value);

static void yyerror(struct parser *parser, const char *msg);

static void append_parser_key_value(struct parser *parser,
				    struct ipsec_conf_keyval *key,
				    shunk_t value,
				    uintmax_t number,
				    deltatime_t deltatime);

static void add_parser_key_value(struct parser *parser,
				 struct ipsec_conf_keyval *key,
				 shunk_t value,
				 uintmax_t number,
				 deltatime_t time);

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
		parser->keyvals = &parser->cfg->config_setup;
		parser->section = SECTION_CONFIG_SETUP;
		ldbg(parser->logger, "reading config setup");
	} kw_sections
	| CONN STRING EOL {
		struct section_list *section = alloc_thing(struct section_list, "section list");
		PASSERT(parser->logger, section != NULL);

		section->name = clone_str($2, "section->name");
		TAILQ_INIT(&section->keyvals);
		TAILQ_INSERT_TAIL(&parser->cfg->sections, section, next);

		/* setup keyword section to record values */
		parser->keyvals = &section->keyvals;
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
		parse_keyval(parser, END_ROOF, shunk1(key), shunk1(value));
		pfreeany(key);
		pfreeany(value);
	}
	| KEYWORD EQUAL STRING {
		char *key = $1;
		char *value = $3;
		parse_keyval(parser, END_ROOF, shunk1(key), shunk1(value));
		/* free strings allocated by lexer */
		pfreeany(key);
		pfreeany(value);
	}
	| KEYWORD EQUAL {
		char *key = $1;
		parse_keyval(parser, END_ROOF, shunk1(key), shunk1(""));
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
	if (parser->stream.warning != NO_STREAM) {
		LLOG_JAMBUF(parser->stream.warning, parser->logger, buf) {
			jam_scanner_file_line(buf, parser);
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

static const char *leftright(const struct ipsec_conf_keyval *keyval)
{
	if (keyval->left && !keyval->right) {
		return "left";
	}
	if (!keyval->left && keyval->right) {
		return "right";
	}
	return "";
}

/*
 * Note: VALUE hasn't yet been copied into KEY.
 */

void parser_key_value_warning(struct parser *parser,
			      const struct ipsec_conf_keyval *key,
			      shunk_t value,
			      const char *s, ...)
{
	if (parser->stream.warning != NO_STREAM) {
		LLOG_JAMBUF(parser->stream.warning, parser->logger, buf) {
			jam(buf, PRI_KEYVAL_SAL": ", pri_keyval_sal(key));
			/* message */
			va_list ap;
			va_start(ap, s);
			jam_va_list(buf, s, ap);
			va_end(ap);
			/* what was specified */
			jam_string(buf, ": ");
			jam_string(buf, leftright(key));
			jam_string(buf, key->key->keyname);
			jam_string(buf, "=");
			jam_shunk(buf, value);
		}
	}
}

void yyerror(struct parser *parser, const char *s)
{
	if (parser->stream.error != NO_STREAM) {
		LLOG_JAMBUF(parser->stream.error, parser->logger, buf) {
			jam_scanner_file_line(buf, parser);
			jam_string(buf, s);
		}
	}
}

static struct ipsec_conf *alloc_ipsec_conf(void)
{
	struct ipsec_conf *cfgp = alloc_thing(struct ipsec_conf, __func__);
	TAILQ_INIT(&cfgp->config_setup);
	TAILQ_INIT(&cfgp->sections);
	TAILQ_INIT(&cfgp->sources);
	return cfgp;
}

struct ipsec_conf *load_ipsec_conf(const char *file,
				   struct logger *logger,
				   bool setuponly,
				   unsigned verbosity)
{
	struct parser parser = {
		.logger = logger,
		.stream.warning = WARNING_STREAM,
		.stream.error = ERROR_STREAM,
		.verbosity = verbosity,
		.setuponly = setuponly,
		.cfg = alloc_ipsec_conf(),
	};

	if (!scanner_open(&parser, file)) {
		pfree_ipsec_conf(&parser.cfg);
		return NULL;
	}

	if (yyparse(&parser) != 0) {
		/* suppress errors and warnings */
		enum stream stream =  (LDBGP(DBG_BASE, logger) ? DEBUG_STREAM : NO_STREAM);
		parser.stream.warning = stream;
		parser.stream.error = stream;
		do {} while (yyparse(&parser) != 0);
		pfree_ipsec_conf(&parser.cfg);
		scanner_close(&parser);
		return NULL;
	}

	scanner_close(&parser);

	/**
	 * Config valid
	 */
	return parser.cfg;
}

struct ipsec_conf *argv_ipsec_conf(const char *name, char *argv[], int start,
				   struct logger *logger)
{
	struct parser parser = {
		.cfg = alloc_ipsec_conf(),
		.logger = logger,
		.setuponly = false,
	};

	/*
	 * There's only section and it's a conn; fudge things up so
	 * that processing just started.
	 */

	struct section_list *section = alloc_thing(struct section_list, __func__);
	section->name = clone_str(name, __func__);
	TAILQ_INIT(&section->keyvals);
	TAILQ_INSERT_TAIL(&parser.cfg->sections, section, next);

	parser.section = SECTION_CONN;
	parser.keyvals = &section->keyvals,

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
				pfree_ipsec_conf(&parser.cfg);
				exit(1);
			}
			scanner_next_line(&parser);
			continue;
		}

		if (whack && hunk_streat(&cursor, "nego")) {
			parse_keyval(&parser, default_end,
				     shunk1("negotiationshunt"),
				     cursor);
			scanner_next_line(&parser);
			continue;
		}

		if (whack && hunk_streat(&cursor, "fail")) {
			parse_keyval(&parser, default_end,
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
				pfree_ipsec_conf(&parser.cfg);
				return NULL;
			}
			/* skip/use next arg */
			argp++;
			value = shunk1(*argp);
			scanner_next_line(&parser);
		} else {
			llog(ERROR_STREAM, logger, "missing '=' in %s", arg);
			pfree_ipsec_conf(&parser.cfg);
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

		parse_keyval(&parser, default_end, key, value);
		scanner_next_line(&parser);
	}

	scanner_close(&parser);

	return parser.cfg;
}

static void pfree_keyval_list(struct keyval_list *list)
{
	struct keyval_entry *head;
	while ((head = TAILQ_FIRST(list)) != NULL) {
		TAILQ_REMOVE(list, head, next);
		pfreeany(head->keyval.val);
		pfree(head);
	}
}

const char *add_ipsec_conf_source(struct ipsec_conf *cfg, const char *name)
{
	struct ipsec_conf_source *source = alloc_thing(struct ipsec_conf_source, __func__);
	source->name = clone_str(name, __func__);
	TAILQ_INSERT_TAIL(&cfg->sources, source, next);
	return source->name;
}

void pfree_ipsec_conf(struct ipsec_conf **cfgp)
{
	if ((*cfgp) != NULL) {
		struct ipsec_conf *cfg = (*cfgp);
		pfree_keyval_list(&cfg->config_setup);

		/* keep deleting the first entry */
		struct section_list *section;
		while ((section = TAILQ_FIRST(&cfg->sections)) != NULL) {
			TAILQ_REMOVE(&cfg->sections, section, next);
			pfreeany(section->name);
			pfree_keyval_list(&section->keyvals);
			pfree(section);
		}

		/* keep deleting the first entry */
		struct ipsec_conf_source *source;
		while ((source = TAILQ_FIRST(&cfg->sources)) != NULL) {
			TAILQ_REMOVE(&cfg->sources, source, next);
			pfreeany(source->name);
			pfreeany(source);
		}

		pfreeany(*cfgp);
	}
}

void add_parser_key_value(struct parser *parser,
			  struct ipsec_conf_keyval *key,
			  shunk_t value,
			  uintmax_t number,
			  deltatime_t deltatime)
{
	/* both means no prefix */
	const char *section = str_parser_section(parser);

	/* Find end, while looking for duplicates. */
	struct keyval_entry *kv;
	TAILQ_FOREACH(kv, parser->keyvals, next) {
		if (kv->keyval.key != key->key) {
			continue;
		}
		if ((kv->keyval.left != key->left) &&
		    (kv->keyval.right != key->right)) {
			continue;
		}
		if (key->key->validity & kv_duplicateok) {
			continue;
		}
		/* note the weird behaviour! */
		if (parser->section == SECTION_CONFIG_SETUP) {
			parser_key_value_warning(parser, key, value,
						 "overriding earlier '%s' keyword with new value", section);
			pfreeany(kv->keyval.val);
			kv->keyval.val = clone_hunk_as_string(value, "keyword.string"); /*handles NULL*/
			kv->number = number;
			kv->deltatime = deltatime;
			return;
		}
		parser_key_value_warning(parser, key, value,
					 "ignoring duplicate %s keyword", section);
		return;
	}

	append_parser_key_value(parser, key, value, number, deltatime);
}

static void append_parser_key_value(struct parser *parser,
				    struct ipsec_conf_keyval *key,
				    shunk_t value,
				    uintmax_t number,
				    deltatime_t deltatime)
{
	/*
	 * fill the values into new
	 * (either string or number might have a placeholder value
	 */
	struct keyval_entry *new = alloc_thing(struct keyval_entry, "kw_list");
	(*new) = (struct keyval_entry) {
		.keyval = *key,
		.number = number,
		.deltatime = deltatime,
	};

	/* add the value */
	new->keyval.val = clone_hunk_as_string(value, /*handles NULL*/
					       "keyword.list");

	if (LDBGP(DBG_TMI, parser->logger)) {
		LLOG_JAMBUF(DEBUG_STREAM, parser->logger, buf) {
			jam(buf, "  %s%s=%s", leftright(key),
			    key->key->keyname, new->keyval.val);
			jam(buf, " number=%ju", new->number);
			jam(buf, " field=%u", key->key->field);
			jam_string(buf, " deltatime=");
			jam_deltatime(buf, new->deltatime);
		}
	}

	/* append the new kw_list to the list */
	TAILQ_INSERT_TAIL(parser->keyvals, new, next);
}

diag_t parse_kt_unsigned(const struct ipsec_conf_keyval *key UNUSED,
			 shunk_t value, uintmax_t *number)
{
	/* treat -1 as special, turning it into max */
	if (hunk_streq(value, "-1")) {
		(*number) = UINTMAX_MAX;
		return NULL;
	}

	err_t err = shunk_to_uintmax(value, NULL, /*base*/10, number);
	if (err == NULL) {
		return NULL;
	}

	return diag("%s", err);
}

diag_t parse_kt_deltatime(const struct ipsec_conf_keyval *key UNUSED,
			  shunk_t value, enum timescale default_timescale,
			  deltatime_t *deltatime)
{
	diag_t diag = ttodeltatime(value, deltatime, default_timescale);
	if (diag != NULL) {
		return diag;
	}

	return NULL;
}

diag_t parse_kt_sparse_name(const struct ipsec_conf_keyval *key,
			    shunk_t value, uintmax_t *number,
			    enum stream warning_stream, struct logger *logger)
{
	const struct sparse_names *names = key->key->sparse_names;

	const struct sparse_name *sn = sparse_lookup_by_name(names, value);
	if (sn == NULL) {
		/*
		 * We didn't find anything, complain.
		 *
		 * XXX: call jam_sparse_names() to list what is valid?
		 */
		return diag("invalid");
	}

	(*number) = sn->value & ~NAME_FLAGS;

	if (warning_stream != NO_STREAM) {
		enum name_flags flags = (sn->value & NAME_FLAGS);
		name_buf new_name;

		switch (flags) {
		case NAME_IMPLEMENTED_AS:
			llog(warning_stream, logger, PRI_KEYVAL_SAL": "PRI_SHUNK" implemented as %s: %s="PRI_SHUNK,
			     pri_keyval_sal(key),
			     pri_shunk(value), str_sparse_short(names, (*number), &new_name),
			     key->key->keyname, pri_shunk(value));
			return NULL;
		case NAME_RENAMED_TO:
			llog(warning_stream, logger, PRI_KEYVAL_SAL": "PRI_SHUNK" renamed to %s: %s="PRI_SHUNK,
			     pri_keyval_sal(key),
			     pri_shunk(value), str_sparse_short(names, (*number), &new_name),
			     key->key->keyname, pri_shunk(value));
			return NULL;
		}
	}

	return NULL;
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
static bool parser_find_key(shunk_t skey, enum end default_end,
			    struct ipsec_conf_keyval *key,
			    struct parser *parser)
{
	bool left = false;
	bool right = false;

	zero(key);

	const struct keywords_def *keywords =
		(parser->section == SECTION_CONFIG_SETUP ? &config_setup_keywords :
		 &config_conn_keywords);

	const struct keyword_def *found = NULL;
	ITEMS_FOR_EACH(k, keywords) {

		if (k->keyname == NULL) {
			continue;
		}

		if (k->validity & kv_ignore) {
			continue;
		}

		if (parser->section == SECTION_CONN_DEFAULT &&
		    k->field == KSCF_ALSO) {
			continue;
		}

		if (hunk_strcaseeq(skey, k->keyname)) {

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
				found = k;
				break;
			}

			/*
			 * For instance --auth=... --to ...
			 */
			if (k->validity & kv_leftright) {
				if (default_end == LEFT_END) {
					left = true;
					found = k;
					break;
				}
				if (default_end == RIGHT_END) {
					right = true;
					found = k;
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
			found = k;
			break;
		}

		if (k->validity & kv_leftright) {
			left = parse_leftright(skey, k, "left");
			if (left) {
				found = k;
				break;
			}
			right = parse_leftright(skey, k, "right");
			if (right) {
				found = k;
				break;
			}
		}
	}

	/* if we still found nothing */
	if (found == NULL) {
		parser_fatal(parser, /*errno*/0, "unrecognized '%s' keyword '"PRI_SHUNK"'",
			     str_parser_section(parser), pri_shunk(skey));
		/* never returns */
		return false;
	}

	/* else, set up llval.k to point, and return KEYWORD */
	key->key = found;
	key->left = left;
	key->right = right;
	key->val = NULL; /* later */
	key->sal = scanner_sal(parser);
	return true;
}

void parse_keyval(struct parser *parser, enum end default_end,
		  shunk_t skey, shunk_t value)
{
	struct ipsec_conf_keyval key;
	if (!parser_find_key(skey, default_end, &key, parser)) {
		return;
	}

	/* fill in once look succeeds */
	PEXPECT(parser->logger, key.val == NULL);

	if (parser->section == SECTION_CONFIG_SETUP) {
		/*
		 * Throw everything onto the end of the list:
		 *
		 * Note: this includes kt_obsolete keyvalues.
		 * Note: this includes duplicate keywords.
		 */
		append_parser_key_value(parser, &key, value, 0, (deltatime_t){0});
		return;
	}


	uintmax_t number = 0;		/* neutral placeholding value */
	deltatime_t deltatime = {.is_set = false, };
	diag_t d = NULL;

	switch (key.key->type) {

	case kt_sparse_name:
		d = parse_kt_sparse_name(&key, value, &number,
					 parser->stream.warning,
					 parser->logger);
		break;

	case kt_string:
	case kt_also:
	case kt_appendstring:
	case kt_appendlist:
		break;

	case kt_unsigned:
		d = parse_kt_unsigned(&key, value, &number);
		break;

	case kt_seconds:
		d = parse_kt_deltatime(&key, value, TIMESCALE_SECONDS, &deltatime);
		break;

	case kt_obsolete:
		/* drop it on the floor */
		parser_key_value_warning(parser, &key, value, "obsolete keyword ignored");
		return;

	}

	if (d != NULL) {
		llog(WARNING_STREAM, parser->logger,
		     PRI_KEYVAL_SAL": %s, keyword ignored: %s%s="PRI_SHUNK,
		     pri_keyval_sal(&key), str_diag(d),
		     leftright(&key), key.key->keyname, pri_shunk(value));
		pfree_diag(&d);
		return;
	}

	add_parser_key_value(parser, &key, value, number, deltatime);
}
