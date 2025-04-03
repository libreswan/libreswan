/* -*- flex-mode -*- */
%option nounput
%option noinput

%{
/* Libreswan config file parser (parser.l)
 * Copyright (C) 2001 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2003-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008, 2014 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 Philippe Vouters <Philippe.Vouters@laposte.net>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
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

/*
 * The generation of this code tends to always give us an unsigned vs signed
 * warning on one of our many OS + compiler + flex + arch combinations.
 * I'm just fed up with them... Paul
 */
#pragma GCC diagnostic ignored "-Wsign-compare"

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <limits.h>

struct parser;
#define YY_DECL int yylex(struct parser *parser)

#include "ipsecconf/keywords.h"
#define YYDEBUG 1	/* HACK! for ipsecconf/parser.h AND parser.tab.h */
#include "ipsecconf/parser.h"	/* includes parser.tab.h */
#include "ipsecconf/scanner.h"
#include "lswlog.h"
#include "lswglob.h"
#include "lswalloc.h"
#include "ipsecconf/scanner.h"

#define MAX_INCLUDE_DEPTH	10

static bool parser_y_eof(struct parser *parser);

/* we want no actual output! */
#define ECHO

struct ic_inputsource {
	YY_BUFFER_STATE state;
	FILE *file;
	unsigned int line;
	bool once;
	char *filename;
	int fileglobcnt;
	char **fileglob;
};

static struct {
	int stack_ptr;
	struct ic_inputsource stack[MAX_INCLUDE_DEPTH];
} ic_private;

static struct ic_inputsource *stacktop;

void jam_scanner_file_line(struct jambuf *buf)
{
	jam(buf, "%s:%u: ", stacktop->filename, stacktop->line);
}

void parser_y_init (const char *name, FILE *f)
{
	memset(&ic_private, 0, sizeof(ic_private));
	ic_private.stack[0].line = 1;
	ic_private.stack[0].once = true;
	ic_private.stack[0].file = f;
	ic_private.stack[0].filename = clone_str(name, "filename");
	stacktop = &ic_private.stack[0];
	ic_private.stack_ptr = 0;
	yyin = f;
}

static void parser_y_close(struct ic_inputsource *iis)
{
	pfreeany(iis->filename);
	if (iis->file != NULL) {
		fclose(iis->file);
		iis->file = NULL;
	}
	if (iis->fileglob != NULL) {
		for (char **p = iis->fileglob; *p; p++) {
			pfree(*p);
		}
		pfreeany(iis->fileglob);
	}
}

static bool parser_y_nextglobfile(struct ic_inputsource *iis, struct parser *parser)
{
	if (iis->fileglob == NULL) {
		/* EOF */
		ldbg(parser->logger, "EOF: no .fileglob");
		return false;
	}

	if (iis->fileglob[iis->fileglobcnt] == NULL) {
		/* EOF */
		ldbg(parser->logger, "EOF: .fileglob[%u] == NULL", iis->fileglobcnt);
		return false;
	}

	/* increment for next time */
	int fcnt = iis->fileglobcnt++;

	if (iis->file != NULL) {
		fclose(iis->file);
		iis->file = NULL;
	}
	pfreeany(iis->filename);

	iis->line = 1;
	iis->once = true;
	iis->filename = clone_str(iis->fileglob[fcnt], "fileglob");

	/* open the file */
	FILE *f = fopen(iis->filename, "r");
	if (f == NULL) {
		int e = errno;
		parser_warning(parser, e,
			       "cannot open include filename: '%s'",
			       iis->fileglob[fcnt]);
		return false;
	}
	iis->file = f;

	yy_switch_to_buffer(yy_create_buffer(f, YY_BUF_SIZE));

	return true;
}

struct lswglob_context {
        struct parser *parser;
	const char *filename;
	const char *try;
};

static void glob_include(unsigned count, char **files,
			  struct lswglob_context *context,
			  struct logger *logger)
{
	/* success */

	if (ic_private.stack_ptr >= MAX_INCLUDE_DEPTH - 1) {
		parser_warning(context->parser, /*errno*/0,
			       "including '%s' exceeds max inclusion depth of %u",
			       context->filename, MAX_INCLUDE_DEPTH);
		return;
	}

	if (context->parser->verbosity > 0) {
		ldbg(logger, "including file '%s' ('%s') from %s:%u",
		     context->filename, context->try,
		     stacktop->filename,
		     stacktop->line);
	}

	PASSERT(logger, ic_private.stack_ptr < sizeof(ic_private.stack) - 1);
	++ic_private.stack_ptr;
	stacktop = &ic_private.stack[ic_private.stack_ptr];
	stacktop->state = YY_CURRENT_BUFFER;
	stacktop->file = NULL;
	stacktop->filename = NULL;
	stacktop->fileglobcnt = 0;

	stacktop->fileglob = alloc_things(char *, count + 1, "globs");
	for (unsigned i = 0; i < count; i++) {
		stacktop->fileglob[i] = clone_str(files[i], "glob");
	}
	stacktop->fileglob[count] = NULL;

	parser_y_eof(context->parser);
}

void parser_y_include (const char *filename, struct parser *parser)
{
	struct lswglob_context context = {
		.filename = filename,
		.parser = parser,
	};

	if (filename[0] != '/' || parser->rootdir == NULL) {
		/* try plain name, with no rootdirs */
		context.try = filename;
		if (lswglob(context.try, "ipsec.conf", glob_include, &context, parser->logger)) {
			return;
		}
		/*
		 * Not a wildcard, throw error.
		 *
		 * XXX: throw?
		 */
		parser_warning(parser, /*errno*/0,
			       "could not open include filename: '%s'",
			       filename);
		return;
	}

	/* try prefixing with rootdir */
	char *newname = alloc_printf("%s%s", parser->rootdir[0], filename); /* must free */
	context.try = newname;

	if (lswglob(context.try, "ipsec.conf", glob_include, &context, parser->logger)) {
		pfree(newname);
		return;
	}

	if (parser->rootdir[1] == NULL) {
		/* not a wildcard, throw error */
		parser_warning(parser, /*errno*/0,
			       "could not open include filename '%s' (tried '%s')",
			       filename, newname);
		pfree(newname);
		return;
	}

	/* try again, prefixing with rootdir2 */
	char *newname2 = alloc_printf("%s%s", parser->rootdir[1], filename); /* must free */
	context.try = newname2;
	if (lswglob(context.try, "ipsec.conf", glob_include, &context, parser->logger)) {
		pfree(newname);
		pfree(newname2);
		return;
	}

	parser_warning(parser, /*errno*/0,
		       "could not open include filename: '%s' (tried '%s' and '%s')",
		       filename, newname, newname2);

	pfree(newname);
	pfree(newname2);
	return;
}

static bool parser_y_eof(struct parser *parser)
{
	if (stacktop->state != YY_CURRENT_BUFFER) {
		yy_delete_buffer(YY_CURRENT_BUFFER);
	}

	if (!parser_y_nextglobfile(stacktop, parser)) {
		/* no more glob'ed files to process */

		if (parser->verbosity > 0) {
			int stackp = ic_private.stack_ptr;

			ldbg(parser->logger, "end of file %s", stacktop->filename);

			if (stackp > 0) {
				ldbg(parser->logger, "resuming %s:%u",
				     ic_private.stack[stackp-1].filename,
				     ic_private.stack[stackp-1].line);
			}
		}

		if (stacktop->state != YY_CURRENT_BUFFER) {
			yy_switch_to_buffer(stacktop->state);
		}

		parser_y_close(stacktop);

		if (--ic_private.stack_ptr < 0) {
			return true;
		}
		stacktop = &ic_private.stack[ic_private.stack_ptr];
	}
	return false;
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
void parser_find_keyword(shunk_t s, struct keyword *kw, struct parser *parser)
{
	bool left = false;
	bool right = false;

	(*kw) = (struct keyword) {0};

	const struct keyword_def *k;
	for (k = ipsec_conf_keywords; k->keyname != NULL; k++) {
		if (hunk_strcaseeq(s, k->keyname)) {
			if ((k->validity & kv_both) == kv_both) {
				left = true;
				right = true;
				break;
			}
			if (k->validity & kv_leftright) {
#if 0 /* see github#663 */
				left = true;
#endif
				right = true;
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
		parser_fatal(parser, /*errno*/0, "unrecognized keyword '"PRI_SHUNK"'",
			     pri_shunk(s));
	}

	/* else, set up llval.k to point, and return KEYWORD */
	kw->keydef = k;
	kw->keyleft = left;
	kw->keyright = right;
}

%}

/* lexical states:
 *
 * INITIAL: pre-defined and default lex state
 *
 * COMMENT_KEY, KEY: just matched the "x-comment", other keyword;
 * expecting '='
 *
 * VALUE: just matched '=' in KEY state; matches a quoted/braced/raw
 * string; returns to INITIAL state
 *
 * COMMENT_VALUE: just matched '=' in COMMENT_KEY state; matches
 * everything up to \n as a string; returns to INITIAL state
 */

%x KEY VALUE COMMENT_KEY COMMENT_VALUE

%%

<<EOF>>	{
	ldbg(parser->logger, "EOF: stacktop->filename = %s",
	     stacktop->filename == NULL ? "<null>" : stacktop->filename);

	/*
	 * Add a newline at the end of the file in case one was missing.
	 * This code assumes that EOF is sticky:
	 * that it can be detected repeatedly.
	 */
	if (stacktop->once) {
		stacktop->once = false;
		return EOL;
	}

	/*
	 * we've finished this file:
	 * continue with the file it was included from (if any)
	 */
	if (parser_y_eof(parser)) {
		yyterminate();
	}
}

^[\t ]*#.*\n		{
				/* eat comment lines */
				stacktop->line++;
			}

^[\t ]*\n		{
				/* eat blank lines */
				stacktop->line++;
			}

^[\t ]+			return FIRST_SPACES;

<INITIAL>[\t ]+		/* ignore spaces in line */ ;

<VALUE>%forever		{
				/* a number, really 0 */
				yylval.s = clone_str("0", "string");
				BEGIN INITIAL;
				return STRING;
			}

<KEY>[\t ]	/* eat blanks */
<KEY>\n	{
				/* missing equals? */
				stacktop->line++;
				BEGIN INITIAL;
				return EOL;
			}
<KEY>=			{ BEGIN VALUE; return EQUAL; }

<VALUE>[\t ]		/* eat blanks (not COMMENT_VALUE) */
<VALUE>\n		{
				/* missing value? (not COMMENT_VALUE) */
				stacktop->line++;
				BEGIN INITIAL;
				return EOL;
			}

<VALUE>\"[^\"\n]*\"	{
				/* "string" */
				char *s = yytext + 1;
				int len = strlen(s);

				assert(len>0);

				/* remove trailing " */
				s[len-1] = '\0';
				yylval.s = clone_str(s, "yyval.s");
				BEGIN INITIAL;
				return STRING;
			}

<VALUE>\{[^\"\n]*\}	{
				/* { string-without-quotes } */
				char *s = yytext + 1;
				int len = strlen(s);

				assert(len > 0);

				/* remove trailing } */
				s[len-1] = '\0';
				yylval.s = clone_str(s, "yyval.s");
				BEGIN INITIAL;
				return STRING;
			}

<VALUE>[^\" \t\n]+	{
				/* string-without-quotes-or-blanks */
				yylval.s = clone_str(yytext, "string-without-quotes-or-blanks");
				BEGIN INITIAL;
				return STRING;
			}

<VALUE>[^\{} \t\n]+	{
				/* string-without-braces-or-blanks */
				yylval.s = clone_str(yytext, "string-without-braces-or-blanks");
				BEGIN INITIAL;
				return STRING;
			}

<INITIAL>\n		{
				stacktop->line++;
				return EOL;
			}

=			{ BEGIN VALUE; return EQUAL; }

version			{ BEGIN VALUE; return VERSION; }

config			return CONFIG;

setup			return SETUP;

conn			{ BEGIN VALUE; return CONN; }

include			{ BEGIN VALUE; return INCLUDE; }

[Xx][_-][^\"= \t\n]+	{
				yylval.s = clone_str(yytext, "X-s");
				BEGIN COMMENT_KEY;
				return COMMENT;
			}
<COMMENT_KEY>[\t ]	/* eat blanks */
<COMMENT_KEY>=		{
				BEGIN COMMENT_VALUE;
				return EQUAL;
			}
<COMMENT_KEY>\n		{
				/* missing equals? */
				stacktop->line++;
				BEGIN INITIAL;
				return EOL;
			}
<COMMENT_VALUE>\n	{
				BEGIN INITIAL;
				return EOL;
			}
<COMMENT_VALUE>[^\n]*	{
				yylval.s = clone_str(yytext, "comment-value");
				BEGIN INITIAL;
				return STRING;
			}

[^\"= \t\n]+		{
				zero(&yylval);
				/* does not return when lookup fails */
				parser_find_keyword(shunk1(yytext), &yylval.k, parser);
				BEGIN KEY;
				return KEYWORD;
			}

#.*			{ /* eat comment to end of line */ }

.			{
				parser_warning(parser, /*errno*/0,
					       "unrecognized: %s", yytext);
			}
%%

int yywrap(void) {
	return 1;
}
