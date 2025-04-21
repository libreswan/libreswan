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
#include "end.h"

#define MAX_INCLUDE_DEPTH	10

static bool scanner_next_file(struct parser *parser);

/* we want no actual output! */
#define ECHO

struct input_source {
	YY_BUFFER_STATE saved_buffer;
	FILE *file;
	char *filename;
	unsigned int line;
	bool once;
	unsigned current;
	char **includes;
	unsigned level;
	struct input_source *next;
};

void jam_scanner_file_line(struct jambuf *buf, struct parser *parser)
{
	jam(buf, "%s:%u: ", parser->input->filename, parser->input->line);
}

void scanner_init(struct parser *parser, const char *name, int start)
{
	parser->input = alloc_thing(struct input_source, __func__);
	parser->input->line = start;
	parser->input->once = true;
	parser->input->level = 1;
	parser->input->filename = clone_str(name, "filename");
}

bool scanner_open(struct parser *parser, const char *file)
{
	FILE *f = (streq(file, "-") ? fdopen(STDIN_FILENO, "r") : fopen(file, "r"));
	if (f == NULL) {
		llog_error(parser->logger, errno, "could not open '%s'", file);
		return false;
	}

	scanner_init(parser, file, 1);
	parser->input->file = f;
	yyin = f;
	return true;
}

void scanner_close(struct parser *parser)
{
	passert(parser->input->next == NULL);
	if (parser->input->file != NULL) {
		fclose(parser->input->file);
	}
	pfree(parser->input->filename);
	pfree(parser->input);
	parser->input = NULL;
}

void scanner_next_line(struct parser *parser)
{
	parser->input->line++;
}

static bool scanner_next_include_file(struct parser *parser)
{
	if (parser->verbosity > 0) {
		ldbg(parser->logger, "including next file after '%s' for %s:%u level %u",
		     parser->input->filename,
		     parser->input->next->filename,
		     parser->input->next->line,
		     parser->input->next->level);
	}

	/*
	 * Clean up the previous include file.
	 */
	fclose(parser->input->file);
	parser->input->file = NULL;
	yy_delete_buffer(YY_CURRENT_BUFFER);

	parser->input->current++; /* advance */
	parser->input->filename = parser->input->includes[parser->input->current];
	if (parser->input->filename == NULL) {
		ldbg(parser->logger, "EOF: .includes[] == NULL");
		return false;
	}

	/* advance to the new include file */
	parser->input->line = 1;
	parser->input->once = true;

	/* open the new file */
	parser->input->file = fopen(parser->input->filename, "r");
	if (parser->input->file == NULL) {
		int e = errno;
		parser_warning(parser, e,
			       "cannot open include filename: '%s'",
			       parser->input->filename);
		return false;
	}

	/* Switch YY_CURRENT_BUFFER to the new buffer */
	yy_switch_to_buffer(yy_create_buffer(parser->input->file, YY_BUF_SIZE));

	return true;
}

struct lswglob_context {
        struct parser *parser;
	const char *filename;
	const char *try;
};

static void glob_include_callback(unsigned count, char **files,
				  struct lswglob_context *context,
				  struct logger *logger)
{
	/* success */

	if (context->parser->input->level >= MAX_INCLUDE_DEPTH) {
		parser_warning(context->parser, /*errno*/0,
			       "including '%s' exceeds max inclusion depth of %u",
			       context->filename, MAX_INCLUDE_DEPTH);
		return;
	}

	if (context->parser->verbosity > 0) {
		ldbg(logger, "including files '%s' ('%s') from %s:%u level %u",
		     context->filename, context->try,
		     context->parser->input->filename,
		     context->parser->input->line,
		     context->parser->input->level);
	}

	/*
	 * Try to open the first of the files.  No point continuing
	 * when it fails.
	 *
	 * When the glob doesn't match, this code is not called.
	 */
	PASSERT(logger, count > 0);
	FILE *file = fopen(files[0], "r");
	if (file == NULL) {
		int e = errno;
		parser_warning(context->parser, e,
			       "cannot open include file '%s' ('%s') from %s:%u level %u",
			       files[0], context->filename,
			       context->parser->input->filename,
			       context->parser->input->line,
			       context->parser->input->level);
		return;
	}

	/*
	 * Since the file is ok, build a new input_source, and in it
	 * the list of expanded files needing to be included.
	 */
	struct input_source *iis = alloc_thing(struct input_source, __func__);
	iis->includes = alloc_things(char *, count + 1, "includes"); /* NULL terminated */
	for (unsigned i = 0; i < count; i++) {
		iis->includes[i] = clone_str(files[i], "include");
	}
	iis->line = 1;
	iis->includes[count] = NULL;
	iis->current = 0;
	iis->file = file;
	iis->level = context->parser->input->level + 1;
	iis->filename = iis->includes[0];

	/*
	 * Save current buffer and switch YY_CURRENT_BUFFER to a new
	 * one.
	 */
	iis->saved_buffer = YY_CURRENT_BUFFER;
	yy_switch_to_buffer(yy_create_buffer(iis->file, YY_BUF_SIZE));

	/*
	 * Finally push the new input_source.
	 */
	iis->next = context->parser->input;
	context->parser->input = iis;
}

void scanner_include(const char *filename, struct parser *parser)
{
	struct lswglob_context context = {
		.filename = filename,
		.parser = parser,
	};

	context.try = filename;
	if (lswglob(context.try, "ipsec.conf", glob_include_callback, &context, parser->logger)) {
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

static bool scanner_next_file(struct parser *parser)
{
	if (parser->input->next != NULL) {
		if (scanner_next_include_file(parser)) {
			return true;
		}
		ldbg(parser->logger, "resuming %s:%u level %u",
		     parser->input->next->filename,
		     parser->input->next->line,
		     parser->input->next->level);
	} else {
		ldbg(parser->logger, "no more include files");
	}

	/* no more include files to process */

	if (parser->input->next == NULL) {
		return false;
	}

	/* Restore YY_CURRENT_BUFFER. */
	yy_switch_to_buffer(parser->input->saved_buffer);

	/* Cleanup */
	for (char **p = parser->input->includes; *p; p++) {
		pfree(*p);
	}
	pfreeany(parser->input->includes);

	/* pop the stack */
	struct input_source *stacktop = parser->input;
	parser->input = parser->input->next;

	pfree(stacktop);

	return true;
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
	ldbg(parser->logger, "EOF: input->filename = %s",
	     parser->input->filename == NULL ? "<null>" : parser->input->filename);

	/*
	 * Add a newline at the end of the file in case one was
	 * missing.
	 *
	 * This code assumes that EOF is sticky: that it can be
	 * detected repeatedly.
	 */
	if (parser->input->once) {
		parser->input->once = false;
		return EOL;
	}

	/*
	 * We've finished this file.  Continue with the next include
	 * file, or the file doing the including.
	 */
	if (!scanner_next_file(parser)) {
		yyterminate();
	}
}

^[\t ]*#.*\n		{
				/* eat comment lines */
				scanner_next_line(parser);
			}

^[\t ]*\n		{
				/* eat blank lines */
				scanner_next_line(parser);
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
				scanner_next_line(parser);
				BEGIN INITIAL;
				return EOL;
			}
<KEY>=			{ BEGIN VALUE; return EQUAL; }

<VALUE>[\t ]		/* eat blanks (not COMMENT_VALUE) */
<VALUE>\n		{
				/* missing value? (not COMMENT_VALUE) */
				scanner_next_line(parser);
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
				scanner_next_line(parser);
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
				scanner_next_line(parser);
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
				yylval.s = clone_str(yytext, "key");
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
