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
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include <sys/queue.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <limits.h>
#include <glob.h>
#include <ctype.h>

#include "ipsecconf/keywords.h"
#define YYDEBUG 1	/* HACK! for ipsecconf/parser.h AND parser.tab.h */
#include "ipsecconf/parser.h"	/* includes parser.tab.h */
#include "ipsecconf/parserlast.h"
#include "ipsecconf/starterlog.h"

#define MAX_INCLUDE_DEPTH	10

int lex_verbosity = 0;	/* how much tracing output to show */

char rootdir[PATH_MAX];		/* when evaluating paths, prefix this to them */
char rootdir2[PATH_MAX];	/* or... try this one too */

static int parser_y_eof(void);

/* we want no actual output! */
#define ECHO

struct ic_inputsource {
	YY_BUFFER_STATE state;
	FILE *file;
	unsigned int line;
	bool once;
	char *filename;
	int fileglobcnt;
	glob_t fileglob;
};

static struct {
	int stack_ptr;
	struct ic_inputsource stack[MAX_INCLUDE_DEPTH];
} ic_private;

static struct ic_inputsource *stacktop;

char *parser_cur_filename(void)
{
	return stacktop->filename;
}

int parser_cur_lineno(void)
{
	return stacktop->line;
}

void parser_y_error(char *b, int size, const char *s)
{
#if defined(SOMETHING_FOR_SOME_ARCH)
	extern char *yytext;
#endif
	snprintf(b, size, "%s:%u: %s [%s]",
		stacktop->filename == NULL ? "<none>" : stacktop->filename,
		stacktop->line,
		s, yytext);
}

void parser_y_init (const char *name, FILE *f)
{
	memset(&ic_private, 0, sizeof(ic_private));
	ic_private.stack[0].line = 1;
	ic_private.stack[0].once = TRUE;
	ic_private.stack[0].file = f;
	ic_private.stack[0].filename = strdup(name);
	stacktop = &ic_private.stack[0];
	ic_private.stack_ptr = 0;
}

static void parser_y_close(struct ic_inputsource *iis)
{
	if (iis->filename != NULL) {
		free(iis->filename);
		iis->filename = NULL;
	}
	if (iis->file != NULL) {
		fclose(iis->file);
		iis->file = NULL;
	}
	if (iis->fileglob.gl_pathv != NULL) {
		globfree(&iis->fileglob);
		iis->fileglob.gl_pathv = NULL;
	}
}

#if 0	/* never used */
static void parser_y_fini(void)
{
	unsigned int i;

	for (i = 0; i < MAX_INCLUDE_DEPTH; i++) {
		parser_y_close(&ic_private.stack[i]);
	}
	memset(&ic_private, 0, sizeof(ic_private));
}
#endif

static int parser_y_nextglobfile(struct ic_inputsource *iis)
{
	FILE *f;
	int fcnt;

#if 0
	printf("fileglobcnt: %d pathc: %d cmp: %u\n",
		iis->fileglobcnt, stacktop->fileglob.gl_pathc,
		(iis->fileglobcnt >= (int)stacktop->fileglob.gl_pathc));
#endif

	if ((int)iis->fileglobcnt >= (int)stacktop->fileglob.gl_pathc) {
		/* EOFiles */
		return -1;
	}

	/* increment for next time */
	fcnt = iis->fileglobcnt++;

	if (iis->file != NULL) {
		fclose(iis->file);
		iis->file = NULL;
	}
	if (iis->filename != NULL) {
		free(iis->filename);
		iis->filename = NULL;
	}

	iis->line = 1;
	iis->once = TRUE;
	iis->filename = strdup(iis->fileglob.gl_pathv[fcnt]);

	/* open the file */
	f = fopen(iis->filename, "r");
	if (f == NULL) {
		char ebuf[128];

		snprintf(ebuf, sizeof(ebuf),
			"cannot open include filename: '%s'",
			iis->fileglob.gl_pathv[fcnt]);
		yyerror(ebuf);
		return -1;
	}
	iis->file = f;

	yy_switch_to_buffer(yy_create_buffer(f, YY_BUF_SIZE));

	return 0;
}

int parser_y_include (const char *filename)
{
	const char *try;
	char newname[PATH_MAX];
	char newname2[PATH_MAX];
	glob_t globbuf;
	int globresult;

	globbuf.gl_offs = 0;

	/*
	 * If the filename starts with /, we try to find it prefixed with
	 * rootdir or rootdir2.
	 *
	 * glob() returns a match if that file exists, even without
	 * having to do any globbing.
	 *
	 * Use GNU GLOB_BRACE extension to glob(3) if available.
	 */

#ifdef GLOB_BRACE
# define GB GLOB_BRACE
#else
# define GB 0
#endif

	/*
	 * If there is no rootdir, but there is a rootdir2, swap them.
	 * This reduces the number of cases to be handled.
	 */
	if (rootdir[0] == '\0' && rootdir2[0] != '\0') {
		strcpy(rootdir, rootdir2);
		rootdir2[0] = '\0';
	}

	if (filename[0] != '/' || rootdir[0] == '\0') {
		/* try plain name, with no rootdirs */
		try = filename;
		globresult = glob(try, GB, NULL, &globbuf);
		if (globresult == GLOB_NOMATCH) {
			/* no files found... */
			starter_log(LOG_LEVEL_ERR,
				"warning: could not open include filename: '%s'",
				filename);
			globfree(&globbuf);
			return 0;
		}
	} else {
		/* try prefixing with rootdir */
		snprintf(newname, sizeof(newname), "%s%s", rootdir, filename);
		try = newname;

		globresult = glob(try, GB, NULL, &globbuf);
		if (globresult == GLOB_NOMATCH) {
			if (rootdir2[0] == '\0') {
				starter_log(LOG_LEVEL_ERR,
					"warning: could not open include filename '%s' (tried '%s')",
					filename, newname);
				globfree(&globbuf);
				return 0;
			} else {
				/* try prefixing with rootdir2 */
				snprintf(newname2, sizeof(newname2),
					 "%s%s", rootdir2, filename);
				try = newname2;
				globresult = glob(try, GB, NULL, &globbuf);
				if (globresult == GLOB_NOMATCH) {
				starter_log(LOG_LEVEL_ERR,
					"warning: could not open include filename: '%s' (tried '%s' and '%s')",
					filename, newname, newname2);
				globfree(&globbuf);
				return 0;
				}
			}
		}
	}

#undef GB


	if (ic_private.stack_ptr >= MAX_INCLUDE_DEPTH) {
		yyerror("max inclusion depth reached");
		return 1;
	}

	if (lex_verbosity > 0) {
		starter_log(LOG_LEVEL_DEBUG,
			    "including file '%s' ('%s') from %s:%u"
			    , filename, try
			    , stacktop->filename
			    , stacktop->line);
	}

	++ic_private.stack_ptr;
	stacktop = &ic_private.stack[ic_private.stack_ptr];
	stacktop->state = YY_CURRENT_BUFFER;
	stacktop->fileglob = globbuf;
	stacktop->fileglobcnt = 0;
	stacktop->file = NULL;
	stacktop->filename = NULL;

	return parser_y_eof();
}

static int parser_y_eof(void)
{
	if (stacktop->state != YY_CURRENT_BUFFER) {
		yy_delete_buffer(YY_CURRENT_BUFFER);
	}

	if (parser_y_nextglobfile(stacktop) == -1) {
		/* no more glob'ed files to process */

		if (lex_verbosity > 0) {
			int stackp = ic_private.stack_ptr;

			starter_log(LOG_LEVEL_DEBUG,
				    "end of file %s", stacktop->filename);

			if (stackp > 0) {
				starter_log(LOG_LEVEL_DEBUG,
					"resuming %s:%u"
					, ic_private.stack[stackp-1].filename
					, ic_private.stack[stackp-1].line);
			}
		}

		if (stacktop->state != YY_CURRENT_BUFFER) {
			yy_switch_to_buffer(stacktop->state);
		}

		parser_y_close(stacktop);

		if (--ic_private.stack_ptr < 0) {
			return 1;
		}
		stacktop = &ic_private.stack[ic_private.stack_ptr];
	}
	return 0;
}

%}

/* lexical states:
 *
 * INITIAL
 * USERDEF: after <INITIAL>"=" or <INITIAL>"conn"; returns to INITIAL after next token (integer or string)
 * BOOLEAN: after keyword with BOOLWORD attribute; followed by '='; returns to INITIAL after next token (bool)
 * COMMENTEQUAL: after keyword "x-comment"; followed by = and then switches to COMMENTSTRING
 * COMMENTSTRING: after = in COMMENTEQUAL state; everything up to \n is a string; then returns to INITIAL
 */

%x USERDEF BOOLEAN COMMENTEQUAL COMMENTSTRING

%%

<<EOF>>	{
#if 0
	printf("EOF: stacktop->filename = %s\n",
		stacktop->filename == NULL ? "NULL" : stacktop->filename);
#endif
	/*
	 * Add a newline at the end of the file in case one was missing.
	 * This code assumes that EOF is sticky:
	 * that it can be detected repeatedly.
	 */
	if (stacktop->once) {
		stacktop->once = FALSE;
		return EOL;
	}

	/*
	 * we've finished this file:
	 * continue with the file it was included from (if any)
	 */
	if (parser_y_eof()) {
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

<INITIAL,BOOLEAN>[\t ]+	/* ignore spaces in line */ ;

<INITIAL,USERDEF>[0-9]+	{
				/* process a number */
				unsigned long val = (errno = 0, strtoul(yytext, NULL, 10));

				if (errno != 0 || val > UINT_MAX) {
					char ebuf[128];

					snprintf(ebuf, sizeof(ebuf),
						"number too large: %s",
						yytext);
					yyerror(ebuf);
				}
				yylval.num = val;
				BEGIN INITIAL;
				return INTEGER;
			}

<USERDEF>%forever	{
				/* a number, really 0 */
				yylval.num = 0;
				BEGIN INITIAL;
				return INTEGER;
			}

<BOOLEAN>y    |
<BOOLEAN>yes  |
<BOOLEAN>true |
<BOOLEAN>on		{
				/* process a boolean */
				yylval.num = 1;
				BEGIN INITIAL;
				return BOOL;
			}

<BOOLEAN>n     |
<BOOLEAN>no    |
<BOOLEAN>false |
<BOOLEAN>off		{
				/* process a boolean */
				yylval.num = 0;
				BEGIN INITIAL;
				return BOOL;
			}

<BOOLEAN>=		return EQUAL;

<BOOLEAN>\n		{
				stacktop->line++;
				BEGIN INITIAL;
				return EOL;
			}

<COMMENTEQUAL>=		{
				BEGIN COMMENTSTRING;
				return EQUAL;
			}

<COMMENTSTRING>[^\n]*	{
				yylval.s = strdup(yytext);
				BEGIN INITIAL;
				return STRING;
			}

<USERDEF>\"[^\"\n]*\"	{
				/* "string" */
				char *s = yytext + 1;
				int len = strlen(s);

				assert(len>0);

				/* remove trailing " */
				s[len-1] = '\0';
				if (yydebug)
					fprintf(stderr, "STRING: \"%s\"\n", s);
				yylval.s = strdup(s);
				BEGIN INITIAL;
				return STRING;
			}

<USERDEF>\{[^\"\n]*\}	{
				/* { string-without-quotes } */
				char *s = yytext + 1;
				int len = strlen(s);

				assert(len > 0);

				/* remove trailing } */
				s[len-1] = '\0';
				if (yydebug)
					fprintf(stderr, "STRING{}: {%s}\n", s);
				yylval.s = strdup(s);
				BEGIN INITIAL;
				return STRING;
			}

<USERDEF>[^\" \t\n]+	{
				/* string-without-quotes-or-whitespace */
				yylval.s = strdup(yytext);
				BEGIN INITIAL;
				return STRING;
			}

<USERDEF>[^\{} \t\n]+	{
				/* string-without-braces-or-whitespace */
				yylval.s = strdup(yytext);
				BEGIN INITIAL;
				return STRING;
			}

\n			{
				stacktop->line++;
				return EOL;
			}

=			{ BEGIN USERDEF; return EQUAL; }

version			return VERSION;

config			return CONFIG;

setup			return SETUP;

conn			{ BEGIN USERDEF; return CONN; }

include			return INCLUDE;

[^\"= \t\n]+		{
				int tok;

				if (yydebug)
					fprintf(stderr, "STR/KEY: %s\n",
						yytext);
				tok = parser_find_keyword(yytext, &yylval);
				switch (tok)
				{
				case BOOLWORD:
					BEGIN BOOLEAN;
					break;
				case COMMENT:
					BEGIN COMMENTEQUAL;
					break;
				default:
					break;
				}
				return tok;
			}

#.*			{ /* eat comment to end of line */ }

.			yyerror(yytext);
%%

int yywrap(void) {
	return 1;
}
