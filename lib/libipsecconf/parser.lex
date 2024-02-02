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
#include <glob.h>

struct logger;
#define YY_DECL int yylex(struct logger *logger)
YY_DECL;

#include "ipsecconf/keywords.h"
#define YYDEBUG 1	/* HACK! for ipsecconf/parser.h AND parser.tab.h */
#include "ipsecconf/parser.h"	/* includes parser.tab.h */
#include "ipsecconf/parserlast.h"
#include "ipsecconf/starterlog.h"
#include "lswlog.h"

#define MAX_INCLUDE_DEPTH	10

int lex_verbosity = 0;	/* how much tracing output to show */

char rootdir[PATH_MAX];		/* when evaluating paths, prefix this to them */
char rootdir2[PATH_MAX];	/* or... try this one too */

static int parser_y_eof(struct logger *logger);

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
	ic_private.stack[0].once = true;
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

static int parser_y_nextglobfile(struct ic_inputsource *iis, struct logger *logger)
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
	iis->once = true;
	iis->filename = strdup(iis->fileglob.gl_pathv[fcnt]);

	/* open the file */
	f = fopen(iis->filename, "r");
	if (f == NULL) {
		char ebuf[128];

		snprintf(ebuf, sizeof(ebuf),
			(strstr(iis->filename, "crypto-policies/back-ends/libreswan.config") == NULL) ?
				"cannot open include filename: '%s': %s" :
				"ignored loading default system-wide crypto-policies file '%s': %s",
			iis->fileglob.gl_pathv[fcnt],
			strerror(errno));
		yyerror(logger, ebuf);
		return -1;
	}
	iis->file = f;

	yy_switch_to_buffer(yy_create_buffer(f, YY_BUF_SIZE));

	return 0;
}

static int globugh_include(const char *epath, int eerrno)
{
	starter_log(LOG_LEVEL_ERR, "problem with include filename '%s': %s",
		epath, strerror(eerrno));
	return 1;	/* stop glob */
}

int parser_y_include (const char *filename, struct logger *logger)
{
	const char *try;
	char newname[PATH_MAX];
	char newname2[PATH_MAX];
	glob_t globbuf;
	int globresult;

	globbuf.gl_offs = 0;

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
		globresult = glob(try, 0, globugh_include, &globbuf);
		if (globresult == GLOB_NOMATCH) {
			if (strchr(filename,'*') == NULL) {
				/* not a wildcard, throw error */
				starter_log(LOG_LEVEL_ERR,
					"warning: could not open include filename: '%s'",
					filename);
			} else {
				/* don't throw an error, just log a warning */
				ldbg(logger, "could not open include wildcard filename(s): '%s'",
				     filename);
			}
		}
	} else {
		/* try prefixing with rootdir */
		snprintf(newname, sizeof(newname), "%s%s", rootdir, filename);
		try = newname;

		globresult = glob(try, 0, globugh_include, &globbuf);
		if (globresult == GLOB_NOMATCH) {
			if (rootdir2[0] == '\0') {
				if (strchr(filename,'*') == NULL) {
					/* not a wildcard, throw error */
					starter_log(LOG_LEVEL_ERR,
						"warning: could not open include filename '%s' (tried '%s')",
						filename, newname);
				} else {
					/* don't throw an error, just log a warning */
					ldbg(logger, "could not open include wildcard filename(s) '%s' (tried '%s')",
					     filename, newname);
				}
			} else {
				/* try again, prefixing with rootdir2 */
				globfree(&globbuf);
				snprintf(newname2, sizeof(newname2),
					 "%s%s", rootdir2, filename);
				try = newname2;
				globresult = glob(try, 0, globugh_include, &globbuf);
				if (globresult == GLOB_NOMATCH) {
					starter_log(LOG_LEVEL_ERR,
						"warning: could not open include filename: '%s' (tried '%s' and '%s')",
						filename, newname, newname2);
				}
			}
		}
	}

	switch (globresult) {
	case 0:
		/* success */

		if (ic_private.stack_ptr >= MAX_INCLUDE_DEPTH - 1) {
			yyerror(logger, "max inclusion depth reached");
			return 1;
		}

		if (lex_verbosity > 0) {
			ldbg(logger, "including file '%s' ('%s') from %s:%u",
			     filename, try,
			     stacktop->filename,
			     stacktop->line);
		}
		++ic_private.stack_ptr;
		stacktop = &ic_private.stack[ic_private.stack_ptr];
		stacktop->state = YY_CURRENT_BUFFER;
		stacktop->fileglob = globbuf;
		stacktop->fileglobcnt = 0;
		stacktop->file = NULL;
		stacktop->filename = NULL;

		return parser_y_eof(logger);

	case GLOB_NOSPACE:
		starter_log(LOG_LEVEL_ERR,
			"out of space processing include filename \"%s\"",
			try);
		break;

	case GLOB_ABORTED:	/* already logged by globugh_include() */
	case GLOB_NOMATCH:	/* already logged above */
		break;

	default:
		starter_log(LOG_LEVEL_ERR, "unknown glob error %d", globresult);
		break;
	}

	/* error happened, but we ignore it */
	globfree(&globbuf);
	return 0;
}

static int parser_y_eof(struct logger *logger)
{
	if (stacktop->state != YY_CURRENT_BUFFER) {
		yy_delete_buffer(YY_CURRENT_BUFFER);
	}

	if (parser_y_nextglobfile(stacktop, logger) == -1) {
		/* no more glob'ed files to process */

		if (lex_verbosity > 0) {
			int stackp = ic_private.stack_ptr;

			ldbg(logger, "end of file %s", stacktop->filename);

			if (stackp > 0) {
				ldbg(logger, "resuming %s:%u",
				     ic_private.stack[stackp-1].filename,
				     ic_private.stack[stackp-1].line);
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
 * INITIAL: pre-defined and default lex state
 *
 * BOOLEAN_KEY, COMMENT_KEY, KEY: just matched the BOOLWORD,
 * "x-comment", other keyword; expecting '='
 *
 * VALUE: just matched '=' in KEY state; matches a quoted/braced/raw
 * string; returns to INITIAL state
 *
 * BOOLEAN_VALUE: just matched '=' in BOOLEAN_KEY state; matches a
 * boolean token; returns to INITIAL state
 *
 * COMMENT_VALUE: just matched '=' in COMMENT_KEY state; matches
 * everything up to \n as a string; returns to INITIAL state
 */

%x KEY VALUE BOOLEAN_KEY BOOLEAN_VALUE COMMENT_KEY COMMENT_VALUE

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
		stacktop->once = false;
		return EOL;
	}

	/*
	 * we've finished this file:
	 * continue with the file it was included from (if any)
	 */
	if (parser_y_eof(logger)) {
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

<INITIAL,BOOLEAN_VALUE>[\t ]+	/* ignore spaces in line */ ;

<VALUE>%forever	{
				/* a number, really 0 */
				yylval.s = strdup("0");
				BEGIN INITIAL;
				return STRING;
			}

<KEY,BOOLEAN_KEY,COMMENT_KEY>[\t ] /* eat blanks */
<KEY,BOOLEAN_KEY,COMMENT_KEY>\n {
				/* missing equals? */
				stacktop->line++;
				BEGIN INITIAL;
				return EOL;
			}
<KEY>=			{ BEGIN VALUE; return EQUAL; }
<BOOLEAN_KEY>=		{ BEGIN BOOLEAN_VALUE; return EQUAL; }
<COMMENT_KEY>=		{ BEGIN COMMENT_VALUE; return EQUAL; }

<VALUE,BOOLEAN_VALUE>[\t ] /* eat blanks (not COMMENT_VALUE) */
<VALUE,BOOLEAN_VALUE>\n	{
				/* missing value? (not COMMENT_VALUE) */
				stacktop->line++;
				BEGIN INITIAL;
				return EOL;
			}

<BOOLEAN_VALUE>1    |
<BOOLEAN_VALUE>y    |
<BOOLEAN_VALUE>yes  |
<BOOLEAN_VALUE>true |
<BOOLEAN_VALUE>on	{
				/* process a boolean */
				yylval.boolean = true;
				BEGIN INITIAL;
				return BOOLEAN;
			}

<BOOLEAN_VALUE>0     |
<BOOLEAN_VALUE>n     |
<BOOLEAN_VALUE>no    |
<BOOLEAN_VALUE>false |
<BOOLEAN_VALUE>off	{
				/* process a boolean */
				yylval.boolean = false;
				BEGIN INITIAL;
				return BOOLEAN;
			}

<COMMENT_VALUE>[^\n]*	{
				yylval.s = strdup(yytext);
				BEGIN INITIAL;
				return STRING;
			}

<VALUE>\"[^\"\n]*\"	{
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

<VALUE>\{[^\"\n]*\}	{
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

<VALUE>[^\" \t\n]+	{
				/* string-without-quotes-or-blanks */
				yylval.s = strdup(yytext);
				BEGIN INITIAL;
				return STRING;
			}

<VALUE>[^\{} \t\n]+	{
				/* string-without-braces-or-blanks */
				yylval.s = strdup(yytext);
				BEGIN INITIAL;
				return STRING;
			}

<INITIAL>\n		{
				stacktop->line++;
				return EOL;
			}

=			{ BEGIN VALUE; return EQUAL; }

version			return VERSION;

config			return CONFIG;

setup			return SETUP;

conn			{ BEGIN VALUE; return CONN; }

include			return INCLUDE;

[^\"= \t\n]+		{
				int tok;

				if (yydebug)
					fprintf(stderr, "STR/KEY: %s\n",
						yytext);
				tok = parser_find_keyword(yytext, &yylval);
				switch (tok) {
				case BOOLWORD:
					BEGIN BOOLEAN_KEY;
					break;
				case COMMENT:
					BEGIN COMMENT_KEY;
					break;
				default:
					BEGIN KEY;
					break;
				}
				return tok;
			}

#.*			{ /* eat comment to end of line */ }

.			yyerror(logger, yytext);
%%

int yywrap(void) {
	return 1;
}
