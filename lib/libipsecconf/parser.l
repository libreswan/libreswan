/* -*- flex-mode -*- */
%option nounput
%option noinput

%top{
/* Libreswan config file parser (parser.l)
 * Copyright (C) 2001 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2003-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 D. Hugh Redelmeier <hugh@mimosa.com>
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
#include "ipsecconf/parser.h"
#include "parser.tab.h"
#include "ipsecconf/parserlast.h"
#include "ipsecconf/starterlog.h"
}

%{ 
#define MAX_INCLUDE_DEPTH  10

int lex_verbosity = 0;	/* how much tracing output to show */

char rootdir[PATH_MAX];      /* when evaluating paths, prefix this to them */
char rootdir2[PATH_MAX];     /* or... try this one too */

int parser_y_eof(void);

/* we want no actual output! */
#define ECHO 

/* do not define this function, as it is not used, and fails -Werror */
#if 0
#define YY_NO_INPUT
#endif

struct ic_inputsource {
	YY_BUFFER_STATE state;
	FILE  *file;
	unsigned int line;
	unsigned int once;
	char  *filename;
	int    fileglobcnt;
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

int  parser_cur_lineno(void)
{
    return stacktop->line;
}

void parser_y_error(char *b, int size, const char *s)
{
#if defined(SOMETHING_FOR_SOME_ARCH)
       extern char *yytext;
#endif
       snprintf(b, size, "%s:%d: %s [%s]",
		stacktop->filename ? stacktop->filename : "<none>",
                stacktop->line,
                s, yytext);
}

void parser_y_init (const char *name, FILE *f)
{
	memset(&ic_private, 0, sizeof(ic_private));
	ic_private.stack[0].line = 1;
	ic_private.stack[0].once = 1;
	ic_private.stack[0].file = f;
	ic_private.stack[0].filename = strdup(name);
	stacktop = &ic_private.stack[0];
	ic_private.stack_ptr = 0;
}

static void parser_y_close(struct ic_inputsource *iis)
{
	if (iis->filename) {
		free(iis->filename);
		iis->filename=NULL;
	}
	if (iis->file) {
		fclose(iis->file);
		iis->file=NULL;
	}
	if (iis->fileglob.gl_pathv) {
		globfree(&iis->fileglob);
		iis->fileglob.gl_pathv=NULL;
	}
}

void parser_y_fini (void)
{
	unsigned int i;

	for (i=0; i<MAX_INCLUDE_DEPTH; i++) {
		parser_y_close(&ic_private.stack[i]);
		
	}
	memset(&ic_private, 0, sizeof(ic_private));
}

static int parser_y_nextglobfile(struct ic_inputsource *iis)
{
	FILE *f;
	int  fcnt;

#if 0
	printf("fileglobcnt: %d pathc: %d cmp: %u\n", 
	       iis->fileglobcnt, stacktop->fileglob.gl_pathc,
	       (iis->fileglobcnt >= (int)stacktop->fileglob.gl_pathc));
#endif

	if((int)iis->fileglobcnt >= (int)stacktop->fileglob.gl_pathc) {
		/* EOFiles */
		return -1;
	}

	/* increment for next time  */
	fcnt = iis->fileglobcnt++;

	if(iis->file)     { fclose(iis->file);   iis->file=NULL; }
	if(iis->filename) { free(iis->filename); iis->filename=NULL;}

	iis->line  = 1;
	iis->once = 1;
	iis->filename = strdup(iis->fileglob.gl_pathv[fcnt]);

	/* open the file */
	f = fopen(iis->filename, "r");
	if (!f) {
                char ebuf[128];
		snprintf(ebuf, 128, "can not open include filename: '%s'", iis->fileglob.gl_pathv[fcnt]);
                yyerror(ebuf);
		return -1;
	}
	iis->file  = f;

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

	try = filename;
	newname[0]='\0';
	newname2[0]='\0';

	/*
	 * order of operations is: try rootdir, and then rootdir2
	 * only if it starts with /.
	 * We never try plain name in that situation.
	 *
	 * glob() returns a match if that file exists, even without
	 * having to do any globbing.
	 */

	if(rootdir[0]!='\0' && filename[0]=='/')
        {
	    snprintf(newname, PATH_MAX, "%s%s", rootdir, filename);
	    try = newname;

	    globresult = glob(try, GLOB_BRACE, NULL, &globbuf);
	    if(globresult == GLOB_NOMATCH && rootdir2[0]!='\0') {
		    /* now try with rootdir2 */
		    snprintf(newname2, PATH_MAX,
			     "%s%s", rootdir2, filename);
		    try = newname2;
			    
		    globresult = glob(try, GLOB_BRACE|GLOB_NOMAGIC, NULL, &globbuf);
	    }
	} else {
		/* try globbing plain name now.. */
		globresult = glob(try, GLOB_BRACE|GLOB_NOMAGIC, NULL, &globbuf);
	}

	if(globresult == GLOB_NOMATCH)
	{
		/* no files found... */
		starter_log(LOG_LEVEL_INFO, "warning: could not open include filename: '%s' (tried %s and %s)", filename, newname, newname2);
		globfree(&globbuf);
		return 0;
	}

	if (ic_private.stack_ptr >= MAX_INCLUDE_DEPTH)
	{
		yyerror("max inclusion depth reached");
		return 1;
	}

	if (lex_verbosity > 0)
	{
		starter_log(LOG_LEVEL_DEBUG, "including file '%s'(%s) from line %s:%d\n"
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
	stacktop->filename=NULL;

	return parser_y_eof();
}

int parser_y_eof(void)
{
	if(stacktop->state != YY_CURRENT_BUFFER) {
		yy_delete_buffer(YY_CURRENT_BUFFER);
	}

	if(parser_y_nextglobfile(stacktop) == -1) {
		/* no more glob'ed files to process */
		
		if (lex_verbosity > 0)
		{
			int stackp = ic_private.stack_ptr;
			starter_log(LOG_LEVEL_DEBUG,
				    "end of file %s\n",stacktop->filename);

			if(stackp > 0) {
				starter_log(LOG_LEVEL_DEBUG,
					    "resuming %s line %d\n"
					    , ic_private.stack[stackp-1].filename 
					    , ic_private.stack[stackp-1].line);
			}
		}
		
		if(stacktop->state != YY_CURRENT_BUFFER)  {
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
     * USERDEF: after "="
     * BOOLEAN: after keyword with BOOLWORD attribute, until \n
     * COMMENTEQUAL: after keyword "x-comment"
     * COMMENTSTRING: after = in COMMENTEQUAL state, until \n
     */

%x USERDEF BOOLEAN COMMENTEQUAL COMMENTSTRING

%%

<<EOF>>	{
#if 0
	printf("stacktop->filename = %s\n",
		stacktop->filename != NULL ? stacktop->filename : "NULL");
#endif
	if (stacktop->file){
	    char ch;
	    fseek(stacktop->file,-1L,SEEK_END);
	    ch = (char)fgetc(stacktop->file);
	    if (ch != '\n' && stacktop->once){
		stacktop->once = 0;
		return EOL;	
	    }
	}
	if(parser_y_eof()) {
	   yyterminate();
	}
}

^[\t ]*#.*\n	        { /* eat comment lines */
                          stacktop->line++;
		        }

^[\t ]*\n	        { /* eat blank lines */
                          stacktop->line++;
		        }

^[\t ]+			return FIRST_SPACES;

[\t ]+			/* ignore spaces in line */ ;

<USERDEF>[0-9]+         { /* process a number */
                           yylval.num = strtoul(yytext, NULL, 10);
                           BEGIN INITIAL;
			   return INTEGER;
                        }

<USERDEF>%forever       { /* a number, really 0 */
                           yylval.num = 0;
                           BEGIN INITIAL;
			   return INTEGER;
			}

[0-9]+                  { /* process a number */
                           yylval.num = strtoul(yytext, NULL, 10);
                           BEGIN INITIAL;
			   return INTEGER;
                        }

<BOOLEAN>y   |
<BOOLEAN>yes |
<BOOLEAN>true |
<BOOLEAN>on             { /* process a boolean */
                          yylval.num = 1;
                          BEGIN INITIAL;
			  return BOOL;
			}

<BOOLEAN>n   |
<BOOLEAN>no  |
<BOOLEAN>false |
<BOOLEAN>off            { /* process a boolean */
                          yylval.num = 0;
                          BEGIN INITIAL;
			  return BOOL;
                        }
  
<BOOLEAN>=		return EQUAL;

<BOOLEAN>\n 	        {
                          stacktop->line++;
			  BEGIN INITIAL;
			  return EOL;
		        }

<COMMENTEQUAL>=        {
                            BEGIN COMMENTSTRING;
                            return EQUAL;
                        }

<COMMENTSTRING>[^\n]*   {
                            yylval.s = strdup(yytext);
                            BEGIN INITIAL;
                            return STRING;
                        }

<USERDEF>\"[^\"\n]*\"	{
                           char *s = yytext + 1;
			   int len = strlen(s);

			   assert(len>0);

			   /* remove trailing " */
			   s[len-1]='\0'; 
			   if(yydebug) { fprintf(stderr, "STRING: \"%s\"\n", s);}
			   yylval.s = strdup(s);
			   BEGIN INITIAL;
                           return STRING;
			}

<USERDEF>\{[^\"\n]*\}	{
                           char *s = yytext + 1;
			   int len = strlen(s);

			   assert(len>0);

			   /* remove trailing } */
			   s[len-1]='\0'; 
			   if(yydebug) { fprintf(stderr, "STRING{}: {%s}\n", s);}
			   yylval.s = strdup(s);
			   BEGIN INITIAL;
                           return STRING;
			}

<USERDEF>[^\" \t\n]+   {
			   yylval.s = strdup(yytext);
			   BEGIN INITIAL;
                           return STRING;
			}

<USERDEF>[^\{} \t\n]+   {
			   yylval.s = strdup(yytext);
			   BEGIN INITIAL;
                           return STRING;
			}

\n  		        {
                          stacktop->line++;
			  return EOL;
		        }

=			{ BEGIN USERDEF; return EQUAL; }
version                 return VERSION;     
config			return CONFIG; 
setup			return SETUP;
conn			{ BEGIN USERDEF; return CONN; }
include			return INCLUDE;

[^\"= \t\n]+	        {  int tok;
    
                           if(yydebug) { fprintf(stderr, "STR/KEY: %s\n", yytext); }
                           tok = parser_find_keyword(yytext, &yylval);
			   switch(tok)
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

#.*		        /* eat comment to end of line */ {
                        }

.			yyerror(yytext);
%%

int yywrap(void) {
	return 1;
}
