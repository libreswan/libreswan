%option nounput
%{ /* -*- flex-mode -*- */
/* FreeS/WAN config file parser (parser.l)
 * Copyright (C) 2001 Mathieu Lafon - Arkoon Network Security
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
 * RCSID $Id: parser.l,v 1.9.14.1 2005/08/18 14:06:23 ken Exp $
 */

#include <sys/queue.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

#include "keywords.h"
#include "parser.h"
#include "parser.tab.h"
#include "parserlast.h"

#define MAX_INCLUDE_DEPTH  10

/*    
#define YY_NO_UNPUT
*/

extern void yyerror(const char *);
extern int yylex (void);
extern int yydebug;
extern int verbose;
    
static struct {
    int stack_ptr;
    YY_BUFFER_STATE stack[MAX_INCLUDE_DEPTH];
    FILE *file[MAX_INCLUDE_DEPTH];
    unsigned int line[MAX_INCLUDE_DEPTH];
    char *filename[MAX_INCLUDE_DEPTH];
} ic_private;

char *parser_cur_filename(void)
{
    return ic_private.filename[ic_private.stack_ptr];
}

int  parser_cur_lineno(void)
{
    return ic_private.line[ic_private.stack_ptr];
}

void parser_y_error(char *b, int size, const char *s)
{
	extern char yytext[];

	snprintf(b, size, "%s:%d: %s [%s]",
		ic_private.filename[ic_private.stack_ptr],
		ic_private.line[ic_private.stack_ptr],
		s, yytext);
}

void parser_y_init (const char *f)
{
	memset(&ic_private, 0, sizeof(ic_private));
	ic_private.line[0] = 1;
	ic_private.filename[0] = strdup(f);
}

void parser_y_fini (void)
{
	unsigned int i;
	for (i=0; i<MAX_INCLUDE_DEPTH; i++) {
		if (ic_private.filename[i])
			free(ic_private.filename[i]);
		if (ic_private.file[i])
			fclose(ic_private.file[i]);
	}
	memset(&ic_private, 0, sizeof(ic_private));
}

int parser_y_include (const char *filename)
{
	unsigned int p;
	FILE *f;
	char newname[PATH_MAX];

	if(rootdir[0]!='\0' && filename[0]=='/')
        {
	    snprintf(newname, PATH_MAX, "%s%s", rootdir, filename);
	    filename=newname;
	}
		

	if (ic_private.stack_ptr >= MAX_INCLUDE_DEPTH)
	{
		yyerror("max inclusion depth reached");
		return 1;
	}

	if(verbose)
	{
	    fprintf(stderr, "including file %s from line %s:%d\n"
		    , filename
		    , ic_private.filename[ic_private.stack_ptr]
		    , ic_private.line[ic_private.stack_ptr]);
	}

	/**
	 * TODO: handle wildcards -- see glob()
	 */
	f = fopen(filename, "r");
	if (!f) {
		yyerror("can't open include filename");
		return 1;
	}

	p = ++ic_private.stack_ptr;
	ic_private.file[p] = f;
	ic_private.stack[p] = YY_CURRENT_BUFFER;
	ic_private.line[p] = 1;
	ic_private.filename[p] = strdup(filename);

	yy_switch_to_buffer(yy_create_buffer(f, YY_BUF_SIZE));

	return 0;
}

%}

%x USERDEF BOOLEAN

%%

<<EOF>>	{
	if (ic_private.filename[ic_private.stack_ptr]) {
		free(ic_private.filename[ic_private.stack_ptr]);
		ic_private.filename[ic_private.stack_ptr] = NULL;
	}
	if (ic_private.file[ic_private.stack_ptr]) {
	    int stackp = ic_private.stack_ptr;

		fclose(ic_private.file[stackp]);
		
		if(verbose)
		{
		    fprintf(stderr, "end of file %s, resuming %s line %d\n"
			    , ic_private.filename[stackp]
			    , (stackp > 0 ? ic_private.filename[stackp-1] : "<none>")
			    , (stackp > 0 ? ic_private.line[stackp-1] : -1));
		}
		
		ic_private.file[stackp] = NULL;
		yy_delete_buffer (YY_CURRENT_BUFFER);
		yy_switch_to_buffer(ic_private.stack[stackp]);
	}
	if (--ic_private.stack_ptr < 0) {
		yyterminate();
	}
}

^\n		        { /* eat totally blank lines */
                          ic_private.line[ic_private.stack_ptr]++;
		        }

^#.*\n		        { /* eat comment lines */
                          ic_private.line[ic_private.stack_ptr]++;
		        }

^[\t ]+#.*\n            { /* eat comment lines inside of stanzas */
                          ic_private.line[ic_private.stack_ptr]++;
		        }

^[\t ]+			return FIRST_SPACES;

[\t ]+			/* ignore spaces in line */ ;

[0-9]+                  { /* process a number */
                           yylval.num = atof(yytext);
			   return INTEGER;
                        }

%forever                { /* a number, really 0 */
                           yylval.num = 0;
			   return INTEGER;
			}

[0-9]+\.[0-9]*          { /* process a number */
                           yylval.dblnum = atof(yytext);
			   return NUMBER;
                        }

<BOOLEAN>y   |
<BOOLEAN>yes |
<BOOLEAN>true |
<BOOLEAN>on             { /* process a boolean */
                          yylval.num = 1;
			  return BOOL;
			}

<BOOLEAN>n   |
<BOOLEAN>no  |
<BOOLEAN>false |
<BOOLEAN>off            { /* process a boolean */
                          yylval.num = 0;
			  return BOOL;
                        }
  
<BOOLEAN>=		return EQUAL;

<BOOLEAN>\n 	        {
                          ic_private.line[ic_private.stack_ptr]++;
			  BEGIN INITIAL;
			  return EOL;
		        }
\n  		        {
                          ic_private.line[ic_private.stack_ptr]++;
			  return EOL;
		        }

=			return EQUAL;
version                 return VERSION;     
config			return CONFIG; 
setup			return SETUP;
conn			{ BEGIN USERDEF; return CONN; }
include			return INCLUDE;
%default                return DEFAULT;

[^\"= \t\n]+	        {  int tok;
    
                           if(yydebug) { fprintf(stderr, "STR/KEY: %s\n", yytext); }
                           tok = parser_find_keyword(yytext, &yylval);
			   switch(tok)
			   {
			   case BOOLWORD:
			       BEGIN BOOLEAN;
			       break;
			   default:
                               break;
			   }
			   return tok;
			}

<USERDEF>%default       {
                           BEGIN INITIAL;
			   return DEFAULT;
			}

<USERDEF>[^\"= \t\n]+   {
			   yylval.s = strdup(yytext);
			   BEGIN INITIAL;
                           return STRING;
			}

\"[^\"\n]*\"	        {
                           char *s = yytext + 1;
			   int len = strlen(s);

			   assert(len>0);

			   /* remove trailing " */
			   s[len-1]='\0';
			   if(yydebug) { fprintf(stderr, "STRING: \"%s\"\n", s);}
			   yylval.s = strdup(s);
                           return STRING;
			}

#.*		        /* eat comment lines */ ;

.			yyerror(yytext);

%%

int yywrap(void) {
	return 1;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
