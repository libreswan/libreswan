%{   /* -*- bison-mode -*- */
/* FreeS/WAN config file parser (parser.y)
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
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <unistd.h>

#define YYDEBUG 1

#include "ipsecconf/keywords.h"
#include "ipsecconf/parser.h"	/* includes parser.tab.h" */
#include "ipsecconf/parser-flex.h"
#include "ipsecconf/confread.h"

#define YYERROR_VERBOSE
#define ERRSTRING_LEN	256

/**
 * Bison
 */
static char parser_errstring[ERRSTRING_LEN+1];
static struct kw_list *alloc_kwlist(void);
static struct starter_comments *alloc_comment(void);

/**
 * Static Globals
 */
static int _save_errors_;
static struct config_parsed *_parser_cfg;
static struct kw_list **_parser_kw, *_parser_kw_last;
static struct starter_comments_list *_parser_comments;

/**
 * Functions
 */

%}

%union {
	char *s;
        unsigned int num;
	struct keyword k;
}
%token EQUAL FIRST_SPACES EOL CONFIG SETUP CONN INCLUDE VERSION
%token <s>      STRING
%token <num>    INTEGER
%token <num>    BOOL
%token <k>      KEYWORD
%token <k>      TIMEWORD
%token <k>      BOOLWORD
%token <k>      PERCENTWORD
%token <k>      COMMENT
%%

/*
 * Config file
 */

config_file: blanklines versionstmt sections ;

/* check out the version number - this is optional (and we're phasing out its use) */
/* we have configs shipped with version 2 (INTEGER) and with version 2.0 (STRING, now  NUMBER/float was removed */

versionstmt: /* NULL */
        | VERSION STRING EOL blanklines
        | VERSION INTEGER EOL blanklines
	;

blanklines: /* NULL */
	| blanklines EOL
	;

sections: /* NULL */
	| sections section_or_include blanklines
	;

section_or_include:
	CONFIG SETUP EOL {
		_parser_kw = &(_parser_cfg->config_setup);
		_parser_kw_last = NULL;
		_parser_comments = &_parser_cfg->comments;
		if (yydebug)
			fprintf(stderr, "\nconfig setup read\n");

	} kw_sections
	| CONN STRING EOL {
		struct section_list *section;
		section = (struct section_list *)malloc(sizeof(struct section_list));
		if (section != NULL) {
			section->name = $2;
			section->kw = NULL;

			TAILQ_INSERT_TAIL(&_parser_cfg->sections, section, link);

        	        /* setup keyword section to record values */
			_parser_kw = &(section->kw);
			_parser_kw_last = NULL;

			/* and comments */
			TAILQ_INIT(&section->comments);
			_parser_comments = &section->comments;

			if(yydebug)
				fprintf(stderr, "\nread conn %s\n", section->name);
		} else {
			_parser_kw = NULL;
			_parser_kw_last = NULL;
			yyerror("can't allocate memory in section_or_include/conn");
		}
	} kw_sections
	| INCLUDE STRING EOL {
 		parser_y_include($2);
	}
	;

kw_sections: /* NULL */
	| kw_sections kw_section
	;

kw_section: FIRST_SPACES statement_kw EOL
	| FIRST_SPACES EOL;	/* kludge to ignore whitespace (without newline) at EOF */

statement_kw:
	KEYWORD EQUAL KEYWORD {
		struct kw_list *new;

		assert(_parser_kw != NULL);
		new = alloc_kwlist();
		if (new == NULL) {
		    yyerror("can't allocate memory in statement_kw");
		} else {
		    struct keyword kw;
                    /* because the third argument was also a keyword, we dig up the string representation. */
	            const char *value = $3.keydef->keyname;

	            kw = $1;
		    new->keyword = kw;

		    switch(kw.keydef->type) {
		    case kt_list:
			new->number = parser_enum_list(kw.keydef, value, TRUE);
			break;
	            case kt_enum:
			new->number = parser_enum_list(kw.keydef, value, FALSE);
			break;
		    case kt_rsakey:
		    case kt_loose_enum:
			new->number = parser_loose_enum(&new->keyword, value);
                        break;
		    case kt_string:
		    case kt_appendstring:
		    case kt_appendlist:
		    case kt_filename:
                    case kt_dirname:
                    case kt_ipaddr:
                    case kt_bitstring:
		    case kt_idtype:
		    case kt_range:
		    case kt_subnet:
		        new->string = strdup(value);
			break;

		    case kt_bool:
		    case kt_invertbool:
		    case kt_number:
		    case kt_time:
		    case kt_percent:
			yyerror("keyword value is a keyword, but type not a string");
			assert(kw.keydef->type != kt_bool);
			break;

           	    case kt_comment:
                        break;

           	    case kt_obsolete:
           	    case kt_obsolete_quiet:
                        break;
		    }
		    new->next = NULL;

		    if (_parser_kw_last)
			_parser_kw_last->next = new;
		    _parser_kw_last = new;
		    if (*_parser_kw == NULL)
			*_parser_kw = new;
		}
	}
	| COMMENT EQUAL STRING {
		struct starter_comments *new;

		new = alloc_comment();
		if (new == NULL) {
		    yyerror("can't allocate memory in statement_kw");
		} else {
		    new->x_comment = strdup($1.string);
		    new->commentvalue = strdup($3);
	            TAILQ_INSERT_TAIL(_parser_comments, new, link);
		}
	}
	| KEYWORD EQUAL STRING {
		struct kw_list *new;

		assert(_parser_kw != NULL);
		new = alloc_kwlist();
		if (new == NULL) {
		    yyerror("can't allocate memory in statement_kw");
		} else {
		    struct keyword kw;

	            kw = $1;
		    new->keyword = kw;

		    switch(kw.keydef->type) {
		    case kt_list:
			new->number = parser_enum_list(kw.keydef, $3, TRUE);
			break;
	            case kt_enum:
			new->number = parser_enum_list(kw.keydef, $3, FALSE);
			break;
		    case kt_rsakey:
		    case kt_loose_enum:
			new->number = parser_loose_enum(&new->keyword, $3);
                        break;
		    case kt_string:
		    case kt_appendstring:
		    case kt_appendlist:
		    case kt_filename:
                    case kt_dirname:
                    case kt_ipaddr:
                    case kt_bitstring:
		    case kt_idtype:
		    case kt_range:
		    case kt_subnet:
		        new->string = $3;
			break;

		    case kt_bool:
		    case kt_invertbool:
		    case kt_number:
		    case kt_time:
		    case kt_percent:
			yyerror("valid keyword, but value is not a number");
			assert(!(kw.keydef->type == kt_bool));
			break;
           	    case kt_comment:
                        break;
           	    case kt_obsolete:
           	    case kt_obsolete_quiet:
                        break;
		    }
		    new->next = NULL;

		    if (_parser_kw_last)
			_parser_kw_last->next = new;
		    _parser_kw_last = new;
		    if (!*_parser_kw) *_parser_kw = new;
		}
	}

	| BOOLWORD EQUAL BOOL {
		struct kw_list *new;

		assert(_parser_kw != NULL);
		new = alloc_kwlist();
		if (new == NULL) {
		    yyerror("can't allocate memory in statement_kw");
		} else {
		    new->keyword = $1;
		    new->number = $<num>3;  /* Should not be necessary! */
		    new->next = NULL;
		    if (_parser_kw_last)
			_parser_kw_last->next = new;
		    _parser_kw_last = new;
		    if (!*_parser_kw) *_parser_kw = new;
		}
	}
	| KEYWORD EQUAL INTEGER {
		struct kw_list *new;

		assert(_parser_kw != NULL);
		new = alloc_kwlist();
		if (new == NULL) {
		    yyerror("can't allocate memory in statement_kw");
		} else {
		    new->keyword = $1;
		    new->number = $<num>3;  /* Should not be necessary! */
		    new->next = NULL;
		    if (_parser_kw_last)
			_parser_kw_last->next = new;
		    _parser_kw_last = new;
		    if (!*_parser_kw) *_parser_kw = new;
		}
	}
	| TIMEWORD EQUAL STRING {
		struct kw_list *new;
		char *endptr, *str;
                unsigned int val;
		struct keyword kw = $1;
		bool fail;
                char buf[80];


		fail = FALSE;

		str = $3;

		val = strtoul(str, &endptr, 10);

		if(endptr == str) {
                  snprintf(buf, sizeof(buf), "bad duration value %s=%s", kw.keydef->keyname, str);
                  yyerror(buf);
		  fail = TRUE;
		}

		if(!fail)
                {
			unsigned scale;

			if (*endptr == '\0') {
				/* seconds: no scaling */
				scale = 1;
			} else if (endptr[1] == '\0') {
				/* single character suffix */
				switch (*endptr) {
				case 's': scale = 1; break;
				case 'm': scale = secs_per_minute; break;
				case 'h': scale = secs_per_hour; break;
				case 'd': scale = secs_per_day; break;
				case 'w': scale = 7*secs_per_day; break;
				default:
					snprintf(buf, sizeof(buf),
						"bad duration multiplier '%c' on %s",
						*endptr, str);
					yyerror(buf);
					fail=TRUE;
				}
			} else {
				snprintf(buf, sizeof(buf),
					"bad duration multiplier \"%s\" on %s",
					endptr, str);
				yyerror(buf);
				fail=TRUE;
			}

			if (!fail) {
				if (UINT_MAX / scale < val) {
					snprintf(buf, sizeof(buf),
						"overflow scaling %s",
						str);
					yyerror(buf);
					fail=TRUE;
				} else {
					val *= scale;
				}
			}
                }

	        if(!fail)
                {
		  assert(_parser_kw != NULL);
		  new = alloc_kwlist();
		  if (new == NULL) {
		    yyerror("can't allocate memory in statement_kw");
		  } else {
		    new->keyword = $1;
		    new->number = val;
		    new->next = NULL;
		    if (_parser_kw_last)
			_parser_kw_last->next = new;
		    _parser_kw_last = new;
		    if (*_parser_kw == NULL)
			*_parser_kw = new;
		  }
                }
	}
	| PERCENTWORD EQUAL STRING {
		struct kw_list *new;
		char *endptr, *str;
		struct keyword kw = $1;
                unsigned int val;
		bool fail;
                char buf[80];


		fail = FALSE;

		str = $3;

		val = strtoul(str, &endptr, 10);

		if(endptr == str) {
                  snprintf(buf, sizeof(buf), "bad percent value %s=%s", kw.keydef->keyname, str);
                  yyerror(buf);
		  fail = TRUE;

		}

		if(!fail)
                {
		  if ((*endptr == '%') && (endptr[1] == '\0')) { }
		  else {
                    snprintf(buf, sizeof(buf), "bad percentage multiplier '%c' on %s", *endptr, str);
                    yyerror(buf);
                    fail=TRUE;
                  }
                }

	        if(!fail)
                {
		  assert(_parser_kw != NULL);
		  new = alloc_kwlist();
		  if (new == NULL) {
		    yyerror("can't allocate memory in statement_kw");
		  } else {
		    new->keyword = $1;
		    new->number = val;
		    new->next = NULL;
		    if (_parser_kw_last)
			_parser_kw_last->next = new;
		    _parser_kw_last = new;
		    if (*_parser_kw == NULL)
			*_parser_kw = new;
		  }
                }
	}
	| KEYWORD EQUAL BOOL {
		struct kw_list *new;

		assert(_parser_kw != NULL);
		new = alloc_kwlist();
		if (new != NULL) {
		    yyerror("can't allocate memory in statement_kw");
		} else {
		    new->keyword = $1;
		    new->number = $<num>3;  /* Should not be necessary! */
		    new->next = NULL;
		    if (_parser_kw_last)
			_parser_kw_last->next = new;
		    _parser_kw_last = new;
		    if (*_parser_kw == NULL)
			*_parser_kw = new;
		}
	}
	| KEYWORD EQUAL { /* this is meaningless, we ignore it */ }
	;

%%

void yyerror(const char *s)
{
	if (_save_errors_)
		parser_y_error(parser_errstring, ERRSTRING_LEN, s);
}

struct config_parsed *parser_load_conf(const char *file, err_t *perr)
{
	struct config_parsed *cfg=NULL;
	int err = 0;
	FILE *f;

	zero(&parser_errstring);
	if (perr != NULL)
		*perr = NULL;

	cfg = (struct config_parsed *)malloc(sizeof(struct config_parsed));
	if (cfg == NULL)
	{
	    snprintf(parser_errstring, ERRSTRING_LEN, "can't allocate memory");
	    err++;
	    goto end;
	}
	zero(cfg);	/* ??? pointer fields may not be NULLed */
	if (strncmp(file, "-", sizeof("-")) == 0) {
		f = fdopen(STDIN_FILENO, "r");
	}
	else {
		f = fopen(file, "r");
	}
        if (!f)
	{
	    snprintf(parser_errstring, ERRSTRING_LEN, "can't load file '%s'",
		     file);
	    err++;
	    goto end;
	}

	yyin = f;
	parser_y_init(file, f);
	_save_errors_=1;
	TAILQ_INIT(&cfg->sections);
	TAILQ_INIT(&cfg->comments);
	_parser_cfg = cfg;

        if (yyparse()!=0) {
 	    if (parser_errstring[0]=='\0') {
		snprintf(parser_errstring, ERRSTRING_LEN,
			"Unknown error...");
	    }
	   _save_errors_=0;
	   while (yyparse()!=0);
	   err++;
           goto end;
	}
	if (parser_errstring[0]!='\0') {
	    err++;
	    goto end;
	}
	/**
	 * Config valid
	 */
end:
	if (err) {
		if (perr) *perr = (err_t)strdup(parser_errstring);
		if (cfg) parser_free_conf (cfg);
		cfg = NULL;
	}

	return cfg;
}

static void parser_free_kwlist(struct kw_list *list)
{
	while (list != NULL) {
		struct kw_list *elt = list;

		list = list->next;
		if (elt->string)
			free(elt->string);
		free(elt);
	}
}

void parser_free_conf(struct config_parsed *cfg)
{
	struct section_list *seci, *sec;
	if (cfg) {
		parser_free_kwlist(cfg->config_setup);

	        for(seci = cfg->sections.tqh_first; seci != NULL; )
		{
			sec = seci;
			seci = seci->link.tqe_next;

			if (sec->name) free(sec->name);
			parser_free_kwlist(sec->kw);
			free(sec);
		}

		free(cfg);
	}
}

static struct kw_list *alloc_kwlist(void)
{
	struct kw_list *new;

	new = (struct kw_list *)malloc(sizeof(struct kw_list));
	zero(new);	/* ??? pointer members might not be set to NULL */
	return new;
}

static struct starter_comments *alloc_comment(void)
{
	struct starter_comments *new;

	new = (struct starter_comments *)malloc(sizeof(struct starter_comments));
	zero(new);	/* ??? pointer members might not be set to NULL */
	return new;
}
