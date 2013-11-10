/* Libreswan config file parser controls
 * This header is for code using libipsecconf.
 *
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
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
 */

/* things from parser.l */

extern int lex_verbosity;	/* how much tracing output to show */

extern char rootdir[PATH_MAX];	/* when evaluating paths, prefix this to them */
extern char rootdir2[PATH_MAX];	/* when evaluating paths, alternatively prefix this to them */

/* things from parser.y */

extern void yyerror(const char *);	/* defined in parser.y */

#ifndef _IPSEC_PARSER_H_	/* ??? dirty trick to prevent redeclaration */
extern int yydebug;	/* declared in parser.tab.h but too hard to include */
#endif
