/* Libreswan config file parser controls
 * This header is for code using libipsecconf.
 *
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
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
 */

/* things from parser.l */

struct logger;

#include <limits.h>		/* for PATH_MAX */
#include "lswcdefs.h"		/* for PRINTF_LIKE() */

extern int lex_verbosity;	/* how much tracing output to show */

extern char rootdir[PATH_MAX];	/* when evaluating paths, prefix this to them */
extern char rootdir2[PATH_MAX];	/* when evaluating paths, alternatively prefix this to them */

/* things from parser.y */

void yyerror(struct logger *logger, const char *, ...) PRINTF_LIKE(2);	/* defined in parser.y */

/* Dirty trick to dodge bison version differences.
 * Old bison (2.5) produces parser.tab.h without yydebug decl and no
 * multiple-inclusion protection.
 * New bison (2.6) is the opposite.
 * So: if the wrapper symbol is missing, do the declarations here.
 * Note: this header is sometimes included without parser.tab.h.
 */
#ifndef YY_YY_PARSER_TAB_H_INCLUDED
extern int yydebug;	/* declared in bison 2.6 parser.tab.h but not 2.5 */
#endif
