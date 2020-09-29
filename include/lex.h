/* lexer (lexical analyzer) for control files
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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

#define MAX_TOK_LEN 2048	/* includes terminal '\0' */
struct file_lex_position {
	int depth;		/* how deeply we are nested */
	char *filename;
	FILE *fp;
	enum { B_none, B_record, B_file } bdry;	/* current boundary */
	int lino;				/* line number in file */
	char buffer[MAX_TOK_LEN + 1];		/* note: one extra char for our use (jamming '"') */
	char *cur;				/* cursor */
	char under;				/* except in shift(): character originally at *cur */
	char *tok;
	struct logger *logger;			/* where to send errors */
};

extern bool lexopen(struct file_lex_position **flp, const char *name,
		    bool optional, const struct file_lex_position *oflp);
extern void lexclose(struct file_lex_position **flp);

#define tokeq(s) (streq(flp->tok, (s)))
#define tokeqword(s) strcaseeq(flp->tok, (s))

extern bool shift(struct file_lex_position *flp);
extern bool flushline(struct file_lex_position *flp, const char *message);
