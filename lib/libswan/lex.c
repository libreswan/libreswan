/*
 * lexer (lexical analyzer) for control files
 *
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
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"
#include "lex.h"

struct file_lex_position *flp = NULL;

/*
 * Open a file for lexical processing.
 *
 * new_flp and name must point into storage and will live
 * at least until the file is closed.
 *
 * @param new_flp file position
 * @param name filename
 * @param bool optional
 * @return bool True if successful
 */
bool lexopen(struct file_lex_position *new_flp, const char *name,
	bool optional)
{
	FILE *f = fopen(name, "r");

	if (f == NULL) {
		if (!optional || errno != ENOENT)
			LOG_ERRNO(errno, "could not open \"%s\"", name);
		return FALSE;
	} else {
		new_flp->previous = flp;
		flp = new_flp;
		flp->filename = name;
		flp->fp = f;
		flp->lino = 0;
		flp->bdry = B_none;

		flp->cur = flp->buffer;	/* nothing loaded yet */
		flp->under = *flp->cur = '\0';

		(void) shift();	/* prime tok */
		return TRUE;
	}
}

/*
 * Close filehandle
 */
void lexclose(void)
{
	fclose(flp->fp);
	flp = flp->previous;
}

/*
 * Token decoding: shift() loads the next token into tok.
 * If a token starts at the left margin, it is considered
 * to be the first in a record.  We create a special condition,
 * Record Boundary (analogous to EOF), just before such a token.
 * We are unwilling to shift through a record boundary:
 * it must be overridden first.
 * Returns FALSE if Record Boundary or EOF (i.e. no token);
 * tok will then be NULL.
 */

/*
 * shift - load next token into tok
 *
 * @return bool True if successful
 */
bool shift(void)
{
	char *p = flp->cur;
	char *sor = NULL;	/* start of record for any new lines */

	passert(flp->bdry == B_none);

	*p = flp->under;
	flp->under = '\0';

	for (;;) {
		switch (*p) {
		case '\0':	/* end of line */
		case '#':	/*
				 * comment to end of line: treat as end of
				 * line
				 */
			/* get the next line */
			if (fgets(flp->buffer, sizeof(flp->buffer) - 1,
					flp->fp) == NULL) {
				flp->bdry = B_file;
				flp->tok = flp->cur = NULL;
				return FALSE;
			} else {
				/* strip trailing whitespace, including \n */
				for (p = flp->buffer + strlen(flp->buffer);
					p > flp->buffer && isspace(p[-1]);
					p--)
					;
				*p = '\0';

				flp->lino++;
				sor = p = flp->buffer;
			}
			break;	/* try again for a token */

		case ' ':	/* whitespace */
		case '\t':
			p++;
			break;	/* try again for a token */

		case '"':	/* quoted token */
		case '\'':
		case '`':	/* or execute quotes */
			if (p != sor) {
				/*
				 * we have a quoted token:
				 * note and advance to its end
				 */
				flp->tok = p;
				p = strchr(p + 1, *p);
				if (p == NULL) {
					loglog(RC_LOG_SERIOUS,
						"\"%s\" line %d: unterminated string",
						flp->filename, flp->lino);
					p = flp->tok + strlen(flp->tok);
				} else {
					p++;	/* include delimiter in token */
				}

				/*
				 * remember token delimiter and replace
				 * with '\0'
				 */
				flp->under = *p;
				*p = '\0';
				flp->cur = p;
				return TRUE;
			}
		/* FALL THROUGH */
		default:
			if (p != sor) {
				/*
				 * we seem to have a token:
				 * note and advance to its end
				 */
				flp->tok = p;

				if (p[0] == '0' && p[1] == 't') {
					/* 0t... token goes to end of line */
					p += strlen(p);
				} else {
					/*
					 * "ordinary" token:
					 * up to whitespace or end of line
					 */
					do {
						p++;
					} while (*p != '\0' && !isspace(*p));

					/*
					 * fudge to separate ':' from
					 * a preceding adjacent token
					 */
					if (p - 1 > flp->tok && p[-1] == ':')
						p--;
				}

				/*
				 * remember token delimiter and replace
				 * with '\0'
				 */
				flp->under = *p;
				*p = '\0';
				flp->cur = p;
				return TRUE;
			}

			/*
			 * we have a start-of-record:
			 * return it, deferring "real" token
			 */
			flp->bdry = B_record;
			flp->tok = NULL;
			flp->under = *p;
			flp->cur = p;
			return FALSE;
		}
	}
}

/*
 * ensures we are at a Record (or File) boundary, optionally warning if not
 *
 * @param m string
 * @return bool True if everything is ok
 */
bool flushline(const char *m)
{
	if (flp->bdry != B_none) {
		return TRUE;
	} else {
		if (m != NULL)
			loglog(RC_LOG_SERIOUS, "\"%s\" line %d: %s",
				flp->filename, flp->lino, m);
		do {} while (shift());
		return FALSE;
	}
}
