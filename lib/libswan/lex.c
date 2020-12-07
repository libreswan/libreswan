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
#include <unistd.h>
#include <errno.h>

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"
#include "lex.h"
#include "lswlog.h"
#include "lswalloc.h"
#include "hunk.h"		/* for char_is_space() */

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
bool lexopen(struct file_lex_position **flp, const char *name,
	     bool optional, const struct file_lex_position *oflp)
{
	FILE *f = fopen(name, "r");
	if (f == NULL) {
		if (!optional || errno != ENOENT) {
			log_errno(oflp->logger, errno, "could not open \"%s\"", name);
		} else {
			DBGF(DBG_TMI, "lex open: %s: "PRI_ERRNO, name, pri_errno(errno));
		}
		return false;
	}

	DBGF(DBG_TMI, "lex open: %s", name);
	struct file_lex_position *new_flp = alloc_thing(struct file_lex_position, name);
	new_flp->depth = oflp->depth + 1;
	new_flp->filename = clone_str(name, "lexopen filename");
	new_flp->fp = f;
	new_flp->lino = 0;
	new_flp->bdry = B_none;
	new_flp->cur = new_flp->buffer;	/* nothing loaded yet */
	new_flp->under = *new_flp->cur = '\0';
	new_flp->logger = oflp->logger;
	shift(new_flp);	/* prime tok */
	*flp = new_flp;
	return true;
}

/*
 * Close filehandle
 */
void lexclose(struct file_lex_position **flp)
{
	DBGF(DBG_TMI, "lex close:");
	fclose((*flp)->fp);
	pfreeany((*flp)->filename);
	pfree(*flp);
	*flp = NULL;
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
 * @return bool True if successful (i.e., there is a token)
 */
bool shift(struct file_lex_position *flp)
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
				DBGF(DBG_TMI, "lex shift: file(eof)");
				return false; /* no token */
			}

			/* strip trailing whitespace, including \n */
			for (p = flp->buffer + strlen(flp->buffer);
			     p > flp->buffer && char_isspace(p[-1]);
			     p--)
				;
			*p = '\0';

			flp->lino++;
			sor = p = flp->buffer;
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
					llog(RC_LOG_SERIOUS, flp->logger,
						    "unterminated string");
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
				DBGF(DBG_TMI, "lex shift: '%s'", flp->tok);
				return true; /* token */
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
					} while (*p != '\0' && !char_isblank(*p));

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
				DBGF(DBG_TMI, "lex shift: '%s'", flp->tok);
				return true; /* token */
			}

			/*
			 * we have an end-of-line aka start-of-record:
			 * return it, deferring "real" token
			 *
			 * Caller will clear .bdry so shift() can read
			 * the new line and return the next token.
			 */
			flp->bdry = B_record;
			flp->tok = NULL;
			flp->under = *p;
			flp->cur = p;
			DBGF(DBG_TMI, "lex shift: record(new line)");
			return false; /* no token */
		}
	}
}

/*
 * ensures we are at a Record (or File) boundary, optionally warning if not
 *
 * @param m string
 * @return bool True if everything is ok
 */
bool flushline(struct file_lex_position *flp, const char *message)
{
	if (flp->bdry != B_none) {
		DBGF(DBG_TMI, "lex flushline: already on eof or record boundary");
		return true;
	}

	/* discard tokens until boundary reached */
	DBGF(DBG_TMI, "lex flushline: need to flush tokens");
	if (message != NULL) {
		llog(RC_LOG_SERIOUS, flp->logger, "%s", message);
	}
	do {
		DBGF(DBG_TMI, "lex flushline: discarding '%s'", flp->tok);
	} while (shift(flp));
	return false;
}
