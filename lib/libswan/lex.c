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
	struct logger *logger = oflp->logger;

	FILE *f = fopen(name, "r");
	if (f == NULL) {
		if (!optional || errno != ENOENT) {
			llog_errno(ERROR_STREAM, logger, errno,
				   "could not open \"%s\": ", name);
		} else if (LDBGP(DBG_TMI, logger)) {
			LDBG_errno(logger, errno, "lex open: %s: ", name);
		}
		return false;
	}

	ldbgf(DBG_TMI, oflp->logger, "lex open: %s", name);
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
	ldbgf(DBG_TMI, (*flp)->logger, "lex close:");
	fclose((*flp)->fp);
	pfreeany((*flp)->filename);
	pfree(*flp);
	*flp = NULL;
}

/*
 * Token decoding: shift() loads the next token into tok.  If a token
 * starts at the left margin, it is considered to be the first in a
 * record.  We create a special condition, Record Boundary (analogous
 * to EOF), just before such a token.  We are unwilling to shift
 * through a record boundary: it must be overridden first.
 *
 * Returns FALSE if Record Boundary or EOF (i.e. no token); tok will
 * then be NULL.
 */

/*
 * We have an end-of-line aka start-of-record: return it, deferring
 * "real" token Caller will clear .bdry so shift() can read the new
 * line and return the next token.
 */

static void start_record(struct file_lex_position *flp, char *p)
{
	flp->bdry = B_record;
	flp->tok = NULL;
	flp->under = *p;
	flp->cur = p;
}

/*
 * shift - load next token into tok
 *
 * @return bool True if successful (i.e., there is a token)
 */

bool shift(struct file_lex_position *flp)
{
	char *p = flp->cur;
	char *start_of_record = NULL;	/* start of record for any new lines */

	passert(flp->bdry == B_none);

	*p = flp->under;
	flp->under = '\0';
	flp->quote = '\0'; /* truthy */

	for (;;) {
		switch (*p) {
		case '\0':	/* end of line */
		case '#':	/* comment at end of line */
			/*
			 * Treat comment at end of line like line end,
			 * by getting the next line.
			 */
			if (fgets(flp->buffer, sizeof(flp->buffer) - 1,
					flp->fp) == NULL) {
				flp->bdry = B_file;
				flp->tok = flp->cur = NULL;
				ldbgf(DBG_TMI, flp->logger,
				      "lex shift: file(eof)");
				return false; /* no token */
			}

			/* strip trailing whitespace, including \n */
			for (p = flp->buffer + strlen(flp->buffer);
			     p > flp->buffer && char_isspace(p[-1]);
			     p--)
				;
			*p = '\0';

			flp->lino++;
			start_of_record = p = flp->buffer;
			break;	/* try again for a token */

		case ' ':	/* whitespace */
		case '\t':
			p++;
			break;	/* try again for a token */

		case '"':	/* quoted token */
		case '\'':
		case '`':	/* or execute quotes */
			if (p == start_of_record) {
				/*
				 * Need to return start of record
				 * before quoted string (on re-entry,
				 * P hasn't advanced, but
				 * START_OF_RECORD is NULL).
				 */
				start_record(flp, p);
				ldbgf(DBG_TMI, flp->logger, "lex shift: record(new line, with quotes)");
				return false; /* no token */
			}

			/*
			 * we have a quoted token:
			 * note and advance to its end
			 */
			flp->tok = p;
			p = strchr(p + 1, *p);
			if (p == NULL) {
				llog(RC_LOG, flp->logger,
				     "unterminated string");
				p = flp->tok + strlen(flp->tok);
			} else {
				/* strip quotes from token */
				flp->quote = *flp->tok;
				flp->tok++;
				*p = '\0';
				p++;
			}

			/*
			 * Remember token delimiter and replace with
			 * '\0' (kind of pointless but consistent).
			 */
			flp->under = *p;
			*p = '\0';
			flp->cur = p;
			ldbgf(DBG_TMI, flp->logger, "lex shift: '%s'", flp->tok);
			return true; /* token */

		default:
			if (p == start_of_record) {
				/*
				 * Need to return start of record
				 * before token (On re-entry, P hasn't
				 * advanced, but START_OF_RECORD is
				 * NULL).
				 */
				start_record(flp, p);
				ldbgf(DBG_TMI, flp->logger, "lex shift: record(new line, with quotes)");
				return false; /* no token */
			}

			/*
			 * we seem to have a token: note and advance
			 * to its end
			 */
			flp->tok = p;

			if (p[0] == '0' && p[1] == 't') {
				/* 0t... token goes to end of line */
				p += strlen(p);
			} else {
				/*
				 * "ordinary" token: up to whitespace
				 * or end of line
				 */
				do {
					p++;
				} while (*p != '\0' && !char_isblank(*p));

				/*
				 * fudge to separate ':' from a
				 * preceding adjacent token
				 */
				if (p - 1 > flp->tok && p[-1] == ':')
					p--;
			}

			/*
			 * remember token delimiter and replace with
			 * '\0'
			 */
			flp->under = *p;
			*p = '\0';
			flp->cur = p;
			ldbgf(DBG_TMI, flp->logger, "lex shift: '%s'", flp->tok);
			return true; /* token */
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
		ldbgf(DBG_TMI, flp->logger, "lex flushline: already on eof or record boundary");
		return true;
	}

	/* discard tokens until boundary reached */
	ldbgf(DBG_TMI, flp->logger, "lex flushline: need to flush tokens");
	if (message != NULL) {
		llog(RC_LOG, flp->logger, "%s", message);
	}
	do {
		ldbgf(DBG_TMI, flp->logger, "lex flushline: discarding '%s'", flp->tok);
	} while (shift(flp));
	return false;
}
