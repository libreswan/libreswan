/* diagnostic return type, for libreswan
 *
 * Copyright (C) 2020  Andrew Cagney
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
#include <stdarg.h>

#include "passert.h"
#include "diag.h"
#include "lswalloc.h"
#include "jambuf.h"
#include "lswlog.h"

struct diag {
	char message[1]; /* buffer overflow hack */
};

diag_t diag_va_list(const char *fmt, va_list ap)
{
	return (diag_t)alloc_vprintf(fmt, ap);
}

diag_t diag(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	diag_t d = diag_va_list(fmt, ap);
	va_end(ap);
	return d;
}

diag_t diag_errno(int error, const char *fmt, ...)
{
	char output[LOG_WIDTH];
	struct jambuf buf = ARRAY_AS_JAMBUF(output);
	va_list ap;
	va_start(ap, fmt);
	jam_va_list(&buf, fmt, ap);
	va_end(ap);
	/* NO ": "; not *perror() */
	jam_errno(&buf, error);
	return (diag_t)clone_str(output, "diag-errno");
}

diag_t diag_diag(diag_t *d, const char *fmt, ...)
{
	va_list fmt_ap;
	va_start(fmt_ap, fmt);
	diag_t dd;
	{
		/* compute size */
		int fmt_len;
		{
			va_list ap;
			va_copy(ap, fmt_ap);
			fmt_len = vsnprintf(NULL, 0, fmt, ap);
			va_end(ap);
		}
		/* allocate */
		passert(fmt_len >= 0);
		size_t length = fmt_len + 1/*'\0'*/ + strlen((*d)->message);
		char *buf = alloc_things(char, length, fmt);
		/* add FMT... */
		{
			va_list ap;
			va_copy(ap, fmt_ap);
			vsnprintf(buf, length, fmt, ap);
			va_end(ap);
		}
		/* add D */
		strcpy(buf + fmt_len, (*d)->message);
		passert(strlen(buf) + 1 == length);
		dd = (diag_t)buf;
	}
	pfree_diag(d);
	va_end(fmt_ap);
	return dd;
}

diag_t diag_jambuf(struct jambuf *buf)
{
	shunk_t msg = jambuf_as_shunk(buf); /* no '\0', but there is one */
	return (diag_t) clone_hunk_as_string(msg, "diag jambuf");
}

diag_t clone_diag(diag_t diag)
{
	/* clone_str() clones NULL as NULL */
	return (diag_t) clone_str((char*)diag, "diag clone");
}

const char *str_diag(diag_t diag)
{
	/* let caller deal with mess */
	return (char*)diag;
}

void pfree_diag(diag_t *diag)
{
	if (*diag != NULL) {
		pfree(*diag);
		*diag = NULL;
	}
}

size_t jam_diag(struct jambuf *buf, diag_t diag)
{
	return jam_string(buf, str_diag(diag));
}

void llog_diag(lset_t rc_flags, const struct logger *logger, diag_t *diag,
	       const char *fmt, ...)
{
	LLOG_JAMBUF(rc_flags, logger, buf) {
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);
		jam_diag(buf, *diag);
	}
	pfree_diag(diag);
}

void fatal_diag(enum pluto_exit_code rc, const struct logger *logger, diag_t *diag,
		const char *fmt, ...)
{
	LLOG_JAMBUF(FATAL_STREAM, logger, buf) {
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);
		jam_diag(buf, *diag);
	}
	pfree_diag(diag); /* XXX: bother? */
	libreswan_exit(rc);
}
