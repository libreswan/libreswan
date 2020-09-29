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

size_t jam_diag(struct jambuf *buf, diag_t *diag)
{
	size_t s = jam_string(buf, str_diag(*diag));
	pfree_diag(diag);
	return s;
}

void log_diag(lset_t rc_flags, struct logger *logger, diag_t *diag,
	      const char *fmt, ...)
{
	LOG_JAMBUF(rc_flags, logger, buf) {
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);
		jam_diag(buf, diag);
	}
}
