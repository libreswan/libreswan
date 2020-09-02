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

diag_t diag(const char *fmt, ...)
{
	int length;
	{
		va_list ap;
		va_start(ap, fmt);
		length = vsnprintf(NULL, 0, fmt, ap);
		va_end(ap);
	}
	passert(length >= 0);
	length++; /* space for '\0' */
	char *buf = alloc_things(char, length, fmt);
	{
		va_list ap;
		va_start(ap, fmt);
		vsnprintf(buf, length, fmt, ap);
		va_end(ap);
	}
	return (diag_t)buf;
}

const char *str_diag(diag_t diag)
{
	return (char*)diag;
}

void pfree_diag(diag_t *diag)
{
	pfree(*diag);
	*diag = NULL;
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
