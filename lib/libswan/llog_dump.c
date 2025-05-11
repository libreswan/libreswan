/* error logging functions
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2005-2007 Michael Richardson
 * Copyright (C) 2006-2010 Bart Trojanowski
 * Copyright (C) 2008-2012 Paul Wouters
 * Copyright (C) 2008-2010 David McCullough.
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013,2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2017,2021 Andrew Cagney <cagney@gnu.org>
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
 *
 */

#include <string.h>

#include "lswlog.h"

/*
 * dump raw bytes; when LABEL is non-NULL prefix the dump with a log
 * line containing the label.
 */

void llog_dump(lset_t rc_flags, const struct logger *logger,
	       const void *p, size_t len)
{
	if (p == NULL) {
		PEXPECT(logger, len == 0);
		llog(rc_flags, logger, "  <null>");
		return;
	}
	const uint8_t *cp = p;
	do {
		/* each line shows 16 bytes; remember sizeof includes '\0' */
		char hex[sizeof("  xx xx xx xx  xx xx xx xx  xx xx xx xx  xx xx xx xx")];
		char str[sizeof("................")];
		char *hp = hex;
		char *sp = str;
		for (int  i = 0; len != 0 && i != 4; i++) {
			*hp++ = ' ';
			for (int j = 0; len != 0 && j != 4; len--, j++) {
				static const char hexdig[] =
					"0123456789abcdef";

				*hp++ = ' ';
				*hp++ = hexdig[(*cp >> 4) & 0xF];
				*hp++ = hexdig[(*cp >> 0) & 0xF];

				*sp++ = (char_isprint(*cp) ? *cp : '.');

				cp++;
			}
		}
		*hp++ = '\0';
		*sp++ = '\0';
		passert(hp <= hex + elemsof(hex));
		passert(sp <= str + elemsof(str));
		llog(rc_flags, logger, "%-*s   %s", (int)sizeof(hex)-1, hex, str);
	} while (len != 0);
}
