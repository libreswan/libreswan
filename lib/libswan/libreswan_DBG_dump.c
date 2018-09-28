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
 * Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
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

/* dump raw bytes in hex to stderr (for lack of any better destination) */

void libreswan_DBG_dump(const char *label, const void *p, size_t len)
{
#define DUMP_LABEL_WIDTH 20  /* arbitrary modest boundary */
#define DUMP_WIDTH   (4 * (1 + 4 * 3) + 1)
	char buf[DUMP_LABEL_WIDTH + DUMP_WIDTH];
	char *bp, *bufstart;
	const unsigned char *cp = p;

	bufstart = buf;

	if (label != NULL && label[0] != '\0') {
		/* Handle the label.  Care must be taken to avoid buffer overrun. */
		size_t llen = strlen(label);

		if (llen + 1 > sizeof(buf)) {
			DBG_log("%s", label);
		} else {
			strcpy(buf, label);
			if (buf[llen - 1] == '\n') {
				buf[llen - 1] = '\0'; /* get rid of newline */
				DBG_log("%s", buf);
			} else if (llen < DUMP_LABEL_WIDTH) {
				bufstart = buf + llen;
			} else {
				DBG_log("%s", buf);
			}
		}
	}

	bp = bufstart;
	do {
		int i, j;

		for (i = 0; len != 0 && i != 4; i++) {
			*bp++ = ' ';
			for (j = 0; len != 0 && j != 4; len--, j++) {
				static const char hexdig[] =
					"0123456789abcdef";

				*bp++ = ' ';
				*bp++ = hexdig[(*cp >> 4) & 0xF];
				*bp++ = hexdig[*cp & 0xF];
				cp++;
			}
		}
		*bp = '\0';
		DBG_log("%s", buf);
		bp = bufstart;
	} while (len != 0);
#undef DUMP_LABEL_WIDTH
#undef DUMP_WIDTH
}
