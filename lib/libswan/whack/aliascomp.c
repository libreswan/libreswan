/* functions to compare a string/list
 * Copyright (C) 2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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

#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include "sysdep.h"
#include "constants.h"
#include "lswalloc.h"
#include "whack.h"

/*
 * lsw_alias_cmp: is name found in aliases?
 *
 * aliases is a string of whitespace-separated names (or a NULL pointer).
 * Assumption: names do not contain whitespace.
 */
bool lsw_alias_cmp(const char *name, const char *aliases)
{
	if (aliases == NULL)
		return false;

	size_t nlen = strlen(name);

	for (const char *s = aliases;;) {
		s += strspn(s, " \t");	/* skip whitespace */

		if (*s == '\0')
			return false;	/* string exhausted */

		size_t aw = strcspn(s, " \t");	/* alias width */

		if (aw == nlen && strneq(s, name, nlen))
			return true;	/* found */

		s += aw;	/* skip this alias */
	}
}
