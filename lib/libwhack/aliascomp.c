/* functions to compare a string/list
 * Copyright (C) 2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
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
 * this is just like "strstr()", only it won't find matches
 * that are substrings (case-sensitive compare), but rather each match
 * must be anchored in front and after with whitespace and/or start/end
 * of string.
 *
 */
bool lsw_alias_cmp(const char *needle, const char *haystack)
{
	int nlen = strlen(needle);
	const char *s = haystack;

	if (s == NULL)
		return FALSE;

	while (*s != '\0') {
		/* does it match, and does it end with a space?
		 * check if things end at same place
		 */
		if (strneq(s, needle, nlen) &&
		    (s[nlen] == ' ' || s[nlen] == '\t' || s[nlen] == '\0'))
			return TRUE;

		for (;; ) {
			s++;
			if (*s == '\0')
				break; /* or return FALSE: we're done */
			if (*s == ' ' || *s == '\t') {
				/* at whitespace: start next scan right after */
				s++;
				break;
			}
		}
	}

	return FALSE;
}
