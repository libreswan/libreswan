/* allocation functions for starter
 * header: starterlog.h
 *
 * Copyright (C) 2004 Michael Richardson <mcr@sandelman.ottawa.on.ca>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
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

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

#include "libreswan.h"
#include "ipsecconf/starterlog.h"

/*
 * die if allocations fail
 * ??? these things do not die.  What's the point?
 */

void *xmalloc(size_t s)
{
	void *m = malloc(s);

	return m;
}

char *xstrdup(const char *s)
{
	char *m = strdup(s);

	return m;
}

void *xrealloc(void *o, size_t s)
{
	void *m = realloc(o, s);

	return m;
}
