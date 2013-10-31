/* FreeS/WAN allocation functions for starter
 * Copyright (C) 2004 Michael Richardson <mcr@sandelman.ottawa.on.ca>
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

/*
 * die if allocations fail
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
