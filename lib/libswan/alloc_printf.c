/* asprintf(), for libreswan
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

#include "lswalloc.h"

char *alloc_vprintf(const char *fmt, va_list master_ap /* must va_copy */)
{
	int length;
	{
		va_list ap;
		va_copy(ap, master_ap);
		length = vsnprintf(NULL, 0, fmt, ap);
		va_end(ap);
	}
	passert(length >= 0);
	length++; /* space for '\0' */
	char *buf = alloc_things(char, length, fmt);
	{
		va_list ap;
		va_copy(ap, master_ap);
		vsnprintf(buf, length, fmt, ap);
		va_end(ap);
	}
	return buf;
}

char *alloc_printf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char *d = alloc_vprintf(fmt, ap);
	va_end(ap);
	return d;
}
