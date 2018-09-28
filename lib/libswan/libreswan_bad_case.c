/* bad_case() wrapper, for libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "lswlog.h"

void libreswan_bad_case(const char *expression, long value,
			const char *func, const char *file, unsigned long line)
{
	LSWLOG_PASSERT_SOURCE(func, file, line, buf) {
		lswlogf(buf, "switch (%s) case %ld (0x%lx) unexpected",
			expression, value, value);
	}
	/* above will panic but compiler doesn't know this */
	abort();
}
