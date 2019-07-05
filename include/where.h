/* source code location (where), for libreswan
 *
 * Copyright (C) 2019  Andrew Cagney
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

#ifndef WHERE_H
#define WHERE_H

/*
 * http://stackoverflow.com/questions/8487986/file-macro-shows-full-path#8488201
 *
 * It is tempting to tweak the .c.o line so that it passes in the
 * required value.
 */

#ifndef HERE_BASENAME
#define HERE_BASENAME (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

/*
 * For appending: (in FUNC() at FILE:LINE)
 */

typedef const struct {
	const char *func;
	const char *basename;
	long line;
} where_t;

#define HERE (where_t) { .func = __func__, .basename = HERE_BASENAME , .line = __LINE__}
#define PRI_WHERE "(in %s() at %s:%lu)"
#define pri_where(SC) (SC).func, (SC).basename, (SC).line

/* XXX: hack for old code passing around parameters */
#define WHERE(FUNC, BASENAME, LINE) (where_t) {FUNC, BASENAME, LINE}

#endif
