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

#ifndef HERE_FILENAME
#define HERE_FILENAME (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

/*
 * For appending: (in FUNC() at FILE:LINE)
 */

typedef const struct where {
	const char *func;
	const char *file;
	long line;
} *where_t;

#define HERE						\
	({						\
		static const struct where here = {	\
			.func = __func__,		\
			.file = HERE_FILENAME,		\
			.line = __LINE__,		\
		};					\
		&here;					\
	})
#define PRI_WHERE "(%s() +%lu %s)"
#define pri_where(SC) (SC)->func, (SC)->line, (SC)->file
#define jam_where(BUF, WHERE) jam(BUF, PRI_WHERE, pri_where(WHERE))

#endif
