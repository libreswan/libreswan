/* libipsecconf log and memory allocation functions
 * definitions: lib/libipsecconf/starterlog.c, lib/libipsecconf/alloc.c
 *
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
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
 */

#ifndef _STARTER_LOG_H_
#define _STARTER_LOG_H_

#define LOG_LEVEL_INFO   1
#define LOG_LEVEL_ERR    2
#define LOG_LEVEL_DEBUG  3

extern void starter_log(int level, const char *fmt, ...) __attribute__ ((format(printf, 2, 3)));

extern void starter_use_log(bool debug, bool console, bool mysyslog);

extern void *xmalloc(size_t s);
extern char *xstrdup(const char *s);
extern void *xrealloc(void *o, size_t s);

#endif /* _STARTER_LOG_H_ */

