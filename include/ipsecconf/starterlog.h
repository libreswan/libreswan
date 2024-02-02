/* libipsecconf log and memory allocation functions
 * definitions: lib/libipsecconf/starterlog.c, lib/libipsecconf/alloc.c
 *
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
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

#ifndef _STARTER_LOG_H_
#define _STARTER_LOG_H_

#include "lswcdefs.h"

#define LOG_LEVEL_INFO   1
#define LOG_LEVEL_ERR    2

extern void starter_log(int level, const char *fmt, ...) PRINTF_LIKE(2);

#endif /* _STARTER_LOG_H_ */

