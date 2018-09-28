/* error return type, for libreswan
 *
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
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

#ifndef ERR_H
#define ERR_H

/*
 * Many routines return only success or failure, but wish to describe
 * the failure in a message.  We use the convention that they return a
 * NULL on success and a pointer to constant string on failure.  The
 * fact that the string is a constant is limiting, but it avoids
 * storage management issues: the recipient is allowed to assume that
 * the string will live "long enough" (usually forever).
 *
 * XXX: Since the above was written pluto has become multi-threaded
 * so, only when on the main thread, can this be true.
 */

typedef const char *err_t;      /* error message, or NULL for success */

#endif
