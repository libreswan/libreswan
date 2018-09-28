/* file descriptor functions
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2004-2008  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2004-2009  Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
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

#ifndef FD_H
#define FD_H

#include <stdbool.h>

typedef struct { int fd; } fd_t;

/*
 * A magic value such that: fd_p(null_fd)==false
 */
extern const fd_t null_fd;

#define NEW_FD(CODE) new_fd((CODE), #CODE, __func__, PASSERT_BASENAME, __LINE__)
fd_t new_fd(int fd, const char *code,
	    const char *func, const char *file, unsigned long line);

#define dup_any(FD) dup_any_fd((FD), __func__, PASSERT_BASENAME, __LINE__)
fd_t dup_any_fd(fd_t fd, const char *func,
		const char *file, unsigned long line);
#define close_any(FD) close_any_fd((FD), __func__, PASSERT_BASENAME, __LINE__)
void close_any_fd(fd_t *fd,
		  const char *func, const char *file, unsigned long line);

/*
 * Is FD valid (as in something non-negative)?
 *
 * Use fd_p() to check the wrapped return value from functions like
 * open(2) (which return -1 on failure).
 */
bool fd_p(fd_t fd);

/*
 * printf("fd "PRI_FD, PRI_fd(whackfd))
 *
 * PRI_... names are consistent with shunk_t and hopefully avoid
 * clashes with reserved PRI* names.
 */
#define PRI_FD "fd@%d"
#define PRI_fd(FD) ((FD).fd)

#endif
 
