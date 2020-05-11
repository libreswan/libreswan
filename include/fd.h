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
#include <stdlib.h>		/* for ssize_t */

#include "where.h"

struct msghdr;

/* opaque and reference counted */
struct fd;

/*
 * A magic value such that: fd_p(null_fd)==false
 */
#define null_fd ((struct fd *) NULL)

struct fd *fd_accept(int socket, where_t where);

#define dup_any(FD) dup_any_fd((FD), HERE)
struct fd *dup_any_fd(struct fd *fd, where_t where);

#define close_any(FD) close_any_fd((FD), HERE)
void close_any_fd(struct fd **fd, where_t where);

void fd_leak(struct fd **fd, where_t where);

ssize_t fd_sendmsg(const struct fd *fd, const struct msghdr *msg,
		   int flags, where_t where);
ssize_t fd_read(const struct fd *fd, void *buf, size_t nbytes,
		where_t where);

/*
 * Is FD valid (as in something non-negative)?
 *
 * Use fd_p() to check the wrapped return value from functions like
 * open(2) (which return -1 on failure).
 */
bool fd_p(const struct fd *fd);

bool same_fd(const struct fd *l, const struct fd *r);

/*
 * dbg("fd "PRI_FD, pri_fd(whackfd))
 *
 * PRI_... names are consistent with shunk_t and hopefully avoid
 * clashes with reserved PRI* names.
 */
#define PRI_FD "fd-fd@%p"
#define pri_fd(FD) (FD)

#endif
