/* whack receive routines, for libreswan
 *
 * Copyright (C) 1998, 1999  D. Hugh Redelmeier.
 * Copyright (C) 2012, 2016 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2018  Andrew Cagney
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

#ifndef RCV_WHACK_H
#define RCV_WHACK_H

#include <event2/event.h>	/* for evutil_socket_t */

#include "lswcdefs.h"
#include "fd.h"

extern void whack_handle_cb(evutil_socket_t fd,
		const short event UNUSED, void *arg UNUSED);

extern void whack_process(fd_t whackfd, const struct whack_message *const m);

#endif
