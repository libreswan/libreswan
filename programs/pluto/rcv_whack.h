/* whack communicating routines
 * Copyright (C) 1998, 1999  D. Hugh Redelmeier.
 * Copyright (C) 2012, 2016 Paul Wouters <paul@libreswan.org>
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

#include "lswcdefs.h"

extern void whack_handle_cb(evutil_socket_t fd,
		const short event UNUSED, void *arg UNUSED);
