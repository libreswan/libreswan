/*
 * Cryptographic helper function.
 * Copyright (C) 2004 Michael C. Richardson <mcr@xelerance.com>
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
 *
 * This code was developed with the support of IXIA communications.
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <signal.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "packet.h"
#include "demux.h"
#include "lswlog.h"
#include "log.h"
#include "state.h"
#include "demux.h"
#include "rnd.h"
#include "pluto_crypt.h"

void alloc_wire_chunk(wire_arena_t *arena,
		      wire_chunk_t *new,
		      size_t size)
{
	/*
	 * passert for now, since we should be able to figure out what
	 * the maximum is.
	 */
	passert(size <= arena->roof - arena->next);

	new->start = arena->next;
	new->len = size;

	arena->next += size;
}

void wire_clone_chunk(wire_arena_t *arena,
		      wire_chunk_t *new,
		      const chunk_t *chunk)
{
	/* allocate some space first */
	alloc_wire_chunk(arena, new, chunk->len);

	/* copy chunk into it */
	memcpy(wire_chunk_ptr(arena, new), chunk->ptr, chunk->len);
}
