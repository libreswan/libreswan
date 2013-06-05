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
#include <libreswan/ipsec_policy.h>

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

void pluto_crypto_allocchunk(wire_chunk_t *space
			     , wire_chunk_t *new
			     , size_t howbig)
{
    /*
     * passert for now, since we should be able to figure out what
     * the maximum is.
     */
    passert(howbig < space->len - space->start);

    new->start = space->start;
    new->len   = howbig;
    
    space->start += howbig;
}

void pluto_crypto_copychunk(wire_chunk_t *spacetrack
			    , unsigned char *space
			    , wire_chunk_t *new
			    , chunk_t data)
{
    /* allocate some space first */
    pluto_crypto_allocchunk(spacetrack, new, data.len);

    /* copy data into it */
    memcpy(space_chunk_ptr(space, new), data.ptr, data.len);
}
