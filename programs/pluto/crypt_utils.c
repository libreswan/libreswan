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
 *
 * RCSID $Id: crypt_utils.c,v 1.1 2005/03/13 00:38:08 mcr Exp $
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <signal.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "constants.h"
#include "defs.h"
#include "packet.h"
#include "demux.h"
#include "oswlog.h"
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
    passert(space->start + howbig < space->len);

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

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
