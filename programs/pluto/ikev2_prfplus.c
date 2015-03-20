/*
 * Cryptographic helper function - calculate prf+() for ikev2
 * Copyright (C) 2007 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2010 Paul Wouters <paul@xelerance.com>
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
 * This code was developed with the support of Redhat corporation.
 *
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
#include "crypto.h"
#include "rnd.h"
#include "state.h"
#include "pluto_crypt.h"
#include "lswlog.h"
#include "log.h"
#include "timer.h"
#include "ike_alg.h"
#include "id.h"
#include "secrets.h"
#include "keys.h"
#include "ikev2_prfplus.h"

void v2prfplus(struct v2prf_stuff *vps)
{
	struct hmac_ctx ctx;

	hmac_init_chunk(&ctx, vps->prf_hasher, *vps->skeyseed);
	hmac_update_chunk(&ctx, vps->t);
	hmac_update_chunk(&ctx, vps->ni);
	hmac_update_chunk(&ctx, vps->nr);
	hmac_update_chunk(&ctx, vps->spii);
	hmac_update_chunk(&ctx, vps->spir);
	hmac_update(&ctx, vps->counter, 1);
	hmac_final_chunk(vps->t, "skeyseed_t1", &ctx);
	DBG(DBG_CRYPT, {
		    char b[20];
		    sprintf(b, "prf+[%u]:", vps->counter[0]);
		    DBG_dump_chunk(b, vps->t);
	    });

	vps->counter[0]++;
	vps->availbytes  = vps->t.len;
	vps->nextbytes   = 0;
}

void v2genbytes(chunk_t *need,
		unsigned int needed, const char *name,
		struct v2prf_stuff *vps)
{
	u_char *target;

	need->ptr = alloc_bytes(needed, name);
	need->len = needed;
	target = need->ptr;

	while (needed > vps->availbytes) {
		if (vps->availbytes) {
			/* use any bytes which are presently in the buffer */
			memcpy(target, &vps->t.ptr[vps->nextbytes],
			       vps->availbytes);
			target += vps->availbytes;
			needed -= vps->availbytes;
			vps->availbytes = 0;
		}
		/* generate more bits into t1 */
		v2prfplus(vps);
	}
	passert(needed <= vps->availbytes);

	memcpy(target, &vps->t.ptr[vps->nextbytes], needed);
	vps->availbytes -= needed;
	vps->nextbytes  += needed;
}

