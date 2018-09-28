/* demultiplex incoming IKE messages
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>   /* only used for belt-and-suspenders select call */
#include <sys/poll.h>   /* only used for forensic poll call */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
#  include <asm/types.h>        /* for __u8, __u32 */
#  include <linux/errqueue.h>
#  include <sys/uio.h>          /* struct iovec */
#endif

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "cookie.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "crypto.h"
#include "ike_alg.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */

/* message digest allocation and deallocation */

static struct msg_digest *md_pool = NULL;

/* free_md_pool is only used to avoid leak reports */
void free_md_pool(void)
{
	for (;; ) {
		struct msg_digest *md = md_pool;

		if (md == NULL)
			break;
		passert(md_pool != md->next);
		md_pool = md->next;
		pfree(md);
	}
}

struct msg_digest *alloc_md(const char *mdname)
{
	struct msg_digest *md = md_pool;

	/* convenient initializer:
	 * - all pointers NULL
	 * - .note = NOTHING_WRONG
	 * - .encrypted = FALSE
	 */
	static const struct msg_digest blank_md;

	if (md == NULL)
		md = alloc_thing(struct msg_digest, mdname);
	else
		md_pool = md->next;

	*md = blank_md;
	md->digest_roof = 0;

	return md;
}

struct msg_digest *clone_md(struct msg_digest *md, const char *name)
{
	struct msg_digest *clone = alloc_md(name);
	clone->fake = true;
	/* raw_packet */
	clone->iface = md->iface; /* copy reference */
	clone->sender = md->sender; /* copy value */
	/* packet_pbs ... */
	size_t packet_size = pbs_room(&md->packet_pbs);
	void *packet_bytes = clone_bytes(md->packet_pbs.start, packet_size, name);
	init_pbs(&clone->packet_pbs, packet_bytes, packet_size, name);
	return clone;
}

void release_md(struct msg_digest *md)
{
	freeanychunk(md->raw_packet);
	pfreeany(md->packet_pbs.start);

	/* check that we are not creating a loop */
	passert(md != md_pool);

#ifdef MSG_DIGEST_ALLOC_DEBUG
	/*
	 * This version does not maintain a pool.
	 * Thus leak-detective, Electric Fence, and valgrind are more effective.
	 */
	pfree(md);
#else
	/*
	 * Shred to useless value.
	 * Redundant but might catch dangling references.
	 */
	memset(md, 0xED, sizeof(struct msg_digest));

	md->next = md_pool;
	md_pool = md;
#endif
}

void release_any_md(struct msg_digest **mdp)
{
	if (*mdp != NULL) {
		release_md(*mdp);
		*mdp = NULL;
	}
}
