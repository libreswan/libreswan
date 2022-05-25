/* demultiplex incoming IKE messages
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#include "defs.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */
#include "iface.h"

static void free_md(void *obj, where_t where)
{
	struct msg_digest *md = obj;
	free_chunk_content(&md->raw_packet);
	free_logger(&md->md_logger, where);
	iface_endpoint_delref_where(&md->iface, where);
	pfree(md);
}

struct msg_digest *alloc_md(struct iface_endpoint *ifp,
			    const ip_endpoint *sender,
			    const uint8_t *packet, size_t packet_len,
			    where_t where)
{
	struct msg_digest *md = refcnt_overalloc(struct msg_digest, packet_len, free_md, where);
	md->iface = iface_endpoint_addref_where(ifp, where);
	md->sender = *sender;
	md->md_logger = alloc_logger(md, &logger_message_vec, where);
	void *buffer = md + 1;
	init_pbs(&md->packet_pbs, buffer, packet_len, "packet");
	if (packet != NULL) {
		memcpy(buffer, packet, packet_len);
	}
	return md;
}

struct msg_digest *clone_raw_md(struct msg_digest *md, where_t where)
{
	size_t packet_len = pbs_room(&md->packet_pbs);
	struct msg_digest *clone = alloc_md(md->iface, &md->sender,
					    md->packet_pbs.start, packet_len,
					    where);
	clone->fake_clone = true;
	clone->md_inception = threadtime_start();
	return clone;
}

struct msg_digest *md_addref_where(struct msg_digest *md, where_t where)
{
	return addref_where(md, where);
}

void md_delref_where(struct msg_digest **mdp, where_t where)
{
	delref_where(mdp, where);
}
