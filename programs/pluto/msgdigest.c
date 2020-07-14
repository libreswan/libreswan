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

struct msg_digest *alloc_md(const struct iface_port *ifp, const ip_endpoint *sender, where_t where)
{
	/* convenient initializer:
	 * - all pointers NULL
	 * - .note = NOTHING_WRONG
	 * - .encrypted = FALSE
	 */
	static const struct msg_digest blank_md;
	struct msg_digest *md = alloc_thing(struct msg_digest, where.func);
	*md = blank_md;
	ref_init(md, where);
	md->iface = ifp;
	md->sender = *sender;
	md->md_logger = alloc_logger(md, &logger_message_vec, where);
	return md;
}

struct msg_digest *clone_raw_md(struct msg_digest *md, const char *name)
{
	struct msg_digest *clone = alloc_md(md->iface, &md->sender, HERE);
	clone->fake_clone = true;
	clone->md_inception = threadtime_start();
	clone->md_logger = alloc_logger(md, &logger_message_vec, HERE);
	/* packet_pbs ... */
	size_t packet_size = pbs_room(&md->packet_pbs);
	void *packet_bytes = clone_bytes(md->packet_pbs.start, packet_size, name);
	init_pbs(&clone->packet_pbs, packet_bytes, packet_size, name);
	return clone;
}

struct msg_digest *md_addref(struct msg_digest *md, where_t where)
{
	return ref_add(md, where);
}

static void free_mdp(struct msg_digest **mdp,
		     where_t unused_where UNUSED)
{
	free_chunk_content(&(*mdp)->raw_packet);
	free_logger(&(*mdp)->md_logger);
	pfreeany((*mdp)->packet_pbs.start);
	pfree(*mdp);
	*mdp = NULL;
}

void md_delref(struct msg_digest **mdp, where_t where)
{
	ref_delete(mdp, free_mdp, where);
}
