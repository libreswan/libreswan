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

#include "lswlog.h"

#include "defs.h"
#include "demux.h"      /* needs packet.h */

struct msg_digest *alloc_md(const char *mdname)
{
	/* convenient initializer:
	 * - all pointers NULL
	 * - .note = NOTHING_WRONG
	 * - .encrypted = FALSE
	 */
	static const struct msg_digest blank_md;
	struct msg_digest *md = alloc_thing(struct msg_digest, mdname);
	*md = blank_md;
	return md;
}

struct msg_digest *clone_raw_md(struct msg_digest *md, const char *name)
{
	struct msg_digest *clone = alloc_md(name);
	clone->fake_clone = true;
	clone->md_inception = threadtime_start();
	/* raw_packet */
	clone->iface = md->iface; /* copy reference */
	clone->sender = md->sender; /* copy value */
	/* packet_pbs ... */
	size_t packet_size = pbs_room(&md->packet_pbs);
	void *packet_bytes = clone_bytes(md->packet_pbs.start, packet_size, name);
	init_pbs(&clone->packet_pbs, packet_bytes, packet_size, name);
	return clone;
}

static void free_mdp(struct msg_digest **mdp)
{
	freeanychunk((*mdp)->raw_packet);
	pfreeany((*mdp)->packet_pbs.start);
	pfree(*mdp);
	*mdp = NULL;
}

void release_any_md(struct msg_digest **mdp)
{
	if (*mdp != NULL) {
		free_mdp(mdp);
	}
}
