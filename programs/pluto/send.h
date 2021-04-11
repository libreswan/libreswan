/* get-next-event loop
 * Copyright (C) 1998-2001,2013  D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
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

#ifndef SEND_H
#define SEND_H

#include "chunk.h"
#include "ip_address.h"
#include "packet.h"		/* for pb_stream */

struct iface_endpoint;
struct state;
struct msg_digest;

bool send_pbs_out_using_md(struct msg_digest *md, const char *where, struct pbs_out *packet);
bool send_pbs_out_using_state(struct state *st, const char *where, struct pbs_out *packet);

bool send_chunks_using_state(struct state *st, const char *where,
			     chunk_t a, chunk_t b);

bool send_chunk_using_state(struct state *st, const char *where, chunk_t packet);

#define send_hunk_using_state(ST, WHERE, HUNK)				\
	({								\
		chunk_t h_ = { .ptr = (HUNK).ptr, .len = (HUNK).len, };	\
		send_chunk_using_state(ST, WHERE, h_);			\
	})

bool send_keepalive_using_state(struct state *st, const char *where);

#endif
