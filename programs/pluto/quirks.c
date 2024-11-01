/* Libreswan ISAKMP Quirks handling
 * Copyright (C) 2003 Michael Richardson <mcr@xelerance.com>
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

#include "quirks.h"

#include "defs.h"
#include "state.h"
#include "demux.h"

/*
 * PAUL: Why are the quirks in the message digest and not in the state?
 *       EECK: they are in both! Candidate to phase out completely
 *
 * message digest quirks are merged into state quirks by merge_quirks.
 */

void merge_quirks(struct state *st, const struct msg_digest *md)
{
	struct isakmp_quirks *dq = &st->st_v1_quirks;
	const struct isakmp_quirks *sq = &md->v1_quirks;

	dq->xauth_ack_msgid   |= sq->xauth_ack_msgid;
	dq->modecfg_pull_mode |= sq->modecfg_pull_mode;
	/* ??? st->quirks.qnat_traversal is never used */
	if (dq->qnat_traversal_vid < sq->qnat_traversal_vid)
		dq->qnat_traversal_vid = sq->qnat_traversal_vid;
	dq->xauth_vid |= sq->xauth_vid;
}
