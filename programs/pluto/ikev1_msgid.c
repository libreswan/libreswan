/* routines for state objects
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001, 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2012 Bram <bram-bcrafjna-erqzvar@spam.wizbit.be>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include <libreswan.h>

#include "rnd.h"
#include "defs.h"
#include "state.h"
#include "ikev1_msgid.h"
#include "log.h"

/* IKEv1 Message-IDs
 *
 * A Message ID is contained in each IKE message header.
 * For Phase 1 exchanges (Main and Aggressive), it will be zero.
 * For other exchanges, which must be under the protection of an
 * ISAKMP SA, the Message ID must be unique within that ISAKMP SA.
 * Effectively, this labels the message as belonging to a particular
 * exchange.
 * BTW, we feel this uniqueness allows rekeying to be somewhat simpler
 * than specified by draft-jenkins-ipsec-rekeying-06.txt.
 *
 * A MessageID is a 32 bit unsigned number.  We represent the value
 * internally in network order -- they are just blobs to us.
 * They are unsigned numbers to make hashing and comparing easy.
 *
 * The following mechanism is used to allocate message IDs.  This
 * requires that we keep track of which numbers have already been used
 * so that we don't allocate one in use.
 *
 * Note that IKEv2 message IDs are 0 for the initial exchanges, and
 * incremented by 1 for subsequent exchanges, so the below functions
 * are only required for IKEv1.
 */

struct msgid_list {
	msgid_t msgid;           /* network order */
	struct msgid_list     *next;
};

bool unique_msgid(const struct state *st, msgid_t msgid)
{
	struct msgid_list *p;

	passert(msgid != v1_MAINMODE_MSGID);
	passert(IS_ISAKMP_ENCRYPTED(st->st_state));

	for (p = st->st_used_msgids; p != NULL; p = p->next)
		if (p->msgid == msgid)
			return FALSE;

	return TRUE;
}

void reserve_msgid(struct state *st, msgid_t msgid)
{
	struct msgid_list *p;

	passert(IS_PHASE1(st->st_state) || IS_PHASE15(st->st_state));
	p = alloc_thing(struct msgid_list, "msgid");
	p->msgid = msgid;
	p->next = st->st_used_msgids;
	st->st_used_msgids = p;
}

msgid_t generate_msgid(const struct state *st)
{
	int timeout = 100; /* only try so hard for unique msgid */
	msgid_t msgid;

	passert(IS_ISAKMP_ENCRYPTED(st->st_state));

	for (;; ) {
		get_rnd_bytes((void *) &msgid, sizeof(msgid));
		if (msgid != v1_MAINMODE_MSGID && unique_msgid(st, msgid))
			break;

		if (--timeout == 0) {
			libreswan_log(
				"gave up looking for unique msgid; using %08" PRIx32,
				msgid);
			break;
		}
	}
	return msgid;
}

void ikev1_clear_msgid_list(const struct state *st)
{
	struct msgid_list *p = st->st_used_msgids;

	passert(st->st_state == STATE_UNDEFINED);
	while (p != NULL) {
		struct msgid_list *q = p;

		p = p->next;
		pfree(q);
	}
}
