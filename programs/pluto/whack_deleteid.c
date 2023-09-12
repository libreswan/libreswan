/* whack communicating routines, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013-2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2011 Mika Ilmaranta <ilmis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2014-2020 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2014-2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2019-2023 Andrew Cagney <cagney@gnu.org>
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

#include "whack_deleteid.h"

#include "defs.h"
#include "connections.h"
#include "state.h"
#include "show.h"
#include "log.h"
#include "ikev1.h"		/* for send_v1_delete() */
#include "ikev2_delete.h"	/* for record_n_send_n_log_v2_delete() */

static void delete_state_by_id_name(struct state *st, const char *name)
{
	struct connection *c = st->st_connection;

	if (!IS_PARENT_SA(st)) {
		return;
	}
	struct ike_sa *ike = pexpect_ike_sa(st); /* per above */

	id_buf thatidb;
	const char *thatidbuf = str_id(&c->remote->host.id, &thatidb);
	if (streq(thatidbuf, name)) {
		if (IS_PARENT_SA_ESTABLISHED(&ike->sa)) {
			switch (ike->sa.st_ike_version) {
#ifdef USE_IKEv1
			case IKEv1:
				/*
				 * Tell the other side of any IPSEC
				 * SAs that are going down
				 */
				send_v1_delete(ike, &ike->sa, HERE);
				break;
#endif
			case IKEv2:
				/*
				 *
				 * ??? in IKEv2, we should not
				 * immediately delete: we should use
				 * an Informational Exchange to
				 * coordinate deletion.
				 *
				 * XXX: It's worse ....
				 *
				 * should_send_delete() can return
				 * true when ST is a Child SA.  But
				 * the below sends out a delete for
				 * the IKE SA.
				 */
				record_n_send_n_log_v2_delete(ike, HERE);
				break;
			}
		}
		on_delete(&ike->sa, skip_send_delete);
		/* XXX: won't this also send deletes? */
		delete_ike_family(&ike);
	}
}

void whack_deleteid(const struct whack_message *m, struct show *s)
{
	if (m->name == NULL ) {
		whack_log(RC_FATAL, s,
			  "received whack command to delete a connection by id, but did not receive the id - ignored");
		return;
	}

	llog(LOG_STREAM, show_logger(s),
	     "received whack to delete connection by id %s", m->name);
	struct state_filter sf = { .where = HERE, };
	while (next_state_new2old(&sf)) {
		delete_state_by_id_name(sf.st, m->name);
	}
}
