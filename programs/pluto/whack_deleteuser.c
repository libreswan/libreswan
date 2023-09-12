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

#include "whack_deleteuser.h"

#include "defs.h"
#include "connections.h"
#include "state.h"
#include "ikev1.h"		/* for send_v1_delete() et.al. */
#include "log.h"
#include "show.h"

static void delete_v1_state_by_username(struct state *st, const char *name)
{
	/* only support deleting ikev1 with XAUTH username */
	if (!IS_ISAKMP_SA(st)) {
		return;
	}
	struct ike_sa *ike = pexpect_ike_sa(st); /* per above */

	if (!streq(ike->sa.st_xauth_username, name)) {
		return;
	}

	if (IS_PARENT_SA_ESTABLISHED(&ike->sa)) {
		send_v1_delete(ike, &ike->sa, HERE);
	}
	on_delete(&ike->sa, skip_send_delete);
	delete_ike_family(&ike);
	/* note: no md->v1_st to clear */
}

void whack_deleteuser(const struct whack_message *m, struct show *s)
{
	if (m->name == NULL ) {
		whack_log(RC_FATAL, s,
			  "received whack command to delete a connection by username, but did not receive the username - ignored");
		return;
	}

	llog(LOG_STREAM, show_logger(s),
	     "received whack to delete connection by user %s", m->name);
	struct state_filter sf = { .where = HERE, };
	while (next_state_new2old(&sf)) {
		delete_v1_state_by_username(sf.st, m->name);
	}
}
