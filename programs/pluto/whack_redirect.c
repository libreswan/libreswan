/* ipsec redirect ..., for libreswan
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
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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

#include "whack_redirect.h"

#include "defs.h"
#include "verbose.h"
#include "log.h"
#include "whack.h"
#include "show.h"
#include "jambuf.h"
#include "passert.h"
#include "state.h"
#include "connections.h"
#include "visit_connection.h"
#include "ikev2_redirect.h"

static connection_state_visitor whack_active_redirect_state;

void jam_whack_redirect(struct jambuf *buf, const struct whack_message *wm)
{
	if (wm->name != NULL) {
		jam_string(buf, " name=");
		jam_string(buf, wm->name);
	}
	if (wm->redirect_to != NULL) {
		jam_string(buf, " redirect-to=");
		jam_string(buf, wm->redirect_to);
	}
	if (wm->global_redirect != 0) {
		jam_string(buf, " redirect_to=");
		jam_sparse_long(buf, &yna_option_names, wm->global_redirect);
	}
}

struct connection_state_visitor_context {
	struct redirect_dests active_dests;
	unsigned count;
};

void whack_active_redirect_state(struct connection *c UNUSED,
				 struct ike_sa **ike_sa,
				 struct child_sa **child UNUSED,
				 enum connection_visit_kind visit_kind,
				 struct connection_state_visitor_context *context)
{
	switch (visit_kind) {
	case FINISH_CONNECTION_PRINCIPAL_IKE_SA:
	{
		struct ike_sa *ike = (*ike_sa);
		/* cycle through the list of redirects */
		shunk_t active_dest = next_redirect_dest(&context->active_dests);
		/* not whack; there could be thousands? */
		llog(LOG_STREAM/*not-whack*/, ike->sa.logger,
		     "redirecting to: "PRI_SHUNK, pri_shunk(active_dest));
		pfreeany(ike->sa.st_active_redirect_gw);
		ike->sa.st_active_redirect_gw = clone_hunk_as_string(active_dest, "redirect");
		v2_msgid_queue_exchange(ike, NULL, &v2_INFORMATIONAL_v2N_REDIRECT_exchange);
		context->count++;
	}
	default:
		break;
	}
}

void whack_active_redirect(const struct whack_message *wm, struct show *s)
{
	struct logger *logger = show_logger(s);
	/*
	 * We are redirecting all peers of one or all connections.
	 *
	 * Whack's --redirect-to is ambitious - is it part of an ADD
	 * or a global op?  Checking .whack_add.
	 */
	PASSERT(logger, wm->redirect_to != NULL);
	struct connection_state_visitor_context context = {0};
	if (!set_redirect_dests(wm->redirect_to, &context.active_dests)) {
		show(s, "redirect-to='%s' is empty", wm->redirect_to);
		return;
	}

	whack_connection_states(wm, s, /*order*/OLD2NEW,
				whack_active_redirect_state, &context,
				(struct each) {
					.future_tense = "redirecting",
					.past_tense = "redirected",
					.log_unknown_name = false,
				});
	if (context.count == 0) {
		LLOG_JAMBUF(RC_LOG, logger, buf) {
			jam(buf, "no active tunnels found");
			if (wm->name != NULL) {
				jam(buf, " for connection \"%s\"", wm->name);
			}
		}
	} else {
		LLOG_JAMBUF(RC_LOG, logger, buf) {
			jam(buf, "redirections sent for %d tunnels", context.count);
			if (wm->name != NULL) {
				jam(buf, " of connection \"%s\"", wm->name);
			}
		}
	}
	free_redirect_dests(&context.active_dests);
}

void whack_global_redirect(const struct whack_message *wm, struct show *s)
{
	set_global_redirect(wm->global_redirect,
			    wm->redirect_to,
			    show_logger(s));
}
