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

#include "whack_deletestate.h"

#include "defs.h"
#include "connections.h"
#include "state.h"
#include "show.h"
#include "log.h"
#include "ikev1.h"		/* for send_v1_delete() */
#include "ikev2_delete.h"	/* for record_n_send_n_log_v2_delete() */
#include "ikev1_delete.h"	/* for record_n_send_n_log_v2_delete() */

static struct logger *merge_loggers(struct logger *o_logger,
				   bool background,
				   struct logger *g_logger)
{
	/*
	 * Create a logger that looks like the object; but also has
	 * whack attached.
	 */
	struct logger *logger = clone_logger(o_logger, HERE);
	whack_attach(logger, g_logger);
	if (!background) {
		whack_attach(o_logger, g_logger);
	}
	return logger;
}

void whack_deletestate(const struct whack_message *m, struct show *s)
{
#if 0
	/* this command uses .deletestateno instead */
	if (m->name == NULL) {
		whack_log(RC_FATAL, s,
			  "received whack command to delete a state by serial number, but did not receive the serial number - ignored");
		return;
	}
#endif

	struct state *st = state_by_serialno(m->whack_deletestateno);
	if (st == NULL) {
		llog_rc(RC_UNKNOWN_NAME, show_logger(s), "no state "PRI_SO" to delete",
			pri_so(m->whack_deletestateno));
		return;
	}

	struct logger *logger = merge_loggers(st->logger,
					      m->whack_async/*background*/,
					      show_logger(s));
	llog(LOG_STREAM/*not-whack*/, logger,
	     "received whack to delete %s state "PRI_SO" %s",
	     st->st_connection->config->ike_info->version_name,
	     pri_so(st->st_serialno), st->st_state->name);

	if (IS_PARENT_SA_ESTABLISHED(st)) {
		struct ike_sa *ike = pexpect_parent_sa(st);
		switch (ike->sa.st_ike_version) {
		case IKEv1:
			llog_n_maybe_send_v1_delete(ike, &ike->sa, HERE);
			connection_teardown_ike(&ike, REASON_DELETED, HERE);
			break;
		case IKEv2:
			submit_v2_delete_exchange(ike, NULL);
			break;
		}
	} else if (IS_PARENT_SA(st)) {
		/* not established */
		struct ike_sa *ike = pexpect_parent_sa(st);
		switch (ike->sa.st_ike_version) {
		case IKEv1:
			llog_n_maybe_send_v1_delete(NULL, &ike->sa, HERE);
			break;
		case IKEv2:
			break;
		}
		connection_teardown_ike(&ike, REASON_DELETED, HERE);
	} else {
		struct child_sa *child = pexpect_child_sa(st);
		switch (child->sa.st_ike_version) {
		case IKEv1:
		{
			struct ike_sa *isakmp =
				established_isakmp_sa_for_state(&child->sa, /*viable-parent*/false);
			llog_n_maybe_send_v1_delete(isakmp, &child->sa, HERE);
			connection_teardown_child(&child, REASON_DELETED, HERE);
			st = NULL;
			break;
		}
		case IKEv2:
		{
			struct ike_sa *ike = ike_sa(&child->sa, HERE);
			if (IS_PARENT_SA_ESTABLISHED(&ike->sa)) {
				submit_v2_delete_exchange(ike, child);
			} else {
				connection_teardown_child(&child, REASON_DELETED, HERE);
			}
			break;
		}
		}
	}

	free_logger(&logger, HERE);
}
