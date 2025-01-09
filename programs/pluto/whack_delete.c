/* <<ipsec delete <connection> >>, for libreswan
 *
 * Copyright (C) 2023 Andrew Cagney
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

#include "whack_delete.h"

#include "visit_connection.h"
#include "show.h"
#include "log.h"
#include "connections.h"
#include "pending.h"
#include "ikev2_delete.h"
#include "ikev1.h"			/* for established_isakmp_for_state() */
#include "ikev1_delete.h"		/* for llog_n_maybe_send_v1_delete() */
#include "connection_event.h"
#include "terminate.h"			/* for terminate_connection_states() */

/*
 * Terminate and then delete connections with the specified name.
 */

static unsigned whack_delete_connections(const struct whack_message *m UNUSED,
					 struct show *s,
					 struct connection *c)
{
	terminate_and_delete_connections(&c, show_logger(s), HERE);
	return 1;
}

void whack_delete(const struct whack_message *m, struct show *s,
		  bool log_unknown_name)
{
	if (m->name == NULL) {
		whack_log(RC_FATAL, s,
			  "received command to delete a connection, but did not receive the connection name - ignored");
		return;
	}

	/*
	 * This is old-to-new which means that aliases are processed
	 * before templates.
	 */
	whack_connection(m, s, whack_delete_connections,
			 /*alias_order*/OLD2NEW,
			 (struct each) {
				 .log_unknown_name = log_unknown_name,
			 });
}
