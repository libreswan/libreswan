/* DDNS, for libreswan
 *
 * Copyright (C) 1998-2010,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2009 Stefan Arentz <stefan@arentz.ca>
 * Copyright (C) 2009-2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2007-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Panagiotis Tamtamis <tamtamis@gmail.com>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
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

#include "whack_ddns.h"

#include "defs.h"
#include "whack.h"
#include "show.h"
#include "verbose.h"
#include "lswlog.h"
#include "log.h"
#include "ddns.h"

#include "connection_event.h"
#include "connections.h"
#include "visit_connection.h"

static connection_visitor whack_ddns_connection;

unsigned whack_ddns_connection(const struct whack_message *wm UNUSED,
			       struct show *s,
			       struct connection *c,
			       struct connection_visitor_context *context UNUSED)
{
	if (connection_event_is_scheduled(c, CONNECTION_CHECK_DDNS)) {
		flush_connection_event(c, CONNECTION_CHECK_DDNS);
		connection_check_ddns(c, VERBOSE(DEBUG_STREAM, show_logger(s), "DDNS"));
		return 1;
	}

	ldbg(show_logger(s), "skipping %s as no outstanding DDNS", c->name);
	return 1;
}

static void whack_ddns_connections(const struct whack_message *wm,
				   struct show *s)
{
	show(s, "updating pending dns lookups");

	struct verbose verbose = VERBOSE(DEBUG_STREAM, show_logger(s), "DDNS");
	vtime_t start = vdbg_start("checking DDNS");

	struct connection_filter cf = {
		.search = {
			.order = NEW2OLD,
			.verbose = verbose,
			.where = HERE,
		},
	};

	while (next_connection(&cf)) {
		struct connection *c = cf.c;
		whack_ddns_connection(wm, s, c, NULL);
	}

	vdbg_stop(&start, "in %s() for hostname lookup", __func__);
}

void whack_ddns(const struct whack_message *wm, struct show *s)
{
	if (wm->name == NULL) {
		whack_ddns_connections(wm, s);
	}

	whack_connection_trees(wm, s, OLD2NEW,
			       whack_ddns_connection, NULL,
			       (struct each) {
				       .log_unknown_name = true,
			       });
}
