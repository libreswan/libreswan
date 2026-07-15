/* autoall mark/sweep, for libreswan
 *
 * Copyright (C) 2026 James Raphael Tiovalen <jamestiotio@meta.com>
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

#include "whack_autoall.h"

#include "show.h"
#include "log.h"
#include "connections.h"
#include "terminate.h"

void whack_autoall_start(const struct whack_message *wm UNUSED, struct show *s)
{
	struct logger *logger = show_logger(s);

	ldbg(logger, "marking root connections as stale for autoall sweep");

	struct connection_filter cq = {
		.search = {
			.order = OLD2NEW,
			.verbose.logger = logger,
			.where = HERE,
		},
	};
	while (next_connection(&cq)) {
		if (cq.c->clonedfrom != NULL) {
			continue;
		}
		cq.c->autoall_stale = true;
	}
}

void whack_autoall_stop(const struct whack_message *wm UNUSED, struct show *s)
{
	struct logger *logger = show_logger(s);

	ldbg(logger, "sweeping stale connections after autoall");

	struct connection_filter cq = {
		.search = {
			.order = OLD2NEW,
			.verbose.logger = logger,
			.where = HERE,
		},
	};
	while (all_connections(&cq)) {
		if (cq.c->clonedfrom != NULL) {
			continue;
		}
		if (!cq.c->autoall_stale) {
			continue;
		}
		llog(RC_LOG, logger, "sweeping stale connection %s", cq.c->name);
		whack_attach(cq.c, logger);
		connection_addref(cq.c, logger);
		terminate_and_delete_connections(cq.c, logger, HERE);
		connection_delref(&cq.c, logger);
	}
}
