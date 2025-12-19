/* resolve helper, for libreswan
 *
 * Copyright (C) 2025 Andrew Cagney
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

#include "resolve_helper.h"

#include "refcnt.h"
#include "defaultroute.h"

#include "extract.h"
#include "helper.h"
#include "connections.h"
#include "connection_db.h"
#include "log.h"
#include "orient.h"
#include "connection_event.h"

static helper_fn resolve_helper;
static helper_cb resolve_continue;

static refcnt_discard_content_fn discard_resolve_help_request_content;

struct help_request {
	refcnt_t refcnt;
	struct connection *connection;
	struct host_addrs extracted_host_addrs;
	struct host_addrs resolved_host_addrs;
	resolve_helper_cb *callback;
};

void discard_resolve_help_request_content(void *pointer, const struct logger *owner, where_t where)
{
	struct help_request *request = pointer;
	connection_delref_where(&request->connection, owner, where);
}

void request_resolve_help(struct connection *c,
			  resolve_helper_cb *callback,
			  struct logger *logger)
{
	struct help_request *request = alloc_help_request("resolve helper",
							  discard_resolve_help_request_content,
							  logger);
	request->connection = connection_addref(c, logger);
	request->extracted_host_addrs = host_addrs_from_connection_config(c);
	request->callback = callback;
	request_help(request, resolve_helper, logger);
}

static struct host_addrs resolve_extracted_host_addrs(const struct host_addrs *host_addrs,
						      struct verbose verbose)
{
	struct host_addrs resolved = *host_addrs;
	/*hope for the best*/
	resolved.needs.route = false;
	resolved.needs.dns = false;

	FOR_EACH_THING(lr, LEFT_END, RIGHT_END) {
 		struct route_addrs *end = &resolved.end[lr];
 		const char *leftright = end->leftright;

		/* host */
		if (end->host.type != KH_IPHOSTNAME) {
			continue;
		}

		ip_address host_addr;
		err_t e = ttoaddress_dns(shunk1(end->host.value),
					 resolved.afi,
					 &host_addr);
		if (e != NULL) {
			/*
			 * XXX: failing ttoaddress*() sets host_addr
			 * to unset but want existing value.
			 */
			vlog("failed to resolve '%s%s=%s' at load time: %s",
			     leftright, "", end->host.value, e);
			resolved.needs.dns = true;
			continue;
		}
		end->host.addr = host_addr;
	}

	if (!resolved.needs.dns) {
		resolve_default_route(&resolved.end[LEFT_END],
				      &resolved.end[RIGHT_END],
				      host_addrs->afi,
				      verbose);
		resolve_default_route(&resolved.end[RIGHT_END],
				      &resolved.end[LEFT_END],
				      host_addrs->afi,
				      verbose);
	}

	return resolved;
}

helper_cb *resolve_helper(struct help_request *request,
			  struct verbose verbose,
			  enum helper_id helper_id UNUSED)
{
	request->resolved_host_addrs = resolve_extracted_host_addrs(&request->extracted_host_addrs,
								    verbose);
	return resolve_continue;
}

void resolve_continue(struct help_request *request,
		      struct verbose verbose)
{
	struct connection *c = request->connection;
	const struct host_addrs *resolved = &request->resolved_host_addrs;

	vdbg("needs.dns = %s needs.route = %s",
	     bool_str(resolved->needs.dns),
	     bool_str(resolved->needs.route));

	build_connection_host_and_proposals_from_resolve(c, resolved, verbose);

	/*
	 * When possible, try to orient the connection.
	 */
	vassert(!oriented(c));
	if (resolved->needs.dns) {
		vdbg("unresolved connection can't orient; scheduling CHECK_DDNS");
		schedule_connection_check_ddns(c, verbose);
	} else if (!orient(c, verbose)) {
		vdbg("connection did not orient, scheduling CHECK_DDNS");
		schedule_connection_check_ddns(c, verbose);
	} else if (verbose.debug) {
		vdbg("connection oriented, re-checking DB");
		connection_db_check(verbose.logger, HERE);
	}

	request->callback(c, resolved, verbose);
}
