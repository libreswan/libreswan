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

static void resolve_finish(struct connection *c,
			   struct host_addrs *resolved,
			   resolve_helper_cb *callback,
			   struct verbose verbose);

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
	struct verbose verbose = VERBOSE(DEBUG_STREAM, logger, NULL);
	struct host_addrs raw_addrs = host_addrs_from_connection_config(c);
	if (host_addrs_need_dns(&raw_addrs, verbose)) {
		struct help_request *request = alloc_help_request("resolve helper",
								  discard_resolve_help_request_content,
								  logger);
		request->connection = connection_addref(c, logger);
		request->extracted_host_addrs = raw_addrs;
		request->callback = callback;
		request_help(request, resolve_helper, logger);
		return;
	}

	resolve_finish(c, &raw_addrs, callback, verbose);
}

helper_cb *resolve_helper(struct help_request *request,
			  struct verbose verbose,
			  enum helper_id helper_id UNUSED)
{
	struct host_addrs *resolved = &request->resolved_host_addrs;
	*resolved = request->extracted_host_addrs;

	FOR_EACH_THING(lr, LEFT_END, RIGHT_END) {
 		struct route_addrs *end = &resolved->end[lr];
 		const char *leftright = end->leftright;

		/* host */
		if (end->host.type != KH_IPHOSTNAME) {
			continue;
		}

		vexpect(!address_is_specified(end->host.addr));
		ip_address host_addr;

		diag_t d = ttoaddress_dns(shunk1(end->host.value),
					  resolved->afi,
					  &host_addr);
		if (d != NULL) {
			vlog("failed to resolve '%s%s=%s', %s",
			     leftright, "", end->host.value,
			     str_diag(d));
			pfree_diag(&d);
			continue;
		}

		end->host.addr = host_addr;
	}

	return resolve_continue;
}

void resolve_continue(struct help_request *request,
		      struct verbose verbose)
{
	resolve_finish(request->connection,
		       &request->resolved_host_addrs,
		       request->callback,
		       verbose);
}

void resolve_finish(struct connection *c,
		    struct host_addrs *resolved,
		    resolve_helper_cb *cb,
		    struct verbose verbose)
{

	unsigned need_dns = (route_addrs_need_dns(&resolved->end[LEFT_END]) +
			     route_addrs_need_dns(&resolved->end[RIGHT_END]));
	if (need_dns > 0) {
		vdbg("connection has unresolved DNS; scheduling CHECK_DDNS");
		schedule_connection_check_ddns(c, verbose);
	}

	/*
	 * Even when need DNS, try to resolve routes.  Connection can
	 * still orient provided one of the addresses is known.
	 *
	 * Should skip end when it has unresolved DNS?
	 */
	resolve_default_route(&resolved->end[LEFT_END],
			      &resolved->end[RIGHT_END],
			      resolved->afi,
			      verbose);
	resolve_default_route(&resolved->end[RIGHT_END],
			      &resolved->end[LEFT_END],
			      resolved->afi,
			      verbose);

	build_connection_host_and_proposals_from_resolve(c, resolved, verbose);

	cb(c, resolved, verbose);
}
