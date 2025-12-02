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
#include "log.h"

static helper_fn resolve_helper;
static helper_cb resolve_continue;

static refcnt_discard_content_fn discard_resolve_help_request_content;

struct help_request {
	refcnt_t refcnt;
	struct whack_message_refcnt *wmr;
	struct extracted_host_addrs extracted_host_addrs;
	struct resolved_host_addrs resolved_host_addrs;
	resolve_helper_cb *callback;
};

void discard_resolve_help_request_content(void *pointer, const struct logger *owner, where_t where)
{
	struct help_request *request = pointer;
	refcnt_delref(&request->wmr, owner, where);
}

void request_resolve_help(struct whack_message_refcnt *wmr,
			  const struct extracted_host_addrs *extracted_host_addrs,
			  resolve_helper_cb *callback,
			  struct logger *logger)
{
	struct help_request *request = alloc_help_request("resolve helper",
							  discard_resolve_help_request_content,
							  logger);
	request->wmr = refcnt_addref(wmr, logger, HERE);
	request->extracted_host_addrs = (*extracted_host_addrs);
	request->callback = callback;
	request_help(request, resolve_helper, logger);
}

helper_cb *resolve_helper(struct help_request *request,
			  struct verbose verbose,
			  enum helper_id helper_id UNUSED)
{
	request->resolved_host_addrs = resolve_extracted_host_addrs(&request->extracted_host_addrs, verbose);
	return resolve_continue;
}

void resolve_continue(struct help_request *request,
		      struct verbose verbose)
{
	request->callback(request->wmr,
			  &request->extracted_host_addrs,
			  &request->resolved_host_addrs,
			  verbose);
}
