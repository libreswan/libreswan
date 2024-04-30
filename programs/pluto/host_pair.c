/* search connections by local-remote, for libreswan
 *
 * Copyright (C) 2024 Andrew Cagney
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

#include "host_pair.h"

#include "log.h"
#include "connections.h"

struct connection *find_host_pair_connection_on_responder(const struct ike_info *ike_info,
							  const ip_address local_address,
							  const ip_address remote_address,
							  match_host_pair_policy_fn *match_connection_policy,
							  const struct host_pair_policy *context,
							  struct logger *logger)
{
	address_buf lb;
	address_buf rb;
	ldbg(logger, "%s() %s %s->%s", __func__,
	     ike_info->version_name,
	     str_address(&remote_address, &rb),
	     str_address(&local_address, &lb));

	struct connection *c = NULL;

	struct connection_filter hpf = {
		.local = &local_address,
		.remote = &remote_address,
		.ike_version = ike_info->version,
		.where = HERE,
	};
	while (next_connection(OLD2NEW, &hpf)) {
		struct connection *d = hpf.c;

		if (!match_connection_policy(d, context, logger)){
			continue;
		}

		/*
		 * This could be a shared ISAKMP SA connection, in
		 * which case we prefer to find the connection that
		 * has the ISAKMP SA.
		 */
		if (d->established_ike_sa != SOS_NOBODY) {
			/* instant winner */
			c = d;
			break;
		}
		if (c == NULL) {
			c = d;
		}
	}

	return c;
}
