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

#ifndef HOST_PAIR_H
#define HOST_PAIR_H

#include <stdbool.h>

#include "ip_address.h"

struct host_pair_policy;
struct logger;
struct connection;
struct ike_info;

typedef bool match_host_pair_policy_fn(const struct connection *d,
				       const struct host_pair_policy *context,
				       struct logger *logger);

struct connection *find_host_pair_connection_on_responder(const struct ike_info *ike_info,
							  const ip_address local,
							  const ip_address remote,
							  match_host_pair_policy_fn *match_policy,
							  const struct host_pair_policy *context,
							  struct logger *logger);

#endif
