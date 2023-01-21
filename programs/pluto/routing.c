/* connection routing, for libreswan
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
 */

#include "enum_names.h"

#include "defs.h"
#include "routing.h"
#include "connections.h"
#include "pending.h"
#include "log.h"
#include "kernel.h"

enum connection_action connection_timeout(struct connection *c,
					  unsigned tries_so_far,
					  struct logger *logger)
{
	unsigned try_limit = c->sa_keying_tries;

	switch (c->child.routing) {

	case RT_UNROUTED:		 /* for instance, permanent */
		if (try_limit > 0 && tries_so_far >= try_limit) {
			ldbg(logger, "maximum number of establish retries reached - abandoning");
			return CONNECTION_FAIL;
		}
		return CONNECTION_RETRY;

	case RT_UNROUTED_NEGOTIATION:
		if (try_limit > 0 && tries_so_far >= try_limit) {
			ldbg(logger, "maximum number of establish retries reached - abandoning");
			if (c->policy & POLICY_OPPORTUNISTIC) {
				/*
				 * A failed OE initiator, make shunt
				 * bare.
				 *
				 * Checking .kind above seems pretty
				 * dodgy.  Suspect it is trying to
				 * capture the initial IKE exchange
				 * when the child hasn't yet been
				 * created, except that when kind is
				 * STATE_V2_PARENT_I2 the larval Child
				 * SA has been created?!?
				 */
				orphan_holdpass(c, c->spd, logger);
				/*
				 * Change routing so we don't get
				 * cleared out when state/connection
				 * dies.
				 */
				set_child_routing(c, RT_UNROUTED);
				dbg("kernel: orphan_holdpas() done - returning success");
			}
			return CONNECTION_FAIL;
		}
		return CONNECTION_RETRY;

	case RT_ROUTED_NEGOTIATION:
		if (try_limit > 0 && tries_so_far >= try_limit) {
			ldbg(logger, "maximum number of establish retries reached - abandoning");
			if (c->policy & POLICY_OPPORTUNISTIC) {
				/*
				 * A failed OE initiator, make shunt
				 * bare.
				 *
				 * Checking .kind above seems pretty
				 * dodgy.  Suspect it is trying to
				 * capture the initial IKE exchange
				 * when the child hasn't yet been
				 * created, except that when kind is
				 * STATE_V2_PARENT_I2 the larval Child
				 * SA has been created?!?
				 */
				orphan_holdpass(c, c->spd, logger);
				/*
				 * Change routing so we don't get
				 * cleared out when state/connection
				 * dies.
				 */
				set_child_routing(c, RT_ROUTED_PROSPECTIVE);
			}
			return CONNECTION_FAIL;
		}
		return CONNECTION_RETRY;

	default:
		break;
	}
	enum_buf eb;
	llog_pexpect(logger, HERE, "connection in %s not expecting %s",
		     str_enum_short(&routing_names, c->child.routing, &eb),
		     __func__);
	return CONNECTION_FAIL;
}

const char *connection_action_name[] = {
#define S(E) [E] = #E
	S(CONNECTION_RETRY),
	S(CONNECTION_FAIL),
#undef S
};

const struct enum_names connection_action_names = {
	CONNECTION_RETRY, CONNECTION_FAIL,
	ARRAY_REF(connection_action_name),
	"CONNECTION_",
	NULL,
};
