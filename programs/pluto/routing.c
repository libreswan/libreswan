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

void connection_negotiating(struct connection *c,
			    const struct kernel_acquire *b)
{
	struct logger *logger = c->logger;
	struct spd_route *spd = c->spd; /*XXX:only-one!?!*/
	bool oe = ((c->policy & POLICY_OPPORTUNISTIC) != LEMPTY);

	/* used below in pexpects */
	struct connection *t = connection_by_serialno(c->serial_from); /* could be NULL */
	struct spd_owner owner = spd_owner(spd, 0);

	PASSERT(logger, (c->kind == CK_PERMANENT ||
			 c->kind == CK_INSTANCE));
	PASSERT(logger, ((c->kind == CK_INSTANCE) >= (t != NULL)));

	/*
	 * Figure out the connection's routing transition.
	 */
	enum routing old_routing = c->child.routing;	/* routing, old */
	enum routing new_routing;
	enum kernel_policy_op op;
	const char *reason;

	switch (old_routing) {
	case RT_UNROUTED:
		/*
		 * For instance:
		 * - an instance with a routed prospective template
		 * but also:
		 * - an unrouted permenant by whack?
		 * - an instance with an unrouted template due to whack?
		 */
		new_routing = RT_UNROUTED_NEGOTIATION;
		op = KERNEL_POLICY_OP_ADD;
		/* XXX: these descriptions make no sense */
		reason = (oe ? "replace unrouted opportunistic %trap with broad %pass or %hold" :
			  "replace unrouted %trap with broad %pass or %hold");
		PEXPECT(logger, t == NULL || t->child.routing == RT_ROUTED_PROSPECTIVE);
		break;
	case RT_ROUTED_PROSPECTIVE:
		/*
		 * For instance?
		 *
		 * XXX: could be whack or acquire.
		 *
		 * XXX: is this just re-installing the same policy?
		 * No?  The prospective policy might be 7.0.0.0/8 but
		 * this is installing 7.7.7.7/32 from a trigger of
		 * 7.7.7.7/32/ICMP/8.
		 */
		new_routing = RT_ROUTED_NEGOTIATION;
		op = KERNEL_POLICY_OP_REPLACE;
		/* XXX: these descriptions make no sense */
		reason = (oe ? "broad prospective opportunistic %pass or %hold" :
			  "broad prospective %pass or %hold");
		PEXPECT(logger, t == NULL);
		break;
	default:
		/* no change: this %hold or %pass is old news */
		new_routing = old_routing;
		op = 0; /* i.e., NOP */
		reason = "NOP";
		break;
	}

	LDBGP_JAMBUF(DBG_BASE, logger, buf) {
		jam(buf, "%s():", __func__);
		jam(buf, " by_acquire=%s", bool_str(b->by_acquire));
		jam(buf, " oppo=%s", bool_str(oe));
		jam(buf, " kind=");
		jam_enum_short(buf, &connection_kind_names, c->kind);
		jam(buf, " routing=");
		jam_enum_short(buf, &routing_names, old_routing);
		if (old_routing != new_routing) {
			jam(buf, "->");
			jam_enum_short(buf, &routing_names, new_routing);
		} else {
			jam_string(buf, "(no-change)");
		}
		jam(buf, " packet=");
		jam_packet(buf, &b->packet);
		jam(buf, " selectors=");
		jam_selector_pair(buf, &spd->local->client, &spd->remote->client);
		jam(buf, " one_address=%s",
		    bool_str(selector_contains_one_address(spd->local->client) &&
			     selector_contains_one_address(spd->remote->client)));
		jam_string(buf, " op=");
		jam_enum(buf, &kernel_policy_op_names, op);
		/* can have policy owner without route owner */
		if (owner.policy != NULL) {
			jam_string(buf, " policy-owner=");
			jam_connection(buf, owner.policy->connection);
		} else if (owner.route != NULL) {
			jam_string(buf, " route-owner=");
			jam_connection(buf, owner.route->connection);
		}
		jam_string(buf, ": ");
		jam_string(buf, reason);
	}

	/*
	 * We need a broad %hold, not the narrow one.
	 *
	 * First we ensure that there is a broad %hold.  There may
	 * already be one (race condition): no need to create one.
	 * There may already be a %trap: replace it.  There may not be
	 * any broad eroute: add %hold.  Once the broad %hold is in
	 * place, delete the narrow one.
	 *
	 * XXX: what race condition?
	 *
	 * XXX: why is OE special (other than that's the way the code
	 * worked in the past)?
	 */
	if (oe || old_routing != new_routing) {
		assign_holdpass(c, spd, op, logger, reason);
		dbg("kernel: %s() done", __func__);
	}

	set_child_routing(c, new_routing);
	dbg("kernel: %s() done - returning success", __func__);
}

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
