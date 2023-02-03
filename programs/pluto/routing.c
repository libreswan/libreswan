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
#include "kernel_policy.h"
#include "revival.h"
#include "ikev2_ike_sa_init.h"		/* for initiate_v2_IKE_SA_INIT_request() */
#include "pluto_stats.h"

void set_child_routing_where(struct connection *c, enum routing routing, where_t where)
{
	enum_buf ob, nb;
	ldbg(c->logger, "kernel: routing connection %s->%s "PRI_WHERE,
	     str_enum(&routing_story, c->child.routing, &ob),
	     str_enum(&routing_story, routing, &nb),
	     pri_where(where));
	c->child.routing = routing;
}

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

static bool should_retry(struct ike_sa *ike)
{
	struct connection *c = ike->sa.st_connection;
	unsigned try_limit = c->sa_keying_tries;
	unsigned tries_so_far = ike->sa.st_try;

	if (try_limit == 0) {
		ldbg_sa(ike, "retying ad infinitum");
		return true;
	}

	if (tries_so_far < try_limit) {
		ldbg_sa(ike, "retrying; only tried %d out of %u", tries_so_far, try_limit);
		return true;
	}

	return false;
}

/*
 * Re-try establishing the IKE SAs (previous attempt failed).
 *
 * This is called when the IKE_SA_INIT and/or IKE_AUTH exchange fails.
 * This is different to having an IKE_SA establish but then have a
 * later exchange fail.
 */

static void retry(struct ike_sa *ike)
{
	struct connection *c = ike->sa.st_connection;
	unsigned long try_limit = c->sa_keying_tries;
	unsigned long try = ike->sa.st_try + 1; /* +1 as this try */

	/*
	 * A lot like EVENT_SA_REPLACE, but over again.  Since we know
	 * that st cannot be in use, we can delete it right away.
	 */
	char story[80]; /* arbitrary limit */

	snprintf(story, sizeof(story), try_limit == 0 ?
		 "starting keying attempt %ld of an unlimited number" :
		 "starting keying attempt %ld of at most %ld",
		 try, try_limit);

	if (fd_p(ike->sa.st_logger->object_whackfd)) {
		/*
		 * Release whack because the observer will get bored.
		 */
		llog_sa(RC_COMMENT, ike,
			"%s, but releasing whack",
			story);
		release_pending_whacks(&ike->sa, story);
	} else if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
		/* no whack: just log to syslog */
		llog_sa(RC_LOG, ike, "%s", story);
	}

	/*
	 * Start billing for the new new state.  The old state also
	 * gets billed for this function call, oops.
	 *
	 * Start from policy in connection
	 */

	lset_t policy = c->policy & ~POLICY_IPSEC_MASK;
	threadtime_t inception = threadtime_start();
	initiate_v2_IKE_SA_INIT_request(c, &ike->sa, policy, try, &inception,
					HUNK_AS_SHUNK(c->child.sec_label),
					/*background?*/false, ike->sa.st_logger);
}

static void fail(struct ike_sa *ike)
{
	pstat_sa_failed(&ike->sa, REASON_TOO_MANY_RETRANSMITS);
}

static void connection_timeout_revive(struct ike_sa *ike, enum routing new_routing)
{
	struct logger *logger = ike->sa.st_logger;
	struct connection *c = ike->sa.st_connection;

	ldbg(logger, "maximum number of establish retries reached - abandoning");
	if (should_revive(&ike->sa)) {
		schedule_revival(&ike->sa);
		return;
	}

	if (c->child.routing != new_routing) {
		if (c->policy & POLICY_OPPORTUNISTIC) {
			/*
			 * A failed OE initiator, make shunt bare.
			 *
			 * Checking .kind above seems pretty dodgy.
			 * Suspect it is trying to capture the initial
			 * IKE exchange when the child hasn't yet been
			 * created, except that when kind is
			 * STATE_V2_PARENT_I2 the larval Child SA has
			 * been created?!?
			 */
			orphan_holdpass(c, c->spd, logger);
			/*
			 * Change routing so we don't get cleared out
			 * when state/connection dies.
			 */
			set_child_routing(c, new_routing);
		}
	}
	/* can't send delete as message window is full */
	fail(ike);
}

void connection_timeout(struct ike_sa *ike)
{
	/*
	 * Part 1: handle the easy cases where the connection didn't
	 * establish and things should retry/revive with kernel
	 * policy/state unchanged.
	 */

	struct connection *c = ike->sa.st_connection;
	const enum routing cr = c->child.routing;
	switch (cr) {

	case RT_UNROUTED:
		/* for instance, permanent+up */
		if (should_retry(ike)) {
			retry(ike);
			return;
		}
		connection_timeout_revive(ike, RT_UNROUTED);
		return;

	case RT_UNROUTED_NEGOTIATION:
		/* for instance, permenant ondemand */
		if (should_retry(ike)) {
			retry(ike);
			return;
		}
		connection_timeout_revive(ike, RT_UNROUTED);
		return;

	case RT_ROUTED_NEGOTIATION:
		if (should_retry(ike)) {
			retry(ike);
			return;
		}
		connection_timeout_revive(ike, RT_ROUTED_PROSPECTIVE/*lie*/);
		return;

	case RT_ROUTED_TUNNEL:
		/* don't retry as well */
		connection_timeout_revive(ike, RT_ROUTED_NEGOTIATION/*lie*/);
		return;

	case RT_ROUTED_PROSPECTIVE:
	case RT_ROUTED_FAILURE:
	case RT_UNROUTED_TUNNEL:
		llog_pexpect(ike->sa.st_logger, HERE, "connection in %s not expecting %s",
			     enum_name_short(&routing_names, cr),
			     __func__);
		/* can't send delete as message window is full */
		fail(ike);
		return;

	}

	bad_case(cr);
}

/*
 * Delete any kernal policies for a connection and unroute it if route
 * isn't shared.
 */

void connection_down(struct connection *c)
{
	enum routing cr = c->child.routing;
	switch (cr) {
	case RT_UNROUTED:
		break;
	case RT_UNROUTED_NEGOTIATION:
	case RT_ROUTED_PROSPECTIVE:
	case RT_ROUTED_NEGOTIATION:
	case RT_ROUTED_FAILURE:
	case RT_ROUTED_TUNNEL:
	case RT_UNROUTED_TUNNEL:
		FOR_EACH_ITEM(spd, &c->child.spds) {
			/* cannot handle a live one */
			passert(cr != RT_ROUTED_TUNNEL);
			/*
			 * XXX: note the hack where missing inbound
			 * policies are ignored.  The connection
			 * should know if there's an inbound policy,
			 * in fact the connection shouldn't even have
			 * inbound policies, just the state.
			 *
			 * For sec_label, it's tearing down the route,
			 * hence that is included.
			 */
			delete_spd_kernel_policy(spd, DIRECTION_OUTBOUND,
						 EXPECT_KERNEL_POLICY_OK,
						 c->logger, HERE,
						 "unrouting connection");
			delete_spd_kernel_policy(spd, DIRECTION_INBOUND,
						 EXPECT_NO_INBOUND,
						 c->logger, HERE,
						 "unrouting connection");
#ifdef IPSEC_CONNECTION_LIMIT
			num_ipsec_eroute--;
#endif
		}
		break;
	}

	/* do now so route_owner won't find us */
	set_child_routing(c, RT_UNROUTED);

	switch (cr) {
	case RT_UNROUTED:
	case RT_UNROUTED_NEGOTIATION:
	case RT_UNROUTED_TUNNEL:
		break;
	case RT_ROUTED_PROSPECTIVE:
	case RT_ROUTED_NEGOTIATION:
	case RT_ROUTED_FAILURE:
	case RT_ROUTED_TUNNEL:
		FOR_EACH_ITEM(spd, &c->child.spds) {
			/* only unroute if no other connection shares it */
			if (route_owner(spd) == NULL) {
				do_updown(UPDOWN_UNROUTE, c, spd, NULL, c->logger);
			}
		}
		break;
	}
}

/*
 * "down" / "unroute" the connection but _don't_ delete the kernel
 * state / policy.
 *
 * Presumably the kernel policy (at least) is acting like a trap while
 * mibike migrates things?
 */

void connection_resume(struct child_sa *child)
{
	struct connection *c = child->sa.st_connection;
	/* do now so route_owner won't find us */
	enum routing cr = c->child.routing;
	switch (cr) {
	case RT_UNROUTED_TUNNEL:
		set_child_routing(c, RT_ROUTED_TUNNEL);
		FOR_EACH_ITEM(spd, &c->child.spds) {
			do_updown(UPDOWN_UP, c, spd, &child->sa, child->sa.st_logger);
			do_updown(UPDOWN_ROUTE, c, spd, &child->sa, child->sa.st_logger);
		}
		break;
	case RT_UNROUTED:
	case RT_UNROUTED_NEGOTIATION:
	case RT_ROUTED_NEGOTIATION:
	case RT_ROUTED_FAILURE:
	case RT_ROUTED_TUNNEL:
	case RT_ROUTED_PROSPECTIVE:
		llog_pexpect(child->sa.st_logger, HERE,
			     "%s() unexpected routing %s",
			     __func__, enum_name_short(&routing_names, cr));
		set_child_routing(c, RT_ROUTED_TUNNEL);
		break;
	}
}

void connection_suspend(struct child_sa *child)
{
	struct connection *c = child->sa.st_connection;
	/*
	 * XXX: this an expansion of routed(); most of these
	 * transitions are probably invalid!
	 */
	enum routing cr = c->child.routing;
	PEXPECT(c->logger, cr == RT_ROUTED_TUNNEL);
	switch (cr) {
	case RT_ROUTED_TUNNEL:
		/*
		 * Update connection's routing so that route_owner()
		 * won't find us.
		 *
		 * Only unroute when no other routed connection shares
		 * the SPD.
		 */
		FOR_EACH_ITEM(spd, &c->child.spds) {
			/* XXX: never finds SPD */
			if (route_owner(spd) == NULL) {
				do_updown(UPDOWN_DOWN, c, spd, &child->sa, child->sa.st_logger);
				child->sa.st_mobike_del_src_ip = true;
				do_updown(UPDOWN_UNROUTE, c, spd, &child->sa, child->sa.st_logger);
				child->sa.st_mobike_del_src_ip = false;
			}
		}
		set_child_routing(c, RT_UNROUTED_TUNNEL);
		break;
	case RT_ROUTED_PROSPECTIVE:
	case RT_ROUTED_NEGOTIATION:
	case RT_ROUTED_FAILURE:
		llog_pexpect(child->sa.st_logger, HERE,
			     "%s() unexpected routing %s",
			     __func__, enum_name_short(&routing_names, cr));
		FOR_EACH_ITEM(spd, &c->child.spds) {
			/* XXX: never finds SPD */
			if (route_owner(spd) == NULL) {
				do_updown(UPDOWN_DOWN, c, spd, &child->sa, child->sa.st_logger);
				child->sa.st_mobike_del_src_ip = true;
				do_updown(UPDOWN_UNROUTE, c, spd, &child->sa, child->sa.st_logger);
				child->sa.st_mobike_del_src_ip = false;
			}
		}
		set_child_routing(c, RT_UNROUTED_TUNNEL);
		break;
	case RT_UNROUTED:
	case RT_UNROUTED_NEGOTIATION:
	case RT_UNROUTED_TUNNEL:
		llog_pexpect(child->sa.st_logger, HERE,
			     "%s() unexpected routing %s",
			     __func__, enum_name_short(&routing_names, cr));
		set_child_routing(c, RT_UNROUTED_TUNNEL);
		break;
	}
}
