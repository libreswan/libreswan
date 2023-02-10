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
#include "foodgroups.h"			/* for connection_group_{route,unroute}() */
#include "orient.h"

enum connection_event {
	CONNECTION_ROUTE,
	CONNECTION_UNROUTE,
	CONNECTION_TIMEOUT,
};

static const char *connection_event_name[] = {
#define S(E) [E] = #E
	S(CONNECTION_ROUTE),
	S(CONNECTION_UNROUTE),
	S(CONNECTION_TIMEOUT),
#undef S
};

static enum_names connection_event_names = {
	0, CONNECTION_TIMEOUT,
	ARRAY_REF(connection_event_name),
	"CONNECTION_",
	NULL,
};

static void do_updown_unroute(struct connection *c);

static void dispatch(struct connection *c, enum connection_event event, struct ike_sa *ike);

static void permanent_event_handler(struct connection *c, enum connection_event event, struct ike_sa *ike);
static void template_event_handler(struct connection *c, enum connection_event event, struct ike_sa *ike);
static void instance_event_handler(struct connection *c, enum connection_event event, struct ike_sa *ike);

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

void connection_timeout(struct ike_sa *ike)
{
	struct connection *c = ike->sa.st_connection;
	dispatch(c, CONNECTION_TIMEOUT, ike);
}

void connection_route(struct connection *c)
{
	if (!oriented(c)) {
		llog(RC_ORIENT, c->logger,
		     "we cannot identify ourselves with either end of this connection");
		return;
	}

	if (c->kind == CK_GROUP) {
		connection_group_route(c);
		return;
	}

	dispatch(c, CONNECTION_ROUTE, NULL/*IKE*/);
}

void dispatch(struct connection *c, enum connection_event event, struct ike_sa *ike)
{
	LDBGP_JAMBUF(DBG_BASE, c->logger, buf) {
		jam(buf, "dispatch %s event %s",
		    enum_name_short(&connection_kind_names, c->kind),
		    enum_name_short(&connection_event_names, event));
		if (ike != NULL) {
			jam(buf, " for "PRI_SO, pri_so(ike->sa.st_serialno));
		}
	}
	switch (c->kind) {
	case CK_PERMANENT:
		permanent_event_handler(c, event, ike);
		break;
	case CK_TEMPLATE:
		template_event_handler(c, event, ike);
		break;
	case CK_INSTANCE:
		instance_event_handler(c, event, ike);
		break;
	default:
		bad_case(c->kind);
	}
}

void permanent_event_handler(struct connection *c, enum connection_event event, struct ike_sa *ike)
{
	/*
	 * Part 1: handle the easy cases where the connection didn't
	 * establish and things should retry/revive with kernel
	 * policy/state unchanged.
	 */

	const enum routing cr = c->child.routing;
	switch (cr) {

	case RT_UNROUTED:
		switch (event) {
		case CONNECTION_ROUTE:
			if (!install_prospective_kernel_policy(c)) {
				/* XXX: why whack only? */
				llog(WHACK_STREAM|RC_ROUTE, c->logger, "could not route");
			}
			return;
		case CONNECTION_UNROUTE:
			ldbg(c->logger, "already unrouted");
			return;
		case CONNECTION_TIMEOUT:
			/* for instance, permanent+up */
			if (should_retry(ike)) {
				retry(ike);
				return;
			}
			if (should_revive(&ike->sa)) {
				schedule_revival(&ike->sa);
				return;
			}
			fail(ike);
			return;
		}
		bad_case(event);

	case RT_UNROUTED_NEGOTIATION:
		switch (event) {
		case CONNECTION_ROUTE:
			llog(RC_LOG_SERIOUS, c->logger, "cannot route negotiating connection");
			return;
		case CONNECTION_UNROUTE:
			delete_connection_kernel_policies(c);
			set_child_routing(c, RT_UNROUTED);
			return;
		case CONNECTION_TIMEOUT:
			/* for instance, permenant ondemand */
			if (should_retry(ike)) {
				retry(ike);
				return;
			}
			if (should_revive(&ike->sa)) {
				schedule_revival(&ike->sa);
				return;
			}
			if (c->policy & POLICY_OPPORTUNISTIC) {
				/*
				 * A failed OE initiator, make shunt bare.
				 */
				orphan_holdpass(c, c->spd, c->logger);
				/*
				 * Change routing so we don't get cleared out
				 * when state/connection dies.
				 */
				set_child_routing(c, RT_UNROUTED);
			}
			fail(ike);
			return;
		}
		bad_case(event);

	case RT_ROUTED_NEGOTIATION:
		switch (event) {
		case CONNECTION_ROUTE:
			llog(RC_LOG_SERIOUS, c->logger, "connection already routed");
			return;
		case CONNECTION_UNROUTE:
			delete_connection_kernel_policies(c);
			/* do now so route_owner won't find us */
			set_child_routing(c, RT_UNROUTED);
			do_updown_unroute(c);
			return;
		case CONNECTION_TIMEOUT:
			if (should_retry(ike)) {
				retry(ike);
				return;
			}
			if (should_revive(&ike->sa)) {
				schedule_revival(&ike->sa);
				return;
			}
			if (c->policy & POLICY_OPPORTUNISTIC) {
				/*
				 * A failed OE initiator, make shunt bare.
				 */
				orphan_holdpass(c, c->spd, c->logger);
				/*
				 * Change routing so we don't get cleared out
				 * when state/connection dies.
				 */
				set_child_routing(c, RT_ROUTED_PROSPECTIVE/*lie?!?*/);
			}
			fail(ike);
			return;
		}
		bad_case(event);

	case RT_ROUTED_TUNNEL:
		switch (event) {
		case CONNECTION_ROUTE:
			llog(RC_LOG_SERIOUS, c->logger, "cannot route established connection");
			return;
		case CONNECTION_UNROUTE:
			llog(RC_RTBUSY, c->logger, "cannot unroute: route busy");
			return;
		case CONNECTION_TIMEOUT:
			/* don't retry as well */
			if (should_revive(&ike->sa)) {
				schedule_revival(&ike->sa);
				return;
			}
			if (c->policy & POLICY_OPPORTUNISTIC) {
				/*
				 * A failed OE initiator, make shunt bare.
				 */
				orphan_holdpass(c, c->spd, c->logger);
				/*
				 * Change routing so we don't get cleared out
				 * when state/connection dies.
				 */
				set_child_routing(c, RT_ROUTED_NEGOTIATION/*lie?!?*/);
			}
			fail(ike);
			return;
		}
		bad_case(event);

	case RT_ROUTED_PROSPECTIVE:
		switch (event) {
		case CONNECTION_ROUTE:
			break; /*barf*/
		case CONNECTION_UNROUTE:
			delete_connection_kernel_policies(c);
			set_child_routing(c, RT_UNROUTED);
			do_updown_unroute(c);
			return;
		case CONNECTION_TIMEOUT:
			break; /*barf*/
		}
		bad_case(event);

	case RT_ROUTED_FAILURE:
		switch (event) {
		case CONNECTION_ROUTE:
			break; /*barf*/
		case CONNECTION_UNROUTE:
			delete_connection_kernel_policies(c);
			/* do now so route_owner won't find us */
			set_child_routing(c, RT_UNROUTED);
			do_updown_unroute(c);
			return;
		case CONNECTION_TIMEOUT:
			break; /*barf*/
		}
		bad_case(event);

	case RT_UNROUTED_TUNNEL:
		switch (event) {
		case CONNECTION_ROUTE:
			break; /*barf*/
		case CONNECTION_UNROUTE:
			delete_connection_kernel_policies(c);
			set_child_routing(c, RT_UNROUTED);
			return;
		case CONNECTION_TIMEOUT:
			break; /*barf*/
		}
		bad_case(event);

	}

	bad_case(cr);
}

void template_event_handler(struct connection *c, enum connection_event event, struct ike_sa *ike)
{
	/*
	 * Part 1: handle the easy cases where the connection didn't
	 * establish and things should retry/revive with kernel
	 * policy/state unchanged.
	 */

	const enum routing cr = c->child.routing;
	switch (cr) {

	case RT_UNROUTED:
		switch (event) {
		case CONNECTION_ROUTE:
			if (!install_prospective_kernel_policy(c)) {
				/* XXX: why whack only? */
				llog(WHACK_STREAM|RC_ROUTE, c->logger, "could not route");
			}
			return;
		case CONNECTION_UNROUTE:
			ldbg(c->logger, "already unrouted");
			return;
		case CONNECTION_TIMEOUT:
			/* for instance, permanent+up */
			if (should_retry(ike)) {
				retry(ike);
				return;
			}
			if (should_revive(&ike->sa)) {
				schedule_revival(&ike->sa);
				return;
			}
			fail(ike);
			return;
		}
		bad_case(event);

	case RT_UNROUTED_NEGOTIATION:
		switch (event) {
		case CONNECTION_ROUTE:
			llog(RC_LOG_SERIOUS, c->logger, "cannot route negotiating connection");
			return;
		case CONNECTION_UNROUTE:
			delete_connection_kernel_policies(c);
			set_child_routing(c, RT_UNROUTED);
			return;
		case CONNECTION_TIMEOUT:
			/* for instance, permenant ondemand */
			if (should_retry(ike)) {
				retry(ike);
				return;
			}
			if (should_revive(&ike->sa)) {
				schedule_revival(&ike->sa);
				return;
			}
			if (c->policy & POLICY_OPPORTUNISTIC) {
				/*
				 * A failed OE initiator, make shunt bare.
				 */
				orphan_holdpass(c, c->spd, c->logger);
				/*
				 * Change routing so we don't get cleared out
				 * when state/connection dies.
				 */
				set_child_routing(c, RT_UNROUTED);
			}
			fail(ike);
			return;
		}
		bad_case(event);

	case RT_ROUTED_NEGOTIATION:
		switch (event) {
		case CONNECTION_ROUTE:
			llog(RC_LOG_SERIOUS, c->logger, "cannot route established connection");
			return;
		case CONNECTION_UNROUTE:
			delete_connection_kernel_policies(c);
			/* do now so route_owner won't find us */
			set_child_routing(c, RT_UNROUTED);
			do_updown_unroute(c);
			return;
		case CONNECTION_TIMEOUT:
			if (should_retry(ike)) {
				retry(ike);
				return;
			}
			if (should_revive(&ike->sa)) {
				schedule_revival(&ike->sa);
				return;
			}
			if (c->policy & POLICY_OPPORTUNISTIC) {
				/*
				 * A failed OE initiator, make shunt bare.
				 */
				orphan_holdpass(c, c->spd, c->logger);
				/*
				 * Change routing so we don't get cleared out
				 * when state/connection dies.
				 */
				set_child_routing(c, RT_ROUTED_PROSPECTIVE/*lie?!?*/);
			}
			fail(ike);
			return;
		}
		bad_case(event);

	case RT_ROUTED_TUNNEL:
		switch (event) {
		case CONNECTION_ROUTE:
			llog(RC_LOG_SERIOUS, c->logger, "cannot route established connection");
			return;
		case CONNECTION_UNROUTE:
			llog(RC_RTBUSY, c->logger, "cannot unroute: route busy");
			return;
		case CONNECTION_TIMEOUT:
			/* don't retry as well */
			if (should_revive(&ike->sa)) {
				schedule_revival(&ike->sa);
				return;
			}
			if (c->policy & POLICY_OPPORTUNISTIC) {
				/*
				 * A failed OE initiator, make shunt bare.
				 */
				orphan_holdpass(c, c->spd, c->logger);
				/*
				 * Change routing so we don't get cleared out
				 * when state/connection dies.
				 */
				set_child_routing(c, RT_ROUTED_NEGOTIATION/*lie?!?*/);
			}
			fail(ike);
			return;
		}
		bad_case(event);

	case RT_ROUTED_PROSPECTIVE:
		switch (event) {
		case CONNECTION_ROUTE:
			break; /*barf*/
		case CONNECTION_UNROUTE:
			delete_connection_kernel_policies(c);
			/* do now so route_owner won't find us */
			set_child_routing(c, RT_UNROUTED);
			do_updown_unroute(c);
			return;
		case CONNECTION_TIMEOUT:
			break; /*barf*/
		}
		bad_case(event);

	case RT_ROUTED_FAILURE:
		switch (event) {
		case CONNECTION_ROUTE:
			break; /*barf*/
		case CONNECTION_UNROUTE:
			delete_connection_kernel_policies(c);
			/* do now so route_owner won't find us */
			set_child_routing(c, RT_UNROUTED);
			do_updown_unroute(c);
			return;
		case CONNECTION_TIMEOUT:
			break; /*barf*/
		}
		bad_case(event);

	case RT_UNROUTED_TUNNEL:
		switch (event) {
		case CONNECTION_ROUTE:
			break; /*barf*/
		case CONNECTION_UNROUTE:
			delete_connection_kernel_policies(c);
			/* do now so route_owner won't find us */
			set_child_routing(c, RT_UNROUTED);
			return;
		case CONNECTION_TIMEOUT:
			break; /*barf*/
		}
		bad_case(event);

	}

	bad_case(cr);
}

void instance_event_handler(struct connection *c, enum connection_event event, struct ike_sa *ike)
{
	/*
	 * Part 1: handle the easy cases where the connection didn't
	 * establish and things should retry/revive with kernel
	 * policy/state unchanged.
	 */

	const enum routing cr = c->child.routing;
	switch (cr) {

	case RT_UNROUTED:
		switch (event) {
		case CONNECTION_ROUTE:
			llog(RC_LOG_SERIOUS, c->logger, "cannot route connection instance");
			return;
		case CONNECTION_UNROUTE:
			ldbg(c->logger, "already unrouted");
			return;
		case CONNECTION_TIMEOUT:
			/* for instance, permanent+up */
			if (should_retry(ike)) {
				retry(ike);
				return;
			}
			if (should_revive(&ike->sa)) {
				schedule_revival(&ike->sa);
				return;
			}
			fail(ike);
			return;
		}
		bad_case(event);

	case RT_UNROUTED_NEGOTIATION:
		switch (event) {
		case CONNECTION_ROUTE:
			llog(RC_LOG_SERIOUS, c->logger, "cannot route connection instance");
			return;
		case CONNECTION_UNROUTE:
			delete_connection_kernel_policies(c);
			/* do now so route_owner won't find us */
			set_child_routing(c, RT_UNROUTED);
			return;
		case CONNECTION_TIMEOUT:
			/* for instance, permenant ondemand */
			if (should_retry(ike)) {
				retry(ike);
				return;
			}
			if (should_revive(&ike->sa)) {
				schedule_revival(&ike->sa);
				return;
			}
			if (c->policy & POLICY_OPPORTUNISTIC) {
				/*
				 * A failed OE initiator, make shunt bare.
				 */
				orphan_holdpass(c, c->spd, c->logger);
				/*
				 * Change routing so we don't get cleared out
				 * when state/connection dies.
				 */
				set_child_routing(c, RT_UNROUTED);
			}
			fail(ike);
			return;
		}
		bad_case(event);

	case RT_ROUTED_NEGOTIATION:
		switch (event) {
		case CONNECTION_ROUTE:
			llog(RC_LOG_SERIOUS, c->logger, "cannot route connection instance");
			return;
		case CONNECTION_UNROUTE:
			delete_connection_kernel_policies(c);
			do_updown_unroute(c);
			break;
		case CONNECTION_TIMEOUT:
			if (should_retry(ike)) {
				retry(ike);
				return;
			}
			if (should_revive(&ike->sa)) {
				schedule_revival(&ike->sa);
				return;
			}
			if (c->policy & POLICY_OPPORTUNISTIC) {
				/*
				 * A failed OE initiator, make shunt bare.
				 */
				orphan_holdpass(c, c->spd, c->logger);
				/*
				 * Change routing so we don't get cleared out
				 * when state/connection dies.
				 */
				set_child_routing(c, RT_ROUTED_PROSPECTIVE/*lie?!?*/);
			}
			fail(ike);
			return;
		}
		bad_case(event);

	case RT_ROUTED_TUNNEL:
		switch (event) {
		case CONNECTION_ROUTE:
			llog(RC_LOG_SERIOUS, c->logger, "cannot route connection instance");
			return;
		case CONNECTION_UNROUTE:
			llog(RC_RTBUSY, c->logger, "cannot unroute: route busy");
			return;
		case CONNECTION_TIMEOUT:
			/* don't retry as well */
			if (should_revive(&ike->sa)) {
				schedule_revival(&ike->sa);
				return;
			}
			if (c->policy & POLICY_OPPORTUNISTIC) {
				/*
				 * A failed OE initiator, make shunt bare.
				 */
				orphan_holdpass(c, c->spd, c->logger);
				/*
				 * Change routing so we don't get cleared out
				 * when state/connection dies.
				 */
				set_child_routing(c, RT_ROUTED_NEGOTIATION/*lie?!?*/);
			}
			fail(ike);
			return;
		}
		bad_case(event);

	case RT_ROUTED_PROSPECTIVE:
		switch (event) {
		case CONNECTION_ROUTE:
			break; /*barf*/
		case CONNECTION_UNROUTE:
			delete_connection_kernel_policies(c);
			/* do now so route_owner won't find us */
			set_child_routing(c, RT_UNROUTED);
			do_updown_unroute(c);
			return;
		case CONNECTION_TIMEOUT:
			break; /*barf*/
		}
		bad_case(event);

	case RT_ROUTED_FAILURE:
		switch (event) {
		case CONNECTION_ROUTE:
			break; /*barf*/
		case CONNECTION_UNROUTE:
			delete_connection_kernel_policies(c);
			/* do now so route_owner won't find us */
			set_child_routing(c, RT_UNROUTED);
			do_updown_unroute(c);
			return;
		case CONNECTION_TIMEOUT:
			break; /*barf*/
		}
		bad_case(event);

	case RT_UNROUTED_TUNNEL:
		switch (event) {
		case CONNECTION_ROUTE:
			break; /*barf*/
		case CONNECTION_UNROUTE:
			delete_connection_kernel_policies(c);
			set_child_routing(c, RT_UNROUTED);
			return;
		case CONNECTION_TIMEOUT:
			break; /*barf*/
		}
		bad_case(event);

	}

	bad_case(cr);
}

/*
 * Delete any kernal policies for a connection and unroute it if route
 * isn't shared.
 */

static void do_updown_unroute(struct connection *c)
{
	FOR_EACH_ITEM(spd, &c->child.spds) {
		/* only unroute if no other connection shares it */
		if (route_owner(spd) == NULL) {
			do_updown(UPDOWN_UNROUTE, c, spd, NULL, c->logger);
		}
	}
}

void connection_unroute(struct connection *c)
{
	if (c->kind == CK_GROUP) {
		/* XXX: may recurse back to here with group
		 * instances. */
		connection_group_unroute(c);
		return;
	}

	dispatch(c, CONNECTION_UNROUTE, NULL/*IKE*/);
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
