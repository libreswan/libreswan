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
#include "initiate.h"			/* for ipsecdoi_initiate() */
#include "updown.h"
#include "instantiate.h"
#include "connection_event.h"

static const char *routing_event_name[] = {
#define S(E) [E] = #E
	S(CONNECTION_ROUTE),
	S(CONNECTION_UNROUTE),
	S(CONNECTION_INITIATE),
	S(CONNECTION_ACQUIRE),
	S(CONNECTION_ESTABLISH_IKE),
	S(CONNECTION_ESTABLISH_INBOUND),
	S(CONNECTION_ESTABLISH_OUTBOUND),
	S(CONNECTION_DELETE_IKE),
	S(CONNECTION_DELETE_CHILD),
	S(CONNECTION_TIMEOUT_IKE),
	S(CONNECTION_TIMEOUT_CHILD),
	S(CONNECTION_SUSPEND),
	S(CONNECTION_RESUME),
#undef S
};

static enum_names routing_event_names = {
	0, ROUTING_EVENT_ROOF-1,
	ARRAY_REF(routing_event_name),
	"CONNECTION_",
	NULL,
};

static void dispatch(const enum routing_event event,
		     struct connection **cp,
		     struct logger *logger, where_t where,
		     struct routing_annex e);

static void jam_sa_update(struct jambuf *buf, const char *sa_name,
			  so_serial_t sa_so, struct state *st)
{
	if (sa_name != NULL) {
		jam_string(buf, " ");
		jam_string(buf, sa_name);
		jam_so(buf, sa_so);
		if (st == NULL) {
			jam_string(buf, "(deleted)");
		} else {
			jam_string(buf, "(");
			jam_string(buf, st->st_state->short_name);
			jam_string(buf, ")");
		}
	}
}

static void jam_event_sa(struct jambuf *buf, struct state *st)
{
	jam_sa_update(buf, state_sa_short_name(st), st->st_serialno, st);
}

static void jam_so_update(struct jambuf *buf, const char *what,
			  so_serial_t old, so_serial_t new,
			  const char **prefix)
{
	if (old != SOS_NOBODY || new != SOS_NOBODY) {
		jam_string(buf, (*prefix)); (*prefix) = "";
		jam_string(buf, " ");
		jam_string(buf, what);
		jam_so(buf, old);
		if (old != new) {
			jam_string(buf, "->");
			jam_so(buf, new);
		}
	}
}

static void jam_routing_update(struct jambuf *buf, enum routing old, enum routing new)
{
	jam_enum_short(buf, &routing_names, old);
	if (old != new) {
		jam_string(buf, "->");
		jam_enum_short(buf, &routing_names, new);
	}
}

static void jam_routing(struct jambuf *buf,
			struct connection *c)
{
	if (c == NULL) {
		jam_string(buf, "EXPECTATION FAILED: C is NULL");
		return;
	}
	jam_enum_short(buf, &routing_names, c->child.routing);
	jam_string(buf, " ");
	jam_enum_short(buf, &connection_kind_names, c->local->kind);
	jam_string(buf, " ");
	jam_connection_co(buf, c);
	jam(buf, "@%p", c);
	if (never_negotiate(c)) {
		jam_string(buf, "; never-negotiate");
	}
	/* no actual update */
	const char *newest = "; newest";
	jam_so_update(buf, "routing", c->newest_routing_sa, c->newest_routing_sa, &newest);
	jam_so_update(buf, c->config->ike_info->child_name, c->newest_ipsec_sa, c->newest_ipsec_sa, &newest);
	jam_so_update(buf, c->config->ike_info->parent_name, c->newest_ike_sa, c->newest_ike_sa, &newest);
}

void jam_routing_annex(struct jambuf *buf, const struct routing_annex *e)
{
	if (e->ike != NULL && (*e->ike) != NULL) {
		jam_event_sa(buf, &(*e->ike)->sa);
	}
	if (e->child != NULL && (*e->child) != NULL) {
		jam_event_sa(buf, &(*e->child)->sa);
	}
	if (e->sec_label.len > 0) {
		jam_string(buf, ", sec_label=");
		jam_shunk(buf, e->sec_label);
	}
}

static void jam_event(struct jambuf *buf,
		      enum routing_event event,
		      struct connection *c,
		      const struct routing_annex *e)
{
	jam_enum_short(buf, &routing_event_names, event);
	jam_routing_annex(buf, e);
	jam_string(buf, " to ");
	jam_routing(buf, c);
}

static void ldbg_routing_skip(struct connection *c,
			       enum routing_event event,
			       where_t where,
			       const struct routing_annex *e)
{
	if (DBGP(DBG_BASE)) {
		/*
		 * XXX: force ADD_PREFIX so that the connection name
		 * is before the interesting stuff.
		 */
		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, c->logger, buf) {
			jam_string(buf, "routing: skip ");
			jam_event(buf, event, c, e);
			jam_string(buf, " ");
			jam_where(buf, where);
		}
	}
}

struct old_routing {
	/* capture what can change */
	const char *ike_name;
	so_serial_t ike_so;
	const char *child_name;
	so_serial_t child_so;
	so_serial_t routing_sa;
	so_serial_t ipsec_sa;
	so_serial_t ike_sa;
	enum routing routing;
};

static struct old_routing ldbg_routing_start(struct connection *c,
					     enum routing_event event,
					     where_t where,
					     struct routing_annex *e)
{
	struct old_routing old = {
		/* capture what can change */
		.ike_name = (e->ike == NULL || (*e->ike) == NULL ? SOS_NOBODY :
			     state_sa_short_name(&(*e->ike)->sa)),
		.ike_so = (e->ike == NULL || (*e->ike) == NULL ? SOS_NOBODY :
			   (*e->ike)->sa.st_serialno),
		.child_name = (e->child == NULL || (*e->child) == NULL ? SOS_NOBODY :
			       state_sa_short_name(&(*e->child)->sa)),
		.child_so = (e->child == NULL || (*e->child) == NULL ? SOS_NOBODY :
			     (*e->child)->sa.st_serialno),
		.ipsec_sa = c->newest_ipsec_sa,
		.routing_sa = c->newest_routing_sa,
		.ike_sa = c->newest_ike_sa,
		.routing = c->child.routing,
	};
	if (DBGP(DBG_BASE)) {
		/*
		 * XXX: force ADD_PREFIX so that the connection name
		 * is before the interesting stuff.
		 */
		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, c->logger, buf) {
			jam_string(buf, "routing: start ");
			jam_event(buf, event, c, e);
			jam_string(buf, " ");
			jam_where(buf, where);
		}
	}
	return old;
}

static void ldbg_routing_stop(struct connection *c,
			      enum routing_event event,
			      where_t where,
			      const struct routing_annex *e,
			      const struct old_routing *old)
{
	if (DBGP(DBG_BASE)) {
		/*
		 * XXX: force ADD_PREFIX so that the connection name
		 * is before the interesting stuff.
		 */
		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, c->logger, buf) {
			jam_string(buf, "routing: stop dispatch ");
			jam_enum_short(buf, &routing_event_names, event);
			jam_sa_update(buf, old->ike_name, old->ike_so,
				      (e->ike == NULL || (*e->ike) == NULL ? NULL : &(*e->ike)->sa));
			jam_sa_update(buf, old->child_name, old->child_so,
				      (e->child == NULL || (*e->child) == NULL ? NULL : &(*e->child)->sa));
			jam_string(buf, "; ");
			/* routing */
			jam_routing_update(buf, old->routing, c->child.routing);
			/* various SAs */
			const char *newest = "; newest";
			jam_so_update(buf, "routing",
				      old->routing_sa, c->newest_routing_sa, &newest);
			jam_so_update(buf, c->config->ike_info->child_name,
				      old->ipsec_sa, c->newest_ipsec_sa, &newest);
			jam_so_update(buf, c->config->ike_info->parent_name,
				      old->ike_sa, c->newest_ike_sa, &newest);
			jam_string(buf, " ");
			jam_where(buf, where);
		}
	}
}

PRINTF_LIKE(2)
void ldbg_routing(struct logger *logger, const char *fmt, ...)
{
	if (DBGP(DBG_BASE)) {
		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
			jam_string(buf, "routing:   ");
			va_list ap;
			va_start(ap, fmt);
			jam_va_list(buf, fmt, ap);
			va_end(ap);
		}
	}
}

void fake_connection_establish_inbound(struct child_sa *child, where_t where)
{
	struct connection *cc = child->sa.st_connection;
	dispatch(CONNECTION_ESTABLISH_INBOUND, &cc,
		 child->sa.st_logger, where,
		 (struct routing_annex) {
			 .child = &child,
		 });
}

void fake_connection_establish_outbound(struct child_sa *child, where_t where)
{
	struct connection *cc = child->sa.st_connection;
	dispatch(CONNECTION_ESTABLISH_OUTBOUND, &cc,
		 child->sa.st_logger, where,
		 (struct routing_annex) {
			 .child = &child,
		 });
}

enum shunt_kind routing_shunt_kind(enum routing routing)
{
	switch (routing) {
	case RT_ROUTED_ONDEMAND:
		return SHUNT_KIND_ONDEMAND;
	case RT_ROUTED_NEVER_NEGOTIATE:
		return SHUNT_KIND_NEVER_NEGOTIATE;
	case RT_UNROUTED_NEGOTIATION:
	case RT_ROUTED_NEGOTIATION:
		return SHUNT_KIND_NEGOTIATION;
	case RT_UNROUTED_FAILURE:
	case RT_ROUTED_FAILURE:
		return SHUNT_KIND_FAILURE;
	case RT_UNROUTED_INBOUND:
	case RT_ROUTED_INBOUND:
		/*outbound*/
		return SHUNT_KIND_NEGOTIATION;
	case RT_UNROUTED_TUNNEL:
	case RT_ROUTED_TUNNEL:
		return SHUNT_KIND_IPSEC;
	case RT_UNROUTED:
		bad_case(routing);
	}
	bad_case(routing);
}

bool routed(const struct connection *c)
{
	enum routing r = c->child.routing;
	switch (r) {
	case RT_ROUTED_ONDEMAND:
	case RT_ROUTED_NEVER_NEGOTIATE:
	case RT_ROUTED_NEGOTIATION:
	case RT_ROUTED_INBOUND:
	case RT_ROUTED_TUNNEL:
	case RT_ROUTED_FAILURE:
		return true;
	case RT_UNROUTED:
	case RT_UNROUTED_NEGOTIATION:
	case RT_UNROUTED_FAILURE:
	case RT_UNROUTED_INBOUND:
	case RT_UNROUTED_TUNNEL:
		return false;
	}
	bad_case(r);
}

bool kernel_policy_installed(const struct connection *c)
{
	switch (c->child.routing) {
	case RT_UNROUTED:
	case RT_UNROUTED_NEGOTIATION:
		return false;
	case RT_ROUTED_ONDEMAND:
	case RT_ROUTED_NEGOTIATION:
	case RT_UNROUTED_INBOUND:
	case RT_ROUTED_NEVER_NEGOTIATE:
	case RT_ROUTED_INBOUND:
	case RT_ROUTED_TUNNEL:
	case RT_UNROUTED_FAILURE:
	case RT_ROUTED_FAILURE:
	case RT_UNROUTED_TUNNEL:
		return true;
	}
	bad_case(c->child.routing);
}

void set_routing(enum routing_event event,
		 struct connection *c,
		 enum routing new_routing,
		 struct child_sa **child,
		 where_t where)
{
	struct logger *logger = c->logger;
	so_serial_t new_routing_sa = (child == NULL ? SOS_NOBODY :
				      *child == NULL ? SOS_NOBODY :
				      (*child)->sa.st_serialno);
	if (DBGP(DBG_BASE)) {
		/*
		 * XXX: force ADD_PREFIX so that the connection name
		 * is before the interesting stuff.
		 */
		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
			jam_string(buf, "routing: change ");
			jam_enum_short(buf, &routing_event_names, event);
			jam_string(buf, " -> ");
			jam_routing(buf, c);
			jam_string(buf, " -> ");
			jam_enum_short(buf, &routing_names, new_routing);
			jam_string(buf, " ");
			jam_so(buf, new_routing_sa);
			jam_string(buf, " ");
			jam_where(buf, where);
		}
	}

#if 0
	/*
	 * Labed children are never routed and/or have a kernel
	 * policy.  However, they do have a kernel state.  Hence they
	 * get put into states such as UNROUTED_INBOUND, and
	 * UNROUTED_TUNNEL.
	 */
	PEXPECT(logger, !is_labeled_child(c));
#endif

#if 0
	/*
	 * Always going forward; never in reverse.
	 *
	 * Well, except during teardown when the kernel policy is
	 * pulled before kernel state.  Hence, when SO is nobody,
	 * can't assert much about the ipsec_sa.
	 */
	PEXPECT(logger, old_routing_sa >= c->newest_ipsec_sa);
	if (new_routing_sa != SOS_NOBODY) {
		PEXPECT(c->logger, new_routing_sa >= c->newest_routing_sa);
		PEXPECT(c->logger, new_routing_sa >= c->newest_ipsec_sa);
	}
#endif
	c->child.routing = new_routing;
	c->newest_routing_sa = new_routing_sa;
}

static void set_established_child(enum routing_event event UNUSED,
				  struct connection *c,
				  enum routing routing,
				  struct child_sa **child,
				  where_t where UNUSED)
{
	c->child.routing = routing;
	c->newest_ipsec_sa = c->newest_routing_sa =
		(*child)->sa.st_serialno;
}

static bool unrouted_to_routed_ondemand(enum routing_event event, struct connection *c, where_t where)
{
	if (!unrouted_to_routed(c, SHUNT_KIND_ONDEMAND, where)) {
		return false;
	}
	set_routing(event, c, RT_ROUTED_ONDEMAND, NULL, where);
	return true;
}

static bool unrouted_to_routed_never_negotiate(enum routing_event event, struct connection *c, where_t where)
{
	if (!unrouted_to_routed(c, SHUNT_KIND_NEVER_NEGOTIATE, where)) {
		return false;
	}
	set_routing(event, c, RT_ROUTED_NEVER_NEGOTIATE, NULL, where);
	return true;
}

/*
 * For instance:
 *
 * = an instance with a routed ondemand template
 *
 * = an instance with an unrouted template due to whack?
 *
 * If this is an instance, then presumably the instance instantiate
 * code has figured out how wide the SPDs need to be.
 *
 * OTOH, if this is an unrouted permenant triggered by whack, just
 * replace.
 */

static void unrouted_instance_to_unrouted_negotiation(enum routing_event event,
						      struct connection *c, where_t where)
{
	struct logger *logger = c->logger;
#if 0
	/* fails when whack forces the initiate so that the template
	 * is instantiated before it is routed */
	struct connection *t = c->clonedfrom; /* could be NULL */
	PEXPECT(logger, t != NULL && t->child.routing == RT_ROUTED_ONDEMAND);
#endif
	bool oe = is_opportunistic(c);
	const char *reason = (oe ? "replace unrouted opportunistic %trap with broad %pass or %hold" :
			      "replace unrouted %trap with broad %pass or %hold");
	add_spd_kernel_policies(c, KERNEL_POLICY_OP_REPLACE,
				DIRECTION_OUTBOUND,
				SHUNT_KIND_NEGOTIATION,
				logger, where, reason);
	set_routing(event, c, RT_UNROUTED_NEGOTIATION, NULL, where);
}

/*
 * This is permanent yet unrouted; presumably the connection is being
 * triggered by whack.
 *
 * The negotiation is for the full set of SPDs which need to be
 * installed as KIND_NEGOTIATION.
 */

static void routed_negotiation_to_unrouted(enum routing_event event,
					   struct connection *c,
					   struct logger *logger, where_t where,
					   const char *story)
{
	PEXPECT(logger, !is_opportunistic(c));
	delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
				   logger, where, story);
	FOR_EACH_ITEM(spd, &c->child.spds) {
		if (route_owner(spd) == NULL) {
			do_updown(UPDOWN_ROUTE, c, spd, NULL/*state*/, c->logger);
		}
	}
	set_routing(event, c, RT_UNROUTED, NULL, where);
}

/*
 * Either C is permanent, or C is an instance that going to be revived
 * - the full set of SPDs need to be changed to negotiation (just
 * instantiated instances do not take this code path).
 */

static void ondemand_to_negotiation(enum routing_event event,
				    struct connection *c, where_t where,
				    const char *reason)
{
        struct logger *logger = c->logger;
	ldbg_routing(c->logger, "%s() %s", __func__, reason);
        PEXPECT(logger, !is_opportunistic(c));
	PASSERT(logger, (event == CONNECTION_INITIATE ||
			 event == CONNECTION_ACQUIRE));
	enum routing rt_negotiation = (c->child.routing == RT_ROUTED_ONDEMAND ? RT_ROUTED_NEGOTIATION :
				       CONNECTION_ROUTING_ROOF);
	PASSERT(logger, (rt_negotiation != CONNECTION_ROUTING_ROOF));
	FOR_EACH_ITEM(spd, &c->child.spds) {
		if (!replace_spd_kernel_policy(spd, DIRECTION_OUTBOUND,
					       rt_negotiation,
					       SHUNT_KIND_NEGOTIATION,
					       logger, where,
					       "ondemand->negotiation")) {
			llog(RC_LOG, c->logger,
			     "converting ondemand kernel policy to negotiation");
		}
	}
	/* the state isn't yet known */
	set_routing(event, c, rt_negotiation, NULL, where);
}

/*
 * Either C is permanent, or C is an instance that going to be revived
 * - the full set of SPDs need to be changed to ondemand (just
 * instantiated instances do not take this code path).
 */

static void routed_negotiation_to_routed_ondemand(enum routing_event event,
						  struct connection *c,
						  struct logger *logger,
						  where_t where,
						  const char *reason)
{
	ldbg_routing(c->logger, "%s() %s", __func__, reason);
	PASSERT(logger, (event == CONNECTION_TIMEOUT_IKE ||
			 event == CONNECTION_DELETE_IKE));
	FOR_EACH_ITEM(spd, &c->child.spds) {
		if (!replace_spd_kernel_policy(spd, DIRECTION_OUTBOUND,
					       RT_ROUTED_ONDEMAND,
					       SHUNT_KIND_ONDEMAND,
					       logger, where, reason)) {
			llog(RC_LOG, logger, "%s failed", reason);
		}
	}
	set_routing(event, c, RT_ROUTED_ONDEMAND, NULL, where);
}

/*
 * Delete the ROUTED_TUNNEL, and possibly delete the connection.
 */

static void down_routed_tunnel(enum routing_event event,
			       struct connection *c,
			       struct child_sa **child,
			       where_t where)
{
	PASSERT((*child)->sa.st_logger, c == (*child)->sa.st_connection);

	if (c->newest_routing_sa > (*child)->sa.st_serialno) {
		/* no longer child's */
		ldbg_routing((*child)->sa.st_logger,
			     "keeping connection kernel policy; routing SA "PRI_SO" is newer",
			     pri_so(c->newest_routing_sa));
		delete_child_sa(child);
		return;
	}

	if (c->newest_ipsec_sa > (*child)->sa.st_serialno) {
		/* covered by above; no!? */
		ldbg_routing((*child)->sa.st_logger,
			     "keeping connection kernel policy; IPsec SA "PRI_SO" is newer",
			     pri_so(c->newest_ipsec_sa));
		delete_child_sa(child);
		return;
	}

	if (should_revive_child(*child)) {
		ldbg_routing((*child)->sa.st_logger,
			     "replacing TUNNEL with ONDEMAND; it will be revived");
		/* it's being stripped of the state, hence SOS_NOBODY */
		set_routing(event, c, RT_ROUTED_ONDEMAND, NULL, where);
		replace_ipsec_with_bare_kernel_policies(*child, SHUNT_KIND_ONDEMAND,
							EXPECT_KERNEL_POLICY_OK, HERE);
		schedule_child_revival(*child, "received Delete/Notify");
		/* covered by above; no!? */
		delete_child_sa(child);
		return;
	}

	/*
	 * Should this go back to on-demand?
	 */
	if (is_permanent(c) && c->policy.route) {
		ldbg_routing((*child)->sa.st_logger,
			     "replacing connection kernel policy with on-demand");
		/* it's being stripped of the state, hence SOS_NOBODY */
		set_routing(event, c, RT_ROUTED_ONDEMAND, NULL, where);
		replace_ipsec_with_bare_kernel_policies(*child, SHUNT_KIND_ONDEMAND,
							EXPECT_KERNEL_POLICY_OK, HERE);
		delete_child_sa(child);
		return;
	}

	/*
	 * Is there a failure shunt?
	 */
	if (is_permanent(c) && c->config->failure_shunt != SHUNT_NONE) {
		ldbg_routing((*child)->sa.st_logger,
			     "replacing connection kernel policy with failure");
		/* it's being stripped of the state, hence SOS_NOBODY */
		set_routing(event, c, RT_ROUTED_FAILURE, NULL, where);
		replace_ipsec_with_bare_kernel_policies(*child, SHUNT_KIND_FAILURE,
							EXPECT_KERNEL_POLICY_OK, HERE);
		delete_child_sa(child);
		return;
	}

	/*
	 * Never delete permanent connections.
	 */
	if (is_permanent(c)) {
		ldbg_routing((*child)->sa.st_logger,
			     "keeping connection; it is permanent");
		do_updown_spds(UPDOWN_DOWN, c, &c->child.spds, &(*child)->sa,
			       (*child)->sa.st_logger);
		delete_spd_kernel_policies(&c->child.spds,
					   EXPECT_KERNEL_POLICY_OK,
					   (*child)->sa.st_logger,
					   where, "delete");
		/*
		 * update routing; route_owner() will see this and not
		 * think this route is the owner?
		 */
		set_routing(event, c, RT_UNROUTED, NULL, HERE);
		do_updown_unroute(c, *child);
		delete_child_sa(child);
		return;
	}

	PASSERT((*child)->sa.st_logger, is_instance(c));

	do_updown_spds(UPDOWN_DOWN, c, &c->child.spds,
		       &(*child)->sa, (*child)->sa.st_logger);

	delete_spd_kernel_policies(&c->child.spds,
				   EXPECT_KERNEL_POLICY_OK,
				   (*child)->sa.st_logger,
				   where, "delete");
	set_routing(event, c, RT_UNROUTED, NULL, where);
	delete_child_sa(child);
}

/*
 * Received a message telling us to delete the connection's Child.SA.
 */

static void zap_child(struct child_sa **child,
		      enum routing_event child_event,
		      where_t where)
{
	struct connection *cc = (*child)->sa.st_connection;

	struct routing_annex annex = {
		.child = child,
	};

	if ((*child)->sa.st_serialno != cc->newest_routing_sa) {
		ldbg_routing_skip(cc, child_event, where, &annex);
		delete_child_sa(child);
		return;
	}

	/*
	 * Caller is responsible for generating any messages; suppress
	 * delete_state()'s desire to send an out-of-band delete.
	 */
	on_delete(&(*child)->sa, skip_send_delete);
	on_delete(&(*child)->sa, skip_revival);

	/*
	 * Let state machine figure out how to react.
	 */
	dispatch(child_event, &cc, (*child)->sa.st_logger, where, annex);
	pexpect((*child) == NULL); /* no logger */
}

void connection_delete_child(struct child_sa **child, where_t where)
{
	zap_child(child, CONNECTION_DELETE_CHILD, where);
}

void connection_timeout_child(struct child_sa **child, where_t where)
{
	zap_child(child, CONNECTION_TIMEOUT_CHILD, where);
}

static void zap_ike(struct ike_sa **ike,
		    enum routing_event ike_event,
		    where_t where)
{
	struct routing_annex annex = {
		.ike = ike,
	};

	struct connection *c = (*ike)->sa.st_connection;
	if (c->newest_ike_sa != SOS_NOBODY &&
	    c->newest_ike_sa != (*ike)->sa.st_serialno) {
		/*
		 * There's an established IKE SA and it isn't this
		 * one; hence not the owner.
		 *
		 * This isn't strong enough.  There could be multiple
		 * larval IKE SAs and this check doesn't filter them
		 * out.
		 */
		ldbg_routing_skip(c, ike_event, where, &annex);
		delete_ike_sa(ike);
		return;
	}

	dispatch(ike_event, &c, (*ike)->sa.st_logger, where, annex);
}

void connection_delete_ike(struct ike_sa **ike, where_t where)
{
	zap_ike(ike, CONNECTION_DELETE_IKE, where);
}

void connection_timeout_ike(struct ike_sa **ike, where_t where)
{
	zap_ike(ike, CONNECTION_TIMEOUT_IKE, where);
}

/*
 * Map the IKE event onto the equivalent child event.
 */

static enum routing_event zap_child_event(struct ike_sa **ike, enum routing_event event)
{
	PASSERT((*ike)->sa.st_logger, (event == CONNECTION_TIMEOUT_IKE ||
				       event == CONNECTION_DELETE_IKE));
	enum routing_event child_event = (event == CONNECTION_TIMEOUT_IKE ? CONNECTION_TIMEOUT_CHILD :
					  event == CONNECTION_DELETE_IKE ? CONNECTION_DELETE_CHILD :
					  ROUTING_EVENT_ROOF);
	PASSERT((*ike)->sa.st_logger, child_event != ROUTING_EVENT_ROOF);
	return child_event;
}

/*
 * Stop reviving children trying to use this IKE SA.
 */

static void zap_revival(struct ike_sa **ike, enum routing_event event)
{
	enum_buf ren;
	ldbg_routing((*ike)->sa.st_logger, "  due to %s, IKE SA is no longer viable",
		     str_enum_short(&routing_event_names, event, &ren));
	(*ike)->sa.st_viable_parent = false;
}

/*
 * If the IKE SA's connection has a direct Child SA (shares
 * connection) that owns the route then send a delete/timeout to that
 * Child SA first.
 *
 * This way the IKE SA's connection can jump to the front of the
 * revival queue (without this an IKE SA with multiple children ends
 * up with its chilren sqabbling over which SA should be revived
 * first).
 *
 * Also remember if there was a direct child.  The event only gets
 * dispatched to the IKE SA when there wasn't a child (such as during
 * IKE_SA_INIT).
 */

static bool zap_connection_child(struct ike_sa **ike, enum routing_event child_event,
				 struct child_sa **child, where_t where)
{

	bool dispatched_to_child;
	(*child) = child_sa_by_serialno((*ike)->sa.st_connection->newest_routing_sa);
	if ((*child) == NULL) {
		dispatched_to_child = false;
		ldbg_routing((*ike)->sa.st_logger, "  IKE SA's connection has no Child SA "PRI_SO,
			     pri_so((*ike)->sa.st_connection->newest_routing_sa));
	} else if ((*child)->sa.st_clonedfrom != (*ike)->sa.st_serialno) {
		dispatched_to_child = false;
		ldbg_routing((*ike)->sa.st_logger, "  IKE SA is not the parent of the connection's Child SA "PRI_SO,
			     pri_so((*child)->sa.st_serialno));
	} else {
		ldbg_routing((*ike)->sa.st_logger, "  dispatching delete to Child SA "PRI_SO,
			     pri_so((*child)->sa.st_serialno));
		state_attach(&(*child)->sa, (*ike)->sa.st_logger);
		/* will delete child and its logger */
		dispatched_to_child = true;
		zap_child(child, child_event, where); /* always dispatches here*/
		PEXPECT((*ike)->sa.st_logger, dispatched_to_child);
		PEXPECT((*ike)->sa.st_logger, (*child) == NULL); /*gone!*/
		PEXPECT((*ike)->sa.st_logger, (*ike)->sa.st_connection->newest_routing_sa == SOS_NOBODY);
		PEXPECT((*ike)->sa.st_logger, (*ike)->sa.st_connection->newest_ipsec_sa == SOS_NOBODY);
	}
	return dispatched_to_child;
}

void connection_unrouted(struct connection *c)
{
	c->newest_routing_sa = SOS_NOBODY;
	c->newest_ike_sa = SOS_NOBODY;
	c->newest_ipsec_sa = SOS_NOBODY;
	c->child.routing = RT_UNROUTED;
}

void connection_routing_clear(struct state *st)
{
	struct connection *c = st->st_connection;
#if 0
	if (c->newest_routing_sa == st->st_serialno) {
#if 0
		llog_pexpect(st->st_logger, HERE,
			     "newest_routing_sa");
#endif
		c->newest_routing_sa = SOS_NOBODY;
	}
#endif
	if (c->newest_ipsec_sa == st->st_serialno) {
#if 0
		llog_pexpect(st->st_logger, HERE,
			     "newest_ipsec_sa");
#endif
		c->newest_ipsec_sa = SOS_NOBODY;
	}
	if (c->newest_ike_sa == st->st_serialno) {
#if 0
		llog_pexpect(st->st_logger, HERE,
			     "newest_ike_sa");
#endif
		c->newest_ike_sa = SOS_NOBODY;
	}
}

void connection_initiate(struct connection *c, const threadtime_t *inception,
			 bool background, where_t where)
{
	dispatch(CONNECTION_INITIATE, &c,
		 c->logger, where,
		 (struct routing_annex) {
			 .inception = inception,
			 .background = background,
		 });
}

void connection_establish_ike(struct ike_sa *ike, where_t where)
{
	struct connection *c = ike->sa.st_connection;
	struct routing_annex e = {
		.ike = &ike,
	};
	struct old_routing old = ldbg_routing_start(c, CONNECTION_ESTABLISH_IKE, where, &e);
	c->newest_ike_sa = ike->sa.st_serialno;
	ike->sa.st_viable_parent = true;
	linux_audit_conn(&ike->sa, LAK_PARENT_START);
	/* dump new keys */
	if (DBGP(DBG_PRIVATE)) {
		DBG_tcpdump_ike_sa_keys(&ike->sa);
	}
	ldbg_routing_stop(c, CONNECTION_ESTABLISH_IKE, where, &e, &old);
}

void connection_acquire(struct connection *c, threadtime_t *inception,
			const struct kernel_acquire *b, where_t where)
{
	dispatch(CONNECTION_ACQUIRE, &c,
		 b->logger, where,
		 (struct routing_annex) {
			 .inception = inception,
			 .background = b->background,
			 .sec_label = b->sec_label,
			 .packet = b->packet,
		 });
}

void connection_route(struct connection *c, where_t where)
{
	if (!oriented(c)) {
		llog(RC_ORIENT, c->logger,
		     "we cannot identify ourselves with either end of this connection");
		return;
	}

	dispatch(CONNECTION_ROUTE, &c, c->logger, where,
		 (struct routing_annex) {
			 0,
		 });

}

void connection_unroute(struct connection *c, where_t where)
{
	/*
	 * XXX: strip POLICY.ROUTE in whack code, not here (code
	 * expects to be able to route/unroute without loosing the
	 * policy bits).
	 */
	dispatch(CONNECTION_UNROUTE, &c,
		 c->logger, where,
		 (struct routing_annex) {
			 0,
		 });
}

static void zap_v1_child(struct ike_sa **ike, struct child_sa *child)
{
	/*
	 * With IKEv1, deleting an ISAKMP SA only deletes larval
	 * children.  Any established children are released to the
	 * wild.
	 */
	if (IS_IPSEC_SA_ESTABLISHED(&child->sa)) {
		ldbg_routing((*ike)->sa.st_logger, "    letting established IPsec SA "PRI_SO" go wild",
			     pri_so(child->sa.st_serialno));
	} else {
		/*
		 * Attach the IKE SA's whack to the child so that the
		 * child can also log its demise.
		 */
		ldbg_routing((*ike)->sa.st_logger, "    deleting larval IPsec SA "PRI_SO,
			     pri_so(child->sa.st_serialno));
		state_attach(&child->sa, (*ike)->sa.st_logger);
		delete_child_sa(&child);
	}
}

static void zap_v2_child(struct ike_sa **ike, struct child_sa *child,
			 enum routing_event child_event, where_t where)
{

	/*
	 * With IKEv2, deleting an IKE SA deletes all children; the
	 * only question is how.
	 *
	 * If the child owns the connection's routing then it needs to
	 * be dispatched; else it can simply be deleted.
	 */
	state_attach(&child->sa, (*ike)->sa.st_logger);

	/* redundant */
	on_delete(&child->sa, skip_send_delete);
	on_delete(&child->sa, skip_log_message);
	struct connection *cc = child->sa.st_connection;

	if (cc->newest_routing_sa == child->sa.st_serialno) {
		PEXPECT((*ike)->sa.st_logger, IS_IPSEC_SA_ESTABLISHED(&child->sa));
		/* will delete child and its logger */
		ldbg_routing((*ike)->sa.st_logger, "    zapping Child SA "PRI_SO,
			     pri_so(child->sa.st_serialno));
		zap_child(&child, child_event, where);
		return;
	}

	if (IS_IPSEC_SA_ESTABLISHED(&child->sa)) {
		/*
		 * Presumably the Child SA lost ownership; or never
		 * gained it.
		 */
		enum_buf ren;
		llog_sa(RC_LOG, child, "deleting lingering %s (%s)",
			child->sa.st_connection->config->ike_info->parent_sa_name,
			str_enum_short(&routing_event_names, child_event, &ren));
		delete_child_sa(&child);
		return;
	}

	if (IS_IKE_SA_ESTABLISHED(&(*ike)->sa)) {
		/*
		 * The IKE SA is established; log any larval children
		 * (presumably from a CREATE_CHILD_SA exchange).
		 */
		enum_buf ren;
		llog_sa(RC_LOG, child, "deleting larval %s (%s)",
			child->sa.st_connection->config->ike_info->child_sa_name,
			str_enum_short(&routing_event_names, child_event, &ren));
		delete_child_sa(&child);
		return;
	}

	ldbg_routing((*ike)->sa.st_logger, "    zapping Child SA "PRI_SO,
		     pri_so(child->sa.st_serialno));
	delete_child_sa(&child);
}

void connection_zap_ike_family(struct ike_sa **ike,
			       enum routing_event ike_event,
			       where_t where)
{
	ldbg_routing((*ike)->sa.st_logger, "%s()", __func__);
	enum routing_event child_event = zap_child_event(ike, ike_event);
	zap_revival(ike, ike_event);
	struct child_sa *connection_child = NULL;
	zap_connection_child(ike, child_event, &connection_child, where);

	/*
	 * We are a parent: prune any remaining children and then
	 * prepare to delete ourself.
	 */

	struct state_filter cf = {
		.clonedfrom = (*ike)->sa.st_serialno,
		.where = HERE,
	};
	while(next_state_new2old(&cf)) {
		struct child_sa *child = pexpect_child_sa(cf.st);

		switch (child->sa.st_ike_version) {
		case IKEv1:
			zap_v1_child(ike, child);
			break;
		case IKEv2:
			zap_v2_child(ike, child, child_event, where);
			break;
		}
	}

	/* delete self */
	zap_ike(ike, ike_event, where);
}

void connection_timeout_ike_family(struct ike_sa **ike, where_t where)
{
	pstat_sa_failed(&(*ike)->sa, REASON_TOO_MANY_RETRANSMITS);
	connection_zap_ike_family(ike, CONNECTION_TIMEOUT_IKE, where);
}

void connection_delete_ike_family(struct ike_sa **ike, where_t where)
{
	connection_zap_ike_family(ike, CONNECTION_DELETE_IKE, where);
}

/*
 * "down" / "unroute" the connection but _don't_ delete the kernel
 * state / policy.
 *
 * Presumably the kernel policy (at least) is acting like a trap while
 * mibike migrates things?
 */

void connection_suspend(struct child_sa *child, where_t where)
{
	struct connection *cc = child->sa.st_connection;
	dispatch(CONNECTION_SUSPEND, &cc,
		 child->sa.st_logger, where,
		 (struct routing_annex) {
			 .child = &child,
		 });
}

void connection_resume(struct child_sa *child, where_t where)
{
	struct connection *cc = child->sa.st_connection;
	dispatch(CONNECTION_RESUME, &cc,
		 child->sa.st_logger, where,
		 (struct routing_annex) {
			 .child = &child,
		 });
}

static void dispatch_1(enum routing_event event,
		       struct connection *c,
		       struct logger *logger, where_t where,
		       struct routing_annex *e)
{
#define XX(CONNECTION_EVENT, CONNECTION_ROUTING, CONNECTION_KIND)	\
	(((CONNECTION_EVENT) *						\
	  CONNECTION_ROUTING_ROOF + CONNECTION_ROUTING) *		\
	 CONNECTION_KIND_ROOF + CONNECTION_KIND)
#define X(EVENT, ROUTING, KIND)				\
	XX(CONNECTION_##EVENT, RT_##ROUTING, CK_##KIND)

	{
		const enum routing routing = c->child.routing;
		const enum connection_kind kind = c->local->kind;

		switch (XX(event, routing, kind)) {

		case X(ROUTE, UNROUTED, GROUP):
			/* caller deals with recursion */
			add_policy(c, policy.route); /* always */
			return;
		case X(UNROUTE, UNROUTED, GROUP):
			/* ROUTE+UP cleared by caller */
			return;

		case X(ROUTE, UNROUTED, TEMPLATE):
		case X(ROUTE, UNROUTED, PERMANENT):
			add_policy(c, policy.route); /* always */
			if (never_negotiate(c)) {
				if (!unrouted_to_routed_never_negotiate(event, c, where)) {
					/* XXX: why whack only? */
					llog(RC_ROUTE, logger, "could not route");
					return;
				}
				PEXPECT(logger, c->child.routing == RT_ROUTED_NEVER_NEGOTIATE);
			} else {
				if (!unrouted_to_routed_ondemand(event, c, where)) {
					/* XXX: why whack only? */
					llog(RC_ROUTE, logger, "could not route");
					return;
				}
				PEXPECT(logger, c->child.routing == RT_ROUTED_ONDEMAND);
			}
			return;

		case X(UNROUTE, ROUTED_NEVER_NEGOTIATE, TEMPLATE):
		case X(UNROUTE, ROUTED_NEVER_NEGOTIATE, PERMANENT):
			PEXPECT(logger, never_negotiate(c));
			delete_spd_kernel_policies(&c->child.spds,
						   EXPECT_KERNEL_POLICY_OK,
						   c->logger, where, "unroute permanent");
			/* stop updown_unroute() finding this
			 * connection */
			set_routing(event, c, RT_UNROUTED, NULL, where);
			do_updown_unroute(c, NULL);
			return;

		case X(UNROUTE, ROUTED_INBOUND, INSTANCE): /* xauth-pluto-25-lsw299 */
		case X(UNROUTE, ROUTED_INBOUND, PERMANENT): /* ikev1-xfrmi-02-aggr */
			if (BROKEN_TRANSITION) {
				/* ikev1-xfrmi-02-aggr ikev1-xfrmi-02
				 * ikev1-xfrmi-02-tcpdump */
				delete_spd_kernel_policies(&c->child.spds,
							   EXPECT_KERNEL_POLICY_OK,
							   c->logger, where, "unroute permanent");
				set_routing(event, c, RT_UNROUTED, NULL, where);
				do_updown_unroute(c, NULL);
				return;
			}
			break;

		case X(UNROUTE, ROUTED_INBOUND, TEMPLATE):
			if (BROKEN_TRANSITION) {
				/* xauth-pluto-25-lsw299
				 * xauth-pluto-25-mixed-addresspool */
				delete_spd_kernel_policies(&c->child.spds,
							   EXPECT_KERNEL_POLICY_OK,
							   c->logger, where, "unroute permanent");
				set_routing(event, c, RT_UNROUTED, NULL, where);
				do_updown_unroute(c, NULL);
				return;
			}
			break;

		case X(UNROUTE, UNROUTED, PERMANENT):
			ldbg_routing(logger, "already unrouted");
			return;

		case X(INITIATE, ROUTED_TUNNEL, PERMANENT):
			if (BROKEN_TRANSITION) {
				/*
				 * Presumably no delete transition is
				 * leaving this in the wrong state.
				 *
				 * See ikev2-13-ah.
				 */
				return;
			}
			break;

		case X(INITIATE, UNROUTED, PERMANENT):
			flush_unrouted_revival(c);
			set_routing(event, c, RT_UNROUTED_NEGOTIATION, NULL, where);
			return;

		case X(INITIATE, ROUTED_ONDEMAND, PERMANENT):
		case X(INITIATE, ROUTED_ONDEMAND, INSTANCE): /* from revival */
			flush_routed_ondemand_revival(c);
			ondemand_to_negotiation(event, c, where, "negotiating permanent");
			PEXPECT(logger, c->child.routing == RT_ROUTED_NEGOTIATION);
			return;

		case X(ACQUIRE, ROUTED_ONDEMAND, PERMANENT):
			flush_routed_ondemand_revival(c);
			ondemand_to_negotiation(event, c, where, "negotiating permanent");
			PEXPECT(logger, c->child.routing == RT_ROUTED_NEGOTIATION);
			/* ipsecdoi_initiate may replace SOS_NOBODY with a state */
			ipsecdoi_initiate(c, child_sa_policy(c), SOS_NOBODY,
					  e->inception, null_shunk,
					  e->background, c->logger,
					  /*update_routing*/LEMPTY, HERE);
			return;

		case X(INITIATE, UNROUTED_NEGOTIATION, PERMANENT):
			if (BROKEN_TRANSITION) {
				/* ikev2-redirect-01-global-load-balancer
				 * ikev2-redirect-01-global
				 * ikev2-redirect-03-auth-loop
				 * ikev2-tcp-07-fail-ike-auth-redirect */
				return;
			}
			break;
		case X(INITIATE, ROUTED_NEGOTIATION, PERMANENT):
			if (BROKEN_TRANSITION) {
				/*
				 * Because there is no delete yet.
				 *
				 * See ikev2-impair-10-nr-ts-selectors
				 */
				return;
			}
			llog(RC_LOG, c->logger, "connection already negotiating");
			return;
		case X(ACQUIRE, ROUTED_NEGOTIATION, PERMANENT):
			llog(RC_LOG, c->logger, "connection already negotiating");
			return;

		case X(ROUTE, UNROUTED_NEGOTIATION, PERMANENT):
			if (BROKEN_TRANSITION) {
				/*
				 * XXX: should install routing+policy!
				 */
				add_policy(c, policy.route);
				llog(RC_LOG_SERIOUS, logger,
				     "policy ROUTE added to negotiating connection");
				return;
			}
			break;
		case X(UNROUTE, UNROUTED_NEGOTIATION, PERMANENT):
			set_routing(event, c, RT_UNROUTED, NULL, where);
			return;

		case X(ROUTE, ROUTED_NEGOTIATION, PERMANENT):
			add_policy(c, policy.route);
			llog(RC_LOG_SERIOUS, logger, "connection already routed");
			return;
		case X(UNROUTE, ROUTED_NEGOTIATION, PERMANENT):
			delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
						   c->logger, where, "unroute permanent");
			/* do now so route_owner won't find us */
			set_routing(event, c, RT_UNROUTED, NULL, where);
			do_updown_unroute(c, NULL);
			return;

		case X(UNROUTE, ROUTED_ONDEMAND, PERMANENT):
			PEXPECT(logger, !never_negotiate(c));
			flush_routed_ondemand_revival(c);
			delete_spd_kernel_policies(&c->child.spds,
						   EXPECT_NO_INBOUND,
						   c->logger, where, "unroute permanent");
			/* stop updown_unroute() finding this
			 * connection */
			set_routing(event, c, RT_UNROUTED, NULL, where);
			do_updown_unroute(c, NULL);
			return;

		case X(ROUTE, ROUTED_TUNNEL, PERMANENT):
			add_policy(c, policy.route); /* always */
			llog(RC_LOG, logger, "policy ROUTE added to established connection");
			return;
		case X(UNROUTE, ROUTED_TUNNEL, PERMANENT):
			llog(RC_RTBUSY, logger, "cannot unroute: route busy");
			return;

		case X(UNROUTE, ROUTED_FAILURE, PERMANENT):
			delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
						   c->logger, where, "unroute permanent");
			/* do now so route_owner won't find us */
			set_routing(event, c, RT_UNROUTED, NULL, where);
			do_updown_unroute(c, NULL);
			return;

		case X(UNROUTE, UNROUTED_TUNNEL, PERMANENT):
			delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
						   c->logger, where, "unroute permanent");
			set_routing(event, c, RT_UNROUTED, NULL, where);
			return;

		case X(UNROUTE, UNROUTED, TEMPLATE):
			ldbg_routing(logger, "already unrouted");
			return;
		case X(UNROUTE, ROUTED_ONDEMAND, TEMPLATE):
			flush_routed_ondemand_revival(c);
			delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
						   c->logger, where, "unroute template");
			/* do now so route_owner won't find us */
			set_routing(event, c, RT_UNROUTED, NULL, where);
			do_updown_unroute(c, NULL);
			return;

		case X(UNROUTE, UNROUTED, INSTANCE):
			ldbg_routing(logger, "already unrouted");
			return;
		case X(INITIATE, UNROUTED, INSTANCE):
			/*
			 * Triggered by whack against the template
			 * which is then instantiated creating this
			 * connection.  The template may or may not be
			 * routed.
			 *
			 * When the template is routed, should this
			 * instead transition to routed_negotiation?
			 *
			 * When the template is routed, should the
			 * instance start in ROUTED_UNINSTALLED?
			 *
			 * NO? because when it is pulled it shouldn't
			 * undo the routing?
			 *
			 * YES? because the routing code has to deal
			 * with that.
			 *
			 * MAYBE? but only when the template and
			 * instance have the same SPDs.
			 */
			if (BROKEN_TRANSITION &&
			    c->config->negotiation_shunt == SHUNT_HOLD) {
				ldbg_routing(logger, "skipping NEGOTIATION=HOLD");
				set_routing(event, c, RT_UNROUTED_NEGOTIATION, NULL, where);
				return;
			}
			unrouted_instance_to_unrouted_negotiation(event, c, where);
			return;

		case X(ACQUIRE, UNROUTED, INSTANCE):
			/*
			 * Triggered by acquire against the template
			 * which then instantiated creating this
			 * connection.  The template may or may not be
			 * routed.
			 *
			 * When the template is routed, should this
			 * instead transition to routed_negotiation?
			 *
			 * NO? because when it is pulled it shouldn't
			 * undo the routing?
			 *
			 * When the template is routed, should the
			 * instance start in ROUTED_UNINSTALLED?
			 *
			 * YES? because the routing code has to deal
			 * with that.
			 *
			 * MAYBE? but only when the template and
			 * instance have the same SPDs.
			 */
			if (BROKEN_TRANSITION &&
			    c->config->negotiation_shunt == SHUNT_HOLD) {
				ldbg_routing(logger, "skipping NEGOTIATION=HOLD");
				set_routing(event, c, RT_UNROUTED_NEGOTIATION, NULL, where);
				ipsecdoi_initiate(c, child_sa_policy(c), SOS_NOBODY,
						  e->inception, null_shunk,
						  e->background, logger,
						  /*update_routing*/LEMPTY, HERE);
				return;
			}
			unrouted_instance_to_unrouted_negotiation(event, c, where);
			ipsecdoi_initiate(c, child_sa_policy(c), SOS_NOBODY,
					  e->inception, e->sec_label,
					  e->background, logger,
					  /*update_routing*/LEMPTY, HERE);
			return;

		case X(UNROUTE, UNROUTED_NEGOTIATION, INSTANCE):
			delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
						   c->logger, where, "unroute instance");
			/* do now so route_owner won't find us */
			set_routing(event, c, RT_UNROUTED, NULL, where);
			return;

		case X(UNROUTE, ROUTED_NEGOTIATION, INSTANCE):
			delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
						   c->logger, where, "unroute instance");
			set_routing(event, c, RT_UNROUTED, NULL, where);
			do_updown_unroute(c, NULL);
			return;

		case X(UNROUTE, ROUTED_TUNNEL, INSTANCE):
			llog(RC_RTBUSY, logger, "cannot unroute: route busy");
			return;

		case X(UNROUTE, ROUTED_ONDEMAND, INSTANCE):
			flush_routed_ondemand_revival(c);
			delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
						   c->logger, where, "unroute instance");
			/* do now so route_owner won't find us */
			set_routing(event, c, RT_UNROUTED, NULL, where);
			do_updown_unroute(c, NULL);
			return;

		case X(UNROUTE, ROUTED_FAILURE, INSTANCE):
			delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
						   c->logger, where, "unroute instance");
			/* do now so route_owner won't find us */
			set_routing(event, c, RT_UNROUTED, NULL, where);
			do_updown_unroute(c, NULL);
			return;

		case X(UNROUTE, UNROUTED_TUNNEL, INSTANCE):
			delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
						   c->logger, where, "unroute instance");
			set_routing(event, c, RT_UNROUTED, NULL, where);
			return;

		case X(TIMEOUT_IKE, UNROUTED, PERMANENT):
		case X(TIMEOUT_IKE, UNROUTED, INSTANCE):		/* ikev2-31-nat-rw-no-rekey */
		case X(TIMEOUT_IKE, ROUTED_ONDEMAND, PERMANENT):	/* ikev2-child-ipsec-retransmit */
		case X(DELETE_IKE, ROUTED_ONDEMAND, INSTANCE):		/* ikev2-30-rw-no-rekey */
#if 0
		case X(DELETE_IKE, UNROUTED, INSTANCE): /*duplicate!?!*/
#endif
			/*
			 * ikev2-31-nat-rw-no-rekey:
			 *
			 * The established child unroutes the
			 * connection; followed by this IKE timeout.
			 *
			 * ikev2-child-ipsec-retransmit:
			 *
			 * The UP and established child schedules
			 * revival, putting the connection into
			 * ROUTED_ONDEMAND, followed by this IKE
			 * timeout.
			 */
			delete_ike_sa(e->ike);
			return;

		case X(DELETE_IKE, UNROUTED_NEGOTIATION, PERMANENT):
		case X(TIMEOUT_IKE, UNROUTED_NEGOTIATION, PERMANENT):
			/* ex, permanent+initiate */
			if (should_revive_ike((*e->ike))) {
				set_routing(event, c, RT_UNROUTED, NULL, where);
				schedule_ike_revival((*e->ike), (event == CONNECTION_DELETE_IKE ? "delete IKE SA" :
								 "timeout IKE SA"));
				delete_ike_sa(e->ike);
				return;
			}
			set_routing(event, c, RT_UNROUTED, NULL, where);
			delete_ike_sa(e->ike);
			return;

		case X(DELETE_IKE, ROUTED_NEGOTIATION, PERMANENT):
		case X(TIMEOUT_IKE, ROUTED_NEGOTIATION, PERMANENT):
			/*
			 * For instance, this end initiated a Child SA
			 * for the connection while at the same time
			 * the peer initiated an IKE SA delete and/or
			 * the exchange timed out.
			 *
			 * Because the Child SA is larval and,
			 * presumably, there is no earlier child the
			 * code below, and not zap_connection(), will
			 * need to deal with revival et.al.
			 */
			/* ex, permanent+up */
			if (should_revive_ike((*e->ike))) {
				routed_negotiation_to_routed_ondemand(event, c, logger, where,
								      "restoring ondemand, reviving");
				PEXPECT(logger, c->child.routing == RT_ROUTED_ONDEMAND);
				schedule_ike_revival((*e->ike), (event == CONNECTION_DELETE_IKE ? "delete IKE SA" :
								 "timeout IKE SA"));
				delete_ike_sa(e->ike);
				return;
			}
			if (c->policy.route) {
				routed_negotiation_to_routed_ondemand(event, c, logger, where,
								      "restoring ondemand, connection is routed");
				PEXPECT(logger, c->child.routing == RT_ROUTED_ONDEMAND);
				delete_ike_sa(e->ike);
				return;
			}
			/* is this reachable? */
			routed_negotiation_to_unrouted(event, c, logger, where, "deleting");
			PEXPECT(logger, c->child.routing == RT_UNROUTED);
			delete_ike_sa(e->ike);
			/* connection lives to fight another day */
			return;

		case X(TIMEOUT_IKE, ROUTED_NEGOTIATION, INSTANCE):
		case X(TIMEOUT_IKE, UNROUTED_NEGOTIATION, INSTANCE):
			if (BROKEN_TRANSITION &&
			    should_revive_ike((*e->ike))) {
				/* when ROUTED_NEGOTIATION should
				 * switch to ROUTED_REVIVAL */
				schedule_ike_revival((*e->ike), "timed out");
				delete_ike_sa(e->ike);
				return;
			}
			if (is_opportunistic(c)) {
				/*
				 * A failed OE initiator, make shunt bare.
				 */
				orphan_holdpass(c, c->spd, logger);
				/*
				 * Change routing so we don't get cleared out
				 * when state/connection dies.
				 */
				set_routing(event, c, RT_UNROUTED, NULL, where);
				delete_ike_sa(e->ike);
				return;
			}
			delete_ike_sa(e->ike);
			set_routing(event, c, RT_UNROUTED, NULL, where);
			return;

		case X(DELETE_IKE, ROUTED_TUNNEL, PERMANENT):
		case X(TIMEOUT_IKE, ROUTED_TUNNEL, PERMANENT):
		case X(DELETE_IKE, ROUTED_TUNNEL, INSTANCE):
		case X(TIMEOUT_IKE, ROUTED_TUNNEL, INSTANCE):
			PEXPECT(c->logger, (*e->ike)->sa.st_ike_version == IKEv1);
			delete_ike_sa(e->ike);
			return;

		case X(DELETE_IKE, UNROUTED, PERMANENT):
			/*
			 * fips-12-ikev2-esp-dh-wrong et.al.
			 *
			 * The IKE_SA_INIT responder rejects the
			 * initial exchange and deletes the IKE SA.
			 *
			 * XXX: can this also happen during IKE_AUTH?
			 *
			 * Since there's no established Child SA
			 * zap_connection_states() should always fail?
			 */
			delete_ike_sa(e->ike);
			return;

		case X(DELETE_IKE, UNROUTED, INSTANCE):			/* certoe-08-nat-packet-cop-restart */
		case X(DELETE_IKE, UNROUTED_NEGOTIATION, INSTANCE):	/* dnsoe-01 ... */
			delete_ike_sa(e->ike);
			/*
			 * XXX: huh? instance isn't routed so why
			 * delete policies?  Instead just drop IKE and
			 * let connection disappear?
			 */
			delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
						   c->logger, where, "unroute instance");
			set_routing(event, c, RT_UNROUTED, NULL, where);
			return;
		case X(DELETE_IKE, ROUTED_ONDEMAND, PERMANENT):		/* ROUTED_NEGOTIATION!?! */
			/*
			 * Happens after all children are killed, and
			 * connection put into routed ondemand.  Just
			 * need to delete IKE.
			 */
			delete_ike_sa(e->ike);
			return;

		case X(TIMEOUT_CHILD, ROUTED_TUNNEL, PERMANENT):
		case X(DELETE_CHILD, ROUTED_TUNNEL, PERMANENT):
			/* permenant connections are never deleted */
			down_routed_tunnel(event, c, e->child, where);
			return;
		case X(TIMEOUT_CHILD, ROUTED_TUNNEL, INSTANCE):
		case X(DELETE_CHILD, ROUTED_TUNNEL, INSTANCE):
			down_routed_tunnel(event, c, e->child, where);
			return;

		case X(TIMEOUT_CHILD, UNROUTED_NEGOTIATION, INSTANCE):
		case X(TIMEOUT_CHILD, UNROUTED, PERMANENT): /* permanent+up */
			if (should_revive_child(*(e->child))) {
				schedule_child_revival((*e->child), "timed out");
				delete_child_sa(e->child);
				set_routing(event, c, RT_UNROUTED, NULL, where);
				return;
			}
			delete_child_sa(e->child);
			set_routing(event, c, RT_UNROUTED, NULL, where);
			return;

		case X(ESTABLISH_INBOUND, ROUTED_ONDEMAND, TEMPLATE): /* ikev1-l2tp-03-two-interfaces */
			if (BROKEN_TRANSITION) {
				flush_routed_ondemand_revival(c);
				/*
				 * ikev1-l2tp-03-two-interfaces
				 * github/693 github/1117
				 */
				set_routing(event, c, RT_ROUTED_INBOUND, NULL, where);
				return;
			}
			break;
		case X(ESTABLISH_OUTBOUND, ROUTED_INBOUND, TEMPLATE): /* ikev1-l2tp-03-two-interfaces */
			/*
			 * ikev1-l2tp-03-two-interfaces
			 * github/693 github/1117
			 */
			set_established_child(event, c, RT_ROUTED_TUNNEL, e->child, where);
			return;

		case X(ESTABLISH_INBOUND, ROUTED_ONDEMAND, INSTANCE): /* ikev2-32-nat-rw-rekey */
			if (BROKEN_TRANSITION) {
				flush_routed_ondemand_revival(c);
				/* ikev2-32-nat-rw-rekey */
				set_routing(event, c, RT_ROUTED_INBOUND, NULL, where);
				return;
			}
			break;
		case X(ESTABLISH_INBOUND, ROUTED_INBOUND, PERMANENT): /* alias-01 */
			if (BROKEN_TRANSITION) {
				/* alias-01 */
				set_routing(event, c, RT_ROUTED_INBOUND, NULL, where);
				return;
			}
			break;
		case X(ESTABLISH_INBOUND, UNROUTED_NEGOTIATION, PERMANENT):
			/* addconn-05-bogus-left-interface
			 * algo-ikev2-aes128-sha1-ecp256 et.al. */
			set_routing(event, c, RT_UNROUTED_INBOUND, NULL, where);
			return;
		case X(ESTABLISH_INBOUND, UNROUTED, TEMPLATE): /* xauth-pluto-14 */
			if (BROKEN_TRANSITION) {
				/*  xauth-pluto-14 */
				set_routing(event, c, RT_ROUTED_INBOUND, NULL, where);
				return;
			}
			break;
		case X(ESTABLISH_INBOUND, ROUTED_ONDEMAND, PERMANENT):
			if (BROKEN_TRANSITION) {
				/* instance was routed by routed-ondemand? */
				flush_routed_ondemand_revival(c);
				set_routing(event, c, RT_ROUTED_INBOUND, NULL, where);
				return;
			}
			break;
		case X(ESTABLISH_INBOUND, ROUTED_NEGOTIATION, INSTANCE):
		case X(ESTABLISH_INBOUND, ROUTED_NEGOTIATION, PERMANENT):
		case X(ESTABLISH_INBOUND, UNROUTED, INSTANCE):
		case X(ESTABLISH_INBOUND, UNROUTED, PERMANENT):
		case X(ESTABLISH_INBOUND, UNROUTED_NEGOTIATION, INSTANCE):
			if (BROKEN_TRANSITION) {
				set_routing(event, c, RT_ROUTED_INBOUND, NULL, where);
				return;
			}
			break;

		case X(ESTABLISH_OUTBOUND, UNROUTED_INBOUND, PERMANENT):
		case X(ESTABLISH_OUTBOUND, UNROUTED_INBOUND, INSTANCE):
		case X(ESTABLISH_OUTBOUND, ROUTED_INBOUND, PERMANENT):
		case X(ESTABLISH_OUTBOUND, ROUTED_INBOUND, INSTANCE):
			set_established_child(event, c, RT_ROUTED_TUNNEL, e->child, where);
			return;

		case X(ESTABLISH_INBOUND, ROUTED_TUNNEL, PERMANENT):
		case X(ESTABLISH_INBOUND, ROUTED_TUNNEL, INSTANCE):
			/*
			 * This happens when there's a re-key where
			 * the state is re-established but not the
			 * policy (that is left untouched).
			 *
			 * For instance ikev2-12-transport-psk and
			 * ikev2-28-rw-server-rekey
			 * ikev1-labeled-ipsec-01-permissive.
			 *
			 * XXX: suspect this is too early - for rekey
			 * should only update after new child
			 * establishes?
			 */
			set_routing(event, c, RT_ROUTED_TUNNEL, e->child, where);
			return;
		case X(ESTABLISH_OUTBOUND, ROUTED_TUNNEL, PERMANENT):
		case X(ESTABLISH_OUTBOUND, ROUTED_TUNNEL, INSTANCE):
			/*
			 * This happens when there's a re-key where
			 * the state is re-established but not the
			 * policy (that is left untouched).
			 *
			 * For instance ikev2-12-transport-psk and
			 * ikev2-28-rw-server-rekey
			 * ikev1-labeled-ipsec-01-permissive.
			 */
			set_established_child(event, c, RT_ROUTED_TUNNEL, e->child, where);
			return;

		case X(SUSPEND, ROUTED_TUNNEL, PERMANENT):
		case X(SUSPEND, ROUTED_TUNNEL, INSTANCE):
			/*
			 * Update connection's routing so that
			 * route_owner() won't find us.
			 *
			 * Only unroute when no other routed
			 * connection shares the SPD.
			 */
			FOR_EACH_ITEM(spd, &c->child.spds) {
				/* XXX: never finds SPD */
				if (route_owner(spd) == NULL) {
					do_updown(UPDOWN_DOWN, c, spd,
						  &(*e->child)->sa, logger);
					(*e->child)->sa.st_mobike_del_src_ip = true;
					do_updown(UPDOWN_UNROUTE, c, spd,
						  &(*e->child)->sa, logger);
					(*e->child)->sa.st_mobike_del_src_ip = false;
				}
			}
			set_routing(event, c, RT_UNROUTED_TUNNEL, e->child, where);
			return;

		case X(RESUME, UNROUTED_TUNNEL, PERMANENT):
		case X(RESUME, UNROUTED_TUNNEL, INSTANCE):
			set_routing(event, c, RT_ROUTED_TUNNEL, e->child, where);
			FOR_EACH_ITEM(spd, &c->child.spds) {
				do_updown(UPDOWN_UP, c, spd, &(*e->child)->sa, logger);
				do_updown(UPDOWN_ROUTE, c, spd, &(*e->child)->sa, logger);
			}
			return;

/*
 * Labeled IPsec.
 */

		case X(ROUTE, UNROUTED, LABELED_TEMPLATE):
			add_policy(c, policy.route); /* always */
			if (never_negotiate(c)) {
				if (!unrouted_to_routed_never_negotiate(event, c, where)) {
					/* XXX: why whack only? */
					llog(WHACK_STREAM|RC_ROUTE, logger, "could not route");
					return;
				}
				PEXPECT(logger, c->child.routing == RT_ROUTED_NEVER_NEGOTIATE);
				return;
			}
			if (!unrouted_to_routed_ondemand_sec_label(c, logger, where)) {
				llog(RC_ROUTE, logger, "could not route");
				return;
			}
			set_routing(event, c, RT_ROUTED_ONDEMAND, NULL, where);
			return;
		case X(ROUTE, ROUTED_ONDEMAND, LABELED_PARENT):
			/*
			 * ikev2-labeled-ipsec-06-rekey-ike-acquire
			 * where the rekey re-routes the existing
			 * routed connection from IKE AUTH.
			 */
			set_routing(event, c, RT_ROUTED_ONDEMAND, NULL, where);
			return;
		case X(ROUTE, UNROUTED, LABELED_PARENT):
			/*
			 * The CK_LABELED_TEMPLATE connection may have
			 * been routed (i.e., route+ondemand), but not
			 * this CK_LABELED_PARENT - it is still
			 * negotiating.
			 *
			 * The negotiating LABELED_PARENT connection
			 * should be in UNROUTED_NEGOTIATION but
			 * ACQUIRE doesn't yet go through that path.
			 *
			 * But what if the two have the same SPDs?
			 * Then the routing happens twice which seems
			 * to be harmless.
			 */
			if (!unrouted_to_routed_ondemand_sec_label(c, logger, where)) {
				llog(RC_ROUTE, logger, "could not route");
				return;
			}
			set_routing(event, c, RT_ROUTED_ONDEMAND, NULL, where);
			return;
		case X(UNROUTE, UNROUTED, LABELED_TEMPLATE):
			ldbg_routing(logger, "already unrouted");
			return;
		case X(UNROUTE, ROUTED_ONDEMAND, LABELED_TEMPLATE):
			delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
						   c->logger, where, "unroute template");
			/* do now so route_owner won't find us */
			set_routing(event, c, RT_UNROUTED, NULL, where);
			do_updown_unroute(c, NULL);
			return;
		case X(UNROUTE, UNROUTED, LABELED_PARENT):
			ldbg_routing(logger, "already unrouted");
			return;
		case X(UNROUTE, ROUTED_ONDEMAND, LABELED_PARENT):
			delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
						   c->logger, where, "unroute instance");
			/* do now so route_owner won't find us */
			set_routing(event, c, RT_UNROUTED, NULL, where);
			do_updown_unroute(c, NULL);
			return;
		case X(INITIATE, UNROUTED, LABELED_PARENT):
			return;
		case X(ACQUIRE, UNROUTED, LABELED_PARENT):
		case X(ACQUIRE, ROUTED_ONDEMAND, LABELED_PARENT):
			ipsecdoi_initiate(c, child_sa_policy(c), SOS_NOBODY,
					  e->inception, e->sec_label, e->background,
					  logger,
					  /*update_routing*/LEMPTY, HERE);
			return;
		case X(DELETE_IKE, ROUTED_ONDEMAND, LABELED_PARENT):
		case X(DELETE_IKE, UNROUTED, LABELED_PARENT):
			delete_ike_sa(e->ike);
			set_routing(event, c, RT_UNROUTED, NULL, where);
			return;

/*
 * Labeled IPsec child.
 */

		case X(ESTABLISH_INBOUND, UNROUTED_TUNNEL, LABELED_CHILD):
			/* rekey */
			set_routing(event, c, RT_UNROUTED_TUNNEL, e->child, where);
			return;
		case X(ESTABLISH_OUTBOUND, UNROUTED_TUNNEL, LABELED_CHILD):
			/* rekey */
			set_established_child(event, c, RT_UNROUTED_TUNNEL, e->child, where);
			return;
		case X(ESTABLISH_INBOUND, UNROUTED, LABELED_CHILD):
			set_routing(event, c, RT_UNROUTED_INBOUND, e->child, where);
			return;
		case X(ESTABLISH_OUTBOUND, UNROUTED_INBOUND, LABELED_CHILD):
			set_established_child(event, c, RT_UNROUTED_TUNNEL, e->child, where);
			return;
		case X(UNROUTE, UNROUTED_INBOUND, LABELED_CHILD):
		case X(UNROUTE, UNROUTED_TUNNEL, LABELED_CHILD):
#if 0
			/* currently done by caller */
			delete_child_sa(e->child);
#endif
			set_routing(event, c, RT_UNROUTED, NULL, where);
			return;
		case X(UNROUTE, UNROUTED, LABELED_CHILD):
			ldbg_routing(logger, "already unrouted");
			return;
		case X(DELETE_CHILD, UNROUTED_INBOUND, LABELED_CHILD):
		case X(DELETE_CHILD, UNROUTED_TUNNEL, LABELED_CHILD):
			delete_child_sa(e->child);
			set_routing(event, c, RT_UNROUTED, NULL, where);
			return;

		}
	}

	BARF_JAMBUF((DBGP(DBG_BASE) ? PASSERT_FLAGS : PEXPECT_FLAGS),
		    c->logger, /*ignore-exit-code*/0, where, buf) {
		jam_string(buf, "routing: unhandled ");
		jam_event(buf, event, c, e);
	}
}

void dispatch(enum routing_event event,
	      struct connection **cp,
	      struct logger *logger, where_t where,
	      struct routing_annex ee)
{
	struct connection *c = connection_addref_where(*cp, logger, HERE);

#if 0
	/*
	 * This isn't true for ONDEMAND when the connection is being
	 * (re) attached to an existing IKE SA.
	 *
	 * For instance:
	 *
	 *   - permanent ike+child establish
	 *   - large pings trigger hard expire of child, and then
	 *   - ondemand request
	 *
	 * because the connection is permanent the IKE SA is set, but
	 * ondemand doesn't think to pass in the existing IKE (and nor
	 * should it?).
	 *
	 * See ikev2-expire-03-bytes-ignore-soft
	 */
	PEXPECT(logger, ((*c)->newest_ike_sa == SOS_NOBODY ||
			 (e->ike != NULL &&
			  (*e->ike)->sa.st_serialno == (*c)->newest_ike_sa)));
#endif
#if 0
	/*
	 * This isn't true when the child transitions from UNROUTED
	 * NEGOTIATION to UNROUTED INBOUND, say.
	 *
	 * When there's a Child SA it must match the routing SA, but
	 * not the reverse.
	 *
	 * For instance, a second acquire while a permanent connection
	 * is still negotiating could find that there's an existing
	 * routing SA.
	 */
	if (e->child != NULL &&
	    (*e->child)->sa.st_serialno != (*c)->newest_routing_sa) {
		LLOG_PEXPECT_JAMBUF(logger, where, buf) {
			jam_string(buf, "Child SA ");
			jam_so(buf, (*e->child)->sa.st_serialno);
			jam_string(buf, " does not match routing SA ");
			jam_so(buf, (*c)->newest_routing_sa);
			jam_string(buf, " ");
			jam_event(buf, event, c, e);
		}
	}
#endif

	struct old_routing old = ldbg_routing_start(c, event, where, &ee);
	dispatch_1(event, c, logger, where, &ee);
	ldbg_routing_stop(c, event, where,&ee, &old);

	connection_delref_where(&c, c->logger, HERE);
}
