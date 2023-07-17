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

static const char *routing_event_name[] = {
#define S(E) [E] = #E
	S(CONNECTION_ROUTE),
	S(CONNECTION_UNROUTE),
	S(CONNECTION_INITIATE),
	S(CONNECTION_TERMINATE),
	S(CONNECTION_ACQUIRE),
	S(CONNECTION_REVIVE),
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
	0, CONNECTION_EVENT_ROOF-1,
	ARRAY_REF(routing_event_name),
	"CONNECTION_",
	NULL,
};

struct annex {
	struct ike_sa **ike;
	struct child_sa **child;
	const threadtime_t *const inception;
	ip_packet packet;
	bool background;
	shunk_t sec_label;
};

static bool zap_connection_states(enum routing_event event,
				  struct connection **c,
				  struct ike_sa **ike,
				  where_t where);

static void dispatch(const enum routing_event event,
		     struct connection **c,
		     struct logger *logger, where_t where,
		     struct annex e);

static void jam_event_sa(struct jambuf *buf, struct state *st)
{
	const struct connection *c = st->st_connection;
	jam_string(buf, "; ");
	enum sa_type sa_type = st->st_sa_type_when_established;
	jam_string(buf, sa_name(c->config->ike_version, sa_type));
	jam_string(buf, " ");
	jam_so(buf, st->st_serialno);
	jam_string(buf, " ");
	jam_string(buf, st->st_state->short_name);
}

static void jam_routing(struct jambuf *buf,
			struct connection **c)
{
	if (*c == NULL) {
		jam_string(buf, "EXPECTATION FAILED: C is NULL");
		return;
	}
	jam_enum_short(buf, &routing_names, (*c)->child.routing);
	jam_string(buf, " ");
	jam_enum_short(buf, &connection_kind_names, (*c)->local->kind);
	jam_string(buf, " ");
	jam_connection_co(buf, *c);
	if (never_negotiate(*c)) {
		jam_string(buf, " never-negotiate");
	}
	if ((*c)->child.newest_routing_sa != SOS_NOBODY) {
		jam_string(buf, " routing");
		jam_so(buf, (*c)->child.newest_routing_sa);
	}
	if ((*c)->newest_ipsec_sa != SOS_NOBODY) {
		jam_string(buf, " IPsec");
		jam_so(buf, (*c)->newest_ipsec_sa);
	}
	if ((*c)->newest_ike_sa != SOS_NOBODY) {
		jam_string(buf, " IKE");
		jam_so(buf, (*c)->newest_ike_sa);
	}
}

static void jam_annex(struct jambuf *buf, const struct annex *e)
{
	if (e->ike != NULL) {
		jam_event_sa(buf, &(*e->ike)->sa);
	}
	if (e->child != NULL) {
		jam_event_sa(buf, &(*e->child)->sa);
	}
	if (e->sec_label.len > 0) {
		jam_string(buf, ", sec_label=");
		jam_shunk(buf, e->sec_label);
	}
}

static void jam_event(struct jambuf *buf,
		      enum routing_event event,
		      struct connection **c,
		      const struct annex *e)
{
	jam_enum_short(buf, &routing_event_names, event);
	jam_string(buf, " to ");
	jam_routing(buf, c);
	jam_annex(buf, e);
}

static void ldbg_dispatch(struct logger *logger,
			  enum routing_event event,
			  struct connection **c,
			  where_t where, const struct annex *e)
{
	if (DBGP(DBG_BASE)) {
		/*
		 * XXX: force ADD_PREFIX so that the connection name
		 * is before the interesting stuff.
		 */
		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
			jam_string(buf, "routing: dispatch ");
			jam_event(buf, event, c, e);
			jam_string(buf, " ");
			jam_where(buf, where);
		}
	}
}

PRINTF_LIKE(2)
static void ldbg_routing(struct logger *logger, const char *fmt, ...)
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

void fake_connection_establish_inbound(struct ike_sa *ike, struct child_sa *child,
				       where_t where)
{
	struct connection *cc = child->sa.st_connection;
	dispatch(CONNECTION_ESTABLISH_INBOUND, &cc,
		 child->sa.st_logger, where,
		 (struct annex) {
			 .ike = &ike,
			 .child = &child,
		 });
}

void fake_connection_establish_outbound(struct ike_sa *ike, struct child_sa *child,
					where_t where)
{
	struct connection *cc = child->sa.st_connection;
	dispatch(CONNECTION_ESTABLISH_OUTBOUND, &cc,
		 child->sa.st_logger, where,
		 (struct annex) {
			 .ike = &ike,
			 .child = &child,
		 });
}

enum shunt_kind routing_shunt_kind(enum routing routing)
{
	switch (routing) {
	case RT_ROUTED_REVIVAL:
	case RT_UNROUTED_ONDEMAND:
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
	case RT_UNROUTED_REVIVAL:
		bad_case(routing);
	}
	bad_case(routing);
}

bool routed(const struct connection *c)
{
	enum routing r = c->child.routing;
	switch (r) {
	case RT_ROUTED_REVIVAL:
	case RT_ROUTED_ONDEMAND:
	case RT_ROUTED_NEVER_NEGOTIATE:
	case RT_ROUTED_NEGOTIATION:
	case RT_ROUTED_INBOUND:
	case RT_ROUTED_TUNNEL:
	case RT_ROUTED_FAILURE:
		return true;
	case RT_UNROUTED:
	case RT_UNROUTED_REVIVAL:
	case RT_UNROUTED_ONDEMAND:
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
	case RT_UNROUTED_REVIVAL:
	case RT_UNROUTED_NEGOTIATION:
		return false;
	case RT_UNROUTED_ONDEMAND:
	case RT_ROUTED_ONDEMAND:
	case RT_ROUTED_REVIVAL:
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
		 const struct child_sa *child,
		 where_t where)
{
	struct logger *logger = (child == NULL ? c->logger :
				 child->sa.st_logger);
	so_serial_t new_routing_sa = (child == NULL ? SOS_NOBODY :
				      child->sa.st_serialno);
	if (DBGP(DBG_BASE)) {
		/*
		 * XXX: force ADD_PREFIX so that the connection name
		 * is before the interesting stuff.
		 */
		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, logger, buf) {
			jam_string(buf, "routing: change ");
			jam_enum_short(buf, &routing_event_names, event);
			jam_string(buf, " -> ");
			jam_routing(buf, &c);
			jam_string(buf, " -> ");
			jam_enum_short(buf, &routing_names, new_routing);
			jam_string(buf, " ");
			jam_so(buf, new_routing_sa);
			jam_string(buf, " ");
			jam_where(buf, where);
		}
	}

	/*
	 * Labed children are never routed and/or have a kernel
	 * policy.  Instead the kernel deals with the policy, and the
	 * template/parent owns the route.
	 */
	PEXPECT(logger, !is_labeled_child(c));
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
		PEXPECT(c->logger, new_routing_sa >= c->child.newest_routing_sa);
		PEXPECT(c->logger, new_routing_sa >= c->newest_ipsec_sa);
	}
#endif
	c->child.routing = new_routing;
	c->child.newest_routing_sa = new_routing_sa;
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
			 event == CONNECTION_ACQUIRE ||
			 event == CONNECTION_REVIVE));
	enum routing rt_negotiation = (c->child.routing == RT_ROUTED_ONDEMAND ? RT_ROUTED_NEGOTIATION :
				       c->child.routing == RT_ROUTED_REVIVAL ? RT_ROUTED_NEGOTIATION :
				       c->child.routing == RT_UNROUTED_ONDEMAND ? RT_UNROUTED_NEGOTIATION :
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

static void negotiation_to_ondemand(enum routing_event event,
				    struct connection *c,
				    struct logger *logger,
				    where_t where,
				    const char *reason)
{
	ldbg_routing(c->logger, "%s() %s", __func__, reason);
	PASSERT(logger, (event == CONNECTION_TIMEOUT_IKE ||
			 event == CONNECTION_DELETE_IKE));
	enum routing rt_ondemand = (c->child.routing == RT_ROUTED_NEGOTIATION ? RT_ROUTED_ONDEMAND :
				    c->child.routing == RT_UNROUTED_NEGOTIATION ? RT_UNROUTED_ONDEMAND :
				    CONNECTION_ROUTING_ROOF);
	PASSERT(logger, rt_ondemand != CONNECTION_ROUTING_ROOF);
	FOR_EACH_ITEM(spd, &c->child.spds) {
		if (!replace_spd_kernel_policy(spd, DIRECTION_OUTBOUND,
					       rt_ondemand,
					       SHUNT_KIND_ONDEMAND,
					       logger, where, reason)) {
			llog(RC_LOG, logger, "%s failed", reason);
		}
	}
	set_routing(event, c, rt_ondemand, NULL, where);
}

void connection_initiate(struct connection *c, const threadtime_t *inception,
			 bool background, where_t where)
{
	if (c->config->ike_version == IKEv1) {
		ipsecdoi_initiate(c, c->policy, SOS_NOBODY, inception,
				  HUNK_AS_SHUNK(c->child.sec_label),
				  background, c->logger);
		return;
	}

	dispatch(CONNECTION_INITIATE, &c,
		 c->logger, where,
		 (struct annex) {
			 .inception = inception,
			 .background = background,
		 });
}

void connection_terminate(struct connection **c, struct logger *logger, where_t where)
{
	dispatch(CONNECTION_TERMINATE, c,
		 logger, where,
		 (struct annex) {0});
}

void connection_acquire(struct connection *c, threadtime_t *inception,
			const struct kernel_acquire *b, where_t where)
{
	dispatch(CONNECTION_ACQUIRE, &c,
		 b->logger, where,
		 (struct annex) {
			 .inception = inception,
			 .background = b->background,
			 .sec_label = b->sec_label,
			 .packet = b->packet,
		 });
}

void connection_revive(struct connection *c, const threadtime_t *inception, where_t where)
{
	if (c->config->ike_version == IKEv1 && is_labeled(c)) {
		initiate_connection(c, /*remote-host-name*/NULL,
				    /*background*/true,
				    c->logger);
		return;
	}

	dispatch(CONNECTION_REVIVE, &c,
		 c->logger, where,
		 (struct annex) {
			 .inception = inception,
			 .background = true,
		 });
}

/*
 * Delete the ROUTED_TUNNEL, and possibly delete the connection.
 */

static void down_routed_tunnel(enum routing_event event,
			       struct connection **c,
			       struct ike_sa *ike,
			       struct child_sa **child,
			       where_t where)
{
	PASSERT((*child)->sa.st_logger, *c == (*child)->sa.st_connection);

	if ((*c)->child.newest_routing_sa > (*child)->sa.st_serialno) {
		/* no longer child's */
		ldbg_routing((*child)->sa.st_logger,
			     "keeping connection kernel policy; routing SA "PRI_SO" is newer",
			     pri_so((*c)->child.newest_routing_sa));
		delete_child_sa(child);
		return;
	}

	if ((*c)->newest_ipsec_sa > (*child)->sa.st_serialno) {
		/* covered by above; no!? */
		ldbg_routing((*child)->sa.st_logger,
			     "keeping connection kernel policy; IPsec SA "PRI_SO" is newer",
			     pri_so((*c)->newest_ipsec_sa));
		delete_child_sa(child);
		return;
	}

	if (should_revive_child(*child)) {
		ldbg_routing((*child)->sa.st_logger,
			     "replacing TUNNEL with ONDEMAND; it will be revived");
		replace_ipsec_with_bare_kernel_policies(event, *child,
							RT_ROUTED_REVIVAL,
							EXPECT_KERNEL_POLICY_OK, HERE);
		schedule_child_revival(ike, *child, "received Delete/Notify");
		/* covered by above; no!? */
		delete_child_sa(child);
		return;
	}

	/*
	 * Should this go back to on-demand?
	 */
	if (is_permanent(*c) && (*c)->policy & POLICY_ROUTE) {
		ldbg_routing((*child)->sa.st_logger,
			     "replacing connection kernel policy with on-demand");
		replace_ipsec_with_bare_kernel_policies(event, *child,
							RT_ROUTED_ONDEMAND,
							EXPECT_KERNEL_POLICY_OK, HERE);
		delete_child_sa(child);
		return;
	}

	/*
	 * Is there a failure shunt?
	 */
	if (is_permanent(*c) && (*c)->config->failure_shunt != SHUNT_NONE) {
		ldbg_routing((*child)->sa.st_logger,
			     "replacing connection kernel policy with failure");
		replace_ipsec_with_bare_kernel_policies(event, *child,
							RT_ROUTED_FAILURE,
							EXPECT_KERNEL_POLICY_OK, HERE);
		delete_child_sa(child);
		return;
	}

	/*
	 * Never delete permanent connections.
	 */
	if (is_permanent(*c)) {
		ldbg_routing((*child)->sa.st_logger,
			     "keeping connection; it is permanent");
		do_updown_spds(UPDOWN_DOWN, *c, &(*c)->child.spds, &(*child)->sa,
			       (*child)->sa.st_logger);
		delete_spd_kernel_policies(&(*c)->child.spds,
					   EXPECT_KERNEL_POLICY_OK,
					   (*child)->sa.st_logger,
					   where, "delete");
		/*
		 * update routing; route_owner() will see this and not
		 * think this route is the owner?
		 */
		set_routing(event, *c, RT_UNROUTED, NULL, HERE);
		do_updown_unroute(*c, *child);
		delete_child_sa(child);
		return;
	}

	PASSERT((*child)->sa.st_logger, is_instance(*c));

	delete_spd_kernel_policies(&(*c)->child.spds,
				   EXPECT_KERNEL_POLICY_OK,
				   (*child)->sa.st_logger,
				   where, "delete");
	set_routing(event, *c, RT_UNROUTED, NULL, where);

	/*
	 * If the Child SA's IKE SA is also using the connection don't
	 * delete it.
	 */
	if ((*c)->newest_ike_sa == (*child)->sa.st_clonedfrom) {
		ldbg_routing((*child)->sa.st_logger,
			     "keeping connection; shared with IKE SA "PRI_SO,
			     pri_so((*c)->newest_ike_sa));
		delete_child_sa(child);
		return;
	}

	ldbg_routing((*child)->sa.st_logger, "keeping connection; NO!");
	delete_child_sa(child);

	remove_connection_from_pending(*c);
	delete_states_by_connection(*c);
	connection_unroute(*c, HERE);

	delete_connection(c);
}

/*
 * Strip a connection of all states.
 */

static bool zap_connection_states(enum routing_event event,
				  struct connection **c,
				  struct ike_sa **ike,
				  where_t where)
{
	PASSERT((*ike)->sa.st_logger, *c == (*ike)->sa.st_connection);
	PASSERT((*ike)->sa.st_logger, (event == CONNECTION_TIMEOUT_IKE ||
				       event == CONNECTION_DELETE_IKE));
	enum routing_event child_event = (event == CONNECTION_TIMEOUT_IKE ? CONNECTION_TIMEOUT_CHILD :
					  event == CONNECTION_DELETE_IKE ? CONNECTION_DELETE_CHILD :
					  CONNECTION_EVENT_ROOF);
	PASSERT((*ike)->sa.st_logger, child_event != CONNECTION_EVENT_ROOF);

	/*
	 * Stop reviving children trying to use this IKE SA.
	 */
	enum_buf ren;
	ldbg_routing((*ike)->sa.st_logger, "due to %s, IKE SA is no longer viable",
		     str_enum_short(&routing_event_names, event, &ren));
	(*ike)->sa.st_viable_parent = false;

	/*
	 * Weed out any lurking larval children that are sharing this
	 * IKE SA (i.e., children that are part way through an
	 * IKE_AUTH or CREATE_CHILD_SA exchange and don't yet own
	 * their connection's route).
	 */

	{
		struct state_filter larval_filter = {
			.ike = *ike,
			.where = HERE,
		};
		while (next_state_new2old(&larval_filter)) {
			struct child_sa *child = pexpect_child_sa(larval_filter.st);
			if (child->sa.st_connection->child.newest_routing_sa ==
			    child->sa.st_serialno) {
				continue;
			}
			/*
			 * The death of a larval child is never logged
			 * by delete_state().  Do it here, but only
			 * when the IKE SA is established (larval
			 * child of larval ike is hidden).
			 */
			if (IS_IKE_SA_ESTABLISHED(&(*ike)->sa)) {
				state_attach(&child->sa, (*ike)->sa.st_logger);
				enum_buf ren;
				llog_sa(RC_LOG, child, "deleting larval %s (%s)",
					child->sa.st_connection->config->ike_info->child_sa_name,
					str_enum_short(&routing_event_names, event, &ren));
			} else {
				ldbg_routing(child->sa.st_logger, "deleting larval %s (%s)",
					     child->sa.st_connection->config->ike_info->child_sa_name,
					     str_enum_short(&routing_event_names, event, &ren));
			}
			delete_child_sa(&child);
		}
	}

	/*
	 * If the IKE SA's connection has a direct Child SA (shares
	 * connection) that owns the route then send a delete/timeout
	 * to that Child SA first.
	 *
	 * This way the IKE SA's connection can jump to the front of
	 * the revival queue (without this an IKE SA with multiple
	 * children ends up with its chilren sqabbling over which SA
	 * should be revived first).
	 *
	 * Also remember if there was a direct child.  The event only
	 * gets dispatched to the IKE SA when there wasn't a child
	 * (such as during IKE_SA_INIT).
	 */

	bool dispatched_to_child;
	struct child_sa *connection_child =
		child_sa_by_serialno((*ike)->sa.st_connection->child.newest_routing_sa);
	if (connection_child == NULL) {
		dispatched_to_child = false;
		ldbg_routing((*ike)->sa.st_logger, "IKE SA's connection has no Child SA "PRI_SO,
			     pri_so((*ike)->sa.st_connection->child.newest_routing_sa));
	} else if (connection_child->sa.st_clonedfrom != (*ike)->sa.st_serialno) {
		dispatched_to_child = false;
		ldbg_routing((*ike)->sa.st_logger, "IKE SA is not the parent of the connection's Child SA "PRI_SO,
			     pri_so(connection_child->sa.st_serialno));
	} else if (connection_child != NULL) {
		dispatched_to_child = true;
		state_attach(&connection_child->sa, (*ike)->sa.st_logger);
		/* will delete child and its logger */
		struct connection *cc = connection_child->sa.st_connection;
		dispatch(child_event, &cc,
			 connection_child->sa.st_logger, where,
			 (struct annex) {
				 .ike = ike,
				 .child = &connection_child,
			 });
		PEXPECT((*ike)->sa.st_logger, connection_child == NULL); /*gone!*/
		PEXPECT((*ike)->sa.st_logger, (*ike)->sa.st_connection->child.newest_routing_sa == SOS_NOBODY);
	}

	/*
	 * Now go through any remaining children.
	 *
	 * This could include children of the first IKE SA that are
	 * been replaced.
	 */

	{
		struct state_filter child_filter = {
			.ike = *ike,
			.where = HERE,
		};
		while (next_state_new2old(&child_filter)) {
			struct child_sa *child = pexpect_child_sa(child_filter.st);
			if (!PEXPECT((*ike)->sa.st_logger,
				     child->sa.st_connection->child.newest_routing_sa ==
				     child->sa.st_serialno)) {
				continue;
			}
			/* will delete child and its logger */
			state_attach(&child->sa, (*ike)->sa.st_logger);
			struct connection *cc = child->sa.st_connection;
			dispatch(child_event, &cc,
				 child->sa.st_logger, where,
				 (struct annex) {
					 .ike = ike,
					 .child = &child,
				 });
			PEXPECT((*ike)->sa.st_logger, child == NULL);
		}
	}

	/*
	 * With everything cleaned up decide what to do with the IKE
	 * SA.
	 */

	if (dispatched_to_child) {
		/*
		 * The connection had a direct and established Child
		 * SA and that was notified.  Presumably that also
		 * handled things like revival and updating the
		 * connection's routing.
		 *
		 * The IKE SA can simply be deleted ...
		 */
		delete_ike_sa(ike);
		/*
		 * ... and if the connection is an instance and was
		 * unrouted then it can be deleted as well
		 * (alternatives include being revived).
		 */
		if (is_instance(*c) &&
		    (*c)->child.routing == RT_UNROUTED) {

			remove_connection_from_pending(*c);
			delete_states_by_connection(*c);
			connection_unroute(*c, HERE);

			delete_connection(c);
		}
		return true;
	}

	if (connection_child != NULL) {
		/*
		 * The connection has a Child SA that is NOT the IKE
		 * SA's child.  For instance, the Child SA has being
		 * migrated to a new IKE SA.
		 *
		 * XXX: suspect it would be easier to just compare the
		 * IKE SA against the connection's .newest_ike_sa as -
		 * reparenting the Child SA should have updated that
		 * field to the newer IKE SA as well.
		 */
		PEXPECT((*ike)->sa.st_logger, (connection_child->sa.st_clonedfrom !=
					       (*ike)->sa.st_serialno));
		delete_ike_sa(ike);
		return true;
	}

	/*
	 * ... otherwize caller gets to:
	 *
	 * - delete the IKE SA
	 *
	 * - update the connectin's routing
	 *
	 * This code could handle this if it weren't for the more
	 * complicated routing changes that are needed.
	 */
	return false;
}

/*
 * zap (unroute) any instances of the connection; for instance when an
 * unrouted template gets instantiated using whack.
 */

static bool unroute_connection_instances(enum routing_event event, struct connection *c, where_t where)
{
	enum_buf ren;
	ldbg_routing(c->logger, "due to %s, zapping instances",
		     str_enum_short(&routing_event_names, event, &ren));
	PASSERT(c->logger, is_template(c));

	struct connection_filter cq = {
		.clonedfrom = c,
		.where = HERE,
	};
	bool had_instances;
	while (next_connection_old2new(&cq)) {
		had_instances = true;
		connection_buf cqb;
		ldbg_routing(c->logger, "zapping instance "PRI_CONNECTION,
			     pri_connection(cq.c, &cqb));
		dispatch(CONNECTION_UNROUTE, &cq.c, cq.c->logger, where,
			 (struct annex) {
				 0,
			 });
		/* unroute doesn't delete instances, should it? */

		remove_connection_from_pending(cq.c);
		delete_states_by_connection(cq.c);
		connection_unroute(cq.c, HERE);

		delete_connection(&cq.c);
	}
	return had_instances;
}

void connection_route(struct connection *c, where_t where)
{
	if (!oriented(c)) {
		llog(RC_ORIENT, c->logger,
		     "we cannot identify ourselves with either end of this connection");
		return;
	}

	dispatch(CONNECTION_ROUTE, &c, c->logger, where,
		 (struct annex) {
			 0,
		 });

}

void connection_unroute(struct connection *c, where_t where)
{
	/*
	 * XXX: strip POLICY_ROUTE in whack code, not here (code
	 * expects to be able to route/unroute without loosing the
	 * policy bits).
	 */
	dispatch(CONNECTION_UNROUTE, &c,
		 c->logger, where,
		 (struct annex) {
			 0,
		 });
}

/*
 * Received a message telling us to delete the connection's Child.SA.
 */

void connection_delete_child(struct ike_sa *ike, struct child_sa **child, where_t where)
{
	struct connection *c = (*child)->sa.st_connection;
	if ((*child)->sa.st_serialno == c->child.newest_routing_sa) {
		/*
		 * Caller is responsible for generating any messages; suppress
		 * delete_state()'s desire to send an out-of-band delete.
		 */
		(*child)->sa.st_on_delete.skip_send_delete = true;
		(*child)->sa.st_on_delete.skip_revival = true;
		(*child)->sa.st_on_delete.skip_connection = true;
		/*
		 * Let state machine figure out how to react.
		 */
		struct connection *cc = (*child)->sa.st_connection;
		dispatch(CONNECTION_DELETE_CHILD, &cc,
			 (*child)->sa.st_logger, where,
			 (struct annex) {
				 .ike = &ike,
				 .child = child,
			 });
		/* no logger as no child */
		pexpect(*child == NULL);
	} else {
		struct connection *c = (*child)->sa.st_connection;
		state_attach(&(*child)->sa, ike->sa.st_logger);
		delete_child_sa(child);
		if (is_labeled_child(c)) {

			remove_connection_from_pending(c);
			delete_states_by_connection(c);
			connection_unroute(c, HERE);

			delete_connection(&c);
		}
	}
}

void connection_timeout_ike(struct ike_sa **ike, where_t where)
{
	pstat_sa_failed(&(*ike)->sa, REASON_TOO_MANY_RETRANSMITS);

	struct connection *c = (*ike)->sa.st_connection;
	dispatch(CONNECTION_TIMEOUT_IKE, &c,
		 (*ike)->sa.st_logger, where,
		 (struct annex) {
			 .ike = ike,
		 });
}

void connection_delete_ike(struct ike_sa **ike, where_t where)
{
	struct connection *c = (*ike)->sa.st_connection;

	if (c->config->ike_version == IKEv1 && is_labeled(c)) {
		delete_ike_family(ike);
		return;
	}

	dispatch(CONNECTION_DELETE_IKE, &c,
		 (*ike)->sa.st_logger, where,
		 (struct annex) {
			 .ike = ike,
		 });
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
		 (struct annex) {
			 .child = &child,
		 });
}

void connection_resume(struct child_sa *child, where_t where)
{
	struct connection *cc = child->sa.st_connection;
	dispatch(CONNECTION_RESUME, &cc,
		 child->sa.st_logger, where,
		 (struct annex) {
			 .child = &child,
		 });
}

void dispatch(enum routing_event event,
	      struct connection **c,
	      struct logger *logger, where_t where,
	      struct annex ee)
{
	struct annex *e = &ee;
	ldbg_dispatch(logger, event, c, where, e);

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
	    (*e->child)->sa.st_serialno != (*c)->child.newest_routing_sa) {
		LLOG_PEXPECT_JAMBUF(logger, where, buf) {
			jam_string(buf, "Child SA ");
			jam_so(buf, (*e->child)->sa.st_serialno);
			jam_string(buf, " does not match routing SA ");
			jam_so(buf, (*c)->child.newest_routing_sa);
			jam_string(buf, " ");
			jam_event(buf, event, c, e);
		}
	}
#endif

#define XX(CONNECTION_EVENT, CONNECTION_ROUTING, CONNECTION_KIND)	\
	(((CONNECTION_EVENT) *						\
	  CONNECTION_ROUTING_ROOF + CONNECTION_ROUTING) *		\
	 CONNECTION_KIND_ROOF + CONNECTION_KIND)
#define X(EVENT, ROUTING, KIND)				\
	XX(CONNECTION_##EVENT, RT_##ROUTING, CK_##KIND)

	{
		const enum routing routing = (*c)->child.routing;
		const enum connection_kind kind = (*c)->local->kind;

		switch (XX(event, routing, kind)) {

		case X(ROUTE, UNROUTED, GROUP):
			/* caller deals with recursion */
			add_policy(*c, POLICY_ROUTE); /* always */
			return;
		case X(UNROUTE, UNROUTED, GROUP):
			/* ROUTE+UP cleared by caller */
			return;

		case X(ROUTE, UNROUTED, TEMPLATE):
		case X(ROUTE, UNROUTED, LABELED_TEMPLATE):
		case X(ROUTE, UNROUTED, PERMANENT):
			add_policy(*c, POLICY_ROUTE); /* always */
			if (never_negotiate(*c)) {
				if (!unrouted_to_routed_never_negotiate(event, *c, where)) {
					/* XXX: why whack only? */
					llog(WHACK_STREAM|RC_ROUTE, logger, "could not route");
					return;
				}
				PEXPECT(logger, (*c)->child.routing == RT_ROUTED_NEVER_NEGOTIATE);
			} else if (is_labeled_template(*c)) {
				if (!unrouted_to_routed_sec_label(event, *c, logger, where)) {
					/* XXX: why whack only? */
					llog(RC_ROUTE, logger, "could not route");
					return;
				}
				PEXPECT(logger, (*c)->child.routing == RT_ROUTED_ONDEMAND);
			} else {
				PEXPECT(logger, !is_labeled(*c));
				if (!unrouted_to_routed_ondemand(event, *c, where)) {
					/* XXX: why whack only? */
					llog(WHACK_STREAM|RC_ROUTE, logger, "could not route");
					return;
				}
				PEXPECT(logger, (*c)->child.routing == RT_ROUTED_ONDEMAND);
			}
			return;

		case X(UNROUTE, ROUTED_NEVER_NEGOTIATE, TEMPLATE):
		case X(UNROUTE, ROUTED_NEVER_NEGOTIATE, PERMANENT):
			PEXPECT(logger, never_negotiate(*c));
			delete_spd_kernel_policies(&(*c)->child.spds,
						   EXPECT_KERNEL_POLICY_OK,
						   (*c)->logger, where, "unroute permanent");
			/* stop updown_unroute() finding this
			 * connection */
			set_routing(event, *c, RT_UNROUTED, NULL, where);
			do_updown_unroute(*c, NULL);
			return;

		case X(UNROUTE, ROUTED_INBOUND, INSTANCE): /* xauth-pluto-25-lsw299 */
		case X(UNROUTE, ROUTED_INBOUND, PERMANENT): /* ikev1-xfrmi-02-aggr */
			if (BROKEN_TRANSITION) {
				/* ikev1-xfrmi-02-aggr ikev1-xfrmi-02
				 * ikev1-xfrmi-02-tcpdump */
				delete_spd_kernel_policies(&(*c)->child.spds,
							   EXPECT_KERNEL_POLICY_OK,
							   (*c)->logger, where, "unroute permanent");
				set_routing(event, *c, RT_UNROUTED, NULL, where);
				do_updown_unroute(*c, NULL);
				return;
			}
			break;

		case X(UNROUTE, ROUTED_INBOUND, TEMPLATE):
			if (BROKEN_TRANSITION) {
				/* xauth-pluto-25-lsw299
				 * xauth-pluto-25-mixed-addresspool */
				delete_spd_kernel_policies(&(*c)->child.spds,
							   EXPECT_KERNEL_POLICY_OK,
							   (*c)->logger, where, "unroute permanent");
				set_routing(event, *c, RT_UNROUTED, NULL, where);
				do_updown_unroute(*c, NULL);
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
				ipsecdoi_initiate(*c, (*c)->policy, SOS_NOBODY,
						  e->inception, null_shunk,
						  e->background, (*c)->logger);
				return;
			}
			break;

		case X(INITIATE, UNROUTED, PERMANENT):
		case X(INITIATE, UNROUTED_REVIVAL, PERMANENT):
			if ((*c)->child.routing == RT_UNROUTED_REVIVAL) {
				delete_revival(*c);
			}
			set_routing(event, *c, RT_UNROUTED_NEGOTIATION, NULL, where);
			ipsecdoi_initiate(*c, (*c)->policy, SOS_NOBODY,
					  e->inception, null_shunk,
					  e->background, (*c)->logger);
			return;

		case X(INITIATE, ROUTED_ONDEMAND, PERMANENT):
		case X(INITIATE, ROUTED_REVIVAL, PERMANENT):
		case X(ACQUIRE, ROUTED_ONDEMAND, PERMANENT):
		case X(ACQUIRE, ROUTED_REVIVAL, PERMANENT):
			if ((*c)->child.routing == RT_ROUTED_REVIVAL) {
				delete_revival(*c);
			}
			ondemand_to_negotiation(event, *c, where, "negotiating permanent");
			PEXPECT(logger, (*c)->child.routing == RT_ROUTED_NEGOTIATION);
			/* ipsecdoi_initiate may replace SOS_NOBODY with a state */
			ipsecdoi_initiate(*c, (*c)->policy, SOS_NOBODY,
					  e->inception, null_shunk,
					  e->background, (*c)->logger);
			return;

		case X(INITIATE, UNROUTED_NEGOTIATION, PERMANENT):
			if (BROKEN_TRANSITION) {
				/* ikev2-redirect-01-global-load-balancer
				 * ikev2-redirect-01-global
				 * ikev2-redirect-03-auth-loop
				 * ikev2-tcp-07-fail-ike-auth-redirect */
				ipsecdoi_initiate(*c, (*c)->policy, SOS_NOBODY,
						  e->inception, null_shunk,
						  e->background, logger);
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
				ipsecdoi_initiate(*c, (*c)->policy, SOS_NOBODY,
						  e->inception, null_shunk,
						  e->background, logger);
				return;
			}
			llog(RC_LOG, (*c)->logger, "connection already negotiating");
			return;
		case X(ACQUIRE, ROUTED_NEGOTIATION, PERMANENT):
			llog(RC_LOG, (*c)->logger, "connection already negotiating");
			return;

		case X(REVIVE, UNROUTED, INSTANCE):
			if (BROKEN_TRANSITION) {
				/*
				 * Ex ikev2-30-rw-no-rekey.
				 *
				 * ROAD in ROUTED_TUNNEL, receiving a
				 * delete message, transitions to
				 * UNROUTED when it should have
				 * transitioned to ROUTED_ONDEMAND?
				*/
				initiate_connection(*c, /*remote-host-name*/NULL,
						    /*background*/true,
						    logger);
				return;
			}
			ipsecdoi_initiate(*c, (*c)->policy, SOS_NOBODY,
					  e->inception, e->sec_label,
					  e->background, logger);
			return;
		case X(REVIVE, UNROUTED_REVIVAL, PERMANENT):
			if (BROKEN_TRANSITION) {
				/*
				 * Same as INITIATE, UNROUTED_REVIVAL,
				 * PERMANENT except slight initiate
				 * difference.
				 */
				set_routing(event, *c, RT_UNROUTED_NEGOTIATION, NULL, where);
				ipsecdoi_initiate(*c, (*c)->policy, SOS_NOBODY, e->inception,
						  null_shunk, /*background*/false, logger);
				return;
			}
			break;
		case X(REVIVE, UNROUTED_ONDEMAND, PERMANENT):
		case X(REVIVE, UNROUTED_ONDEMAND, INSTANCE):
			ondemand_to_negotiation(event, *c, where, "negotiating unrouted");
			PEXPECT(logger, (*c)->child.routing == RT_UNROUTED_NEGOTIATION);
			ipsecdoi_initiate(*c, (*c)->policy, SOS_NOBODY, e->inception,
					  null_shunk, /*background*/false, logger);
			return;
		case X(REVIVE, ROUTED_ONDEMAND, PERMANENT):
		case X(REVIVE, ROUTED_REVIVAL, PERMANENT):
		case X(REVIVE, ROUTED_ONDEMAND, INSTANCE):
		case X(REVIVE, ROUTED_REVIVAL, INSTANCE):
			if (BROKEN_TRANSITION) {
				/*
				 * ikev2-20-ikesa-reauth:
				 *
				 * The re-auth code still calls
				 * delete_ike_family().
				 *
				 * others?
				 */
				if ((*c)->config->negotiation_shunt == SHUNT_HOLD) {
					ldbg_routing((*c)->logger, "skipping NEGOTIATION=HOLD");
					set_routing(event, *c, RT_ROUTED_NEGOTIATION, NULL, where);
					/* ipsecdoi_initiate may replace SOS_NOBODY with a state */
					ipsecdoi_initiate(*c, (*c)->policy, SOS_NOBODY,
							  e->inception, null_shunk,
							  e->background, (*c)->logger);
					return;
				}
				ondemand_to_negotiation(event, *c, where, "negotiating revival");
				PEXPECT(logger, (*c)->child.routing == RT_ROUTED_NEGOTIATION);
				ipsecdoi_initiate(*c, (*c)->policy, SOS_NOBODY, e->inception,
						  null_shunk, /*background*/false, logger);
				return;
			}
			break;

		case X(REVIVE, UNROUTED_NEGOTIATION, INSTANCE):
			if (BROKEN_TRANSITION) {
				/* ikev2-redirect-01-global
				 * ikev2-redirect-02-auth
				 * ikev2-redirect-03-auth-loop
				 * ikev2-tcp-05-transport-mode
				 * ikev2-tcp-06-fail-ike-sa-init-redirect
				 * ikev2-tcp-07-fail-ike-auth-redirect */
				ipsecdoi_initiate(*c, (*c)->policy, SOS_NOBODY, e->inception,
						  null_shunk, /*background*/false, logger);
				return;
			}
			break;
		case X(REVIVE, ROUTED_NEGOTIATION, INSTANCE):
			if (BROKEN_TRANSITION) {
				/* ikev2-32-nat-rw-rekey
				 * ikev2-liveness-05 ikev2-liveness-07
				 * ikev2-liveness-08 */
				ipsecdoi_initiate(*c, (*c)->policy, SOS_NOBODY, e->inception,
						  null_shunk, /*background*/false, logger);
				return;
			}
			break;
		case X(REVIVE, UNROUTED_NEGOTIATION, PERMANENT):
			if (BROKEN_TRANSITION) {
				/* ikev2-x509-31-wifi-assist */
				ipsecdoi_initiate(*c, (*c)->policy, SOS_NOBODY, e->inception,
						  null_shunk, /*background*/false, logger);
				return;
			}
			break;
		case X(REVIVE, ROUTED_TUNNEL, PERMANENT):
			if (BROKEN_TRANSITION) {
				/* ikev2-59-multiple-acquires-alias. */
				ipsecdoi_initiate(*c, (*c)->policy, SOS_NOBODY, e->inception,
						  null_shunk, /*background*/false, logger);
				return;
			}
			break;

		case X(ROUTE, UNROUTED_NEGOTIATION, PERMANENT):
			if (BROKEN_TRANSITION) {
				/*
				 * XXX: should install routing+policy!
				 */
				add_policy(*c, POLICY_ROUTE);
				llog(RC_LOG_SERIOUS, logger,
				     "policy ROUTE added to negotiating connection");
				return;
			}
			break;
		case X(UNROUTE, UNROUTED_NEGOTIATION, PERMANENT):
		case X(UNROUTE, UNROUTED_REVIVAL, PERMANENT):
			if ((*c)->child.routing == RT_UNROUTED_REVIVAL) {
				delete_revival(*c);
			}
			set_routing(event, *c, RT_UNROUTED, NULL, where);
			return;

		case X(ROUTE, ROUTED_NEGOTIATION, PERMANENT):
			add_policy(*c, POLICY_ROUTE);
			llog(RC_LOG_SERIOUS, logger, "connection already routed");
			return;
		case X(UNROUTE, ROUTED_NEGOTIATION, PERMANENT):
			delete_spd_kernel_policies(&(*c)->child.spds, EXPECT_NO_INBOUND,
						   (*c)->logger, where, "unroute permanent");
			/* do now so route_owner won't find us */
			set_routing(event, *c, RT_UNROUTED, NULL, where);
			do_updown_unroute(*c, NULL);
			return;

		case X(UNROUTE, ROUTED_ONDEMAND, PERMANENT):
		case X(UNROUTE, ROUTED_REVIVAL, PERMANENT):
			PEXPECT(logger, !never_negotiate(*c));
			if ((*c)->child.routing == RT_ROUTED_REVIVAL) {
				delete_revival(*c);
			}
			delete_spd_kernel_policies(&(*c)->child.spds,
						   EXPECT_NO_INBOUND,
						   (*c)->logger, where, "unroute permanent");
			/* stop updown_unroute() finding this
			 * connection */
			set_routing(event, *c, RT_UNROUTED, NULL, where);
			do_updown_unroute(*c, NULL);
			return;
		case X(UNROUTE, UNROUTED_ONDEMAND, PERMANENT):
			if (BROKEN_TRANSITION) {
				PEXPECT(logger, !never_negotiate(*c));
				delete_spd_kernel_policies(&(*c)->child.spds,
							   EXPECT_NO_INBOUND,
							   (*c)->logger, where, "unroute permanent");
				/* stop updown_unroute() finding this
				 * connection */
				set_routing(event, *c, RT_UNROUTED, NULL, where);
				return;
			}
			break;

		case X(ROUTE, ROUTED_TUNNEL, PERMANENT):
			add_policy(*c, POLICY_ROUTE); /* always */
			llog(RC_LOG, logger, "policy ROUTE added to established connection");
			return;
		case X(UNROUTE, ROUTED_TUNNEL, PERMANENT):
			llog(RC_RTBUSY, logger, "cannot unroute: route busy");
			return;

		case X(UNROUTE, ROUTED_FAILURE, PERMANENT):
			delete_spd_kernel_policies(&(*c)->child.spds, EXPECT_NO_INBOUND,
						   (*c)->logger, where, "unroute permanent");
			/* do now so route_owner won't find us */
			set_routing(event, *c, RT_UNROUTED, NULL, where);
			do_updown_unroute(*c, NULL);
			return;

		case X(UNROUTE, UNROUTED_TUNNEL, PERMANENT):
			delete_spd_kernel_policies(&(*c)->child.spds, EXPECT_NO_INBOUND,
						   (*c)->logger, where, "unroute permanent");
			set_routing(event, *c, RT_UNROUTED, NULL, where);
			return;

		case X(UNROUTE, UNROUTED, TEMPLATE):
		case X(UNROUTE, UNROUTED, LABELED_TEMPLATE):
			if (unroute_connection_instances(event, *c, where)) {
				return;
			}
			ldbg_routing(logger, "already unrouted");
			return;
		case X(UNROUTE, ROUTED_ONDEMAND, LABELED_TEMPLATE):
		case X(UNROUTE, ROUTED_ONDEMAND, TEMPLATE):
		case X(UNROUTE, ROUTED_REVIVAL, TEMPLATE):
			if ((*c)->child.routing == RT_ROUTED_REVIVAL) {
				delete_revival(*c);
			}
			unroute_connection_instances(event, *c, where);
			delete_spd_kernel_policies(&(*c)->child.spds, EXPECT_NO_INBOUND,
						   (*c)->logger, where, "unroute template");
			/* do now so route_owner won't find us */
			set_routing(event, *c, RT_UNROUTED, NULL, where);
			do_updown_unroute(*c, NULL);
			return;

		case X(UNROUTE, UNROUTED, INSTANCE):
		case X(UNROUTE, UNROUTED, LABELED_CHILD):
		case X(UNROUTE, UNROUTED, LABELED_PARENT):
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
			    (*c)->config->negotiation_shunt == SHUNT_HOLD) {
				ldbg_routing(logger, "skipping NEGOTIATION=HOLD");
				set_routing(event, *c, RT_UNROUTED_NEGOTIATION, NULL, where);
				ipsecdoi_initiate(*c, (*c)->policy, SOS_NOBODY,
						  e->inception, null_shunk,
						  e->background, logger);
				return;
			}
			unrouted_instance_to_unrouted_negotiation(event, *c, where);
			ipsecdoi_initiate(*c, (*c)->policy, SOS_NOBODY,
					  e->inception, null_shunk,
					  e->background, logger);
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
			    (*c)->config->negotiation_shunt == SHUNT_HOLD) {
				ldbg_routing(logger, "skipping NEGOTIATION=HOLD");
				set_routing(event, *c, RT_UNROUTED_NEGOTIATION, NULL, where);
				ipsecdoi_initiate(*c, (*c)->policy, SOS_NOBODY,
						  e->inception, null_shunk,
						  e->background, logger);
				return;
			}
			unrouted_instance_to_unrouted_negotiation(event, *c, where);
			ipsecdoi_initiate(*c, (*c)->policy, SOS_NOBODY,
					  e->inception, e->sec_label,
					  e->background, logger);
			return;

		case X(UNROUTE, UNROUTED_NEGOTIATION, INSTANCE):
			delete_spd_kernel_policies(&(*c)->child.spds, EXPECT_NO_INBOUND,
						   (*c)->logger, where, "unroute instance");
			/* do now so route_owner won't find us */
			set_routing(event, *c, RT_UNROUTED, NULL, where);
			return;

		case X(UNROUTE, ROUTED_NEGOTIATION, INSTANCE):
			delete_spd_kernel_policies(&(*c)->child.spds, EXPECT_NO_INBOUND,
						   (*c)->logger, where, "unroute instance");
			set_routing(event, *c, RT_UNROUTED, NULL, where);
			do_updown_unroute(*c, NULL);
			return;

		case X(UNROUTE, ROUTED_TUNNEL, INSTANCE):
			llog(RC_RTBUSY, logger, "cannot unroute: route busy");
			return;

		case X(UNROUTE, ROUTED_ONDEMAND, INSTANCE):
		case X(UNROUTE, ROUTED_ONDEMAND, LABELED_PARENT):
		case X(UNROUTE, ROUTED_REVIVAL, INSTANCE):
			if ((*c)->child.routing == RT_ROUTED_REVIVAL) {
				delete_revival(*c);
			}
			delete_spd_kernel_policies(&(*c)->child.spds, EXPECT_NO_INBOUND,
						   (*c)->logger, where, "unroute instance");
			/* do now so route_owner won't find us */
			set_routing(event, *c, RT_UNROUTED, NULL, where);
			do_updown_unroute(*c, NULL);
			return;

		case X(UNROUTE, ROUTED_FAILURE, INSTANCE):
			delete_spd_kernel_policies(&(*c)->child.spds, EXPECT_NO_INBOUND,
						   (*c)->logger, where, "unroute instance");
			/* do now so route_owner won't find us */
			set_routing(event, *c, RT_UNROUTED, NULL, where);
			do_updown_unroute(*c, NULL);
			return;

		case X(UNROUTE, UNROUTED_TUNNEL, INSTANCE):
			delete_spd_kernel_policies(&(*c)->child.spds, EXPECT_NO_INBOUND,
						   (*c)->logger, where, "unroute instance");
			set_routing(event, *c, RT_UNROUTED, NULL, where);
			return;

		case X(DELETE_IKE, UNROUTED_NEGOTIATION, PERMANENT):
		case X(TIMEOUT_IKE, UNROUTED_NEGOTIATION, PERMANENT):
			if (zap_connection_states(event, c, e->ike, where)) {
				return;
			}
			/* ex, permanent+initiate */
			if (should_revive(&(*e->ike)->sa)) {
				set_routing(event, *c, RT_UNROUTED_REVIVAL, NULL, where);
				schedule_revival(&(*e->ike)->sa, "timed out");
				delete_ike_sa(e->ike);
				return;
			}
			set_routing(event, *c, RT_UNROUTED, NULL, where);
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
			if (zap_connection_states(event, c, e->ike, where)) {
				/* will this happen? */
				return;
			}
			/* ex, permanent+up */
			if (should_revive(&(*e->ike)->sa)) {
				negotiation_to_ondemand(event, *c, logger, where,
							"restoring ondemand, reviving");
				PEXPECT(logger, (*c)->child.routing == RT_ROUTED_REVIVAL);
				schedule_revival(&(*e->ike)->sa, "timed out");
				delete_ike_sa(e->ike);
				return;
			}
			if ((*c)->policy & POLICY_ROUTE) {
				negotiation_to_ondemand(event, *c, logger, where,
							"restoring ondemand, connection is routed");
				PEXPECT(logger, (*c)->child.routing == RT_ROUTED_ONDEMAND);
				delete_ike_sa(e->ike);
				return;
			}
			/* is this reachable? */
			routed_negotiation_to_unrouted(event, *c, logger, where, "deleting");
			PEXPECT(logger, (*c)->child.routing == RT_UNROUTED);
			delete_ike_sa(e->ike);
			/* connection lives to fight another day */
			return;

		case X(TIMEOUT_IKE, ROUTED_NEGOTIATION, INSTANCE):
		case X(TIMEOUT_IKE, UNROUTED_NEGOTIATION, INSTANCE):
			if (BROKEN_TRANSITION) {
				if (zap_connection_states(event, c, e->ike, where)) {
					return;
				}
			}
			if (BROKEN_TRANSITION &&
			    should_revive(&(*e->ike)->sa)) {
				/* when ROUTED_NEGOTIATION should
				 * switch to ROUTED_REVIVAL */
				schedule_revival(&(*e->ike)->sa, "timed out");
				delete_ike_sa(e->ike);
				return;
			}
			if (is_opportunistic(*c)) {
				/*
				 * A failed OE initiator, make shunt bare.
				 */
				orphan_holdpass(*c, (*c)->spd, logger);
				/*
				 * Change routing so we don't get cleared out
				 * when state/connection dies.
				 */
				set_routing(event, *c, RT_UNROUTED, NULL, where);
			}
			delete_ike_sa(e->ike);

			remove_connection_from_pending(*c);
			delete_states_by_connection(*c);
			connection_unroute(*c, HERE);

			delete_connection(c);
			return;

		case X(ACQUIRE, ROUTED_TUNNEL, LABELED_PARENT): /* IKEv1 */
			PEXPECT(logger, (*c)->config->ike_version == IKEv1);
			ipsecdoi_initiate(*c, (*c)->policy, SOS_NOBODY,
					  e->inception, e->sec_label, e->background,
					  logger);
			return;
		case X(ACQUIRE, UNROUTED, LABELED_PARENT):
		case X(ACQUIRE, ROUTED_ONDEMAND, LABELED_PARENT):
		case X(INITIATE, UNROUTED, LABELED_PARENT):
			if (BROKEN_TRANSITION) {
				ipsecdoi_initiate(*c, (*c)->policy, SOS_NOBODY,
						  e->inception, e->sec_label, e->background,
						  logger);
				return;
			}
			break;
		case X(DELETE_IKE, ROUTED_ONDEMAND, LABELED_PARENT):
			if (BROKEN_TRANSITION) {
				delete_ike_family(e->ike);
			}
			return;

		case X(DELETE_IKE, ROUTED_TUNNEL, PERMANENT):
		case X(DELETE_IKE, ROUTED_TUNNEL, INSTANCE):
		case X(TIMEOUT_IKE, ROUTED_TUNNEL, PERMANENT):
		case X(TIMEOUT_IKE, ROUTED_TUNNEL, INSTANCE):
			/*
			 * Since the connection has an established
			 * tunnel there must be a child to notify.
			 * Hence this should always succeed.
			 */
			if (zap_connection_states(event, c, e->ike, where)) {
				return;
			}
			break;

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
			if (zap_connection_states(event, c, e->ike, where)) {
				pexpect(0); /* logger is invalid */
				return;
			}
			delete_ike_sa(e->ike);
			return;

		case X(DELETE_IKE, UNROUTED, INSTANCE):			/* certoe-08-nat-packet-cop-restart */
		case X(DELETE_IKE, UNROUTED_NEGOTIATION, INSTANCE):	/* dnsoe-01 ... */
		case X(DELETE_IKE, ROUTED_ONDEMAND, PERMANENT):		/* ROUTED_NEGOTIATION!?! */
		case X(DELETE_IKE, ROUTED_REVIVAL, PERMANENT):		/* ROUTED_NEGOTIATION!?! */
			if (BROKEN_TRANSITION) {
				delete_ike_family(e->ike);
				return;
			}
			break;

		case X(TIMEOUT_CHILD, ROUTED_TUNNEL, PERMANENT):
		case X(DELETE_CHILD, ROUTED_TUNNEL, PERMANENT):
			/* permenant connections are never deleted */
			down_routed_tunnel(event, c, *e->ike, e->child, where);
			return;
		case X(TIMEOUT_CHILD, ROUTED_TUNNEL, INSTANCE):
		case X(DELETE_CHILD, ROUTED_TUNNEL, INSTANCE):
			down_routed_tunnel(event, c, *e->ike, e->child, where);
			return;

		case X(TIMEOUT_CHILD, UNROUTED_NEGOTIATION, INSTANCE):
		case X(TIMEOUT_CHILD, UNROUTED, PERMANENT): /* permanent+up */
			if (should_revive_child(*(e->child))) {
				schedule_child_revival(*e->ike, *e->child, "timed out");
				delete_child_sa(e->child);
				return;
			}
			delete_child_sa(e->child);
			if (is_instance(*c) &&
			    e->ike != NULL/*IKEv1?*/ &&
			    *c != (*e->ike)->sa.st_connection) {

				remove_connection_from_pending(*c);
				delete_states_by_connection(*c);
				connection_unroute(*c, HERE);

				delete_connection(c);
			}
			return;

		case X(ESTABLISH_INBOUND, ROUTED_ONDEMAND, TEMPLATE): /* ikev1-l2tp-03-two-interfaces */
		case X(ESTABLISH_INBOUND, ROUTED_REVIVAL, TEMPLATE): /* ? */
			if (BROKEN_TRANSITION) {
				if ((*c)->child.routing == RT_ROUTED_REVIVAL) {
					delete_revival(*c);
				}
				/*
				 * ikev1-l2tp-03-two-interfaces
				 * github/693 github/1117
				 */
				set_routing(event, *c, RT_ROUTED_INBOUND, NULL, where);
				return;
			}
			break;
		case X(ESTABLISH_OUTBOUND, ROUTED_INBOUND, TEMPLATE): /* ikev1-l2tp-03-two-interfaces */
			if (BROKEN_TRANSITION) {
				/*
				 * ikev1-l2tp-03-two-interfaces
				 * github/693 github/1117
				 */
				set_routing(event, *c, RT_ROUTED_TUNNEL, *(e->child), where);
				return;
			}
			break;

		case X(ESTABLISH_INBOUND, ROUTED_ONDEMAND, INSTANCE): /* ikev2-32-nat-rw-rekey */
		case X(ESTABLISH_INBOUND, ROUTED_REVIVAL, INSTANCE): /* ? */
			if (BROKEN_TRANSITION) {
				if ((*c)->child.routing == RT_ROUTED_REVIVAL) {
					delete_revival(*c);
				}
				/* ikev2-32-nat-rw-rekey */
				set_routing(event, *c, RT_ROUTED_INBOUND, NULL, where);
				return;
			}
			break;
		case X(ESTABLISH_INBOUND, ROUTED_INBOUND, PERMANENT): /* alias-01 */
			if (BROKEN_TRANSITION) {
				/* alias-01 */
				set_routing(event, *c, RT_ROUTED_INBOUND, NULL, where);
				return;
			}
			break;
		case X(ESTABLISH_INBOUND, UNROUTED_NEGOTIATION, PERMANENT):
			/* addconn-05-bogus-left-interface
			 * algo-ikev2-aes128-sha1-ecp256 et.al. */
			set_routing(event, *c, RT_UNROUTED_INBOUND, NULL, where);
			return;
		case X(ESTABLISH_INBOUND, UNROUTED, TEMPLATE): /* xauth-pluto-14 */
			if (BROKEN_TRANSITION) {
				/*  xauth-pluto-14 */
				set_routing(event, *c, RT_ROUTED_INBOUND, NULL, where);
				return;
			}
			break;
		case X(ESTABLISH_INBOUND, ROUTED_NEGOTIATION, INSTANCE):
		case X(ESTABLISH_INBOUND, ROUTED_NEGOTIATION, PERMANENT):
		case X(ESTABLISH_INBOUND, ROUTED_ONDEMAND, PERMANENT):
		case X(ESTABLISH_INBOUND, ROUTED_REVIVAL, PERMANENT):
		case X(ESTABLISH_INBOUND, UNROUTED, INSTANCE):
		case X(ESTABLISH_INBOUND, UNROUTED, LABELED_PARENT):
		case X(ESTABLISH_INBOUND, UNROUTED, PERMANENT):
		case X(ESTABLISH_INBOUND, UNROUTED_NEGOTIATION, INSTANCE):
			if (BROKEN_TRANSITION) {
				/* instance was routed by routed-ondemand? */
				if ((*c)->child.routing == RT_ROUTED_REVIVAL) {
					delete_revival(*c);
				}
				set_routing(event, *c, RT_ROUTED_INBOUND, NULL, where);
				return;
			}
			break;

		case X(ESTABLISH_OUTBOUND, UNROUTED_INBOUND, PERMANENT):
		case X(ESTABLISH_OUTBOUND, UNROUTED_INBOUND, INSTANCE):
		case X(ESTABLISH_OUTBOUND, ROUTED_INBOUND, PERMANENT):
		case X(ESTABLISH_OUTBOUND, ROUTED_INBOUND, INSTANCE):
		case X(ESTABLISH_OUTBOUND, ROUTED_INBOUND, LABELED_PARENT):
			if (BROKEN_TRANSITION) {
				set_routing(event, *c, RT_ROUTED_TUNNEL, *(e->child), where);
				return;
			}
			break;

		case X(ESTABLISH_OUTBOUND, ROUTED_TUNNEL, PERMANENT):
		case X(ESTABLISH_OUTBOUND, ROUTED_TUNNEL, INSTANCE):
		case X(ESTABLISH_OUTBOUND, ROUTED_TUNNEL, LABELED_PARENT): /* ikev1-labeled-ipsec-01-permissive */
			if (BROKEN_TRANSITION) {
				/*
				 * For instance rekey in
				 * ikev2-12-transport-psk and
				 * ikev2-28-rw-server-rekey
				 * ikev1-labeled-ipsec-01-permissive
				 */
				set_routing(event, *c, RT_ROUTED_TUNNEL, *(e->child), where);
				return;
			}
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
			FOR_EACH_ITEM(spd, &(*c)->child.spds) {
				/* XXX: never finds SPD */
				if (route_owner(spd) == NULL) {
					do_updown(UPDOWN_DOWN, *c, spd,
						  &(*e->child)->sa, logger);
					(*e->child)->sa.st_mobike_del_src_ip = true;
					do_updown(UPDOWN_UNROUTE, *c, spd,
						  &(*e->child)->sa, logger);
					(*e->child)->sa.st_mobike_del_src_ip = false;
				}
			}
			set_routing(event, *c, RT_UNROUTED_TUNNEL,
				    *e->child, where);
			return;

		case X(RESUME, UNROUTED_TUNNEL, PERMANENT):
		case X(RESUME, UNROUTED_TUNNEL, INSTANCE):
			set_routing(event, *c, RT_ROUTED_TUNNEL, *e->child, where);
			FOR_EACH_ITEM(spd, &(*c)->child.spds) {
				do_updown(UPDOWN_UP, *c, spd, &(*e->child)->sa, logger);
				do_updown(UPDOWN_ROUTE, *c, spd, &(*e->child)->sa, logger);
			}
			return;

		}

	}

	LLOG_PEXPECT_JAMBUF(logger, where, buf) {
		jam_string(buf, "routing: unhandled ");
		jam_event(buf, event, c, e);
	}
}
