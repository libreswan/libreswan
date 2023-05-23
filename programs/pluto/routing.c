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

static const char *routing_event_name[] = {
#define S(E) [E] = #E
	S(CONNECTION_ROUTE),
	S(CONNECTION_UNROUTE),
	S(CONNECTION_UP),
	S(CONNECTION_DOWN),
	S(CONNECTION_INITIATE),
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
	bool background;
	const struct kernel_acquire *const acquire;
};

static void dispatch(const enum routing_event event,
		     struct connection *c,
		     struct logger *logger, where_t where,
		     struct annex e);

static void jam_event_sa(struct jambuf *buf, struct state *st)
{
	jam_string(buf, "; ");
	enum sa_type sa_type = IS_PARENT_SA(st) ? IKE_SA : IPSEC_SA;
	jam_string(buf, st->st_connection->config->ike_info->sa_type_name[sa_type]);
	jam_string(buf, " ");
	jam_so(buf, st->st_serialno);
	jam_string(buf, " ");
	jam_string(buf, st->st_state->short_name);
}

static void jam_routing(struct jambuf *buf, const struct connection *c)
{
	jam_enum_short(buf, &routing_names, c->child.routing);
	jam_string(buf, " ");
	jam_enum_short(buf, &connection_kind_names, c->kind);
	jam_string(buf, " ");
	jam_connection_co(buf, c);
	if (never_negotiate(c)) {
		jam_string(buf, " never-negotiate");
	}
	if (c->child.newest_routing_sa != SOS_NOBODY) {
		jam_string(buf, " routing");
		jam_so(buf, c->child.newest_routing_sa);
	}
	if (c->newest_ipsec_sa != SOS_NOBODY) {
		jam_string(buf, " IPsec");
		jam_so(buf, c->newest_ipsec_sa);
	}
	if (c->newest_ike_sa != SOS_NOBODY) {
		jam_string(buf, " IKE");
		jam_so(buf, c->newest_ike_sa);
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
	if (e->acquire != NULL) {
		jam_string(buf, "; ");
		jam_kernel_acquire(buf, e->acquire);
	}
}

static void jam_event(struct jambuf *buf, enum routing_event event,
		      const struct connection *c, const struct annex *e)
{
	jam_enum_short(buf, &routing_event_names, event);
	jam_string(buf, " to ");
	jam_routing(buf, c);
	jam_annex(buf, e);
}

static void ldbg_dispatch(struct logger *logger, enum routing_event event,
			  const struct connection *c,
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
	dispatch(CONNECTION_ESTABLISH_INBOUND,
		 child->sa.st_connection,
		 child->sa.st_logger, where,
		 (struct annex) {
			 .ike = &ike,
			 .child = &child,
		 });
}

void fake_connection_establish_outbound(struct ike_sa *ike, struct child_sa *child,
					where_t where)
{
	dispatch(CONNECTION_ESTABLISH_OUTBOUND,
		 child->sa.st_connection,
		 child->sa.st_logger, where,
		 (struct annex) {
			 .ike = &ike,
			 .child = &child,
		 });
}

enum shunt_kind routing_shunt_kind(enum routing routing)
{
	switch (routing) {
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
		return false;
	case RT_UNROUTED_ONDEMAND:
	case RT_ROUTED_ONDEMAND:
	case RT_UNROUTED_NEGOTIATION:
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
			jam_routing(buf, c);
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
	PEXPECT(logger, !labeled_child(c));
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
	bool oe = opportunistic(c);
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
	PEXPECT(logger, !opportunistic(c));
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
        PEXPECT(logger, !opportunistic(c));
	PASSERT(logger, (event == CONNECTION_INITIATE ||
			 event == CONNECTION_ACQUIRE ||
			 event == CONNECTION_REVIVE));
	enum routing rt_negotiation = (c->child.routing == RT_ROUTED_ONDEMAND ? RT_ROUTED_NEGOTIATION :
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
	if (labeled(c)) {
		ipsecdoi_initiate(c, c->policy, SOS_NOBODY, inception,
				  (c->config->ike_version == IKEv1 ? HUNK_AS_SHUNK(c->child.sec_label) : null_shunk),
				  background, c->logger);
		return;
	}

	if (c->config->ike_version == IKEv1) {
		ipsecdoi_initiate(c, c->policy, SOS_NOBODY, inception,
				  (c->config->ike_version == IKEv1 ? HUNK_AS_SHUNK(c->child.sec_label) : null_shunk),
				  background, c->logger);
		return;
	}

	dispatch(CONNECTION_INITIATE, c,
		 c->logger, where,
		 (struct annex) {
			 .inception = inception,
			 .background = background,
		 });
}

void connection_acquire(struct connection *c, threadtime_t *inception,
			const struct kernel_acquire *b, where_t where)
{
	if (labeled(c)) {
		PASSERT(c->logger, labeled_parent(c));
		ipsecdoi_initiate(c, c->policy, SOS_NOBODY,
				  inception, b->sec_label, b->background, b->logger);
		packet_buf pb;
		enum_buf hab;
		dbg("initiated on demand using security label and %s %s",
		    str_enum_short(&keyword_auth_names, c->local->host.config->auth, &hab),
		    str_packet(&b->packet, &pb));
		return;
	}

	dispatch(CONNECTION_ACQUIRE, c,
		 c->logger, where,
		 (struct annex) {
			 .inception = inception,
			 .background = b->background,
			 .acquire = b,
		 });
}

void connection_revive(struct connection *c, const threadtime_t *inception, where_t where)
{
	if (labeled(c)) {
		initiate_connection(c, /*remote-host-name*/NULL,
				    /*background*/true,
				    /*log-failure*/true,
				    c->logger);
		return;
	}

	dispatch(CONNECTION_REVIVE, c,
		 c->logger, where,
		 (struct annex) {
			 .inception = inception,
			 .background = true,
		 });
}

/*
 * Delete the ROUTED_TUNNEL, and possibly delete the connection.
 */

static void delete_routed_tunnel(enum routing_event event,
				 struct connection *c,
				 where_t where,
				 struct annex *e)
{
	if (c->child.newest_routing_sa > (*e->child)->sa.st_serialno) {
		/* no longer child's */
		ldbg_routing(c->logger, "keeping connection kernel policy; routing SA "PRI_SO" is newer",
			     pri_so(c->child.newest_routing_sa));
		delete_child_sa(e->child);
		return;
	}

	if (c->newest_ipsec_sa > (*e->child)->sa.st_serialno) {
		/* covered by above; no!? */
		ldbg_routing(c->logger, "keeping connection kernel policy; IPsec SA "PRI_SO" is newer",
			     pri_so(c->newest_ipsec_sa));
		delete_child_sa(e->child);
		return;
	}

	if (should_revive_connection(*(e->child))) {
		/* XXX: should this be ROUTED_NEGOTIATING? */
		ldbg_routing(c->logger, "replacing connection kernel policy with ROUTED_ONDEMAND; it will be revived");
		replace_ipsec_with_bare_kernel_policies(event, *(e->child), RT_ROUTED_ONDEMAND,
							EXPECT_KERNEL_POLICY_OK, HERE);
		schedule_revival(&(*e->child)->sa, "received Delete/Notify");
		/* covered by above; no!? */
		delete_child_sa(e->child);
		return;
	}

	/*
	 * Change routing so we don't get cleared out
	 * when state/connection dies.
	 */
	enum routing new_routing =
		(c->policy & POLICY_ROUTE ? RT_ROUTED_ONDEMAND :
		 c->config->failure_shunt != SHUNT_NONE ? RT_ROUTED_FAILURE :
		 RT_ROUTED_ONDEMAND);
	enum_buf rb;
	ldbg_routing(c->logger, "replacing connection kernel policy with %s",
		     str_enum_short(&routing_names, new_routing, &rb));

	replace_ipsec_with_bare_kernel_policies(event, (*e->child), new_routing,
						EXPECT_KERNEL_POLICY_OK, HERE);
	delete_child_sa(e->child);

	/*
	 * Never delete permanent (leaving only instances)
	 */
	if (c->kind == CK_PERMANENT) {
		ldbg_routing(c->logger, "keeping connection; it is permanent");
		return;
	}

	PEXPECT(c->logger, c->kind == CK_INSTANCE);

	/*
	 * If the connection is shared with the IKE SA, don't delete
	 * it.
	 */
	if (pexpect(e->ike != NULL)/*IKEv1?*/ &&
	    c == (*e->ike)->sa.st_connection) {
		ldbg_routing(c->logger, "keeping connection; shared with IKE SA "PRI_SO,
			     pri_so((*e->ike)->sa.st_serialno));
		return;
	}

	/*.
	 * See of a state, any state (presumably the
	 * IKE SA, is using the connection.
	 */
	struct state_filter sf = {
		.connection_serialno = c->serialno,
		.where = HERE,
	};
	if (next_state_new2old(&sf)) {
		connection_buf cb;
		llog_pexpect(c->logger, where,
			     "connection "PRI_CONNECTION" in use by #%lu, skipping delete-unused",
			     pri_connection(c, &cb), sf.st->st_serialno);
		return;
	}

	ldbg_routing(c->logger, "keeping connection; NO!");
	delete_connection(&c);
}

static bool zap_connection(enum routing_event event,
			   struct ike_sa **ike, where_t where)
{
	struct connection *c = (*ike)->sa.st_connection;

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
	 * Weed out any lurking larval children (i.e., children that
	 * don't yet own their connection's route) that are sharing
	 * this IKE SA.
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
				attach_whack(child->sa.st_logger, (*ike)->sa.st_logger);
				enum_buf ren;
				llog_sa(RC_LOG, child, "deleting larval %s (%s)",
					child->sa.st_connection->config->ike_info->sa_type_name[IPSEC_SA],
					str_enum_short(&routing_event_names, event, &ren));
			} else {
				ldbg_routing(child->sa.st_logger, "deleting larval %s (%s)",
					     child->sa.st_connection->config->ike_info->sa_type_name[IPSEC_SA],
					     str_enum_short(&routing_event_names, event, &ren));
			}
			delete_child_sa(&child);
		}
	}

	/*
	 * If the IKE SA's connection has Child SA owning the route
	 * and the Child SA's parent is this IKE SA then then send a
	 * delete/timeout to that Child SA first.
	 *
	 * This way, the IKE SA's connection is always put at the
	 * front of the revival queue (without this the IKE SA and
	 * other Child SAs all fight for who is first to revive).
	 *
	 * Also remember if the first child was told; later the event
	 * only gets dispatched for IKE when there wasn't a child
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
		attach_whack(connection_child->sa.st_logger, (*ike)->sa.st_logger);
		/* will delete child and its logger */
		dispatch(child_event, connection_child->sa.st_connection,
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
	 * If the child is the routing owner, notify it of the
	 * timeout.  Otherwise just blow it away.
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
			attach_whack(child->sa.st_logger, (*ike)->sa.st_logger);
			dispatch(child_event, child->sa.st_connection,
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
	 *
	 * If the connection had a Child SA and it was notified, the
	 * IKE SA can be deleted ...
	 */
	if (dispatched_to_child) {
		delete_ike_sa(ike);
		if (c->kind == CK_TEMPLATE &&
		    c->child.routing == RT_UNROUTED) {
			delete_connection(&c);
		}
		return true;
	}

	/*
	 * If the connection has a Child SA but it isn't also the IKE
	 * SA's child then delete the IKE SA but not the connection
	 * (the child, and likely another IKE SA share it).
	 *
	 * XXX: would it be easier to compare IKE against the
	 * connection's .newest_ike_sa.
	 */

	if (connection_child != NULL) {
		PEXPECT((*ike)->sa.st_logger, (connection_child->sa.st_clonedfrom !=
					       (*ike)->sa.st_serialno));
		delete_ike_sa(ike);
		return true;
	}

	/*
	 * ... otherwize caller gets to decide.  This code could
	 * handle this if it weren't for the more complicated routing
	 * changes that are needed.
	 */
	return false;
}

/*
 * zap (unroute) any instances of the connection; for instance when an
 * unrouted template gets instantiated using whack.
 */

static bool zap_instances(enum routing_event event, struct connection *c, where_t where)
{
	enum_buf ren;
	ldbg_routing(c->logger, "due to %s, zapping instances",
		     str_enum_short(&routing_event_names, event, &ren));
	PASSERT(c->logger, c->kind == CK_TEMPLATE);

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
		dispatch(CONNECTION_UNROUTE, cq.c, cq.c->logger, where,
			 (struct annex) {
				 0,
			 });
		/* unroute doesn't delete instances, should it? */
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

	if (c->kind == CK_GROUP) {
		connection_group_route(c, where);
		return;
	}

	dispatch(CONNECTION_ROUTE, c, c->logger, where,
		 (struct annex) {
			 0,
		 });

}

void connection_unroute(struct connection *c, where_t where)
{
	if (c->kind == CK_GROUP) {
		/* XXX: may recurse back to here with group
		 * instances. */
		connection_group_unroute(c, where);
		return;
	}

	c->policy &= ~POLICY_ROUTE;
	dispatch(CONNECTION_UNROUTE, c,
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
		dispatch(CONNECTION_DELETE_CHILD, (*child)->sa.st_connection,
			 (*child)->sa.st_logger, where,
			 (struct annex) {
				 .ike = &ike,
				 .child = child,
			 });
		/* no logger as no child */
		pexpect(*child == NULL);
	} else {
		attach_whack((*child)->sa.st_logger, ike->sa.st_logger);
		llog_sa(RC_LOG, (*child), "deleted");
		delete_child_sa(child);
	}
}

void connection_timeout_ike(struct ike_sa **ike, where_t where)
{
	pstat_sa_failed(&(*ike)->sa, REASON_TOO_MANY_RETRANSMITS);

	dispatch(CONNECTION_TIMEOUT_IKE,
		 (*ike)->sa.st_connection,
		 (*ike)->sa.st_logger, where,
		 (struct annex) {
			 .ike = ike,
		 });
}

void connection_delete_ike(struct ike_sa **ike, where_t where)
{
	if (labeled((*ike)->sa.st_connection)) {
		delete_ike_family(ike);
		return;
	}

	dispatch(CONNECTION_DELETE_IKE,
		 (*ike)->sa.st_connection,
		 (*ike)->sa.st_logger, where,
		 (struct annex) {
			 .ike = ike,
		 });
}

void dispatch(enum routing_event event, struct connection *c,
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
	PEXPECT(logger, (c->newest_ike_sa == SOS_NOBODY ||
			 (e->ike != NULL &&
			  (*e->ike)->sa.st_serialno == c->newest_ike_sa)));
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
	    (*e->child)->sa.st_serialno != c->child.newest_routing_sa) {
		LLOG_PEXPECT_JAMBUF(logger, where, buf) {
			jam_string(buf, "Child SA ");
			jam_so(buf, (*e->child)->sa.st_serialno);
			jam_string(buf, " does not match routing SA ");
			jam_so(buf, c->child.newest_routing_sa);
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
		const enum routing routing = c->child.routing;
		const enum connection_kind kind = c->kind;

		switch (XX(event, routing, kind)) {

		case X(ROUTE, UNROUTED, TEMPLATE):
		case X(ROUTE, UNROUTED, PERMANENT):
			c->policy |= POLICY_ROUTE; /* always */
			if (never_negotiate(c)) {
				if (!unrouted_to_routed_never_negotiate(event, c, where)) {
					/* XXX: why whack only? */
					llog(WHACK_STREAM|RC_ROUTE, logger, "could not route");
					return;
				}
				PEXPECT(logger, c->child.routing == RT_ROUTED_NEVER_NEGOTIATE);
			} else if (labeled_template(c)) {
				if (!unrouted_to_routed_sec_label(event, c, logger, where)) {
					/* XXX: why whack only? */
					llog(RC_ROUTE, logger, "could not route");
					return;
				}
				PEXPECT(logger, c->child.routing == RT_ROUTED_ONDEMAND);
			} else {
				PEXPECT(logger, !labeled(c));
				if (!unrouted_to_routed_ondemand(event, c, where)) {
					/* XXX: why whack only? */
					llog(WHACK_STREAM|RC_ROUTE, logger, "could not route");
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
				ipsecdoi_initiate(c, c->policy, SOS_NOBODY,
						  e->inception, null_shunk,
						  e->background, c->logger);
				return;
			}
			break;

		case X(INITIATE, UNROUTED, PERMANENT):
			set_routing(event, c, RT_UNROUTED_NEGOTIATION, NULL, where);
			ipsecdoi_initiate(c, c->policy, SOS_NOBODY,
					  e->inception, null_shunk,
					  e->background, c->logger);
			return;

		case X(INITIATE, ROUTED_ONDEMAND, PERMANENT):
		case X(ACQUIRE, ROUTED_ONDEMAND, PERMANENT):
			PEXPECT(logger, ((event == CONNECTION_INITIATE && e->acquire == NULL) ||
					 (event == CONNECTION_ACQUIRE && e->acquire->sec_label.ptr == NULL)));
			ondemand_to_negotiation(event, c, where, "negotiating permanent");
			PEXPECT(logger, c->child.routing == RT_ROUTED_NEGOTIATION);
			/* ipsecdoi_initiate may replace SOS_NOBODY with a state */
			ipsecdoi_initiate(c, c->policy, SOS_NOBODY,
					  e->inception, null_shunk,
					  e->background, c->logger);
			return;

		case X(INITIATE, UNROUTED_NEGOTIATION, PERMANENT):
			if (BROKEN_TRANSITION) {
				/* ikev2-redirect-01-global-load-balancer
				 * ikev2-redirect-01-global
				 * ikev2-redirect-03-auth-loop
				 * ikev2-tcp-07-fail-ike-auth-redirect */
				ipsecdoi_initiate(c, c->policy, SOS_NOBODY,
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
				ipsecdoi_initiate(c, c->policy, SOS_NOBODY,
						  e->inception, null_shunk,
						  e->background, logger);
				return;
			}
			llog(RC_LOG, c->logger, "connection already negotiating");
			return;
		case X(ACQUIRE, ROUTED_NEGOTIATION, PERMANENT):
			llog(RC_LOG, c->logger, "connection already negotiating");
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
				initiate_connection(c, /*remote-host-name*/NULL,
						    /*background*/true,
						    /*log-failure*/true,
						    logger);
				return;
			}
			ipsecdoi_initiate(c, c->policy, SOS_NOBODY,
					  e->inception, e->acquire->sec_label,
					  e->background, e->acquire->logger);
			return;
		case X(REVIVE, UNROUTED_REVIVAL, PERMANENT):
			set_routing(event, c, RT_UNROUTED_NEGOTIATION, NULL, where);
			ipsecdoi_initiate(c, c->policy, SOS_NOBODY, e->inception,
					  null_shunk, /*background*/false, logger);
			return;
		case X(REVIVE, UNROUTED_ONDEMAND, PERMANENT):
		case X(REVIVE, UNROUTED_ONDEMAND, INSTANCE):
			ondemand_to_negotiation(event, c, where, "negotiating unrouted");
			PEXPECT(logger, c->child.routing == RT_UNROUTED_NEGOTIATION);
			ipsecdoi_initiate(c, c->policy, SOS_NOBODY, e->inception,
					  null_shunk, /*background*/false, logger);
			return;
		case X(REVIVE, ROUTED_ONDEMAND, PERMANENT):
		case X(REVIVE, ROUTED_ONDEMAND, INSTANCE):
			if (BROKEN_TRANSITION &&
			    c->config->negotiation_shunt == SHUNT_HOLD) {
				ldbg_routing(c->logger, "skipping NEGOTIATION=HOLD");
				set_routing(event, c, RT_ROUTED_NEGOTIATION, NULL, where);
				/* ipsecdoi_initiate may replace SOS_NOBODY with a state */
				ipsecdoi_initiate(c, c->policy, SOS_NOBODY,
						  e->inception, null_shunk,
						  e->background, c->logger);
				return;
			}
			ondemand_to_negotiation(event, c, where, "negotiating revival");
			PEXPECT(logger, c->child.routing == RT_ROUTED_NEGOTIATION);
			ipsecdoi_initiate(c, c->policy, SOS_NOBODY, e->inception,
					  null_shunk, /*background*/false, logger);
			return;

		case X(REVIVE, UNROUTED_NEGOTIATION, INSTANCE):
			if (BROKEN_TRANSITION) {
				/* ikev2-redirect-01-global
				 * ikev2-redirect-02-auth
				 * ikev2-redirect-03-auth-loop
				 * ikev2-tcp-05-transport-mode
				 * ikev2-tcp-06-fail-ike-sa-init-redirect
				 * ikev2-tcp-07-fail-ike-auth-redirect */
				ipsecdoi_initiate(c, c->policy, SOS_NOBODY, e->inception,
						  null_shunk, /*background*/false, logger);
				return;
			}
			break;
		case X(REVIVE, ROUTED_NEGOTIATION, INSTANCE):
			if (BROKEN_TRANSITION) {
				/* ikev2-32-nat-rw-rekey
				 * ikev2-liveness-05 ikev2-liveness-07
				 * ikev2-liveness-08 */
				ipsecdoi_initiate(c, c->policy, SOS_NOBODY, e->inception,
						  null_shunk, /*background*/false, logger);
				return;
			}
			break;
		case X(REVIVE, UNROUTED_NEGOTIATION, PERMANENT):
			if (BROKEN_TRANSITION) {
				/* ikev2-x509-31-wifi-assist */
				ipsecdoi_initiate(c, c->policy, SOS_NOBODY, e->inception,
						  null_shunk, /*background*/false, logger);
				return;
			}
			break;
		case X(REVIVE, ROUTED_TUNNEL, PERMANENT):
			if (BROKEN_TRANSITION) {
				/* ikev2-59-multiple-acquires-alias. */
				ipsecdoi_initiate(c, c->policy, SOS_NOBODY, e->inception,
						  null_shunk, /*background*/false, logger);
				return;
			}
			break;

		case X(ROUTE, UNROUTED_NEGOTIATION, PERMANENT):
			if (BROKEN_TRANSITION) {
				/*
				 * XXX: should install routing+policy!
				 */
				c->policy |= POLICY_ROUTE;
				llog(RC_LOG_SERIOUS, logger,
				     "policy ROUTE added to negotiating connection");
				return;
			}
			break;
		case X(UNROUTE, UNROUTED_NEGOTIATION, PERMANENT):
		case X(UNROUTE, UNROUTED_REVIVAL, PERMANENT):
			set_routing(event, c, RT_UNROUTED, NULL, where);
			return;

		case X(ROUTE, ROUTED_NEGOTIATION, PERMANENT):
			c->policy |= POLICY_ROUTE;
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
			delete_spd_kernel_policies(&c->child.spds,
						   EXPECT_NO_INBOUND,
						   c->logger, where, "unroute permanent");
			/* stop updown_unroute() finding this
			 * connection */
			set_routing(event, c, RT_UNROUTED, NULL, where);
			do_updown_unroute(c, NULL);
			return;
		case X(UNROUTE, UNROUTED_ONDEMAND, PERMANENT):
			if (BROKEN_TRANSITION) {
				PEXPECT(logger, !never_negotiate(c));
				delete_spd_kernel_policies(&c->child.spds,
							   EXPECT_NO_INBOUND,
							   c->logger, where, "unroute permanent");
				/* stop updown_unroute() finding this
				 * connection */
				set_routing(event, c, RT_UNROUTED, NULL, where);
				return;
			}
			break;

		case X(ROUTE, ROUTED_TUNNEL, PERMANENT):
			c->policy |= POLICY_ROUTE; /* always */
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
			if (zap_instances(event, c, where)) {
				return;
			}
			ldbg_routing(logger, "already unrouted");
			return;
		case X(UNROUTE, ROUTED_ONDEMAND, TEMPLATE):
			zap_instances(event, c, where);
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
				ipsecdoi_initiate(c, c->policy, SOS_NOBODY,
						  e->inception, null_shunk,
						  e->background, logger);
				return;
			}
			unrouted_instance_to_unrouted_negotiation(event, c, where);
			ipsecdoi_initiate(c, c->policy, SOS_NOBODY,
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
			    c->config->negotiation_shunt == SHUNT_HOLD) {
				ldbg_routing(logger, "skipping NEGOTIATION=HOLD");
				set_routing(event, c, RT_UNROUTED_NEGOTIATION, NULL, where);
				ipsecdoi_initiate(c, c->policy, SOS_NOBODY,
						  e->inception, null_shunk,
						  e->background, logger);
				return;
			}
			unrouted_instance_to_unrouted_negotiation(event, c, where);
			ipsecdoi_initiate(c, c->policy, SOS_NOBODY,
					  e->inception, e->acquire->sec_label,
					  e->background, e->acquire->logger);
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

		case X(DELETE_IKE, UNROUTED_NEGOTIATION, PERMANENT):
		case X(TIMEOUT_IKE, UNROUTED_NEGOTIATION, PERMANENT):
			if (zap_connection(event, e->ike, where)) {
				return;
			}
			/* ex, permanent+initiate */
			if (should_revive(&(*e->ike)->sa)) {
				set_routing(event, c, RT_UNROUTED_REVIVAL, NULL, where);
				schedule_revival(&(*e->ike)->sa, "timed out");
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
			if (zap_connection(event, e->ike, where)) {
				/* will this happen? */
				return;
			}
			/* ex, permanent+up */
			if (should_revive(&(*e->ike)->sa)) {
				negotiation_to_ondemand(event, c, logger, where,
							"restoring ondemand, reviving");
				PEXPECT(logger, c->child.routing == RT_ROUTED_ONDEMAND);
				schedule_revival(&(*e->ike)->sa, "timed out");
				delete_ike_sa(e->ike);
				return;
			}
			if (c->policy & POLICY_ROUTE) {
				negotiation_to_ondemand(event, c, logger, where,
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
			if (BROKEN_TRANSITION) {
				if (zap_connection(event, e->ike, where)) {
					return;
				}
			}
			if (should_revive(&(*e->ike)->sa)) {
				schedule_revival(&(*e->ike)->sa, "timed out");
				delete_ike_sa(e->ike);
				return;
			}
			if (opportunistic(c)) {
				/*
				 * A failed OE initiator, make shunt bare.
				 */
				orphan_holdpass(c, c->spd, logger);
				/*
				 * Change routing so we don't get cleared out
				 * when state/connection dies.
				 */
				set_routing(event, c, RT_UNROUTED, NULL, where);
			}
			delete_ike_sa(e->ike);
			delete_connection(&c);
			return;

		case X(DELETE_IKE, ROUTED_TUNNEL, PERMANENT):
#if 0 /* TODO: delete below */
		case X(DELETE_IKE, ROUTED_TUNNEL, INSTANCE):
#endif
		case X(TIMEOUT_IKE, ROUTED_TUNNEL, PERMANENT):
		case X(TIMEOUT_IKE, ROUTED_TUNNEL, INSTANCE):
			/*
			 * Since the connection has an established
			 * tunnel there there must be a child to
			 * notify.  Hence this should always succeed.
			 */
			if (zap_connection(event, e->ike, where)) {
				return;
			}
			break;

		case X(DELETE_IKE, UNROUTED, INSTANCE):		/* certoe-08-nat-packet-cop-restart */
		case X(DELETE_IKE, UNROUTED_NEGOTIATION, INSTANCE):	/* dnsoe-01 ... */
		case X(DELETE_IKE, ROUTED_ONDEMAND, PERMANENT):
		case X(DELETE_IKE, UNROUTED, PERMANENT): /* UNROUTED_NEGOTIATION!?! */
#if 1 /* TODO: move to above */
		case X(DELETE_IKE, ROUTED_TUNNEL, INSTANCE):
#endif
			if (BROKEN_TRANSITION) {
				delete_ike_family(e->ike);
				return;
			}
			break;

		case X(TIMEOUT_CHILD, ROUTED_TUNNEL, PERMANENT):
		case X(DELETE_CHILD, ROUTED_TUNNEL, PERMANENT):
			/* permenant connections are never deleted */
			delete_routed_tunnel(event, c, where, e);
			return;
		case X(TIMEOUT_CHILD, ROUTED_TUNNEL, INSTANCE):
		case X(DELETE_CHILD, ROUTED_TUNNEL, INSTANCE):
			delete_routed_tunnel(event, c, where, e);
			return;

		case X(TIMEOUT_CHILD, UNROUTED_NEGOTIATION, INSTANCE):
		case X(TIMEOUT_CHILD, UNROUTED, PERMANENT): /* permanent+up */
			if (should_revive_connection(*(e->child))) {
				schedule_revival(&(*e->child)->sa, "timed out");
				delete_child_sa(e->child);
				return;
			}
			delete_child_sa(e->child);
			if (kind == CK_INSTANCE &&
			    e->ike != NULL/*IKEv1?*/ &&
			    c != (*e->ike)->sa.st_connection) {
				delete_connection(&c);
			}
			return;

		case X(ESTABLISH_INBOUND, ROUTED_ONDEMAND, TEMPLATE): /* ikev1-l2tp-03-two-interfaces */
			if (BROKEN_TRANSITION) {
				/*
				 * ikev1-l2tp-03-two-interfaces
				 * github/693 github/1117
				 */
				set_routing(event, c, RT_ROUTED_INBOUND, NULL, where);
				return;
			}
			break;
		case X(ESTABLISH_OUTBOUND, ROUTED_INBOUND, TEMPLATE): /* ikev1-l2tp-03-two-interfaces */
			if (BROKEN_TRANSITION) {
				/*
				 * ikev1-l2tp-03-two-interfaces
				 * github/693 github/1117
				 */
				set_routing(event, c, RT_ROUTED_TUNNEL, *(e->child), where);
				return;
			}
			break;

		case X(ESTABLISH_INBOUND, ROUTED_ONDEMAND, INSTANCE): /* ikev2-32-nat-rw-rekey */
			if (BROKEN_TRANSITION) {
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
		case X(ESTABLISH_INBOUND, ROUTED_NEGOTIATION, INSTANCE):
		case X(ESTABLISH_INBOUND, ROUTED_NEGOTIATION, PERMANENT):
		case X(ESTABLISH_INBOUND, ROUTED_ONDEMAND, PERMANENT):
		case X(ESTABLISH_INBOUND, UNROUTED, INSTANCE):
		case X(ESTABLISH_INBOUND, UNROUTED, PERMANENT):
		case X(ESTABLISH_INBOUND, UNROUTED_NEGOTIATION, INSTANCE):
			if (BROKEN_TRANSITION) {
				/* instance was routed by routed-ondemand? */
				set_routing(event, c, RT_ROUTED_INBOUND, NULL, where);
				return;
			}
			break;

		case X(ESTABLISH_OUTBOUND, UNROUTED_INBOUND, PERMANENT):
		case X(ESTABLISH_OUTBOUND, UNROUTED_INBOUND, INSTANCE):
		case X(ESTABLISH_OUTBOUND, ROUTED_INBOUND, PERMANENT):
		case X(ESTABLISH_OUTBOUND, ROUTED_INBOUND, INSTANCE):
			if (BROKEN_TRANSITION) {
				set_routing(event, c, RT_ROUTED_TUNNEL, *(e->child), where);
				return;
			}
			break;

		case X(ESTABLISH_OUTBOUND, ROUTED_TUNNEL, PERMANENT):
		case X(ESTABLISH_OUTBOUND, ROUTED_TUNNEL, INSTANCE):
			if (BROKEN_TRANSITION) {
				/*
				 * For instance rekey in
				 * ikev2-12-transport-psk and
				 * ikev2-28-rw-server-rekey
				 */
				set_routing(event, c, RT_ROUTED_TUNNEL, *(e->child), where);
				return;
			}
			return;

		}
	}

	LLOG_PEXPECT_JAMBUF(logger, where, buf) {
		jam_string(buf, "routing: unhandled ");
		jam_event(buf, event, c, e);
	}
}

/*
 * "down" / "unroute" the connection but _don't_ delete the kernel
 * state / policy.
 *
 * Presumably the kernel policy (at least) is acting like a trap while
 * mibike migrates things?
 */

void connection_resume(struct child_sa *child, where_t where)
{
	struct connection *c = child->sa.st_connection;
	enum routing_event event = CONNECTION_RESUME;
	/* do now so route_owner won't find us */
	enum routing cr = c->child.routing;
	switch (cr) {
	case RT_UNROUTED_TUNNEL:
		set_routing(event, c, RT_ROUTED_TUNNEL, child, where);
		FOR_EACH_ITEM(spd, &c->child.spds) {
			do_updown(UPDOWN_UP, c, spd, &child->sa, child->sa.st_logger);
			do_updown(UPDOWN_ROUTE, c, spd, &child->sa, child->sa.st_logger);
		}
		return;
	case RT_UNROUTED:
	case RT_UNROUTED_REVIVAL:
	case RT_UNROUTED_ONDEMAND:
	case RT_ROUTED_ONDEMAND:
	case RT_UNROUTED_NEGOTIATION:
	case RT_ROUTED_NEGOTIATION:
	case RT_UNROUTED_INBOUND:
	case RT_ROUTED_INBOUND:
	case RT_UNROUTED_FAILURE:
	case RT_ROUTED_FAILURE:
	case RT_ROUTED_TUNNEL:
	case RT_ROUTED_NEVER_NEGOTIATE:
		llog_pexpect(child->sa.st_logger, where,
			     "%s() unexpected routing %s",
			     __func__, enum_name_short(&routing_names, cr));
		set_routing(event, c, RT_ROUTED_TUNNEL, child, where);
		return;
	}
	bad_case(cr);
}

void connection_suspend(struct child_sa *child, where_t where)
{
	struct connection *c = child->sa.st_connection;
	enum routing_event event = CONNECTION_SUSPEND;
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
		set_routing(event, c, RT_UNROUTED_TUNNEL, child, where);
		return;
	case RT_ROUTED_ONDEMAND:
	case RT_ROUTED_NEVER_NEGOTIATE:
	case RT_ROUTED_NEGOTIATION:
	case RT_ROUTED_INBOUND:
	case RT_ROUTED_FAILURE:
		llog_pexpect(child->sa.st_logger, where,
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
		set_routing(event, c, RT_UNROUTED_TUNNEL, child, where);
		return;
	case RT_UNROUTED:
	case RT_UNROUTED_REVIVAL:
	case RT_UNROUTED_ONDEMAND:
	case RT_UNROUTED_NEGOTIATION:
	case RT_UNROUTED_FAILURE:
	case RT_UNROUTED_INBOUND:
	case RT_UNROUTED_TUNNEL:
		llog_pexpect(child->sa.st_logger, HERE,
			     "%s() unexpected routing %s",
			     __func__, enum_name_short(&routing_names, cr));
		set_routing(event, c, RT_UNROUTED_TUNNEL, child, where);
		return;
	}
	bad_case(cr);
}
