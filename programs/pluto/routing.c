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

static void do_updown_unroute(struct connection *c);

enum connection_event {
	CONNECTION_ROUTE,
	CONNECTION_UNROUTE,
	CONNECTION_ACQUIRE,
	CONNECTION_ESTABLISH_INBOUND,
	CONNECTION_ESTABLISH_OUTBOUND,
	CONNECTION_DELETE_IKE,
	CONNECTION_DELETE_CHILD,
	CONNECTION_TIMEOUT_IKE,
	CONNECTION_TIMEOUT_CHILD,
#define CONNECTION_EVENT_ROOF (CONNECTION_TIMEOUT_CHILD+1)
};

static const char *connection_event_name[] = {
#define S(E) [E] = #E
	S(CONNECTION_ROUTE),
	S(CONNECTION_UNROUTE),
	S(CONNECTION_ACQUIRE),
	S(CONNECTION_ESTABLISH_INBOUND),
	S(CONNECTION_ESTABLISH_OUTBOUND),
	S(CONNECTION_DELETE_IKE),
	S(CONNECTION_DELETE_CHILD),
	S(CONNECTION_TIMEOUT_IKE),
	S(CONNECTION_TIMEOUT_CHILD),
#undef S
};

static enum_names connection_event_names = {
	0, CONNECTION_EVENT_ROOF-1,
	ARRAY_REF(connection_event_name),
	"CONNECTION_",
	NULL,
};

struct annex {
	struct ike_sa **ike;
	struct child_sa **child;
	const threadtime_t *const inception;
	const struct kernel_acquire *const acquire;
};

static void dispatch(const enum connection_event event,
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

static void jam_routing(struct jambuf *buf, struct connection *c)
{
	jam_enum_short(buf, &routing_names, c->child.routing);
	jam_string(buf, " ");
	jam_enum_short(buf, &connection_kind_names, c->kind);
	if (NEVER_NEGOTIATE(c->policy)) {
		jam_string(buf, " never-negotiate");
	}
	jam_string(buf, " ");
	jam_co(buf, c->serialno);
	jam_string(buf, " ");
	jam_connection(buf, c);
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

static void jam_event(struct jambuf *buf, enum connection_event event, struct connection *c, struct annex *e)
{
	jam_enum_short(buf, &connection_event_names, event);
	jam_string(buf, " to ");
	jam_routing(buf, c);
	jam_annex(buf, e);
}

void ldbg_connection_establish(struct ike_sa *ike, struct child_sa *child,
			       enum direction direction, where_t where)
{
	struct annex ee = {
		.ike = &ike,
		.child = &child,
	};
	struct annex *e = &ee;
	LDBGP_JAMBUF(DBG_BASE, child->sa.st_logger, buf) {
		jam_string(buf, "routing: dispatch ");
		jam_event(buf,
			  (direction == DIRECTION_INBOUND ? CONNECTION_ESTABLISH_INBOUND :
			   direction == DIRECTION_OUTBOUND ? CONNECTION_ESTABLISH_OUTBOUND :
			   CONNECTION_EVENT_ROOF),
			  child->sa.st_connection, e);
		jam_string(buf, " ");
		jam_where(buf, where);
	}
}

bool routed(enum routing r)
{
	switch (r) {
	case RT_ROUTED_ONDEMAND:
	case RT_ROUTED_NEVER_NEGOTIATE:
	case RT_ROUTED_NEGOTIATION:
	case RT_ROUTED_FAILURE:
	case RT_ROUTED_TUNNEL:
		return true;
	case RT_UNROUTED:
	case RT_UNROUTED_NEGOTIATION:
	case RT_UNROUTED_TUNNEL:
		return false;
	}
	bad_case(r);
}

bool kernel_policy_installed(const struct connection *c)
{
	switch (c->child.routing) {
	case RT_UNROUTED_NEGOTIATION:
	case RT_ROUTED_ONDEMAND:
	case RT_ROUTED_NEVER_NEGOTIATE:
	case RT_ROUTED_NEGOTIATION:
	case RT_ROUTED_FAILURE:
	case RT_ROUTED_TUNNEL:
	case RT_UNROUTED_TUNNEL:
		return true;
	case RT_UNROUTED:
		return false;
	}
	bad_case(c->child.routing);
}

void set_routing_where(struct connection *c,
		       enum routing new_routing,
		       const struct child_sa *child,
		       where_t where)
{
	struct logger *logger = (child == NULL ? c->logger :
				 child->sa.st_logger);
	so_serial_t new_routing_sa = (child == NULL ? SOS_NOBODY :
				      child->sa.st_serialno);
	LDBGP_JAMBUF(DBG_BASE, logger, buf) {
		jam_string(buf, "routing: ");
		jam_routing(buf, c);
		jam_string(buf, " -> ");
		jam_enum_short(buf, &routing_names, new_routing);
		jam_string(buf, " ");
		jam_so(buf, new_routing_sa);
		jam_string(buf, " ");
		jam_where(buf, where);
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
 * XXX: this funcion is named to preserve some history.
 */
static void assign_holdpass(struct connection *c, enum kernel_policy_op op,
			    const char *reason)
{
	struct logger *logger = c->logger;
	PEXPECT(logger, (op == KERNEL_POLICY_OP_REPLACE ||
			 op == KERNEL_POLICY_OP_ADD));
	FOR_EACH_ITEM(spd, &c->child.spds) {
		if (!add_spd_kernel_policy(spd, op, DIRECTION_OUTBOUND,
					   SHUNT_KIND_NEGOTIATION,
					   logger, HERE, reason)) {
			llog(RC_LOG, logger,
			     "converting ondemand kernel policy to negotiating");
		}
	}
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
 * replace.  Should assign_holdpass() instead just look around?
 */

static void unrouted_instance_to_unrouted_negotiation(struct connection *c, const struct annex *e)
{
	struct logger *logger = c->logger;
	struct connection *t = c->clonedfrom; /* could be NULL */
	PEXPECT(logger, t != NULL && t->child.routing == RT_ROUTED_ONDEMAND);
	bool oe = ((c->policy & POLICY_OPPORTUNISTIC) != LEMPTY);
	const char *reason = (oe ? "replace unrouted opportunistic %trap with broad %pass or %hold" :
			      "replace unrouted %trap with broad %pass or %hold");
	assign_holdpass(c, KERNEL_POLICY_OP_REPLACE, reason);

	set_routing(c, RT_UNROUTED_NEGOTIATION, NULL);
	ipsecdoi_initiate(c, c->policy, 1, SOS_NOBODY,
			  e->inception, e->acquire->sec_label, e->acquire->background, e->acquire->logger);
}

/*
 * This is permanent yet unrouted; presumably the connection is being
 * triggered by whack.
 *
 * The negotiation is for the full set of SPDs which need to be
 * installed as KIND_NEGOTIATION.
 */

static void permanent_unrouted_to_unrouted_negotiation(struct connection *c, const struct annex *e)
{
	struct logger *logger = c->logger;
	PEXPECT(logger, (c->policy & POLICY_OPPORTUNISTIC) == LEMPTY);
	assign_holdpass(c, KERNEL_POLICY_OP_ADD,
			"installing negotiation kernel policy for permanent connection");
	set_routing(c, RT_UNROUTED_NEGOTIATION, NULL);
	/* ipsecdoi_initiate may replace SOS_NOBODY with a state */
	ipsecdoi_initiate(c, c->policy, 1, SOS_NOBODY,
			  e->inception, e->acquire->sec_label, e->acquire->background, e->acquire->logger);
}

/*
 * This is permanent and routed.
 *
 * The negotiation is for the full SPDs which have been installed as
 * KIND_ONDEMAND.  Hence the full suite of SPDs needs to be converted
 * to KIND_NEGOTIATION.
 *
 * But what of the lurking acquire?
 */

static void permanent_routed_ondemand_to_routed_negotiation(struct connection *c, const struct annex *e)
{
	struct logger *logger = c->logger;
	PEXPECT(logger, (c->policy & POLICY_OPPORTUNISTIC) == LEMPTY);
	assign_holdpass(c, KERNEL_POLICY_OP_REPLACE,
			"converting permanent connection's ondemand kernel policy to negotiating");
	/* the state isn't yet known */
	set_routing(c, RT_ROUTED_NEGOTIATION, NULL);
	/* ipsecdoi_initiate may replace SOS_NOBODY with a state */
	ipsecdoi_initiate(c, c->policy, 1, SOS_NOBODY, e->inception,
			  e->acquire->sec_label, e->acquire->background, e->acquire->logger);
}

static void routed_negotiation_to_routed_ondemand(struct connection *c,
						  struct logger *logger,
						  const char *reason)
{
	FOR_EACH_ITEM(spd, &c->child.spds) {
		if (!add_spd_kernel_policy(spd, KERNEL_POLICY_OP_REPLACE,
					   DIRECTION_OUTBOUND,
					   SHUNT_KIND_ONDEMAND,
					   logger, HERE, reason)) {
			llog(RC_LOG, logger, "%s failed", reason);
		}
	}
	set_routing(c, RT_ROUTED_ONDEMAND, NULL);
}

void connection_acquire(struct connection *c, threadtime_t *inception, const struct kernel_acquire *b)
{
	if (labeled(c)) {
		PASSERT(c->logger, labeled_parent(c));
		ipsecdoi_initiate(c, c->policy, 1, SOS_NOBODY,
				  inception, b->sec_label, b->background, b->logger);
		packet_buf pb;
		enum_buf hab;
		dbg("initiated on demand using security label and %s %s",
		    str_enum_short(&keyword_auth_names, c->local->host.config->auth, &hab),
		    str_packet(&b->packet, &pb));
		return;
	}

	dispatch(CONNECTION_ACQUIRE, c,
		 c->logger, HERE,
		 (struct annex) {
			 .inception = inception,
			 .acquire = b,
		 });
}

/*
 * Delete the ROUTED_TUNNEL, and possibly delete the connection.
 */

static void delete_routed_tunnel(struct connection *c,
				 where_t where,
				 struct annex *e)
{
	if (c->child.newest_routing_sa > (*e->child)->sa.st_serialno) {
		/* no longer child's */
		ldbg(c->logger, "keeping connection kernel policy; routing SA "PRI_SO" is newer",
		     pri_so(c->child.newest_routing_sa));
		delete_child_sa(e->child);
		return;
	}
	if (c->newest_ipsec_sa > (*e->child)->sa.st_serialno) {
		/* covered by above; no!? */
		ldbg(c->logger, "keeping connection kernel policy; IPsec SA "PRI_SO" is newer",
		     pri_so(c->newest_ipsec_sa));
		delete_child_sa(e->child);
		return;
	}
	if (should_revive_connection(*(e->child))) {
		/* XXX: should this be ROUTED_NEGOTIATING? */
		ldbg(c->logger, "replacing connection kernel policy with ROUTED_ONDEMAND; it will be revived");
		replace_ipsec_with_bare_kernel_policies(*(e->child), RT_ROUTED_ONDEMAND,
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
		(c->config->autostart == AUTOSTART_ONDEMAND ? RT_ROUTED_ONDEMAND :
		 c->config->failure_shunt != SHUNT_NONE ? RT_ROUTED_FAILURE :
		 RT_ROUTED_ONDEMAND);
	enum_buf rb;
	ldbg(c->logger, "replacing connection kernel policy with %s",
	     str_enum_short(&routing_names, new_routing, &rb));

	replace_ipsec_with_bare_kernel_policies((*e->child), new_routing,
						EXPECT_KERNEL_POLICY_OK, HERE);
	delete_child_sa(e->child);

	/*
	 * Never delete permanent (leaving only instances)
	 */
	if (c->kind == CK_PERMANENT) {
		ldbg(c->logger, "keeping connection; it is permanent");
		return;
	}

	PEXPECT(c->logger, c->kind == CK_INSTANCE);

	/*
	 * If the connection is shared with the IKE SA, don't delete
	 * it.
	 */
	if (pexpect(e->ike != NULL)/*IKEv1?*/ &&
	    c == (*e->ike)->sa.st_connection) {
		ldbg(c->logger, "keeping connection; shared with IKE SA "PRI_SO,
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

	ldbg(c->logger, "keeping connection; NO!");
	delete_connection(&c);
}

void connection_timeout(struct ike_sa **ike)
{
	/*
	 * Stop reviving children trying to use this IKE SA.
	 */
	ldbg_sa(*ike, "IKE SA is no longer viable");
	(*ike)->sa.st_viable_parent = false;
	pstat_sa_failed(&(*ike)->sa, REASON_TOO_MANY_RETRANSMITS);

	/*
	 * Weed out any lurking larval children (i.e., children that
	 * don't own their connection's route) that are sharing a
	 * connection.
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
			 * This delete doesn't get logged by
			 * delete_state(), do it here?!?
			 */
			attach_whack(child->sa.st_logger, (*ike)->sa.st_logger);
			llog_sa(RC_LOG, child, "deleting larval state due to timeout");
			delete_child_sa(&child);
		}
	}

	/*
	 * If the IKE SA's connection has Child SA owning the route
	 * then notify that first.
	 *
	 * This way, the IKE SA's connection can jump to the head of
	 * the revival queue.  Without this, the IKE SA's connection
	 * could end up flip-flopping between several of the children
	 * (harmless but annoying).
	 *
	 * Also remember if the first child was told; later the event
	 * only gets dispatched for IKE when there wasn't a child
	 * (such as during IKE_SA_INIT).
	 */

	bool told_connection = false;
	{
		struct child_sa *first_child =
			child_sa_by_serialno((*ike)->sa.st_connection->child.newest_routing_sa);
		if (first_child != NULL) {
			told_connection = true;
			attach_whack(first_child->sa.st_logger, (*ike)->sa.st_logger);
			/* will delete child and its logger */
			dispatch(CONNECTION_TIMEOUT_CHILD,
				 first_child->sa.st_connection,
				 first_child->sa.st_logger, HERE,
				 (struct annex) {
					 .ike = ike,
					 .child = &first_child,
				 });
		}
		PEXPECT((*ike)->sa.st_logger, first_child == NULL); /*gone!*/
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
			dispatch(CONNECTION_TIMEOUT_CHILD,
				 child->sa.st_connection,
				 child->sa.st_logger, HERE,
				 (struct annex) {
					 .ike = ike,
					 .child = &child,
				 });
			PEXPECT((*ike)->sa.st_logger, child == NULL);
		}
	}

	/*
	 * Finally notify the IKE SA.
	 *
	 * Only do this when there's no Child SA sharing the
	 * connection.
	 */
	if (told_connection) {
		struct connection *c = (*ike)->sa.st_connection;
		delete_ike_sa(ike);
		if (c->kind == CK_TEMPLATE &&
		    c->child.routing == RT_UNROUTED) {
			delete_connection(&c);
		}
	} else {
		dispatch(CONNECTION_TIMEOUT_IKE,
			 (*ike)->sa.st_connection,
			 (*ike)->sa.st_logger, HERE,
			 (struct annex) {
				 .ike = ike,
			 });
		/* no logger! */
		pexpect(*ike == NULL);
	}
}

void connection_route(struct connection *c)
{
	if (c->kind == CK_GROUP) {
		connection_group_route(c);
		return;
	}

	if (!oriented(c)) {
		llog(RC_ORIENT, c->logger,
		     "we cannot identify ourselves with either end of this connection");
		return;
	}

	dispatch(CONNECTION_ROUTE, c, c->logger, HERE,
		 (struct annex) {
			 0,
		 });

}

void connection_unroute(struct connection *c)
{
	if (c->kind == CK_GROUP) {
		/* XXX: may recurse back to here with group
		 * instances. */
		connection_group_unroute(c);
		return;
	}

	c->policy &= ~POLICY_ROUTE;
	dispatch(CONNECTION_UNROUTE, c,
		 c->logger, HERE,
		 (struct annex) {
			 0,
		 });
}

/*
 * Received a message telling us to delete the connection's Child.SA.
 */

void connection_delete_child(struct ike_sa *ike, struct child_sa **child)
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
		dispatch(CONNECTION_DELETE_CHILD,
			 (*child)->sa.st_connection,
			 (*child)->sa.st_logger, HERE,
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

void connection_delete_ike(struct ike_sa **ike)
{
	/*
	 * Caller is responsible for generating any messages; suppress
	 * delete_state()'s desire to send an out-of-band delete.
	 */
	(*ike)->sa.st_on_delete.skip_send_delete = true;
	(*ike)->sa.st_on_delete.skip_revival = true;
	(*ike)->sa.st_on_delete.skip_connection = true;

	ldbg_sa(*ike, "IKE SA is no longer viable");
	(*ike)->sa.st_viable_parent = false;
	/*
	 * Let state machine figure out how to react.
	 */
	dispatch(CONNECTION_DELETE_IKE,
		 (*ike)->sa.st_connection,
		 (*ike)->sa.st_logger, HERE,
		 (struct annex) {
			 .ike = ike,
		 });
}

void dispatch(enum connection_event event, struct connection *c,
	      struct logger *logger, where_t where,
	      struct annex ee)
{
	struct annex *e = &ee;
	LDBGP_JAMBUF(DBG_BASE, logger, buf) {
		jam_string(buf, "routing: dispatch ");
		jam_event(buf, event, c, e);
		jam_string(buf, " ");
		jam_where(buf, where);
	}

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
	/*
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
			if (NEVER_NEGOTIATE(c->policy)) {
				if (!unrouted_to_routed_never_negotiate(c)) {
					/* XXX: why whack only? */
					llog(WHACK_STREAM|RC_ROUTE, logger, "could not route");
					return;
				}
				PEXPECT(logger, c->child.routing == RT_ROUTED_NEVER_NEGOTIATE);
			} else if (labeled_template(c)) {
				if (!unrouted_to_routed_sec_label(c, logger)) {
					/* XXX: why whack only? */
					llog(RC_ROUTE, logger, "could not route");
					return;
				}
				PEXPECT(logger, c->child.routing == RT_ROUTED_ONDEMAND);
			} else {
				PEXPECT(logger, !labeled(c));
				if (!unrouted_to_routed_ondemand(c)) {
					/* XXX: why whack only? */
					llog(WHACK_STREAM|RC_ROUTE, logger, "could not route");
					return;
				}
				PEXPECT(logger, c->child.routing == RT_ROUTED_ONDEMAND);
			}
			return;

		case X(UNROUTE, ROUTED_NEVER_NEGOTIATE, TEMPLATE):
		case X(UNROUTE, ROUTED_NEVER_NEGOTIATE, PERMANENT):
			PEXPECT(logger, NEVER_NEGOTIATE(c->policy));
			delete_spd_kernel_policies(&c->child.spds,
						   EXPECT_KERNEL_POLICY_OK,
						   c->logger, where, "unroute permanent");
			/* stop updown_unroute() finding this
			 * connection */
			set_routing(c, RT_UNROUTED, NULL);
			do_updown_unroute(c);
			return;

		case X(UNROUTE, UNROUTED, PERMANENT):
			ldbg(logger, "already unrouted");
			return;
		case X(ACQUIRE, UNROUTED, PERMANENT):
			/* presumably triggered by whack */
			permanent_unrouted_to_unrouted_negotiation(c, e);
			PEXPECT(logger, c->child.routing == RT_UNROUTED_NEGOTIATION);
			return;

		case X(ROUTE, UNROUTED_NEGOTIATION, PERMANENT):
			c->policy |= POLICY_ROUTE;
			llog(RC_LOG_SERIOUS, logger,
			     "policy ROUTE added to negotiating connection");
			return;
		case X(UNROUTE, UNROUTED_NEGOTIATION, PERMANENT):
			delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
						   c->logger, where, "unroute permanent");
			set_routing(c, RT_UNROUTED, NULL);
			return;

		case X(ROUTE, ROUTED_NEGOTIATION, PERMANENT):
			c->policy |= POLICY_ROUTE;
			llog(RC_LOG_SERIOUS, logger, "connection already routed");
			return;
		case X(UNROUTE, ROUTED_NEGOTIATION, PERMANENT):
			delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
						   c->logger, where, "unroute permanent");
			/* do now so route_owner won't find us */
			set_routing(c, RT_UNROUTED, NULL);
			do_updown_unroute(c);
			return;

		case X(UNROUTE, ROUTED_ONDEMAND, PERMANENT):
			PEXPECT(logger, !NEVER_NEGOTIATE(c->policy));
			delete_spd_kernel_policies(&c->child.spds,
						   EXPECT_NO_INBOUND,
						   c->logger, where, "unroute permanent");
			/* stop updown_unroute() finding this
			 * connection */
			set_routing(c, RT_UNROUTED, NULL);
			do_updown_unroute(c);
			return;

		case X(ACQUIRE, ROUTED_ONDEMAND, PERMANENT):
			permanent_routed_ondemand_to_routed_negotiation(c, e);
			return;
		case X(ACQUIRE, ROUTED_NEGOTIATION, PERMANENT):
			llog(RC_LOG, c->logger, "connection already negotiating");
			return;

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
			set_routing(c, RT_UNROUTED, NULL);
			do_updown_unroute(c);
			return;

		case X(UNROUTE, UNROUTED_TUNNEL, PERMANENT):
			delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
						   c->logger, where, "unroute permanent");
			set_routing(c, RT_UNROUTED, NULL);
			return;

		case X(UNROUTE, UNROUTED, TEMPLATE):
			ldbg(logger, "already unrouted");
			return;
		case X(UNROUTE, ROUTED_ONDEMAND, TEMPLATE):
			delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
						   c->logger, where, "unroute template");
			/* do now so route_owner won't find us */
			set_routing(c, RT_UNROUTED, NULL);
			do_updown_unroute(c);
			return;

		case X(UNROUTE, UNROUTED, INSTANCE):
			ldbg(logger, "already unrouted");
			return;
		case X(ACQUIRE, UNROUTED, INSTANCE):
			/*
			 * Triggered by whack or acquire against the
			 * template which then instantiated this
			 * connection.
			 *
			 * The template may or may not be routed (but
			 * this code seems to expect it to).
			 */
			unrouted_instance_to_unrouted_negotiation(c, e);
			return;

		case X(UNROUTE, UNROUTED_NEGOTIATION, INSTANCE):
			delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
						   c->logger, where, "unroute instance");
			/* do now so route_owner won't find us */
			set_routing(c, RT_UNROUTED, NULL);
			return;

		case X(UNROUTE, ROUTED_NEGOTIATION, INSTANCE):
			delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
						   c->logger, where, "unroute instance");
			do_updown_unroute(c);
			return;

		case X(UNROUTE, ROUTED_TUNNEL, INSTANCE):
			llog(RC_RTBUSY, logger, "cannot unroute: route busy");
			return;

		case X(UNROUTE, ROUTED_ONDEMAND, INSTANCE):
			delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
						   c->logger, where, "unroute instance");
			/* do now so route_owner won't find us */
			set_routing(c, RT_UNROUTED, NULL);
			do_updown_unroute(c);
			return;

		case X(UNROUTE, ROUTED_FAILURE, INSTANCE):
			delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
						   c->logger, where, "unroute instance");
			/* do now so route_owner won't find us */
			set_routing(c, RT_UNROUTED, NULL);
			do_updown_unroute(c);
			return;

		case X(UNROUTE, UNROUTED_TUNNEL, INSTANCE):
			delete_spd_kernel_policies(&c->child.spds, EXPECT_NO_INBOUND,
						   c->logger, where, "unroute instance");
			set_routing(c, RT_UNROUTED, NULL);
			return;

		case X(TIMEOUT_IKE, UNROUTED, PERMANENT):
			/* ex, permanent+up */
			if (should_revive(&(*e->ike)->sa)) {
				schedule_revival(&(*e->ike)->sa, "timed out");
				delete_ike_sa(e->ike);
				return;
			}
			delete_ike_sa(e->ike);
			/* connection lives to fight another day */
			return;

		case X(TIMEOUT_IKE, ROUTED_NEGOTIATION, PERMANENT):
			/* ex, permanent+up */
			if (should_revive(&(*e->ike)->sa)) {
				routed_negotiation_to_routed_ondemand(c, logger,
								      "restoring ondemand kernel policy as will revive");
				PEXPECT(logger, c->child.routing == RT_ROUTED_ONDEMAND);
				schedule_revival(&(*e->ike)->sa, "timed out");
				delete_ike_sa(e->ike);
				return;
			}
			if (c->policy & POLICY_ROUTE) {
				routed_negotiation_to_routed_ondemand(c, logger,
								      "restoring ondemand kernel policy as routed");
				PEXPECT(logger, c->child.routing == RT_ROUTED_ONDEMAND);
				delete_ike_sa(e->ike);
				return;
			}
#if 0
			/* is this reachable? */
			routed_negotiation_to_unrouted(c);
#endif
			delete_ike_sa(e->ike);
			/* connection lives to fight another day */
			return;

		case X(TIMEOUT_IKE, UNROUTED_NEGOTIATION, INSTANCE):
			/* for instance, permenant ondemand */
			if (should_revive(&(*e->ike)->sa)) {
				schedule_revival(&(*e->ike)->sa, "timed out");
				delete_ike_sa(e->ike);
				return;
			}
			if (c->policy & POLICY_OPPORTUNISTIC) {
				/*
				 * A failed OE initiator, make shunt bare.
				 */
				orphan_holdpass(c, c->spd, logger);
				/*
				 * Change routing so we don't get cleared out
				 * when state/connection dies.
				 */
				set_routing(c, RT_UNROUTED, NULL);
			}
			delete_ike_sa(e->ike);
			delete_connection(&c);
			return;

		case X(TIMEOUT_CHILD, ROUTED_TUNNEL, PERMANENT):
		case X(DELETE_CHILD, ROUTED_TUNNEL, PERMANENT):
			/* permenant connections are never deleted */
			delete_routed_tunnel(c, where, e);
			return;
		case X(TIMEOUT_CHILD, ROUTED_TUNNEL, INSTANCE):
		case X(DELETE_CHILD, ROUTED_TUNNEL, INSTANCE):
			delete_routed_tunnel(c, where, e);
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
		}
	}

	LLOG_PEXPECT_JAMBUF(logger, where, buf) {
		jam_string(buf, "routing: unhandled ");
		jam_event(buf, event, c, e);
	}
}

/*
 * Delete any kernal policies for a connection and unroute it if route
 * isn't shared.
 */

static void do_updown_unroute(struct connection *c)
{
	do_updown_unowned_spds(UPDOWN_UNROUTE, c, &c->child.spds, NULL, c->logger);
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
		set_routing(c, RT_ROUTED_TUNNEL, child);
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
	case RT_ROUTED_ONDEMAND:
	case RT_ROUTED_NEVER_NEGOTIATE:
		llog_pexpect(child->sa.st_logger, HERE,
			     "%s() unexpected routing %s",
			     __func__, enum_name_short(&routing_names, cr));
		set_routing(c, RT_ROUTED_TUNNEL, child);
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
		set_routing(c, RT_UNROUTED_TUNNEL, child);
		break;
	case RT_ROUTED_ONDEMAND:
	case RT_ROUTED_NEVER_NEGOTIATE:
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
		set_routing(c, RT_UNROUTED_TUNNEL, child);
		break;
	case RT_UNROUTED:
	case RT_UNROUTED_NEGOTIATION:
	case RT_UNROUTED_TUNNEL:
		llog_pexpect(child->sa.st_logger, HERE,
			     "%s() unexpected routing %s",
			     __func__, enum_name_short(&routing_names, cr));
		set_routing(c, RT_UNROUTED_TUNNEL, child);
		break;
	}
}
