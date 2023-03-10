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

static void do_updown_unroute(struct connection *c);

enum connection_event {
	CONNECTION_ROUTE,
	CONNECTION_UNROUTE,
	CONNECTION_ONDEMAND,
	CONNECTION_DELETE_CHILD,
	CONNECTION_DELETE_IKE,
	CONNECTION_TIMEOUT,
#define CONNECTION_EVENT_ROOF (CONNECTION_TIMEOUT+1)
};

static const char *connection_event_name[] = {
#define S(E) [E] = #E
	S(CONNECTION_ROUTE),
	S(CONNECTION_UNROUTE),
	S(CONNECTION_ONDEMAND),
	S(CONNECTION_DELETE_CHILD),
	S(CONNECTION_DELETE_IKE),
	S(CONNECTION_TIMEOUT),
#undef S
};

static enum_names connection_event_names = {
	0, CONNECTION_TIMEOUT,
	ARRAY_REF(connection_event_name),
	"CONNECTION_",
	NULL,
};

struct annex {
	struct ike_sa *ike;
	struct child_sa *child;
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

static void jam_event(struct jambuf *buf, enum connection_event event, struct connection *c, struct annex *e)
{
	jam_enum_short(buf, &connection_event_names, event);
	jam_string(buf, " to ");
	jam_enum_short(buf, &routing_names, c->child.routing);
	jam_string(buf, " ");
	jam_enum_short(buf, &connection_kind_names, c->kind);
	jam_string(buf, " ");
	jam(buf, PRI_CO, pri_co(c->serialno));
	jam_string(buf, " ");
	jam_connection(buf, c);
	if (e->ike != NULL) {
		jam_event_sa(buf, &e->ike->sa);
	}
	if (e->child != NULL) {
		jam_event_sa(buf, &e->child->sa);
	}
	if (e->acquire != NULL) {
		jam_string(buf, "; ");
		jam_kernel_acquire(buf, e->acquire);
	}
}

void set_child_routing_where(struct connection *c, enum routing routing,
			     so_serial_t so, where_t where)
{
	connection_buf cb;
	enum_buf ob, nb;
	ldbg(c->logger, "kernel: routing connection "PRI_CONNECTION" "PRI_SO"->"PRI_SO" %s->%s "PRI_WHERE,
	     pri_connection(c, &cb),
	     pri_so(c->child.newest_routing_sa),
	     pri_so(so),
	     str_enum(&routing_story, c->child.routing, &ob),
	     str_enum(&routing_story, routing, &nb),
	     pri_where(where));
	c->child.routing = routing;
	c->child.newest_routing_sa = so;
}

static void ondemand_unrouted_to_unrouted_negotiation(struct connection *c, const struct annex *e)
{
	/*
	 * For instance:
	 * - an instance with a routed prospective template
	 * but also:
	 * - an unrouted permanent by whack?
	 * - an instance with an unrouted template due to whack?
	 */

	struct logger *logger = c->logger;
	struct spd_route *spd = c->spd; /*XXX:only-one!?!*/
	bool oe = ((c->policy & POLICY_OPPORTUNISTIC) != LEMPTY);

	/* used below in pexpects */
	struct connection *t = connection_by_serialno(c->clonedfrom); /* could be NULL */

	enum routing old_routing = c->child.routing;	/* routing, old */
	enum routing new_routing = RT_UNROUTED_NEGOTIATION;
	enum kernel_policy_op op = KERNEL_POLICY_OP_ADD;
	/* XXX: these descriptions make no sense */
	const char *reason = (oe ? "replace unrouted opportunistic %trap with broad %pass or %hold" :
			      "replace unrouted %trap with broad %pass or %hold");
	PEXPECT(logger, t == NULL || t->child.routing == RT_ROUTED_PROSPECTIVE);
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

	set_child_routing(c, new_routing, c->child.newest_routing_sa);
	dbg("kernel: %s() done - returning success", __func__);

	ipsecdoi_initiate(c, c->policy, 1, SOS_NOBODY,
			  e->inception, e->acquire->sec_label, e->acquire->background, e->acquire->logger);
}

static void ondemand_routed_prospective_to_routed_negotiation(struct connection *c, const struct annex *e)
{
	struct logger *logger = c->logger;
	struct spd_route *spd = c->spd; /*XXX:only-one!?!*/
	bool oe = ((c->policy & POLICY_OPPORTUNISTIC) != LEMPTY);

	/* used below in pexpects */
	struct connection *t = connection_by_serialno(c->clonedfrom); /* could be NULL */

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
	enum routing old_routing = c->child.routing;	/* routing, old */
	enum routing new_routing = RT_ROUTED_NEGOTIATION;
	enum kernel_policy_op op = KERNEL_POLICY_OP_REPLACE;
	/* XXX: these descriptions make no sense */
	const char *reason = (oe ? "broad prospective opportunistic %pass or %hold" :
			      "broad prospective %pass or %hold");
	PEXPECT(logger, t == NULL);
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

	set_child_routing(c, new_routing, c->child.newest_routing_sa);
	dbg("kernel: %s() done - returning success", __func__);

	ipsecdoi_initiate(c, c->policy, 1, SOS_NOBODY,
			  e->inception, e->acquire->sec_label, e->acquire->background, e->acquire->logger);
}

void connection_ondemand(struct connection *c, threadtime_t *inception, const struct kernel_acquire *b)
{
	/*
	 * SEC_LABELs get instantiated as follows:
	 *
	 *   labeled_template(): an on-demand (routed) connenection
	 *   CK_TEMPLATE.
	 *
	 *   labeled_parent(): the labeled-template instantiated as a
	 *   CK_TEMPLATE.  This should probably be CK_INSTANCE or
	 *   CK_PARENT?
	 *
	 *   labeled_child(): the labeled parent instantiated as
	 *   CK_INSTANCE.  This should probably be CK_CHILD?
	 *
	 * None of which really fit.  Unlike CK_INSTANCE where the
	 * ondemand connection has both the IKE and Child SAs tied to
	 * it.  Labeled IPsec instead has the IKE SA tied to
	 * labeled-parent, and, optionally, the Child SA tied to
	 * labeled-child.
	 *
	 * Rather than have the template m/c try to deal with this,
	 * handle it here.
	 *
	 * XXX: labeled_template(c) here looks wrong - it should have
	 * been instantiated?
	 */
	if (labeled_torp(c)) {
		ipsecdoi_initiate(c, c->policy, 1, SOS_NOBODY,
				  inception, b->sec_label, b->background, b->logger);
		packet_buf pb;
		enum_buf hab;
		dbg("initiated on demand using security label and %s %s",
		    str_enum_short(&keyword_auth_names, c->local->host.config->auth, &hab),
		    str_packet(&b->packet, &pb));
		return;
	}

	dispatch(CONNECTION_ONDEMAND, c,
		 c->logger, HERE,
		 (struct annex) {
			 .inception = inception,
			 .acquire = b,
		 });
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

/*
 * Return TRUE when the connection must be preserved.
 */
static bool delete_routed_tunnel_child(struct connection *c,
				       struct logger *logger,
				       struct annex *e)
{
	if (c->child.newest_routing_sa > e->child->sa.st_serialno) {
		/* no longer child's */
		ldbg(logger, "not the newest routing SA; leaving connection alone");
		delete_child_sa(&e->child);
		return true;
	}
	if (c->newest_ipsec_sa > e->child->sa.st_serialno) {
		/* covered by above? */
		llog_pexpect(logger, HERE,
			     "not the newest child; leaving connection alone");
		delete_child_sa(&e->child);
		return true;
	}
	if (should_revive(&(e->child->sa))) {
		/* XXX: should this be ROUTED_NEGOTIATING? */
		replace_ipsec_with_bare_kernel_policies(e->child, RT_ROUTED_PROSPECTIVE,
							EXPECT_KERNEL_POLICY_OK, HERE);
		schedule_revival(&(e->child->sa));
		delete_child_sa(&e->child);
		return true;
	}
	if (c->config->autostart == AUTOSTART_ONDEMAND) {
		/*
		 * Change routing so we don't get cleared out
		 * when state/connection dies.
		 */
		replace_ipsec_with_bare_kernel_policies(e->child, RT_ROUTED_PROSPECTIVE,
							EXPECT_KERNEL_POLICY_OK, HERE);
		delete_child_sa(&e->child);
		return false;
	}
	/* XXX: should this be responder only? */
	enum routing new_routing =
		(c->config->failure_shunt != SHUNT_NONE ? RT_ROUTED_FAILURE :
		 RT_ROUTED_PROSPECTIVE);
	replace_ipsec_with_bare_kernel_policies(e->child, new_routing,
						EXPECT_KERNEL_POLICY_OK, HERE);
	delete_child_sa(&e->child);
	return false;
}

void connection_timeout(struct ike_sa *ike)
{
	struct connection *c = ike->sa.st_connection;
	dispatch(CONNECTION_TIMEOUT, c,
		 ike->sa.st_logger, HERE,
		 (struct annex) {
			 .ike = ike,
		 });
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

	dispatch(CONNECTION_ROUTE, c,
		 c->logger, HERE,
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

void connection_delete_child(struct child_sa **childp)
{
	struct child_sa *child = (*childp); *childp = NULL;
	struct connection *c = child->sa.st_connection;
#if 0
	if (c->kind != CK_PERMANENT) {
		ldbg_sa(child, "%s() doesn't yet handle %s",
			__func__, enum_name_short(&connection_kind_names, c->kind));
		child->sa.st_on_delete.send_delete = DONT_SEND_DELETE;
		delete_state(&child->sa);
		return;
	}
#endif
	/*
	 * Caller is responsible for generating any messages; suppress
	 * delete_state()'s desire to send an out-of-band delete.
	 */
	child->sa.st_on_delete.send_delete = DONT_SEND_DELETE;
	child->sa.st_on_delete.skip_revival = true;
	child->sa.st_on_delete.skip_connection = true;
	/*
	 * Let state machine figure out how to react.
	 */
	dispatch(CONNECTION_DELETE_CHILD, c,
		 child->sa.st_logger, HERE,
		 (struct annex) {
			 .child = child,
		 });
}

void connection_delete_ike(struct ike_sa **ikep)
{
	struct ike_sa *ike = (*ikep); *ikep = NULL;
	struct connection *c = ike->sa.st_connection;
	/*
	 * Caller is responsible for generating any messages; suppress
	 * delete_state()'s desire to send an out-of-band delete.
	 */
	ike->sa.st_on_delete.send_delete = DONT_SEND_DELETE;
	ike->sa.st_on_delete.skip_revival = true;
	ike->sa.st_on_delete.skip_connection = true;
	/*
	 * Let state machine figure out how to react.
	 */
	dispatch(CONNECTION_DELETE_IKE, c,
		 ike->sa.st_logger, HERE,
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
		jam_string(buf, "dispatch ");
		jam_event(buf, event, c, e);
		jam_string(buf, " ");
		jam_where(buf, where);
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

		case X(ROUTE, UNROUTED, PERMANENT):
			c->policy |= POLICY_ROUTE; /* always */
			if (!install_prospective_kernel_policy(c)) {
				/* XXX: why whack only? */
				llog(WHACK_STREAM|RC_ROUTE, logger, "could not route");
				return;
			}
			PEXPECT(logger, c->child.routing == RT_ROUTED_PROSPECTIVE);
			return;
		case X(UNROUTE, UNROUTED, PERMANENT):
			ldbg(logger, "already unrouted");
			return;
		case X(ONDEMAND, UNROUTED, PERMANENT):
			/* presumably triggered by whack */
			ondemand_unrouted_to_unrouted_negotiation(c, e);
			return;
		case X(TIMEOUT, UNROUTED, PERMANENT):
			/* ex, permanent+up */
			if (should_retry(e->ike)) {
				retry(e->ike);
				return;
			}
			if (should_revive(&(e->ike->sa))) {
				schedule_revival(&(e->ike->sa));
				return;
			}
			pstat_sa_failed(&e->ike->sa, REASON_TOO_MANY_RETRANSMITS);
			return;

		case X(ROUTE, UNROUTED_NEGOTIATION, PERMANENT):
			c->policy |= POLICY_ROUTE;
			llog(RC_LOG_SERIOUS, logger,
			     "policy ROUTE added to negotiating connection");
			return;
		case X(UNROUTE, UNROUTED_NEGOTIATION, PERMANENT):
			delete_connection_kernel_policies(c);
			set_child_routing(c, RT_UNROUTED, c->child.newest_routing_sa);
			return;
		case X(TIMEOUT, UNROUTED_NEGOTIATION, PERMANENT):
			/* for instance, permenant ondemand */
			if (should_retry(e->ike)) {
				retry(e->ike);
				return;
			}
			if (should_revive(&(e->ike->sa))) {
				schedule_revival(&(e->ike->sa));
				return;
			}
			pstat_sa_failed(&e->ike->sa, REASON_TOO_MANY_RETRANSMITS);
			return;

		case X(ROUTE, ROUTED_NEGOTIATION, PERMANENT):
			c->policy |= POLICY_ROUTE;
			llog(RC_LOG_SERIOUS, logger, "connection already routed");
			return;
		case X(UNROUTE, ROUTED_NEGOTIATION, PERMANENT):
			delete_connection_kernel_policies(c);
			/* do now so route_owner won't find us */
			set_child_routing(c, RT_UNROUTED, c->child.newest_routing_sa);
			do_updown_unroute(c);
			return;
		case X(TIMEOUT, ROUTED_NEGOTIATION, PERMANENT):
			if (should_retry(e->ike)) {
				retry(e->ike);
				return;
			}
			if (should_revive(&(e->ike->sa))) {
				schedule_revival(&(e->ike->sa));
				return;
			}
			pstat_sa_failed(&e->ike->sa, REASON_TOO_MANY_RETRANSMITS);
			return;

		case X(UNROUTE, ROUTED_PROSPECTIVE, PERMANENT):
			delete_connection_kernel_policies(c);
			set_child_routing(c, RT_UNROUTED, c->child.newest_routing_sa);
			do_updown_unroute(c);
			return;
		case X(ONDEMAND, ROUTED_PROSPECTIVE, PERMANENT):
			ondemand_routed_prospective_to_routed_negotiation(c, e);
			return;

		case X(ROUTE, ROUTED_TUNNEL, PERMANENT):
			c->policy |= POLICY_ROUTE; /* always */
			llog(RC_LOG, logger, "policy ROUTE added to established connection");
			return;
		case X(UNROUTE, ROUTED_TUNNEL, PERMANENT):
			llog(RC_RTBUSY, logger, "cannot unroute: route busy");
			return;
		case X(DELETE_CHILD, ROUTED_TUNNEL, PERMANENT):
			/* permenant connections are never deleted */
			delete_routed_tunnel_child(c, logger, e);
			return;
		case X(TIMEOUT, ROUTED_TUNNEL, PERMANENT):
			/* don't retry as well */
			if (should_revive(&(e->ike->sa))) {
				schedule_revival(&(e->ike->sa));
				return;
			}
			pstat_sa_failed(&e->ike->sa, REASON_TOO_MANY_RETRANSMITS);
			return;

		case X(UNROUTE, ROUTED_FAILURE, PERMANENT):
			delete_connection_kernel_policies(c);
			/* do now so route_owner won't find us */
			set_child_routing(c, RT_UNROUTED, c->child.newest_routing_sa);
			do_updown_unroute(c);
			return;

		case X(UNROUTE, UNROUTED_TUNNEL, PERMANENT):
			delete_connection_kernel_policies(c);
			set_child_routing(c, RT_UNROUTED, c->child.newest_routing_sa);
			return;

		case X(ROUTE, UNROUTED, TEMPLATE):
			c->policy |= POLICY_ROUTE;
			if (!install_prospective_kernel_policy(c)) {
				/* XXX: why whack only? */
				llog(WHACK_STREAM|RC_ROUTE, logger, "could not route");
				return;
			}
			PEXPECT(logger, c->child.routing == RT_ROUTED_PROSPECTIVE);
			return;
		case X(UNROUTE, UNROUTED, TEMPLATE):
			ldbg(logger, "already unrouted");
			return;
		case X(UNROUTE, ROUTED_PROSPECTIVE, TEMPLATE):
			delete_connection_kernel_policies(c);
			/* do now so route_owner won't find us */
			set_child_routing(c, RT_UNROUTED, c->child.newest_routing_sa);
			do_updown_unroute(c);
			return;

		case X(UNROUTE, UNROUTED, INSTANCE):
			ldbg(logger, "already unrouted");
			return;
		case X(ONDEMAND, UNROUTED, INSTANCE):
			/*
			 * Triggered by whack or ondemand against the
			 * template which instantiates this
			 * connection.
			 *
			 * The template may or may not be routed (but
			 * this code seems to expect it to).
			 */
			ondemand_unrouted_to_unrouted_negotiation(c, e);
			return;
		case X(TIMEOUT, UNROUTED, INSTANCE):
			/* for instance, permanent+up */
			if (should_retry(e->ike)) {
				retry(e->ike);
				return;
			}
			if (should_revive(&(e->ike->sa))) {
				schedule_revival(&(e->ike->sa));
				return;
			}
			pstat_sa_failed(&e->ike->sa, REASON_TOO_MANY_RETRANSMITS);
			return;

		case X(UNROUTE, UNROUTED_NEGOTIATION, INSTANCE):
			delete_connection_kernel_policies(c);
			/* do now so route_owner won't find us */
			set_child_routing(c, RT_UNROUTED, c->child.newest_routing_sa);
			return;
		case X(TIMEOUT, UNROUTED_NEGOTIATION, INSTANCE):
			/* for instance, permenant ondemand */
			if (should_retry(e->ike)) {
				retry(e->ike);
				return;
			}
			if (should_revive(&(e->ike->sa))) {
				schedule_revival(&(e->ike->sa));
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
				set_child_routing(c, RT_UNROUTED, c->child.newest_routing_sa);
			}
			pstat_sa_failed(&e->ike->sa, REASON_TOO_MANY_RETRANSMITS);
			return;

		case X(UNROUTE, ROUTED_NEGOTIATION, INSTANCE):
			delete_connection_kernel_policies(c);
			do_updown_unroute(c);
			return;
		case X(TIMEOUT, ROUTED_NEGOTIATION, INSTANCE):
			if (should_retry(e->ike)) {
				retry(e->ike);
				return;
			}
			if (should_revive(&(e->ike->sa))) {
				schedule_revival(&(e->ike->sa));
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
				set_child_routing(c, RT_ROUTED_PROSPECTIVE/*lie?!?*/,
						  c->child.newest_routing_sa);
			}
			pstat_sa_failed(&e->ike->sa, REASON_TOO_MANY_RETRANSMITS);
			return;

		case X(UNROUTE, ROUTED_TUNNEL, INSTANCE):
			llog(RC_RTBUSY, logger, "cannot unroute: route busy");
			return;
		case X(DELETE_CHILD, ROUTED_TUNNEL, INSTANCE):
			if (delete_routed_tunnel_child(c, logger, e)) {
				/* connection is being revived so
				 * don't touch */
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
				dbg("connection "PRI_CONNECTION" in use by #%lu, skipping delete-unused",
				    pri_connection(c, &cb), sf.st->st_serialno);
				return;
			}

			delete_connection(&c);
			return;
		case X(TIMEOUT, ROUTED_TUNNEL, INSTANCE):
			/* don't retry as well */
			if (should_revive(&(e->ike->sa))) {
				schedule_revival(&(e->ike->sa));
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
				set_child_routing(c, RT_ROUTED_NEGOTIATION/*lie?!?*/,
						  SOS_NOBODY);
			}
			pstat_sa_failed(&e->ike->sa, REASON_TOO_MANY_RETRANSMITS);
			return;

		case X(UNROUTE, ROUTED_PROSPECTIVE, INSTANCE):
			delete_connection_kernel_policies(c);
			/* do now so route_owner won't find us */
			set_child_routing(c, RT_UNROUTED, c->child.newest_routing_sa);
			do_updown_unroute(c);
			return;

		case X(UNROUTE, ROUTED_FAILURE, INSTANCE):
			delete_connection_kernel_policies(c);
			/* do now so route_owner won't find us */
			set_child_routing(c, RT_UNROUTED, c->child.newest_routing_sa);
			do_updown_unroute(c);
			return;

		case X(UNROUTE, UNROUTED_TUNNEL, INSTANCE):
			delete_connection_kernel_policies(c);
			set_child_routing(c, RT_UNROUTED, c->child.newest_routing_sa);
			return;

		}
	}

	LLOG_PEXPECT_JAMBUF(logger, where, buf) {
		jam_string(buf, "unhandled ");
		jam_event(buf, event, c, e);
	}
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
		set_child_routing(c, RT_ROUTED_TUNNEL, c->child.newest_routing_sa);
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
		set_child_routing(c, RT_ROUTED_TUNNEL, c->child.newest_routing_sa);
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
		set_child_routing(c, RT_UNROUTED_TUNNEL, c->child.newest_routing_sa);
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
		set_child_routing(c, RT_UNROUTED_TUNNEL, c->child.newest_routing_sa);
		break;
	case RT_UNROUTED:
	case RT_UNROUTED_NEGOTIATION:
	case RT_UNROUTED_TUNNEL:
		llog_pexpect(child->sa.st_logger, HERE,
			     "%s() unexpected routing %s",
			     __func__, enum_name_short(&routing_names, cr));
		set_child_routing(c, RT_UNROUTED_TUNNEL, c->child.newest_routing_sa);
		break;
	}
}
