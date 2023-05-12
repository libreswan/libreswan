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

#ifndef ROUTING_H
#define ROUTING_H

/*
 * The transition contains broken code.
 */
#define BROKEN_TRANSITION true

#include "pluto_timing.h"	/* for threadtime_t */

struct connection;
struct logger;
struct state;
struct kernel_acquire;
struct child_sa;
struct ike_sa;
enum direction;

/*
 * Routing status.
 *
 * Note: routing ignores the source address, but kernel policies do
 * not!
 *
 * Note: a connection can only be routed if it is NEVER_NEGOTIATE or
 * HAS_IPSEC_POLICY.
 *
 * Note: UNROUTED can be misleading.  .  A CK_INSTANCE is UNROUTED
 * while the CK_TEMPLATE has prospective route.
 */

enum routing {
	RT_UNROUTED,			/* unrouted */
	RT_ROUTED_NEVER_NEGOTIATE,	/* routed, and .never_negotiate_shunt installed */
	RT_UNROUTED_ONDEMAND,		/* unrouted, and SHUNT_TRAP installed */
	RT_ROUTED_ONDEMAND,		/* routed, and SHUNT_TRAP installed */
	RT_UNROUTED_NEGOTIATION,	/* unrouted, but .negotiation_shunt installed */
	RT_ROUTED_NEGOTIATION,		/* routed, and .negotiation_shunt installed */
	RT_UNROUTED_FAILURE,      	/* unrouted, and .failure_shunt installed */
	RT_ROUTED_FAILURE,      	/* routed, and .failure_shunt installed */
	/* half established */
	RT_UNROUTED_INBOUND,		/* unrouted, outbound: negotiation, inbound: installed */
	RT_ROUTED_INBOUND,		/* routed, outbound: negotiate, inbound: installed */
	/* fully established */
	RT_ROUTED_TUNNEL,       	/* routed, and erouted to an IPSEC SA group */
	RT_UNROUTED_TUNNEL,		/* unrouted, and established; used by MOBIKE */
#define CONNECTION_ROUTING_ROOF (RT_UNROUTED_TUNNEL+1)
};

extern const struct enum_names routing_names;
extern const struct enum_names routing_story;

bool routed(enum routing r);
enum shunt_kind routing_shunt_kind(enum routing routing);
bool kernel_policy_installed(const struct connection *c);

void connection_route(struct connection *c, where_t where);
void connection_unroute(struct connection *c, where_t where);

/*
 * These are speculative.
 */
void connection_up(struct connection *c, where_t where);
void connection_down(struct connection *c, where_t where);

/*
 * These are closely related; with one possibly redundant?
 */
void connection_initiate(struct connection *c, const threadtime_t *inception,
			 bool background, where_t where);
void connection_revive(struct connection *c, where_t where);

void connection_acquire(struct connection *c, threadtime_t *inception,
			const struct kernel_acquire *b, where_t where);

/*
 * Mobike
 */
void connection_resume(struct child_sa *child, where_t where);
void connection_suspend(struct child_sa *child, where_t where);

/*
 * Both delete_ike and timeout are close to identical?
 */
void connection_timeout_ike(struct ike_sa **ike, where_t where);
void connection_delete_child(struct ike_sa *ike, struct child_sa **child, where_t where);
void connection_delete_ike(struct ike_sa **ike, where_t where);

/* fake a debug message for establish for now */
void fake_connection_establish_inbound(struct ike_sa *ike, struct child_sa *child, where_t where);
void fake_connection_establish_outbound(struct ike_sa *ike, struct child_sa *child, where_t where);

enum routing_event {
	/* fiddle with the ROUTE bit */
	CONNECTION_ROUTE,
	CONNECTION_UNROUTE,
	/* fiddle with the UP bit (speculative) */
	CONNECTION_UP,
	CONNECTION_DOWN,
	/* start a connection */
	CONNECTION_INITIATE,
	CONNECTION_ACQUIRE,
	CONNECTION_REVIVE,
	/* establish a connection (speculative) */
	CONNECTION_ESTABLISH_INBOUND,
	CONNECTION_ESTABLISH_OUTBOUND,
	/* tear down a connection */
	CONNECTION_DELETE_IKE,
	CONNECTION_DELETE_CHILD,
	CONNECTION_TIMEOUT_IKE,
	CONNECTION_TIMEOUT_CHILD,
	/* mobike */
	CONNECTION_SUSPEND,
	CONNECTION_RESUME,
#define CONNECTION_EVENT_ROOF (CONNECTION_RESUME+1)
};

void set_routing(enum routing_event event,
		 struct connection *c, enum routing routing,
		 const struct child_sa *child, where_t where);

#endif
