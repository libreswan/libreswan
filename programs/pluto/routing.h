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

#include "ip_packet.h"
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
	RT_UNROUTED,			/* unrouted, no shunts */
	RT_ROUTED_NEVER_NEGOTIATE,	/* routed, and .never_negotiate_shunt installed */
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

bool routed(const struct connection *c);
enum shunt_kind routing_shunt_kind(enum routing routing);
bool kernel_policy_installed(const struct connection *c);

void connection_unrouted(struct connection *);
void connection_routing_clear(struct state *st);

void connection_route(struct connection *c, where_t where);
void connection_unroute(struct connection *c, where_t where);

/*
 * These are closely related
 */
void connection_initiate(struct connection *c, const threadtime_t *inception,
			 bool background, where_t where);
void connection_establish_ike(struct ike_sa *ike, where_t where);

void connection_revive(struct connection *c, const threadtime_t *inception, where_t where);
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
void connection_timeout_ike_family(struct ike_sa **ike, where_t where);
void connection_delete_ike_family(struct ike_sa **ike, where_t where);

void connection_timeout_child(struct child_sa **child, where_t where);
void connection_delete_child(struct child_sa **child, where_t where);

void connection_timeout_ike(struct ike_sa **ike, where_t where);
void connection_delete_ike(struct ike_sa **ike, where_t where);


/* fake a debug message for establish for now */
void fake_connection_establish_inbound(struct ike_sa *ike, struct child_sa *child, where_t where);
void fake_connection_establish_outbound(struct ike_sa *ike, struct child_sa *child, where_t where);

enum routing_event {
	/* fiddle with the ROUTE bit */
	CONNECTION_ROUTE,
	CONNECTION_UNROUTE,
	/* start/stop a connection */
	CONNECTION_INITIATE,
	CONNECTION_ACQUIRE,
	CONNECTION_REVIVE,
	/* establish a connection (speculative) */
	CONNECTION_ESTABLISH_IKE,
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

struct routing_annex {
	struct ike_sa **ike;
	struct child_sa **child;
	const threadtime_t *const inception;
	ip_packet packet;
	bool background;
	shunk_t sec_label;
};

/*
 * Wrapper that zaps the IKE SA of any children before deleting the
 * IKE SA.
 *
 * IKEv1: any non-established children are deleted.  Established
 * children are set free.
 *
 * IKEv2: all children are deleted.
 */
void connection_zap_ike_family(struct ike_sa **ike, enum routing_event event, where_t where);

void jam_routing_annex(struct jambuf *buf, const struct routing_annex *e);

void set_routing(enum routing_event event,
		 struct connection *c, enum routing routing,
		 struct child_sa **child, where_t where);

PRINTF_LIKE(2)
void ldbg_routing(struct logger *logger, const char *fmt, ...);

#endif
