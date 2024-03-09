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
#include "connection_owner.h"

struct connection;
struct logger;
struct state;
struct kernel_acquire;
struct child_sa;
struct ike_sa;
enum direction;
enum initiated_by;
struct spd;

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
	RT_UNROUTED,				/* unrouted, inbound: none,        outbound: none */
	RT_ROUTED_NEVER_NEGOTIATE,		/* routed,   inbound: ?,           outbound: never */
	RT_ROUTED_ONDEMAND,			/* routed,   inbound: none,        outbound: ondemand */
	RT_UNROUTED_BARE_NEGOTIATION,		/* unrouted, inbound: none,        outbound: none */
	RT_UNROUTED_NEGOTIATION,		/* unrouted, inbound: none,        outbound: negotiation */
	RT_ROUTED_NEGOTIATION,			/* routed,   inbound: none,        outbound: negotiation */
	/* failed */
	RT_ROUTED_FAILURE,      		/* routed,   inbound: ?,           outbound: failure */
	/* half established */
	RT_UNROUTED_INBOUND,			/* unrouted, inbound: established, outbound: none */
	RT_UNROUTED_INBOUND_NEGOTIATION,	/* unrouted, inbound: established, outbound: negotiation */
	RT_ROUTED_INBOUND_NEGOTIATION,		/* routed,   inbound: established, outbound: negotiation */
	/* fully established */
	RT_ROUTED_TUNNEL,       		/* routed,   inbound: established, outbound: established */
	RT_UNROUTED_TUNNEL,			/* unrouted, inbound: established, outbound: established; used by MOBIKE */
#define CONNECTION_ROUTING_ROOF (RT_UNROUTED_TUNNEL+1)
};

extern const struct enum_names routing_names;
extern const struct enum_names routing_tails;

enum shunt_kind routing_shunt_kind(enum routing routing);
enum shunt_kind spd_shunt_kind(const struct spd *spd);

bool kernel_route_installed(const struct connection *c);
bool kernel_policy_installed(const struct connection *c);

void connection_routing_init(struct connection *);
bool pexpect_connection_is_unrouted(struct connection *c, struct logger *, where_t where);
bool pexpect_connection_is_disowned(struct connection *c, struct logger *, where_t where);
void state_disowns_connection(struct state *st);

void connection_route(struct connection *c, where_t where);
void connection_unroute(struct connection *c, where_t where);

/*
 * These are closely related
 */

void connection_initiated_ike(struct ike_sa *ike, enum initiated_by, where_t where);
void connection_initiated_child(struct ike_sa *ike, struct child_sa *child, enum initiated_by, where_t where);

void connection_establish_ike(struct ike_sa *ike, where_t where);

void connection_pending(struct connection *c, enum initiated_by, where_t where);
void connection_reschedule(struct connection *c, struct logger *logger, where_t where);

/*
 * Mobike
 */
void connection_resume(struct child_sa *child, where_t where);
void connection_suspend(struct child_sa *child, where_t where);

/*
 * Both delete_ike and timeout are close to identical?
 */
void connection_timeout_child(struct child_sa **child, where_t where);
void connection_delete_child(struct child_sa **child, where_t where);

void connection_timeout_ike(struct ike_sa **ike, where_t where);
void connection_delete_ike(struct ike_sa **ike, where_t where);

bool connection_establish_child(struct ike_sa *ike, struct child_sa *child, where_t where);
bool connection_establish_inbound(struct child_sa *child, where_t where);
bool connection_establish_outbound(struct ike_sa *ike, struct child_sa *child, where_t where);

PRINTF_LIKE(2)
void ldbg_routing(struct logger *logger, const char *fmt, ...);

#endif
