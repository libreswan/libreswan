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
enum initiated_by;

/*
 * Number of ways a connection can be owned by a state.
 */

enum connection_owner {

#define IKE_SA_OWNER_FLOOR NEGOTIATING_IKE_SA
	NEGOTIATING_IKE_SA,
	ESTABLISHED_IKE_SA,
#define IKE_SA_OWNER_ROOF (ESTABLISHED_IKE_SA+1)

#define CHILD_SA_OWNER_FLOOR NEWEST_ROUTING_SA
	NEWEST_ROUTING_SA,
	NEWEST_IPSEC_SA,
#define CHILD_SA_OWNER_ROOF NEWEST_IPSEC_SA

#define CONNECTION_OWNER_ROOF (NEWEST_IPSEC_SA+1)
};

extern const struct enum_names connection_owner_names;
extern const struct enum_names connection_owner_story;

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
	RT_BARE_NEGOTIATION,		/* negotiating, unrouted, no .negotiation_shunt installed */
	RT_UNROUTED_NEGOTIATION,	/* negotiating, unrouted, .negotiation_shunt installed */
	RT_ROUTED_NEGOTIATION,		/* negotiating, routed, .negotiation_shunt installed */
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
void connection_unpend(struct connection *c, struct logger *logger, where_t where);

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
