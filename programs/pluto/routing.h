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
#include "connection_routing.h"

enum terminate_reason;
struct connection;
struct logger;
struct state;
struct kernel_acquire;
struct child_sa;
struct ike_sa;
enum direction;
enum initiated_by;
struct spd;

enum shunt_kind routing_shunt_kind(enum connection_routing routing);
enum shunt_kind spd_shunt_kind(const struct spd *spd);

bool kernel_route_installed(const struct connection *c);
bool kernel_policy_installed(const struct connection *c);
bool outbound_kernel_policy_installed(const struct connection *c);

void connection_routing_init(struct connection *);
bool pexpect_connection_is_unrouted(struct connection *c, struct logger *, where_t where);
bool pexpect_connection_is_disowned(struct connection *c, struct logger *, where_t where);
void state_disowns_connection(struct state *st);

void connection_oriented(struct connection *c,
			 bool background,
			 where_t where);

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

void connection_teardown_ike(struct ike_sa **ike, enum terminate_reason reason, where_t where);
void connection_teardown_child(struct child_sa **child, enum terminate_reason reason, where_t where);

bool connection_establish_child(struct ike_sa *ike, struct child_sa *child, where_t where);
bool connection_establish_inbound(struct child_sa *child, where_t where);
bool connection_establish_outbound(struct ike_sa *ike, struct child_sa *child, where_t where);

PRINTF_LIKE(2)
void ldbg_routing(struct logger *logger, const char *fmt, ...);

/* jam the routing SA prefixed by its type */
void jam_routing_sa(struct jambuf *buf, const struct connection *c);

#endif
