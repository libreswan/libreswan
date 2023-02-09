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

struct connection;
struct logger;
struct state;
struct kernel_acquire;
struct child_sa;
struct ike_sa;

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
	RT_UNROUTED_NEGOTIATION,	/* unrouted, but .negotiation_shunt installed */
	RT_ROUTED_PROSPECTIVE,		/* routed, and .prospective_shunt installed */
	RT_ROUTED_NEGOTIATION,		/* routed, and .negotiation_shunt installed */
	RT_ROUTED_FAILURE,      	/* routed, and .failure_shunt installed */
	RT_ROUTED_TUNNEL,       	/* routed, and erouted to an IPSEC SA group */
	RT_UNROUTED_TUNNEL,		/* unrouted, and established; used by MOBIKE */
};

extern const struct enum_names routing_names;
extern const struct enum_names routing_story;

#define routed(RS) ((RS) == RT_ROUTED_PROSPECTIVE ||		\
		    (RS) == RT_ROUTED_NEGOTIATION ||		\
		    (RS) == RT_ROUTED_FAILURE ||		\
		    (RS) == RT_ROUTED_TUNNEL)
#define erouted(RS) ((RS) == RT_UNROUTED_NEGOTIATION ||		\
		     (RS) == RT_ROUTED_PROSPECTIVE ||		\
		     (RS) == RT_ROUTED_NEGOTIATION ||		\
		     (RS) == RT_ROUTED_FAILURE ||		\
		     (RS) == RT_ROUTED_TUNNEL ||		\
		     (RS) == RT_UNROUTED_TUNNEL)

void connection_route(struct connection *c);
void connection_down(struct connection *c);
void connection_prospective(struct connection *c);
void connection_negotiating(struct connection *c,
			    const struct kernel_acquire *b);
void connection_resume(struct child_sa *child);
void connection_suspend(struct child_sa *child);

void connection_timeout(struct ike_sa *ike);

#endif
