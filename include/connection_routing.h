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

#ifndef CONNECTION_ROUTING_H
#define CONNECTION_ROUTING_H

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

enum connection_routing {
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

extern const struct names connection_routing_names;

#endif
