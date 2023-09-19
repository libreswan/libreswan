/* tables of names for values defined in constants.h
 *
 * Copyright (C) 2022 Andrew Cagney
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

#include "lswcdefs.h"		/* for ARRAY_REF() */
#include "enum_names.h"

#include "defs.h"
#include "routing.h"		/* for enum routing */

/* routing status names */
static const char *const routing_story_strings[] = {
	[RT_UNROUTED] = "unrouted",			  /* unrouted */
	[RT_UNROUTED_REVIVAL] = "unrouted revival",	  /* unrouted, no shunts, revival */
	[RT_ROUTED_REVIVAL] = "prospective erouted",	  /* routed, ondemand shunts, revival (LOG A LIE) */
	[RT_UNROUTED_NEGOTIATION] = "unrouted HOLD",      /* unrouted, but HOLD shunt installed */
	[RT_UNROUTED_INBOUND] = "unrouted HOLD",	/* unrouted, outbound negotiation, inbound established */
	[RT_ROUTED_ONDEMAND] = "prospective erouted",  /* routed, and prospective shunt installed */
#if 0
	[RT_ROUTED_NEVER_NEGOTIATE] = "routed never-negotiate",  /* routed, and .never_negotiate_shunt installed */
#else
	[RT_ROUTED_NEVER_NEGOTIATE] = "prospective erouted",  /* routed, and .never_negotiate_shunt installed */
#endif
	[RT_ROUTED_NEGOTIATION] = "erouted HOLD",         /* routed, and HOLD shunt installed */
	[RT_ROUTED_INBOUND] = "erouted HOLD",		/* (lie) routed, outbound negotiation, inbound established */
	[RT_UNROUTED_FAILURE] = "unrouted failure",       /* unrouted, and failure shunt installed */
	[RT_ROUTED_FAILURE] = "fail erouted",         	  /* routed, and failure-context shunt eroute installed */
	[RT_ROUTED_TUNNEL] = "erouted",		      	  /* routed, and erouted to an IPSEC SA group */
	[RT_UNROUTED_TUNNEL] = "migrating",		  /* unrouted, established; used by MOBIKE */
};

const struct enum_names routing_story = {
	RT_UNROUTED, RT_UNROUTED_TUNNEL,
	ARRAY_REF(routing_story_strings),
	NULL, /* prefix */
	NULL
};
