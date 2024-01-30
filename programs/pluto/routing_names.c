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

static const char *routing_name[] = {
#define S(E) [E] = #E
	S(RT_UNROUTED),
	S(RT_ROUTED_NEVER_NEGOTIATE),
	S(RT_ROUTED_ONDEMAND),
	S(RT_UNROUTED_BARE_NEGOTIATION),
	S(RT_UNROUTED_NEGOTIATION),
	S(RT_ROUTED_NEGOTIATION),
	/* failed */
	S(RT_ROUTED_FAILURE),
	/* half established */
	S(RT_UNROUTED_INBOUND),
	S(RT_UNROUTED_INBOUND_NEGOTIATION),
	S(RT_ROUTED_INBOUND_NEGOTIATION),
	/* fully established */
	S(RT_ROUTED_TUNNEL),
	S(RT_UNROUTED_TUNNEL),
#undef S
};

const struct enum_names routing_names = {
	0, CONNECTION_ROUTING_ROOF-1,
	ARRAY_REF(routing_name),
	"RT_", NULL,
};
