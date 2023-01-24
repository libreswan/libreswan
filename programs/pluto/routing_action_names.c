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

/* these go at the end so renames don't find them */

#include "lswcdefs.h"		/* for ARRAY_REF() */
#include "enum_names.h"
#include "routing.h"

const char *routing_action_name[] = {
#define S(E) [E] = #E
	S(CONNECTION_RETRY),
	S(CONNECTION_FAIL),
#undef S
};

const struct enum_names routing_action_names = {
	CONNECTION_RETRY, CONNECTION_FAIL,
	ARRAY_REF(routing_action_name),
	"CONNECTION_",
	NULL,
};
