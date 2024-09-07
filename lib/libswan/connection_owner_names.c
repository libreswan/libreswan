/* connection owner, for libreswan
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

#include "connection_owner.h"

#include "enum_names.h"
#include "lswcdefs.h"		/* for ARRAY_REF */

const char *connection_owner_name[] = {
	[ROUTING_SA] = "routing_sa",
	[NEGOTIATING_IKE_SA] = "negotiating_ike_sa",
	[ESTABLISHED_IKE_SA] = "established_ike_sa",
	[NEGOTIATING_CHILD_SA] = "negotiating_child_sa",
	[ESTABLISHED_CHILD_SA] = "established_child_sa",
};

const struct enum_names connection_owner_names = {
	ROUTING_SA, ESTABLISHED_CHILD_SA,
	ARRAY_REF(connection_owner_name),
	.en_prefix = NULL,
};


const char *connection_owner_story[] = {
	[ROUTING_SA] = "routing SA",
	[NEGOTIATING_IKE_SA] = "negotiating IKE SA",
	[ESTABLISHED_IKE_SA] = "established IKE SA",
	[NEGOTIATING_CHILD_SA] = "negotiating Child SA",
	[ESTABLISHED_CHILD_SA] = "established Child SA",
};

const struct enum_names connection_owner_stories = {
	ROUTING_SA, ESTABLISHED_CHILD_SA,
	ARRAY_REF(connection_owner_story),
	.en_prefix = NULL,
};
