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

#ifndef CONNECTION_OWNER_H
#define CONNECTION_OWNER_H

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
extern const struct enum_names connection_owner_stories;

#endif
