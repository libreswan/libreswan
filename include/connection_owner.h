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
#define CONNECTION_OWNER_FLOOR IKE_SA_OWNER_FLOOR

	/*
	 * The current SA, IKE or Child, that owns the kernel policy.
	 *
	 * For instance, during an on-demand IKE_SA_INIT exchange the
	 * ROUTING_SA starts with the IKE_SA.  But then, at the start
	 * of IKE_AUTH, ownership transfers to the IKE_SA's first
	 * Child SA.
	 */
	ROUTING_SA,

#define IKE_SA_OWNER_FLOOR NEGOTIATING_IKE_SA
	NEGOTIATING_IKE_SA,
	ESTABLISHED_IKE_SA,
#define IKE_SA_OWNER_ROOF (ESTABLISHED_IKE_SA+1)

#define CHILD_SA_OWNER_FLOOR NEGOTIATING_CHILD_SA
	NEGOTIATING_CHILD_SA,
	ESTABLISHED_CHILD_SA,
#define CHILD_SA_OWNER_ROOF (ESTABLISHED_CHILD_SA+1)

#define CONNECTION_OWNER_ROOF CHILD_SA_OWNER_ROOF
};

extern const struct enum_names connection_owner_names;
extern const struct enum_names connection_owner_stories;

#endif
