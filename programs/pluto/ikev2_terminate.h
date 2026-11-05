/* terminate an IKEv2 connection, for libreswan
 *
 * Copyright (C) 2026 Andrew Cagney
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

#ifndef IKEv2_TERMINATE_H
#define IKEv2_TERMINATE_H

#include "where.h"

struct connection;
struct ike_sa;
struct verbose;
enum terminate_reason;

void terminate_all_ikev2_connection_states(struct connection *c, where_t where);

void terminate_ikev2_family(struct ike_sa **ike, enum terminate_reason reason,
			    struct verbose verbose);



#endif
