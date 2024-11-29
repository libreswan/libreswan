/* IKEv1 notifications, for libreswan
 *
 * Copyright (C) 2024 Andrew Cagney
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

#ifndef IKEV1_NOTIFICATION_H
#define IKEV1_NOTIFICATION_H

#include "constants.h"

struct state;
enum state_kind;
struct msg_digest;
struct ike_sa;

void send_v1_notification_from_state(struct state *st,
				     enum state_kind from_state,
				     v1_notification_t type);
void send_encrypted_v1_notification_from_ike(struct ike_sa *ike,
					     v1_notification_t type);
void send_v1_notification_from_md(struct msg_digest *md,
				  v1_notification_t type);

#endif
