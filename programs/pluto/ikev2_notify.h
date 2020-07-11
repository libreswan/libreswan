/* IKEv2 notify routines, for Libreswan
 *
 * Copyright (C) 2020 Andrew Cagney <cagney@gnu.org>
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

#ifndef IKEV2_NOTIFY_H
#define IKEV2_NOTIFY_H

#include <stdbool.h>

struct msg_digest;
struct ike_sa;
struct logger;
struct payload_digest;

void decode_v2N_payload(struct logger *logger, struct msg_digest *md,
			const struct payload_digest *notify);

enum v2_pbs v2_notification_to_v2_pbs(v2_notification_t);

#endif
