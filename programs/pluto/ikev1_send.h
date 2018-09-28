/* IKEv1 send, for libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
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

#ifndef IKEV1_SEND_H
#define IKEV1_SEND_H

#include "packet.h"

struct state;

bool record_and_send_v1_ike_msg(struct state *st, pb_stream *pbs,
				const char *what);

bool resend_recorded_v1_ike_msg(struct state *st, const char *where);

#endif
