/* IKEv2 cookie calculation, for Libreswan
 *
 * Copyright (C) 2018-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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

#ifndef IKEV2_COOKIE_H
#define IKEV2_COOKIE_H

#include <stdint.h>
#include <stdbool.h>

struct msg_digest;
struct ike_sa;
struct child_sa;

void refresh_v2_cookie_secret(struct logger *logger);

bool v2_rejected_initiator_cookie(struct msg_digest *md,
				  bool me_want_cookies);

stf_status process_v2_IKE_SA_INIT_response_v2N_COOKIE(struct ike_sa *ike,
						      struct child_sa *child,
						      struct msg_digest *md);

stf_status process_v2_IKE_SESSION_RESUME_response_v2N_COOKIE(struct ike_sa *ike,
							     struct child_sa *child,
							     struct msg_digest *md);

#endif
