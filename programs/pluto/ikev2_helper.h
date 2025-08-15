/* IKEv2 specific helper interface, for libreswan
 *
 * Copyright (C) 2025 Andrew Cagney <cagney@gnu.org>
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

#ifndef IKEV2_HELPER_H
#define IKEV2_HELPER_H

#include "where.h"

struct ike_sa;
struct msg_digest;
struct ikev2_task;
struct logger;

typedef stf_status (ikev2_helper_fn)(struct ikev2_task *task,
				     struct msg_digest *md,
				     struct logger *logger);

typedef stf_status (ikev2_resume_fn)(struct ike_sa *ike,
				     struct msg_digest *md,
				     struct ikev2_task *task);

typedef void (ikev2_cleanup_fn)(struct ikev2_task **task,
				struct logger *logger);

void submit_ikev2_task(struct ike_sa *ike,
		       struct msg_digest *md,
		       struct ikev2_task *helper_task,
		       ikev2_helper_fn *helper,
		       ikev2_resume_fn *helper_resume,
		       ikev2_cleanup_fn *helper_cleanup,
		       where_t where);

#endif
