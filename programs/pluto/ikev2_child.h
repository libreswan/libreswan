/* IKEv2 CHILD SA routines, for libreswan
 *
 * Copyright (C) 2021  Andrew cagney
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

#ifndef IKEV2_CHILD_H
#define IKEV2_CHILD_H

bool ikev2_process_childs_sa_payload(const char *what, struct ike_sa *ike,
				     struct child_sa *larval_child,
				     struct msg_digest *md,
				     bool expect_accepted_proposal);

#endif
