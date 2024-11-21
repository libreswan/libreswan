/* IKEv2 CREATE_CHILD_SA code, for libreswan
 *
 * Copyright (C) 2021   Andrew Cagney <cagney@gnu.org>
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

#ifndef IKEV2_CREATE_CHILD_SA_H
#define IKEV2_CREATE_CHILD_SA_H

#include "shunk.h"
#include "lset.h"
#include "ikev2.h"	/* for ikev2_state_transition_fn */

struct ike_sa;
struct child_sa;
struct connection;

struct child_sa *submit_v2_CREATE_CHILD_SA_rekey_ike(struct ike_sa *ike,
						     bool detach_whack);

extern ikev2_state_transition_fn process_v2_CREATE_CHILD_SA_rekey_ike_request;
extern ikev2_state_transition_fn process_v2_CREATE_CHILD_SA_rekey_ike_response;

struct child_sa *submit_v2_CREATE_CHILD_SA_new_child(struct ike_sa *ike,
						     struct connection *c, /*child+whack*/
						     const struct child_policy *policy,
						     bool detach_whack);

extern ikev2_state_transition_fn process_v2_CREATE_CHILD_SA_new_child_request;

extern struct child_sa *submit_v2_CREATE_CHILD_SA_rekey_child(struct ike_sa *ike,
							      struct child_sa *child,
							      bool detach_whack);

extern ikev2_state_transition_fn process_v2_CREATE_CHILD_SA_rekey_child_request;

extern ikev2_state_transition_fn process_v2_CREATE_CHILD_SA_child_response;
extern ikev2_state_transition_fn process_v2_CREATE_CHILD_SA_failure_response;

extern const struct v2_exchange v2_CREATE_CHILD_SA_new_child_exchange;
extern const struct v2_exchange v2_CREATE_CHILD_SA_rekey_child_exchange;
extern const struct v2_exchange v2_CREATE_CHILD_SA_rekey_ike_exchange;

#endif
