/* IKEv2 IKE_FOLLOWUP_KE exchange, for libreswan
 *
 * Copyright (C) 2026 Daiki Ueno <dueno@redhat.com>
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

#ifndef IKEV2_FOLLOWUP_KE_H
#define IKEV2_FOLLOWUP_KE_H

#include "ikev2.h"	/* for ikev2_state_transition_fn */

struct ike_sa;
struct child_sa;

bool next_is_ikev2_ike_followup_ke_exchange(struct state *st);

bool next_ikev2_ike_followup_ke_exchange(struct state *st);

void generate_ikev2_followup_ke_link(struct state *st);

bool extract_ikev2_followup_ke_link(struct state *st,
				    struct msg_digest *md,
				    struct logger *logger);

/*
 * IKE_FOLLOWUP_KE exchange (RFC 9370)
 *
 * This exchange may occur multiple times after CREATE_CHILD_SA
 * to provide additional key material.
 */

struct ikev2_ike_followup_ke_exchange {
	const struct ke_desc *kem;
	enum ikev2_trans_type type;
};

/* Exchange declaration */
extern const struct v2_exchange v2_IKE_FOLLOWUP_KE_rekey_ike_exchange;

#endif
