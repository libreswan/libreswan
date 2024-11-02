/*
 * Copyright (C) 2001-2002 Colubris Networks
 * Copyright (C) 2003-2004 Xelerance Corporation
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

#ifndef XAUTH_H
#define XAUTH_H

#include "ikev1.h"

struct state;	/* so state.h is not a prerequisite */
struct msg_digest;	/* so demux.h is not a prerequisite */

extern stf_status xauth_send_request(struct ike_sa *ike);

extern stf_status modecfg_start_set(struct ike_sa *ike);

/* XAUTH state transitions */

extern ikev1_state_transition_fn xauth_inR0;
extern ikev1_state_transition_fn xauth_inR1;
extern ikev1_state_transition_fn modecfg_inR0;
extern ikev1_state_transition_fn modecfg_inR1;
extern ikev1_state_transition_fn xauth_inI0;
extern ikev1_state_transition_fn xauth_inI1;

extern oakley_auth_t xauth_calcbaseauth(oakley_auth_t baseauth);

extern stf_status modecfg_send_request(struct ike_sa *ike);

#endif  /* XAUTH_H */
