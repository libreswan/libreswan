/* IKEv2 EAP authentication, for libreswan
 *
 * Copyright (C) 2021 Timo Teräs <timo.teras@iki.fi>
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

#ifndef IKEV2_EAP_H
#define IKEV2_EAP_H

#include "ikev2.h"

struct eap_state {
	struct logger    *logger;
	uint8_t          eap_id;
	uint8_t          eap_established;

	PRFileDesc     *eaptls_desc;	/* EAP TLS */
	struct pbs_out eaptls_outbuf;
	shunk_t        eaptls_inbuf;
	chunk_t        eaptls_chunk;
	uint32_t       eaptls_pos;
};

extern void free_eap_state(struct eap_state **eap);

extern ikev2_state_transition_fn process_v2_IKE_AUTH_request_EAP_start;

#endif
