/* IKEv1 message contents, for libreswan
 *
 * Copyright (C) 2019 Andrew Cagney
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

#include "shunk.h"
#include "id.h"

#include "connections.h"
#include "packet.h"
#include "ikev1_message.h"

struct isakmp_ipsec_id build_v1_id_payload(const struct end *end, shunk_t *body)
{
	struct isakmp_ipsec_id id_hd = {
		.isaiid_idtype = id_to_payload(&end->id, &end->host_addr, body),
	};
	return id_hd;
}
