/* IKEv1 CERT/CR payload support, for libreswan
 *
 * Copyright (C) 2018-2022 Andrew Cagney
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
 *
 */

#ifndef IKEV1_CERT_H
#define IKEV1_CERT_H

#include <stdbool.h>

#include "shunk.h"
#include "chunk.h"

#include "demux.h"	/* HACK to expose pbs_out macro */

struct msg_digest;
struct pbs_out;
enum ike_cert_type;
struct ike_sa;

bool ikev1_ship_chain(chunk_t *chain, int n, struct pbs_out *outs, uint8_t type);

bool v1_decode_certs(struct msg_digest *md);
void decode_v1_certificate_requests(struct ike_sa *ike, struct msg_digest *md);
bool ikev1_ship_CERT(enum ike_cert_type type, shunk_t cert, struct pbs_out *outs);
bool ikev1_build_and_ship_CR(enum ike_cert_type type, chunk_t ca, struct pbs_out *outs);

#endif
