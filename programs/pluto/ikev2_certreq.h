/* IKEv2 CERTREQ payload, for libreswan
 *
 * Copyright (C) 2022 Andrew Cagney
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

#ifndef IKEV2_CERTREQ_H
#define IKEV2_CERTREQ_H

#include <stdbool.h>

#include "demux.h"	/* HACK to expose pbs_out macro */

struct ike_sa;
struct msg_digest;
struct pbs_out;
struct state;

/*
 * CERTREQ payloads are sent in the message just prior to the CERT:
 *
 * + in the IKE_SA_INIT response so that the initiator knows to
 * include its certificate in the IKE_AUTH request
 *
 * + in the IKE_AUTH request so that the responder knows to include
 * the certificate in its IKE_AUTH response
 */

bool need_v2CERTREQ_in_IKE_AUTH_request(const struct ike_sa *ike);
bool need_v2CERTREQ_in_IKE_SA_INIT_response(const struct ike_sa *ike);

stf_status emit_v2CERTREQ(struct ike_sa *ike, struct msg_digest *md,
			  struct pbs_out *outpbs);

void decode_v2_certificate_requests(struct state *st, struct msg_digest *md);

#endif
