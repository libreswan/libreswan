/* IKEv2 CERT/CERTREQ payload routes, for libreswan
 * defined in x509.c
 *
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2003 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2015 Matt Rogers, <mrogers@libreswan.org>
 * Copyright (C) 2019-2022 Andrew Cagney
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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

#ifndef IKEV2_CERT_H
#define IKEV2_CERT_H

#include "demux.h"	/* "for" pbs_out */

struct ike_sa;
struct msg_digest;
struct connection;

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

bool ikev2_send_cert_decision(const struct ike_sa *ike);
stf_status emit_v2CERT(const struct connection *c, struct pbs_out *outpbs);

#endif /* _PLUTO_X509_H */
