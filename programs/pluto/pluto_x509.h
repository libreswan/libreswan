/* IKE x509 routines for pluto - formerly x509more.h
 * defined in x509.c
 *
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2003 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2015 Matt Rogers, <mrogers@libreswan.org>
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

#ifndef _PLUTO_X509_H
#define _PLUTO_X509_H

#include "defs.h"
#include "packet.h"
#include "demux.h"
#include "server.h"

#include <cert.h>

/* forward reference */
struct msg_digest;

extern lsw_cert_ret ike_decode_cert(struct msg_digest *md);
extern void ikev1_decode_cr(struct msg_digest *md);
extern void ikev2_decode_cr(struct msg_digest *md);

extern generalName_t *collect_rw_ca_candidates(struct msg_digest *md);

extern bool ikev1_build_and_ship_CR(enum ike_cert_type type,
				    chunk_t ca, pb_stream *outs,
				    enum next_payload_types_ikev1 np);

extern bool ikev2_build_and_ship_CR(enum ike_cert_type type,
				    chunk_t ca, pb_stream *outs);

extern void load_authcerts(const char *type, const char *path,
			   u_char auth_flags);

extern bool match_requested_ca(generalName_t *requested_ca,
			       chunk_t our_ca, int *our_pathlen);

extern bool ikev1_ship_CERT(uint8_t type, chunk_t cert, pb_stream *outs,
							 uint8_t np);
extern int get_auth_chain(chunk_t *out_chain, int chain_max,
					      CERTCertificate *end_cert,
					      bool full_chain);
extern void free_auth_chain(chunk_t *chain, int chain_len);
extern bool ikev2_send_cert_decision(const struct state *st);
extern stf_status ikev2_send_certreq(struct state *st, struct msg_digest *md,
				     pb_stream *outpbs);

stf_status ikev2_send_cert(struct state *st, pb_stream *outpbs);

bool ikev2_send_certreq_INIT_decision(struct state *st,
				      enum original_role role);

#endif /* _PLUTO_X509_H */
