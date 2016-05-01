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
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
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

extern bool ikev1_decode_cert(struct msg_digest *md);
extern bool ikev2_decode_cert(struct msg_digest *md);
extern void ikev1_decode_cr(struct msg_digest *md);
extern void ikev2_decode_cr(struct msg_digest *md);

extern generalName_t *collect_rw_ca_candidates(struct msg_digest *md);

extern bool ikev1_build_and_ship_CR(enum ike_cert_type type,
				    chunk_t ca, pb_stream *outs,
				    enum next_payload_types_ikev1 np);

extern bool ikev2_build_and_ship_CR(enum ike_cert_type type,
				    chunk_t ca, pb_stream *outs,
				    enum next_payload_types_ikev2 np);

extern void load_authcerts(const char *type, const char *path,
			   u_char auth_flags);

extern bool match_requested_ca(generalName_t *requested_ca,
			       chunk_t our_ca, int *our_pathlen);

extern bool ikev1_ship_CERT(u_int8_t type, chunk_t cert, pb_stream *outs,
							 u_int8_t np);
extern int get_auth_chain(chunk_t *out_chain, int chain_max,
					      CERTCertificate *end_cert,
					      bool full_chain);
extern bool ikev2_send_cert_decision(struct state *st);
extern stf_status ikev2_send_certreq(struct state *st, struct msg_digest *md,
				     enum original_role role UNUSED,
				     enum next_payload_types_ikev2 np,
				     pb_stream *outpbs);

stf_status ikev2_send_cert(struct state *st, struct msg_digest *md,
			   enum original_role role,
			   enum next_payload_types_ikev2 np,
			   pb_stream *outpbs);

#endif /* _PLUTO_X509_H */
