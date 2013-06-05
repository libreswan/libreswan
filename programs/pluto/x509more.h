/* Support of X.509 certificates and CRLs - more functions exported
 *
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2003 Andreas Steffen, Zuercher Hochschule Winterthur
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

#ifndef _X509MORE_H
#define _X509MORE_H

#include "packet.h"
#include "demux.h"
#include "server.h"
#include "secrets.h"

/* forward reference */
struct msg_digest;

extern void decode_cert(struct msg_digest *md);
extern void ikev2_decode_cert(struct msg_digest *md);
extern void ikev2_decode_cr(struct msg_digest *md,
			    generalName_t **requested_ca);
extern void decode_cr(struct msg_digest *md, generalName_t **requested_ca);
extern bool collect_rw_ca_candidates(struct msg_digest *md,
				     generalName_t **top);
extern bool build_and_ship_CR(u_int8_t type, chunk_t ca, pb_stream *outs,
			      u_int8_t np);
extern bool ikev2_build_and_ship_CR(u_int8_t type, chunk_t ca, pb_stream *outs,
				    u_int8_t np);
extern err_t process_rsa_keyfile(struct RSA_private_key *rsak, int whackfd);
#endif /* _X509MORE_H */
