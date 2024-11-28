/* IKEv2 notify routines, for Libreswan
 *
 * Copyright (C) 2020 Andrew Cagney <cagney@gnu.org>
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

#ifndef IKEV2_NOTIFY_H
#define IKEV2_NOTIFY_H

#include <stdbool.h>

struct msg_digest;
struct ike_sa;
struct logger;
struct payload_digest;
struct pbs_out;
enum payload_security;

/*
 * Construct IKEv2 notification payloads.
 */

/*
 * Emit an SA Notification header (could be 0/none), and then open the
 * sub_payload.
 */
bool open_v2N_SA_output_pbs(struct pbs_out *outs,
			    v2_notification_t ntype,
			    enum ikev2_sec_proto_id protoid,
			    const ipsec_spi_t *spi, /* optional */
			    struct pbs_out *sub_payload);

/*
 * Emit a non-SA v2 Notification payload header and then open the
 * sub-payload.
 */
bool open_v2N_output_pbs(struct pbs_out *outs,
			 v2_notification_t ntype,
			 struct pbs_out *sub_payload);

/*
 * Emit a v2 Notification payload, with optional hunk as sub-payload.
 */
bool emit_v2N_bytes(v2_notification_t ntype,
		   const void *bytes, size_t size,
		   struct pbs_out *outs);
#define emit_v2N_hunk(NTYPE, HUNK, OUTS)	emit_v2N_bytes(NTYPE, (HUNK).ptr, (HUNK).len, OUTS)

/* output an empty v2 notification payload */
bool emit_v2N(v2_notification_t ntype, struct pbs_out *outs);

void decode_v2N_payload(struct logger *logger, struct msg_digest *md,
			const struct payload_digest *notify);

enum v2_pd v2_pd_from_notification(v2_notification_t);

void record_v2N_response(struct logger *logger,
			 struct ike_sa *ike,
			 struct msg_digest *md,
			 v2_notification_t type,
			 const chunk_t *data /* optional */,
			 enum payload_security security);

void record_v2N_spi_response(struct logger *logger,
			     struct ike_sa *st,
			     struct msg_digest *md,
			     enum ikev2_sec_proto_id protoid,
			     ipsec_spi_t *spi,
			     v2_notification_t type,
			     const chunk_t *data /* optional */,
			     enum payload_security security);

void send_v2N_response_from_md(struct msg_digest *md,
			       v2_notification_t type,
			       const shunk_t *data,
			       const char *format, ...) PRINTF_LIKE(4);

#endif
