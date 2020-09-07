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
#include "diag.h"
#include "lswlog.h"

struct isakmp_ipsec_id build_v1_id_payload(const struct end *end, shunk_t *body)
{
	struct isakmp_ipsec_id id_hd = {
		.isaiid_idtype = id_to_payload(&end->id, &end->host_addr, body),
	};
	return id_hd;
}

bool out_zero(size_t len, pb_stream *outs, const char *name)
{
	diag_t d = pbs_out_zero(outs, len, name);
	if (d != NULL) {
		log_diag(RC_LOG_SERIOUS, outs->out_logger, &d, "%s", "");
		return false;
	}

	return true;
}

bool out_repeated_byte(uint8_t byte, size_t len, pb_stream *outs, const char *name)
{
	diag_t d = pbs_out_repeated_byte(outs, byte, len, name);
	if (d != NULL) {
		log_diag(RC_LOG_SERIOUS, outs->out_logger, &d, "%s", "");
		return false;
	}

	return true;
}

bool out_raw(const void *bytes, size_t len, pb_stream *outs, const char *name)
{
	diag_t d = pbs_out_raw(outs, bytes, len, name);
	if (d != NULL) {
		log_diag(RC_LOG_SERIOUS, outs->out_logger, &d, "%s", "");
		return false;
	}

	return true;
}
