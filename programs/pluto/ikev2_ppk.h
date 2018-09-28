/*
 * Helper function for dealing with post-quantum preshared keys
 *
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2017 Paul Wouters <pwouters@redhat.com>
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

#include "state.h"
#include "packet.h"

struct ppk_id_payload {
	enum ppk_id_type type;
	chunk_t ppk_id;
};

extern bool create_ppk_id_payload(chunk_t *ppk_id, struct ppk_id_payload *payl);
extern chunk_t create_unified_ppk_id(struct ppk_id_payload *payl);
extern bool extract_ppk_id(pb_stream *pbs, struct ppk_id_payload *payl);
extern stf_status ikev2_calc_no_ppk_auth(struct connection *c, struct state *st,
			unsigned char *id_hash, chunk_t *no_ppk_auth);
extern void ppk_recalculate(const chunk_t *ppk, const struct prf_desc *prf,
				PK11SymKey **sk_d,
				PK11SymKey **sk_pi,
				PK11SymKey **sk_pr,
				PK11SymKey *sk_d_no_ppk,
				PK11SymKey *sk_pi_no_ppk,
				PK11SymKey *sk_pr_no_ppk);
