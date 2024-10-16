/*
 * Helper function for dealing with post-quantum preshared keys
 *
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2017 Paul Wouters <pwouters@redhat.com>
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

#include "state.h"

#define PPK_CONFIRMATION_LEN 8

struct ppk_id_payload {
	enum ikev2_ppk_id_type type;
	chunk_t ppk_id;
};

struct ppk_id_key_payload {
	struct ppk_id_payload ppk_id_payl;
	chunk_t ppk_confirmation;
};

extern bool create_ppk_id_payload(chunk_t *ppk_id, struct ppk_id_payload *payl);
extern bool emit_unified_ppk_id(struct ppk_id_payload *payl, struct pbs_out *pbs);
extern bool extract_v2N_ppk_identity(const struct pbs_in *pbs, struct ppk_id_payload *payl,
				     struct ike_sa *ike);
extern bool extract_v2N_ppk_id_key(const struct pbs_in *notify_pbs,
				   struct ppk_id_key_payload *payl,
				   struct ike_sa *ike);

extern bool ikev2_calc_no_ppk_auth(struct ike_sa *ike,
				   const struct crypt_mac *id_hash,
				   chunk_t *no_ppk_auth /* output */);

extern void ppk_recalculate(shunk_t ppk, const struct prf_desc *prf,
			    PK11SymKey **sk_d,	/* updated */
			    PK11SymKey **sk_pi,	/* updated */
			    PK11SymKey **sk_pr,	/* updated */
			    struct logger *logger);
