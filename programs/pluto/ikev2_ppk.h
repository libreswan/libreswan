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

#ifndef IKEV2_PPK_H
#define IKEV2_PPK_H

#define PPK_CONFIRMATION_LEN 8

struct ppk_id_payload {
	enum ikev2_ppk_id_type type;
	/* points into either the PBS or the connection */
	shunk_t ppk_id;
};

struct ppk_id_key_payload {
	struct ppk_id_payload ppk_id_payl;
	/* points into the PBS */
	shunk_t ppk_confirmation;
};

/*
 * Construct above by pointing into either the PBS or the connection.
 *
 * Note: lifetime of returned structure MUST be less than PBS or
 * connection (in reality is local to a function).
 */
struct ppk_id_payload ppk_id_payload(enum ikev2_ppk_id_type type,
				     const shunk_t ppk_id,
				     struct logger *logger);
extern bool extract_v2N_ppk_identity(const struct pbs_in *pbs, struct ppk_id_payload *payl,
				     struct ike_sa *ike);
extern bool extract_v2N_ppk_id_key(const struct pbs_in *notify_pbs,
				   struct ppk_id_key_payload *payl,
				   struct ike_sa *ike);

bool emit_unified_ppk_id(const struct ppk_id_payload *payl, struct pbs_out *pbs);
bool emit_v2N_PPK_IDENTITY_KEY();

extern bool ikev2_calc_no_ppk_auth(struct ike_sa *ike,
				   const struct crypt_mac *id_hash,
				   chunk_t *no_ppk_auth /* output */);

chunk_t calc_PPK_IDENTITY_KEY_confirmation(const struct prf_desc *prf_desc,
					   const struct secret_ppk_stuff *ppk,
					   const chunk_t Ni,
					   const chunk_t Nr,
					   const ike_spis_t *ike_spis,
					   struct logger *logger);

extern void ppk_recalculate(shunk_t ppk, const struct prf_desc *prf,
			    PK11SymKey **sk_d,	/* updated */
			    PK11SymKey **sk_pi,	/* updated */
			    PK11SymKey **sk_pr,	/* updated */
			    struct logger *logger);

#endif
