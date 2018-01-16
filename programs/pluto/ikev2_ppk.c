/*
 * Helper function for dealing with post-quantum preshared keys
 *
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
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

#include <libreswan.h>

#include "lswlog.h"

#include "defs.h"

#include "id.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "keys.h" /* needs state.h */
#include "demux.h"
#include "packet.h"
#include "ikev2_prf.h"

#include "ike_alg.h"
#include "crypt_symkey.h"
#include "pluto_crypt.h"
#include "ikev2.h"
#include "ikev2_ppk.h"

/*
 * used by initiator, to properly construct struct
 * from chunk_t we got from .secrets
 */
bool create_ppk_id_payload(chunk_t *ppk_id, struct ppk_id_payload *payl)
{
	payl->type = PPK_ID_FIXED;	/* currently we support only this type */
	payl->ppk_id = *ppk_id;
	return TRUE;
}

/*
 * used by initiator to make chunk_t from ppk_id payload
 * for sending it in PPK_ID Notify Payload over the wire
 */
chunk_t create_unified_ppk_id(struct ppk_id_payload *payl)
{
	u_char type = PPK_ID_FIXED;	/* PPK_ID_FIXED */
	const chunk_t *ppk_id = &payl->ppk_id;

	chunk_t unified = alloc_chunk(ppk_id->len + 1, "Unified PPK_ID");
	unified.ptr[0] = type;
	memcpy(&unified.ptr[1], ppk_id->ptr, ppk_id->len);
	return unified;
}

/*
 * used by responder, for extracting PPK_ID from IKEv2 Notify
 * PPK_ID Payload, we store PPK_ID and it's type in payl
 */
bool extract_ppk_id(pb_stream *pbs, struct ppk_id_payload *payl)
{
	size_t len = pbs_left(pbs);
	u_char dst[PPK_ID_MAXLEN];
	int idtype;

	if (len > PPK_ID_MAXLEN) {
		loglog(RC_LOG_SERIOUS, "PPK ID length is too big");
		return FALSE;
	}
	if (len <= 1) {
		loglog(RC_LOG_SERIOUS, "PPK ID data must be at least 1 byte (received %zd bytes including ppk type byte)",
			len);
		return FALSE;
	}

	if (!in_raw(dst, len, pbs, "Unified PPK_ID Payload")) {
		loglog(RC_LOG_SERIOUS, "PPK ID data could not be read");
		return FALSE;
	}

	DBG(DBG_CONTROL, DBG_log("received PPK_ID type: %s",
		enum_name(&ikev2_ppk_id_names, dst[0])));

	idtype = (int)dst[0];
	switch (idtype) {
	case PPK_ID_FIXED:
		DBG(DBG_CONTROL, DBG_log("PPK_ID of type PPK_ID_FIXED."));
		break;

	case PPK_ID_OPAQUE:
	default:
		loglog(RC_LOG_SERIOUS, "PPK_ID type %d (%s) not supported",
			idtype, enum_name(&ikev2_ppk_id_names, idtype));
		return FALSE;
	}

	/* clone ppk id data without ppk id type byte */
	clonetochunk(payl->ppk_id, dst + 1, len - 1, "PPK_ID data");
	DBG(DBG_CONTROL, DBG_dump_chunk("Extracted PPK_ID", payl->ppk_id));

	return TRUE;
}

stf_status ikev2_calc_no_ppk_auth(struct connection *c, struct state *st, unsigned char *id_hash, chunk_t *no_ppk_auth)
{
	enum keyword_authby authby = c->spd.this.authby;
	switch (authby) {
	case AUTH_RSASIG:
		/* TODO */
		break;
	case AUTH_PSK:
		if (ikev2_create_psk_auth(AUTH_PSK, st, id_hash, NULL, TRUE, no_ppk_auth))
			return STF_OK;
		break;
	default:
		break;
	}
	return STF_INTERNAL_ERROR;
}

/* in X_no_ppk keys are stored keys that go into PRF, and we store result in sk_X */
void ppk_recalculate(const chunk_t *ppk, const struct prf_desc *prf_desc,
			PK11SymKey **sk_d, PK11SymKey **sk_pi, PK11SymKey **sk_pr,
			PK11SymKey *sk_d_no_ppk,
			PK11SymKey *sk_pi_no_ppk,
			PK11SymKey *sk_pr_no_ppk)
{
	PK11SymKey *new_sk_pi, *new_sk_pr, *new_sk_d;
	PK11SymKey *ppk_key = symkey_from_chunk("PPK Keying material", DBG_CRYPT, *ppk);

	DBG(DBG_CRYPT, DBG_log("Starting to recalculate SK_d, SK_pi, SK_pr");
			 DBG_dump_chunk("PPK:", *ppk));

	new_sk_d = ikev2_prfplus(prf_desc, ppk_key, sk_d_no_ppk, prf_desc->prf_key_size);
	*sk_d = new_sk_d;

	new_sk_pi = ikev2_prfplus(prf_desc, ppk_key, sk_pi_no_ppk, prf_desc->prf_key_size);
	*sk_pi = new_sk_pi;

	new_sk_pr = ikev2_prfplus(prf_desc, ppk_key, sk_pr_no_ppk, prf_desc->prf_key_size);
	*sk_pr = new_sk_pr;

	if (DBGP(DBG_PRIVATE)) {
		/* declaring chunks for dumping them beneath */
		chunk_t chunk_sk_d = chunk_from_symkey("chunk_SK_d", DBG_CRYPT, *sk_d);
		chunk_t chunk_sk_pi = chunk_from_symkey("chunk_SK_pi", DBG_CRYPT, *sk_pi);
		chunk_t chunk_sk_pr = chunk_from_symkey("chunk_SK_pr", DBG_CRYPT, *sk_pr);

		DBG(DBG_PRIVATE,
		    DBG_log("PPK Finished recalculating SK_d, SK_pi, SK_pr");
		    DBG_log("PPK Recalculated pointers: SK_d-key@%p, SK_pi-key@%p, SK_pr-key@%p",
			     *sk_d, *sk_pi, *sk_pr);
		    DBG_dump_chunk("new SK_d", chunk_sk_d);
		    DBG_dump_chunk("new SK_pi", chunk_sk_pi);
		    DBG_dump_chunk("new SK_pr", chunk_sk_pr));

		freeanychunk(chunk_sk_d);
		freeanychunk(chunk_sk_pi);
		freeanychunk(chunk_sk_pr);
	}

}
