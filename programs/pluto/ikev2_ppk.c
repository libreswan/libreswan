/*
 * Helper function for dealing with post-quantum preshared keys
 *
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
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
#include "ikev2.h"
#include "ikev2_ppk.h"
#include "ike_alg_hash.h"
#include "crypt_mac.h"
#include "ikev2_auth.h"
#include "log.h"
#include "ikev2_psk.h"

/*
 * used by initiator, to properly construct struct
 * from chunk_t we got from .secrets
 */
bool create_ppk_id_payload(chunk_t *ppk_id, struct ppk_id_payload *payl)
{
	payl->type = PPK_ID_FIXED;	/* currently we support only this type */
	payl->ppk_id = *ppk_id;
	return true;
}

/*
 * used by initiator to make chunk_t from ppk_id payload
 * for sending it in PPK_ID Notify Payload over the wire
 */
bool emit_unified_ppk_id(struct ppk_id_payload *payl, struct pbs_out *outs)
{
	uint8_t type = PPK_ID_FIXED;
	if (!pbs_out_thing(outs, type, "PPK_ID_FIXED")) {
		/* already logged */
		return false;
	}
	return pbs_out_hunk(outs, payl->ppk_id, "PPK_ID");
}

/*
 * used by responder, for extracting PPK_ID from IKEv2 Notify PPK_ID
 * Payload, we store PPK_ID and its type in payl
 */
bool extract_v2N_ppk_identity(const struct pbs_in *notify_pbs,
			      struct ppk_id_payload *payl, struct ike_sa *ike)
{
	diag_t d;
	struct pbs_in pbs = *notify_pbs;

	/* read in and verify the first (type) byte */

	uint8_t id_byte;
	d = pbs_in_thing(&pbs, id_byte, "PPK_ID type");
	if (d != NULL) {
		llog(RC_LOG, ike->sa.logger, "reading PPK ID: %s", str_diag(d));
		pfree_diag(&d);
		return false;

	}

	/* XXX: above+below could be turned into a descr? */
	enum ikev2_ppk_id_type id_type = id_byte;
	switch (id_type) {
	case PPK_ID_FIXED:
		dbg("PPK_ID of type PPK_ID_FIXED.");
		break;
	case PPK_ID_OPAQUE:
	default:
	{
		enum_buf eb;
		llog_sa(RC_LOG, ike, "PPK_ID type %d (%s) not supported",
			id_type, str_enum(&ikev2_ppk_id_type_names, id_type, &eb));
		return false;
	}
	}

	shunk_t data = pbs_in_left(&pbs);

	if (data.len == 0) {
		llog_sa(RC_LOG, ike, "PPK ID data must be at least 1 byte");
		return false;
	}

	if (data.len > PPK_ID_MAXLEN) {
		llog_sa(RC_LOG, ike, "PPK ID %zu byte length exceeds %u",
			data.len, PPK_ID_MAXLEN);
		return false;
	}

	/* clone ppk id data without ppk id type byte */
	payl->ppk_id = clone_hunk(data, "PPK_ID data");
	if (DBGP(DBG_BASE)) {
		DBG_dump_hunk("Extracted PPK_ID", payl->ppk_id);
	}

	return true;
}

static bool ikev2_calculate_hash(struct ike_sa *ike,
				 const struct crypt_mac *idhash,
				 struct pbs_out *a_pbs,
				 chunk_t *no_ppk_auth, /* optional output */
				 const struct hash_desc *hash_algo,
				 const struct pubkey_signer *signer)
{
	const struct pubkey_type *type = &pubkey_type_rsa;
	statetime_t start = statetime_start(&ike->sa);
	const struct connection *c = ike->sa.st_connection;

	const struct secret_stuff *pks = get_local_private_key(c, type,
								    ike->sa.logger);
	if (pks == NULL) {
		llog_sa(RC_LOG, ike, "No %s private key found", type->name);
		return false; /* failure: no key to use */
	}

	struct crypt_mac hash = v2_calculate_sighash(ike, idhash, hash_algo,
						     LOCAL_PERSPECTIVE);
	passert(hash.len <= sizeof(hash.ptr/*array*/));

	if (DBGP(DBG_CRYPT)) {
		DBG_dump_hunk("v2rsa octets", *idhash);
	}

	/* now generate signature blob */
	statetime_t sign_time = statetime_start(&ike->sa);
	struct hash_signature sig;
	sig = signer->sign_hash(pks, idhash->ptr, idhash->len,
				hash_algo, ike->sa.logger);
	statetime_stop(&sign_time, "%s() calling sign_hash_RSA()", __func__);
	if (sig.len == 0)
		return false;

	if (no_ppk_auth != NULL) {
		*no_ppk_auth = clone_hunk(sig, "NO_PPK_AUTH chunk");
		if (DBGP(DBG_PRIVATE) || DBGP(DBG_CRYPT)) {
			DBG_dump_hunk("NO_PPK_AUTH payload", *no_ppk_auth);
		}
	} else {
		if (!out_hunk(sig, a_pbs, "rsa signature"))
			return false;
	}

	statetime_stop(&start, "%s()", __func__);
	return true;
}

bool ikev2_calc_no_ppk_auth(struct ike_sa *ike,
			    const struct crypt_mac *id_hash,
			    chunk_t *no_ppk_auth /* output */)
{
	struct connection *c = ike->sa.st_connection;
	enum keyword_auth authby = c->local->host.config->auth;

	free_chunk_content(no_ppk_auth);	/* in case it was occupied */

	switch (authby) {
	case AUTH_RSASIG:
	{
		const struct hash_desc *hash_algo = v2_auth_negotiated_signature_hash(ike);
		if (hash_algo == NULL) {
			if (c->config->sighash_policy == LEMPTY) {
				/* RSA with SHA1 without Digsig: no oid blob appended */
				if (!ikev2_calculate_hash(ike, id_hash, NULL, no_ppk_auth,
							  &ike_alg_hash_sha1,
							  &pubkey_signer_raw_pkcs1_1_5_rsa)) {
					return false;
				}
				return true;
			} else {
				llog_sa(RC_LOG, ike,
					  "no compatible hash algo");
				return false;
			}
		}

		shunk_t h = hash_algo->digital_signature_blob[DIGITAL_SIGNATURE_RSASSA_PSS_BLOB];
		if (h.len == 0) {
			llog_pexpect(ike->sa.logger, HERE,
				     "negotiated hash algorithm %s has no RSA ASN1 blob",
				     hash_algo->common.fqn);
			return false;
		}

		chunk_t hashval = NULL_HUNK;
		if (!ikev2_calculate_hash(ike, id_hash, NULL, &hashval,
					  hash_algo, &pubkey_signer_digsig_rsassa_pss)) {
			return false;
		}

		if (ike->sa.st_seen_hashnotify) {
			/*
			 * combine blobs to create no_ppk_auth:
			 * - ASN.1 algo blob
			 * - hashval
			 */
			int len = h.len + hashval.len;
			uint8_t *blobs = alloc_bytes(len,
				"bytes for blobs for AUTH_DIGSIG NO_PPK_AUTH");

			memcpy(&blobs[0], h.ptr, h.len);
			memcpy(&blobs[h.len], hashval.ptr, hashval.len);
			*no_ppk_auth = chunk2(blobs, len);
		}
		free_chunk_content(&hashval);
		return true;
	}
	case AUTH_PSK:
		/* store in no_ppk_auth */
		if (!ikev2_create_psk_auth(AUTH_PSK, ike, id_hash, no_ppk_auth)) {
			return false; /* was STF_INTERNAL_ERROR but don't tell */
		}
		return true;

	default:
		bad_case(authby);
	}
}

/* in X_no_ppk keys are stored keys that go into PRF, and we store result in sk_X */

static void ppk_recalc_one(PK11SymKey **sk /* updated */, PK11SymKey *ppk_key,
			   const struct prf_desc *prf_desc, const char *name,
			   struct logger *logger)
{
	PK11SymKey *t = ikev2_prfplus(prf_desc, ppk_key, *sk, prf_desc->prf_key_size, logger);
	symkey_delref(logger, name, sk);
	*sk = t;
	if (DBGP(DBG_CRYPT)) {
		chunk_t chunk_sk = chunk_from_symkey("sk_chunk", *sk, logger);
		DBG_dump_hunk(name, chunk_sk);
		free_chunk_content(&chunk_sk);
	}
}

void ppk_recalculate(shunk_t ppk, const struct prf_desc *prf_desc,
		     PK11SymKey **sk_d,	/* updated */
		     PK11SymKey **sk_pi,	/* updated */
		     PK11SymKey **sk_pr,	/* updated */
		     struct logger *logger)
{
	PK11SymKey *ppk_key = symkey_from_hunk("PPK Keying material", ppk, logger);

	if (DBGP(DBG_CRYPT)) {
		DBG_log("Starting to recalculate SK_d, SK_pi, SK_pr");
		DBG_dump_hunk("PPK:", ppk);
	}

	ppk_recalc_one(sk_d, ppk_key, prf_desc, "sk_d", logger);
	ppk_recalc_one(sk_pi, ppk_key, prf_desc, "sk_pi", logger);
	ppk_recalc_one(sk_pr, ppk_key, prf_desc, "sk_pr", logger);

	symkey_delref(logger, "PPK chunk", &ppk_key);
}
