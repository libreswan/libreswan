/* IKEv2 Authentication, for libreswan
 *
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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
 *
 */

#include "ike_alg.h"
#include "ike_alg_hash.h"
#include "crypt_hash.h"

#include "defs.h"
#include "ikev2_auth.h"
#include "state.h"
#include "log.h"
#include "connections.h"
#include "nat_traversal.h"
#include "keys.h"
#include "secrets.h"
#include "ikev2_message.h"
#include "ikev2.h"
#include "keys.h"
#include "ikev2_psk.h"
#include "ikev2_send.h"

struct crypt_mac v2_calculate_sighash(const struct ike_sa *ike,
				      const struct crypt_mac *idhash,
				      const struct hash_desc *hasher,
				      enum perspective from_the_perspective_of)
{
	enum sa_role role;
	chunk_t firstpacket;
	switch (from_the_perspective_of) {
	case LOCAL_PERSPECTIVE:
		firstpacket = ike->sa.st_firstpacket_me;
		role = ike->sa.st_sa_role;
		break;
	case REMOTE_PERSPECTIVE:
		firstpacket = ike->sa.st_firstpacket_peer;
		role = (ike->sa.st_sa_role == SA_INITIATOR ? SA_RESPONDER :
			ike->sa.st_sa_role == SA_RESPONDER ? SA_INITIATOR :
			0);
		break;
	default:
		bad_case(from_the_perspective_of);
	}

	const chunk_t *nonce;
	const char *nonce_name;
	chunk_t ia1;
	chunk_t ia2;
	switch (role) {
	case SA_INITIATOR:
		/* on initiator, we need to hash responders nonce */
		nonce = &ike->sa.st_nr;
		nonce_name = "inputs to hash2 (responder nonce)";
		ia1 = ike->sa.st_v2_ike_intermediate.initiator;
		ia2 = ike->sa.st_v2_ike_intermediate.responder;
		break;
	case SA_RESPONDER:
		/* on responder, we need to hash initiators nonce */
		nonce = &ike->sa.st_ni;
		nonce_name = "inputs to hash2 (initiator nonce)";
		ia1 = ike->sa.st_v2_ike_intermediate.responder;
		ia2 = ike->sa.st_v2_ike_intermediate.initiator;
		break;
	default:
		bad_case(role);
	}

	if (DBGP(DBG_CRYPT)) {
		DBG_dump_hunk("inputs to hash1 (first packet)", firstpacket);
		DBG_dump_hunk(nonce_name, *nonce);
		DBG_dump_hunk("idhash", *idhash);
		if (ike->sa.st_v2_ike_intermediate.enabled) {
			DBG_dump_hunk("IntAuth_*_I_A", ia1);
			DBG_dump_hunk("IntAuth_*_R_A", ia2);
		}
	}

	struct crypt_hash *ctx = crypt_hash_init("sighash", hasher,
						 ike->sa.logger);
	crypt_hash_digest_hunk(ctx, "first packet", firstpacket);
	crypt_hash_digest_hunk(ctx, "nonce", *nonce);
	/* we took the PRF(SK_d,ID[ir]'), so length is prf hash length */
	passert(idhash->len == ike->sa.st_oakley.ta_prf->prf_output_size);
	crypt_hash_digest_hunk(ctx, "IDHASH", *idhash);
	if (ike->sa.st_v2_ike_intermediate.enabled) {
		crypt_hash_digest_hunk(ctx, "IntAuth_*_I_A", ia1);
		crypt_hash_digest_hunk(ctx, "IntAuth_*_R_A", ia2);
		/* IKE AUTH's first Message ID */
		uint8_t ike_auth_mid[sizeof(ike->sa.st_v2_ike_intermediate.id)];
		hton_bytes(ike->sa.st_v2_ike_intermediate.id + 1,
			   ike_auth_mid, sizeof(ike_auth_mid));
		crypt_hash_digest_thing(ctx, "IKE_AUTH_MID", ike_auth_mid);
	}
	return crypt_hash_final_mac(&ctx);
}

enum keyword_auth local_v2_auth(struct ike_sa *ike)
{
	if (ike->sa.st_peer_wants_null) {
		/* we allow authby=null and IDr payload told us to use it */
		return AUTH_NULL;
	}
	const struct connection *c = ike->sa.st_connection;
	enum keyword_auth authby = c->local->host.config->auth;
	pexpect(authby != AUTH_UNSET);
	return authby;
}

/*
 * Map the configuration's authby=... onto the IKEv2 AUTH message's
 * auth method.
 */

enum ikev2_auth_method local_v2AUTH_method(struct ike_sa *ike,
					   enum keyword_auth authby)
{
	struct connection *c = ike->sa.st_connection;

	if (impair.force_v2_auth_method.enabled) {
		enum_buf eb;
		llog_sa(RC_LOG, ike, "IMPAIR: forcing auth method %s",
			str_enum(&ikev2_auth_method_names,
				 impair.force_v2_auth_method.value, &eb));
		return impair.force_v2_auth_method.value;
	}

	switch (authby) {
	case AUTH_RSASIG:
		/*
		 * Peer sent us N(SIGNATURE_HASH_ALGORITHMS)
		 * indicating a preference for Digital Signature
		 * Method, and local policy was ok with the
		 * suggestion.
		 */
		pexpect(authby_has_rsasig(c->local->host.config->authby));
		if (ike->sa.st_v2_digsig.negotiated_hashes != LEMPTY) {
			return IKEv2_AUTH_DIGSIG;
		}

		/*
		 * Local policy allows proof-of-identity using legacy
		 * RSASIG_v1_5.
		 */
		if (c->local->host.config->authby.rsasig_v1_5) {
			return IKEv2_AUTH_RSA;
		}

		/*
		 * Nothing acceptable, try to log something helpful.
		 */
		if (ike->sa.st_seen_hashnotify) {
			llog_sa(RC_LOG_SERIOUS, ike,
				"local policy does not allow legacy RSA-SHA1 but connection allows no other hash policy");
		} else {
			llog_sa(RC_LOG_SERIOUS, ike,
				"legacy RSA-SHA1 is not allowed but peer supports nothing else");
		}
		return IKEv2_AUTH_RESERVED;

	case AUTH_ECDSA:
		/*
		 * Peer sent us N(SIGNATURE_HASH_ALGORITHMS)
		 * indicating a preference for Digital Signature
		 * Method, and local policy was ok with the
		 * suggestion.
		 */
		pexpect(authby_has_ecdsa(c->local->host.config->authby));
		if (ike->sa.st_v2_digsig.negotiated_hashes != LEMPTY) {
			return IKEv2_AUTH_DIGSIG;
		}

		/*
		 * If there are HASH algorithms, prute force pick the
		 * first and use that.  Note that this doesn't check
		 * that the ECDSA key matches the Pnnn.  Instead, like
		 * for Digital Signature Method, it allows any ECDSA
		 * key.
		 *
		 * XXX: this _should_ be looking at the ECDSA key.
		 */
		if (ike->sa.st_connection->config->sighash_policy & POL_SIGHASH_SHA2_512) {
			return IKEv2_AUTH_ECDSA_SHA2_512_P521;
		}
		if (ike->sa.st_connection->config->sighash_policy & POL_SIGHASH_SHA2_384) {
			return IKEv2_AUTH_ECDSA_SHA2_384_P384;
		}
		if (ike->sa.st_connection->config->sighash_policy & POL_SIGHASH_SHA2_256) {
			return IKEv2_AUTH_ECDSA_SHA2_256_P256;
		}

		/*
		 * Nothing acceptable, try to log something helpful.
		 */
		if (ike->sa.st_seen_hashnotify) {
			llog_sa(RC_LOG_SERIOUS, ike,
				"local policy requires ECDSA but peer sent no acceptable signature hash algorithms");
			return IKEv2_AUTH_RESERVED;
		}

		llog_sa(RC_LOG_SERIOUS, ike,
			"legacy ECDSA is not implemented");
		return IKEv2_AUTH_RESERVED;

	case AUTH_EAPONLY:
		/*
		 * EAP-Only uses an EAP Generated KEY; which is
		 * bundled in PSK (it certainly isn't one of the
		 * signature payloads)?
		 */
		return IKEv2_AUTH_PSK;

	case AUTH_PSK:
		return IKEv2_AUTH_PSK;

	case AUTH_NULL:
		return IKEv2_AUTH_NULL;

	case AUTH_NEVER:
	case AUTH_UNSET:
		break;

	}
	bad_case(authby);
}

/*
 * Map negotiation bit <-> hash algorithm; in preference order.
 */

static const struct hash_desc *negotiated_hash_map[] = {
	&ike_alg_hash_sha2_512,
	&ike_alg_hash_sha2_384,
	&ike_alg_hash_sha2_256,
	/* RFC 8420 IDENTITY algo not supported yet */
	/* { POL_SIGHASH_IDENTITY, IKEv2_HASH_ALGORITHM_IDENTITY }, */
};

const struct hash_desc *v2_auth_negotiated_signature_hash(struct ike_sa *ike)
{
	dbg("digsig: selecting negotiated hash algorithm");
	FOR_EACH_ELEMENT(hash, negotiated_hash_map) {
		if (ike->sa.st_v2_digsig.negotiated_hashes & LELEM((*hash)->common.ikev2_alg_id)) {
			dbg("digsig:   selected hash algorithm %s",
			    (*hash)->common.fqn);
			return (*hash);
		}
		dbg("digsig:   skipped hash algorithm %s as not negotiated",
		    (*hash)->common.fqn);
	}
	dbg("DigSig: no compatible DigSig hash algo");
	return NULL;
}

bool emit_local_v2AUTH(struct ike_sa *ike,
		       const struct hash_signature *auth_sig,
		       struct pbs_out *outs)
{
	enum keyword_auth authby = ike->sa.st_eap_sa_md ? AUTH_PSK : local_v2_auth(ike);
	enum ikev2_auth_method local_auth_method = local_v2AUTH_method(ike, authby);
	struct ikev2_auth a = {
		.isaa_critical = build_ikev2_critical(false, ike->sa.logger),
		.isaa_auth_method = local_auth_method,
	};

	struct pbs_out auth_pbs;
	if (!out_struct(&a, &ikev2_auth_desc, outs, &auth_pbs)) {
		return false;
	}

	switch (local_auth_method) {
	case IKEv2_AUTH_RSA:
	case IKEv2_AUTH_ECDSA_SHA2_256_P256:
	case IKEv2_AUTH_ECDSA_SHA2_384_P384:
	case IKEv2_AUTH_ECDSA_SHA2_512_P521:
	case IKEv2_AUTH_PSK:
	case IKEv2_AUTH_NULL:
		if (!out_hunk(*auth_sig, &auth_pbs, "signature")) {
			return false;
		}
		break;

	case IKEv2_AUTH_DIGSIG:
	{
		/* saved during signing */
		const struct hash_desc *hash_alg = ike->sa.st_v2_digsig.hash;
		const struct pubkey_signer *signer = ike->sa.st_v2_digsig.signer;
		shunk_t b = hash_alg->digital_signature_blob[signer->digital_signature_blob];
		if (!pexpect(b.len > 0)) {
			return false;
		}

		if (!pbs_out_hunk(&auth_pbs, b, "OID of ASN.1 Algorithm Identifier")) {
			/* already logged */
			return false;
		}

		if (!pbs_out_hunk(&auth_pbs, *auth_sig, "signature")) {
			/* already logged */
			return false;
		}
		break;
	}

	default:
		bad_case(a.isaa_auth_method);
	}

	close_output_pbs(&auth_pbs);
	return true;
}

/*
 * Called by process_v2_IKE_AUTH_request_tail() and
 * ikev2_in_IKE_AUTH_R() Do the actual AUTH payload verification
 *
 * ??? Several verify routines return an stf_status and yet we just
 *     return a bool.  We perhaps should return an stf_status so
 *     distinctions don't get lost.
 *
 * XXX: IKEv2 doesn't do subtle distinctions
 *
 * This just needs to answer the very simple yes/no question.  Did
 * auth succeed.  Caller needs to decide what response is appropriate.
 */

static diag_t verify_v2AUTH_and_log_using_pubkey(struct authby authby,
						 struct ike_sa *ike,
						 const struct crypt_mac *idhash,
						 const struct pbs_in *signature_pbs,
						 const struct hash_desc *hash_algo,
						 const struct pubkey_signer *pubkey_signer,
						 const char *signature_payload_name)
{
	statetime_t start = statetime_start(&ike->sa);

	struct connection *c = ike->sa.st_connection;

	if (hash_algo->common.ikev2_alg_id < 0) {
		return diag("authentication failed: unknown or unsupported hash algorithm");
	}

	/*
	 * The field c->config->sighash_policy contains values
	 * intended for Digital Signature method.  Since that method
	 * never allows SHA1, that bit is never set in in
	 * .sighash_policy.
	 *
	 * Hence the hack to allow PKCS#1 1.5 RSA + SHA1 which can
	 * only be for legacy RSA_DIGITAL_SIGNATURE.
	 *
	 * XXX: suspect adding that bit and then using .sighash_policy
	 * to determine if SHA1 is allowed at all would be cleaner.
	 */

	lset_t hash_bit = LELEM(hash_algo->common.ikev2_alg_id);
	if (authby.rsasig_v1_5 && hash_algo == &ike_alg_hash_sha1) {
		pexpect(!(c->config->sighash_policy & hash_bit));
		dbg("skipping sighash check as PKCS#1 1.5 RSA + SHA1");
	} else if (!(c->config->sighash_policy & hash_bit)) {
		return diag("authentication failed: peer authentication requires hash algorithm %s",
			    hash_algo->common.fqn);
	}

	if (!authby_le(authby, c->remote->host.config->authby)) {
		authby_buf pb;
		return diag("authentication failed: peer authentication requires policy %s",
			    str_authby(authby, &pb));
	}

	shunk_t signature = pbs_in_left(signature_pbs);
	if (signature.len == 0) {
		return diag("authentication failed: rejecting received zero-length signature");
	}

	struct crypt_mac hash = v2_calculate_sighash(ike, idhash, hash_algo,
						     REMOTE_PERSPECTIVE);
	diag_t d = authsig_and_log_using_pubkey(ike, &hash, signature,
						hash_algo, pubkey_signer,
						signature_payload_name);
	statetime_stop(&start, "%s()", __func__);
	return d;
}

diag_t verify_v2AUTH_and_log(enum ikev2_auth_method recv_auth,
			     struct ike_sa *ike,
			     const struct crypt_mac *idhash_in,
			     struct pbs_in *signature_pbs,
			     const enum keyword_auth that_auth)
{
	enum_buf ramb, eanb;
	dbg("verifying auth payload, remote sent v2AUTH=%s we want auth=%s",
	    str_enum_short(&ikev2_auth_method_names, recv_auth, &ramb),
	    str_enum_short(&keyword_auth_names, that_auth, &eanb));

	/*
	 * XXX: can the boiler plate check that THAT_AUTH matches
	 * recv_auth appearing in all case branches be merged?
	 */

	switch (recv_auth) {
	case IKEv2_AUTH_RSA:
		return verify_v2AUTH_and_log_using_pubkey((struct authby) { .rsasig_v1_5 = true, },
							  ike, idhash_in,
							  signature_pbs,
							  &ike_alg_hash_sha1,
							  &pubkey_signer_raw_pkcs1_1_5_rsa,
							  NULL/*legacy-signature-name*/);

	case IKEv2_AUTH_ECDSA_SHA2_256_P256:
		return verify_v2AUTH_and_log_using_pubkey((struct authby) { .ecdsa = true, },
							  ike, idhash_in,
							  signature_pbs,
							  &ike_alg_hash_sha2_256,
							  &pubkey_signer_raw_ecdsa/*_p256*/,
							  NULL/*legacy-signature-name*/);

	case IKEv2_AUTH_ECDSA_SHA2_384_P384:
		return verify_v2AUTH_and_log_using_pubkey((struct authby) { .ecdsa = true, },
							  ike, idhash_in,
							  signature_pbs,
							  &ike_alg_hash_sha2_384,
							  &pubkey_signer_raw_ecdsa/*_p384*/,
							  NULL/*legacy-signature-name*/);
	case IKEv2_AUTH_ECDSA_SHA2_512_P521:
		return verify_v2AUTH_and_log_using_pubkey((struct authby) { .ecdsa = true, },
							  ike, idhash_in,
							  signature_pbs,
							  &ike_alg_hash_sha2_512,
							  &pubkey_signer_raw_ecdsa/*_p521*/,
							  NULL/*legacy-signature-name*/);

	case IKEv2_AUTH_PSK:
	{
		if (that_auth != AUTH_PSK) {
			return diag("authentication failed: peer attempted PSK authentication but we want %s",
				    enum_name(&keyword_auth_names, that_auth));
		}

		diag_t d = verify_v2AUTH_and_log_using_psk(AUTH_PSK, ike, idhash_in,
							   signature_pbs, NULL/*auth_sig*/);
		if (d != NULL) {
			dbg("authentication failed: PSK AUTH mismatch");
			return d;
		}

		return NULL;
	}

	case IKEv2_AUTH_NULL:
	{
		/*
		 * Given authby=rsa+null, that_auth==rsa.  Hence the
		 * second test; but doesn't that make the first test
		 * redundant?
		 */
		if (that_auth != AUTH_NULL &&
		    !ike->sa.st_connection->remote->host.config->authby.null) {
			return diag("authentication failed: peer attempted NULL authentication but we want %s",
				    enum_name(&keyword_auth_names, that_auth));
		}

		diag_t d = verify_v2AUTH_and_log_using_psk(AUTH_NULL, ike, idhash_in,
							   signature_pbs, NULL/*auth_sig*/);
		if (d != NULL) {
			dbg("authentication failed: NULL AUTH mismatch (implementation bug?)");
			return d;
		}

		ike->sa.st_ikev2_anon = true;
		return NULL;
	}

	case IKEv2_AUTH_DIGSIG:
	{
		if (that_auth != AUTH_ECDSA &&
		    that_auth != AUTH_RSASIG) {
			return diag("authentication failed: peer attempted authentication through Digital Signature but we want %s",
				    enum_name(&keyword_auth_names, that_auth));
		}

		/* try to match ASN.1 blob designating the hash algorithm */

		shunk_t signature = pbs_in_left(signature_pbs);

		dbg("digsig: looking for matching DIGSIG blob");
		FOR_EACH_ELEMENT(hash, negotiated_hash_map) {

			if ((ike->sa.st_connection->config->sighash_policy &
			     LELEM((*hash)->common.ikev2_alg_id)) == LEMPTY) {
				dbg("digsig:   skipping %s as not negotiated",
				    (*hash)->common.fqn);
				continue;
			}

			/*
			 * Try all signers and their blob.
			 *
			 * That way, when a disabled blob matches a
			 * more meaningful log message can be printed
			 * (we're looking at you PKCS#1 1.5 RSA).
			 */
			dbg("digsig:   trying %s", (*hash)->common.fqn);
			static const struct {
				const struct pubkey_signer *signer;
				struct authby authby;
			} signers[] = {
				{ &pubkey_signer_digsig_ecdsa, { .ecdsa = true, }, },
				{ &pubkey_signer_digsig_rsassa_pss, { .rsasig = true, }, },
				{ &pubkey_signer_digsig_pkcs1_1_5_rsa, { .rsasig_v1_5 = true, }, }
			};

			FOR_EACH_ELEMENT(s, signers) {
				enum digital_signature_blob b = s->signer->digital_signature_blob;
				shunk_t blob = (*hash)->digital_signature_blob[b];
				if (blob.len == 0) {
					dbg("digsig:     skipping %s as no blob",
					    s->signer->name);
					continue;
				}
				if (!hunk_starteq(signature, blob)) {
					dbg("digsig:     skipping %s as blob does not match",
					    s->signer->name);
					continue;
				};

				dbg("digsig:    using signer %s and hash %s",
				    s->signer->name, (*hash)->common.fqn);

				/* eat the blob */
				shunk_t ignore;
				diag_t d = pbs_in_shunk(signature_pbs, blob.len, &ignore,
							"skip ASN.1 blob for hash algo");
				if (d != NULL) {
					dbg("digsig:     failing %s due to I/O error: %s",
					    s->signer->name, str_diag(d));
					return d;
				}

				/*
				 * Save the choice so that the
				 * responder can prefer the same
				 * values.
				 */
				ike->sa.st_v2_digsig.hash = (*hash);
				ike->sa.st_v2_digsig.signer = s->signer;

				return verify_v2AUTH_and_log_using_pubkey(s->authby,
									  ike, idhash_in,
									  signature_pbs,
									  (*hash),
									  s->signer,
									  "digital signature");
			}
		}

		dbg("digsig:   no match");
		return diag("authentication failed: no acceptable ECDSA/RSA-PSS ASN.1 signature hash proposal included for %s",
			    enum_name(&keyword_auth_names, that_auth));

	}
	default:
	{
		enum_buf eb;
		return diag("authentication failed: method %s not supported",
			    str_enum(&ikev2_auth_method_names, recv_auth, &eb));
	}
	}
}

static stf_status submit_v2_IKE_AUTH_response_signature(struct ike_sa *ike, struct msg_digest *md,
							const struct v2_id_payload *id_payload,
							const struct hash_desc *hash_algo,
							const struct pubkey_signer *signer,
							v2_auth_signature_cb *cb)
{
	struct crypt_mac hash_to_sign = v2_calculate_sighash(ike, &id_payload->mac, hash_algo,
							     LOCAL_PERSPECTIVE);
	if (!submit_v2_auth_signature(ike, &hash_to_sign, hash_algo, signer, cb, HERE)) {
		dbg("submit_v2_auth_signature() died, fatal");
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_AUTHENTICATION_FAILED, NULL/*no data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL;
	}
	return STF_SUSPEND;
}

stf_status submit_v2AUTH_generate_responder_signature(struct ike_sa *ike, struct msg_digest *md,
						      v2_auth_signature_cb auth_cb)
{
	struct connection *const c = ike->sa.st_connection;

	/*
	 * Construct the IDr payload and store it in state so that it
	 * can be emitted later.  Then use that to construct the
	 * "MACedIDFor[R]".
	 *
	 * Code assumes that struct ikev2_id's "IDType|RESERVED" is
	 * laid out the same as the packet.
	 */

	if (ike->sa.st_peer_wants_null) {
		/* make it the Null ID */
		ike->sa.st_v2_id_payload.header.isai_type = ID_NULL;
		ike->sa.st_v2_id_payload.data = empty_chunk;
	} else {
		shunk_t data;
		ike->sa.st_v2_id_payload.header =
			build_v2_id_payload(&c->local->host, &data,
					    "my IDr", ike->sa.logger);
		ike->sa.st_v2_id_payload.data = clone_hunk(data, "my IDr");
	}

	/* will be signed in auth payload */
	ike->sa.st_v2_id_payload.mac = v2_hash_id_payload("IDr", ike, "st_skey_pr_nss",
							  ike->sa.st_skey_pr_nss);

	enum keyword_auth authby = local_v2_auth(ike);
	enum ikev2_auth_method auth_method = local_v2AUTH_method(ike, authby);
	switch (auth_method) {

	case IKEv2_AUTH_RSA:
		return submit_v2_IKE_AUTH_response_signature(ike, md,
							     &ike->sa.st_v2_id_payload,
							     &ike_alg_hash_sha1,
							     &pubkey_signer_raw_pkcs1_1_5_rsa,
							     auth_cb);

	case IKEv2_AUTH_ECDSA_SHA2_256_P256:
		return submit_v2_IKE_AUTH_response_signature(ike, md,
							    &ike->sa.st_v2_id_payload,
							    &ike_alg_hash_sha2_256,
							    &pubkey_signer_raw_ecdsa/*_p256*/,
							    auth_cb);
	case IKEv2_AUTH_ECDSA_SHA2_384_P384:
		return submit_v2_IKE_AUTH_response_signature(ike, md,
							    &ike->sa.st_v2_id_payload,
							    &ike_alg_hash_sha2_384,
							    &pubkey_signer_raw_ecdsa/*_p384*/,
							    auth_cb);
	case IKEv2_AUTH_ECDSA_SHA2_512_P521:
		return submit_v2_IKE_AUTH_response_signature(ike, md,
							    &ike->sa.st_v2_id_payload,
							    &ike_alg_hash_sha2_512,
							    &pubkey_signer_raw_ecdsa/*_p521*/,
							    auth_cb);

	case IKEv2_AUTH_DIGSIG:
	{
		/*
		 * Prefer the HASH and SIGNER algorithms saved when
		 * authenticating the initiator (assuming the
		 * initiator was authenticated using DIGSIG).
		 *
		 * For HASH, both ends negotiated acceptable hash
		 * algorithms during IKE_SA_INIT.  For SIGNER, the
		 * algorithm also needs to be consistent with local
		 * AUTHBY.
		 *
		 * Save the decision so it is available when emitting
		 * the computed hash.
		 */
		dbg("digsig: selecting hash and signer");
		const char *hash_story;
		if (ike->sa.st_v2_digsig.hash == NULL) {
			ike->sa.st_v2_digsig.hash = v2_auth_negotiated_signature_hash(ike);
			hash_story = "from policy";
		} else {
			hash_story = "saved earlier";
		}
		if (ike->sa.st_v2_digsig.hash == NULL) {
			record_v2N_response(ike->sa.logger, ike, md,
					    v2N_AUTHENTICATION_FAILED, NULL/*no data*/,
					    ENCRYPTED_PAYLOAD);
			return STF_FATAL;
		}
		dbg("digsig:   using hash %s %s",
		    ike->sa.st_v2_digsig.hash->common.fqn,
		    hash_story);
		const char *signer_story;
		switch (authby) {
		case AUTH_RSASIG:
			if (ike->sa.st_v2_digsig.signer == NULL ||
			    ike->sa.st_v2_digsig.signer->type != &pubkey_type_rsa) {
				ike->sa.st_v2_digsig.signer = &pubkey_signer_digsig_rsassa_pss;
				signer_story = "from policy";
			} else {
				signer_story = "saved earlier";
			}
			break;
		case AUTH_ECDSA:
			/* no choice */
			signer_story = "hardwired";
			ike->sa.st_v2_digsig.signer = &pubkey_signer_digsig_ecdsa;
			break;
		default:
			bad_case(authby);
		}
		dbg("digsig:   using %s signer %s",
		    ike->sa.st_v2_digsig.signer->name, signer_story);

		return submit_v2_IKE_AUTH_response_signature(ike, md,
							     &ike->sa.st_v2_id_payload,
							     ike->sa.st_v2_digsig.hash,
							     ike->sa.st_v2_digsig.signer, auth_cb);
	}

	case IKEv2_AUTH_PSK:
	case IKEv2_AUTH_NULL:
	{
		struct crypt_mac signed_octets = empty_mac;
		diag_t d = ikev2_calculate_psk_sighash(LOCAL_PERSPECTIVE,
						       /*accumulated EAP hash*/NULL,
						       ike, authby,
						       &ike->sa.st_v2_id_payload.mac,
						       ike->sa.st_firstpacket_me,
						       &signed_octets);
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, ike->sa.logger, &d, "%s", "");
			record_v2N_response(ike->sa.logger, ike, md,
					    v2N_AUTHENTICATION_FAILED, NULL/*no data*/,
					    ENCRYPTED_PAYLOAD);
			return STF_FATAL;
		}

		if (DBGP(DBG_CRYPT)) {
			DBG_dump_hunk("PSK auth octets", signed_octets);
		}

		struct hash_signature signed_signature = {
			.len = signed_octets.len,
		};
		PASSERT(ike->sa.logger, sizeof(signed_signature.ptr) >= sizeof(signed_octets.ptr));
		memcpy_hunk(signed_signature.ptr, signed_octets, signed_octets.len);

		return auth_cb(ike, md, &signed_signature);
	}

	default:
	{
		enum_buf eb;
		llog_sa(RC_LOG, ike,
			"authentication method %s not supported",
			str_enum(&ikev2_auth_method_names, auth_method, &eb));
		return STF_FATAL;
	}
	}
}

static stf_status submit_v2_IKE_AUTH_request_signature(struct ike_sa *ike,
						       const struct v2_id_payload *id_payload,
						       const struct hash_desc *hash_algo,
						       const struct pubkey_signer *signer,
						       v2_auth_signature_cb *cb)
{
	struct crypt_mac hash_to_sign = v2_calculate_sighash(ike, &id_payload->mac, hash_algo,
							     LOCAL_PERSPECTIVE);
	if (!submit_v2_auth_signature(ike, &hash_to_sign, hash_algo, signer, cb, HERE)) {
		dbg("submit_v2_auth_signature() died, fatal");
		return STF_FATAL;
	}
	return STF_SUSPEND;
}

stf_status submit_v2AUTH_generate_initiator_signature(struct ike_sa *ike, struct msg_digest *md,
						      v2_auth_signature_cb *cb)
{

	enum keyword_auth authby = local_v2_auth(ike);
	enum ikev2_auth_method auth_method = local_v2AUTH_method(ike, authby);
	switch (auth_method) {
	case IKEv2_AUTH_RSA:
		return submit_v2_IKE_AUTH_request_signature(ike,
							    &ike->sa.st_v2_id_payload,
							    &ike_alg_hash_sha1,
							    &pubkey_signer_raw_pkcs1_1_5_rsa,
							    cb);

	case IKEv2_AUTH_ECDSA_SHA2_256_P256:
		return submit_v2_IKE_AUTH_request_signature(ike,
							    &ike->sa.st_v2_id_payload,
							    &ike_alg_hash_sha2_256,
							    &pubkey_signer_raw_ecdsa/*_p256*/,
							    cb);
	case IKEv2_AUTH_ECDSA_SHA2_384_P384:
		return submit_v2_IKE_AUTH_request_signature(ike,
							    &ike->sa.st_v2_id_payload,
							    &ike_alg_hash_sha2_384,
							    &pubkey_signer_raw_ecdsa/*_p384*/,
							    cb);
	case IKEv2_AUTH_ECDSA_SHA2_512_P521:
		return submit_v2_IKE_AUTH_request_signature(ike,
							    &ike->sa.st_v2_id_payload,
							    &ike_alg_hash_sha2_512,
							    &pubkey_signer_raw_ecdsa/*_p521*/,
							    cb);

	case IKEv2_AUTH_DIGSIG:
		/*
		 * Save the HASH and SIGNER for later - used when
		 * emitting the siguature (should the signature
		 * instead include the bonus blob?).
		 */
		ike->sa.st_v2_digsig.hash = v2_auth_negotiated_signature_hash(ike);
		if (ike->sa.st_v2_digsig.hash == NULL) {
			return STF_FATAL;
		}

		const struct pubkey_signer *signer;
		switch (authby) {
		case AUTH_RSASIG:
			/* XXX: way to force PKCS#1 1.5? */
			signer = &pubkey_signer_digsig_rsassa_pss;
			break;
		case AUTH_ECDSA:
			signer = &pubkey_signer_digsig_ecdsa;
			break;
		default:
			bad_case(authby);
		}
		enum_buf ana;
		dbg("digsig:   authby %s selects signer %s",
		    str_enum(&keyword_auth_names, authby, &ana),
		    signer->name);
		ike->sa.st_v2_digsig.signer = signer;

		return submit_v2_IKE_AUTH_request_signature(ike,
							    &ike->sa.st_v2_id_payload,
							    ike->sa.st_v2_digsig.hash,
							    ike->sa.st_v2_digsig.signer,
							    cb);

	case IKEv2_AUTH_PSK:
	case IKEv2_AUTH_NULL:
	{
		struct crypt_mac signed_octets = empty_mac;
		diag_t d = ikev2_calculate_psk_sighash(LOCAL_PERSPECTIVE,
						       /*accumulated EAP hash*/NULL,
						       ike, authby,
						       &ike->sa.st_v2_id_payload.mac,
						       ike->sa.st_firstpacket_me,
						       &signed_octets);
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, ike->sa.logger, &d, "%s", "");
			return STF_FATAL;
		}

		if (DBGP(DBG_CRYPT)) {
			DBG_dump_hunk("PSK auth octets", signed_octets);
		}

		struct hash_signature signed_signature = {
			.len = signed_octets.len,
		};
		PASSERT(ike->sa.logger, sizeof(signed_signature.ptr) >= sizeof(signed_octets.ptr));
		memcpy_hunk(signed_signature.ptr, signed_octets, signed_octets.len);

		return cb(ike, md, &signed_signature);
	}

	default:
	{
		enum_buf eb;
		llog_sa(RC_LOG, ike,
			"authentication method %s not supported",
			str_enum(&ikev2_auth_method_names, auth_method, &eb));
		return STF_FATAL;
	}
	}

}
