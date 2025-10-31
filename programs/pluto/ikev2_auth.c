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
#include "crypt_prf.h"

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
#include "ikev2_notification.h"

struct v2AUTH_blobs {
	uint32_t mid;
	struct hash_hunk blob[8];
	struct hash_hunks hunks;
};

static void extract_v2AUTH_blobs(const struct ike_sa *ike,
				 const struct crypt_mac *idhash,
				 enum perspective from_the_perspective_of,
				 struct v2AUTH_blobs *blobs)
{
	struct logger *logger = ike->sa.logger;
	zero(blobs);

	enum sa_role role;
	struct hash_hunk *blob = blobs->blob;

	*blob++ = (from_the_perspective_of == LOCAL_PERSPECTIVE ? (struct hash_hunk) { "first-packet-me", HUNK_REF(ike->sa.st_firstpacket_me), } :
		   from_the_perspective_of == REMOTE_PERSPECTIVE ? (struct hash_hunk) { "first-packet-peer", HUNK_REF(ike->sa.st_firstpacket_peer), } :
		   (struct hash_hunk) {0});

	switch (from_the_perspective_of) {
	case LOCAL_PERSPECTIVE:
		role = ike->sa.st_sa_role;
		break;
	case REMOTE_PERSPECTIVE:
		role = (ike->sa.st_sa_role == SA_INITIATOR ? SA_RESPONDER :
			ike->sa.st_sa_role == SA_RESPONDER ? SA_INITIATOR :
			0);
		break;
	default:
		bad_case(from_the_perspective_of);
	}

	/* inbound nonce */
	*blob++ = (role == SA_INITIATOR ? (struct hash_hunk) { "responder nonce", HUNK_REF(&ike->sa.st_nr), } :
		   role == SA_RESPONDER ? (struct hash_hunk) { "initiator nonce", HUNK_REF(&ike->sa.st_ni), } :
		   (struct hash_hunk) {0});

	passert(idhash->len == ike->sa.st_oakley.ta_prf->prf_output_size);
	*blob++ = (struct hash_hunk) { "idhash", HUNK_REF(idhash), };

	if (ike->sa.st_v2_ike_intermediate.enabled) {
		chunk_t ia1;
		chunk_t ia2;
		switch (role) {
		case SA_INITIATOR:
			ia1 = ike->sa.st_v2_ike_intermediate.initiator;
			ia2 = ike->sa.st_v2_ike_intermediate.responder;
			break;
		case SA_RESPONDER:
			ia1 = ike->sa.st_v2_ike_intermediate.responder;
			ia2 = ike->sa.st_v2_ike_intermediate.initiator;
			break;
		default:
			bad_case(role);
		}
		*blob++ = (struct hash_hunk) { "IntAuth_*_I_A", HUNK_REF(&ia1), };
		*blob++ = (struct hash_hunk) { "IntAuth_*_R_A", HUNK_REF(&ia2), };
		/* IKE AUTH's first Message ID */
		hton_thing(ike->sa.st_v2_ike_intermediate.id + 1, blobs->mid);
		shunk_t mid = THING_AS_HUNK(blobs->mid);
		*blob++ = (struct hash_hunk) { "IKE_AUTH_MID", HUNK_REF(&mid), };
	}

	blobs->hunks.len = blob - blobs->blob;
	blobs->hunks.hunk = blobs->blob;
	PASSERT(logger, blobs->hunks.len <= elemsof(blobs->blob));

	if (LDBGP(DBG_CRYPT, logger)) {
		for (unsigned u = 0; u < blobs->hunks.len; u++) {
			struct hash_hunk *hunk = &blobs->blob[u];
			if (hunk->len > 0) {
				LDBG_log_hunk(logger, "%s:", hunk, hunk->name);
			}
		}
	}
}

struct crypt_mac v2_calculate_sighash(const struct ike_sa *ike,
				      const struct crypt_mac *idhash,
				      const struct hash_desc *hasher,
				      enum perspective from_the_perspective_of)
{
	struct v2AUTH_blobs blobs;
	extract_v2AUTH_blobs(ike, idhash, from_the_perspective_of, &blobs);
	return crypt_hash_hunks("sighash", hasher, &blobs.hunks, ike->sa.logger);
}

enum auth local_v2_auth(struct ike_sa *ike)
{
	if (ike->sa.st_v2_resume_session != NULL) {
		return AUTH_PSK;
	}

	if (ike->sa.st_peer_wants_null) {
		/* we allow authby=null and IDr payload told us to use it */
		return AUTH_NULL;
	}

	const struct connection *c = ike->sa.st_connection;
	enum auth authby = c->local->host.config->auth;
	pexpect(authby != AUTH_UNSET);
	return authby;
}

/*
 * Map the configuration's authby=... onto the IKEv2 AUTH message's
 * auth method.
 */

enum ikev2_auth_method local_v2AUTH_method(struct ike_sa *ike,
					   enum auth authby)
{
	struct connection *c = ike->sa.st_connection;

	if (impair.force_v2_auth_method.enabled) {
		name_buf eb;
		llog(RC_LOG, ike->sa.logger, "IMPAIR: forcing auth method %s",
		     str_enum_long(&ikev2_auth_method_names,
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
		pexpect(auth_in_authby(AUTH_RSASIG, c->local->host.config->authby));
		if (ike->sa.st_v2_digsig.negotiated_hashes != LEMPTY) {
			return IKEv2_AUTH_DIGITAL_SIGNATURE;
		}

		/*
		 * Local policy allows proof-of-identity using legacy
		 * RSASIG_v1_5.
		 */
		if (c->local->host.config->authby.rsasig_v1_5) {
			return IKEv2_AUTH_RSA_DIGITAL_SIGNATURE;
		}

		/*
		 * Nothing acceptable, try to log something helpful.
		 */
		if (ike->sa.st_seen_hashnotify) {
			llog_sa(RC_LOG, ike,
				"local policy does not allow legacy RSA-SHA1 but connection allows no other hash policy");
		} else {
			llog_sa(RC_LOG, ike,
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
		pexpect(auth_in_authby(AUTH_ECDSA, c->local->host.config->authby));
		if (ike->sa.st_v2_digsig.negotiated_hashes != LEMPTY) {
			return IKEv2_AUTH_DIGITAL_SIGNATURE;
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
			llog_sa(RC_LOG, ike,
				"local policy requires ECDSA but peer sent no acceptable signature hash algorithms");
			return IKEv2_AUTH_RESERVED;
		}

		llog_sa(RC_LOG, ike,
			"legacy ECDSA is not implemented");
		return IKEv2_AUTH_RESERVED;

	case AUTH_EDDSA:
		/*
		 * Peer sent us N(SIGNATURE_HASH_ALGORITHMS)
		 * indicating a preference for Digital Signature
		 * Method, and local policy was ok with the
		 * suggestion.
		 */
		pexpect(auth_in_authby(AUTH_EDDSA, c->local->host.config->authby));
		if (ike->sa.st_v2_digsig.negotiated_hashes != LEMPTY) {
			return IKEv2_AUTH_DIGITAL_SIGNATURE;
		}

		llog(RC_LOG, ike->sa.logger, "EDDSA only supports Digital Signature authentication");
		return IKEv2_AUTH_RESERVED;

	case AUTH_EAPONLY:
		/*
		 * EAP-Only uses an EAP Generated KEY; which is
		 * bundled in PSK (it certainly isn't one of the
		 * signature payloads)?
		 */
		return IKEv2_AUTH_SHARED_KEY_MAC;

	case AUTH_PSK:
		return IKEv2_AUTH_SHARED_KEY_MAC;

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
	&ike_alg_hash_identity,
};

const struct hash_desc *v2_auth_negotiated_signature_hash(struct ike_sa *ike)
{
	ldbg(ike->sa.logger, "digsig: selecting negotiated hash algorithm");
	FOR_EACH_ELEMENT(hash, negotiated_hash_map) {
		if (ike->sa.st_v2_digsig.negotiated_hashes & LELEM((*hash)->ikev2_alg_id)) {
			ldbg(ike->sa.logger, "digsig:   selected hash algorithm %s",
			     (*hash)->common.fqn);
			return (*hash);
		}
		ldbg(ike->sa.logger, "digsig:   skipped hash algorithm %s as not negotiated",
		     (*hash)->common.fqn);
	}
	ldbg(ike->sa.logger, "DigSig: no compatible DigSig hash algo");
	return NULL;
}

bool emit_local_v2AUTH(struct ike_sa *ike,
		       const struct hash_signature *auth_sig,
		       struct pbs_out *outs)
{
	/* EAP only does PSK?!? */
	enum auth authby = (ike->sa.st_eap != NULL ? AUTH_PSK : local_v2_auth(ike));
	enum ikev2_auth_method local_auth_method = local_v2AUTH_method(ike, authby);
	struct ikev2_auth a = {
		.isaa_critical = build_ikev2_critical(false, ike->sa.logger),
		.isaa_auth_method = local_auth_method,
	};

	struct pbs_out auth_pbs;
	if (!pbs_out_struct(outs, a, &ikev2_auth_desc, &auth_pbs)) {
		return false;
	}

	switch (local_auth_method) {
	case IKEv2_AUTH_RSA_DIGITAL_SIGNATURE:
	case IKEv2_AUTH_ECDSA_SHA2_256_P256:
	case IKEv2_AUTH_ECDSA_SHA2_384_P384:
	case IKEv2_AUTH_ECDSA_SHA2_512_P521:
	case IKEv2_AUTH_SHARED_KEY_MAC:
	case IKEv2_AUTH_NULL:
		if (!pbs_out_hunk(&auth_pbs, *auth_sig, "signature")) {
			return false;
		}
		break;

	case IKEv2_AUTH_DIGITAL_SIGNATURE:
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

	close_pbs_out(&auth_pbs);
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

	if (hash_algo->ikev2_alg_id < 0) {
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

	lset_t hash_bit = LELEM(hash_algo->ikev2_alg_id);
	if (authby.rsasig_v1_5 && hash_algo == &ike_alg_hash_sha1) {
		pexpect(!(c->config->sighash_policy & hash_bit));
		ldbg(ike->sa.logger, "skipping sighash check as PKCS#1 1.5 RSA + SHA1");
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

	struct v2AUTH_blobs blobs;
	extract_v2AUTH_blobs(ike, idhash, REMOTE_PERSPECTIVE, &blobs);
	struct crypt_mac hash = {0};
	if (hash_algo == &ike_alg_hash_identity) {
		llog(RC_LOG, ike->sa.logger, "identity hash, skipping hash calculation");
	} else {
		hash = crypt_hash_hunks("pubkey hash", hash_algo,
					&blobs.hunks, ike->sa.logger);
	}
	diag_t d = authsig_and_log_using_pubkey(ike, &hash, &blobs.hunks, signature,
						hash_algo, pubkey_signer,
						signature_payload_name);
	statetime_stop(&start, "%s()", __func__);
	return d;
}

diag_t verify_v2AUTH_and_log(enum ikev2_auth_method recv_auth,
			     struct ike_sa *ike,
			     const struct crypt_mac *idhash_in,
			     struct pbs_in *signature_pbs,
			     const enum auth that_auth)
{
	name_buf ramb, eanb;
	ldbg(ike->sa.logger, "verifying auth payload, remote sent v2AUTH=%s we want auth=%s",
	     str_enum_short(&ikev2_auth_method_names, recv_auth, &ramb),
	     str_enum_short(&auth_names, that_auth, &eanb));

	/*
	 * XXX: can the boiler plate check that THAT_AUTH matches
	 * recv_auth appearing in all case branches be merged?
	 */

	switch (recv_auth) {
	case IKEv2_AUTH_RSA_DIGITAL_SIGNATURE:
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

	case IKEv2_AUTH_SHARED_KEY_MAC:
	{
		if (that_auth != AUTH_PSK) {
			name_buf an;
			return diag("authentication failed: peer attempted PSK authentication but we want %s",
				    str_enum_short(&auth_names, that_auth, &an));
		}

		diag_t d = verify_v2AUTH_and_log_using_psk(AUTH_PSK, ike, idhash_in,
							   signature_pbs, NULL/*auth_sig*/);
		if (d != NULL) {
			ldbg(ike->sa.logger, "authentication failed: PSK AUTH mismatch");
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
			name_buf an;
			return diag("authentication failed: peer attempted NULL authentication but we want %s",
				    str_enum_short(&auth_names, that_auth, &an));
		}

		diag_t d = verify_v2AUTH_and_log_using_psk(AUTH_NULL, ike, idhash_in,
							   signature_pbs, NULL/*auth_sig*/);
		if (d != NULL) {
			ldbg(ike->sa.logger, "authentication failed: NULL AUTH mismatch (implementation bug?)");
			return d;
		}

		ike->sa.st_ikev2_anon = true;
		return NULL;
	}

	case IKEv2_AUTH_DIGITAL_SIGNATURE:
	{
		if (!digital_signature_in_authby(authby_from_auth(that_auth))) {
			name_buf an;
			return diag("authentication failed: peer attempted authentication through Digital Signature but we want %s",
				    str_enum_short(&auth_names, that_auth, &an));
		}

		/* try to match ASN.1 blob designating the hash algorithm */

		shunk_t signature = pbs_in_left(signature_pbs);

		ldbg(ike->sa.logger, "digsig: looking for matching DIGSIG blob");
		FOR_EACH_ELEMENT(hash, negotiated_hash_map) {

			if ((ike->sa.st_connection->config->sighash_policy &
			     LELEM((*hash)->ikev2_alg_id)) == LEMPTY) {
				ldbg(ike->sa.logger, "digsig:   skipping %s as not negotiated",
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
			ldbg(ike->sa.logger, "digsig:   trying %s", (*hash)->common.fqn);
			static const struct {
				const struct pubkey_signer *signer;
				struct authby authby;
			} signers[] = {
				{ &pubkey_signer_digsig_eddsa_ed25519, { .eddsa = true, }, },
				{ &pubkey_signer_digsig_ecdsa, { .ecdsa = true, }, },
				{ &pubkey_signer_digsig_rsassa_pss, { .rsasig = true, }, },
				{ &pubkey_signer_digsig_pkcs1_1_5_rsa, { .rsasig_v1_5 = true, }, }
			};

			FOR_EACH_ELEMENT(s, signers) {
				enum digital_signature_blob b = s->signer->digital_signature_blob;
				shunk_t blob = (*hash)->digital_signature_blob[b];
				if (blob.len == 0) {
					ldbg(ike->sa.logger,
					     "digsig:     skipping %s as no blob",
					     s->signer->name);
					continue;
				}
				if (!hunk_starteq(signature, blob)) {
					ldbg(ike->sa.logger,
					     "digsig:     skipping %s as blob does not match",
					     s->signer->name);
					continue;
				};

				ldbg(ike->sa.logger, "digsig:    using signer %s and hash %s",
				     s->signer->name, (*hash)->common.fqn);

				/* eat the blob */
				shunk_t ignore;
				diag_t d = pbs_in_shunk(signature_pbs, blob.len, &ignore,
							"skip ASN.1 blob for hash algo");
				if (d != NULL) {
					ldbg(ike->sa.logger,
					     "digsig:     failing %s due to I/O error: %s",
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

		ldbg(ike->sa.logger, "digsig:   no match");
		name_buf an;
		return diag("authentication failed: no acceptable ECDSA/RSA-PSS ASN.1 signature hash proposal included for %s",
			    str_enum_short(&auth_names, that_auth, &an));

	}
	default:
	{
		name_buf eb;
		return diag("authentication failed: method %s not supported",
			    str_enum_long(&ikev2_auth_method_names, recv_auth, &eb));
	}
	}
}

static stf_status submit_v2_IKE_AUTH_response_signature(struct ike_sa *ike,
							struct msg_digest *md,
							const struct v2_id_payload *id_payload,
							const struct hash_desc *hash_algo,
							const struct pubkey_signer *signer,
							v2_auth_signature_cb *cb)
{
	if (!submit_v2_auth_signature(ike, md,
				      &id_payload->mac, hash_algo, LOCAL_PERSPECTIVE,
				      signer, cb, HERE)) {
		ldbg(ike->sa.logger, "submit_v2_auth_signature() died, fatal");
		record_v2N_response(ike->sa.logger, ike, md,
				    v2N_AUTHENTICATION_FAILED, empty_shunk/*no data*/,
				    ENCRYPTED_PAYLOAD);
		return STF_FATAL;
	}
	return STF_SUSPEND;
}

stf_status submit_v2AUTH_generate_responder_signature(struct ike_sa *ike, struct msg_digest *md,
						      v2_auth_signature_cb auth_cb)
{
	struct logger *logger = ike->sa.logger;

	enum auth authby = local_v2_auth(ike);
	enum ikev2_auth_method auth_method = local_v2AUTH_method(ike, authby);
	switch (auth_method) {

	case IKEv2_AUTH_RSA_DIGITAL_SIGNATURE:
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

	case IKEv2_AUTH_DIGITAL_SIGNATURE:
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
		ldbg(ike->sa.logger, "digsig: selecting hash and signer");
		const char *hash_story;
		if (ike->sa.st_v2_digsig.hash == NULL) {
			ike->sa.st_v2_digsig.hash = v2_auth_negotiated_signature_hash(ike);
			hash_story = "from policy";
		} else {
			hash_story = "saved earlier";
		}
		if (ike->sa.st_v2_digsig.hash == NULL) {
			record_v2N_response(ike->sa.logger, ike, md,
					    v2N_AUTHENTICATION_FAILED, empty_shunk/*no data*/,
					    ENCRYPTED_PAYLOAD);
			return STF_FATAL;
		}
		ldbg(ike->sa.logger,"digsig:   using hash %s %s",
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
			signer_story = "hardwired(ECDSA)";
			ike->sa.st_v2_digsig.signer = &pubkey_signer_digsig_ecdsa;
			break;
		case AUTH_EDDSA:
			signer_story = "hardwired(EDDSA)";
			ike->sa.st_v2_digsig.signer = &pubkey_signer_digsig_eddsa_ed25519;
			break;
		default:
			bad_case(authby);
		}
		ldbg(ike->sa.logger, "digsig:   using %s signer %s",
		     ike->sa.st_v2_digsig.signer->name, signer_story);

		return submit_v2_IKE_AUTH_response_signature(ike, md,
							     &ike->sa.st_v2_id_payload,
							     ike->sa.st_v2_digsig.hash,
							     ike->sa.st_v2_digsig.signer, auth_cb);
	}

	case IKEv2_AUTH_SHARED_KEY_MAC:
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
			llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
			pfree_diag(&d);
			record_v2N_response(ike->sa.logger, ike, md,
					    v2N_AUTHENTICATION_FAILED, empty_shunk/*no-data*/,
					    ENCRYPTED_PAYLOAD);
			return STF_FATAL;
		}

		if (LDBGP(DBG_CRYPT, logger)) {
			LDBG_log_hunk(logger, "PSK auth octets:", &signed_octets);
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
		name_buf eb;
		llog_sa(RC_LOG, ike,
			"authentication method %s not supported",
			str_enum_long(&ikev2_auth_method_names, auth_method, &eb));
		return STF_FATAL;
	}
	}
}

static stf_status submit_v2_IKE_AUTH_request_signature(struct ike_sa *ike,
						       struct msg_digest *md,
						       const struct v2_id_payload *id_payload,
						       const struct hash_desc *hash_algo,
						       const struct pubkey_signer *signer,
						       v2_auth_signature_cb *cb)
{
	if (!submit_v2_auth_signature(ike, md,
				      &id_payload->mac, hash_algo, LOCAL_PERSPECTIVE,
				      signer, cb, HERE)) {
		ldbg(ike->sa.logger, "submit_v2_auth_signature() died, fatal");
		return STF_FATAL;
	}
	return STF_SUSPEND;
}

stf_status submit_v2AUTH_generate_initiator_signature(struct ike_sa *ike,
						      struct msg_digest *md,
						      v2_auth_signature_cb *cb)
{
	struct logger *logger = ike->sa.logger;
	enum auth authby = local_v2_auth(ike);
	enum ikev2_auth_method auth_method = local_v2AUTH_method(ike, authby);
	switch (auth_method) {
	case IKEv2_AUTH_RSA_DIGITAL_SIGNATURE:
		return submit_v2_IKE_AUTH_request_signature(ike, md,
							    &ike->sa.st_v2_id_payload,
							    &ike_alg_hash_sha1,
							    &pubkey_signer_raw_pkcs1_1_5_rsa,
							    cb);

	case IKEv2_AUTH_ECDSA_SHA2_256_P256:
		return submit_v2_IKE_AUTH_request_signature(ike, md,
							    &ike->sa.st_v2_id_payload,
							    &ike_alg_hash_sha2_256,
							    &pubkey_signer_raw_ecdsa/*_p256*/,
							    cb);
	case IKEv2_AUTH_ECDSA_SHA2_384_P384:
		return submit_v2_IKE_AUTH_request_signature(ike, md,
							    &ike->sa.st_v2_id_payload,
							    &ike_alg_hash_sha2_384,
							    &pubkey_signer_raw_ecdsa/*_p384*/,
							    cb);
	case IKEv2_AUTH_ECDSA_SHA2_512_P521:
		return submit_v2_IKE_AUTH_request_signature(ike, md,
							    &ike->sa.st_v2_id_payload,
							    &ike_alg_hash_sha2_512,
							    &pubkey_signer_raw_ecdsa/*_p521*/,
							    cb);

	case IKEv2_AUTH_DIGITAL_SIGNATURE:
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
		case AUTH_EDDSA:
			signer = &pubkey_signer_digsig_eddsa_ed25519;
			break;
		default:
			bad_case(authby);
		}
		name_buf ana;
		ldbg(ike->sa.logger, "digsig:   authby %s selects signer %s",
		     str_enum_long(&auth_names, authby, &ana),
		     signer->name);
		ike->sa.st_v2_digsig.signer = signer;

		return submit_v2_IKE_AUTH_request_signature(ike, md,
							    &ike->sa.st_v2_id_payload,
							    ike->sa.st_v2_digsig.hash,
							    ike->sa.st_v2_digsig.signer,
							    cb);

	case IKEv2_AUTH_SHARED_KEY_MAC:
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
			llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
			pfree_diag(&d);
			return STF_FATAL;
		}

		if (LDBGP(DBG_CRYPT, logger)) {
			LDBG_log_hunk(logger, "PSK auth octets:", &signed_octets);
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
		name_buf eb;
		llog_sa(RC_LOG, ike,
			"authentication method %s not supported",
			str_enum_long(&ikev2_auth_method_names, auth_method, &eb));
		return STF_FATAL;
	}
	}

}

/*
 * Construct the ID[ir] payload and store it in state so that it can
 * be emitted later.  Then use that to construct the "MACedIDFor[IR]".
 *
 * Code assumes that struct ikev2_id's "IDType|RESERVED" is laid out
 * the same as the packet.
 */

static struct crypt_mac v2_hash_id_payload(const char *id_name, const struct ike_sa *ike,
					   const char *key_name, PK11SymKey *key)
{
	/*
	 * InitiatorIDPayload = PayloadHeader | RestOfInitIDPayload
	 * RestOfInitIDPayload = IDType | RESERVED | InitIDData
	 * MACedIDForR = prf(SK_pr, RestOfInitIDPayload)
	 */
	struct crypt_prf *id_ctx = crypt_prf_init_symkey(id_name, ike->sa.st_oakley.ta_prf,
							 key_name, key, ike->sa.logger);
	/* skip PayloadHeader; hash: IDType | RESERVED */
	crypt_prf_update_bytes(id_ctx, "IDType", &ike->sa.st_v2_id_payload.header.isai_type,
				sizeof(ike->sa.st_v2_id_payload.header.isai_type));
	/* note that res1+res2 is 3 zero bytes */
	crypt_prf_update_byte(id_ctx, "RESERVED 1", ike->sa.st_v2_id_payload.header.isai_res1);
	crypt_prf_update_byte(id_ctx, "RESERVED 2", ike->sa.st_v2_id_payload.header.isai_res2);
	crypt_prf_update_byte(id_ctx, "RESERVED 3", ike->sa.st_v2_id_payload.header.isai_res3);
	/* hash: InitIDData */
	crypt_prf_update_hunk(id_ctx, "InitIDData", ike->sa.st_v2_id_payload.data);
	return crypt_prf_final_mac(&id_ctx, NULL/*no-truncation*/);
}

void v2_IKE_AUTH_responder_id_payload(struct ike_sa *ike)
{
	struct connection *const c = ike->sa.st_connection;

	if (ike->sa.st_peer_wants_null) {
		/* make it the Null ID */
		ike->sa.st_v2_id_payload.header.isai_type = ID_NULL;
		ike->sa.st_v2_id_payload.data = empty_chunk;
	} else {
		shunk_t data;
		ike->sa.st_v2_id_payload.header =
			build_v2_id_payload(&c->local->host, &data,
					    "my IDr", ike->sa.logger);
		ike->sa.st_v2_id_payload.data = clone_hunk_as_chunk(&data, "my IDr");
	}

	/* will be signed in auth payload */
	ike->sa.st_v2_id_payload.mac = v2_hash_id_payload("IDr", ike, "st_skey_pr_nss",
					    ike->sa.st_skey_pr_nss);
}

void v2_IKE_AUTH_initiator_id_payload(struct ike_sa *ike)
{
	struct connection *c = ike->sa.st_connection;

	shunk_t data;
	ike->sa.st_v2_id_payload.header =
		build_v2_id_payload(&c->local->host, &data,
				    "my IDi", ike->sa.logger);
	ike->sa.st_v2_id_payload.data = clone_hunk_as_chunk(&data, "my IDi");

	ike->sa.st_v2_id_payload.mac = v2_hash_id_payload("IDi", ike,
					    "st_skey_pi_nss",
					    ike->sa.st_skey_pi_nss);
	if (ike->sa.st_v2_ike_ppk == PPK_IKE_AUTH && !c->config->ppk.insist) {
		/* ID payload that we've build is the same */
		ike->sa.st_v2_id_payload.mac_no_ppk_auth =
			v2_hash_id_payload("IDi (no-PPK)", ike,
					   "sk_pi_no_pkk",
					   ike->sa.st_sk_pi_no_ppk);
	}
}

struct crypt_mac v2_remote_id_hash(const struct ike_sa *ike,
				   const char *why,
				   const struct msg_digest *md)
{
	/*
	 * Computing hash according to peer, hence initiator uses
	 * responder's IDr payload and responder's secret, and
	 * vis-vis.
	 */

	PK11SymKey *key;
	const struct pbs_in *id_pbs;
	const char *key_name;
	const char *id_name;
	switch (ike->sa.st_sa_role) {
	case SA_INITIATOR:
		key_name = "st_skey_pr_nss";
		key = ike->sa.st_skey_pr_nss;
		id_name = "IDr";
		id_pbs = &md->chain[ISAKMP_NEXT_v2IDr]->pbs;
		break;
	case SA_RESPONDER:
		key_name = "st_skey_pi_nss";
		key = ike->sa.st_skey_pi_nss;
		id_name = "IDi";
		id_pbs = &md->chain[ISAKMP_NEXT_v2IDi]->pbs;
		break;
	default:
		bad_case(ike->sa.st_sa_role);
	}

	shunk_t id_payload = pbs_in_all(id_pbs);
	const uint8_t *id_start = id_payload.ptr;
	size_t id_size = id_payload.len;
	/* HASH of ID is not done over common header */
	id_start += NSIZEOF_isakmp_generic;
	id_size -= NSIZEOF_isakmp_generic;
	struct crypt_prf *id_ctx = crypt_prf_init_symkey(why, ike->sa.st_oakley.ta_prf,
							 key_name, key, ike->sa.logger);
	crypt_prf_update_bytes(id_ctx, id_name, id_start, id_size);
	return crypt_prf_final_mac(&id_ctx, NULL/*no-truncation*/);
}

/*
 * Convert the proposed connections into something this responder
 * might accept.
 *
 * + DIGITAL_SIGNATURE code seems a bit dodgy, should this be looking
 * inside the auth proposal to see what is actually required?
 *
 * + the legacy ECDSA_SHA2* methods also seem to be a bit dodgy,
 * shouldn't they also specify the SHA algorithm so that can be
 * matched?
 */

lset_t proposed_v2AUTH(struct ike_sa *ike,
		       struct msg_digest *md)
{
	enum ikev2_auth_method atype =
		md->chain[ISAKMP_NEXT_v2AUTH]->payload.v2auth.isaa_auth_method;
	name_buf nb;
	ldbg(ike->sa.logger, "converting v2AUTH %s into authbys set",
	     str_enum_short(&ikev2_auth_method_names, atype, &nb));

	switch (atype) {
	case IKEv2_AUTH_RSA_DIGITAL_SIGNATURE:
		return LELEM(AUTH_RSASIG);
	case IKEv2_AUTH_ECDSA_SHA2_256_P256:
	case IKEv2_AUTH_ECDSA_SHA2_384_P384:
	case IKEv2_AUTH_ECDSA_SHA2_512_P521:
		return LELEM(AUTH_ECDSA);
	case IKEv2_AUTH_SHARED_KEY_MAC:
		return LELEM(AUTH_PSK);
	case IKEv2_AUTH_NULL:
		return LELEM(AUTH_NULL);
	case IKEv2_AUTH_DIGITAL_SIGNATURE:
		return LELEM(AUTH_RSASIG) | LELEM(AUTH_ECDSA) | LELEM(AUTH_EDDSA);
	default:
	{
		name_buf nb;
		llog(RC_LOG, ike->sa.logger, "auth method %s unrecognized",
		     str_enum_short(&ikev2_auth_method_names,
				    atype, &nb));
		return LEMPTY;
	}
	}
}

/*
 * Check if a given permanent connection has another IKE SA with
 * IKE_AUTH request outstanding. This is useful to detect potential
 * IKE_AUTH crossing streams scenarios.
 */
bool has_outstanding_ike_auth_request(const struct connection *c,
		const struct ike_sa *ike,
		const struct msg_digest *md)
{
	/* Check can be disable in a connection config */
	if (!c->config->reject_simultaneous_ike_auth) {
		return false;
	}

	/* Connection must be permanent and request must be incoming */
	if (v2_msg_role(md) != MESSAGE_REQUEST || !is_permanent(c)) {
		return false;
	}

	struct state_filter sf = {
	  .connection_serialno = c->serialno,
	  .search = {
		.order = NEW2OLD,
		.verbose.logger = ike->sa.logger,
		.where = HERE,
	  },
	};

	while (next_state(&sf)) {
		if (!IS_IKE_SA(sf.st)) {
			continue;
		}

		struct ike_sa *simultaneous_ike = pexpect_ike_sa(sf.st);
		if (simultaneous_ike == NULL || simultaneous_ike == ike) {
			continue;
		} else if (simultaneous_ike->sa.st_sa_role != SA_INITIATOR) {
			continue;
		} else if (!v2_msgid_request_outstanding(simultaneous_ike)) {
			continue;
		}

		const struct v2_exchange *outstanding_request =
			simultaneous_ike->sa.st_v2_msgid_windows.initiator.exchange;
		if (outstanding_request != NULL && outstanding_request->type == ISAKMP_v2_IKE_AUTH) {
			llog(RC_LOG, ike->sa.logger, "IKE SA "PRI_SO" has outstanding IKE_AUTH request",
					pri_so(simultaneous_ike->sa.st_serialno));
			return true;
		}
	}
	return false;
}
