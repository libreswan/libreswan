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
		if (ike->sa.st_v2_ike_intermediate.used) {
			DBG_dump_hunk("IntAuth_*_I_A", ia1);
			DBG_dump_hunk("IntAuth_*_R_A", ia2);
		}
	}

	struct crypt_hash *ctx = crypt_hash_init("sighash", hasher,
						 ike->sa.st_logger);
	crypt_hash_digest_hunk(ctx, "first packet", firstpacket);
	crypt_hash_digest_hunk(ctx, "nonce", *nonce);
	/* we took the PRF(SK_d,ID[ir]'), so length is prf hash length */
	passert(idhash->len == ike->sa.st_oakley.ta_prf->prf_output_size);
	crypt_hash_digest_hunk(ctx, "IDHASH", *idhash);
	if (ike->sa.st_v2_ike_intermediate.used) {
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

enum keyword_authby v2_auth_by(struct ike_sa *ike)
{
	const struct connection *c = ike->sa.st_connection;
	enum keyword_authby authby = c->local->config->host.authby;
	if (ike->sa.st_peer_wants_null) {
		/* we allow authby=null and IDr payload told us to use it */
		authby = AUTHBY_NULL;
	} else if (authby == AUTHBY_UNSET) {
		/*
		 * Asymmetric policy unset.
		 * Pick up from symmetric policy, in order of preference!
		 */
		if ((c->policy & POLICY_ECDSA) &&
		    (c->config->sighash_policy != LEMPTY)) {
			authby = AUTHBY_ECDSA;
		} else if (c->policy & POLICY_RSASIG) {
			authby = AUTHBY_RSASIG;
		} else if (c->policy & POLICY_PSK) {
			authby = AUTHBY_PSK;
		} else if (c->policy & POLICY_AUTH_NULL) {
			authby = AUTHBY_NULL;
		} else {
			/* leave authby == AUTHBY_UNSET */
			/* ??? we will surely crash with bad_case */
		}
	}
	return authby;
}

/*
 * Map the configuration's authby=... onto the IKEv2 AUTH message's
 * auth method.
 */

enum ikev2_auth_method v2AUTH_method_from_authby(struct ike_sa *ike,
						 enum keyword_authby authby)
{
	struct connection *c = ike->sa.st_connection;

	if (impair.force_v2_auth_method != 0) {
		enum_buf eb;
		llog_sa(RC_LOG, ike, "IMPAIR: forcing auth method %s",
			str_enum(&ikev2_auth_method_names, impair.force_v2_auth_method, &eb));
		return impair.force_v2_auth_method;
	}

	switch (authby) {
	case AUTHBY_RSASIG:
		if (ike->sa.st_seen_hashnotify &&
		    c->config->sighash_policy != LEMPTY) {
			return IKEv2_AUTH_DIGSIG;
		}

		if (LIN(POLICY_RSASIG_v1_5, c->policy)) {
			return IKEv2_AUTH_RSA;
		}

		/* try to log something helpful */
		if (ike->sa.st_seen_hashnotify) {
			llog_sa(RC_LOG_SERIOUS, ike,
				"local policy does not allow legacy RSA-SHA1 but connection allows no other hash policy");
		} else {
			llog_sa(RC_LOG_SERIOUS, ike,
				"legacy RSA-SHA1 is not allowed but peer supports nothing else");
		}
		return IKEv2_AUTH_RESERVED;

	case AUTHBY_ECDSA:
		return IKEv2_AUTH_DIGSIG;

	case AUTHBY_PSK:
		return IKEv2_AUTH_PSK;

	case AUTHBY_NULL:
		return IKEv2_AUTH_NULL;

	case AUTHBY_EAPONLY:
	case AUTHBY_NEVER:
	case AUTHBY_UNSET:
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
	FOR_EACH_ELEMENT(negotiated_hash_map, hash) {
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

bool emit_v2_auth(struct ike_sa *ike,
		  const struct hash_signature *auth_sig,
		  const struct crypt_mac *id_payload_mac,
		  struct pbs_out *outs)
{
	enum keyword_authby authby = ike->sa.st_eap_sa_md ? AUTHBY_PSK : v2_auth_by(ike);
	struct ikev2_auth a = {
		.isaa_critical = build_ikev2_critical(false, ike->sa.st_logger),
		.isaa_auth_method = v2AUTH_method_from_authby(ike, authby),
	};

	struct pbs_out auth_pbs;
	if (!out_struct(&a, &ikev2_auth_desc, outs, &auth_pbs)) {
		return false;
	}

	switch (a.isaa_auth_method) {
	case IKEv2_AUTH_RSA:
	case IKEv2_AUTH_ECDSA_SHA2_256_P256:
	case IKEv2_AUTH_ECDSA_SHA2_384_P384:
	case IKEv2_AUTH_ECDSA_SHA2_512_P521:
		if (!out_hunk(*auth_sig, &auth_pbs, "signature")) {
			return false;
		}
		break;

	case IKEv2_AUTH_DIGSIG:
	{
		diag_t d;
		/* saved during signing */
		const struct hash_desc *hash_alg = ike->sa.st_v2_digsig.hash;
		const struct pubkey_signer *signer = ike->sa.st_v2_digsig.signer;
		shunk_t b = hash_alg->digital_signature_blob[signer->digital_signature_blob];
		if (!pexpect(b.len > 0)) {
			return false;
		}

		d = pbs_out_hunk(&auth_pbs, b, "OID of ASN.1 Algorithm Identifier");
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, outs->outs_logger, &d,
				  "DigSig: failed to emit OID of ASN.1 Algorithm Identifier");
			return false;
		}

		d = pbs_out_hunk(&auth_pbs, *auth_sig, "signature");
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, outs->outs_logger, &d,
				  "DigSig: failed to emit HASH");
			return false;
		}
		break;
	}

	case IKEv2_AUTH_PSK:
	case IKEv2_AUTH_NULL:
		/* emit */
		if (!ikev2_emit_psk_auth(authby, ike, id_payload_mac, &auth_pbs, auth_sig)) {
			llog(RC_LOG_SERIOUS, outs->outs_logger, "Failed to find our PreShared Key");
			return false;
		}
		break;

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

static diag_t v2_authsig_and_log_using_pubkey(lset_t auth_policy,
					      struct ike_sa *ike,
					      const struct crypt_mac *idhash,
					      const struct pbs_in *signature_pbs,
					      const struct hash_desc *hash_algo,
					      const struct pubkey_signer *pubkey_signer)
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
	if (auth_policy & POLICY_RSASIG_v1_5 &&
	    hash_algo == &ike_alg_hash_sha1) {
		pexpect(!(c->config->sighash_policy & hash_bit));
		dbg("skipping sighash check as PKCS#1 1.5 RSA + SHA1");
	} else if (!(c->config->sighash_policy & hash_bit)) {
		return diag("authentication failed: peer authentication requires hash algorithm %s",
			    hash_algo->common.fqn);
	}

	if ((c->policy & auth_policy) != auth_policy) {
		policy_buf pb;
		return diag("authentication failed: peer authentication requires policy %s",
			    str_policy(auth_policy, &pb));
	}

	shunk_t signature = pbs_in_left_as_shunk(signature_pbs);
	if (signature.len == 0) {
		return diag("authentication failed: rejecting received zero-length signature");
	}

	struct crypt_mac hash = v2_calculate_sighash(ike, idhash, hash_algo,
						     REMOTE_PERSPECTIVE);
	diag_t d = authsig_and_log_using_pubkey(ike, &hash, signature,
						hash_algo, pubkey_signer);
	statetime_stop(&start, "%s()", __func__);
	return d;
}

diag_t v2_authsig_and_log(enum ikev2_auth_method recv_auth,
			  struct ike_sa *ike,
			  const struct crypt_mac *idhash_in,
			  struct pbs_in *signature_pbs,
			  const enum keyword_authby that_authby)
{
	/*
	 * XXX: can the boiler plate check that THAT_AUTHBY matches
	 * recv_auth appearing in all case branches be merged?
	 */

	switch (recv_auth) {
	case IKEv2_AUTH_RSA:
		return v2_authsig_and_log_using_pubkey(POLICY_RSASIG_v1_5,
						       ike, idhash_in,
						       signature_pbs,
						       &ike_alg_hash_sha1,
						       &pubkey_signer_pkcs1_1_5_rsa);

	case IKEv2_AUTH_ECDSA_SHA2_256_P256:
		return v2_authsig_and_log_using_pubkey(POLICY_ECDSA,
						       ike, idhash_in,
						       signature_pbs,
						       &ike_alg_hash_sha2_256,
						       &pubkey_signer_ecdsa/*_p256*/);

	case IKEv2_AUTH_ECDSA_SHA2_384_P384:
		return v2_authsig_and_log_using_pubkey(POLICY_ECDSA,
						       ike, idhash_in,
						       signature_pbs,
						       &ike_alg_hash_sha2_384,
						       &pubkey_signer_ecdsa/*_p384*/);
	case IKEv2_AUTH_ECDSA_SHA2_512_P521:
		return v2_authsig_and_log_using_pubkey(POLICY_ECDSA,
						       ike, idhash_in,
						       signature_pbs,
						       &ike_alg_hash_sha2_512,
						       &pubkey_signer_ecdsa/*_p521*/);

	case IKEv2_AUTH_PSK:
	{
		if (that_authby != AUTHBY_PSK) {
			return diag("authentication failed: peer attempted PSK authentication but we want %s",
				    enum_name(&keyword_authby_names, that_authby));
		}

		diag_t d = v2_authsig_and_log_using_psk(AUTHBY_PSK, ike, idhash_in,
							signature_pbs, NULL/*auth_sig*/);
		if (d != NULL) {
			dbg("authentication failed: PSK AUTH mismatch");
			return d;
		}

		return NULL;
	}

	case IKEv2_AUTH_NULL:
	{
		if (!(that_authby == AUTHBY_NULL ||
		      (that_authby == AUTHBY_RSASIG && LIN(POLICY_AUTH_NULL, ike->sa.st_connection->policy)))) {
			return diag("authentication failed: peer attempted NULL authentication but we want %s",
				    enum_name(&keyword_authby_names, that_authby));
		}

		diag_t d = v2_authsig_and_log_using_psk(AUTHBY_NULL, ike, idhash_in,
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
		if (that_authby != AUTHBY_ECDSA &&
		    that_authby != AUTHBY_RSASIG) {
			return diag("authentication failed: peer attempted authentication through Digital Signature but we want %s",
				    enum_name(&keyword_authby_names, that_authby));
		}

		/* try to match ASN.1 blob designating the hash algorithm */

		shunk_t signature = pbs_in_left_as_shunk(signature_pbs);

		dbg("digsig: looking for matching DIGSIG blob");
		FOR_EACH_ELEMENT(negotiated_hash_map, hash) {

			if ((ike->sa.st_v2_digsig.negotiated_hashes &
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
				lset_t policy;
			} signers[] = {
				{ &pubkey_signer_ecdsa, POLICY_ECDSA, },
				{ &pubkey_signer_rsassa_pss, POLICY_RSASIG, },
				{ &pubkey_signer_pkcs1_1_5_rsa, POLICY_RSASIG_v1_5, }
			};

			FOR_EACH_ELEMENT(signers, s) {
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
				diag_t d = pbs_in_raw(signature_pbs, NULL/*toss*/, blob.len,
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

				return v2_authsig_and_log_using_pubkey(s->policy,
								       ike, idhash_in,
								       signature_pbs,
								       (*hash),
								       s->signer);
			}
		}

		dbg("digsig:   no match");
		return diag("authentication failed: no acceptable ECDSA/RSA-PSS ASN.1 signature hash proposal included for %s",
			    enum_name(&keyword_authby_names, that_authby));

	}
	default:
	{
		enum_buf eb;
		return diag("authentication failed: method %s not supported",
			    str_enum(&ikev2_auth_method_names, recv_auth, &eb));
	}
	}
}
