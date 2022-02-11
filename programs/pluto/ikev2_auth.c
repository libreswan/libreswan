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

const struct pubkey_signer *v2_auth_digsig_pubkey_signer(enum keyword_authby authby)
{
	switch (authby) {
	case AUTHBY_RSASIG:
		return &pubkey_signer_rsassa_pss;
	case AUTHBY_ECDSA:
		return &pubkey_signer_ecdsa;
	default:
		bad_case(authby);
	}
}

enum ikev2_auth_method v2_auth_method(struct ike_sa *ike, enum keyword_authby authby)
{
	struct connection *c = ike->sa.st_connection;
	enum ikev2_auth_method auth_method;
	switch (authby) {
	case AUTHBY_RSASIG:
	{
		bool allow_legacy = LIN(POLICY_RSASIG_v1_5, c->policy);

		if (!ike->sa.st_seen_hashnotify) {
			if (allow_legacy) {
				auth_method = IKEv2_AUTH_RSA;
			} else {
				log_state(RC_LOG_SERIOUS, &ike->sa,
					  "legacy RSA-SHA1 is not allowed but peer supports nothing else");
				auth_method = IKEv2_AUTH_RESERVED;
			}
		} else {
			if (c->config->sighash_policy != LEMPTY) {
				auth_method = IKEv2_AUTH_DIGSIG;
			} else {
				if (allow_legacy) {
					auth_method = IKEv2_AUTH_RSA;
				} else {
					log_state(RC_LOG_SERIOUS, &ike->sa,
						  "Local policy does not allow legacy RSA-SHA1 but connection allows no other hash policy");
					auth_method = IKEv2_AUTH_RESERVED;

				}
			}
		}
		break;
	}
	case AUTHBY_ECDSA:
		auth_method = IKEv2_AUTH_DIGSIG;
		break;
	case AUTHBY_PSK:
		auth_method = IKEv2_AUTH_PSK;
		break;
	case AUTHBY_NULL:
		auth_method = IKEv2_AUTH_NULL;
		break;
	case AUTHBY_NEVER:
	default:
		bad_case(authby);
	}
	return auth_method;
}

const struct hash_desc *v2_auth_negotiated_signature_hash(struct ike_sa *ike)
{
	const struct hash_desc *hash_algo;
	/* RFC 8420 IDENTITY algo not supported yet */
	if (ike->sa.st_hash_negotiated & NEGOTIATE_AUTH_HASH_SHA2_512) {
		hash_algo = &ike_alg_hash_sha2_512;
		dbg("emit hash algo NEGOTIATE_AUTH_HASH_SHA2_512");
	} else if (ike->sa.st_hash_negotiated & NEGOTIATE_AUTH_HASH_SHA2_384) {
		hash_algo = &ike_alg_hash_sha2_384;
		dbg("emit hash algo NEGOTIATE_AUTH_HASH_SHA2_384");
	} else if (ike->sa.st_hash_negotiated & NEGOTIATE_AUTH_HASH_SHA2_256) {
		hash_algo = &ike_alg_hash_sha2_256;
		dbg("emit hash algo NEGOTIATE_AUTH_HASH_SHA2_256");
	} else {
		hash_algo = NULL;
		dbg("DigSig: no compatible DigSig hash algo");
	}
	return hash_algo;
}

shunk_t authby_asn1_hash_blob(const struct hash_desc *hash_algo,
			      enum keyword_authby authby)
{
	switch(authby) {
	case AUTHBY_RSASIG:
		return hash_algo->digital_signature_blob[DIGITAL_SIGNATURE_RSASSA_PSS_BLOB];
	case AUTHBY_ECDSA:
		return hash_algo->digital_signature_blob[DIGITAL_SIGNATURE_ECDSA_BLOB];
	default:
		return null_shunk;
	}
}

bool emit_v2_asn1_hash_blob(const struct hash_desc *hash_algo,
			    struct pbs_out *outs, enum keyword_authby authby)
{
	shunk_t b = authby_asn1_hash_blob(hash_algo, authby);
	if (!pexpect(b.len > 0)) {
		return false;
	}

	if (!out_hunk(b, outs, "OID of ASN.1 Algorithm Identifier")) {
		llog(RC_LOG_SERIOUS, outs->outs_logger,
		     "DigSig: failed to emit OID of ASN.1 Algorithm Identifier");
		return false;
	}
	return true;
}

bool emit_v2_auth(struct ike_sa *ike,
		  const struct hash_signature *auth_sig,
		  const struct crypt_mac *id_payload_mac,
		  struct pbs_out *outs)
{
	enum keyword_authby authby = ike->sa.st_eap_sa_md ? IKEv2_AUTH_PSK : v2_auth_by(ike);

	struct ikev2_auth a = {
		.isaa_critical = build_ikev2_critical(false, ike->sa.st_logger),
		.isaa_auth_method = v2_auth_method(ike, authby),
	};

	pb_stream a_pbs;
	if (!out_struct(&a, &ikev2_auth_desc, outs, &a_pbs)) {
		return false;
	}

	switch (a.isaa_auth_method) {
	case IKEv2_AUTH_RSA:
		if (!out_hunk(*auth_sig, &a_pbs, "signature")) {
			return false;
		}
		break;

	case IKEv2_AUTH_DIGSIG:
	{
		const struct hash_desc *hash_algo = v2_auth_negotiated_signature_hash(ike);
		if (!emit_v2_asn1_hash_blob(hash_algo, &a_pbs, authby) ||
		    !out_hunk(*auth_sig, &a_pbs, "signature")) {
			return false;
		}
		break;
	}

	case IKEv2_AUTH_PSK:
	case IKEv2_AUTH_NULL:
		/* emit */
		if (!ikev2_emit_psk_auth(authby, ike, id_payload_mac, &a_pbs,
					 chunk2((void*) auth_sig->ptr, auth_sig->len))) {
			llog(RC_LOG_SERIOUS, outs->outs_logger, "Failed to find our PreShared Key");
			return false;
		}
		break;

	default:
		bad_case(a.isaa_auth_method);
	}
	close_output_pbs(&a_pbs);
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

static diag_t v2_authsig_and_log_using_pubkey(struct ike_sa *ike,
					      const struct crypt_mac *idhash,
					      shunk_t signature,
					      const struct hash_desc *hash_algo,
					      const struct pubkey_signer *pubkey_signer)
{
	statetime_t start = statetime_start(&ike->sa);

	/* XXX: table lookup? */
	if (hash_algo->common.ikev2_alg_id < 0) {
		return diag("authentication failed: unknown or unsupported hash algorithm");
	}

	if (signature.len == 0) {
		return diag("authentication failed: rejecting received zero-length RSA signature");
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
	{
		if (that_authby != AUTHBY_RSASIG) {
			return diag("authentication failed: peer attempted RSA authentication but we want %s",
				    enum_name(&keyword_authby_names, that_authby));
		}

		shunk_t signature = pbs_in_left_as_shunk(signature_pbs);
		diag_t d = v2_authsig_and_log_using_pubkey(ike, idhash_in, signature,
							   &ike_alg_hash_sha1,
							   &pubkey_signer_pkcs1_1_5_rsa);
		if (d != NULL) {
			return d;
		}

		return NULL;
	}

	case IKEv2_AUTH_PSK:
	{
		if (that_authby != AUTHBY_PSK) {
			return diag("authentication failed: peer attempted PSK authentication but we want %s",
				    enum_name(&keyword_authby_names, that_authby));
		}

		diag_t d = v2_authsig_and_log_using_psk(AUTHBY_PSK, ike, idhash_in, signature_pbs, EMPTY_CHUNK);
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

		diag_t d = v2_authsig_and_log_using_psk(AUTHBY_NULL, ike, idhash_in, signature_pbs, EMPTY_CHUNK);
		if (d != NULL) {
			dbg("authentication failed: NULL AUTH mismatch (implementation bug?)");
			return d;
		}

		ike->sa.st_ikev2_anon = true;
		return NULL;
	}

	case IKEv2_AUTH_DIGSIG:
	{
		if (that_authby != AUTHBY_ECDSA && that_authby != AUTHBY_RSASIG) {
			return diag("authentication failed: peer attempted authentication through Digital Signature but we want %s",
				    enum_name(&keyword_authby_names, that_authby));
		}

		/* try to match ASN.1 blob designating the hash algorithm */

		struct hash_alts {
			lset_t neg;
			const struct hash_desc *algo;
		};

		static const struct hash_alts hash_alts[] = {
			{ NEGOTIATE_AUTH_HASH_SHA2_512, &ike_alg_hash_sha2_512 },
			{ NEGOTIATE_AUTH_HASH_SHA2_384, &ike_alg_hash_sha2_384 },
			{ NEGOTIATE_AUTH_HASH_SHA2_256, &ike_alg_hash_sha2_256 },
			/* { NEGOTIATE_AUTH_HASH_IDENTITY, IKEv2_HASH_ALGORITHM_IDENTITY }, */
		};

		shunk_t signature = pbs_in_left_as_shunk(signature_pbs);
		shunk_t blob;
		const struct pubkey_signer *pubkey_signer;

		const struct hash_alts *hap = NULL;
		FOR_EACH_ELEMENT(hash_alts, hash_alt) {
			if (!(hash_alt->neg & ike->sa.st_hash_negotiated)) {
				continue;
			}
			switch(that_authby) {
			case AUTHBY_RSASIG:
				blob = hash_alt->algo->digital_signature_blob[DIGITAL_SIGNATURE_RSASSA_PSS_BLOB];
				pubkey_signer = &pubkey_signer_rsassa_pss;
				break;
			case AUTHBY_ECDSA:
				blob = hash_alt->algo->digital_signature_blob[DIGITAL_SIGNATURE_ECDSA_BLOB];
				pubkey_signer = &pubkey_signer_ecdsa;
				break;
			default:
				bad_case(that_authby);
			}
			if (blob.len == 0) {
				continue;
			}
			if (!hunk_starteq(signature, blob)) {
				dbg("st_hash_negotiated policy does not match hash algorithm %s",
				    hash_alt->algo->common.fqn);
				continue;
			};
			hap = hash_alt;
			break;
		}

		if (hap == NULL) {
			return diag("authentication failed: no acceptable ECDSA/RSA-PSS ASN.1 signature hash proposal included for %s",
				    enum_name(&keyword_authby_names, that_authby));
		}

		/* eat the blob */
		diag_t d = pbs_in_raw(signature_pbs, NULL/*toss*/, blob.len,
				      "skip ASN.1 blob for hash algo");
		if (d != NULL) {
			return d;
		}

		dbg("verifying signature using %s", pubkey_signer->name);
		return v2_authsig_and_log_using_pubkey(ike, idhash_in,
						       pbs_in_left_as_shunk(signature_pbs),
						       hap->algo, pubkey_signer);
	}
	default:
		return diag("authentication failed: method %s not supported",
			    enum_name(&ikev2_auth_names, recv_auth));
	}
}
