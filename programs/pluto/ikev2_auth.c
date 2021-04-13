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
#include "keys.h"
#include "secrets.h"
#include "ikev2_message.h"
#include "ikev2.h"
#include "keys.h"
#include "ikev2_psk.h"

static const uint8_t rsa_sha1_der_header[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
	0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};

struct crypt_mac v2_calculate_sighash(const struct ike_sa *ike,
				      const struct crypt_mac *idhash,
				      const struct hash_desc *hasher,
				      enum perspective from_the_perspective_of)
{
	enum sa_role role;
	chunk_t firstpacket;
	/*
	 * NOTE: intermediate_auth is only initialized to quiet GCC.
	 * It doesn't understand that all uses and references are
	 * guarded identically, with ike->sa.st_intermediate_used.
	 * Using a local copy ike->sa.st_intermediate_used doesn't help.
	 * DHR 2020 Sept 12; GCC 10.2.1
	 */
	chunk_t ia1 = NULL_HUNK;
	chunk_t ia2 = NULL_HUNK;
	switch (from_the_perspective_of) {
	case LOCAL_PERSPECTIVE:
		firstpacket = ike->sa.st_firstpacket_me;
		role = ike->sa.st_sa_role;
		if (ike->sa.st_intermediate_used) {
			ia1 = ike->sa.st_intermediate_packet_me;
			ia2 = ike->sa.st_intermediate_packet_peer;
		}
		break;
	case REMOTE_PERSPECTIVE:
		firstpacket = ike->sa.st_firstpacket_peer;
		role = (ike->sa.st_sa_role == SA_INITIATOR ? SA_RESPONDER :
			ike->sa.st_sa_role == SA_RESPONDER ? SA_INITIATOR :
			0);
		if (ike->sa.st_intermediate_used) {
			ia1 = ike->sa.st_intermediate_packet_peer;
			ia2 = ike->sa.st_intermediate_packet_me;
		}
		break;
	default:
		bad_case(from_the_perspective_of);
	}

	const chunk_t *nonce;
	const char *nonce_name;
	switch (role) {
	case SA_INITIATOR:
		/* on initiator, we need to hash responders nonce */
		nonce = &ike->sa.st_nr;
		nonce_name = "inputs to hash2 (responder nonce)";
		break;
	case SA_RESPONDER:
		/* on responder, we need to hash initiators nonce */
		nonce = &ike->sa.st_ni;
		nonce_name = "inputs to hash2 (initiator nonce)";
		break;
	default:
		bad_case(from_the_perspective_of);
	}

	if (DBGP(DBG_CRYPT)) {
		DBG_dump_hunk("inputs to hash1 (first packet)", firstpacket);
		DBG_dump_hunk(nonce_name, *nonce);
		DBG_dump_hunk("idhash", *idhash);
		if (ike->sa.st_intermediate_used) {
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
	if (ike->sa.st_intermediate_used) {
		crypt_hash_digest_hunk(ctx, "IntAuth_*_I_A", ia1);
		crypt_hash_digest_hunk(ctx, "IntAuth_*_R_A", ia2);
	}
	return crypt_hash_final_mac(&ctx);
}

enum keyword_authby v2_auth_by(struct ike_sa *ike)
{
	const struct connection *c = ike->sa.st_connection;
	enum keyword_authby authby = c->spd.this.authby;
	if (ike->sa.st_peer_wants_null) {
		/* we allow authby=null and IDr payload told us to use it */
		authby = AUTHBY_NULL;
	} else if (authby == AUTHBY_UNSET) {
		/*
		 * Asymmetric policy unset.
		 * Pick up from symmetric policy, in order of preference!
		 */
		if ((c->policy & POLICY_ECDSA) && (c->sighash_policy != LEMPTY)) {
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
			if (c->sighash_policy != LEMPTY) {
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
		return hash_algo->hash_asn1_blob_rsa;
	case AUTHBY_ECDSA:
		return hash_algo->hash_asn1_blob_ecdsa;
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

struct hash_signature v2_auth_signature(struct logger *logger,
					const struct crypt_mac *hash_to_sign,
					const struct hash_desc *hash_algo,
					enum ikev2_auth_method auth_method,
					const struct private_key_stuff *pks)
{
	passert(hash_to_sign->len <= sizeof(hash_to_sign->ptr/*array*/)); /*hint to coverity*/
	logtime_t start = logtime_start(logger);

	/*
	 * Allocate large enough space for any digest.
	 * Bound could be tightened because the signature octets are
	 * only concatenated to a SHA1 hash.
	 */
	uint8_t hash_octets[sizeof(rsa_sha1_der_header) + sizeof(hash_to_sign->ptr/*an array*/)];
	size_t hash_len;

	switch (auth_method) {

	case IKEv2_AUTH_RSA:
		/* old style RSA with SHA1 */
		passert(hash_algo == &ike_alg_hash_sha1);
		memcpy(hash_octets, &rsa_sha1_der_header,
		       sizeof(rsa_sha1_der_header));
		memcpy(hash_octets + sizeof(rsa_sha1_der_header),
		       hash_to_sign->ptr, hash_to_sign->len);
		hash_len = sizeof(rsa_sha1_der_header) + hash_to_sign->len;
		break;

	case IKEv2_AUTH_DIGSIG:
		hash_len = hash_to_sign->len;
		passert(hash_len <= sizeof(hash_octets));
		memcpy(hash_octets, hash_to_sign->ptr, hash_to_sign->len);
		break;

	default:
		bad_case(auth_method);
	}

	if (DBGP(DBG_BASE)) {
		DBG_dump("hash to sign", hash_octets, hash_len);
	}

	logtime_t sign_time = logtime_start(logger);
	struct hash_signature sig = pks->pubkey_type->sign_hash(pks,
								hash_octets,
								hash_len,
								hash_algo,
								logger);
	logtime_stop(&sign_time, "%s() calling sign_hash()", __func__);
	passert(sig.len <= sizeof(sig.ptr/*array*/));
	logtime_stop(&start, "%s()", __func__);
	return sig;
}

bool emit_v2_auth(struct ike_sa *ike,
		  const struct hash_signature *auth_sig,
		  const struct crypt_mac *id_payload_mac,
		  struct pbs_out *outs)
{
	enum keyword_authby authby = v2_auth_by(ike);

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
		if (!ikev2_emit_psk_auth(authby, ike, id_payload_mac, &a_pbs)) {
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

/* check for ASN.1 blob; if found, consume it */
static bool ikev2_try_asn1_hash_blob(const struct hash_desc *hash_algo,
				     pb_stream *a_pbs,
				     enum keyword_authby authby)
{
	shunk_t b = authby_asn1_hash_blob(hash_algo, authby);

	uint8_t in_blob[ASN1_LEN_ALGO_IDENTIFIER +
		PMAX(ASN1_SHA1_ECDSA_SIZE,
			PMAX(ASN1_SHA2_RSA_PSS_SIZE, ASN1_SHA2_ECDSA_SIZE))];
	dbg("looking for ASN.1 blob for method %s for hash_algo %s",
	    enum_name(&keyword_authby_names, authby), hash_algo->common.fqn);
	return
		pexpect(b.ptr != NULL) &&	/* we know this hash */
		pbs_left(a_pbs) >= b.len && /* the stream has enough octets */
		memeq(a_pbs->cur, b.ptr, b.len) && /* they are the right octets */
		pexpect(b.len <= sizeof(in_blob)) && /* enough space in in_blob[] */
		pexpect(pbs_in_raw(a_pbs, in_blob, b.len, "ASN.1 blob for hash algo") == NULL); /* can eat octets */
}

/*
 * Called by ikev2_in_IKE_AUTH_I_out_IKE_AUTH_R_tail() and
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

bool v2_authsig_and_log(enum ikev2_auth_method recv_auth,
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
			log_state(RC_LOG_SERIOUS, &ike->sa,
				  "authentication failed: peer attempted RSA authentication but we want %s",
				  enum_name(&keyword_authby_names, that_authby));
			return false;
		}

		shunk_t signature = pbs_in_left_as_shunk(signature_pbs);
		stf_status authstat = v2_authsig_and_log_using_RSA_pubkey(ike, idhash_in,
									  signature,
									  &ike_alg_hash_sha1);
		if (authstat != STF_OK) {
			return false;
		}

		return true;
	}

	case IKEv2_AUTH_PSK:
	{
		if (that_authby != AUTHBY_PSK) {
			log_state(RC_LOG_SERIOUS, &ike->sa,
				  "authentication failed: peer attempted PSK authentication but we want %s",
				  enum_name(&keyword_authby_names, that_authby));
			return false;
		}

		if (!v2_authsig_and_log_using_psk(AUTHBY_PSK, ike, idhash_in, signature_pbs)) {
			dbg("authentication failed: PSK AUTH mismatch");
			return false;
		}
		return TRUE;
	}

	case IKEv2_AUTH_NULL:
	{
		if (!(that_authby == AUTHBY_NULL ||
		      (that_authby == AUTHBY_RSASIG && LIN(POLICY_AUTH_NULL, ike->sa.st_connection->policy)))) {
			log_state(RC_LOG, &ike->sa,
				  "authentication failed: peer attempted NULL authentication but we want %s",
				  enum_name(&keyword_authby_names, that_authby));
			return false;
		}

		if (!v2_authsig_and_log_using_psk(AUTHBY_NULL, ike, idhash_in, signature_pbs)) {
			dbg("authentication failed: NULL AUTH mismatch (implementation bug?)");
			return false;
		}

		ike->sa.st_ikev2_anon = true;
		return true;
	}

	case IKEv2_AUTH_DIGSIG:
	{
		if (that_authby != AUTHBY_ECDSA && that_authby != AUTHBY_RSASIG) {
			log_state(RC_LOG_SERIOUS, &ike->sa,
				  "authentication failed: peer attempted authentication through Digital Signature but we want %s",
				  enum_name(&keyword_authby_names, that_authby));
			return false;
		}

		/* try to match ASN.1 blob designating the hash algorithm */

		lset_t hn = ike->sa.st_hash_negotiated;

		struct hash_alts {
			lset_t neg;
			const struct hash_desc *algo;
		};

		static const struct hash_alts ha[] = {
			{ NEGOTIATE_AUTH_HASH_SHA2_512, &ike_alg_hash_sha2_512 },
			{ NEGOTIATE_AUTH_HASH_SHA2_384, &ike_alg_hash_sha2_384 },
			{ NEGOTIATE_AUTH_HASH_SHA2_256, &ike_alg_hash_sha2_256 },
			/* { NEGOTIATE_AUTH_HASH_IDENTITY, IKEv2_HASH_ALGORITHM_IDENTITY }, */
		};

		const struct hash_alts *hap;

		for (hap = ha; ; hap++) {
			if (hap == &ha[elemsof(ha)]) {
				log_state(RC_LOG_SERIOUS, &ike->sa,
					  "authentication failed: no acceptable ECDSA/RSA-PSS ASN.1 signature hash proposal included for %s",
					  enum_name(&keyword_authby_names, that_authby));
				if (DBGP(DBG_BASE)) {
					size_t dl = min(pbs_left(signature_pbs),
							(size_t) (ASN1_LEN_ALGO_IDENTIFIER +
								  PMAX(ASN1_SHA1_ECDSA_SIZE,
								       PMAX(ASN1_SHA2_RSA_PSS_SIZE,
									    ASN1_SHA2_ECDSA_SIZE))));
					DBG_dump("offered blob", signature_pbs->cur, dl);
				}
				return false;	/* none recognized */
			}

			if ((hn & hap->neg) && ikev2_try_asn1_hash_blob(hap->algo, signature_pbs, that_authby))
				break;

			dbg("st_hash_negotiated policy does not match hash algorithm %s",
			    hap->algo->common.fqn);
		}

		/* try to match the hash */
		stf_status authstat;

		shunk_t signature = pbs_in_left_as_shunk(signature_pbs);
		switch (that_authby) {
		case AUTHBY_RSASIG:
			authstat = v2_authsig_and_log_using_RSA_pubkey(ike, idhash_in,
								       signature,
								       hap->algo);
			break;

		case AUTHBY_ECDSA:
			authstat = v2_authsig_and_log_using_ECDSA_pubkey(ike, idhash_in,
									 signature,
									 hap->algo);
			break;

		default:
			bad_case(that_authby);
		}

		if (authstat != STF_OK) {
			return false;
		}

		return true;
	}

	default:
		log_state(RC_LOG_SERIOUS, &ike->sa,
			  "authentication failed: method %s not supported",
			  enum_name(&ikev2_auth_names, recv_auth));
		return false;
	}
}
