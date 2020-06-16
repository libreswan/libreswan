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
	default: bad_case(from_the_perspective_of);
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
	}

	struct crypt_hash *ctx = crypt_hash_init("sighash", hasher);
	crypt_hash_digest_hunk(ctx, "first packet", firstpacket);
	crypt_hash_digest_hunk(ctx, "nonce", *nonce);
	/* we took the PRF(SK_d,ID[ir]'), so length is prf hash length */
	passert(idhash->len == ike->sa.st_oakley.ta_prf->prf_output_size);
	crypt_hash_digest_hunk(ctx, "IDHASH", *idhash);
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
				loglog(RC_LOG_SERIOUS, "legacy RSA-SHA1 is not allowed but peer supports nothing else");
				auth_method = IKEv2_AUTH_RESERVED;
			}
		} else {
			if (c->sighash_policy != LEMPTY) {
				auth_method = IKEv2_AUTH_DIGSIG;
			} else {
				if (allow_legacy) {
					auth_method = IKEv2_AUTH_RSA;
				} else {
					loglog(RC_LOG_SERIOUS, "Local policy does not allow legacy RSA-SHA1 but connection allows no other hash policy");
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
		libreswan_log("Unknown or unsupported authby method for DigSig");
		return null_shunk;
	}
}

bool emit_v2_asn1_hash_blob(const struct hash_desc *hash_algo,
			    pb_stream *a_pbs, enum keyword_authby authby)
{
	shunk_t b = authby_asn1_hash_blob(hash_algo, authby);
	if (!pexpect(b.len > 0)) {
		/* already logged */
		return false;
	}

	if (!pbs_out_hunk(b, a_pbs,
			  "OID of ASN.1 Algorithm Identifier")) {
		loglog(RC_LOG_SERIOUS, "DigSig: failed to emit OID of ASN.1 Algorithm Identifier");
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
		  pb_stream *outpbs)
{
	enum keyword_authby authby = v2_auth_by(ike);

	struct ikev2_auth a = {
		.isaa_critical = build_ikev2_critical(false),
		.isaa_auth_method = v2_auth_method(ike, authby),
	};

	pb_stream a_pbs;
	if (!out_struct(&a, &ikev2_auth_desc, outpbs, &a_pbs)) {
		return false;
	}

	switch (a.isaa_auth_method) {
	case IKEv2_AUTH_RSA:
		if (!pbs_out_hunk(*auth_sig, &a_pbs, "signature")) {
			return false;
		}
		break;

	case IKEv2_AUTH_DIGSIG:
	{
		const struct hash_desc *hash_algo = v2_auth_negotiated_signature_hash(ike);
		if (!emit_v2_asn1_hash_blob(hash_algo, &a_pbs, authby) ||
		    !pbs_out_hunk(*auth_sig, &a_pbs, "signature")) {
			return false;
		}
		break;
	}

	case IKEv2_AUTH_PSK:
	case IKEv2_AUTH_NULL:
		/* emit */
		if (!ikev2_emit_psk_auth(authby, ike, id_payload_mac, &a_pbs)) {
			loglog(RC_LOG_SERIOUS, "Failed to find our PreShared Key");
			return false;
		}
		break;

	default:
		bad_case(a.isaa_auth_method);
	}
	close_output_pbs(&a_pbs);
	return true;
}
