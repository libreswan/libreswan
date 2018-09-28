/* do ECDSA operations for IKEv2
 *
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2018 Paul Wouters <pwouters@redhat.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "secitem.h"
#include "cryptohi.h"
#include "keyhi.h"

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "cookie.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "crypto.h"
#include "ike_alg.h"
#include "ike_alg_hash.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */
#include "pluto_crypt.h"  /* for pluto_crypto_req & pluto_crypto_req_cont */
#include "ikev2.h"
#include "server.h"
#include "vendor.h"
#include "keys.h"
#include "secrets.h"
#include "crypt_hash.h"
#include "ietf_constants.h"
#include "asn1.h"
#include "lswnss.h"

/*
 * XXX: isn't this function identical to that used by RSA?  And why
 * not pass in the hash_desc?
 */

static bool ECDSA_calculate_sighash(const struct state *st,
				    enum original_role role,
				    const unsigned char *idhash,
				    const chunk_t firstpacket,
				    unsigned char *sig_octets,
				    enum notify_payload_hash_algorithms hash_algo)
{
	const chunk_t *nonce;
	const char *nonce_name;

	if (role == ORIGINAL_INITIATOR) {
		/* on initiator, we need to hash responders nonce */
		nonce = &st->st_nr;
		nonce_name = "inputs to hash2 (responder nonce)";
	} else {
		nonce = &st->st_ni;
		nonce_name = "inputs to hash2 (initiator nonce)";
	}

	DBG(DBG_CRYPT,
	    DBG_dump_chunk("inputs to hash1 (first packet)", firstpacket);
	    DBG_dump_chunk(nonce_name, *nonce);
	    DBG_dump("idhash", idhash, st->st_oakley.ta_prf->prf_output_size));

	const struct hash_desc *hd;

	switch (hash_algo) {
#ifdef USE_SHA1
	/*
	 * While ecdsa-sha1 is defined in RFC 4724, should we support it for IKEv2?
	 * It is not listed in RFC 8247, meaning it is only a MAY to be implemented
	 */
	case IKEv2_AUTH_HASH_SHA1:
		hd = &ike_alg_hash_sha1;
		break;
#endif
#ifdef USE_SHA2
	case IKEv2_AUTH_HASH_SHA2_256:
		hd = &ike_alg_hash_sha2_256;
		break;
	case IKEv2_AUTH_HASH_SHA2_384:
		hd = &ike_alg_hash_sha2_384;
		break;
	case IKEv2_AUTH_HASH_SHA2_512:
		hd = &ike_alg_hash_sha2_512;
		break;
#endif
	default:
		return FALSE;
	}

	struct crypt_hash *ctx = crypt_hash_init(hd, "sighash", DBG_CRYPT);

	crypt_hash_digest_chunk(ctx, "first packet", firstpacket);
	crypt_hash_digest_chunk(ctx, "nonce", *nonce);

	/* we took the PRF(SK_d,ID[ir]'), so length is prf hash length */
	crypt_hash_digest_bytes(ctx, "IDHASH", idhash,
				st->st_oakley.ta_prf->prf_output_size);

	crypt_hash_final_bytes(&ctx, sig_octets, hd->hash_digest_size);

	return TRUE;
}

bool ikev2_calculate_ecdsa_hash(struct state *st,
			      enum original_role role,
			      unsigned char *idhash,
			      pb_stream *a_pbs,
			      bool calc_no_ppk_auth,
			      chunk_t *no_ppk_auth,
			      enum notify_payload_hash_algorithms hash_algo)
{
	const struct connection *c = st->st_connection;
	const struct ECDSA_private_key *k = get_ECDSA_private_key(c);
	if (k == NULL) {
		DBGF(DBG_CRYPT, "no ECDSA key for connection");
		return false; /* failure: no key to use */
	}

	DBGF(DBG_CRYPT, "ikev2_calculate_ecdsa_hash get_ECDSA_private_key");
	/* XXX: use struct hash_desc and a lookup? */
	unsigned int hash_digest_size;
 	switch (hash_algo) {
#ifdef USE_SHA2
	case IKEv2_AUTH_HASH_SHA2_256:
		hash_digest_size = SHA2_256_DIGEST_SIZE;
		break;
	case IKEv2_AUTH_HASH_SHA2_384:
		hash_digest_size = SHA2_384_DIGEST_SIZE;
		break;
	case IKEv2_AUTH_HASH_SHA2_512:
		hash_digest_size = SHA2_512_DIGEST_SIZE;
		break;
#endif
	default:
		libreswan_log("Unknown or unsupported hash algorithm %d for ECDSA operation", hash_algo);
		return FALSE;
	}

	/* hash the packet et.al. */
	uint8_t *hash = alloc_bytes(hash_digest_size, "signed octets size");
	ECDSA_calculate_sighash(st, role, idhash,
				st->st_firstpacket_me,
				hash, hash_algo);
	DBG(DBG_CRYPT, DBG_dump("ECDSA hash", hash, hash_digest_size));

	/*
	 * Sign the hash.
	 *
	 * XXX: See https://tools.ietf.org/html/rfc4754#section-7 for
	 * where 1056 is comming from should be constant in struct
	 * hash_desc.
	 */
	uint8_t sig_val[BYTES_FOR_BITS(1056)];
	size_t shr = sign_hash_ECDSA(k, hash, hash_digest_size,
				     sig_val, sizeof(sig_val), hash_algo);
	if (shr == 0) {
		DBGF(DBG_CRYPT, "sign_hash_ECDSA failed\n");
		pfree(hash);
		return false;
	}

	if (calc_no_ppk_auth) {
		clonetochunk(*no_ppk_auth, sig_val, shr, "NO_PPK_AUTH chunk");
		DBG(DBG_PRIVATE, DBG_dump_chunk("NO_PPK_AUTH payload", *no_ppk_auth));
		pfree(hash);
		return true;
	}

	SECItem der_signature;
	SECItem raw_signature = {
		.type = siBuffer,
		.data = sig_val,
		.len = shr,
	};
	if (DSAU_EncodeDerSigWithLen(&der_signature, &raw_signature,
				     raw_signature.len) != SECSuccess) {
		pfree(hash);
		LSWLOG(buf) {
			lswlogs(buf, "NSS: constructing DER encoded ECDSA signature using DSAU_EncodeDerSigWithLen() failed:");
			lswlog_nss_error(buf);
		}
		return false;
	}

	LSWDBGP(DBG_CONTROL, buf) {
		lswlogf(buf, "%d-byte DER encoded ECDSA signature: ", der_signature.len);
		lswlog_nss_secitem(buf, &der_signature);
	}

	if (!out_raw(der_signature.data, der_signature.len, a_pbs, "ecdsa signature")) {

		SECITEM_FreeItem(&der_signature, PR_FALSE);
		pfree(hash);
		return FALSE;
	}

	SECITEM_FreeItem(&der_signature, PR_FALSE);
	pfree(hash);

	return TRUE;
}

static err_t try_ECDSA_signature_v2(const u_char hash_val[MAX_DIGEST_LEN],
				    size_t hash_len,
				    const pb_stream *sig_pbs, struct pubkey *kr,
				    struct state *st,
				    enum notify_payload_hash_algorithms hash_algo UNUSED)
{
	PRArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (arena == NULL) {
		LSWLOG(buf) {
			lswlogs(buf, "NSS: allocating ECDSA arena using PORT_NewArena() failed: ");
			lswlog_nss_error(buf);
		}
		return "10" "NSS error: Not enough memory to create arena";
	}

	/*
	 * convert K(R) into a public key
	 */

	/* allocate the pubkey */
	const struct ECDSA_public_key *k = &kr->u.ecdsa;
	SECKEYPublicKey *publicKey = (SECKEYPublicKey *)
		PORT_ArenaZAlloc(arena, sizeof(SECKEYPublicKey));
	if (publicKey == NULL) {
		PORT_FreeArena(arena, PR_FALSE);
		LSWLOG(buf) {
			lswlogs(buf, "NSS: allocating ECDSA public key using PORT_ArenaZAlloc() failed:");
			lswlog_nss_error(buf);
		}
		return "11" "NSS error: Not enough memory to create publicKey";
	}
	publicKey->arena = arena;
	publicKey->keyType = ecKey;
	publicKey->pkcs11Slot = NULL;
	publicKey->pkcs11ID = CK_INVALID_HANDLE;

	/* copy k's public key value into the arena / publicKey */
	SECItem k_pub = same_chunk_as_secitem(k->pub, siBuffer);
	if (SECITEM_CopyItem(arena, &publicKey->u.ec.publicValue, &k_pub) != SECSuccess) {
		LSWLOG(buf) {
			lswlogs(buf, "NSS: constructing ECDSA public value using SECITEM_CopyItem() failed:");
			lswlog_nss_error(buf);
		}
		PORT_FreeArena(arena, PR_FALSE);
		return "10" "NSS error: copy failed";
	}

	/* construct the EC Parameters */
	SECItem k_ecParams = same_chunk_as_secitem(k->ecParams, siBuffer);
	if (SECITEM_CopyItem(arena,
			     &publicKey->u.ec.DEREncodedParams,
			     &k_ecParams) != SECSuccess) {
		LSWLOG(buf) {
			lswlogs(buf, "NSS: construction of ecParams using SECITEM_CopyItem() failed:");
			lswlog_nss_error(buf);
		}
		PORT_FreeArena(arena, PR_FALSE);
		return "1" "NSS error: Not able to copy modulus or exponent or both while forming SECKEYPublicKey structure";
	}


	/*
	 * Convert the signature into raw form
	 */
	SECItem der_signature = {
		.type = siBuffer,
		.data = sig_pbs->cur,
		.len = pbs_left(sig_pbs),
	};
	LSWDBGP(DBG_CONTROL, buf) {
		lswlogf(buf, "%d-byte DER encoded ECDSA signature: ",
			der_signature.len);
		lswlog_nss_secitem(buf, &der_signature);
	}
	SECItem *raw_signature = DSAU_DecodeDerSigToLen(&der_signature,
							SECKEY_SignatureLen(publicKey));
	if (raw_signature == NULL) {
		LSWLOG(buf) {
			lswlogs(buf, "NSS: unpacking DER encoded ECDSA signature using DSAU_DecodeDerSigToLen() failed:");
			lswlog_nss_error(buf);
		}
		PORT_FreeArena(arena, PR_FALSE);
		return "1" "Decode failed";
	}
	LSWDBGP(DBG_CONTROL, buf) {
		lswlogf(buf, "%d-byte raw ESCSA signature: ",
			raw_signature->len);
		lswlog_nss_secitem(buf, raw_signature);
	}

	/*
	 * put the hash somewhere writable; so it can later be logged?
	 */
	SECItem hash = {
		.type = siBuffer,
		.data = PORT_ArenaZAlloc(arena, hash_len),
		.len = hash_len,
	};
	memcpy(hash.data, hash_val, hash_len);

	if (PK11_Verify(publicKey, raw_signature, &hash,
			lsw_return_nss_password_file_info()) != SECSuccess) {
		LSWLOG(buf) {
			lswlogs(buf, "NSS: verifying AUTH hash using PK11_Verify() failed:");
			lswlog_nss_error(buf);
		}
		PORT_FreeArena(arena, PR_FALSE);
		SECITEM_FreeItem(raw_signature, PR_TRUE);
		return "1" "NSS error: Not able to verify";
	}

	DBGF(DBG_CONTROL, "NSS: verified signature");

	SECITEM_FreeItem(raw_signature, PR_TRUE);
	unreference_key(&st->st_peer_pubkey);
	st->st_peer_pubkey = reference_key(kr);

	return NULL;
}

stf_status ikev2_verify_ecdsa_hash(struct state *st,
				 enum original_role role,
				 const unsigned char *idhash,
				 pb_stream *sig_pbs,
				 enum notify_payload_hash_algorithms hash_algo)
{
	unsigned int hash_len;
	stf_status retstat;
	enum original_role invertrole;

	switch (hash_algo) {
	/* We don't suppor tecdsa-sha1 */
#ifdef USE_SHA2
	case IKEv2_AUTH_HASH_SHA2_256:
		hash_len = SHA2_256_DIGEST_SIZE;
		break;
	case IKEv2_AUTH_HASH_SHA2_384:
		hash_len = SHA2_384_DIGEST_SIZE;
		break;
	case IKEv2_AUTH_HASH_SHA2_512:
		hash_len = SHA2_512_DIGEST_SIZE;
		break;
#endif
	default:
		return STF_FATAL;
	}

	unsigned char *calc_hash = alloc_bytes(hash_len, "hash size");

	invertrole = (role == ORIGINAL_INITIATOR ? ORIGINAL_RESPONDER : ORIGINAL_INITIATOR);

	if (!ECDSA_calculate_sighash(st, invertrole, idhash, st->st_firstpacket_him,
				calc_hash, hash_algo)) {
		return STF_FATAL;
	}

	retstat = ECDSA_check_signature_gen(st, calc_hash, hash_len,
					  sig_pbs, hash_algo, try_ECDSA_signature_v2);
	pfree(calc_hash);
	return retstat;
}
