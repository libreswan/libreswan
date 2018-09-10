/* do ECDSA operations for IKEv2
 *
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2018 Paul Wouters <pwouters@redhat.com>
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

	/*
	 * Per https://tools.ietf.org/html/rfc3279#section-2.2.2
	 * convert R:S to the DER:
	 *
	 * Dss-Sig-Value  ::=  SEQUENCE  {
         *     r       INTEGER,
         *     s       INTEGER
	 * }
	 *
	 * Since R and S are unsigned the most significant bit of the
	 * most significant byte of the encoded value can never be 1.
	 * Hence, if the raw R or S value has its MSB 1, a leading
	 * zero must be added.
	 *
	 * A 1056 bit R:S is larger than 127 (but less than 256) so
	 * need to allow for a 2-byte "long form" length octet.  See
	 * http://luca.ntop.org/Teaching/Appunti/asn1.html
	 *
	 * XXX: hand generating DER isn't right.  Is there a library?
	 * Because of length octet encoding it really needs to be
	 * two-pass or built backard.
	 */
	const size_t point_size = shr / 2;
	const size_t max_der_size = (1+2 /* SEQUENCE:size */
				     + (1+2 /* INTEGER:size */
					+ 1 /* possible leading zero */
					+ point_size) * 2 /* R and S */);
	uint8_t *der_encoded_sig_val = alloc_things(uint8_t, max_der_size,
						    "der encoded signature");
	DBGF(DBG_CRYPT, "Converting ECDSA signature length %zu point size %zu to DER",
	     shr, point_size);

	/* SEQUENCE */
	uint8_t *derp = der_encoded_sig_val;
	*derp++ = ASN1_SEQUENCE;
	/* length octets */
	uint8_t *sequence_size; /* save for updates */
	passert(shr < 256);
	if (shr > 127) {
		/* >127 is a heuristic */
		*derp++ = 0x81;
		sequence_size = derp;
		*derp++ = 0;
	} else {
		sequence_size = derp;
		*derp++ = 0;
	}
	/* R and S */
	for (int p = 0; p < 2; p++) {
		uint8_t *point = sig_val + p*point_size;
		size_t size = point_size;
		DBG(DBG_CRYPT,
		    const char *name = (p == 0 ? "R" : "S");
		    DBG_dump(name, point, size));
		/* strip leading zeros */
		while (size > 1 && *point == 0) {
			point++;
			size--;
		}
		/* INTEGER: size */
		*derp++ = ASN1_INTEGER;
		if (*point >= 0x80) {
			/* add leading 0 */
			*derp++ = size + 1;
			*derp++ = 0;
		} else {
			*derp++ = size;
		}
		/* value */
		memcpy(derp, point, size);
		derp += size;
	}
	passert(derp - sequence_size - 1 < 256);
	*sequence_size = derp - sequence_size - 1;
	size_t der_size = derp - der_encoded_sig_val;

	DBG(DBG_CRYPT,
	    DBG_log("ECDSA signature encoded as a %zu byte DER ...", der_size);
	    DBG_dump("ECDSA DER:", der_encoded_sig_val, der_size));

	if (!out_raw(der_encoded_sig_val, der_size, a_pbs, "ecdsa signature")) {
		pfree(der_encoded_sig_val);
		pfree(hash);
		return FALSE;
	}

	pfree(der_encoded_sig_val);
	pfree(hash);

	return TRUE;
}

static err_t try_ECDSA_signature_v2(const u_char hash_val[MAX_DIGEST_LEN],
				  size_t hash_len,
				  const pb_stream *sig_pbs, struct pubkey *kr,
				  struct state *st,
				  enum notify_payload_hash_algorithms hash_algo)
{
	u_char *sig_val = sig_pbs->cur;
	size_t sig_len = pbs_left(sig_pbs);
	const struct ECDSA_public_key *k = &kr->u.ecdsa;
	chunk_t sig_val_chunk;

	DBG(DBG_CRYPT, DBG_log("sig_length is %zu",sig_len));
	DBG(DBG_CRYPT, DBG_log("key_length is %d",k->k));
	sig_val_chunk.ptr = sig_val;
	sig_val_chunk.len = sig_len;
	chunk_t sig_val_der_decoded;
	is_asn1_der_encoded_signature(sig_val_chunk, &sig_val_der_decoded);

	if (k == NULL)
		return "1" "no key available"; /* failure: no key to use */

	/* decrypt the signature */
/*	if (sig_len != k->k)
		return "1" "SIG length does not match public key length";*/
	DBG_dump("sig_val",sig_val,sig_len);
	DBG_dump("sig_val_new",sig_val_der_decoded.ptr,sig_val_der_decoded.len);
	
	err_t ugh = ECDSA_signature_verify_nss(k, hash_val, hash_len, sig_val_der_decoded.ptr,
					     sig_val_der_decoded.len, hash_algo);
	if (ugh != NULL)
		return ugh;

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
