/* do RSA operations for IKEv2
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

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
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
#include "ikev2_auth.h"

static const uint8_t rsa_sha1_der_header[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
	0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};

bool ikev2_calculate_rsa_hash(struct ike_sa *ike,
			      const struct crypt_mac *idhash,
			      pb_stream *a_pbs,
			      chunk_t *no_ppk_auth, /* optional output */
			      const struct hash_desc *hash_algo)
{
	const struct pubkey_type *type = &pubkey_type_rsa;
	statetime_t start = statetime_start(&ike->sa);
	const struct connection *c = ike->sa.st_connection;

	const struct private_key_stuff *pks =
		get_connection_private_key(c, type,
					   ike->sa.st_logger);
	if (pks == NULL) {
		libreswan_log("No %s private key found", type->name);
		return false; /* failure: no key to use */
	}

	/* XXX: merge ikev2_calculate_{rsa,ecdsa}_hash()? */
	const struct RSA_private_key *k = &pks->u.RSA_private_key;
	unsigned int sz = k->pub.k;

	struct crypt_mac hash = v2_calculate_sighash(ike, idhash, hash_algo,
						     LOCAL_PERSPECTIVE);

	/*
	 * Allocate large enough space for any digest.  Bound could be
	 * tightened because the signature octets are only
	 * concatenated to a SHA1.
	 */
	unsigned char signed_octets[sizeof(rsa_sha1_der_header) + sizeof(hash.ptr/*array*/)];
	size_t signed_len;

	switch (hash_algo->common.ikev2_alg_id) {
	case IKEv2_HASH_ALGORITHM_SHA1:
		/* old style RSA with SHA1 */
		memcpy(signed_octets, &rsa_sha1_der_header, sizeof(rsa_sha1_der_header));
		memcpy(signed_octets + sizeof(rsa_sha1_der_header), hash.ptr, hash.len);
		signed_len = sizeof(rsa_sha1_der_header) + hash.len;
		break;
	case IKEv2_HASH_ALGORITHM_SHA2_256:
	case IKEv2_HASH_ALGORITHM_SHA2_384:
	case IKEv2_HASH_ALGORITHM_SHA2_512:
		passert(hash.len <= sizeof(signed_octets));
		memcpy(signed_octets, hash.ptr, hash.len);
		signed_len = hash.len;
		break;
	default:
		bad_case(hash_algo->common.ikev2_alg_id);
	}

	passert(RSA_MIN_OCTETS <= sz && 4 + signed_len < sz &&
		sz <= RSA_MAX_OCTETS);

	DBG(DBG_CRYPT,
	    DBG_dump("v2rsa octets", signed_octets, signed_len));

	{
		/* now generate signature blob */
		statetime_t sign_time = statetime_start(&ike->sa);
		struct hash_signature sig;
		passert(sizeof(sig.ptr/*array*/) >= RSA_MAX_OCTETS);
		sig = pubkey_type_rsa.sign_hash(pks, signed_octets, signed_len,
						hash_algo, ike->sa.st_logger);
		statetime_stop(&sign_time, "%s() calling sign_hash_RSA()", __func__);
		if (sig.len == 0)
			return false;

		passert(sig.len == sz);
		if (no_ppk_auth != NULL) {
			*no_ppk_auth = clone_hunk(sig, "NO_PPK_AUTH chunk");
			DBG(DBG_PRIVATE, DBG_dump_hunk("NO_PPK_AUTH payload", *no_ppk_auth));
		} else {
			if (!pbs_out_hunk(sig, a_pbs, "rsa signature"))
				return FALSE;
		}
	}

	statetime_stop(&start, "%s()", __func__);
	return TRUE;
}

static try_signature_fn try_RSA_signature_v2; /* type assertion */

static err_t try_RSA_signature_v2(const struct crypt_mac *hash,
				  const pb_stream *sig_pbs, struct pubkey *kr,
				  struct state *st,
				  const struct hash_desc *hash_algo)
{
	const u_char *sig_val = sig_pbs->cur;
	size_t sig_len = pbs_left(sig_pbs);
	const struct RSA_public_key *k = &kr->u.rsa;

	if (k == NULL)
		return "1" "no key available"; /* failure: no key to use */

	/* decrypt the signature -- reversing RSA_sign_hash */
	if (sig_len != k->k) {
		loglog(RC_LOG_SERIOUS, "sig length %zu does not match pubkey length %d", sig_len, k->k);
		return "1" "SIG length does not match public key length";
	}

	err_t ugh = RSA_signature_verify_nss(k, hash, sig_val, sig_len,
					     hash_algo);
	if (ugh != NULL)
		return ugh;

	unreference_key(&st->st_peer_pubkey);
	st->st_peer_pubkey = reference_key(kr);

	return NULL;
}

stf_status ikev2_verify_rsa_hash(struct ike_sa *ike,
				 const struct crypt_mac *idhash,
				 pb_stream *sig_pbs,
				 const struct hash_desc *hash_algo)
{
	statetime_t start = statetime_start(&ike->sa);
	size_t sig_len = pbs_left(sig_pbs);

	/* XXX: table lookup? */
	if (hash_algo->common.ikev2_alg_id < 0) {
		loglog(RC_LOG_SERIOUS, "unknown or unsupported hash algorithm");
		return STF_INTERNAL_ERROR;
	}

	if (sig_len ==0) {
		loglog(RC_LOG_SERIOUS, "rejecting received zero-length RSA signature");
		return STF_FATAL;
	}

	struct crypt_mac hash = v2_calculate_sighash(ike, idhash, hash_algo,
						     REMOTE_PERSPECTIVE);
	stf_status retstat = check_signature_gen(&ike->sa, &hash, sig_pbs, hash_algo,
						 &pubkey_type_rsa, try_RSA_signature_v2);
	statetime_stop(&start, "%s()", __func__);
	return retstat;
}
