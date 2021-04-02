/* do ECDSA operations for IKEv2
 *
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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
 *
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "secitem.h"
#include "cryptohi.h"
#include "keyhi.h"


#include "sysdep.h"
#include "constants.h"

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
#include "ikev2.h"
#include "server.h"
#include "vendor.h"
#include "keys.h"
#include "secrets.h"
#include "crypt_hash.h"
#include "ietf_constants.h"
#include "asn1.h"
#include "lswnss.h"
#include "ikev2_auth.h"

static authsig_using_pubkey_fn authsig_using_ECDSA_ikev2_pubkey; /* type assert */

bool authsig_using_ECDSA_ikev2_pubkey(const struct crypt_mac *hash, shunk_t signature,
				      struct pubkey *kr,
				      const struct hash_desc *unused_hash_algo UNUSED,
				      diag_t *fatal_diag,
				      struct logger *logger)
{
	PRArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (arena == NULL) {
		*fatal_diag = diag_nss_error("allocating ECDSA arena");
		return false;
	}

	/*
	 * convert K(R) into a public key
	 */

	/* allocate the pubkey */
	const struct ECDSA_public_key *k = &kr->u.ecdsa;
	SECKEYPublicKey *publicKey = (SECKEYPublicKey *)
		PORT_ArenaZAlloc(arena, sizeof(SECKEYPublicKey));
	if (publicKey == NULL) {
		*fatal_diag = diag_nss_error("allocating ECDSA pubkey arena");
		PORT_FreeArena(arena, PR_FALSE);
		return false;
	}

	publicKey->arena = arena;
	publicKey->keyType = ecKey;
	publicKey->pkcs11Slot = NULL;
	publicKey->pkcs11ID = CK_INVALID_HANDLE;

	/*
	 * Copy k and ec params into the arena / publicKey.
	 */

	SECItem k_pub = same_chunk_as_secitem(k->pub, siBuffer);
	if (SECITEM_CopyItem(arena, &publicKey->u.ec.publicValue, &k_pub) != SECSuccess) {
		*fatal_diag = diag_nss_error("copying 'k' to EDSA public key");
		PORT_FreeArena(arena, PR_FALSE);
		return false;
	}

	SECItem k_ecParams = same_chunk_as_secitem(k->ecParams, siBuffer);
	if (SECITEM_CopyItem(arena, &publicKey->u.ec.DEREncodedParams, &k_ecParams) != SECSuccess) {
		*fatal_diag = diag_nss_error("copying ecParams to ECDSA public key");
		PORT_FreeArena(arena, PR_FALSE);
		return false;
	}

	/*
	 * Convert the signature into raw form (NSS doesn't do const).
	 */
	SECItem der_signature = {
		.type = siBuffer,
		.data = DISCARD_CONST(unsigned char *, signature.ptr),/*NSS doesn't do const*/
		.len = signature.len
	};
	LSWDBGP(DBG_BASE, buf) {
		jam(buf, "%d-byte DER encoded ECDSA signature: ",
		    der_signature.len);
		jam_nss_secitem(buf, &der_signature);
	}

	SECItem *raw_signature = DSAU_DecodeDerSigToLen(&der_signature,
							SECKEY_SignatureLen(publicKey));
	if (raw_signature == NULL) {
		/* not fatal as dependent on key being tried */
		log_nss_error(DEBUG_STREAM, logger,
			      "unpacking DER encoded ECDSA signature using DSAU_DecodeDerSigToLen()");
		PORT_FreeArena(arena, PR_FALSE);
		*fatal_diag = NULL;
		return false;
	}

	LSWDBGP(DBG_BASE, buf) {
		jam(buf, "%d-byte raw ESCSA signature: ",
		    raw_signature->len);
		jam_nss_secitem(buf, raw_signature);
	}

	/*
	 * put the hash somewhere writable; so it can later be logged?
	 *
	 * XXX: cast away const?
	 */
	struct crypt_mac hash_data = *hash;
	SECItem hash_item = {
		.type = siBuffer,
		.data = hash_data.ptr,
		.len = hash_data.len,
	};

	if (PK11_Verify(publicKey, raw_signature, &hash_item,
			lsw_nss_get_password_context(logger)) != SECSuccess) {
		log_nss_error(DEBUG_STREAM, logger,
			      "verifying AUTH hash using PK11_Verify() failed:");
		PORT_FreeArena(arena, PR_FALSE);
		SECITEM_FreeItem(raw_signature, PR_TRUE);
		*fatal_diag = NULL;
		return false;
	}

	dbg("NSS: verified signature");
	SECITEM_FreeItem(raw_signature, PR_TRUE);

	*fatal_diag = NULL;
	return true;
}

stf_status v2_authsig_and_log_using_ECDSA_pubkey(struct ike_sa *ike,
						 const struct crypt_mac *idhash,
						 shunk_t signature,
						 const struct hash_desc *hash_algo)
{
	if (hash_algo->common.ikev2_alg_id < 0) {
		return STF_FATAL;
	}

	struct crypt_mac calc_hash = v2_calculate_sighash(ike, idhash, hash_algo,
							  REMOTE_PERSPECTIVE);
	return authsig_and_log_using_pubkey(ike, &calc_hash, signature, hash_algo,
					    &pubkey_type_ecdsa,
					    authsig_using_ECDSA_ikev2_pubkey);
}
