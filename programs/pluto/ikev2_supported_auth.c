/* IKEv2 SUPPORTED_AUTH_METHODS notification, for libreswan
 *
 * Copyright (C) 2026   Osema Fadhel <osemafadhel01@gmail.com>
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
 */

#include "defs.h"

#include "ike_alg_hash.h"
#include "ikev2_supported_auth.h"
#include "ikev2_notification.h"
#include "state.h"
#include "connections.h"
#include "log.h"

bool emit_v2N_SUPPORTED_AUTH_METHODS(const struct ike_sa *ike,
					       struct pbs_out *outs) 
{
	struct authby authby = ike->sa.st_connection->remote->host.config->authby;

	v2_notification_t ntype = v2N_SUPPORTED_AUTH_METHODS;

	if (impair.omit_v2_notification.enabled &&
		impair.omit_v2_notification.value == ntype) {
		name_buf eb;
		llog(IMPAIR_STREAM, outs->logger, "omitting %s notification",
			str_enum_short(&v2_notification_names, ntype, &eb));
		return true;
	}

	struct pbs_out n_pbs;

	if (!open_v2N_output_pbs(outs, ntype, &n_pbs)) {
		llog(RC_LOG, outs->logger, "error initializing notify payload for notify message");
		return false;
	}

	/* --- 2-octet announcements --- 
	 *
	 *	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *	|  Length (=2)  |  Auth Method  |
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 */

	if (authby.psk) {
		uint8_t ann2[2] = { TWO_OCTET_ANNOUNCEMENT_LENGTH, 
					IKEv2_AUTH_SHARED_KEY_MAC };
		if (!pbs_out_raw(&n_pbs, ann2, sizeof(ann2) , 
				"SUPPORTED_AUTH_METHODS 'PSK' announced")) {
			return false;
		}
	}

	if (authby.null) {
		uint8_t ann2[2] = { TWO_OCTET_ANNOUNCEMENT_LENGTH, IKEv2_AUTH_NULL };
		if (!pbs_out_raw(&n_pbs, ann2, sizeof(ann2), 
				"SUPPORTED_AUTH_METHODS 'NULL' announced")) {
			return false;
		}
	}

	/* --- 3-octet announcements --- 
	 *						 1                   2
	 *	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *	|  Length (=3)  |  Auth Method  |   Cert Link   |
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 */

	if (authby.rsasig_v1_5) {
		uint8_t ann3[3] = { THREE_OCTET_ANNOUNCEMENT_LENGTH, 
					IKEv2_AUTH_RSA_DIGITAL_SIGNATURE, 0 /* cert link */ };
		if (!pbs_out_raw(&n_pbs, ann3, sizeof(ann3), 
				"SUPPORTED_AUTH_METHODS 'RSASSA-PKCS1-v1_5' announced")) {
			return false;
		}
	}

	if (authby.ecdsa_sha2_256) {
		uint8_t ann3[3] = { THREE_OCTET_ANNOUNCEMENT_LENGTH, 
					IKEv2_AUTH_ECDSA_SHA2_256_P256, 0 /* cert link */ };
		if (!pbs_out_raw(&n_pbs, ann3, sizeof(ann3), 
				"SUPPORTED_AUTH_METHODS 'ECDSA-SHA2-256-P256' announced")) {
			return false;
		}
	}

	if (authby.ecdsa_sha2_384) {
		uint8_t ann3[3] = { THREE_OCTET_ANNOUNCEMENT_LENGTH, 
					IKEv2_AUTH_ECDSA_SHA2_384_P384, 0 /* cert link */ };
		if (!pbs_out_raw(&n_pbs, ann3, sizeof(ann3), 
				"SUPPORTED_AUTH_METHODS 'ECDSA_SHA2_384_P384' announced")) {
			return false;
		}
	}

	if (authby.ecdsa_sha2_512) {
		uint8_t ann3[3] = { THREE_OCTET_ANNOUNCEMENT_LENGTH, 
					IKEv2_AUTH_ECDSA_SHA2_512_P521, 0 /* cert link */ };
		if (!pbs_out_raw(&n_pbs, ann3, sizeof(ann3), 
				"SUPPORTED_AUTH_METHODS 'ECDSA_SHA2_512_P521' announced")) {
			return false;
		}
	}

	/* --- multi-octet announcements ---
	 *						1                   2                   3
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |  Length (>3)  |  Auth Method  |   Cert Link   |               |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
	 * |                                                               |
	 * ~                      AlgorithmIdentifier                      ~
	 * |                                                               |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 */

#define EMIT_DIGSIG(AUTH, HASH, BLOB, NAME)												\
	{																					\
		if (authby.AUTH) {																\
			shunk_t b = (HASH)->digital_signature_blob[BLOB];							\
			if (b.len > 0) {															\
				/* +1/-1 skips the first byte, which contains the size of the blob */	\
				shunk_t algid = shunk2(b.ptr + 1, b.len - 1);							\
				uint8_t hdr[3] = { 														\
					(uint8_t)(THREE_OCTET_ANNOUNCEMENT_LENGTH + algid.len),				\
						IKEv2_AUTH_DIGITAL_SIGNATURE, 0 /* cert link */ };				\
				if (!pbs_out_raw(&n_pbs, hdr, sizeof(hdr),								\
						"SUPPORTED_AUTH_METHODS '"NAME"' announced")) {					\
					return false;														\
				}																		\
				if (!pbs_out_hunk(&n_pbs, algid, "AlgorithmIdentifier '"NAME"'")) {		\
					return false;														\
				}																		\
			}																			\
		}																				\
	}																					

	EMIT_DIGSIG(rsasig_sha2_512, &ike_alg_hash_sha2_512, 
			DIGITAL_SIGNATURE_RSASSA_PSS_BLOB, "RSASSA-PSS-SHA2-512");
	EMIT_DIGSIG(rsasig_sha2_384, &ike_alg_hash_sha2_384, 
			DIGITAL_SIGNATURE_RSASSA_PSS_BLOB, "RSASSA-PSS-SHA2-384");
	EMIT_DIGSIG(rsasig_sha2_256, &ike_alg_hash_sha2_256, 
			DIGITAL_SIGNATURE_RSASSA_PSS_BLOB, "RSASSA-PSS-SHA2-256");
	EMIT_DIGSIG(ecdsa_sha2_512, &ike_alg_hash_sha2_512, 
			DIGITAL_SIGNATURE_ECDSA_BLOB, "ECDSA-SHA2-512");
	EMIT_DIGSIG(ecdsa_sha2_384, &ike_alg_hash_sha2_384, 
			DIGITAL_SIGNATURE_ECDSA_BLOB, "ECDSA-SHA2-384");
	EMIT_DIGSIG(ecdsa_sha2_256, &ike_alg_hash_sha2_256, 
			DIGITAL_SIGNATURE_ECDSA_BLOB, "ECDSA-SHA2-256");
	EMIT_DIGSIG(eddsa, &ike_alg_hash_identity, 
			DIGITAL_SIGNATURE_EDDSA_IDENTITY_ED25519_BLOB, "EDDSA-ED25519");
	EMIT_DIGSIG(eddsa, &ike_alg_hash_identity, 
			DIGITAL_SIGNATURE_EDDSA_IDENTITY_ED448_BLOB, "EDDSA-ED448");
#undef EMIT_DIGSIG

	close_pbs_out(&n_pbs);
	return true;
}
