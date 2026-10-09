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

	static const struct auth_method {
		const char *story;
		enum {
			NO_OCTET = 1,
			TWO_OCTET,
			THREE_OCTET,
			MULTI_OCTET,
		} kind;
		enum ikev2_auth_method method;
		const struct hash_desc *hash;
		enum digital_signature_blob blob;
	} auth_methods[AUTH_ROOF] = {
		/*ignore these*/
		[AUTH_NEVER].kind = NO_OCTET,
		[AUTH_EAPONLY].kind = NO_OCTET,
		/*real*/
		[AUTH_PSK] = {
			"SUPPORTED_AUTH_METHODS 'PSK' announced",
			TWO_OCTET,
			IKEv2_AUTH_SHARED_KEY_MAC,
		},
		[AUTH_NULL] = {
			"SUPPORTED_AUTH_METHODS 'NULL' announced",
			TWO_OCTET,
			IKEv2_AUTH_NULL,
		},

		[AUTH_RSASIG_V1_5_SHA1_RAW] = {
			"SUPPORTED_AUTH_METHODS 'RSASSA-PKCS1-v1_5' announced",
			THREE_OCTET,
			IKEv2_AUTH_RSA_DIGITAL_SIGNATURE,
		},

		[AUTH_ECDSA_SHA2_256_RAW] = {
			"SUPPORTED_AUTH_METHODS 'ECDSA-SHA2-256-P256' announced",
			THREE_OCTET,
			IKEv2_AUTH_ECDSA_SHA2_256_P256,
		},
		[AUTH_ECDSA_SHA2_384_RAW] = {
			"SUPPORTED_AUTH_METHODS 'ECDSA_SHA2_384_P384' announced",
			THREE_OCTET,
			IKEv2_AUTH_ECDSA_SHA2_384_P384,
		},
		[AUTH_ECDSA_SHA2_512_RAW] = {
			"SUPPORTED_AUTH_METHODS 'ECDSA_SHA2_512_P521' announced",
			THREE_OCTET,
			IKEv2_AUTH_ECDSA_SHA2_512_P521,
		},

		[AUTH_RSASIG_SHA2_512] = {
			"RSASSA-PSS-SHA2-512",
			MULTI_OCTET,
			IKEv2_AUTH_DIGITAL_SIGNATURE,
			&ike_alg_hash_sha2_512,
			DIGITAL_SIGNATURE_RSASSA_PSS_BLOB,
		},
		[AUTH_RSASIG_SHA2_384] = {
			"RSASSA-PSS-SHA2-384",
			MULTI_OCTET,
			IKEv2_AUTH_DIGITAL_SIGNATURE,
			&ike_alg_hash_sha2_384,
			DIGITAL_SIGNATURE_RSASSA_PSS_BLOB,
		},
		[AUTH_RSASIG_SHA2_256] = {
			"RSASSA-PSS-SHA2-256",
			MULTI_OCTET,
			IKEv2_AUTH_DIGITAL_SIGNATURE,
			&ike_alg_hash_sha2_256,
			DIGITAL_SIGNATURE_RSASSA_PSS_BLOB,
		},

		[AUTH_ECDSA_SHA2_512_BLOB] = {
			"ECDSA-SHA2-512",
			MULTI_OCTET,
			IKEv2_AUTH_DIGITAL_SIGNATURE,
			&ike_alg_hash_sha2_512,
			DIGITAL_SIGNATURE_ECDSA_BLOB,
		},
		[AUTH_ECDSA_SHA2_384_BLOB] = {
			"ECDSA-SHA2-384",
			MULTI_OCTET,
			IKEv2_AUTH_DIGITAL_SIGNATURE,
			&ike_alg_hash_sha2_384,
			DIGITAL_SIGNATURE_ECDSA_BLOB,
		},
		[AUTH_ECDSA_SHA2_256_BLOB] = {
			"ECDSA-SHA2-256",
			MULTI_OCTET,
			IKEv2_AUTH_DIGITAL_SIGNATURE,
			&ike_alg_hash_sha2_256,
			DIGITAL_SIGNATURE_ECDSA_BLOB,
		},
		[AUTH_EDDSA] = {
			"EDDSA-ED25519",
			MULTI_OCTET,
			IKEv2_AUTH_DIGITAL_SIGNATURE,
			&ike_alg_hash_identity,
			DIGITAL_SIGNATURE_EDDSA_IDENTITY_ED25519_BLOB,
		},
#if 0
		[AUTH_EDDSA] = {
			"EDDSA-ED448",
			MULTI_OCTET,
			IKEv2_AUTH_DIGITAL_SIGNATURE,
			&ike_alg_hash_identity,
			DIGITAL_SIGNATURE_EDDSA_IDENTITY_ED448_BLOB,
		},
#endif
	};

	for (enum auth auth = AUTH_FLOOR; auth < AUTH_ROOF; auth++) {
		if (authby.authby[auth]) {
			const struct auth_method *method = &auth_methods[auth];
			switch (method->kind) {
			case NO_OCTET:
			{
				/* ignore these */
				continue;
			}
			case TWO_OCTET:
			{
				/* --- 2-octet announcements ---
				 *
				 *	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
				 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *	|  Length (=2)  |  Auth Method  |
				 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *
				 */
				uint8_t ann2[TWO_OCTET_ANNOUNCEMENT_LENGTH] = {
					TWO_OCTET_ANNOUNCEMENT_LENGTH,
					method->method,
				};
				if (!pbs_out_raw(&n_pbs, ann2, sizeof(ann2),
						 method->story)) {
					return false;
				}
				continue;
			}
			case THREE_OCTET:
			{
				/* --- 3-octet announcements ---
				 *						 1                   2
				 *	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
				 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *	|  Length (=3)  |  Auth Method  |   Cert Link   |
				 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 *
				 */
				uint8_t ann3[THREE_OCTET_ANNOUNCEMENT_LENGTH] = {
					THREE_OCTET_ANNOUNCEMENT_LENGTH,
					method->method,
					0 /* cert link */
				};
				if (!pbs_out_raw(&n_pbs, ann3, sizeof(ann3),
						 method->story)) {
					return false;
				}
				continue;
			}
			case MULTI_OCTET:
			{
				if (PBAD(outs->logger, method->hash == NULL)) {
					continue;
				}

				shunk_t b = method->hash->digital_signature_blob[method->blob];
				if (PBAD(outs->logger, b.len == 0)) {
					continue;
				}

				/* +1/-1 skips the first byte, which contains the size of the blob */
				shunk_t algid = shunk_slice(b, 1, b.len);
				uint8_t hdr[THREE_OCTET_ANNOUNCEMENT_LENGTH] = {
					(uint8_t)(THREE_OCTET_ANNOUNCEMENT_LENGTH + algid.len),
					IKEv2_AUTH_DIGITAL_SIGNATURE,
					0, /* cert link */
				};
				if (!pbs_out_raw(&n_pbs, hdr, sizeof(hdr),
						 method->story)) {
					return false;
				}
				if (!pbs_out_hunk(&n_pbs, algid,
						  method->story)) {
					return false;
				}
				continue;
			}
			default:
			{
				name_buf ab;
				llog_pexpect(outs->logger, HERE,
					     "unhandled auth method %s",
					     str_name_short(&auth_names, auth, &ab));
				continue;
			}
			}
		}
	}

	close_pbs_out(&n_pbs);
	return true;
}

bool process_v2N_SUPPORTED_AUTH_METHODS(struct ike_sa *ike,
					const struct pbs_in *notify_pbs)
{
	struct authby peer = {0};
	struct pbs_in input_pbs = *notify_pbs;
	diag_t d;

	while (pbs_left(&input_pbs) > 0) {
		uint8_t length;
		uint8_t auth_method;

		d = pbs_in_thing(&input_pbs, length, "SUPPORTED_AUTH_METHODS announcement length");
		if (d != NULL) {
			llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
			pfree_diag(&d);
			return false;
		}

		d = pbs_in_thing(&input_pbs, auth_method, "SUPPORTED_AUTH_METHODS auth method");
		if (d != NULL) {
			llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
			pfree_diag(&d);
			return false;
		}

		if (length == TWO_OCTET_ANNOUNCEMENT_LENGTH) {
			switch (auth_method) {
			case IKEv2_AUTH_SHARED_KEY_MAC:
				peer.authby_psk = true;
				break;
			case IKEv2_AUTH_NULL:
				peer.authby_null = true;
				break;
			default:
				ldbg(ike->sa.logger,
					"SUPPORTED_AUTH_METHODS ignoring unknown auth method %d in %d-octet announcement",
					auth_method, length);
				break;
			}
		} else if (length == THREE_OCTET_ANNOUNCEMENT_LENGTH) {
			uint8_t cert_link;

			d = pbs_in_thing(&input_pbs, cert_link, "SUPPORTED_AUTH_METHODS Cert Link");
			if (d != NULL) {
				llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
				pfree_diag(&d);
				return false;
			}

			switch (auth_method) {
			case IKEv2_AUTH_RSA_DIGITAL_SIGNATURE:
				peer.authby_rsasig_v1_5_sha1_raw = true;
				break;
			case IKEv2_AUTH_ECDSA_SHA2_256_P256:
				peer.authby_ecdsa_sha2_256_raw = true;
				break;
			case IKEv2_AUTH_ECDSA_SHA2_384_P384:
				peer.authby_ecdsa_sha2_384_raw = true;
				break;
			case IKEv2_AUTH_ECDSA_SHA2_512_P521:
				peer.authby_ecdsa_sha2_512_raw = true;
				break;
			default:
				ldbg(ike->sa.logger,
					"SUPPORTED_AUTH_METHODS ignoring unknown auth method %d in %d-octet announcement",
					auth_method, length);
				break;
			}
		} else if (length > THREE_OCTET_ANNOUNCEMENT_LENGTH && 
				auth_method == IKEv2_AUTH_DIGITAL_SIGNATURE) {
			uint8_t cert_link;
			d = pbs_in_thing(&input_pbs, cert_link, "SUPPORTED_AUTH_METHODS Cert Link");
			if (d != NULL) {
				llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
				pfree_diag(&d);
				return false;
			}
			shunk_t algid;
			d = pbs_in_shunk(&input_pbs, length - 3, &algid, "AlgorithmIdentifier");
			if (d != NULL) {
				llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
				pfree_diag(&d);
				return false;
			}

			bool matched = false;

#define MATCH_DIGSIG(AUTH, HASH, BLOB)										\
			{																\
				if (!matched) {												\
					shunk_t b = (HASH)->digital_signature_blob[BLOB];		\
					if (b.len > 0) {										\
						/*
						 * +1/-1 skips the first byte, which contains 		
						 * the size of the blob
						 */													\
						shunk_t known = shunk2(b.ptr + 1, b.len - 1);		\
						if (hunk_eq(algid, known)) {						\
							peer.AUTH = true;								\
							matched = true;									\
						}													\
					}														\
				}															\
			}																					

			MATCH_DIGSIG(authby_rsasig_sha2_512, &ike_alg_hash_sha2_512,
					DIGITAL_SIGNATURE_RSASSA_PSS_BLOB);
			MATCH_DIGSIG(authby_rsasig_sha2_384, &ike_alg_hash_sha2_384,
					DIGITAL_SIGNATURE_RSASSA_PSS_BLOB);
			MATCH_DIGSIG(authby_rsasig_sha2_256, &ike_alg_hash_sha2_256,
					DIGITAL_SIGNATURE_RSASSA_PSS_BLOB);
			MATCH_DIGSIG(authby_ecdsa_sha2_512_blob, &ike_alg_hash_sha2_512,
					DIGITAL_SIGNATURE_ECDSA_BLOB);
			MATCH_DIGSIG(authby_ecdsa_sha2_384_blob, &ike_alg_hash_sha2_384,
					DIGITAL_SIGNATURE_ECDSA_BLOB);
			MATCH_DIGSIG(authby_ecdsa_sha2_256_blob, &ike_alg_hash_sha2_256,
					DIGITAL_SIGNATURE_ECDSA_BLOB);
			MATCH_DIGSIG(authby_eddsa, &ike_alg_hash_identity,
					DIGITAL_SIGNATURE_EDDSA_IDENTITY_ED25519_BLOB);
			MATCH_DIGSIG(authby_eddsa, &ike_alg_hash_identity,
					DIGITAL_SIGNATURE_EDDSA_IDENTITY_ED448_BLOB);
#undef MATCH_DIGSIG
		} else {
			shunk_t skip_bytes;

			d = pbs_in_shunk(&input_pbs, length - 2, &skip_bytes,
					"Unknown SUPPORTED_AUTH_METHODS Announcement");
			if (d != NULL) {
				llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
				pfree_diag(&d);
				return false;
			}
	
			ldbg(ike->sa.logger,
					"SUPPORTED_AUTH_METHODS ignoring unknown announcement");
		}
	}

	ike->sa.st_v2_peer_authby = peer;

	return true;
}
