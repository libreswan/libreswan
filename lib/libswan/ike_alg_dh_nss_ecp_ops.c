/*
 * Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
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

#include <stddef.h>
#include <stdint.h>

#include "nspr.h"
#include "pk11pub.h"
#include "keyhi.h"
/*
 * In addition to EC_POINT_FORM_UNCOMPRESSED, "blapit.h" things like
 * AES_BLOCK_SIZE which conflicts with "ietf_constants.h".
 */
#if 0
#include "blapit.h"
#else
#define EC_POINT_FORM_UNCOMPRESSED 0x04
#endif

#include "constants.h"
#include "lswalloc.h"
#include "lswnss.h"
#include "lswlog.h"

#include "ike_alg.h"
#include "ike_alg_dh_ops.h"
#include "crypt_symkey.h"

static void nss_ecp_calc_local_secret(const struct dh_desc *group,
				      SECKEYPrivateKey **privk,
				      SECKEYPublicKey **pubk,
				      struct logger *logger)
{
	/*
	 * Get the PK11 formatted EC parameters (stored in static
	 * data) from NSS.
	 */
	DBGF(DBG_CRYPT, "oid %d %x", group->nss_oid, group->nss_oid);
	SECOidData *pk11_data = SECOID_FindOIDByTag(group->nss_oid);
	if (pk11_data == NULL) {
		passert_fail(logger, HERE, "lookup of OID %d for EC group %s parameters failed",
			     group->nss_oid, group->common.fqn);
	}
	if (DBGP(DBG_CRYPT)) {
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam_string(buf, "pk11_data->oid: ");
			jam_nss_secitem(buf, &pk11_data->oid);
		}
	}

	/*
	 * Need to prepend the param with its size; for moment assume
	 * the returned value is small.  If it ever gets too big will
	 * need to re-encode the length some how.
	 */
	passert(pk11_data->oid.len < 256);
	SECKEYECParams *pk11_param = SECITEM_AllocItem(NULL, NULL, (2 + pk11_data->oid.len));
	pk11_param->type = siBuffer,
	pk11_param->data[0] = SEC_ASN1_OBJECT_ID;
	pk11_param->data[1] = pk11_data->oid.len;
	memcpy(pk11_param->data + 2, pk11_data->oid.data, pk11_data->oid.len);
	if (DBGP(DBG_CRYPT)) {
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam_string(buf, "pk11_param");
			jam_nss_secitem(buf, pk11_param);
		}
	}

	*privk = SECKEY_CreateECPrivateKey(pk11_param, pubk,
					   lsw_nss_get_password_context(logger));

	SECITEM_FreeItem(pk11_param, PR_TRUE);

	if (*pubk == NULL || *privk == NULL) {
		passert_nss_error(logger, HERE,
				  "DH ECP private key creation failed");
	}

	if (DBGP(DBG_CRYPT)) {
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam(buf, "public keyType %d size %d publicValue@%p %d bytes public key: ",
			    (*pubk)->keyType,
			    (*pubk)->u.ec.size,
			    (*pubk)->u.ec.publicValue.data,
			    (*pubk)->u.ec.publicValue.len);
			jam_nss_secitem(buf, &(*pubk)->u.ec.publicValue);
		}
	}
}

static chunk_t nss_ecp_clone_local_secret_ke(const struct dh_desc *group,
					     const SECKEYPublicKey *local_pubk)
{
#ifdef USE_DH31
	if (group->nss_oid == SEC_OID_CURVE25519) {
		/*
		 * NSS returns the plain EC X-point (see documentation
		 * in pk11_get_EC_PointLenInBytes(), and that is what
		 * needs to go over the wire.
		 */
		passert(local_pubk->u.ec.publicValue.len == group->bytes);
		DBG_log("putting NSS raw CURVE25519 public key blob on wire");
		return clone_bytes_as_chunk(local_pubk->u.ec.publicValue.data, group->bytes, "ECP KE");
	}
#endif
	passert(local_pubk->u.ec.publicValue.data[0] == EC_POINT_FORM_UNCOMPRESSED);
	passert(local_pubk->u.ec.publicValue.len == group->bytes + 1);
	return clone_bytes_as_chunk(local_pubk->u.ec.publicValue.data + 1, group->bytes, "ECP KE");
}

static diag_t nss_ecp_calc_shared_secret(const struct dh_desc *group,
					 SECKEYPrivateKey *local_privk,
					 const SECKEYPublicKey *local_pubk,
					 chunk_t remote_ke,
					 PK11SymKey **shared_secret,
					 struct logger *logger)
{
	SECKEYPublicKey remote_pubk = {
		.keyType = ecKey,
		.u.ec = {
			.DEREncodedParams = local_pubk->u.ec.DEREncodedParams,
#if 0
			/*
			 * NSS, at one point, added the field
			 * .encoding and then removed it.  Building
			 * against one version and executing against
			 * the next will be 'bad'.
			 */
			.encoding = local_pubk->u.ec.encoding,
#endif
		},
	};

	/* Allocate same space for remote key as local key */
	passert(remote_ke.len == group->bytes);
	if (SECITEM_AllocItem(NULL, &remote_pubk.u.ec.publicValue,
			      local_pubk->u.ec.publicValue.len) == NULL) {
		return diag_nss_error("location of ECC public key failed");
	}
	/* must NSS-free remote_pubk.u.ec.publicValue */

#ifdef USE_DH31
	if (group->nss_oid == SEC_OID_CURVE25519) {
		/*
		 * NSS returns and expects the raw EC X-point as the
		 * public part.  The raw remote KE matches this format
		 * (see comments in pk11_get_EC_PointLenInBytes()).
		 */
		passert(remote_ke.len == local_pubk->u.ec.publicValue.len);
		DBG_log("passing raw CURVE25519 public key blob to NSS");
		memcpy(remote_pubk.u.ec.publicValue.data, remote_ke.ptr, remote_ke.len);
	} else {
#endif
		/*
		 * NSS returns and expects the encoded EC X-point as
		 * the public part.  Need to encode the raw remote KE
		 * so it matches (which is easy, just prefix the
		 * uncompressed tag to the raw value).
		 */
		passert(remote_ke.len + 1 == local_pubk->u.ec.publicValue.len);
		remote_pubk.u.ec.publicValue.data[0] = EC_POINT_FORM_UNCOMPRESSED;
		memcpy(remote_pubk.u.ec.publicValue.data + 1, remote_ke.ptr, remote_ke.len);
#ifdef USE_DH31
	}
#endif

	/*
	 * XXX: The "result type" can be nearly everything.  Use
	 * CKM_ECDH1_DERIVE as a marker so it is easy to spot this key
	 * type.
	 *
	 * Like all calls in the NSS source code, leave KDF=CKD_NULL.
	 * The raw key is also what CAVP tests expect.
	 */
	PK11SymKey *temp = PK11_PubDeriveWithKDF(local_privk, &remote_pubk,
						 /* is sender */ PR_FALSE,
						 /* secrets */ NULL, NULL,
						 /* Operation */ CKM_ECDH1_DERIVE,
						 /* result type */ CKM_ECDH1_DERIVE,
						 /* operation */ CKA_DERIVE,
						 /* key size */ 0,
						 /* KDF */ CKD_NULL,
						 /* shared data */ NULL,
						 /* ctx */ lsw_nss_get_password_context(logger));
	if (temp == NULL) {
		*shared_secret = NULL;
		SECITEM_FreeItem(&remote_pubk.u.ec.publicValue, PR_FALSE);
		return diag_nss_error("shared key calculation using ECP failed");
	}

	if (DBGP(DBG_CRYPT)) {
		DBG_symkey(logger, "g_ir ", "temp", temp);
	}

	/*
	 * The key returned above doesn't play well with PK11_Derive()
	 * - "softokn" fails to extract its value when trying to
	 * CKM_CONCATENATE_BASE_AND_KEY - work around this by
	 * returning a copy of the key.
	 */
	*shared_secret = key_from_symkey_bytes(temp, 0, sizeof_symkey(temp), HERE, logger);
	if (DBGP(DBG_BASE)) {
		DBG_symkey(logger, "newref ", "ecp-key", *shared_secret);
	}

	release_symkey(__func__, "temp", &temp);
	SECITEM_FreeItem(&remote_pubk.u.ec.publicValue, PR_FALSE);

	return NULL;
}

static void nss_ecp_check(const struct dh_desc *dhmke, struct logger *logger)
{
	const struct ike_alg *alg = &dhmke->common;
	pexpect_ike_alg(logger, alg, dhmke->nss_oid > 0);
}

const struct dh_ops ike_alg_dh_nss_ecp_ops = {
	.backend = "NSS(ECP)",
	.check = nss_ecp_check,
	.calc_local_secret = nss_ecp_calc_local_secret,
	.clone_local_secret_ke = nss_ecp_clone_local_secret_ke,
	.calc_shared_secret = nss_ecp_calc_shared_secret,
};
