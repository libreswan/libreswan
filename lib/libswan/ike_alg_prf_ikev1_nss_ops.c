/*
 * Calculate IKEv1 prf and keying material, for libreswan
 *
 * Copyright (C) 2007 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2015-2020 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2020 Paul Wouters <pwouters@redhat.com>
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

#include "ike_alg.h"
#include "ike_alg_prf_ikev1_ops.h"
#include "crypt_symkey.h"
#include "lswlog.h"

/*
 * Compute: SKEYID = prf(Ni_b | Nr_b, g^xy)
 *
 * MUST BE THREAD-SAFE
 */
static PK11SymKey *signature_skeyid(const struct prf_desc *prf_desc,
				    const chunk_t Ni,
				    const chunk_t Nr,
				    /*const*/ PK11SymKey *dh_secret /* NSS doesn't do const */,
				    struct logger *logger)
{
	CK_NSS_IKE_PRF_DERIVE_PARAMS ike_prf_params = {
		.prfMechanism = prf_desc->nss.mechanism,
		.bDataAsKey = CK_TRUE,
		.bRekey = CK_FALSE,
		.pNi = Ni.ptr,
		.ulNiLen = Ni.len,
		.pNr = Nr.ptr,
		.ulNrLen = Nr.len,
	};
	SECItem params = {
		.data = (unsigned char *)&ike_prf_params,
		.len = sizeof(ike_prf_params),
	};

	return crypt_derive(dh_secret, CKM_NSS_IKE_PRF_DERIVE, &params,
			    "skeyid", CKM_NSS_IKE1_PRF_DERIVE, CKA_DERIVE,
			    /*key,flags*/ 0, 0,
			    HERE, logger);
}

/*
 * Compute: SKEYID = prf(pre-shared-key, Ni_b | Nr_b)
 */
static PK11SymKey *pre_shared_key_skeyid(const struct prf_desc *prf_desc,
					 chunk_t pre_shared_key,
					 chunk_t Ni, chunk_t Nr,
					 struct logger *logger)
{
	PK11SymKey *psk = prf_key_from_hunk("psk", prf_desc, pre_shared_key, logger);
	PK11SymKey *skeyid;
	if (psk == NULL) {
		return NULL;
	}

	CK_NSS_IKE_PRF_DERIVE_PARAMS ike_prf_params = {
		.prfMechanism = prf_desc->nss.mechanism,
		.bDataAsKey = CK_FALSE,
		.bRekey = CK_FALSE,
		.pNi = Ni.ptr,
		.ulNiLen = Ni.len,
		.pNr = Nr.ptr,
		.ulNrLen = Nr.len,
	};
	SECItem params = {
		.data = (unsigned char *)&ike_prf_params,
		.len = sizeof(ike_prf_params),
	};

	skeyid = crypt_derive(psk, CKM_NSS_IKE_PRF_DERIVE, &params,
			      "skeyid", CKM_NSS_IKE1_PRF_DERIVE, CKA_DERIVE,
			      /*key_size*/0, /*flags*/0,
			      HERE, logger);
	release_symkey("SKEYID psk", "psk", &psk);
	return skeyid;
}

/*
 * SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0)
 */
static PK11SymKey *skeyid_d(const struct prf_desc *prf_desc,
			    PK11SymKey *skeyid,
			    PK11SymKey *dh_secret,
			    chunk_t cky_i, chunk_t cky_r,
			    struct logger *logger)
{
	CK_NSS_IKE1_PRF_DERIVE_PARAMS ike1_prf_params = {
		.prfMechanism = prf_desc->nss.mechanism,
		.bHasPrevKey = CK_FALSE,
		.hKeygxy = PK11_GetSymKeyHandle(dh_secret),
		.pCKYi = cky_i.ptr,
		.ulCKYiLen = cky_i.len,
		.pCKYr = cky_r.ptr,
		.ulCKYrLen = cky_r.len,
		.keyNumber = 0,
	};
	SECItem params = {
		.data = (unsigned char *)&ike1_prf_params,
		.len = sizeof(ike1_prf_params),
	};

	return crypt_derive(skeyid, CKM_NSS_IKE1_PRF_DERIVE, &params,
			    "skeyid_d", CKM_EXTRACT_KEY_FROM_KEY, CKA_DERIVE,
			    /*key-size*/0, /*flags*/0,
			    HERE, logger);
}

/*
 * SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1)
 */
static PK11SymKey *skeyid_a(const struct prf_desc *prf_desc,
			    PK11SymKey *skeyid,
			    PK11SymKey *skeyid_d, PK11SymKey *dh_secret,
			    chunk_t cky_i, chunk_t cky_r,
			    struct logger *logger)
{
	CK_NSS_IKE1_PRF_DERIVE_PARAMS ike1_prf_params = {
		.prfMechanism = prf_desc->nss.mechanism,
		.bHasPrevKey = CK_TRUE,
		.hKeygxy = PK11_GetSymKeyHandle(dh_secret),
		.hPrevKey = PK11_GetSymKeyHandle(skeyid_d),
		.pCKYi = cky_i.ptr,
		.ulCKYiLen = cky_i.len,
		.pCKYr = cky_r.ptr,
		.ulCKYrLen = cky_r.len,
		.keyNumber = 1,
	};
	SECItem params = {
		.data = (unsigned char *)&ike1_prf_params,
		.len = sizeof(ike1_prf_params),
	};

	return crypt_derive(skeyid, CKM_NSS_IKE1_PRF_DERIVE, &params,
			    "skeyid_a", CKM_EXTRACT_KEY_FROM_KEY, CKA_DERIVE,
			    /*key-size*/0, /*flags*/0,
			    HERE, logger);
}

/*
 * SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2)
 */
static PK11SymKey *skeyid_e(const struct prf_desc *prf_desc,
			    PK11SymKey *skeyid,
			    PK11SymKey *skeyid_a, PK11SymKey *dh_secret,
			    chunk_t cky_i, chunk_t cky_r,
			    struct logger *logger)
{
	CK_NSS_IKE1_PRF_DERIVE_PARAMS ike1_prf_params = {
		.prfMechanism = prf_desc->nss.mechanism,
		.bHasPrevKey = CK_TRUE,
		.hKeygxy = PK11_GetSymKeyHandle(dh_secret),
		.hPrevKey = PK11_GetSymKeyHandle(skeyid_a),
		.pCKYi = cky_i.ptr,
		.ulCKYiLen = cky_i.len,
		.pCKYr = cky_r.ptr,
		.ulCKYrLen = cky_r.len,
		.keyNumber = 2,
	};
	SECItem params = {
		.data = (unsigned char *)&ike1_prf_params,
		.len = sizeof(ike1_prf_params),
	};

	return crypt_derive(skeyid, CKM_NSS_IKE1_PRF_DERIVE, &params,
			    "skeyid_e", CKM_EXTRACT_KEY_FROM_KEY, CKA_DERIVE,
			    /*key-size*/0, /*flags*/0,
			    HERE, logger);
}

static PK11SymKey *appendix_b_keymat_e(const struct prf_desc *prf,
				       const struct encrypt_desc *encrypter,
				       PK11SymKey *skeyid_e,
				       unsigned required_keymat,
				       struct logger *logger)
{

	/*
	 * XXX: This requires a fix to an old bug adding
	 * CKM_NSS_IKE1_APP_B_PRF_DERIVE to the allowed operations
	 * that was embedded in the below changeset.
	 *
	 * changeset:   15575:225bb39eade1
	 * user:        Robert Relyea <rrelyea@redhat.com>
	 * date:        Mon Apr 20 16:58:16 2020 -0700
	 * summary:     Bug 1629663 NSS missing IKEv1 Quick Mode KDF prf r=kjacobs
	 */
	CK_MECHANISM_TYPE mechanism = prf->nss.mechanism;
	CK_MECHANISM_TYPE target = encrypter->nss.mechanism;
	SECItem params = {
		.data = (unsigned char *)&mechanism,
		.len = sizeof(mechanism),
	};
	/* for when ENCRYPTER isn't NSS */
	if (target == 0)
		target = CKM_EXTRACT_KEY_FROM_KEY;

	return crypt_derive(skeyid_e, CKM_NSS_IKE1_APP_B_PRF_DERIVE,
			    &params, "keymat_e", target, CKA_ENCRYPT,
			    /*key-size*/required_keymat, /*flags*/CKF_DECRYPT|CKF_ENCRYPT,
			    HERE, logger);
}

static chunk_t section_5_keymat(const struct prf_desc *prf,
				PK11SymKey *SKEYID_d,
				PK11SymKey *g_xy,
				uint8_t protocol,
				shunk_t SPI,
				chunk_t Ni_b, chunk_t Nr_b,
				unsigned required_keymat,
				struct logger *logger)
{
	/*
	 * XXX: this requires:
	 *
	 * changeset:   15575:225bb39eade1
	 * user:        Robert Relyea <rrelyea@redhat.com>
	 * date:        Mon Apr 20 16:58:16 2020 -0700
	 * summary:     Bug 1629663 NSS missing IKEv1 Quick Mode KDF prf r=kjacobs
	 *
	 * We found another KDF function in libreswan that is not
	 * using the NSS KDF API.
	 *
	 * Unfortunately, it seems the existing IKE KDF's in NSS are
	 * not usable for the Quick Mode use.
	 *
	 * The libreswan code is in compute_proto_keymat() and the
	 * specification is in
	 * https://tools.ietf.org/html/rfc2409#section-5.5
	 *
	 * [...]
	 *
	 * This patch implements this by extendind the Appendix B
	 * Mechanism to take and optional key and data in a new
	 * Mechanism parameter structure.  Which flavor is used (old
	 * CK_MECHANISM_TYPE or the new parameter) is determined by
	 * the mechanism parameter lengths. Application which try to
	 * use this new feature on old versions of NSS will get an
	 * error (rather than invalid data).
	 *
	 * XXX: yes, it looks at params.len; ewwwww!
	 */
	size_t extra_size = (1/* protocol*/ + SPI.len + Ni_b.len + Nr_b.len);
	uint8_t *extra = alloc_things(uint8_t, extra_size,
				      "protocol | SPI | Ni_b | Nr_b");
	uint8_t *p = extra;
	*p++ = protocol;
	memcpy(p, SPI.ptr, SPI.len);
	p += SPI.len;
	memcpy(p, Ni_b.ptr, Ni_b.len);
	p += Ni_b.len;
	memcpy(p, Nr_b.ptr, Nr_b.len);
	p += Nr_b.len;
	passert(extra + extra_size == p);

	/*
	 * If this fails to compile, a newer nss version is needed.
	 */
	CK_NSS_IKE1_APP_B_PRF_DERIVE_PARAMS dparams = {
		.prfMechanism = prf->nss.mechanism,
		.bHasKeygxy = g_xy != NULL,
		.hKeygxy = g_xy != NULL ? PK11_GetSymKeyHandle(g_xy) : 0,
		.pExtraData = extra, /* protocol | SPI | Ni_b | Nr_b */
		.ulExtraDataLen = extra_size,
	};
	SECItem params = {
		.data = (unsigned char *)&dparams,
		.len = sizeof(dparams),
	};
	PK11SymKey *key = crypt_derive(SKEYID_d, CKM_NSS_IKE1_APP_B_PRF_DERIVE, &params,
				       "section_5_keymat", CKM_EXTRACT_KEY_FROM_KEY,
				       CKA_ENCRYPT,
				       /*key-size*/required_keymat,
				       /*flags*/CKF_DECRYPT|CKF_ENCRYPT,
				       HERE, logger);
	chunk_t keymat = chunk_from_symkey("section 5 keymat", key, logger);
	PASSERT(logger, keymat.len == required_keymat);
	release_symkey("section 5 keymat", "keymat", &key);
	pfree(extra);
	return keymat;
}

const struct prf_ikev1_ops ike_alg_prf_ikev1_nss_ops = {
	.backend = "NSS",
	.signature_skeyid = signature_skeyid,
	.pre_shared_key_skeyid = pre_shared_key_skeyid,
	.skeyid_d = skeyid_d,
	.skeyid_a = skeyid_a,
	.skeyid_e = skeyid_e,
	.appendix_b_keymat_e = appendix_b_keymat_e,
	.section_5_keymat = section_5_keymat,
};
