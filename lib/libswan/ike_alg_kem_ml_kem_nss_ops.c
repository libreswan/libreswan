/* Key Exchange Method algorithms, for libreswan
 *
 * Copyright (C) 2025 Andrew Cagney
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

#include <cryptohi.h>
#include <keyhi.h>

#include "crypt_kem.h"
#include "crypt_symkey.h"

#include "lswnss.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "ike_alg_kem_ops.h"
#include "passert.h"
#include "lswalloc.h"

/*
 * The official ML-KEM mechanisms from PKCS#11 3.2 are only supported
 * in NSS 3.116 or later. Use the vendor-specific constants otherwise.
 */
#if (defined(NSS_VMAJOR) ? NSS_VMAJOR : 0) > 3 || \
	((defined(NSS_VMAJOR) ? NSS_VMAJOR : 0) >= 3 && \
	 (defined(NSS_VMINOR) ? NSS_VMINOR : 0) >= 116)
#define LSW_CKM_ML_KEM_KEY_PAIR_GEN CKM_ML_KEM_KEY_PAIR_GEN
#define LSW_CKM_ML_KEM CKM_ML_KEM
#define LSW_CKP_ML_KEM_768 CKP_ML_KEM_768
#define LSW_CK_ML_KEM_PARAMETER_SET_TYPE CK_ML_KEM_PARAMETER_SET_TYPE
#else
#define LSW_CKM_ML_KEM_KEY_PAIR_GEN CKM_NSS_ML_KEM_KEY_PAIR_GEN
#define LSW_CKM_ML_KEM CKM_NSS_ML_KEM
#define LSW_CKP_ML_KEM_768 CKP_NSS_ML_KEM_768
#define LSW_CK_ML_KEM_PARAMETER_SET_TYPE CK_NSS_KEM_PARAMETER_SET_TYPE
#endif

static void nss_ml_kem_calc_local_secret(const struct kem_desc *kem UNUSED,
					 SECKEYPrivateKey **private_key,
					 SECKEYPublicKey **public_key,
					 struct logger *logger)
{
    CK_MECHANISM_TYPE mechanism = LSW_CKM_ML_KEM_KEY_PAIR_GEN;
    LSW_CK_ML_KEM_PARAMETER_SET_TYPE param = LSW_CKP_ML_KEM_768;

    void *password_context = lsw_nss_get_password_context(logger);
    PK11SlotInfo *slot = PK11_GetBestSlot(mechanism, password_context);
    PASSERT(logger, slot != NULL);

#if 0
    /*
     * Also sets the usage.
     */
    (*private_key) = PK11_GenerateKeyPairWithOpFlags(slot, mechanism, &param,
						     public_key,
						     /*attrFlags*/PK11_ATTR_SESSION | PK11_ATTR_INSENSITIVE | PK11_ATTR_PUBLIC,
						     /*opFlags*/CKF_DERIVE,
						     /*opFlagsMask*/CKF_DERIVE,
						     password_context);

    if ((*private_key) == NULL) {
	    *private_key = PK11_GenerateKeyPairWithOpFlags(slot, mechanism, &param,
							   public_key,
							   /*attrFlags*/PK11_ATTR_SESSION | PK11_ATTR_SENSITIVE | PK11_ATTR_PRIVATE,
							   /*opFlags*/CKF_DERIVE,
							   /*opFlagsMask*/CKF_DERIVE,
							   password_context);
    }
#else
    (*private_key) = PK11_GenerateKeyPair(slot, mechanism, &param,
					  public_key,
					  /*isPerm*/PR_FALSE,
					  /*isSensitive*/PK11_IsFIPS() ? PR_TRUE : PR_FALSE,
					  password_context);
#endif

    PK11_FreeSlot(slot);

    PASSERT(logger, (*private_key) != NULL);
    PASSERT(logger, (*public_key) != NULL);
}

static shunk_t nss_ml_kem_local_secret_ke(const struct kem_desc *kem UNUSED,
					  const SECKEYPublicKey *public_key)
{
#if 0
	passert(local_pubk->u.kyber.publicValue.len == group->bytes);
#endif
	return shunk2(public_key->u.kyber.publicValue.data,
		      public_key->u.kyber.publicValue.len);
}

static diag_t nss_ml_kem_encapsulate_1(struct kem_responder *responder,
				       shunk_t initiator_ke,
				       struct logger *logger,
				       PRArenaPool *arena)
{
	void *password_context = lsw_nss_get_password_context(logger);
	SECStatus status;

	SECKEYPublicKey *initiator_pubkey = PORT_ArenaZNew(arena, SECKEYPublicKey);
	if (initiator_pubkey == NULL) {
		return diag_nss_error("allocating %s() SECKEYPublicKey", __func__);
	}

	initiator_pubkey->arena = arena;
	initiator_pubkey->keyType = kyberKey;
	initiator_pubkey->pkcs11Slot = NULL;
	initiator_pubkey->pkcs11ID = CK_INVALID_HANDLE;

	/*
	 * Now copy the kyber bits.
	 */

	SECKEYKyberPublicKey *kyber = &initiator_pubkey->u.kyber;
	kyber->params = params_ml_kem768;

	status = SECITEM_MakeItem(arena, &kyber->publicValue, initiator_ke.ptr, initiator_ke.len);
	if (status != SECSuccess) {
		return diag_nss_error("allocating %s() publicValue", __func__);
	}

	CK_OBJECT_HANDLE handle;
	{
		PK11SlotInfo *slot = PK11_GetBestSlot(LSW_CKM_ML_KEM, password_context);
		if (slot == NULL) {
			return diag_nss_error("getting %s() slot", __func__);
		}

		handle = PK11_ImportPublicKey(slot, initiator_pubkey, PR_FALSE);
		PK11_FreeSlot(slot);
		if (handle == CK_INVALID_HANDLE) {
			return diag_nss_error("importing %s() initiator pubkey", __func__);
		}
	}

	SECItem *responder_ke; /* must SECITEM_FreeItem(PR_TRUE); */
	status = PK11_Encapsulate(initiator_pubkey,
				  CKM_HKDF_DERIVE, PK11_ATTR_SESSION | PK11_ATTR_INSENSITIVE | PK11_ATTR_PUBLIC,
				  CKF_DERIVE,
				  &responder->shared_key,
				  &responder_ke);

	/* Destroy the imported public key */
	PASSERT(logger, initiator_pubkey->pkcs11Slot != NULL);
	PK11_DestroyObject(initiator_pubkey->pkcs11Slot, initiator_pubkey->pkcs11ID);
	PK11_FreeSlot(initiator_pubkey->pkcs11Slot);

	if (status != SECSuccess) {
		return diag_nss_error("encapsulate %s() initiator pubkey", __func__);
	}

	if (responder_ke == NULL) {
		return diag_nss_error("encapsulate %s() initiator pubkey", __func__);
	}

	symkey_newref(logger, "responder-shared-key", responder->shared_key);

	responder->internal.ke = clone_bytes_as_chunk(responder_ke->data, responder_ke->len, "responder-ke");
	SECITEM_FreeItem(responder_ke, /*free-item?*/PR_TRUE);
	responder->ke = HUNK_AS_SHUNK(responder->internal.ke);

	return NULL;
}

static diag_t nss_ml_kem_encapsulate(struct kem_responder *responder,
				     shunk_t initiator_ke,
				     struct logger *logger)
{
	/*
	 * Allocate the public key, giving it its own arena.
	 *
	 * Since the arena contains everything allocated to the
	 * seckey, error recovery just requires freeing that.
	 */

	PRArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (arena == NULL) {
		return diag_nss_error("allocating %s() arena", __func__);
	}

	diag_t d = nss_ml_kem_encapsulate_1(responder, initiator_ke, logger, arena);
	PORT_FreeArena(arena, /*zero*/PR_TRUE);
	return d;
}

static diag_t nss_ml_kem_decapsulate(struct kem_initiator *initiator,
				     shunk_t responder_ke,
				     struct logger *logger UNUSED)
{
	SECItem responder_ke_item = same_shunk_as_secitem(responder_ke, siBuffer);
	SECStatus status = PK11_Decapsulate(initiator->internal.private_key,
					    &responder_ke_item,
					    CKM_HKDF_DERIVE,
					    PK11_ATTR_SESSION | PK11_ATTR_INSENSITIVE,
					    CKF_DERIVE,
					    &initiator->shared_key);
	if (status != SECSuccess) {
		return diag_nss_error("decapsulating %s() responder KE", __func__);
	}

	symkey_newref(logger, "initiator-shared-key", initiator->shared_key);
	return NULL;
}

static void nss_ml_kem_check(const struct kem_desc *kem, struct logger *logger)
{
	ldbg(logger, "ignoring %s", kem->common.fqn);
}


const struct kem_ops ike_alg_kem_ml_kem_nss_ops = {
	.backend = "NSS(MLKEM)",
	.check = nss_ml_kem_check,
	.calc_local_secret = nss_ml_kem_calc_local_secret,
	.local_secret_ke = nss_ml_kem_local_secret_ke,
	.kem_encapsulate = nss_ml_kem_encapsulate,
	.kem_decapsulate = nss_ml_kem_decapsulate,
};
