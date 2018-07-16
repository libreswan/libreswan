/*
 * Kernel runtime algorithm handling interface
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
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
 * Fixes by:
 *	ML: Mathieu Lafon <mlafon@arkoon.net>
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/queue.h>

#include <libreswan.h>

#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include "constants.h"
#include "alg_info.h"
#include "kernel_alg.h"
#include "lswlog.h"
#include "lswalloc.h"
#include "ietf_constants.h"

#include "ike_alg.h"
#include "ike_alg_encrypt.h"
#include "ike_alg_integ.h"

/*
 * XXX: The kernel algorithm database is indexed by SADB kernel values
 * (which date back to the defunct pfkey interface) and assumes there
 * is a value for every single supported algorithm.
 *
 * The assumption isn't valid.  Magic SADB values have been added when
 * no official value was available.
 *
 * The code should instead be rewritten to use 'struct ike_alg*' as a
 * kernel interface agnostic way of identifying algorithms.  Later.
 */

/* ALG storage */
static struct sadb_alg esp_aalg[K_SADB_AALG_MAX + 1];	/* ??? who fills this table in? */
static struct sadb_alg esp_ealg[K_SADB_EALG_MAX + 1];
static int esp_ealg_num = 0;
static int esp_aalg_num = 0;

#define ESP_EALG_PRESENT(algo) ((algo) <= K_SADB_EALG_MAX && \
				esp_ealg[algo].sadb_alg_id == (algo))

#define ESP_EALG_FOR_EACH(algo) \
	for ((algo) = 1; (algo) <= K_SADB_EALG_MAX; (algo)++) \
		if (ESP_EALG_PRESENT(algo))

#define ESP_AALG_PRESENT(algo) ((algo) <= SADB_AALG_MAX && \
				esp_aalg[algo].sadb_alg_id == (algo))

#define ESP_AALG_FOR_EACH(algo) \
	for ((algo) = 1; (algo) <= SADB_AALG_MAX; (algo)++) \
		if (ESP_AALG_PRESENT(algo))

static struct sadb_alg *sadb_alg_ptr(unsigned satype, unsigned exttype,
				unsigned alg_id, bool rw)
{
	struct sadb_alg *alg_p = NULL;

	switch (exttype) {
	case SADB_EXT_SUPPORTED_AUTH:
		/* ??? should this be a passert? */
		if (alg_id > SADB_AALG_MAX)
			return NULL;	/* fail */

		switch (satype) {
		case SADB_SATYPE_AH:
		case SADB_SATYPE_ESP:
			/* ??? even though this might be AH, we only talk of ESP */
			alg_p = &esp_aalg[alg_id];

			/* get for write: increment elem count */
			if (rw)
				esp_aalg_num++;
			return alg_p;

		default:
			/* ??? should this be a passert? */
			return NULL;	/* fail */
		}

	case SADB_EXT_SUPPORTED_ENCRYPT:
		/* ??? should this be a passert? */
		if (alg_id > K_SADB_EALG_MAX)
			return NULL;	/* fail */

		switch (satype) {
		case SADB_SATYPE_ESP:
			alg_p = &esp_ealg[alg_id];

			/* get for write: increment elem count */
			if (rw)
				esp_ealg_num++;
			return alg_p;

		default:
			/* ??? should this be a passert? */
			return NULL;	/* fail */
		}
		break;

	default:
		/* ??? should this be a passert? */
		return NULL;	/* fail */
	}
}

/*
 *      Forget previous registration
 */
void kernel_alg_init(void)
{
	DBG(DBG_KERNEL, DBG_log("kernel_alg_init()"));
	/* ??? do these zero calls do anything useful? */
	zero(&esp_aalg);
	zero(&esp_ealg);
	esp_ealg_num = esp_aalg_num = 0;
}

/* used by kernel_netlink.c and kernel_bsdkame.c */
int kernel_alg_add(int satype, int exttype, const struct sadb_alg *sadb_alg)
{
	struct sadb_alg *alg_p, tmp_alg;
	uint8_t alg_id = sadb_alg->sadb_alg_id;

	bool supported;
	switch (exttype) {
	case SADB_EXT_SUPPORTED_ENCRYPT:
		supported = encrypt_desc_by_sadb_ealg_id(alg_id);
		break;
	case SADB_EXT_SUPPORTED_AUTH:
		supported = integ_desc_by_sadb_aalg_id(alg_id);
		break;
	default:
		supported = true;
	}

	if (DBGP(DBG_KERNEL|DBG_CRYPT)) {
		const char *exttype_name =
			exttype == SADB_EXT_SUPPORTED_AUTH ? "SADB_EXT_SUPPORTED_AUTH"
			: exttype == SADB_EXT_SUPPORTED_ENCRYPT ? "SADB_EXT_SUPPORTED_ENCRYPT"
			: "SADB_EXT_SUPPORTED_???";
		struct esb_buf alg_name_buf;
		/*
		 * XXX: The ALG_ID value found here comes from the
		 * Linux kernel (see libreswan/pfkeyv2.h) so using
		 * AH_TRANSFORMID_NAMES and ESP_TRANSFORMID_NAMES is
		 * only an approximation.
		 */
		const char *alg_name =
			exttype == SADB_EXT_SUPPORTED_AUTH ? enum_showb(&ah_transformid_names, alg_id, &alg_name_buf)
			: exttype == SADB_EXT_SUPPORTED_ENCRYPT ? enum_showb(&esp_transformid_names, alg_id, &alg_name_buf)
			: "???";
		const char *satype_name =
			satype == SADB_SATYPE_ESP ? "SADB_SATYPE_ESP"
			: satype == SADB_SATYPE_AH ? "SADB_SATYPE_AH"
			: "SADB_SATYPE_???";
		DBG_log("kernel_alg_add(): satype=%d(%s), exttype=%d(%s), alg_id=%d(%s), alg_ivlen=%d, alg_minbits=%d, alg_maxbits=%d%s",
			satype, satype_name,
			exttype, exttype_name,
			alg_id, alg_name,
			sadb_alg->sadb_alg_ivlen,
			sadb_alg->sadb_alg_minbits,
			sadb_alg->sadb_alg_maxbits,
			supported ? "" : " not supported");
	}

	if (!supported) {
		return 0;
	}

	/*
	 * XXX: if the 'return 0' below is executed, this leaks the
	 * ALG_P allocated by sadb_alg_ptr() .  Fortunately the array
	 * is large.
	 */
	alg_p = sadb_alg_ptr(satype, exttype, alg_id, TRUE);
	if (alg_p == NULL) {
		DBG(DBG_KERNEL,
			DBG_log("kernel_alg_add(%d,%d,%d) fails because alg combo is invalid",
			satype, exttype, alg_id));
		return -1;
	}

	/* This logic "mimics" KLIPS: first algo implementation will be used */
	if (alg_p->sadb_alg_id != 0) {
		DBG(DBG_KERNEL,
			DBG_log("kernel_alg_add(): discarding already setup satype=%d, exttype=%d, alg_id=%d",
				satype, exttype,
				alg_id);
			);
		return 0;
	}
	/*
	 * The kernel PFKEY interface gives us options we do not want to
	 * support. The kernel allows ESP_CAST with variable keysizes, and
	 * we only want to support 128bit. The kernel also allows ESP_BLOWFISH,
	 * but its inventor Bruce Schneier has said to stop using blowfish
	 * and use twofish instead. The kernel allows ESP_DES, which
	 * is simply too weak to be allowed. And for ESP_AES_CTR it returns
	 * the keysize including the 4 bytes of nonce.
	 */
	tmp_alg = *sadb_alg;
	switch (exttype) {
	case SADB_EXT_SUPPORTED_ENCRYPT:
		switch (satype) {
		case SADB_SATYPE_ESP:
			switch (alg_id) {
			case ESP_CAST:
				/* Overruling kernel - we only want to support 128 */
				tmp_alg.sadb_alg_minbits = 128;
				tmp_alg.sadb_alg_maxbits = 128;
				break;
			case ESP_AES_CTR:
				/* Overruling kernel - remove salt from calculation */
				tmp_alg.sadb_alg_minbits = 128;
				tmp_alg.sadb_alg_maxbits = 256;
				break;
			case ESP_BLOWFISH:
			case ESP_DES:
				DBG(DBG_KERNEL,
					DBG_log("kernel_alg_add(): Ignoring alg_id=%d(%s) - too weak",
						alg_id,
						enum_name(&esp_transformid_names,
							alg_id)));
				return 0;
			}
			break;
		}
		break;
	}

	*alg_p = tmp_alg;
	return 1;
}

/*
 * The kernel_alg database should work with IKE_ALGs and not SADBs,
 * this works for the moment.
 */
struct sadb_id {
	const struct ike_alg *alg;
	int id;
};

static int find_sadb_id(const struct sadb_id *table, const struct ike_alg *alg)
{
	for (const struct sadb_id *map = table; map->alg != NULL; map++) {
		if (map->alg == alg) {
			return map->id;
		}
	}
	return -1;
}

const struct sadb_id integ_sadb_ids[] = {
	{ &ike_alg_integ_aes_cmac.common, SADB_X_AALG_AES_CMAC_96, },
	{ NULL, 0 },
};

void kernel_integ_add(const struct integ_desc *integ)
{
	int sadb_aalg = find_sadb_id(integ_sadb_ids, &integ->common);
	if (sadb_aalg < 0) {
		PEXPECT_LOG("Integrity algorithm %s has no matching SADB ID",
			    integ->common.fqn);
		return;
	}
	struct sadb_alg alg = {
		.sadb_alg_minbits = integ->integ_keymat_size * BITS_PER_BYTE,
		.sadb_alg_maxbits = integ->integ_keymat_size * BITS_PER_BYTE,
		.sadb_alg_id = sadb_aalg,
	};
	if (kernel_alg_add(SADB_SATYPE_ESP,  SADB_EXT_SUPPORTED_AUTH, &alg) != 1) {
		DBGF(DBG_KERNEL|DBG_CRYPT,
		     "Note: failed to register integrity algorithm %s for ESP/AH",
		     integ->common.fqn);
		return;
	}
}

const struct sadb_id encrypt_sadb_ids[] = {
	{ &ike_alg_encrypt_aes_gcm_8.common, SADB_X_EALG_AES_GCM_ICV8, },
	{ &ike_alg_encrypt_aes_gcm_12.common, SADB_X_EALG_AES_GCM_ICV12, },
	{ &ike_alg_encrypt_aes_gcm_16.common, SADB_X_EALG_AES_GCM_ICV16, },
	{ &ike_alg_encrypt_aes_ccm_8.common, SADB_X_EALG_AES_CCM_ICV8, },
	{ &ike_alg_encrypt_aes_ccm_12.common, SADB_X_EALG_AES_CCM_ICV12, },
	{ &ike_alg_encrypt_aes_ccm_16.common, SADB_X_EALG_AES_CCM_ICV16, },
	{ &ike_alg_encrypt_null_integ_aes_gmac.common, SADB_X_EALG_NULL_AUTH_AES_GMAC, },
	{ NULL, 0},
};

void kernel_encrypt_add(const struct encrypt_desc *encrypt)
{
	int sadb_ealg = find_sadb_id(encrypt_sadb_ids, &encrypt->common);
	if (sadb_ealg < 0) {
		PEXPECT_LOG("Encryption algorithm %s has no matching SADB ID",
			    encrypt->common.fqn);
		return;
	}

	struct sadb_alg alg = {
		.sadb_alg_ivlen = encrypt->wire_iv_size,
		.sadb_alg_minbits = encrypt_min_key_bit_length(encrypt),
		.sadb_alg_maxbits = encrypt_max_key_bit_length(encrypt),
		.sadb_alg_id = sadb_ealg,
	};

	if (kernel_alg_add(SADB_SATYPE_ESP, SADB_EXT_SUPPORTED_ENCRYPT, &alg) != 1) {
		DBGF(DBG_KERNEL|DBG_CRYPT,
		     "Note: failed to register encryption algorithm %s for ESP",
		     encrypt->common.fqn);
		return;
	}
}

bool kernel_alg_dh_ok(const struct oakley_group_desc *dh)
{
	if (dh == NULL) {
		PEXPECT_LOG("%s", "DH needs to be valid (non-NULL)");
		return false;
	}
	/* require an in-process/ike implementation of DH */
	return ike_alg_is_ike(&dh->common);
}

bool kernel_alg_encrypt_ok(const struct encrypt_desc *encrypt)
{
	if (encrypt == NULL) {
		PEXPECT_LOG("%s", "encryption needs to be valid (non-NULL)");
		return false;
	}
	return ESP_EALG_PRESENT(encrypt->common.id[IKEv1_ESP_ID]);
}

bool kernel_alg_integ_ok(const struct integ_desc *integ)
{
	if (integ == NULL) {
		PEXPECT_LOG("%s", "integrity needs to be valid (non-NULL)");
		return false;
	}
	return ESP_AALG_PRESENT(integ->integ_ikev1_ah_transform);
}

bool kernel_alg_is_ok(const struct ike_alg *alg)
{
	if (alg == NULL) {
		PEXPECT_LOG("%s", "algorithm needs to be valid (non-NULL)");
		return false;
	} else if (alg->algo_type == &ike_alg_dh) {
		return kernel_alg_dh_ok(dh_desc(alg));
	} else if (alg->algo_type == &ike_alg_encrypt) {
		return kernel_alg_encrypt_ok(encrypt_desc(alg));
	} else if (alg->algo_type == &ike_alg_integ) {
		return kernel_alg_integ_ok(integ_desc(alg));
	} else {
		PASSERT_FAIL("algorithm %s of type %s is not valid in the kernel",
			     alg->fqn, ike_alg_type_name(alg->algo_type));
	}
}

bool kernel_alg_encrypt_key_size(const struct encrypt_desc *encrypt,
				 int keylen, size_t *key_size)
{
	/*
	 * Assume the two ENUMs are the same!
	 */
	enum ipsec_cipher_algo transid = encrypt->common.id[IKEv1_ESP_ID];
	int sadb_ealg = transid;

	/*
	 * XXX: Is KEYLEN ever zero for any case other than 'null'
	 * encryption?  If it is, patch it up and then log it to find
	 * out.
	 */
	if (keylen == 0) {
		if (encrypt != &ike_alg_encrypt_null) {
			keylen = esp_ealg[sadb_ealg].sadb_alg_minbits;
			DBG(DBG_KERNEL,
			    DBG_log("XXX: %s has key length of 0, adjusting to %d",
				    encrypt->common.fqn, keylen));
		}
	}

	if (esp_ealg[sadb_ealg].sadb_alg_minbits <= keylen &&
	    keylen <= esp_ealg[sadb_ealg].sadb_alg_maxbits) {
		/*
		 * XXX: is the above check equivalent to
		 * encrypt_has_key_bit_length()?  If it is then it
		 * should have been applied already by the parser?
		 * Find out.
		 */
		if (!encrypt_has_key_bit_length(encrypt, keylen)) {
			DBG(DBG_KERNEL, DBG_log("XXX: IKE_ALG rejects %s key length of %d accepted by SADB",
						encrypt->common.fqn, keylen));

		}
	} else {
		/*
		 * XXX: conversely is SADB rejecting something IKE_ALG
		 * things is ok?
		 */
		if (encrypt_has_key_bit_length(encrypt, keylen)) {
			DBG(DBG_KERNEL, DBG_log("XXX: IKE_ALG accepts %s key length of %d rejected by SADB",
						encrypt->common.fqn, keylen));
		}
		DBG(DBG_KERNEL,
		    DBG_log("kernel_alg_esp_info(): transid=%d, proposed keylen=%u is invalid, not %u<=X<=%u",
			    transid, keylen,
			    esp_ealg[sadb_ealg].sadb_alg_minbits,
			    esp_ealg[sadb_ealg].sadb_alg_maxbits));
		/* proposed key length is invalid! */
		return FALSE;
	}

	/*
	 * This is all this function should be doing, which isn't
	 * much.
	 */
	*key_size = keylen / BITS_PER_BYTE;
	DBG(DBG_PARSING,
	    DBG_log("encrypt %s keylen=%d transid=%d, key_size=%zu, encryptalg=%d",
		    encrypt->common.fqn, keylen, transid, *key_size, sadb_ealg));
	return TRUE;
}

struct sadb_alg *next_kernel_encrypt_alg(struct sadb_alg *last)
{
	if (last == NULL) {
		last = &esp_ealg[1];
	} else {
		last++;
	}
	for (; last < &esp_ealg[elemsof(esp_ealg)]; last++) {
		if (last->sadb_alg_id != 0) {
			return last;
		}
	}
	return NULL;
}

struct sadb_alg *next_kernel_integ_alg(struct sadb_alg *last)
{
	if (last == NULL) {
		last = &esp_aalg[1];
	} else {
		last++;
	}
	for (; last < &esp_aalg[elemsof(esp_aalg)]; last++) {
		if (last->sadb_alg_id != 0) {
			return last;
		}
	}
	return NULL;
}

int kernel_alg_encrypt_count(void)
{
	return esp_ealg_num;
}

int kernel_alg_integ_count(void)
{
	return esp_aalg_num;
}
