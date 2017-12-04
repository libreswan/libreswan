/*
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2014 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2014-2016 Andrew Cagney <andrew.cagney@gmail.com>
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
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <libreswan.h>

#include "constants.h"
#include "klips-crypto/aes_cbc.h"
#include "lswlog.h"
#include "ike_alg.h"

#include <pk11pub.h>
#include <prmem.h>
#include <prerror.h>
#include <blapit.h>

#include "ike_alg_nss_cbc.h"
#include "ike_alg_nss_gcm.h"
#include "ike_alg_aes.h"

const struct encrypt_desc ike_alg_encrypt_aes_cbc = {
	.common = {
		.name = "aes",
		.fqn = "AES_CBC",
		.names = { "aes", "aes_cbc", },
		.officname = "aes",
		.algo_type =   IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_AES_CBC,
			[IKEv1_ESP_ID] = ESP_AES,
			[IKEv2_ALG_ID] = IKEv2_ENCR_AES_CBC,
		},
		.fips =        TRUE,
	},
	.nss = {
		.mechanism = CKM_AES_CBC,
	},
	.enc_blocksize = AES_CBC_BLOCK_SIZE,
	.pad_to_blocksize = TRUE,
	.wire_iv_size =       AES_CBC_BLOCK_SIZE,
	.keydeflen =    AES_KEY_DEF_LEN,
	.key_bit_lengths = { 256, 192, 128, },
	.encrypt_ops = &ike_alg_nss_cbc_encrypt_ops,
};

static void do_aes_ctr(const struct encrypt_desc *alg UNUSED,
		       u_int8_t *buf, size_t buf_len, PK11SymKey *sym_key,
		       u_int8_t *counter_block, bool encrypt)
{
	DBG(DBG_CRYPT, DBG_log("do_aes_ctr: enter"));

	passert(sym_key);
	if (sym_key == NULL) {
		PASSERT_FAIL("%s", "NSS derived enc key in NULL");
	}

	CK_AES_CTR_PARAMS counter_param;
	counter_param.ulCounterBits = sizeof(u_int32_t) * 8;/* Per RFC 3686 */
	memcpy(counter_param.cb, counter_block, sizeof(counter_param.cb));
	SECItem param;
	param.type = siBuffer;
	param.data = (void*)&counter_param;
	param.len = sizeof(counter_param);

	/* Output buffer for transformed data.  */
	u_int8_t *out_buf = PR_Malloc((PRUint32)buf_len);
	unsigned int out_len = 0;

	if (encrypt) {
		SECStatus rv = PK11_Encrypt(sym_key, CKM_AES_CTR, &param,
					    out_buf, &out_len, buf_len,
					    buf, buf_len);
		if (rv != SECSuccess) {
			PASSERT_FAIL("PK11_Encrypt failure (err %d)", PR_GetError());
		}
	} else {
		SECStatus rv = PK11_Decrypt(sym_key, CKM_AES_CTR, &param,
					    out_buf, &out_len, buf_len,
					    buf, buf_len);
		if (rv != SECSuccess) {
			PASSERT_FAIL("PK11_Decrypt failure (err %d)", PR_GetError());
		}
	}

	memcpy(buf, out_buf, buf_len);
	PR_Free(out_buf);

	/*
	 * Finally update the counter located at the end of the
	 * counter_block. It is incremented by 1 for every full or
	 * partial block encoded/decoded.
	 *
	 * There's a portability assumption here that the IV buffer is
	 * at least sizeof(u_int32_t) (4-byte) aligned.
	 */
	u_int32_t *counter = (u_int32_t*)(counter_block + AES_BLOCK_SIZE
					  - sizeof(u_int32_t));
	u_int32_t old_counter = ntohl(*counter);
	size_t increment = (buf_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
	u_int32_t new_counter = old_counter + increment;
	DBG(DBG_CRYPT, DBG_log("do_aes_ctr: counter-block updated from 0x%lx to 0x%lx for %zd bytes",
			       (unsigned long)old_counter, (unsigned long)new_counter, buf_len));
	if (new_counter < old_counter) {
		/* Wrap ... */
		loglog(RC_LOG_SERIOUS,
		       "do_aes_ctr: counter wrapped");
		/* what next??? */
	}
	*counter = htonl(new_counter);

	DBG(DBG_CRYPT, DBG_log("do_aes_ctr: exit"));
}

static void ctr_check(const struct encrypt_desc *alg UNUSED)
{
}

static const struct encrypt_ops aes_ctr_encrypt_ops = {
	.check = ctr_check,
	.do_crypt = do_aes_ctr,
};

const struct encrypt_desc ike_alg_encrypt_aes_ctr =
{
	.common = {
		.name = "aes_ctr",
		.fqn = "AES_CTR",
		.names = { "aesctr", "aes_ctr", },
		.officname = "aes_ctr",
		.algo_type =   IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_AES_CTR,
			[IKEv1_ESP_ID] = ESP_AES_CTR,
			[IKEv2_ALG_ID] = IKEv2_ENCR_AES_CTR,
		},
		.fips =        TRUE,
	},
	.nss = {
		.mechanism = CKM_AES_CTR,
	},
	.enc_blocksize = AES_BLOCK_SIZE,
	.pad_to_blocksize = FALSE,
	.wire_iv_size =	8,
	.salt_size = 4,
	.keydeflen =    AES_KEY_DEF_LEN,
	.key_bit_lengths = { 256, 192, 128, },
	.encrypt_ops = &aes_ctr_encrypt_ops,
};

const struct encrypt_desc ike_alg_encrypt_aes_gcm_8 =
{
	.common = {
		.name = "aes_gcm_8",
		.fqn = "AES_GCM_8",
		.names = { "aes_gcm_8", "aes_gcm_a" },
		/* XXX: aes_gcm_16 has aes_gcm as alias */
		.officname = "aes_gcm",
		.algo_type =   IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_ESP_ID] = ESP_AES_GCM_8,
			[IKEv2_ALG_ID] = IKEv2_ENCR_AES_GCM_8,
		},
		.fips =        TRUE,
	},
	.nss = {
		.mechanism = CKM_AES_GCM,
	},
	.enc_blocksize = AES_BLOCK_SIZE,
	.pad_to_blocksize = FALSE,
	.wire_iv_size =	8,
	.salt_size = AES_GCM_SALT_BYTES,
	.keydeflen =    AES_GCM_KEY_DEF_LEN,
	.key_bit_lengths = { 256, 192, 128, },
	.aead_tag_size = 8,
	.encrypt_ops = &ike_alg_nss_gcm_encrypt_ops,
};

const struct encrypt_desc ike_alg_encrypt_aes_gcm_12 =
{
	.common = {
		.name = "aes_gcm_12",
		.fqn = "AES_GCM_12",
		.names = { "aes_gcm_12", "aes_gcm_b" },
		.officname = "aes_gcm_12",
		.algo_type =   IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_ESP_ID] = ESP_AES_GCM_12,
			[IKEv2_ALG_ID] = IKEv2_ENCR_AES_GCM_12,
		},
		.fips =        TRUE,
	},
	.nss = {
		.mechanism = CKM_AES_GCM,
	},
	.enc_blocksize = AES_BLOCK_SIZE,
	.wire_iv_size = 8,
	.pad_to_blocksize = FALSE,
	.salt_size = AES_GCM_SALT_BYTES,
	.keydeflen =     AEAD_AES_KEY_DEF_LEN,
	.key_bit_lengths = { 256, 192, 128, },
	.aead_tag_size = 12,
	.encrypt_ops = &ike_alg_nss_gcm_encrypt_ops,
};

const struct encrypt_desc ike_alg_encrypt_aes_gcm_16 =
{
	.common = {
		.name = "aes_gcm_16",
		.fqn = "AES_GCM_16",
		/* aes_gcm_8 has aes_gcm as officname */
		.names = { "aes_gcm", "aes_gcm_16", "aes_gcm_c" },
		.officname = "aes_gcm_16",
		.algo_type =  IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_ESP_ID] = ESP_AES_GCM_16,
			[IKEv2_ALG_ID] = IKEv2_ENCR_AES_GCM_16,
		},
		.fips =        TRUE,
	},
	.nss = {
		.mechanism = CKM_AES_GCM,
	},
	.enc_blocksize = AES_BLOCK_SIZE,
	.wire_iv_size = 8,
	.pad_to_blocksize = FALSE,
	.salt_size = AES_GCM_SALT_BYTES,
	.keydeflen =    AEAD_AES_KEY_DEF_LEN,
	.key_bit_lengths = { 256, 192, 128, },
	.aead_tag_size = 16,
	.encrypt_ops = &ike_alg_nss_gcm_encrypt_ops,
};

/*
 * References for AES_CCM.
 *
 * https://en.wikipedia.org/wiki/CCM_mode
 * https://tools.ietf.org/html/rfc4309#section-7.1
 */

const struct encrypt_desc ike_alg_encrypt_aes_ccm_8 =
{
	.common = {
		.name = "aes_ccm_8",
		.fqn = "AES_CCM_8",
		.names = { "aes_ccm_8", "aes_ccm_a" },
		.officname = "aes_ccm_8",
		.algo_type =    IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_ESP_ID] = ESP_AES_CCM_8,
			[IKEv2_ALG_ID] = IKEv2_ENCR_AES_CCM_8,
		},
		.fips =         TRUE,
	},
	.enc_blocksize =  AES_BLOCK_SIZE,
	.salt_size = 3,
	.wire_iv_size =  8,
	.pad_to_blocksize = FALSE,
	/* Only 128, 192 and 256 are supported (24 bits KEYMAT for salt not included) */
	.keydeflen =      AEAD_AES_KEY_DEF_LEN,
	.key_bit_lengths = { 256, 192, 128, },
	.aead_tag_size = 8,
};

const struct encrypt_desc ike_alg_encrypt_aes_ccm_12 =
{
	.common = {
		.name = "aes_ccm_12",
		.fqn = "AES_CCM_12",
		.names = { "aes_ccm_12", "aes_ccm_b" },
		.officname = "aes_ccm_12",
		.algo_type =    IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_ESP_ID] = ESP_AES_CCM_12,
			[IKEv2_ALG_ID] = IKEv2_ENCR_AES_CCM_12,
		},
		.fips =         TRUE,
	},
	.enc_blocksize =  AES_BLOCK_SIZE,
	.salt_size = 3,
	.wire_iv_size =  8,
	.pad_to_blocksize = FALSE,
	/* Only 128, 192 and 256 are supported (24 bits KEYMAT for salt not included) */
	.keydeflen =      AEAD_AES_KEY_DEF_LEN,
	.key_bit_lengths = { 256, 192, 128, },
	.aead_tag_size = 12,
};

const struct encrypt_desc ike_alg_encrypt_aes_ccm_16 =
{
	.common = {
		.name = "aes_ccm_16",
		.fqn = "AES_CCM_16",
		.names = { "aes_ccm", "aes_ccm_16", "aes_ccm_c" },
		.officname = "aes_ccm_16",
		.algo_type =   IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_ESP_ID] = ESP_AES_CCM_16,
			[IKEv2_ALG_ID] = IKEv2_ENCR_AES_CCM_16,
		},
		.fips =         TRUE,
	},
	.enc_blocksize = AES_BLOCK_SIZE,
	.salt_size = 3,
	.wire_iv_size = 8,
	.pad_to_blocksize = FALSE,
	/* Only 128, 192 and 256 are supported (24 bits KEYMAT for salt not included) */
	.keydeflen =     AEAD_AES_KEY_DEF_LEN,
	.key_bit_lengths = { 256, 192, 128, },
	.aead_tag_size = 16,
};

const struct integ_desc ike_alg_integ_aes_xcbc = {
	.common = {
		.name = "aes_xcbc",
		.fqn = "AES_XCBC_96",
		.names = { "aes_xcbc", "aes_xcbc_96", },
		.officname =  "aes_xcbc",
		.algo_type = IKE_ALG_INTEG,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_ESP_ID] = AUTH_ALGORITHM_AES_XCBC,
			[IKEv2_ALG_ID] = IKEv2_AUTH_AES_XCBC_96,
		},
		.fips = TRUE,
	},
	.integ_keymat_size = AES_XCBC_DIGEST_SIZE,
	.integ_output_size = AES_XCBC_DIGEST_SIZE_TRUNC, /* XXX 96 */
	.integ_ikev1_ah_transform = AH_AES_XCBC_MAC,
};

const struct integ_desc ike_alg_integ_aes_cmac = {
	.common = {
		.name = "aes_cmac",
		.fqn = "AES_CMAC_96",
		.names = { "aes_cmac", "aes_cmac_96", },
		.officname =  "aes_cmac",
		.algo_type = IKE_ALG_INTEG,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_ESP_ID] = AUTH_ALGORITHM_AES_CMAC_96,
			[IKEv2_ALG_ID] = IKEv2_AUTH_AES_CMAC_96,
		},
		.fips = TRUE,
	},
	.integ_keymat_size = BYTES_FOR_BITS(128),
	.integ_output_size = BYTES_FOR_BITS(96), /* truncated */
	.integ_ikev1_ah_transform = AH_AES_CMAC_96,
};

/*
 * See: https://tools.ietf.org/html/rfc4543
 */

const struct encrypt_desc ike_alg_encrypt_null_integ_aes_gmac = {
	.common = {
		.name = "aes_gmac",
		.fqn = "NULL_AUTH_AES_GMAC",
		.names = { "null_auth_aes_gmac", "aes_gmac", },
		.officname = "NULL_AUTH_AES_GMAC",
		.algo_type = IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_ESP_ID] = ESP_NULL_AUTH_AES_GMAC,
			[IKEv2_ALG_ID] = IKEv2_ENCR_NULL_AUTH_AES_GMAC,
		},
	},
	.enc_blocksize = AES_BLOCK_SIZE,
	.wire_iv_size = 8,
	.pad_to_blocksize = FALSE,
	.salt_size = AES_GCM_SALT_BYTES,
	.keydeflen = AEAD_AES_KEY_DEF_LEN,
	.key_bit_lengths = { 256, 192, 128, },
	.aead_tag_size = 16,
};
