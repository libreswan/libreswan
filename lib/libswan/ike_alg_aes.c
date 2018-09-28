/*
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2014 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2014-2018 Andrew Cagney <andrew.cagney@gmail.com>
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

#include <blapit.h>		/* for AES_BLOCK_SIZE */

#include "constants.h"		/* for BYTES_FOR_BITS() */
#include "ietf_constants.h"
#include "ike_alg.h"
#include "ike_alg_encrypt_nss_cbc_ops.h"
#include "ike_alg_encrypt_nss_ctr_ops.h"
#include "ike_alg_encrypt_nss_gcm_ops.h"
#include "ike_alg_prf_nss_xcbc_ops.h"
#include "ike_alg_encrypt.h"
#include "ike_alg_integ.h"
#include "ike_alg_prf.h"
#include "sadb.h"

const struct encrypt_desc ike_alg_encrypt_aes_cbc = {
	.common = {
		.name = "aes",
		.fqn = "AES_CBC",
		.names = { "aes", "aes_cbc", },
		.algo_type =   IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_AES_CBC,
			[IKEv1_ESP_ID] = ESP_AES,
			[IKEv2_ALG_ID] = IKEv2_ENCR_AES_CBC,
		},
		.fips = true,
	},
	.nss = {
		.mechanism = CKM_AES_CBC,
	},
	.enc_blocksize = AES_CBC_BLOCK_SIZE,
	.pad_to_blocksize = TRUE,
	.wire_iv_size =       AES_CBC_BLOCK_SIZE,
	.keydeflen =    AES_KEY_DEF_LEN,
	.key_bit_lengths = { 256, 192, 128, },
	.encrypt_ops = &ike_alg_encrypt_nss_cbc_ops,
#ifdef SADB_X_EALG_AESCBC
	.encrypt_sadb_ealg_id = SADB_X_EALG_AESCBC,
#endif
#ifdef SADB_X_EALG_AES
	.encrypt_sadb_ealg_id = SADB_X_EALG_AES,
#endif
	.encrypt_netlink_xfrm_name = "aes",
	.encrypt_tcpdump_name = "aes",
	.encrypt_ike_audit_name = "aes",
	.encrypt_kernel_audit_name = "AES",
};

const struct encrypt_desc ike_alg_encrypt_aes_ctr =
{
	.common = {
		.name = "aes_ctr",
		.fqn = "AES_CTR",
		.names = { "aesctr", "aes_ctr", },
		.algo_type =   IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = OAKLEY_AES_CTR,
			[IKEv1_ESP_ID] = ESP_AES_CTR,
			[IKEv2_ALG_ID] = IKEv2_ENCR_AES_CTR,
		},
		.fips = true,
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
	.encrypt_ops = &ike_alg_encrypt_nss_ctr_ops,
#ifdef SADB_X_EALG_AESCTR
	.encrypt_sadb_ealg_id = SADB_X_EALG_AESCTR,
#endif
	.encrypt_netlink_xfrm_name = "rfc3686(ctr(aes))",
	.encrypt_tcpdump_name = "aes_ctr",
	.encrypt_ike_audit_name = "aes_ctr",
	.encrypt_kernel_audit_name = "AES_CTR",
};

const struct encrypt_desc ike_alg_encrypt_aes_gcm_8 =
{
	.common = {
		.name = "aes_gcm_8",
		.fqn = "AES_GCM_8",
		.names = { "aes_gcm_8", "aes_gcm_a" },
		/* XXX: aes_gcm_16 has aes_gcm as alias */
		.algo_type =   IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_ESP_ID] = ESP_AES_GCM_8,
			[IKEv2_ALG_ID] = IKEv2_ENCR_AES_GCM_8,
		},
		.fips = true,
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
	.encrypt_ops = &ike_alg_encrypt_nss_gcm_ops,
#ifdef SADB_X_EALG_AES_GCM_ICV8
	.encrypt_sadb_ealg_id = SADB_X_EALG_AES_GCM_ICV8,
#endif
#ifdef SADB_X_EALG_AES_GCM8
	.encrypt_sadb_ealg_id = SADB_X_EALG_AES_GCM8,
#endif
	.encrypt_netlink_xfrm_name = "rfc4106(gcm(aes))",
	.encrypt_tcpdump_name = "aes_gcm",
	.encrypt_ike_audit_name = "aes_gcm",
	.encrypt_kernel_audit_name = "AES_GCM_A",
};

const struct encrypt_desc ike_alg_encrypt_aes_gcm_12 =
{
	.common = {
		.name = "aes_gcm_12",
		.fqn = "AES_GCM_12",
		.names = { "aes_gcm_12", "aes_gcm_b" },
		.algo_type =   IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_ESP_ID] = ESP_AES_GCM_12,
			[IKEv2_ALG_ID] = IKEv2_ENCR_AES_GCM_12,
		},
		.fips = true,
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
	.encrypt_ops = &ike_alg_encrypt_nss_gcm_ops,
#ifdef SADB_X_EALG_AES_GCM_ICV12
	.encrypt_sadb_ealg_id = SADB_X_EALG_AES_GCM_ICV12,
#endif
#ifdef SADB_X_EALG_AES_GCM12
	.encrypt_sadb_ealg_id = SADB_X_EALG_AES_GCM12,
#endif
	.encrypt_netlink_xfrm_name = "rfc4106(gcm(aes))",
	.encrypt_tcpdump_name = "aes_gcm_12",
	.encrypt_ike_audit_name = "aes_gcm_12",
	.encrypt_kernel_audit_name = "AES_GCM_B",
};

const struct encrypt_desc ike_alg_encrypt_aes_gcm_16 =
{
	.common = {
		.name = "aes_gcm_16",
		.fqn = "AES_GCM_16",
		/* aes_gcm_8 has aes_gcm as officname */
		.names = { "aes_gcm", "aes_gcm_16", "aes_gcm_c" },
		.algo_type =  IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_ESP_ID] = ESP_AES_GCM_16,
			[IKEv2_ALG_ID] = IKEv2_ENCR_AES_GCM_16,
		},
		.fips = true,
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
	.encrypt_ops = &ike_alg_encrypt_nss_gcm_ops,
#ifdef SADB_X_EALG_AES_GCM_ICV16
	.encrypt_sadb_ealg_id = SADB_X_EALG_AES_GCM_ICV16,
#endif
#ifdef SADB_X_EALG_AES_GCM16
	.encrypt_sadb_ealg_id = SADB_X_EALG_AES_GCM16,
#endif
	.encrypt_netlink_xfrm_name = "rfc4106(gcm(aes))",
	.encrypt_tcpdump_name = "aes_gcm_16",
	.encrypt_ike_audit_name = "aes_gcm_16",
	.encrypt_kernel_audit_name = "AES_GCM_C",
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
		.algo_type =    IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_ESP_ID] = ESP_AES_CCM_8,
			[IKEv2_ALG_ID] = IKEv2_ENCR_AES_CCM_8,
		},
		.fips = true,
	},
	.enc_blocksize =  AES_BLOCK_SIZE,
	.salt_size = 3,
	.wire_iv_size =  8,
	.pad_to_blocksize = FALSE,
	/* Only 128, 192 and 256 are supported (24 bits KEYMAT for salt not included) */
	.keydeflen =      AEAD_AES_KEY_DEF_LEN,
	.key_bit_lengths = { 256, 192, 128, },
	.aead_tag_size = 8,
#ifdef SADB_X_EALG_AES_CCM_ICV8
	.encrypt_sadb_ealg_id = SADB_X_EALG_AES_CCM_ICV8,
#endif
	.encrypt_netlink_xfrm_name = "rfc4309(ccm(aes))",
	.encrypt_tcpdump_name = "aes_ccm_8",
	.encrypt_ike_audit_name = "aes_ccm_8",
	.encrypt_kernel_audit_name = "AES_CCM_A",
};

const struct encrypt_desc ike_alg_encrypt_aes_ccm_12 =
{
	.common = {
		.name = "aes_ccm_12",
		.fqn = "AES_CCM_12",
		.names = { "aes_ccm_12", "aes_ccm_b" },
		.algo_type =    IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_ESP_ID] = ESP_AES_CCM_12,
			[IKEv2_ALG_ID] = IKEv2_ENCR_AES_CCM_12,
		},
		.fips = true,
	},
	.enc_blocksize =  AES_BLOCK_SIZE,
	.salt_size = 3,
	.wire_iv_size =  8,
	.pad_to_blocksize = FALSE,
	/* Only 128, 192 and 256 are supported (24 bits KEYMAT for salt not included) */
	.keydeflen =      AEAD_AES_KEY_DEF_LEN,
	.key_bit_lengths = { 256, 192, 128, },
	.aead_tag_size = 12,
#ifdef SADB_X_EALG_AES_CCM_ICV12
	.encrypt_sadb_ealg_id = SADB_X_EALG_AES_CCM_ICV12,
#endif
	.encrypt_netlink_xfrm_name = "rfc4309(ccm(aes))",
	.encrypt_tcpdump_name = "aes_ccm_12",
	.encrypt_ike_audit_name = "aes_ccm_12",
	.encrypt_kernel_audit_name = "AES_CCM_B",
};

const struct encrypt_desc ike_alg_encrypt_aes_ccm_16 =
{
	.common = {
		.name = "aes_ccm_16",
		.fqn = "AES_CCM_16",
		.names = { "aes_ccm", "aes_ccm_16", "aes_ccm_c" },
		.algo_type =   IKE_ALG_ENCRYPT,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_ESP_ID] = ESP_AES_CCM_16,
			[IKEv2_ALG_ID] = IKEv2_ENCR_AES_CCM_16,
		},
		.fips = true,
	},
	.enc_blocksize = AES_BLOCK_SIZE,
	.salt_size = 3,
	.wire_iv_size = 8,
	.pad_to_blocksize = FALSE,
	/* Only 128, 192 and 256 are supported (24 bits KEYMAT for salt not included) */
	.keydeflen =     AEAD_AES_KEY_DEF_LEN,
	.key_bit_lengths = { 256, 192, 128, },
	.aead_tag_size = 16,
#ifdef SADB_X_EALG_AES_CCM_ICV16
	.encrypt_sadb_ealg_id = SADB_X_EALG_AES_CCM_ICV16,
#endif
	.encrypt_netlink_xfrm_name = "rfc4309(ccm(aes))",
	.encrypt_tcpdump_name = "aes_ccm_16",
	.encrypt_ike_audit_name = "aes_ccm_16",
	.encrypt_kernel_audit_name = "AES_CCM_C",
};

const struct prf_desc ike_alg_prf_aes_xcbc = {
	.common = {
		.name = "aes_xcbc",
		.fqn = "AES_XCBC",
		.names = { "aes128_xcbc", "aes_xcbc", },
		.algo_type = IKE_ALG_PRF,
		.id = {
			[IKEv1_OAKLEY_ID] = -1,
			[IKEv1_ESP_ID] = -1,
			[IKEv2_ALG_ID] = IKEv2_PRF_AES128_XCBC,
		},
		.fips = true,
	},
	.nss = {
		.mechanism = CKM_AES_ECB,
	},
	.prf_key_size = BYTES_FOR_BITS(128),
	.prf_output_size = BYTES_FOR_BITS(128),
	.prf_ops = &ike_alg_prf_nss_xcbc_ops,
	.prf_ike_audit_name = "aes_xcbc",
};

const struct integ_desc ike_alg_integ_aes_xcbc = {
	.common = {
		.name = "aes_xcbc",
		.fqn = "AES_XCBC_96",
		.names = { "aes_xcbc", "aes128_xcbc", "aes_xcbc_96", "aes128_xcbc_96", },
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
#ifdef USE_XCBC
	.prf = &ike_alg_prf_aes_xcbc,
#endif
#ifdef SADB_X_AALG_AES_XCBC_MAC
	.integ_sadb_aalg_id = SADB_X_AALG_AES_XCBC_MAC,
#endif
	.integ_netlink_xfrm_name = "xcbc(aes)",
	.integ_tcpdump_name = "aes_xcbc",
	.integ_ike_audit_name = "aes_xcbc",
	.integ_kernel_audit_name = "AES_XCBC",
};

const struct integ_desc ike_alg_integ_aes_cmac = {
	.common = {
		.name = "aes_cmac",
		.fqn = "AES_CMAC_96",
		.names = { "aes_cmac", "aes_cmac_96", },
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
#ifdef SADB_X_AALG_AES_CMAC_96
	.integ_sadb_aalg_id = SADB_X_AALG_AES_CMAC_96,
#endif
	.integ_netlink_xfrm_name = "cmac(aes)",
	.integ_tcpdump_name = "aes_cmac",
	.integ_ike_audit_name = "aes_cmac",
	.integ_kernel_audit_name = "AES_CMAC_96",
};

/*
 * See: https://tools.ietf.org/html/rfc4543
 */

const struct encrypt_desc ike_alg_encrypt_null_integ_aes_gmac = {
	.common = {
		.name = "aes_gmac",
		.fqn = "NULL_AUTH_AES_GMAC",
		.names = { "null_auth_aes_gmac", "aes_gmac", },
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
#ifdef SADB_X_EALG_NULL_AUTH_AES_GMAC
	.encrypt_sadb_ealg_id = SADB_X_EALG_NULL_AUTH_AES_GMAC,
#endif
#ifdef SADB_X_EALG_AESGMAC
	.encrypt_sadb_ealg_id = SADB_X_EALG_AESGMAC,
#endif
	.encrypt_netlink_xfrm_name = "rfc4543(gcm(aes))",
	.encrypt_tcpdump_name = "NULL_AUTH_AES_GMAC",
	.encrypt_ike_audit_name = "NULL_AUTH_AES_GMAC",
	.encrypt_kernel_audit_name = "NULL_AUTH_AES_GMAC",
};
