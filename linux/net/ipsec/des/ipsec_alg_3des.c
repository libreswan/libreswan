/*
 * ipsec_alg 3DES cipher stubs
 *
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 *
 * Adapted from ipsec_alg_aes.c by JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 *
 * ipsec_alg_aes.c,v 1.1.2.1 2003/11/21 18:12:23 jjo Exp
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
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) && \
	!defined(AUTOCONF_INCLUDED)
#include <linux/config.h>
#endif
#include <linux/version.h>

/*
 *	special case: ipsec core modular with this static algo inside:
 *	must avoid MODULE magic for this file
 */
#if defined(CONFIG_KLIPS_MODULE) && defined(CONFIG_KLIPS_ENC_3DES)
#undef MODULE
#endif

#include <linux/module.h>
#include <linux/init.h>

#include <linux/kernel.h>       /* printk() */
#include <linux/errno.h>        /* error codes */
#include <linux/types.h>        /* size_t */
#include <linux/string.h>

/*	Low Libreswan header coupling	*/
#include "libreswan/ipsec_xform.h"
#include "libreswan/ipsec_alg.h"
#include "klips-crypto/des.h"
#include "libreswan/ipsec_alg_3des.h"

#define AES_CONTEXT_T aes_context
static int debug_3des = 0;
static int test_3des = 0;
static int excl_3des = 0;

#if defined(CONFIG_KLIPS_ENC_3DES_MODULE)
MODULE_AUTHOR("Michael Richardson <mcr@xelerance.com>");
#ifdef module_param
module_param(debug_3des, int, 0664);
module_param(test_des, int, 0664);
module_param(excl_des, int, 0664);
#else
MODULE_PARM(debug_3des, "i");
MODULE_PARM(test_des, "i");
MODULE_PARM(excl_des, "i");
#endif
#endif

#define ESP_AES_MAC_KEY_SZ      16      /* 128 bit MAC key */
#define ESP_AES_MAC_BLK_LEN     16      /* 128 bit block */

static int _3des_set_key(struct ipsec_alg_enc *alg,
			 __u8 * key_e, const __u8 * key,
			 size_t keysize)
{
	int ret = 0;
	TripleDES_context *ctx = (TripleDES_context*)key_e;

	if (keysize != 192 / 8)
		return EINVAL;

	des_set_key((des_cblock *)(key + DES_KEY_SZ * 0), ctx->s1);
	des_set_key((des_cblock *)(key + DES_KEY_SZ * 1), ctx->s2);
	des_set_key((des_cblock *)(key + DES_KEY_SZ * 2), ctx->s3);

	if (debug_3des > 0) {
		printk(KERN_DEBUG "klips_debug:_3des_set_key:"
		       "ret=%d key_e=%p key=%p keysize=%ld\n",
		       ret, key_e, key, (unsigned long int) keysize);
	}
	return ret;
}

static int _3des_cbc_encrypt(struct ipsec_alg_enc *alg,
			     __u8 * key_e,
			     __u8 * in,
			     int ilen, __u8 * iv,
			     int encrypt)
{
	TripleDES_context *ctx = (TripleDES_context*)key_e;
	des_cblock miv;

	memcpy(&miv, iv, sizeof(miv));

	if (debug_3des > 0) {
		printk(KERN_DEBUG "klips_debug:_3des_cbc_encrypt:"
		       "key_e=%p in=%p ilen=%d iv=%p encrypt=%d\n",
		       key_e, in, ilen, iv, encrypt);
	}

	des_ede3_cbc_encrypt((des_cblock *)in,
			     (des_cblock *)in,
			     ilen,
			     ctx->s1,
			     ctx->s2,
			     ctx->s3,
			     &miv, encrypt);
	return 1;
}

static struct ipsec_alg_enc ipsec_alg_3DES = {
	ixt_common: {   ixt_version:    IPSEC_ALG_VERSION,
			ixt_refcnt:     ATOMIC_INIT(0),
			ixt_name:       "3des",
			ixt_blocksize:  ESP_3DES_CBC_BLK_LEN,
			ixt_support: {
				ias_exttype:    IPSEC_ALG_TYPE_ENCRYPT,
				ias_id:         ESP_3DES,
				//ias_ivlen:      64,
				ias_keyminbits: ESP_3DES_KEY_SZ * 8,
				ias_keymaxbits: ESP_3DES_KEY_SZ * 8,
			}, },
#if defined(MODULE_KLIPS_ENC_3DES_MODULE)
	ixt_module:     THIS_MODULE,
#endif
	ixt_e_keylen:   ESP_3DES_KEY_SZ * 8,
	ixt_e_ctx_size: sizeof(TripleDES_context),
	ixt_e_set_key:  _3des_set_key,
	ixt_e_cbc_encrypt:_3des_cbc_encrypt,
};

#if defined(CONFIG_KLIPS_ENC_3DES_MODULE)
IPSEC_ALG_MODULE_INIT_MOD( ipsec_3des_init )
#else
IPSEC_ALG_MODULE_INIT_STATIC( ipsec_3des_init )
#endif
{
	int ret, test_ret;

	if (excl_3des)
		ipsec_alg_3DES.ixt_common.ixt_state |= IPSEC_ALG_ST_EXCL;
	ret = register_ipsec_alg_enc(&ipsec_alg_3DES);
	printk("ipsec_3des_init(alg_type=%d alg_id=%d name=%s): ret=%d\n",
	       ipsec_alg_3DES.ixt_common.ixt_support.ias_exttype,
	       ipsec_alg_3DES.ixt_common.ixt_support.ias_id,
	       ipsec_alg_3DES.ixt_common.ixt_name,
	       ret);
	if (ret == 0 && test_3des) {
		test_ret = ipsec_alg_test(
			ipsec_alg_3DES.ixt_common.ixt_support.ias_exttype,
			ipsec_alg_3DES.ixt_common.ixt_support.ias_id,
			test_3des);
		printk("ipsec_3des_init(alg_type=%d alg_id=%d): test_ret=%d\n",
		       ipsec_alg_3DES.ixt_common.ixt_support.ias_exttype,
		       ipsec_alg_3DES.ixt_common.ixt_support.ias_id,
		       test_ret);
	}
	return ret;
}

#if defined(CONFIG_KLIPS_ENC_3DES_MODULE)
IPSEC_ALG_MODULE_EXIT_MOD( ipsec_3des_fini )
#else
IPSEC_ALG_MODULE_EXIT_STATIC( ipsec_3des_fini )
#endif
{
	unregister_ipsec_alg_enc(&ipsec_alg_3DES);
}

/* Dual, because 3des code is 4-clause BSD licensed */
#ifdef MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif

