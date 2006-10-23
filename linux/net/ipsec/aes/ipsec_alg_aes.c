/*
 * ipsec_alg AES cipher stubs
 *
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * 
 * ipsec_alg_aes.c,v 1.1.2.1 2003/11/21 18:12:23 jjo Exp
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
 * 	PK:	Pawel Krawczyk <kravietz@aba.krakow.pl>
 * Fixes list:
 * 	PK:	make XCBC comply with latest draft (keylength)
 *
 */
#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/version.h>

/*	
 *	special case: ipsec core modular with this static algo inside:
 *	must avoid MODULE magic for this file
 */
#if defined(CONFIG_KLIPS_MODULE) && defined(CONFIG_KLIPS_ENC_AES)
#undef MODULE
#endif

#include <linux/module.h>
#include <linux/init.h>

#include <linux/kernel.h> /* printk() */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/string.h>

/* Check if __exit is defined, if not null it */
#ifndef __exit
#define __exit
#endif

/*	Low freeswan header coupling	*/
#include "openswan/ipsec_alg.h"
#include "crypto/aes_cbc.h"

#define CONFIG_KLIPS_ENC_AES_MAC 1

#define AES_CONTEXT_T aes_context
static int debug_aes=0;
static int test_aes=0;
static int excl_aes=0;
static int keyminbits=0;
static int keymaxbits=0;
#if defined(CONFIG_KLIPS_ENC_AES_MODULE)
MODULE_AUTHOR("JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>");
#ifdef module_param
module_param(debug_aes,int,0664);
module_param(test_aes,int,0664);
module_param(excl_aes,int,0664);
module_param(keyminbits,int,0664);
module_param(keymaxbits,int,0664);
#else
MODULE_PARM(debug_aes, "i");
MODULE_PARM(test_aes, "i");
MODULE_PARM(excl_aes, "i");
MODULE_PARM(keyminbits, "i");
MODULE_PARM(keymaxbits, "i");
#endif
#endif

#if CONFIG_KLIPS_ENC_AES_MAC
#include "crypto/aes_xcbc_mac.h"

/*	
 *	Not IANA number yet (draft-ietf-ipsec-ciph-aes-xcbc-mac-00.txt).
 *	We use 9 for non-modular algorithm and none for modular, thus
 *	forcing user to specify one on module load. -kravietz
 */
#ifdef MODULE
static int auth_id=0;
#else
static int auth_id=9;
#endif
#if 0
#ifdef MODULE_PARM
MODULE_PARM(auth_id, "i");
#else
module_param(auth_id,int,0664);
#endif
#endif
#endif

#define ESP_AES			12	/* truely _constant_  :)  */

/* 128, 192 or 256 */
#define ESP_AES_KEY_SZ_MIN	16 	/* 128 bit secret key */
#define ESP_AES_KEY_SZ_MAX	32 	/* 256 bit secret key */
#define ESP_AES_CBC_BLK_LEN	16	/* AES-CBC block size */

/* Values according to draft-ietf-ipsec-ciph-aes-xcbc-mac-02.txt
 * -kravietz
 */
#define ESP_AES_MAC_KEY_SZ	16	/* 128 bit MAC key */
#define ESP_AES_MAC_BLK_LEN	16	/* 128 bit block */

static int _aes_set_key(struct ipsec_alg_enc *alg,
			__u8 * key_e, const __u8 * key,
			size_t keysize)
{
	int ret;
	AES_CONTEXT_T *ctx=(AES_CONTEXT_T*)key_e;
	ret=AES_set_key(ctx, key, keysize)!=0? 0: -EINVAL;
	if (debug_aes > 0)
		printk(KERN_DEBUG "klips_debug:_aes_set_key:"
				"ret=%d key_e=%p key=%p keysize=%ld\n",
                                ret, key_e, key, (unsigned long int) keysize);
	return ret;
}

static int _aes_cbc_encrypt(struct ipsec_alg_enc *alg, __u8 * key_e,
			    __u8 * in, int ilen, const __u8 * iv,
			    int encrypt)
{
	AES_CONTEXT_T *ctx=(AES_CONTEXT_T*)key_e;
	if (debug_aes > 0)
		printk(KERN_DEBUG "klips_debug:_aes_cbc_encrypt:"
				"key_e=%p in=%p ilen=%d iv=%p encrypt=%d\n",
				key_e, in, ilen, iv, encrypt);
	return AES_cbc_encrypt(ctx, in, in, ilen, iv, encrypt);
}
#if CONFIG_KLIPS_ENC_AES_MAC
static int _aes_mac_set_key(struct ipsec_alg_auth *alg, __u8 * key_a, const __u8 * key, int keylen) {
	aes_context_mac *ctxm=(aes_context_mac *)key_a;
	return AES_xcbc_mac_set_key(ctxm, key, keylen)? 0 : -EINVAL;
}
static int _aes_mac_hash(struct ipsec_alg_auth *alg, __u8 * key_a, const __u8 * dat, int len, __u8 * hash, int hashlen) {
	int ret;
	char hash_buf[16];
	aes_context_mac *ctxm=(aes_context_mac *)key_a;
	ret=AES_xcbc_mac_hash(ctxm, dat, len, hash_buf);
	memcpy(hash, hash_buf, hashlen);
	return ret;
}
static struct ipsec_alg_auth ipsec_alg_AES_MAC = {
	ixt_common: { ixt_version:	IPSEC_ALG_VERSION,
		      ixt_refcnt:	ATOMIC_INIT(0),
		      ixt_name: 	"aes_mac",
		      ixt_blocksize:	ESP_AES_MAC_BLK_LEN,
		      ixt_support: {
			ias_exttype:	IPSEC_ALG_TYPE_AUTH,
			ias_id: 	0,
			ias_keyminbits:	ESP_AES_MAC_KEY_SZ*8,
			ias_keymaxbits:	ESP_AES_MAC_KEY_SZ*8,
		},
	},
#if defined(CONFIG_KLIPS_ENC_AES_MODULE)
	ixt_module:	THIS_MODULE,
#endif
	ixt_a_keylen:	ESP_AES_MAC_KEY_SZ,
	ixt_a_ctx_size:	sizeof(aes_context_mac),
	ixt_a_hmac_set_key:	_aes_mac_set_key,
	ixt_a_hmac_hash:_aes_mac_hash,
};
#endif /* CONFIG_KLIPS_ENC_AES_MAC */
static struct ipsec_alg_enc ipsec_alg_AES = {
	ixt_common: { ixt_version:	IPSEC_ALG_VERSION,
		      ixt_refcnt:	ATOMIC_INIT(0),
		      ixt_name: 	"aes",
		      ixt_blocksize:	ESP_AES_CBC_BLK_LEN, 
		      ixt_support: {
			ias_exttype:	IPSEC_ALG_TYPE_ENCRYPT,
			//ias_ivlen:      128,
			ias_id: 	ESP_AES,
			ias_keyminbits:	ESP_AES_KEY_SZ_MIN*8,
			ias_keymaxbits:	ESP_AES_KEY_SZ_MAX*8,
		},
	},
#if defined(CONFIG_KLIPS_ENC_AES_MODULE)
	ixt_module:	THIS_MODULE,
#endif
	ixt_e_keylen:	ESP_AES_KEY_SZ_MAX,
	ixt_e_ctx_size:	sizeof(AES_CONTEXT_T),
	ixt_e_set_key:	_aes_set_key,
	ixt_e_cbc_encrypt:_aes_cbc_encrypt,
};

#if defined(CONFIG_KLIPS_ENC_AES_MODULE)
IPSEC_ALG_MODULE_INIT_MOD( ipsec_aes_init )
#else
IPSEC_ALG_MODULE_INIT_STATIC( ipsec_aes_init )
#endif
{
	int ret, test_ret;

	if (keyminbits)
		ipsec_alg_AES.ixt_common.ixt_support.ias_keyminbits=keyminbits;
	if (keymaxbits) {
		ipsec_alg_AES.ixt_common.ixt_support.ias_keymaxbits=keymaxbits;
		if (keymaxbits*8>ipsec_alg_AES.ixt_common.ixt_support.ias_keymaxbits)
			ipsec_alg_AES.ixt_e_keylen=keymaxbits*8;
	}
	if (excl_aes) ipsec_alg_AES.ixt_common.ixt_state |= IPSEC_ALG_ST_EXCL;
	ret=register_ipsec_alg_enc(&ipsec_alg_AES);
	printk("ipsec_aes_init(alg_type=%d alg_id=%d name=%s): ret=%d\n", 
			ipsec_alg_AES.ixt_common.ixt_support.ias_exttype, 
			ipsec_alg_AES.ixt_common.ixt_support.ias_id, 
			ipsec_alg_AES.ixt_common.ixt_name, 
			ret);
	if (ret==0 && test_aes) {
		test_ret=ipsec_alg_test(
				ipsec_alg_AES.ixt_common.ixt_support.ias_exttype ,
				ipsec_alg_AES.ixt_common.ixt_support.ias_id, 
				test_aes);
		printk("ipsec_aes_init(alg_type=%d alg_id=%d): test_ret=%d\n", 
				ipsec_alg_AES.ixt_common.ixt_support.ias_exttype , 
				ipsec_alg_AES.ixt_common.ixt_support.ias_id, 
				test_ret);
	}
#if CONFIG_KLIPS_ENC_AES_MAC
	if (auth_id!=0){
		int ret;
		ipsec_alg_AES_MAC.ixt_common.ixt_support.ias_id=auth_id;
		ret=register_ipsec_alg_auth(&ipsec_alg_AES_MAC);
		printk("ipsec_aes_init(alg_type=%d alg_id=%d name=%s): ret=%d\n", 
				ipsec_alg_AES_MAC.ixt_common.ixt_support.ias_exttype, 
				ipsec_alg_AES_MAC.ixt_common.ixt_support.ias_id, 
				ipsec_alg_AES_MAC.ixt_common.ixt_name, 
				ret);
		if (ret==0 && test_aes) {
			test_ret=ipsec_alg_test(
					ipsec_alg_AES_MAC.ixt_common.ixt_support.ias_exttype,
					ipsec_alg_AES_MAC.ixt_common.ixt_support.ias_id, 
					test_aes);
			printk("ipsec_aes_init(alg_type=%d alg_id=%d): test_ret=%d\n", 
					ipsec_alg_AES_MAC.ixt_common.ixt_support.ias_exttype, 
					ipsec_alg_AES_MAC.ixt_common.ixt_support.ias_id, 
					test_ret);
		}
	} else {
		printk(KERN_DEBUG "klips_debug: experimental ipsec_alg_AES_MAC not registered [Ok] (auth_id=%d)\n", auth_id);
	}
#endif /* CONFIG_KLIPS_ENC_AES_MAC */
	return ret;
}

#if defined(CONFIG_KLIPS_ENC_AES_MODULE)
IPSEC_ALG_MODULE_EXIT_MOD( ipsec_aes_fini )
#else
IPSEC_ALG_MODULE_EXIT_STATIC( ipsec_aes_fini )
#endif
{
#if CONFIG_KLIPS_ENC_AES_MAC
	if (auth_id) unregister_ipsec_alg_auth(&ipsec_alg_AES_MAC);
#endif /* CONFIG_KLIPS_ENC_AES_MAC */
	unregister_ipsec_alg_enc(&ipsec_alg_AES);
	return;
}
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif

#if 0  /* +NOT_YET */
#ifndef MODULE
/*
 * 	This is intended for static module setups, currently
 * 	doesn't work for modular ipsec.o with static algos inside
 */
static int setup_keybits(const char *str)
{
	unsigned aux;
	char *end;

	aux = simple_strtoul(str,&end,0);
	if (aux != 128 && aux != 192 && aux != 256)
		return 0;
	keyminbits = aux;

	if (*end == 0 || *end != ',')
		return 1;
	str=end+1;
	aux = simple_strtoul(str, NULL, 0);
	if (aux != 128 && aux != 192 && aux != 256)
		return 0;
	if (aux >= keyminbits)
		keymaxbits = aux;
	return 1;
}
__setup("ipsec_aes_keybits=", setup_keybits);
#endif
#endif

