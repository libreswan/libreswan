/*
 * ipsec_alg to linux cryptoapi GLUE
 *
 * Authors: CODE.ar TEAM
 *      Harpo MAxx <harpo@linuxmendoza.org.ar>
 *      JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 *      Luciano Ruete <docemeses@softhome.net>
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
 * Example usage:
 *   modinfo -p ipsec_cryptoapi   (quite useful info, including supported algos)
 *   modprobe ipsec_cryptoapi
 *   modprobe ipsec_cryptoapi test=1
 *   modprobe ipsec_cryptoapi excl=1                     (exclusive cipher/algo)
 *   modprobe ipsec_cryptoapi noauto=1  aes=1 twofish=1  (only these ciphers)
 *   modprobe ipsec_cryptoapi aes=128,128                (force these keylens)
 *   modprobe ipsec_cryptoapi des_ede3=0                 (everything but 3DES)
 */
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) && \
	!defined(AUTOCONF_INCLUDED)
#include <linux/config.h>
#endif

/*
 *	special case: ipsec core modular with this static algo inside:
 *	must avoid MODULE magic for this file
 */
#if CONFIG_KLIPS_MODULE && CONFIG_KLIPS_ENC_CRYPTOAPI
#undef MODULE
#endif

#include <linux/module.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0)
# include <linux/moduleparam.h>
#endif
#include <linux/init.h>

#include <linux/kernel.h>       /* printk() */
#include <linux/errno.h>        /* error codes */
#include <linux/types.h>        /* size_t */
#include <linux/string.h>

/* Check if __exit is defined, if not null it */
#ifndef __exit
#define __exit
#endif

/* warn the innocent */
#if !defined (CONFIG_CRYPTO) && !defined (CONFIG_CRYPTO_MODULE)
#warning \
	"No linux CryptoAPI configured, install 2.4.22+ or 2.6.x or enable CryptoAPI"
#define NO_CRYPTOAPI_SUPPORT
#endif

#include "libreswan.h"
#include "libreswan/ipsec_alg.h"
#include "libreswan/ipsec_policy.h"

#include <linux/crypto.h>
#ifdef CRYPTO_API_VERSION_CODE
#warning \
	"Old CryptoAPI is not supported. Only linux-2.4.22+ or linux-2.6.x are supported"
#define NO_CRYPTOAPI_SUPPORT
#endif

#ifdef NO_CRYPTOAPI_SUPPORT
#warning "Building an unusable module :P"
/* Catch old CryptoAPI by not allowing module to load */
IPSEC_ALG_MODULE_INIT_STATIC( ipsec_cryptoapi_init ){
	printk(KERN_WARNING "ipsec_cryptoapi.o was not built on stock Linux CryptoAPI (2.4.22+ or 2.6.x), not loading.\n");
	return -EINVAL;
}
#else
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 0, 0)
#include <linux/scatterlist.h>
#else
#include <asm/scatterlist.h>
#endif
#include <asm/pgtable.h>
#include <linux/mm.h>

/*
 * CryptoAPI compat code - we use the current API and macro back to
 * the older ones.
 */

#ifndef CRYPTO_TFM_MODE_CBC
/*
 * As of linux-2.6.21 this is no longer defined, and presumably no longer
 * needed to be passed into the crypto core code.
 */
#define CRYPTO_TFM_MODE_CBC     0
#define CRYPTO_TFM_MODE_ECB     0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)

static inline void sg_set_page(struct scatterlist *sg,  struct page *page,
			       unsigned int len, unsigned int offset)
{
	sg->page = page;
	sg->offset = offset;
	sg->length = len;
}

static inline void *sg_virt(struct scatterlist *sg)
{
	return page_address(sg->page) + sg->offset;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
#define offset_in_page(p) ((unsigned long)(p) & ~PAGE_MASK)
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19) && \
	!HAVE_BACKPORTED_NEW_CRYPTOAPI
/*
 * Linux 2.6.19 introduced a new Crypto API, setup macro's to convert new
 * API into old API. Some SuSe distributions have backported it.
 */

/* Symmetric/Block Cipher */
struct blkcipher_desc {
	struct crypto_tfm *tfm;
	void *info;
};
	#define ecb(X) \
	#X
	#define cbc(X) \
	#X
	#define crypto_has_blkcipher(X, Y, Z)           crypto_alg_available(X, \
									     0)
	#define crypto_blkcipher_cast(X)                        X
	#define crypto_blkcipher_tfm(X)                         X
	#define crypto_alloc_blkcipher(X, Y, Z)         crypto_alloc_tfm(X, \
									 CRYPTO_TFM_MODE_CBC)
	#define crypto_blkcipher_ivsize(X) \
	crypto_tfm_alg_ivsize(X)
	#define crypto_blkcipher_blocksize(X) \
	crypto_tfm_alg_blocksize(X)
	#define crypto_blkcipher_setkey(X, Y, Z)        crypto_cipher_setkey(X, \
									     Y, \
									     Z)
	#define crypto_blkcipher_encrypt_iv(W, X, Y, Z) \
	crypto_cipher_encrypt_iv((W)->tfm, X, Y, Z, (u8 *)((W)->info))
	#define crypto_blkcipher_decrypt_iv(W, X, Y, Z) \
	crypto_cipher_decrypt_iv((W)->tfm, X, Y, Z, (u8 *)((W)->info))

/* Hash/HMAC/Digest */
struct hash_desc {
	struct crypto_tfm *tfm;
};
	#define hmac(X)                                                 #X
	#define crypto_has_hash(X, Y, Z)                crypto_alg_available(X, \
									     0)
	#define crypto_hash_cast(X)                             X
	#define crypto_hash_tfm(X)                              X
	#define crypto_alloc_hash(X, Y, Z)              crypto_alloc_tfm(X, 0)
	#define crypto_hash_digestsize(X) \
	crypto_tfm_alg_digestsize(X)
	#define crypto_hash_digest(W, X, Y, Z)  \
	crypto_digest_digest((W)->tfm, X, sg_num, Z)

/* Asymmetric Cipher */
	#define crypto_has_cipher(X, Y, Z)              crypto_alg_available(X, \
									     0)

/* Compression */
	#define crypto_has_comp(X, Y, Z)                crypto_alg_available(X, \
									     0)
	#define crypto_comp_tfm(X)                              X
	#define crypto_comp_cast(X)                             X
	#define crypto_alloc_comp(X, Y, Z)              crypto_alloc_tfm(X, 0)
#else
	#define ecb(X)  "ecb(" #X ")"
	#define cbc(X)  "cbc(" #X ")"
	#define hmac(X) "hmac(" #X ")"
#endif /* if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19) */

#define CIPHERNAME_NULL         "cipher_null"
#define CIPHERNAME_AES          cbc(aes)
#define CIPHERNAME_3DES         cbc(des3_ede)
#define CIPHERNAME_CAST         cbc(cast5)
#define CIPHERNAME_SERPENT      cbc(serpent)
#define CIPHERNAME_TWOFISH      cbc(twofish)
/* 1DES no longer supported */
#undef CIPHERNAME_1DES

#define DIGESTNAME_MD5          "md5"
#define DIGESTNAME_SHA1         "sha1"

#define ESP_NULL                11
#define ESP_SERPENT             252     /* from ipsec drafts */
#define ESP_TWOFISH             253     /* from ipsec drafts */

MODULE_AUTHOR("Juanjo Ciarlante, Harpo MAxx, Luciano Ruete");
static int debug_crypto = 0;
static int test_crypto = 0;
static int excl_crypto = 0;
static int noauto = 0;
module_param(debug_crypto, int, 0644);
module_param(test_crypto, int, 0644);
module_param(excl_crypto, int, 0644);
module_param(noauto, int, 0644);

MODULE_PARM_DESC(noauto, "Dont try all known algos, just setup enabled ones");

static int cipher_null[] = { -1, -1 };
static int des_ede3[] = { -1, -1 };
static int aes[] = { -1, -1 };
static int cast[] = { -1, -1 };
static int serpent[] = { -1, -1 };
static int twofish[] = { -1, -1 };

module_param_array(cipher_null, int, NULL, 0444);
module_param_array(des_ede3, int, NULL, 0444);
module_param_array(aes, int, NULL, 0444);
module_param_array(cast, int, NULL, 0444);
module_param_array(serpent, int, NULL, 0444);
module_param_array(twofish, int, NULL, 0444);

MODULE_PARM_DESC(cipher_null,
		 "0: disable | 1: force_enable | min,max: dontuse");
MODULE_PARM_DESC(des_ede3, "0: disable | 1: force_enable | min,max: dontuse");
MODULE_PARM_DESC(aes, "0: disable | 1: force_enable | min,max: keybitlens");
MODULE_PARM_DESC(cast, "0: disable | 1: force_enable | min,max: keybitlens");
MODULE_PARM_DESC(serpent,
		 "0: disable | 1: force_enable | min,max: keybitlens");
MODULE_PARM_DESC(twofish,
		 "0: disable | 1: force_enable | min,max: keybitlens");

struct ipsec_alg_capi_cipher {
	const char *ciphername; /* cryptoapi's ciphername */
	unsigned blocksize;
	unsigned short minbits;
	unsigned short maxbits;
	int *parm;                      /* lkm param for this cipher */
	struct ipsec_alg_enc alg;       /* note it's not a pointer */
};

static struct ipsec_alg_capi_cipher alg_capi_carray[] = {
	{ CIPHERNAME_AES,     16, 128, 256, aes,
	  { ixt_common:{ ixt_support:{ ias_id: ESP_AES } } } },
	{ CIPHERNAME_TWOFISH, 16, 128, 256, twofish,
	  { ixt_common:{ ixt_support:{ ias_id: ESP_TWOFISH, } } } },
	{ CIPHERNAME_SERPENT, 16, 128, 256, serpent,
	  { ixt_common:{ ixt_support:{ ias_id: ESP_SERPENT, } } } },
	{ CIPHERNAME_CAST,     8, 128, 128, cast,
	  { ixt_common:{ ixt_support:{ ias_id: ESP_CAST, } } } },
	{ CIPHERNAME_3DES,     8, 192, 192, des_ede3,
	  { ixt_common:{ ixt_support:{ ias_id: ESP_3DES, } } } },
	{ CIPHERNAME_NULL,     1,  0,  0, cipher_null,
	  { ixt_common:{ ixt_support:{ ias_id: ESP_NULL, } } } },
	{ NULL, 0, 0, 0, NULL, {} }
};

#ifdef NOT_YET
struct ipsec_alg_capi_digest {
	const char *digestname;         /* cryptoapi's digestname */
	struct digest_implementation *di;
	struct ipsec_alg_auth alg;      /* note it's not a pointer */
};
static struct ipsec_alg_capi_cipher alg_capi_darray[] = {
	{ DIGESTNAME_MD5,     NULL, { ixt_alg_id: AH_MD5, } },
	{ DIGESTNAME_SHA1,    NULL, { ixt_alg_id: AH_SHA, } },
	{ NULL, NULL, {} }
};
#endif
/*
 *      "generic" linux cryptoapi setup_cipher() function
 */
int setup_cipher(const char *ciphername)
{
	return crypto_has_blkcipher(ciphername, 0, 0);
}

/*
 *      setups ipsec_alg_capi_cipher "hyper" struct components, calling
 *      register_ipsec_alg for cointaned ipsec_alg object
 */
static void _capi_destroy_key(struct ipsec_alg_enc *alg, __u8 *key_e);
static __u8 * _capi_new_key(struct ipsec_alg_enc *alg, const __u8 *key,
			    size_t keylen);
static int _capi_cbc_encrypt(struct ipsec_alg_enc *alg, __u8 * key_e,
			     __u8 * in, int ilen, __u8 * iv, int encrypt);

static int setup_ipsec_alg_capi_cipher(struct ipsec_alg_capi_cipher *cptr)
{
	int ret;

	cptr->alg.ixt_common.ixt_version = IPSEC_ALG_VERSION;
	cptr->alg.ixt_common.ixt_module  = THIS_MODULE;
	atomic_set(&cptr->alg.ixt_common.ixt_refcnt, 0);
	strncpy(cptr->alg.ixt_common.ixt_name, cptr->ciphername,
		sizeof(cptr->alg.ixt_common.ixt_name));

	cptr->alg.ixt_common.ixt_blocksize = cptr->blocksize;
	cptr->alg.ixt_common.ixt_support.ias_keyminbits = cptr->minbits;
	cptr->alg.ixt_common.ixt_support.ias_keymaxbits = cptr->maxbits;
	cptr->alg.ixt_common.ixt_state = 0;
	if (excl_crypto)
		cptr->alg.ixt_common.ixt_state |= IPSEC_ALG_ST_EXCL;
	cptr->alg.ixt_e_keylen =
		cptr->alg.ixt_common.ixt_support.ias_keymaxbits / 8;
	cptr->alg.ixt_e_ctx_size = 0;
	cptr->alg.ixt_common.ixt_support.ias_exttype = IPSEC_ALG_TYPE_ENCRYPT;
	cptr->alg.ixt_e_new_key = _capi_new_key;
	cptr->alg.ixt_e_destroy_key = _capi_destroy_key;
	cptr->alg.ixt_e_cbc_encrypt = _capi_cbc_encrypt;
	cptr->alg.ixt_common.ixt_data = cptr;

	ret = register_ipsec_alg_enc(&cptr->alg);
	printk(KERN_INFO "KLIPS cryptoapi interface: "
	       "alg_type=%d alg_id=%d name=%s "
	       "keyminbits=%d keymaxbits=%d, %s(%d)\n",
	       cptr->alg.ixt_common.ixt_support.ias_exttype,
	       cptr->alg.ixt_common.ixt_support.ias_id,
	       cptr->alg.ixt_common.ixt_name,
	       cptr->alg.ixt_common.ixt_support.ias_keyminbits,
	       cptr->alg.ixt_common.ixt_support.ias_keymaxbits,
	       ret ? "not found" : "found", ret);
	return ret;
}
/*
 *      called in ipsec_sa_wipe() time, will destroy key contexts
 *      and do 1 unbind()
 */
static void _capi_destroy_key(struct ipsec_alg_enc *alg, __u8 *key_e)
{
	struct crypto_tfm *tfm = (struct crypto_tfm*)key_e;

	if (debug_crypto > 0)
		printk(KERN_DEBUG "klips_debug: _capi_destroy_key:"
		       "name=%s key_e=%p \n",
		       alg->ixt_common.ixt_name, key_e);
	if (!key_e) {
		printk(KERN_ERR "klips_debug: _capi_destroy_key:"
		       "name=%s NULL key_e!\n",
		       alg->ixt_common.ixt_name);
		return;
	}
	crypto_free_tfm(tfm);
}

/*
 *      create new key context, need alg->ixt_data to know which
 *      (of many) cipher inside this module is the target
 */
static __u8 *_capi_new_key(struct ipsec_alg_enc *alg, const __u8 *key,
			   size_t keylen)
{
	struct ipsec_alg_capi_cipher *cptr;
	struct crypto_tfm *tfm = NULL;

	cptr = alg->ixt_common.ixt_data;
	if (!cptr) {
		printk(KERN_ERR "_capi_new_key(): "
		       "NULL ixt_data (?!) for \"%s\" algo\n",
		       alg->ixt_common.ixt_name);
		goto err;
	}
	if (debug_crypto > 0)
		printk(KERN_DEBUG "klips_debug:_capi_new_key:"
		       "name=%s cptr=%p key=%p keysize=%zd\n",
		       alg->ixt_common.ixt_name, cptr, key, keylen);

	/*
	 *	alloc tfm
	 */
	tfm =
		crypto_blkcipher_tfm(crypto_alloc_blkcipher(cptr->ciphername,
							    0, 0));
	if (!tfm) {
		printk(KERN_ERR "_capi_new_key(): "
		       "NULL tfm for \"%s\" cryptoapi (\"%s\") algo\n",
		       alg->ixt_common.ixt_name, cptr->ciphername);
		goto err;
	}
	if (crypto_blkcipher_setkey(crypto_blkcipher_cast(tfm), key,
				    keylen) < 0) {
		printk(KERN_ERR "_capi_new_key(): "
		       "failed new_key() for \"%s\" cryptoapi algo (keylen=%zd)\n",
		       alg->ixt_common.ixt_name, keylen);
		crypto_free_tfm(tfm);
		tfm = NULL;
	}
err:
	if (debug_crypto > 0)
		printk(KERN_DEBUG "klips_debug:_capi_new_key:"
		       "name=%s key=%p keylen=%zd tfm=%p\n",
		       alg->ixt_common.ixt_name, key, keylen, tfm);
	return (__u8 *) tfm;
}
/*
 *      core encryption function: will use cx->ci to call actual cipher's
 *      cbc function
 */
static int _capi_cbc_encrypt(struct ipsec_alg_enc *alg, __u8 * key_e,
			     __u8 * in, int ilen, __u8 * iv, int encrypt)
{
	int error = 0;
	struct crypto_tfm *tfm = (struct crypto_tfm *)key_e;
	struct scatterlist sg;
	struct blkcipher_desc desc;
	int ivsize = crypto_blkcipher_ivsize(crypto_blkcipher_cast(tfm));
	char ivp[ivsize];

	/* we do not want them copying back the IV in place so copy it */
	memcpy(ivp, iv, ivsize);

	if (debug_crypto > 1)
		printk(KERN_DEBUG "klips_debug:_capi_cbc_encrypt:"
		       "key_e=%p "
		       "in=%p out=%p ilen=%d iv=%p encrypt=%d\n",
		       key_e,
		       in, in, ilen, iv, encrypt);

	memset(&sg, 0, sizeof(sg));
	sg_init_table(&sg, 1);
	sg_set_page(&sg, virt_to_page(in), ilen, offset_in_page(in));

	memset(&desc, 0, sizeof(desc));
	desc.tfm = crypto_blkcipher_cast(tfm);
	desc.info = (void *) &ivp[0];

	if (encrypt)
		error = crypto_blkcipher_encrypt_iv(&desc, &sg, &sg, ilen);
	else
		error = crypto_blkcipher_decrypt_iv(&desc, &sg, &sg, ilen);
	if (debug_crypto > 1)
		printk(KERN_DEBUG "klips_debug:_capi_cbc_encrypt:"
		       "error=%d\n",
		       error);
	return (error < 0) ? error : ilen;
}
/*
 *      main initialization loop: for each cipher in list, do
 *      1) setup cryptoapi cipher else continue
 *      2) register ipsec_alg object
 */
static int setup_cipher_list(struct ipsec_alg_capi_cipher* clist)
{
	struct ipsec_alg_capi_cipher *cptr;

	/* foreach cipher in list ... */
	for (cptr = clist; cptr->ciphername; cptr++) {
		/*
		 * see if cipher has been disabled (0) or
		 * if noauto set and not enabled (1)
		 */
		if (cptr->parm[0] == 0 || (noauto && cptr->parm[0] < 0)) {
			if (debug_crypto > 0)
				printk(KERN_INFO "setup_cipher_list(): "
				       "ciphername=%s skipped at user request: "
				       "noauto=%d parm[0]=%d parm[1]=%d\n",
				       cptr->ciphername,
				       noauto,
				       cptr->parm[0],
				       cptr->parm[1]);
			continue;
		} else {
			if (debug_crypto > 0)
				printk(KERN_INFO "setup_cipher_list(): going to init ciphername=%s: noauto=%d parm[0]=%d parm[1]=%d\n",
					cptr->ciphername,
					noauto,
					cptr->parm[0],
					cptr->parm[1]);
		}
		/*
		 *      use a local ci to avoid touching cptr->ci,
		 *      if register ipsec_alg success then bind cipher
		 */
		if (cptr->alg.ixt_common.ixt_support.ias_name == NULL)
			cptr->alg.ixt_common.ixt_support.ias_name =
				cptr->ciphername;

		if ( setup_cipher(cptr->ciphername) ) {
			if (debug_crypto > 0)
				printk(KERN_DEBUG "klips_debug:"
				       "setup_cipher_list():"
				       "ciphername=%s found\n",
				       cptr->ciphername);

			if (setup_ipsec_alg_capi_cipher(cptr) != 0) {
				printk(KERN_ERR "klips_debug:"
				       "setup_cipher_list():"
				       "ciphername=%s failed ipsec_alg_register\n",
				       cptr->ciphername);
			}
		} else {
			printk(KERN_INFO "KLIPS: lookup for ciphername=%s: not found \n",
				cptr->ciphername);
		}
	}
	return 0;
}
/*
 *      deregister ipsec_alg objects and unbind ciphers
 */
static int unsetup_cipher_list(struct ipsec_alg_capi_cipher* clist)
{
	struct ipsec_alg_capi_cipher *cptr;

	/* foreach cipher in list ... */
	for (cptr = clist; cptr->ciphername; cptr++) {
		if (cptr->alg.ixt_common.ixt_state & IPSEC_ALG_ST_REGISTERED)
			unregister_ipsec_alg_enc(&cptr->alg);
	}
	return 0;
}
/*
 *      test loop for registered algos
 */
static int test_cipher_list(struct ipsec_alg_capi_cipher* clist)
{
	int test_ret;
	struct ipsec_alg_capi_cipher *cptr;

	/* foreach cipher in list ... */
	for (cptr = clist; cptr->ciphername; cptr++) {
		if (cptr->alg.ixt_common.ixt_state & IPSEC_ALG_ST_REGISTERED) {
			test_ret = ipsec_alg_test(
				cptr->alg.ixt_common.ixt_support.ias_exttype,
				cptr->alg.ixt_common.ixt_support.ias_id,
				test_crypto);
			printk("test_cipher_list(alg_type=%d alg_id=%d): test_ret=%d\n",
				cptr->alg.ixt_common.ixt_support.ias_exttype,
				cptr->alg.ixt_common.ixt_support.ias_id,
				test_ret);
		}
	}
	return 0;
}

IPSEC_ALG_MODULE_INIT_STATIC( ipsec_cryptoapi_init ){
	int ret, test_ret;

	if ((ret = setup_cipher_list(alg_capi_carray)) < 0)
		return -EPROTONOSUPPORT;

	if (ret == 0 && test_crypto)
		test_ret = test_cipher_list(alg_capi_carray);
	return ret;
}
IPSEC_ALG_MODULE_EXIT_STATIC( ipsec_cryptoapi_fini ){
	unsetup_cipher_list(alg_capi_carray);
	return;
}
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif

#endif /* NO_CRYPTOAPI_SUPPORT */
