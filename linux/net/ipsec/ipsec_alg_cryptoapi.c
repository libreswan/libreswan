/*
 * ipsec_alg to linux cryptoapi GLUE
 *
 * Authors: CODE.ar TEAM
 *      Harpo MAxx <harpo@linuxmendoza.org.ar>
 *      JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 *      Luciano Ruete <docemeses@softhome.net>
 *      (C) 2017 Richard Guy Briggs <rgb@tricolour.ca>
 *      (C) 2017 Paul Wouters <pwouters@redhat.com>
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
#if defined(CONFIG_KLIPS_MODULE) && defined(CONFIG_KLIPS_ENC_CRYPTOAPI)
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

#include "libreswan/ipsec_kversion.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
# include <crypto/hash.h>
#endif

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
#include "libreswan/ipsec_xform.h"

#include <linux/crypto.h>
#ifdef HAS_SKCIPHER
#include <crypto/skcipher.h>

#define crypto_has_blkcipher    crypto_has_skcipher
#define crypto_alloc_blkcipher  crypto_alloc_skcipher
#define crypto_blkcipher_tfm    crypto_skcipher_tfm
#define crypto_blkcipher_setkey crypto_skcipher_setkey
#define crypto_blkcipher_ivsize crypto_skcipher_ivsize
#define crypto_blkcipher_cast   __crypto_skcipher_cast
#endif /* HAS_SKCIPHER */
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
#ifdef HAS_AHASH
	#define crypto_has_ahash(X, Y, Z) 		crypto_alg_available(X,0)

	#define crypto_alloc_ahash(X, Y, Z)              crypto_alloc_tfm(X, 0)
	#define crypto_ahash_digest(W, X, Y, Z)  crypto_digest_digest((W)->tfm, X, sg_num, Z)
#else
	#define crypto_alloc_hash(X, Y, Z)              crypto_alloc_tfm(X, 0)
	#define crypto_hash_digestsize(X) crypto_tfm_alg_digestsize(X)
	#define crypto_hash_digest(W, X, Y, Z) crypto_digest_digest((W)->tfm, X, sg_num, Z)
#endif
	#define crypto_hash_cast(X)                             X
	#define crypto_hash_tfm(X)                              X

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

#define DIGESTNAME_MD5            "hmac(md5)"
#define DIGESTNAME_SHA            "hmac(sha1)"
#define DIGESTNAME_SHA2_256       "hmac(sha256)"
#define DIGESTNAME_SHA2_256_TRUNC "hmac(sha256)"
#define DIGESTNAME_SHA2_384       "hmac(sha384)"
#define DIGESTNAME_SHA2_512       "hmac(sha512)"

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

MODULE_PARM_DESC(noauto, "Don't try all known algos, just setup enabled ones");

static int cipher_null[] = { -1, -1 };
static int des_ede3[] = { -1, -1 };
static int aes[] = { -1, -1 };
static int cast[] = { -1, -1 };
static int serpent[] = { -1, -1 };
static int twofish[] = { -1, -1 };
static int md5[] = {-1, -1};
static int sha1[] = {-1, -1};
static int sha256[] = {-1, -1};
static int sha512[] = {-1, -1};
static int sha384[] = {-1, -1};

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

struct ipsec_alg_capi_digest {
	const char *digestname;         /* cryptoapi's digestname */
	unsigned blocksize;
	unsigned short minbits;
	unsigned short maxbits;
	unsigned short authlen;
	int *parm;		/* lkm param for this digest */
	struct ipsec_alg_auth alg;      /* note it's not a pointer */
};
static struct ipsec_alg_capi_digest alg_capi_darray[] = {
	{ DIGESTNAME_MD5,             64, 128, 128, 12,    md5, { ixt_common:{ ixt_support:{ ias_id: AH_MD5, }}}},
	{ DIGESTNAME_SHA,             64, 160, 160, 12,   sha1, { ixt_common:{ ixt_support:{ ias_id: AH_SHA, }}}},
	{ DIGESTNAME_SHA2_256,        64, 256, 256, 16, sha256, { ixt_common:{ ixt_support:{ ias_id: AH_SHA2_256,}}}},
	{ DIGESTNAME_SHA2_384,       128, 384, 384, 24, sha384, { ixt_common:{ ixt_support:{ ias_id: AH_SHA2_384,}}}},
	{ DIGESTNAME_SHA2_512,       128, 512, 512, 32, sha512, { ixt_common:{ ixt_support:{ ias_id: AH_SHA2_512,}}}},
	{ DIGESTNAME_SHA2_256_TRUNC,  64, 256, 256, 12, sha256, { ixt_common:{ ixt_support:{ ias_id: AH_SHA2_256_TRUNC,}}}},
	{ NULL, 0, 0, 0, 0, NULL, {} }
};
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
	/* fill_and_terminate(cptr->alg.ixt_common.ixt_name, cptr->ciphername,
	 *	sizeof(cptr->alg.ixt_common.ixt_name));
	 */
	strncpy(cptr->alg.ixt_common.ixt_name, cptr->ciphername,
		sizeof(cptr->alg.ixt_common.ixt_name)-1);
	cptr->alg.ixt_common.ixt_name[sizeof(cptr->alg.ixt_common.ixt_name)-1] = '\0';

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
		       "name=%s key_e=%p\n",
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
	tfm = crypto_blkcipher_tfm(crypto_alloc_blkcipher(cptr->ciphername,
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
#ifdef HAS_SKCIPHER
	SKCIPHER_REQUEST_ON_STACK(req, __crypto_skcipher_cast(tfm));
#else
	struct blkcipher_desc desc;
#endif
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

#ifdef HAS_SKCIPHER
	skcipher_request_set_tfm(req, crypto_blkcipher_cast(tfm));
	skcipher_request_set_callback(req, 0, NULL, NULL);
	skcipher_request_set_crypt(req, &sg, &sg, ilen, (void*)&ivp[0]);

	if (encrypt)
		error = crypto_skcipher_encrypt(req);
	else
		error = crypto_skcipher_decrypt(req);

	skcipher_request_zero(req);
#else
	memset(&desc, 0, sizeof(desc));
	desc.tfm = crypto_blkcipher_cast(tfm);
	desc.info = (void *) &ivp[0];

	if (encrypt)
		error = crypto_blkcipher_encrypt_iv(&desc, &sg, &sg, ilen);
	else
		error = crypto_blkcipher_decrypt_iv(&desc, &sg, &sg, ilen);
#endif
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
static int setup_cipher_list(struct ipsec_alg_capi_cipher *clist)
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
		}
		if (debug_crypto > 0)
			printk(KERN_INFO "setup_cipher_list(): going to init ciphername=%s: noauto=%d parm[0]=%d parm[1]=%d\n",
				cptr->ciphername,
				noauto,
				cptr->parm[0],
				cptr->parm[1]);
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
			printk(KERN_INFO "KLIPS: lookup for ciphername=%s: not found\n",
				cptr->ciphername);
		}
	}
	return 0;
}
/*
 *      deregister ipsec_alg objects and unbind ciphers
 */
static int unsetup_cipher_list(struct ipsec_alg_capi_cipher *clist)
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
static int test_cipher_list(struct ipsec_alg_capi_cipher *clist)
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
/*
 * 	"generic" linux cryptoapi setup_digest() function
 */
int setup_digest(const char *digestname)
{
#ifdef HAS_AHASH
    return crypto_has_ahash(digestname, 0, 0);
#else
    return crypto_has_hash(digestname, 0, 0);
#endif
}
/*
 *      setups ipsec_alg_capi_dgest "hyper" struct components, calling
 *      register_ipsec_alg for cointaned ipsec_alg object
 */
static void _capi_destroy_hmac_key (struct ipsec_alg_auth *alg, __u8 *key_a);
static __u8 * _capi_hmac_new_key(struct ipsec_alg_auth *alg, const __u8 *key, int keylen);
static int _capi_hmac_hash(struct ipsec_alg_auth *alg, __u8 *key_a, const __u8 *dat, int len, __u8 *hash, int hashlen);

static int
setup_ipsec_alg_capi_digest(struct ipsec_alg_capi_digest *dptr)
{
	int ret;
	dptr->alg.ixt_common.ixt_version = IPSEC_ALG_VERSION;
	dptr->alg.ixt_common.ixt_module  = THIS_MODULE;
	atomic_set(& dptr->alg.ixt_common.ixt_refcnt, 0);
	/* fill_and_terminate(dptr->alg.ixt_common.ixt_name, dptr->digestname, sizeof(dptr->alg.ixt_common.ixt_name)); */
	strncpy(dptr->alg.ixt_common.ixt_name, dptr->digestname, sizeof(dptr->alg.ixt_common.ixt_name)-1);
	dptr->alg.ixt_common.ixt_name[sizeof(dptr->alg.ixt_common.ixt_name)-1] = '\0';

	dptr->alg.ixt_common.ixt_blocksize=dptr->blocksize;
	dptr->alg.ixt_common.ixt_support.ias_keyminbits=dptr->minbits;
	dptr->alg.ixt_common.ixt_support.ias_keymaxbits=dptr->maxbits;
	dptr->alg.ixt_common.ixt_support.ias_ivlen=0;
	dptr->alg.ixt_common.ixt_state = 0;
	if (excl_crypto)
		dptr->alg.ixt_common.ixt_state |= IPSEC_ALG_ST_EXCL;
	dptr->alg.ixt_a_keylen=dptr->alg.ixt_common.ixt_support.ias_keymaxbits/8;
	dptr->alg.ixt_a_ctx_size = sizeof(struct crypto_tfm);
	dptr->alg.ixt_a_authlen = dptr->authlen;
	dptr->alg.ixt_common.ixt_support.ias_exttype = IPSEC_ALG_TYPE_AUTH;
	dptr->alg.ixt_a_hmac_new_key = _capi_hmac_new_key;
	dptr->alg.ixt_a_hmac_hash = _capi_hmac_hash;
	dptr->alg.ixt_a_destroy_key = _capi_destroy_hmac_key;
	dptr->alg.ixt_common.ixt_data = dptr;

	ret=register_ipsec_alg_auth(&dptr->alg);
	printk(KERN_INFO "KLIPS cryptoapi interface: "
			"alg_type=%d alg_id=%d name=%s "
			"ctx_size=%d keyminbits=%d keymaxbits=%d, %s(%d)\n",
				dptr->alg.ixt_common.ixt_support.ias_exttype,
				dptr->alg.ixt_common.ixt_support.ias_id,
				dptr->alg.ixt_common.ixt_name,
				dptr->alg.ixt_a_ctx_size,
				dptr->alg.ixt_common.ixt_support.ias_keyminbits,
				dptr->alg.ixt_common.ixt_support.ias_keymaxbits,
	       ret ? "not found" : "found", ret);
	return ret;
}
/*
 *      called in ipsec_sa_wipe() time, will destroy key contexts
 *      and do 1 unbind()
 */
static void
_capi_destroy_hmac_key (struct ipsec_alg_auth *alg, __u8 *key_a)
{
#ifdef HAS_AHASH
	struct crypto_ahash *tfm = (struct crypto_ahash*)key_a;
#else
	struct  crypto_hash *tfm = (struct  crypto_hash*)key_a;
#endif

	if (debug_crypto > 0)
		printk(KERN_DEBUG "klips_debug: _capi_destroy_hmac_key:"
		       "name=%s key_e=%p\n",
		       alg->ixt_common.ixt_name, key_a);
	if (!key_a) {
		printk(KERN_ERR "klips_debug: _capi_destroy_hmac_key:"
		       "name=%s NULL key_e!\n",
		       alg->ixt_common.ixt_name);
		return;
	}

#ifdef HAS_AHASH
	crypto_free_ahash(tfm);
#else
	crypto_free_hash(tfm);
#endif
}
/*
 *      create hash
 *
 */
static __u8 *
_capi_hmac_new_key(struct ipsec_alg_auth *alg, const __u8 *key, int keylen)
{
	struct ipsec_alg_capi_digest *dptr;
#ifdef HAS_AHASH
	struct crypto_ahash *tfm  = NULL;
#else
	struct crypto_hash *tfm  = NULL;
#endif
	int ret = 0;

	dptr = alg->ixt_common.ixt_data;
	if (!dptr) {
		printk(KERN_ERR "_capi_hmac_new_key_auth(): "
		       "NULL ixt_data (?!) for \"%s\" algo\n"
		       , alg->ixt_common.ixt_name);
		goto err;
	}
	if (debug_crypto > 0)
		printk(KERN_DEBUG "klips_debug:_capi_hmac_new_key_auth:"
				"name=%s dptr=%p key=%p keysize=%d\n",
				alg->ixt_common.ixt_name, dptr, key, keylen);
#ifdef HAS_AHASH
	tfm = crypto_alloc_ahash(dptr->digestname, 0, CRYPTO_ALG_ASYNC);
#else
	tfm = crypto_alloc_hash(dptr->digestname, 0, CRYPTO_ALG_ASYNC);
#endif
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "_capi_hmac_new_key_auth(): "
				"NULL hmac for \"%s\" cryptoapi (\"%s\") algo\n"
				, alg->ixt_common.ixt_name, dptr->digestname);
		goto err;
	}
#ifdef HAS_AHASH
	if (crypto_ahash_setkey(tfm, key, keylen)<0)
#else
	if (crypto_hash_setkey(tfm, key, keylen)<0)
#endif
	{
		printk(KERN_ERR "_capi_hmac_new_key_auth(): "
				"failed set_key() for \"%s\" cryptoapi algo (key=%p, keylen=%d, err=%d)\n"
				, alg->ixt_common.ixt_name, key, keylen, ret);
#ifdef HAS_AHASH
		crypto_free_ahash(tfm);
#else
		crypto_free_hash(tfm);
#endif
		tfm=NULL;
		goto err;
	}
err:
	if (debug_crypto > 0)
		printk(KERN_DEBUG "klips_debug:_capi_hmac_new_key:"
				"name=%s key=%p keylen=%d tfm=%p\n",
				alg->ixt_common.ixt_name, key, keylen, tfm);
	return (__u8 *) tfm;
}
/*
 *      core encryption function
 *
 */
static int
_capi_hmac_hash(struct ipsec_alg_auth *alg, __u8 *key_a, const __u8 *dat, int len, __u8 *hash, int hashlen)
{
#ifdef HAS_AHASH
	struct crypto_ahash *tfm = (struct crypto_ahash*)key_a;
	struct ahash_request *req;
#else
	struct crypto_hash *tfm = (struct crypto_hash*)key_a;
	struct hash_desc desc;
#endif
	struct scatterlist sg;
	int ret = 0;
	char hash_buf[512];

	if (debug_crypto > 0)
		printk(KERN_DEBUG "klips_debug: _capi_hmac_hash:"
				"name=%s key_a=%p hash=%p dat=%p len=%d keylen=%d\n",
				alg->ixt_common.ixt_name, key_a, hash, dat, len, hashlen);
	if (!key_a) {
		printk(KERN_ERR "klips_debug: _capi_hmac_hash:"
				"name=%s NULL key_a!\n",
				alg->ixt_common.ixt_name);
		return -1;
	}

	memset(&sg, 0, sizeof(sg));
	sg_init_table(&sg, 1);
	sg_set_buf(&sg, dat, len);

#ifdef HAS_AHASH
	req = ahash_request_alloc(tfm, GFP_ATOMIC);
	if (!req)
		return -1;

	ahash_request_set_callback(req, 0, NULL, NULL);
	ahash_request_set_crypt(req, &sg, hash_buf, len);
	ret = crypto_ahash_digest(req);
#else
	memset(&desc, 0, sizeof(desc));
	desc.tfm = tfm;
	desc.flags = 0;

	ret = crypto_hash_digest(&desc, &sg, len, hash_buf);
#endif
	memcpy(hash, hash_buf, hashlen);
#ifdef HAS_AHASH
	ahash_request_free(req);
#endif
	return ret;
}
 /*
 * 	main initialization loop: for each digest in list, do
 * 	1) setup cryptoapi digest else continue
 * 	2) register ipsec_alg object
 */
static int
setup_digest_list (struct ipsec_alg_capi_digest* dlist)
{
	struct ipsec_alg_capi_digest *dptr;
	/* foreach digest in list ... */
	for (dptr=dlist;dptr->digestname;dptr++) {
		/*
		 * see if digest has been disabled (0) or
		 * if noauto set and not enabled (1)
		 */
		if (dptr->parm[0] == 0 || (noauto && dptr->parm[0] < 0)) {
			if (debug_crypto>0)
				printk(KERN_INFO "setup_digest_list(): "
					"digest=%s skipped at user request: "
					"noauto=%d parm[0]=%d parm[1]=%d\n"
					, dptr->digestname
					, noauto
					, dptr->parm[0]
					, dptr->parm[1]);
			continue;
		}

		if (debug_crypto>0)
			printk(KERN_INFO "setup_digest_list(): going to init digest=%s: noauto=%d parm[0]=%d parm[1]=%d\n"
			, dptr->digestname
			, noauto
			, dptr->parm[0]
			, dptr->parm[1]);

		/*
		 * 	use a local ci to avoid touching dptr->ci,
		 * 	if register ipsec_alg success then bind digest
		 */
		if (dptr->alg.ixt_common.ixt_support.ias_name == NULL) {
			dptr->alg.ixt_common.ixt_support.ias_name = dptr->digestname;
		}

		if (setup_digest(dptr->digestname) ) {
			if (debug_crypto > 0)
				printk(KERN_DEBUG "klips_debug:"
						"setup_digest_list():"
						"digestname=%s found\n"
						, dptr->digestname);

			if (setup_ipsec_alg_capi_digest(dptr) != 0) {
				printk(KERN_ERR "klips_debug:"
				       "setup_digest_list():"
				       "digestname=%s failed ipsec_alg_register\n"
				       , dptr->digestname);
			}
		} else {
			printk(KERN_INFO "KLIPS: lookup for digestname=%s: not found\n",
			       dptr->digestname);
		}
	}
	return 0;
}
/*
 *      deregister ipsec_alg objects and unbind digests
 */
static int
unsetup_digest_list (struct ipsec_alg_capi_digest* dlist)
{
	struct ipsec_alg_capi_digest *dptr;
	/* foreach digest in list ... */
	for (dptr=dlist;dptr->digestname;dptr++) {
		if (dptr->alg.ixt_common.ixt_state & IPSEC_ALG_ST_REGISTERED) {
			unregister_ipsec_alg_auth(&dptr->alg);
		}
	}
	return 0;
}
/*
 *      test loop for registered algos
 */
 static int test_digest_list (struct ipsec_alg_capi_digest* dlist)
{
	int test_ret;
	struct ipsec_alg_capi_digest *dptr;
	/* foreach digest in list ... */
	for (dptr=dlist;dptr->digestname;dptr++) {
		if (dptr->alg.ixt_common.ixt_state & IPSEC_ALG_ST_REGISTERED) {
			test_ret=ipsec_alg_test(
					dptr->alg.ixt_common.ixt_support.ias_exttype,
					dptr->alg.ixt_common.ixt_support.ias_id,
					test_crypto);
			printk("test_digest_list(alg_type=%d alg_id=%d): test_ret=%d\n",
			       dptr->alg.ixt_common.ixt_support.ias_exttype,
			       dptr->alg.ixt_common.ixt_support.ias_id,
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

	if ((ret=setup_digest_list(alg_capi_darray)) < 0)
		return  -EPROTONOSUPPORT;

	if (ret==0 && test_crypto) {
		test_ret=test_digest_list(alg_capi_darray);
	}

	return ret;
}

IPSEC_ALG_MODULE_EXIT_STATIC( ipsec_cryptoapi_fini ){
	unsetup_cipher_list(alg_capi_carray);
	unsetup_digest_list(alg_capi_darray);
}
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif

#endif /* NO_CRYPTOAPI_SUPPORT */
