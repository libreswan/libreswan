/*
 * Modular extensions service and registration functions
 *
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 *
 * Michael Richardson <mcr@xelerance.com>
 * Paul Wouters <paul@xelerance.com>
 * Nick Jones <nick.jones@network-box.com>
 *  Copyright (C) 2012  Paul Wouters  <paul@libreswan.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl.txt>.
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

#define __NO_VERSION__
#include <linux/module.h>
#include <linux/kernel.h>       /* printk() */

#include <linux/netdevice.h>    /* struct device, and other headers */
#include <linux/etherdevice.h>  /* eth_type_trans */
#include <linux/ip.h>           /* struct iphdr */
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/types.h>
#include <linux/string.h>       /* memcmp() */
#include <linux/random.h>       /* get_random_bytes() */
#include <linux/errno.h>        /* error codes */
#include <linux/spinlock.h>     /* *lock* */

#include "libreswan/ipsec_param.h"
#include <libreswan.h>
#include "libreswan/ipsec_sa.h"
#include "libreswan/radij.h"
#include "libreswan/ipsec_encap.h"
#include "libreswan/ipsec_radij.h"
#include "libreswan/ipsec_xform.h"
#include "libreswan/ipsec_tunnel.h"
#include "libreswan/ipsec_rcv.h"
#if defined(CONFIG_KLIPS_ESP) || defined(CONFIG_KLIPS_AH)
# include "libreswan/ipsec_ah.h"
#endif /* defined(CONFIG_KLIPS_ESP) || defined(CONFIG_KLIPS_AH) */
#ifdef CONFIG_KLIPS_ESP
# include "libreswan/ipsec_esp.h"
#endif /* !CONFIG_KLIPS_ESP */
#ifdef CONFIG_KLIPS_IPCOMP
# include "libreswan/ipcomp.h"
#endif /* CONFIG_KLIPS_COMP */

#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include "libreswan/ipsec_alg.h"
#include "libreswan/ipsec_proto.h"

#if K_SADB_EALG_MAX < 255
#warning Compiling with limited ESP support ( K_SADB_EALG_MAX < 256 )
#endif

static DEFINE_RWLOCK(ipsec_alg_lock);
#define IPSEC_ALG_HASHSZ        16      /* must be power of 2, even 2^0=1 */
static struct list_head ipsec_alg_hash_table[IPSEC_ALG_HASHSZ];

/*	Old gcc's will fail here        */
#define barf_out(fmt, args ...)  do { struct ipsec_alg *ixtc = \
					      (struct ipsec_alg *)ixt; printk( \
					      KERN_ERR "%s: (%s) " fmt, \
					      __FUNCTION__, ixtc->ixt_name, \
					      ## args) \
				      ; goto out; } while (0)

#ifdef NET_26
/*
 *      Must be already protected by lock
 */
static void __ipsec_alg_usage_inc(struct ipsec_alg *ixt)
{
#ifdef MODULE
	if (ixt->ixt_module)
		try_module_get(ixt->ixt_module);
#endif
	atomic_inc(&ixt->ixt_refcnt);
}
static void __ipsec_alg_usage_dec(struct ipsec_alg *ixt)
{
	atomic_dec(&ixt->ixt_refcnt);
#ifdef MODULE
	if (ixt->ixt_module)
		module_put(ixt->ixt_module);
#endif
}

#else

/*
 *      Must be already protected by lock
 */
static void __ipsec_alg_usage_inc(struct ipsec_alg *ixt)
{
#ifdef MODULE
	if (ixt->ixt_module)
		__MOD_INC_USE_COUNT(ixt->ixt_module);

#endif
	atomic_inc(&ixt->ixt_refcnt);
}
static void __ipsec_alg_usage_dec(struct ipsec_alg *ixt)
{
	atomic_dec(&ixt->ixt_refcnt);
#ifdef MODULE
	if (ixt->ixt_module)
		__MOD_DEC_USE_COUNT(ixt->ixt_module);
#endif
}
#endif

/*
 *      simple hash function, optimized for 0-hash (1 list) special
 *      case
 */
#if IPSEC_ALG_HASHSZ > 1
static inline unsigned ipsec_alg_hashfn(int alg_type, int alg_id)
{
	return (alg_type ^ alg_id) & (IPSEC_ALG_HASHSZ - 1);
}
#else
#define ipsec_alg_hashfn(x, y) (0)
#endif

/*****************************************************************
*
*       INTERNAL table handling: insert, delete, find
*
*****************************************************************/

/*
 *	hash table initialization, called from ipsec_alg_init()
 */
static void ipsec_alg_hash_init(void)
{
	struct list_head *head = ipsec_alg_hash_table;
	int i = IPSEC_ALG_HASHSZ;

	do {
		INIT_LIST_HEAD(head);
		head++;
		i--;
	} while (i);
}
/*
 *      hash list lookup by {alg_type, alg_id} and table head,
 *      must be already protected by lock
 */
static struct ipsec_alg *__ipsec_alg_find(unsigned alg_type, unsigned alg_id,
					  struct list_head * head)
{
	struct list_head *p;
	struct ipsec_alg *ixt = NULL;

	for (p = head->next; p != head; p = p->next) {
		ixt = list_entry(p, struct ipsec_alg, ixt_list);
		if (ixt->ixt_alg_type == alg_type && ixt->ixt_alg_id == alg_id)
			goto out;
	}
	ixt = NULL;
out:
	return ixt;
}
/*
 *      inserts (in front) a new entry in hash table,
 *      called from ipsec_alg_register() when new algorithm is registered.
 */
static int ipsec_alg_insert(struct ipsec_alg *ixt)
{
	int ret = -EINVAL;
	unsigned hashval =
		ipsec_alg_hashfn(ixt->ixt_alg_type, ixt->ixt_alg_id);
	struct list_head *head = ipsec_alg_hash_table + hashval;
	struct ipsec_alg *ixt_cur;

	/*      new element must be virgin ... */
	if (ixt->ixt_list.next != &ixt->ixt_list ||
	    ixt->ixt_list.prev != &ixt->ixt_list) {
		printk(KERN_ERR "ipsec_alg_insert: ixt object \"%s\" "
		       "list head not initialized\n",
		       ixt->ixt_name);
		return ret;
	}
	write_lock_bh(&ipsec_alg_lock);

	ixt_cur = __ipsec_alg_find(ixt->ixt_alg_type, ixt->ixt_alg_id, head);

	/* if previous (current) ipsec_alg found check excl flag of _anyone_ */
	if (ixt_cur &&
	    ((ixt->ixt_state | ixt_cur->ixt_state) & IPSEC_ALG_ST_EXCL)) {
		barf_out("ipsec_alg for alg_type=%d, alg_id=%d already exist. "
			 "Not loaded (ret=%d).\n",
			 ixt->ixt_alg_type,
			 ixt->ixt_alg_id, ret = -EEXIST);
	}
	list_add(&ixt->ixt_list, head);
	ixt->ixt_state |= IPSEC_ALG_ST_REGISTERED;
	ret = 0;
out:
	write_unlock_bh(&ipsec_alg_lock);
	return ret;
}

/*
 *      deletes an existing entry in hash table,
 *      called from ipsec_alg_unregister() when algorithm is unregistered.
 */
static int ipsec_alg_delete(struct ipsec_alg *ixt)
{
	write_lock_bh(&ipsec_alg_lock);
	list_del(&ixt->ixt_list);
	write_unlock_bh(&ipsec_alg_lock);
	return 0;
}

/*
 *      here @user context (read-only when @kernel bh context)
 *      -> no bh disabling
 *
 *      called from ipsec_alg_enc_key_create(), ipsec_alg_auth_key_create()
 *      ipsec_alg_test_encrypt() and ipsec_alg_test_auth()
 */
static struct ipsec_alg *ipsec_alg_get(int alg_type, int alg_id)
{
	unsigned hashval = ipsec_alg_hashfn(alg_type, alg_id);
	struct list_head *head = ipsec_alg_hash_table + hashval;
	struct ipsec_alg *ixt;

	read_lock(&ipsec_alg_lock);
	ixt = __ipsec_alg_find(alg_type, alg_id, head);
	if (ixt)
		__ipsec_alg_usage_inc(ixt);
	read_unlock(&ipsec_alg_lock);

	return ixt;
}

static void ipsec_alg_put(struct ipsec_alg *ixt)
{
	__ipsec_alg_usage_dec((struct ipsec_alg *)ixt);
}

/*****************************************************************
*
*       INTERFACE for ENC services: key creation, encrypt function
*
*****************************************************************/

/*
 *      main encrypt service entry point
 *      called from ipsec_rcv() with encrypt=IPSEC_ALG_DECRYPT and
 *      ipsec_tunnel_start_xmit with encrypt=IPSEC_ALG_ENCRYPT
 */
int ipsec_alg_esp_encrypt(struct ipsec_sa *sa_p, __u8 * idat,
			  int ilen, __u8 * iv, int encrypt)
{
	int ret;
	struct ipsec_alg_enc *ixt_e = sa_p->ips_alg_enc;
	int debug_flag = (encrypt == IPSEC_ALG_ENCRYPT ?
			  debug_tunnel : debug_rcv);

	KLIPS_PRINT(debug_flag,
		    "klips_debug:ipsec_alg_esp_encrypt: "
		    "entering with encalg=%d, ixt_e=%p\n",
		    sa_p->ips_encalg, ixt_e);
	if (ixt_e == NULL) {
		KLIPS_ERROR(debug_flag,
			    "klips_debug:ipsec_alg_esp_encrypt: "
			    "NULL ipsec_alg_enc object\n");
		return -1;
	}
	KLIPS_PRINT(debug_flag,
		    "klips_debug:ipsec_alg_esp_encrypt: "
		    "calling cbc_encrypt encalg=%d "
		    "ips_key_e=%p idat=%p ilen=%d iv=%p, encrypt=%d\n",
		    sa_p->ips_encalg,
		    sa_p->ips_key_e, idat, ilen, iv, encrypt);
	ret = ixt_e->ixt_e_cbc_encrypt(ixt_e, sa_p->ips_key_e, idat,
				       ilen, iv, encrypt);
	KLIPS_PRINT(debug_flag,
		    "klips_debug:ipsec_alg_esp_encrypt: "
		    "returned ret=%d\n",
		    ret);
	return ret;
}

/*
 *      encryption key context creation function
 *      called from pfkey_v2_parser.c:pfkey_ips_init()
 */
int ipsec_alg_enc_key_create(struct ipsec_sa *sa_p)
{
	int ret = 0;
	int keyminbits, keymaxbits;
	caddr_t ekp = NULL;
	struct ipsec_alg_enc *ixt_e =
		(struct ipsec_alg_enc *)ipsec_alg_get(IPSEC_ALG_TYPE_ENCRYPT,
						      sa_p->ips_encalg);

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:ipsec_alg_enc_key_create: "
		    "entering with encalg=%d ixt_e=%p\n",
		    sa_p->ips_encalg, ixt_e);
	if (!ixt_e) {
		KLIPS_ERROR(debug_pfkey,
			    "klips_debug:ipsec_alg_enc_key_create: "
			    "NULL ipsec_alg_enc object\n");
		return -EPROTO;
	}

	/*
	 * grRRR... DES 7bits jurassic stuff ... f*ckk --jjo
	 */
	switch (ixt_e->ixt_common.ixt_support.ias_id) {
	case ESP_3DES:
		keyminbits = keymaxbits = 192;
		break;
	case ESP_DES:
		keyminbits = keymaxbits = 64;
		break;
	default:
		keyminbits = ixt_e->ixt_common.ixt_support.ias_keyminbits;
		keymaxbits = ixt_e->ixt_common.ixt_support.ias_keymaxbits;
	}
	if (sa_p->ips_key_bits_e < keyminbits ||
	    sa_p->ips_key_bits_e > keymaxbits) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:ipsec_alg_enc_key_create: "
			    "incorrect encryption key size for id=%d: %d bits -- "
			    "must be between %d,%d bits\n" /*octets (bytes)\n"*/,
			    ixt_e->ixt_common.ixt_support.ias_id,
			    sa_p->ips_key_bits_e, keyminbits, keymaxbits);
		ret = -EINVAL;
		goto ixt_out;
	}

	if (ixt_e->ixt_e_new_key) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:ipsec_alg_enc_key_create: "
			    "using ixt_e_new_key to generate key\n");

		if ((ekp = ixt_e->ixt_e_new_key(ixt_e,
						sa_p->ips_key_e,
						sa_p->ips_key_bits_e / 8)) ==
		    NULL) {
			ret = -EINVAL;
			goto ixt_out;
		}
	} else if (ixt_e->ixt_e_set_key) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:ipsec_alg_enc_key_create: "
			    "using ixt_e_set_key to generate key context\n");

		if ((ekp = (caddr_t)kmalloc(ixt_e->ixt_e_ctx_size,
					    GFP_ATOMIC)) == NULL) {
			ret = -ENOMEM;
			goto ixt_out;
		}
		/* zero-out key_e */
		memset(ekp, 0, ixt_e->ixt_e_ctx_size);

		/* I cast here to allow more decoupling in alg module */
		KLIPS_PRINT(debug_pfkey,
			    "set_key(key_ctx=%p, key=%p, key_size=%d)\n",
			    ekp, (caddr_t)sa_p->ips_key_e,
			    sa_p->ips_key_bits_e / 8);

		ret = ixt_e->ixt_e_set_key(ixt_e,
					   ekp, (caddr_t)sa_p->ips_key_e,
					   sa_p->ips_key_bits_e / 8);
		if (ret < 0) {
			kfree(ekp);
			goto ixt_out;
		}
	} else {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:ipsec_alg_enc_key_create: "
			    "no function available to generate a key!\n");

		ret = -EPROTO;
		goto ixt_out;
	}

	if (sa_p->ips_key_e) {
		memset(sa_p->ips_key_e, 0, sa_p->ips_key_bits_e / 8);
		kfree(sa_p->ips_key_e);
	}

	sa_p->ips_key_e = ekp;
	sa_p->ips_key_e_size = ixt_e->ixt_e_ctx_size;

	sa_p->ips_alg_enc = ixt_e;
	ixt_e = NULL;

ixt_out:
	if (ixt_e)
		ipsec_alg_put((struct ipsec_alg *)ixt_e);

	return ret;
}

/***************************************************************
*
*       INTERFACE for AUTH services: key creation, hash functions
*
***************************************************************/

/*
 *      auth key context creation function
 *      called from pfkey_v2_parser.c:pfkey_ips_init()
 */
int ipsec_alg_auth_key_create(struct ipsec_sa *sa_p)
{
	int ret = 0;
	int keyminbits, keymaxbits;
	caddr_t akp = NULL;
	struct ipsec_alg_auth *ixt_a = (struct ipsec_alg_auth *)
		ipsec_alg_get(IPSEC_ALG_TYPE_AUTH, sa_p->ips_authalg);

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:ipsec_alg_auth_key_create: "
		    "entering with authalg=%d ixt_a=%p\n",
		    sa_p->ips_authalg, ixt_a);
	if (!ixt_a) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:ipsec_alg_auth_key_create: "
			    "NULL ipsec_alg_auth object\n");
		return -EPROTO;
	}

	keyminbits = ixt_a->ixt_common.ixt_support.ias_keyminbits;
	keymaxbits = ixt_a->ixt_common.ixt_support.ias_keymaxbits;
	if (sa_p->ips_key_bits_a < keyminbits ||
	    sa_p->ips_key_bits_a > keymaxbits) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:ipsec_alg_auth_key_create: incorrect auth"
			    "key size: %d bits -- must be between %d,%d bits\n" /*octets (bytes)\n"*/,
			    sa_p->ips_key_bits_a, keyminbits, keymaxbits);
		ret = -EINVAL;
		goto ixt_out;
	}

	if (ixt_a->ixt_a_hmac_new_key){
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:ipsec_alg_auth_key_create: "
			    "using ixt_a_new_key to generate key\n");
		if ((akp =  ixt_a->ixt_a_hmac_new_key(ixt_a,
						      sa_p->ips_key_a,
						      sa_p->ips_key_bits_a/8)) == NULL) {
		    ret = -ENOMEM;
		    goto ixt_out;
		}
	} else if (ixt_a->ixt_a_hmac_set_key) {
	    /* will hold: 2 ctx and a blocksize buffer: kb */
		if ((akp = (caddr_t)kmalloc(ixt_a->ixt_a_ctx_size,
					    GFP_ATOMIC)) == NULL) {
			ret = -ENOMEM;
			goto ixt_out;
		}
		/* zero-out key_a */
		memset(akp, 0, ixt_a->ixt_a_ctx_size);

		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:ipsec_alg_auth_key_create: about to call:"
			    "hmac_set_key(key_ctx=%p, key=%p, key_size=%d)\n",
			    akp, (caddr_t)sa_p->ips_key_a, sa_p->ips_key_bits_a/8);
		ret = ixt_a->ixt_a_hmac_set_key(ixt_a,
						akp, sa_p->ips_key_a,
						sa_p->ips_key_bits_a / 8); /* XXX XXX */
		if (ret < 0) {
			kfree(akp);
			goto ixt_out;
		}
	} else {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:ipsec_alg_auth_key_create: "
			    "no hmac_set_key function available!\n");
		ret = -EPROTO;
		goto ixt_out;
	}

	if (sa_p->ips_key_a) {
		memset(sa_p->ips_key_a, 0, sa_p->ips_key_bits_a / 8);
		kfree(sa_p->ips_key_a);
	}

	sa_p->ips_key_a = akp;
	sa_p->ips_key_a_size = ixt_a->ixt_a_ctx_size;

	sa_p->ips_auth_bits = ixt_a->ixt_a_keylen * 8; /* XXX XXX */

	sa_p->ips_alg_auth = ixt_a;
	ixt_a = NULL;

ixt_out:
	if (ixt_a)
		ipsec_alg_put((struct ipsec_alg *)ixt_a);

	return ret;
}

int ipsec_alg_sa_esp_hash(const struct ipsec_sa *sa_p, const __u8 *espp,
			  int len, __u8 *hash, int hashlen)
{
	struct ipsec_alg_auth *ixt_a = sa_p->ips_alg_auth;

	if (!ixt_a) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:ipsec_sa_esp_hash: "
			    "NULL ipsec_alg_auth object\n");
		return -EPROTO;
	}
	KLIPS_PRINT(debug_tunnel | debug_rcv,
		    "klips_debug:ipsec_sa_esp_hash: "
		    "hashing %p (%d bytes) to %p (%d bytes)\n",
		    espp, len,
		    hash, hashlen);
	ixt_a->ixt_a_hmac_hash(ixt_a,
			       sa_p->ips_key_a,
			       espp, len,
			       hash, hashlen);
	return 0;
}

int ipsec_alg_sa_ah_hash(const struct ipsec_sa *sa_p, const __u8 *ahp,
			  int len, __u8 *hash, int hashlen)
{
	struct ipsec_alg_auth *ixt_a = sa_p->ips_alg_auth;

	if (!ixt_a) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:ipsec_sa_ah_hash: "
			    "NULL ipsec_alg_auth object\n");
		return -EPROTO;
	}
	KLIPS_PRINT(debug_tunnel | debug_rcv,
		    "klips_debug:ipsec_sa_ah_hash: "
		    "hashing %p (%d bytes) to %p (%d bytes)\n",
		    ahp, len,
		    hash, hashlen);
	ixt_a->ixt_a_hmac_hash(ixt_a,
			       sa_p->ips_key_a,
			       ahp, len,
			       hash, hashlen);
	return 0;
}

/***************************************************************
*
*       INTERFACE for module loading,testing, and unloading
*
***************************************************************/

/* validation for registering (enc) module */
static int check_enc(struct ipsec_alg_enc *ixt)
{
	int ret = -EINVAL;

	if (ixt->ixt_common.ixt_blocksize == 0) /*  || ixt->ixt_common.ixt_blocksize%2) need for ESP_NULL */
		barf_out(KERN_ERR "invalid blocksize=%d\n",
			 ixt->ixt_common.ixt_blocksize);
	if (ixt->ixt_common.ixt_support.ias_keyminbits == 0 &&
	    ixt->ixt_common.ixt_support.ias_keymaxbits == 0 &&
	    ixt->ixt_e_keylen == 0)
		goto zero_key_ok;

	if (ixt->ixt_common.ixt_support.ias_keyminbits == 0)
		barf_out(KERN_ERR "invalid keyminbits=%d\n",
			 ixt->ixt_common.ixt_support.ias_keyminbits);

	if (ixt->ixt_common.ixt_support.ias_keymaxbits == 0)
		barf_out(KERN_ERR "invalid keymaxbits=%d\n",
			 ixt->ixt_common.ixt_support.ias_keymaxbits);

	if (ixt->ixt_e_keylen == 0)
		barf_out(KERN_ERR "invalid keysize=%d\n", ixt->ixt_e_keylen);

zero_key_ok:
	if (ixt->ixt_e_ctx_size == 0 && ixt->ixt_e_new_key == NULL) {
		barf_out(KERN_ERR "invalid key_e_size=%d and ixt_e_new_key=NULL\n",
			ixt->ixt_e_ctx_size);
	}
	if (ixt->ixt_e_cbc_encrypt == NULL)
		barf_out(KERN_ERR "e_cbc_encrypt() must be not NULL\n");
	ret = 0;
out:
	return ret;
}

/* validation for registering (auth) module */
static int check_auth(struct ipsec_alg_auth *ixt)
{
	int ret = -EINVAL;

	if (ixt->ixt_common.ixt_support.ias_id == 0 ||
	    ixt->ixt_common.ixt_support.ias_id > K_SADB_AALG_MAX)
		barf_out("invalid alg_id=%d > %d (K_SADB_AALG_MAX)\n",
			 ixt->ixt_common.ixt_support.ias_id, K_SADB_AALG_MAX);

	if (ixt->ixt_common.ixt_blocksize == 0 ||
	    ixt->ixt_common.ixt_blocksize % 2)
		barf_out(KERN_ERR "invalid blocksize=%d\n",
			 ixt->ixt_common.ixt_blocksize);

	if (ixt->ixt_common.ixt_blocksize > AH_BLKLEN_MAX) {
		barf_out(KERN_ERR "sorry blocksize=%d > %d. "
			 "Please increase AH_BLKLEN_MAX and recompile\n",
			 ixt->ixt_common.ixt_blocksize,
			 AH_BLKLEN_MAX);
	}
	if (ixt->ixt_common.ixt_support.ias_keyminbits == 0 &&
	    ixt->ixt_common.ixt_support.ias_keymaxbits == 0 &&
	    ixt->ixt_a_keylen == 0)
		goto zero_key_ok;
	if (ixt->ixt_common.ixt_support.ias_keyminbits == 0)
		barf_out(KERN_ERR "invalid keyminbits=%d\n",
			 ixt->ixt_common.ixt_support.ias_keyminbits);
	if (ixt->ixt_common.ixt_support.ias_keymaxbits == 0)
		barf_out(KERN_ERR "invalid keymaxbits=%d\n",
			 ixt->ixt_common.ixt_support.ias_keymaxbits);
	if (ixt->ixt_common.ixt_support.ias_keymaxbits !=
	    ixt->ixt_common.ixt_support.ias_keyminbits)
		barf_out(KERN_ERR "keymaxbits must equal keyminbits (not sure).\n");


	if (ixt->ixt_a_keylen == 0)
		barf_out(KERN_ERR "invalid keysize=%d\n", ixt->ixt_a_keylen);
zero_key_ok:
	if (ixt->ixt_a_ctx_size == 0)
		barf_out(KERN_ERR "invalid a_ctx_size=%d\n",
			 ixt->ixt_a_ctx_size);
	if (ixt->ixt_a_hmac_set_key==NULL && ixt->ixt_a_hmac_new_key == NULL)
		barf_out(KERN_ERR "a_hmac_set_key() or a_hmac_new_key() must be not NULL\n");
	if (ixt->ixt_a_hmac_hash == NULL)
		barf_out(KERN_ERR "a_hmac_hash() must be not NULL\n");
	ret = 0;
out:
	return ret;
}

/*
 * Generic (enc, auth) registration entry point
 */
int register_ipsec_alg(struct ipsec_alg *ixt)
{
	int ret = -EINVAL;

	/*	Validation      */
	if (ixt == NULL)
		barf_out("NULL ipsec_alg object passed\n");
	if ((ixt->ixt_version & 0xffffff00) !=
	    (IPSEC_ALG_VERSION & 0xffffff00)) {
		barf_out("incorrect version: %d.%d.%d-%d, "
			 "must be %d.%d.%d[-%d]\n",
			 IPSEC_ALG_VERSION_QUAD(ixt->ixt_version),
			 IPSEC_ALG_VERSION_QUAD(IPSEC_ALG_VERSION));
	}

	switch (ixt->ixt_alg_type) {
	case IPSEC_ALG_TYPE_AUTH:
		if ((ret = check_auth((struct ipsec_alg_auth *)ixt) < 0))
			goto out;
		break;
	case IPSEC_ALG_TYPE_ENCRYPT:
		if ((ret = check_enc((struct ipsec_alg_enc *)ixt) < 0))
			goto out;
		/*
		 * Adapted two lines below:
		 *      ivlen == 0 is possible (NULL enc has blocksize==1)
		 *
		 * fixed NULL support by David De Reu <DeReu@tComLabs.com>
		 */
		if (ixt->ixt_support.ias_ivlen == 0 &&
		    ixt->ixt_blocksize > 1)
			ixt->ixt_support.ias_ivlen = ixt->ixt_blocksize * 8;
		break;
	default:
		barf_out("alg_type=%d not supported\n", ixt->ixt_alg_type);
	}
	INIT_LIST_HEAD(&ixt->ixt_list);
	ret = ipsec_alg_insert(ixt);
	if (ret < 0) {
		barf_out(KERN_WARNING "ipsec_alg for alg_id=%d failed."
			 "Not loaded (ret=%d).\n",
			 ixt->ixt_support.ias_id, ret);
	}

	ret = pfkey_list_insert_supported(
		(struct ipsec_alg_supported *)&ixt->ixt_support,
		&(pfkey_supported_list[
			  K_SADB_SATYPE_ESP]));

	if (ret == 0) {
		ixt->ixt_state |= IPSEC_ALG_ST_SUPP;
		/*	send register event to userspace	*/
		pfkey_register_reply(K_SADB_SATYPE_ESP, NULL);
	} else {
		printk(KERN_ERR "pfkey_list_insert_supported returned %d. "
		       "Loading anyway.\n", ret);
	}
	ret = 0;
out:
	return ret;
}

/*
 *      unregister ipsec_alg object from own tables, if
 *      success => calls pfkey_list_remove_supported()
 */
int unregister_ipsec_alg(struct ipsec_alg *ixt)
{
	int ret = -EINVAL;

	switch (ixt->ixt_alg_type) {
	case IPSEC_ALG_TYPE_AUTH:
	case IPSEC_ALG_TYPE_ENCRYPT:
		break;
	default:
		/*	this is not a typo :) */
		barf_out("frog found in list (\"%s\"): ixt_p=NULL\n",
			 ixt->ixt_name);
	}

	ret = ipsec_alg_delete(ixt);
	if (ixt->ixt_state & IPSEC_ALG_ST_SUPP) {
		ixt->ixt_state &= ~IPSEC_ALG_ST_SUPP;
		pfkey_list_remove_supported(
			(struct ipsec_alg_supported *)&ixt->ixt_support,
			&(pfkey_supported_list[
				  K_SADB_SATYPE_ESP]));

		/*	send register event to userspace	*/
		pfkey_register_reply(K_SADB_SATYPE_ESP, NULL);
	}

out:
	return ret;
}

/*
 *      Must be called from user context
 *      used at module load type for testing algo implementation
 */
static int ipsec_alg_test_encrypt(int enc_alg, int test)
{
	int ret;
	caddr_t buf = NULL;
	int iv_size, keysize, key_e_size;
	struct ipsec_alg_enc *ixt_e;
	void *tmp_key_e = NULL;

#	define BUFSZ   1024
#	define MARGIN  0
#	define test_enc   (buf + MARGIN)
#	define test_dec   (test_enc + BUFSZ + MARGIN)
#	define test_tmp   (test_dec + BUFSZ + MARGIN)
#	define test_key_e (test_tmp + BUFSZ + MARGIN)
#	define test_iv    (test_key_e + key_e_size + MARGIN)
#	define test_key   (test_iv + iv_size + MARGIN)
#	define test_size  (BUFSZ * 3 + key_e_size + iv_size + keysize + \
			    MARGIN * 7)
	ixt_e = (struct ipsec_alg_enc *)ipsec_alg_get(IPSEC_ALG_TYPE_ENCRYPT,
						      enc_alg);
	if (ixt_e == NULL) {
		KLIPS_PRINT(1,
			    "klips_debug: ipsec_alg_test_encrypt: "
			    "encalg=%d object not found\n",
			    enc_alg);
		ret = -EINVAL;
		goto out;
	}
	iv_size = ixt_e->ixt_common.ixt_support.ias_ivlen / 8;
	key_e_size = ixt_e->ixt_e_ctx_size;
	keysize = ixt_e->ixt_e_keylen;
	KLIPS_PRINT(1,
		    "klips_debug: ipsec_alg_test_encrypt: "
		    "enc_alg=%d blocksize=%d key_e_size=%d keysize=%d\n",
		    enc_alg, iv_size, key_e_size, keysize);
	if ((buf = kmalloc(test_size, GFP_KERNEL)) == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	get_random_bytes(test_key, keysize);
	get_random_bytes(test_iv, iv_size);
	if (ixt_e->ixt_e_new_key) {
		tmp_key_e = ixt_e->ixt_e_new_key(ixt_e, test_key, keysize);
		ret = tmp_key_e ? 0 : -EINVAL;
	} else {
		tmp_key_e = test_key_e;
		ret = ixt_e->ixt_e_set_key(ixt_e, test_key_e, test_key,
					     keysize);
	}
	if (ret < 0)
		goto out;
	get_random_bytes(test_enc, BUFSZ);
	memcpy(test_tmp, test_enc, BUFSZ);
	ret = ixt_e->ixt_e_cbc_encrypt(ixt_e, tmp_key_e, test_enc, BUFSZ,
				       test_iv, 1);
	printk(KERN_INFO
	       "klips_info: ipsec_alg_test_encrypt: "
	       "cbc_encrypt=1 ret=%d\n",
	       ret);
	ret = memcmp(test_enc, test_tmp, BUFSZ);
	printk(KERN_INFO
	       "klips_info: ipsec_alg_test_encrypt: "
	       "memcmp(enc, tmp) ret=%d: %s\n", ret,
	       ret != 0 ? "OK. (encr->DIFFers)" : "FAIL! (encr->SAME)" );
	memcpy(test_dec, test_enc, BUFSZ);
	ret = ixt_e->ixt_e_cbc_encrypt(ixt_e, tmp_key_e, test_dec, BUFSZ,
				       test_iv, 0);
	printk(KERN_INFO
	       "klips_info: ipsec_alg_test_encrypt: "
	       "cbc_encrypt=0 ret=%d\n", ret);
	ret = memcmp(test_dec, test_tmp, BUFSZ);
	printk(KERN_INFO
	       "klips_info: ipsec_alg_test_encrypt: "
	       "memcmp(dec,tmp) ret=%d: %s\n", ret,
	       ret == 0 ?
		   "OK. (encr->decr->SAME)" : "FAIL! (encr->decr->DIFFers)" );
	{
		/*	Shamelessly taken from drivers/md sources  O:)  */
		unsigned long now;
		int i, count, max = 0;
		int encrypt, speed;
		for (encrypt = 0; encrypt < 2; encrypt++) {
			for (i = 0; i < 5; i++) {
				now = jiffies;
				count = 0;
				while (jiffies == now) {
					mb();
					ixt_e->ixt_e_cbc_encrypt(ixt_e,
								 tmp_key_e,
								 test_tmp,
								 BUFSZ,
								 test_iv,
								 encrypt);
					mb();
					count++;
					mb();
				}
				if (count > max)
					max = count;
			}
			speed = max * (HZ * BUFSZ / 1024);
			printk(KERN_INFO
			       "klips_info: ipsec_alg_test_encrypt: "
			       "%s %s speed=%d KB/s\n",
			       ixt_e->ixt_common.ixt_name,
			       encrypt ? "encrypt" : "decrypt", speed);
		}
	}
out:
	if (tmp_key_e && ixt_e->ixt_e_destroy_key)
		ixt_e->ixt_e_destroy_key(ixt_e, tmp_key_e);
	if (buf)
		kfree(buf);
	if (ixt_e)
		ipsec_alg_put((struct ipsec_alg *)ixt_e);
	return ret;

#	undef test_enc
#	undef test_dec
#	undef test_tmp
#	undef test_key_e
#	undef test_iv
#	undef test_key
#	undef test_size
}

/*
 *      Must be called from user context
 *      used at module load type for testing algo implementation
 */
static int ipsec_alg_test_auth(int auth_alg, int test)
{
	int ret;
	caddr_t buf = NULL;
	int blocksize, keysize, key_a_size;
	struct ipsec_alg_auth *ixt_a;

	#define BUFSZ   1024
	#define MARGIN  0
	#define test_auth  (buf + MARGIN)
	#define test_key_a (test_auth + BUFSZ + MARGIN)
	#define test_key   (test_key_a + key_a_size + MARGIN)
	#define test_hash  (test_key + keysize + MARGIN)
	#define test_size  (BUFSZ + key_a_size + keysize + AHHMAC_HASHLEN + \
			    MARGIN * 4)
	ixt_a = (struct ipsec_alg_auth *)ipsec_alg_get(IPSEC_ALG_TYPE_AUTH,
						       auth_alg);
	if (ixt_a == NULL) {
		KLIPS_PRINT(1,
			    "klips_debug: ipsec_alg_test_auth: "
			    "encalg=%d object not found\n",
			    auth_alg);
		ret = -EINVAL;
		goto out;
	}
	blocksize = ixt_a->ixt_common.ixt_blocksize;
	key_a_size = ixt_a->ixt_a_ctx_size;
	keysize = ixt_a->ixt_a_keylen;
	KLIPS_PRINT(1,
		    "klips_debug: ipsec_alg_test_auth: "
		    "auth_alg=%d blocksize=%d key_a_size=%d keysize=%d\n",
		    auth_alg, blocksize, key_a_size, keysize);
	if (ixt_a->ixt_a_hmac_new_key){
		get_random_bytes(test_key, keysize);
		if ((buf =  ixt_a->ixt_a_hmac_new_key(ixt_a,
			test_key,
			keysize)) == NULL) {
			ret= -ENOMEM;
			goto out;
		}
	} else {
		if ((buf=kmalloc (test_size, GFP_KERNEL)) == NULL) {
			ret= -ENOMEM;
			goto out;
		}
		get_random_bytes(test_key, keysize);
		ret = ixt_a->ixt_a_hmac_set_key(ixt_a, test_key_a, test_key, keysize);
		if (ret < 0 )
			goto out;
	}
	get_random_bytes(test_auth, BUFSZ);
	ret = ixt_a->ixt_a_hmac_hash(ixt_a, test_key_a, test_auth, BUFSZ,
				     test_hash, AHHMAC_HASHLEN);
	printk(KERN_INFO
	       "klips_info: ipsec_alg_test_auth: "
	       "ret=%d\n", ret);
	{
		/*	Shamelessly taken from drivers/md sources  O:)  */
		unsigned long now;
		int i, count, max = 0;
		int speed;
		for (i = 0; i < 5; i++) {
			now = jiffies;
			count = 0;
			while (jiffies == now) {
				mb();
				ixt_a->ixt_a_hmac_hash(ixt_a, test_key_a,
						       test_auth, BUFSZ,
						       test_hash,
						       AHHMAC_HASHLEN);
				mb();
				count++;
				mb();
			}
			if (count > max)
				max = count;
		}
		speed = max * (HZ * BUFSZ / 1024);
		printk(KERN_INFO
		       "klips_info: ipsec_alg_test_auth: "
		       "%s hash speed=%d KB/s\n",
		       ixt_a->ixt_common.ixt_name,
		       speed);
	}
out:
	if (buf)
		kfree(buf);
	if (ixt_a)
		ipsec_alg_put((struct ipsec_alg *)ixt_a);
	return ret;

#	undef test_auth
#	undef test_key_a
#	undef test_key
#	undef test_hash
#	undef test_size
}

int ipsec_alg_test(unsigned alg_type, unsigned alg_id, int test)
{
	switch (alg_type) {
	case IPSEC_ALG_TYPE_ENCRYPT:
		return ipsec_alg_test_encrypt(alg_id, test);

		break;
	case IPSEC_ALG_TYPE_AUTH:
		return ipsec_alg_test_auth(alg_id, test);

		break;
	}
	printk(KERN_ERR "klips_info: ipsec_alg_test() called incorrectly: "
	       "alg_type=%d alg_id=%d\n",
	       alg_type, alg_id);
	return -EINVAL;
}

int ipsec_alg_init(void)
{
	KLIPS_PRINT(1, "klips_info:ipsec_alg_init: "
		    "KLIPS alg v=%d.%d.%d-%d (EALG_MAX=%d, AALG_MAX=%d)\n",
		    IPSEC_ALG_VERSION_QUAD(IPSEC_ALG_VERSION),
		    K_SADB_EALG_MAX, K_SADB_AALG_MAX);
	/*	Initialize tables */
	write_lock_bh(&ipsec_alg_lock);
	ipsec_alg_hash_init();
	write_unlock_bh(&ipsec_alg_lock);

	/*	Initialize static algos         */
	KLIPS_PRINT(1, "klips_info:ipsec_alg_init: "
		    "calling ipsec_alg_static_init()\n");

#if defined(CONFIG_KLIPS_ENC_AES) && CONFIG_KLIPS_ENC_AES && \
	!defined(CONFIG_KLIPS_ENC_AES_MODULE)
	/* register our own AES code */
	{
		extern int ipsec_aes_init(void);
		ipsec_aes_init();
	}
#endif

#if defined(CONFIG_KLIPS_ENC_3DES) && !defined(CONFIG_KLIPS_ENC_3DES_MODULE)
	/* register our own 3DES code */
	{
		extern int ipsec_3des_init(void);
		ipsec_3des_init();
	}
#endif

	/* If we are doing CryptoAPI, then init */
#if defined(CONFIG_KLIPS_ENC_CRYPTOAPI) && CONFIG_KLIPS_ENC_CRYPTOAPI && \
	!defined(CONFIG_KLIPS_ENC_CRYPTOAPI_MODULE)
	{
		extern int ipsec_cryptoapi_init(void);
		ipsec_cryptoapi_init();
	}
#endif

	return 0;
}

/**********************************************
*
*       INTERFACE for ipsec_sa init and wipe
*
**********************************************/

/*
 *	Called from pluto -> ipsec_sa.c:ipsec_sa_delchain()
 */
int ipsec_alg_sa_wipe(struct ipsec_sa *sa_p)
{
	struct ipsec_alg *ixt;

	if ((ixt = (struct ipsec_alg *)sa_p->ips_alg_enc)) {
		KLIPS_PRINT(debug_pfkey, "klips_debug: ipsec_alg_sa_wipe() :"
			    "unlinking for encalg=%d\n",
			    ixt->ixt_support.ias_id);
		ipsec_alg_put(ixt);
	}
	if ((ixt = (struct ipsec_alg *)sa_p->ips_alg_auth)) {
		KLIPS_PRINT(debug_pfkey, "klips_debug: ipsec_alg_sa_wipe() :"
			    "unlinking for authalg=%d\n",
			    ixt->ixt_support.ias_id);
		ipsec_alg_put(ixt);
	}
	return 0;
}

IPSEC_PROCFS_DEBUG_NO_STATIC
int ipsec_xform_show(struct seq_file *seq, void *offset)
{
	int i;
	struct list_head *head;
	struct ipsec_alg *ixt;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_tncfg_show: seq=%p offset=%p\n", seq, offset);

	for (i=0, head = ipsec_alg_hash_table; i < IPSEC_ALG_HASHSZ; i++, head++) {
		struct list_head *p;
		for (p = head->next; p != head; p = p->next) {
			ixt = list_entry(p, struct ipsec_alg, ixt_list);
			seq_printf(seq, "VERSION=%d TYPE=%d ID=%d NAME=%s REFCNT=%d ",
				   ixt->ixt_version, ixt->ixt_alg_type,
				   ixt->ixt_support.ias_id, ixt->ixt_name,
				   atomic_read(&ixt->ixt_refcnt));
			seq_printf(seq,
				   "STATE=%08x BLOCKSIZE=%d IVLEN=%d "
				   "KEYMINBITS=%d KEYMAXBITS=%d ",
				   ixt->ixt_state, ixt->ixt_blocksize,
				   ixt->ixt_support.ias_ivlen,
				   ixt->ixt_support.ias_keyminbits,
				   ixt->ixt_support.ias_keymaxbits);
			seq_printf(seq,
				   "IVLEN=%d KEYMINBITS=%d KEYMAXBITS=%d ",
				   ixt->ixt_support.ias_ivlen,
				   ixt->ixt_support.ias_keyminbits,
				   ixt->ixt_support.ias_keymaxbits);

			switch (ixt->ixt_alg_type) {
			case IPSEC_ALG_TYPE_AUTH:
			{
				struct ipsec_alg_auth *auth =
					(struct ipsec_alg_auth *)ixt;

				seq_printf(seq,
					   "KEYLEN=%d CTXSIZE=%d AUTHLEN=%d ",
					   auth->ixt_a_keylen,
					   auth->ixt_a_ctx_size,
					   auth->ixt_a_authlen);
				break;
			}
			case IPSEC_ALG_TYPE_ENCRYPT:
			{
				struct ipsec_alg_enc *enc =
					(struct ipsec_alg_enc *)ixt;

				seq_printf(seq,
					   "KEYLEN=%d CTXSIZE=%d ",
					   enc->ixt_e_keylen,
					   enc->ixt_e_ctx_size);
				break;
			}
			}

			seq_printf(seq, "\n");
		}
	}

	return 0;
}

/*
 *      As the author of this module, I ONLY ALLOW using it from
 *      GPL (or same LICENSE TERMS as kernel source) modules.
 *
 *      In respect to hardware crypto engines this means:
 *      * Closed-source device drivers ARE NOT ALLOWED to use
 *        this interface.
 *      * Closed-source VHDL/Verilog firmware running on
 *        the crypto hardware device IS ALLOWED to use this interface
 *        via a GPL (or same LICENSE TERMS as kernel source) device driver.
 *      --Juan Jose Ciarlante 20/03/2002 (thanks RGB for the correct wording)
 */

/*
 *	These symbols can only be used from GPL modules
 *	for now, I'm disabling this because it creates false
 *	symbol problems for old modutils.
 */

#ifdef CONFIG_MODULES
#ifndef NET_26
#if 0
#ifndef EXPORT_SYMBOL_GPL
#undef EXPORT_SYMBOL_GPL
#define EXPORT_SYMBOL_GPL EXPORT_SYMBOL
#endif
#endif
EXPORT_SYMBOL(register_ipsec_alg);
EXPORT_SYMBOL(unregister_ipsec_alg);
EXPORT_SYMBOL(ipsec_alg_test);
#endif
#endif
