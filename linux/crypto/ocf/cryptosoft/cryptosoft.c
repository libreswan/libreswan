/*
 * An OCF module that uses the linux kernel cryptoapi, based on the
 * original cryptosoft for BSD by Angelos D. Keromytis (angelos@cis.upenn.edu)
 * but is mostly unrecognisable,
 *
 * Written by David McCullough <david_mccullough@au.securecomputing.com>
 * Copyright (C) 2004-2006 David McCullough <david_mccullough@au.securecomputing.com>
 * Copyright (C) 2004-2005 Intel Corporation.
 *
 * LICENSE TERMS
 *
 * The free distribution and use of this software in both source and binary
 * form is allowed (with or without changes) provided that:
 *
 *   1. distributions of this source code include the above copyright
 *      notice, this list of conditions and the following disclaimer;
 *
 *   2. distributions in binary form include the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other associated materials;
 *
 *   3. the copyright holder's name is not used to endorse products
 *      built using this software without specific written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this product
 * may be distributed under the terms of the GNU General Public License (GPL),
 * in which case the provisions of the GPL apply INSTEAD OF those given above.
 *
 * DISCLAIMER
 *
 * This software is provided 'as is' with no explicit or implied warranties
 * in respect of its properties, including, but not limited to, correctness
 * and/or fitness for purpose.
 * ---------------------------------------------------------------------------
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/skbuff.h>
#include <linux/random.h>
#include <linux/uio.h>
#include <asm/scatterlist.h>

#include <crypto/cryptodev.h>

#define offset_in_page(p) ((unsigned long)(p) & ~PAGE_MASK)

/* Software session entry */

#define SW_TYPE_CIPHER	0
#define SW_TYPE_HMAC	1
#define SW_TYPE_AUTH2	2
#define SW_TYPE_HASH	3
#define SW_TYPE_COMP	4

struct swcr_data {
	int					sw_type;
	int					sw_alg;
	struct crypto_tfm	*sw_tfm;
	union {
		struct {
			char sw_key[HMAC_BLOCK_LEN];
			int  sw_klen;
			int  sw_authlen;
		} hmac;
	} u;
	struct swcr_data	*sw_next;
};

static int32_t swcr_id = -1;
module_param(swcr_id, int, 0444);

static struct swcr_data **swcr_sessions = NULL;
static u_int32_t swcr_sesnum = 0;

static	int swcr_process(void *, struct cryptop *, int);
static	int swcr_newsession(void *, u_int32_t *, struct cryptoini *);
static	int swcr_freesession(void *, u_int64_t);

static int debug = 0;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug,
	   "Enable debug");

static void
skb_copy_bits_back(struct sk_buff *skb, int offset, caddr_t cp, int len)
{
	int i;
	if (offset < skb_headlen(skb)) {
		memcpy(skb->data + offset, cp, min_t(int, skb_headlen(skb), len));
		len -= skb_headlen(skb);
		cp += skb_headlen(skb);
	}
	offset -= skb_headlen(skb);
	for (i = 0; len > 0 && i < skb_shinfo(skb)->nr_frags; i++) {
		if (offset < skb_shinfo(skb)->frags[i].size) {
			memcpy(page_address(skb_shinfo(skb)->frags[i].page) +
					skb_shinfo(skb)->frags[i].page_offset,
					cp, min_t(int, skb_shinfo(skb)->frags[i].size, len));
			len -= skb_shinfo(skb)->frags[i].size;
			cp += skb_shinfo(skb)->frags[i].size;
		}
		offset -= skb_shinfo(skb)->frags[i].size;
	}
}

/*
 * Generate a new software session.
 */
static int
swcr_newsession(void *arg, u_int32_t *sid, struct cryptoini *cri)
{
	struct swcr_data **swd;
	u_int32_t i;
	int error;
	char *algo;
	int mode, sw_type;

	dprintk("%s()\n", __FUNCTION__);
	if (sid == NULL || cri == NULL) {
		dprintk("%s,%d - EINVAL\n", __FILE__, __LINE__);
		return EINVAL;
	}

	if (swcr_sessions) {
		for (i = 1; i < swcr_sesnum; i++)
			if (swcr_sessions[i] == NULL)
				break;
	} else
		i = 1;		/* NB: to silence compiler warning */

	if (swcr_sessions == NULL || i == swcr_sesnum) {
		if (swcr_sessions == NULL) {
			i = 1; /* We leave swcr_sessions[0] empty */
			swcr_sesnum = CRYPTO_SW_SESSIONS;
		} else
			swcr_sesnum *= 2;

		swd = kmalloc(swcr_sesnum * sizeof(struct swcr_data *), GFP_ATOMIC);
		if (swd == NULL) {
			/* Reset session number */
			if (swcr_sesnum == CRYPTO_SW_SESSIONS)
				swcr_sesnum = 0;
			else
				swcr_sesnum /= 2;
			dprintk("%s,%d: ENOBUFS\n", __FILE__, __LINE__);
			return ENOBUFS;
		}
		memset(swd, 0, swcr_sesnum * sizeof(struct swcr_data *));

		/* Copy existing sessions */
		if (swcr_sessions) {
			memcpy(swd, swcr_sessions,
			    (swcr_sesnum / 2) * sizeof(struct swcr_data *));
			kfree(swcr_sessions);
		}

		swcr_sessions = swd;
	}

	swd = &swcr_sessions[i];
	*sid = i;

	while (cri) {
		*swd = (struct swcr_data *) kmalloc(sizeof(struct swcr_data),
				GFP_ATOMIC);
		if (*swd == NULL) {
			swcr_freesession(NULL, i);
			dprintk("%s,%d: EINVAL\n", __FILE__, __LINE__);
			return ENOBUFS;
		}
		memset(*swd, 0, sizeof(struct swcr_data));

		algo = NULL;
		mode = 0;
		sw_type = SW_TYPE_CIPHER;

		switch (cri->cri_alg) {
		case CRYPTO_DES_CBC:
			algo = "des";
			mode = CRYPTO_TFM_MODE_CBC;
			break;
		case CRYPTO_3DES_CBC:
			algo = "des3_ede";
			mode = CRYPTO_TFM_MODE_CBC;
			break;
		case CRYPTO_BLF_CBC:
			algo = "blowfish";
			mode = CRYPTO_TFM_MODE_CBC;
			break;
		case CRYPTO_CAST_CBC:
			algo = "cast5";
			mode = CRYPTO_TFM_MODE_CBC;
			break;
		case CRYPTO_SKIPJACK_CBC:
			algo = "skipjack";
			mode = CRYPTO_TFM_MODE_CBC;
			break;
		case CRYPTO_RIJNDAEL128_CBC:
			algo = "aes";
			mode = CRYPTO_TFM_MODE_CBC;
			break;
		case CRYPTO_NULL_CBC:
			algo = "cipher_null";
			mode = CRYPTO_TFM_MODE_CBC;
			cri->cri_klen = 0; /* make it work with crypto API */
			break;

#if defined(CONFIG_CRYPTO_HMAC) || defined(CONFIG_CRYPTO_HMAC_MODULE)
		case CRYPTO_MD5_HMAC:
			algo = "md5";
			sw_type = SW_TYPE_HMAC;
			(*swd)->u.hmac.sw_authlen = 12;
			break;
		case CRYPTO_SHA1_HMAC:
			algo = "sha1";
			sw_type = SW_TYPE_HMAC;
			(*swd)->u.hmac.sw_authlen = 12;
			break;
		case CRYPTO_SHA2_HMAC:
			if (cri->cri_klen == 256)
				algo = "sha256";
			else if (cri->cri_klen == 384)
				algo = "sha384";
			else if (cri->cri_klen == 512)
				algo = "sha512";
			sw_type = SW_TYPE_HMAC;
			break;
		case CRYPTO_NULL_HMAC:
			algo = "digest_null";
			sw_type = SW_TYPE_HMAC;
			break;
		case CRYPTO_RIPEMD160_HMAC:
			algo = "ripemd160";
			sw_type = SW_TYPE_HMAC;
			break;
		case CRYPTO_MD5:
			algo = "md5";
			sw_type = SW_TYPE_HASH;
			(*swd)->u.hmac.sw_authlen = 16;
			break;
		case CRYPTO_SHA1:
			algo = "sha1";
			sw_type = SW_TYPE_HASH;
			(*swd)->u.hmac.sw_authlen = 20;
			break;
#endif /* defined(CONFIG_CRYPTO_HMAC) || defined(CONFIG_CRYPTO_HMAC_MODULE) */

		case CRYPTO_MD5_KPDK:
			algo = "??";
			sw_type = SW_TYPE_AUTH2;
			break;
		case CRYPTO_SHA1_KPDK:
			algo = "??";
			sw_type = SW_TYPE_AUTH2;
			break;
		case CRYPTO_DEFLATE_COMP:
			algo = "deflate";
			sw_type = SW_TYPE_COMP;
			break;
		default:
			break;
		}

		if (!algo || !*algo) {
			printk("cryptosoft: Unknown algo 0x%x\n", cri->cri_alg);
			swcr_freesession(NULL, i);
			return EINVAL;
		}

		dprintk("%s crypto_alloc_tfm(%s, 0x%x)\n", __FUNCTION__, algo, mode);

		(*swd)->sw_tfm = crypto_alloc_tfm(algo, mode);
		if (!(*swd)->sw_tfm) {
			printk("cryptosoft: crypto_alloc_tfm failed(%s,0x%x)\n",algo,mode);
			swcr_freesession(NULL, i);
			return EINVAL;
		}

		if (sw_type == SW_TYPE_CIPHER) {
			if (debug) {
				dprintk("%s key:", __FUNCTION__);
				for (i = 0; i < (cri->cri_klen + 7) / 8; i++)
					dprintk("%s0x%x", (i % 8) ? " " : "\n    ",cri->cri_key[i]);
				dprintk("\n");
			}
			error = crypto_cipher_setkey((*swd)->sw_tfm, cri->cri_key,
					(cri->cri_klen + 7) / 8);
			if (error) {
				printk("cryptosoft: setkey failed %d (crt_flags=0x%x)\n", error,
						(*swd)->sw_tfm->crt_flags);
				swcr_freesession(NULL, i);
				return error;
			}
		} else if (sw_type == SW_TYPE_HMAC || sw_type == SW_TYPE_HASH) {
			(*swd)->u.hmac.sw_klen = (cri->cri_klen + 7) / 8;
			if (HMAC_BLOCK_LEN < (*swd)->u.hmac.sw_klen)
				printk("%s,%d: ERROR ERROR ERROR\n", __FILE__, __LINE__);
			memcpy((*swd)->u.hmac.sw_key, cri->cri_key, (*swd)->u.hmac.sw_klen);
		} else {
			printk("cryptosoft: Unhandled sw_type %d\n", sw_type);
			swcr_freesession(NULL, i);
			return EINVAL;
		}

		(*swd)->sw_alg = cri->cri_alg;
		(*swd)->sw_type = sw_type;

		cri = cri->cri_next;
		swd = &((*swd)->sw_next);
	}
	return 0;
}

/*
 * Free a session.
 */
static int
swcr_freesession(void *arg, u_int64_t tid)
{
	struct swcr_data *swd;
	u_int32_t sid = CRYPTO_SESID2LID(tid);

	dprintk("%s()\n", __FUNCTION__);
	if (sid > swcr_sesnum || swcr_sessions == NULL ||
			swcr_sessions[sid] == NULL) {
		dprintk("%s,%d: EINVAL\n", __FILE__, __LINE__);
		return(EINVAL);
	}

	/* Silently accept and return */
	if (sid == 0)
		return(0);

	while ((swd = swcr_sessions[sid]) != NULL) {
		swcr_sessions[sid] = swd->sw_next;
		if (swd->sw_tfm)
			crypto_free_tfm(swd->sw_tfm);
		kfree(swd);
	}
	return 0;
}

/*
 * Process a software request.
 */
static int
swcr_process(void *arg, struct cryptop *crp, int hint)
{
	struct cryptodesc *crd;
	struct swcr_data *sw;
	u_int32_t lid;
	int type;
#define SCATTERLIST_MAX 16
	struct scatterlist sg[SCATTERLIST_MAX];
	int sg_num, sg_len, skip;
	struct sk_buff *skb = NULL;
	struct uio *uiop = NULL;

	dprintk("%s()\n", __FUNCTION__);
	/* Sanity check */
	if (crp == NULL) {
		dprintk("%s,%d: EINVAL\n", __FILE__, __LINE__);
		return EINVAL;
	}

	crp->crp_etype = 0;

	if (crp->crp_desc == NULL || crp->crp_buf == NULL) {
		dprintk("%s,%d: EINVAL\n", __FILE__, __LINE__);
		crp->crp_etype = EINVAL;
		goto done;
	}

	lid = crp->crp_sid & 0xffffffff;
	if (lid >= swcr_sesnum || lid == 0 || swcr_sessions == NULL ||
			swcr_sessions[lid] == NULL) {
		crp->crp_etype = ENOENT;
		dprintk("%s,%d: ENOENT\n", __FILE__, __LINE__);
		goto done;
	}

	/*
	 * do some error checking outside of the loop for SKB and IOV processing
	 * this leaves us with valid skb or uiop pointers for later
	 */
	if (crp->crp_flags & CRYPTO_F_SKBUF) {
		skb = (struct sk_buff *) crp->crp_buf;
		if (skb_shinfo(skb)->nr_frags >= SCATTERLIST_MAX) {
			printk("%s,%d: %d nr_frags > SCATTERLIST_MAX", __FILE__, __LINE__,
					skb_shinfo(skb)->nr_frags);
			goto done;
		}
	} else if (crp->crp_flags & CRYPTO_F_IOV) {
		uiop = (struct uio *) crp->crp_buf;
		if (uiop->uio_iovcnt > SCATTERLIST_MAX) {
			printk("%s,%d: %d uio_iovcnt > SCATTERLIST_MAX", __FILE__, __LINE__,
					uiop->uio_iovcnt);
			goto done;
		}
	}

	/* Go through crypto descriptors, processing as we go */
	for (crd = crp->crp_desc; crd; crd = crd->crd_next) {
		/*
		 * Find the crypto context.
		 *
		 * XXX Note that the logic here prevents us from having
		 * XXX the same algorithm multiple times in a session
		 * XXX (or rather, we can but it won't give us the right
		 * XXX results). To do that, we'd need some way of differentiating
		 * XXX between the various instances of an algorithm (so we can
		 * XXX locate the correct crypto context).
		 */
		for (sw = swcr_sessions[lid]; sw && sw->sw_alg != crd->crd_alg;
				sw = sw->sw_next)
			;

		/* No such context ? */
		if (sw == NULL) {
			crp->crp_etype = EINVAL;
			dprintk("%s,%d: EINVAL\n", __FILE__, __LINE__);
			goto done;
		}

		skip = crd->crd_skip;

		/*
		 * setup the SG list skip from the start of the buffer
		 */
		memset(sg, 0, sizeof(sg));
		if (crp->crp_flags & CRYPTO_F_SKBUF) {
			int i, len;

			type = CRYPTO_BUF_SKBUF;

			sg_num = 0;
			sg_len = 0;

			if (skip < skb_headlen(skb)) {
				sg[sg_num].page   = virt_to_page(skb->data + skip);
				sg[sg_num].offset = offset_in_page(skb->data + skip);
				len = skb_headlen(skb) - skip;
				if (len + sg_len > crd->crd_len)
					len = crd->crd_len - sg_len;
				sg[sg_num].length = len;
				sg_len += sg[sg_num].length;
				sg_num++;
				skip = 0;
			} else
				skip -= skb_headlen(skb);

			for (i = 0; sg_len < crd->crd_len &&
						i < skb_shinfo(skb)->nr_frags &&
						sg_num < SCATTERLIST_MAX; i++) {
				if (skip < skb_shinfo(skb)->frags[i].size) {
					sg[sg_num].page   = skb_shinfo(skb)->frags[i].page;
					sg[sg_num].offset = skb_shinfo(skb)->frags[i].page_offset +
							skip;
					len = skb_shinfo(skb)->frags[i].size - skip;
					if (len + sg_len > crd->crd_len)
						len = crd->crd_len - sg_len;
					sg[sg_num].length = len;
					sg_len += sg[sg_num].length;
					sg_num++;
					skip = 0;
				} else
					skip -= skb_shinfo(skb)->frags[i].size;
			}
		} else if (crp->crp_flags & CRYPTO_F_IOV) {
			int len;

			type = CRYPTO_BUF_IOV;

			sg_len = 0;
			for (sg_num = 0; sg_len < crd->crd_len &&
					sg_num < uiop->uio_iovcnt &&
					sg_num < SCATTERLIST_MAX; sg_num++) {
				if (skip < uiop->uio_iov[sg_num].iov_len) {
					sg[sg_num].page   =
							virt_to_page(uiop->uio_iov[sg_num].iov_base+skip);
					sg[sg_num].offset =
							offset_in_page(uiop->uio_iov[sg_num].iov_base+skip);
					len = uiop->uio_iov[sg_num].iov_len - skip;
					if (len + sg_len > crd->crd_len)
						len = crd->crd_len - sg_len;
					sg[sg_num].length = len;
					sg_len += sg[sg_num].length;
					skip = 0;
				} else 
					skip -= uiop->uio_iov[sg_num].iov_len;
			}
		} else {
			type = CRYPTO_BUF_CONTIG;
			sg[0].page   = virt_to_page(crp->crp_buf + skip);
			sg[0].offset = offset_in_page(crp->crp_buf + skip);
			sg_len = (crp->crp_ilen - skip);
			if (sg_len > crd->crd_len)
				sg_len = crd->crd_len;
			sg[0].length = sg_len;
			sg_num = 1;
		}


		switch (sw->sw_type) {
		case SW_TYPE_CIPHER: {
			unsigned char iv[64/*FIXME*/];
			unsigned char *ivp = iv;
			int ivsize = crypto_tfm_alg_ivsize(sw->sw_tfm);

			if (sg_len < crypto_tfm_alg_blocksize(sw->sw_tfm)) {
				crp->crp_etype = EINVAL;
				dprintk("%s,%d: EINVAL len %d < %d\n", __FILE__, __LINE__,
						sg_len, crypto_tfm_alg_blocksize(sw->sw_tfm));
				goto done;
			}

			if (ivsize > sizeof(iv)) {
				crp->crp_etype = EINVAL;
				dprintk("%s,%d: EINVAL\n", __FILE__, __LINE__);
				goto done;
			}

			if (crd->crd_flags & CRD_F_KEY_EXPLICIT) {
				int i, error;

				if (debug) {
					dprintk("%s key:", __FUNCTION__);
					for (i = 0; i < (crd->crd_klen + 7) / 8; i++)
						dprintk("%s0x%x", (i % 8) ? " " : "\n    ",
								crd->crd_key[i]);
					dprintk("\n");
				}
				error = crypto_cipher_setkey(sw->sw_tfm, crd->crd_key,
						(crd->crd_klen + 7) / 8);
				if (error) {
					dprintk("cryptosoft: setkey failed %d (crt_flags=0x%x)\n",
							error, sw->sw_tfm->crt_flags);
					crp->crp_etype = -error;
				}
			}

			if (crd->crd_flags & CRD_F_ENCRYPT) { /* encrypt */

				if (crd->crd_flags & CRD_F_IV_EXPLICIT) {
					ivp = crd->crd_iv;
				} else {
					get_random_bytes(ivp, ivsize);
				}
				/*
				 * do we have to copy the IV back to the buffer ?
				 */
				if ((crd->crd_flags & CRD_F_IV_PRESENT) == 0) {
					if (type == CRYPTO_BUF_CONTIG)
						memcpy(crp->crp_buf + crd->crd_inject, ivp, ivsize);
					else if (type == CRYPTO_BUF_SKBUF)
						skb_copy_bits_back(skb, crd->crd_inject, ivp, ivsize);
					else if (type == CRYPTO_BUF_IOV)
						cuio_copyback(uiop,crd->crd_inject,ivsize,(caddr_t)ivp);
				}
				if(sw->sw_tfm->crt_cipher.cit_mode == CRYPTO_TFM_MODE_ECB) {
					printk("can not do cryptoAPI with ECB mode\n");
				} else {
					crypto_cipher_encrypt_iv(sw->sw_tfm,
								 sg, sg,
								 sg_len, ivp);
				}

			} else { /*decrypt */

				if (crd->crd_flags & CRD_F_IV_EXPLICIT) {
					ivp = crd->crd_iv;
				} else {
					if (type == CRYPTO_BUF_CONTIG)
						memcpy(ivp, crp->crp_buf + crd->crd_inject, ivsize);
					else if (type == CRYPTO_BUF_SKBUF)
						skb_copy_bits(skb, crd->crd_inject, ivp, ivsize);
					else if (type == CRYPTO_BUF_IOV)
						cuio_copydata(uiop,crd->crd_inject,ivsize,(caddr_t)ivp);
				}
				if(sw->sw_tfm->crt_cipher.cit_mode == CRYPTO_TFM_MODE_ECB) {
					printk("can not do cryptoAPI with ECB mode\n");
				} else {
					crypto_cipher_decrypt_iv(sw->sw_tfm, sg, sg, sg_len, ivp);
				}
			}
			} break;
		case SW_TYPE_HMAC:
		case SW_TYPE_HASH:
#if defined(CONFIG_CRYPTO_HMAC) || defined(CONFIG_CRYPTO_HMAC_MODULE)
			{
			char result[AALG_MAX_RESULT_LEN];
			int alen;
			/*
			 * if the authlen is set,  use it,  otherwise use the
			 * digest size.
			 */
			if (sw->u.hmac.sw_authlen)
				alen = sw->u.hmac.sw_authlen;
			else
				alen = crypto_tfm_alg_digestsize(sw->sw_tfm);

			/*
			 * make sure that the space we are putting it into
			 * is not bigger than the declared size of the buffer.
			 * this is a sanity check to avoid corruption
			 */
			if(alen > crp->crp_maclen) {
				alen = crp->crp_maclen;
			}
			/*
			 * check we have room for the result,  the IOV option
			 * can have it's own local space,  check for that as well
			 */
			if (crp->crp_ilen - crd->crd_inject < alen &&
					((type != CRYPTO_BUF_IOV || !crp->crp_mac))) {
				dprintk("cryptosoft: EINVAL len=%d, inject=%d digestsize=%d\n",
						crd->crd_skip + sg_len, crd->crd_inject, alen);
				crp->crp_etype = EINVAL;
				goto done;
			}
			memset(result, 0, sizeof(result));
			if (sw->sw_type == SW_TYPE_HMAC)
				crypto_hmac(sw->sw_tfm, sw->u.hmac.sw_key, &sw->u.hmac.sw_klen,
						sg, sg_num, result);
			else /* SW_TYPE_HASH */
				crypto_digest_digest(sw->sw_tfm, sg, sg_num, result);

			if (type == CRYPTO_BUF_CONTIG) {
				memcpy(crp->crp_buf + crd->crd_inject, result, alen);
			} else if (type == CRYPTO_BUF_IOV) {
				if (crp->crp_mac) {
					memcpy(crp->crp_mac, result, alen);
				} else {
					cuio_copyback(uiop, crd->crd_inject, alen, result);
				}
			} else if (type == CRYPTO_BUF_SKBUF) {
				skb_copy_bits_back(skb, crd->crd_inject, result, alen);
			} else
				printk("cryptosoft: unknown buffer type 0x%x\n", type);
			}
#else
			crp->crp_etype = EINVAL;
			goto done;
#endif
			break;

		case SW_TYPE_COMP:
#if 0
			data = allocate contiguous buffer (crp->crp_buf, crd->crd_len)
			if (crd->crd_flags & CRD_F_COMP)
				ret = crypto_comp_compress(sw->sw_tfm, data, len, result, &dlen);
			else
				ret = crypto_comp_decompress(sw->sw_tfm, data, len, result, &dlen);
#endif
			break;

		default:
			/* Unknown/unsupported algorithm */
			dprintk("%s,%d: EINVAL\n", __FILE__, __LINE__);
			crp->crp_etype = EINVAL;
			goto done;
		}
	}

done:
	crypto_done(crp);
	return 0;
}

static int
cryptosoft_init(void)
{
	dprintk("%s(%p)\n", __FUNCTION__, cryptosoft_init);
	swcr_id = crypto_get_driverid(CRYPTOCAP_F_SOFTWARE | CRYPTOCAP_F_SYNC, "cryptosoft");
	if (swcr_id < 0)
		panic("Software crypto device cannot initialize!");

	printk("cryptosoft: registered as device: %d\n", swcr_id);

	crypto_register(swcr_id, CRYPTO_DES_CBC,
	    0, 0, swcr_newsession, swcr_freesession, swcr_process, NULL);
#define	REGISTER(alg) \
	crypto_register(swcr_id, alg, 0,0,NULL,NULL,NULL,NULL)
	REGISTER(CRYPTO_3DES_CBC);
	REGISTER(CRYPTO_BLF_CBC);
	REGISTER(CRYPTO_CAST_CBC);
	REGISTER(CRYPTO_SKIPJACK_CBC);
	REGISTER(CRYPTO_NULL_CBC);
	REGISTER(CRYPTO_MD5);
	REGISTER(CRYPTO_SHA1);
	REGISTER(CRYPTO_MD5_HMAC);
	REGISTER(CRYPTO_SHA1_HMAC);
	REGISTER(CRYPTO_SHA2_HMAC);
	REGISTER(CRYPTO_RIPEMD160_HMAC);
	REGISTER(CRYPTO_NULL_HMAC);
	REGISTER(CRYPTO_MD5_KPDK);
	REGISTER(CRYPTO_SHA1_KPDK);
	REGISTER(CRYPTO_MD5);
	REGISTER(CRYPTO_SHA1);
	REGISTER(CRYPTO_RIJNDAEL128_CBC);
	REGISTER(CRYPTO_DEFLATE_COMP);
#undef REGISTER
	return(0);
}

static void
cryptosoft_exit(void)
{
	dprintk("%s()\n", __FUNCTION__);
	crypto_unregister_all(swcr_id);
	swcr_id = -1;
}

module_init(cryptosoft_init);
module_exit(cryptosoft_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("David McCullough <dmccullough@cyberguard.com>");
MODULE_DESCRIPTION("Cryptosoft (OCF module for kernel crypto)");
