/*
 * IPSEC OCF support
 *
 * This code written by David McCullough <dmccullough@cyberguard.com>
 * Copyright (C) 2005 Intel Corporation.  All Rights Reserved.
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

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) && \
	!defined(AUTOCONF_INCLUDED)
#include <linux/config.h>
#endif

#define __NO_VERSION__
#include <linux/module.h>
#include <linux/kernel.h>       /* printk() */

#include <linux/errno.h>        /* error codes */
#include <linux/types.h>        /* size_t */

#include <linux/interrupt.h>

#include <asm/uaccess.h>
#include <asm/checksum.h>

#include <net/ip.h>

#include <libreswan.h>
#include "libreswan/ipsec_sa.h"
#include "libreswan/ipsec_rcv.h"
#include "libreswan/ipsec_xmit.h"
#include "libreswan/ipsec_tunnel.h"
#include "libreswan/ipsec_xform.h"
#include "libreswan/ipsec_auth.h"
#include "libreswan/ipsec_esp.h"
#include "libreswan/ipsec_ah.h"
#include "libreswan/ipcomp.h"
#include "libreswan/ipsec_proto.h"

#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include "ipsec_ocf.h"

extern int debug_pfkey;
extern int debug_rcv;

int ipsec_ocf_crid = (CRYPTOCAP_F_HARDWARE | CRYPTOCAP_F_SOFTWARE);

/* tuning params for OCF */

int ipsec_ocf_batch = 1;
module_param(ipsec_ocf_batch, int, 0644);
MODULE_PARM_DESC(ipsec_ocf_batch,
		 "Make OCF queue packets rather than process them immediately");

int ipsec_ocf_cbimm = 1;
module_param(ipsec_ocf_cbimm, int, 0644);
MODULE_PARM_DESC(ipsec_ocf_cbimm,
		 "Does OCF immediately (ie., at irq time) run callbacks or queue and call later");

/*
 * processing on different kernels
 */

#ifdef DECLARE_TASKLET
static struct tasklet_struct ipsec_ocf_task;
static struct sk_buff_head ipsec_ocf_skbq;

static void ipsec_ocf_skbq_process(unsigned long arg)
{
	void (*func)(void *arg);
	void *this;
	struct sk_buff *skb;

	if ((skb = skb_dequeue(&ipsec_ocf_skbq)) != NULL) {
		func = ((void **) (&skb->cb[0]))[0];
		this = ((void **) (&skb->cb[0]))[1];
		(*func)(this);
		/* make sure we run again */
		tasklet_schedule(&ipsec_ocf_task);
	}
}

static void ipsec_ocf_queue_init(void)
{
	skb_queue_head_init(&ipsec_ocf_skbq);
	tasklet_init(&ipsec_ocf_task, ipsec_ocf_skbq_process,
		     0ul);
}

#define ipsec_ocf_queue_task(func, this) \
	((void **) (&(this)->skb->cb[0]))[0] = func; \
	((void **) (&(this)->skb->cb[0]))[1] = this; \
	skb_queue_tail(&ipsec_ocf_skbq, (this)->skb); \
	tasklet_schedule(&ipsec_ocf_task);

#endif

/*
 * convert libreswan values to OCF values
 */

static int ipsec_ocf_compalg(int compalg)
{
	switch (compalg) {
	case IPCOMP_DEFLATE:    return CRYPTO_DEFLATE_COMP;

	case IPCOMP_LZS:        return CRYPTO_LZS_COMP;

		/* ocf does not have these yet... */
#if 0
	case IPCOMP_OUI:
	case IPCOMP_V42BIS:
#endif
	}
	return 0;
}

static int ipsec_ocf_authalg(int authalg)
{
	switch (authalg) {
	case AH_SHA:     return CRYPTO_SHA1_HMAC;

	case AH_SHA2_256: return CRYPTO_SHA2_256_HMAC;

	case AH_SHA2_384: return CRYPTO_SHA2_384_HMAC;

	case AH_SHA2_512: return CRYPTO_SHA2_512_HMAC;

	case AH_MD5:      return CRYPTO_MD5_HMAC;
	}
	return 0;
}

static int ipsec_ocf_encalg(int encalg)
{
	switch (encalg) {
	case ESP_NULL:      return CRYPTO_NULL_CBC;

	case ESP_3DES:      return CRYPTO_3DES_CBC;

	case ESP_AES:       return CRYPTO_AES_CBC;

	case ESP_CAST:      return CRYPTO_CAST_CBC;
	}
	return 0;
}

/*
 * We use this function because sometimes we want to pass a negative offset
 * into skb_put(), this does not work on 64bit platforms because long to
 * unsigned int casting.
 */
static inline unsigned char *safe_skb_put(struct sk_buff *skb, int extend)
{
	unsigned char *ptr;

	if (extend > 0) {
		/* increase the size of the packet */
		ptr = skb_put(skb, extend);
	} else {
		/* shrink the size of the packet */
		ptr = skb_tail_pointer(skb);
		skb_trim(skb, skb->len + extend);
	}

	return ptr;
}

/*
 * We need to grow the skb to accommodate the expanssion of the ipcomp packet.
 *
 * The following comment comes from the skb_decompress() which does the
 * same...
 *
 * We have no way of knowing the exact length of the resulting
 * decompressed output before we have actually done the decompression.
 * For now, we guess that the packet will not be bigger than the
 * attached ipsec device's mtu or 16260, whichever is biggest.
 * This may be wrong, since the sender's mtu may be bigger yet.
 * XXX This must be dealt with later XXX
 */
static int ipsec_ocf_ipcomp_copy_expand(struct ipsec_rcv_state *irs)
{
	struct sk_buff *nskb;
	unsigned grow_to, grow_by;
	ptrdiff_t ptr_delta;

	if (!irs->skb)
		return IPSEC_RCV_IPCOMPFAILED;

	if (irs->skb->dev) {
		grow_to = irs->skb->dev->mtu <
			  16260 ? 16260 : irs->skb->dev->mtu;
	} else {
		int tot_len;
		if (lsw_ip_hdr_version(irs) == 6)
			tot_len = ntohs(lsw_ip6_hdr(irs)->payload_len) +
				  sizeof(struct ipv6hdr);
		else
			tot_len = ntohs(lsw_ip4_hdr(irs)->tot_len);
		grow_to = 65520 - tot_len;
	}
	grow_by = grow_to - irs->skb->len;
	grow_by -= skb_headroom(irs->skb);
	grow_by -= skb_tailroom(irs->skb);

	/* it's big enough */
	if (!grow_by)
		return IPSEC_RCV_OK;

	nskb = skb_copy_expand(irs->skb, skb_headroom(irs->skb),
			       skb_tailroom(irs->skb) + grow_by, GFP_ATOMIC);
	if (!nskb)
		return IPSEC_RCV_ERRMEMALLOC;

	memcpy(nskb->head, irs->skb->head, skb_headroom(irs->skb));

	skb_set_network_header(nskb,
			       ipsec_skb_offset(irs->skb,
						skb_network_header(irs->skb)));
	skb_set_transport_header(nskb,
				 ipsec_skb_offset(irs->skb,
						  skb_transport_header(
							  irs->skb)));

	/* update all irs pointers */
	ptr_delta = nskb->data - irs->skb->data;
	irs->authenticator = (void*)((char*)irs->authenticator + ptr_delta);
	irs->iph           = (void*)((char*)irs->iph           + ptr_delta);

	/* flip in the large one */
	irs->pre_ipcomp_skb = irs->skb;
	irs->skb = nskb;

	/* move the tail up to the end to let OCF know how big the buffer is */
	if (grow_by > (irs->skb->end - irs->skb->tail))
		grow_by = irs->skb->end - irs->skb->tail;
	skb_put(irs->skb, grow_by);

	return IPSEC_RCV_OK;
}

/*
 * if we can do the request ops, setup the sessions and return true
 * otherwise return false with ipsp unchanged
 */

int ipsec_ocf_sa_init(struct ipsec_sa *ipsp, int authalg, int encalg)
{
	struct cryptoini crie, cria;
	int error;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:ipsec_ocf_sa_init(a=0x%x,e=0x%x)\n",
		    authalg, encalg);

	if (authalg && ipsp->ips_key_bits_a == 0) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:ipsec_ocf_sa_init(a=0x%x,e=0x%x) a-key-bits=0\n",
			    authalg, encalg);
		/* pretend we are happy with this */
		return 1;
	}

	/* ESP_NULL is a special case,  no key */
	if (encalg && encalg != ESP_NULL && ipsp->ips_key_bits_e == 0) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:ipsec_ocf_sa_init(a=0x%x,e=0x%x) e-key-bits=0\n",
			    authalg, encalg);
		/* pretend we are happy with this */
		return 1;
	}

	if (ipsp->ocf_in_use)
		printk("KLIPS: ipsec_ocf_sa_init received SA is already initted?\n");


	memset(&crie, 0, sizeof(crie));
	memset(&cria, 0, sizeof(cria));

	cria.cri_alg = ipsec_ocf_authalg(authalg);
	cria.cri_klen = ipsp->ips_key_bits_a;
	cria.cri_key  = ipsp->ips_key_a;
	cria.cri_mlen = 12;

	crie.cri_alg = ipsec_ocf_encalg(encalg);
	crie.cri_klen = ipsp->ips_key_bits_e;
	crie.cri_key  = ipsp->ips_key_e;
	switch (crie.cri_alg) {
	case CRYPTO_AES_CBC:
		ipsp->ips_iv_size = 16;
		break;
	case CRYPTO_3DES_CBC:
		ipsp->ips_iv_size = 8;
		break;
	default:
		ipsp->ips_iv_size = 0;
		break;
	}
	ipsp->ips_iv_bits = ipsp->ips_iv_size * 8;
	ipsp->ips_auth_bits = ipsp->ips_key_bits_a;

	if (authalg && encalg) {
		crie.cri_next = &cria;
		error = crypto_newsession(&ipsp->ocf_cryptoid, &crie,
					  ipsec_ocf_crid);
	} else if (encalg) {
		error = crypto_newsession(&ipsp->ocf_cryptoid, &crie,
					  ipsec_ocf_crid);
	} else if (authalg) {
		error = crypto_newsession(&ipsp->ocf_cryptoid, &cria,
					  ipsec_ocf_crid);
	} else {
		KLIPS_PRINT(debug_pfkey, "klips_debug:ipsec_ocf_sa_init: "
			    "no authalg or encalg\n");
		return 0;
	}

	if (error) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:ipsec_ocf_sa_init: "
			    "crypto_newsession failed 0x%x\n", error);
		return 0;
	}

	/* make sure no ALG stuff bites us */
	if (ipsp->ips_alg_enc)
		printk("We received an ALG initted SA\n");
	ipsp->ips_alg_enc = NULL;

	ipsp->ocf_in_use = 1;
	return 1;
}

/* this function returns true if OCF can do the compression */
int ipsec_ocf_comp_sa_init(struct ipsec_sa *ipsp, int compalg)
{
	struct cryptoini cric;
	int error;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:ipsec_ocf_comp_sa_init(c=0x%x)\n",
		    compalg);

	memset(&cric, 0, sizeof(cric));

	cric.cri_alg = ipsec_ocf_compalg(compalg);

	if (!cric.cri_alg) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:ipsec_ocf_comp_sa_init: "
			    "invalid compalg=%d given\n", compalg);
		return 0;
	}

	error = crypto_newsession(&ipsp->ocf_cryptoid, &cric, ipsec_ocf_crid);
	if (error) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:ipsec_ocf_comp_sa_init: "
			    "crypto_newsession failed 0x%x\n", error);
		return 0;
	}

	ipsp->ocf_in_use = 1;
	return 1;
}

int ipsec_ocf_sa_free(struct ipsec_sa *ipsp)
{
	KLIPS_PRINT(debug_pfkey, "klips_debug:ipsec_ocf_sa_free()\n");
	if (!ipsp->ocf_in_use)
		printk("KLIPS: ipsec_ocf_sa_free received SA that is not initted?\n");


	crypto_freesession(ipsp->ocf_cryptoid);
	ipsp->ocf_cryptoid = -1;
	ipsp->ocf_in_use = 0;
	return 1;
}

static int ipsec_ocf_rcv_cb(struct cryptop *crp)
{
	struct ipsec_rcv_state *irs =
		(struct ipsec_rcv_state *)crp->crp_opaque;
	struct iphdr *newiph;
	unsigned orig_len, decomp_len;
	struct cryptodesc *crdc = NULL;

	KLIPS_PRINT(debug_rcv, "klips_debug:ipsec_ocf_rcv_cb\n");

	if (irs == NULL) {
		KLIPS_PRINT(debug_rcv, "klips_debug:ipsec_ocf_rcv_cb: "
			    "NULL irs in callback\n");
		return 0;
	}

	/*
	 * we must update the state before returning to the state machine.
	 * if we have an error,  terminate the processing by moving to the DONE
	 * state
	 */

	irs->state = IPSEC_RSM_DONE; /* assume it went badly */

	if (crp->crp_etype) {
		ptrdiff_t ptr_delta;

		if (crp->crp_etype == EAGAIN) {
			/* Session has been migrated. Store the new session id and retry */
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_ocf_rcv_cb: crypto session migrated\n");
			irs->ipsp->ocf_cryptoid = crp->crp_sid;
			/* resubmit request */
			if (crypto_dispatch(crp) == 0)
				return 0;
			/* resubmit failed */
		}

		KLIPS_PRINT(debug_rcv, "klips_debug:ipsec_ocf_rcv_cb: "
			    "error in processing 0x%x\n", crp->crp_etype);

		switch (irs->ipsp->ips_said.proto) {
		case IPPROTO_COMP:
			/*
			 * we restore the previous skb on error and pretend nothing
			 * happened, just no compression
			 */
			ptr_delta = irs->pre_ipcomp_skb->data - irs->skb->data;
			irs->authenticator =
				(void*)((char*)irs->authenticator + ptr_delta);
			irs->iph           =
				(void*)((char*)irs->iph           + ptr_delta);

			kfree_skb(irs->skb);
			irs->skb = irs->pre_ipcomp_skb;
			irs->pre_ipcomp_skb = NULL;
			break;
		}

		goto bail;
	}

	switch (irs->ipsp->ips_said.proto) {
	case IPPROTO_ESP:
		/* ESP, process it */
		if (ipsec_rcv_esp_post_decrypt(irs) == IPSEC_RCV_OK) {
			/* this one came up good, set next state */
			irs->state = IPSEC_RSM_DECAP_CONT;
		}
		break;

	case IPPROTO_AH:
		/* AH post processing, put back fields we had to zero */
		if (lsw_ip_hdr_version(irs) == 4) {
			lsw_ip4_hdr(irs)->ttl      = irs->ttl;
			lsw_ip4_hdr(irs)->check    = irs->check;
			lsw_ip4_hdr(irs)->frag_off = irs->frag_off;
			lsw_ip4_hdr(irs)->tos      = irs->tos;
		}
		irs->state         = IPSEC_RSM_AUTH_CHK;

		/* pull up the IP header again after processing */
		skb_pull(irs->skb,
			 ((unsigned char *)irs->protostuff.ahstuff.ahp) -
			 ((unsigned char *)irs->iph));

		break;

	case IPPROTO_COMP:
		crdc = crp->crp_desc;

		KLIPS_PRINT(debug_rcv, "comp before adjustments:\n");
		KLIPS_IP_PRINT(debug_rcv & DB_TN_XMIT, irs->iph);

		orig_len = irs->skb->len - sizeof(struct ipcomphdr);
		decomp_len = crp->crp_olen;

		newiph = (struct iphdr*)
			((char*)irs->iph + sizeof(struct ipcomphdr));

		KLIPS_PRINT(debug_rcv,
			    "comp results: olen: %u, inject: %u (len=%d) iph->totlen=%u\n",
			    crp->crp_olen, crdc->crd_inject, decomp_len,
			    ntohs(newiph->tot_len));

		/*
		 * move the ip header to consume room previously taken by
		 * the ipcomp header
		 */
		skb_pull(irs->skb, sizeof(struct ipcomphdr));
		memmove(newiph, irs->iph, irs->iphlen);

		/* adjust the ipp pointer to point to the header we decoded */
		irs->iph = newiph;

		skb_set_network_header(irs->skb,
				       ipsec_skb_offset(irs->skb,
							((unsigned char *)
							skb_network_header(irs->skb))
								  +
								  sizeof(struct
									 ipcomphdr)));
		skb_set_transport_header(irs->skb,
					 ipsec_skb_offset(irs->skb,
							  ((unsigned char *)
							  skb_transport_header(irs->skb))
								    +
								    sizeof(struct
									    ipcomphdr)));

		if (lsw_ip_hdr_version(irs) == 6) {
			lsw_ip6_hdr(irs)->nexthdr  = irs->next_header;
		} else {
			lsw_ip4_hdr(irs)->protocol = irs->next_header;
			lsw_ip4_hdr(irs)->tot_len = htons(
				irs->iphlen + decomp_len);
			lsw_ip4_hdr(irs)->check = 0;
			lsw_ip4_hdr(irs)->check = ip_fast_csum(irs->iph, lsw_ip4_hdr(
								       irs)->ihl);
		}

		KLIPS_PRINT(debug_rcv, "comp after len adjustments:\n");
		KLIPS_IP_PRINT(debug_rcv & DB_TN_XMIT, irs->iph);

		/* Update skb length/tail by "putting" the growth */
		safe_skb_put(irs->skb, decomp_len - crp->crp_olen);

		/* set the new header in the skb */
		skb_set_network_header(irs->skb,
				       ipsec_skb_offset(irs->skb, irs->iph));
		KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, ip_hdr(irs->skb));

		/* relese the backup copy */
		if (irs->pre_ipcomp_skb) {
			kfree_skb(irs->pre_ipcomp_skb);
			irs->pre_ipcomp_skb = NULL;
		}

		/* IPcomp finished, continue processing */
		irs->state = IPSEC_RSM_DECAP_CONT;
		break;
	}

bail:
	crypto_freereq(crp);
	crp = NULL;
	ipsec_ocf_queue_task(ipsec_rsm, irs);
	return 0;
}

enum ipsec_rcv_value ipsec_ocf_rcv(struct ipsec_rcv_state *irs)
{
	struct cryptop *crp;
	struct cryptodesc *crde = NULL, *crda = NULL, *crdc = NULL;
	struct ipsec_sa *ipsp;
	int req_count = 0;
	int rc, err;

	KLIPS_PRINT(debug_rcv, "klips_debug:ipsec_ocf_rcv\n");

	ipsp = irs->ipsp;
	if (!ipsp) {
		KLIPS_PRINT(debug_rcv, "klips_debug:ipsec_ocf_rcv: "
			    "no SA for rcv processing\n");
		return IPSEC_RCV_SAIDNOTFOUND;
	}

	if (!irs->skb) {
		KLIPS_PRINT(debug_rcv, "klips_debug:ipsec_ocf_rcv: no skb\n");
		return IPSEC_RCV_SAIDNOTFOUND;
	}

	switch (ipsp->ips_said.proto) {
	case IPPROTO_COMP:
		rc = ipsec_ocf_ipcomp_copy_expand(irs);
		if (rc != IPSEC_RCV_OK) {
			KLIPS_PRINT(debug_rcv, "klips_debug:ipsec_ocf_rcv: "
				    "growing skb for ipcomp failed, rc=%d\n",
				    rc);
			return rc;
		}
		break;
	case IPPROTO_ESP:
	case IPPROTO_AH:
		break;
	default:
		KLIPS_PRINT(debug_rcv & DB_RX_XF, "klips_debug:ipsec_ocf_rcv: "
			    "bad protocol %d\n", ipsp->ips_said.proto);
		return IPSEC_RCV_BADPROTO;
	}

	req_count = (ipsp->ips_authalg ? 1 : 0) +
		    (ipsp->ips_encalg  ? 1 : 0);
	crp = crypto_getreq(req_count);

	if (!crp) {
		KLIPS_PRINT(debug_rcv, "klips_debug:ipsec_ocf_rcv: "
			    "crypto_getreq returned NULL\n");
		return IPSEC_RCV_REALLYBAD;
	}

	/* we currently don't support any chaining across protocols */
	switch (ipsp->ips_said.proto) {
	case IPPROTO_ESP:
		/*
		 * we are decrypting,  from the setup in ipsec_ocf_sa_init above,  we
		 * need to flip the order of hash/cipher for receive so that it is
		 * hash first then decrypt.  Transmit is ok.
		 */
		if (crp->crp_desc && crp->crp_desc->crd_next) {
			crda = crp->crp_desc;
			crde = crda->crd_next;
		} else {
			crde = crp->crp_desc;
			crda = crde->crd_next;
		}
		break;
	case IPPROTO_COMP:
		crdc = crp->crp_desc;
		break;
	case IPPROTO_AH:
		crda = crp->crp_desc;
		break;
	}

	if (crda) {
		/* Authentication descriptor */
		crda->crd_alg = ipsec_ocf_authalg(ipsp->ips_authalg);
		if (!crda->crd_alg) {
			KLIPS_PRINT(debug_rcv, "klips_debug:ipsec_ocf_rcv: "
				    "bad auth alg 0x%x\n", ipsp->ips_authalg);
			crypto_freereq(crp);
			return IPSEC_RCV_BADPROTO;
		}

		if (!crde) { /* assuming AH processing */
			/* push the IP header so we can authenticate it */
			skb_push(irs->skb,
				 ((unsigned char *)irs->protostuff.ahstuff.ahp) -
				 ((unsigned char *)irs->iph));
		}

		crda->crd_key          = ipsp->ips_key_a;
		crda->crd_klen         = ipsp->ips_key_bits_a;
		crda->crd_inject       = irs->authenticator - irs->skb->data;

		/* OCF needs cri_mlen initialized in order to properly migrate the
		 * session to another driver */
		crda->crd_mlen = 12;

		/* Copy the authenticator to check aganinst later */
		memcpy(irs->hash, irs->authenticator, 12);

		if (!crde) { /* assume AH processing */
			/* AH processing, save fields we have to zero */
			if (lsw_ip_hdr_version(irs) == 4) {
				irs->ttl                   =
					lsw_ip4_hdr(irs)->ttl;
				irs->check                 =
					lsw_ip4_hdr(irs)->check;
				irs->frag_off              =
					lsw_ip4_hdr(irs)->frag_off;
				irs->tos                   =
					lsw_ip4_hdr(irs)->tos;
				lsw_ip4_hdr(irs)->ttl      = 0;
				lsw_ip4_hdr(irs)->check    = 0;
				lsw_ip4_hdr(irs)->frag_off = 0;
				lsw_ip4_hdr(irs)->tos      = 0;
			}
			crda->crd_len      = irs->skb->len;
			crda->crd_skip     = ((unsigned char *)irs->iph) -
					     irs->skb->data;
			memset(irs->authenticator, 0, 12);
		} else {
			crda->crd_len      = irs->ilen;
			crda->crd_skip     =
				((unsigned char *) irs->protostuff.espstuff.
				 espp) -
				irs->skb->data;
			/*
			 * It would be nice to clear the authenticator here
			 * to be sure we do not see it again later when checking.
			 * We cannot.  Some HW actually expects to check the in-data
			 * hash and and flag an error if it is incorrect.
			 *
			 * What we do to allow this is to pass in the current in-data
			 * value.  Your OCF driver must ensure that it fails a request
			 * for hash+decrypt with an invalid hash value, or returns the
			 * computed in-data hash as requested.
			 *
			 * If your driver does not check the in-data hash but just
			 * computes it value,  you must ensure that it does not return
			 * the original in-data hash by accident.  It must invalidate the
			 * in-data hash itself to force an auth check error.
			 *
			 * All existing drivers that do not care about the current
			 * in-data hash do this by clearing the in-data hash before
			 * processing, either directly or via their implementation.
			 */
#if 0
			memset(irs->authenticator, 0, 12);
#endif
		}
	}

	if (crde) {
		crde->crd_alg = ipsec_ocf_encalg(ipsp->ips_encalg);
		if (!crde->crd_alg) {
			KLIPS_PRINT(debug_rcv, "klips_debug:ipsec_ocf_rcv: "
				    "bad enc alg 0x%x\n", ipsp->ips_encalg);
			crypto_freereq(crp);
			return IPSEC_RCV_BADPROTO;
		}

		irs->esphlen     = ESP_HEADER_LEN + ipsp->ips_iv_size;
		irs->ilen       -= irs->esphlen;
		crde->crd_skip   =
			(skb_transport_header(irs->skb) -
			 irs->skb->data) + irs->esphlen;
		crde->crd_len    = irs->ilen;
		crde->crd_inject = crde->crd_skip - ipsp->ips_iv_size;
		crde->crd_klen   = ipsp->ips_key_bits_e;
		crde->crd_key    = ipsp->ips_key_e;
	}

	if (crdc) {
		struct ipcomphdr *cmph;
		int compalg = ipsp->ips_encalg;
		/* Decompression descriptor */
		crdc->crd_alg = ipsec_ocf_compalg(compalg);
		if (!crdc->crd_alg) {
			KLIPS_PRINT(debug_rcv, "klips_debug:ipsec_ocf_rcv: "
				    "bad decomp alg 0x%x\n",
				    ipsp->ips_encalg);
			crypto_freereq(crp);
			return IPSEC_RCV_BADPROTO;
		}
		crdc->crd_flags  = 0;
		/* this is where the current ipcomp header is */
		cmph = (struct ipcomphdr*)((char*)irs->iph + irs->iphlen);
		/* store the nested protocol */
		irs->next_header = cmph->ipcomp_nh;
		/* start decompressing after ip header and the ipcomp header */
		crdc->crd_skip   = ((unsigned char*)irs->iph) + irs->iphlen +
				   sizeof(struct ipcomphdr) - irs->skb->data;
		/* decompress all ip data past the ipcomp header */
		if (lsw_ip_hdr_version(irs) == 6) {
			crdc->crd_len    =
				(ntohs(lsw_ip6_hdr(irs)->payload_len) +
				 sizeof(struct ipv6hdr)) -
				irs->iphlen -
				sizeof(struct ipcomphdr);
		} else {
			crdc->crd_len    = ntohs(lsw_ip4_hdr(irs)->tot_len) -
					   irs->iphlen -
					   sizeof(struct ipcomphdr);
		}
		/* decompress inplace (some hardware can only do inplace) */
		crdc->crd_inject = crdc->crd_skip;
	}

	crp->crp_ilen = irs->skb->len;  /* Total input length */
	crp->crp_olen = irs->skb->len;  /* Total output length */
	crp->crp_flags =
		CRYPTO_F_SKBUF |
		(ipsec_ocf_cbimm ? CRYPTO_F_CBIMM : 0) |
		(ipsec_ocf_batch ? CRYPTO_F_BATCH : 0);
	crp->crp_buf = (caddr_t) irs->skb;
	crp->crp_callback = ipsec_ocf_rcv_cb;
	crp->crp_sid = ipsp->ocf_cryptoid;
	crp->crp_opaque = (caddr_t) irs;
rcv_migrate:
	if ((err = crypto_dispatch(crp))) {
		KLIPS_PRINT(debug_rcv, "crypto_dispatch rcv failure %u\n",
			    err);
		crypto_freereq(crp);
		return IPSEC_RCV_REALLYBAD;
	}
	if (crp->crp_etype == EAGAIN) {
		/* Session has been migrated. Store the new session id and retry */
		ipsp->ocf_cryptoid = crp->crp_sid;
		goto rcv_migrate;
	}

	return IPSEC_RCV_PENDING;
}

static int ipsec_ocf_xmit_cb(struct cryptop *crp)
{
	struct ipsec_xmit_state *ixs =
		(struct ipsec_xmit_state *)crp->crp_opaque;
	struct iphdr *newiph;
	struct ipcomphdr *cmph;
	unsigned orig_len, comp_len;
	struct cryptodesc *crdc = NULL;

	KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
		    "klips_debug:ipsec_ocf_xmit_cb\n");

	if (ixs == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT, "klips_debug:ipsec_ocf_xmit_cb: "
			    "NULL ixs in callback\n");
		return 0;
	}

	/*
	 * we must update the state before returning to the state machine.
	 * if we have an error,  terminate the processing by moving to the DONE
	 * state
	 */

	ixs->state = IPSEC_XSM_DONE; /* assume bad xmit */
	if (crp->crp_etype) {
		ptrdiff_t ptr_delta;

		if (crp->crp_etype == EAGAIN) {
			/* Session has been migrated. Store the new session id and retry */
			KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
				    "klips_debug:ipsec_ocf_xmit_cb: crypto session migrated\n");
			ixs->ipsp->ocf_cryptoid = crp->crp_sid;
			/* resubmit request */
			if (crypto_dispatch(crp) == 0)
				return 0;
			/* resubmit failed */
		}

		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT, "klips_debug:ipsec_ocf_xmit_cb: "
			    "error in processing 0x%x\n",
			    crp->crp_etype);

		switch (ixs->ipsp->ips_said.proto) {
		case IPPROTO_COMP:
			/*
			 * It's ok for compression to fail... we made a clone
			 * of the packet, so we just revert it now...
			 */
			if (!ixs->pre_ipcomp_skb) {
				KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
					    "klips_debug:ipsec_ocf_xmit_cb: "
					    "IPcomp on %u bytes failed, "
					    "but we have no clone!\n",
					    (unsigned int)
					    (lsw_ip_hdr_version(ixs) == 6 ?
					     (ntohs(lsw_ip6_hdr(ixs)->
						    payload_len) +
					      sizeof(struct ipv6hdr))
					     :
					     ntohs(lsw_ip4_hdr(
							   ixs)->tot_len)) -
					    ixs->iphlen);
				/* this is a fail. */
				break;
			}

			KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
				    "klips_debug:ipsec_ocf_xmit_cb: "
				    "IPcomp on %u bytes failed, "
				    "using backup clone.\n",
				    (unsigned int)
				    (lsw_ip_hdr_version(ixs) == 6 ?
				     (ntohs(lsw_ip6_hdr(ixs)->payload_len) +
				      sizeof(struct ipv6hdr)) :
				     ntohs(lsw_ip4_hdr(ixs)->tot_len)) -
				    ixs->iphlen);

			ptr_delta = ixs->pre_ipcomp_skb->data - ixs->skb->data;
			ixs->iph = (void*)((char*)ixs->iph + ptr_delta);

			/*
			 * cannot free it here, because we are under
			 * IRQ, potentially, so queue it for later
			 */
			kfree_skb(ixs->skb);
			ixs->skb = ixs->pre_ipcomp_skb;
			ixs->pre_ipcomp_skb = NULL;

			skb_set_network_header(ixs->skb,
					       ipsec_skb_offset(ixs->skb,
								((void *)
								 skb_network_header(
									 ixs->skb))
								+
								ptr_delta));
			skb_set_transport_header(ixs->skb,
						 ipsec_skb_offset(ixs->skb,
								  ((void *)
								   skb_transport_header(
									   ixs->skb))
								  +
								  ptr_delta));
			KLIPS_IP_PRINT(debug_tunnel & DB_TN_XMIT, ixs->iph);

			/* this means we don't compress */
			ixs->state = IPSEC_XSM_CONT;
			break;
		}
		goto bail;
	}

	switch (ixs->ipsp->ips_said.proto) {
	case IPPROTO_ESP:
		/* ESP, nothing to do */
		break;

	case IPPROTO_AH:
		/* AH post processing, put back fields we had to zero */
		if (lsw_ip_hdr_version(ixs) == 4) {
			lsw_ip4_hdr(ixs)->ttl      = ixs->ttl;
			lsw_ip4_hdr(ixs)->check    = ixs->check;
			lsw_ip4_hdr(ixs)->frag_off = ixs->frag_off;
			lsw_ip4_hdr(ixs)->tos      = ixs->tos;
		}
		break;

	case IPPROTO_COMP:
		/* IPcomp fill in the header */
		crdc = crp->crp_desc;

		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_debug:ipsec_ocf_xmit_cb: "
			    "after <%s%s%s>, SA:%s:\n",
			    IPS_XFORM_NAME(ixs->ipsp),
			    ixs->sa_len ? ixs->sa_txt : " (error)");
		KLIPS_IP_PRINT(debug_tunnel & DB_TN_XMIT, ixs->iph);

		orig_len = (lsw_ip_hdr_version(ixs) == 6 ?
			    (ntohs(lsw_ip6_hdr(ixs)->payload_len) +
			     sizeof(struct ipv6hdr)) :
			    ntohs(lsw_ip4_hdr(ixs)->tot_len)) -
			   ixs->iphlen;
		comp_len = crp->crp_olen;

		if (sysctl_ipsec_debug_ipcomp && sysctl_ipsec_debug_verbose) {
			ipsec_dmp_block("compress after",
					((unsigned char*)ixs->iph) + ixs->iphlen,
					comp_len);
		}

		newiph = (struct iphdr *)
			((char*)ixs->iph - sizeof(struct ipcomphdr));
		cmph = (struct ipcomphdr *)((char*)newiph + ixs->iphlen);

		/* move the ip header to make room for the new ipcomp header */
		memmove(((unsigned char *) ixs->skb->data) -
			sizeof(struct ipcomphdr),
			ixs->skb->data,
			(((unsigned char *) ixs->iph) + ixs->iphlen) -
			((unsigned char *) ixs->skb->data));
		/* DAVIDM check for head room */
		skb_push(ixs->skb, sizeof(struct ipcomphdr));

		ixs->iph = newiph;
		skb_set_network_header(ixs->skb,
				       ipsec_skb_offset(ixs->skb, newiph));
		skb_set_transport_header(ixs->skb,
					 ipsec_skb_offset(ixs->skb,
							  newiph) +
					 ixs->iphlen);

		/* now we can fill in the ipcomp header */
		cmph->ipcomp_nh = ixs->next_header;
		cmph->ipcomp_flags = 0;
		cmph->ipcomp_cpi =
			htons((__u16)(ntohl(ixs->ipsp->ips_said.spi) &
				      0x0000ffff));

		/* update the ip header to reflect the compression */
		if (lsw_ip_hdr_version(ixs) == 6) {
			lsw_ip6_hdr(ixs)->nexthdr = IPPROTO_COMP;
			lsw_ip6_hdr(ixs)->payload_len =
				htons(ixs->iphlen + sizeof(struct ipcomphdr) +
				      comp_len - sizeof(struct ipv6hdr));
		} else {
			lsw_ip4_hdr(ixs)->protocol = IPPROTO_COMP;
			lsw_ip4_hdr(ixs)->tot_len =
				htons(ixs->iphlen + sizeof(struct ipcomphdr) +
				      comp_len);
			lsw_ip4_hdr(ixs)->check = 0;
			lsw_ip4_hdr(ixs)->check =
				ip_fast_csum((char *) ixs->iph,
					     lsw_ip4_hdr(ixs)->ihl);
		}

		/* Update skb length/tail by "unputting" the shrinkage */
		safe_skb_put(ixs->skb, comp_len - orig_len);

		ixs->ipsp->ips_comp_adapt_skip = 0;
		ixs->ipsp->ips_comp_adapt_tries = 0;

		/* release the backup copy */
		if (ixs->pre_ipcomp_skb) {
			kfree_skb(ixs->pre_ipcomp_skb);
			ixs->pre_ipcomp_skb = NULL;
		}

		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_debug:ipsec_ocf_xmit_cb: "
			    "after <%s%s%s>, SA:%s:\n",
			    IPS_XFORM_NAME(ixs->ipsp),
			    ixs->sa_len ? ixs->sa_txt : " (error)");
		KLIPS_IP_PRINT(debug_tunnel & DB_TN_XMIT, ixs->iph);
		break;
	}

	/* all good */
	ixs->state = IPSEC_XSM_CONT;

bail:
	crypto_freereq(crp);
	crp = NULL;
	ipsec_ocf_queue_task(ipsec_xsm, ixs);
	return 0;
}

enum ipsec_xmit_value ipsec_ocf_xmit(struct ipsec_xmit_state *ixs)
{
	struct cryptop *crp;
	struct cryptodesc *crde = NULL, *crda = NULL, *crdc = NULL;
	struct ipsec_sa *ipsp;
	int req_count, payload_size;
	int err;

	KLIPS_PRINT(debug_tunnel & DB_TN_XMIT, "klips_debug:ipsec_ocf_xmit\n");

	ipsp = ixs->ipsp;
	if (!ipsp) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT, "klips_debug:ipsec_ocf_xmit: "
			    "no SA for rcv processing\n");
		return IPSEC_XMIT_SAIDNOTFOUND;
	}

	if (!ixs->skb) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_debug:ipsec_ocf_xmit: no skb\n");
		return IPSEC_XMIT_SAIDNOTFOUND;
	}

	switch (ipsp->ips_said.proto) {
	case IPPROTO_COMP:
		/*
		 * skip packets that have less then 90 bytes of payload to
		 * compress
		 */
#ifdef CONFIG_KLIPS_IPV6
		if (lsw_ip_hdr_version(ixs) == 6) {
			IPSEC_FRAG_OFF_DECL(frag_off)
			int nexthdroff;
			unsigned char nexthdr = lsw_ip6_hdr(ixs)->nexthdr;
			nexthdroff = ipsec_ipv6_skip_exthdr(ixs->skb,
							    ((void *)(
								     lsw_ip6_hdr(
									     ixs)
								     +
								     1)) -
							    (void*)ixs->skb->data,
							    &nexthdr,
							    &frag_off);
			ixs->iphlen = nexthdroff -
				      (ixs->iph - (void*)ixs->skb->data);
			payload_size = ntohs(lsw_ip6_hdr(ixs)->payload_len);
		} else
#endif          /* CONFIG_KLIPS_IPV6 */
		{
			ixs->iphlen = lsw_ip4_hdr(ixs)->ihl << 2;
			payload_size = ntohs(lsw_ip4_hdr(ixs)->tot_len) -
				       ixs->iphlen;
		}
		if (payload_size < 90) {
			KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
				    "klips_debug:ipsec_ocf_xmit: "
				    "skipping IPcomp on packet with "
				    "%d payload bytes\n", payload_size);
			return IPSEC_XMIT_OK;
		}
		/*
		 * there is a chance that we may not compress, and
		 * since the compression overwrites the data, we will clone
		 * the packet and restore it if we fail to compress
		 */
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_debug:ipsec_ocf_xmit: "
			    "IPcomp on %d bytes can fail, "
			    "duplicating the skb\n", payload_size);
		ixs->pre_ipcomp_skb =
			skb_copy_expand(ixs->skb, skb_headroom(ixs->skb),
					skb_tailroom(ixs->skb), GFP_ATOMIC);
		if (!ixs->pre_ipcomp_skb) {
			/*
			 * We can either drop the packet, but instead we try
			 * to do the compression as it might succeed.  Should it
			 * fail, the packet will be dropped in the callback.
			 */
			KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
				    "klips_debug:ipsec_ocf_xmit: "
				    "skb_clone failed -- ignoring\n");
		}
		break;
	case IPPROTO_ESP:
	case IPPROTO_AH:
		break;
	default:
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT, "klips_debug:ipsec_ocf_xmit: "
			    "bad protocol %d\n",
			    ipsp->ips_said.proto);
		return IPSEC_XMIT_BADPROTO;
	}

	req_count = (ipsp->ips_authalg ? 1 : 0) + (ipsp->ips_encalg ? 1 : 0);

	crp = crypto_getreq(req_count);
	if (!crp) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT, "klips_debug:ipsec_ocf_xmit: "
			    "crypto_getreq returned NULL\n");
		return IPSEC_XMIT_ERRMEMALLOC;
	}

	/* we currently don't support any chaining across protocols */
	switch (ipsp->ips_said.proto) {
	case IPPROTO_ESP:
		crde = crp->crp_desc;
		crda = crde->crd_next;
		break;
	case IPPROTO_COMP:
		crdc = crp->crp_desc;
		break;
	case IPPROTO_AH:
		crda = crp->crp_desc;
		break;
	}

	if (crda) {
		/* Authentication descriptor */
		crda->crd_alg = ipsec_ocf_authalg(ipsp->ips_authalg);
		if (!crda->crd_alg) {
			KLIPS_PRINT(debug_tunnel & DB_TN_XMIT, "klips_debug:ipsec_ocf_xmit: "
				    "bad auth alg 0x%x\n",
				    ipsp->ips_authalg);
			crypto_freereq(crp);
			return IPSEC_RCV_BADPROTO;
		}
		if (!crde) { /* assume AH processing */
			/* AH processing, save fields we have to zero */
			crda->crd_skip = ((unsigned char *) ixs->iph) -
					 ixs->skb->data;
			if (lsw_ip_hdr_version(ixs) == 4) {
				ixs->ttl = lsw_ip4_hdr(ixs)->ttl;
				ixs->check = lsw_ip4_hdr(ixs)->check;
				ixs->frag_off = lsw_ip4_hdr(ixs)->frag_off;
				ixs->tos = lsw_ip4_hdr(ixs)->tos;
				lsw_ip4_hdr(ixs)->ttl      = 0;
				lsw_ip4_hdr(ixs)->check    = 0;
				lsw_ip4_hdr(ixs)->frag_off = 0;
				lsw_ip4_hdr(ixs)->tos      = 0;
			}
			crda->crd_inject =
				((struct ahhdr *)(ixs->dat + ixs->iphlen))->
						 ah_data -
				ixs->skb->data;
			crda->crd_len = ixs->len - ixs->authlen;
			memset(ixs->skb->data + crda->crd_inject, 0, 12);
		} else {
			crda->crd_skip     = ((unsigned char *) ixs->espp) -
					     ixs->skb->data;
			crda->crd_inject   = ixs->len - ixs->authlen;
			crda->crd_len      = ixs->len - ixs->iphlen -
					     ixs->authlen;
		}

		/* OCF needs cri_mlen initialized in order to properly migrate
		 * the session to another driver */
		crda->crd_mlen = 12;

		crda->crd_key    = ipsp->ips_key_a;
		crda->crd_klen   = ipsp->ips_key_bits_a;
	}

	if (crde) {
		/* Encryption descriptor */
		crde->crd_alg = ipsec_ocf_encalg(ipsp->ips_encalg);
		if (!crde->crd_alg) {
			KLIPS_PRINT(debug_tunnel & DB_TN_XMIT, "klips_debug:ipsec_ocf_xmit: "
				    "bad enc alg 0x%x\n",
				    ipsp->ips_encalg);
			crypto_freereq(crp);
			return IPSEC_RCV_BADPROTO;
		}
		crde->crd_flags  = CRD_F_ENCRYPT;
		crde->crd_skip   = ixs->idat - ixs->dat;
		crde->crd_len    = ixs->ilen;
		crde->crd_inject = ((unsigned char *) ixs->espp->esp_iv) -
				   ixs->dat;
		crde->crd_klen   = ipsp->ips_key_bits_e;
		crde->crd_key    = ipsp->ips_key_e;
	}

	if (crdc) {
		int compalg = ipsp->ips_encalg;
		/* Compression descriptor */
		crdc->crd_alg = ipsec_ocf_compalg(compalg);
		if (!crdc->crd_alg) {
			KLIPS_PRINT(debug_tunnel & DB_TN_XMIT, "klips_debug:ipsec_ocf_xmit: "
				    "bad comp alg 0x%x\n",
				    ipsp->ips_encalg);
			crypto_freereq(crp);
			return IPSEC_RCV_BADPROTO;
		}
		crdc->crd_flags  = CRD_F_ENCRYPT;
		/* store the nested protocol */
		if (lsw_ip_hdr_version(ixs) == 6)
			ixs->next_header = lsw_ip6_hdr(ixs)->nexthdr;
		else
			ixs->next_header = lsw_ip4_hdr(ixs)->protocol;
		/* start compressing after ip header */
		crdc->crd_skip   = ipsec_skb_offset(ixs->skb,
						    ((unsigned char*)ixs->iph) +
						    ixs->iphlen);
		/* compress all ip data */
		if (lsw_ip_hdr_version(ixs) == 6)
			crdc->crd_len =
				ntohs(lsw_ip6_hdr(ixs)->payload_len);
		else
			crdc->crd_len =
				ntohs(lsw_ip4_hdr(ixs)->tot_len) - ixs->iphlen;
		/* compress inplace (some hardware can only do inplace) */
		crdc->crd_inject = crdc->crd_skip;

		if (sysctl_ipsec_debug_ipcomp && sysctl_ipsec_debug_verbose) {
			ipsec_dmp_block("compress before",
					((unsigned char*)ixs->iph) + ixs->iphlen,
					crdc->crd_len);
		}
	}

	crp->crp_ilen = ixs->skb->len;  /* Total input length */
	crp->crp_olen = ixs->skb->len;  /* Total output length */
	crp->crp_flags =
		CRYPTO_F_SKBUF |
		(ipsec_ocf_cbimm ? CRYPTO_F_CBIMM : 0) |
		(ipsec_ocf_batch ? CRYPTO_F_BATCH : 0);
	crp->crp_buf = (caddr_t) ixs->skb;
	crp->crp_callback = ipsec_ocf_xmit_cb;
	crp->crp_sid = ipsp->ocf_cryptoid;
	crp->crp_opaque = (caddr_t) ixs;
xmit_migrate:
	if ((err = crypto_dispatch(crp))) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "crypto_dispatch xmit failure %u\n", err);
		crypto_freereq(crp);
		return IPSEC_XMIT_ERRMEMALLOC;
	}
	if (crp->crp_etype == EAGAIN) {
		/* Session has been migrated. Store the new session id */
		ipsp->ocf_cryptoid = crp->crp_sid;
		goto xmit_migrate;
	}

	return IPSEC_XMIT_PENDING;
}

#ifdef CONFIG_KLIPS_AH
static struct ipsec_alg_supported ocf_ah_algs[] = {
	{
		.ias_name       = "ocf-md5hmac",
		.ias_id         = AH_MD5,
		.ias_exttype    = SADB_EXT_SUPPORTED_AUTH,
		.ias_ivlen      = 0,
		.ias_keyminbits = 128,
		.ias_keymaxbits = 128,
	},
	{
		.ias_name       = "ocf-sha1hmac",
		.ias_id         = AH_SHA,
		.ias_exttype    = SADB_EXT_SUPPORTED_AUTH,
		.ias_ivlen      = 0,
		.ias_keyminbits = 160,
		.ias_keymaxbits = 160,
	},
	{
		.ias_name       = "ocf-sha256hmac",
		.ias_id         = AH_SHA2_256,
		.ias_exttype    = SADB_EXT_SUPPORTED_AUTH,
		.ias_ivlen      = 0,
		.ias_keyminbits = 256,
		.ias_keymaxbits = 256,
	},
	{
		.ias_name       = "ocf-sha384hmac",
		.ias_id         = AH_SHA2_384,
		.ias_exttype    = SADB_EXT_SUPPORTED_AUTH,
		.ias_ivlen      = 0,
		.ias_keyminbits = 384,
		.ias_keymaxbits = 384,
	},
	{
		.ias_name       = "ocf-sha512hmac",
		.ias_id         = AH_SHA2_512,
		.ias_exttype    = SADB_EXT_SUPPORTED_AUTH,
		.ias_ivlen      = 0,
		.ias_keyminbits = 512,
		.ias_keymaxbits = 512,
	},
	{
		.ias_name       = NULL,
		.ias_id         = 0,
		.ias_exttype    = 0,
		.ias_ivlen      = 0,
		.ias_keyminbits = 0,
		.ias_keymaxbits = 0,
	}
};
#endif /* CONFIG_KLIPS_AH */

static struct ipsec_alg_supported ocf_esp_algs[] = {
	{
		.ias_name       = "ocf-md5hmac",
		.ias_id         = AH_MD5,
		.ias_exttype    = SADB_EXT_SUPPORTED_AUTH,
		.ias_ivlen      = 0,
		.ias_keyminbits = 128,
		.ias_keymaxbits = 128,
	},
	{
		.ias_name       = "ocf-sha1hmac",
		.ias_id         = AH_SHA,
		.ias_exttype    = SADB_EXT_SUPPORTED_AUTH,
		.ias_ivlen      = 0,
		.ias_keyminbits = 160,
		.ias_keymaxbits = 160,
	},
	{
		.ias_name       = "ocf-sha256hmac",
		.ias_id         = AH_SHA2_256,
		.ias_exttype    = SADB_EXT_SUPPORTED_AUTH,
		.ias_ivlen      = 0,
		.ias_keyminbits = 256,
		.ias_keymaxbits = 256,
	},
	{
		.ias_name       = "ocf-sha384hmac",
		.ias_id         = AH_SHA2_384,
		.ias_exttype    = SADB_EXT_SUPPORTED_AUTH,
		.ias_ivlen      = 0,
		.ias_keyminbits = 384,
		.ias_keymaxbits = 384,
	},
	{
		.ias_name       = "ocf-sha512hmac",
		.ias_id         = AH_SHA2_512,
		.ias_exttype    = SADB_EXT_SUPPORTED_AUTH,
		.ias_ivlen      = 0,
		.ias_keyminbits = 512,
		.ias_keymaxbits = 512,
	},
	{
		.ias_name       = "ocf-aes",
		.ias_id         = ESP_AES,
		.ias_exttype    = SADB_EXT_SUPPORTED_ENCRYPT,
		.ias_ivlen      = 16,
		.ias_keyminbits = 128,
		.ias_keymaxbits = 256,
	},
	{
		.ias_name       = "ocf-3des",
		.ias_id         = ESP_3DES,
		.ias_exttype    = SADB_EXT_SUPPORTED_ENCRYPT,
		.ias_ivlen      = 8,
		.ias_keyminbits = 192,
		.ias_keymaxbits = 192,
	},
	{
		.ias_name       = NULL,
		.ias_id         = 0,
		.ias_exttype    = 0,
		.ias_ivlen      = 0,
		.ias_keyminbits = 0,
		.ias_keymaxbits = 0,
	}
};

static int ipsec_ocf_check_alg(struct ipsec_alg_supported *s)
{
	struct cryptoini cri;
	int64_t cryptoid;

	memset(&cri, 0, sizeof(cri));
	if (s->ias_exttype == SADB_EXT_SUPPORTED_ENCRYPT)
		cri.cri_alg  = ipsec_ocf_encalg(s->ias_id);
	else
		cri.cri_alg  = ipsec_ocf_authalg(s->ias_id);
	cri.cri_klen     = s->ias_keyminbits;
	cri.cri_key      = "0123456789abcdefghijklmnopqrstuvwxyz";

	if (crypto_newsession(&cryptoid, &cri, ipsec_ocf_crid)) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:ipsec_ocf:%s not supported\n",
			    s->ias_name);
		return 0;
	}
	crypto_freesession(cryptoid);
	KLIPS_PRINT(debug_pfkey, "klips_debug:ipsec_ocf:%s supported\n",
		    s->ias_name);
	return 1;
}

void ipsec_ocf_init(void)
{
	struct ipsec_alg_supported *s;

	ipsec_ocf_queue_init();

	for (s = ocf_esp_algs; s->ias_name; s++) {
		if (ipsec_ocf_check_alg(s)) {
			(void)pfkey_list_insert_supported(s,
							  &(pfkey_supported_list
								  [
									  SADB_SATYPE_ESP
								  ]));
		}
	}

#ifdef CONFIG_KLIPS_AH
	for (s = ocf_ah_algs; s->ias_name; s++) {
		if (ipsec_ocf_check_alg(s))
			(void)pfkey_list_insert_supported(s,
							  &(pfkey_supported_list
								  [
									  SADB_SATYPE_AH
								  ]));
	}
#endif

	/* send register event to userspace	*/
	pfkey_register_reply(SADB_SATYPE_ESP, NULL);
	pfkey_register_reply(SADB_SATYPE_AH, NULL);
}

