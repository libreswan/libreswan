/*
 * processing code for AH
 * Copyright (C) 2003-2004   Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012  Paul Wouters  <paul@libreswan.org>
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
#include <linux/kernel.h> /* printk() */

#include "libreswan/ipsec_param.h"

#include <linux/slab.h>         /* kmalloc() */
#include <linux/errno.h>        /* error codes */
#include <linux/types.h>        /* size_t */
#include <linux/interrupt.h>    /* mark_bh */

#include <linux/netdevice.h>    /* struct device, and other headers */
#include <linux/etherdevice.h>  /* eth_type_trans */
#include <linux/ip.h>           /* struct iphdr */
#include <linux/skbuff.h>
#include <libreswan.h>
#include <linux/spinlock.h> /* *lock* */

#include <net/ip.h>
#include <net/protocol.h>

#include "libreswan/radij.h"
#include "libreswan/ipsec_encap.h"
#include "libreswan/ipsec_sa.h"
#ifdef CONFIG_KLIPS_ALG
#include "libreswan/ipsec_alg.h"
#endif

#include "libreswan/ipsec_radij.h"
#include "libreswan/ipsec_xform.h"
#include "libreswan/ipsec_tunnel.h"
#include "libreswan/ipsec_rcv.h"
#include "libreswan/ipsec_xmit.h"

#include "libreswan/ipsec_auth.h"
#include "libreswan/ipsec_ah.h"
#include "libreswan/ipsec_proto.h"

#ifdef CONFIG_KLIPS_OCF
# include "ipsec_ocf.h"
#endif

__u32 zeroes[AH_AMAX];

enum ipsec_rcv_value ipsec_rcv_ah_checks(struct ipsec_rcv_state *irs,
					 struct sk_buff *skb)
{
	int ahminlen;

	ahminlen = irs->hard_header_len + sizeof(struct iphdr);

	/* take care not to deref this pointer until we check the minlen though */
	irs->protostuff.ahstuff.ahp =
		(struct ahhdr *)skb_transport_header(skb);

	if ((skb->len < ahminlen + sizeof(struct ahhdr)) ||
	    (skb->len < ahminlen +
	     (irs->protostuff.ahstuff.ahp->ah_hl << 2))) {
		KLIPS_PRINT(debug_rcv & DB_RX_INAU,
			    "klips_debug:ipsec_rcv: "
			    "runt ah packet of skb->len=%d received from %s, dropped.\n",
			    skb->len,
			    irs->ipsaddr_txt);
		if (irs->stats)
			irs->stats->rx_errors++;
		return IPSEC_RCV_BADLEN;
	}

	irs->said.spi = irs->protostuff.ahstuff.ahp->ah_spi;

	/* XXX we only support the one 12-byte authenticator for now */
	if (irs->protostuff.ahstuff.ahp->ah_hl !=
	    ((AHHMAC_HASHLEN + AHHMAC_RPLLEN) >> 2)) {
		KLIPS_PRINT(debug_rcv & DB_RX_INAU,
			    "klips_debug:ipsec_rcv: "
			    "bad authenticator length %ld, expected %zu from %s.\n",
			    (long)irs->protostuff.ahstuff.ahp->ah_hl << 2,
			    sizeof(struct ahhdr),
			    irs->ipsaddr_txt);
		if (irs->stats)
			irs->stats->rx_errors++;
		return IPSEC_RCV_BADLEN;
	}

	return IPSEC_RCV_OK;
}

enum ipsec_rcv_value ipsec_rcv_ah_setup_auth(struct ipsec_rcv_state *irs,
					     struct sk_buff *skb,
					     __u32          *replay,
					     unsigned char **authenticator)
{
	struct ahhdr *ahp = irs->protostuff.ahstuff.ahp;

	*replay = ntohl(ahp->ah_rpl);
	*authenticator = ahp->ah_data;

	return IPSEC_RCV_OK;
}

enum ipsec_rcv_value ipsec_rcv_ah_authcalc(struct ipsec_rcv_state *irs,
					   struct sk_buff *skb)
{
	struct ahhdr *ahp = irs->protostuff.ahstuff.ahp;
#if defined(CONFIG_KLIPS_AUTH_HMAC_MD5) || defined(CONFIG_KLIPS_AUTH_HMAC_SHA1)
	struct auth_alg *aa;

	union {
		MD5_CTX md5;
		SHA1_CTX sha1;
	} tctx;
#endif
	struct iphdr ipo;
	int ahhlen;
#ifdef CONFIG_KLIPS_ALG
	unsigned char *buf;
	int len = 0;
#endif

	KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv: "
		    "ipsec_alg hashing proto=%d... ",
		    irs->said.proto);
	if (irs->said.proto != IPPROTO_AH)
		return IPSEC_RCV_BADPROTO;

#ifdef CONFIG_KLIPS_OCF
	if (irs->ipsp->ocf_in_use)
		return ipsec_ocf_rcv(irs);

#endif

	ipo = *lsw_ip4_hdr(irs);
	ipo.tos = 0;    /* mutable RFC 2402 3.3.3.1.1.1 */
	ipo.frag_off = 0;
	ipo.ttl = 0;
	ipo.check = 0;

	ahhlen = AH_BASIC_LEN + (ahp->ah_hl << 2);

#ifdef CONFIG_KLIPS_ALG
	if (irs->ipsp->ips_alg_auth) {
		if ((buf = kmalloc(sizeof(struct iphdr)+skb->len, GFP_KERNEL)) == NULL)
			return IPSEC_RCV_ERRMEMALLOC;

		/* do the sanitized header */
		memcpy(buf,(caddr_t)&ipo,  sizeof(struct iphdr));
		len =  sizeof(struct iphdr);
		/* now do the AH header itself */
		memcpy(buf+len, (caddr_t)ahp,  ahhlen - AHHMAC_HASHLEN);
		len += (ahhlen - AHHMAC_HASHLEN);
		/* now, do some zeroes */
		memcpy(buf+len, (caddr_t)zeroes, AHHMAC_HASHLEN);
		len += AHHMAC_HASHLEN;
		/* finally, do the packet contents themselves */
		memcpy(buf+len, (caddr_t)skb_transport_header(skb) + ahhlen, skb->len - ahhlen);
		len += (skb->len - ahhlen);

		ipsec_alg_sa_ah_hash(irs->ipsp,
				     (caddr_t)buf, len,
				     irs->hash, AHHMAC_HASHLEN);
		if (buf)
			kfree(buf);
	} else {
#endif
#if defined(CONFIG_KLIPS_AUTH_HMAC_MD5) || defined(CONFIG_KLIPS_AUTH_HMAC_SHA1)
	aa = irs->authfuncs;

	/* copy the initialized keying material */
	memcpy(&tctx, irs->ictx, irs->ictx_len);

	/* do the sanitized header */
	(*aa->update)((void*)&tctx, (caddr_t)&ipo, sizeof(struct iphdr));

	/* XXX we didn't do the options here! */

	/* now do the AH header itself */
	(*aa->update)((void*)&tctx, (caddr_t)ahp,  ahhlen - AHHMAC_HASHLEN);

	/* now, do some zeroes */
	(*aa->update)((void*)&tctx, (caddr_t)zeroes,  AHHMAC_HASHLEN);

	/* finally, do the packet contents themselves */
	(*aa->update)((void*)&tctx,
		      (caddr_t)skb_transport_header(skb) + ahhlen,
		      skb->len - ahhlen);

	(*aa->final)(irs->hash, (void *)&tctx);

	memcpy(&tctx, irs->octx, irs->octx_len);

	(*aa->update)((void *)&tctx, irs->hash, aa->hashlen);
	(*aa->final)(irs->hash, (void *)&tctx);

#endif
#ifdef CONFIG_KLIPS_ALG
	}
#endif
	return IPSEC_RCV_OK;
}

enum ipsec_rcv_value ipsec_rcv_ah_decap(struct ipsec_rcv_state *irs)
{
	struct ahhdr *ahp = irs->protostuff.ahstuff.ahp;
	struct sk_buff *skb;
	int ahhlen;

	skb = irs->skb;

	ahhlen = AH_BASIC_LEN + (ahp->ah_hl << 2);

	lsw_ip4_hdr(irs)->tot_len = htons(ntohs(lsw_ip4_hdr(
							irs)->tot_len) -
					  ahhlen);
	irs->next_header  = ahp->ah_nh;

	/*
	 * move the IP header forward by the size of the AH header,
	 * thus removing the the AH header from the packet.
	 */
	memmove((void *)(skb_network_header(skb) + ahhlen),
		(void *)(skb_network_header(skb)), irs->iphlen);

	ipsec_rcv_dmp("ah postmove", skb->data, skb->len);

	/* skb_pull below, will move up by ahhlen */

	/* XXX not clear how this can happen, as the message indicates */
	if (skb->len < ahhlen) {
		printk(KERN_WARNING
		       "klips_error:ipsec_rcv: "
		       "tried to skb_pull ahhlen=%d, %d available.  This should never happen, please report.\n",
		       ahhlen,
		       (int)(skb->len));
		return IPSEC_RCV_DECAPFAIL;
	}
	skb_pull(skb, ahhlen);

	skb_set_network_header(skb, -irs->iphlen);
	irs->iph = (void *) ip_hdr(skb);

	ipsec_rcv_dmp("ah postpull", (void *)ip_hdr(skb), skb->len);

	return IPSEC_RCV_OK;
}

enum ipsec_xmit_value ipsec_xmit_ah_setup(struct ipsec_xmit_state *ixs)
{
	struct iphdr ipo;
	struct ahhdr *ahp;

#if defined(CONFIG_KLIPS_AUTH_HMAC_MD5) || defined(CONFIG_KLIPS_AUTH_HMAC_SHA1)
	__u8 hash[AH_AMAX];
	union {
#ifdef CONFIG_KLIPS_AUTH_HMAC_MD5
		MD5_CTX md5;
#endif          /* CONFIG_KLIPS_AUTH_HMAC_MD5 */
#ifdef CONFIG_KLIPS_AUTH_HMAC_SHA1
		SHA1_CTX sha1;
#endif          /* CONFIG_KLIPS_AUTH_HMAC_SHA1 */
	} tctx;
#endif
	unsigned char *dat = (unsigned char *)ixs->iph;

	ahp = (struct ahhdr *)(dat + ixs->iphlen);
	ahp->ah_spi = ixs->ipsp->ips_said.spi;
	ahp->ah_rpl = htonl(++(ixs->ipsp->ips_replaywin_lastseq));
	ahp->ah_rv = 0;
	ahp->ah_nh = lsw_ip4_hdr(ixs)->protocol;
	ahp->ah_hl =
		(sizeof(struct ahhdr) >> 2) - sizeof(__u64) / sizeof(__u32);
	lsw_ip4_hdr(ixs)->protocol = IPPROTO_AH;
	ipsec_xmit_dmp("ahp", (char*)ahp, sizeof(*ahp));

	ipo = *lsw_ip4_hdr(ixs);
	ipo.tos = 0;
	ipo.frag_off = 0;
	ipo.ttl = 0;
	ipo.check = 0;
	ipsec_xmit_dmp("ipo", (char*)&ipo, sizeof(ipo));

	switch (ixs->ipsp->ips_authalg) {
#ifdef CONFIG_KLIPS_AUTH_HMAC_MD5
	case AH_MD5:
		tctx.md5 = ((struct md5_ctx*)(ixs->ipsp->ips_key_a))->ictx;
		ipsec_xmit_dmp("ictx", (char*)&tctx.md5, sizeof(tctx.md5));
		osMD5Update(&tctx.md5, (unsigned char *)&ipo,
			    sizeof(struct iphdr));
		ipsec_xmit_dmp("ictx+ipo", (char*)&tctx.md5, sizeof(tctx.md5));
		osMD5Update(&tctx.md5, (unsigned char *)ahp,
			    sizeof(struct ahhdr) - sizeof(ahp->ah_data));
		ipsec_xmit_dmp("ictx+ahp", (char*)&tctx.md5, sizeof(tctx.md5));
		osMD5Update(&tctx.md5, (unsigned char *)zeroes,
			    AHHMAC_HASHLEN);
		ipsec_xmit_dmp("ictx+zeroes", (char*)&tctx.md5,
			       sizeof(tctx.md5));
		osMD5Update(&tctx.md5,
			    dat + ixs->iphlen + sizeof(struct ahhdr),
			    ixs->skb->len - ixs->iphlen -
			    sizeof(struct ahhdr));
		ipsec_xmit_dmp("ictx+dat", (char*)&tctx.md5, sizeof(tctx.md5));
		osMD5Final(hash, &tctx.md5);
		ipsec_xmit_dmp("ictx hash", (char*)&hash, sizeof(hash));
		tctx.md5 = ((struct md5_ctx*)(ixs->ipsp->ips_key_a))->octx;
		ipsec_xmit_dmp("octx", (char*)&tctx.md5, sizeof(tctx.md5));
		osMD5Update(&tctx.md5, hash, AHMD596_ALEN);
		ipsec_xmit_dmp("octx+hash", (char*)&tctx.md5,
			       sizeof(tctx.md5));
		osMD5Final(hash, &tctx.md5);
		ipsec_xmit_dmp("octx hash", (char*)&hash, sizeof(hash));

		memcpy(ahp->ah_data, hash, AHHMAC_HASHLEN);

		/* paranoid */
		memset((caddr_t)&tctx.md5, 0, sizeof(tctx.md5));
		memset((caddr_t)hash, 0, sizeof(*hash));
		break;
#endif          /* CONFIG_KLIPS_AUTH_HMAC_MD5 */
#ifdef CONFIG_KLIPS_AUTH_HMAC_SHA1
	case AH_SHA:
		tctx.sha1 = ((struct sha1_ctx*)(ixs->ipsp->ips_key_a))->ictx;
		SHA1Update(&tctx.sha1, (unsigned char *)&ipo,
			   sizeof(struct iphdr));
		SHA1Update(&tctx.sha1, (unsigned char *)ahp,
			   sizeof(struct ahhdr) - sizeof(ahp->ah_data));
		SHA1Update(&tctx.sha1, (unsigned char *)zeroes,
			   AHHMAC_HASHLEN);
		SHA1Update(&tctx.sha1,
			   dat + ixs->iphlen + sizeof(struct ahhdr),
			   ixs->skb->len - ixs->iphlen - sizeof(struct ahhdr));
		SHA1Final(hash, &tctx.sha1);
		tctx.sha1 = ((struct sha1_ctx*)(ixs->ipsp->ips_key_a))->octx;
		SHA1Update(&tctx.sha1, hash, AHSHA196_ALEN);
		SHA1Final(hash, &tctx.sha1);

		memcpy(ahp->ah_data, hash, AHHMAC_HASHLEN);

		/* paranoid */
		memset((caddr_t)&tctx.sha1, 0, sizeof(tctx.sha1));
		memset((caddr_t)hash, 0, sizeof(*hash));
		break;
#endif          /* CONFIG_KLIPS_AUTH_HMAC_SHA1 */
	default:
		ixs->stats->tx_errors++;
		return IPSEC_XMIT_AH_BADALG;
	}
	skb_set_transport_header(ixs->skb, ipsec_skb_offset(ixs->skb, ahp));

	return IPSEC_XMIT_OK;
}

struct xform_functions ah_xform_funcs[] = {
	{
		protocol:           IPPROTO_AH,
		rcv_checks:         ipsec_rcv_ah_checks,
		rcv_setup_auth:     ipsec_rcv_ah_setup_auth,
		rcv_calc_auth:      ipsec_rcv_ah_authcalc,
		rcv_decrypt:        ipsec_rcv_ah_decap,

		xmit_setup:         ipsec_xmit_ah_setup,
		xmit_headroom:      sizeof(struct ahhdr),
		xmit_needtailroom:  0,
	},
};

#ifndef CONFIG_XFRM_ALTERNATE_STACK
#ifdef NET_26
struct inet_protocol ah_protocol = {
	.handler = ipsec_rcv,
	.no_policy = 1,
#ifdef HAVE_NAMESPACES
	.netns_ok = 1,
#endif
};
#else
struct inet_protocol ah_protocol =
{
	ipsec_rcv,                      /* AH handler */
	NULL,                           /* TUNNEL error control */
	0,                              /* next */
	IPPROTO_AH,                     /* protocol ID */
	0,                              /* copy */
	NULL,                           /* data */
	"AH"                            /* name */
};
#endif /* NET_26 */
#endif /* CONFIG_XFRM_ALTERNATE_STACK */
