/*
 * processing code for ESP
 * Copyright (C) 2003 Michael Richardson <mcr@sandelman.ottawa.on.ca>
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

#include "libreswan/ipsec_radij.h"
#include "libreswan/ipsec_xform.h"
#include "libreswan/ipsec_tunnel.h"
#include "libreswan/ipsec_rcv.h"
#include "libreswan/ipsec_xmit.h"

#include "libreswan/ipsec_auth.h"

#ifdef CONFIG_KLIPS_ESP
#include "libreswan/ipsec_esp.h"
#endif /* CONFIG_KLIPS_ESP */

#include "libreswan/ipsec_proto.h"
#include "libreswan/ipsec_alg.h"
#ifdef CONFIG_KLIPS_OCF
# include "ipsec_ocf.h"
#endif

#define ESP_DMP(_x, _y, _z) { \
		if (debug_rcv && sysctl_ipsec_debug_verbose) \
			ipsec_dmp_block((_x), (_y), (_z)); \
	}

#ifdef CONFIG_KLIPS_ESP
enum ipsec_rcv_value ipsec_rcv_esp_checks(struct ipsec_rcv_state *irs,
					  struct sk_buff *skb)
{
	/* XXX this will need to be 8 for IPv6 */
	if ((irs->proto == IPPROTO_ESP) && ((skb->len - irs->iphlen) % 4)) {
		printk("klips_error:ipsec_rcv: "
		       "got packet with content length %d - %d = %d from %s -- should be on 4 octet boundary, packet dropped\n",
		       skb->len, irs->iphlen,
		       skb->len - irs->iphlen,
		       irs->ipsaddr_txt);
		if (irs->stats)
			irs->stats->rx_errors++;
		return IPSEC_RCV_BADLEN;
	}

#if 0
/* The problem with this check manifests itself when using l2tp over esp in
 * udp over pptp/ppp. This check seems to break for ESPinUDP packets,
 * probably because of how hard_header_len is used with decapsulation.
 *
 * When pinging using -s 0 with Windows, one sees:
 * skb->len = Payload(0) + ICMP (8) + IP (20) + ESP (16) + UDP (16) = 60.
 * hard_header_len is calculated as 14 (ethernet) instead of 22 (ppp)
 *
 * Manifests itself only with Windows, not with xl2tpd as client.
 *
 * Disabling this check should not be harmfull, as broken too-short
 * packets should fail their integrity check anyway.
 *
 * Thanks to Hiren Joshi for his excellent debugging on this
 *
 */
	if (skb->len <
	    (irs->hard_header_len + sizeof(struct iphdr) +
	     sizeof(struct esphdr))) {
		KLIPS_PRINT(debug_rcv & DB_RX_INAU,
			    "klips_debug:ipsec_rcv: "
			    "runt esp packet of skb->len=%d received from %s, dropped.\n",
			    skb->len,
			    irs->ipsaddr_txt);
		if (irs->stats)
			irs->stats->rx_errors++;
		return IPSEC_RCV_BADLEN;
	}
#endif

	irs->protostuff.espstuff.espp = (struct esphdr *)skb_transport_header(
		skb);
	irs->said.spi = irs->protostuff.espstuff.espp->esp_spi;

	return IPSEC_RCV_OK;
}

enum ipsec_rcv_value ipsec_rcv_esp_decrypt_setup(struct ipsec_rcv_state *irs,
						 struct sk_buff *skb,
						 __u32          *replay,
						 unsigned char **authenticator)
{
	struct esphdr *espp = irs->protostuff.espstuff.espp;

	/* unsigned char *idat = (unsigned char *)espp; */

	KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv: "
		    "packet from %s received with seq=%d (iv)=0x%08x%08x iplen=%d esplen=%d sa=%s\n",
		    irs->ipsaddr_txt,
		    (__u32)ntohl(espp->esp_rpl),
		    (__u32)ntohl(*((__u32 *)(espp->esp_iv)    )),
		    (__u32)ntohl(*((__u32 *)(espp->esp_iv) + 1)),
		    irs->len,
		    irs->ilen,
		    irs->sa_len ? irs->sa : " (error)");

	*replay = ntohl(espp->esp_rpl);
	*authenticator = &(skb_transport_header(skb)[irs->ilen]);

	return IPSEC_RCV_OK;
}

enum ipsec_rcv_value ipsec_rcv_esp_authcalc(struct ipsec_rcv_state *irs,
					    struct sk_buff *skb)
{
	struct auth_alg *aa;
	struct esphdr *espp = irs->protostuff.espstuff.espp;

	union {
		MD5_CTX md5;
		SHA1_CTX sha1;
	} tctx;

#ifdef CONFIG_KLIPS_OCF
	if (irs->ipsp->ocf_in_use)
		return ipsec_ocf_rcv(irs);

#endif

#ifdef CONFIG_KLIPS_ALG
	if (irs->ipsp->ips_alg_auth) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "ipsec_alg hashing proto=%d... ",
			    irs->said.proto);
		if (irs->said.proto == IPPROTO_ESP) {
			ipsec_alg_sa_esp_hash(irs->ipsp,
					      (caddr_t)espp, irs->ilen,
					      irs->hash, irs->ixt_a->ixt_a_authlen);
			return IPSEC_RCV_OK;
		}
		return IPSEC_RCV_BADPROTO;
	}
#endif
	aa = irs->authfuncs;

	/* copy the initialized keying material */
	memcpy(&tctx, irs->ictx, irs->ictx_len);

#ifdef HASH_DEBUG
	ESP_DMP("ictx", irs->ictx, irs->ictx_len);

	ESP_DMP("mac_esp", (caddr_t)espp, irs->ilen);
#endif
	(*aa->update)((void *)&tctx, (caddr_t)espp, irs->ilen);

	(*aa->final)(irs->hash, (void *)&tctx);

#ifdef HASH_DEBUG
	ESP_DMP("hash1", irs->hash, aa->hashlen);
#endif

	memcpy(&tctx, irs->octx, irs->octx_len);

#ifdef HASH_DEBUG
	ESP_DMP("octx", irs->octx, irs->octx_len);
#endif

	(*aa->update)((void *)&tctx, irs->hash, aa->hashlen);
	(*aa->final)(irs->hash, (void *)&tctx);

	return IPSEC_RCV_OK;
}

enum ipsec_rcv_value ipsec_rcv_esp_decrypt(struct ipsec_rcv_state *irs)
{
#if defined(CONFIG_KLIPS_ALG) || defined(CONFIG_KLIPS_OCF)
	struct ipsec_sa *ipsp = irs->ipsp;
#endif
#ifdef CONFIG_KLIPS_ALG
	struct esphdr *espp = irs->protostuff.espstuff.espp;
	__u8 *idat;     /* pointer to content to be decrypted/authenticated */
	int encaplen = 0;
	struct sk_buff *skb;
	struct ipsec_alg_enc *ixt_e = NULL;
#endif

#ifdef CONFIG_KLIPS_OCF
	if (ipsp->ocf_in_use)
		return ipsec_ocf_rcv(irs);

#endif

#ifdef CONFIG_KLIPS_ALG
	skb = irs->skb;

	idat = skb_transport_header(skb);

	/* encaplen is the distance between the end of the IP
	 * header and the beginning of the ESP header.
	 * on ESP headers it is zero, but on UDP-encap ESP
	 * it includes the space for the UDP header.
	 *
	 * Note: UDP-encap code has already moved the
	 *       skb->data forward to accommodate this.
	 */
	encaplen = skb_transport_header(skb) -
		   (skb_network_header(skb) + irs->iphlen);

	ixt_e = ipsp->ips_alg_enc;
	irs->esphlen = ESP_HEADER_LEN +
		       ixt_e->ixt_common.ixt_support.ias_ivlen / 8;
	KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv: "
		    "encalg=%d esphlen=%d\n",
		    ipsp->ips_encalg, irs->esphlen);

	idat += irs->esphlen;
	irs->ilen -= irs->esphlen;

	if (ipsec_alg_esp_encrypt(ipsp,
				  idat, irs->ilen, espp->esp_iv,
				  IPSEC_ALG_DECRYPT) <= 0) {
		KLIPS_ERROR(debug_rcv, "klips_error:ipsec_rcv: "
			    "got packet with esplen = %d "
			    "from %s -- should be on "
			    "ENC(%d) octet boundary, "
			    "packet dropped\n",
			    irs->ilen,
			    irs->ipsaddr_txt,
			    ipsp->ips_encalg);
		if (irs->stats)
			irs->stats->rx_errors++;
		return IPSEC_RCV_BAD_DECRYPT;
	}

	return ipsec_rcv_esp_post_decrypt(irs);

#else
	return IPSEC_RCV_BAD_DECRYPT;

#endif  /* CONFIG_KLIPS_ALG */
}

enum ipsec_rcv_value ipsec_rcv_esp_post_decrypt(struct ipsec_rcv_state *irs)
{
	struct sk_buff *skb;
	__u8 *idat;     /* pointer to content to be decrypted/authenticated */
	struct ipsec_sa *ipsp = irs->ipsp;
	int pad = 0, padlen;
	int badpad = 0;
	int i;

	skb = irs->skb;

	idat = skb_transport_header(skb) + irs->esphlen;

	ESP_DMP("postdecrypt", idat, irs->ilen);

	irs->next_header = idat[irs->ilen - 1];
	padlen = idat[irs->ilen - 2];
	pad = padlen + 2 + irs->authlen;

	KLIPS_PRINT(debug_rcv & DB_RX_IPAD,
		    "klips_debug:ipsec_rcv_esp_post_decrypt: "
		    "padlen=%d, contents: 0x<offset>: 0x<value> 0x<value> ...\n",
		    padlen);

	for (i = 1; i <= padlen; i++) {
		if ((i % 16) == 1) {
			KLIPS_PRINT(debug_rcv & DB_RX_IPAD,
				    "klips_debug:           %02x:",
				    i - 1);
		}
		KLIPS_PRINTMORE(debug_rcv & DB_RX_IPAD,
				" %02x",
				idat[irs->ilen - 2 - padlen + i - 1]);
		if (i != idat[irs->ilen - 2 - padlen + i - 1])
			badpad = 1;
		if ((i % 16) == 0) {
			KLIPS_PRINTMORE(debug_rcv & DB_RX_IPAD,
					"\n");
		}
	}
	if ((i % 16) != 1) {
		KLIPS_PRINTMORE(debug_rcv & DB_RX_IPAD,
				"\n");
	}
	if (badpad) {
		KLIPS_PRINT(debug_rcv & DB_RX_IPAD,
			    "klips_debug:ipsec_rcv_esp_post_decrypt: "
			    "warning, decrypted packet from %s has bad padding\n",
			    irs->ipsaddr_txt);
		KLIPS_PRINT(debug_rcv & DB_RX_IPAD,
			    "klips_debug:ipsec_rcv_esp_post_decrypt: "
			    "...may be bad decryption -- not dropped\n");
		ipsp->ips_errs.ips_encpad_errs += 1;
	}

	KLIPS_PRINT(debug_rcv & DB_RX_IPAD,
		    "klips_debug:ipsec_rcv_esp_post_decrypt: "
		    "packet decrypted from %s: next_header = %d, padding = %d\n",
		    irs->ipsaddr_txt,
		    irs->next_header,
		    pad - 2 - irs->authlen);

	if (lsw_ip_hdr_version(irs) == 6)
		lsw_ip6_hdr(irs)->payload_len =
			htons(ntohs(lsw_ip6_hdr(irs)->payload_len) -
			      (irs->esphlen + pad));
	else
		lsw_ip4_hdr(irs)->tot_len =
			htons(ntohs(lsw_ip4_hdr(irs)->tot_len) -
			      (irs->esphlen + pad));

	/*
	 * move the IP header forward by the size of the ESP header,
	 * thus removing the the ESP header from the packet.
	 *
	 * XXX this is really unnecessary, since odds we are in tunnel
	 *     mode, and we will be *removing* this IP header.
	 *
	 */
	memmove((void *)(idat - irs->iphlen),
		(void *)(skb_network_header(skb)), irs->iphlen);

	ESP_DMP("esp postmove", (idat - irs->iphlen),
		irs->iphlen + irs->ilen);

	/* skb_pull below, will move up by esphlen */

	/* XXX not clear how this can happen, as the message indicates */
	if (skb->len < irs->esphlen) {
		printk(KERN_WARNING
		       "klips_error:ipsec_rcv_esp_post_decrypt: "
		       "tried to skb_pull esphlen=%d, %d available.  This should never happen, please report.\n",
		       irs->esphlen, (int)(skb->len));
		return IPSEC_RCV_ESP_DECAPFAIL;
	}
	skb_pull(skb, irs->esphlen);
	skb_set_network_header(skb, ipsec_skb_offset(skb, idat - irs->iphlen));
	irs->iph = (void *) ip_hdr(skb);

	ESP_DMP("esp postpull", skb->data, skb->len);

	/* now, trip off the padding from the end */
	KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
		    "klips_debug:ipsec_rcv: "
		    "trimming to %d.\n",
		    irs->len - irs->esphlen - pad);
	if (pad + irs->esphlen <= irs->len) {
		skb_trim(skb, irs->len - irs->esphlen - pad);
	} else {
		KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
			    "klips_debug:ipsec_rcv: "
			    "bogus packet, size is zero or negative, dropping.\n");
		return IPSEC_RCV_DECAPFAIL;
	}

	ESP_DMP("esp posttrim", skb->data, skb->len);

	return IPSEC_RCV_OK;
}

#if 0
/*
 *
 */
enum ipsec_xmit_value ipsec_xmit_esp_setup(struct ipsec_xmit_state *ixs)
{
#ifdef CONFIG_KLIPS_ENC_3DES
	__u32 iv[2];
#endif
	struct esphdr *espp;
	int ilen = 0;
	int padlen = 0, i;
	unsigned char *dat;
	unsigned char *idat, *pad;
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

	dat = (unsigned char *)ixs->iph;

	espp = (struct esphdr *)(dat + ixs->iphlen);
	espp->esp_spi = ixs->ipsp->ips_said.spi;
	espp->esp_rpl = htonl(++(ixs->ipsp->ips_replaywin_lastseq));

	switch (ixs->ipsp->ips_encalg) {
#if defined(CONFIG_KLIPS_ENC_3DES)
#ifdef CONFIG_KLIPS_ENC_3DES
	case ESP_3DES:
#endif          /* CONFIG_KLIPS_ENC_3DES */
		iv[0] = *((__u32*)&(espp->esp_iv)    ) =
				((__u32*)(ixs->ipsp->ips_iv))[0];
		iv[1] = *((__u32*)&(espp->esp_iv) + 1) =
				((__u32*)(ixs->ipsp->ips_iv))[1];
		break;
#endif          /* defined(CONFIG_KLIPS_ENC_3DES) */
	default:
		ixs->stats->tx_errors++;
		return IPSEC_XMIT_ESP_BADALG;
	}

	idat = dat + ixs->iphlen + sizeof(struct esphdr);
	ilen = ixs->skb->len -
	       (ixs->iphlen + sizeof(struct esphdr) + ixs->authlen);

	/* Self-describing padding */
	pad = &dat[ixs->skb->len - ixs->tailroom];
	padlen = ixs->tailroom - 2 - ixs->authlen;
	for (i = 0; i < padlen; i++)
		pad[i] = i + 1;
	dat[ixs->skb->len - ixs->authlen - 2] = padlen;

	dat[ixs->skb->len - ixs->authlen - 1] = lsw_ip4_hdr(ixs)->protocol;
	lsw_ip4_hdr(ixs)->protocol = IPPROTO_ESP;

	switch (ixs->ipsp->ips_encalg) {
#ifdef CONFIG_KLIPS_ENC_3DES
	case ESP_3DES:
		des_ede3_cbc_encrypt((des_cblock *)idat,
				     (des_cblock *)idat,
				     ilen,
				     ((struct des_eks *)(ixs->ipsp->ips_key_e))[
					     0].ks,
				     ((struct des_eks *)(ixs->ipsp->ips_key_e))[
					     1].ks,
				     ((struct des_eks *)(ixs->ipsp->ips_key_e))[
					     2].ks,
				     (des_cblock *)iv,
				     1);
		break;
#endif          /* CONFIG_KLIPS_ENC_3DES */
	default:
		ixs->stats->tx_errors++;
		return IPSEC_XMIT_ESP_BADALG;
	}

	switch (ixs->ipsp->ips_encalg) {
#if defined(CONFIG_KLIPS_ENC_3DES)
#ifdef CONFIG_KLIPS_ENC_3DES
	case ESP_3DES:
#endif          /* CONFIG_KLIPS_ENC_3DES */
		/* XXX update IV with the last 8 octets of the encryption */
#if KLIPS_IMPAIRMENT_ESPIV_CBC_ATTACK
		((__u32*)(ixs->ipsp->ips_iv))[0] =
			((__u32 *)(idat))[(ilen >> 2) - 2];
		((__u32*)(ixs->ipsp->ips_iv))[1] =
			((__u32 *)(idat))[(ilen >> 2) - 1];
#else           /* KLIPS_IMPAIRMENT_ESPIV_CBC_ATTACK */
		prng_bytes(&ipsec_prng, (char *)ixs->ipsp->ips_iv,
			   EMT_ESPDES_IV_SZ);
#endif  /* KLIPS_IMPAIRMENT_ESPIV_CBC_ATTACK */
		break;
#endif  /* defined(CONFIG_KLIPS_ENC_3DES) */
	default:
		ixs->stats->tx_errors++;
		return IPSEC_XMIT_ESP_BADALG;
	}

	switch (ixs->ipsp->ips_authalg) {
#ifdef CONFIG_KLIPS_AUTH_HMAC_MD5
	case AH_MD5:
		ipsec_xmit_dmp("espp", (char*)espp,
			       ixs->skb->len - ixs->iphlen - ixs->authlen);
		tctx.md5 = ((struct md5_ctx*)(ixs->ipsp->ips_key_a))->ictx;
		ipsec_xmit_dmp("ictx", (char*)&tctx.md5, sizeof(tctx.md5));
		osMD5Update(&tctx.md5, (caddr_t)espp,
			    ixs->skb->len - ixs->iphlen - ixs->authlen);
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
		memcpy(&(dat[ixs->skb->len - ixs->authlen]), hash,
		       ixs->authlen);

		/* paranoid */
		memset((caddr_t)&tctx.md5, 0, sizeof(tctx.md5));
		memset((caddr_t)hash, 0, sizeof(*hash));
		break;
#endif          /* CONFIG_KLIPS_AUTH_HMAC_MD5 */
#ifdef CONFIG_KLIPS_AUTH_HMAC_SHA1
	case AH_SHA:
		tctx.sha1 = ((struct sha1_ctx*)(ixs->ipsp->ips_key_a))->ictx;
		SHA1Update(&tctx.sha1, (caddr_t)espp,
			   ixs->skb->len - ixs->iphlen - ixs->authlen);
		SHA1Final(hash, &tctx.sha1);
		tctx.sha1 = ((struct sha1_ctx*)(ixs->ipsp->ips_key_a))->octx;
		SHA1Update(&tctx.sha1, hash, AHSHA196_ALEN);
		SHA1Final(hash, &tctx.sha1);
		memcpy(&(dat[ixs->skb->len - ixs->authlen]), hash,
		       ixs->authlen);

		/* paranoid */
		memset((caddr_t)&tctx.sha1, 0, sizeof(tctx.sha1));
		memset((caddr_t)hash, 0, sizeof(*hash));
		break;
#endif          /* CONFIG_KLIPS_AUTH_HMAC_SHA1 */
	case AH_NONE:
		break;
	default:
		ixs->stats->tx_errors++;
		return IPSEC_XMIT_AH_BADALG;
	}

	skb_set_transport_header(ixs->skb, ipsec_skb_offset(ixs->skb, espp));

	return IPSEC_XMIT_OK;
}
#endif

struct xform_functions esp_xform_funcs[] = {
	{
		protocol:           IPPROTO_ESP,
		rcv_checks:         ipsec_rcv_esp_checks,
		rcv_setup_auth:     ipsec_rcv_esp_decrypt_setup,
		rcv_calc_auth:      ipsec_rcv_esp_authcalc,
		rcv_decrypt:        ipsec_rcv_esp_decrypt,

#if 0
		xmit_setup:         ipsec_xmit_esp_setup,
		xmit_headroom:      sizeof(struct esphdr),
		xmit_needtailroom:  1,
#endif
	},
};

#ifndef CONFIG_XFRM_ALTERNATE_STACK
#ifdef NET_26
struct inet_protocol esp_protocol = {
	.handler = ipsec_rcv,
	.no_policy = 1,
#ifdef HAVE_NAMESPACES
	.netns_ok = 1,
#endif
};

#ifdef CONFIG_KLIPS_IPV6
struct inet6_protocol esp6_protocol = {
	.handler = ipsec_rcv,
	.flags = INET6_PROTO_NOPOLICY,
};
#endif
#else
struct inet_protocol esp_protocol =
{
	ipsec_rcv,                      /* ESP handler		*/
	NULL,                           /* TUNNEL error control */
	0,                              /* next */
	IPPROTO_ESP,                    /* protocol ID */
	0,                              /* copy */
	NULL,                           /* data */
	"ESP"                           /* name */
};
#endif /* NET_26 */
#endif  /* CONFIG_XFRM_ALTERNATE_STACK */

#endif  /* !CONFIG_KLIPS_ESP */
