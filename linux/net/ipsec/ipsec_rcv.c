/*
 * receive code
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998-2003   Richard Guy Briggs.
 * Copyright (C) 2004-2007   Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2008   Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2011 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2012,2015  Paul Wouters  <paul@libreswan.org>
 * Copyright (C) 2011-2012 David McCullough <david_mccullough@mcafee.com>
 *
 * OCF/receive state machine written by
 * David McCullough <dmccullough@cyberguard.com>
 * Copyright (C) 2004-2005 Intel Corporation.  All Rights Reserved.
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0) && LINUX_VERSION_CODE >= \
	KERNEL_VERSION(2, 4, 26)
# include <linux/moduleparam.h>
#endif
#include <linux/kernel.h> /* printk() */

#include "libreswan/ipsec_param.h"

#include <linux/slab.h>		/* kmalloc() */
#include <linux/errno.h>	/* error codes */
#include <linux/types.h>	/* size_t */
#include <linux/interrupt.h>	/* mark_bh */

#include <linux/netdevice.h>	/* struct device, and other headers */
#include <linux/etherdevice.h>	/* eth_type_trans */
#include <linux/ip.h>		/* struct iphdr */

#include <net/tcp.h>
#include <net/udp.h>
#ifdef NET_26
# include <net/xfrm.h>
#endif
#include <linux/skbuff.h>
#include <libreswan.h>

#include <linux/spinlock.h> /* *lock* */
#ifdef NEED_SPINLOCK_TYPES
# include <linux/spinlock_types.h>
#endif

#include <net/ip.h>

#include "libreswan/ipsec_kversion.h"
#include "libreswan/radij.h"
#include "libreswan/ipsec_encap.h"
#include "libreswan/ipsec_sa.h"

#include "libreswan/ipsec_radij.h"
#include "libreswan/ipsec_xform.h"
#include "libreswan/ipsec_tunnel.h"
#include "libreswan/ipsec_mast.h"
#include "libreswan/ipsec_rcv.h"

#include "libreswan/ipsec_auth.h"

#include "libreswan/ipsec_esp.h"

#ifdef CONFIG_KLIPS_AH
#include "libreswan/ipsec_ah.h"
#endif /* CONFIG_KLIPS_AH */

#ifdef CONFIG_KLIPS_IPCOMP
#include "libreswan/ipsec_ipcomp.h"
#endif /* CONFIG_KLIPS_COMP */

#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include "libreswan/ipsec_proto.h"
#include "libreswan/ipsec_alg.h"

#ifdef CONFIG_KLIPS_OCF
#include "ipsec_ocf.h"
#endif

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
#include <linux/udp.h>
#endif

/* This is a private use protocol, and AT&T should be ashamed. They should have
 * used protocol # 59, which is "no next header" instead of 0xFE.
 */
#ifndef IPPROTO_ATT_HEARTBEAT
#define IPPROTO_ATT_HEARTBEAT 0xFE
#endif

/* management of buffers */
static struct ipsec_rcv_state *ipsec_rcv_state_new(void);
static void ipsec_rcv_state_delete(struct ipsec_rcv_state *irs);

/*
 * Check-replay-window routine, adapted from the original
 * by J. Hughes, from draft-ietf-ipsec-esp-des-md5-03.txt
 *
 *  This is a routine that implements a 64 packet window. This is intend-
 *  ed on being an implementation sample.
 */

int ipsec_replaywin_override = -1;
module_param(ipsec_replaywin_override, int, 0644);
MODULE_PARM_DESC(ipsec_replaywin_override,
		 "override replay window (-1=no change, 0=disable, N=override value");

DEBUG_NO_STATIC int ipsec_checkreplaywindow(struct ipsec_sa *ipsp, __u32 seq)
{
	__u32 diff;

	if (ipsec_replaywin_override >= 0)
		ipsp->ips_replaywin = ipsec_replaywin_override;

	if (ipsp->ips_replaywin == 0)	/* replay shut off */
		return 1;

	if (seq == 0)
		return 0;		/* first == 0 or wrapped */

	/* new larger sequence number */
	if (seq > ipsp->ips_replaywin_lastseq)
		return 1;		/* larger is good */

	diff = ipsp->ips_replaywin_lastseq - seq;

	/* too old or wrapped */ /* if wrapped, kill off SA? */
	if (diff >= ipsp->ips_replaywin)
		return 0;

	/* this packet already seen */
	if (ipsp->ips_replaywin_bitmap & (1 << diff))
		return 0;

	return 1;			/* out of order but good */
}

DEBUG_NO_STATIC int ipsec_updatereplaywindow(struct ipsec_sa *ipsp, __u32 seq)
{
	__u32 diff;

	if (ipsec_replaywin_override >= 0)
		ipsp->ips_replaywin = ipsec_replaywin_override;

	if (ipsp->ips_replaywin == 0)	/* replay shut off */
		return 1;

	if (seq == 0)
		return 0;		/* first == 0 or wrapped */

	/* new larger sequence number */
	if (seq > ipsp->ips_replaywin_lastseq) {
		diff = seq - ipsp->ips_replaywin_lastseq;

		/* In win, set bit for this pkt */
		if (diff < ipsp->ips_replaywin)
			ipsp->ips_replaywin_bitmap =
				(ipsp->ips_replaywin_bitmap << diff) | 1;
		else
			/* This packet has way larger seq num */
			ipsp->ips_replaywin_bitmap = 1;

		if (seq - ipsp->ips_replaywin_lastseq - 1 >
		    ipsp->ips_replaywin_maxdiff) {
			ipsp->ips_replaywin_maxdiff = seq -
						      ipsp->
						      ips_replaywin_lastseq -
						      1;
		}
		ipsp->ips_replaywin_lastseq = seq;
		return 1;		/* larger is good */
	}
	diff = ipsp->ips_replaywin_lastseq - seq;

	/* too old or wrapped */ /* if wrapped, kill off SA? */
	if (diff >= ipsp->ips_replaywin) {
/*
		if (seq < 0.25*max && ipsp->ips_replaywin_lastseq > 0.75*max) {
			ipsec_sa_delchain(ipsp);
		}
 */
		return 0;
	}
	/* this packet already seen */
	if (ipsp->ips_replaywin_bitmap & (1 << diff))
		return 0;

	ipsp->ips_replaywin_bitmap |= (1 << diff);	/* mark as seen */
	return 1;					/* out of order but good */
}

#ifdef CONFIG_KLIPS_AUTH_HMAC_MD5
struct auth_alg ipsec_rcv_md5[] = {
	{ osMD5Init, osMD5Update, osMD5Final, AHMD596_ALEN }
};

#endif /* CONFIG_KLIPS_AUTH_HMAC_MD5 */

#ifdef CONFIG_KLIPS_AUTH_HMAC_SHA1
struct auth_alg ipsec_rcv_sha1[] = {
	{ SHA1Init, SHA1Update, SHA1Final, AHSHA196_ALEN }
};
#endif /* CONFIG_KLIPS_AUTH_HMAC_MD5 */

static inline void ipsec_rcv_redodebug(struct ipsec_rcv_state *irs)
{
	if (lsw_ip_hdr_version(irs) == 4) {
		inet_addrtot(AF_INET,
			     &lsw_ip4_hdr(irs)->saddr,
			     0, irs->ipsaddr_txt,
			     sizeof(irs->ipsaddr_txt));
		inet_addrtot(AF_INET, &lsw_ip4_hdr(irs)->daddr,
			     0, irs->ipdaddr_txt,
			     sizeof(irs->ipdaddr_txt));
	} else if (lsw_ip_hdr_version(irs) == 6) {
		inet_addrtot(AF_INET6, &lsw_ip6_hdr(irs)->saddr,
			     0, irs->ipsaddr_txt,
			     sizeof(irs->ipsaddr_txt));
		inet_addrtot(AF_INET6, &lsw_ip6_hdr(irs)->daddr,
			     0, irs->ipdaddr_txt,
			     sizeof(irs->ipdaddr_txt));
	} else {
		snprintf(irs->ipsaddr_txt, sizeof(irs->ipsaddr_txt),
			 "<BAD ADDRESS>");
		snprintf(irs->ipdaddr_txt, sizeof(irs->ipdaddr_txt),
			 "<BAD ADDRESS>");
	}
}

DEBUG_NO_STATIC char *ipsec_rcv_err(int err)
{
	static char tmp[32];

	switch ((int) err) {
	case IPSEC_RCV_PENDING:			return "IPSEC_RCV_PENDING";

	case IPSEC_RCV_LASTPROTO:		return "IPSEC_RCV_LASTPROTO";

	case IPSEC_RCV_OK:			return "IPSEC_RCV_OK";

	case IPSEC_RCV_BADPROTO:		return "IPSEC_RCV_BADPROTO";

	case IPSEC_RCV_BADLEN:			return "IPSEC_RCV_BADLEN";

	case IPSEC_RCV_ESP_BADALG:		return "IPSEC_RCV_ESP_BADALG";

	case IPSEC_RCV_3DES_BADBLOCKING:	return "IPSEC_RCV_3DES_BADBLOCKING";

	case IPSEC_RCV_ESP_DECAPFAIL:		return "IPSEC_RCV_ESP_DECAPFAIL";

	case IPSEC_RCV_DECAPFAIL:		return "IPSEC_RCV_DECAPFAIL";

	case IPSEC_RCV_SAIDNOTFOUND:		return "IPSEC_RCV_SAIDNOTFOUND";

	case IPSEC_RCV_IPCOMPALONE:		return "IPSEC_RCV_IPCOMPALONE";

	case IPSEC_RCV_IPCOMPFAILED:		return "IPSEC_RCV_IPCOMPFAILED";

	case IPSEC_RCV_SAIDNOTLIVE:		return "IPSEC_RCV_SAIDNOTLIVE";

	case IPSEC_RCV_FAILEDINBOUND:		return "IPSEC_RCV_FAILEDINBOUND";

	case IPSEC_RCV_LIFETIMEFAILED:		return "IPSEC_RCV_LIFETIMEFAILED";

	case IPSEC_RCV_BADAUTH:			return "IPSEC_RCV_BADAUTH";

	case IPSEC_RCV_REPLAYFAILED:		return "IPSEC_RCV_REPLAYFAILED";

	case IPSEC_RCV_AUTHFAILED:		return "IPSEC_RCV_AUTHFAILED";

	case IPSEC_RCV_REPLAYROLLED:		return "IPSEC_RCV_REPLAYROLLED";

	case IPSEC_RCV_BAD_DECRYPT:		return "IPSEC_RCV_BAD_DECRYPT";

	case IPSEC_RCV_REALLYBAD:		return "IPSEC_RCV_REALLYBAD";

	case IPSEC_RCV_ERRMEMALLOC:		return "IPSEC_RCV_ERRMEMALLOC";
	}
	snprintf(tmp, sizeof(tmp), "%d", err);
	return tmp;
}

/*
 * here is a state machine to handle receiving ipsec packets.
 * basically we keep getting re-entered until processing is
 * complete.  For the simple case we step down the states and finish.
 * each state is ideally some logical part of the process.  If a state
 * can pend (ie., require async processing to complete),  then this
 * should be the part of last action before it returns IPSEC_RCV_PENDING
 *
 * Any particular action may alter the next_state in irs to move us to
 * a state other than the preferred "next_state",  but this is the
 * exception and is highlighted when it is done.
 *
 * prototypes for state action
 */

static enum ipsec_rcv_value ipsec_rcv_init(struct ipsec_rcv_state *irs);
static enum ipsec_rcv_value ipsec_rcv_decap_init(struct ipsec_rcv_state *irs);
static enum ipsec_rcv_value ipsec_rcv_decap_lookup(struct ipsec_rcv_state *irs);
static enum ipsec_rcv_value ipsec_rcv_auth_init(struct ipsec_rcv_state *irs);
static enum ipsec_rcv_value ipsec_rcv_auth_decap(struct ipsec_rcv_state *irs);
static enum ipsec_rcv_value ipsec_rcv_auth_calc(struct ipsec_rcv_state *irs);
static enum ipsec_rcv_value ipsec_rcv_auth_chk(struct ipsec_rcv_state *irs);
static enum ipsec_rcv_value ipsec_rcv_decrypt(struct ipsec_rcv_state *irs);
static enum ipsec_rcv_value ipsec_rcv_decap_cont(struct ipsec_rcv_state *irs);
static enum ipsec_rcv_value ipsec_rcv_cleanup(struct ipsec_rcv_state *irs);
static enum ipsec_rcv_value ipsec_rcv_complete(struct ipsec_rcv_state *irs);

/*
 * the state table and each action
 */

static struct {
	enum ipsec_rcv_value (*action)(struct ipsec_rcv_state *irs);
	int next_state;
} rcv_state_table[] = {
	[IPSEC_RSM_INIT]	=
		{ ipsec_rcv_init,	IPSEC_RSM_DECAP_INIT },
	[IPSEC_RSM_DECAP_INIT]	=
		{ ipsec_rcv_decap_init,	IPSEC_RSM_DECAP_LOOKUP },
	[IPSEC_RSM_DECAP_LOOKUP] =
		{ ipsec_rcv_decap_lookup,	IPSEC_RSM_AUTH_INIT },
	[IPSEC_RSM_AUTH_INIT]	=
		{ ipsec_rcv_auth_init,	IPSEC_RSM_AUTH_DECAP },
	[IPSEC_RSM_AUTH_DECAP]	=
		{ ipsec_rcv_auth_decap,	IPSEC_RSM_AUTH_CALC },
	[IPSEC_RSM_AUTH_CALC]	=
		{ ipsec_rcv_auth_calc,	IPSEC_RSM_AUTH_CHK },
	[IPSEC_RSM_AUTH_CHK]	=
		{ ipsec_rcv_auth_chk,	IPSEC_RSM_DECRYPT },
	[IPSEC_RSM_DECRYPT]	=
		{ ipsec_rcv_decrypt,	IPSEC_RSM_DECAP_CONT },
	[IPSEC_RSM_DECAP_CONT]	=
		{ ipsec_rcv_decap_cont,	IPSEC_RSM_CLEANUP },
	[IPSEC_RSM_CLEANUP]	=
		{ ipsec_rcv_cleanup,	IPSEC_RSM_COMPLETE },
	[IPSEC_RSM_COMPLETE]	=
		{ ipsec_rcv_complete,	IPSEC_RSM_DONE },

	[IPSEC_RSM_DONE]	=
		{ NULL,			IPSEC_RSM_DONE },
};

struct sk_buff *ipsec_rcv_unclone(struct sk_buff *skb,
				  struct ipsec_rcv_state *irs)
{
	/* if skb was cloned (most likely due to a packet sniffer such as
	   tcpdump being momentarily attached to the interface), make
	   a copy of our own to modify */
	if (skb_cloned(skb)) {
		/* include any mac header while copying.. */
		if (skb_headroom(skb) < irs->hard_header_len) {
			printk(KERN_WARNING "klips_error:ipsec_rcv_unclone: "
			       "tried to skb_push hhlen=%d, %d available.  This should never happen, please report(1).\n",
			       irs->hard_header_len,
			       skb_headroom(skb));
			return NULL;
		}
		skb_push(skb, irs->hard_header_len);
		if
		(skb_cow(skb, skb_headroom(skb)) != 0)
			return NULL;

		if (skb->len < irs->hard_header_len) {
			printk(KERN_WARNING "klips_error:ipsec_rcv_unclone: "
			       "tried to skb_pull hhlen=%d, %d available.  This should never happen, please report(2).\n",
			       irs->hard_header_len,
			       skb->len);
			return NULL;
		}
		skb_pull(skb, irs->hard_header_len);
	}
	return skb;

}

#if !defined(NET_26) && defined(CONFIG_IPSEC_NAT_TRAVERSAL)
/*
 * decapsulate a UDP encapsulated ESP packet
 */
struct sk_buff *ipsec_rcv_natt_decap(struct sk_buff *skb,
				     struct ipsec_rcv_state *irs,
				     int *udp_decap_ret_p)
{
	*udp_decap_ret_p = 0;
	if (skb->sk && ip_hdr(skb) && ip_hdr(skb)->protocol == IPPROTO_UDP) {
		/**
		 * Packet comes from udp_queue_rcv_skb so it is already defrag,
		 * checksum verified, ... (ie safe to use)
		 *
		 * If the packet is not for us, return -1 and udp_queue_rcv_skb
		 * will continue to handle it (do not kfree skb !!).
		 */

#ifndef UDP_OPT_IN_SOCK
		struct udp_opt {
			__u32 esp_in_udp;
		};
		struct udp_opt *tp =
			(struct udp_opt *)&(skb->sk->tp_pinfo.af_tcp);
#else
		struct udp_opt *tp =  &(skb->sk->tp_pinfo.af_udp);
#endif

		struct iphdr *ip = ip_hdr(skb);
		struct udphdr *udp = (struct udphdr *)((__u32 *)ip + ip->ihl);
		__u8 *udpdata = (__u8 *)udp + sizeof(struct udphdr);
		__u32 *udpdata32 = (__u32 *)udpdata;

		irs->natt_sport = ntohs(udp->source);
		irs->natt_dport = ntohs(udp->dest);

		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_natt_decap: "
			    "suspected ESPinUDP packet (NAT-Traversal) [%d].\n",
			    tp->esp_in_udp);
		KLIPS_IP_PRINT(debug_rcv, ip);

		if (udpdata < skb->tail) {
			unsigned int len = skb->tail - udpdata;
			if ((len == 1) && (udpdata[0] == 0xff)) {
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv_natt_decap: "
					    /* not IPv6 compliant message */
					    "NAT-keepalive from %pI4.\n",
					    &ip->saddr);
				*udp_decap_ret_p = 0;
				return NULL;
			} else if (tp->esp_in_udp == ESPINUDP_WITH_NON_IKE &&
				   len > 2 * sizeof(__u32) +
					sizeof(struct esphdr) &&
				   udpdata32[0] == 0 &&
				   udpdata32[1] == 0) {
				/* ESP Packet with Non-IKE header */
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv_natt_decap: "
					    "ESPinUDP pkt with Non-IKE - spi=0x%x\n",
					    ntohl(udpdata32[2]));
				irs->natt_type = ESPINUDP_WITH_NON_IKE;
				irs->natt_len = sizeof(struct udphdr) +
						(2 * sizeof(__u32));
			} else if (tp->esp_in_udp == ESPINUDP_WITH_NON_ESP &&
				   len > sizeof(struct esphdr) &&
				   udpdata32[0] != 0) {
				/* ESP Packet without Non-ESP header */
				irs->natt_type = ESPINUDP_WITH_NON_ESP;
				irs->natt_len = sizeof(struct udphdr);
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv_natt_decap: "
					    "ESPinUDP pkt without Non-ESP - spi=0x%x\n",
					    ntohl(udpdata32[0]));
			} else {
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv_natt_decap: "
					    "IKE packet - not handled here\n");
				*udp_decap_ret_p = -1;
				return NULL;
			}
		} else {
			return NULL;
		}
	}
	return skb;
}
#endif

void ipsec_rcv_setoutif(struct ipsec_rcv_state *irs)
{
	struct sk_buff *skb = irs->skb;

	if (skb != NULL && irs->ipsp->ips_out) {
		if (skb->dev != irs->ipsp->ips_out) {
			KLIPS_PRINT(debug_rcv,
				    "changing originating interface from %s to %s\n",
				    skb->dev->name,
				    irs->ipsp->ips_out->name);
		}
		skb->dev = irs->ipsp->ips_out;

#ifdef USE_NETDEV_OPS
		if (skb->dev && skb->dev->netdev_ops->ndo_get_stats) {
			struct net_device_stats *stats =
				skb->dev->netdev_ops->ndo_get_stats(skb->dev);
			irs->stats = stats;
		}
#else
		if (skb->dev && skb->dev->get_stats) {
			struct net_device_stats *stats = skb->dev->get_stats(
				skb->dev);
			irs->stats = stats;
		}
#endif
	}
}

static enum ipsec_rcv_value ipsec_rcv_decap_ipip(struct ipsec_rcv_state *irs)
{
	struct ipsec_sa *ipsp;
	struct ipsec_sa *ipsnext = NULL;
	struct sk_buff *skb;
	struct iphdr *ipp = lsw_ip4_hdr(irs);

#ifdef CONFIG_KLIPS_IPV6
	struct ipv6hdr *ipp6 = lsw_ip6_hdr(irs);
#endif	/* CONFIG_KLIPS_IPV6 */
	int failed_inbound_check = 0;
	enum ipsec_rcv_value result = IPSEC_RCV_DECAPFAIL;

	ipsp = irs->ipsp;
	skb  = irs->skb;
	irs->sa_len =
		KLIPS_SATOT(debug_rcv, &irs->said, 0, irs->sa,
			    sizeof(irs->sa));
	if (ipp->version == 4 &&
	    ipp->protocol != IPPROTO_IPIP &&
	    ipp->protocol != IPPROTO_IPV6 &&
	    ipp->protocol != IPPROTO_ATT_HEARTBEAT) {	/* AT&T heartbeats to SIG/GIG */
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_decap_ipip: "
			    "SA:%s, Hey!  How did this get through?  Dropped.\n",
			    irs->sa_len ? irs->sa : " (error)");
		if (irs->stats)
			irs->stats->rx_dropped++;
		goto rcvleave;
	}
	if (sysctl_ipsec_inbound_policy_check) {
		struct sockaddr_in *psin = NULL;
		struct sockaddr_in6 *psin6 = NULL;

		if ((ipsnext = ipsp->ips_next)) {
			char sa2[SATOT_BUF];
			size_t sa_len2;
			sa_len2 = KLIPS_SATOT(debug_rcv, &ipsnext->ips_said, 0,
					      sa2, sizeof(sa2));
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv_decap_ipip: "
				    "unexpected SA:%s after IPIP SA:%s\n",
				    sa_len2 ? sa2 : " (error)",
				    irs->sa_len ? irs->sa : " (error)");
			if (irs->stats)
				irs->stats->rx_dropped++;
			goto rcvleave;
		}

		if (((struct sockaddr_in6*)(ipsp->ips_addr_s))->sin6_family ==
		    AF_INET6)
			psin6 = (struct sockaddr_in6*)(ipsp->ips_addr_s);
		else if (((struct sockaddr_in*)(ipsp->ips_addr_s))->sin_family
			 == AF_INET)
			psin = (struct sockaddr_in*)(ipsp->ips_addr_s);
		if ((psin && ipp->saddr != psin->sin_addr.s_addr)
#ifdef CONFIG_KLIPS_IPV6
		    || (psin6 &&
			memcmp(&ipp6->saddr, &psin6->sin6_addr,
			       sizeof(ipp6->saddr)) != 0)
#endif
		    ) {
			char saddr1[SUBNETTOA_BUF], saddr2[SUBNETTOA_BUF];
			*saddr1 = 0;
#ifdef CONFIG_KLIPS_IPV6
			if (ipp->version == 6)
				inet_addrtot(AF_INET6, &ipp6->saddr, 0, saddr1,
					     sizeof(saddr1));
			else
#endif
			inet_addrtot(AF_INET, &ipp->saddr, 0, saddr1,
				     sizeof(saddr1));
			*saddr2 = 0;
			sin_addrtot(&psin->sin_addr, 0, saddr2,
				    sizeof(saddr2));
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv_decap_ipip: "
				    "SA:%s, src=%s(%s) does match expected %s.\n",
				    irs->sa_len ? irs->sa : " (error)",
				    irs->ipsaddr_txt,
				    saddr1, saddr2);
			if (irs->stats)
				irs->stats->rx_dropped++;
			goto rcvleave;
		}
	}

	ipsec_rcv_setoutif(irs);

	/* added to support AT&T heartbeats to SIG/GIG */
	if ((ipp->version == 4 || ipp->version == 6) &&
	    (irs->proto == IPPROTO_IPIP || irs->proto == IPPROTO_IPV6)) {
		/*
		 * XXX this needs to be locked from when it was first looked
		 * up in the decapsulation loop.  Perhaps it is better to put
		 * the IPIP decap inside the loop.
		 */
		ipsp->ips_life.ipl_bytes.ipl_count += skb->len;
		ipsp->ips_life.ipl_bytes.ipl_last   = skb->len;

		if (!ipsp->ips_life.ipl_usetime.ipl_count)
			ipsp->ips_life.ipl_usetime.ipl_count = jiffies / HZ;
		ipsp->ips_life.ipl_usetime.ipl_last = jiffies / HZ;
		ipsp->ips_life.ipl_packets.ipl_count += 1;

		/* new L3 header is where L4 payload was */
		skb_set_network_header(skb,
				       ipsec_skb_offset(skb,
							skb_transport_header(
								skb)));

		/* now setup new L4 payload location */
		ipp = (struct iphdr *)skb_network_header(skb);
#ifdef CONFIG_KLIPS_IPV6
		ipp6 = (struct ipv6hdr *) ipp;
		if (ipp->version == 6) {
			IPSEC_FRAG_OFF_DECL(frag_off)
			unsigned char nexthdr = ipp6->nexthdr;
			int nexthdroff;
			nexthdroff = ipsec_ipv6_skip_exthdr(skb,
							    ipsec_skb_offset(
								    skb,
								    ipp6 + 1),
							    &nexthdr,
							    &frag_off);
			skb_set_transport_header(skb,
						 ipsec_skb_offset(skb,
								  (void*)skb->
								  data +
								  nexthdroff));
			irs->iphlen = nexthdroff - ipsec_skb_offset(skb, ipp6);
		} else
#endif		/* CONFIG_KLIPS_IPV6 */
		{
			skb_set_transport_header(skb,
						 ipsec_skb_offset(skb,
								  skb_network_header(
									  skb)
								  +
								  (ipp->ihl <<
								   2)));
			irs->iphlen = ipp->ihl << 2;
		}

		if (skb->len < irs->iphlen) {
			printk(KERN_WARNING "klips_debug:ipsec_rcv_decap_ipip: "
			       "tried to skb_pull iphlen=%d, %d available.  This should never happen, please report(3).\n",
			       irs->iphlen,
			       (int)(skb->len));

			goto rcvleave;
		}

		/*
		 * we need to pull up by size of the new IP header,
		 * + options, but also by any UDP/ESP encap there might
		 * have been, and this deals with all cases.
		 */
		skb_pull(skb,
			 (skb_transport_header(skb) -
			  skb_network_header(skb)));

		/* remove any saved options that we might have,
		 * since we have a new IP header.
		 */
		memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));

#if 0
		KLIPS_PRINT(debug_rcv, "csum: %d\n",
			    ip_fast_csum((u8 *)ipp, ipp->ihl));
#endif

		/* re-do any strings for debugging */
		irs->iph = (void*)ipp;
		if (debug_rcv)
			ipsec_rcv_redodebug(irs);

		if (lsw_ip_hdr_version(irs) == 6)
			skb->protocol = htons(ETH_P_IPV6);
		else
			skb->protocol = htons(ETH_P_IP);
		skb->ip_summed = 0;
		KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
			    "klips_debug:ipsec_rcv_decap_ipip: "
			    "IPIP tunnel stripped.\n");
		KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, ipp);
	}

	if (sysctl_ipsec_inbound_policy_check) {
		/*
		   Note: "xor" (^) logically replaces "not equal"
		   (!=) and "bitwise or" (|) logically replaces
		   "boolean or" (||).  This is done to speed up
		   execution by doing only bitwise operations and
		   no branch operations
		 */
		if (ipp->version == 4) {
			if (ip_address_family(&ipsp->ips_flow_s) != AF_INET)
				failed_inbound_check = 1;
			else if (ip_address_family(&ipsp->ips_flow_d) !=
				 AF_INET)
				failed_inbound_check = 1;
			else if (((ipp->saddr &
				   ipsp->ips_mask_s.u.v4.sin_addr.s_addr) ^
				  ipsp->ips_flow_s.u.v4.sin_addr.s_addr) |
				 ((ipp->daddr &
				   ipsp->ips_mask_d.u.v4.sin_addr.s_addr) ^
				  ipsp->ips_flow_d.u.v4.sin_addr.s_addr))
				failed_inbound_check = 1;
		}
#ifdef CONFIG_KLIPS_IPV6
		else if (ipp->version == 6) {
			/* boilerplate macro for Bad Bits in address */
#define BB(end, i) ((ipp6->end##addr.s6_addr32[i] & \
		     ipsp->ips_mask_##end.u.v6.sin6_addr.s6_addr32[i]) ^ \
		    ipsp->ips_flow_##end.u.v6.sin6_addr.s6_addr32[i])

			if (ip_address_family(&ipsp->ips_flow_s) != AF_INET6)
				failed_inbound_check = 1;
			else if (ip_address_family(&ipsp->ips_flow_d) !=
				 AF_INET6)
				failed_inbound_check = 1;
			else if (BB(s, 0) | BB(d, 0) |
				 BB(s, 1) | BB(d, 1) |
				 BB(s, 2) | BB(d, 2) |
				 BB(s, 3) | BB(d, 3))
				failed_inbound_check = 1;
#undef BB
		}
#endif		/* CONFIG_KLIPS_IPV6 */
	}
	if (failed_inbound_check) {
		char sflow_txt[SUBNETTOA_BUF], dflow_txt[SUBNETTOA_BUF];

#ifdef CONFIG_KLIPS_IPV6
		if (ipsp->ips_flow_s.u.v6.sin6_family == AF_INET6) {
			subnet6toa(&ipsp->ips_flow_s.u.v6.sin6_addr,
				   &ipsp->ips_mask_s.u.v6.sin6_addr,
				   0, sflow_txt, sizeof(sflow_txt));
			subnet6toa(&ipsp->ips_flow_d.u.v6.sin6_addr,
				   &ipsp->ips_mask_d.u.v6.sin6_addr,
				   0, dflow_txt, sizeof(dflow_txt));
		} else
#endif
		{
			subnettoa(ipsp->ips_flow_s.u.v4.sin_addr,
				  ipsp->ips_mask_s.u.v4.sin_addr,
				  0, sflow_txt, sizeof(sflow_txt));
			subnettoa(ipsp->ips_flow_d.u.v4.sin_addr,
				  ipsp->ips_mask_d.u.v4.sin_addr,
				  0, dflow_txt, sizeof(dflow_txt));
		}
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_decap_ipip: "
			    "SA:%s, inner tunnel policy [%s -> %s] does not agree with pkt contents [%s -> %s].\n",
			    irs->sa_len ? irs->sa : " (error)",
			    sflow_txt,
			    dflow_txt,
			    irs->ipsaddr_txt,
			    irs->ipdaddr_txt);
		if (irs->stats)
			irs->stats->rx_dropped++;
		goto rcvleave;
	}
#if 0
	if (sysctl_ipsec_inbound_policy_check) {
		char sflow_txt[SUBNETTOA_BUF], dflow_txt[SUBNETTOA_BUF];

		subnettoa(ipsp->ips_flow_s.u.v4.sin_addr,
			  ipsp->ips_mask_s.u.v4.sin_addr,
			  0, sflow_txt, sizeof(sflow_txt));
		subnettoa(ipsp->ips_flow_d.u.v4.sin_addr,
			  ipsp->ips_mask_d.u.v4.sin_addr,
			  0, dflow_txt, sizeof(dflow_txt));

		KLIPS_PRINT(debug_mast,
			    "klips_debug:ipsec_rcv_decap_ipip: "
			    "SA:%s, inner tunnel policy [%s -> %s] agrees with pkt contents [%s -> %s].\n",
			    irs->sa_len ? irs->sa : " (error)",
			    sflow_txt, dflow_txt,
			    irs->ipsaddr_txt,
			    irs->ipdaddr_txt);
	}
#endif
#if defined(CONFIG_KLIPS_COMPAT_NAT_NFMARK)
#if defined(CONFIG_NETFILTER)
	skb->nfmark = IPSEC_NFMARK_IS_SAREF_BIT |
		      (skb->nfmark &
		       (~(IPsecSAref2NFmark(IPSEC_SA_REF_MASK)))) |
		      IPsecSAref2NFmark(IPsecSA2SAref(ipsp));
	KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
		    "klips_debug:ipsec_rcv_decap_ipip: "
		    "IPIP SA sets skb->nfmark=0x%x.\n",
		    (unsigned)skb->nfmark);
#endif	/* CONFIG_NETFILTER */
#endif
	result = IPSEC_RCV_OK;

rcvleave:
	return result;
}

/*
 * get all the initial checking and setup done.  None of this can be off
 * loaded by any currently support hardware
 *
 * the following things should be setup when we exit this function.
 *
 * irs->stats	== stats structure (or NULL)
 * irs->ipp	= IP header.
 * irs->len	= total length of packet
 * skb->nh.iph	= ipp;
 * skb->h.raw	= start of payload
 * irs->ipsp	= NULL.
 * irs->iphlen	= N/A = is recalculated.
 * irs->ilen	= 0;
 * irs->authlen	= 0;
 * irs->authfuncs	= NULL;
 * irs->skb	= the skb;
 *
 * proto_funcs should be from ipsec_esp.c, ipsec_ah.c or ipsec_ipcomp.c.
 *
 */

static enum ipsec_rcv_value ipsec_rcv_init(struct ipsec_rcv_state *irs)
{
	struct net_device_stats *stats = NULL;		/* This device's statistics */
	int i;
	struct sk_buff *skb;

	KLIPS_PRINT(debug_rcv, "klips_debug: %s(st=%d,nxt=%d)\n", __FUNCTION__,
		    irs->state, irs->next_state);

	if (irs == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_init: NULL irs.");
		return IPSEC_RCV_REALLYBAD;
	}

	skb = irs->skb;
	if (!skb) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_init: NULL skb.");
		return IPSEC_RCV_REALLYBAD;
	}

	if (skb->data == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_init: "
			    "NULL skb->data passed in, packet is bogus, dropping.\n");
		return IPSEC_RCV_REALLYBAD;
	}

	/* dev->hard_header_len is unreliable and should not be used */
	/* klips26_rcv_encap will have already set hard_header_len for us */
	if (irs->hard_header_len == 0) {
		irs->hard_header_len = skb_mac_header(skb) ?
			(skb_network_header(skb) - skb_mac_header(skb)) : 0;
		if ((irs->hard_header_len < 0) ||
		    (irs->hard_header_len > skb_headroom(skb)))
			irs->hard_header_len = 0;
	}

	skb = ipsec_rcv_unclone(skb, irs);
	if (skb == NULL)
		return IPSEC_RCV_REALLYBAD;

	/* In Linux >2.4.4, we may have to reassemble fragments. They are
	   not assembled automatically to save TCP from having to copy
	   twice.
	 */
	if (skb_is_nonlinear(skb)) {
#ifdef HAVE_NEW_SKB_LINEARIZE
		if (skb_linearize_cow(skb) != 0)
#else
		if (skb_linearize(skb, GFP_ATOMIC) != 0)
#endif

			return IPSEC_RCV_REALLYBAD;
	}

	irs->iph = (void *)ip_hdr(skb);

#if defined(CONFIG_IPSEC_NAT_TRAVERSAL) && !defined(NET_26)
	if (irs->natt_len) {
		/**
		 * Now, we are sure packet is ESPinUDP, and we have a private
		 * copy that has been linearized, remove natt_len bytes
		 * from packet and modify protocol to ESP.
		 */
		if (((unsigned char *)skb->data >
		     (unsigned char *)ip_hdr(skb)) &&
		    ((unsigned char *)ip_hdr(skb) >
		     (unsigned char *)skb->head)) {
			unsigned int _len = (unsigned char *)skb->data -
					    (unsigned char *)ip_hdr(skb);
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv_init: adjusting skb: skb_push(%u)\n",
				    _len);
			skb_push(skb, _len);
		}
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_init: "
			    "removing %d bytes from ESPinUDP packet\n",
			    irs->natt_len);

		irs->iph = (struct iphdr *)skb->data;
		irs->iphlen = lsw_ip4_hdr(irs)->ihl << 2;
		lsw_ip4_hdr(irs)->tot_len =
			htons(ntohs(lsw_ip4_hdr(irs)->tot_len) -
			      irs->natt_len);
		if (skb->len < irs->iphlen + irs->natt_len) {
			printk(KERN_WARNING
			       "klips_error:ipsec_rcv_init: "
			       "ESPinUDP packet is too small (%d < %d+%d). "
			       "This should never happen, please report.\n",
			       (int)(skb->len), irs->iphlen, irs->natt_len);
			return IPSEC_RCV_REALLYBAD;
		}

		/* advance payload pointer to point past the UDP header */
		skb->h.raw = skb->h.raw + irs->natt_len;

		/* modify protocol */
		lsw_ip4_hdr(irs)->protocol = IPPROTO_ESP;

		skb->sk = NULL;

		KLIPS_IP_PRINT(debug_rcv, ip_hdr(skb));
	}
#endif

	if (debug_rcv)
		ipsec_rcv_redodebug(irs);

#ifdef CONFIG_KLIPS_IPV6
	if (lsw_ip_hdr_version(irs) == 6) {
		IPSEC_FRAG_OFF_DECL(frag_off)
		int nexthdroff;
		irs->proto = lsw_ip6_hdr(irs)->nexthdr;
		nexthdroff = ipsec_ipv6_skip_exthdr(irs->skb,
						    ((void *)(lsw_ip6_hdr(
								      irs) +
							      1)) - (void*)irs->skb->data,
						    &irs->proto, &frag_off);
		irs->iphlen = nexthdroff - (irs->iph - (void*)irs->skb->data);
	} else
#endif	/* CONFIG_KLIPS_IPV6 */
	{
		irs->iphlen = lsw_ip4_hdr(irs)->ihl << 2;
		irs->proto = lsw_ip4_hdr(irs)->protocol;
	}

	KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv_init: "
		    "<<< Info -- ");
	KLIPS_PRINTMORE(debug_rcv && skb->dev, "skb->dev=%s ",
			skb->dev->name ? skb->dev->name : "NULL");
	KLIPS_PRINTMORE(debug_rcv, "\n");

	if (irs->proto != IPPROTO_AH &&
#ifdef CONFIG_KLIPS_IPCOMP_disabled_until_we_register_IPCOMP_HANDLER
	    irs->proto != IPPROTO_COMP &&
#endif	/* CONFIG_KLIPS_IPCOMP */
	    irs->proto != IPPROTO_ESP) {
		KLIPS_PRINT(debug_rcv & DB_RX_IPSA,
			    "klips_debug:ipsec_rcv_init: Why the hell is someone "
			    "passing me a non-ipsec irs->proto = %d packet? -- dropped.\n",
			    irs->proto);
		return IPSEC_RCV_REALLYBAD;
	}

	/*
	 * if there is an attached ipsec device, then use that device for
	 * stats until we know better.
	 */
	if (skb->dev) {
		struct ipsecpriv  *prvdev = NULL;
		struct net_device *ipsecdev = NULL;

		for (i = 0; i <= ipsecdevices_max; i++) {
			if (ipsecdevices[i] == NULL)
				continue;
			if (!netdev_priv(ipsecdevices[i]))
				continue;

			prvdev = netdev_to_ipsecpriv(ipsecdevices[i]);

			if (prvdev->dev == skb->dev) {
				ipsecdev = ipsecdevices[i];
				break;
			}
		}

		if (ipsecdev) {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv_init: "
				    "assigning packet ownership to "
				    "virtual device %s from "
				    "physical device %s.\n",
				    ipsecdev->name, skb->dev->name);
			skb->dev = ipsecdev;
		} else {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv_init: "
				    "assigning packet ownership to "
				    "virtual device mast0 from "
				    "physical device %s.\n",
				    skb->dev->name);

			skb->dev = ipsec_mast_get_device(0);

			/* ipsec_mast_get takes the device */
			if (skb->dev)
				dev_put(skb->dev);
		}

		if (prvdev)
			stats = (struct net_device_stats *) &(prvdev->mystats);
	} else {
		KLIPS_PRINT(debug_rcv, "klips_debug:ipsec_rcv_init: "
			    "device supplied with skb is NULL\n");
	}

	if (stats)
		stats->rx_packets++;

	KLIPS_IP_PRINT(debug_rcv, irs->iph);

	/* set up for decap */
	irs->stats = stats;
	irs->ipsp = NULL;
	irs->lastipsp = NULL;
	irs->ilen = 0;
	irs->authlen = 0;
	irs->authfuncs = NULL;
	irs->skb = skb;
	return IPSEC_RCV_OK;
}

static enum ipsec_rcv_value ipsec_rcv_decap_init(struct ipsec_rcv_state *irs)
{
	KLIPS_PRINT(debug_rcv, "klips_debug: %s(st=%d,nxt=%d)\n", __FUNCTION__,
		    irs->state, irs->next_state);

	switch (irs->proto) {
	case IPPROTO_ESP:
		irs->proto_funcs = esp_xform_funcs;
		break;

#ifdef CONFIG_KLIPS_AH
	case IPPROTO_AH:
		irs->proto_funcs = ah_xform_funcs;
		break;
#endif		/* !CONFIG_KLIPS_AH */

#ifdef CONFIG_KLIPS_IPCOMP
	case IPPROTO_COMP:
		irs->proto_funcs = ipcomp_xform_funcs;
		break;
#endif		/* !CONFIG_KLIPS_IPCOMP */

	default:
		if (irs->stats)
			irs->stats->rx_errors++;
		return IPSEC_RCV_BADPROTO;
	}
	return IPSEC_RCV_OK;
}

static enum ipsec_rcv_value ipsec_rcv_decap_lookup(struct ipsec_rcv_state *irs)
{
	struct sk_buff *skb;

	KLIPS_PRINT(debug_rcv, "klips_debug: %s(st=%d,nxt=%d)\n", __FUNCTION__,
		    irs->state, irs->next_state);

	irs->replay = 0;
#ifdef CONFIG_KLIPS_ALG
	irs->ixt_a = NULL;
#endif	/* CONFIG_KLIPS_ALG */

	skb = irs->skb;
	irs->len = skb->len;
	if (debug_rcv)
		ipsec_rcv_redodebug(irs);

	if (lsw_ip_hdr_version(irs) == 6) {
		irs->said.dst.u.v6.sin6_addr = lsw_ip6_hdr(irs)->daddr;
		SET_V6(irs->said.dst);
	} else {
		irs->said.dst.u.v4.sin_addr.s_addr = lsw_ip4_hdr(irs)->daddr;
		SET_V4(irs->said.dst);
	}

	/* note: rcv_checks set up the said.spi value, if appropriate */
	if (irs->proto_funcs->rcv_checks)
		return (*irs->proto_funcs->rcv_checks)(irs, irs->skb);

	return IPSEC_RCV_OK;
}

static enum ipsec_rcv_value ipsec_rcv_auth_init(struct ipsec_rcv_state *irs)
{
	struct ipsec_sa *newipsp;

	KLIPS_PRINT(debug_rcv, "klips_debug: %s(st=%d,nxt=%d)\n", __FUNCTION__,
		    irs->state, irs->next_state);

	irs->said.proto = irs->proto;
	irs->sa_len =
		KLIPS_SATOT(debug_rcv, &irs->said, 0, irs->sa,
			    sizeof(irs->sa));
	newipsp = ipsec_sa_getbyid(&irs->said, IPSEC_REFRX);
	if (newipsp == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_auth_init: "
			    "no ipsec_sa for SA:%s: incoming packet with no SA dropped\n",
			    irs->sa_len ? irs->sa : " (error)");
		if (irs->stats)
			irs->stats->rx_dropped++;
		return IPSEC_RCV_SAIDNOTFOUND;
	}

	/* If it is in larval state, drop the packet, we cannot process yet. */
	if (newipsp->ips_state == K_SADB_SASTATE_LARVAL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_auth_init: "
			    "ipsec_sa in larval state, cannot be used yet, dropping packet.\n");
		if (irs->stats)
			irs->stats->rx_dropped++;
		ipsec_sa_put(newipsp, IPSEC_REFRX);
		return IPSEC_RCV_SAIDNOTLIVE;
	}

	if (newipsp->ips_state == K_SADB_SASTATE_DEAD) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_auth_init: "
			    "ipsec_sa in dead state, cannot be used any more, dropping packet.\n");
		if (irs->stats)
			irs->stats->rx_dropped++;
		ipsec_sa_put(newipsp, IPSEC_REFRX);
		return IPSEC_RCV_SAIDNOTLIVE;
	}

	if (sysctl_ipsec_inbound_policy_check) {
		struct sockaddr_in *psin = NULL;
		struct sockaddr_in6 *psin6 = NULL;
		char sa_saddr_txt[ADDRTOA_BUF] = { 0, };

		if (((struct sockaddr_in6*)(newipsp->ips_addr_s))->sin6_family
		    == AF_INET6)
			psin6 = (struct sockaddr_in6*)(newipsp->ips_addr_s);
		else if (((struct sockaddr_in*)(newipsp->ips_addr_s))->
			 sin_family == AF_INET)
			psin = (struct sockaddr_in*)(newipsp->ips_addr_s);
		if ((psin && lsw_ip4_hdr(irs)->saddr !=
		     psin->sin_addr.s_addr) ||
		    (psin6 &&
		     memcmp(&lsw_ip6_hdr(irs)->saddr, &psin6->sin6_addr,
			    sizeof(lsw_ip6_hdr(irs)->saddr)) != 0)) {
			if (debug_rcv) {
				/* generate SA->saddr */
				if (psin) {
					inet_addrtot(AF_INET,
						     &psin->sin_addr.s_addr, 0,
						     sa_saddr_txt,
						     sizeof(sa_saddr_txt));
				} else if (psin6) {
					inet_addrtot(AF_INET6,
						     &psin6->sin6_addr.s6_addr,
						     0,
						     sa_saddr_txt,
						     sizeof(sa_saddr_txt));
				}
				/* generate ipsaddr_txt */
				if (!(*irs->ipsaddr_txt))
					ipsec_rcv_redodebug(irs);
				/* regenerate sa_len */
				if (!irs->sa_len) {
					irs->sa_len = KLIPS_SATOT(debug_rcv,
								  &irs->said,
								  0,
								  irs->sa,
								  sizeof(irs->
									 sa));
				}
			}
			KLIPS_ERROR(debug_rcv,
				    "klips_debug:ipsec_rcv_auth_init: "
				    "SA:%s, src=%s of pkt does not agree with expected SA source address policy (%s).\n",
				    irs->sa_len ? irs->sa : " (error)",
				    irs->ipsaddr_txt,
				    sa_saddr_txt);
			if (irs->stats)
				irs->stats->rx_dropped++;
			ipsec_sa_put(newipsp, IPSEC_REFRX);
			return IPSEC_RCV_FAILEDINBOUND;
		}

		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_auth_init: "
			    "SA:%s, src=%s of pkt agrees with expected SA source address policy.\n",
			    irs->sa_len ? irs->sa : " (error)",
			    irs->ipsaddr_txt);

		/*
		 * at this point, we have looked up a new SA, and we want to
		 * make sure that if this isn't the first SA in the list,
		 * that the previous SA actually points at this one.
		 */
		if (irs->ipsp) {
			if (irs->ipsp->ips_next != newipsp) {
				KLIPS_ERROR(debug_rcv,
					    "klips_debug:ipsec_rcv_auth_init: "
					    "unexpected SA:%s: does not agree with ips->inext policy, dropped\n",
					    irs->sa_len ? irs->sa : " (error)");
				if (irs->stats)
					irs->stats->rx_dropped++;
				ipsec_sa_put(newipsp, IPSEC_REFRX);
				return IPSEC_RCV_FAILEDINBOUND;
			}
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv_auth_init: "
				    "SA:%s grouping from previous SA is OK.\n",
				    irs->sa_len ? irs->sa : " (error)");
		} else {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv_auth_init: "
				    "SA:%s First SA in group.\n",
				    irs->sa_len ? irs->sa : " (error)");
		}

		if (irs->proto == IPPROTO_ESP) {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv_auth_init: "
				    "natt_type=%u tdbp->ips_natt_type=%u : %s\n",
				    irs->natt_type, newipsp->ips_natt_type,
				    (irs->natt_type == newipsp->ips_natt_type) ?
					"ok" : "bad");
			if (irs->natt_type != newipsp->ips_natt_type) {
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv_auth_init: "
					    "SA:%s does not agree with expected NAT-T policy.\n",
					    irs->sa_len ? irs->sa : " (error)");
				if (irs->stats)
					irs->stats->rx_dropped++;
				ipsec_sa_put(newipsp, IPSEC_REFRX);
				return IPSEC_RCV_FAILEDINBOUND;
			}
		}
	}

	if (newipsp != irs->ipsp) {
		if (irs->lastipsp)
			ipsec_sa_put(irs->lastipsp, IPSEC_REFRX);
		irs->lastipsp = irs->ipsp;
		irs->ipsp = newipsp;
	} else {
		/* we already have a refcount for it */
		ipsec_sa_put(newipsp, IPSEC_REFRX);
	}

	return IPSEC_RCV_OK;
}

static enum ipsec_rcv_value ipsec_rcv_auth_decap(struct ipsec_rcv_state *irs)
{
	ipsec_rcv_setoutif(irs);

	irs->proto_funcs = irs->ipsp->ips_xformfuncs;
	if (irs->proto_funcs == NULL)
		return IPSEC_RCV_BADPROTO;

	if (irs->proto_funcs->protocol != irs->proto) {
		if (irs->proto_funcs->protocol == IPPROTO_COMP) {
			/* looks like an IPCOMP that we can skip */
			struct ipsec_sa *newipsp;

			newipsp = irs->ipsp->ips_next;
			if (newipsp)
				ipsec_sa_get(newipsp, IPSEC_REFRX);
			if (irs->lastipsp)
				ipsec_sa_put(irs->lastipsp, IPSEC_REFRX);
			irs->lastipsp = irs->ipsp;
			irs->ipsp = newipsp;

			/* come back into here with the next transform */
			irs->next_state = IPSEC_RSM_DECAP_INIT;
			return IPSEC_RCV_OK;
		}

		KLIPS_PRINT(debug_rcv, "klips_debug:ipsec_rcv_auth_decap: "
			    "packet with protocol %d!=%d dropped, last successful SA:%s.\n",
			    irs->proto_funcs->protocol, irs->proto,
			    irs->sa_len ? irs->sa : " (error)");
		if (irs->stats)
			irs->stats->rx_errors++;
		return IPSEC_RCV_FAILEDINBOUND;
	}

	if (debug_rcv)
		ipsec_rcv_redodebug(irs);

	/* now check the lifetimes */
	if (ipsec_lifetime_check(&irs->ipsp->ips_life.ipl_bytes,   "bytes",
				 irs->sa, ipsec_life_countbased,
				 ipsec_incoming,
				 irs->ipsp) == ipsec_life_harddied ||
	    ipsec_lifetime_check(&irs->ipsp->ips_life.ipl_addtime, "addtime",
				 irs->sa, ipsec_life_timebased,
				 ipsec_incoming,
				 irs->ipsp) == ipsec_life_harddied ||
	    ipsec_lifetime_check(&irs->ipsp->ips_life.ipl_addtime, "usetime",
				 irs->sa, ipsec_life_timebased,
				 ipsec_incoming,
				 irs->ipsp) == ipsec_life_harddied ||
	    ipsec_lifetime_check(&irs->ipsp->ips_life.ipl_packets, "packets",
				 irs->sa, ipsec_life_countbased,
				 ipsec_incoming,
				 irs->ipsp) == ipsec_life_harddied) {
		/*
		 * disconnect SA from the hash table, so it cannot be
		 * found again.
		 */
		ipsec_sa_rm(irs->ipsp);
		if (irs->stats)
			irs->stats->rx_dropped++;

		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_auth_decap: "
			    "decap (%d) failed lifetime check\n",
			    irs->proto);

		return IPSEC_RCV_LIFETIMEFAILED;
	}

#if 0
	/*
	 * This is removed for some reasons:
	 *   1) it needs to happen *after* authentication.
	 *   2) do we really care, if it authenticates, if it came
	 *      from the wrong location?
	 *   3) the NAT_KA messages in IKE will also get to pluto
	 *      and it will figure out that stuff has moved.
	 *   4) the 2.6 udp-esp encap function does not pass us
	 *      the originating port number, and I can't tell
	 *      if skb->sk is guaranteed to be valid here.
	 *  2005-04-16: mcr@xelerance.com
	 */
	/*
	 *
	 * XXX we should ONLY update pluto if the SA passes all checks,
	 *     which we clearly {do not know | don't do now}.
	 */
	if (irs->natt_type != 0 &&
	    (irs->ipp->saddr !=
	       ((struct sockaddr_in*)(newipsp->ips_addr_s))->sin_addr.s_addr ||
	     irs->natt_sport != newipsp->ips_natt_sport)) {
		struct sockaddr sipaddr;
		struct sockaddr_in *psin =
			(struct sockaddr_in*)(newipsp->ips_addr_s);

		/** Advertise NAT-T addr change to pluto **/
		sipaddr.sa_family = AF_INET;
		((struct sockaddr_in*)&sipaddr)->sin_addr.s_addr =
			irs->ipp->saddr;
		((struct sockaddr_in*)&sipaddr)->sin_port = htons(
			irs->natt_sport);
		pfkey_nat_t_new_mapping(newipsp, &sipaddr, irs->natt_sport);

		/**
		 * Then allow or block packet depending on
		 * sysctl_ipsec_inbound_policy_check.
		 *
		 * In all cases, pluto will update SA if new mapping is
		 * accepted.
		 */
		if (sysctl_ipsec_inbound_policy_check) {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv_auth_decap: "
				    "SA:%s, src=%s:%u of pkt does not agree with expected "
				    "SA source address [%08x:%u] (notifying pluto of change).\n",
				    irs->sa_len ? irs->sa : " (error)",
				    irs->ipsaddr_txt, irs->natt_sport,
				    psin->sin_addr.s_addr,
				    newipsp->ips_natt_sport);
			if (irs->stats)
				irs->stats->rx_dropped++;
			ipsec_sa_put(newipsp);
			return IPSEC_RCV_FAILEDINBOUND;
		}
	}
#endif

	irs->authfuncs = NULL;

	/* authenticate, if required */
#ifdef CONFIG_KLIPS_OCF
	if (irs->ipsp->ocf_in_use) {
		irs->authlen = AHHMAC_HASHLEN;
		irs->authfuncs = NULL;
		irs->ictx = NULL;
		irs->octx = NULL;
		irs->ictx_len = 0;
		irs->octx_len = 0;
	} else
#endif	/* CONFIG_KLIPS_OCF */
#ifdef CONFIG_KLIPS_ALG
	/* authenticate, if required */
	if ((irs->ixt_a = irs->ipsp->ips_alg_auth)) {
		irs->authlen = irs->ixt_a->ixt_a_authlen;
		irs->authfuncs = NULL;
		irs->ictx = NULL;
		irs->octx = NULL;
		irs->ictx_len = 0;
		irs->octx_len = 0;
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_auth_decap: "
			    "authalg=%d authlen=%d\n",
			    irs->ipsp->ips_authalg,
			    irs->authlen);
	} else
#endif	/* CONFIG_KLIPS_ALG */
	switch (irs->ipsp->ips_authalg) {
#ifdef CONFIG_KLIPS_AUTH_HMAC_MD5
	case AH_MD5:
		irs->authlen = AHHMAC_HASHLEN;
		irs->authfuncs = ipsec_rcv_md5;
		irs->ictx = (void *)
			&((struct md5_ctx*)(irs->ipsp->ips_key_a))->ictx;
		irs->octx = (void *)
			&((struct md5_ctx*)(irs->ipsp->ips_key_a))->octx;
		irs->ictx_len =
			sizeof(((struct md5_ctx*)(irs->ipsp->ips_key_a))->ictx);
		irs->octx_len =
			sizeof(((struct md5_ctx*)(irs->ipsp->ips_key_a))->octx);
		break;
#endif		/* CONFIG_KLIPS_AUTH_HMAC_MD5 */
#ifdef CONFIG_KLIPS_AUTH_HMAC_SHA1
	case AH_SHA:
		irs->authlen = AHHMAC_HASHLEN;
		irs->authfuncs = ipsec_rcv_sha1;
		irs->ictx = (void *)
			&((struct sha1_ctx*)(irs->ipsp->ips_key_a))->ictx;
		irs->octx = (void *)
			&((struct sha1_ctx*)(irs->ipsp->ips_key_a))->octx;
		irs->ictx_len =
			sizeof(((struct sha1_ctx*)(irs->ipsp->ips_key_a))->ictx);
		irs->octx_len =
			sizeof(((struct sha1_ctx*)(irs->ipsp->ips_key_a))->octx);
		break;
#endif		/* CONFIG_KLIPS_AUTH_HMAC_SHA1 */
	case AH_NONE:
		irs->authlen = 0;
		irs->authfuncs = NULL;
		irs->ictx = NULL;
		irs->octx = NULL;
		irs->ictx_len = 0;
		irs->octx_len = 0;
		break;
	default:
		irs->ipsp->ips_errs.ips_alg_errs += 1;
		if (irs->stats)
			irs->stats->rx_errors++;
		return IPSEC_RCV_BADAUTH;
	}

	/* ilen counts number of bytes in ESP portion */
	irs->ilen =
		((irs->skb->data +
		  irs->skb->len) -
		 skb_transport_header(irs->skb)) - irs->authlen;
	if (irs->ilen <= 0) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_auth_decap: "
			    "runt %s packet with no data, dropping.\n",
			    (irs->proto == IPPROTO_ESP ? "esp" : "ah"));
		if (irs->stats)
			irs->stats->rx_dropped++;
		return IPSEC_RCV_BADLEN;
	}

	if (irs->authfuncs
#ifdef CONFIG_KLIPS_OCF
	    || irs->ipsp->ocf_in_use
#endif
#ifdef CONFIG_KLIPS_ALG
	    || irs->ixt_a
#endif
	    ) {
		if (irs->proto_funcs->rcv_setup_auth) {
			return (*irs->proto_funcs->rcv_setup_auth)(
					irs,
					irs->skb,
					&irs->replay,
					&irs->authenticator);
		}
	}
	return IPSEC_RCV_OK;
}

static enum ipsec_rcv_value ipsec_rcv_auth_calc(struct ipsec_rcv_state *irs)
{
	KLIPS_PRINT(debug_rcv, "klips_debug: %s(st=%d,nxt=%d)\n", __FUNCTION__,
		    irs->state, irs->next_state);

	if (irs->authfuncs ||
#ifdef CONFIG_KLIPS_OCF
	    (irs->ipsp->ocf_in_use && irs->ipsp->ips_authalg) ||
#endif
#ifdef CONFIG_KLIPS_ALG
	    irs->ixt_a ||
#endif
	    0) {
		if (!irs->authenticator) {
			irs->ipsp->ips_errs.ips_auth_errs += 1;
			if (irs->stats)
				irs->stats->rx_dropped++;
			return IPSEC_RCV_BADAUTH;
		}

		if (!ipsec_checkreplaywindow(irs->ipsp, irs->replay)) {
			irs->ipsp->ips_errs.ips_replaywin_errs += 1;
			KLIPS_PRINT(debug_rcv & DB_RX_REPLAY,
				    "klips_debug:ipsec_rcv_auth_calc: "
				    "duplicate frame from %s, packet dropped\n",
				    irs->ipsaddr_txt);
			if (irs->stats)
				irs->stats->rx_dropped++;
			return IPSEC_RCV_REPLAYFAILED;
		}

		/*
		 * verify authenticator
		 */

		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_auth_calc: "
			    "encalg = %d, authalg = %d.\n",
			    irs->ipsp->ips_encalg,
			    irs->ipsp->ips_authalg);

		/* calculate authenticator */
		if (irs->proto_funcs->rcv_calc_auth == NULL)
			return IPSEC_RCV_BADAUTH;

		return (*irs->proto_funcs->rcv_calc_auth)(irs, irs->skb);
	}
	return IPSEC_RCV_OK;
}

static enum ipsec_rcv_value ipsec_rcv_auth_chk(struct ipsec_rcv_state *irs)
{
	KLIPS_PRINT(debug_rcv, "klips_debug: %s(st=%d,nxt=%d) - %s\n",
		    __FUNCTION__,
		    irs->state, irs->next_state,
		    irs->auth_checked ? "already checked" : "will check");

	if (irs->auth_checked)
		return IPSEC_RCV_OK;

	if (irs->authfuncs ||
#ifdef CONFIG_KLIPS_OCF
	    (irs->ipsp->ocf_in_use && irs->ipsp->ips_authalg) ||
#endif
#ifdef CONFIG_KLIPS_ALG
	    irs->ixt_a ||
#endif
	    0) {
		if (memcmp(irs->hash, irs->authenticator, irs->authlen)) {
			irs->ipsp->ips_errs.ips_auth_errs += 1;
			KLIPS_ERROR(debug_rcv & DB_RX_INAU,
				    "klips_debug:ipsec_rcv_auth_chk: "
				    "auth failed on incoming packet from %s (replay=%d): calculated hash=%08x%08x%08x received hash=%08x%08x%08x, dropped\n",
				    irs->ipsaddr_txt,
				    irs->replay,
				    ntohl(*(__u32*)&irs->hash[0]),
				    ntohl(*(__u32*)&irs->hash[4]),
				    ntohl(*(__u32*)&irs->hash[8]),
				    ntohl(*(__u32*)irs->authenticator),
				    ntohl(*((__u32*)irs->authenticator + 1)),
				    ntohl(*((__u32*)irs->authenticator + 2)));
			if (irs->stats)
				irs->stats->rx_dropped++;
			return IPSEC_RCV_AUTHFAILED;
		} else {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv_auth_chk: "
				    "authentication successful.\n");
		}

		/* Crypto hygiene: clear memory used to calculate autheticator.
		 * The length varies with the algorithm.
		 */
		memset(irs->hash, 0, irs->authlen);

		/* If the sequence number == 0, expire SA, it had rolled */
		if (irs->ipsp->ips_replaywin &&
		    !irs->replay /* !irs->ipsp->ips_replaywin_lastseq */) {
			/* we need to remove it from the sadb hash, so that it can't be found again */
			ipsec_sa_rm(irs->ipsp);

			KLIPS_ERROR(debug_rcv,
				    "klips_debug:ipsec_rcv_auth_chk: "
				    "replay window counter rolled, expiring SA.\n");
			if (irs->stats)
				irs->stats->rx_dropped++;
			return IPSEC_RCV_REPLAYROLLED;
		}

		/* now update the replay counter */
		if (!ipsec_updatereplaywindow(irs->ipsp, irs->replay)) {
			irs->ipsp->ips_errs.ips_replaywin_errs += 1;
			KLIPS_ERROR(debug_rcv & DB_RX_REPLAY,
				    "klips_debug:ipsec_rcv_auth_chk: "
				    "duplicate frame from %s, packet dropped\n",
				    irs->ipsaddr_txt);
			if (irs->stats)
				irs->stats->rx_dropped++;
			return IPSEC_RCV_REPLAYROLLED;
		}
		irs->auth_checked = 1;
	}
	return IPSEC_RCV_OK;
}

static enum ipsec_rcv_value ipsec_rcv_decrypt(struct ipsec_rcv_state *irs)
{
	KLIPS_PRINT(debug_rcv, "klips_debug: %s(st=%d,nxt=%d)\n", __FUNCTION__,
		    irs->state, irs->next_state);

	if (irs->proto_funcs->rcv_decrypt)
		return (*irs->proto_funcs->rcv_decrypt)(irs);

	return IPSEC_RCV_OK;
}

/*
 * here we decide if there is more decapsulating required and
 * change the next state appropriately
 */
static enum ipsec_rcv_value ipsec_rcv_decap_cont(struct ipsec_rcv_state *irs)
{
	struct sk_buff *skb;
	struct ipsec_sa *ipsnext = NULL; /* next SA towards inside of packet */
	enum ipsec_rcv_value rv;

	KLIPS_PRINT(debug_rcv, "klips_debug: %s(st=%d,nxt=%d)\n", __FUNCTION__,
		    irs->state, irs->next_state);

	/*
	 * if we haven't checked the auth values yet, do it now.
	 * This is needed for the case where drivers do crypt+hash
	 * in one operation.
	 */
	rv = ipsec_rcv_auth_chk(irs);
	if (rv != IPSEC_RCV_OK)
		return rv;

	/*
	 *	Adjust pointers after decrypt
	 */
	skb = irs->skb;
	irs->len = skb->len;
	irs->iph = (void *) ip_hdr(skb);
#ifdef CONFIG_KLIPS_IPV6
	if (lsw_ip_hdr_version(irs) == 6) {
		IPSEC_FRAG_OFF_DECL(frag_off)
		unsigned char nexthdr = lsw_ip6_hdr(irs)->nexthdr;
		int nexthdroff;
		nexthdroff =
			ipsec_ipv6_skip_exthdr(irs->skb,
					       (void *)(lsw_ip6_hdr(irs) + 1) -
						 (void *)irs->skb->data,
					       &nexthdr, &frag_off);
		irs->iphlen = nexthdroff - (irs->iph - (void*)irs->skb->data);
		skb_set_transport_header(skb,
					 ipsec_skb_offset(skb,
							  skb_network_header(
								  skb) +
							  irs->iphlen));
	} else
#endif	/* CONFIG_KLIPS_IPV6 */
	{
		irs->iphlen = lsw_ip4_hdr(irs)->ihl << 2;
		skb_set_transport_header(skb,
					 ipsec_skb_offset(skb,
							  skb_network_header(
								  skb) +
							  irs->iphlen));
	}

	/* zero any options that there might be */
	memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));

	if (debug_rcv)
		ipsec_rcv_redodebug(irs);

	/*
	 *	Discard the original ESP/AH header
	 */
	if (lsw_ip_hdr_version(irs) == 6) {
		lsw_ip6_hdr(irs)->nexthdr = irs->next_header;
		skb->protocol = htons(ETH_P_IPV6);
	} else {
		lsw_ip4_hdr(irs)->protocol = irs->next_header;
		lsw_ip4_hdr(irs)->check = 0;	/* NOTE: this will be included in checksum */
		lsw_ip4_hdr(irs)->check =
			ip_fast_csum((unsigned char *)ip_hdr(skb),
				     irs->iphlen >> 2);
		skb->protocol = htons(ETH_P_IP);
	}
	irs->proto = irs->next_header; /* needed for decap_init recursion */
	KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
		    "klips_debug:ipsec_rcv_decap_cont: "
		    "after <%s%s%s>, SA:%s:\n",
		    IPS_XFORM_NAME(irs->ipsp),
		    irs->sa_len ? irs->sa : " (error)");
	KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, irs->iph);
	skb->ip_summed = 0;

	ipsnext = irs->ipsp->ips_next;
	if (sysctl_ipsec_inbound_policy_check) {
		if (ipsnext) {
			if (irs->next_header != IPPROTO_AH &&
			    irs->next_header != IPPROTO_ESP &&
#ifdef CONFIG_KLIPS_IPCOMP
			    irs->next_header != IPPROTO_COMP &&
			    (ipsnext->ips_said.proto != IPPROTO_COMP ||
			     ipsnext->ips_next) &&
#endif			/* CONFIG_KLIPS_IPCOMP */
			    irs->next_header != IPPROTO_IPIP &&
			    irs->next_header != IPPROTO_IPV6 &&
			    irs->next_header != IPPROTO_ATT_HEARTBEAT	/* heartbeats to AT&T SIG/GIG */
			   ) {
				KLIPS_PRINT(debug_rcv,
					    "packet with incomplete policy dropped, last successful SA:%s.\n",
					    irs->sa_len ? irs->sa : " (error)");
				if (irs->stats)
					irs->stats->rx_dropped++;
				return IPSEC_RCV_FAILEDINBOUND;
			}
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv_decap_cont: "
				    "SA:%s, Another IPSEC header to process.\n",
				    irs->sa_len ? irs->sa : " (error)");
		} else {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv_decap_cont: "
				    "No ips_inext from this SA:%s.\n",
				    irs->sa_len ? irs->sa : " (error)");
		}
	}

#ifdef CONFIG_KLIPS_IPCOMP
	/* update ipcomp ratio counters, even if no ipcomp packet is present */
	if (ipsnext &&
	    ipsnext->ips_said.proto == IPPROTO_COMP &&
	    irs->next_header != IPPROTO_COMP) {
		int tot_len;
		if (lsw_ip_hdr_version(irs) == 6)
			tot_len = ntohs(lsw_ip6_hdr(irs)->payload_len) +
				  sizeof(struct ipv6hdr);
		else
			tot_len = ntohs(lsw_ip4_hdr(irs)->tot_len);
		ipsnext->ips_comp_ratio_cbytes += tot_len;
		ipsnext->ips_comp_ratio_dbytes += tot_len;
	}
#endif	/* CONFIG_KLIPS_IPCOMP */

	irs->ipsp->ips_life.ipl_bytes.ipl_count += irs->len;
	irs->ipsp->ips_life.ipl_bytes.ipl_last   = irs->len;

	if (!irs->ipsp->ips_life.ipl_usetime.ipl_count)
		irs->ipsp->ips_life.ipl_usetime.ipl_count = jiffies / HZ;
	irs->ipsp->ips_life.ipl_usetime.ipl_last = jiffies / HZ;
	irs->ipsp->ips_life.ipl_packets.ipl_count += 1;

#if defined(CONFIG_KLIPS_COMPAT_NAT_NFMARK) && defined(CONFIG_NETFILTER)
	if (irs->proto == IPPROTO_ESP || irs->proto == IPPROTO_AH) {
		skb->nfmark = IPSEC_NFMARK_IS_SAREF_BIT |
			      (skb->nfmark &
			       (~(IPsecSAref2NFmark(IPSEC_SA_REF_MASK)))) |
			      IPsecSAref2NFmark(IPsecSA2SAref(irs->ipsp));
		KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
			    "klips_debug:ipsec_rcv_decap_cont: "
			    "%s SA sets skb->nfmark=0x%x.\n",
			    irs->proto == IPPROTO_ESP ? "ESP" : "AH",
			    (unsigned)skb->nfmark);
	}
#endif
	/* do we need to do more decapsulation */
	if ((irs->proto == IPPROTO_ESP ||
	     irs->proto == IPPROTO_AH ||
#ifdef CONFIG_KLIPS_IPCOMP
	     irs->proto == IPPROTO_COMP ||
#endif	/* CONFIG_KLIPS_IPCOMP */
	     0) && irs->ipsp != NULL)
		irs->next_state = IPSEC_RSM_DECAP_INIT;
	return IPSEC_RCV_OK;
}

static enum ipsec_rcv_value ipsec_rcv_cleanup(struct ipsec_rcv_state *irs)
{
	struct sk_buff *skb;

	KLIPS_PRINT(debug_rcv, "klips_debug: %s(st=%d,nxt=%d)\n", __FUNCTION__,
		    irs->state, irs->next_state);

	/* set up for cleanup */
	skb = irs->skb;

	if ((irs->natt_type) && (irs->proto != IPPROTO_IPIP)) {
		/*
		 * NAT-Traversal and Transport Mode:
		 *   we need to correct TCP/UDP checksum
		 * If we've got NAT-OA, we can fix checksum without recalculation.
		 */
		__u32 natt_oa = (irs->ipsp && irs->ipsp->ips_natt_oa) ?
				((struct sockaddr_in*)(irs->ipsp->ips_natt_oa))
				->sin_addr.s_addr : 0;

		if (natt_oa != 0) {
			/* reset source address to what it was before NAT */
			lsw_ip4_hdr(irs)->saddr = natt_oa;
			lsw_ip4_hdr(irs)->check = 0;
			lsw_ip4_hdr(irs)->check = ip_fast_csum(
				(unsigned char *)irs->iph, lsw_ip4_hdr(
					irs)->ihl);
			KLIPS_PRINT(debug_rcv, "csum: %04x\n",
				    lsw_ip4_hdr(irs)->check);
		}
/*
 * This fails when both systems are behind NAT
 * mcr: So, either the ports passed in by the NAT-OA mechanism for the fixup
 * are wrong, and so the checksum fixup is wrong
 * Not very harmful since the checksum is useless and the crypto hash will
 * be used anyway.
 */
#ifdef DISABLE_UDP_CHECKSUM
		/* see https://bugs.libreswan.org/issues/601 */
		if (lsw_ip4_hdr(irs)->protocol == IPPROTO_UDP) {
			udp_hdr(skb)->check = 0;
			KLIPS_PRINT(debug_rcv,
				    "UDP checksum for NAT packet disabled at compile time\n");
		}
#endif
	}

	/* okay, acted on all SA's, so free the last SA, and move to the next */
	if (irs->ipsp) {
		struct ipsec_sa *newipsp;
		newipsp = irs->ipsp->ips_next;
		if (newipsp)
			ipsec_sa_get(newipsp, IPSEC_REFRX);
		if (irs->lastipsp)
			ipsec_sa_put(irs->lastipsp, IPSEC_REFRX);
		irs->lastipsp = irs->ipsp;
		irs->ipsp = newipsp;
	}

#ifdef CONFIG_KLIPS_IPCOMP
	/* if there is an IPCOMP, but we don't have an IPPROTO_COMP,
	 * then we can just skip it
	 */
	if (irs->ipsp && irs->ipsp->ips_said.proto == IPPROTO_COMP) {
		struct ipsec_sa *newipsp = NULL;
		newipsp = irs->ipsp->ips_next;
		if (newipsp)
			ipsec_sa_get(newipsp, IPSEC_REFRX);
		if (irs->lastipsp)
			ipsec_sa_put(irs->lastipsp, IPSEC_REFRX);
		irs->lastipsp = irs->ipsp;
		irs->ipsp = newipsp;
		irs->sa_len = 0;
	}
#endif	/* CONFIG_KLIPS_IPCOMP */

	/*
	 * the SA is still locked from the loop
	 */
	if (irs->ipsp && irs->ipsp->ips_xformfuncs->protocol == IPPROTO_IPIP) {
		enum ipsec_rcv_value decap_stat;

		decap_stat = ipsec_rcv_decap_ipip(irs);
		if (decap_stat != IPSEC_RCV_OK)
			return decap_stat;
	}

	if (irs->stats)
		irs->stats->rx_bytes += skb->len;

	/*
	 * if we are supposed to return the packet directly to the transport
	 * layer, then dump it out correctly.
	 */
	if (unlikely(!irs->lastipsp))
		printk("%s,%d: %s lastipsp should never be NULL\n",
		       __FILE__, __LINE__, __FUNCTION__);
	if (irs->lastipsp->ips_transport_direct) {
		KLIPS_PRINT(debug_rcv,
			    "receiving packet as transport direct\n");
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		/* STUFF */
	}

#ifdef CONFIG_INET_IPSEC_SAREF
	if (skb->sp)
		secpath_put(skb->sp);
	skb->sp = secpath_dup(NULL);
	if (skb->sp)
		skb->sp->ref = irs->lastipsp->ips_ref;
	else
		return IPSEC_RCV_REALLYBAD;

#endif

	return IPSEC_RCV_OK;
}

static enum ipsec_rcv_value ipsec_rcv_complete(struct ipsec_rcv_state *irs)
{
	KLIPS_PRINT(debug_rcv, "klips_debug: %s(st=%d,nxt=%d)\n", __FUNCTION__,
		    irs->state, irs->next_state);

	/*
	 * make sure that data now starts at IP header, since we are going
	 * to pass this back to ip_input (aka netif_rx). Rules for what the
	 * pointers wind up a different for 2.6 vs 2.4, so we just fudge it here.
	 */
#ifdef NET_26
	irs->skb->data = skb_push(irs->skb,
				  skb_transport_header(irs->skb) -
				  skb_network_header(irs->skb));
#else
	irs->skb->data = skb_network_header(irs->skb);
	{
		int len;
		struct iphdr *iph = ip_hdr(irs->skb);
#ifdef CONFIG_KLIPS_IPV6
		struct ipv6hdr *ip6h = (struct ipv6hdr *) iph;
		if (iph->version == 6)
			len = ntohs(iph->payload_len) + sizeof(*ip6h);
		else
#endif		/* CONFIG_KLIPS_IPV6 */
		len = ntohs(iph->tot_len);
		irs->skb->len  = len;
	}
#endif

	/*
	 * release the dst that was attached, since we have likely
	 * changed the actual destination of the packet.
	 */
	skb_dst_drop(irs->skb);
	irs->skb->pkt_type = PACKET_HOST;
	if (irs->hard_header_len &&
	    (skb_mac_header(irs->skb) !=
	     (skb_network_header(irs->skb) - irs->hard_header_len)) &&
	    (irs->hard_header_len <= skb_headroom(irs->skb))) {
		/* copy back original MAC header */
		memmove(skb_network_header(irs->skb) - irs->hard_header_len,
			skb_mac_header(irs->skb), irs->hard_header_len);
		skb_set_mac_header(irs->skb,
				   ipsec_skb_offset(irs->skb,
						    skb_network_header(irs->skb)
						    -
						    irs->hard_header_len));
		/* we have to fix the protocol,  it's not right with IP4/IP6 or
		 * IP6/IP4 tunnels */
		if (irs->hard_header_len == ETH_HLEN)
			eth_hdr(irs->skb)->h_proto = irs->skb->protocol;
	}

	ipsec_nf_reset(irs->skb);

	if (irs->skb->dev == NULL) {
		/* the physical dev went down and is no longer attached */
		KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
			    "klips_debug:ipsec_rcv_complete: interface for skb is detached.\n");
		return IPSEC_RCV_REALLYBAD;
	}

	KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
		    "klips_debug:ipsec_rcv_complete: "
		    "netif_rx(%s) called.\n", irs->skb->dev->name);
	netif_rx(irs->skb);
	irs->skb = NULL;
	return IPSEC_RCV_OK;
}

/*
 * ipsec_rsm is responsible for walking us through the state machine
 * it is the only entry point into the receive processing and does
 * appropriate checks and state changes for us.
 */

void ipsec_rsm(struct ipsec_rcv_state *irs)
{
	if (irs == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rsm: "
			    "irs == NULL.\n");
		return;
	}

	/*
	 * make sure nothing is removed from underneath us
	 */
	spin_lock_bh(&tdb_lock);

	/*
	 * if we have a valid said,  then we must check it here to ensure it
	 * hasn't gone away while we were waiting for a task to complete
	 */

	if (irs->said.proto) {
		struct ipsec_sa *ipsp;
		ipsp = ipsec_sa_getbyid(&irs->said, IPSEC_REFRX);
		if (ipsp == NULL) {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rsm: "
				    "no ipsec_sa for SA:%s: "
				    "incoming packet with no SA dropped\n",
				    irs->sa_len ? irs->sa : " (error)");
			if (irs->stats)
				irs->stats->rx_dropped++;
			/* drop through and cleanup */
			irs->state = IPSEC_RSM_DONE;
		} else {
			/* set the refcount back */
			ipsec_sa_put(ipsp, IPSEC_REFRX);
		}
	}

	while (irs->state != IPSEC_RSM_DONE) {
		int rc;

		irs->next_state = rcv_state_table[irs->state].next_state;

		rc = rcv_state_table[irs->state].action(irs);

		if (rc == IPSEC_RCV_OK) {
			/* some functions change the next state, see the state table */
			irs->state = irs->next_state;
		} else if (rc == IPSEC_RCV_PENDING) {
			/*
			 * things are on hold until we return here in the next/new state
			 * we check our SA is valid when we return
			 */
			spin_unlock_bh(&tdb_lock);
			return;
		} else {
			/* bad result, force state change to done */
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rsm: "
				    "processing completed due to %s.\n",
				    ipsec_rcv_err(rc));
			irs->state = IPSEC_RSM_DONE;
		}
	}

	if (irs->lastipsp) {
		ipsec_sa_put(irs->lastipsp, IPSEC_REFRX);
		irs->lastipsp = NULL;
	}

	if (irs->ipsp) {
		ipsec_sa_put(irs->ipsp, IPSEC_REFRX);
		irs->ipsp = NULL;
	}

	/*
	 * all done with anything needing locks
	 */
	spin_unlock_bh(&tdb_lock);

	if (irs->skb) {
		ipsec_kfree_skb(irs->skb);
		irs->skb = NULL;
	}

	if (irs->pre_ipcomp_skb) {
		ipsec_kfree_skb(irs->pre_ipcomp_skb);
		irs->pre_ipcomp_skb = NULL;
	}

	ipsec_rcv_state_delete(irs);

	KLIPS_DEC_USE; /* once less packet using the driver */
}

int ipsec_rcv(struct sk_buff *skb
	      )
{
	struct ipsec_rcv_state *irs = NULL;

	/* Don't unlink in the middle of a turnaround */
	KLIPS_INC_USE;

	if (skb == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NULL skb passed in.\n");
		goto rcvleave;
	}

	if (skb->data == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NULL skb->data passed in, packet is bogus, dropping.\n");
		goto rcvleave;
	}

	irs = ipsec_rcv_state_new();
	if (unlikely(!irs)) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "failled to allocate a rcv state object\n");
		goto rcvleave;
	}

#if defined(CONFIG_IPSEC_NAT_TRAVERSAL) && !defined(NET_26)
	{
		/* NET_26 NAT-T is handled by separate function */
		struct sk_buff *nskb;
		int udp_decap_ret = 0;

		nskb = ipsec_rcv_natt_decap(skb, irs, &udp_decap_ret);
		if (nskb == NULL) {
			/* return with non-zero, because UDP.c code
			 * need to send it upstream.
			 */
			if (skb && udp_decap_ret == 0)
				ipsec_kfree_skb(skb);
			if (irs)
				ipsec_rcv_state_delete(irs);
			KLIPS_DEC_USE;
			return udp_decap_ret;
		}
		skb = nskb;
	}
#endif	/* NAT_T */

	irs->skb = skb;
	/*
	 * we hand off real early to the state machine because we just cannot
	 * know how much processing it is off-loading
	 */
	ipsec_rsm(irs);

	return 0;

rcvleave:
	if (irs)
		ipsec_rcv_state_delete(irs);
	if (skb)
		ipsec_kfree_skb(skb);
	KLIPS_DEC_USE;
	return 0;
}

#ifdef NET_26
/*
 * this entry point is not a protocol entry point, so the entry
 * is a bit different.
 *
 * skb->iph->tot_len has been byte-swapped, and reduced by the size of
 *              the IP header (and options).
 *
 * skb->h.raw has been pulled up the ESP header.
 *
 * skb->iph->protocol = 50 IPPROTO_ESP;
 *
 */
int klips26_udp_encap_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct udp_sock *up = udp_sk(sk);
	struct udphdr *uh;
	struct iphdr *iph;
	int iphlen, len;
	int ret;

	__u8 *udpdata;
	__be32 *udpdata32;
	__u16 encap_type = up->encap_type;

	/* if this is not encapsulated socket, then just return now */
	if (!encap_type)
		return 1;

	/* If this is a paged skb, make sure we pull up
	 * whatever data we need to look at. */
	len = skb->len - sizeof(struct udphdr);
	if (!pskb_may_pull(skb, sizeof(struct udphdr) + min(len, 8)))
		return 1;

	/* Now we can get the pointers */
	uh = udp_hdr(skb);
	udpdata = (__u8 *)(uh + 1);
	udpdata32 = (__be32 *)udpdata;

	switch (encap_type) {
	default:
	case UDP_ENCAP_ESPINUDP:
		KLIPS_PRINT(debug_rcv,
			    "UDP_ENCAP_ESPINUDP_NON_IKE: len=%d 0x%x\n",
			    len, udpdata32[0]);
		/* Check if this is a keepalive packet.  If so, eat it. */
		if (len == 1 && udpdata[0] == 0xff) {
			KLIPS_PRINT(debug_rcv,
				    "UDP_ENCAP_ESPINUDP: keepalive packet detected\n");
			goto drop;
		} else if (len > sizeof(struct ip_esp_hdr) &&
			   udpdata32[0] != 0) {
			KLIPS_PRINT(debug_rcv,
				    "UDP_ENCAP_ESPINUDP: ESP IN UDP packet detected\n");
			/* ESP Packet without Non-ESP header */
			len = sizeof(struct udphdr);
		} else {
			/* Must be an IKE packet.. pass it through */
			KLIPS_PRINT(debug_rcv,
				    "UDP_ENCAP_ESPINUDP: IKE packet detected\n");
			return 1;
		}
		break;
	case UDP_ENCAP_ESPINUDP_NON_IKE:
		KLIPS_PRINT(debug_rcv,
			    "UDP_ENCAP_ESPINUDP_NON_IKE: len=%d 0x%x\n",
			    len, udpdata32[0]);
		/* Check if this is a keepalive packet.  If so, eat it. */
		if (len == 1 && udpdata[0] == 0xff) {
			KLIPS_PRINT(debug_rcv,
				    "UDP_ENCAP_ESPINUDP_NON_IKE: keepalive packet detected\n");
			goto drop;
		} else if (len > 2 * sizeof(u32) + sizeof(struct ip_esp_hdr) &&
			   udpdata32[0] == 0 && udpdata32[1] == 0) {
			KLIPS_PRINT(debug_rcv,
				    "UDP_ENCAP_ESPINUDP_NON_IKE: ESP IN UDP NON IKE packet detected\n");
			/* ESP Packet with Non-IKE marker */
			len = sizeof(struct udphdr) + 2 * sizeof(u32);
		} else {
			/* Must be an IKE packet.. pass it through */
			KLIPS_PRINT(debug_rcv,
				    "UDP_ENCAP_ESPINUDP_NON_IKE: IKE packet detected\n");
			return 1;
		}
		break;
	}

	/* At this point we are sure that this is an ESPinUDP packet,
	 * so we need to remove 'len' bytes from the packet (the UDP
	 * header and optional ESP marker bytes) and then modify the
	 * protocol to ESP, and then call into the transform receiver.
	 */
	if (skb_cloned(skb) && pskb_expand_head(skb, 0, 0, GFP_ATOMIC)) {
		KLIPS_PRINT(debug_rcv, "clone or expand problem\n");
		goto drop;
	}

	/* Now we can update and verify the packet length... */
	iph = ip_hdr(skb);
	iphlen = iph->ihl << 2;
	iph->tot_len = htons(ntohs(iph->tot_len) - len);
	if (skb->len < iphlen + len) {
		/* packet is too small!?! */
		KLIPS_PRINT(debug_rcv, "packet too small\n");
		goto drop;
	}

	/* pull the data buffer up to the ESP header and set the
	 * transport header to point to ESP.  Keep UDP on the stack
	 * for later.
	 */
	__skb_pull(skb, len);
	skb_reset_transport_header(skb);

	/* modify the protocol (it's ESP!) */
	iph->protocol = IPPROTO_ESP;

	/* process ESP */
	KLIPS_PRINT(debug_rcv, "starting processing ESP packet\n");
	ret = klips26_rcv_encap(skb, encap_type);
	return ret;

drop:
	kfree_skb(skb);
	return 0;
}

int klips26_rcv_encap(struct sk_buff *skb, __u16 encap_type)
{
	struct ipsec_rcv_state *irs = NULL;

	/* Don't unlink in the middle of a turnaround */
	KLIPS_INC_USE;

	if (skb == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:klips26_rcv_encap: "
			    "NULL skb passed in.\n");
		goto rcvleave;
	}

	if (skb->data == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:klips26_rcv_encap: "
			    "NULL skb->data passed in, packet is bogus, dropping.\n");
		goto rcvleave;
	}

	irs = ipsec_rcv_state_new();
	if (unlikely(!irs)) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:klips26_rcv_encap: "
			    "failled to allocate a rcv state object\n");
		goto rcvleave;
	}

	irs->hard_header_len = skb->dev->hard_header_len;

	switch (encap_type) {
	case UDP_ENCAP_ESPINUDP:
		irs->natt_type = ESPINUDP_WITH_NON_ESP;
		break;

	case UDP_ENCAP_ESPINUDP_NON_IKE:
		irs->natt_type = ESPINUDP_WITH_NON_IKE;
		break;

	default:
		if (printk_ratelimit()) {
			printk(KERN_INFO "KLIPS received unknown UDP-ESP encap type %u\n",
				encap_type);
		}
		goto rcvleave;
	}

	irs->skb = skb;

	/*
	 * we hand off real early to the state machine because we just cannot
	 * know how much processing it is off-loading
	 */
	ipsec_rsm(irs);

	return 0;

rcvleave:
	if (irs)
		ipsec_rcv_state_delete(irs);
	if (skb)
		ipsec_kfree_skb(skb);
	KLIPS_DEC_USE;
	return 0;
}
#endif

/* ------------------------------------------------------------------------
 * this handles creating and managing state for recv path
 */

static DEFINE_SPINLOCK(irs_cache_lock);
#ifdef HAVE_KMEM_CACHE_MACRO
static struct kmem_cache *irs_cache_allocator = NULL;
#else
static kmem_cache_t *irs_cache_allocator = NULL;
#endif
static unsigned irs_cache_allocated_count = 0;

int ipsec_irs_cache_allocated_max = 1000;
module_param(ipsec_irs_cache_allocated_max, int, 0644);
MODULE_PARM_DESC(ipsec_irs_cache_allocated_max,
		 "Maximum outstanding receive packets (before they are dropped)");

int ipsec_rcv_state_cache_init(void)
{
	if (irs_cache_allocator)
		return -EBUSY;

	spin_lock_init(&irs_cache_lock);
#ifdef HAVE_KMEM_CACHE_MACRO
	irs_cache_allocator = KMEM_CACHE(ipsec_rcv_state, 0);
#else
	irs_cache_allocator = kmem_cache_create("ipsec_irs",
						sizeof(struct ipsec_rcv_state),
						0,
						0, NULL, NULL);
#endif
	if (!irs_cache_allocator)
		return -ENOMEM;

	return 0;
}

void ipsec_rcv_state_cache_cleanup(void)
{
	if (unlikely(irs_cache_allocated_count))
		printk("ipsec: deleting ipsec_irs kmem_cache while in use\n");

	if (irs_cache_allocator) {
		kmem_cache_destroy(irs_cache_allocator);
		irs_cache_allocator = NULL;
	}
	irs_cache_allocated_count = 0;
}

static struct ipsec_rcv_state *ipsec_rcv_state_new(void)
{
	struct ipsec_rcv_state *irs;

	spin_lock_bh(&irs_cache_lock);

	if (irs_cache_allocated_count >= ipsec_irs_cache_allocated_max) {
		spin_unlock_bh(&irs_cache_lock);
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_state_new: "
			    "exceeded maximum outstanding RX packet cnt %d\n",
			    irs_cache_allocated_count);
		return NULL;
	}

	irs = kmem_cache_alloc(irs_cache_allocator, GFP_ATOMIC);

	if (likely(irs != NULL))
		irs_cache_allocated_count++;

	spin_unlock_bh(&irs_cache_lock);

	if (unlikely(NULL == irs))
		goto bail;

	/* initialize the object */
#if 1
	memset((caddr_t)irs, 0, sizeof(*irs));
#else
	/* optimised to only clear the essentials */
	irs->state = 0;
	irs->next_state = 0;
	irs->auth_checked = 0;
	irs->stats = NULL;
	irs->authenticator = NULL;
	irs->said.proto = 0;

	irs->hard_header_len = 0;
	irs->natt_type = 0;
	irs->natt_len = 0;

	irs->lastipsp = NULL;
	irs->ipsp = NULL;
#endif

bail:
	return irs;
}

static void ipsec_rcv_state_delete(struct ipsec_rcv_state *irs)
{
	if (unlikely(!irs))
		return;

	spin_lock_bh(&irs_cache_lock);

	irs_cache_allocated_count--;
	kmem_cache_free(irs_cache_allocator, irs);

	spin_unlock_bh(&irs_cache_lock);
}
