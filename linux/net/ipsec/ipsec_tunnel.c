/*
 * IPSEC Tunneling code. Heavily based on drivers/net/new_tunnel.c
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2016 Richard Guy Briggs.
 * Copyright (C) 2012, 2016 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012  David McCullough <david_mccullough@mcafee.com>
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
#define __NO_VERSION__
#include <linux/module.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0) && LINUX_VERSION_CODE >= \
	KERNEL_VERSION(2, 4, 26)
# include <linux/moduleparam.h>
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) && \
	!defined(AUTOCONF_INCLUDED)
#include <linux/config.h>
#endif
#include <linux/kernel.h> /* printk() */

#include "libreswan/ipsec_param.h"

#include <linux/slab.h>         /* kmalloc() */
#include <linux/errno.h>        /* error codes */
#include <linux/types.h>        /* size_t */
#include <linux/file.h>
#include <linux/interrupt.h>    /* mark_bh */

#include <net/tcp.h>
#include <net/udp.h>
#include <linux/skbuff.h>

#include <linux/netdevice.h>    /* struct device, struct net_device_stats, dev_queue_xmit() and other headers */
#include <linux/etherdevice.h>  /* eth_type_trans */
#include <linux/ip.h>           /* struct iphdr */
#include <net/arp.h>
#include <linux/skbuff.h>

#include <libreswan.h>

# include <linux/in6.h>
# define IS_MYADDR RTN_LOCAL
# include <net/dst.h>
# define PHYSDEV_TYPE

#ifndef NETDEV_TX_BUSY
# ifdef NETDEV_XMIT_CN
#  define NETDEV_TX_BUSY NETDEV_XMIT_CN
# else
#  define NETDEV_TX_BUSY 1
# endif
#endif

#include <net/icmp.h>           /* icmp_send() */
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/arp.h>
# include <linux/netfilter_ipv4.h>

#include <linux/if_arp.h>
#include <linux/delay.h>
#include <net/arp.h>

#include "libreswan/ipsec_kversion.h"
#include "libreswan/radij.h"
#include "libreswan/ipsec_life.h"
#include "libreswan/ipsec_xform.h"
#include "libreswan/ipsec_eroute.h"
#include "libreswan/ipsec_encap.h"
#include "libreswan/ipsec_radij.h"
#include "libreswan/ipsec_sa.h"
#include "libreswan/ipsec_tunnel.h"
#include "libreswan/ipsec_xmit.h"
#include "libreswan/ipsec_rcv.h"
#include "libreswan/ipsec_ipe4.h"
#include "libreswan/ipsec_ah.h"
#include "libreswan/ipsec_esp.h"

#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include "libreswan/ipsec_proto.h"
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
#include <linux/udp.h>
#endif

static __u32 zeroes[64];

/* forward references */
DEBUG_NO_STATIC int ipsec_tunnel_attach(struct net_device *dev,
					struct net_device *physdev);
DEBUG_NO_STATIC int ipsec_tunnel_detach(struct net_device *dev);
extern const struct net_device_ops klips_device_ops;

#ifdef HAVE_UDP_ENCAP_CONVERT
DEBUG_NO_STATIC int ipsec_tunnel_udp_encap_prepare(int fd, int encap_type);
DEBUG_NO_STATIC void ipsec_tunnel_udp_encap_destruct(struct sock *sk);
DEBUG_NO_STATIC void ipsec_tunnel_upd_encap_cleanup(void);
#endif

#ifdef CONFIG_KLIPS_DEBUG
int debug_tunnel = 0;
#endif /* CONFIG_KLIPS_DEBUG */

DEBUG_NO_STATIC int ipsec_tunnel_open(struct net_device *dev)
{
	struct ipsecpriv *prv = netdev_to_ipsecpriv(dev);

	/*
	 * Can't open until attached.
	 */

	KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
		    "klips_debug:ipsec_tunnel_open: "
		    "dev = %s, prv->dev = %s\n",
		    dev->name, prv->dev ? prv->dev->name : "NONE");

	if (prv->dev == NULL)
		return -ENODEV;

	KLIPS_INC_USE;
	return 0;
}

DEBUG_NO_STATIC int ipsec_tunnel_close(struct net_device *dev)
{
	KLIPS_DEC_USE;
	return 0;
}

static inline int ipsec_tunnel_xmit2(struct sk_buff *skb)
{
#ifdef NET_26   /* 2.6 kernels */
#  if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	return dst_output(dev_net(skb->dev), skb->sk, skb);
#  else
	return dst_output(skb);
#  endif
#else
	return ip_send(skb);
#endif
}

#ifdef HAVE_NETDEV_HEADER_OPS

int klips_header(struct sk_buff *skb, struct net_device *dev,
		 unsigned short type,
		 const void *daddr, const void *saddr, unsigned len)
{
	struct ipsecpriv *prv = netdev_to_ipsecpriv(dev);
	struct net_device *tmp;
	int ret;
	struct net_device_stats *stats; /* This device's statistics */

	if (skb == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_hard_header: "
			    "no skb...\n");
		return -ENODATA;
	}

	if (dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_hard_header: "
			    "no device...\n");
		return -ENODEV;
	}

	KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
		    "klips_debug:ipsec_tunnel_hard_header: "
		    "skb->dev=%s dev=%s.\n",
		    skb->dev ? skb->dev->name : "NULL",
		    dev->name);

	if (prv == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_hard_header: "
			    "no private space associated with dev=%s\n",
			    dev->name ? dev->name : "NULL");
		return -ENODEV;
	}

	stats = (struct net_device_stats *) &(prv->mystats);

	if (prv->dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_hard_header: "
			    "no physical device associated with dev=%s\n",
			    dev->name ? dev->name : "NULL");
		stats->tx_dropped++;
		return -ENODEV;
	}

	if (prv->dev->header_ops == NULL ||
	    prv->dev->header_ops->create == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_hard_header: "
			    "cannot revector dev=%s op=%p func=%p",
			    dev->name ? dev->name : "NULL",
			    prv->dev->header_ops, prv->dev->header_ops ?
			    prv->dev->header_ops->create : 0);
		/* don't fail here or devices without header ops (like ppp) fail */
		return 0;
	}

	/* check if we have to send a IPv6 packet. It might be a Router
	   Solicitation, where the building of the packet happens in
	   reverse order:
	   1. ll hdr,
	   2. IPv6 hdr,
	   3. ICMPv6 hdr
	   -> skb->nh.raw is still uninitialized when this function is
	   called!!  If this is no IPv6 packet, we can print debugging
	   messages, otherwise we skip all debugging messages and just
	   build the ll header */
	if (type != ETH_P_IPV6) {
		/* execute this only, if we don't have to build the
		   header for a IPv6 packet */
		if (!prv->dev) {
			KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
				    "klips_debug:ipsec_tunnel_hard_header: "
				    "physical device has been detached, packet dropped 0p%p->0p%p len=%d type=%d dev=%s->NULL ",
				    saddr,
				    daddr,
				    len,
				    type,
				    dev->name);
			KLIPS_PRINTMORE(debug_tunnel & DB_TN_REVEC,
					"ip=%08x->%08x\n",
					(__u32)ntohl(ip_hdr(skb)->saddr),
					(__u32)ntohl(ip_hdr(skb)->daddr) );
			stats->tx_dropped++;
			return -ENODEV;
		}

#define da ((struct net_device *)(prv->dev))->dev_addr
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_hard_header: "
			    "Revectored 0p%p->0p%p len=%d type=%d dev=%s->%s dev_addr=%02x:%02x:%02x:%02x:%02x:%02x ",
			    saddr,
			    daddr,
			    len,
			    type,
			    dev->name,
			    prv->dev->name,
			    da[0], da[1], da[2], da[3], da[4], da[5]);
		KLIPS_PRINTMORE(debug_tunnel & DB_TN_REVEC,
				"ip=%08x->%08x\n",
				(__u32)ntohl(ip_hdr(skb)->saddr),
				(__u32)ntohl(ip_hdr(skb)->daddr) );
	} else {
		KLIPS_PRINT(debug_tunnel,
			    "klips_debug:ipsec_tunnel_hard_header: "
			    "is IPv6 packet, skip debugging messages, only revector and build linklocal header.\n");
	}
	tmp = skb->dev;
	skb->dev = prv->dev;
	ret = prv->dev->header_ops->create(skb, prv->dev, type,
					   (void *)daddr, (void *)saddr, len);
	skb->dev = tmp;
	return ret;
}

int klips_header_parse(const struct sk_buff *skb, unsigned char *haddr)
{
	struct ipsecpriv *prv = netdev_to_ipsecpriv(skb->dev);
	struct net_device_stats *stats; /* This device's statistics */
	int ret;

	stats = (struct net_device_stats *) &(prv->mystats);
	if (prv->dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:klips_header_parse: "
			    "no physical device associated with dev=%s",
			    skb->dev->name ? skb->dev->name : "NULL");
		stats->tx_dropped++;
		return 0;
	}

	if (prv->dev->header_ops == NULL ||
	    prv->dev->header_ops->parse == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:klips_header_parse: "
			    "cannot revector dev=%s op=%p func=%p",
			    skb->dev->name ? skb->dev->name : "NULL",
			    prv->dev->header_ops, prv->dev->header_ops ?
			    prv->dev->header_ops->parse : 0);
		stats->tx_dropped++;
		return 0;
	}

	{
#if 0
		struct net_device *tmp;
		tmp = skb->dev;
		skb->dev = prv->dev;
#endif
		ret = prv->dev->header_ops->parse(skb, haddr);
#if 0
		skb->dev = tmp;
#endif
	}
	return ret;
}

#ifdef HAVE_REBUILD_HEADER
DEBUG_NO_STATIC int klips_rebuild_header(struct sk_buff *skb)
{
	struct ipsecpriv *prv = netdev_to_ipsecpriv(skb->dev);
	struct net_device *tmp;
	int ret;
	struct net_device_stats *stats; /* This device's statistics */

	if (skb->dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_rebuild_header: "
			    "no device...");
		return -ENODEV;
	}

	if (prv == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_rebuild_header: "
			    "no private space associated with dev=%s",
			    skb->dev->name ? skb->dev->name : "NULL");
		return -ENODEV;
	}

	stats = (struct net_device_stats *) &(prv->mystats);

	if (prv->dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_rebuild_header: "
			    "no physical device associated with dev=%s",
			    skb->dev->name ? skb->dev->name : "NULL");
		stats->tx_dropped++;
		return -ENODEV;
	}

	if (prv->dev->header_ops == NULL ||
	    prv->dev->header_ops->rebuild == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_rebuild_header: "
			    "cannot revector dev=%s op=%p func=%p",
			    skb->dev->name ? skb->dev->name : "NULL",
			    prv->dev->header_ops, prv->dev->header_ops ?
			    prv->dev->header_ops->rebuild : 0);
		stats->tx_dropped++;
		return -ENODEV;
	}

	KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
		    "klips_debug:ipsec_tunnel: "
		    "Revectored rebuild_header dev=%s->%s ",
		    skb->dev->name, prv->dev->name);
	KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
		    "ip=%08x->%08x\n",
		    (__u32)ntohl(ip_hdr(skb)->saddr),
		    (__u32)ntohl(ip_hdr(skb)->daddr) );
	tmp = skb->dev;
	skb->dev = prv->dev;

	ret = prv->dev->header_ops->rebuild(skb);
	skb->dev = tmp;
	return ret;
}
#endif

int klips_header_cache(const struct neighbour *neigh,
		       struct hh_cache *hh
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0)
		       , __be16 type
#endif
		       )
{
	const struct net_device *dev = neigh->dev;
	struct ipsecpriv *prv = netdev_to_ipsecpriv(dev);
	struct net_device_stats *stats;

	stats = (struct net_device_stats *) &(prv->mystats);
	if (prv->dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:klips_header_cache: "
			    "no physical device associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		stats->tx_dropped++;
		return -1;
	}

	if (prv->dev->header_ops == NULL ||
	    prv->dev->header_ops->cache == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:klips_header_cache: "
			    "cannot revector dev=%s op=%p func=%p",
			    dev->name ? dev->name : "NULL",
			    prv->dev->header_ops, prv->dev->header_ops ?
			    prv->dev->header_ops->cache : 0);
		/* don't fail here or devices without header ops (like ppp) fail */
		return 0;
	}

	KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
		    "klips_debug:ipsec_tunnel: "
		    "Revectored cache_update\n");
	return prv->dev->header_ops->cache(neigh, hh
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0)
					   , type
#endif
					   );
}

DEBUG_NO_STATIC void klips_header_cache_update(struct hh_cache *hh,
					       const struct net_device *dev,
					       const unsigned char *  haddr)
{
	struct ipsecpriv *prv = netdev_to_ipsecpriv(dev);

	struct net_device_stats *stats; /* This device's statistics */

	if (dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_cache_update: "
			    "no device...");
		return;
	}

	if (prv == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_cache_update: "
			    "no private space associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		return;
	}

	stats = (struct net_device_stats *) &(prv->mystats);

	if (prv->dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_cache_update: "
			    "no physical device associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		stats->tx_dropped++;
		return;
	}

	if (prv->dev->header_ops == NULL ||
	    prv->dev->header_ops->cache_update == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_cache_update: "
			    "cannot revector dev=%s op=%p func=%p",
			    dev->name ? dev->name : "NULL",
			    prv->dev->header_ops, prv->dev->header_ops ?
			    prv->dev->header_ops->cache_update : 0);
		stats->tx_dropped++;
		return;
	}

	KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
		    "klips_debug:ipsec_tunnel: "
		    "Revectored cache_update\n");
	prv->dev->header_ops->cache_update(hh, prv->dev, haddr);
}

const struct header_ops klips_header_ops ____cacheline_aligned = {
	.create         = klips_header,
	.parse          = klips_header_parse,
#ifdef HAVE_REBUILD_HEADER
	.rebuild        = klips_rebuild_header,
#endif
	.cache          = klips_header_cache,
	.cache_update   = klips_header_cache_update,
};

#endif /* HAVE_NETDEV_HEADER_OPS */

enum ipsec_xmit_value ipsec_tunnel_strip_hard_header(
	struct ipsec_xmit_state *ixs)
{
	/* ixs->physdev->hard_header_len is unreliable and should not be used */
	ixs->hard_header_len = (unsigned char *)ixs->iph - ixs->skb->data;

	if (ixs->hard_header_len < 0) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_error:ipsec_xmit_strip_hard_header: "
			    "Negative hard_header_len (%d)?!\n",
			    ixs->hard_header_len);
		ixs->stats->tx_dropped++;
		return IPSEC_XMIT_BADHHLEN;
	}

	/* while ixs->physdev->hard_header_len is unreliable and
	 * should not be trusted, it accurate and required for ATM, GRE and
	 * some other interfaces to work. Thanks to Willy Tarreau
	 * <willy@w.ods.org>.
	 */
	if (ixs->hard_header_len == 0) { /* no hard header present */
		ixs->hard_header_stripped = 1;
		ixs->hard_header_len = ixs->physdev->hard_header_len;
	}

	if (debug_tunnel & DB_TN_XMIT) {
		int i;
		char c;

		printk(KERN_INFO "klips_debug:ipsec_xmit_strip_hard_header: "
		       ">>> skb->len=%ld hard_header_len:%d",
		       (unsigned long int)ixs->skb->len, ixs->hard_header_len);
		c = ' ';
		for (i = 0; i < ixs->hard_header_len; i++) {
			printk("%c%02x", c, ixs->skb->data[i]);
			c = ':';
		}
		printk("\n");
	}

	KLIPS_IP_PRINT(debug_tunnel & DB_TN_XMIT, ixs->iph);

	KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
		    "klips_debug:ipsec_xmit_strip_hard_header: "
		    "Original head,tailroom: %d,%d\n",
		    skb_headroom(ixs->skb), skb_tailroom(ixs->skb));

	return IPSEC_XMIT_OK;
}

enum ipsec_xmit_value ipsec_tunnel_SAlookup(struct ipsec_xmit_state *ixs)
{
	unsigned int bypass;
	unsigned char nexthdr;
	int nexthdroff;
	char tsrc[ADDRTOT_BUF + 1], tdst[ADDRTOT_BUF + 1];

	bypass = FALSE;

	/*
	 * First things first -- look us up in the erouting tables.
	 */
	ixs->matcher.sen_len = sizeof(struct sockaddr_encap);
	ixs->matcher.sen_family = AF_ENCAP;
#ifdef CONFIG_KLIPS_IPV6
	if (lsw_ip_hdr_version(ixs) == 6) {
		IPSEC_FRAG_OFF_DECL(frag_off)
		nexthdr = lsw_ip6_hdr(ixs)->nexthdr;
		nexthdroff = ipsec_ipv6_skip_exthdr(ixs->skb,
						    ((void *)(lsw_ip6_hdr(
								      ixs) +
							      1)) - (void*)ixs->skb->data,
						    &nexthdr, &frag_off);
		ixs->matcher.sen_type = SENT_IP6;
		ixs->matcher.sen_ip6_src = lsw_ip6_hdr(ixs)->saddr;
		ixs->matcher.sen_ip6_dst = lsw_ip6_hdr(ixs)->daddr;
		ixs->matcher.sen_proto6 = nexthdr;
		if (debug_tunnel & DB_TN_XMIT) {
			inet_addrtot(AF_INET6, &lsw_ip6_hdr(
					     ixs)->saddr, 0, tsrc,
				     sizeof(tsrc));
			inet_addrtot(AF_INET6, &lsw_ip6_hdr(
					     ixs)->daddr, 0, tdst,
				     sizeof(tdst));
		}
	} else
#endif  /* CONFIG_KLIPS_IPV6 */
	{
		nexthdr = lsw_ip4_hdr(ixs)->protocol;
		nexthdroff = 0;
		if ((ntohs(lsw_ip4_hdr(ixs)->frag_off) & IP_OFFSET) == 0) {
			nexthdroff =
				(ixs->iph + (lsw_ip4_hdr(ixs)->ihl << 2)) -
				(void *)ixs->skb->data;
		}
		ixs->matcher.sen_type = SENT_IP4;
		ixs->matcher.sen_ip_src.s_addr = lsw_ip4_hdr(ixs)->saddr;
		ixs->matcher.sen_ip_dst.s_addr = lsw_ip4_hdr(ixs)->daddr;
		ixs->matcher.sen_proto = nexthdr;
		if (debug_tunnel & DB_TN_XMIT) {
			inet_addrtot(AF_INET, &lsw_ip4_hdr(
					     ixs)->saddr, 0, tsrc,
				     sizeof(tsrc));
			inet_addrtot(AF_INET, &lsw_ip4_hdr(
					     ixs)->daddr, 0, tdst,
				     sizeof(tdst));
		}
	}
	ipsec_extract_ports(ixs->skb, nexthdr, nexthdroff, &ixs->matcher);

	/*
	 * The spinlock is to prevent any other process from accessing or deleting
	 * the eroute while we are using and updating it.
	 */
	spin_lock_bh(&eroute_lock);

	ixs->eroute = ipsec_findroute(&ixs->matcher);

	if (nexthdr == IPPROTO_UDP) {
		struct udphdr _udphdr, *udphdr = NULL;

		if (nexthdroff)
			udphdr = skb_header_pointer(ixs->skb, nexthdroff,
						    sizeof(*udphdr), &_udphdr);


		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_debug:udp port check: "
			    "version: %d "
			    "nexthdroff: %d "
			    "udphdr: %p\n",
			    lsw_ip_hdr_version(ixs), nexthdroff, udphdr);

		ixs->sport = 0;
		ixs->dport = 0;

		if (ixs->skb->sk) {
#ifdef NET_26
#ifdef HAVE_INET_SK_SPORT
			ixs->sport = ntohs(inet_sk(ixs->skb->sk)->inet_sport);
			ixs->dport = ntohs(inet_sk(ixs->skb->sk)->inet_dport);
#else
			struct udp_sock *us;

			us = (struct udp_sock *)ixs->skb->sk;

			ixs->sport = ntohs(us->inet.sport);
			ixs->dport = ntohs(us->inet.dport);
#endif
#else
			ixs->sport = ntohs(ixs->skb->sk->sport);
			ixs->dport = ntohs(ixs->skb->sk->dport);
#endif
		}

		if (udphdr != NULL) {
			if (ixs->sport == 0)
				ixs->sport = ntohs(udphdr->source);
			if (ixs->dport == 0)
				ixs->dport = ntohs(udphdr->dest);
		}
	}

	/*
	 * practically identical to above, but let's be careful about
	 * tcp vs udp headers
	 */
	if (nexthdr == IPPROTO_TCP) {
		struct tcphdr _tcphdr, *tcphdr = NULL;

		if (nexthdroff)
			tcphdr = skb_header_pointer(ixs->skb, nexthdroff,
						    sizeof(*tcphdr), &_tcphdr);


		ixs->sport = 0;
		ixs->dport = 0;

		if (ixs->skb->sk) {
#ifdef NET_26
#ifdef HAVE_INET_SK_SPORT
			ixs->sport = ntohs(inet_sk(ixs->skb->sk)->inet_sport);
			ixs->dport = ntohs(inet_sk(ixs->skb->sk)->inet_dport);
#else
			struct tcp_tw_bucket *tw;
			tw = (struct tcp_tw_bucket *)ixs->skb->sk;
			ixs->sport = ntohs(tw->tw_sport);
			ixs->dport = ntohs(tw->tw_dport);
#endif
#else
			ixs->sport = ntohs(ixs->skb->sk->sport);
			ixs->dport = ntohs(ixs->skb->sk->dport);
#endif
		}

		if (tcphdr != NULL) {
			if (ixs->sport == 0)
				ixs->sport = ntohs(tcphdr->source);
			if (ixs->dport == 0)
				ixs->dport = ntohs(tcphdr->dest);
		}
	}

#ifdef CONFIG_KLIPS_IPV6
	if (lsw_ip_hdr_version(ixs) == 6) {
		char edst[ADDRTOT_BUF + 1];
		struct in6_addr addr6_any = IN6ADDR_ANY_INIT;

		/* default to a %drop eroute */
		ixs->outgoing_said.proto = IPPROTO_INT;
		ixs->outgoing_said.spi = htonl(SPI_DROP);
		ixs->outgoing_said.dst.u.v6.sin6_addr = addr6_any;
		if (debug_tunnel & DB_TN_XMIT) {
			if (ixs->eroute)
				sin_addrtot(&ixs->eroute->er_said.dst.u, 0,
					    edst, sizeof(edst));
			else
				memcpy(edst, "0", 2);
		}

		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_debug:ipsec_xmit_SAlookup: "
			    "checking for local udp/500 IKE, udp/4500 NAT-T, ESP or AH packets "
			    "saddr=%s, er=0p%p, daddr=%s, er_dst=%s, proto=%d sport=%d dport=%d\n",
			    tsrc,
			    ixs->eroute,
			    tdst,
			    edst,
			    nexthdr,
			    ixs->sport,
			    ixs->dport);

		/*
		 * cheat for now...are we udp/500? If so, let it through
		 * without interference since it is most likely an IKE packet.
		 */

		if (ip6_chk_addr(&lsw_ip6_hdr(ixs)->saddr) == IS_MYADDR &&
		    (ixs->eroute == NULL ||
		     ipv6_addr_cmp(&lsw_ip6_hdr(ixs)->daddr,
				   &ixs->eroute->er_said.dst.u.v6.sin6_addr) ==
		     0 ||
		     ipv6_addr_any(&ixs->eroute->er_said.dst.u.v6.sin6_addr))
		    &&
		    (nexthdr == IPPROTO_ESP || nexthdr == IPPROTO_AH ||
		     (nexthdr == IPPROTO_UDP &&
		      (ixs->sport == 500 || ixs->sport == 4500)))) {
			/* Whatever the eroute, this is an IKE message
			 * from us (i.e. not being forwarded).
			 * Furthermore, if there is a tunnel eroute,
			 * the destination is the peer for this eroute.
			 * So %pass the packet: modify the default %drop.
			 */
			unsigned int ptr;

			ixs->outgoing_said.spi = htonl(SPI_PASS);
			if (!ixs->skb->sk &&
			    lsw_ipv6_find_hdr(ixs->skb, &ptr, NEXTHDR_FRAGMENT,
					      NULL) != ENOENT) {
				KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
					    "klips_debug:ipsec_xmit_SAlookup: "
					    "local UDP/500 (probably IKE) passthrough: base fragment, rest of fragments will probably get filtered.\n");
			}
			bypass = TRUE;
		}
	} else
#endif  /* CONFIG_KLIPS_IPV6 */
	{
		/* default to a %drop eroute */
		ixs->outgoing_said.proto = IPPROTO_INT;
		ixs->outgoing_said.spi = htonl(SPI_DROP);
		ixs->outgoing_said.dst.u.v4.sin_addr.s_addr = INADDR_ANY;
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_debug:ipsec_xmit_SAlookup: "
			    "checking for local udp/500 IKE, udp/4500 NAT-T, ESP or AH packets "
			    "saddr=%s, er=0p%p, daddr=%s, er_dst=%x, proto=%d sport=%d dport=%d\n",
			    tsrc,
			    ixs->eroute,
			    tdst,
			    ixs->eroute ? ntohl((unsigned int)ixs->eroute->
						er_said.dst.u.v4.sin_addr.
						s_addr) : 0,
			    nexthdr,
			    ixs->sport,
			    ixs->dport);

		/*
		 * cheat for now...are we udp/500? If so, let it through
		 * without interference since it is most likely an IKE packet.
		 */

		if (ip_chk_addr(lsw_ip4_hdr(ixs)->saddr) == IS_MYADDR &&
		    (ixs->eroute == NULL ||
		     lsw_ip4_hdr(ixs)->daddr ==
		     ixs->eroute->er_said.dst.u.v4.sin_addr.s_addr ||
		     INADDR_ANY ==
		     ixs->eroute->er_said.dst.u.v4.sin_addr.s_addr) &&
		    (nexthdr == IPPROTO_ESP || nexthdr == IPPROTO_AH ||
		     (nexthdr == IPPROTO_UDP &&
		      (ixs->sport == 500 || ixs->sport == 4500)))) {
			/* Whatever the eroute, this is an IKE message
			 * from us (i.e. not being forwarded).
			 * Furthermore, if there is a tunnel eroute,
			 * the destination is the peer for this eroute.
			 * So %pass the packet: modify the default %drop.
			 */

			ixs->outgoing_said.spi = htonl(SPI_PASS);
			if (!(ixs->skb->sk) &&
			    ((ntohs(lsw_ip4_hdr(ixs)->frag_off) & IP_MF) !=
			     0)) {
				KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
					    "klips_debug:ipsec_xmit_SAlookup: "
					    "local UDP/500 (probably IKE) passthrough: base fragment, rest of fragments will probably get filtered.\n");
			}
			bypass = TRUE;
		}
	}

	if (!bypass && ixs->eroute != NULL) {
		ixs->eroute->er_count++;
		ixs->eroute->er_lasttime = jiffies / HZ;
		if (ixs->eroute->er_said.proto == IPPROTO_INT &&
		    ixs->eroute->er_said.spi == htonl(SPI_HOLD)) {
			KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
				    "klips_debug:ipsec_xmit_SAlookup: "
				    "shunt SA of HOLD: skb stored in HOLD.\n");
			if (ixs->eroute->er_last != NULL) {
				ipsec_kfree_skb(ixs->eroute->er_last);
				ixs->stats->tx_dropped++;
			}
			ixs->eroute->er_last = ixs->skb;
			ixs->skb = NULL;
			spin_unlock_bh(&eroute_lock);
			return IPSEC_XMIT_STOLEN;
		}
		ixs->outgoing_said = ixs->eroute->er_said;
		ixs->eroute_pid = ixs->eroute->er_pid;

		/* Copy of the ident for the TRAP/TRAPSUBNET eroutes */
		if (ixs->outgoing_said.proto == IPPROTO_INT &&
		    (ixs->outgoing_said.spi == htonl(SPI_TRAP) ||
		     (ixs->outgoing_said.spi == htonl(SPI_TRAPSUBNET)))) {
			int len;

			ixs->ips.ips_ident_s.type =
				ixs->eroute->er_ident_s.type;
			ixs->ips.ips_ident_s.id = ixs->eroute->er_ident_s.id;
			ixs->ips.ips_ident_s.len = ixs->eroute->er_ident_s.len;
			if (ixs->ips.ips_ident_s.len) {
				len = ixs->ips.ips_ident_s.len *
				      IPSEC_PFKEYv2_ALIGN -
				      sizeof(struct sadb_ident);
				KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
					    "klips_debug:ipsec_xmit_SAlookup: "
					    "allocating %d bytes for ident_s shunt SA of HOLD: skb stored in HOLD.\n",
					    len);
				if ((ixs->ips.ips_ident_s.data =
					     kmalloc(len,
						     GFP_ATOMIC)) == NULL) {
					printk(KERN_WARNING "klips_debug:ipsec_xmit_SAlookup: "
					       "Failed, tried to allocate %d bytes for source ident.\n",
					       len);
					ixs->stats->tx_dropped++;
					spin_unlock_bh(&eroute_lock);
					return IPSEC_XMIT_ERRMEMALLOC;
				}
				memcpy(ixs->ips.ips_ident_s.data,
				       ixs->eroute->er_ident_s.data, len);
			}
			ixs->ips.ips_ident_d.type =
				ixs->eroute->er_ident_d.type;
			ixs->ips.ips_ident_d.id = ixs->eroute->er_ident_d.id;
			ixs->ips.ips_ident_d.len = ixs->eroute->er_ident_d.len;
			if (ixs->ips.ips_ident_d.len) {
				len = ixs->ips.ips_ident_d.len *
				      IPSEC_PFKEYv2_ALIGN -
				      sizeof(struct sadb_ident);
				KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
					    "klips_debug:ipsec_xmit_SAlookup: "
					    "allocating %d bytes for ident_d shunt SA of HOLD: skb stored in HOLD.\n",
					    len);
				if ((ixs->ips.ips_ident_d.data =
					     kmalloc(len,
						     GFP_ATOMIC)) == NULL) {
					printk(KERN_WARNING "klips_debug:ipsec_xmit_SAlookup: "
					       "Failed, tried to allocate %d bytes for dest ident.\n",
					       len);
					ixs->stats->tx_dropped++;
					spin_unlock_bh(&eroute_lock);
					return IPSEC_XMIT_ERRMEMALLOC;
				}
				memcpy(ixs->ips.ips_ident_d.data,
				       ixs->eroute->er_ident_d.data, len);
			}
		}
	}

	spin_unlock_bh(&eroute_lock);
	return IPSEC_XMIT_OK;
}

enum ipsec_xmit_value ipsec_tunnel_restore_hard_header(
	struct ipsec_xmit_state*ixs)
{
	KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
		    "klips_debug:ipsec_xmit_restore_hard_header: "
		    "After recursive xforms -- head,tailroom: %d,%d\n",
		    skb_headroom(ixs->skb),
		    skb_tailroom(ixs->skb));

	if (ixs->saved_header) {
		if (skb_headroom(ixs->skb) < ixs->hard_header_len) {
			printk(KERN_WARNING
			       "klips_error:ipsec_xmit_restore_hard_header: "
			       "tried to skb_push hhlen=%d, %d available.  This should never happen, please report.\n",
			       ixs->hard_header_len,
			       skb_headroom(ixs->skb));
			ixs->stats->tx_errors++;
			return IPSEC_XMIT_PUSHPULLERR;

		}
		skb_push(ixs->skb, ixs->hard_header_len);
		{
			int i;
			for (i = 0; i < ixs->hard_header_len; i++)
				ixs->skb->data[i] = ixs->saved_header[i];
		}
	}

	KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
		    "klips_debug:ipsec_xmit_restore_hard_header: "
		    "With hard_header, final head,tailroom: %d,%d\n",
		    skb_headroom(ixs->skb),
		    skb_tailroom(ixs->skb));

	return IPSEC_XMIT_OK;
}

/*
 * when encap processing is complete it call this for us to continue
 */

void ipsec_tunnel_xsm_complete(struct ipsec_xmit_state *ixs,
			       enum ipsec_xmit_value stat)
{
	unsigned char nexthdr;
	int nexthdroff;

	if (stat != IPSEC_XMIT_OK) {
		if (stat == IPSEC_XMIT_PASS)
			goto bypass;

		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_debug:ipsec_tunnel_start_xmit: encap_bundle failed: %d\n",
			    stat);
		goto cleanup;
	}

#ifdef CONFIG_KLIPS_IPV6
	if (lsw_ip_hdr_version(ixs) == 6) {
		IPSEC_FRAG_OFF_DECL(frag_off)
		nexthdr = lsw_ip6_hdr(ixs)->nexthdr;
		nexthdroff = ipsec_ipv6_skip_exthdr(ixs->skb,
						    ((void *)(lsw_ip6_hdr(
								      ixs) +
							      1)) - (void*)ixs->skb->data,
						    &nexthdr, &frag_off);
		ixs->matcher.sen_type = SENT_IP6;
		ixs->matcher.sen_ip6_src = lsw_ip6_hdr(ixs)->saddr;
		ixs->matcher.sen_ip6_dst = lsw_ip6_hdr(ixs)->daddr;
		ixs->matcher.sen_proto6 = nexthdr;
	} else
#endif  /* CONFIG_KLIPS_IPV6 */
	{
		nexthdr = lsw_ip4_hdr(ixs)->protocol;
		nexthdroff = 0;
		if ((ntohs(lsw_ip4_hdr(ixs)->frag_off) & IP_OFFSET) == 0) {
			nexthdroff =
				(ixs->iph + (lsw_ip4_hdr(ixs)->ihl << 2)) -
				(void *)ixs->skb->data;
		}
		ixs->matcher.sen_type = SENT_IP4;
		ixs->matcher.sen_ip_src.s_addr = lsw_ip4_hdr(ixs)->saddr;
		ixs->matcher.sen_ip_dst.s_addr = lsw_ip4_hdr(ixs)->daddr;
		ixs->matcher.sen_proto = nexthdr;
	}
	ipsec_extract_ports(ixs->skb, nexthdr, nexthdroff, &ixs->matcher);

	spin_lock_bh(&eroute_lock);
	ixs->eroute = ipsec_findroute(&ixs->matcher);
	if (ixs->eroute) {
		ixs->outgoing_said = ixs->eroute->er_said;
		ixs->eroute_pid = ixs->eroute->er_pid;
		ixs->eroute->er_count++;
		ixs->eroute->er_lasttime = jiffies / HZ;
	}
	spin_unlock_bh(&eroute_lock);

	if ( /*((ixs->orgdst != ixs->newdst) || (ixs->orgsrc != ixs->newsrc))*/
		!ip_address_eq(&ixs->orgedst, &ixs->outgoing_said.dst) &&
		!ip_address_isany(&ixs->outgoing_said.dst) &&
		ixs->eroute) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_debug:ipsec_tunnel_start_xmit: "
			    "We are recursing here.\n");
		ipsec_xsm(ixs);
		return;
	}

	stat = ipsec_nat_encap(ixs);
	if (stat != IPSEC_XMIT_OK)
		goto cleanup;

	stat = ipsec_tunnel_restore_hard_header(ixs);
	if (stat != IPSEC_XMIT_OK)
		goto cleanup;

bypass:
	stat = ipsec_tunnel_send(ixs);

cleanup:
	ipsec_xmit_cleanup(ixs);
	ipsec_xmit_state_delete(ixs);
}

/*
 *	This function assumes it is being called from dev_queue_xmit()
 *	and that skb is filled properly by that function.
 */
int ipsec_tunnel_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ipsec_xmit_state *ixs = NULL;
	enum ipsec_xmit_value stat;

	KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
		    "\n\nipsec_tunnel_start_xmit: STARTING");

	stat = IPSEC_XMIT_ERRMEMALLOC;
	ixs = ipsec_xmit_state_new(dev);
	if (ixs == NULL)
		return NETDEV_TX_BUSY;

	ixs->dev = dev;
	ixs->skb = skb;

	stat = ipsec_xmit_sanity_check_ipsec_dev(ixs);
	if (stat != IPSEC_XMIT_OK)
		goto cleanup;

	stat = ipsec_xmit_sanity_check_skb(ixs);
	if (stat != IPSEC_XMIT_OK)
		goto cleanup;

	stat = ipsec_tunnel_strip_hard_header(ixs);
	if (stat != IPSEC_XMIT_OK)
		goto cleanup;

	stat = ipsec_tunnel_SAlookup(ixs);
	if (stat != IPSEC_XMIT_OK) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_debug:ipsec_tunnel_start_xmit: SAlookup failed: %d\n",
			    stat);
		goto cleanup;
	}

	ixs->xsm_complete = ipsec_tunnel_xsm_complete;

	ipsec_xsm(ixs);
	return 0;

cleanup:
	ipsec_xmit_cleanup(ixs);
	ipsec_xmit_state_delete(ixs);
	return 0;
}

DEBUG_NO_STATIC struct net_device_stats *ipsec_tunnel_get_stats(
	struct net_device *dev)
{
	return &(netdev_to_ipsecpriv(dev)->mystats);
}

/*
 * Revectored calls.
 * For each of these calls, a field exists in our private structure.
 */

DEBUG_NO_STATIC int ipsec_tunnel_hard_header(struct sk_buff *skb,
					     struct net_device *dev,
					     unsigned short type,
					     const void *daddr,
					     const void *saddr, unsigned len)
{
	struct ipsecpriv *prv = netdev_to_ipsecpriv(dev);
	struct net_device *tmp;
	int ret;
	struct net_device_stats *stats; /* This device's statistics */

	if (skb == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_hard_header: "
			    "no skb...\n");
		return -ENODATA;
	}

	if (dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_hard_header: "
			    "no device...\n");
		return -ENODEV;
	}

	KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
		    "klips_debug:ipsec_tunnel_hard_header: "
		    "skb->dev=%s dev=%s.\n",
		    skb->dev ? skb->dev->name : "NULL",
		    dev->name);

	if (prv == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_hard_header: "
			    "no private space associated with dev=%s\n",
			    dev->name ? dev->name : "NULL");
		return -ENODEV;
	}

	stats = (struct net_device_stats *) &(prv->mystats);

	if (prv->dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_hard_header: "
			    "no physical device associated with dev=%s\n",
			    dev->name ? dev->name : "NULL");
		stats->tx_dropped++;
		return -ENODEV;
	}

	/* check if we have to send a IPv6 packet. It might be a Router
	   Solicitation, where the building of the packet happens in
	   reverse order:
	   1. ll hdr,
	   2. IPv6 hdr,
	   3. ICMPv6 hdr
	   -> skb->nh.raw is still uninitialized when this function is
	   called!!  If this is no IPv6 packet, we can print debugging
	   messages, otherwise we skip all debugging messages and just
	   build the ll header */
	if (type != ETH_P_IPV6) {
		/* execute this only, if we don't have to build the
		   header for a IPv6 packet */
#ifdef HAVE_NETDEV_HEADER_OPS
		if (!prv->header_ops->create)
#else
		if (!prv->hard_header)
#endif
		{
			KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
				    "klips_debug:ipsec_tunnel_hard_header: "
				    "physical device has been detached, packet dropped 0p%p->0p%p len=%d type=%d dev=%s->NULL ",
				    saddr,
				    daddr,
				    len,
				    type,
				    dev->name);
			KLIPS_PRINTMORE(debug_tunnel & DB_TN_REVEC,
					"ip=%08x->%08x\n",
					(__u32)ntohl(ip_hdr(skb)->saddr),
					(__u32)ntohl(ip_hdr(skb)->daddr) );
			stats->tx_dropped++;
			return -ENODEV;
		}

#define da ((struct net_device *)(prv->dev))->dev_addr
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_hard_header: "
			    "Revectored 0p%p->0p%p len=%d type=%d dev=%s->%s dev_addr=%02x:%02x:%02x:%02x:%02x:%02x ",
			    saddr,
			    daddr,
			    len,
			    type,
			    dev->name,
			    prv->dev->name,
			    da[0], da[1], da[2], da[3], da[4], da[5]);
		KLIPS_PRINTMORE(debug_tunnel & DB_TN_REVEC,
				"ip=%08x->%08x\n",
				(__u32)ntohl(ip_hdr(skb)->saddr),
				(__u32)ntohl(ip_hdr(skb)->daddr) );
	} else {
		KLIPS_PRINT(debug_tunnel,
			    "klips_debug:ipsec_tunnel_hard_header: "
			    "is IPv6 packet, skip debugging messages, only revector and build linklocal header.\n");
	}
	tmp = skb->dev;
	skb->dev = prv->dev;
#ifdef HAVE_NETDEV_HEADER_OPS
	ret = prv->header_ops->create(skb, prv->dev, type, (void *)daddr,
				      (void *)saddr, len);
#else
	ret = prv->hard_header(skb, prv->dev, type, (void *)daddr,
			       (void *)saddr, len);
#endif
	skb->dev = tmp;
	return ret;
}

#ifdef HAVE_REBUILD_HEADER
DEBUG_NO_STATIC int ipsec_tunnel_rebuild_header(struct sk_buff *skb)
{
	struct ipsecpriv *prv = netdev_to_ipsecpriv(skb->dev);
	struct net_device *tmp;
	int ret;
	struct net_device_stats *stats; /* This device's statistics */

	if (skb->dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_rebuild_header: "
			    "no device...");
		return -ENODEV;
	}

	if (prv == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_rebuild_header: "
			    "no private space associated with dev=%s",
			    skb->dev->name ? skb->dev->name : "NULL");
		return -ENODEV;
	}

	stats = (struct net_device_stats *) &(prv->mystats);

	if (prv->dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_rebuild_header: "
			    "no physical device associated with dev=%s",
			    skb->dev->name ? skb->dev->name : "NULL");
		stats->tx_dropped++;
		return -ENODEV;
	}

#ifdef HAVE_NETDEV_HEADER_OPS
	if (!prv->header_ops->rebuild)
#else
	if (!prv->rebuild_header)
#endif
	{
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_rebuild_header: "
			    "physical device has been detached, packet dropped skb->dev=%s->NULL ",
			    skb->dev->name);
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "ip=%08x->%08x\n",
			    (__u32)ntohl(ip_hdr(skb)->saddr),
			    (__u32)ntohl(ip_hdr(skb)->daddr) );
		stats->tx_dropped++;
		return -ENODEV;
	}

	KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
		    "klips_debug:ipsec_tunnel: "
		    "Revectored rebuild_header dev=%s->%s ",
		    skb->dev->name, prv->dev->name);
	KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
		    "ip=%08x->%08x\n",
		    (__u32)ntohl(ip_hdr(skb)->saddr),
		    (__u32)ntohl(ip_hdr(skb)->daddr) );
	tmp = skb->dev;
	skb->dev = prv->dev;

#ifdef HAVE_NETDEV_HEADER_OPS
	ret = prv->header_ops->rebuild(skb);
#else
	ret = prv->rebuild_header(skb);
#endif
	skb->dev = tmp;
	return ret;
}
#endif

#ifdef HAVE_SET_MAC_ADDR
DEBUG_NO_STATIC int ipsec_tunnel_set_mac_address(struct net_device *dev,
						 void *addr)
{
	struct ipsecpriv *prv = netdev_to_ipsecpriv(dev);

	struct net_device_stats *stats; /* This device's statistics */

	if (dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_set_mac_address: "
			    "no device...");
		return -ENODEV;
	}

	if (prv == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_set_mac_address: "
			    "no private space associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		return -ENODEV;
	}

	stats = (struct net_device_stats *) &(prv->mystats);

	if (prv->dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_set_mac_address: "
			    "no physical device associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		stats->tx_dropped++;
		return -ENODEV;
	}

	if (!prv->dev) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_set_mac_address: "
			    "physical device has been detached, cannot set - skb->dev=%s->NULL\n",
			    dev->name);
		return -ENODEV;
	}

	KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
		    "klips_debug:ipsec_tunnel_set_mac_address: "
		    "Revectored dev=%s->%s addr=0p%p\n",
		    dev->name, prv->dev->name, addr);
	return prv->set_mac_address(prv->dev, addr);

}
#endif /* HAVE_SET_MAC_ADDR */

DEBUG_NO_STATIC void ipsec_tunnel_cache_update(struct hh_cache *hh,
					       const struct net_device *dev,
					       const unsigned char *  haddr)
{
	struct ipsecpriv *prv = netdev_to_ipsecpriv(dev);

	struct net_device_stats *stats; /* This device's statistics */

	if (dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_cache_update: "
			    "no device...");
		return;
	}

	if (prv == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_cache_update: "
			    "no private space associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		return;
	}

	stats = (struct net_device_stats *) &(prv->mystats);

	if (prv->dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_cache_update: "
			    "no physical device associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		stats->tx_dropped++;
		return;
	}

#ifdef HAVE_NETDEV_HEADER_OPS
	if (!prv->header_ops->cache_update)
#else
	if (!prv->header_cache_update)
#endif
	{
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_cache_update: "
			    "physical device has been detached, cannot set - skb->dev=%s->NULL\n",
			    dev->name);
		return;
	}

	KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
		    "klips_debug:ipsec_tunnel: "
		    "Revectored cache_update\n");
#ifdef HAVE_NETDEV_HEADER_OPS
	prv->header_ops->cache_update(hh, prv->dev, haddr);
#else
	prv->header_cache_update(hh, prv->dev, haddr);
#endif
}

#ifdef HAVE_NETDEV_HEADER_OPS
const struct header_ops ipsec_tunnel_header_ops = {
	.create         = ipsec_tunnel_hard_header,
#ifdef HAVE_REBUILD_HEADER
	.rebuild        = ipsec_tunnel_rebuild_header,
#endif
	.cache_update   = ipsec_tunnel_cache_update,
};
#endif

DEBUG_NO_STATIC int ipsec_tunnel_neigh_setup(struct neighbour *n)
{
	KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
		    "klips_debug:ipsec_tunnel_neigh_setup:\n");

	if (n->nud_state == NUD_NONE) {
#ifndef PRIVATE_ARP_BROKEN_OPS
		n->ops = &arp_broken_ops;
#endif
		n->output = n->ops->output;
	}
	return 0;
}

DEBUG_NO_STATIC int ipsec_tunnel_neigh_setup_dev(struct net_device *dev,
						 struct neigh_parms *p)
{
	KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
		    "klips_debug:ipsec_tunnel_neigh_setup_dev: "
		    "setting up %s\n",
		    dev ? dev->name : "NULL");

	if (p->tbl->family == AF_INET) {
		p->neigh_setup = ipsec_tunnel_neigh_setup;
#ifdef NEIGH_VAR_SET
		/*
		 * see kernel's include/net/neighbour.h
		 * ??? Not sure which to use:
		 * NEIGH_VAR_INIT or NEIGH_VAR_INIT
		 */
		NEIGH_VAR_SET(p, UCAST_PROBES, 0);
		NEIGH_VAR_SET(p, MCAST_PROBES, 0);
#else
		p->ucast_probes = 0;
		p->mcast_probes = 0;
#endif
	}
	return 0;
}

/*
 * We call the detach routine to detach the ipsec tunnel from another device.
 */

DEBUG_NO_STATIC int ipsec_tunnel_detach(struct net_device *dev)
{
	int i;
	struct ipsecpriv *prv = netdev_to_ipsecpriv(dev);

	if (dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_detach: "
			    "no device...");
		return -ENODEV;
	}

	if (prv == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_detach: "
			    "no private space associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		return -ENODATA;
	}

	KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
		    "klips_debug:ipsec_tunnel_detach: "
		    "physical device %s being detached from virtual device %s\n",
		    prv->dev ? prv->dev->name : "NULL",
		    dev->name);

	ipsec_dev_put(prv->dev);
	prv->dev = NULL;
	prv->hard_start_xmit = NULL;
	prv->get_stats = NULL;

#ifdef HAVE_NETDEV_HEADER_OPS
	prv->header_ops = NULL;
#else
	prv->hard_header = NULL;
#ifdef HAVE_REBUILD_HEADER
	prv->rebuild_header = NULL;
#endif
	prv->header_cache_update = NULL;
#endif
	prv->set_mac_address = NULL;
	dev->hard_header_len = 0;

#ifdef DETACH_AND_DOWN
#ifdef HAVE_NETDEV_HEADER_OPS
	dev->header_ops = NULL;
#else
	dev->hard_header = NULL;
#ifdef HAVE_REBUILD_HEADER
	dev->rebuild_header = NULL;
#endif
	dev->header_cache_update = NULL;
	dev->neigh_setup        = NULL;
#endif
#ifdef HAVE_SET_MAC_ADDR
	dev->set_mac_address = NULL;
#endif
	dev->mtu = 0;
#endif  /* DETACH_AND_DOWN */

	prv->mtu = 0;
	for (i = 0; i < MAX_ADDR_LEN; i++)
		dev->dev_addr[i] = 0;
	dev->addr_len = 0;
#ifdef PHYSDEV_TYPE
	dev->type = ARPHRD_VOID; /* ARPHRD_TUNNEL; */
#endif /*  PHYSDEV_TYPE */

	return 0;
}

/*
 * We call the clear routine to detach all ipsec tunnels from other devices.
 */
DEBUG_NO_STATIC int ipsec_tunnel_clear(void)
{
	int i;
	struct net_device *ipsecdev = NULL, *prvdev;
	struct ipsecpriv *prv;
	int ret;

	KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
		    "klips_debug:ipsec_tunnel_clear: .\n");

	for (i = 0; i < IPSEC_NUM_IFMAX; i++) {
		ipsecdev = ipsecdevices[i];
		if (!ipsecdev || !netdev_priv(ipsecdev))
			continue;

		prv = netdev_to_ipsecpriv(ipsecdev);
		if (!prv)
			continue;

		prvdev = (struct net_device *)(prv->dev);
		if (!prvdev)
			continue;

		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_tunnel_clear: "
			    "physical device for device %s is %s\n",
			    ipsecdev->name, prvdev->name);
		if ((ret = ipsec_tunnel_detach(ipsecdev))) {
			KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
				    "klips_debug:ipsec_tunnel_clear: "
				    "error %d detatching device %s from device %s.\n",
				    ret, ipsecdev->name, prvdev->name);
			return ret;
		}
	}
	return 0;
}

/*
 * Used mostly for KLIPS to setup interface, for also with NETKEY when using
 * 2.6.23+ UDP XFRM code to mark sockets UDP_ENCAP_ESPINUDP_NON_IKE
 */
DEBUG_NO_STATIC int ipsec_tunnel_ioctl(struct net_device *dev,
				       struct ifreq *ifr, int cmd)
{
	/* struct ipsectunnelconf *cf = (struct ipsectunnelconf *)&ifr->ifr_data;*/
	/* overlay our struct ipsectunnel onto ifr.ifr_ifru union (hope it fits!) */
	struct ipsectunnelconf *cf =
		(struct ipsectunnelconf *)ifr->ifr_ifru.ifru_newname;
	struct ipsecpriv *prv = netdev_to_ipsecpriv(dev);
	struct net_device *them; /* physical device */
	char *colon;
	char realphysname[IFNAMSIZ];

	if (dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_tunnel_ioctl: "
			    "device not supplied.\n");
		return -ENODEV;
	}

	KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
		    "klips_debug:ipsec_tunnel_ioctl: "
		    "tncfg service call #%d for dev=%s\n",
		    cmd,
		    dev->name ? dev->name : "NULL");
	switch (cmd) {
#if defined(KLIPS)
	/* attach a virtual ipsec? device to a physical device */
	case IPSEC_SET_DEV:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_tunnel_ioctl: "
			    "calling ipsec_tunnel_attatch...\n");
		/* If this is an IP alias interface, get its real physical name */
		/* fill_and_terminate(realphysname, cf->cf_name, IFNAMSIZ); */
		strncpy(realphysname, cf->cf_name, IFNAMSIZ-1);
		realphysname[IFNAMSIZ - 1] = 0;

		colon = strchr(realphysname, ':');
		if (colon)
			*colon = 0;
		them = ipsec_dev_get(realphysname);

		if (them == NULL) {
			KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
				    "klips_debug:ipsec_tunnel_ioctl: "
				    "physical device %s requested is null\n",
				    cf->cf_name);
			return -ENXIO;
		}

#if 0
		if (them->flags & IFF_UP) {
			KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
				    "klips_debug:ipsec_tunnel_ioctl: "
				    "physical device %s requested is not up.\n",
				    cf->cf_name);
			ipsec_dev_put(them);
			return -ENXIO;
		}
#endif

		if (prv && prv->dev) {
			KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
				    "klips_debug:ipsec_tunnel_ioctl: "
				    "virtual device is already connected to %s.\n",
				    prv->dev->name ? prv->dev->name : "NULL");
			ipsec_dev_put(them);
			return -EBUSY;
		}
		return ipsec_tunnel_attach(dev, them);

	case IPSEC_DEL_DEV:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_tunnel_ioctl: "
			    "calling ipsec_tunnel_detatch.\n");
		if (!prv->dev) {
			KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
				    "klips_debug:ipsec_tunnel_ioctl: "
				    "physical device not connected.\n");
			return -ENODEV;
		}
		return ipsec_tunnel_detach(dev);

	case IPSEC_CLR_DEV:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_tunnel_ioctl: "
			    "calling ipsec_tunnel_clear.\n");
		return ipsec_tunnel_clear();

#endif          /* KLIPS */

#ifdef HAVE_UDP_ENCAP_CONVERT
	/*
	 * we get two int args in ifr_data, the socket fd (0)
	 * and the type of encapsulation needed (1).
	 */
	case IPSEC_UDP_ENCAP_CONVERT:
	{
		/*unsigned int *ifp =(unsigned int *)&ifr->ifr_data;*/
		/* overlay our struct ipsectunnel onto ifr.ifr_ifru union (hope it fits!) */
		unsigned int *ifp = (unsigned int *)ifr->ifr_ifru.ifru_newname;

		return ipsec_tunnel_udp_encap_prepare(ifp[0], ifp[1]);
	}
#endif          /* HAVE_UDP_ENCAP_CONVERT */

	default:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_tunnel_ioctl: "
			    "unknown command %d.\n",
			    cmd);
		return -EOPNOTSUPP;
	}
}

#ifdef HAVE_UDP_ENCAP_CONVERT

#define IPSEC_TUNNEL_UDP_ENCAP_MAGIC 0x58c0b472
struct ipsec_tunnel_udp_encap_ctx {
	u32 magic;
	struct list_head link;
	struct sock *sk;
	void (*old_sk_destruct)(struct sock *sk);
};
#define list_head_to_udp_encap_ctx(lh) \
	list_entry(lh, struct ipsec_tunnel_udp_encap_ctx, link)

static DEFINE_SPINLOCK(ipsec_tunnel_udp_encap_lock);
static LIST_HEAD(ipsec_tunnel_udp_encap_list);

DEBUG_NO_STATIC int ipsec_tunnel_udp_encap_prepare(int fd, int encap_type)
{
	struct socket *sock = NULL;
	struct sock *sk;
	struct ipsec_tunnel_udp_encap_ctx *ctx = NULL;
	unsigned long flags;
	int err = 0;

	switch (encap_type) {
	case UDP_ENCAP_ESPINUDP:
	case UDP_ENCAP_ESPINUDP_NON_IKE:
		break;
	default:
		printk("ipsec: pid %d sent fd %d with invalid encap_type %d\n",
		       fd, current->pid, encap_type);
		return -EINVAL;
	}

	/* translate descriptor to socket structure */
	err = -EBADF;
	sock = sockfd_lookup(fd, &err);
	if (!sock) {
		printk("ipsec: failed to lookup socket for fd %d for pid %d\n",
		       fd, current->pid);
		goto error;
	}
	sk = sock->sk;

	/* Quick sanity checks */
	err = -EAFNOSUPPORT;
	if (sock->ops->family != AF_INET) {
		printk("ipsec: pid %d sent fd %d with wrong family, "
		       "got %d, expected %d\n",
		       current->pid, fd, sock->ops->family, AF_INET);
		goto error;
	}

	err = -EPROTONOSUPPORT;
	if (sk->sk_protocol != IPPROTO_UDP) {
		printk("ipsec: pid %d sent fd %d with wrong protocol, "
		       "got %d, expected %d\n",
		       current->pid, fd, sk->sk_protocol, IPPROTO_UDP);
		goto error;
	}

	err = -EBUSY;
	if (udp_sk(sk)->encap_type) {
		printk("ipsec: pid %d sent fd %d with encap_type "
		       "assigned to %d",
		       current->pid, fd, udp_sk(sk)->encap_type);
		goto error;
	}

	err = -EBUSY;
	ctx = (struct ipsec_tunnel_udp_encap_ctx*)sk->sk_user_data;
	if (ctx) {
		printk("ipsec: pid %d sent fd %d with user_data assigned\n",
		       current->pid, fd);
		goto error;
	}

	err = -ENOMEM;
	sk->sk_user_data = ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		goto error;

	/* setup the context */
	ctx->magic           = IPSEC_TUNNEL_UDP_ENCAP_MAGIC;
	ctx->sk              = sk;
	ctx->old_sk_destruct = sk->sk_destruct;

	/* convert socket to use our (de)encapsulation routine */
	sk->sk_destruct        = ipsec_tunnel_udp_encap_destruct;
	udp_sk(sk)->encap_type = encap_type;
	udp_sk(sk)->encap_rcv  = klips26_udp_encap_rcv;
#ifdef NEED_UDP_ENCAP_ENABLE
	udp_encap_enable();
#endif

	spin_lock_irqsave(&ipsec_tunnel_udp_encap_lock, flags);
	/* add the tunnel to our list so we can check on it later */
	list_add(&ctx->link, &ipsec_tunnel_udp_encap_list);

	spin_unlock_irqrestore(&ipsec_tunnel_udp_encap_lock, flags);

	KLIPS_PRINT(debug_tunnel,
		    "UDP socket: %u set to %s (0x%x) encap mode\n",
		    fd,
		    encap_type == UDP_ENCAP_ESPINUDP_NON_IKE ?
		    "UDP_ENCAP_ESPINUDP_NON_IKE" : "UDP_ENCAP_ESPINUDP_NON_ESP",
		    encap_type
		    );

	/* success */
	err = 0;

error:
	if (sock)
		sockfd_put(sock);
	return err;
}

DEBUG_NO_STATIC void ipsec_tunnel_udp_encap_destruct(struct sock *sk)
{
	struct ipsec_tunnel_udp_encap_ctx *ctx;
	unsigned long flags;

	if (!sk || !sk->sk_user_data)
		return;

	if (!sock_flag(sk, SOCK_DEAD)) {
		pr_err("Attempt to destruct a live pfkey socket: %p\n", sk);
		return;
	}

	ctx = (struct ipsec_tunnel_udp_encap_ctx*)sk->sk_user_data;
	if (ctx->magic != IPSEC_TUNNEL_UDP_ENCAP_MAGIC) {
		printk("ipsec: called to destroy ctx with wrong magic, "
		       "got %08x, expected %08x\n",
		       ctx->magic, IPSEC_TUNNEL_UDP_ENCAP_MAGIC);
		return;
	}

	if (ctx->sk != sk) {
		printk("ipsec: called to destroy ctx with sk(%p) != ctx->sk(%p)\n",
			sk, ctx->sk);
		return;
	}

	spin_lock_irqsave(&ipsec_tunnel_udp_encap_lock, flags);

	/* revert the socket back */
	udp_sk(sk)->encap_type = 0;
	udp_sk(sk)->encap_rcv  = NULL;

	sk->sk_user_data = NULL;
	sk->sk_destruct = ctx->old_sk_destruct;

	/* remove it from the list */
	list_del(&ctx->link);
	ctx->sk = NULL;

	spin_unlock_irqrestore(&ipsec_tunnel_udp_encap_lock, flags);

	if (sk->sk_destruct)
		sk->sk_destruct(sk);

	kfree(ctx);
}

DEBUG_NO_STATIC void ipsec_tunnel_upd_encap_cleanup(void)
{
	struct ipsec_tunnel_udp_encap_ctx *ctx, *tmp;
	unsigned long flags;
	int i = 0;

	/* wait a bit, see if we can cleanup nicely */
	while (i++ < 60 && !list_empty(&ipsec_tunnel_udp_encap_list))
		mdelay(50);

	/*
	 * ok,  if there is anything left now force it back to the old
	 * destructor
	 */
	spin_lock_irqsave(&ipsec_tunnel_udp_encap_lock, flags);
	list_for_each_entry_safe(ctx, tmp, &ipsec_tunnel_udp_encap_list,
				 link) {
		struct sock *sk = ctx->sk;

		/* revert the socket back */
		udp_sk(sk)->encap_type = 0;
		udp_sk(sk)->encap_rcv  = NULL;

		sk->sk_user_data = NULL;
		sk->sk_destruct = ctx->old_sk_destruct;

		/* remove it from the list */
		list_del(&ctx->link);
		kfree(ctx);
	}
	spin_unlock_irqrestore(&ipsec_tunnel_udp_encap_lock, flags);
}
#endif

struct net_device *ipsec_get_device(int inst)
{
	struct net_device *ipsec_dev;

	ipsec_dev = NULL;

	if (inst < IPSEC_NUM_IFMAX)
		ipsec_dev = ipsecdevices[inst];

	return ipsec_dev;
}

int ipsec_device_event(struct notifier_block *unused, unsigned long event,
		       void *ptr)
{
#ifdef HAVE_NETDEV_INFO
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
#else
	struct net_device *dev = ptr;
#endif
	struct net_device *ipsec_dev;
	struct ipsecpriv *priv;
	int i;

	if (dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_device_event: "
			    "dev=NULL for event type %ld.\n",
			    event);
		return NOTIFY_DONE;
	}
	/* check for loopback devices */
	if (dev && (dev->flags & IFF_LOOPBACK))
		return NOTIFY_DONE;

	if (dev->name[0] == '\0') {
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_device_event: "
			    "dev=\"\" ??? for event type.\n");
	}

	switch (event) {
	case NETDEV_DOWN:
	/* look very carefully at the scope of these compiler
	   directives before changing anything... -- RGB */
	case NETDEV_UNREGISTER:
	case NETDEV_UNREGISTER_FINAL:
		switch (event) {
		case NETDEV_DOWN:
			KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
				    "klips_debug:ipsec_device_event: "
				    "NETDEV_DOWN dev=%s flags=%x\n",
				    dev->name,
				    dev->flags);
			if (strncmp(dev->name, "ipsec", strlen("ipsec")) == 0) {
				printk(KERN_CRIT "IPSEC EVENT: KLIPS device %s shut down.\n",
					dev->name);
			}
			break;
		case NETDEV_UNREGISTER:
			KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
				    "klips_debug:ipsec_device_event: "
				    "NETDEV_UNREGISTER dev=%s flags=%x\n",
				    dev->name,
				    dev->flags);
			break;
		case NETDEV_UNREGISTER_FINAL:
			KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
				    "klips_debug:ipsec_device_event: "
				    "NETDEV_UNREGISTER_FINAL dev=%s flags=%x\n",
				    dev->name,
				    dev->flags);
			break;
		}

		/* find the attached physical device and detach it. */
		for (i = 0; i < IPSEC_NUM_IFMAX; i++) {
			ipsec_dev = ipsecdevices[i];
			if (!ipsec_dev || !netdev_priv(ipsec_dev))
				continue;

			priv = netdev_to_ipsecpriv(ipsec_dev);
			if (priv) {
				if (((struct net_device *)(priv->dev)) == dev) {
					ipsec_tunnel_detach(ipsec_dev);
					KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
						    "klips_debug:ipsec_device_event: "
						    "device '%s' has been detached.\n",
						    ipsec_dev->name);
					break;
				}
			} else {
				KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
					    "klips_debug:ipsec_device_event: "
					    "device '%s' has no private data space!\n",
					    ipsec_dev->name);
			}
		}
		break;
	case NETDEV_UP:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_device_event: "
			    "NETDEV_UP dev=%s\n",
			    dev->name);
		break;
	case NETDEV_REBOOT:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_device_event: "
			    "NETDEV_REBOOT dev=%s\n",
			    dev->name);
		break;
	case NETDEV_CHANGE:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_device_event: "
			    "NETDEV_CHANGE dev=%s flags=%x\n",
			    dev->name,
			    dev->flags);
		break;
	case NETDEV_REGISTER:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_device_event: "
			    "NETDEV_REGISTER dev=%s\n",
			    dev->name);
		break;
	case NETDEV_CHANGEMTU:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_device_event: "
			    "NETDEV_CHANGEMTU dev=%s to mtu=%d\n",
			    dev->name,
			    dev->mtu);
		break;
	case NETDEV_CHANGEADDR:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_device_event: "
			    "NETDEV_CHANGEADDR dev=%s\n",
			    dev->name);
		break;
	case NETDEV_GOING_DOWN:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_device_event: "
			    "NETDEV_GOING_DOWN dev=%s\n",
			    dev->name);
		break;
	case NETDEV_CHANGENAME:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_device_event: "
			    "NETDEV_CHANGENAME dev=%s\n",
			    dev->name);
		break;
	default:
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_device_event: "
			    "event type %ld unrecognised for dev=%s\n",
			    event,
			    dev->name);
		break;
	}
	return NOTIFY_DONE;
}

/*
 *	Called when an ipsec tunnel device is initialized.
 *	The ipsec tunnel device structure is passed to us.
 */

int ipsec_tunnel_init(struct net_device *dev)
{
	int i;
	struct ipsecpriv *iprv;

	KLIPS_PRINT(debug_tunnel,
		    "klips_debug:ipsec_tunnel_init: "
		    "allocating %zu bytes initialising device: %s\n",
		    sizeof(struct ipsecpriv),
		    dev->name ? dev->name : "NULL");

#ifdef ipsec_alloc_netdev
# ifdef HAS_PRIV_DESTRUCTOR
	dev->priv_destructor         = free_netdev;
# else
	dev->destructor         = free_netdev;
# endif
#endif

#ifndef HAVE_NETDEV_PRIV
	{
		struct ipsecpriv *priv_dev;
		priv_dev = kmalloc(sizeof(struct ipsecpriv), GFP_KERNEL);
		if (priv_dev == NULL)
			return;

		dev->priv = priv_dev;
	}
#endif
	iprv = netdev_priv(dev);
	memset(iprv, 0, sizeof(struct ipsecpriv));
	iprv->magic = IPSECPRIV_MAGIC;

	for (i = 0; i < sizeof(zeroes); i++)
		((__u8*)(zeroes))[i] = 0;

#ifdef HAVE_NETDEV_HEADER_OPS
	dev->header_ops         = NULL;
#else
	dev->hard_header        = NULL;
#ifdef HAVE_REBUILD_HEADER
	dev->rebuild_header     = NULL;
#endif
	dev->header_cache_update = NULL;
#endif
#ifdef HAVE_NET_DEVICE_OPS
	dev->netdev_ops         = &klips_device_ops;
#else
	dev->open               = ipsec_tunnel_open;
	dev->stop               = ipsec_tunnel_close;
	dev->hard_start_xmit    = ipsec_tunnel_start_xmit;
	dev->get_stats          = ipsec_tunnel_get_stats;
#ifdef HAVE_SET_MAC_ADDR
	dev->set_mac_address    = NULL;
#endif
	dev->do_ioctl           = ipsec_tunnel_ioctl;
	dev->neigh_setup        = ipsec_tunnel_neigh_setup_dev;
#endif

	dev->hard_header_len    = 0;
	dev->mtu                = 0;
	dev->addr_len           = 0;
	dev->type               = ARPHRD_VOID;  /* ARPHRD_TUNNEL; */ /* ARPHRD_ETHER; */
	dev->tx_queue_len       = 10;           /* Small queue */
#ifdef IFF_XMIT_DST_RELEASE
	dev->priv_flags        &= ~IFF_XMIT_DST_RELEASE;
#endif
	memset((caddr_t)(dev->broadcast), 0xFF, ETH_ALEN);       /* what if this is not attached to ethernet? */

	/* New-style flags. */
	dev->flags              = IFF_NOARP /* 0 */ /* Petr Novak */;

	/* We're done.  Have I forgotten anything? */
	return 0;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*  Module specific interface (but it links with the rest of IPSEC)  */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

int ipsec_tunnel_probe(struct net_device *dev)
{
	ipsec_tunnel_init(dev);
	return 0;
}

#ifdef ipsec_alloc_netdev
static void ipsec_tunnel_netdev_setup(struct net_device *dev)
{
}
#endif

struct net_device *ipsecdevices[IPSEC_NUM_IFMAX];
int ipsecdevices_max = -1;

int ipsec_tunnel_createnum(int ifnum)
{
	char name[IFNAMSIZ];
	struct net_device *dev_ipsec;
	int vifentry;

	if (ifnum >= IPSEC_NUM_IFMAX)
		return -ENOENT;

	if (ipsecdevices[ifnum] != NULL)
		return -EEXIST;

	/* no identical device */
	if (ifnum > ipsecdevices_max)
		ipsecdevices_max = ifnum;
	vifentry = ifnum;

	KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
		    "klips_debug:ipsec_tunnel_init_devices: "
		    "creating and registering IPSEC_NUM_IF=%u device\n",
		    ifnum);

	sprintf(name, IPSEC_DEV_FORMAT, ifnum);
#ifdef alloc_netdev
	dev_ipsec = ipsec_alloc_netdev(sizeof(struct ipsecpriv), name,
				 NET_NAME_UNKNOWN, ipsec_tunnel_netdev_setup);
#else
	dev_ipsec = (struct net_device*)kmalloc(sizeof(struct net_device),
						GFP_KERNEL);
#endif
	if (dev_ipsec == NULL) {
		printk(KERN_ERR "klips_debug:ipsec_tunnel_init_devices: "
		       "failed to allocate memory for device %s, quitting device init.\n",
		       name);
		return -ENOMEM;
	}
#ifndef ipsec_alloc_netdev
	memset((caddr_t)dev_ipsec, 0, sizeof(struct net_device));
	/* fill_and_terminate(dev_ipsec->name, name, sizeof(dev_ipsec->name)); */
	strncpy(dev_ipsec->name, name, sizeof(dev_ipsec->name)-1);
	dev_ipsec->name[sizeof(dev_ipsec->name)-1] ='\0';

#ifdef PAUL_FIXME
	dev_ipsec->next = NULL;
#endif
#endif  /* ipsec_alloc_netdev */
#ifndef USE_NETDEV_OPS
	dev_ipsec->init = &ipsec_tunnel_probe;
#else
	dev_ipsec->netdev_ops = &klips_device_ops;
#endif
	KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
		    "klips_debug:ipsec_tunnel_init_devices: "
		    "registering device %s\n",
		    dev_ipsec->name);

	/* reference and hold the device reference */
	ipsec_dev_hold(dev_ipsec);
	ipsecdevices[vifentry] = dev_ipsec;

	if (register_netdev(dev_ipsec) != 0) {
		KLIPS_PRINT(1 || debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_tunnel_init_devices: "
			    "registering device %s failed, quitting device init.\n",
			    dev_ipsec->name);
		return -EIO;
	} else {
		KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
			    "klips_debug:ipsec_tunnel_init_devices: "
			    "registering device %s succeeded, continuing...\n",
			    dev_ipsec->name);
	}
	return 0;
}

int ipsec_tunnel_init_devices(void)
{
	int i;
	int error;

	KLIPS_PRINT(debug_tunnel & DB_TN_INIT,
		    "klips_debug:ipsec_tunnel_init_devices: "
		    "creating and registering IPSEC_NUM_IF=%u devices, allocating %zu per device, IFNAMSIZ=%u.\n",
		    IPSEC_NUM_IF,
		    sizeof(struct net_device) + IFNAMSIZ,
		    IFNAMSIZ);

	for (i = 0; i < IPSEC_NUM_IF; i++) {
		error = ipsec_tunnel_createnum(i);

		if (error)
			break;
	}
	return 0;
}

int ipsec_tunnel_deletenum(int vifnum)
{
	struct net_device *dev_ipsec;

	if (vifnum >= IPSEC_NUM_IFMAX)
		return -ENOENT;

	dev_ipsec = ipsecdevices[vifnum];
	if (dev_ipsec == NULL)
		return -ENOENT;

	/* release reference */
	ipsecdevices[vifnum] = NULL;
	ipsec_dev_put(dev_ipsec);

	KLIPS_PRINT(debug_tunnel, "Unregistering %s\n", dev_ipsec->name);
	unregister_netdev(dev_ipsec);
	KLIPS_PRINT(debug_tunnel, "Unregisted %s\n", dev_ipsec->name);
#ifndef ipsec_alloc_netdev
	kfree(dev_ipsec->priv);
	dev_ipsec->priv = NULL;
#endif  /* ipsec_alloc_netdev */

	return 0;
}

struct net_device *ipsec_tunnel_get_device(int vifnum)
{
	struct net_device *nd;

	if (vifnum < ipsecdevices_max) {
		nd = ipsecdevices[vifnum];

		if (nd)
			ipsec_dev_hold(nd);
		return nd;
	} else {
		return NULL;
	}
}

/* void */
int ipsec_tunnel_cleanup_devices(void)
{
	int error = 0;
	int i;
	struct net_device *dev_ipsec;

	for (i = 0; i <= ipsecdevices_max; i++) {
		dev_ipsec = ipsecdevices[i];
		if (dev_ipsec == NULL)
			continue;

		/* release reference */
		ipsecdevices[i] = NULL;
		ipsec_dev_put(dev_ipsec);

		KLIPS_PRINT(debug_tunnel, "Unregistering %s\n",
			    dev_ipsec->name);
		unregister_netdev(dev_ipsec);
		KLIPS_PRINT(debug_tunnel, "Unregisted %s\n", dev_ipsec->name);
#ifndef ipsec_alloc_netdev
		kfree(dev_ipsec->priv);
		dev_ipsec->priv = NULL;
#endif          /* ipsec_alloc_netdev */
	}

#ifdef HAVE_UDP_ENCAP_CONVERT
	/* once all devices are down, it's time to restore UDP connections to
	 * not use as for (de)encapsulation anymore */
	ipsec_tunnel_upd_encap_cleanup();
#endif

	return error;
}

/* ------------------------------------------------------------------------
 * this handles creating and managing state for xmit path
 */

static DEFINE_SPINLOCK(ixs_cache_lock);
#ifdef HAVE_KMEM_CACHE_MACRO
static struct kmem_cache *ixs_cache_allocator = NULL;
#else
static kmem_cache_t *ixs_cache_allocator = NULL;
#endif
static unsigned ixs_cache_allocated_count = 0;

int ipsec_ixs_cache_allocated_max = 1000;
module_param(ipsec_ixs_cache_allocated_max, int, 0644);
MODULE_PARM_DESC(ipsec_ixs_cache_allocated_max,
		 "Maximum outstanding transmit packets");

int ipsec_xmit_state_cache_init(void)
{
	if (ixs_cache_allocator)
		return -EBUSY;

	spin_lock_init(&ixs_cache_lock);
#ifdef HAVE_KMEM_CACHE_MACRO
	/* ixs_cache_allocator = KMEM_CACHE(ipsec_ixs,0); */
	ixs_cache_allocator = kmem_cache_create("ipsec_ixs",
						sizeof(struct ipsec_xmit_state), 0,
						0, NULL);
#else
	ixs_cache_allocator = kmem_cache_create("ipsec_ixs",
						sizeof(struct ipsec_xmit_state), 0,
						0, NULL, NULL);
#endif
	if (!ixs_cache_allocator)
		return -ENOMEM;

	return 0;
}

void ipsec_xmit_state_cache_cleanup(void)
{
	if (unlikely(ixs_cache_allocated_count))
		printk("ipsec: deleting ipsec_ixs kmem_cache while in use\n");

	if (ixs_cache_allocator) {
		kmem_cache_destroy(ixs_cache_allocator);
		ixs_cache_allocator = NULL;
	}
	ixs_cache_allocated_count = 0;
}

struct ipsec_xmit_state *ipsec_xmit_state_new(struct net_device *dev)
{
	struct ipsec_xmit_state *ixs;

	spin_lock_bh(&ixs_cache_lock);

	if (ixs_cache_allocated_count >= ipsec_ixs_cache_allocated_max) {
		/* check for something that should never happen */
		if (!netif_queue_stopped(dev)) {
			netif_stop_queue(dev);
			printk("ipsec_tunnel_start_xmit: cannot TX while awake\n");
		}
		spin_unlock_bh(&ixs_cache_lock);
		KLIPS_PRINT(debug_tunnel,
			    "klips_debug:ipsec_xmit_state_new: "
			    "exceeded maximum outstanding TX packet cnt %d\n",
			    ixs_cache_allocated_count);
		return NULL;
	}

	ixs = kmem_cache_alloc(ixs_cache_allocator, GFP_ATOMIC);

	if (likely(ixs != NULL)) {
		ixs_cache_allocated_count++;
		/* stop the Q if we took the last one */
		if (ixs_cache_allocated_count >= ipsec_ixs_cache_allocated_max)
			netif_stop_queue(dev);
	}

	spin_unlock_bh(&ixs_cache_lock);

	if (unlikely(NULL == ixs))
		return NULL;

	/* initialize the object */
#if 1   /* optimised to only clear the required bits */
	memset((caddr_t)ixs, 0, sizeof(*ixs));
#else
	ixs->pass = 0;
	ixs->state = 0;
	ixs->next_state = 0;
	ixs->ipsp = NULL;
	ixs->sa_len = 0;
	ixs->stats = NULL;
	ixs->ips.ips_ident_s.data = NULL;
	ixs->ips.ips_ident_d.data = NULL;
	ixs->outgoing_said.proto = 0;
	ixs->natt_type = 0, ixs->natt_head = 0;
	ixs->natt_sport = 0, ixs->natt_dport = 0;
	ixs->tot_headroom = 0;
	ixs->tot_tailroom = 0;
	ixs->eroute = NULL;
	ixs->hard_header_stripped = 0;
	ixs->hard_header_len = 0;
	ixs->cur_mtu = 0;         /* FIXME: can we do something better ? */

	ixs->oskb = NULL;
	ixs->saved_header = NULL;               /* saved copy of the hard header */
	ixs->route = NULL;
#endif /* memset */
	return ixs;
}

void ipsec_xmit_state_delete(struct ipsec_xmit_state *ixs)
{
	struct net_device *dev;

	if (unlikely(!ixs))
		return;

	dev = ixs->dev;

	spin_lock_bh(&ixs_cache_lock);
	ixs_cache_allocated_count--;
	kmem_cache_free(ixs_cache_allocator, ixs);
#if defined(HAS_NETIF_QUEUE) || defined (HAVE_NETIF_QUEUE)
	if (dev && netif_queue_stopped(dev))
		netif_wake_queue(dev);
#else   /* defined(HAS_NETIF_QUEUE) || defined (HAVE_NETIF_QUEUE) */
	if (dev)
		dev->tbusy = 0;
#endif  /* defined(HAS_NETIF_QUEUE) || defined (HAVE_NETIF_QUEUE) */
	spin_unlock_bh(&ixs_cache_lock);
}

#ifdef HAVE_NET_DEVICE_OPS
const struct net_device_ops klips_device_ops = {
	/* Add our tunnel functions to the device */
	.ndo_init               = ipsec_tunnel_probe,
	.ndo_open               = ipsec_tunnel_open,
	.ndo_stop               = ipsec_tunnel_close,
	.ndo_start_xmit         = ipsec_tunnel_start_xmit,
	.ndo_get_stats          = ipsec_tunnel_get_stats,
	.ndo_neigh_setup        = ipsec_tunnel_neigh_setup_dev,
	.ndo_do_ioctl           = ipsec_tunnel_ioctl,

#ifdef HAVE_SET_MAC_ADDR
	.ndo_set_mac_address = ipsec_tunnel_set_mac_address,
#endif
};
#endif

/*
 * We call the attach routine to attach another device.
 */

DEBUG_NO_STATIC int ipsec_tunnel_attach(struct net_device *dev,
					struct net_device *physdev)
{
	int i;
	struct ipsecpriv *prv = netdev_to_ipsecpriv(dev);

	if (dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_attach: "
			    "no device...");
		return -ENODEV;
	}

	if (prv == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_REVEC,
			    "klips_debug:ipsec_tunnel_attach: "
			    "no private space associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		return -ENODATA;
	}

#ifdef HAVE_NETDEV_HEADER_OPS
	dev->header_ops = &klips_header_ops;
#endif
#ifdef HAVE_NET_DEVICE_OPS
	dev->netdev_ops = &klips_device_ops;
#else
# ifdef HAVE_SET_MAC_ADDR
	dev->set_mac_address = ipsec_tunnel_set_mac_address;
# endif
#endif  /* HAVE_NET_DEVICE_OPS */
	prv->dev = physdev;

#ifdef HAVE_NET_DEVICE_OPS
	prv->hard_start_xmit = physdev->netdev_ops->ndo_start_xmit;
	prv->get_stats       = physdev->netdev_ops->ndo_get_stats;
#else
	prv->hard_start_xmit = physdev->hard_start_xmit;
	prv->get_stats       = physdev->get_stats;
#endif

	/*
	 * David: I haven't worked through this fully yet,  but we were
	 * always copying SKB's because they didn't have enough head room
	 * (even though they were large SKB's). This change got me a 20%
	 * improvement (on TX IIRC)
	 */
	dev->hard_header_len = physdev->hard_header_len + 64;

/*	prv->neigh_setup        = physdev->neigh_setup; */
	dev->mtu = 16260; /* 0xfff0; */ /* dev->mtu; */
	prv->mtu = physdev->mtu;

#ifdef PHYSDEV_TYPE
	dev->type = physdev->type; /* ARPHRD_TUNNEL; */
#endif /*  PHYSDEV_TYPE */

	dev->addr_len = physdev->addr_len;
	for (i = 0; i < dev->addr_len; i++)
		dev->dev_addr[i] = physdev->dev_addr[i];

#ifdef CONFIG_KLIPS_DEBUG
	if (debug_tunnel & DB_TN_INIT) {
		printk(KERN_INFO "klips_debug:ipsec_tunnel_attach: "
		       "physical device %s being attached has HW address: %2x",
		       physdev->name, physdev->dev_addr[0]);
		for (i = 1; i < physdev->addr_len; i++)
			printk(":%02x", physdev->dev_addr[i]);
		printk("\n");
	}
#endif  /* CONFIG_KLIPS_DEBUG */

	return 0;
}

#ifdef CONFIG_KLIPS_IPV6
/*
 * stolen from ip6tables,  we need a copy in case iptables is compiled out of
 * the kernel.
 *
 * find the offset to specified header or the protocol number of last header
 * if target < 0. "last header" is transport protocol header, ESP, or
 * "No next header".
 *
 * If target header is found, its offset is set in *offset and return protocol
 * number. Otherwise, return -1.
 *
 * If the first fragment doesn't contain the final protocol header or
 * NEXTHDR_NONE it is considered invalid.
 *
 * Note that non-1st fragment is special case that "the protocol number
 * of last header" is "next header" field in Fragment header. In this case,
 * *offset is meaningless and fragment offset is stored in *fragoff if fragoff
 * isn't NULL.
 *
 */
int lsw_ipv6_find_hdr(const struct sk_buff *skb,
		      unsigned int *offset, int target,
		      unsigned short *fragoff)
{
	unsigned int start = skb_network_offset(skb) + sizeof(struct ipv6hdr);
	u8 nexthdr = ipv6_hdr(skb)->nexthdr;
	unsigned int len = skb->len - start;

	if (fragoff)
		*fragoff = 0;

	while (nexthdr != target) {
		struct ipv6_opt_hdr _hdr, *hp;
		unsigned int hdrlen;

		if ((!ipv6_ext_hdr(nexthdr)) || nexthdr == NEXTHDR_NONE) {
			if (target < 0)
				break;
			return -ENOENT;
		}

		hp = skb_header_pointer(skb, start, sizeof(_hdr), &_hdr);
		if (hp == NULL)
			return -EBADMSG;

		if (nexthdr == NEXTHDR_FRAGMENT) {
			unsigned short _frag_off;
			__be16 *fp;
			fp = skb_header_pointer(skb,
						start +
						offsetof(struct frag_hdr,
							 frag_off),
						sizeof(_frag_off),
						&_frag_off);
			if (fp == NULL)
				return -EBADMSG;

			_frag_off = ntohs(*fp) & ~0x7;
			if (_frag_off) {
				if (target < 0 &&
				    ((!ipv6_ext_hdr(hp->nexthdr)) ||
				     hp->nexthdr == NEXTHDR_NONE)) {
					if (fragoff)
						*fragoff = _frag_off;
					return hp->nexthdr;
				}
				return -ENOENT;
			}
			hdrlen = 8;
		} else if (nexthdr == NEXTHDR_AUTH) {
			hdrlen = (hp->hdrlen + 2) << 2;
		} else {
			hdrlen = ipv6_optlen(hp);
		}

		nexthdr = hp->nexthdr;
		len -= hdrlen;
		start += hdrlen;
	}

	*offset = start;
	return nexthdr;
}
#endif /* CONFIG_KLIPS_IPV6 */
