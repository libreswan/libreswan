/*
 * IPSEC Transmit code.
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998-2003   Richard Guy Briggs.
 * Copyright (C) 2004-2005   Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2010-2012   David McCullough <david_mccullough@mcafee.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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

#define __NO_VERSION__
#include <linux/module.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) && \
	!defined(AUTOCONF_INCLUDED)
#include <linux/config.h>
#endif  /* for CONFIG_IP_FORWARD */
#include <linux/kernel.h> /* printk() */

#include "libreswan/ipsec_param.h"

#include <linux/slab.h>         /* kmalloc() */
#include <linux/errno.h>        /* error codes */
#include <linux/types.h>        /* size_t */
#include <linux/interrupt.h>    /* mark_bh */

#include <linux/netdevice.h>    /* struct device, struct net_device_stats, dev_queue_xmit() and other headers */
#include <linux/etherdevice.h>  /* eth_type_trans */
#include <linux/ip.h>           /* struct iphdr */
#ifdef CONFIG_KLIPS_IPV6
#include <linux/ipv6.h>         /* struct iphdr */
#endif /* CONFIG_KLIPS_IPV6 */

#include <net/tcp.h>
#include <net/udp.h>
#ifdef CONFIG_KLIPS_IPV6
#include <net/ip6_route.h>
#endif /* CONFIG_KLIPS_IPV6 */
#include <linux/skbuff.h>

#include <asm/uaccess.h>
#include <asm/checksum.h>

#include "libreswan/ipsec_param2.h"

#include <libreswan.h>
# define MSS_HACK_              /* experimental */
# include <linux/in6.h>
# include <net/dst.h>
# define proto_priv cb

#include <net/icmp.h>           /* icmp_send() */
#include <net/ip.h>
#include <linux/netfilter_ipv4.h>

#include <linux/if_arp.h>
#ifdef MSS_HACK_DELETE_ME_PLEASE
# include <net/tcp.h>           /* TCP options */
#endif  /* MSS_HACK_DELETE_ME_PLEASE */

#include "libreswan/ipsec_kversion.h"
#include "libreswan/radij.h"
#include "libreswan/ipsec_life.h"
#include "libreswan/ipsec_xform.h"
#include "libreswan/ipsec_eroute.h"
#include "libreswan/ipsec_encap.h"
#include "libreswan/ipsec_radij.h"
#include "libreswan/ipsec_xmit.h"
#include "libreswan/ipsec_sa.h"
#include "libreswan/ipsec_tunnel.h"
#include "libreswan/ipsec_ipe4.h"
#include "libreswan/ipsec_ah.h"
#include "libreswan/ipsec_esp.h"
#include "libreswan/ipsec_mast.h"

#ifdef CONFIG_KLIPS_IPCOMP
#include "libreswan/ipcomp.h"
#endif /* CONFIG_KLIPS_IPCOMP */

#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include "libreswan/ipsec_proto.h"
#include "libreswan/ipsec_alg.h"
#ifdef CONFIG_KLIPS_OCF
# include "ipsec_ocf.h"
#endif

#if defined(CONFIG_KLIPS_AH)
#if defined(CONFIG_KLIPS_AUTH_HMAC_MD5) || defined(CONFIG_KLIPS_AUTH_HMAC_SHA1) || defined(CONFIG_KLIPS_ALG)
static __u32 zeroes[64];
#endif
#endif

static int ipsec_set_dst(struct ipsec_xmit_state *ixs);

int ipsec_xmit_trap_count = 0;
int ipsec_xmit_trap_sendcount = 0;

#define dmp(_x, _y, _z) if (debug_xmit && sysctl_ipsec_debug_verbose) \
		ipsec_dmp_block(_x, _y, _z)

#if defined(KLIPS_UNIT_TESTS)
# ifdef CONFIG_KLIPS_IPV6
#  error "this code is broken for IPv6"
# endif

/*
 *	This is mostly skbuff.c:skb_copy().
 */
struct sk_buff *skb_copy_expand(const struct sk_buff *skb, int headroom,
				int tailroom, int priority)
{
	struct sk_buff *n;
	unsigned long offset;

	/*
	 *	Do sanity checking
	 */
	if ((headroom < 0) || (tailroom < 0) || ((headroom + tailroom) < 0)) {
		printk(KERN_WARNING
		       "klips_error:skb_copy_expand: "
		       "Illegal negative head,tailroom %d,%d\n",
		       headroom,
		       tailroom);
		return NULL;
	}
	/*
	 *	Allocate the copy buffer
	 */

	n = alloc_skb(skb->end - skb->head + headroom + tailroom, priority);

	KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
		    "klips_debug:skb_copy_expand: "
		    "allocating %d bytes, head=0p%p data=0p%p tail=0p%p end=0p%p end-head=%d tail-data=%d\n",
		    skb->end - skb->head + headroom + tailroom,
		    skb->head,
		    skb->data,
		    skb->tail,
		    skb->end,
		    skb->end - skb->head,
		    skb->tail - skb->data);

	if (n == NULL)
		return NULL;

	/*
	 *	Shift between the two data areas in bytes
	 */

	/* Set the data pointer */
	skb_reserve(n, skb->data - skb->head + headroom);
	/* Set the tail pointer and length */
	if (skb_tailroom(n) < skb->len) {
		printk(KERN_WARNING "klips_error:skb_copy_expand: "
		       "tried to skb_put %ld, %d available.  This should never happen, please report.\n",
		       (unsigned long int)skb->len,
		       skb_tailroom(n));
		ipsec_kfree_skb(n);
		return NULL;
	}
	skb_put(n, skb->len);

	offset = n->head + headroom - skb->head;

	/* Copy the bytes */
	memcpy(n->head + headroom, skb->head, skb->end - skb->head);
	n->csum = skb->csum;
	n->priority = skb->priority;
	skb_dst_set(n, dst_clone(skb_dst(skb)));
	if (skb->nh.raw)
		n->nh.raw = skb->nh.raw + offset;
	atomic_set(&n->users, 1);
	n->destructor = NULL;
#ifdef HAVE_SOCK_SECURITY
	n->security = skb->security;
#endif
	n->protocol = skb->protocol;
	n->list = NULL;
	n->sk = NULL;
	n->dev = skb->dev;
	if (skb->h.raw)
		n->h.raw = skb->h.raw + offset;
	if (skb->mac.raw)
		n->mac.raw = skb->mac.raw + offset;
	memcpy(n->proto_priv, skb->proto_priv, sizeof(skb->proto_priv));
	n->pkt_type = skb->pkt_type;
	n->stamp = skb->stamp;

	return n;
}
#endif /* KLIPS_UNIT_TESTS */

static void ipsec_print_ip4(struct iphdr *ip)
{
	char buf[ADDRTOA_BUF];
	struct tcphdr *tcphdr = NULL;

	if (!ip)
		return;

	/* we are taking some liberties here assuming that the IP and TCP
	 * headers are contiguous in memory */
	switch (ip->protocol) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		/* NOTE: we only use this for getting port numbers, and they
		 * are at the same offsets for both tcp and udp headers
		 */
		tcphdr = (struct tcphdr*)((caddr_t)ip + (ip->ihl << 2));
		break;
	}

	printk(KERN_INFO "klips_debug:   IP:");
	printk(" ihl:%d", ip->ihl << 2);
	printk(" ver:%d", ip->version);
	printk(" tos:%d", ip->tos);
	printk(" tlen:%d", ntohs(ip->tot_len));
	printk(" id:%d", ntohs(ip->id));
	printk(" %s%s%sfrag_off:%d",
	       ip->frag_off & __constant_htons(IP_CE) ? "CE " : "",
	       ip->frag_off & __constant_htons(IP_DF) ? "DF " : "",
	       ip->frag_off & __constant_htons(IP_MF) ? "MF " : "",
	       (ntohs(ip->frag_off) & IP_OFFSET) << 3);
	printk(" ttl:%d", ip->ttl);
	printk(" proto:%d", ip->protocol);
	if (ip->protocol == IPPROTO_UDP)
		printk(" (UDP)");
	if (ip->protocol == IPPROTO_TCP)
		printk(" (TCP)");
	if (ip->protocol == IPPROTO_ICMP)
		printk(" (ICMP)");
	if (ip->protocol == IPPROTO_ESP)
		printk(" (ESP)");
	if (ip->protocol == IPPROTO_AH)
		printk(" (AH)");
	if (ip->protocol == IPPROTO_COMP)
		printk(" (COMP)");
	printk(" chk:%d", ntohs(ip->check));
	addrtoa(*((struct in_addr*)(&ip->saddr)), 0, buf, sizeof(buf));
	printk(" saddr:%s", buf);
	if (tcphdr)
		printk(":%d",
		       ntohs(tcphdr->source));
	addrtoa(*((struct in_addr*)(&ip->daddr)), 0, buf, sizeof(buf));
	printk(" daddr:%s", buf);
	if (tcphdr)
		printk(":%d",
		       ntohs(tcphdr->dest));
	if (ip->protocol == IPPROTO_ICMP) {
		printk(" type:code=%d:%d",
		       ((struct icmphdr*)((caddr_t)ip + (ip->ihl << 2)))->type,
		       ((struct icmphdr*)((caddr_t)ip +
					  (ip->ihl << 2)))->code);
	}
	if (ip->protocol == IPPROTO_TCP) {
		printk(" seq=%u ack=%u", tcphdr->seq, tcphdr->ack_seq);
		if (tcphdr->fin)
			printk(" FIN");
		if (tcphdr->syn)
			printk(" SYN");
		if (tcphdr->rst)
			printk(" RST");
		if (tcphdr->psh)
			printk(" PSH");
		if (tcphdr->ack)
			printk(" ACK");
		if (tcphdr->urg)
			printk(" URG");
		if (tcphdr->ece)
			printk(" ECE");
		if (tcphdr->cwr)
			printk(" CWR");
	}
	printk("\n");

	if (sysctl_ipsec_debug_verbose) {
		__u8 *c;
		int len = ntohs(ip->tot_len) - ip->ihl * 4;

		c = ((__u8*)ip) + ip->ihl * 4;
		ipsec_dmp_block("ip_print", c, len);
	}
}

#ifdef CONFIG_KLIPS_IPV6
static void ipsec_print_ip6(struct ipv6hdr *ip)
{
	char buf[ADDRTOA_BUF];

	printk(KERN_INFO "klips_debug:   IPV6:");
	printk(" prio:%d", ip->priority);
	printk(" ver:%d", ip->version);
	printk(" flow:%02x%02x%02x", ip->flow_lbl[0], ip->flow_lbl[1],
	       ip->flow_lbl[2]);
	printk(" pllen:%d", ntohs(ip->payload_len));
	printk(" hopl:%d", ip->hop_limit);
	printk(" nexthdr:%d", ip->nexthdr);
	if (ip->nexthdr == IPPROTO_UDP)
		printk(" (UDP)");
	if (ip->nexthdr == IPPROTO_TCP)
		printk(" (TCP)");
	if (ip->nexthdr == IPPROTO_ICMP)
		printk(" (ICMP)");
	if (ip->nexthdr == IPPROTO_ICMPV6)
		printk(" (ICMP)");
	if (ip->nexthdr == IPPROTO_ESP)
		printk(" (ESP)");
	if (ip->nexthdr == IPPROTO_AH)
		printk(" (AH)");
	if (ip->nexthdr == IPPROTO_COMP)
		printk(" (COMP)");
	inet_addrtot(AF_INET6, &ip->saddr, 0, buf, sizeof(buf));
	printk(" saddr:%s", buf);
#if 0
	if (ip->protocol == IPPROTO_UDP)
		printk(":%d",
		       ntohs(((struct udphdr*)((caddr_t)ip +
					       (ip->ihl << 2)))->source));
	if (ip->protocol == IPPROTO_TCP)
		printk(":%d",
		       ntohs(((struct tcphdr*)((caddr_t)ip +
					       (ip->ihl << 2)))->source));
#endif
	inet_addrtot(AF_INET6, &ip->daddr, 0, buf, sizeof(buf));
	printk(" daddr:%s", buf);
#if 0
	if (ip->protocol == IPPROTO_UDP)
		printk(":%d",
		       ntohs(((struct udphdr*)((caddr_t)ip +
					       (ip->ihl << 2)))->dest));
	if (ip->protocol == IPPROTO_TCP)
		printk(":%d",
		       ntohs(((struct tcphdr*)((caddr_t)ip +
					       (ip->ihl << 2)))->dest));
	if (ip->protocol == IPPROTO_ICMP)
		printk(" type:code=%d:%d",
		       ((struct icmphdr*)((caddr_t)ip + (ip->ihl << 2)))->type,
		       ((struct icmphdr*)((caddr_t)ip +
					  (ip->ihl << 2)))->code);
#endif
	printk("\n");

	if (sysctl_ipsec_debug_verbose) {
		__u8 *c;
		int len = ntohs(ip->payload_len);

		c = (__u8 *)&ip[1];
		ipsec_dmp_block("ip_print", c, len);
	}
}
#endif /* CONFIG_KLIPS_IPV6 */

void ipsec_print_ip(void *ip)
{
#ifdef CONFIG_KLIPS_IPV6
	if (((struct iphdr *) ip)->version == 6)
		ipsec_print_ip6((struct ipv6hdr *) ip);
	else
#endif
	ipsec_print_ip4((struct iphdr *) ip);
}

#ifdef MSS_HACK_DELETE_ME_PLEASE
/*
 * Issues:
 *  1) Fragments arriving in the tunnel should probably be rejected.
 *  2) How does this affect syncookies, mss_cache, dst cache ?
 *  3) Path MTU discovery handling needs to be reviewed.  For example,
 *     if we receive an ICMP 'packet too big' message from an intermediate
 *     router specifying its next hop MTU, our stack may process this and
 *     adjust the MSS without taking our AH/ESP overheads into account.
 */

/*
 * Recaclulate checksum using differences between changed datum,
 * borrowed from netfilter.
 */
DEBUG_NO_STATIC u_int16_t ipsec_fast_csum(u_int32_t oldvalinv,
					  u_int32_t newval, u_int16_t oldcheck)
{
	u_int32_t diffs[] = { oldvalinv, newval };

	return csum_fold(csum_partial((char *)diffs, sizeof(diffs),
				      oldcheck ^ 0xFFFF));
}

/*
 * Determine effective MSS.
 *
 * Note that we assume that there is always an MSS option for our own
 * SYN segments, which is mentioned in tcp_syn_build_options(), kernel 2.2.x.
 * This could change, and we should probably parse TCP options instead.
 *
 */
DEBUG_NO_STATIC u_int8_t ipsec_adjust_mss(struct sk_buff *skb,
					  struct tcphdr *tcph, u_int16_t mtu)
{
	u_int16_t oldmss, newmss;
	u_int32_t *mssp;
	struct sock *sk = skb->sk;

	newmss = tcp_sync_mss(sk, mtu);
	printk(KERN_INFO "klips: setting mss to %u\n", newmss);
	mssp = (u_int32_t *)tcph + sizeof(struct tcphdr) / sizeof(u_int32_t);
	oldmss = ntohl(*mssp) & 0x0000FFFF;
	*mssp = htonl((TCPOPT_MSS << 24) | (TCPOLEN_MSS << 16) | newmss);
	tcph->check = ipsec_fast_csum(htons(~oldmss),
				      htons(newmss), tcph->check);
	return 1;
}
#endif  /* MSS_HACK_DELETE_ME_PLEASE */

DEBUG_NO_STATIC const char *ipsec_xmit_err(int err)
{
	static char tmp[32];

	switch ((int) err) {
	case IPSEC_XMIT_STOLEN:                 return "IPSEC_XMIT_STOLEN";

	case IPSEC_XMIT_PASS:                   return "IPSEC_XMIT_PASS";

	case IPSEC_XMIT_OK:                             return "IPSEC_XMIT_OK";

	case IPSEC_XMIT_ERRMEMALLOC:    return "IPSEC_XMIT_ERRMEMALLOC";

	case IPSEC_XMIT_ESP_BADALG:             return "IPSEC_XMIT_ESP_BADALG";

	case IPSEC_XMIT_BADPROTO:               return "IPSEC_XMIT_BADPROTO";

	case IPSEC_XMIT_ESP_PUSHPULLERR: return "IPSEC_XMIT_ESP_PUSHPULLERR";

	case IPSEC_XMIT_BADLEN:                 return "IPSEC_XMIT_BADLEN";

	case IPSEC_XMIT_AH_BADALG:              return "IPSEC_XMIT_AH_BADALG";

	case IPSEC_XMIT_SAIDNOTFOUND:   return "IPSEC_XMIT_SAIDNOTFOUND";

	case IPSEC_XMIT_SAIDNOTLIVE:    return "IPSEC_XMIT_SAIDNOTLIVE";

	case IPSEC_XMIT_REPLAYROLLED:   return "IPSEC_XMIT_REPLAYROLLED";

	case IPSEC_XMIT_LIFETIMEFAILED: return "IPSEC_XMIT_LIFETIMEFAILED";

	case IPSEC_XMIT_CANNOTFRAG:             return "IPSEC_XMIT_CANNOTFRAG";

	case IPSEC_XMIT_MSSERR:                 return "IPSEC_XMIT_MSSERR";

	case IPSEC_XMIT_ERRSKBALLOC:    return "IPSEC_XMIT_ERRSKBALLOC";

	case IPSEC_XMIT_ENCAPFAIL:              return "IPSEC_XMIT_ENCAPFAIL";

	case IPSEC_XMIT_NODEV:                  return "IPSEC_XMIT_NODEV";

	case IPSEC_XMIT_NOPRIVDEV:              return "IPSEC_XMIT_NOPRIVDEV";

	case IPSEC_XMIT_NOPHYSDEV:              return "IPSEC_XMIT_NOPHYSDEV";

	case IPSEC_XMIT_NOSKB:                  return "IPSEC_XMIT_NOSKB";

	case IPSEC_XMIT_NOIPV6:                 return "IPSEC_XMIT_NOIPV6";

	case IPSEC_XMIT_NOIPOPTIONS:    return "IPSEC_XMIT_NOIPOPTIONS";

	case IPSEC_XMIT_TTLEXPIRED:             return "IPSEC_XMIT_TTLEXPIRED";

	case IPSEC_XMIT_BADHHLEN:               return "IPSEC_XMIT_BADHHLEN";

	case IPSEC_XMIT_PUSHPULLERR:    return "IPSEC_XMIT_PUSHPULLERR";

	case IPSEC_XMIT_ROUTEERR:               return "IPSEC_XMIT_ROUTEERR";

	case IPSEC_XMIT_RECURSDETECT:   return "IPSEC_XMIT_RECURSDETECT";

	case IPSEC_XMIT_IPSENDFAILURE:  return "IPSEC_XMIT_IPSENDFAILURE";

	case IPSEC_XMIT_ESPUDP:                 return "IPSEC_XMIT_ESPUDP";

	case IPSEC_XMIT_ESPUDP_BADTYPE: return "IPSEC_XMIT_ESPUDP_BADTYPE";

	case IPSEC_XMIT_PENDING:                return "IPSEC_XMIT_PENDING";
	}
	snprintf(tmp, sizeof(tmp), "%d", err);
	return tmp;
}

/*
 * Sanity checks
 */
enum ipsec_xmit_value ipsec_xmit_sanity_check_ipsec_dev(
	struct ipsec_xmit_state *ixs)
{
	if (ixs->dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_error:ipsec_xmit_sanity_check_dev: "
			    "No device associated with skb!\n" );
		return IPSEC_XMIT_NODEV;
	}

	ixs->iprv = netdev_priv(ixs->dev);
	if (ixs->iprv == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_error:ipsec_xmit_sanity_check_dev: "
			    "Device has no private structure!\n" );
		return IPSEC_XMIT_NOPRIVDEV;
	}

	ixs->physdev = ixs->iprv->dev;

	if (ixs->physdev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_error:ipsec_xmit_sanity_check_dev: "
			    "No physical device set\n" );
		return IPSEC_XMIT_NOPHYSDEV;
	}

	if (ixs->mast_mode) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_error:ipsec_xmit_sanity_check_dev: "
			    "Unexpectedly using mast device\n" );
		return IPSEC_XMIT_NOPHYSDEV;
	}

	ixs->physmtu = ixs->physdev->mtu;
	ixs->cur_mtu = ixs->physdev->mtu;
	ixs->stats = (struct net_device_stats *) &(ixs->iprv->mystats);

	return IPSEC_XMIT_OK;
}

/*
 * Sanity checks
 */
enum ipsec_xmit_value ipsec_xmit_sanity_check_mast_dev(
	struct ipsec_xmit_state *ixs)
{
	if (ixs->dev == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_error:ipsec_xmit_sanity_check_dev: "
			    "No device associated with skb!\n" );
		return IPSEC_XMIT_NODEV;
	}

	ixs->mprv = netdev_priv(ixs->dev);
	if (ixs->mprv == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_error:ipsec_xmit_sanity_check_dev: "
			    "Device has no private structure!\n" );
		return IPSEC_XMIT_NOPRIVDEV;
	}

	ixs->physdev = NULL; // not used here

	/*
	 * we should be calculating the MTU by looking up a route
	 * based upon the destination in the SA, and then cache
	 * it into the SA, but we don't do that right now.
	 */
	ixs->cur_mtu = 1460;
	ixs->physmtu = 1460;

	ixs->stats = (struct net_device_stats *) &(ixs->mprv->mystats);

	return IPSEC_XMIT_OK;
}

enum ipsec_xmit_value ipsec_xmit_sanity_check_skb(struct ipsec_xmit_state *ixs)
{
	/*
	 *	Return if there is nothing to do.  (Does this ever happen?) XXX
	 */
	if (ixs->skb == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_error:ipsec_xmit_sanity_check_skb: "
			    "Nothing to do!\n" );
		return IPSEC_XMIT_NOSKB;
	}

	/* if skb was cloned (most likely due to a packet sniffer such as
	   tcpdump being momentarily attached to the interface), make
	   a copy of our own to modify */
	if (skb_cloned(ixs->skb)) {
		if
		(skb_cow(ixs->skb, skb_headroom(ixs->skb)) != 0) {
			KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
				    "klips_error:ipsec_xmit_sanity_check_skb: "
				    "skb_cow failed to allocate buffer, dropping.\n" );
			if (ixs->stats)
				ixs->stats->tx_dropped++;
			return IPSEC_XMIT_ERRSKBALLOC;
		}
	}

	ixs->iph = ip_hdr(ixs->skb);

#ifdef CONFIG_KLIPS_IPV6
	if (lsw_ip_hdr_version(ixs) == 6) {
		if (lsw_ip6_hdr(ixs)->hop_limit <= 0) {
			/* Tell the sender its packet died... */
			ixs->skb->dev = ixs->physdev;
			ICMP6_SEND(ixs->skb, ICMPV6_TIME_EXCEED,
				   ICMPV6_EXC_HOPLIMIT, 0, ixs->physdev);

			KLIPS_PRINT(debug_tunnel, "klips_debug:ipsec_xmit_sanity_check_skb: "
				    "hop_limit=0, too many hops!\n");
			if (ixs->stats)
				ixs->stats->tx_dropped++;
			return IPSEC_XMIT_TTLEXPIRED;
		}
	} else
#endif  /* CONFIG_KLIPS_IPV6 */
	{
#if IPSEC_DISALLOW_IPOPTIONS
		if ((lsw_ip4_hdr(ixs)->ihl << 2) != sizeof(struct iphdr)) {
			KLIPS_PRINT(debug_tunnel,
				    "klips_debug:ipsec_xmit_sanity_check_skb: "
				    "cannot process IP header options yet.  May be mal-formed packet.\n"); /* XXX */
			if (ixs->stats)
				ixs->stats->tx_dropped++;
			return IPSEC_XMIT_NOIPOPTIONS;
		}
#endif          /* IPSEC_DISALLOW_IPOPTIONS */
	}

	return IPSEC_XMIT_OK;
}

enum ipsec_xmit_value ipsec_xmit_encap_init(struct ipsec_xmit_state *ixs)
{
	int new_version = lsw_ip_hdr_version(ixs);

	ixs->blocksize = 8;
	ixs->headroom = 0;
	ixs->tailroom = 0;
	ixs->authlen = 0;

#ifdef CONFIG_KLIPS_ALG
	ixs->ixt_e = NULL;
	ixs->ixt_a = NULL;
#endif  /* CONFIG_KLIPS_ALG */

#ifdef CONFIG_KLIPS_IPV6
	if (lsw_ip_hdr_version(ixs) == 6) {
		IPSEC_FRAG_OFF_DECL(frag_off)
		int nexthdroff;
		unsigned char nexthdr = lsw_ip6_hdr(ixs)->nexthdr;
		nexthdroff = ipsec_ipv6_skip_exthdr(ixs->skb,
			((void *)(lsw_ip6_hdr(ixs) +1)) - (void*)ixs->skb->data,
						    &nexthdr, &frag_off);
		ixs->iphlen = nexthdroff - (ixs->iph - (void*)ixs->skb->data);
		ixs->pyldsz = ntohs(lsw_ip6_hdr(ixs)->payload_len) +
			      sizeof(struct ipv6hdr) - ixs->iphlen;
	} else
#endif  /* CONFIG_KLIPS_IPV6 */
	{
		ixs->iphlen = lsw_ip4_hdr(ixs)->ihl << 2;
		ixs->pyldsz = ntohs(lsw_ip4_hdr(ixs)->tot_len) - ixs->iphlen;
	}
	ixs->sa_len = KLIPS_SATOT(debug_tunnel, &ixs->ipsp->ips_said, 0,
				  ixs->sa_txt, SATOT_BUF);
	KLIPS_PRINT(debug_tunnel & DB_TN_OXFS,
		    "klips_debug:ipsec_xmit_encap_init: "
		    "calling output for <%s%s%s>, SA:%s\n",
		    IPS_XFORM_NAME(ixs->ipsp),
		    ixs->sa_len ? ixs->sa_txt : " (error)");
	switch (ixs->ipsp->ips_said.proto) {
#ifdef CONFIG_KLIPS_AH
	case IPPROTO_AH:
#ifdef CONFIG_KLIPS_ALG
		if ((ixs->ixt_a = ixs->ipsp->ips_alg_auth)) {
			ixs->authlen = AHHMAC_HASHLEN;
		}
#endif          /* CONFIG_KLIPS_ALG */
		ixs->headroom += sizeof(struct ahhdr);
		break;
#endif          /* CONFIG_KLIPS_AH */
#ifdef CONFIG_KLIPS_ESP
	case IPPROTO_ESP:
#ifdef CONFIG_KLIPS_OCF
		/*
		 * this needs cleaning up for sure - DM
		 */
		if (ixs->ipsp->ocf_in_use) {
			switch (ixs->ipsp->ips_encalg) {
			case ESP_DES:
			case ESP_3DES:
				ixs->blocksize = 8;
				ixs->headroom += ESP_HEADER_LEN +
						 8 /* ivsize */;
				break;
			case ESP_AES:
				ixs->blocksize = 16;
				ixs->headroom += ESP_HEADER_LEN +
						 16 /* ivsize */;
				break;
			case ESP_NULL:
				ixs->blocksize = 1;
				ixs->headroom += ESP_HEADER_LEN + 0 /* ivsize */;
				break;
			default:
				if (ixs->stats)
					ixs->stats->tx_errors++;
				return IPSEC_XMIT_ESP_BADALG;
			}
		} else
#endif
#ifdef CONFIG_KLIPS_ALG
		if ((ixs->ixt_e = ixs->ipsp->ips_alg_enc)) {
			ixs->blocksize = ixs->ixt_e->ixt_common.ixt_blocksize;
			ixs->headroom += ESP_HEADER_LEN +
					 ixs->ixt_e->ixt_common.ixt_support.
					 ias_ivlen / 8;
		} else
#endif          /* CONFIG_KLIPS_ALG */
		{
			if (ixs->stats)
				ixs->stats->tx_errors++;
			return IPSEC_XMIT_ESP_BADALG;
		}
#ifdef CONFIG_KLIPS_OCF
		if (ixs->ipsp->ocf_in_use) {
			switch (ixs->ipsp->ips_authalg) {
			case AH_MD5:
			case AH_SHA:
				ixs->authlen = AHHMAC_HASHLEN;
				break;
			case AH_NONE:
				break;
			}
		} else
#endif          /* CONFIG_KLIPS_OCF */
#ifdef CONFIG_KLIPS_ALG

		if ((ixs->ixt_a = ixs->ipsp->ips_alg_auth)) {
			ixs->authlen = ixs->ixt_a->ixt_a_authlen;
		} else
#endif          /* CONFIG_KLIPS_ALG */
		switch (ixs->ipsp->ips_authalg) {
#ifdef CONFIG_KLIPS_AUTH_HMAC_MD5
		case AH_MD5:
			ixs->authlen = AHHMAC_HASHLEN;
			break;
#endif                  /* CONFIG_KLIPS_AUTH_HMAC_MD5 */
#ifdef CONFIG_KLIPS_AUTH_HMAC_SHA1
		case AH_SHA:
			ixs->authlen = AHHMAC_HASHLEN;
			break;
#endif                  /* CONFIG_KLIPS_AUTH_HMAC_SHA1 */
		case AH_NONE:
			break;
		default:
			if (ixs->stats)
				ixs->stats->tx_errors++;
			return IPSEC_XMIT_ESP_BADALG;
		}
		ixs->tailroom += ixs->blocksize != 1 ?
				 ((ixs->blocksize -
				   ((ixs->pyldsz +
				     2) %
				    ixs->blocksize)) % ixs->blocksize) + 2 :
				 ((4 - ((ixs->pyldsz + 2) % 4)) % 4) + 2;
		ixs->tailroom += ixs->authlen;
		break;
#endif          /* !CONFIG_KLIPS_ESP */
#ifdef CONFIG_KLIPS_IPIP
	case IPPROTO_IPIP:
		if (ip_address_family(&ixs->ipsp->ips_said.dst) == AF_INET6) {
			ixs->headroom += sizeof(struct ipv6hdr);
			ixs->iphlen = sizeof(struct ipv6hdr);
			new_version = 6;
		} else {
			ixs->headroom += sizeof(struct iphdr);
			ixs->iphlen = sizeof(struct iphdr);
			new_version = 4;
		}
		break;
#endif          /* !CONFIG_KLIPS_IPIP */
#ifdef CONFIG_KLIPS_IPCOMP
	case IPPROTO_COMP:
		break;
#endif          /* CONFIG_KLIPS_IPCOMP */
	default:
		if (ixs->stats)
			ixs->stats->tx_errors++;
		return IPSEC_XMIT_BADPROTO;
	}

	KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
		    "klips_debug:ipsec_xmit_encap_init: "
		    "pushing %d bytes, putting %d, proto %d.\n",
		    ixs->headroom, ixs->tailroom, ixs->ipsp->ips_said.proto);
	if (skb_headroom(ixs->skb) < ixs->headroom) {
		printk(KERN_WARNING
		       "klips_error:ipsec_xmit_encap_init: "
		       "tried to skb_push headroom=%d, %d available.  This should never happen, please report.\n",
		       ixs->headroom, skb_headroom(ixs->skb));
		if (ixs->stats)
			ixs->stats->tx_errors++;
		return IPSEC_XMIT_ESP_PUSHPULLERR;
	}

	ixs->dat = skb_push(ixs->skb, ixs->headroom);
	ixs->ilen = ixs->skb->len - ixs->tailroom;
	if (skb_tailroom(ixs->skb) < ixs->tailroom) {
		printk(KERN_WARNING
		       "klips_error:ipsec_xmit_encap_init: "
		       "tried to skb_put %d, %d available. Retuning IPSEC_XMIT_ESP_PUSHPULLERR  This should never happen, please report.\n",
		       ixs->tailroom, skb_tailroom(ixs->skb));
		if (ixs->stats)
			ixs->stats->tx_errors++;
		return IPSEC_XMIT_ESP_PUSHPULLERR;
	}
	skb_put(ixs->skb, ixs->tailroom);
	KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
		    "klips_debug:ipsec_xmit_encap_init: "
		    "head,tailroom: %d,%d before xform.\n",
		    skb_headroom(ixs->skb), skb_tailroom(ixs->skb));
	ixs->len = ixs->skb->len;
	if (ixs->len > 0xfff0) {
		printk(KERN_WARNING "klips_error:ipsec_xmit_encap_init: "
		       "tot_len (%d) > 65520.  This should never happen, please report.\n",
		       ixs->len);
		if (ixs->stats)
			ixs->stats->tx_errors++;
		return IPSEC_XMIT_BADLEN;
	}
	/*
	 * only copy the old ip header if it's the same version,  not even sure
	 * we should do it then - DAVIDM
	 */
	if (new_version == lsw_ip_hdr_version(ixs))
		memmove((void *)ixs->dat, (void *)(ixs->dat + ixs->headroom),
			ixs->iphlen);
	else
		memset((void *)ixs->dat, 0, ixs->iphlen);
	ixs->iph = (void *)ixs->dat;

	if (new_version == 6)
		lsw_ip6_hdr(ixs)->payload_len =
			htons(ixs->skb->len - sizeof(struct ipv6hdr));
	else
		lsw_ip4_hdr(ixs)->tot_len = htons(ixs->skb->len);

	return IPSEC_XMIT_OK;
}

/*
 * work out which state to proceed to next
 */

enum ipsec_xmit_value ipsec_xmit_encap_select(struct ipsec_xmit_state *ixs)
{
	switch (ixs->ipsp->ips_said.proto) {
#ifdef CONFIG_KLIPS_ESP
	case IPPROTO_ESP:
		ixs->next_state = IPSEC_XSM_ESP;
		break;
#endif
#ifdef CONFIG_KLIPS_AH
	case IPPROTO_AH:
		ixs->next_state = IPSEC_XSM_AH;
		break;
#endif
#ifdef CONFIG_KLIPS_IPIP
	case IPPROTO_IPIP:
		ixs->next_state = IPSEC_XSM_IPIP;
		break;
#endif
#ifdef CONFIG_KLIPS_IPCOMP
	case IPPROTO_COMP:
		ixs->next_state = IPSEC_XSM_IPCOMP;
		break;
#endif
	default:
		if (ixs->stats)
			ixs->stats->tx_errors++;
		return IPSEC_XMIT_BADPROTO;
	}
	return IPSEC_XMIT_OK;
}

#ifdef CONFIG_KLIPS_ESP

enum ipsec_xmit_value ipsec_xmit_esp(struct ipsec_xmit_state *ixs)
{
	int i;
	unsigned char *pad;
	int padlen = 0;
	unsigned char nexthdr;

	ixs->espp = (struct esphdr *)(ixs->dat + ixs->iphlen);
	skb_set_transport_header(ixs->skb, ipsec_skb_offset(ixs->skb,
							    ixs->espp));
	ixs->espp->esp_spi = ixs->ipsp->ips_said.spi;
	ixs->espp->esp_rpl = htonl(++(ixs->ipsp->ips_replaywin_lastseq));

	ixs->idat = ixs->dat + ixs->iphlen + ixs->headroom;
	ixs->ilen = ixs->len - (ixs->iphlen + ixs->headroom + ixs->authlen);

	/* Self-describing padding */
	pad = &ixs->dat[ixs->len - ixs->tailroom];
	padlen = ixs->tailroom - 2 - ixs->authlen;
	for (i = 0; i < padlen; i++)
		pad[i] = i + 1;
	ixs->dat[ixs->len - ixs->authlen - 2] = padlen;

#ifdef CONFIG_KLIPS_IPV6
	if (lsw_ip_hdr_version(ixs) == 6) {
		IPSEC_FRAG_OFF_DECL(frag_off)
		nexthdr = lsw_ip6_hdr(ixs)->nexthdr;
		i = ipsec_ipv6_skip_exthdr(ixs->skb,
			   ((void *)(lsw_ip6_hdr(ixs) +1)) - (void*)ixs->skb->data,
					   &nexthdr, &frag_off);
	} else
#endif  /* CONFIG_KLIPS_IPV6 */
	{
		nexthdr = lsw_ip4_hdr(ixs)->protocol;
	}
	ixs->dat[ixs->len - ixs->authlen - 1] = nexthdr;
	if (ip_address_family(&ixs->ipsp->ips_said.dst) == AF_INET6)
		lsw_ip6_hdr(ixs)->nexthdr = IPPROTO_ESP;
	else
		lsw_ip4_hdr(ixs)->protocol = IPPROTO_ESP;

#ifdef CONFIG_KLIPS_OCF
	if (ixs->ipsp->ocf_in_use) {
		/* handle the IV code here for now,  near the similar code below */
		prng_bytes(&ipsec_prng,
			   (char *)ixs->espp->esp_iv, ixs->ipsp->ips_iv_size);
		return ipsec_ocf_xmit(ixs);
	}
#endif

#ifdef CONFIG_KLIPS_ALG
	if (!ixs->ixt_e) {
		if (ixs->stats)
			ixs->stats->tx_errors++;
		return IPSEC_XMIT_ESP_BADALG;
	}

	if (debug_tunnel & DB_TN_ENCAP)
		dmp("pre-encrypt", ixs->dat, ixs->len);

	/*
	 * Do all operations here:
	 * copy IV->ESP, encrypt, update ips IV
	 *
	 */
	{
		int ret;
		memcpy(ixs->espp->esp_iv,
		       ixs->ipsp->ips_iv,
		       ixs->ipsp->ips_iv_size);
		ret = ipsec_alg_esp_encrypt(ixs->ipsp,
					    ixs->idat, ixs->ilen,
					    ixs->espp->esp_iv,
					    IPSEC_ALG_ENCRYPT);

		prng_bytes(&ipsec_prng,
			   (char *)ixs->ipsp->ips_iv,
			   ixs->ipsp->ips_iv_size);
	}
	return IPSEC_XMIT_OK;

#else
	return IPSEC_XMIT_ESP_BADALG;

#endif  /*  CONFIG_KLIPS_ALG */
}

enum ipsec_xmit_value ipsec_xmit_esp_ah(struct ipsec_xmit_state *ixs)
{
#if defined(CONFIG_KLIPS_AUTH_HMAC_MD5) || defined(CONFIG_KLIPS_AUTH_HMAC_SHA1)
	__u8 hash[AH_AMAX];
#endif
#if defined(CONFIG_KLIPS_AUTH_HMAC_MD5) || defined(CONFIG_KLIPS_AUTH_HMAC_SHA1)
	union {
#ifdef CONFIG_KLIPS_AUTH_HMAC_MD5
		MD5_CTX md5;
#endif          /* CONFIG_KLIPS_AUTH_HMAC_MD5 */
#ifdef CONFIG_KLIPS_AUTH_HMAC_SHA1
		SHA1_CTX sha1;
#endif  /* CONFIG_KLIPS_AUTH_HMAC_SHA1 */
	} tctx;
#endif  /* defined(CONFIG_KLIPS_AUTH_HMAC_MD5) || defined(CONFIG_KLIPS_AUTH_HMAC_SHA1) */

#ifdef CONFIG_KLIPS_OCF
	if (ixs->ipsp->ocf_in_use) {
		/* we should never be here using OCF */
		if (ixs->stats)
			ixs->stats->tx_errors++;
		return IPSEC_XMIT_AH_BADALG;
	} else
#endif
#ifdef CONFIG_KLIPS_ALG
	if (ixs->ixt_a) {
		ipsec_alg_sa_esp_hash(ixs->ipsp,
				      (caddr_t)ixs->espp,
				      ixs->len - ixs->iphlen - ixs->authlen,
				      &(ixs->dat[ixs->len - ixs->authlen]),
				      ixs->authlen);
	} else
#endif  /* CONFIG_KLIPS_ALG */
	switch (ixs->ipsp->ips_authalg) {
#ifdef CONFIG_KLIPS_AUTH_HMAC_MD5
	case AH_MD5:
		dmp("espp", (char*)ixs->espp,
		    ixs->len - ixs->iphlen - ixs->authlen);
		tctx.md5 = ((struct md5_ctx*)(ixs->ipsp->ips_key_a))->ictx;
		dmp("ictx", (char*)&tctx.md5, sizeof(tctx.md5));
		osMD5Update(&tctx.md5, (caddr_t)ixs->espp,
			    ixs->len - ixs->iphlen - ixs->authlen);
		dmp("ictx+dat", (char*)&tctx.md5, sizeof(tctx.md5));
		osMD5Final(hash, &tctx.md5);
		dmp("ictx hash", (char*)&hash, sizeof(hash));
		tctx.md5 = ((struct md5_ctx*)(ixs->ipsp->ips_key_a))->octx;
		dmp("octx", (char*)&tctx.md5, sizeof(tctx.md5));
		osMD5Update(&tctx.md5, hash, AHMD596_ALEN);
		dmp("octx+hash", (char*)&tctx.md5, sizeof(tctx.md5));
		osMD5Final(hash, &tctx.md5);
		dmp("octx hash", (char*)&hash, sizeof(hash));
		memcpy(&(ixs->dat[ixs->len - ixs->authlen]), hash,
		       ixs->authlen);

		/* paranoid */
		memset((caddr_t)&tctx.md5, 0, sizeof(tctx.md5));
		memset((caddr_t)hash, 0, sizeof(*hash));
		break;
#endif          /* CONFIG_KLIPS_AUTH_HMAC_MD5 */
#ifdef CONFIG_KLIPS_AUTH_HMAC_SHA1
	case AH_SHA:
		tctx.sha1 = ((struct sha1_ctx*)(ixs->ipsp->ips_key_a))->ictx;
		SHA1Update(&tctx.sha1, (caddr_t)ixs->espp,
			   ixs->len - ixs->iphlen - ixs->authlen);
		SHA1Final(hash, &tctx.sha1);
		tctx.sha1 = ((struct sha1_ctx*)(ixs->ipsp->ips_key_a))->octx;
		SHA1Update(&tctx.sha1, hash, AHSHA196_ALEN);
		SHA1Final(hash, &tctx.sha1);
		memcpy(&(ixs->dat[ixs->len - ixs->authlen]), hash,
		       ixs->authlen);

		/* paranoid */
		memset((caddr_t)&tctx.sha1, 0, sizeof(tctx.sha1));
		memset((caddr_t)hash, 0, sizeof(*hash));
		break;
#endif          /* CONFIG_KLIPS_AUTH_HMAC_SHA1 */
	case AH_NONE:
		break;
	default:
		if (ixs->stats)
			ixs->stats->tx_errors++;
		return IPSEC_XMIT_AH_BADALG;
	}
	return IPSEC_XMIT_OK;
}

#endif /* CONFIG_KLIPS_ESP */

#ifdef CONFIG_KLIPS_AH

enum ipsec_xmit_value ipsec_xmit_ah(struct ipsec_xmit_state *ixs)
{
	struct iphdr ipo;
	struct ahhdr *ahp;
#ifdef CONFIG_KLIPS_ALG
	unsigned char *buf;
	int len = 0;
#endif

#if defined(CONFIG_KLIPS_AUTH_HMAC_MD5) || defined(CONFIG_KLIPS_AUTH_HMAC_SHA1)
	__u8 hash[AH_AMAX];
#endif
#if defined(CONFIG_KLIPS_AUTH_HMAC_MD5) || defined(CONFIG_KLIPS_AUTH_HMAC_SHA1)
	union {
#ifdef CONFIG_KLIPS_AUTH_HMAC_MD5
		MD5_CTX md5;
#endif          /* CONFIG_KLIPS_AUTH_HMAC_MD5 */
#ifdef CONFIG_KLIPS_AUTH_HMAC_SHA1
		SHA1_CTX sha1;
#endif  /* CONFIG_KLIPS_AUTH_HMAC_SHA1 */
	} tctx;
#endif  /* defined(CONFIG_KLIPS_AUTH_HMAC_MD5) || defined(CONFIG_KLIPS_AUTH_HMAC_SHA1) */

	if (lsw_ip_hdr_version(ixs) == 6) {
		printk("KLIPS AH doesn't support IPv6 yet\n");
		return IPSEC_XMIT_AH_BADALG;
	}

	ahp = (struct ahhdr *)(ixs->dat + ixs->iphlen);
	skb_set_transport_header(ixs->skb, ipsec_skb_offset(ixs->skb, ahp));
	ahp->ah_spi = ixs->ipsp->ips_said.spi;
	ahp->ah_rpl = htonl(++(ixs->ipsp->ips_replaywin_lastseq));
	ahp->ah_rv = 0;
	ahp->ah_nh = lsw_ip4_hdr(ixs)->protocol;
	ahp->ah_hl = (ixs->headroom >> 2) - sizeof(__u64) / sizeof(__u32);
	lsw_ip4_hdr(ixs)->protocol = IPPROTO_AH;
	dmp("ahp", (char*)ahp, sizeof(*ahp));

#ifdef CONFIG_KLIPS_OCF
	if (ixs->ipsp->ocf_in_use)
		return ipsec_ocf_xmit(ixs);

#endif

	ipo = *lsw_ip4_hdr(ixs);
	ipo.tos = 0;
	ipo.frag_off = 0;
	ipo.ttl = 0;
	ipo.check = 0;
	dmp("ipo", (char*)&ipo, sizeof(ipo));

#ifdef CONFIG_KLIPS_ALG
	if (ixs->ixt_a) {
		if (ixs->ipsp->ips_authalg != AH_SHA && ixs->ipsp->ips_authalg != AH_MD5) {
			printk("KLIPS AH doesn't support authalg=%d yet\n",ixs->ipsp->ips_authalg);
			return IPSEC_XMIT_AH_BADALG;
		}

		if ((buf = kmalloc(sizeof(struct iphdr)+ixs->skb->len, GFP_KERNEL)) == NULL)
			return IPSEC_XMIT_ERRMEMALLOC;

		memcpy(buf, (unsigned char *)&ipo,sizeof(struct iphdr));
		len = sizeof(struct iphdr);
		memcpy(buf+len, (unsigned char*)ahp,ixs->headroom - sizeof(ahp->ah_data));
		len+=(ixs->headroom - sizeof(ahp->ah_data));
		memcpy(buf+len, (unsigned char *)zeroes, AHHMAC_HASHLEN);
		len+=AHHMAC_HASHLEN;
		memcpy(buf+len,  ixs->dat + ixs->iphlen + ixs->headroom, ixs->len - ixs->iphlen - ixs->headroom);
		len+=(ixs->len - ixs->iphlen - ixs->headroom);

		ipsec_alg_sa_ah_hash(ixs->ipsp,
				     (caddr_t)buf,
				     len,
				     ahp->ah_data,
				     AHHMAC_HASHLEN);

		if (buf)
			kfree(buf);
	} else
#endif  /* CONFIG_KLIPS_ALG */
	switch (ixs->ipsp->ips_authalg) {
#ifdef CONFIG_KLIPS_AUTH_HMAC_MD5
	case AH_MD5:
		tctx.md5 = ((struct md5_ctx*)(ixs->ipsp->ips_key_a))->ictx;
		dmp("ictx", (char*)&tctx.md5, sizeof(tctx.md5));
		osMD5Update(&tctx.md5, (unsigned char *)&ipo,
			    sizeof(struct iphdr));
		dmp("ictx+ipo", (char*)&tctx.md5, sizeof(tctx.md5));
		osMD5Update(&tctx.md5, (unsigned char *)ahp,
			    ixs->headroom - sizeof(ahp->ah_data));
		dmp("ictx+ahp", (char*)&tctx.md5, sizeof(tctx.md5));
		osMD5Update(&tctx.md5, (unsigned char *)zeroes,
			    AHHMAC_HASHLEN);
		dmp("ictx+zeroes", (char*)&tctx.md5, sizeof(tctx.md5));
		osMD5Update(&tctx.md5,  ixs->dat + ixs->iphlen + ixs->headroom,
			    ixs->len - ixs->iphlen - ixs->headroom);
		dmp("ictx+dat", (char*)&tctx.md5, sizeof(tctx.md5));
		osMD5Final(hash, &tctx.md5);
		dmp("ictx hash", (char*)&hash, sizeof(hash));
		tctx.md5 = ((struct md5_ctx*)(ixs->ipsp->ips_key_a))->octx;
		dmp("octx", (char*)&tctx.md5, sizeof(tctx.md5));
		osMD5Update(&tctx.md5, hash, AHMD596_ALEN);
		dmp("octx+hash", (char*)&tctx.md5, sizeof(tctx.md5));
		osMD5Final(hash, &tctx.md5);
		dmp("octx hash", (char*)&hash, sizeof(hash));

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
			   ixs->headroom - sizeof(ahp->ah_data));
		SHA1Update(&tctx.sha1, (unsigned char *)zeroes,
			   AHHMAC_HASHLEN);
		SHA1Update(&tctx.sha1,  ixs->dat + ixs->iphlen + ixs->headroom,
			   ixs->len - ixs->iphlen - ixs->headroom);
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
		if (ixs->stats)
			ixs->stats->tx_errors++;
		return IPSEC_XMIT_AH_BADALG;
	}
	return IPSEC_XMIT_OK;
}

#endif /* CONFIG_KLIPS_AH */

#ifdef CONFIG_KLIPS_IPIP

enum ipsec_xmit_value ipsec_xmit_ipip(struct ipsec_xmit_state *ixs)
{
	int error;

#ifdef CONFIG_KLIPS_IPV6
	if (ip_address_family(&ixs->ipsp->ips_said.dst) == AF_INET6) {
		ixs->skb->ip_summed = CHECKSUM_NONE;
		lsw_ip6_hdr(ixs)->version  = 6;
		/* DAVIDM TOS / DSFIELD stuff in following line */
		lsw_ip6_hdr(ixs)->priority = 0;
		/* what to do with flow_lbl? */
		lsw_ip6_hdr(ixs)->flow_lbl[0] = 0;
		lsw_ip6_hdr(ixs)->flow_lbl[1] = 0;
		lsw_ip6_hdr(ixs)->flow_lbl[2] = 0;
		lsw_ip6_hdr(ixs)->hop_limit = SYSCTL_IPSEC_DEFAULT_TTL;
		lsw_ip6_hdr(ixs)->saddr    =
			((struct sockaddr_in6*)(ixs->ipsp->ips_addr_s))->
			sin6_addr;
		lsw_ip6_hdr(ixs)->daddr    =
			((struct sockaddr_in6*)(ixs->ipsp->ips_addr_d))->
			sin6_addr;
		lsw_ip6_hdr(ixs)->nexthdr  = ixs->ipip_proto;
		error = ipsec_set_dst(ixs);
		if (error != IPSEC_XMIT_OK)
			return error;

		/* DAVIDM No identification/fragment code here yet */
		skb_set_transport_header(ixs->skb,
					 ipsec_skb_offset(ixs->skb, ixs->iph));
	} else
#endif  /* CONFIG_KLIPS_IPV6 */
	{
		lsw_ip4_hdr(ixs)->version  = 4;
		switch (sysctl_ipsec_tos) {
		case 0:
			lsw_ip4_hdr(ixs)->tos = ip_hdr(ixs->skb)->tos;
			break;
		case 1:
			lsw_ip4_hdr(ixs)->tos = 0;
			break;
		default:
			break;
		}
		lsw_ip4_hdr(ixs)->ttl      = SYSCTL_IPSEC_DEFAULT_TTL;
		lsw_ip4_hdr(ixs)->frag_off = 0;
		lsw_ip4_hdr(ixs)->saddr    =
			((struct sockaddr_in*)(ixs->ipsp->ips_addr_s))->
			sin_addr.s_addr;
		lsw_ip4_hdr(ixs)->daddr    =
			((struct sockaddr_in*)(ixs->ipsp->ips_addr_d))->
			sin_addr.s_addr;
		lsw_ip4_hdr(ixs)->protocol = ixs->ipip_proto;
		lsw_ip4_hdr(ixs)->ihl      = sizeof(struct iphdr) >> 2;
		/* newer kernels require skb->dst to be set in KLIPS_IP_SELECT_IDENT */
		/* we need to do this before any HASH generation is done */
		error = ipsec_set_dst(ixs);
		if (error != IPSEC_XMIT_OK)
			return error;

		KLIPS_IP_SELECT_IDENT(lsw_ip4_hdr(ixs), ixs->skb);
		skb_set_transport_header(ixs->skb,
					 ipsec_skb_offset(ixs->skb, ixs->iph));
	}

	return IPSEC_XMIT_OK;
}

#endif /* CONFIG_KLIPS_IPIP */

#ifdef CONFIG_KLIPS_IPCOMP

enum ipsec_xmit_value ipsec_xmit_ipcomp(struct ipsec_xmit_state *ixs)
{
	unsigned int old_tot_len, tot_len;
	int flags = 0;

#ifdef CONFIG_KLIPS_OCF
	if (ixs->ipsp->ocf_in_use)
		return ipsec_ocf_xmit(ixs);

#endif

#ifdef CONFIG_KLIPS_IPV6
	if (lsw_ip_hdr_version(ixs) == 6)
		old_tot_len = ntohs(lsw_ip6_hdr(ixs)->payload_len) +
			      sizeof(struct ipv6hdr);
	else
#endif
	old_tot_len = ntohs(lsw_ip4_hdr(ixs)->tot_len);
	ixs->ipsp->ips_comp_ratio_dbytes += old_tot_len;

	ixs->skb = skb_compress(ixs->skb, ixs->ipsp, &flags);

	ixs->iph = ip_hdr(ixs->skb);

#ifdef CONFIG_KLIPS_IPV6
	if (lsw_ip_hdr_version(ixs) == 6) {
		IPSEC_FRAG_OFF_DECL(frag_off)
		int nexthdroff;
		unsigned char nexthdr = lsw_ip6_hdr(ixs)->nexthdr;
		nexthdroff = ipsec_ipv6_skip_exthdr(ixs->skb,
			    ((void *)(lsw_ip6_hdr(ixs) +1)) - (void*)ixs->skb->data,
						    &nexthdr, &frag_off);
		tot_len = ntohs(lsw_ip6_hdr(ixs)->payload_len) +
			  sizeof(struct ipv6hdr);
	} else
#endif
	tot_len = ntohs(lsw_ip4_hdr(ixs)->tot_len);
	ixs->ipsp->ips_comp_ratio_cbytes += tot_len;

	if (debug_tunnel & DB_TN_CROUT) {
		if (old_tot_len > tot_len)
			KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
				    "klips_debug:ipsec_xmit_ipcomp: "
				    "packet shrunk from %d to %d bytes after compression, cpi=%04x (should be from spi=%08x, spi&0xffff=%04x.\n",
				    old_tot_len, tot_len,
				    ntohs(((struct ipcomphdr*)(((char*)
								lsw_ip4_hdr(ixs))
							       +
							       ((lsw_ip4_hdr(
									 ixs)->
								 ihl) <<
								2)))->
					  ipcomp_cpi),
				    ntohl(ixs->ipsp->ips_said.spi),
				    (__u16)(ntohl(ixs->ipsp->ips_said.spi) &
					    0x0000ffff));
		else
			KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
				    "klips_debug:ipsec_xmit_ipcomp: "
				    "packet did not compress (flags = %d).\n",
				    flags);
	}
	return IPSEC_XMIT_OK;
}

#endif /* CONFIG_KLIPS_IPCOMP */

/*
 * upon entry to this function, ixs->skb should be setup
 * as follows:
 *
 *   data   = beginning of IP packet   <- differs from ipsec_rcv().
 *   nh.raw = beginning of IP packet.
 *   h.raw  = data after the IP packet.
 *
 */
enum ipsec_xmit_value ipsec_xmit_cont(struct ipsec_xmit_state *ixs)
{
	__u8 padlen;
	skb_set_network_header(ixs->skb,
			       ipsec_skb_offset(ixs->skb, ixs->skb->data));

	/*
	 * if we have more work to do,  it's likely this checksum is getting
	 * encapsulated,  and we must do it.  Otherwise,  we do a final one
	 * just before the ip_send/nf hook in ipsec_xmit_send.
	 */
	if (ixs->ipsp->ips_next && lsw_ip_hdr_version(ixs) == 4) {
		lsw_ip4_hdr(ixs)->check = 0;
		lsw_ip4_hdr(ixs)->check = ip_fast_csum(
			(unsigned char *)ixs->iph, lsw_ip4_hdr(ixs)->ihl);
	}

	KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
		    "klips_debug:ipsec_xmit_cont: "
		    "after <%s%s%s>, SA:%s:\n",
		    IPS_XFORM_NAME(ixs->ipsp),
		    ixs->sa_len ? ixs->sa_txt : " (error)");
	KLIPS_IP_PRINT(debug_tunnel & DB_TN_XMIT, ixs->iph);

	padlen = ixs->tailroom - ixs->authlen;
	ixs->ipsp->ips_life.ipl_bytes.ipl_count += ixs->ilen - padlen;
	ixs->ipsp->ips_life.ipl_bytes.ipl_last = ixs->ilen - padlen;

	if (!ixs->ipsp->ips_life.ipl_usetime.ipl_count)
		ixs->ipsp->ips_life.ipl_usetime.ipl_count = jiffies / HZ;
	ixs->ipsp->ips_life.ipl_usetime.ipl_last = jiffies / HZ;
	ixs->ipsp->ips_life.ipl_packets.ipl_count++;

	/* we are done with this SA */
	ipsec_sa_put(ixs->ipsp, IPSEC_REFTX);

	/* move to the next SA */
	ixs->ipsp = ixs->ipsp->ips_next;
	if (ixs->ipsp)
		ipsec_sa_get(ixs->ipsp, IPSEC_REFTX);

	/*
	 * start again if we have more work to do
	 */
	if (ixs->ipsp)
		ixs->next_state = IPSEC_XSM_ENCAP_INIT;

	return IPSEC_XMIT_OK;
}

/*
 * If the IP packet (iph) is a carrying TCP/UDP, then set the encaps
 * source and destination ports to those from the TCP/UDP header.
 */

void ipsec_extract_ports(struct sk_buff *skb, unsigned char nexthdr,
			 int nexthdroff, struct sockaddr_encap * er)
{
	struct udphdr _udp, *udp;

	switch (nexthdr) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		/*
		 * The ports are at the same offsets in a TCP and UDP
		 * header so hack it ...
		 */
		udp = skb_header_pointer(skb, nexthdroff, sizeof(*udp), &_udp);
		if (udp) {
			if (SENT_IP4 == er->sen_type) {
				er->sen_sport = udp->source;
				er->sen_dport = udp->dest;
			} else if (SENT_IP6 == er->sen_type) {
				er->sen_sport6 = udp->source;
				er->sen_dport6 = udp->dest;
			}
			break;
		}
	/* FALL THROUGH */
	default:
		if (SENT_IP4 == er->sen_type) {
			er->sen_sport = 0;
			er->sen_dport = 0;
		} else if (SENT_IP6 == er->sen_type) {
			er->sen_sport6 = 0;
			er->sen_dport6 = 0;
		}
		break;
	}
}

/*
 * A TRAP eroute is installed and we want to replace it with a HOLD
 * eroute.
 *
 * NOTE iph == skb->iph
 */
static int create_hold_eroute(struct ipsec_xmit_state *ixs)
{
	struct eroute hold_eroute;
	ip_said hold_said;
	struct sk_buff *first, *last;
	int error;

	first = last = NULL;
	memset((caddr_t)&hold_eroute, 0, sizeof(hold_eroute));
	memset((caddr_t)&hold_said, 0, sizeof(hold_said));

	hold_said.proto = IPPROTO_INT;
	hold_said.spi = htonl(SPI_HOLD);

#ifdef CONFIG_KLIPS_IPV6
	if (lsw_ip_hdr_version(ixs) == 6) {
		struct in6_addr addr6_any = IN6ADDR_ANY_INIT;
		hold_said.dst.u.v6.sin6_addr = addr6_any;
		SET_V6(hold_said.dst);
	} else
#endif
	{
		hold_said.dst.u.v4.sin_addr.s_addr = INADDR_ANY;
		SET_V4(hold_said.dst);
	}

	hold_eroute.er_eaddr.sen_len = sizeof(struct sockaddr_encap);
	hold_eroute.er_emask.sen_len = sizeof(struct sockaddr_encap);
	hold_eroute.er_eaddr.sen_family = AF_ENCAP;
	hold_eroute.er_emask.sen_family = AF_ENCAP;
	hold_eroute.er_eaddr.sen_type =
		(lsw_ip_hdr_version(ixs) == 6) ? SENT_IP6 : SENT_IP4;
	hold_eroute.er_emask.sen_type = 255;

#ifdef CONFIG_KLIPS_IPV6
	if (lsw_ip_hdr_version(ixs) == 6) {
		const struct in6_addr in6addr_linklocal_allnodes =
			IN6ADDR_LINKLOCAL_ALLNODES_INIT;
		hold_eroute.er_eaddr.sen_ip6_src = lsw_ip6_hdr(ixs)->saddr;
		hold_eroute.er_eaddr.sen_ip6_dst = lsw_ip6_hdr(ixs)->daddr;
		hold_eroute.er_emask.sen_ip6_src = in6addr_linklocal_allnodes;
		hold_eroute.er_emask.sen_ip6_dst = in6addr_linklocal_allnodes;
	} else
#endif  /* CONFIG_KLIPS_IPV6 */
	{
		hold_eroute.er_eaddr.sen_ip_src.s_addr =
			lsw_ip4_hdr(ixs)->saddr;
		hold_eroute.er_eaddr.sen_ip_dst.s_addr =
			lsw_ip4_hdr(ixs)->daddr;
		hold_eroute.er_emask.sen_ip_src.s_addr = INADDR_BROADCAST;
		hold_eroute.er_emask.sen_ip_dst.s_addr = INADDR_BROADCAST;
	}
	hold_eroute.er_emask.sen_sport = 0;
	hold_eroute.er_emask.sen_dport = 0;
	hold_eroute.er_pid = ixs->eroute_pid;
	hold_eroute.er_count = 0;
	hold_eroute.er_lasttime = jiffies / HZ;

	/*
	 * if it wasn't captured by a wildcard, then don't record it as
	 * a wildcard.
	 */
	if (ixs->eroute->er_eaddr.sen_proto != 0) {
		unsigned char nexthdr;
		int nexthdroff;

#ifdef CONFIG_KLIPS_IPV6
		if (lsw_ip_hdr_version(ixs) == 6) {
			IPSEC_FRAG_OFF_DECL(frag_off)
			nexthdr = lsw_ip6_hdr(ixs)->nexthdr;
			nexthdroff = ipsec_ipv6_skip_exthdr(ixs->skb,
							    ((void *)(
								     lsw_ip6_hdr(
									     ixs)
								     +
								     1)) -
							    (void*)ixs->skb->data,
							    &nexthdr,
							    &frag_off);

			hold_eroute.er_eaddr.sen_proto6 = nexthdr;
		} else
#endif          /* CONFIG_KLIPS_IPV6 */
		{
			nexthdr = lsw_ip4_hdr(ixs)->protocol;
			nexthdroff = 0;
			if ((ntohs(lsw_ip4_hdr(ixs)->frag_off) & IP_OFFSET) ==
			    0) {
				nexthdroff =
					(ixs->iph +
					 (lsw_ip4_hdr(ixs)->ihl << 2)) -
					(void *)ixs->skb->data;
			}

			hold_eroute.er_eaddr.sen_proto = nexthdr;
		}

		if (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP) {
			if (ixs->eroute->er_eaddr.sen_type == SENT_IP4 &&
			    (ixs->eroute->er_eaddr.sen_sport != 0 ||
			     ixs->eroute->er_eaddr.sen_dport != 0)) {

				if (ixs->eroute->er_eaddr.sen_sport != 0)
					hold_eroute.er_emask.sen_sport = ~0;

				if (ixs->eroute->er_eaddr.sen_dport != 0)
					hold_eroute.er_emask.sen_dport = ~0;

				ipsec_extract_ports(ixs->skb, nexthdr,
						    nexthdroff,
						    &hold_eroute.er_eaddr);
			} else if (ixs->eroute->er_eaddr.sen_type ==
				   SENT_IP6 &&
				   (ixs->eroute->er_eaddr.sen_sport6 != 0 ||
				    ixs->eroute->er_eaddr.sen_dport6 != 0)) {

				if (ixs->eroute->er_eaddr.sen_sport6 != 0)
					hold_eroute.er_emask.sen_sport6 = ~0;

				if (ixs->eroute->er_eaddr.sen_dport6 != 0)
					hold_eroute.er_emask.sen_dport6 = ~0;

				ipsec_extract_ports(ixs->skb, nexthdr,
						    nexthdroff,
						    &hold_eroute.er_eaddr);
			}
		}
	}

	if (debug_pfkey) {
		char buf1[64], buf2[64];
		if (lsw_ip_hdr_version(ixs) == 6) {
			subnet6toa(&hold_eroute.er_eaddr.sen_ip6_src,
				   &hold_eroute.er_emask.sen_ip6_src, 0, buf1,
				   sizeof(buf1));
			subnet6toa(&hold_eroute.er_eaddr.sen_ip6_dst,
				   &hold_eroute.er_emask.sen_ip6_dst, 0, buf2,
				   sizeof(buf2));
		} else {
			subnettoa(hold_eroute.er_eaddr.sen_ip_src,
				  hold_eroute.er_emask.sen_ip_src, 0, buf1,
				  sizeof(buf1));
			subnettoa(hold_eroute.er_eaddr.sen_ip_dst,
				  hold_eroute.er_emask.sen_ip_dst, 0, buf2,
				  sizeof(buf2));
		}
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:ipsec_tunnel_start_xmit: "
			    "calling breakeroute and makeroute for %s:%d->%s:%d %d HOLD eroute.\n",
			    buf1, ntohs(hold_eroute.er_eaddr.sen_sport),
			    buf2, ntohs(hold_eroute.er_eaddr.sen_dport),
			    hold_eroute.er_eaddr.sen_proto);
	}

	if (ipsec_breakroute(&(hold_eroute.er_eaddr), &(hold_eroute.er_emask),
			     &first, &last)) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:ipsec_tunnel_start_xmit: "
			    "HOLD breakeroute found nothing.\n");
	} else if (hold_eroute.er_eaddr.sen_type == SENT_IP6 && debug_pfkey) {
		char buf1[64], buf2[64];

		subnet6toa(&hold_eroute.er_eaddr.sen_ip6_src,
			   &hold_eroute.er_emask.sen_ip6_src, 0, buf1,
			   sizeof(buf1));
		subnet6toa(&hold_eroute.er_eaddr.sen_ip6_dst,
			   &hold_eroute.er_emask.sen_ip6_dst, 0, buf2,
			   sizeof(buf2));
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:ipsec_tunnel_start_xmit: "
			    "HOLD breakroute deleted [%s]:%u -> [%s]:%u %u\n",
			    buf1, ntohs(hold_eroute.er_eaddr.sen_sport6),
			    buf1, ntohs(hold_eroute.er_eaddr.sen_dport6),
			    hold_eroute.er_eaddr.sen_proto6);
	} else {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:ipsec_tunnel_start_xmit: "
			    "HOLD breakroute deleted %pI4:%u -> %pI4:%u %u\n",
			    &hold_eroute.er_eaddr.sen_ip_src,
			    ntohs(hold_eroute.er_eaddr.sen_sport),
			    &hold_eroute.er_eaddr.sen_ip_dst,
			    ntohs(hold_eroute.er_eaddr.sen_dport),
			    hold_eroute.er_eaddr.sen_proto);
	}
	if (first != NULL)
		ipsec_kfree_skb(first);
	if (last != NULL)
		ipsec_kfree_skb(last);

	error = ipsec_makeroute(&(hold_eroute.er_eaddr),
				&(hold_eroute.er_emask),
				hold_said, ixs->eroute_pid, ixs->skb, NULL,
				NULL);
	if (error) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:ipsec_tunnel_start_xmit: "
			    "HOLD makeroute returned %d, failed.\n", error);
	} else {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:ipsec_tunnel_start_xmit: "
			    "HOLD makeroute call successful.\n");
	}
	return error == 0;
}

/*
 * upon entry to this function, ixs->skb should be setup
 * as follows:
 *
 *   data   = beginning of IP packet   <- differs from ipsec_rcv().
 *   nh.raw = beginning of IP packet.
 *   h.raw  = data after the IP packet.
 *
 */
enum ipsec_xmit_value ipsec_xmit_init1(struct ipsec_xmit_state *ixs)
{
	ixs->orgedst = ixs->outgoing_said.dst;
	ixs->max_headroom = ixs->max_tailroom = 0;
#ifdef CONFIG_KLIPS_IPV6
	if (lsw_ip_hdr_version(ixs) == 6) {
		IPSEC_FRAG_OFF_DECL(frag_off)
		int nexthdroff;
		unsigned char nexthdr = lsw_ip6_hdr(ixs)->nexthdr;
		nexthdroff = ipsec_ipv6_skip_exthdr(ixs->skb,
						    ((void *)(lsw_ip6_hdr(
								      ixs) +
							      1)) - (void*)ixs->skb->data,
						    &nexthdr, &frag_off);
		ixs->iphlen = nexthdroff - (ixs->iph - (void*)ixs->skb->data);
		ixs->pyldsz = ntohs(lsw_ip6_hdr(ixs)->payload_len);
	} else
#endif  /* CONFIG_KLIPS_IPV6 */
	{
		ixs->iphlen = lsw_ip4_hdr(ixs)->ihl << 2;
		ixs->pyldsz = ntohs(lsw_ip4_hdr(ixs)->tot_len) - ixs->iphlen;
	}

	if (ixs->outgoing_said.proto == IPPROTO_INT) {
		switch (ntohl(ixs->outgoing_said.spi)) {
		case SPI_DROP:
			KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
				    "klips_debug:ipsec_xmit_encap_bundle: "
				    "shunt SA of DROP or no eroute: dropping.\n");
			if (ixs->stats)
				ixs->stats->tx_dropped++;
			break;

		case SPI_REJECT:
			KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
				    "klips_debug:ipsec_xmit_encap_bundle: "
				    "shunt SA of REJECT: notifying and dropping.\n");
#ifdef CONFIG_KLIPS_IPV6
			if (lsw_ip_hdr_version(ixs) == 6)
				ICMP6_SEND(ixs->skb,
					   ICMP_DEST_UNREACH,
					   ICMP_PKT_FILTERED,
					   0,
					   ixs->physdev);
			else
#endif
			ICMP_SEND(ixs->skb,
				  ICMP_DEST_UNREACH,
				  ICMP_PKT_FILTERED,
				  0,
				  ixs->physdev);
			if (ixs->stats)
				ixs->stats->tx_dropped++;
			break;

		case SPI_PASS:
			ixs->pass = 1;
			KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
				    "klips_debug:ipsec_xmit_encap_bundle: "
				    "PASS: calling dev_queue_xmit\n");
			return IPSEC_XMIT_PASS;

		case SPI_HOLD:
			KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
				    "klips_debug:ipsec_xmit_encap_bundle: "
				    "shunt SA of HOLD: this does not make sense here, dropping.\n");
			if (ixs->stats)
				ixs->stats->tx_dropped++;
			break;

		case SPI_TRAP:
		case SPI_TRAPSUBNET:
#ifdef CONFIG_KLIPS_IPV6
			if (lsw_ip_hdr_version(ixs) == 6) {
				struct sockaddr_in6 src, dst;
				char bufsrc[ADDRTOA_BUF], bufdst[ADDRTOA_BUF];
				unsigned char nexthdr;
				int nexthdroff;
				IPSEC_FRAG_OFF_DECL(frag_off)

				/* Signal all listening KMds with a PF_KEY ACQUIRE */

				memset(&src, 0, sizeof(src));
				memset(&dst, 0, sizeof(dst));
				src.sin6_family = AF_INET6;
				dst.sin6_family = AF_INET6;
#ifdef NEED_SIN_LEN
				src.sin6_len = sizeof(struct sockaddr_in6);
				dst.sin6_len = sizeof(struct sockaddr_in6);
#endif
				src.sin6_addr = lsw_ip6_hdr(ixs)->saddr;
				dst.sin6_addr = lsw_ip6_hdr(ixs)->daddr;

				ixs->ips.ips_transport_protocol = 0;
				src.sin6_port = 0;
				dst.sin6_port = 0;

				nexthdr = lsw_ip6_hdr(ixs)->nexthdr;
				nexthdroff = ipsec_ipv6_skip_exthdr(ixs->skb,
								    ((void *)(
									     lsw_ip6_hdr(
										     ixs)
									     +
									     1)) -
								    (void*)ixs->skb->data,
								    &nexthdr,
								    &frag_off);
				if (nexthdroff == 0) {
					printk("KLIPS: broken ipv6 header\n");
					nexthdr = -1;
				}

				if (ixs->eroute->er_eaddr.sen_type != SENT_IP6)
					printk("KLIPS: IPv6 on non IPv6 eroute\n");


				if (ixs->eroute->er_eaddr.sen_proto != 0) {
					struct udphdr _udphdr, *udphdr = NULL;
					struct tcphdr _tcphdr, *tcphdr = NULL;

					ixs->ips.ips_transport_protocol =
						nexthdr;

					if (nexthdroff) {
						if (nexthdr == IPPROTO_UDP)
							udphdr =
								skb_header_pointer(
									ixs->skb,
									nexthdroff,
									sizeof(*udphdr),
									&_udphdr);


						else if (nexthdr ==
							 IPPROTO_TCP)
							tcphdr =
								skb_header_pointer(
									ixs->skb,
									nexthdroff,
									sizeof(*tcphdr),
									&_tcphdr);


					}

					if (ixs->eroute->er_eaddr.sen_sport6 !=
					    0) {
						src.sin6_port =
							(udphdr ? udphdr->
							 source : (tcphdr ?
								   tcphdr->
								   source : 0));
					}
					if (ixs->eroute->er_eaddr.sen_dport6 !=
					    0) {
						dst.sin6_port =
							(udphdr ? udphdr->dest
							 :
							 (tcphdr ? tcphdr->
							  dest : 0));
					}
				}

				ixs->ips.ips_addr_s = (struct sockaddr*)(&src);
				ixs->ips.ips_addr_d = (struct sockaddr*)(&dst);
				KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
					    "klips_debug:ipsec_xmit_encap_bundle: "
					    "SADB_ACQUIRE sent with src=%s:%d, dst=%s:%d, proto=%d.\n",
					    sin_addrtot(ixs->ips.ips_addr_s, 0,
							bufsrc,
							sizeof(bufsrc)) <= ADDRTOA_BUF ? bufsrc : "BAD_ADDR",
					    ntohs(((struct sockaddr_in6*)(ixs->
									  ips.
									  ips_addr_s))
						  ->sin6_port),
					    sin_addrtot(ixs->ips.ips_addr_d, 0,
							bufdst,
							sizeof(bufdst)) <= ADDRTOA_BUF ? bufdst : "BAD_ADDR",
					    ntohs(((struct sockaddr_in6*)(ixs->
									  ips.
									  ips_addr_d))
						  ->sin6_port),
					    ixs->ips.ips_said.proto);

				/* increment count of total traps needed */
				ipsec_xmit_trap_count++;

				if (pfkey_acquire(&ixs->ips) == 0) {
					/* note that we succeeded */
					ipsec_xmit_trap_sendcount++;

					if (ixs->outgoing_said.spi ==
					    htonl(SPI_TRAPSUBNET)) {
						/*
						 * The spinlock is to prevent any other
						 * process from accessing or deleting
						 * the eroute while we are using and
						 * updating it.
						 */
						spin_lock_bh(&eroute_lock);
						ixs->eroute = ipsec_findroute(
							&ixs->matcher);
						if (ixs->eroute) {
							ixs->eroute->er_said.
							spi = htonl(SPI_HOLD);
							ixs->eroute->er_first =
								ixs->skb;
							ixs->skb = NULL;
						}
						spin_unlock_bh(&eroute_lock);
					} else if (create_hold_eroute(ixs)) {
						ixs->skb = NULL;
					}
					/* whether or not the above succeeded, we continue */

				}
				if (ixs->stats)
					ixs->stats->tx_dropped++;
			} else
#endif                  /* CONFIG_KLIPS_IPV6 */
			{
				struct sockaddr_in src, dst;
				char bufsrc[ADDRTOA_BUF], bufdst[ADDRTOA_BUF];

				/* Signal all listening KMds with a PF_KEY ACQUIRE */

				memset(&src, 0, sizeof(src));
				memset(&dst, 0, sizeof(dst));
				src.sin_family = AF_INET;
				dst.sin_family = AF_INET;
#ifdef NEED_SIN_LEN
				src.sin_len = sizeof(struct sockaddr_in);
				dst.sin_len = sizeof(struct sockaddr_in);
#endif
				src.sin_addr.s_addr = lsw_ip4_hdr(ixs)->saddr;
				dst.sin_addr.s_addr = lsw_ip4_hdr(ixs)->daddr;

				ixs->ips.ips_transport_protocol = 0;
				src.sin_port = 0;
				dst.sin_port = 0;

				if (ixs->eroute->er_eaddr.sen_proto != 0) {
					ixs->ips.ips_transport_protocol =
						lsw_ip4_hdr(ixs)->protocol;

					if (ixs->eroute->er_eaddr.sen_sport !=
					    0) {
						src.sin_port =
							lsw_ip4_hdr(ixs)->protocol == IPPROTO_UDP ?
							 ((struct udphdr*) (((caddr_t)ixs->iph) +
									    (lsw_ip4_hdr(ixs)->ihl
										    << 2)))
								->source :
							 lsw_ip4_hdr(ixs)->protocol ==IPPROTO_TCP ?
							  ((struct tcphdr*)((caddr_t)ixs->iph +
									    (lsw_ip4_hdr(ixs)->ihl
										    <<2)))
								->source :
							  0;
					}
					if (ixs->eroute->er_eaddr.sen_dport != 0)
					{
						dst.sin_port =
							lsw_ip4_hdr(ixs)->protocol == IPPROTO_UDP ?
							 ((struct udphdr*) (((caddr_t)ixs->iph) +
									    (lsw_ip4_hdr(ixs)->ihl << 2)))
								->dest :
							 lsw_ip4_hdr(ixs)->protocol ==IPPROTO_TCP ?
							  ((struct tcphdr*)((caddr_t)ixs->iph +
									    (lsw_ip4_hdr(ixs)->ihl << 2)))
								->dest :
							  0;
					}
				}

				ixs->ips.ips_addr_s = (struct sockaddr*)(&src);
				ixs->ips.ips_addr_d = (struct sockaddr*)(&dst);
				KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
					    "klips_debug:ipsec_xmit_encap_bundle: "
					    "SADB_ACQUIRE sent with src=%s:%d, dst=%s:%d, proto=%d.\n",
					    sin_addrtot(ixs->ips.ips_addr_s, 0,
							bufsrc,
							sizeof(bufsrc)) <= ADDRTOA_BUF ? bufsrc : "BAD_ADDR",
					    ntohs(((struct sockaddr_in*)(ixs->
									 ips.
									 ips_addr_s))
						  ->sin_port),
					    sin_addrtot(ixs->ips.ips_addr_d, 0,
							bufdst,
							sizeof(bufdst)) <= ADDRTOA_BUF ? bufdst : "BAD_ADDR",
					    ntohs(((struct sockaddr_in*)(ixs->
									 ips.
									 ips_addr_d))
						  ->sin_port),
					    ixs->ips.ips_said.proto);

				/* increment count of total traps needed */
				ipsec_xmit_trap_count++;

				if (pfkey_acquire(&ixs->ips) == 0) {
					/* note that we succeeded */
					ipsec_xmit_trap_sendcount++;

					if (ixs->outgoing_said.spi ==
					    htonl(SPI_TRAPSUBNET)) {
						/*
						 * The spinlock is to prevent any other
						 * process from accessing or deleting
						 * the eroute while we are using and
						 * updating it.
						 */
						spin_lock_bh(&eroute_lock);
						ixs->eroute = ipsec_findroute(
							&ixs->matcher);
						if (ixs->eroute) {
							ixs->eroute->er_said.
							spi = htonl(SPI_HOLD);
							ixs->eroute->er_first =
								ixs->skb;
							ixs->skb = NULL;
						}
						spin_unlock_bh(&eroute_lock);
					} else if (create_hold_eroute(ixs)) {
						ixs->skb = NULL;
					}
					/* whether or not the above succeeded, we continue */

				}
				if (ixs->stats)
					ixs->stats->tx_dropped++;
			}
		default:
			/* XXX what do we do with an unknown shunt spi? */
			break;
		}       /* switch (ntohl(ixs->outgoing_said.spi)) */
		return IPSEC_XMIT_STOLEN;
	}               /* if (ixs->outgoing_said.proto == IPPROTO_INT) */

	ixs->ipsp = ipsec_sa_getbyid(&ixs->outgoing_said, IPSEC_REFTX);
	ixs->sa_len = KLIPS_SATOT(debug_tunnel, &ixs->outgoing_said, 0,
				  ixs->sa_txt, sizeof(ixs->sa_txt));

	if (ixs->ipsp == NULL) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_debug:ipsec_xmit_encap_bundle: "
			    "no ipsec_sa for SA%s: outgoing packet with no SA, dropped.\n",
			    ixs->sa_len ? ixs->sa_txt : " (error)");
		if (ixs->stats)
			ixs->stats->tx_dropped++;
		return IPSEC_XMIT_SAIDNOTFOUND;
	}

	return IPSEC_XMIT_OK;
}

enum ipsec_xmit_value ipsec_xmit_init2(struct ipsec_xmit_state *ixs)
{
	enum ipsec_xmit_value bundle_stat = IPSEC_XMIT_OK;
	struct ipsec_sa *saved_ipsp;

#ifdef CONFIG_KLIPS_ALG
	ixs->blocksize = 8;
	ixs->ixt_e = NULL;
	ixs->ixt_a = NULL;
#endif  /* CONFIG_KLIPS_ALG */

	KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
		    "klips_debug:ipsec_xmit_init2: "
		    "found ipsec_sa -- SA:<%s%s%s> %s\n",
		    IPS_XFORM_NAME(ixs->ipsp),
		    ixs->sa_len ? ixs->sa_txt : " (error)");

	/*
	 * How much headroom do we need to be able to apply
	 * all the grouped transforms?
	 */
	saved_ipsp = ixs->ipsp; /* save the head of the ipsec_sa chain */
	while (ixs->ipsp) {
		if (debug_tunnel & DB_TN_XMIT) {
			ixs->sa_len = KLIPS_SATOT(debug_tunnel,
						  &ixs->ipsp->ips_said, 0,
						  ixs->sa_txt,
						  sizeof(ixs->sa_txt));
			if (ixs->sa_len == 0)
				strcpy(ixs->sa_txt, "(error)");
		} else {
			*ixs->sa_txt = 0;
			ixs->sa_len = 0;
		}

		/* If it is in larval state, drop the packet, we cannot process yet. */
		if (ixs->ipsp->ips_state == K_SADB_SASTATE_LARVAL) {
			KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
				    "klips_debug:ipsec_xmit_init2: "
				    "ipsec_sa in larval state for SA:<%s%s%s> %s, cannot be used yet, dropping packet.\n",
				    IPS_XFORM_NAME(ixs->ipsp),
				    ixs->sa_len ? ixs->sa_txt : " (error)");
			if (ixs->stats)
				ixs->stats->tx_errors++;
			bundle_stat = IPSEC_XMIT_SAIDNOTLIVE;
			goto cleanup;
		}

		if (ixs->ipsp->ips_state == K_SADB_SASTATE_DEAD) {
			KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
				    "klips_debug:ipsec_xmit_init2: "
				    "ipsec_sa in dead state for SA:<%s%s%s> %s, can no longer be used, dropping packet.\n",
				    IPS_XFORM_NAME(ixs->ipsp),
				    ixs->sa_len ? ixs->sa_txt : " (error)");
			if (ixs->stats)
				ixs->stats->tx_errors++;
			bundle_stat = IPSEC_XMIT_SAIDNOTLIVE;
			goto cleanup;
		}

		/* If the replay window counter == -1, expire SA, it will roll */
		if (ixs->ipsp->ips_replaywin &&
		    ixs->ipsp->ips_replaywin_lastseq == -1) {
			pfkey_expire(ixs->ipsp, 1);
			KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
				    "klips_debug:ipsec_xmit_init2: "
				    "replay window counter rolled for SA:<%s%s%s> %s, packet dropped, expiring SA.\n",
				    IPS_XFORM_NAME(ixs->ipsp),
				    ixs->sa_len ? ixs->sa_txt : " (error)");
			ipsec_sa_rm(ixs->ipsp);
			if (ixs->stats)
				ixs->stats->tx_errors++;
			bundle_stat = IPSEC_XMIT_REPLAYROLLED;
			goto cleanup;
		}

		/*
		 * if this is the first time we are using this SA, mark start time,
		 * and offset hard/soft counters by "now" for later checking.
		 */
#if 0
		if (ixs->ipsp->ips_life.ipl_usetime.count == 0) {
			ixs->ipsp->ips_life.ipl_usetime.count = jiffies;
			ixs->ipsp->ips_life.ipl_usetime.hard += jiffies;
			ixs->ipsp->ips_life.ipl_usetime.soft += jiffies;
		}
#endif

		if (ipsec_lifetime_check(&ixs->ipsp->ips_life.ipl_bytes,
					 "bytes", ixs->sa_txt,
					 ipsec_life_countbased, ipsec_outgoing,
					 ixs->ipsp) == ipsec_life_harddied ||
		    ipsec_lifetime_check(&ixs->ipsp->ips_life.ipl_addtime,
					 "addtime", ixs->sa_txt,
					 ipsec_life_timebased,  ipsec_outgoing,
					 ixs->ipsp) == ipsec_life_harddied ||
		    ipsec_lifetime_check(&ixs->ipsp->ips_life.ipl_usetime,
					 "usetime", ixs->sa_txt,
					 ipsec_life_timebased,  ipsec_outgoing,
					 ixs->ipsp) == ipsec_life_harddied ||
		    ipsec_lifetime_check(&ixs->ipsp->ips_life.ipl_packets,
					 "packets", ixs->sa_txt,
					 ipsec_life_countbased, ipsec_outgoing,
					 ixs->ipsp) == ipsec_life_harddied) {

			ipsec_sa_rm(ixs->ipsp);
			if (ixs->stats)
				ixs->stats->tx_errors++;
			bundle_stat = IPSEC_XMIT_LIFETIMEFAILED;
			goto cleanup;
		}

		ixs->headroom = ixs->tailroom = 0;
		KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
			    "klips_debug:ipsec_xmit_init2: "
			    "calling room for <%s%s%s>, SA:%s\n",
			    IPS_XFORM_NAME(ixs->ipsp),
			    ixs->sa_len ? ixs->sa_txt : " (error)");
		switch (ixs->ipsp->ips_said.proto) {
#ifdef CONFIG_KLIPS_AH
		case IPPROTO_AH:
			ixs->headroom += sizeof(struct ahhdr);
			break;
#endif                  /* CONFIG_KLIPS_AH */

#ifdef CONFIG_KLIPS_ESP
		case IPPROTO_ESP:
#ifdef CONFIG_KLIPS_OCF
			/*
			 * this needs cleaning up for sure - DM
			 */
			if (ixs->ipsp->ocf_in_use) {
				switch (ixs->ipsp->ips_encalg) {
				case ESP_DES:
				case ESP_3DES:
					ixs->blocksize = 8;
					ixs->headroom += ESP_HEADER_LEN +
							 8 /* ivsize */;
					break;
				case ESP_AES:
					ixs->blocksize = 16;
					ixs->headroom += ESP_HEADER_LEN +
							 16 /* ivsize */;
					break;
				case ESP_NULL:
					ixs->blocksize = 16;
					ixs->headroom += ESP_HEADER_LEN + 0 /* ivsize */;
					break;
				default:
					if (ixs->stats)
						ixs->stats->tx_errors++;
					bundle_stat = IPSEC_XMIT_ESP_BADALG;
					goto cleanup;
				}
			} else
#endif                  /* CONFIG_KLIPS_OCF */
#ifdef CONFIG_KLIPS_ALG
			if ((ixs->ixt_e = ixs->ipsp->ips_alg_enc)) {
				ixs->blocksize =
					ixs->ixt_e->ixt_common.ixt_blocksize;
				ixs->headroom += ESP_HEADER_LEN +
						 ixs->ixt_e->ixt_common.
						 ixt_support.ias_ivlen /
						 8;
			} else
#endif                  /* CONFIG_KLIPS_ALG */
			{
				if (ixs->stats)
					ixs->stats->tx_errors++;
				bundle_stat = IPSEC_XMIT_ESP_BADALG;
				goto cleanup;
			}
#ifdef CONFIG_KLIPS_OCF
			if (ixs->ipsp->ocf_in_use) {
				switch (ixs->ipsp->ips_authalg) {
				case AH_MD5:
				case AH_SHA:
					ixs->tailroom += AHHMAC_HASHLEN;
					break;
				case AH_NONE:
					break;
				}
			} else
#endif                  /* CONFIG_KLIPS_OCF */
#ifdef CONFIG_KLIPS_ALG
			if ((ixs->ixt_a = ixs->ipsp->ips_alg_auth))
				ixs->tailroom += ixs->ixt_a->ixt_a_authlen;
			else
#endif                  /* CONFIG_KLIPS_ALG */
			switch (ixs->ipsp->ips_authalg) {
#ifdef CONFIG_KLIPS_AUTH_HMAC_MD5
			case AH_MD5:
				ixs->tailroom += AHHMAC_HASHLEN;
				break;
#endif                          /* CONFIG_KLIPS_AUTH_HMAC_MD5 */
#ifdef CONFIG_KLIPS_AUTH_HMAC_SHA1
			case AH_SHA:
				ixs->tailroom += AHHMAC_HASHLEN;
				break;
#endif                          /* CONFIG_KLIPS_AUTH_HMAC_SHA1 */
			case AH_NONE:
				break;
			default:
				if (ixs->stats)
					ixs->stats->tx_errors++;
				bundle_stat = IPSEC_XMIT_AH_BADALG;
				goto cleanup;
			}
			ixs->tailroom += ixs->blocksize != 1 ?
					 ((ixs->blocksize -
					   ((ixs->pyldsz +
					     2) %
					    ixs->blocksize)) %
					  ixs->blocksize) + 2 :
					 ((4 -
					   ((ixs->pyldsz + 2) % 4)) % 4) + 2;

			if ((ixs->ipsp->ips_natt_type) && (!ixs->natt_type)) {
				ixs->natt_type = ixs->ipsp->ips_natt_type;
				ixs->natt_sport = ixs->ipsp->ips_natt_sport;
				ixs->natt_dport = ixs->ipsp->ips_natt_dport;
				switch (ixs->natt_type) {
				case ESPINUDP_WITH_NON_IKE:
					ixs->natt_head =
						sizeof(struct udphdr) +
						(2 * sizeof(__u32));
					break;

				case ESPINUDP_WITH_NON_ESP:
					ixs->natt_head = sizeof(struct udphdr);
					break;

				default:
					KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
						    "klips_xmit: invalid nat-t type %d",
						    ixs->natt_type);
					bundle_stat =
						IPSEC_XMIT_ESPUDP_BADTYPE;
					goto cleanup;

					break;
				}
				ixs->tailroom += ixs->natt_head;
			}

			break;
#endif                  /* CONFIG_KLIPS_ESP */
#ifdef CONFIG_KLIPS_IPIP
		case IPPROTO_IPIP:
			if (ip_address_family(&ixs->ipsp->ips_said.dst) ==
			    AF_INET6)
				ixs->headroom += sizeof(struct ipv6hdr);
			else
				ixs->headroom += sizeof(struct iphdr);
			ixs->ipip_proto = lsw_ip_hdr_version(ixs) ==
					  6 ?  IPPROTO_IPV6 : IPPROTO_IPIP;
			break;
#endif                  /* !CONFIG_KLIPS_IPIP */
		case IPPROTO_COMP:
#ifdef CONFIG_KLIPS_IPCOMP
			/*
			   We can't predict how much the packet will
			   shrink without doing the actual compression.
			   We could do it here, if we were the first
			   encapsulation in the chain.  That might save
			   us a skb_copy_expand, since we might fit
			   into the existing skb then.  However, this
			   would be a bit unclean (and this hack has
			   bit us once), so we better not do it. After
			   all, the skb_copy_expand is cheap in
			   comparison to the actual compression.
			   At least we know the packet will not grow.
			 */
			break;
#endif                  /* CONFIG_KLIPS_IPCOMP */
		default:
			if (ixs->stats)
				ixs->stats->tx_errors++;
			bundle_stat = IPSEC_XMIT_BADPROTO;
			goto cleanup;
		}
		ixs->ipsp = ixs->ipsp->ips_next;
		KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
			    "klips_debug:ipsec_xmit_init2: "
			    "Required head,tailroom: %d,%d\n",
			    ixs->headroom, ixs->tailroom);
		ixs->max_headroom += ixs->headroom;
		ixs->max_tailroom += ixs->tailroom;
		ixs->pyldsz += (ixs->headroom + ixs->tailroom);
	}
	ixs->ipsp = saved_ipsp; /* restore the head of the ipsec_sa chain */

	KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
		    "klips_debug:ipsec_xmit_init2: "
		    "existing head,tailroom: %d,%d before applying xforms with head,tailroom: %d,%d .\n",
		    skb_headroom(ixs->skb), skb_tailroom(ixs->skb),
		    ixs->max_headroom, ixs->max_tailroom);

	ixs->tot_headroom += ixs->max_headroom;
	ixs->tot_tailroom += ixs->max_tailroom;

	ixs->mtudiff = ixs->cur_mtu + ixs->tot_headroom + ixs->tot_tailroom -
		       ixs->physmtu;

	KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
		    "klips_debug:ipsec_xmit_init2: "
		    "mtu:%d physmtu:%d tothr:%d tottr:%d mtudiff:%d ippkttotlen:%u\n",
		    ixs->cur_mtu, ixs->physmtu,
		    ixs->tot_headroom, ixs->tot_tailroom, ixs->mtudiff,
		    (unsigned int) (lsw_ip_hdr_version(ixs) == 6 ?
				    (ntohs(lsw_ip6_hdr(ixs)->payload_len) +
				     sizeof(struct ipv6hdr)) :
				    ntohs(lsw_ip4_hdr(ixs)->tot_len)));
	if (ixs->cur_mtu == 0 || ixs->mtudiff > 0) {
		int newmtu = ixs->physmtu -
			     (ixs->tot_headroom +
			      ((ixs->tot_tailroom + 2) & ~7) + 5);

		KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
			    "klips_info:ipsec_xmit_init2: "
			    "dev %s mtu of %d decreased by %d to %d\n",
			    ixs->dev ? ixs->dev->name : "ifX",
			    ixs->cur_mtu,
			    ixs->cur_mtu - newmtu,
			    newmtu);
		ixs->cur_mtu = newmtu;

		/* this would seem to adjust the MTU of the route as well */
#if 0
		skb_dst(ixs->skb)->pmtu = ixs->iprv->mtu; /* RGB */
#endif /* 0 */
	}

	/*
	   If the sender is doing PMTU discovery, and the
	   packet doesn't fit within ixs->prv->mtu, notify him
	   (unless it was an ICMP packet, or it was not the
	   zero-offset packet) and send it anyways.

	   Note: buggy firewall configuration may prevent the
	   ICMP packet from getting back.
	 */
	if (sysctl_ipsec_icmp) {
		int tot_len = lsw_ip_hdr_version(ixs) == 6 ?
			      (ntohs(lsw_ip6_hdr(ixs)->payload_len) +
			       sizeof(struct ipv6hdr)) :
			      ntohs(lsw_ip4_hdr(ixs)->tot_len);
		if (ixs->cur_mtu < tot_len && lsw_ip_hdr_version(ixs) == 4 &&
		    (lsw_ip4_hdr(ixs)->frag_off & __constant_htons(IP_DF))) {
			int notify = lsw_ip4_hdr(ixs)->protocol !=
				     IPPROTO_ICMP &&
				     (lsw_ip4_hdr(ixs)->frag_off &
				      __constant_htons(IP_OFFSET)) == 0;

#ifdef IPSEC_obey_DF
			KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
				    "klips_debug:ipsec_xmit_init2: "
				    "fragmentation needed and DF set; %sdropping packet\n",
				    notify ? "sending ICMP and " : "");
			if (notify)
				ICMP_SEND(ixs->skb,
					  ICMP_DEST_UNREACH,
					  ICMP_FRAG_NEEDED,
					  ixs->cur_mtu,
					  ixs->physdev);
			if (ixs->stats)
				ixs->stats->tx_errors++;
			bundle_stat = IPSEC_XMIT_CANNOTFRAG;
			goto cleanup;
#else                   /* IPSEC_obey_DF */
			KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
				    "klips_debug:ipsec_xmit_init2: "
				    "fragmentation needed and DF set; %spassing packet\n",
				    notify ? "sending ICMP and " : "");
			if (notify)
				ICMP_SEND(ixs->skb,
					  ICMP_DEST_UNREACH,
					  ICMP_FRAG_NEEDED,
					  ixs->cur_mtu,
					  ixs->physdev);
#endif                  /* IPSEC_obey_DF */
		}
#ifdef CONFIG_KLIPS_IPV6
		else if (ixs->cur_mtu < tot_len &&
			 lsw_ip_hdr_version(ixs) == 6) {
			IPSEC_FRAG_OFF_DECL(frag_off)
			int nexthdroff;
			unsigned char nexthdr = lsw_ip6_hdr(ixs)->nexthdr;
			nexthdroff = ipsec_ipv6_skip_exthdr(ixs->skb,
				    ((void *)(lsw_ip6_hdr(ixs) + 1)) -
				    (void*)ixs->skb->data,
				    &nexthdr, &frag_off);
			ixs->iphlen = nexthdroff -
				      (ixs->iph - (void*)ixs->skb->data);
			ixs->pyldsz = ntohs(lsw_ip6_hdr(ixs)->payload_len) +
				      sizeof(struct ipv6hdr) - ixs->iphlen;

			KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
				    "klips_debug:ipsec_xmit_init2: "
				    "fragmentation needed for nexthdr(%d) (got %d but mtu is %d); sending ICMPV6_PKT_TOOBIG and dropping the packet\n",
				    nexthdr, tot_len, ixs->cur_mtu);

			ICMP6_SEND(ixs->skb,
				   ICMPV6_PKT_TOOBIG,   /* type */
				   0,                   /* code */
				   ntohl(ixs->cur_mtu),
				   ixs->physdev);

			if (ixs->stats)
				ixs->stats->tx_errors++;
			bundle_stat = IPSEC_XMIT_CANNOTFRAG;
			goto cleanup;
		}
#endif
	}

#ifdef MSS_HACK_DELETE_ME_PLEASE
#ifdef CONFIG_KLIPS_IPV6
#error "this code is broken for IPv6"
#endif
	/*
	 * If this is a transport mode TCP packet with
	 * SYN set, determine an effective MSS based on
	 * AH/ESP overheads determined above.
	 */
	if (ixs->iph->protocol == IPPROTO_TCP &&
	    ixs->outgoing_said.proto != IPPROTO_IPIP) {
		struct tcphdr *tcph = ixs->skb->h.th;
		if (tcph->syn && !tcph->ack) {
			if (!ipsec_adjust_mss(ixs->skb, tcph, ixs->cur_mtu)) {
				printk(KERN_WARNING
				       "klips_warning:ipsec_xmit_init2: "
				       "ipsec_adjust_mss() failed\n");
				if (ixs->stats)
					ixs->stats->tx_errors++;
				bundle_stat = IPSEC_XMIT_MSSERR;
				goto cleanup;
			}
		}
	}
#endif  /* MSS_HACK_DELETE_ME_PLEASE */

	if ((ixs->natt_type) && (ixs->outgoing_said.proto != IPPROTO_IPIP)) {
		/**
		 * NAT-Traversal and Transport Mode:
		 *   we need to force destination address to sane value
		 */

		struct sockaddr_in *sv4 =
			(struct sockaddr_in *)ixs->ipsp->ips_addr_d;
		__u32 natt_d = sv4->sin_addr.s_addr;
		struct iphdr *ipp = ixs->iph;

		/* set the destination address to what it needs to be for the
		 * NAT encapsulation.
		 */
		KLIPS_PRINT(debug_tunnel,
			    "xmit: setting ND=%08x\n", natt_d);
		ipp->daddr = natt_d;
		ipp->check = 0; /* zeroed so we get the right checksum */
		ipp->check = ip_fast_csum((unsigned char *)ipp, ipp->ihl);
	}

	if (!ixs->hard_header_stripped && ixs->hard_header_len > 0) {
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_debug:ipsec_xmit_init2: "
			    "allocating %d bytes for hardheader.\n",
			    ixs->hard_header_len);
		if ((ixs->saved_header = kmalloc(ixs->hard_header_len,
						 GFP_ATOMIC)) == NULL) {
			printk(KERN_WARNING "klips_debug:ipsec_xmit_init2: "
			       "Failed, tried to allocate %d bytes for temp hard_header.\n",
			       ixs->hard_header_len);
			if (ixs->stats)
				ixs->stats->tx_errors++;
			bundle_stat = IPSEC_XMIT_ERRMEMALLOC;
			goto cleanup;
		}
		memcpy(&ixs->saved_header[0], &ixs->skb->data[0],
		       ixs->hard_header_len);
		if (ixs->skb->len < ixs->hard_header_len) {
			printk(KERN_WARNING "klips_error:ipsec_xmit_init2: "
			       "tried to skb_pull hhlen=%d, %d available.  This should never happen, please report.\n",
			       ixs->hard_header_len, (int)(ixs->skb->len));
			if (ixs->stats)
				ixs->stats->tx_errors++;
			bundle_stat = IPSEC_XMIT_ESP_PUSHPULLERR;
			goto cleanup;
		}
		skb_pull(ixs->skb, ixs->hard_header_len);
		ixs->hard_header_stripped = 1;

/*			ixs->iph = (struct iphdr *) (ixs->skb->data); */
		KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
			    "klips_debug:ipsec_xmit_init2: "
			    "head,tailroom: %d,%d after hard_header stripped.\n",
			    skb_headroom(ixs->skb), skb_tailroom(ixs->skb));
		KLIPS_IP_PRINT(debug_tunnel & DB_TN_CROUT, ixs->iph);
	} else {
		KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
			    "klips_debug:ipsec_xmit_init2: "
			    "hard header already stripped.\n");
	}

	ixs->ll_headroom = (ixs->hard_header_len + 15) & ~15;

	if ((skb_headroom(ixs->skb) >= ixs->max_headroom + 2 *
	     ixs->ll_headroom) &&
	    (skb_tailroom(ixs->skb) >= ixs->max_tailroom)
	    ) {
		KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
			    "klips_debug:ipsec_xmit_init2: "
			    "data fits in existing skb\n");
	} else {
		struct sk_buff *tskb;

		tskb = skb_copy_expand(ixs->skb,
				       /* The need for 2 * link layer length here remains unexplained...RGB */
				       ixs->max_headroom + 2 * ixs->ll_headroom,
				       ixs->max_tailroom,
				       GFP_ATOMIC);

		if (tskb && ixs->skb->sk)
			skb_set_owner_w(tskb, ixs->skb->sk);

		if (ixs->oskb)
			ipsec_kfree_skb(ixs->skb);
		else
			ixs->oskb = ixs->skb;
		ixs->skb = tskb;
		if (!ixs->skb) {
			printk(KERN_WARNING
			       "klips_debug:ipsec_xmit_init2: "
			       "Failed, tried to allocate %d head and %d tailroom\n",
			       ixs->max_headroom, ixs->max_tailroom);
			if (ixs->stats)
				ixs->stats->tx_errors++;
			bundle_stat = IPSEC_XMIT_ERRSKBALLOC;
			goto cleanup;
		}
		KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
			    "klips_debug:ipsec_xmit_init2: "
			    "head,tailroom: %d,%d after allocation\n",
			    skb_headroom(ixs->skb), skb_tailroom(ixs->skb));
	}

	KLIPS_IP_PRINT(debug_tunnel & DB_TN_ENCAP, ixs->iph);

cleanup:
	return bundle_stat;
}

void ipsec_xmit_cleanup(struct ipsec_xmit_state *ixs)
{
	void *p;
	if (ixs->saved_header) {
		p = ixs->saved_header;
		ixs->saved_header = NULL;
		kfree(p);
	}
	if (ixs->skb) {
		p = ixs->skb;
		ixs->skb = NULL;
		ipsec_kfree_skb(p);
	}
	if (ixs->oskb) {
		p = ixs->oskb;
		ixs->oskb = NULL;
		ipsec_kfree_skb(p);
	}
	if (ixs->pre_ipcomp_skb) {
		p = ixs->pre_ipcomp_skb;
		ixs->pre_ipcomp_skb = NULL;
		ipsec_kfree_skb(p);
	}
	if (ixs->ips.ips_ident_s.data) {
		p = ixs->ips.ips_ident_s.data;
		ixs->ips.ips_ident_s.data = NULL;
		kfree(p);
	}
	if (ixs->ips.ips_ident_d.data) {
		p = ixs->ips.ips_ident_d.data;
		ixs->ips.ips_ident_d.data = NULL;
		kfree(p);
	}
	if (ixs->ipsp) {
		p = ixs->ipsp;
		ixs->ipsp = NULL;
		ipsec_sa_put(p, IPSEC_REFTX);
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static inline int ipsec_xmit_send2(struct sk_buff *skb)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static inline int ipsec_xmit_send2(struct sock *sk, struct sk_buff *skb)
#else
static inline int ipsec_xmit_send2(struct net *net, struct sock *sk, struct sk_buff *skb)
#endif
{
#ifdef NET_26   /* 2.6 kernels */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	return dst_output(dev_net(skb->dev), sk, skb);
#else
	return dst_output(skb);
#endif

#else
	return ip_send(skb);

#endif
}

static inline int ipsec_xmit_send2_mast(struct sk_buff *skb)
{
#ifdef NET_26   /* 2.6 kernels */
# if defined(CONFIG_NETFILTER)
	/* prevent recursion through the saref route */
	if (skb->nfmark & 0x80000000)
		skb->nfmark = 0;
# endif
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
	return ipsec_xmit_send2(skb);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
	return ipsec_xmit_send2(skb->sk, skb);
#else
	return ipsec_xmit_send2(dev_net(skb->dev), skb->sk, skb);
#endif

}

enum ipsec_xmit_value ipsec_nat_encap(struct ipsec_xmit_state *ixs)
{
	if (ixs->natt_type && ixs->natt_head) {
		struct iphdr *ipp = ip_hdr(ixs->skb);
		struct udphdr *udp;
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_debug:ipsec_nat_encap: "
			    "encapsuling packet into UDP (NAT-Traversal) (%d %d)\n",
			    ixs->natt_type, ixs->natt_head);

		ixs->iphlen = ipp->ihl << 2;
		ipp->tot_len =
			htons(ntohs(ipp->tot_len) + ixs->natt_head);
		if (skb_tailroom(ixs->skb) < ixs->natt_head) {
			printk(KERN_WARNING "klips_error:ipsec_nat_encap: "
			       "tried to skb_put %d, %d available. Returning IPSEC_XMIT_ESPUDP. "
			       "This should never happen, please report.\n",
			       ixs->natt_head,
			       skb_tailroom(ixs->skb));
			if (ixs->stats)
				ixs->stats->tx_errors++;
			return IPSEC_XMIT_ESPUDP;
		}
		skb_put(ixs->skb, ixs->natt_head);

		udp = (struct udphdr *)((char *)ipp + ixs->iphlen);

		/* move ESP hdr after UDP hdr */
		memmove((void *)((char *)udp + ixs->natt_head),
			(void *)(udp),
			ntohs(ipp->tot_len) - ixs->iphlen - ixs->natt_head);

#if 0
		/* set IP destination address (matters in transport mode) */
		{
			struct sockaddr_in *d =
				(struct sockaddr_in *)ixs->ipsp->ips_addr_d;
			ipp->daddr = d->sin_addr.s_addr;
		}
#endif

		/* clear UDP & Non-IKE Markers (if any) */
		memset(udp, 0, ixs->natt_head);

		/* fill UDP with useful informations ;-) */
		udp->source = htons(ixs->natt_sport);
		udp->dest = htons(ixs->natt_dport);
		udp->len = htons(ntohs(ipp->tot_len) - ixs->iphlen);

		/* set protocol */
		ipp->protocol = IPPROTO_UDP;

		/* fix IP checksum */
		ipp->check = 0;
		ipp->check = ip_fast_csum((unsigned char *)ipp, ipp->ihl);
	}
	return IPSEC_XMIT_OK;
}

static int ipsec_set_dst(struct ipsec_xmit_state *ixs)
{
	struct dst_entry *dst = NULL;
	int error = 0;

#ifdef NET_26
	struct flowi fl;
#endif

	if (ixs->set_dst)
		return IPSEC_XMIT_OK;

#ifdef NET_26
	memset(&fl, 0, sizeof(fl));

	/* new route/dst cache code from James Morris */
	ixs->skb->dev = ixs->physdev;
	fl.flowi_oif = ixs->physdev ? ixs->physdev->ifindex : 0;

# ifdef CONFIG_KLIPS_IPV6
	if (lsw_ip_hdr_version(ixs) == 6) {
		/* saddr must not be set with ipv6, otherwise you can't
		 * force the output device with linux kernels >= 4.3.
		 * (kernel commit d46a9d678e4c9fac1e968d0593e4dba683389324)
		 */
		memset(&fl.nl_u.ip6_u.saddr, 0, sizeof(fl.nl_u.ip6_u.saddr));
		fl.nl_u.ip6_u.daddr = lsw_ip6_hdr(ixs)->daddr;
		/* fl->nl_u.ip6_u.tos = RT_TOS(lsw_ip6_hdr(ixs)->tos); */
		fl.flowi_proto = IPPROTO_IPV6;
#  ifndef FLOW_HAS_NO_MARK
		fl.flowi_mark = ixs->skb->mark;
#  endif
#  if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 24)
		dst = ip6_route_output(NULL, &fl);
#  elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
		dst = ip6_route_output(&init_net, NULL, &fl);
#  else
		dst = ip6_route_output(&init_net, NULL, &fl.nl_u.ip6_u);
#  endif
		error = dst->error;
	} else
# endif /* CONFIG_KLIPS_IPV6 */
	{
		fl.nl_u.ip4_u.daddr = lsw_ip4_hdr(ixs)->daddr;
		fl.nl_u.ip4_u.saddr = ixs->pass ? 0 : lsw_ip4_hdr(ixs)->saddr;
		fl.flowi_tos = RT_TOS(lsw_ip4_hdr(ixs)->tos);
		fl.flowi_proto = lsw_ip4_hdr(ixs)->protocol;
# ifndef FLOW_HAS_NO_MARK
		fl.flowi_mark = ixs->skb->mark;
# endif
# if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
#  if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 24)
		error = ip_route_output_key(&ixs->route, &fl);
#  else
		error = ip_route_output_key(&init_net, &ixs->route, &fl);
#  endif
		if (ixs->route)
			dst = &ipsec_route_dst(ixs->route);
# else
		ixs->route = ip_route_output_key(&init_net, &fl.u.ip4);
		if (IS_ERR(ixs->route)) {
			error = PTR_ERR(ixs->route);
			ixs->route = NULL;
		} else {
			error = 0;
			dst = &ipsec_route_dst(ixs->route);
		}
# endif
	}
#else
# ifdef CONFIG_KLIPS_IPV6
#  error "this code is broken for IPv6"
# endif
	/*skb_orphan(ixs->skb);*/
	error = ip_route_output(&ixs->route,
				lsw_ip4_hdr(ixs)->daddr,
				ixs->pass ? 0 : lsw_ip4_hdr(ixs)->saddr,
				RT_TOS(lsw_ip4_hdr(ixs)->tos),
				/* mcr->rgb: should this be 0 instead? */
				ixs->physdev->ifindex);
	if (ixs->route)
		dst = &ipsec_route_dst(ixs->route);
#endif
	if (error) {
		if (ixs->stats)
			ixs->stats->tx_errors++;
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_debug:ipsec_set_dst: "
			    "ip_route_output failed with error code %d, dropped\n",
			    error);
		return IPSEC_XMIT_ROUTEERR;
	}

	if (dst == NULL) {
		if (ixs->stats)
			ixs->stats->tx_errors++;
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_debug:ipsec_set_dst: "
			    "ip_route_output failed with no dst, dropped\n");
		return IPSEC_XMIT_ROUTEERR;
	}

	/* ixs->physdev can be NULL in mast mode and we searched for a non-device
	 * specific route.  Now we can use the device for the route we found. */
	if (!ixs->skb->dev)
		ixs->skb->dev = dst->dev;

	if (ixs->dev == dst->dev) {
		if (lsw_ip_hdr_version(ixs) == 6)
			dst_release(dst);
		else
			ip_rt_put(ixs->route);
		/* This is recursion, drop it. */
		if (ixs->stats)
			ixs->stats->tx_errors++;
		KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
			    "klips_debug:ipsec_set_dst: "
			    "suspect recursion, dev=rt->u.dst.dev=%s, dropped\n",
			    ixs->dev->name);
		return IPSEC_XMIT_RECURSDETECT;
	}

	skb_dst_drop(ixs->skb);
	skb_dst_set(ixs->skb, dst);

	ixs->set_dst = 1;

	return IPSEC_XMIT_OK;
}

enum ipsec_xmit_value ipsec_xmit_send(struct ipsec_xmit_state *ixs)
{
	int error;

	if (ixs->skb == NULL || ixs->skb->dev == NULL)
		return IPSEC_XMIT_NODEV;

	/*
	 * ipsec_set_dst may have been done in the IPIP code,  or we do it now.
	 * DAVIDM - I actually think it must have always been done before
	 *          now,  but ESP without IPIP and no AH may be the
	 *          exception.  You cannot hash and then do ipsec_set_dst :-)
	 */
	error = ipsec_set_dst(ixs);
	if (error != IPSEC_XMIT_OK)
		return error;

	if (ixs->stats)
		ixs->stats->tx_bytes += ixs->skb->len;

	if (ixs->skb->len < skb_network_header(ixs->skb) - ixs->skb->data) {
		if (ixs->stats)
			ixs->stats->tx_errors++;
		printk(KERN_WARNING
		       "klips_error:ipsec_xmit_send: "
		       "tried to __skb_pull nh-data=%td, %d available.  This should never happen, please report.\n",
		       skb_network_header(ixs->skb) - ixs->skb->data,
		       ixs->skb->len);
		return IPSEC_XMIT_PUSHPULLERR;
	}
	__skb_pull(ixs->skb, skb_network_header(ixs->skb) - ixs->skb->data);
	if (!ixs->pass)
		ipsec_nf_reset(ixs->skb);

	/* fix up the checksum after changes to the header */
	if (ip_hdr(ixs->skb)->version == 4) {
		ip_hdr(ixs->skb)->check = 0;
		ip_hdr(ixs->skb)->check =
			ip_fast_csum((unsigned char *)ip_hdr(ixs->skb),
				     ip_hdr(ixs->skb)->ihl);
	}

	KLIPS_PRINT(debug_tunnel & DB_TN_XMIT,
		    "klips_debug:ipsec_xmit_send: "
		    "...done, calling ip_send() on device:%s%s\n",
		    ixs->skb->dev ? ixs->skb->dev->name : "NULL",
		    ixs->mast_mode ? "(mast)" : "");
	KLIPS_IP_PRINT(debug_tunnel & DB_TN_XMIT, ip_hdr(ixs->skb));
	{
		int err;
		if (ixs->mast_mode) {
			/* skip filtering on mast devices, since it resets our
			 * route, nfmark, and causes nasty reentrancy. */
			err = ipsec_xmit_send2_mast(ixs->skb);
		} else if (ip_hdr(ixs->skb)->version == 6) {
			err = NF_HOOK(PF_INET6, LSW_NF_INET_LOCAL_OUT,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
				      dev_net(ixs->skb->dev),
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
				      ixs->skb->sk,
#endif
				      ixs->skb, NULL,
				      ixs->route ?
					 ipsec_route_dst(ixs->route).dev :
					 skb_dst(ixs->skb)->dev,
				      ipsec_xmit_send2);
		} else {
			err = NF_HOOK(PF_INET, LSW_NF_INET_LOCAL_OUT,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
				      dev_net(ixs->skb->dev),
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
				      ixs->skb->sk,
#endif
				      ixs->skb, NULL,
				      ixs->route ?
					ipsec_route_dst(ixs->route).dev :
					skb_dst(ixs->skb)->dev,
				      ipsec_xmit_send2);
		}

		if (err != NET_XMIT_SUCCESS && err != NET_XMIT_CN) {
			if (net_ratelimit()) {
				printk(KERN_ERR
				       "klips_error:ipsec_xmit_send: "
				       "ip_send() failed, err=%d\n",
				       -err);
			}
			if (ixs->stats) {
				ixs->stats->tx_errors++;
				ixs->stats->tx_aborted_errors++;
			}
			ixs->skb = NULL;
			return IPSEC_XMIT_IPSENDFAILURE;
		}
	}
	if (ixs->stats)
		ixs->stats->tx_packets++;

	ixs->skb = NULL;

	return IPSEC_XMIT_OK;
}

enum ipsec_xmit_value ipsec_tunnel_send(struct ipsec_xmit_state *ixs)
{
	return ipsec_xmit_send(ixs);
}

/*
 * here is a state machine to handle encapsulation
 * basically we keep getting re-entered until processing is
 * complete.  For the simple case we step down the states and finish.
 * each state is ideally some logical part of the process.  If a state
 * can pend (ie., require async processing to complete),  then this
 * should be the part of last action before it returns IPSEC_RCV_PENDING
 *
 * Any particular action may alter the next_state in ixs to move us to
 * a state other than the preferred "next_state",  but this is the
 * exception and is highlighted when it is done.
 *
 * prototypes for state action
 */

static struct {
	enum ipsec_xmit_value (*action)(struct ipsec_xmit_state *ixs);
	int next_state;
} xmit_state_table[] = {
	[IPSEC_XSM_INIT1]       = { ipsec_xmit_init1,       IPSEC_XSM_INIT2 },
	[IPSEC_XSM_INIT2]       =
		{ ipsec_xmit_init2,       IPSEC_XSM_ENCAP_INIT },
	[IPSEC_XSM_ENCAP_INIT]  =
		{ ipsec_xmit_encap_init,  IPSEC_XSM_ENCAP_SELECT },
	[IPSEC_XSM_ENCAP_SELECT] = { ipsec_xmit_encap_select, IPSEC_XSM_DONE },

#ifdef CONFIG_KLIPS_ESP
	[IPSEC_XSM_ESP]         = { ipsec_xmit_esp,         IPSEC_XSM_ESP_AH },
	[IPSEC_XSM_ESP_AH]      = { ipsec_xmit_esp_ah,      IPSEC_XSM_CONT },
#endif

#ifdef CONFIG_KLIPS_AH
	[IPSEC_XSM_AH]          = { ipsec_xmit_ah,          IPSEC_XSM_CONT },
#endif

#ifdef CONFIG_KLIPS_IPIP
	[IPSEC_XSM_IPIP]        = { ipsec_xmit_ipip,        IPSEC_XSM_CONT },
#endif

#ifdef CONFIG_KLIPS_IPCOMP
	[IPSEC_XSM_IPCOMP]      = { ipsec_xmit_ipcomp,      IPSEC_XSM_CONT },
#endif

	[IPSEC_XSM_CONT]        = { ipsec_xmit_cont,        IPSEC_XSM_DONE },
	[IPSEC_XSM_DONE]        = { NULL,                   IPSEC_XSM_DONE },
};

void ipsec_xsm(struct ipsec_xmit_state *ixs)
{
	enum ipsec_xmit_value stat = IPSEC_XMIT_ENCAPFAIL;
	unsigned more_allowed;

	if (ixs == NULL) {
		KLIPS_PRINT(debug_tunnel,
			    "klips_debug:ipsec_xsm: ixs == NULL.\n");
		return;
	}

	/*
	 * make sure nothing is removed from underneath us
	 */
	spin_lock_bh(&tdb_lock);

	/*
	 * if we have a valid said,  then we must check it here to ensure it
	 * hasn't gone away while we were waiting for a task to complete.
	 *
	 * If the said was found via saref in mast code, skip this check.
	 */

	if (ixs->ipsp && !ixs->mast_mode) {
		struct ipsec_sa *ipsp;
		ipsp = ipsec_sa_getbyid(&ixs->outgoing_said, IPSEC_REFTX);
		if (unlikely(ipsp == NULL)) {
			KLIPS_PRINT(debug_tunnel,
				    "klips_debug:ipsec_xsm: "
				    "no ipsec_sa for SA:%s: "
				    "outgoing packet with no SA dropped\n",
				    ixs->sa_len ? ixs->sa_txt : " (error)");
			if (ixs->stats)
				ixs->stats->tx_dropped++;

			/* drop through and cleanup */
			stat = IPSEC_XMIT_SAIDNOTFOUND;
			ixs->state = IPSEC_XSM_DONE;
		} else {
			/* put the ref count back */
			ipsec_sa_put(ipsp, IPSEC_REFTX);
		}
	}

	more_allowed = 1000;
	while (ixs->state != IPSEC_XSM_DONE && --more_allowed) {
		ixs->next_state = xmit_state_table[ixs->state].next_state;

		stat = xmit_state_table[ixs->state].action(ixs);

		if (stat == IPSEC_XMIT_OK) {
			/* some functions change the next state, see the state table */
			ixs->state = ixs->next_state;
		} else if (stat == IPSEC_XMIT_PENDING) {
			/*
			 * things are on hold until we return here in the next/new state
			 * we check our SA is valid when we return
			 */
			spin_unlock_bh(&tdb_lock);
			return;
		} else {
			/* bad result, force state change to done */
			KLIPS_PRINT(debug_tunnel,
				    "klips_debug:ipsec_xsm: "
				    "processing completed due to %s.\n",
				    ipsec_xmit_err(stat));
			ixs->state = IPSEC_XSM_DONE;
		}
	}

	/*
	 * all done with anything needing locks
	 */
	spin_unlock_bh(&tdb_lock);

	/*
	 * let the caller continue with their processing
	 */
	ixs->xsm_complete(ixs, stat);
}
