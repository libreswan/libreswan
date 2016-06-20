/*
 * IPSEC MAST code.
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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
 */

char ipsec_mast_c_version[] = "Please use ipsec --version instead";

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

#include <net/arp.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/skbuff.h>

#include <linux/netdevice.h>    /* struct device, struct net_device_stats, dev_queue_xmit() and other headers */
#include <linux/etherdevice.h>  /* eth_type_trans */
#include <linux/ip.h>           /* struct iphdr */
#include <linux/skbuff.h>
#ifdef NET_26                   /* 2.6 kernels */
# include <net/xfrm.h>
#endif

#include <libreswan.h>

#include <net/icmp.h>           /* icmp_send() */
#include <net/ip.h>
#include <linux/netfilter_ipv4.h>

#include <linux/if_arp.h>

#include "libreswan/ipsec_kversion.h"
#include "libreswan/radij.h"
#include "libreswan/ipsec_life.h"
#include "libreswan/ipsec_xform.h"
#include "libreswan/ipsec_eroute.h"
#include "libreswan/ipsec_encap.h"
#include "libreswan/ipsec_radij.h"
#include "libreswan/ipsec_sa.h"
#include "libreswan/ipsec_xmit.h"
#include "libreswan/ipsec_mast.h"
#include "libreswan/ipsec_tunnel.h"
#include "libreswan/ipsec_ipe4.h"
#include "libreswan/ipsec_ah.h"
#include "libreswan/ipsec_esp.h"

#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include "libreswan/ipsec_proto.h"
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
# include <linux/udp.h>
#endif

int ipsec_mastdevice_count = -1;
int debug_mast;

static __u32 zeroes[64];

DEBUG_NO_STATIC int ipsec_mast_open(struct net_device *dev)
{
	struct mastpriv *prv = netdev_to_mastpriv(dev);

	prv = prv;

	/*
	 * Can't open until attached.
	 */

	KLIPS_PRINT(debug_mast & DB_MAST_INIT,
		    "klips_debug:ipsec_mast_open: "
		    "dev = %s\n",
		    dev->name);

	return 0;
}

DEBUG_NO_STATIC int ipsec_mast_close(struct net_device *dev)
{
	return 0;
}

static inline int ipsec_mast_xmit2(struct sk_buff *skb)
{
#ifdef NET_26   /* 2.6 kernels */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	return dst_output(dev_net(skb->dev), skb->sk, skb);
#else
	return dst_output(skb);
#endif

#else
	return ip_send(skb);

#endif
}

#ifdef CONFIG_INET_IPSEC_SAREF
static int klips_set_ipc_saref(struct ipcm_cookie *ipc,
			       xfrm_sec_unique_t ref)
{
	struct ipsec_sa *sa1;
	struct sec_path *sp;

	sp = secpath_dup(NULL);
	if (!sp)
		return -EINVAL;

	sp->ref = ref;
	KLIPS_PRINT(debug_mast, "klips_debug:klips_set_ipc_saref: "
		    "sending with saref=%u\n", sp->ref);

	sa1 = ipsec_sa_getbyref(sp->ref, IPSEC_REFOTHER);
	if (sa1 && sa1->ips_out) {
		ipc->oif = sa1->ips_out->ifindex;
		KLIPS_PRINT(debug_mast, "klips_debug:klips_set_ipc_saref: "
			    "setting oif: %d\n", ipc->oif);
	}
	ipsec_sa_put(sa1, IPSEC_REFOTHER);

	ipc->sp  = sp;

	return 0;
}

static void klips_get_secpath_refs(struct sec_path *sp,
				   xfrm_sec_unique_t *refme,
				   xfrm_sec_unique_t *refhim)
{
	struct ipsec_sa *sa1;

	if (sp == NULL)
		return;

	KLIPS_PRINT(debug_rcv, "klips_debug:klips_get_secpath_refs: "
		    "retrieving saref=%u from sp=%p\n",
		    sp->ref, sp);

	*refme = sp->ref;

	sa1 = ipsec_sa_getbyref(sp->ref, IPSEC_REFOTHER);
	*refhim = sa1 ? sa1->ips_refhim : 0;

	if (sa1)
		ipsec_sa_put(sa1, IPSEC_REFOTHER);
}

static struct ipsec_secpath_saref_ops klips_saref_ops = {
	.set_ipc_saref = klips_set_ipc_saref,
	.get_secpath_sarefs = klips_get_secpath_refs,
};

int ipsec_mast_init_saref(void)
{
	return register_ipsec_secpath_saref_ops(&klips_saref_ops);
}
void ipsec_mast_cleanup_saref(void)
{
	unregister_ipsec_secpath_saref_ops(&klips_saref_ops);
}
#endif

#if 0
/* Paul: This seems to be unused dead code */
enum ipsec_xmit_value ipsec_mast_send(struct ipsec_xmit_state *ixs)
{
	/* new route/dst cache code from James Morris */
	ixs->skb->dev = ixs->physdev;
	/*skb_orphan(ixs->skb);*/
	if ((ixs->error = ip_route_output(&ixs->route,
					  ixs->skb->nh.iph->daddr,
					  ixs->pass ? 0 : ixs->skb->nh.iph->
					  saddr,
					  RT_TOS(ixs->skb->nh.iph->tos),
					  ixs->physdev->ifindex /* rgb: should this be 0? */)))
	{
		ixs->stats->tx_errors++;
		KLIPS_PRINT(debug_mast & DB_MAST_XMIT,
			    "klips_debug:ipsec_mast_send: "
			    "ip_route_output failed with error code %d, dropped\n",
			    ixs->error);
		return IPSEC_XMIT_ROUTEERR;
	}
	if (ixs->dev == ixs->route->u.dst.dev) {
		ip_rt_put(ixs->route);
		/* This is recursion, drop it. */
		ixs->stats->tx_errors++;
		KLIPS_PRINT(debug_mast & DB_MAST_XMIT,
			    "klips_debug:ipsec_mast_send: "
			    "suspect recursion, dev=rt->u.dst.dev=%s, dropped\n",
			    ixs->dev->name);
		return IPSEC_XMIT_RECURSDETECT;
	}
	dst_release(skb_dst(ixs->skb));
	skb_dst_set(ixs->skb, &ixs->route->u.dst);
	ixs->stats->tx_bytes += ixs->skb->len;
	if (ixs->skb->len < ixs->skb->nh.raw - ixs->skb->data) {
		ixs->stats->tx_errors++;
		printk(KERN_WARNING
		       "klips_error:ipsec_mast_send: "
		       "tried to __skb_pull nh-data=%ld, %d available.  This should never happen, please report.\n",
		       (unsigned long)(ixs->skb->nh.raw - ixs->skb->data),
		       ixs->skb->len);
		return IPSEC_XMIT_PUSHPULLERR;
	}
	__skb_pull(ixs->skb, ixs->skb->nh.raw - ixs->skb->data);

	ipsec_nf_reset(ixs->skb);

	KLIPS_PRINT(debug_mast & DB_MAST_XMIT,
		    "klips_debug:ipsec_mast_send: "
		    "...done, calling ip_send() on device:%s\n",
		    ixs->skb->dev ? ixs->skb->dev->name : "NULL");
	KLIPS_IP_PRINT(debug_mast & DB_MAST_XMIT, ixs->skb->nh.iph);
	{
		int err;

		err = NF_HOOK(PF_INET, LSW_NF_INET_LOCAL_OUT, ixs->skb, NULL,
			      ixs->route->u.dst.dev,
			      ipsec_mast_xmit2);
		if (err != NET_XMIT_SUCCESS && err != NET_XMIT_CN) {
			if (net_ratelimit())
				printk(KERN_ERR
				       "klips_error:ipsec_mast_send: "
				       "ip_send() failed, err=%d\n",
				       -err);
			ixs->stats->tx_errors++;
			ixs->stats->tx_aborted_errors++;
			ixs->skb = NULL;
			return IPSEC_XMIT_IPSENDFAILURE;
		}
	}
	ixs->stats->tx_packets++;
	ixs->skb = NULL;

	return IPSEC_XMIT_OK;
}
#endif

static void ipsec_mast_xsm_complete(struct ipsec_xmit_state *ixs,
				    enum ipsec_xmit_value stat)
{
	if (stat != IPSEC_XMIT_OK) {
		KLIPS_PRINT(debug_mast,
			    "klips_debug:ipsec_mast_xsm_complete: "
			    "ipsec_xsm failed: %d\n",
			    stat);
		goto cleanup;
	}

	/* do any final NAT-encapsulation */
	stat = ipsec_nat_encap(ixs);
	if (stat != IPSEC_XMIT_OK)
		goto cleanup;

	ipsec_xmit_send(ixs);

cleanup:
	ipsec_xmit_cleanup(ixs);

	if (ixs->ipsp) {
		ipsec_sa_put(ixs->ipsp, IPSEC_REFOTHER);
		ixs->ipsp = NULL;
	}
	if (ixs->skb) {
		ipsec_kfree_skb(ixs->skb);
		ixs->skb = NULL;
	}
	ipsec_xmit_state_delete(ixs);
}

/*
 * Verify that the skb can go out on this ipsp.
 * Return 0 if OK, error code otherwise.
 */
static int ipsec_mast_check_outbound_policy(struct ipsec_xmit_state *ixs)
{
	int failed_outbound_check = 0;
	struct ipsec_sa *ipsp = ixs->ipsp;

	if (!ixs || !ixs->ipsp || !ixs->iph)
		return -EFAULT;

	/* Note: "xor" (^) logically replaces "not equal"
	 * (!=) and "bitwise or" (|) logically replaces
	 * "boolean or" (||).  This is done to speed up
	 * execution by doing only bitwise operations and
	 * no branch operations */
	if (lsw_ip_hdr_version(ixs) == 4) {
		struct iphdr *ipp = lsw_ip4_hdr(ixs);
		if (ip_address_family(&ipsp->ips_said.dst) != AF_INET)
			failed_outbound_check = 1;
		else if (((ipp->saddr &
			   ipsp->ips_mask_s.u.v4.sin_addr.s_addr) ^
			  ipsp->ips_flow_s.u.v4.sin_addr.s_addr) |
			 ((ipp->daddr &
			   ipsp->ips_mask_d.u.v4.sin_addr.s_addr) ^
			  ipsp->ips_flow_d.u.v4.sin_addr.s_addr))
			failed_outbound_check = 1;
	} else if (lsw_ip_hdr_version(ixs) == 6) {
		struct ipv6hdr *ipp6 = lsw_ip6_hdr(ixs);
		if (ip_address_family(&ipsp->ips_said.dst) != AF_INET6)
			failed_outbound_check = 1;
		else if (((ipp6->saddr.s6_addr32[0] &
			   ipsp->ips_mask_s.u.v6.sin6_addr.s6_addr32[0]) ^
			  ipsp->ips_flow_s.u.v6.sin6_addr.s6_addr32[0]) |
			 ((ipp6->daddr.s6_addr32[0] &
			   ipsp->ips_mask_d.u.v6.sin6_addr.s6_addr32[0]) ^
			  ipsp->ips_flow_d.u.v6.sin6_addr.s6_addr32[0]))
			failed_outbound_check = 1;
		else if (((ipp6->saddr.s6_addr32[1] &
			   ipsp->ips_mask_s.u.v6.sin6_addr.s6_addr32[1]) ^
			  ipsp->ips_flow_s.u.v6.sin6_addr.s6_addr32[1]) |
			 ((ipp6->daddr.s6_addr32[1] &
			   ipsp->ips_mask_d.u.v6.sin6_addr.s6_addr32[1]) ^
			  ipsp->ips_flow_d.u.v6.sin6_addr.s6_addr32[1]))
			failed_outbound_check = 1;
		else if (((ipp6->saddr.s6_addr32[2] &
			   ipsp->ips_mask_s.u.v6.sin6_addr.s6_addr32[2]) ^
			  ipsp->ips_flow_s.u.v6.sin6_addr.s6_addr32[2]) |
			 ((ipp6->daddr.s6_addr32[2] &
			   ipsp->ips_mask_d.u.v6.sin6_addr.s6_addr32[2]) ^
			  ipsp->ips_flow_d.u.v6.sin6_addr.s6_addr32[2]))
			failed_outbound_check = 1;
		else if (((ipp6->saddr.s6_addr32[3] &
			   ipsp->ips_mask_s.u.v6.sin6_addr.s6_addr32[3]) ^
			  ipsp->ips_flow_s.u.v6.sin6_addr.s6_addr32[3]) |
			 ((ipp6->daddr.s6_addr32[3] &
			   ipsp->ips_mask_d.u.v6.sin6_addr.s6_addr32[3]) ^
			  ipsp->ips_flow_d.u.v6.sin6_addr.s6_addr32[3]))
			failed_outbound_check = 1;
	}
	if (failed_outbound_check) {
		char saddr_txt[ADDRTOA_BUF], daddr_txt[ADDRTOA_BUF];
		char sflow_txt[SUBNETTOA_BUF], dflow_txt[SUBNETTOA_BUF];

		if (ipsp->ips_flow_s.u.v4.sin_family == AF_INET6) {
			subnet6toa(&ipsp->ips_flow_s.u.v6.sin6_addr,
				   &ipsp->ips_mask_s.u.v6.sin6_addr,
				   0, sflow_txt, sizeof(sflow_txt));
			subnet6toa(&ipsp->ips_flow_d.u.v6.sin6_addr,
				   &ipsp->ips_mask_d.u.v6.sin6_addr,
				   0, dflow_txt, sizeof(dflow_txt));
			inet_addrtot(AF_INET6,
				     &lsw_ip6_hdr(ixs)->saddr, 0, saddr_txt,
				     sizeof(saddr_txt));
			inet_addrtot(AF_INET6,
				     &lsw_ip6_hdr(ixs)->daddr, 0, daddr_txt,
				     sizeof(daddr_txt));
		} else {
			subnettoa(ipsp->ips_flow_s.u.v4.sin_addr,
				  ipsp->ips_mask_s.u.v4.sin_addr,
				  0, sflow_txt, sizeof(sflow_txt));
			subnettoa(ipsp->ips_flow_d.u.v4.sin_addr,
				  ipsp->ips_mask_d.u.v4.sin_addr,
				  0, dflow_txt, sizeof(dflow_txt));
			inet_addrtot(AF_INET,
				     &lsw_ip4_hdr(ixs)->saddr, 0, saddr_txt,
				     sizeof(saddr_txt));
			inet_addrtot(AF_INET,
				     &lsw_ip4_hdr(ixs)->daddr, 0, daddr_txt,
				     sizeof(daddr_txt));
		}

		if (!ixs->sa_len) {
			ixs->sa_len = KLIPS_SATOT(debug_mast,
						  &ixs->outgoing_said, 0,
						  ixs->sa_txt,
						  sizeof(ixs->sa_txt));
		}

		KLIPS_PRINT(debug_mast,
			    "klips_debug:ipsec_mast_check_outbound_policy: "
			    "SA:%s, inner tunnel policy [%s -> %s] does not agree with pkt contents [%s -> %s].\n",
			    ixs->sa_len ? ixs->sa_txt : " (error)",
			    sflow_txt, dflow_txt, saddr_txt, daddr_txt);
		if (ixs->stats)
			ixs->stats->rx_dropped++;
		return -EACCES;
	}

#if 0
	{
		char sflow_txt[SUBNETTOA_BUF], dflow_txt[SUBNETTOA_BUF];
		char saddr_txt[ADDRTOA_BUF], daddr_txt[ADDRTOA_BUF];
		struct in_addr ipaddr;

		subnettoa(ixs->ipsp->ips_flow_s.u.v4.sin_addr,
			  ixs->ipsp->ips_mask_s.u.v4.sin_addr,
			  0, sflow_txt, sizeof(sflow_txt));
		subnettoa(ixs->ipsp->ips_flow_d.u.v4.sin_addr,
			  ixs->ipsp->ips_mask_d.u.v4.sin_addr,
			  0, dflow_txt, sizeof(dflow_txt));

		ipaddr.s_addr = ixs->iph->saddr;
		addrtoa(ipaddr, 0, saddr_txt, sizeof(saddr_txt));
		ipaddr.s_addr = ixs->iph->daddr;
		addrtoa(ipaddr, 0, daddr_txt, sizeof(daddr_txt));

		if (!ixs->sa_len)
			ixs->sa_len = KLIPS_SATOT(debug_mast,
						  &ixs->outgoing_said, 0,
						  ixs->sa_txt,
						  sizeof(ixs->sa_txt));

		KLIPS_PRINT(debug_mast,
			    "klips_debug:ipsec_mast_check_outbound_policy: "
			    "SA:%s, inner tunnel policy [%s -> %s] agrees with pkt contents [%s -> %s].\n",
			    ixs->sa_len ? ixs->sa_txt : " (error)",
			    sflow_txt, dflow_txt, saddr_txt, daddr_txt);
	}
#endif

	return 0;
}

/*
 *	This function assumes it is being called from dev_queue_xmit()
 *	and that skb is filled properly by that function.
 */
int ipsec_mast_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ipsec_xmit_state *ixs;
	IPsecSAref_t SAref;

	KLIPS_PRINT(debug_mast, "klips_debug:ipsec_mast_start_xmit: skb=%p\n",
		    skb);
	if (skb == NULL) {
		printk("ipsec_mast_start_xmit: "
		       "passed NULL\n");
		return 0;
	}

	ixs = ipsec_xmit_state_new(dev);
	if (ixs == NULL)
		return NETDEV_TX_BUSY;

	ixs->dev = dev;
	ixs->skb = skb;
	SAref = 0;
#ifdef NET_26
# if defined(CONFIG_NETFILTER)
	if (skb->nfmark & IPSEC_NFMARK_IS_SAREF_BIT) {
		SAref = NFmark2IPsecSAref(skb->nfmark);
		KLIPS_PRINT(debug_mast, "klips_debug:ipsec_mast_start_xmit: "
			    "getting SAref=%d from nfmark\n",
			    SAref);
	}
# endif
#endif

#ifdef CONFIG_INET_IPSEC_SAREF
	if (skb->sp && skb->sp->ref != IPSEC_SAREF_NULL) {
		SAref = skb->sp->ref;
		KLIPS_PRINT(debug_mast, "klips_debug:ipsec_mast_start_xmit: "
			    "getting SAref=%d from sec_path\n",
			    SAref);
	}
#endif

	if (ipsec_xmit_sanity_check_mast_dev(ixs) != IPSEC_XMIT_OK) {
		ipsec_xmit_cleanup(ixs);
		ipsec_xmit_state_delete(ixs);
		return 0;
	}

	if (ipsec_xmit_sanity_check_skb(ixs) != IPSEC_XMIT_OK) {
		ipsec_xmit_cleanup(ixs);
		ipsec_xmit_state_delete(ixs);
		return 0;
	}

	ixs->ipsp = ipsec_sa_getbyref(SAref, IPSEC_REFOTHER);
	if (ixs->ipsp == NULL) {
		KLIPS_ERROR(debug_mast, "klips_debug:ipsec_mast_start_xmit: "
			    "%s: no SA for saref=%d\n",
			    dev->name, SAref);
		ipsec_xmit_cleanup(ixs);
		ipsec_xmit_state_delete(ixs);
		return 0;
	}

	/* make sure this packet can go out on this SA */
	if (ipsec_mast_check_outbound_policy(ixs)) {
		ipsec_xmit_cleanup(ixs);
		ipsec_xmit_state_delete(ixs);
		return 0;
	}

	/* fill in outgoing_said using the ipsp we have */
	ixs->outgoing_said = ixs->ipsp->ips_said;

#ifdef NET_26
# if defined(CONFIG_NETFILTER)
	/* prevent recursion through the saref route */
	if (skb->nfmark & 0x80000000)
		skb->nfmark = 0;

# endif
#endif
#if 0
	/* TODO: do we have to also have to do this? */
	if (skb->sp && skb->sp->ref != IPSEC_SAREF_NULL) {
		secpath_put(skb->sp);
		skb->sp = NULL;
	}
#endif

	ixs->mast_mode = 1;
	ixs->xsm_complete = ipsec_mast_xsm_complete;
	ixs->state = IPSEC_XSM_INIT2;   /* we start later in the process */

	ipsec_xsm(ixs);
	return 0;

}

DEBUG_NO_STATIC struct net_device_stats *ipsec_mast_get_stats(
	struct net_device *dev)
{
	return &(netdev_to_mastpriv(dev)->mystats);
}

#if 0
/*
 * Revectored calls.
 * For each of these calls, a field exists in our private structure.
 */
DEBUG_NO_STATIC int ipsec_mast_hard_header(struct sk_buff *skb,
					   struct net_device *dev,
					   unsigned short type, void *daddr,
					   void *saddr, unsigned len)
{
	struct mastpriv *mprv = netdev_to_mastpriv(dev);
	struct net_device_stats *stats; /* This device's statistics */
	int ret = 0;

	if (skb == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_hard_header: "
			    "no skb...\n");
		return -ENODATA;
	}

	if (dev == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_hard_header: "
			    "no device...\n");
		return -ENODEV;
	}

	KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
		    "klips_debug:ipsec_mast_hard_header: "
		    "skb->dev=%s\n",
		    dev->name);

	if (prv == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_hard_header: "
			    "no private space associated with dev=%s\n",
			    dev->name ? dev->name : "NULL");
		return -ENODEV;
	}

	stats = (struct net_device_stats *) &(prv->mystats);

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
		if (!prv->hard_header) {
			KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
				    "klips_debug:ipsec_mast_hard_header: "
				    "physical device has been detached, packet dropped 0p%p->0p%p len=%d type=%d dev=%s->NULL ",
				    saddr,
				    daddr,
				    len,
				    type,
				    dev->name);
			KLIPS_PRINTMORE(debug_mast & DB_MAST_REVEC,
					"ip=%08x->%08x\n",
					(__u32)ntohl(skb->nh.iph->saddr),
					(__u32)ntohl(skb->nh.iph->daddr) );
			stats->tx_dropped++;
			return -ENODEV;
		}
	} else {
		KLIPS_PRINT(debug_mast,
			    "klips_debug:ipsec_mast_hard_header: "
			    "is IPv6 packet, skip debugging messages, only revector and build linklocal header.\n");
	}

	return ret;
}

DEBUG_NO_STATIC int ipsec_mast_rebuild_header(struct sk_buff *skb)
{
	struct mastpriv *prv = netdev_to_mastpriv(skb->dev);

	prv = prv;
	return 0;
}

DEBUG_NO_STATIC int ipsec_mast_set_mac_address(struct net_device *dev,
					       void *addr)
{
	struct mastpriv *prv = netdev_to_mastpriv(dev);

	prv = prv;
	return 0;

}

DEBUG_NO_STATIC void ipsec_mast_cache_update(struct hh_cache *hh,
					     struct net_device *dev,
					     unsigned char *  haddr)
{
	struct mastpriv *prv = netdev_to_mastpriv(dev);

	if (dev == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_cache_update: "
			    "no device...");
		return;
	}

	if (prv == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_cache_update: "
			    "no private space associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		return;
	}

	KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
		    "klips_debug:ipsec_mast: "
		    "Revectored cache_update\n");
}
#endif

DEBUG_NO_STATIC int ipsec_mast_neigh_setup(struct neighbour *n)
{
	KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
		    "klips_debug:ipsec_mast_neigh_setup:\n");

	if (n->nud_state == NUD_NONE) {
#ifndef PRIVATE_ARP_BROKEN_OPS
		n->ops = &arp_broken_ops;
#endif
		n->output = n->ops->output;
	}
	return 0;
}

DEBUG_NO_STATIC int ipsec_mast_neigh_setup_dev(struct net_device *dev,
					       struct neigh_parms *p)
{
	KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
		    "klips_debug:ipsec_mast_neigh_setup_dev: "
		    "setting up %s\n",
		    dev ? dev->name : "NULL");

	if (p->tbl->family == AF_INET) {
		p->neigh_setup = ipsec_mast_neigh_setup;
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

DEBUG_NO_STATIC int ipsec_mast_ioctl(struct net_device *dev, struct ifreq *ifr,
				     int cmd)
{
	/* struct ipsecmastconf *cf = (struct ipsecmastconf *)&ifr->ifr_data;*/
	/* overlay our struct ipsecmast onto ifr.ifr_ifru union (hope it fits!) */
	struct ipsecmastconf *cf =
		(struct ipsecmastconf *)ifr->ifr_ifru.ifru_newname;
	struct mastpriv *mprv = netdev_to_mastpriv(dev);

	cf = cf;
	mprv = mprv;

	if (dev == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_ioctl: "
			    "device not supplied.\n");
		return -ENODEV;
	}

	KLIPS_PRINT(debug_mast & DB_MAST_INIT,
		    "klips_debug:ipsec_mast_ioctl: "
		    "tncfg service call #%d for dev=%s\n",
		    cmd,
		    dev->name ? dev->name : "NULL");

	switch (cmd) {
	default:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_ioctl: "
			    "unknown command %d.\n",
			    cmd);
		return -EOPNOTSUPP;
	}
}

int ipsec_mast_device_event(struct notifier_block *unused, unsigned long event,
			    void *ptr)
{
	struct net_device *dev = ptr;
	struct mastpriv *priv = netdev_to_mastpriv(dev);

	priv = priv;

	if (dev == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_device_event: "
			    "dev=NULL for event type %ld.\n",
			    event);
		return NOTIFY_DONE;
	}

	/* check for loopback devices */
	if (dev && (dev->flags & IFF_LOOPBACK))
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_DOWN:
	/* look very carefully at the scope of these compiler
	   directives before changing anything... -- RGB */

	case NETDEV_UNREGISTER:
		switch (event) {
		case NETDEV_DOWN:
			KLIPS_PRINT(debug_mast & DB_MAST_INIT,
				    "klips_debug:ipsec_mast_device_event: "
				    "NETDEV_DOWN dev=%s flags=%x\n",
				    dev->name,
				    dev->flags);
			if (strncmp(dev->name, "ipsec",
				    strlen("ipsec")) == 0) {
				printk(KERN_CRIT "IPSEC EVENT: KLIPS device %s shut down.\n",
					dev->name);
			}
			break;
		case NETDEV_UNREGISTER:
			KLIPS_PRINT(debug_mast & DB_MAST_INIT,
				    "klips_debug:ipsec_mast_device_event: "
				    "NETDEV_UNREGISTER dev=%s flags=%x\n",
				    dev->name,
				    dev->flags);
			break;
		}
		break;

	case NETDEV_UP:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_device_event: "
			    "NETDEV_UP dev=%s\n",
			    dev->name);
		break;

	case NETDEV_REBOOT:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_device_event: "
			    "NETDEV_REBOOT dev=%s\n",
			    dev->name);
		break;

	case NETDEV_CHANGE:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_device_event: "
			    "NETDEV_CHANGE dev=%s flags=%x\n",
			    dev->name,
			    dev->flags);
		break;

	case NETDEV_REGISTER:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_device_event: "
			    "NETDEV_REGISTER dev=%s\n",
			    dev->name);
		break;

	case NETDEV_CHANGEMTU:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_device_event: "
			    "NETDEV_CHANGEMTU dev=%s to mtu=%d\n",
			    dev->name,
			    dev->mtu);
		break;

	case NETDEV_CHANGEADDR:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_device_event: "
			    "NETDEV_CHANGEADDR dev=%s\n",
			    dev->name);
		break;

	case NETDEV_GOING_DOWN:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_device_event: "
			    "NETDEV_GOING_DOWN dev=%s\n",
			    dev->name);
		break;

	case NETDEV_CHANGENAME:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_device_event: "
			    "NETDEV_CHANGENAME dev=%s\n",
			    dev->name);
		break;

	default:
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_device_event: "
			    "event type %ld unrecognised for dev=%s\n",
			    event,
			    dev->name);
		break;
	}
	return NOTIFY_DONE;
}

/*
 *	Called when an ipsec mast device is initialized.
 *	The ipsec mast device structure is passed to us.
 */
int ipsec_mast_probe(struct net_device *dev)
{
	int i;
	struct mastpriv *mprv;

	KLIPS_PRINT(debug_mast,
		    "klips_debug:ipsec_mast_probe: "
		    "allocating %lu bytes initialising device: %s\n",
		    (unsigned long) sizeof(struct mastpriv),
		    dev->name ? dev->name : "NULL");

#ifndef USE_NETDEV_OPS
	/* Add our mast functions to the device */
	dev->open               = ipsec_mast_open;
	dev->stop               = ipsec_mast_close;
	dev->hard_start_xmit    = ipsec_mast_start_xmit;
	dev->get_stats          = ipsec_mast_get_stats;
	dev->set_multicast_list = NULL;
	dev->do_ioctl           = ipsec_mast_ioctl;
	dev->set_mac_address    = NULL;
	dev->neigh_setup        = ipsec_mast_neigh_setup_dev;
#endif
#ifdef ipsec_alloc_netdev
	dev->destructor         = free_netdev;
#endif

#ifndef ipsec_alloc_netdev
	dev->priv = kmalloc(sizeof(struct mastpriv), GFP_KERNEL);
	if (dev->priv == NULL)
		return -ENOMEM;

#endif
	mprv = netdev_priv(dev);
	memset(mprv, 0, sizeof(struct mastpriv));
	mprv->magic = MASTPRIV_MAGIC;

	for (i = 0; i < sizeof(zeroes); i++)
		((__u8*)(zeroes))[i] = 0;

#ifdef HAVE_NETDEV_HEADER_OPS
	dev->header_ops = NULL;
#else
	dev->hard_header        = NULL;
	dev->rebuild_header     = NULL;
	dev->header_cache_update = NULL;
#endif
	dev->hard_header_len    = 8 + 20 + 20 + 8;
	dev->mtu                = 0;
	dev->addr_len           = 0;
	dev->type               = ARPHRD_NONE;
	dev->tx_queue_len       = 10;
#ifdef IFF_XMIT_DST_RELEASE
	dev->priv_flags        &= ~IFF_XMIT_DST_RELEASE;
#endif
	memset((caddr_t)(dev->broadcast), 0xFF, ETH_ALEN);       /* what if this is not attached to ethernet? */

	/* New-style flags. */
	dev->flags              = IFF_NOARP;

	/* pick a random ethernet address for now. */
	random_ether_addr(dev->dev_addr);

	/* We're done.  Have I forgotten anything? */
	return 0;
}

#ifdef ipsec_alloc_netdev
static void ipsec_mast_netdev_setup(struct net_device *dev)
{
}
#endif
struct net_device *mastdevices[IPSEC_NUM_IFMAX];
int mastdevices_max = -1;

#ifdef USE_NETDEV_OPS
static const struct net_device_ops ipsec_mast_ops = {
	.ndo_init               = ipsec_mast_probe,
	.ndo_open               = ipsec_mast_open,
	.ndo_stop               = ipsec_mast_close,
	.ndo_start_xmit         = ipsec_mast_start_xmit,
	.ndo_get_stats          = ipsec_mast_get_stats,
	.ndo_do_ioctl           = ipsec_mast_ioctl,
	.ndo_neigh_setup        = ipsec_mast_neigh_setup_dev,
};
#endif

int ipsec_mast_createnum(int vifnum)
{
	struct net_device *im;
	int vifentry;
	char name[IFNAMSIZ];

	if (vifnum >= IPSEC_NUM_IFMAX)
		return -ENOENT;

	if (mastdevices[vifnum] != NULL)
		return -EEXIST;

	/* no identical device */
	if (vifnum > mastdevices_max)
		mastdevices_max = vifnum;
	vifentry = vifnum;

	snprintf(name, IFNAMSIZ, MAST_DEV_FORMAT, vifnum);

#ifdef ipsec_alloc_netdev
	im = ipsec_alloc_netdev(sizeof(struct mastpriv), name,
			  NET_NAME_UNKNOWN, ipsec_mast_netdev_setup);
#else
	im = (struct net_device *)kmalloc(sizeof(struct net_device),
					  GFP_KERNEL);
#endif
	if (im == NULL) {
		printk(KERN_ERR "failed to allocate space for mast%d device\n",
		       vifnum);
		return -ENOMEM;
	}

#ifndef ipsec_alloc_netdev
	memset((caddr_t)im, 0, sizeof(struct net_device));
	memcpy(im->name, name, IFNAMSIZ);
#endif

#ifdef USE_NETDEV_OPS
	im->netdev_ops = &ipsec_mast_ops;
#else
	im->init = ipsec_mast_probe;
#endif

	if (register_netdev(im) != 0) {
		printk(KERN_ERR "ipsec_mast: failed to register %s\n",
		       im->name);
		return -EIO;
	}

	ipsec_dev_hold(im);
	mastdevices[vifentry] = im;

	return 0;
}

int ipsec_mast_deletenum(int vifnum)
{
	struct net_device *dev_ipsec;

	if (vifnum >= IPSEC_NUM_IFMAX)
		return -ENOENT;

	dev_ipsec = mastdevices[vifnum];
	if (dev_ipsec == NULL)
		return -ENOENT;

	/* release reference */
	mastdevices[vifnum] = NULL;
	ipsec_dev_put(dev_ipsec);

	KLIPS_PRINT(debug_tunnel, "Unregistering %s\n", dev_ipsec->name);
	unregister_netdev(dev_ipsec);
	KLIPS_PRINT(debug_tunnel, "Unregisted %s\n", dev_ipsec->name);
#ifndef ipsec_alloc_netdev
	kfree(dev_ipsec->priv);
	dev_ipsec->priv = NULL;
#endif

	return 0;
}

struct net_device *ipsec_mast_get_device(int vifnum)
{
	int ovifnum = vifnum;

	if (vifnum > IPSECDEV_OFFSET) {
		return ipsec_tunnel_get_device(vifnum - IPSECDEV_OFFSET);
	} else {
		struct net_device *nd;

		if (vifnum >= MASTTRANSPORT_OFFSET)
			vifnum -= MASTTRANSPORT_OFFSET;

		if (vifnum <= mastdevices_max) {
			nd = mastdevices[vifnum];

			if (nd)
				ipsec_dev_hold(nd);
			return nd;
		} else {
			KLIPS_ERROR(debug_tunnel,
				    "no such vif %d (ovif=%d)\n", vifnum,
				    ovifnum);
			return NULL;
		}
	}
}

unsigned int ipsec_mast_is_transport(int vifnum)
{
	if (vifnum > MASTTRANSPORT_OFFSET && vifnum < IPSECDEV_OFFSET)
		return 1;

	return 0;
}

int ipsec_mast_init_devices(void)
{
	/*
	 * mast0 is used for transport mode stuff, and generally is
	 * the default unless the user decides to create more.
	 */
	ipsec_mast_createnum(0);

	return 0;
}

/* void */
int ipsec_mast_cleanup_devices(void)
{
	int error = 0;
	int i;
	struct net_device *dev_mast;

	for (i = 0; i <= mastdevices_max; i++) {
		if (mastdevices[i] != NULL) {
			dev_mast = mastdevices[i];
			mastdevices[i] = NULL;
			ipsec_dev_put(dev_mast);
			unregister_netdev(dev_mast);
#ifndef ipsec_alloc_netdev
			kfree(dev_mast->priv);
			dev_mast->priv = NULL;
#endif
		}
	}
	return error;
}
