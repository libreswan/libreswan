/*
 * IPSEC MAST code.
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
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

char ipsec_mast_c_version[] = "RCSID $Id: ipsec_mast.c,v 1.7 2005/04/29 05:10:22 mcr Exp $";

#define __NO_VERSION__
#include <linux/module.h>
#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif	/* for CONFIG_IP_FORWARD */
#include <linux/version.h>
#include <linux/kernel.h> /* printk() */

#include "openswan/ipsec_param.h"

#ifdef MALLOC_SLAB
# include <linux/slab.h> /* kmalloc() */
#else /* MALLOC_SLAB */
# include <linux/malloc.h> /* kmalloc() */
#endif /* MALLOC_SLAB */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */

#include <net/arp.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/skbuff.h>

#include <linux/netdevice.h>   /* struct device, struct net_device_stats, dev_queue_xmit() and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/skbuff.h>
#include <net/xfrm.h>

#include <openswan.h>

#include <net/icmp.h>		/* icmp_send() */
#include <net/ip.h>
#ifdef NETDEV_23
# include <linux/netfilter_ipv4.h>
#endif /* NETDEV_23 */

#include <linux/if_arp.h>

#include "openswan/ipsec_kversion.h"
#include "openswan/radij.h"
#include "openswan/ipsec_life.h"
#include "openswan/ipsec_xform.h"
#include "openswan/ipsec_eroute.h"
#include "openswan/ipsec_encap.h"
#include "openswan/ipsec_radij.h"
#include "openswan/ipsec_sa.h"
#include "openswan/ipsec_xmit.h"
#include "openswan/ipsec_mast.h"
#include "openswan/ipsec_tunnel.h"
#include "openswan/ipsec_ipe4.h"
#include "openswan/ipsec_ah.h"
#include "openswan/ipsec_esp.h"
#include "openswan/ipsec_kern24.h"

#include <openswan/pfkeyv2.h>
#include <openswan/pfkey.h>

#include "openswan/ipsec_proto.h"
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
#include <linux/udp.h>
#endif

int ipsec_mastdevice_count = -1;
int debug_mast;

static __u32 zeroes[64];

DEBUG_NO_STATIC int
ipsec_mast_open(struct net_device *dev)
{
        struct mastpriv *prv = dev->priv; 

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

DEBUG_NO_STATIC int
ipsec_mast_close(struct net_device *dev)
{
	return 0;
}

static inline int ipsec_mast_xmit2(struct sk_buff *skb)
{
	return dst_output(skb);
}

int ip_cmsg_send_ipsec(struct cmsghdr *cmsg, struct ipcm_cookie *ipc)
{
	struct ipsec_sa *sa1;
	xfrm_sec_unique_t *ref;
	struct sec_path *sp;

	if(cmsg->cmsg_len != CMSG_LEN(sizeof(xfrm_sec_unique_t))) {
		return -EINVAL;
	}
	
	ref = (xfrm_sec_unique_t *)CMSG_DATA(cmsg);

	sp = secpath_dup(NULL);
	if(!sp) {
		return -EINVAL;
	}

	sp->ref = *ref;
	KLIPS_PRINT(debug_mast, "sending with saref=%u\n", sp->ref);
		
	sa1 = ipsec_sa_getbyref(sp->ref);
	if(sa1 && sa1->ips_out) {
		ipc->oif = sa1->ips_out->ifindex;
		KLIPS_PRINT(debug_mast, "setting oif: %d\n", ipc->oif);
	}
	ipsec_sa_put(sa1);
	
	ipc->sp  = sp;

	return 0;
}

#if 0
/* Paul: This seems to be unused dead code */
enum ipsec_xmit_value
ipsec_mast_send(struct ipsec_xmit_state*ixs)
{
	/* new route/dst cache code from James Morris */
	ixs->skb->dev = ixs->physdev;
	/*skb_orphan(ixs->skb);*/
	if((ixs->error = ip_route_output(&ixs->route,
				    ixs->skb->nh.iph->daddr,
				    ixs->pass ? 0 : ixs->skb->nh.iph->saddr,
				    RT_TOS(ixs->skb->nh.iph->tos),
				    ixs->physdev->ifindex /* rgb: should this be 0? */))) {
		ixs->stats->tx_errors++;
		KLIPS_PRINT(debug_mast & DB_MAST_XMIT,
			    "klips_debug:ipsec_xmit_send: "
			    "ip_route_output failed with error code %d, rt->u.dst.dev=%s, dropped\n",
			    ixs->error,
			    ixs->route->u.dst.dev->name);
		return IPSEC_XMIT_ROUTEERR;
	}
	if(ixs->dev == ixs->route->u.dst.dev) {
		ip_rt_put(ixs->route);
		/* This is recursion, drop it. */
		ixs->stats->tx_errors++;
		KLIPS_PRINT(debug_mast & DB_MAST_XMIT,
			    "klips_debug:ipsec_xmit_send: "
			    "suspect recursion, dev=rt->u.dst.dev=%s, dropped\n",
			    ixs->dev->name);
		return IPSEC_XMIT_RECURSDETECT;
	}
	dst_release(ixs->skb->dst);
	ixs->skb->dst = &ixs->route->u.dst;
	ixs->stats->tx_bytes += ixs->skb->len;
	if(ixs->skb->len < skb_network_header(ixs->skb) - ixs->skb->data) {
		ixs->stats->tx_errors++;
		printk(KERN_WARNING
		       "klips_error:ipsec_xmit_send: "
		       "tried to __skb_pull nh-data=%ld, %d available.  This should never happen, please report.\n",
		       (unsigned long)(skb_network_header(ixs->skb) - ixs->skb->data),
		       ixs->skb->len);
		return IPSEC_XMIT_PUSHPULLERR;
	}
	__skb_pull(ixs->skb, skb_network_header(ixs->skb)- ixs->skb->data);
#ifdef SKB_RESET_NFCT
	nf_conntrack_put(ixs->skb->nfct);
	ixs->skb->nfct = NULL;
#ifdef CONFIG_NETFILTER_DEBUG
	ixs->skb->nf_debug = 0;
#endif /* CONFIG_NETFILTER_DEBUG */
#endif /* SKB_RESET_NFCT */
	KLIPS_PRINT(debug_mast & DB_MAST_XMIT,
		    "klips_debug:ipsec_xmit_send: "
		    "...done, calling ip_send() on device:%s\n",
		    ixs->skb->dev ? ixs->skb->dev->name : "NULL");
	KLIPS_IP_PRINT(debug_mast & DB_MAST_XMIT, ixs->skb->nh.iph);
	{
		int err;

		err = NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, ixs->skb, NULL, ixs->route->u.dst.dev,
			      ipsec_mast_xmit2);
		if(err != NET_XMIT_SUCCESS && err != NET_XMIT_CN) {
			if(net_ratelimit())
				printk(KERN_ERR
				       "klips_error:ipsec_xmit_send: "
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

/*
 *	This function assumes it is being called from dev_queue_xmit()
 *	and that skb is filled properly by that function.
 */
int
ipsec_mast_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ipsec_xmit_state *ixs;
	enum ipsec_xmit_value stat = IPSEC_XMIT_OK;
	IPsecSAref_t SAref;

	if(skb == NULL) {
		printk("mast start_xmit passed NULL\n");
		return 0;
	}
		
	ixs = ipsec_xmit_state_new();
	if(ixs == NULL) {
		printk("mast failed to allocate IXS\n");
		return 0;
	}

	ixs->skb = skb;
	SAref = 0;
	if(skb->nfmark & 0x80000000) {
		SAref = NFmark2IPsecSAref(skb->nfmark);
		KLIPS_PRINT(debug_mast, "getting SAref=%d from nfmark\n",
			    SAref);
	}

	if(skb->sp && skb->sp->ref != IPSEC_SAREF_NULL) {
		SAref = skb->sp->ref;
		KLIPS_PRINT(debug_mast, "getting SAref=%d from sec_path\n",
			    SAref);
	}

	KLIPS_PRINT(debug_mast, "skb=%p\n", skb);

	ipsec_xmit_sanity_check_skb(ixs);

	ixs->ipsp = ipsec_sa_getbyref(SAref);
	if(ixs->ipsp == NULL) {
		KLIPS_ERROR(debug_mast, "%s: no SA for saref=%d (sp=%p)\n",
			    dev->name, SAref, skb->sp);
		ipsec_kfree_skb(skb);
		return 0;
	}

	/*
	 * we should be calculating the MTU by looking up a route
	 * based upon the destination in the SA, and then cache
	 * it into the SA, but we don't do that right now.
	 */
	ixs->cur_mtu = 1460;
	ixs->physmtu = 1460;

	stat = ipsec_xmit_encap_bundle_2(ixs);

	if(stat != IPSEC_XMIT_OK) {
		/* SA processing failed */
		/* log it somehow */
		goto failed;
	}

	/* do any final NAT-encapsulation */
	stat = ipsec_nat_encap(ixs);
	if(stat != IPSEC_XMIT_OK) {
		goto failed;
	}

	/* now send the packet again */
	{
		struct flowi fl;
		
		memset(&fl, 0, sizeof(fl));
		ipsec_xmit_send(ixs, &fl);
	}

failed:
	ipsec_xmit_cleanup(ixs);

	if(ixs->ipsp) {
		ipsec_sa_put(ixs->ipsp);
		ixs->ipsp=NULL;
	}
	if(ixs->skb) {
		ipsec_kfree_skb(ixs->skb);
		ixs->skb=NULL;
	}
	return 0;
}

DEBUG_NO_STATIC struct net_device_stats *
ipsec_mast_get_stats(struct net_device *dev)
{
	return &(((struct mastpriv *)(dev->priv))->mystats);
}

#if 0
/*
 * Revectored calls.
 * For each of these calls, a field exists in our private structure.
 */
DEBUG_NO_STATIC int
ipsec_mast_hard_header(struct sk_buff *skb, struct net_device *dev,
	unsigned short type, void *daddr, void *saddr, unsigned len)
{
	struct mastpriv *prv = dev->priv;
	struct net_device_stats *stats;	/* This device's statistics */
	int ret = 0;
	
	if(skb == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_hard_header: "
			    "no skb...\n");
		return -ENODATA;
	}

	if(dev == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_hard_header: "
			    "no device...\n");
		return -ENODEV;
	}

	KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
		    "klips_debug:ipsec_mast_hard_header: "
		    "skb->dev=%s\n",
		    dev->name);
	
	if(prv == NULL) {
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
	if(type != ETH_P_IPV6) {
		/* execute this only, if we don't have to build the
		   header for a IPv6 packet */
		if(!prv->hard_header) {
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

DEBUG_NO_STATIC int
ipsec_mast_rebuild_header(struct sk_buff *skb)
{
	struct mastpriv *prv = skb->dev->priv;

	prv = prv;
	return 0;
}

DEBUG_NO_STATIC int
ipsec_mast_set_mac_address(struct net_device *dev, void *addr)
{
	struct mastpriv *prv = dev->priv;
	
	prv = prv;
	return 0;

}

DEBUG_NO_STATIC void
ipsec_mast_cache_update(struct hh_cache *hh, struct net_device *dev, unsigned char *  haddr)
{
	struct mastpriv *prv = dev->priv;
	
	if(dev == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_cache_update: "
			    "no device...");
		return;
	}

	if(prv == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
			    "klips_debug:ipsec_mast_cache_update: "
			    "no private space associated with dev=%s",
			    dev->name ? dev->name : "NULL");
		return;
	}

	KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
		    "klips_debug:ipsec_mast: "
		    "Revectored cache_update\n");
	return;
}
#endif

DEBUG_NO_STATIC int
ipsec_mast_neigh_setup(struct neighbour *n)
{
	KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
		    "klips_debug:ipsec_mast_neigh_setup:\n");

        if (n->nud_state == NUD_NONE) {
                n->ops = &arp_broken_ops;
                n->output = n->ops->output;
        }
        return 0;
}

DEBUG_NO_STATIC int
ipsec_mast_neigh_setup_dev(struct net_device *dev, struct neigh_parms *p)
{
	KLIPS_PRINT(debug_mast & DB_MAST_REVEC,
		    "klips_debug:ipsec_mast_neigh_setup_dev: "
		    "setting up %s\n",
		    dev ? dev->name : "NULL");

        if (p->tbl->family == AF_INET) {
                p->neigh_setup = ipsec_mast_neigh_setup;
                p->ucast_probes = 0;
                p->mcast_probes = 0;
        }
        return 0;
}

DEBUG_NO_STATIC int
ipsec_mast_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct ipsecmastconf *cf = (struct ipsecmastconf *)&ifr->ifr_data;
	struct ipsecpriv *prv = dev->priv;

	cf = cf;
	prv=prv;
	
	if(dev == NULL) {
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

int
ipsec_mast_device_event(struct notifier_block *unused, unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;
	struct mastpriv *priv = dev->priv;

	priv = priv;

	if (dev == NULL) {
		KLIPS_PRINT(debug_mast & DB_MAST_INIT,
			    "klips_debug:ipsec_mast_device_event: "
			    "dev=NULL for event type %ld.\n",
			    event);
		return(NOTIFY_DONE);
	}

	/* check for loopback devices */
	if (dev && (dev->flags & IFF_LOOPBACK)) {
		return(NOTIFY_DONE);
	}

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
			if(strncmp(dev->name, "ipsec", strlen("ipsec")) == 0) {
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
int
ipsec_mast_probe(struct net_device *dev)
{
	int i;

	KLIPS_PRINT(debug_mast,
		    "klips_debug:ipsec_mast_init: "
		    "allocating %lu bytes initialising device: %s\n",
		    (unsigned long) sizeof(struct mastpriv),
		    dev->name ? dev->name : "NULL");

	/* Add our mast functions to the device */
	dev->open		= ipsec_mast_open;
	dev->stop		= ipsec_mast_close;
	dev->hard_start_xmit	= ipsec_mast_start_xmit;
	dev->get_stats		= ipsec_mast_get_stats;

	dev->priv = kmalloc(sizeof(struct mastpriv), GFP_KERNEL);
	if (dev->priv == NULL)
		return -ENOMEM;
	memset((caddr_t)(dev->priv), 0, sizeof(struct mastpriv));

	for(i = 0; i < sizeof(zeroes); i++) {
		((__u8*)(zeroes))[i] = 0;
	}
	
	dev->set_multicast_list = NULL;
	dev->do_ioctl		= ipsec_mast_ioctl;
	dev->hard_header	= NULL;
	dev->rebuild_header 	= NULL;
	dev->set_mac_address 	= NULL;
	dev->header_cache_update= NULL;
	dev->neigh_setup        = ipsec_mast_neigh_setup_dev;
	dev->hard_header_len 	= 8+20+20+8;
	dev->mtu		= 0;
	dev->addr_len		= 0;
	dev->type		= ARPHRD_NONE;
	dev->tx_queue_len	= 10;		
	memset((caddr_t)(dev->broadcast),0xFF, ETH_ALEN);	/* what if this is not attached to ethernet? */

	/* New-style flags. */
	dev->flags		= IFF_NOARP;

	/* We're done.  Have I forgotten anything? */
	return 0;
}

struct net_device *mastdevices[IPSEC_NUM_IFMAX];
int mastdevices_max=-1;

int ipsec_mast_createnum(int vifnum) 
{
	struct net_device *im;
	int vifentry;

	if(vifnum > IPSEC_NUM_IFMAX) {
		return -ENOENT;
	}

	if(mastdevices[vifnum]!=NULL) {
		return -EEXIST;
	}
	
	/* no identical device */
	if(vifnum > mastdevices_max) {
		mastdevices_max=vifnum;
	}
	vifentry = vifnum;
	
	im = (struct net_device *)kmalloc(sizeof(struct net_device),GFP_KERNEL);
	if(im == NULL) {
		printk(KERN_ERR "failed to allocate space for mast%d device\n", vifnum);
		return -ENOMEM;
	}
		
	memset((caddr_t)im, 0, sizeof(struct net_device));
	snprintf(im->name, IFNAMSIZ, MAST_DEV_FORMAT, vifnum);

#ifdef HAVE_NEXT_DEV
	im->next = NULL;
#endif
	im->init = ipsec_mast_probe;

	if(register_netdev(im) != 0) {
		printk(KERN_ERR "ipsec_mast: failed to register %s\n",
		       im->name);
		return -EIO;
	}

	dev_hold(im);
	mastdevices[vifentry]=im;

	return 0;
}


int
ipsec_mast_deletenum(int vifnum)
{
	struct net_device *dev_ipsec;
	
	if(vifnum > IPSEC_NUM_IFMAX) {
		return -ENOENT;
	}

	dev_ipsec = mastdevices[vifnum];
	if(dev_ipsec == NULL) {
		return -ENOENT;
	}

	/* release reference */
	mastdevices[vifnum]=NULL;
	ipsec_dev_put(dev_ipsec);
	
	KLIPS_PRINT(debug_tunnel, "Unregistering %s (refcnt=%d)\n",
		    dev_ipsec->name,
		    atomic_read(&dev_ipsec->refcnt));
	unregister_netdev(dev_ipsec);
	KLIPS_PRINT(debug_tunnel, "Unregisted %s\n", dev_ipsec->name);
#ifndef NETDEV_23
	kfree(dev_ipsec->name);
	dev_ipsec->name=NULL;
#endif /* !NETDEV_23 */
	kfree(dev_ipsec->priv);
	dev_ipsec->priv=NULL;

	return 0;
}


struct net_device *
ipsec_mast_get_device(int vifnum)
{
	int ovifnum = vifnum;

	if(vifnum > IPSECDEV_OFFSET) {
		return ipsec_tunnel_get_device(vifnum-IPSECDEV_OFFSET);
	} else {
		struct net_device *nd;
		
		if(vifnum >= MASTTRANSPORT_OFFSET) {
			vifnum -= MASTTRANSPORT_OFFSET;
		}

		if(vifnum <= mastdevices_max) {
			nd = mastdevices[vifnum];

			if(nd) dev_hold(nd);
			return nd;
		} else {
			KLIPS_ERROR(debug_tunnel,
				    "no such vif %d (ovif=%d)\n", vifnum, ovifnum);
			return NULL;
		}
	}
}

unsigned int
ipsec_mast_is_transport(int vifnum)
{
	if(vifnum > MASTTRANSPORT_OFFSET && vifnum <IPSECDEV_OFFSET) {
		return 1;
	}
	return 0;
}

int 
ipsec_mast_init_devices(void)
{
	/*
	 * mast0 is used for transport mode stuff, and generally is
	 * the default unless the user decides to create more.
	 */
	ipsec_mast_createnum(0);
  
	return 0;
}

/* void */
int
ipsec_mast_cleanup_devices(void)
{
	int error = 0;
	int i;
	struct net_device *dev_mast;
	
	for(i = 0; i <= mastdevices_max; i++) {
		if(mastdevices[i]!=NULL) {
			dev_mast = mastdevices[i];
			unregister_netdev(dev_mast);
			kfree(dev_mast->priv);
			dev_mast->priv=NULL;
			dev_put(mastdevices[i]);
			mastdevices[i]=NULL;
		}
	}
	return error;
}

/*
 *
 * Local Variables:
 * c-file-style: "linux"
 * End:
 *
 */


