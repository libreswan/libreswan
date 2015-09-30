/*

   Copyright (c) 2003,2004 Jeremy Kerr & Rusty Russell

   This file is part of nfsim.

   nfsim is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   nfsim is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with nfsim; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "ipv4.h"
#include "utils.h"
#include <core.h>
#include <field.h>

#if 0
#include <linux/netfilter_ipv4.h>
#endif

int route(struct sk_buff *skb);

LIST_HEAD(routes);

static struct notifier_block *inetaddr_chain;

static int __ip_route_output_key(struct rtable **rp, struct flowi *flp);

static int destroy_route(void *r)
{
	struct ipv4_route *route = r;

	list_del(&route->entry);
	return 0;
}

void add_route_for_device(struct in_device *indev)
{
	struct ipv4_route *route;

	route = talloc(indev, struct ipv4_route);
	talloc_set_destructor(route, destroy_route);
	route->netmask = indev->ifa_list->ifa_mask;
	route->network = indev->ifa_list->ifa_address &
			 indev->ifa_list->ifa_mask;
	route->interface = indev->dev;
	route->gateway = indev->ifa_list->ifa_address;
	list_add_tail(&route->entry, &routes);
}

struct rtable *rcache;
static int destroy_rtable(void *r)
{
	struct rtable *rt = r, **p;

	/* Remove from cache if it's there (it should be, currently) */
	for (p = &rcache; *p; p = &(*p)->u.rt_next) {
		if (*p == rt) {
			*p = rt->u.rt_next;
			break;
		}
	}
	return 0;
}

#if 0
/* need the following:
    - interfaces
    - routes
 */
static void init(void)
{
	/* name our hooks */
	nf_hooknames[PF_INET][0] = "NF_IP_PRE_ROUTING";
	nf_hooknames[PF_INET][1] = "NF_IP_LOCAL_IN";
	nf_hooknames[PF_INET][2] = "NF_IP_FORWARD";
	nf_hooknames[PF_INET][3] = "NF_IP_LOCAL_OUT";
	nf_hooknames[PF_INET][4] = "NF_IP_POST_ROUTING";
}

init_call(init);
#endif

int register_inetaddr_notifier(struct notifier_block *nb)
{
	return notifier_chain_register(&inetaddr_chain, nb);
}

int unregister_inetaddr_notifier(struct notifier_block *nb)
{
	return notifier_chain_unregister(&inetaddr_chain, nb);
}

int __call_inetaddr_notifier(unsigned long val, struct in_ifaddr *ifa)
{
	struct notifier_block *nb = inetaddr_chain;

	return notifier_call_chain(&nb, val, ifa);
}

#if 0
static int ip_rcv_finish(struct sk_buff *skb)
{
	if (!skb->dst &&
	    ip_route_input(skb, skb->nh.iph->daddr, skb->nh.iph->saddr,
			   skb->nh.iph->tos, skb->dev)) {
		kfree_skb(skb);
		return -1;
	}

	return dst_input(skb);
}
#endif

int ip_rcv(struct sk_buff *skb)
{
#if 0
	skb->dev->stats.rxpackets++;
	skb->dev->stats.rxbytes += skb->len;

	/* pull data to the start of the ip header */
	skb_pull(skb, skb->nh.raw - skb->data);

	log_packet(skb, "rcv:%s", skb->dev->name);

	return NF_HOOK(PF_INET, NF_IP_PRE_ROUTING, skb, skb->dev, NULL,
		       ip_rcv_finish);

#else
	return 0;

#endif
}

int ip_rcv_local(struct sk_buff *skb)
{
	struct rtable *rt;
	struct flowi fl;

	log_packet(skb, "rcv_local");

	/* pull data to the start of the ip header */
	skb_pull(skb, skb->nh.raw - skb->data);

	rt = (struct rtable *)skb->dst;
	if (rt)
		goto routed;

	memset(&fl, 0, sizeof(fl));

	fl.fl4_dst    = skb->nh.iph->daddr;
	fl.fl4_src    = skb->nh.iph->saddr;
	fl.fl4_tos    = skb->nh.iph->tos;
#ifdef CONFIG_IP_ROUTE_FWMARK
	fl.fl4_fwmark = skb->nfmark;
#endif

	if (__ip_route_output_key(&rt, &fl)) {
		log_route(skb, "no route");
		kfree_skb(skb);
		return 1;
	}

	skb->dst = (struct dst_entry *)rt;
	dst_hold(skb_dst);
routed:
	skb->dev = skb->dst->dev;
#if 0
	return NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, skb->dev,
		       dst_output);

#else
	return 0;

#endif
}

static int ip_local_deliver(struct sk_buff *skb)
{
#if 0
	return NF_HOOK(PF_INET, NF_IP_LOCAL_IN, skb, skb->dev, NULL,
		       nf_send_local);

#else
	return 0;

#endif
}

int ip_finish_output(struct sk_buff *skb)
{
	struct net_device *dev = skb->dst->dev;

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);
	/*
	   if (skb->mac.ethernet)
		skb->mac.ethernet->h_proto = skb->protocol;
	 */

#if 0
	return NF_HOOK(PF_INET, NF_IP_POST_ROUTING, skb, NULL, dev,
		       nf_send);

#else
	return 0;

#endif
}

static int ip_output(struct sk_buff *skb)
{
	/* FIXME: fragment? */
	return ip_finish_output(skb);
}

unsigned short ip_compute_csum(unsigned char * buff, int len)
{
	return csum_fold(csum_partial(buff, len, 0));
}

static int __ip_route_output_key(struct rtable **rp, struct flowi *flp)
{
	struct rtable *rth;
	struct net_device *dev;
	struct ipv4_route *route;

	if (should_i_fail(__func__))
		return -ENOMEM;

	/* check for a cached route */
	for (rth = rcache; rth; rth = rth->u.rt_next) {
		if (rth->fl.fl4_dst == flp->fl4_dst &&
		    rth->fl.fl4_src == flp->fl4_src &&
		    rth->fl.iif     == 0 &&
		    rth->fl.oif     == flp->oif &&
#ifdef CONFIG_IP_ROUTE_FWMARK
		    rth->fl.fl4_fwmark == flp->fl4_fwmark &&
#endif
		    rth->fl.fl4_tos == flp->fl4_tos) {
			dst_hold(&rth->u.dst) *
			rp = rth;
			return 0;
		}
	}

	list_for_each_entry(dev, &interfaces, entry) {
		struct in_ifaddr *ifaddr;

		if (!dev->ip_ptr)
			continue;

		ifaddr = ((struct in_device *)(dev->ip_ptr))->ifa_list;
		while (ifaddr) {
			if (flp->fl4_dst == ifaddr->ifa_local) {
				rth = talloc_zero(dev->ip_ptr, struct rtable);
				talloc_set_destructor(rth, destroy_rtable);

				rth->u.dst.output = ip_output;
				rth->u.dst.input  = ip_local_deliver;
				rth->u.dst.dev    = &loopback_dev;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
				rth->u.dst.pmtu   = 1500;
#endif
				rth->rt_src       = rth->fl.fl4_src =
							    flp->fl4_src;
				rth->rt_dst       = rth->fl.fl4_dst =
							    flp->fl4_dst;
				rth->rt_gateway   = flp->fl4_dst;
				rth->rt_iif       = rth->fl.iif = flp->iif;

				rth->fl.fl4_tos = flp->fl4_tos;
#ifdef CONFIG_IP_ROUTE_FWMARK
				rth->fl.fl4_fwmark = flp->fl4_fwmark;
#endif

				rth->u.rt_next = rcache;
				rcache = rth;

				*rp = rth;
				return 0;
			}
			ifaddr = ifaddr->ifa_next;
		}

	}

	/* otherwise, find the appropriate route & create an rcache entry */
	list_for_each_entry(route, &routes, entry) {
		if ((flp->fl4_dst & route->netmask) ==
		    route->network) {
			rth = talloc_zero(route, struct rtable);
			talloc_set_destructor(rth, destroy_rtable);

			rth->u.dst.dev    =  route->interface;
			rth->u.dst.output = ip_output;
			rth->u.dst.input  = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
			rth->u.dst.pmtu   = 1500;
#endif
			rth->rt_src       = rth->fl.fl4_src = flp->fl4_src;
			if (!rth->rt_src) {
				rth->rt_src =
					inet_select_addr(route->interface,
							 flp->fl4_dst,
							 RT_SCOPE_UNIVERSE);
			}
			rth->rt_dst       = rth->fl.fl4_dst = flp->fl4_dst;
			rth->rt_gateway   = route->gateway;
			rth->fl.oif       = route->interface->ifindex;
			rth->fl.oif = flp->oif;
			rth->fl.fl4_tos = flp->fl4_tos;
#ifdef CONFIG_IP_ROUTE_FWMARK
			rth->fl.fl4_fwmark = flp->fl4_fwmark;
#endif
			/* add to rcache list */
			rth->u.rt_next = rcache;
			rcache = rth;

			*rp = rth;

			return 0;
		}
	}

	return 1;

}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
int ip_route_output_key(struct rtable **rp, struct rt_key *key)
{
	struct flowi fl;

	fl.fl4_dst = key->dst;
	fl.fl4_src = key->src;
	fl.iif = 0;
	fl.oif = key->oif;
#ifdef CONFIG_IP_ROUTE_FWMARK
	fl.fl4_fwmark = key->fwmark;
#endif
	fl.fl4_tos = key->tos;

	return __ip_route_output_key(rp, &fl);
}
#else
int ip_route_output_key(struct rtable **rp, struct flowi *flp)
{
	return __ip_route_output_key(rp, flp);
}
#endif

/* 2.6.10-rc3 added this. */
int xfrm_lookup(struct dst_entry **dst_p, struct flowi *fl,
		struct sock *sk, int flags)
{
	struct rtable **rp = (void *)dst_p;

	return __ip_route_output_key(rp, fl);
}

#if 0
static int ip_forward(struct sk_buff *skb)
{
	u32 check;

	if (!(--skb->nh.iph->ttl)) {
		log_route(skb, "ip_forward:ttl expired");
		icmp_send(skb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
		kfree_skb(skb);
		return 1;
	}
	nfsim_update_skb(skb, &skb->nh.iph->ttl, sizeof(skb->nh.iph->ttl));

	check = skb->nh.iph->check;
	check += htons(0x0100);
	skb->nh.iph->check = check + (check >= 0xFFFF);

	/* Tell nfsim it's me changing data here. */
	nfsim_update_skb(skb, &skb->nh.iph->check, sizeof(skb->nh.iph->check));

	/* FIXME: strict source routing... */

#if 0
	return NF_HOOK(PF_INET, NF_IP_FORWARD, skb, skb->dev, skb->dst->dev,
		       dst_output);

#else
	return 0;

#endif
}
#endif

#if 0
int ip_route_input(struct sk_buff *skb, u32 daddr, u32 saddr,
		   u8 tos, struct net_device *dev)
{
	struct rtable *rth;
	struct ipv4_route *route;
	int iif = dev->ifindex;

	for (rth = rcache; rth; rth = rth->u.rt_next) {
		if (rth->fl.fl4_dst == daddr &&
		    rth->fl.fl4_src == saddr &&
		    rth->fl.iif == iif &&
		    rth->fl.oif == 0 &&
#ifdef CONFIG_IP_ROUTE_FWMARK
		    rth->fl.fl4_fwmark == skb->nfmark &&
#endif
		    rth->fl.fl4_tos == tos) {
			dst_hold(&rth->u.dst);
			skb->dst = (struct dst_entry*)rth;
			return 0;
		}
	}

	/* is this a local packet ? */
	list_for_each_entry(dev, &interfaces, entry) {
		struct in_ifaddr *ifaddr;

		if (!dev->ip_ptr)
			continue;

		ifaddr = ((struct in_device *)(dev->ip_ptr))->ifa_list;
		while (ifaddr) {
			if (skb->nh.iph->daddr == ifaddr->ifa_local) {
				log_route(skb,
					  "route:local packet (%s)",
					  dev->name);
				rth = talloc_zero(dev->ip_ptr, struct rtable);
				talloc_set_destructor(rth, destroy_rtable);

				rth->u.dst.output = NULL;
				rth->u.dst.input  = ip_local_deliver;
				rth->u.dst.dev    = &loopback_dev;
				rth->rt_src       = rth->fl.fl4_src = saddr;
				rth->rt_dst       = rth->fl.fl4_dst = daddr;
				rth->rt_gateway   = daddr;
				rth->rt_iif       = rth->fl.iif = dev->ifindex;

				rth->fl.fl4_tos = tos;
#ifdef CONFIG_IP_ROUTE_FWMARK
				rth->fl.fl4_fwmark = skb->nfmark;
#endif
				skb->dst = &rth->u.dst;

				return 0;
			}
			ifaddr = ifaddr->ifa_next;
		}

	}

	/* otherwise, find the appropriate route & create an rcache entry */
	list_for_each_entry(route, &routes, entry) {
		if ((skb->nh.iph->daddr & route->netmask) ==
		    route->network) {
			rth = talloc_zero(route, struct rtable);
			talloc_set_destructor(rth, destroy_rtable);

			rth->u.dst.dev = route->interface;

			rth->u.dst.output = ip_output;
			rth->u.dst.input  = ip_forward;
			rth->rt_src       = rth->fl.fl4_src = saddr;
			rth->rt_dst       = rth->fl.fl4_dst = daddr;
			rth->rt_gateway   = route->gateway;
			rth->rt_iif       = rth->fl.iif =
						    route->interface->ifindex;
			rth->fl.oif = 0;
			rth->fl.fl4_tos = tos;
#ifdef CONFIG_IP_ROUTE_FWMARK
			rth->fl.fl4_fwmark = skb->nfmark;
#endif
			/* add to rcache list */
			rth->u.rt_next = rcache;
			rcache = rth;

			skb->dst = &rth->u.dst;

			return 0;
		}
	}

	log_route(skb, "ERROR: packet is not local and no matching "
		  "route (dst=%u.%u.%u.%u)",
		  ((unsigned char *)&daddr)[0],
		  ((unsigned char *)&daddr)[1],
		  ((unsigned char *)&daddr)[2],
		  ((unsigned char *)&daddr)[3]);

	return 1;

}
#endif

int ip_fragment(struct sk_buff *skb, int (*output)(struct sk_buff *))
{
	log_packet(skb, "ip_fragment");
	(*output)(skb);
	return 0;
}

struct fraglist {
	struct list_head list;
	struct sk_buff *frags[20];
};
static struct list_head fraglist[IP_DEFRAG_VS_FWD];

static void init_fraglist(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(fraglist); i++)
		INIT_LIST_HEAD(&fraglist[i]);
}
init_call(init_fraglist);

#if 0
static struct sk_buff *gather_frag(struct fraglist *f, struct sk_buff *skb)
{
	unsigned int i, len, off, max = 0;
	bool ended = false;
	char filled[70000] = { 0 };
	char data[70000];

	for (i = 0; i < ARRAY_SIZE(f->frags); i++) {
		if (!f->frags[i]) {
			if (!skb)
				break;
			f->frags[i] = skb;
			talloc_steal(f, skb);
			skb = NULL;
		}

		off = (ntohs(f->frags[i]->nh.iph->frag_off) & IP_OFFSET) * 8;
		len = ntohs(f->frags[i]->nh.iph->tot_len) -
		      f->frags[i]->nh.iph->ihl * 4;
		if (len + off > max)
			max = len + off;

		memset(filled + off, 1, len);
		skb_copy_bits(f->frags[i], f->frags[i]->nh.iph->ihl * 4,
			      data + off, len);
		if (!(ntohs(f->frags[i]->nh.iph->frag_off) & IP_MF))
			ended = true;
	}
	if (skb)
		barf("Can't handle %i frags!\n", i);

	/* Not a complete packet? */
	if (!ended || memchr(filled, 0, max) != NULL)
		return NULL;

	/* Copy header and data. */
	suppress_failtest++;
	skb = skb_copy_expand(f->frags[0], 0, max, GFP_KERNEL);
	suppress_failtest--;

	skb->nh.iph = (void *)skb->data;
	memcpy(skb->nh.iph, f->frags[0]->nh.iph, f->frags[0]->nh.iph->ihl * 4);
	memcpy(skb_put(skb, max), data, max);

	/* Except we're not a fragment, and we're longer. */
	skb->nh.iph->frag_off = 0;
	skb->nh.iph->tot_len = htons(max + skb->nh.iph->ihl * 4);

	list_del(&f->list);
	talloc_free(f);
	return skb;
}

static struct sk_buff *ip_defrag_user(struct sk_buff *skb, u32 user)
{
	struct fraglist *i;

	list_for_each_entry(i, &fraglist[user], list) {
		if (i->frags[0]->nh.iph->saddr != skb->nh.iph->saddr ||
		    i->frags[0]->nh.iph->daddr != skb->nh.iph->daddr ||
		    i->frags[0]->nh.iph->protocol != skb->nh.iph->protocol)
			continue;
		return gather_frag(i, skb);
	}
	i = talloc(NULL, struct fraglist);
	memset(i->frags, 0, sizeof(i->frags));
	i->frags[0] = skb;
	list_add(&i->list, &fraglist[user]);
	talloc_steal(i, skb);
	return NULL;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 11)
struct sk_buff *ip_defrag(struct sk_buff *skb)
{
	return ip_defrag_user(skb, 0);
}
#else
struct sk_buff *ip_defrag(struct sk_buff *skb, u32 user)
{
	return ip_defrag_user(skb, user);
}
#endif

void ipfrag_flush(void)
{
}
#endif

void icmp_send(struct sk_buff *skb_in, int type, int code, u32 info)
{
	log_packet(skb_in, "icmp_send:type=%d, code=%d, info=%d",
		   type, code, info);
}

void ip_send_check(struct iphdr *iph)
{
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}

static inline unsigned short from32to16(unsigned long x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

static unsigned long do_csum(const unsigned char * buff, int len)
{
	int odd, count;
	unsigned long result = 0;

	if (len <= 0)
		return 0;

	odd = 1 & (unsigned long) buff;
	if (odd) {
		result = *buff;
		len--;
		buff++;
	}
	count = len >> 1;               /* nr of 16-bit words.. */
	if (count) {
		if (2 & (unsigned long) buff) {
			result += *(const unsigned short *) buff;
			count--;
			len -= 2;
			buff += 2;
		}
		count >>= 1;            /* nr of 32-bit words.. */
		if (count) {
			unsigned long carry = 0;
			do {
				unsigned int w = *(const unsigned int *) buff;
				count--;
				buff += 4;
				result += carry;
				result += w;
				carry = (w > result);
			} while (count);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if (len & 2) {
			result += *(const unsigned short *) buff;
			buff += 2;
		}
	}
	if (len & 1)
		result += (*buff << 8);
	result = from32to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);

	return result;
}

unsigned short ip_fast_csum(void * iph, unsigned int ihl)
{
	return ~do_csum(iph, ihl * 4);
}

unsigned int csum_fold(unsigned int sum)
{
	return ~from32to16(sum);
}

#if 0
unsigned int csum_partial(const void * buff, int len, unsigned int sum)
{
	unsigned int result = do_csum(buff, len);

	/* add in old sum, and carry.. */
	result += sum;
	if (sum > result)
		result += 1;
	return result;
}
#endif

u32 csum_tcpudp_nofold(unsigned long saddr,
		       unsigned long daddr,
		       unsigned short len,
		       unsigned short proto,
		       unsigned int sum)
{
	struct {
		u32 srcip, dstip;
		u8 mbz, protocol;
		u16 proto_len;
	} pseudo_header = { saddr, daddr, 0, proto, htons(len) };

	return csum_partial(&pseudo_header, sizeof(pseudo_header), sum);
}

unsigned short csum_tcpudp_magic(unsigned long saddr,
				 unsigned long daddr,
				 unsigned short len,
				 unsigned short proto,
				 unsigned int sum)
{
	return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

uint16_t tcp_v4_check(struct tcphdr *th, int len,
		      unsigned long saddr, unsigned long daddr,
		      unsigned long base)
{
	return csum_tcpudp_magic(saddr, daddr, len, IPPROTO_TCP, base);
}

unsigned inet_addr_type(u32 addr)
{
	struct net_device *dev;

	if (ZERONET(addr) || BADCLASS(addr))
		return RTN_BROADCAST;

	if (MULTICAST(addr))
		return RTN_MULTICAST;

	list_for_each_entry(dev, &interfaces, entry) {
		struct in_ifaddr *ifaddr;

		if (!dev->ip_ptr)
			continue;

		for (ifaddr = ((struct in_device *)(dev->ip_ptr))->ifa_list;
		     ifaddr; ifaddr = ifaddr->ifa_next)
			if (ifaddr->ifa_local == addr)
				return RTN_LOCAL;
	}

	return RTN_UNICAST;

}

static __inline__ int inet_ifa_match(u32 addr, struct in_ifaddr *ifa)
{
	return !((addr ^ ifa->ifa_address) & ifa->ifa_mask);
}

/* Not strictly correct for loopback packets: they ignore device if it
 * doesn't match. */
u32 inet_select_addr(const struct net_device *dev, u32 dst, int scope)
{
	u32 addr = 0;
	struct in_device *in_dev;
	struct in_ifaddr *ifa;

	in_dev = dev->ip_ptr;
	if (!in_dev)
		return 0;

	for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
		if (!dst || inet_ifa_match(dst, ifa)) {
			addr = ifa->ifa_local;
			break;
		}
		if (!addr)
			addr = ifa->ifa_local;
	}

	return addr;
}

int lastid = 4;
void __ip_select_ident(struct iphdr *iph,
		       struct dst_entry *dst, struct sock *sk)
{
	iph->id = ++lastid;
}

void ip_select_ident(struct iphdr *iph,
		     struct dst_entry *dst, struct sock *sk)
{
	__ip_select_ident(iph, dst, sk);
}

static char *print_data(char *ptr, const char *data, int len)
{
	static const char hexbuf[] = "0123456789abcdef";
	int i;

	ptr += sprintf(ptr, "DATA ");
	for (i = 0; i < len; i++) {
		if (data[i] == '\n') {
			*ptr++ = '\\';
			*ptr++ = 'n';
		} else if (data[i] == '\r') {
			*ptr++ = '\\';
			*ptr++ = 'r';
		} else if (data[i] == '\0') {
			*ptr++ = '\\';
			*ptr++ = '0';
		} else if (data[i] == '\t') {
			*ptr++ = '\\';
			*ptr++ = 't';
		} else if (data[i] == '\\') {
			*ptr++ = '\\';
			*ptr++ = '\\';
		} else if (data[i] & 0x80 || (data[i] & 0xe0) == 0) {
			*ptr++ = '\\';
			*ptr++ = 'x';
			*ptr++ = hexbuf[(data[i] >> 4) & 0xf];
			*ptr++ = hexbuf[data[i] & 0xf];
		} else {
			*ptr++ = data[i];
		}
	}
	*ptr = '\0';
	return ptr;
}

static char *describe(char *ptr, int len, struct iphdr *iph, char *dump_flags)
{
	/* the length of the packet reported by the ipv4 header */
	int iplen;
	struct icmphdr *icmph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	char *p;

	*ptr = '\0';

	if (len < sizeof(struct iphdr)) {
		strcat(ptr, "-TRUNCATED-");
		goto out;
	}

	if (csum_partial(iph, sizeof(struct iphdr), 0) !=
	    0xFFFF) {
		strcat(ptr, "-BAD IP CSUM-");
		goto out;
	}

	if (ntohs(iph->frag_off) & IP_OFFSET)
		ptr += sprintf(ptr, "FRAG=%u ",
			       (ntohs(iph->frag_off) & IP_OFFSET) * 8);
	if (ntohs(iph->frag_off) & IP_DF)
		ptr += sprintf(ptr, "DF ");
	if (ntohs(iph->frag_off) & IP_MF)
		ptr += sprintf(ptr, "MF ");
	if (ntohs(iph->frag_off) & IP_CE)
		ptr += sprintf(ptr, "CE ");
	if (dump_flags && strstr(dump_flags, "ttl"))
		ptr += sprintf(ptr, "TTL=%i ", iph->ttl);
	if (dump_flags && strstr(dump_flags, "tos"))
		ptr += sprintf(ptr, "TOS=%i ", iph->tos);
	if (dump_flags && strstr(dump_flags, "dscp"))
		ptr += sprintf(ptr, "DSCP=0x%x ",
			       (iph->tos >> IPT_DSCP_SHIFT));
	if (dump_flags && strstr(dump_flags, "ect"))
		ptr += sprintf(ptr, "ECT=0x%x ", (iph->tos & 3));
	ptr += sprintf(ptr, "%u.%u.%u.%u %u.%u.%u.%u ",
		       ((unsigned char *)&iph->saddr)[0],
		       ((unsigned char *)&iph->saddr)[1],
		       ((unsigned char *)&iph->saddr)[2],
		       ((unsigned char *)&iph->saddr)[3],
		       ((unsigned char *)&iph->daddr)[0],
		       ((unsigned char *)&iph->daddr)[1],
		       ((unsigned char *)&iph->daddr)[2],
		       ((unsigned char *)&iph->daddr)[3]);

	if (ntohs(iph->frag_off) & IP_OFFSET)
		goto out;

	iplen = htons(iph->tot_len) - sizeof(struct iphdr);
	len -= sizeof(struct iphdr);

	switch (iph->protocol) {
	case IPPROTO_ICMP:
		icmph = (struct icmphdr *)(iph + 1);
		ptr += sprintf(ptr, "%Zu %u ",
			       iplen - sizeof(struct icmphdr), iph->protocol);

		if (len < sizeof(struct icmphdr)) {
			ptr += sprintf(ptr, "-TRUNCATED-");
			goto out;
		}
		ptr += sprintf(ptr, "%u %u ", icmph->type, icmph->code);

		if (len < iplen) {
			ptr += sprintf(ptr, "-TRUNCATED-");
			goto out;
		}

		if (!(ntohs(iph->frag_off) & IP_MF) &&
		    csum_partial((char *)icmph, iplen, 0) != 0xFFFF) {
			ptr += sprintf(ptr, "-BAD ICMP CSUM-");
			goto out;

		}

		if (icmph->type == 0 || icmph->type == 8) {
			ptr += sprintf(ptr, "%u %u ",
				       ntohs(icmph->un.echo.id),
				       ntohs(icmph->un.echo.sequence));
		} else {
			/* Print out packet inside it. */
			ptr += sprintf(ptr, "CONTAINS ");
			ptr = describe(ptr,
				       iplen - sizeof(struct icmphdr),
				       (struct iphdr *)(icmph + 1),
				       dump_flags);
		}
		break;

	case IPPROTO_UDP:
		udph = (struct udphdr *)(iph + 1);
		ptr += sprintf(ptr, "%Zu %u ",
			       iplen - sizeof(struct udphdr), iph->protocol);

		if (len < sizeof(struct udphdr)) {
			ptr += sprintf(ptr, "-TRUNCATED-");
			goto out;
		}

		ptr += sprintf(ptr, "%u %u ",
			       ntohs(udph->source),
			       ntohs(udph->dest));

		if (len < iplen) {
			ptr += sprintf(ptr, "-TRUNCATED-");
			goto out;
		}

		if (!(ntohs(iph->frag_off) & IP_MF) &&
		    udph->check &&
		    csum_tcpudp_magic(iph->saddr, iph->daddr,
				      iplen, IPPROTO_UDP,
				      csum_partial(udph, iplen, 0))) {
			ptr += sprintf(ptr, "-BAD UDP CSUM- (%04x)",
				       udph->check);
			goto out;
		}

		if (dump_flags && strstr(dump_flags, "data"))
			ptr = print_data(ptr, (char *)(udph + 1),
					 iplen - sizeof(*udph));
		break;

	case IPPROTO_TCP:
		tcph = (struct tcphdr *)(iph + 1);
		if (len < sizeof(struct tcphdr)) {
			/* Assume no tcp options... */
			ptr += sprintf(ptr, "%Zu %u ",
				       iplen - sizeof(*tcph), iph->protocol);

			ptr += sprintf(ptr, "-TRUNCATED-");
			goto out;
		}
		ptr += sprintf(ptr, "%u %u ",
			       iplen - tcph->doff * 4, iph->protocol);

		ptr += sprintf(ptr, "%u %u ",
			       ntohs(tcph->source), ntohs(tcph->dest));

		if (len < iplen) {
			ptr += sprintf(ptr, "-TRUNCATED-");
			goto out;
		}
		p = ptr;

		if (tcph->syn)
			ptr += sprintf(ptr, "SYN");
		if (tcph->fin)
			ptr += sprintf(ptr, "%sFIN", ptr == p ? "" : "/");
		if (tcph->rst)
			ptr += sprintf(ptr, "%sRST", ptr == p ? "" : "/");
		if (tcph->ack)
			ptr += sprintf(ptr, "%sACK", ptr == p ? "" : "/");
		if (tcph->urg)
			ptr += sprintf(ptr, "%sURG", ptr == p ? "" : "/");
		if (tcph->psh)
			ptr += sprintf(ptr, "%sPSH", ptr == p ? "" : "/");
		if (tcph->cwr)
			ptr += sprintf(ptr, "%sCWR", ptr == p ? "" : "/");
		if (tcph->ece)
			ptr += sprintf(ptr, "%sECE", ptr == p ? "" : "/");
		if (ptr == p)
			ptr += sprintf(ptr, "NONE");
		ptr += sprintf(ptr, " ");

		if (tcph->seq)
			ptr += sprintf(ptr, "SEQ=%u ", ntohl(tcph->seq));

		if (tcph->ack_seq)
			ptr += sprintf(ptr, "ACK=%u ", ntohl(tcph->ack_seq));

		if (tcph->window)
			ptr += sprintf(ptr, "WIN=%u ", ntohs(tcph->window));

		if (tcph->doff * 4 != sizeof(struct tcphdr)) {
			char sep = '=';
			int i;
			ptr += sprintf(ptr, "OPT");
			for (i = sizeof(struct tcphdr); i < tcph->doff * 4;
			     i++) {
				ptr += sprintf(ptr, "%c%u",
					       sep,
					       ((u_int8_t *)tcph)[i]);
				sep = ',';
			}
			ptr += sprintf(ptr, " ");
		}

		if (!(ntohs(iph->frag_off) & IP_MF) &&
		    csum_tcpudp_magic(iph->saddr, iph->daddr,
				      iplen, IPPROTO_TCP,
				      csum_partial(tcph, iplen, 0))) {
			ptr += sprintf(ptr, "-BAD TCP CSUM- (%04x)",
				       tcph->check);
			goto out;
		}

		if (dump_flags && strstr(dump_flags, "data"))
			ptr = print_data(ptr, (char *)tcph + tcph->doff * 4,
					 iplen - tcph->doff * 4);
		break;

	default:
		ptr += sprintf(ptr, "%u %u", iplen, iph->protocol);
		if (len < iplen) {
			ptr += sprintf(ptr, "-TRUNCATED-");
			goto out;
		}
	}

out:
	if (ptr[-1] == ' ') {
		ptr--;
		*ptr = '\0';
	}
	return ptr;
}

#if 0
char *ipv4_describe_packet(struct sk_buff *skb)
{
	static char ipv4_pbuf[1024];
	char packet[skb->len];

	if (skb_copy_bits(skb, 0, packet, skb->len) != 0)
		barf("skb_copy_bits failed");
	describe(ipv4_pbuf, skb->len, (struct iphdr *)packet,
		 field_value(skb, "dump_flags"));
	return ipv4_pbuf;
}
#endif
