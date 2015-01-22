/*
 * IPSEC tunneling code
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003  Richard Guy Briggs.
 * Copyright (C) 2006        Michael Richardson <mcr@xelerance.com>
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
 *
 */

# define DEV_QUEUE_XMIT(skb, device, pri) { \
		(skb)->dev = (device); \
		neigh_compat_output(skb); \
		/* (skb)->dst->output(skb); */ \
}
# define ICMP_SEND(skb_in, type, code, info, dev) \
	icmp_send((skb_in), (type), (code), htonl(info))
# define IP_SEND(skb, dev) \
	ip_send(skb);

#if defined(KLIPS)

#define lsw_ip_hdr_version(ixirs)  (((struct iphdr *) (ixirs)->iph)->version)
#define lsw_ip4_hdr(ixirs)      ((struct iphdr *) (ixirs)->iph)
#define lsw_ip6_hdr(ixirs)      ((struct ipv6hdr *) (ixirs)->iph)

/*
 * Heavily based on drivers/net/new_tunnel.c.  Lots
 * of ideas also taken from the 2.1.x version of drivers/net/shaper.c
 */

struct ipsectunnelconf {
	uint32_t cf_cmd;
	union {
		char cfu_name[12];
	} cf_u;
#define cf_name cf_u.cfu_name
};

#define IPSEC_SET_DEV   (SIOCDEVPRIVATE)
#define IPSEC_DEL_DEV   (SIOCDEVPRIVATE + 1)
#define IPSEC_CLR_DEV   (SIOCDEVPRIVATE + 2)
#endif

/* This is used for KLIPS as well as NETKEY */
#define IPSEC_UDP_ENCAP_CONVERT (SIOCDEVPRIVATE + 3)

#ifdef __KERNEL__
#include <linux/version.h>
#ifndef KERNEL_VERSION
#  define KERNEL_VERSION(x, y, z) (((x) << 16) + ((y) << 8) + (z))
#endif
#define IPSECPRIV_MAGIC 0x15ECC0DE
struct ipsecpriv {
	uint32_t magic;

	struct sk_buff_head sendq;
	struct net_device *dev;
	struct wait_queue *wait_queue;
	int vifnum;
	char locked;
	int (*hard_start_xmit) (struct sk_buff *skb,
				struct net_device *dev);
#ifdef HAVE_NETDEV_HEADER_OPS
	const struct header_ops *header_ops;
#else

	int (*hard_header) (struct sk_buff *skb,
			    struct net_device *dev,
			    unsigned short type,
			    void *daddr,
			    void *saddr,
			    unsigned len);
	int (*rebuild_header)(struct sk_buff *skb);
	void (*header_cache_update)(struct hh_cache *hh,
				    struct net_device *dev,
				    unsigned char *  haddr);
#endif
#ifdef USE_NETDEV_OPS
	const struct net_device_ops *saved_netdev_ops;
	struct net_device_ops netdev_ops;
#endif
	int (*set_mac_address)(struct net_device *dev, void *addr);
	struct net_device_stats *(*get_stats)(struct net_device *dev);
	struct net_device_stats mystats;
	int mtu;        /* What is the desired MTU? */
};

static inline struct ipsecpriv *netdev_to_ipsecpriv(
	const struct net_device *dev)
{
	struct ipsecpriv *iprv = netdev_priv(dev);

	BUG_ON(!iprv);
	BUG_ON(iprv->magic != IPSECPRIV_MAGIC);

	return iprv;
}

extern char ipsec_tunnel_c_version[];

extern struct net_device *ipsecdevices[IPSEC_NUM_IFMAX];
extern int ipsecdevices_max;

int ipsec_tunnel_init_devices(void);

/* void */ int ipsec_tunnel_cleanup_devices(void);

extern /* void */ int ipsec_init(void);

extern int ipsec_tunnel_start_xmit(struct sk_buff *skb,
				   struct net_device *dev);
extern struct net_device *ipsec_get_device(int inst);

extern int debug_tunnel;
extern int sysctl_ipsec_debug_verbose;

extern int lsw_ipv6_find_hdr(const struct sk_buff *skb, unsigned int *offset,
			     int target, unsigned short *fragoff);

#ifdef CONFIG_KLIPS_IPV6
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34)
# define ICMP6_SEND(skb_in, type, code, info, dev) \
	icmpv6_send((skb_in), (type), (code), htonl(info), (dev))
#else
# define ICMP6_SEND(skb_in, type, code, info, dev) \
	icmpv6_send((skb_in), (type), (code), htonl(info))
#endif
#endif  /* CONFIG_KLIPS_IPV6 */

#endif  /* __KERNEL__ */

#define DB_TN_INIT      0x0001
#define DB_TN_PROCFS    0x0002
#define DB_TN_XMIT      0x0010
#define DB_TN_OHDR      0x0020
#define DB_TN_CROUT     0x0040
#define DB_TN_OXFS      0x0080
#define DB_TN_REVEC     0x0100
#define DB_TN_ENCAP     0x0200

extern int ipsec_tunnel_deletenum(int vifnum);
extern int ipsec_tunnel_createnum(int vifnum);
extern struct net_device *ipsec_tunnel_get_device(int vifnum);

/* manage ipsec xmit state objects */
extern int ipsec_xmit_state_cache_init(void);
extern void ipsec_xmit_state_cache_cleanup(void);
struct ipsec_xmit_state *ipsec_xmit_state_new(struct net_device *dev);
void ipsec_xmit_state_delete(struct ipsec_xmit_state *ixs);

