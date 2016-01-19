#ifndef _LIBRESWAN_KVERSIONS_H
/*
 * header file for Libreswan library functions
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 * Copyright (C) 2003 - 2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 - 2011 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2012-2014 David McCullough <david_mccullough@mcafee.com>
 * Copyright (C) 2012-2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2015 Greg Ungerer <gerg@uclinux.org>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 */
#define _LIBRESWAN_KVERSIONS_H  /* seen it, no need to see it again */

/*
 * this file contains a series of atomic defines that depend upon
 * kernel version numbers. The kernel versions are arranged
 * in version-order number (which is often not chronological)
 * and each clause enables or disables a feature.
 */

/*
 * First, assorted kernel-version-dependent trickery.
 */
#include <linux/version.h>
#ifndef KERNEL_VERSION
# define KERNEL_VERSION(x, y, z) (((x) << 16) + ((y) << 8) + (z))
#endif

#if __KERNEL__
# if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 0)
#  if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 4, 0)
#   include "libreswan/ipsec_kern24.h"
#  else
#   error "kernels before 2.4 are not supported at this time"
#  endif
# else
#   define KLIPS_INC_USE        /* nothing */
#   define KLIPS_DEC_USE        /* nothing */
# endif
#endif
/*
 * We use a lot of config defines,  on older kernels that means we
 * need to include config.h
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) && \
	!defined(AUTOCONF_INCLUDED)
# include <linux/config.h>
#endif

#if !defined(RHEL_RELEASE_CODE)
# define RHEL_RELEASE_CODE 0
# define RHEL_RELEASE_VERSION(x, y) 10
#endif

/* these seem debian/ubuntu specific and do not match fedora/rhel kernels */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,10)
# define IP_SELECT_IDENT_NEW
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,17)
# define IP_SELECT_IDENT_NEW
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,11)
# define IP_SELECT_IDENT_NEW
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,0)
# define IP_SELECT_IDENT_NEW
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,53)
# define IP_SELECT_IDENT_NEW
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,103)
# define IP_SELECT_IDENT_NEW
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,63)
# define IP_SELECT_IDENT_NEW
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
# define SK_FOR_EACH(a,c) sk_for_each(a,c)
# define ipsec_proc_net_remove(a) remove_proc_entry(a, init_net.proc_net)
#else
# define SK_FOR_EACH_NEED_NODE
# define SK_FOR_EACH(a,c) sk_for_each(a,node,c)
# define remove_proc_subtree(a,b) remove_proc_entry(a,b)
# if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
#  define ipsec_proc_net_remove(a) proc_net_remove(&init_net, a)
# else
#  define ipsec_proc_net_remove(a) proc_net_remove(a)
# endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
# define NEED_UDP_ENCAP_ENABLE
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
# define ipsec_ipv6_skip_exthdr ipv6_skip_exthdr
# define IPSEC_FRAG_OFF_DECL(x) __be16 x;
#else
# define ipsec_ipv6_skip_exthdr(a, b, c, d) ipv6_skip_exthdr(a, b, c)
# define IPSEC_FRAG_OFF_DECL(x)
#endif

/*
 * try to handle time wraps in a nicer manner
 */
#define ipsec_jiffies_elapsed(now, last) \
	((last) <= \
	 (now) ? ((now) - (last)) : (((typeof(jiffies)) ~0) - (last) + (now)))
#define ipsec_jiffieshz_elapsed(now, last) \
	((last) <= \
	 (now) ? ((now) - \
		  (last)) : ((((typeof(jiffies)) ~0) / HZ) - (last) + (now)))

/*
 * Kernel version specific defines, in order from oldest to newest kernel
 * If possible, use the latest native writing, and write macro's to port back
 * the new code to older kernels.
 */

#ifndef CONFIG_IP_ALIAS
# define CONFIG_IP_ALIAS
#endif

/* API changes are documented at: http://lwn.net/Articles/2.6-kernel-api/ */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
# define HAVE_NETDEV_PRINTK 1
# define NET_26
# define NEED_SPINLOCK_TYPES
/* Only enable IPv6 support on newer kernels with IPv6 enabled */
# if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#  define CONFIG_KLIPS_IPV6 1
# endif
#else
/*
   The obsolete MODULE_PARM() macro is gone forevermore [in 2.6.17+]
    It was introduced in 2.6.0
   Zero-filled memory can now be allocated from slab caches with
    kmem_cache_zalloc(). There is also a new slab debugging option
    to produce a /proc/slab_allocators file with detailed allocation
    information.
 */
# ifndef module_param
#  define module_param(a, b, c)  MODULE_PARM(#a, "i")
# endif
/* note below is only true for our current calls to module_param_array */
# define module_param_array(a, b, c, d)  MODULE_PARM(#a, "1-2i")
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
# define NEED_INET_PROTOCOL
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 12)
# define HAVE_SOCK_ZAPPED
# if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
#  define NET_44_SKALLOC
# elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
#  define NET_26_24_SKALLOC
# else
#  define NET_26_12_SKALLOC
# endif
#endif

/* see <linux/security.h> */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 13)) && \
	defined(CONFIG_NETFILTER_DEBUG)
# define HAVE_SOCK_SECURITY
/* skb->nf_debug disappared completely in 2.6.13 */
# define ipsec_nf_debug_reset(skb)      ((skb)->nf_debug = 0)
#else
# define ipsec_nf_debug_reset(skb)
#endif

/* skb->stamp changed to skb->tstamp in 2.6.14 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 14)
# define HAVE_TSTAMP
# define HAVE_INET_SK_SPORT
#else
# define HAVE_SKB_LIST
#endif

/* it seems 2.6.14 accidentally removed sysctl_ip_default_ttl */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 14)
# define SYSCTL_IPSEC_DEFAULT_TTL IPSEC_DEFAULT_TTL
#else
# define SYSCTL_IPSEC_DEFAULT_TTL sysctl_ip_default_ttl
#endif

/* how to reset an skb we are reusing after encrpytion/decryption etc */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 17)
# define ipsec_nf_reset(skb)    nf_reset((skb))
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 3, 50) && \
	defined(CONFIG_NETFILTER)
# define ipsec_nf_reset(skb)    do { \
		nf_conntrack_put((skb)->nfct); \
		(skb)->nfct = NULL; \
		ipsec_nf_debug_reset(skb); \
} while (0)
#else
# define ipsec_nf_reset(skb)    /**/
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
/*
   The skb_linearize() function has been reworked, and no longer has a
    GFP flags argument. There is also a new skb_linearize_cow() function
    which ensures that the resulting SKB is writable.
   Network drivers should no longer manipulate the xmit_lock  spinlock
    in the net_device structure; instead, the following new functions
    should be used:
     int netif_tx_lock(struct net_device *dev);
     int netif_tx_lock_bh(struct net_device *dev);
     void netif_tx_unlock(struct net_device *dev);
     void netif_tx_unlock_bh(struct net_device *dev);
     int netif_tx_trylock(struct net_device *dev);
   A number of crypto API changes have been merged, the biggest being
    a change to most algorithm-specific functions to take a pointer to
    the crypto_tfm structure, rather than the old "context" pointer. This
    change was necessary to support parameterized algorithms.
 */

# define HAVE_NEW_SKB_LINEARIZE
#elif defined(CONFIG_XEN)
/* this is the best we can do to detect XEN, which makes
 * patches to linux/skbuff.h, making it look like 2.6.18+ version
 */
# define HAVE_NEW_SKB_LINEARIZE
#elif defined(SLE_VERSION_CODE)
/* And the same for SuSe kernels who have it before it got into the
 * linus kernel.
 */
# if SLE_VERSION_CODE >= 655616
#  define HAVE_NEW_SKB_LINEARIZE
# else
#  warning \
	"A Suse kernel was detected, but we are unsure if it requires HAVE_NEW_SKB_LINEARIZE"
# endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)
# define VOID_SOCK_UNREGISTER
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)
/* skb->nfmark changed to skb->mark in 2.6.20 */
# define nfmark mark
#else
# define HAVE_KMEM_CACHE_T
# if defined(RHEL_RELEASE_CODE)
#  if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(5, 0)
#   define FLOW_HAS_NO_MARK
#  endif
# elif defined(CONFIG_SLE_VERSION) && defined(CONFIG_SLE_SP) && \
	(CONFIG_SLE_VERSION == 10)
#  define FLOW_HAS_NO_MARK
# endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 21)
/*
   Significant changes have been made to the crypto support interface.
   The sysctl code has been heavily reworked, leading to a number of
    internal API changes.
 */
# define ipsec_register_sysctl_table(a, b) register_sysctl_table(a)
# define CTL_TABLE_PARENT
#else
# define ipsec_register_sysctl_table(a, b) register_sysctl_table(a, b)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 22)
#  define HAVE_KERNEL_TSTAMP
#  define grab_socket_timeval(tv, sock)  { (tv) = ktime_to_timeval( \
						   (sock).sk_stamp); }
#else
#  define grab_socket_timeval(tv, sock)  { (tv) = (sock).sk_stamp; }
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 22) || (RHEL_RELEASE_CODE >= \
						       RHEL_RELEASE_VERSION(5, \
									    2))
/* need to include ip.h early, no longer pick it up in skbuff.h */
#include <linux/ip.h>
/* type of sock.sk_stamp changed from timeval to ktime  */
#else
/* internals of struct skbuff changed */
/* but RedHat/SUSE ported some of this back to their RHEL kernel, so check for that */
# if !defined(RHEL_MAJOR) || !defined(RHEL_MINOR) || !(RHEL_MAJOR == 5 && \
						       RHEL_MINOR >= 2)
#  define        HAVE_DEV_NEXT
#  if defined(CONFIG_SLE_VERSION) && defined(CONFIG_SLE_SP) && \
	(CONFIG_SLE_VERSION == 10 && CONFIG_SLE_SP <= 2)
#   define ip_hdr(skb)  ((skb)->nh.iph)
#  endif
#  define skb_tail_pointer(skb)  ((skb)->tail)
#  define skb_end_pointer(skb)  ((skb)->end)
#  define skb_network_header(skb)  ((skb)->nh.raw)
#  define skb_set_network_header(skb, off)  ((skb)->nh.raw = (skb)->data + \
							     (off))
#  define tcp_hdr(skb)  ((skb)->h.th)
#  define udp_hdr(skb)  ((skb)->h.uh)
#  define skb_transport_header(skb)  ((skb)->h.raw)
#  define skb_network_offset(skb)  ((skb)->nh.raw - (skb)->data)
#  define skb_set_transport_header(skb, off)  ((skb)->h.raw = (skb)->data + \
							      (off))
#  define skb_reset_transport_header(skb) ((skb)->h.raw = (skb)->data - \
							  (skb)->head)
#  define skb_mac_header(skb)  ((skb)->mac.raw)
#  define skb_set_mac_header(skb, off)  ((skb)->mac.raw = (skb)->data + (off))
# endif
# if defined(CONFIG_SLE_VERSION) && defined(CONFIG_SLE_SP) && \
	(CONFIG_SLE_VERSION == 10 && CONFIG_SLE_SP == 2)
#  define ip_hdr(skb) ((skb)->nh.iph)
# endif
#endif
/* turn a pointer into an offset for above macros */
#define ipsec_skb_offset(skb, ptr) (((unsigned char *)(ptr)) - (skb)->data)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23)
/*
 * The macro got introduced in 2,6,22 but it does not work properly, and
 * still uses the old number of arguments.
 */
/*
   The destructor argument has been removed from kmem_cache_create(), as
   destructors are no longer supported. All in-kernel callers have been
   updated
 */
# define HAVE_KMEM_CACHE_MACRO

/* Try using the new klips encaps hook for nat-t, instead of udp.c */
# define HAVE_UDP_ENCAP_CONVERT 1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
# define HAVE_NETDEV_HEADER_OPS 1
/*
 * We can switch on earlier kernels, but from here on we have no choice
 * but to abandon the old style proc_net and use seq_file
 * The hard_header() method has been removed from struct net_device;
    it has been replaced by a per-protocol header_ops structure pointer.

   The prototype for slab constructor callbacks has changed to:
    void (*ctor)(struct kmem_cache *cache, void *object);
   The unused flags argument has been removed and the order of the other
    two arguments has been reversed to match other slab functions.
 */
# define HAVE_PROC_DIR_ENTRY
# define        PROC_NET        init_net.proc_net
# define        PROC_EOF_DATA

# define __ipsec_dev_get(x) __dev_get_by_name(&init_net, x)
# define ipsec_dev_get(x) dev_get_by_name(&init_net, x)
#else

# define        PROC_NET        proc_net

# define ipsec_dev_get(x) dev_get_by_name(x)
# define __ipsec_dev_get(x) __dev_get_by_name(x)
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 9, 0)
# define PDE_DATA(inode)	PDE(inode)->data
#endif

/*
 * We do not use CONFIG_NAMSPACES due to a kernel bug
 * that checks for namespaces in inet_add_protocol()
 * even when compiled without CONFIG_NAMSPACES
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
# define HAVE_NAMESPACES
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
# define ip_chk_addr(a) inet_addr_type(&init_net, a)
# define l_inet_addr_type(a)    inet_addr_type(&init_net, a)
#else
# define ip_chk_addr inet_addr_type
# define l_inet_addr_type       inet_addr_type
#endif

#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <net/addrconf.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
# define ip6_chk_addr(a) (ipv6_chk_addr(&init_net, a, NULL, 1) ? IS_MYADDR : 0)
#else
# define ip6_chk_addr(a) (ipv6_chk_addr(a, NULL, 1) ? IS_MYADDR : 0)
#endif
#define l_ipv6_addr_type(a)     ip6_chk_addr(a)

/* not sure when network name spaces got introduced, but it is in 2.6.26 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
# define HAVE_NETWORK_NAMESPACE 1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
# define HAVE_CURRENT_UID
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 31)
# ifndef NETDEV_TX_BUSY
#  ifdef NETDEV_XMIT_CN
#   define NETDEV_TX_BUSY NETDEV_XMIT_CN
#  else
#   define NETDEV_TX_BUSY 1
#  endif
# endif
#endif

#if LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 30)
# ifndef CONFIG_COMPAT_NET_DEV_OPS
#  define USE_NETDEV_OPS
# endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
# define USE_NETDEV_OPS
#else
# define skb_dst_drop(s)        ({ \
					 if ((s)->dst) \
						 dst_release((s)->dst); \
					 (s)->dst = NULL; \
				 })
# define skb_dst_set(s, p)       ((s)->dst = (p))
# define skb_dst(s)             ((s)->dst)
#endif

/* The SLES10 kernel is known to not have these defines */
#ifdef CONFIG_KLIPS_IPV6
# ifndef IN6ADDR_ANY_INIT
#  define IN6ADDR_ANY_INIT { { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
				 0 } } }
# endif
# ifndef IN6ADDR_LINKLOCAL_ALLNODES_INIT
#  define IN6ADDR_LINKLOCAL_ALLNODES_INIT { { { 0xff, 2, 0, 0, 0, 0, 0, 0, 0, \
						0, 0, 0, 0, 0, 0, 1 } } }
# endif
#endif

#if !defined(HAVE_CURRENT_UID)
# define current_uid() (current->uid)
#endif

#define ipsec_kfree_skb(a) kfree_skb(a)

#ifndef HAVE_NETDEV_PRINTK
# define netdev_printk(sevlevel, netdev, msglevel, format, arg ...) \
	printk(sevlevel "%s: " format, netdev->name, ## arg)
#endif

#define ipsec_dev_put(x) dev_put(x)
#define __ipsec_dev_put(x) __dev_put(x)
#define ipsec_dev_hold(x) dev_hold(x)

#ifndef late_initcall
# include <linux/init.h>
# ifndef late_initcall
#  define       late_initcall(x)        module_init(x)
# endif
#endif

#include <linux/in6.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#ifdef NF_IP_LOCAL_OUT
# define LSW_NF_INET_LOCAL_OUT  NF_IP_LOCAL_OUT
#endif
#ifndef LSW_NF_INET_LOCAL_OUT
# define LSW_NF_INET_LOCAL_OUT NF_INET_LOCAL_OUT
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
# define        inet_sport      sport
# define        inet_dport      dport
# define        CTL_NAME(n)     .ctl_name = n,
#else
# define        CTL_NAME(n)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
# define HAVE_SOCKET_WQ
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
# define        ipsec_route_dst(x)      (x)->dst
#else
# define        ipsec_route_dst(x)      (x)->u.dst
#endif
#if defined(CONFIG_SLE_VERSION) && defined(CONFIG_SLE_SP) && \
	(CONFIG_SLE_VERSION == 10 && CONFIG_SLE_SP >= 3)
# define HAVE_BACKPORTED_NEW_CRYPTOAPI 1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)
# define PRIVATE_ARP_BROKEN_OPS
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 38)
# ifndef DEFINE_SPINLOCK
#  define DEFINE_SPINLOCK(x) spinlock_t x = SPIN_LOCK_UNLOCKED
# endif
# define flowi_tos nl_u.ip4_u.tos
# define flowi_proto proto
# define flowi_mark mark
# define flowi_oif oif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
# define nl_u u
# define ip4_u ip4
# define ip6_u ip6
#endif

/*
 * Note that kernel 3.x maps to 2.6.40+x with the UNAME26 patch
 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0) || (LINUX_VERSION_CODE >= \
						      KERNEL_VERSION(2, 6, 41))
# define        HAVE_NETDEV_PRIV
# define        HAVE_NET_DEVICE_OPS
# define        HAVE_NETIF_QUEUE
#endif

#ifdef alloc_netdev
# if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
#  define ipsec_alloc_netdev(a,b,c,d) alloc_netdev(a,b,c,d)
typedef struct ctl_table ctl_table;
# else
#  define ipsec_alloc_netdev(a,b,c,d) alloc_netdev(a,b,d)
# endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
# define memcpy_from_msg(a,b,c)        memcpy_fromiovec(a,(b)->msg_iov,c)
# define skb_copy_datagram_msg(a,b,c,d) skb_copy_datagram_iovec(a,b,(c)->msg_iov,d)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
# define HAVE_REBUILD_HEADER
#endif

#if !defined(DEFINE_RWLOCK)
# define DEFINE_RWLOCK(x) rwlock_t x = RW_LOCK_UNLOCKED
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
# define HAVE_USER_NS
/* CONFIG_USER_NS is now on in Fedora 20 kernels */
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
# if defined(CONFIG_USER_NS)
#  define HAVE_USER_NS
# endif
#endif

#endif /* _LIBRESWAN_KVERSIONS_H */

