#ifndef _OPENSWAN_KVERSIONS_H
/*
 * header file for FreeS/WAN library functions
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
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
 * RCSID $Id: ipsec_kversion.h,v 1.23 2005/11/13 15:24:07 ken Exp $
 */
#define	_OPENSWAN_KVERSIONS_H	/* seen it, no need to see it again */

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
#define KERNEL_VERSION(x,y,z) (((x)<<16)+((y)<<8)+(z))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,1,0)
#define HEADER_CACHE_BIND_21
#error "KLIPS is no longer supported on Linux 2.0. Sorry"
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,1,0)
#define SPINLOCK
#define PROC_FS_21
#define NETLINK_SOCK
#define NET_21
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,1,19)
#define net_device_stats enet_statistics
#endif                                                                         

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
#define SPINLOCK_23
#define NETDEV_23
#  ifndef CONFIG_IP_ALIAS
#  define CONFIG_IP_ALIAS
#  endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,25)
#define PROC_FS_2325
#undef  PROC_FS_21
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,30)
#define PROC_NO_DUMMY
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,35)
#define SKB_COPY_EXPAND
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,37)
#define IP_SELECT_IDENT
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,50)) && defined(CONFIG_NETFILTER)
#define SKB_RESET_NFCT
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,2)
#define IP_SELECT_IDENT_NEW
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,4)
#define IPH_is_SKB_PULLED
#define SKB_COW_NEW
#define PROTO_HANDLER_SINGLE_PARM
#define IP_FRAGMENT_LINEARIZE 1
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,4) */
#  ifdef REDHAT_BOGOSITY
#  define IP_SELECT_IDENT_NEW
#  define IPH_is_SKB_PULLED
#  define SKB_COW_NEW
#  define PROTO_HANDLER_SINGLE_PARM
#  endif /* REDHAT_BOGOSITY */
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,4) */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,9)
#define MALLOC_SLAB
#define LINUX_KERNEL_HAS_SNPRINTF
#endif                                                                         

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#define HAVE_NETDEV_PRINTK 1
#define NET_26
#define NETDEV_25
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,8)
#define NEED_INET_PROTOCOL
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
#define HAVE_SOCK_ZAPPED
#define NET_26_12_SKALLOC
#endif

/* see <linux/security.h> */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,13)
#define HAVE_SOCK_SECURITY
/* skb->nf_debug disappared completely in 2.6.13 */
#define HAVE_SKB_NF_DEBUG
#endif

/* skb->stamp changed to skb->tstamp in 2.6.14 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
#define HAVE_TSTAMP
#define HAVE_INET_SK_SPORT
#else
#define HAVE_SKB_LIST 
#endif

#define SYSCTL_IPSEC_DEFAULT_TTL sysctl_ip_default_ttl                      
/* it seems 2.6.14 accidentally removed sysctl_ip_default_ttl */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
#undef  SYSCTL_IPSEC_DEFAULT_TTL
#define SYSCTL_IPSEC_DEFAULT_TTL IPSEC_DEFAULT_TTL
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
#define HAVE_NEW_SKB_LINEARIZE
#endif
 
#if __KERNEL__
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0) 
#include "openswan/ipsec_kern24.h"
#else
#error "kernels before 2.4 are not supported at this time"
#endif
#endif
#endif

#endif /* _OPENSWAN_KVERSIONS_H */

/*
 * $Log: ipsec_kversion.h,v $
 * Revision 1.23  2005/11/13 15:24:07  ken
 * sysctl_ip_default_ttl is missing in 2.6.14.2, and might be for awhile
 *
 * Revision 1.22  2005/11/11 05:01:28  paul
 * Added HAVE_SKB_LIST for 2.6.14 that no longer has skb->list
 *
 * Revision 1.21  2005/11/11 04:42:02  paul
 * Added define for HAVE_INET_SK_SPORT for 2.6.14 and up
 *
 * Revision 1.20  2005/11/11 03:58:34  paul
 * Added a define for 2.6.14 that is not exporting sysctl_ip_default_ttl
 * by accident.
 *
 * Revision 1.19  2005/11/11 03:16:22  paul
 * Added HAVE_TSTAMP define for 2.6.14 kernels
 * (skb->stamp changed to skb->tstamp)
 *
 * Revision 1.18  2005/08/31 23:26:11  mcr
 * 	fixes for 2.6.13
 *
 * Revision 1.15.2.3  2005/11/22 04:11:52  ken
 * Backport fixes for 2.6.14 kernels from HEAD
 *
 * Revision 1.15.2.2  2005/09/01 01:57:19  paul
 * michael's fixes for 2.6.13 from head
 *
 * Revision 1.17  2005/08/27 23:07:21  paul
 * Somewhere between 2.6.12 and 2.6.13rc7 the unused security memnber in sk_buff
 * has been removed. This patch should fix compilation for both cases.
 *
 * Revision 1.16  2005/08/05 08:48:38  mcr
 * 	many compat definitions moved to kern24.h because
 * 	ipsec_kversion.h may be needed by openswan.h.
 *
 * Revision 1.15  2005/07/19 20:02:15  mcr
 * 	sk_alloc() interface change.
 *
 * Revision 1.14  2005/07/08 16:20:05  mcr
 * 	fix for 2.6.12 disapperance of sk_zapped field -> sock_flags.
 *
 * Revision 1.13  2005/05/20 03:19:18  mcr
 * 	modifications for use on 2.4.30 kernel, with backported
 * 	printk_ratelimit(). all warnings removed.
 *
 * Revision 1.12  2005/04/13 22:46:21  mcr
 * 	note that KLIPS does not work on Linux 2.0.
 *
 * Revision 1.11  2004/09/13 02:22:26  mcr
 * 	#define inet_protocol if necessary.
 *
 * Revision 1.10  2004/08/03 18:17:15  mcr
 * 	in 2.6, use "net_device" instead of #define device->net_device.
 * 	this probably breaks 2.0 compiles.
 *
 * Revision 1.9  2004/04/05 19:55:05  mcr
 * Moved from linux/include/freeswan/ipsec_kversion.h,v
 *
 * Revision 1.8  2003/12/13 19:10:16  mcr
 * 	refactored rcv and xmit code - same as FS 2.05.
 *
 * Revision 1.7  2003/07/31 22:48:08  mcr
 * 	derive NET25-ness from presence of NETLINK_XFRM macro.
 *
 * Revision 1.6  2003/06/24 20:22:32  mcr
 * 	added new global: ipsecdevices[] so that we can keep track of
 * 	the ipsecX devices. They will be referenced with dev_hold(),
 * 	so 2.2 may need this as well.
 *
 * Revision 1.5  2003/04/03 17:38:09  rgb
 * Centralised ipsec_kfree_skb and ipsec_dev_{get,put}.
 *
 * Revision 1.4  2002/04/24 07:36:46  mcr
 * Moved from ./klips/net/ipsec/ipsec_kversion.h,v
 *
 * Revision 1.3  2002/04/12 03:21:17  mcr
 * 	three parameter version of ip_select_ident appears first
 * 	in 2.4.2 (RH7.1) not 2.4.4.
 *
 * Revision 1.2  2002/03/08 21:35:22  rgb
 * Defined LINUX_KERNEL_HAS_SNPRINTF to shut up compiler warnings after
 * 2.4.9.  (Andreas Piesk).
 *
 * Revision 1.1  2002/01/29 02:11:42  mcr
 * 	removal of kversions.h - sources that needed it now use ipsec_param.h.
 * 	updating of IPv6 structures to match latest in6.h version.
 * 	removed dead code from freeswan.h that also duplicated kversions.h
 * 	code.
 *
 *
 */
