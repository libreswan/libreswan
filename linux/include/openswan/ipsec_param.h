/*
 * @(#) Openswan tunable paramaters
 *
 * Copyright (C) 2001  Richard Guy Briggs  <rgb@freeswan.org>
 *                 and Michael Richardson  <mcr@freeswan.org>
 * Copyright (C) 2004  Michael Richardson  <mcr@xelerance.com>
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
 * RCSID $Id: ipsec_param.h,v 1.29.6.2 2005/11/27 21:40:14 paul Exp $
 *
 */

/* 
 * This file provides a set of #define's which may be tuned by various
 * people/configurations. It keeps all compile-time tunables in one place.
 *
 * This file should be included before all other IPsec kernel-only files.
 *
 */

#ifndef _IPSEC_PARAM_H_

#ifdef __KERNEL__
#include "ipsec_kversion.h"

/* Set number of ipsecX virtual devices here. */
/* This must be < exp(field width of IPSEC_DEV_FORMAT) */
/* It must also be reasonable so as not to overload the memory and CPU */
/* constraints of the host. */
#define IPSEC_NUM_IF	4
/* The field width must be < IF_NAM_SIZ - strlen("ipsec") - 1. */
/* With "ipsec" being 5 characters, that means 10 is the max field width */
/* but machine memory and CPU constraints are not likely to tollerate */
/* more than 3 digits.  The default is one digit. */
/* Update: userland scripts get upset if they can't find "ipsec0", so */
/* for now, no "0"-padding should be used (which would have been helpful */
/* to make text-searches work */
#define IPSEC_DEV_FORMAT "ipsec%d"
/* For, say, 500 virtual ipsec devices, I would recommend: */
/* #define IPSEC_NUM_IF	500 */
/* #define IPSEC_DEV_FORMAT "ipsec%03d" */
/* Note that the "interfaces=" line in /etc/ipsec.conf would be, um, challenging. */

/* use dynamic ipsecX device allocation */
#ifndef CONFIG_KLIPS_DYNDEV
#define CONFIG_KLIPS_DYNDEV 1
#endif /* CONFIG_KLIPS_DYNDEV */


#ifdef CONFIG_KLIPS_BIGGATE
# define SADB_HASHMOD   8069
#else /* CONFIG_KLIPS_BIGGATE */
# define SADB_HASHMOD	257
#endif /* CONFIG_KLIPS_BIGGATE */
#endif /* __KERNEL__ */

/*
 * This is for the SA reference table. This number is related to the
 * maximum number of SAs that KLIPS can concurrently deal with, plus enough
 * space for keeping expired SAs around.
 *
 * TABLE_MAX_WIDTH is the number of bits that we will use.
 * MAIN_TABLE_WIDTH is the number of bits used for the primary index table.
 *
 */
#ifndef IPSEC_SA_REF_TABLE_IDX_WIDTH
# define IPSEC_SA_REF_TABLE_IDX_WIDTH 16
#endif

#ifndef IPSEC_SA_REF_MAINTABLE_IDX_WIDTH 
# define IPSEC_SA_REF_MAINTABLE_IDX_WIDTH 4 
#endif

#ifndef IPSEC_SA_REF_FREELIST_NUM_ENTRIES 
# define IPSEC_SA_REF_FREELIST_NUM_ENTRIES 256
#endif

#ifndef IPSEC_SA_REF_CODE 
# define IPSEC_SA_REF_CODE 1 
#endif

#ifdef __KERNEL__
/* This is defined for 2.4, but not 2.2.... */
#ifndef ARPHRD_VOID
# define ARPHRD_VOID 0xFFFF
#endif

/* always turn on IPIP mode */
#ifndef CONFIG_KLIPS_IPIP 
#define CONFIG_KLIPS_IPIP 1
#endif

/*
 * Worry about PROC_FS stuff
 */
#if defined(PROC_FS_2325)
/* kernel 2.4 */
# define IPSEC_PROC_LAST_ARG ,int *eof,void *data
# define IPSEC_PROCFS_DEBUG_NO_STATIC
# define IPSEC_PROC_SUBDIRS
#else
/* kernel <2.4 */
# define IPSEC_PROCFS_DEBUG_NO_STATIC DEBUG_NO_STATIC

# ifndef PROC_NO_DUMMY
#  define IPSEC_PROC_LAST_ARG , int dummy
# else
#  define IPSEC_PROC_LAST_ARG
# endif /* !PROC_NO_DUMMY */
#endif /* PROC_FS_2325 */

#if !defined(LINUX_KERNEL_HAS_SNPRINTF)
/* GNU CPP specific! */
# define snprintf(buf, len, fmt...) sprintf(buf, ##fmt)
#endif /* !LINUX_KERNEL_HAS_SNPRINTF */

#ifdef SPINLOCK
# ifdef SPINLOCK_23
#  include <linux/spinlock.h> /* *lock* */
# else /* SPINLOCK_23 */
#  include <asm/spinlock.h> /* *lock* */
# endif /* SPINLOCK_23 */
#endif /* SPINLOCK */

#ifndef KLIPS_FIXES_DES_PARITY
# define KLIPS_FIXES_DES_PARITY 1
#endif /* !KLIPS_FIXES_DES_PARITY */

/* we don't really want to print these unless there are really big problems */
#ifndef KLIPS_DIVULGE_CYPHER_KEY
# define KLIPS_DIVULGE_CYPHER_KEY 0
#endif /* !KLIPS_DIVULGE_CYPHER_KEY */

#ifndef KLIPS_DIVULGE_HMAC_KEY
# define KLIPS_DIVULGE_HMAC_KEY 0
#endif /* !KLIPS_DIVULGE_HMAC_KEY */

#ifndef IPSEC_DISALLOW_IPOPTIONS
# define IPSEC_DISALLOW_IPOPTIONS 1
#endif /* !KLIPS_DIVULGE_HMAC_KEY */

/* extra toggles for regression testing */
#ifdef CONFIG_KLIPS_REGRESS

/* 
 * should pfkey_acquire() become 100% lossy?
 *
 */
extern int sysctl_ipsec_regress_pfkey_lossage;
#ifndef KLIPS_PFKEY_ACQUIRE_LOSSAGE
# ifdef CONFIG_KLIPS_PFKEY_ACQUIRE_LOSSAGE
#  define KLIPS_PFKEY_ACQUIRE_LOSSAGE 100
# else /* CONFIG_KLIPS_PFKEY_ACQUIRE_LOSSAGE */
/* not by default! */
#  define KLIPS_PFKEY_ACQUIRE_LOSSAGE 0
# endif /* CONFIG_KLIPS_PFKEY_ACQUIRE_LOSSAGE */
#endif /* KLIPS_PFKEY_ACQUIRE_LOSSAGE */

#endif /* CONFIG_KLIPS_REGRESS */


/*
 * debugging routines.
 */
#ifdef CONFIG_KLIPS_DEBUG
extern void ipsec_print_ip(struct iphdr *ip);

	#define KLIPS_PRINT(flag, format, args...) \
		((flag) ? printk(KERN_INFO format , ## args) : 0)
	#define KLIPS_PRINTMORE(flag, format, args...) \
		((flag) ? printk(format , ## args) : 0)
	#define KLIPS_IP_PRINT(flag, ip) \
		((flag) ? ipsec_print_ip(ip) : 0)
#else /* CONFIG_KLIPS_DEBUG */
	#define KLIPS_PRINT(flag, format, args...) do ; while(0)
	#define KLIPS_PRINTMORE(flag, format, args...) do ; while(0)
	#define KLIPS_IP_PRINT(flag, ip) do ; while(0)
#endif /* CONFIG_KLIPS_DEBUG */


/* 
 * Stupid kernel API differences in APIs. Not only do some
 * kernels not have ip_select_ident, but some have differing APIs,
 * and SuSE has one with one parameter, but no way of checking to
 * see what is really what.
 */

#ifdef SUSE_LINUX_2_4_19_IS_STUPID
#define KLIPS_IP_SELECT_IDENT(iph, skb) ip_select_ident(iph)
#else

/* simplest case, nothing */
#if !defined(IP_SELECT_IDENT)
#define KLIPS_IP_SELECT_IDENT(iph, skb)  do { iph->id = htons(ip_id_count++); } while(0)
#endif

/* kernels > 2.3.37-ish */
#if defined(IP_SELECT_IDENT) && !defined(IP_SELECT_IDENT_NEW)
#define KLIPS_IP_SELECT_IDENT(iph, skb) ip_select_ident(iph, skb->dst)
#endif

/* kernels > 2.4.2 */
#if defined(IP_SELECT_IDENT) && defined(IP_SELECT_IDENT_NEW)
#define KLIPS_IP_SELECT_IDENT(iph, skb) ip_select_ident(iph, skb->dst, NULL)
#endif

#endif /* SUSE_LINUX_2_4_19_IS_STUPID */

/*
 * make klips fail test:east-espiv-01.
 * exploit is at testing/attacks/espiv
 *
 */
#define KLIPS_IMPAIRMENT_ESPIV_CBC_ATTACK 0


/* IP_FRAGMENT_LINEARIZE is set in freeswan.h if Kernel > 2.4.4 */
#ifndef IP_FRAGMENT_LINEARIZE
# define IP_FRAGMENT_LINEARIZE 0
#endif /* IP_FRAGMENT_LINEARIZE */
#endif /* __KERNEL__ */

#ifdef NEED_INET_PROTOCOL
#define inet_protocol net_protocol
#endif

#if defined(CONFIG_IPSEC_NAT_TRAVERSAL) && CONFIG_IPSEC_NAT_TRAVERSAL
#define NAT_TRAVERSAL 1
#else
/* let people either #undef, or #define = 0 it */
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
#undef CONFIG_IPSEC_NAT_TRAVERSAL
#endif
#endif

#ifndef IPSEC_DEFAULT_TTL
#define IPSEC_DEFAULT_TTL 64
#endif

#define _IPSEC_PARAM_H_
#endif /* _IPSEC_PARAM_H_ */

/*
 * $Log: ipsec_param.h,v $
 * Revision 1.29.6.2  2005/11/27 21:40:14  paul
 * Pull down TTL fixes from head. this fixes "Unknown symbol sysctl_ip_default_ttl"
 * in for klips as module.
 *
 * Revision 1.29.6.1  2005/08/12 16:24:18  ken
 * Pull in NAT-T compile logic from HEAD
 *
 * Revision 1.29  2005/01/26 00:50:35  mcr
 * 	adjustment of confusion of CONFIG_IPSEC_NAT vs CONFIG_KLIPS_NAT,
 * 	and make sure that NAT_TRAVERSAL is set as well to match
 * 	userspace compiles of code.
 *
 * Revision 1.28  2004/09/13 15:50:15  mcr
 * 	spell NEED_INET properly, not NET_INET.
 *
 * Revision 1.27  2004/09/13 02:21:45  mcr
 * 	always turn on IPIP mode.
 * 	#define inet_protocol if necessary.
 *
 * Revision 1.26  2004/08/17 03:25:43  mcr
 * 	freeswan->openswan.
 *
 * Revision 1.25  2004/07/10 19:08:41  mcr
 * 	CONFIG_IPSEC -> CONFIG_KLIPS.
 *
 * Revision 1.24  2004/04/05 19:55:06  mcr
 * Moved from linux/include/freeswan/ipsec_param.h,v
 *
 * Revision 1.23  2003/12/13 19:10:16  mcr
 * 	refactored rcv and xmit code - same as FS 2.05.
 *
 * Revision 1.22  2003/10/31 02:27:05  mcr
 * 	pulled up port-selector patches and sa_id elimination.
 *
 * Revision 1.21.4.1  2003/10/29 01:10:19  mcr
 * 	elimited "struct sa_id"
 *
 * Revision 1.21  2003/04/03 17:38:18  rgb
 * Centralised ipsec_kfree_skb and ipsec_dev_{get,put}.
 * Change indentation for readability.
 *
 * Revision 1.20  2003/03/14 08:09:26  rgb
 * Fixed up CONFIG_IPSEC_DYNDEV definitions.
 *
 * Revision 1.19  2003/01/30 02:31:43  rgb
 *
 * Rename SAref table macro names for clarity.
 *
 * Revision 1.18  2002/09/30 19:06:26  rgb
 * 	Reduce default table to 16 bits width.
 *
 * Revision 1.17  2002/09/20 15:40:29  rgb
 * Define switch to activate new SAref code.
 * Prefix macros with "IPSEC_".
 * Rework saref freelist.
 * Restrict some bits to kernel context for use to klips utils.
 *
 * Revision 1.16  2002/09/20 05:00:31  rgb
 * Define switch to divulge hmac keys for debugging.
 * Added IPOPTIONS switch.
 *
 * Revision 1.15  2002/09/19 02:34:24  mcr
 * 	define IPSEC_PROC_SUBDIRS if we are 2.4, and use that in ipsec_proc.c
 * 	to decide if we are to create /proc/net/ipsec/.
 *
 * Revision 1.14  2002/08/30 01:20:54  mcr
 * 	reorganized 2.0/2.2/2.4 procfs support macro so match
 * 	2.4 values/typedefs.
 *
 * Revision 1.13  2002/07/28 22:03:28  mcr
 * 	added some documentation to SA_REF_*
 * 	turned on fix for ESPIV attack, now that we have the attack code.
 *
 * Revision 1.12  2002/07/26 08:48:31  rgb
 * Added SA ref table code.
 *
 * Revision 1.11  2002/07/23 02:57:45  rgb
 * Define ARPHRD_VOID for < 2.4 kernels.
 *
 * Revision 1.10  2002/05/27 21:37:28  rgb
 * Set the defaults sanely for those adventurous enough to try more than 1
 * digit of ipsec devices.
 *
 * Revision 1.9  2002/05/27 18:56:07  rgb
 * Convert to dynamic ipsec device allocation.
 *
 * Revision 1.8  2002/04/24 07:36:47  mcr
 * Moved from ./klips/net/ipsec/ipsec_param.h,v
 *
 * Revision 1.7  2002/04/20 00:12:25  rgb
 * Added esp IV CBC attack fix, disabled.
 *
 * Revision 1.6  2002/01/29 02:11:42  mcr
 * 	removal of kversions.h - sources that needed it now use ipsec_param.h.
 * 	updating of IPv6 structures to match latest in6.h version.
 * 	removed dead code from freeswan.h that also duplicated kversions.h
 * 	code.
 *
 * Revision 1.5  2002/01/28 19:22:01  mcr
 * 	by default, turn off LINEARIZE option
 * 	(let kversions.h turn it on)
 *
 * Revision 1.4  2002/01/20 20:19:36  mcr
 * 	renamed option to IP_FRAGMENT_LINEARIZE.
 *
 * Revision 1.3  2002/01/12 02:57:25  mcr
 * 	first regression test causes acquire messages to be lost
 * 	100% of the time. This is to help testing of pluto.
 *
 * Revision 1.2  2001/11/26 09:16:14  rgb
 * Merge MCR's ipsec_sa, eroute, proc and struct lifetime changes.
 *
 * Revision 1.1.2.3  2001/10/23 04:40:16  mcr
 * 	added #define for DIVULGING session keys in debug output.
 *
 * Revision 1.1.2.2  2001/10/22 20:53:25  mcr
 * 	added a define to control forcing of DES parity.
 *
 * Revision 1.1.2.1  2001/09/25 02:20:19  mcr
 * 	many common kernel configuration questions centralized.
 * 	more things remain that should be moved from freeswan.h.
 *
 *
 * Local variables:
 * c-file-style: "linux"
 * End:
 *
 */
