/*
 * @(#) Libreswan tunable paramaters
 *
 * Copyright (C) 2001  Richard Guy Briggs  <rgb@freeswan.org>
 *                 and Michael Richardson  <mcr@freeswan.org>
 * Copyright (C) 2004  Michael Richardson  <mcr@xelerance.com>
 * Copyright (C) 2012  Paul Wouters  <paul@libreswan.org>
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
 *
 *
 */

/*
 * This file provides a set of #defines that may be tuned by various
 * people/configurations. It keeps all compile-time tunables in one place.
 *
 * This file should be included before all other IPsec kernel-only files.
 *
 */

#ifndef _IPSEC_PARAM_H_

#ifdef __KERNEL__

#include "libreswan/ipsec_kversion.h"

/* Set number of ipsecX virtual devices here. */
/* This must be < exp(field width of IPSEC_DEV_FORMAT) */
/* It must also be reasonable so as not to overload the memory and CPU */
/* constraints of the host. */
#ifdef CONFIG_KLIPS_IF_MAX
#define IPSEC_NUM_IFMAX CONFIG_KLIPS_IF_MAX
#endif
#ifndef IPSEC_NUM_IFMAX
#define IPSEC_NUM_IFMAX 64
#endif

/* default number of ipsecX devices to create */
#ifdef CONFIG_KLIPS_IF_NUM
#define IPSEC_NUM_IF    CONFIG_KLIPS_IF_NUM
#else
#define IPSEC_NUM_IF    2
#endif

/* The field width must be < IF_NAM_SIZ - strlen("ipsec") - 1. */
/* With "ipsec" being 5 characters, that means 10 is the max field width */
/* but machine memory and CPU constraints are not likely to tolerate */
/* more than 3 digits.  The default is one digit. */
/* Update: userland scripts get upset if they can't find "ipsec0", so */
/* for now, no "0"-padding should be used (which would have been helpful) */
/* to make text-searches work */
#define IPSEC_DEV_FORMAT "ipsec%d"
#define MAST_DEV_FORMAT "mast%d"

/* For, say, 500 virtual ipsec devices, I would recommend: */
/* #define IPSEC_NUM_IF	500 */
/* #define IPSEC_DEV_FORMAT "ipsec%03d" */
/* Note that the "interfaces=" line in /etc/ipsec.conf would be, um, challenging. */

/* use dynamic ipsecX device allocation */
#ifndef CONFIG_KLIPS_DYNDEV
#define CONFIG_KLIPS_DYNDEV 1
#endif /* CONFIG_KLIPS_DYNDEV */

# define SADB_HASHMOD   257

#endif /* __KERNEL__ */

/*
 * This is for the SA reference table. This number is related to the
 * maximum number of SAs that KLIPS can concurrently deal with, plus enough
 * space for keeping expired SAs around.
 *
 * TABLE_IDX_WIDTH is the number of bits that we will use.
 * MAIN_TABLE_WIDTH is the number of bits used for the primary index table.
 *
 */
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
/* kernel 2.4 */
# define IPSEC_PROC_LAST_ARG , int *eof, void *data
# define IPSEC_PROCFS_DEBUG_NO_STATIC
# define IPSEC_PROC_SUBDIRS

#  include <linux/spinlock.h> /* *lock* */

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
#endif  /* KLIPS_PFKEY_ACQUIRE_LOSSAGE */

#endif  /* CONFIG_KLIPS_REGRESS */

/*
 * debugging routines.
 */
#define KLIPS_ERROR(flag, format, args ...) { \
		if (printk_ratelimit() || (flag)) \
			printk(KERN_ERR "KLIPS " format, ## args); \
	}
#define KLIPS_PRINT(flag, format, args ...) \
	((flag) ? printk(KERN_INFO format, ## args) : 0)
#define KLIPS_PRINTMORE(flag, format, args ...) \
	((flag) ? printk(format, ## args) : 0)
#define KLIPS_IP_PRINT(flag, ip) \
	((flag) ? ipsec_print_ip(ip) : 0)
#define KLIPS_SATOT(flag, sa, format, dst, dstlen) \
	((flag) ? satot(sa, format, dst, dstlen) : 0)
#if 0 /* not CONFIG_KLIPS_DEBUG */
#define KLIPS_ERROR(flag, format, args ...) { \
		if (printk_ratelimit()) \
			printk(KERN_ERR "KLIPS " format, ## args); \
	}
#define KLIPS_PRINT(flag, format, args ...)  { }
#define KLIPS_PRINTMORE(flag, format, args ...) { }
#define KLIPS_IP_PRINT(flag, ip) { }
#define KLIPS_SATOT(flag, sa, format, dst, dstlen) (0)
#endif /* CONFIG_KLIPS_DEBUG */

/*
 * make klips fail test:east-espiv-01.
 * exploit is at testing/attacks/espiv
 *
 */
#define KLIPS_IMPAIRMENT_ESPIV_CBC_ATTACK 0

#endif /* __KERNEL__ */

#ifdef NEED_INET_PROTOCOL
#define inet_protocol net_protocol
#endif

#ifndef IPSEC_DEFAULT_TTL
#define IPSEC_DEFAULT_TTL 64
#endif

#define _IPSEC_PARAM_H_
#endif /* _IPSEC_PARAM_H_ */
