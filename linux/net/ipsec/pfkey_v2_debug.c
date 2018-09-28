/*
 * @(#) pfkey version 2 debugging messages
 *
 * Copyright (C) 2001  Richard Guy Briggs  <rgb@freeswan.org>
 *                 and Michael Richardson  <mcr@freeswan.org>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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
 */

#ifdef __KERNEL__

# include <linux/kernel.h>              /* for printk */

# include "libreswan/ipsec_kversion.h"  /* for malloc switch */
# include <linux/slab.h>                /* kmalloc() */
# include <linux/errno.h>               /* error codes */
# include <linux/types.h>               /* size_t */
# include <linux/interrupt.h>           /* mark_bh */

# include <linux/netdevice.h>           /* struct device, and other headers */
# include <linux/etherdevice.h>         /* eth_type_trans */
extern int debug_pfkey;

#else /* __KERNEL__ */

# include <sys/types.h>

#if defined(linux)
# include <linux/types.h>
# include <linux/errno.h>
#endif

#endif /* __KERNEL__ */

#include "libreswan.h"
#include "libreswan/pfkeyv2.h"
#include "libreswan/pfkey.h"

/*
 * This file provides ASCII translations of PF_KEY magic numbers.
 *
 */

static char *pfkey_sadb_ext_strings[] = {
	"reserved",                     /* K_SADB_EXT_RESERVED             0 */
	"security-association",         /* K_SADB_EXT_SA                   1 */
	"lifetime-current",             /* K_SADB_EXT_LIFETIME_CURRENT     2 */
	"lifetime-hard",                /* K_SADB_EXT_LIFETIME_HARD        3 */
	"lifetime-soft",                /* K_SADB_EXT_LIFETIME_SOFT        4 */
	"source-address",               /* K_SADB_EXT_ADDRESS_SRC          5 */
	"destination-address",          /* K_SADB_EXT_ADDRESS_DST          6 */
	"proxy-address",                /* K_SADB_EXT_ADDRESS_PROXY        7 */
	"authentication-key",           /* K_SADB_EXT_KEY_AUTH             8 */
	"cipher-key",                   /* K_SADB_EXT_KEY_ENCRYPT          9 */
	"source-identity",              /* K_SADB_EXT_IDENTITY_SRC         10 */
	"destination-identity",         /* K_SADB_EXT_IDENTITY_DST         11 */
	"sensitivity-label",            /* K_SADB_EXT_SENSITIVITY          12 */
	"proposal",                     /* K_SADB_EXT_PROPOSAL             13 */
	"supported-auth",               /* K_SADB_EXT_SUPPORTED_AUTH       14 */
	"supported-cipher",             /* K_SADB_EXT_SUPPORTED_ENCRYPT    15 */
	"spi-range",                    /* K_SADB_EXT_SPIRANGE             16 */
	"X-kmpprivate",                 /* K_SADB_X_EXT_KMPRIVATE          17 */
	"X-satype2",                    /* K_SADB_X_EXT_SATYPE2            18 */
	"X-security-association",       /* K_SADB_X_EXT_SA2                19 */
	"X-destination-address2",       /* K_SADB_X_EXT_ADDRESS_DST2       20 */
	"X-source-flow-address",        /* K_SADB_X_EXT_ADDRESS_SRC_FLOW   21 */
	"X-dest-flow-address",          /* K_SADB_X_EXT_ADDRESS_DST_FLOW   22 */
	"X-source-mask",                /* K_SADB_X_EXT_ADDRESS_SRC_MASK   23 */
	"X-dest-mask",                  /* K_SADB_X_EXT_ADDRESS_DST_MASK   24 */
	"X-set-debug",                  /* K_SADB_X_EXT_DEBUG              25 */
	"X-ext-protocol",               /* K_SADB_X_EXT_PROTOCOL           26 */
	"X-NAT-T-type",                 /* K_SADB_X_EXT_NAT_T_TYPE         27 */
	"X-NAT-T-sport",                /* K_SADB_X_EXT_NAT_T_SPORT        28 */
	"X-NAT-T-dport",                /* K_SADB_X_EXT_NAT_T_DPORT        29 */
	"X-NAT-T-OA",                   /* K_SADB_X_EXT_NAT_T_OA           30 */
	"X-plumbif",                    /* K_SADB_X_EXT_PLUMBIF            31 */
	"X-saref",                      /* K_SADB_X_EXT_SAREF              32 */
};

const char *pfkey_v2_sadb_ext_string(int ext)
{
	if (ext <= K_SADB_EXT_MAX)
		return pfkey_sadb_ext_strings[ext];
	else
		return "unknown-ext";
}

static char *pfkey_sadb_type_strings[K_SADB_MAX + 1] = {
	[K_SADB_RESERVED] = "reserved",                         /* K_SADB_RESERVED      */
	[K_SADB_GETSPI] = "getspi",                             /* K_SADB_GETSPI        */
	[K_SADB_UPDATE] = "update",                             /* K_SADB_UPDATE        */
	[K_SADB_ADD] = "add",                                   /* K_SADB_ADD           */
	[K_SADB_DELETE] = "delete",                             /* K_SADB_DELETE        */
	[K_SADB_GET] = "get",                                   /* K_SADB_GET           */
	[K_SADB_ACQUIRE] = "acquire",                           /* K_SADB_ACQUIRE       */
	[K_SADB_REGISTER] = "register",                         /* K_SADB_REGISTER      */
	[K_SADB_EXPIRE] = "expire",                             /* K_SADB_EXPIRE        */
	[K_SADB_FLUSH] = "flush",                               /* K_SADB_FLUSH         */
	[K_SADB_DUMP] = "dump",                                 /* K_SADB_DUMP          */
	[K_SADB_X_PROMISC] = "x-promisc",                       /* K_SADB_X_PROMISC     */
	[K_SADB_X_PCHANGE] = "x-pchange",                       /* K_SADB_X_PCHANGE     */
	[K_SADB_X_GRPSA] = "x-groupsa",                         /* K_SADB_X_GRPSA       */
	[K_SADB_X_ADDFLOW] = "x-addflow(eroute)",               /* K_SADB_X_ADDFLOW     */
	[K_SADB_X_DELFLOW] = "x-delflow(eroute)",               /* K_SADB_X_DELFLOW     */
	[K_SADB_X_DEBUG] = "x-debug",                           /* K_SADB_X_DEBUG       */
	[K_SADB_X_NAT_T_NEW_MAPPING] = "x-natt-new-mapping",    /* K_SADB_X_NAT_T_NEW_MAPPING */
	[K_SADB_X_PLUMBIF] = "x-plumbif",                       /* K_SADB_X_PLUMBIF     */
	[K_SADB_X_UNPLUMBIF] = "x-unplumbif",                   /* K_SADB_X_UNPLUMBIF   */
};

const char *pfkey_v2_sadb_type_string(unsigned sadb_type)
{
	if (sadb_type <= K_SADB_MAX && pfkey_sadb_type_strings[sadb_type] !=
	    NULL)
		return pfkey_sadb_type_strings[sadb_type];
	else
		return "unknown-sadb-type";
}
