/*
 * IP compression header declations
 *
 * Copyright (C) 2003 Michael Richardson <mcr@sandelman.ottawa.on.ca>
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
 * RCSID $Id: ipsec_ipcomp.h,v 1.4 2004/07/10 19:08:41 mcr Exp $
 */

#ifndef IPSEC_IPCOMP_H
#define IPSEC_IPCOMP_H

#include "openswan/ipsec_auth.h"

/* Prefix all global deflate symbols with "ipcomp_" to avoid collisions with ppp_deflate & ext2comp */
#ifndef IPCOMP_PREFIX
#define IPCOMP_PREFIX
#endif /* IPCOMP_PREFIX */

#ifndef IPPROTO_COMP
#define IPPROTO_COMP 108
#endif /* IPPROTO_COMP */

#ifdef CONFIG_KLIPS_DEBUG
extern int sysctl_ipsec_debug_ipcomp;
#endif /* CONFIG_KLIPS_DEBUG */

struct ipcomphdr {			/* IPCOMP header */
    __u8    ipcomp_nh;		/* Next header (protocol) */
    __u8    ipcomp_flags;	/* Reserved, must be 0 */
    __u16   ipcomp_cpi;		/* Compression Parameter Index */
};

#ifndef CONFIG_XFRM_ALTERNATE_STACK
extern struct inet_protocol comp_protocol;
#endif /* CONFIG_XFRM_ALTERNATE_STACK */

extern int sysctl_ipsec_debug_ipcomp;

#define IPCOMP_UNCOMPRESSABLE     0x000000001
#define IPCOMP_COMPRESSIONERROR   0x000000002
#define IPCOMP_PARMERROR          0x000000004
#define IPCOMP_DECOMPRESSIONERROR 0x000000008

#define IPCOMP_ADAPT_INITIAL_TRIES	8
#define IPCOMP_ADAPT_INITIAL_SKIP	4
#define IPCOMP_ADAPT_SUBSEQ_TRIES	2
#define IPCOMP_ADAPT_SUBSEQ_SKIP	8

/* Function prototypes */
struct sk_buff *skb_compress(struct sk_buff *skb, struct ipsec_sa *ips, unsigned int *flags);
struct sk_buff *skb_decompress(struct sk_buff *skb, struct ipsec_sa *ips, unsigned int *flags);

extern struct xform_functions ipcomp_xform_funcs[];

#endif /* IPSEC_IPCOMP_H */

/*
 * $Log: ipsec_ipcomp.h,v $
 * Revision 1.4  2004/07/10 19:08:41  mcr
 * 	CONFIG_IPSEC -> CONFIG_KLIPS.
 *
 * Revision 1.3  2004/04/06 02:49:08  mcr
 * 	pullup of algo code from alg-branch.
 *
 * Revision 1.2  2004/04/05 19:55:05  mcr
 * Moved from linux/include/freeswan/ipsec_ipcomp.h,v
 *
 * Revision 1.1  2003/12/13 19:10:16  mcr
 * 	refactored rcv and xmit code - same as FS 2.05.
 *
 * Revision 1.2  2003/12/11 20:14:58  mcr
 * 	refactored the xmit code, to move all encapsulation
 * 	code into protocol functions. Note that all functions
 * 	are essentially done by a single function, which is probably
 * 	wrong.
 * 	the rcv_functions structures are renamed xform_functions.
 *
 * Revision 1.1  2003/12/06 21:21:19  mcr
 * 	split up receive path into per-transform files, for
 * 	easier later removal.
 *
 *
 *
 */



