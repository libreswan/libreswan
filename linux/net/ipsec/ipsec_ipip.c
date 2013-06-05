/*
 * processing code for IPIP
 * Copyright (C) 2003 Michael Richardson <mcr@sandelman.ottawa.on.ca>
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

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) && \
	!defined(AUTOCONF_INCLUDED)
#include <linux/config.h>
#endif

#define __NO_VERSION__
#include <linux/module.h>
#include <linux/kernel.h> /* printk() */

#include "libreswan/ipsec_param.h"

#include <linux/slab.h>         /* kmalloc() */
#include <linux/errno.h>        /* error codes */
#include <linux/types.h>        /* size_t */
#include <linux/interrupt.h>    /* mark_bh */

#include <linux/netdevice.h>    /* struct device, and other headers */
#include <linux/etherdevice.h>  /* eth_type_trans */
#include <linux/ip.h>           /* struct iphdr */
#include <linux/skbuff.h>
#include <libreswan.h>
#include <linux/spinlock.h> /* *lock* */

#include <net/ip.h>

#include "libreswan/radij.h"
#include "libreswan/ipsec_encap.h"
#include "libreswan/ipsec_sa.h"

#include "libreswan/ipsec_radij.h"
#include "libreswan/ipsec_xform.h"
#include "libreswan/ipsec_tunnel.h"
#include "libreswan/ipsec_rcv.h"
#include "libreswan/ipsec_xmit.h"

#include "libreswan/ipsec_auth.h"
#include "libreswan/ipsec_ipip.h"
#include "libreswan/ipsec_param.h"

#include "libreswan/ipsec_proto.h"

#include "libreswan/ipsec_param2.h"

enum ipsec_xmit_value ipsec_xmit_ipip_setup(struct ipsec_xmit_state *ixs)
{
	lsw_ip4_hdr(ixs)->version  = 4;

	switch (sysctl_ipsec_tos) {
	case 0:
		lsw_ip4_hdr(ixs)->tos = ip_hdr(ixs->skb)->tos;
		break;
	case 1:
		lsw_ip4_hdr(ixs)->tos = 0;
		break;
	default:
		break;
	}
	lsw_ip4_hdr(ixs)->ttl      = SYSCTL_IPSEC_DEFAULT_TTL;
	lsw_ip4_hdr(ixs)->frag_off = 0;
	lsw_ip4_hdr(ixs)->saddr    =
		((struct sockaddr_in*)(ixs->ipsp->ips_addr_s))->sin_addr.s_addr;
	lsw_ip4_hdr(ixs)->daddr    =
		((struct sockaddr_in*)(ixs->ipsp->ips_addr_d))->sin_addr.s_addr;
	lsw_ip4_hdr(ixs)->protocol = IPPROTO_IPIP;
	lsw_ip4_hdr(ixs)->ihl      = sizeof(struct iphdr) >> 2;

#ifdef NET_21
	printk("THIS CODE IS NEVER CALLED\n");
	skb_set_transport_header(ixs->skb,
				 ipsec_skb_offset(ixs->skb, ip_hdr(ixs->skb)));
#endif  /* NET_21 */
	return IPSEC_XMIT_OK;
}

struct xform_functions ipip_xform_funcs[] = {
	{
		protocol:           IPPROTO_IPIP,
		rcv_checks:         NULL,
		rcv_setup_auth:     NULL,
		rcv_calc_auth:      NULL,
		rcv_decrypt:        NULL,

		xmit_setup:         ipsec_xmit_ipip_setup,
		xmit_headroom:      sizeof(struct iphdr),
		xmit_needtailroom:  0,
	},
};

