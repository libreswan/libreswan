/*
 * processing code for IPCOMP
 * Copyright (C) 2003 Michael Richardson <mcr@sandelman.ottawa.on.ca>
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
extern int sysctl_ipsec_inbound_policy_check;
#include "libreswan/ipsec_xmit.h"

#include "libreswan/ipsec_auth.h"

#ifdef CONFIG_KLIPS_IPCOMP
#include "libreswan/ipsec_ipcomp.h"
#endif /* CONFIG_KLIPS_IPCOMP */

#include "libreswan/ipsec_proto.h"

#ifdef CONFIG_KLIPS_OCF
#include "ipsec_ocf.h"
#endif

#ifdef CONFIG_KLIPS_IPCOMP
enum ipsec_rcv_value ipsec_rcv_ipcomp_checks(struct ipsec_rcv_state *irs,
					     struct sk_buff *skb)
{
	int ipcompminlen;

	ipcompminlen = sizeof(struct iphdr);

	if (skb->len < (ipcompminlen + sizeof(struct ipcomphdr))) {
		KLIPS_PRINT(debug_rcv & DB_RX_INAU,
			    "klips_debug:ipsec_rcv_ipcomp_checks: "
			    "runt comp packet of skb->len=%d received from %s, dropped.\n",
			    skb->len,
			    irs->ipsaddr_txt);
		if (irs->stats)
			irs->stats->rx_errors++;
		return IPSEC_RCV_BADLEN;
	}

	irs->protostuff.ipcompstuff.compp =
		(struct ipcomphdr *)skb_transport_header(skb);
	irs->said.spi =
		htonl((__u32)ntohs(irs->protostuff.ipcompstuff.compp->
				   ipcomp_cpi));
	return IPSEC_RCV_OK;
}

enum ipsec_rcv_value ipsec_rcv_ipcomp_decomp(struct ipsec_rcv_state *irs)
{
	unsigned int flags = 0;
	struct ipsec_sa *ipsp = irs->ipsp;
	struct sk_buff *skb;

	skb = irs->skb;

	ipsec_xmit_dmp("ipcomp", skb_transport_header(skb), skb->len);

	if (ipsp == NULL)
		return IPSEC_RCV_SAIDNOTFOUND;

	if (sysctl_ipsec_inbound_policy_check &&
	    ((((ntohl(ipsp->ips_said.spi) & 0x0000ffff) !=
	       (ntohl(irs->said.spi) & 0x0000ffff)) &&
	      (ipsp->ips_encalg != ntohl(irs->said.spi))  /* this is a workaround for peer non-compliance with rfc2393 */
	      ))) {
		char sa2[SATOT_BUF];
		size_t sa_len2 = 0;

		sa_len2 = KLIPS_SATOT(debug_rcv, &ipsp->ips_said, 0, sa2,
				      sizeof(sa2));

		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_ipcomp_decomp: "
			    "Incoming packet with SA(IPCA):%s does not match policy SA(IPCA):%s cpi=%04x cpi->spi=%08x spi=%08x, spi->cpi=%04x for SA grouping, dropped.\n",
			    irs->sa_len ? irs->sa : " (error)",
			    sa_len2 ? sa2 : " (error)",
			    ntohs(irs->protostuff.ipcompstuff.compp->ipcomp_cpi),
			    (__u32)ntohl(irs->said.spi),
			    (__u32)ntohl((ipsp->ips_said.spi)),
			    (__u16)(ntohl(ipsp->ips_said.spi) & 0x0000ffff));
		if (irs->stats)
			irs->stats->rx_dropped++;
		return IPSEC_RCV_SAIDNOTFOUND;
	}

	if (lsw_ip_hdr_version(irs) == 6)
		ipsp->ips_comp_ratio_cbytes +=
			ntohs(lsw_ip6_hdr(irs)->payload_len) +
			sizeof(struct ipv6hdr);
	else
		ipsp->ips_comp_ratio_cbytes +=
			ntohs(lsw_ip4_hdr(irs)->tot_len);
	irs->next_header = irs->protostuff.ipcompstuff.compp->ipcomp_nh;

#ifdef CONFIG_KLIPS_OCF
	if (irs->ipsp->ocf_in_use)
		return ipsec_ocf_rcv(irs);

#endif

	skb = skb_decompress(skb, ipsp, &flags);
	if (!skb || flags) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_ipcomp_decomp: "
			    "skb_decompress() returned error flags=%x, dropped.\n",
			    flags);
		if (irs->stats) {
			if (flags)
				irs->stats->rx_errors++;
			else
				irs->stats->rx_dropped++;
		}
		return IPSEC_RCV_IPCOMPFAILED;
	}

	/* make sure we update the pointer */
	irs->skb = skb;

	irs->iph = (void *) ip_hdr(skb);

	if (lsw_ip_hdr_version(irs) == 6)
		ipsp->ips_comp_ratio_dbytes +=
			ntohs(lsw_ip6_hdr(irs)->payload_len) +
			sizeof(struct ipv6hdr);
	else
		ipsp->ips_comp_ratio_dbytes +=
			ntohs(lsw_ip4_hdr(irs)->tot_len);

	KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv_ipcomp_decomp: "
		    "packet decompressed SA(IPCA):%s cpi->spi=%08x spi=%08x, spi->cpi=%04x, nh=%d.\n",
		    irs->sa_len ? irs->sa : " (error)",
		    (__u32)ntohl(irs->said.spi),
		    ipsp != NULL ? (__u32)ntohl((ipsp->ips_said.spi)) : 0,
		    ipsp != NULL ?
		      (__u16)(ntohl(ipsp->ips_said.spi) & 0x0000ffff) : 0,
		    irs->next_header);
	KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, irs->iph);

	return IPSEC_RCV_OK;
}

#if 0
enum ipsec_xmit_value ipsec_xmit_ipcomp_setup(struct ipsec_xmit_state *ixs)
{
	unsigned int flags = 0;
	unsigned int tot_len, old_tot_len;

#ifdef CONFIG_KLIPS_IPV6
	if (lsw_ip_hdr_version(ixs) == 6)
		old_tot_len = ntohs(lsw_ip6_hdr(ixs)->payload_len) +
			      sizeof(struct ipv6hdr);
	else
#endif
	old_tot_len = ntohs(lsw_ip4_hdr(ixs)->tot_len);
	ixs->ipsp->ips_comp_ratio_dbytes += old_tot_len;

	ixs->skb = skb_compress(ixs->skb, ixs->ipsp, &flags);

	ixs->iph = (void *)ip_hdr(ixs->skb);

#ifdef CONFIG_KLIPS_IPV6
	if (lsw_ip_hdr_version(ixs) == 6) {
		IPSEC_FRAG_OFF_DECL(frag_off)
		int nexthdroff;
		unsigned char nexthdr = lsw_ip6_hdr(ixs)->nexthdr;
		nexthdroff = ipsec_ipv6_skip_exthdr(ixs->skb,
				    ((void *)(lsw_ip6_hdr(ixs) + 1)) -
				    (void*)ixs->skb->data,
						    &nexthdr, &frag_off);
		ixs->iphlen = nexthdroff - (ixs->iph - (void*)ixs->skb->data);
		tot_len = ntohs(lsw_ip6_hdr(ixs)->payload_len) +
			  sizeof(struct ipv6hdr);
	} else
#endif
	{
		ixs->iphlen = lsw_ip4_hdr(ixs)->ihl << 2;
		tot_len = ntohs(lsw_ip4_hdr(ixs)->tot_len);
	}
	ixs->ipsp->ips_comp_ratio_cbytes += tot_len;

	if (debug_tunnel & DB_TN_CROUT) {
		if (old_tot_len > tot_len)
			KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
				    "klips_debug:ipsec_xmit_ipcomp_setup: "
				    "packet shrunk from %d to %d bytes after compression, cpi=%04x (should be from spi=%08x, spi&0xffff=%04x.\n",
				    old_tot_len, tot_len,
				    ntohs(((struct ipcomphdr *)
					(((char*)ixs->iph) +
					 (lsw_ip4_hdr(ixs)->ihl << 2)))->
					  ipcomp_cpi),
				    ntohl(ixs->ipsp->ips_said.spi),
				    (__u16)(ntohl(ixs->ipsp->ips_said.spi) &
					    0x0000ffff));
		else
			KLIPS_PRINT(debug_tunnel & DB_TN_CROUT,
				    "klips_debug:ipsec_xmit_ipcomp_setup: "
				    "packet did not compress (flags = %d).\n",
				    flags);
	}

	return IPSEC_XMIT_OK;
}
#endif

struct xform_functions ipcomp_xform_funcs[] = {
	{
		protocol:           IPPROTO_COMP,
		rcv_checks:  ipsec_rcv_ipcomp_checks,
		rcv_decrypt: ipsec_rcv_ipcomp_decomp,
#if 0
		xmit_setup:  ipsec_xmit_ipcomp_setup,
		xmit_headroom: 0,
		xmit_needtailroom: 0,
#endif
	},
};

#if 0
/* We probably don't want to install a pure IPCOMP protocol handler, but
   only want to handle IPCOMP if it is encapsulated inside an ESP payload
   (which is already handled) */
#ifndef CONFIG_XFRM_ALTERNATE_STACK
#ifdef CONFIG_KLIPS_IPCOMP
struct inet_protocol comp_protocol =
{
	ipsec_rcv,                      /* COMP handler		*/
	NULL,                           /* COMP error control	*/
#ifdef NET_26
	1,                              /* no policy */
#else
	0,                              /* next */
	IPPROTO_COMP,                   /* protocol ID */
	0,                              /* copy */
	NULL,                           /* data */
	"COMP"                          /* name */
#endif
};
#endif  /* CONFIG_KLIPS_IPCOMP */
#endif  /* CONFIG_XFRM_ALTERNATE_STACK */
#endif

#endif /* CONFIG_KLIPS_IPCOMP */
