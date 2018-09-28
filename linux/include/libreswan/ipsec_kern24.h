/*
 * @(#) routines to makes kernel 2.4 compatible with 2.6 usage.
 *
 * Copyright (C) 2004 Michael Richardson <mcr@sandelman.ottawa.on.ca>
 * Copyright (C) 2005 - 2008 Paul Wouters <paul@xelerance.com>
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

#ifndef _IPSEC_KERN24_H

#include <linux/if_ether.h>
#include <linux/random.h>

static inline void random_ether_addr(u8 *addr)
{
	get_random_bytes(addr, ETH_ALEN);
	addr[0] &= 0xfe;
	addr[0] |= 0x02;
}

#define ip_hdr(skb)     ((skb)->nh.iph)

#ifdef NET_26
#error \
	"ipsec_kern24.h should not be included directly or at all on 2.6 kernels"
#endif

#define sk_receive_queue  receive_queue
#define sk_destruct       destruct
#define sk_reuse          reuse
#define sk_zapped         zapped
#define sk_family         family
#define sk_protocol       protocol
#define sk_protinfo       protinfo
#define sk_sleep          sleep
#define sk_state_change   state_change
#define sk_shutdown       shutdown
#define sk_err            err
#define sk_stamp          stamp
#define sk_socket         socket
#define sk_sndbuf         sndbuf
#define sock_flag(sk, flag)  ((sk)->dead)
#define sk_for_each(sk, node, plist) \
	for ((sk) = *(plist); (sk) != NULL; (sk) = (sk)->next)

/* deal with 2.4 vs 2.6 issues with module counts */

/* in 2.6, all refcounts are maintained *outside* of the
 * module to deal with race conditions.
 */

#define KLIPS_INC_USE MOD_INC_USE_COUNT
#define KLIPS_DEC_USE MOD_DEC_USE_COUNT

#ifndef printk_ratelimit
extern int printk_ratelimit(void);
#endif

#include <linux/skbuff.h>
static inline void *skb_header_pointer(const struct sk_buff *skb, int offset,
				       int len, void *buffer)
{
	int hlen = skb_headlen(skb);

	if (offset + len <= hlen)
		return skb->data + offset;

	if (skb_copy_bits(skb, offset, buffer, len) < 0)
		return NULL;

	return buffer;
}

static inline struct ethhdr *eth_hdr(const struct sk_buff *skb)
{
	return (struct ethhdr *)skb_mac_header(skb);
}
#define _IPSEC_KERN24_H 1

#define proc_create_data(n,m,p,o,a) \
	({ \
		struct proc_dir_entry *_p = create_proc_entry((n),(m),(p)); \
		if (_p) { \
			_p->proc_fops = (o); \
			_p->data = (void *) (a); \
		} \
		(_p); \
	 })

#endif /* _IPSEC_KERN24_H */

