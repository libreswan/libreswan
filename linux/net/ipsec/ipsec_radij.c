/*
 * Interface between the IPSEC code and the radix (radij) tree code
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
 * Copyright (C) 2005 Michael Richardson <mcr@sandelman.ca>
 * Copyright (C) 2006-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2006-2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2006-2011 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2009-2012 David McCullough <david_mccullough@mcafee.com>
 * Copyright (C) 2012  Paul Wouters  <paul@libreswan.org>
 * Copyright (C) 2013  David McCullough <ucdevel@gmail.com>
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

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) && \
	!defined(AUTOCONF_INCLUDED)
#include <linux/config.h>
#endif
#include <linux/kernel.h> /* printk() */

#include "libreswan/ipsec_param.h"

#include <linux/slab.h>         /* kmalloc() */
#include <linux/errno.h>        /* error codes */
#include <linux/types.h>        /* size_t */
#include <linux/interrupt.h>    /* mark_bh */

#include <linux/netdevice.h>    /* struct device, struct net_device_stats and other headers */
#include <linux/etherdevice.h>  /* eth_type_trans */
#include <linux/ip.h>           /* struct iphdr */
#include <linux/skbuff.h>
#include <libreswan.h>
#include <linux/spinlock.h> /* *lock* */

#include <net/ip.h>

#include "libreswan/ipsec_eroute.h"
#include "libreswan/ipsec_sa.h"

#include "libreswan/radij.h"
#include "libreswan/ipsec_encap.h"
#include "libreswan/radij.h"
#include "libreswan/ipsec_encap.h"
#include "libreswan/ipsec_radij.h"
#include "libreswan/ipsec_tunnel.h"     /* struct ipsecpriv */
#include "libreswan/ipsec_xform.h"

#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include "libreswan/ipsec_proto.h"

struct radij_node_head *rnh = NULL;
DEFINE_SPINLOCK(eroute_lock);

int ipsec_radijinit(void)
{
	maj_keylen = sizeof(struct sockaddr_encap);

	rj_init();

	if (rj_inithead((void **)&rnh,
	                /*16*/ offsetof(struct sockaddr_encap,
					sen_type) * sizeof(__u8)) == 0)                                      /* 16 is bit offset of sen_type */
		return -1;

	return 0;
}

int ipsec_radijcleanup(void)
{
	int error = 0;

	spin_lock_bh(&eroute_lock);

	error = radijcleanup();

	spin_unlock_bh(&eroute_lock);

	return error;
}

int ipsec_cleareroutes(void)
{
	int error;

	spin_lock_bh(&eroute_lock);

	error = radijcleartree();

	spin_unlock_bh(&eroute_lock);

	return error;
}

int ipsec_breakroute(struct sockaddr_encap *eaddr,
		     struct sockaddr_encap *emask,
		     struct sk_buff **first,
		     struct sk_buff **last)
{
	struct eroute *ro;
	struct radij_node *rn;
	int error;

	if (debug_eroute) {
		char buf1[SUBNETTOA_BUF], buf2[SUBNETTOA_BUF];
		subnettoa(eaddr->sen_ip_src, emask->sen_ip_src, 0, buf1,
			  sizeof(buf1));
		subnettoa(eaddr->sen_ip_dst, emask->sen_ip_dst, 0, buf2,
			  sizeof(buf2));
		KLIPS_PRINT(debug_eroute,
			    "klips_debug:ipsec_breakroute: "
			    "attempting to delete eroute for %s:%d->%s:%d %d\n",
			    buf1, ntohs(eaddr->sen_sport),
			    buf2, ntohs(eaddr->sen_dport), eaddr->sen_proto);
	}

	spin_lock_bh(&eroute_lock);

	if ((error = rj_delete(eaddr, emask, rnh, &rn)) != 0) {
		spin_unlock_bh(&eroute_lock);
		KLIPS_PRINT(debug_eroute,
			    "klips_debug:ipsec_breakroute: "
			    "node not found, eroute delete failed.\n");
		return error;
	}

	spin_unlock_bh(&eroute_lock);

	ro = (struct eroute *)rn;

	KLIPS_PRINT(debug_eroute,
		    "klips_debug:ipsec_breakroute: "
		    "deleted eroute=0p%p, ident=0p%p->0p%p, first=0p%p, last=0p%p\n",
		    ro,
		    ro->er_ident_s.data,
		    ro->er_ident_d.data,
		    ro->er_first,
		    ro->er_last);

	if (ro->er_ident_s.data != NULL)
		kfree(ro->er_ident_s.data);
	if (ro->er_ident_d.data != NULL)
		kfree(ro->er_ident_d.data);
	if (ro->er_first != NULL) {
#if 0
		struct net_device_stats *stats =
			&(netdev_to_ipsecpriv(dev)->mystats);
		stats->tx_dropped--;
#endif
		*first = ro->er_first;
	}
	if (ro->er_last != NULL) {
#if 0
		struct net_device_stats *stats =
			&(netdev_to_ipsecpriv(dev)->mystats);
		stats->tx_dropped--;
#endif
		*last = ro->er_last;
	}

	if (rn->rj_flags & (RJF_ACTIVE | RJF_ROOT))
		panic("ipsec_breakroute RMT_DELEROUTE root or active node\n");
	memset((caddr_t)rn, 0, sizeof(struct eroute));
	kfree(rn);

	return 0;
}

int ipsec_makeroute(struct sockaddr_encap *eaddr,
		    struct sockaddr_encap *emask,
		    ip_said said,
		    uint32_t pid,
		    struct sk_buff *skb,
		    struct ident *ident_s,
		    struct ident *ident_d)
{
	struct eroute *retrt;
	int error;
	char sa[SATOT_BUF];
	size_t sa_len;

	if (debug_eroute) {
		{
			char buf1[SUBNETTOA_BUF], buf2[SUBNETTOA_BUF];
			if (eaddr->sen_type == SENT_IP6) {
				subnet6toa(&eaddr->sen_ip6_src,
					   &emask->sen_ip6_src,
					   0, buf1, sizeof(buf1));
				subnet6toa(&eaddr->sen_ip6_dst,
					   &emask->sen_ip6_dst,
					   0, buf2, sizeof(buf2));
			} else {
				subnettoa(eaddr->sen_ip_src, emask->sen_ip_src,
					  0, buf1, sizeof(buf1));
				subnettoa(eaddr->sen_ip_dst, emask->sen_ip_dst,
					  0, buf2, sizeof(buf2));
			}

			sa_len = KLIPS_SATOT(debug_eroute, &said, 0, sa,
					     sizeof(sa));
			KLIPS_PRINT(debug_eroute,
				    "klips_debug:ipsec_makeroute: "
				    "attempting to allocate %zu bytes to insert eroute for %s->%s, SA: %s, PID:%d, skb=0p%p, ident:%s->%s\n",
				    sizeof(struct eroute),
				    buf1,
				    buf2,
				    sa_len ? sa : " (error)",
				    pid,
				    skb,
				    (ident_s ? (ident_s->data ? ident_s->data :
						"NULL") : "NULL"),
				    (ident_d ? (ident_d->data ? ident_d->data :
						"NULL") : "NULL"));
		}
		{
			char buf1[sizeof(struct sockaddr_encap) * 2 + 1],
			     buf2[sizeof(struct sockaddr_encap) * 2 + 1];
			int i;
			unsigned char *b1 = buf1,
			*b2 = buf2,
			*ea = (unsigned char *)eaddr,
			*em = (unsigned char *)emask;

			for (i = 0; i < sizeof(struct sockaddr_encap); i++) {
				sprintf(b1, "%02x", ea[i]);
				sprintf(b2, "%02x", em[i]);
				b1 += 2;
				b2 += 2;
			}
			KLIPS_PRINT(debug_eroute,
				    "klips_debug:ipsec_makeroute: %s / %s\n",
				    buf1, buf2);
		}
	}

	retrt = (struct eroute *)kmalloc(sizeof(struct eroute), GFP_ATOMIC);
	if (retrt == NULL) {
		printk("klips_error:ipsec_makeroute: "
		       "not able to allocate kernel memory");
		return -ENOMEM;
	}

	memset((caddr_t)retrt, 0, sizeof(struct eroute));

	retrt->er_eaddr = *eaddr;
	retrt->er_emask = *emask;
	retrt->er_said = said;
	retrt->er_pid = pid;
	retrt->er_count = 0;
	retrt->er_lasttime = jiffies / HZ;

	{
		/* this is because gcc 3. doesn't like cast's as lvalues */
		struct rjtentry *rje = (struct rjtentry *)&(retrt->er_rjt);
		caddr_t er = (caddr_t)&(retrt->er_eaddr);

		rje->rd_nodes->rj_key = er;
	}

	if (ident_s && ident_s->type != SADB_IDENTTYPE_RESERVED) {
		int data_len = ident_s->len * IPSEC_PFKEYv2_ALIGN -
			       sizeof(struct sadb_ident);

		retrt->er_ident_s.type = ident_s->type;
		retrt->er_ident_s.id = ident_s->id;
		retrt->er_ident_s.len = ident_s->len;
		if (data_len) {
			KLIPS_PRINT(debug_eroute,
				    "klips_debug:ipsec_makeroute: "
				    "attempting to allocate %u bytes for ident_s.\n",
				    data_len);
			if (!(retrt->er_ident_s.data =
				      kmalloc(data_len, GFP_KERNEL))) {
				kfree(retrt);
				printk("klips_error:ipsec_makeroute: not able to allocate kernel memory (%d)\n",
					data_len);
				return ENOMEM;
			}
			memcpy(retrt->er_ident_s.data, ident_s->data,
			       data_len);
		} else {
			retrt->er_ident_s.data = NULL;
		}
	}

	if (ident_d && ident_d->type != SADB_IDENTTYPE_RESERVED) {
		int data_len = ident_d->len  * IPSEC_PFKEYv2_ALIGN -
			       sizeof(struct sadb_ident);

		retrt->er_ident_d.type = ident_d->type;
		retrt->er_ident_d.id = ident_d->id;
		retrt->er_ident_d.len = ident_d->len;
		if (data_len) {
			KLIPS_PRINT(debug_eroute,
				    "klips_debug:ipsec_makeroute: "
				    "attempting to allocate %u bytes for ident_d.\n",
				    data_len);
			if (!(retrt->er_ident_d.data =
				      kmalloc(data_len, GFP_KERNEL))) {
				if (retrt->er_ident_s.data)
					kfree(retrt->er_ident_s.data);
				kfree(retrt);
				printk("klips_error:ipsec_makeroute: not able to allocate kernel memory (%d)\n",
					data_len);
				return ENOMEM;
			}
			memcpy(retrt->er_ident_d.data, ident_d->data,
			       data_len);
		} else {
			retrt->er_ident_d.data = NULL;
		}
	}
	retrt->er_first = skb;
	retrt->er_last = NULL;

	KLIPS_PRINT(debug_eroute,
		    "klips_debug:ipsec_makeroute: "
		    "calling rj_addroute now\n");

	spin_lock_bh(&eroute_lock);

	error = rj_addroute(&(retrt->er_eaddr), &(retrt->er_emask),
			    rnh, retrt->er_rjt.rd_nodes);

	spin_unlock_bh(&eroute_lock);

	if (error) {
		sa_len = KLIPS_SATOT(debug_eroute, &said, 0, sa, sizeof(sa));
		KLIPS_PRINT(debug_eroute,
			    "klips_debug:ipsec_makeroute: "
			    "rj_addroute not able to insert eroute for SA:%s (error:%d)\n",
			    sa_len ? sa : " (error)", error);
		if (retrt->er_ident_s.data)
			kfree(retrt->er_ident_s.data);
		if (retrt->er_ident_d.data)
			kfree(retrt->er_ident_d.data);

		kfree(retrt);

		return error;
	}

	if (debug_eroute) {
		char buf1[SUBNETTOA_BUF], buf2[SUBNETTOA_BUF];
		if (rd_key(&retrt->er_rjt)->sen_type == SENT_IP6) {
			subnet6toa(&rd_key(&retrt->er_rjt)->sen_ip6_src,
				   &rd_mask(&retrt->er_rjt)->sen_ip6_src,
				   0, buf1, sizeof(buf1));
			subnet6toa(&rd_key(&retrt->er_rjt)->sen_ip6_dst,
				   &rd_mask(&retrt->er_rjt)->sen_ip6_dst,
				   0, buf2, sizeof(buf2));
		} else {
			subnettoa(rd_key(&retrt->er_rjt)->sen_ip_src,
				  rd_mask(&retrt->er_rjt)->sen_ip_src,
				  0, buf1, sizeof(buf1));
			subnettoa(rd_key(&retrt->er_rjt)->sen_ip_dst,
				  rd_mask(&retrt->er_rjt)->sen_ip_dst,
				  0, buf2, sizeof(buf2));
		}
		sa_len = KLIPS_SATOT(debug_eroute, &retrt->er_said, 0, sa,
				     sizeof(sa));

		KLIPS_PRINT(debug_eroute,
			    "klips_debug:ipsec_makeroute: "
			    "pid=%05d "
			    "count=%10d "
			    "lasttime=%6d "
			    "%-18s -> %-18s => %s\n",
			    retrt->er_pid,
			    retrt->er_count,
			    (int)(ipsec_jiffieshz_elapsed(jiffies / HZ,
							  retrt->er_lasttime)),
			    buf1,
			    buf2,
			    sa_len ? sa : " (error)");
	}
	KLIPS_PRINT(debug_eroute,
		    "klips_debug:ipsec_makeroute: "
		    "succeeded.\n");
	return 0;
}

struct eroute *ipsec_findroute(struct sockaddr_encap *eaddr)
{
	struct radij_node *rn;
	char buf1[ADDRTOA_BUF], buf2[ADDRTOA_BUF];

	if (debug_radij & DB_RJ_FINDROUTE) {
		unsigned short *sp, *dp;
		unsigned char *pp, *sb, *eb;
		if (eaddr->sen_type == SENT_IP6) {
			inet_addrtot(AF_INET6, &eaddr->sen_ip6_src, 0, buf1,
				     sizeof(buf1));
			inet_addrtot(AF_INET6, &eaddr->sen_ip6_dst, 0, buf2,
				     sizeof(buf2));
			sp = &eaddr->sen_sport6;
			dp = &eaddr->sen_dport6;
			pp = &eaddr->sen_proto6;
			sb = "[";
			eb = "]";
		} else {
			addrtoa(eaddr->sen_ip_src, 0, buf1, sizeof(buf1));
			addrtoa(eaddr->sen_ip_dst, 0, buf2, sizeof(buf2));
			sp = &eaddr->sen_sport;
			dp = &eaddr->sen_dport;
			pp = &eaddr->sen_proto;
			sb = eb = "";
		}
		KLIPS_PRINT(debug_eroute,
			    "klips_debug:ipsec_findroute: "
			    "%s%s%s:%d->%s%s%s:%d %d\n",
			    sb, buf1, eb, ntohs(*sp),
			    sb, buf2, eb, ntohs(*dp),
			    *pp);
	}
	rn = rj_match((caddr_t)eaddr, rnh);
	if (rn) {
		if (debug_eroute && sysctl_ipsec_debug_verbose)
			sin_addrtot(&((struct eroute*)rn)->er_said.dst.u, 0,
				    buf1, sizeof(buf1));
		KLIPS_PRINT(debug_eroute && sysctl_ipsec_debug_verbose,
			    "klips_debug:ipsec_findroute: "
			    "found, points to proto=%d, spi=%x, dst=%s.\n",
			    ((struct eroute*)rn)->er_said.proto,
			    ntohl(((struct eroute*)rn)->er_said.spi),
			    buf1);
	}
	return (struct eroute *)rn;
}

#ifdef CONFIG_PROC_FS
/*
 * ipsec_rj_walker_show: print one line of eroute table output.
 */

int ipsec_rj_walker_show(struct radij_node *rn, void *arg)
{
	struct eroute *ro = (struct eroute *)rn;
	struct rjtentry *rd = (struct rjtentry *)rn;
	struct seq_file *seq = arg;
	char buf1[SUBNETTOA_BUF], buf2[SUBNETTOA_BUF];
	char buf3[16];
	char sa[SATOT_BUF];
	size_t sa_len, buf_len;
	struct sockaddr_encap *key, *mask;

	KLIPS_PRINT(debug_radij,
		    "klips_debug:ipsec_rj_walker_show: rn=%p, arg=%p\n", rn, arg);
	if (rn->rj_b >= 0)
		return 0;

	key = rd_key(rd);
	mask = rd_mask(rd);

	if (key == NULL || mask == NULL)
		return 0;

	if (key->sen_type == SENT_IP6) {
		if (key->sen_sport6 != 0) {
			*buf1 = '[';
			buf_len = subnet6toa(&key->sen_ip6_src,
					     &mask->sen_ip6_src, 0, buf1 + 1,
					     sizeof(buf1));
			buf1[buf_len - 1] = ']';
			sprintf(buf1 + buf_len, ":%d", ntohs(key->sen_sport6));
		} else {
			buf_len = subnet6toa(&key->sen_ip6_src,
					     &mask->sen_ip6_src, 0, buf1,
					     sizeof(buf1));
		}
		if (key->sen_dport6 != 0) {
			*buf1 = '[';
			buf_len = subnet6toa(&key->sen_ip6_dst,
					     &mask->sen_ip6_dst, 0, buf2 + 1,
					     sizeof(buf2));
			buf1[buf_len - 1] = ']';
			sprintf(buf2 + buf_len, ":%d", ntohs(key->sen_dport6));
		} else {
			buf_len = subnet6toa(&key->sen_ip6_dst,
					     &mask->sen_ip6_dst, 0, buf2,
					     sizeof(buf2));
		}
	} else if (key->sen_type == SENT_IP4) {
		buf_len = subnettoa(key->sen_ip_src, mask->sen_ip_src, 0, buf1,
				    sizeof(buf1));
		if (key->sen_sport != 0)
			sprintf(buf1 + buf_len - 1, ":%d",
				ntohs(key->sen_sport));
		buf_len = subnettoa(key->sen_ip_dst, mask->sen_ip_dst, 0, buf2,
				    sizeof(buf2));
		if (key->sen_dport != 0)
			sprintf(buf2 + buf_len - 1, ":%d",
				ntohs(key->sen_dport));
	} else {
		return 0;
	}

	buf3[0] = '\0';
	if (key->sen_proto != 0)
		sprintf(buf3, ":%d", key->sen_proto);

	sa_len = KLIPS_SATOT(1, &ro->er_said, 'x', sa, sizeof(sa));
	seq_printf(seq,
				 "%-10d "
				 "%-18s -> %-18s => %s%s\n",
				 ro->er_count,
				 buf1,
				 buf2,
				 sa_len ? sa : " (error)",
				 buf3);

	return 0;
}
#endif          /* CONFIG_PROC_FS */

int ipsec_rj_walker_delete(struct radij_node *rn, void *w0)
{
	struct eroute *ro;
	struct rjtentry *rd = (struct rjtentry *)rn;
	struct radij_node *rn2;
	int error;
	struct sockaddr_encap *key, *mask;

	key = rd_key(rd);
	mask = rd_mask(rd);

	if (!key || !mask)
		return -ENODATA;

	if (debug_radij) {
		char buf1[SUBNETTOA_BUF], buf2[SUBNETTOA_BUF];
		if (key->sen_type == SENT_IP6) {
			subnet6toa(&key->sen_ip6_src, &mask->sen_ip6_src, 0,
				   buf1, sizeof(buf1));
			subnet6toa(&key->sen_ip6_dst, &mask->sen_ip6_dst, 0,
				   buf2, sizeof(buf2));
		} else {
			subnettoa(key->sen_ip_src, mask->sen_ip_src, 0, buf1,
				  sizeof(buf1));
			subnettoa(key->sen_ip_dst, mask->sen_ip_dst, 0, buf2,
				  sizeof(buf2));
		}
		KLIPS_PRINT(debug_radij,
			    "klips_debug:ipsec_rj_walker_delete: "
			    "deleting: %s -> %s\n",
			    buf1,
			    buf2);
	}

	if ((error = rj_delete(key, mask, rnh, &rn2))) {
		KLIPS_PRINT(debug_radij,
			    "klips_debug:ipsec_rj_walker_delete: "
			    "rj_delete failed with error=%d.\n", error);
		return error;
	}

	if (rn2 != rn) {
		printk("klips_debug:ipsec_rj_walker_delete: "
		       "tried to delete a different node?!?  This should never happen!\n");
	}

	ro = (struct eroute *)rn;

	if (ro->er_ident_s.data)
		kfree(ro->er_ident_s.data);
	if (ro->er_ident_d.data)
		kfree(ro->er_ident_d.data);

	memset((caddr_t)rn, 0, sizeof(struct eroute));
	kfree(rn);

	return 0;
}
