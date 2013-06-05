/*
 * @(#) /proc file system interface code.
 *
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs <rgb@freeswan.org>
 *                                 2001  Michael Richardson <mcr@freeswan.org>
 * Copyright (C) 2005 Michael Richardson <mcr@sandelman.ca>
 * Copyright (C) 2005-2008  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2006-2012 David McCullough <david_mccullough@mcafee.com>
 * Copyright (C) 2006-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2011 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2012  Paul Wouters  <paul@libreswan.org>
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38) && !defined(AUTOCONF_INCLUDED)
# include <linux/config.h>
#endif
#define __NO_VERSION__
#include <linux/module.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,26)
# include <linux/moduleparam.h> 
#endif 
#include <linux/kernel.h> /* printk() */
#include <linux/ip.h>          /* struct iphdr */

#include "libreswan/ipsec_kversion.h"
#include "libreswan/ipsec_param.h"

#include <linux/slab.h> /* kmalloc() */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */

#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/in.h>          /* struct sockaddr_in */
#include <linux/skbuff.h>
#include <asm/uaccess.h>       /* copy_from_user */
#include <libreswan.h>
#include <linux/spinlock.h> /* *lock* */

#include <net/ip.h>
#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#endif /* CONFIG_PROC_FS */
#include <linux/netlink.h>

#include "libreswan/radij.h"

#include "libreswan/ipsec_life.h"
#include "libreswan/ipsec_stats.h"
#include "libreswan/ipsec_sa.h"

#include "libreswan/ipsec_encap.h"
#include "libreswan/ipsec_radij.h"
#include "libreswan/ipsec_xform.h"
#include "libreswan/ipsec_tunnel.h"
#include "libreswan/ipsec_xmit.h"

#include "libreswan/ipsec_rcv.h"
#include "libreswan/ipsec_ah.h"
#include "libreswan/ipsec_esp.h"

#ifdef CONFIG_KLIPS_IPCOMP
#include "libreswan/ipcomp.h"
#endif /* CONFIG_KLIPS_IPCOMP */

#include "libreswan/ipsec_proto.h"

#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include <linux/in.h>
#if defined(IP_IPSEC_REFINFO) || defined(IP_IPSEC_BINDREF)
#define IPSEC_PROC_SHOW_SAREF_INFO
#endif

#ifdef CONFIG_PROC_FS

#ifdef IPSEC_PROC_SUBDIRS
static struct proc_dir_entry *proc_net_ipsec_dir = NULL;
static struct proc_dir_entry *proc_eroute_dir    = NULL;
static struct proc_dir_entry *proc_spi_dir       = NULL;
static struct proc_dir_entry *proc_spigrp_dir    = NULL;
#ifdef IPSEC_SA_RECOUNT_DEBUG
static struct proc_dir_entry *proc_saraw_dir     = NULL;
#endif
static struct proc_dir_entry *proc_birth_dir     = NULL;
static struct proc_dir_entry *proc_stats_dir     = NULL;
#endif

struct ipsec_birth_reply ipsec_ipv4_birth_packet;
struct ipsec_birth_reply ipsec_ipv6_birth_packet;

int debug_esp = 0;
int debug_ah = 0;
int sysctl_ipsec_inbound_policy_check = 1;
int debug_xmit = 0;
int debug_xform = 0;
int debug_eroute = 0;
int debug_spi = 0;
int debug_radij = 0;
int debug_pfkey = 0;
int debug_rcv = 0;
int debug_netlink = 0;
int sysctl_ipsec_debug_verbose = 0;
int sysctl_ipsec_debug_ipcomp =0;
int sysctl_ipsec_icmp = 0;
int sysctl_ipsec_tos = 0;

#define DECREMENT_UNSIGNED(X, amount) ((amount < (X)) ? (X)-amount : 0)

#ifdef CONFIG_KLIPS_ALG
extern int ipsec_xform_get_info(char *buffer, char **start,
				off_t offset, int length IPSEC_PROC_LAST_ARG);
#endif

IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_eroute_get_info(char *buffer, 
		      char **start, 
		      off_t offset, 
		      int length        IPSEC_PROC_LAST_ARG)
{
	struct wsbuf w = {buffer, length, offset, 0, 0};

	if (debug_radij & DB_RJ_DUMPTREES)
	  rj_dumptrees();			/* XXXXXXXXX */

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_eroute_get_info: "
		    "buffer=0p%p, *start=0p%p, offset=%d, length=%d\n",
		    buffer,
		    *start,
		    (int)offset,
		    length);

	spin_lock_bh(&eroute_lock);

	rj_walktree(rnh, ipsec_rj_walker_procprint, &w);
/*	rj_walktree(mask_rjhead, ipsec_rj_walker_procprint, &w); */

	spin_unlock_bh(&eroute_lock);

	*start = buffer + (offset - w.begin);	/* Start of wanted data */
	return w.len - (offset - w.begin);
}


IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_spi_format(struct ipsec_sa *sa_p,
		 char *buffer,
		 int len,
		 int length)
{
	char sa[SATOT_BUF];
	char buf_s[SUBNETTOA_BUF];
	char buf_d[SUBNETTOA_BUF];
	size_t sa_len;

	ipsec_sa_get(sa_p, IPSEC_REFPROC);
	sa_len = satot(&sa_p->ips_said, 'x', sa, sizeof(sa));
	len += ipsec_snprintf(buffer+len, length-len, "%s ",
		       sa_len ? sa : " (error)");

	len += ipsec_snprintf(buffer+len, length-len, "%s%s%s",
		       IPS_XFORM_NAME(sa_p));

	len += ipsec_snprintf(buffer+len, length-len, ": dir=%s",
		       (sa_p->ips_flags & EMT_INBOUND) ?
		       "in " : "out");

	if(sa_p->ips_addr_s) {
		sin_addrtot(sa_p->ips_addr_s, 0, buf_s, sizeof(buf_s));
		len += ipsec_snprintf(buffer+len, length-len, " src=%s", buf_s);
	}

	if((sa_p->ips_said.proto == IPPROTO_IPIP)
	   && (sa_p->ips_flags & (SADB_X_SAFLAGS_INFLOW
			   |SADB_X_SAFLAGS_POLICYONLY))) {
		if (sa_p->ips_flow_s.u.v4.sin_family == AF_INET) {
		subnettoa(sa_p->ips_flow_s.u.v4.sin_addr,
			  sa_p->ips_mask_s.u.v4.sin_addr,
			  0,
			  buf_s,
			  sizeof(buf_s));

		subnettoa(sa_p->ips_flow_d.u.v4.sin_addr,
			  sa_p->ips_mask_d.u.v4.sin_addr,
			  0,
			  buf_d,
			  sizeof(buf_d));
		} else {
		subnet6toa(&sa_p->ips_flow_s.u.v6.sin6_addr,
			  &sa_p->ips_mask_s.u.v6.sin6_addr,
			  0,
			  buf_s,
			  sizeof(buf_s));

		subnet6toa(&sa_p->ips_flow_d.u.v6.sin6_addr,
			  &sa_p->ips_mask_d.u.v6.sin6_addr,
			  0,
			  buf_d,
			  sizeof(buf_d));
		}

		len += ipsec_snprintf(buffer+len, length-len, " policy=%s->%s",
			       buf_s, buf_d);
	}
	
	if(sa_p->ips_iv_bits) {
		int j;
		len += ipsec_snprintf(buffer+len, length-len, " iv_bits=%dbits iv=0x",
			       sa_p->ips_iv_bits);

#ifdef CONFIG_KLIPS_OCF
		if (!sa_p->ips_iv) {
			/* ocf doesn't set the IV, fake it for the UML tests */
			len += ipsec_snprintf(buffer+len, length-len, "0cf0");
			for (j = 0; j < (sa_p->ips_iv_bits / 8) - 2; j++) {
				len += ipsec_snprintf(buffer+len, length-len, "%02x",
						   (int) ((((long)sa_p) >> j) & 0xff));
			}
		} else
#endif
		for(j = 0; j < sa_p->ips_iv_bits / 8; j++) {
			len += ipsec_snprintf(buffer+len, length-len, "%02x",
				       (__u32)((__u8*)(sa_p->ips_iv))[j]);
		}
	}

	if(sa_p->ips_encalg || sa_p->ips_authalg) {
		if(sa_p->ips_replaywin) {
			len += ipsec_snprintf(buffer+len, length-len, " ooowin=%d",
				       sa_p->ips_replaywin);
		}
		if(sa_p->ips_errs.ips_replaywin_errs) {
			len += ipsec_snprintf(buffer+len, length-len, " ooo_errs=%d",
				       sa_p->ips_errs.ips_replaywin_errs);
		}
		if(sa_p->ips_replaywin_lastseq) {
		       len += ipsec_snprintf(buffer+len, length-len, " seq=%d",
				      sa_p->ips_replaywin_lastseq);
		}
		if(sa_p->ips_replaywin_bitmap) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
			len += ipsec_snprintf(buffer+len, length-len, " bit=0x%Lx",
				       sa_p->ips_replaywin_bitmap);
#else
			len += ipsec_snprintf(buffer+len, length-len, " bit=0x%x%08x",
				       (__u32)(sa_p->ips_replaywin_bitmap >> 32),
				       (__u32)sa_p->ips_replaywin_bitmap);
#endif
		}
		if(sa_p->ips_replaywin_maxdiff) {
			len += ipsec_snprintf(buffer+len, length-len, " max_seq_diff=%d",
				       sa_p->ips_replaywin_maxdiff);
		}
	}
	if(sa_p->ips_flags & ~EMT_INBOUND) {
		len += ipsec_snprintf(buffer+len, length-len, " flags=0x%x",
			       sa_p->ips_flags & ~EMT_INBOUND);
		len += ipsec_snprintf(buffer+len, length-len, "<");
		/* flag printing goes here */
		len += ipsec_snprintf(buffer+len, length-len, ">");
	}
	if(sa_p->ips_auth_bits) {
		len += ipsec_snprintf(buffer+len, length-len, " alen=%d",
			       sa_p->ips_auth_bits);
	}
	if(sa_p->ips_key_bits_a) {
		len += ipsec_snprintf(buffer+len, length-len, " aklen=%d",
			       sa_p->ips_key_bits_a);
	}
	if(sa_p->ips_errs.ips_auth_errs) {
		len += ipsec_snprintf(buffer+len, length-len, " auth_errs=%d",
			       sa_p->ips_errs.ips_auth_errs);
	}
	if(sa_p->ips_key_bits_e) {
		len += ipsec_snprintf(buffer+len, length-len, " eklen=%d",
			       sa_p->ips_key_bits_e);
	}
	if(sa_p->ips_errs.ips_encsize_errs) {
		len += ipsec_snprintf(buffer+len, length-len, " encr_size_errs=%d",
			       sa_p->ips_errs.ips_encsize_errs);
	}
	if(sa_p->ips_errs.ips_encpad_errs) {
		len += ipsec_snprintf(buffer+len, length-len, " encr_pad_errs=%d",
			       sa_p->ips_errs.ips_encpad_errs);
	}
	
	len += ipsec_snprintf(buffer+len, length-len, " life(c,s,h)=");

	len += ipsec_lifetime_format(buffer + len,
				     length - len,
				     "alloc", 
				     ipsec_life_countbased,
				     &sa_p->ips_life.ipl_allocations);

	len += ipsec_lifetime_format(buffer + len,
				     length - len,
				     "bytes",
				     ipsec_life_countbased,
				     &sa_p->ips_life.ipl_bytes);

	len += ipsec_lifetime_format(buffer + len,
				     length - len,
				     "addtime",
				     ipsec_life_timebased,
				     &sa_p->ips_life.ipl_addtime);

	len += ipsec_lifetime_format(buffer + len,
				     length - len,
				     "usetime",
				     ipsec_life_timebased,
				     &sa_p->ips_life.ipl_usetime);
	
	len += ipsec_lifetime_format(buffer + len,
				     length - len,
				     "packets",
				     ipsec_life_countbased,
				     &sa_p->ips_life.ipl_packets);
	
	if(sa_p->ips_life.ipl_usetime.ipl_last) { /* XXX-MCR should be last? */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
		len += ipsec_snprintf(buffer+len, length-len, " idle=%Ld",
			       ipsec_jiffieshz_elapsed(jiffies/HZ, sa_p->ips_life.ipl_usetime.ipl_last));
#else
		len += ipsec_snprintf(buffer+len, length-len, " idle=%lu", ipsec_jiffieshz_elapsed(jiffies/HZ, (unsigned long)sa_p->ips_life.ipl_usetime.ipl_last));
#endif
	}

#ifdef CONFIG_KLIPS_IPCOMP
	if(sa_p->ips_said.proto == IPPROTO_COMP &&
	   (sa_p->ips_comp_ratio_dbytes ||
	    sa_p->ips_comp_ratio_cbytes)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
		len += ipsec_snprintf(buffer+len, length-len, " ratio=%Ld:%Ld",
			       sa_p->ips_comp_ratio_dbytes,
			       sa_p->ips_comp_ratio_cbytes);
#else
		len += ipsec_snprintf(buffer+len, length-len, " ratio=%lu:%lu",
			       (unsigned long)sa_p->ips_comp_ratio_dbytes,
			       (unsigned long)sa_p->ips_comp_ratio_cbytes);
#endif
	}
#endif /* CONFIG_KLIPS_IPCOMP */

#ifdef NAT_TRAVERSAL
	{
		char *natttype_name;

		switch(sa_p->ips_natt_type)
		{
		case 0:
			natttype_name="none";
			break;
		case ESPINUDP_WITH_NON_IKE:
			natttype_name="nonike";
			break;
		case ESPINUDP_WITH_NON_ESP:
			natttype_name="nonesp";
			break;
		default:
			natttype_name = "unknown";
			break;
		}

		len += ipsec_snprintf(buffer + len, length-len, " natencap=%s",
			       natttype_name);
		
		len += ipsec_snprintf(buffer + len, length-len, " natsport=%d",
			       sa_p->ips_natt_sport);
		
		len += ipsec_snprintf(buffer + len,length-len, " natdport=%d",
			       sa_p->ips_natt_dport);
	}
#else
	len += ipsec_snprintf(buffer + len, length-len, " natencap=na");
#endif /* NAT_TRAVERSAL */
		
	/* we decrement by one, because this SA has been referenced in order to dump this info */
	len += ipsec_snprintf(buffer + len,length-len, " refcount=%d",
		       atomic_read(&sa_p->ips_refcount)-1);
#ifdef IPSEC_SA_RECOUNT_DEBUG
	{
		int f;
		len += ipsec_snprintf(buffer + len,length-len, "[");
		for (f=0; f<sizeof(sa_p->ips_track); f++)
			len += ipsec_snprintf(buffer + len,length-len, "%s%d",
					   f == 0 ? "" : ",", sa_p->ips_track[f]);
		len += ipsec_snprintf(buffer + len,length-len, "]");
	}
#endif

	len += ipsec_snprintf(buffer+len, length-len, " ref=%d",
		       sa_p->ips_ref);
	len += ipsec_snprintf(buffer+len, length-len, " refhim=%d",
		       sa_p->ips_refhim);

	if(sa_p->ips_out) {
		len += ipsec_snprintf(buffer+len, length-len, " outif=%s:%d",
				      sa_p->ips_out->name,
				      sa_p->ips_transport_direct);
	}
	if(debug_xform) {
		len += ipsec_snprintf(buffer+len, length-len, " reftable=%lu refentry=%lu",
		       (unsigned long)IPsecSAref2table(sa_p->ips_ref),
		       (unsigned long)IPsecSAref2entry(sa_p->ips_ref));
	}

	len += ipsec_snprintf(buffer+len, length-len, "\n");

	ipsec_sa_put(sa_p, IPSEC_REFPROC);   
	return len;
}


IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_spi_get_info(char *buffer,
		   char **start,
		   off_t offset,
		   int length    IPSEC_PROC_LAST_ARG)
{
	const int max_content = length > 0? length-1 : 0;
	int len = 0;
	off_t begin = 0;
	int i;
	struct ipsec_sa *sa_p;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_spi_get_info: "
		    "buffer=0p%p, *start=0p%p, offset=%d, length=%d\n",
		    buffer,
		    *start,
		    (int)offset,
		    length);
	
	spin_lock_bh(&tdb_lock);

	for (i = 0; i < SADB_HASHMOD; i++) {
		for (sa_p = ipsec_sadb_hash[i];
		     sa_p;
		     sa_p = sa_p->ips_hnext) {

		     	len = ipsec_spi_format(sa_p, buffer, len, length);
                       
                        if (len >= max_content) {
                               /* we've done all that can fit -- stop loops */
                               len = max_content;      /* truncate crap */
                                goto done_spi_i;
                        } else {
                               const off_t pos = begin + len;  /* file position of end of what we've generated */

                               if (pos <= offset) {
                                       /* all is before first interesting character:
                                        * discard, but note where we are.
                                        */
                                       len = 0;
                                       begin = pos;
                               }
                        }
                }
        }

done_spi_i:	
	spin_unlock_bh(&tdb_lock);

	*start = buffer + (offset - begin);	/* Start of wanted data */
	return len - (offset - begin);
}

IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_spigrp_get_info(char *buffer,
		      char **start,
		      off_t offset,
		      int length     IPSEC_PROC_LAST_ARG)
{
	/* Limit of useful snprintf output */
	const int max_content = length > 0? length-1 : 0; 

	int len = 0;
	off_t begin = 0;
	int i;
	struct ipsec_sa *sa_p, *sa_p2;
	char sa[SATOT_BUF];
	size_t sa_len;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_spigrp_get_info: "
		    "buffer=0p%p, *start=0p%p, offset=%d, length=%d\n",
		    buffer,
		    *start,
		    (int)offset,
		    length);

	spin_lock_bh(&tdb_lock);
	
	for (i = 0; i < SADB_HASHMOD; i++) {
		for (sa_p = ipsec_sadb_hash[i];
		     sa_p != NULL;
		     sa_p = sa_p->ips_hnext)
		{
			sa_p2 = sa_p;
			while(sa_p2 != NULL) {
				struct ipsec_sa *sa2n;
				sa_len = satot(&sa_p2->ips_said,
					       'x', sa, sizeof(sa));
				
				len += ipsec_snprintf(buffer+len, length-len, "%s ",
						      sa_len ? sa : " (error)");
				
				sa2n = sa_p2->ips_next;
				sa_p2 = sa2n;
			}
			len += ipsec_snprintf(buffer+len, length-len, "\n");
			
			if (len >= max_content) {
				/* we've done all that can fit -- stop loops */
				len = max_content;      /* truncate crap */
				goto done_spigrp_i;
			} else {
				const off_t pos = begin + len;
				
				if (pos <= offset) {
					/* all is before first interesting character:
					 * discard, but note where we are.
					 */
                                        len = 0;
                                        begin = pos;
				}
			}
		}
	}

done_spigrp_i:	
	spin_unlock_bh(&tdb_lock);

	*start = buffer + (offset - begin);	/* Start of wanted data */
	return len - (offset - begin);
}


#ifdef IPSEC_SA_RECOUNT_DEBUG
IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_saraw_get_info(char *buffer,
		   char **start,
		   off_t offset,
		   int length    IPSEC_PROC_LAST_ARG)
{
	const int max_content = length > 0? length-1 : 0;
	int len = 0;
	off_t begin = 0;
	struct ipsec_sa *sa_p;
	extern struct ipsec_sa *ipsec_sa_raw;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_saraw_get_info: "
		    "buffer=0p%p, *start=0p%p, offset=%d, length=%d\n",
		    buffer,
		    *start,
		    (int)offset,
		    length);
	
	spin_lock_bh(&tdb_lock);

	for (sa_p = ipsec_sa_raw; sa_p; sa_p = sa_p->ips_raw) {
	       
		len = ipsec_spi_format(sa_p, buffer, len, length);

		if (len >= max_content) {
		       /* we've done all that can fit -- stop loops */
		       len = max_content;      /* truncate crap */
			goto done_spi_i;
		} else {
		       const off_t pos = begin + len;  /* file position of end of what we've generated */

		       if (pos <= offset) {
			       /* all is before first interesting character:
				* discard, but note where we are.
				*/
			       len = 0;
			       begin = pos;
		       }
		}
	}

done_spi_i:	
	spin_unlock_bh(&tdb_lock);

	*start = buffer + (offset - begin);	/* Start of wanted data */
	return len - (offset - begin);
}
#endif /* IPSEC_SA_RECOUNT_DEBUG */


IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_tncfg_get_info(char *buffer,
		     char **start,
		     off_t offset,
		     int length     IPSEC_PROC_LAST_ARG)
{
	/* limit of useful snprintf output */ 
	const int max_content = length > 0? length-1 : 0;
	int len = 0;
	off_t begin = 0;
	int i;
	char name[9];
	struct net_device *dev, *privdev;
	struct ipsecpriv *priv;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_tncfg_get_info: "
		    "buffer=0p%p, *start=0p%p, offset=%d, length=%d\n",
		    buffer,
		    *start,
		    (int)offset,
		    length);

	for(i = 0; i < IPSEC_NUM_IFMAX; i++) {
		ipsec_snprintf(name, (ssize_t) sizeof(name), IPSEC_DEV_FORMAT, i);
		dev = __ipsec_dev_get(name);
		if(dev) {
			priv = netdev_to_ipsecpriv(dev);
			len += ipsec_snprintf(buffer+len, length-len, "%s",
				       dev->name);
			if(priv) {
				privdev = (struct net_device *)(priv->dev);
				len += ipsec_snprintf(buffer+len, length-len, " -> %s",
					       privdev ? privdev->name : "NULL");
				len += ipsec_snprintf(buffer+len, length-len, " mtu=%d(%d) -> %d",
					       dev->mtu,
					       priv->mtu,
					       privdev ? privdev->mtu : 0);
			} else {
				KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
					    "klips_debug:ipsec_tncfg_get_info: device '%s' has no private data space!\n",
					    dev->name);
			}
			len += ipsec_snprintf(buffer+len, length-len, "\n");

                        if (len >= max_content) {
                                /* we've done all that can fit -- stop loop */
                                len = max_content;      /* truncate crap */
                                 break;
                        } else {
                                const off_t pos = begin + len;
                                if (pos <= offset) {
                                        len = 0;
                                        begin = pos;
                                }
			}
		}
	}
	*start = buffer + (offset - begin);	/* Start of wanted data */
	len -= (offset - begin);			/* Start slop */
	if (len > length)
		len = length;
	return len;
}

IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_version_get_info(char *buffer,
		       char **start,
		       off_t offset,
		       int length  IPSEC_PROC_LAST_ARG)
{
	int len = 0;
	off_t begin = 0;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_version_get_info: "
		    "buffer=0p%p, *start=0p%p, offset=%d, length=%d\n",
		    buffer,
		    *start,
		    (int)offset,
		    length);

	len += ipsec_snprintf(buffer + len,length-len, "Libreswan version: %s\n",
		       ipsec_version_code());
#if 0
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_version_get_info: "
		    "ipsec_init version: %s\n",
		    ipsec_init_c_version);
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_version_get_info: "
		    "ipsec_tunnel version: %s\n",
		    ipsec_tunnel_c_version);
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_version_get_info: "
		    "ipsec_netlink version: %s\n",
		    ipsec_netlink_c_version);
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_version_get_info: "
		    "radij_c_version: %s\n",
		    radij_c_version);
#endif


	*start = buffer + (offset - begin);	/* Start of wanted data */
	len -= (offset - begin);			/* Start slop */
	if (len > length)
		len = length;
	return len;
}

#ifdef IPSEC_PROC_SHOW_SAREF_INFO
IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_saref_get_info(char *buffer,
		       char **start,
		       off_t offset,
		       int length  IPSEC_PROC_LAST_ARG)
{
	int rc, len = 0;
	off_t begin = 0;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_saref_get_info: "
		    "buffer=0p%p, *start=0p%p, offset=%d, length=%d\n",
		    buffer,
		    *start,
		    (int)offset,
		    length);

#ifdef IP_IPSEC_REFINFO
	len += rc = ipsec_snprintf(buffer + len,length-len, "refinfo patch applied\n",
		       ipsec_version_code());
	if (rc<0) return 0;
#endif

#ifdef IP_IPSEC_BINDREF
	len += rc = ipsec_snprintf(buffer + len,length-len, "bindref patch applied\n",
		       ipsec_version_code());
	if (rc<0) return 0;
#endif

#ifdef CONFIG_INET_IPSEC_SAREF
	len += rc = ipsec_snprintf(buffer + len,length-len, "saref enabled\n",
		       ipsec_version_code());
#else
	len += rc = ipsec_snprintf(buffer + len,length-len, "saref disabled\n",
		       ipsec_version_code());
#endif
	if (rc<0) return 0;

	*start = buffer + (offset - begin);	/* Start of wanted data */
	len -= (offset - begin);			/* Start slop */
	if (len > length)
		len = length;
	return len;
}
#endif

#ifdef CONFIG_KLIPS_OCF
unsigned int ocf_available = 1;
#else
unsigned int ocf_available = 0;
#endif
module_param(ocf_available,int,0644);

IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_ocf_get_info(char *buffer,
		    char **start,
		    off_t offset,
		    int length  IPSEC_PROC_LAST_ARG)
{
	int len = 0;
	off_t begin = 0;

	len += ipsec_snprintf(buffer + len,
			      length-len, "%d\n", ocf_available);

	*start = buffer + (offset - begin);	/* Start of wanted data */
	len -= (offset - begin);			/* Start slop */
	if (len > length)
		len = length;
	return len;
}

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
unsigned int natt_available = 1;
#elif defined (HAVE_UDP_ENCAP_CONVERT)
unsigned int natt_available = 2;
#else
unsigned int natt_available = 0;
#endif
module_param(natt_available,int,0644);

IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_natt_get_info(char *buffer,
		    char **start,
		    off_t offset,
		    int length  IPSEC_PROC_LAST_ARG)
{
	int len = 0;
	off_t begin = 0;

	len += ipsec_snprintf(buffer + len,
			      length-len, "%d\n", natt_available);

	*start = buffer + (offset - begin);	/* Start of wanted data */
	len -= (offset - begin);			/* Start slop */
	if (len > length)
		len = length;
	return len;
}

IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_birth_info(char *page,
		 char **start,
		 off_t offset,
		 int count,
		 int *eof,
		 void *data)
{
	struct ipsec_birth_reply *ibr = (struct ipsec_birth_reply *)data;
	int len;

	if(offset >= ibr->packet_template_len) {
		if(eof) {
			*eof=1;
		}
		return 0;
	}

	len = ibr->packet_template_len;
	len -= offset;
	if (len > count)
		len = count;

	memcpy(page + offset, ibr->packet_template+offset, len);

	return len;
}

IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_birth_set(struct file *file, const char *buffer,
		unsigned long count, void *data)
{
	struct ipsec_birth_reply *ibr = (struct ipsec_birth_reply *)data;
	int len;

	KLIPS_INC_USE;
        if(count > IPSEC_BIRTH_TEMPLATE_MAXLEN) {
                len = IPSEC_BIRTH_TEMPLATE_MAXLEN;
	} else {
                len = count;
	}

        if(copy_from_user(ibr->packet_template, buffer, len)) {
                KLIPS_DEC_USE;
                return -EFAULT;
        }
	ibr->packet_template_len = len;

        KLIPS_DEC_USE;

        return len;
}


IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_klipsdebug_get_info(char *buffer,
			  char **start,
			  off_t offset,
			  int length      IPSEC_PROC_LAST_ARG)
{
	int len = 0;
	off_t begin = 0;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_klipsdebug_get_info: "
		    "buffer=0p%p, *start=0p%p, offset=%d, length=%d\n",
		    buffer,
		    *start,
		    (int)offset,
		    length);

	len += ipsec_snprintf(buffer+len, length-len, "debug_tunnel=%08x.\n", debug_tunnel);
	len += ipsec_snprintf(buffer+len, length-len, "debug_xform=%08x.\n", debug_xform);
	len += ipsec_snprintf(buffer+len, length-len, "debug_eroute=%08x.\n", debug_eroute);
	len += ipsec_snprintf(buffer+len, length-len, "debug_spi=%08x.\n", debug_spi);
	len += ipsec_snprintf(buffer+len, length-len, "debug_radij=%08x.\n", debug_radij);
	len += ipsec_snprintf(buffer+len, length-len, "debug_esp=%08x.\n", debug_esp);
	len += ipsec_snprintf(buffer+len, length-len, "debug_ah=%08x.\n", debug_ah);
	len += ipsec_snprintf(buffer+len, length-len, "debug_rcv=%08x.\n", debug_rcv);
	len += ipsec_snprintf(buffer+len, length-len, "debug_pfkey=%08x.\n", debug_pfkey);

	*start = buffer + (offset - begin);	/* Start of wanted data */
	len -= (offset - begin);			/* Start slop */
	if (len > length)
		len = length;
	return len;
}

IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_stats_get_int_info(char *buffer,
			 char **start,
			 off_t offset,
			 int   length,
			 int   *eof,
			 void  *data)
{

	const int max_content = length > 0? length-1 : 0;
	int len = 0;
	int *thing;

	thing = (int *)data;
	
	len = ipsec_snprintf(buffer+len, length-len, "%08x\n", *thing);

	if (len >= max_content)
               len = max_content;      /* truncate crap */

        *start = buffer + offset;       /* Start of wanted data */
        return len > offset? len - offset : 0;

}

#endif /* CONFIG_PROC_FS */

struct ipsec_proc_list {
	char                   *name;
	struct proc_dir_entry **parent;
	struct proc_dir_entry **dir;
	read_proc_t            *readthing;
	write_proc_t           *writething;
	void                   *data;
};
static struct ipsec_proc_list proc_items[]={
	{"klipsdebug", &proc_net_ipsec_dir, NULL,             ipsec_klipsdebug_get_info, NULL, NULL},
	{"eroute",     &proc_net_ipsec_dir, &proc_eroute_dir, NULL, NULL, NULL},
	{"all",        &proc_eroute_dir,    NULL,             ipsec_eroute_get_info,     NULL, NULL},
	{"spi",        &proc_net_ipsec_dir, &proc_spi_dir,    NULL, NULL, NULL},
	{"all",        &proc_spi_dir,       NULL,             ipsec_spi_get_info,        NULL, NULL},
	{"spigrp",     &proc_net_ipsec_dir, &proc_spigrp_dir, NULL, NULL, NULL},
	{"all",        &proc_spigrp_dir,    NULL,             ipsec_spigrp_get_info,     NULL, NULL},
#ifdef IPSEC_SA_RECOUNT_DEBUG
	{"saraw",      &proc_net_ipsec_dir, &proc_saraw_dir,  NULL, NULL, NULL},
	{"all",        &proc_saraw_dir,     NULL,             ipsec_saraw_get_info,      NULL, NULL},
#endif
	{"birth",      &proc_net_ipsec_dir, &proc_birth_dir,  NULL,      NULL, NULL},
	{"ipv4",       &proc_birth_dir,     NULL,             ipsec_birth_info, ipsec_birth_set, (void *)&ipsec_ipv4_birth_packet},
	{"ipv6",       &proc_birth_dir,     NULL,             ipsec_birth_info, ipsec_birth_set, (void *)&ipsec_ipv6_birth_packet},
	{"tncfg",      &proc_net_ipsec_dir, NULL,             ipsec_tncfg_get_info,      NULL, NULL},
#ifdef CONFIG_KLIPS_ALG

	{"xforms",     &proc_net_ipsec_dir, NULL,             ipsec_xform_get_info,      NULL, NULL},
#endif
	{"stats",      &proc_net_ipsec_dir, &proc_stats_dir,  NULL,      NULL, NULL},
	{"trap_count", &proc_stats_dir,     NULL,             ipsec_stats_get_int_info, NULL, &ipsec_xmit_trap_count},
	{"trap_sendcount", &proc_stats_dir, NULL,             ipsec_stats_get_int_info, NULL, &ipsec_xmit_trap_sendcount},
	{"natt",       &proc_net_ipsec_dir, NULL,             ipsec_natt_get_info,    NULL, NULL},
	{"ocf",       &proc_net_ipsec_dir, NULL,             ipsec_ocf_get_info,    NULL, NULL},
	{"version",    &proc_net_ipsec_dir, NULL,             ipsec_version_get_info,    NULL, NULL},
#ifdef IPSEC_PROC_SHOW_SAREF_INFO
	{"saref",      &proc_net_ipsec_dir, NULL,             ipsec_saref_get_info,    NULL, NULL},
#endif
	{NULL,         NULL,                NULL,             NULL,      NULL, NULL}
};
		
int
ipsec_proc_init()
{
	int error = 0;
#ifdef IPSEC_PROC_SUBDIRS
	struct proc_dir_entry *item;
#endif

	/*
	 * just complain because pluto won't run without /proc!
	 */
#ifndef CONFIG_PROC_FS 
#error You must have PROC_FS built in to use KLIPS
#endif

	/* for 2.4 kernels */
	/* create /proc/net/ipsec */

	/* zero these out before we initialize /proc/net/ipsec/birth/stuff */
	memset(&ipsec_ipv4_birth_packet, 0, sizeof(struct ipsec_birth_reply));
	memset(&ipsec_ipv6_birth_packet, 0, sizeof(struct ipsec_birth_reply));

	proc_net_ipsec_dir = proc_mkdir("ipsec", PROC_NET);
	if(proc_net_ipsec_dir == NULL) {
		/* no point in continuing */
		return 1;
	} 	

	{
		struct ipsec_proc_list *it;

		it=proc_items;
		while(it->name!=NULL) {
			if(it->dir) {
				/* make a dir instead */
				item = proc_mkdir(it->name, *it->parent);
				*it->dir = item;
			} else {
				/* FIXME: we put the mode in the struct proc_dir_entry, but it is not used here?? */
				item = create_proc_entry(it->name, strcmp(it->name, "version") == 0 ? 0444 : 0400, *it->parent);
			}
			if(item) {
				item->read_proc  = it->readthing;
				item->write_proc = it->writething;
				item->data       = it->data;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
# ifdef MODULE
				item->owner = THIS_MODULE;
# endif
#endif
			} else {
				error |= 1;
			}
			it++;
		}
	}
	
	/* now create some symlinks to provide compatibility */
	proc_symlink("ipsec_eroute", PROC_NET, "ipsec/eroute/all");
	proc_symlink("ipsec_spi",    PROC_NET, "ipsec/spi/all");
	proc_symlink("ipsec_spigrp", PROC_NET, "ipsec/spigrp/all");
#ifdef IPSEC_SA_RECOUNT_DEBUG
	proc_symlink("ipsec_saraw",  PROC_NET, "ipsec/saraw/all");
#endif
	proc_symlink("ipsec_tncfg",  PROC_NET, "ipsec/tncfg");
	proc_symlink("ipsec_version",PROC_NET, "ipsec/version");
	proc_symlink("ipsec_klipsdebug",PROC_NET,"ipsec/klipsdebug");

	return error;
}

void
ipsec_proc_cleanup()
{
	{
		struct ipsec_proc_list *it;

		/* find end of list */
		it=proc_items;
		while(it->name!=NULL) {
			it++;
		}
		it--;

		do {
			remove_proc_entry(it->name, *it->parent);
			it--;
		} while(it >= proc_items);
	}


	remove_proc_entry("ipsec_klipsdebug", PROC_NET);
	remove_proc_entry("ipsec_eroute",     PROC_NET);
	remove_proc_entry("ipsec_spi",        PROC_NET);
	remove_proc_entry("ipsec_spigrp",     PROC_NET);
#ifdef IPSEC_SA_RECOUNT_DEBUG
	remove_proc_entry("ipsec_saraw",      PROC_NET);
#endif
	remove_proc_entry("ipsec_tncfg",      PROC_NET);
	remove_proc_entry("ipsec_version",    PROC_NET);
	remove_proc_entry("ipsec",            PROC_NET);
}
