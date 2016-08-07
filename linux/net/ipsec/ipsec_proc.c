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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) && \
	!defined(AUTOCONF_INCLUDED)
# include <linux/config.h>
#endif
#define __NO_VERSION__
#include <linux/module.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0) && LINUX_VERSION_CODE >= \
	KERNEL_VERSION(2, 4, 26)
# include <linux/moduleparam.h>
#endif
#include <linux/kernel.h>       /* printk() */
#include <linux/ip.h>           /* struct iphdr */

#include "libreswan/ipsec_kversion.h"
#include "libreswan/ipsec_param.h"

#include <linux/slab.h>         /* kmalloc() */
#include <linux/errno.h>        /* error codes */
#include <linux/types.h>        /* size_t */
#include <linux/interrupt.h>    /* mark_bh */

#include <linux/netdevice.h>    /* struct device, and other headers */
#include <linux/etherdevice.h>  /* eth_type_trans */
#include <linux/in.h>           /* struct sockaddr_in */
#include <linux/skbuff.h>
#include <asm/uaccess.h>        /* copy_from_user */
#include <libreswan.h>
#include <linux/spinlock.h>     /* *lock* */

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

#ifndef CONFIG_PROC_FS
/*
 * just complain because pluto won't run without /proc!
 */
#error You must have PROC_FS built in to use KLIPS
#endif

static struct proc_dir_entry *proc_net_ipsec_dir = NULL;
static struct proc_dir_entry *proc_eroute_dir    = NULL;
static struct proc_dir_entry *proc_spi_dir       = NULL;
static struct proc_dir_entry *proc_spigrp_dir    = NULL;
static struct proc_dir_entry *proc_stats_dir     = NULL;
#ifdef IPSEC_SA_RECOUNT_DEBUG
static struct proc_dir_entry *proc_saraw_dir     = NULL;
#endif

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
int sysctl_ipsec_debug_ipcomp = 0;
int sysctl_ipsec_icmp = 0;
int sysctl_ipsec_tos = 1; /* hide per default, unless hidetos=no */

#define DECREMENT_UNSIGNED(X, amount) (((X) >= (amount)) ? (X) - (amount) : 0)

#ifdef CONFIG_KLIPS_ALG
extern int ipsec_xform_show(struct seq_file *seq, void *offset);
#endif


IPSEC_PROCFS_DEBUG_NO_STATIC
int ipsec_eroute_show(struct seq_file *seq, void *offset)
{
	if (debug_radij & DB_RJ_DUMPTREES)
		rj_dumptrees();			/* XXXXXXXXX */

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_eroute_show: seq=%p offset=%p\n",
		    seq, offset);

	spin_lock_bh(&eroute_lock);
	rj_walktree(rnh, ipsec_rj_walker_show, seq);
	spin_unlock_bh(&eroute_lock);
	return 0;
}


IPSEC_PROCFS_DEBUG_NO_STATIC
int ipsec_spi_format(struct ipsec_sa *sa_p, struct seq_file *seq)
{
	char sa[SATOT_BUF];
	char buf_s[SUBNETTOA_BUF];
	char buf_d[SUBNETTOA_BUF];
	size_t sa_len;

	ipsec_sa_get(sa_p, IPSEC_REFPROC);
	sa_len = satot(&sa_p->ips_said, 'x', sa, sizeof(sa));
	seq_printf(seq, "%s ", sa_len ? sa : " (error)");
	seq_printf(seq, "%s%s%s", IPS_XFORM_NAME(sa_p));
	seq_printf(seq, ": dir=%s", (sa_p->ips_flags & EMT_INBOUND) ? "in " : "out");

	if (sa_p->ips_addr_s) {
		sin_addrtot(sa_p->ips_addr_s, 0, buf_s, sizeof(buf_s));
		seq_printf(seq, " src=%s", buf_s);
	}

	if ((sa_p->ips_said.proto == IPPROTO_IPIP)
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

		seq_printf(seq, " policy=%s->%s", buf_s, buf_d);
	}

	if (sa_p->ips_iv_bits) {
		int j;
		seq_printf(seq, " iv_bits=%dbits iv=0x", sa_p->ips_iv_bits);

		for (j = 0; j < sa_p->ips_iv_bits / 8; j++) {
#ifdef CONFIG_KLIPS_OCF
			if (sa_p->ips_iv == NULL) {
				/*
				 * ocf doesn't set the IV
				 * so fake it for the test cases
				 */
				seq_printf(seq, "%02x", 0xA5 + j);
			} else
#endif
			seq_printf(seq, "%02x", ((__u8*)sa_p->ips_iv)[j]);
		}
	}

	if (sa_p->ips_encalg || sa_p->ips_authalg) {
		if (sa_p->ips_replaywin)
			seq_printf(seq, " ooowin=%d", sa_p->ips_replaywin);
		if (sa_p->ips_errs.ips_replaywin_errs)
			seq_printf(seq, " ooo_errs=%d", sa_p->ips_errs.ips_replaywin_errs);
		if (sa_p->ips_replaywin_lastseq)
		       seq_printf(seq, " seq=%d", sa_p->ips_replaywin_lastseq);
		if (sa_p->ips_replaywin_bitmap)
			seq_printf(seq, " bit=0x%Lx", sa_p->ips_replaywin_bitmap);
		if (sa_p->ips_replaywin_maxdiff)
			seq_printf(seq, " max_seq_diff=%d", sa_p->ips_replaywin_maxdiff);
	}

	if (sa_p->ips_flags & ~EMT_INBOUND) {
		seq_printf(seq, " flags=0x%x", sa_p->ips_flags & ~EMT_INBOUND);
		seq_printf(seq, "<");
		/* flag printing goes here */
		seq_printf(seq, ">");
	}

	if (sa_p->ips_auth_bits)
		seq_printf(seq, " alen=%d", sa_p->ips_auth_bits);
	if (sa_p->ips_key_bits_a)
		seq_printf(seq, " aklen=%d", sa_p->ips_key_bits_a);
	if (sa_p->ips_errs.ips_auth_errs)
		seq_printf(seq, " auth_errs=%d", sa_p->ips_errs.ips_auth_errs);
	if (sa_p->ips_key_bits_e)
		seq_printf(seq, " eklen=%d", sa_p->ips_key_bits_e);
	if (sa_p->ips_errs.ips_encsize_errs)
		seq_printf(seq, " encr_size_errs=%d", sa_p->ips_errs.ips_encsize_errs);
	if (sa_p->ips_errs.ips_encpad_errs)
		seq_printf(seq, " encr_pad_errs=%d", sa_p->ips_errs.ips_encpad_errs);

	seq_printf(seq, " jiffies=%lu", jiffies);

	seq_printf(seq, " life(c,s,h)=");

	ipsec_lifetime_format(seq, "alloc",
			      ipsec_life_countbased, &sa_p->ips_life.ipl_allocations);

	ipsec_lifetime_format(seq, "bytes",
			      ipsec_life_countbased, &sa_p->ips_life.ipl_bytes);

	ipsec_lifetime_format(seq, "addtime",
			      ipsec_life_timebased, &sa_p->ips_life.ipl_addtime);

	ipsec_lifetime_format(seq, "usetime",
			      ipsec_life_timebased, &sa_p->ips_life.ipl_usetime);

	ipsec_lifetime_format(seq, "packets",
			      ipsec_life_countbased, &sa_p->ips_life.ipl_packets);

	if (sa_p->ips_life.ipl_usetime.ipl_last) { /* XXX-MCR should be last? */
		seq_printf(seq, " idle=%Ld",
			   ipsec_jiffieshz_elapsed(jiffies/HZ, sa_p->ips_life.ipl_usetime.ipl_last));
	}

#ifdef CONFIG_KLIPS_IPCOMP
	if (sa_p->ips_said.proto == IPPROTO_COMP &&
	   (sa_p->ips_comp_ratio_dbytes ||
	    sa_p->ips_comp_ratio_cbytes)) {
		seq_printf(seq, " ratio=%Ld:%Ld",
			   sa_p->ips_comp_ratio_dbytes,
			   sa_p->ips_comp_ratio_cbytes);
	}
#endif /* CONFIG_KLIPS_IPCOMP */

	seq_printf(seq, " natencap=");
	switch (sa_p->ips_natt_type) {
	case 0:
		seq_printf(seq, "none");
		break;
	case ESPINUDP_WITH_NON_IKE:
		seq_printf(seq, "nonike");
		break;
	case ESPINUDP_WITH_NON_ESP:
		seq_printf(seq, "nonesp");
		break;
	default:
		seq_printf(seq, "unknown");
		break;
	}

	seq_printf(seq, " natsport=%d", sa_p->ips_natt_sport);
	seq_printf(seq, " natdport=%d", sa_p->ips_natt_dport);

	/* we decrement by one, because this SA has been referenced in order to dump this info */
	seq_printf(seq, " refcount=%d", atomic_read(&sa_p->ips_refcount)-1);
#ifdef IPSEC_SA_RECOUNT_DEBUG
	{
		int f;
		seq_printf(seq, "[");
		for (f = 0; f < sizeof(sa_p->ips_track); f++)
			seq_printf(seq, "%s%d", f == 0 ? "" : ",", sa_p->ips_track[f]);
		seq_printf(seq, "]");
	}
#endif

	seq_printf(seq, " ref=%d", sa_p->ips_ref);
	seq_printf(seq, " refhim=%d", sa_p->ips_refhim);

	if (sa_p->ips_out) {
		seq_printf(seq, " outif=%s:%d",
			   sa_p->ips_out->name,
			   sa_p->ips_transport_direct);
	}

	if (debug_xform) {
		seq_printf(seq, " reftable=%lu refentry=%lu",
			   (unsigned long)IPsecSAref2table(sa_p->ips_ref),
			   (unsigned long)IPsecSAref2entry(sa_p->ips_ref));
	}

	seq_printf(seq, "\n");

	ipsec_sa_put(sa_p, IPSEC_REFPROC);
	return 0;
}


IPSEC_PROCFS_DEBUG_NO_STATIC
int ipsec_spi_show(struct seq_file *seq, void *offset)
{
	int i;
	struct ipsec_sa *sa_p;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_spi_show: seq=%p offset=%p\n",
		    seq, offset);

	spin_lock_bh(&tdb_lock);

	for (i = 0; i < SADB_HASHMOD; i++)
		for (sa_p = ipsec_sadb_hash[i]; sa_p; sa_p = sa_p->ips_hnext)
			ipsec_spi_format(sa_p, seq);

	spin_unlock_bh(&tdb_lock);

	return 0;
}


IPSEC_PROCFS_DEBUG_NO_STATIC
int ipsec_spigrp_show(struct seq_file *seq, void *offset)
{
	int i;
	struct ipsec_sa *sa_p, *sa_p2;
	char sa[SATOT_BUF];
	size_t sa_len;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_spigrp_show: seq=%p offset=%p\n",
		    seq, offset);

	spin_lock_bh(&tdb_lock);

	for (i = 0; i < SADB_HASHMOD; i++) {
		for (sa_p = ipsec_sadb_hash[i]; sa_p != NULL; sa_p = sa_p->ips_hnext) {
			sa_p2 = sa_p;
			while (sa_p2 != NULL) {
				struct ipsec_sa *sa2n;
				sa_len = satot(&sa_p2->ips_said,
					       'x', sa, sizeof(sa));
				seq_printf(seq, "%s ", sa_len ? sa : " (error)");
				sa2n = sa_p2->ips_next;
				sa_p2 = sa2n;
			}
			seq_printf(seq, "\n");
		}
	}

	spin_unlock_bh(&tdb_lock);

	return 0;
}


#ifdef IPSEC_SA_RECOUNT_DEBUG
IPSEC_PROCFS_DEBUG_NO_STATIC
int ipsec_saraw_show(struct seq_file *seq, void *offset)
{
	struct ipsec_sa *sa_p;
	extern struct ipsec_sa *ipsec_sa_raw;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_saraw_show: seq=%p offset=%p\n",
		    seq, offset);

	spin_lock_bh(&tdb_lock);

	for (sa_p = ipsec_sa_raw; sa_p; sa_p = sa_p->ips_raw)
		ipsec_spi_format(sa_p, seq);

	spin_unlock_bh(&tdb_lock);

	return 0;
}
#endif /* IPSEC_SA_RECOUNT_DEBUG */


IPSEC_PROCFS_DEBUG_NO_STATIC
int ipsec_tncfg_show(struct seq_file *seq, void *offset)
{
	int i;
	char name[9];
	struct net_device *dev, *privdev;
	struct ipsecpriv *priv;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_tncfg_show: seq=%p offset=%p\n",
		    seq, offset);

	for (i = 0; i < IPSEC_NUM_IFMAX; i++) {
		ipsec_snprintf(name, (ssize_t) sizeof(name), IPSEC_DEV_FORMAT, i);
		dev = __ipsec_dev_get(name);
		if (dev) {
			priv = netdev_to_ipsecpriv(dev);
			seq_printf(seq, "%s", dev->name);
			if (priv) {
				privdev = (struct net_device *)(priv->dev);
				seq_printf(seq, " -> %s", privdev ? privdev->name : "NULL");
				seq_printf(seq, " mtu=%d(%d) -> %d",
					       dev->mtu, priv->mtu, privdev ? privdev->mtu : 0);
			} else {
				KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
					    "klips_debug:ipsec_tncfg_show: "
					    "device '%s' has no private data space!\n",
					    dev->name);
			}
			seq_printf(seq, "\n");
		}
	}

	return 0;
}


IPSEC_PROCFS_DEBUG_NO_STATIC
int ipsec_version_show(struct seq_file *seq, void *offset)
{
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_version_show: seq=%p offset=%p\n",
		    seq, offset);
	seq_printf(seq, "Libreswan version: %s\n", ipsec_version_code());
	return 0;
}


#ifdef IPSEC_PROC_SHOW_SAREF_INFO
IPSEC_PROCFS_DEBUG_NO_STATIC
int ipsec_saref_show(struct seq_file *seq, void *offset)
{
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_saref_show: seq=%p offset=%p\n",
		    seq, offset);

#ifdef IP_IPSEC_REFINFO
	seq_printf(seq, "refinfo patch applied\n");
#endif

#ifdef IP_IPSEC_BINDREF
	seq_printf(seq, "bindref patch applied\n");
#endif

#ifdef CONFIG_INET_IPSEC_SAREF
	seq_printf(seq, "saref enabled (%s)\n", ipsec_version_code());
#else
	seq_printf(seq, "saref disabled (%s)\n", ipsec_version_code());
#endif

	return 0;
}
#endif


#ifdef CONFIG_KLIPS_OCF
unsigned int ocf_available = 1;
#else
unsigned int ocf_available = 0;
#endif
module_param(ocf_available, int, 0644);

IPSEC_PROCFS_DEBUG_NO_STATIC
int ipsec_ocf_show(struct seq_file *seq, void *offset)
{
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_ocf_show: seq=%p offset=%p\n",
		    seq, offset);
	seq_printf(seq, "%d\n", ocf_available);
	return 0;
}


#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
unsigned int natt_available = 1;
#elif defined (HAVE_UDP_ENCAP_CONVERT)
unsigned int natt_available = 2;
#else
unsigned int natt_available = 0;
#endif
module_param(natt_available, int, 0644);

IPSEC_PROCFS_DEBUG_NO_STATIC
int ipsec_natt_show(struct seq_file *seq, void *offset)
{
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_natt_show: seq=%p offset=%p\n",
		    seq, offset);
	seq_printf(seq, "%d\n", natt_available);
	return 0;
}


IPSEC_PROCFS_DEBUG_NO_STATIC
int ipsec_klipsdebug_show(struct seq_file *seq, void *offset)
{
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_klipsdebug_show: seq=%p, offset=%p\n",
		    seq, offset);

	seq_printf(seq, "debug_tunnel=%08x.\n", debug_tunnel);
	seq_printf(seq, "debug_xform=%08x.\n", debug_xform);
	seq_printf(seq, "debug_eroute=%08x.\n", debug_eroute);
	seq_printf(seq, "debug_spi=%08x.\n", debug_spi);
	seq_printf(seq, "debug_radij=%08x.\n", debug_radij);
	seq_printf(seq, "debug_esp=%08x.\n", debug_esp);
	seq_printf(seq, "debug_ah=%08x.\n", debug_ah);
	seq_printf(seq, "debug_rcv=%08x.\n", debug_rcv);
	seq_printf(seq, "debug_pfkey=%08x.\n", debug_pfkey);
	return 0;
}


IPSEC_PROCFS_DEBUG_NO_STATIC
int ipsec_trap_count_show(struct seq_file *seq, void *offset)
{
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_trap_count_show: seq=%p offset=%p\n",
		    seq, offset);
	seq_printf(seq, "%08x\n", ipsec_xmit_trap_count);
	return 0;
}


IPSEC_PROCFS_DEBUG_NO_STATIC
int ipsec_trap_sendcount_show(struct seq_file *seq, void *offset)
{
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_trap_sendcount_show: seq=%p offset=%p\n",
		    seq, offset);
	seq_printf(seq, "%08x\n", ipsec_xmit_trap_sendcount);
	return 0;
}


struct ipsec_proc_list {
	char                   *name;
	umode_t                 mode;
	struct proc_dir_entry **parent;
	struct proc_dir_entry **dir;
	int                   (*proc_open)(struct seq_file *seq, void *offset);
	void                   *data; /* not currently used but implemented */
};

#define DIRE(n,p,d) \
	{ .name = (n), .parent = (p), .dir = (d) }

#define NODE(n,p,o,m) \
	{ .name = (n), .mode = (m), .parent = (p), .proc_open = (o), .data = NULL }

static int ipsec_proc_open(struct inode *inode, struct file *file)
{
	struct ipsec_proc_list *it = PDE_DATA(inode);
    return single_open(file, it->proc_open, it->data);
}

static const struct file_operations ipsec_proc_fops = {
    .open       = ipsec_proc_open,
    .read       = seq_read,
    .llseek     = seq_lseek,
    .release    = single_release,
};

static struct ipsec_proc_list proc_items[]={
    NODE("klipsdebug",     &proc_net_ipsec_dir, ipsec_klipsdebug_show,     0),

    DIRE("eroute",         &proc_net_ipsec_dir, &proc_eroute_dir),
    NODE("all",            &proc_eroute_dir,    ipsec_eroute_show,         0),

    DIRE("spi",            &proc_net_ipsec_dir, &proc_spi_dir),
    NODE("all",            &proc_spi_dir,       ipsec_spi_show,            0),

    DIRE("spigrp",         &proc_net_ipsec_dir, &proc_spigrp_dir),
    NODE("all",            &proc_spigrp_dir,    ipsec_spigrp_show,         0),

#ifdef IPSEC_SA_RECOUNT_DEBUG
    DIRE("saraw",          &proc_net_ipsec_dir, &proc_saraw_dir),
    NODE("all",            &proc_saraw_dir,     ipsec_saraw_show,          0),
#endif

    NODE("tncfg",          &proc_net_ipsec_dir, ipsec_tncfg_show,          0),

#ifdef CONFIG_KLIPS_ALG
    NODE("xforms",         &proc_net_ipsec_dir, ipsec_xform_show,          0),
#endif

    DIRE("stats",          &proc_net_ipsec_dir, &proc_stats_dir),
    NODE("trap_count",     &proc_stats_dir,     ipsec_trap_count_show,     0),
    NODE("trap_sendcount", &proc_stats_dir,     ipsec_trap_sendcount_show, 0),
    NODE("natt",           &proc_net_ipsec_dir, ipsec_natt_show,           0),
    NODE("ocf",            &proc_net_ipsec_dir, ipsec_ocf_show,            0),
    NODE("version",        &proc_net_ipsec_dir, ipsec_version_show,     0444),
#ifdef IPSEC_PROC_SHOW_SAREF_INFO
    NODE("saref",          &proc_net_ipsec_dir, ipsec_saref_show,          0),
#endif

    NODE("pf_key",           &PROC_NET,         pfkey_show,                0),
    NODE("pf_key_supported", &PROC_NET,         pfkey_supported_show,      0),
    NODE("pf_key_registered",&PROC_NET,         pfkey_registered_show,     0),

    {}
};

int ipsec_proc_init(void)
{
	int error = 0;
	struct proc_dir_entry *item;
	struct ipsec_proc_list *it;

	/* create /proc/net/ipsec */
	proc_net_ipsec_dir = proc_mkdir("ipsec", PROC_NET);
	if (proc_net_ipsec_dir == NULL) {
		/* no point in continuing */
		return 1;
	}

	for (it = proc_items; it->name; it++) {
		if (it->dir) {
			item = proc_mkdir(it->name, *it->parent);
			*it->dir = item;
		} else
			item = proc_create_data(it->name, it->mode, *it->parent,
						&ipsec_proc_fops, it);
		if (!item)
			error |= 1;
	}

	/* now create some symlinks to provide compatibility */
	proc_symlink("ipsec_eroute", PROC_NET, "ipsec/eroute/all");
	proc_symlink("ipsec_spi",    PROC_NET, "ipsec/spi/all");
	proc_symlink("ipsec_spigrp", PROC_NET, "ipsec/spigrp/all");
#ifdef IPSEC_SA_RECOUNT_DEBUG
	proc_symlink("ipsec_saraw",  PROC_NET, "ipsec/saraw/all");
#endif
	proc_symlink("ipsec_tncfg",  PROC_NET, "ipsec/tncfg");
	proc_symlink("ipsec_version", PROC_NET, "ipsec/version");
	proc_symlink("ipsec_klipsdebug", PROC_NET, "ipsec/klipsdebug");

	return error;
}

void ipsec_proc_cleanup(void)
{
	struct ipsec_proc_list *it;

	/* remove entries in reverse */
	for (it = proc_items; it->name; it++)
		;
	for (it--; it >= proc_items && it->name; it--)
		remove_proc_subtree(it->name, *it->parent);

	remove_proc_subtree("ipsec_klipsdebug", PROC_NET);
	remove_proc_subtree("ipsec_eroute",     PROC_NET);
	remove_proc_subtree("ipsec_spi",        PROC_NET);
	remove_proc_subtree("ipsec_spigrp",     PROC_NET);
#ifdef IPSEC_SA_RECOUNT_DEBUG
	remove_proc_subtree("ipsec_saraw",      PROC_NET);
#endif
	remove_proc_subtree("ipsec_tncfg",      PROC_NET);
	remove_proc_subtree("ipsec_version",    PROC_NET);
	remove_proc_subtree("ipsec",            PROC_NET);
}
