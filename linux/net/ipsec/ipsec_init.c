/*
 * @(#) Initialization code.
 * Copyright (C) 1996, 1997   John Ioannidis.
 * Copyright (C) 1998 - 2002  Richard Guy Briggs <rgb@freeswan.org>
 *               2001 - 2004  Michael Richardson <mcr@xelerance.com>
 *  Copyright (C) 2012  Paul Wouters  <paul@libreswan.org>
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
 * /proc system code was split out into ipsec_proc.c after rev. 1.70.
 *
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) && \
	!defined(AUTOCONF_INCLUDED)
#include <linux/config.h>
#endif
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
#include <linux/in.h>           /* struct sockaddr_in */
#include <linux/skbuff.h>
#include <linux/random.h>       /* get_random_bytes() */
#include <net/protocol.h>

#include "libreswan/ipsec_param2.h"

#include <libreswan.h>

#include <linux/spinlock.h> /* *lock* */

#include <net/ip.h>

#ifdef CONFIG_PROC_FS
# include <linux/proc_fs.h>
#endif /* CONFIG_PROC_FS */

# include <linux/netlink.h>

#include "libreswan/radij.h"

#include "libreswan/ipsec_life.h"
#include "libreswan/ipsec_stats.h"
#include "libreswan/ipsec_sa.h"

#include "libreswan/ipsec_encap.h"
#include "libreswan/ipsec_radij.h"
#include "libreswan/ipsec_xform.h"
#include "libreswan/ipsec_tunnel.h"
#include "libreswan/ipsec_mast.h"

#include "libreswan/ipsec_rcv.h"
#include "libreswan/ipsec_xmit.h"
#include "libreswan/ipsec_ah.h"
#include "libreswan/ipsec_esp.h"

#ifdef CONFIG_KLIPS_IPCOMP
# include "libreswan/ipcomp.h"
#endif /* CONFIG_KLIPS_IPCOMP */

#include "libreswan/ipsec_proto.h"
#include "libreswan/ipsec_alg.h"

#ifdef CONFIG_KLIPS_OCF
#include "ipsec_ocf.h"
#endif

#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#if defined(HAVE_UDP_ENCAP_CONVERT) && defined(CONFIG_IPSEC_NAT_TRAVERSAL)
#  warning \
	"You have CONFIG_IPSEC_NAT_TRAVERSAL set on a kernel > 2.6.22 that no longer need the NAT-T patch - you should recompile without it"
#include <net/xfrmudp.h>
#endif

#ifndef HAVE_UDP_ENCAP_CONVERT
# if defined(NET_26) && defined(CONFIG_IPSEC_NAT_TRAVERSAL) && \
	!defined(HAVE_XFRM4_UDP_REGISTER)
# warning \
	"You are trying to build KLIPS2.6 with NAT-T support, but you did not"
# error   "properly apply the NAT-T patch to your < 2.6.23 kernel source tree."
# endif
#endif

#if !defined(CONFIG_KLIPS_ESP) && !defined(CONFIG_KLIPS_AH)
#error "kernel configuration must include ESP or AH"
#endif

/*
 * seems to be present in 2.4.10 (Linus), but also in some RH and other
 * distro kernels of a lower number.
 */
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif

struct prng ipsec_prng;

#if defined(NET_26) && defined(CONFIG_IPSEC_NAT_TRAVERSAL)
xfrm4_rcv_encap_t klips_old_encap = NULL;
#endif

extern int ipsec_device_event(struct notifier_block *dnot, unsigned long event,
			      void *ptr);
/*
 * the following structure is required so that we receive
 * event notifications when network devices are enabled and
 * disabled (ifconfig up and down).
 */
static struct notifier_block ipsec_dev_notifier = {
	.notifier_call = ipsec_device_event
};

#ifdef CONFIG_SYSCTL
extern int ipsec_sysctl_register(void);
extern void ipsec_sysctl_unregister(void);
#endif

/*
 * inet_*_protocol returns void on 2.4.x, int on 2.6.x
 * So we need our own wrapper
 */
#ifdef NET_26
static inline int libreswan_inet_add_protocol(struct inet_protocol *prot,
					      unsigned protocol, char *protstr)
{
	int err = inet_add_protocol(prot, protocol);

	if (err)
		printk(KERN_ERR "KLIPS: cannot register %s protocol - recompile with CONFIG_INET_%s disabled or as module\n", protstr,
			protstr);
	return err;
}

#ifdef CONFIG_KLIPS_IPV6
static inline int libreswan_inet6_add_protocol(struct inet6_protocol *prot,
					       unsigned protocol,
					       char *protstr)
{
	int err = inet6_add_protocol(prot, protocol);

	if (err)
		printk(KERN_ERR "KLIPS: cannot register %s protocol - recompile with CONFIG_INET_%s disabled or as module\n", protstr,
			protstr);
	return err;
}
#endif

static inline int libreswan_inet_del_protocol(struct inet_protocol *prot,
					      unsigned protocol)
{
	return inet_del_protocol(prot, protocol);
}

#ifdef CONFIG_KLIPS_IPV6
static inline int libreswan_inet6_del_protocol(struct inet6_protocol *prot,
					       unsigned protocol)
{
	return inet6_del_protocol(prot, protocol);
}
#endif
#else
static inline int libreswan_inet_add_protocol(struct inet_protocol *prot,
					      unsigned protocol, char *protstr)
{
#ifdef IPSKB_XFRM_TUNNEL_SIZE
	inet_add_protocol(prot, protocol);
#else
	inet_add_protocol(prot);
#endif
	return 0;
}

static inline int libreswan_inet_del_protocol(struct inet_protocol *prot,
					      unsigned protocol)
{
#ifdef IPSKB_XFRM_TUNNEL_SIZE
	inet_del_protocol(prot, protocol);
#else
	inet_del_protocol(prot);
#endif
	return 0;
}

#endif

/* void */
int ipsec_klips_init(void)
{
	int error = 0;
	unsigned char seed[256];

#ifdef CONFIG_KLIPS_ENC_3DES
	extern int des_check_key;

	/* turn off checking of keys */
	des_check_key = 0;
#endif  /* CONFIG_KLIPS_ENC_3DES */

	KLIPS_PRINT(1, "klips_info:ipsec_init: "
		    "KLIPS startup, Libreswan KLIPS IPsec stack version: %s\n",
		    ipsec_version_code());

	error = ipsec_xmit_state_cache_init();
	if (error)
		goto error_xmit_state_cache;

	error = ipsec_rcv_state_cache_init();
	if (error)
		goto error_rcv_state_cache;

	error |= ipsec_proc_init();
	if (error)
		goto error_proc_init;

	spin_lock_init(&ipsec_sadb.sadb_lock);

	error |= ipsec_sadb_init();
	if (error)
		goto error_sadb_init;

	error |= ipsec_radijinit();
	if (error)
		goto error_radijinit;

	error |= pfkey_init();
	if (error)
		goto error_pfkey_init;

	error |= register_netdevice_notifier(&ipsec_dev_notifier);
	if (error)
		goto error_netdev_notifier;

#ifdef CONFIG_XFRM_ALTERNATE_STACK
	error = xfrm_register_alternate_rcv(ipsec_rcv);
	if (error)
		goto error_xfrm_register;

#else   /* CONFIG_XFRM_ALTERNATE_STACK */

#ifdef CONFIG_KLIPS_ESP
	error |= libreswan_inet_add_protocol(&esp_protocol, IPPROTO_ESP, "ESP");
	if (error)
		goto error_libreswan_inet_add_protocol_esp;

#ifdef CONFIG_KLIPS_IPV6
	error |= libreswan_inet6_add_protocol(&esp6_protocol, IPPROTO_ESP,
					      "ESP");
	if (error)
		goto error_libreswan_inet6_add_protocol_esp;
#endif
#endif  /* CONFIG_KLIPS_ESP */

#ifdef CONFIG_KLIPS_AH
	error |= libreswan_inet_add_protocol(&ah_protocol, IPPROTO_AH, "AH");
	if (error)
		goto error_libreswan_inet_add_protocol_ah;
#endif  /* CONFIG_KLIPS_AH */

/* we never actually link IPCOMP to the stack */
#ifdef IPCOMP_USED_ALONE
#ifdef CONFIG_KLIPS_IPCOMP
	error |= libreswan_inet_add_protocol(&comp_protocol, IPPROTO_COMP,
					     "IPCOMP");
	if (error)
		goto error_libreswan_inet_add_protocol_comp;
#endif  /* CONFIG_KLIPS_IPCOMP */
#endif

#endif  /* CONFIG_XFRM_ALTERNATE_STACK */

	error |= ipsec_tunnel_init_devices();
	if (error)
		goto error_tunnel_init_devices;

	error |= ipsec_mast_init_devices();
	if (error)
		goto error_mast_init_devices;

#ifdef CONFIG_INET_IPSEC_SAREF
	error = ipsec_mast_init_saref();
	if (error)
		goto error_mast_init_saref;
#endif

/* This is no longer needed for >= 2.6.23. We use HAVE_UDP_ENCAP_CONVERT */
#if defined(NET_26) && defined(CONFIG_IPSEC_NAT_TRAVERSAL)
	/* register our ESP-UDP handler */
	if (udp4_register_esp_rcvencap(klips26_rcv_encap,
				       &klips_old_encap) != 0)
		printk(KERN_ERR "KLIPS: cannot register klips26_rcv_encap function\n");


	else
		KLIPS_PRINT(1, "KLIPS: registered klips26_rcv_encap function\n");

#endif

#ifdef CONFIG_SYSCTL
	error |= ipsec_sysctl_register();
	if (error)
		goto error_sysctl_register;
#endif

#ifdef CONFIG_KLIPS_ALG
	ipsec_alg_init();
#endif

#ifdef CONFIG_KLIPS_OCF
	ipsec_ocf_init();
#endif

	get_random_bytes((void *)seed, sizeof(seed));
	prng_init(&ipsec_prng, seed, sizeof(seed));
	return error;

	/* undo ipsec_sysctl_register */
error_sysctl_register:
#ifdef CONFIG_INET_IPSEC_SAREF
	ipsec_mast_cleanup_saref();
error_mast_init_saref:
#endif
	ipsec_mast_cleanup_devices();
error_mast_init_devices:
	ipsec_tunnel_cleanup_devices();
error_tunnel_init_devices:
#ifdef CONFIG_XFRM_ALTERNATE_STACK
	xfrm_deregister_alternate_rcv(ipsec_rcv);
error_xfrm_register:
#else   /* CONFIG_XFRM_ALTERNATE_STACK */
#ifdef IPCOMP_USED_ALONE
#ifdef CONFIG_KLIPS_IPCOMP
error_libreswan_inet_add_protocol_comp:
	libreswan_inet_del_protocol(&comp_protocol, IPPROTO_COMP);
#endif  /* CONFIG_KLIPS_IPCOMP */
#endif
#ifdef CONFIG_KLIPS_AH
error_libreswan_inet_add_protocol_ah:
	libreswan_inet_del_protocol(&ah_protocol, IPPROTO_AH);
#endif
#ifdef CONFIG_KLIPS_IPV6
error_libreswan_inet6_add_protocol_esp:
	libreswan_inet6_del_protocol(&esp6_protocol, IPPROTO_ESP);
#endif
error_libreswan_inet_add_protocol_esp:
	libreswan_inet_del_protocol(&esp_protocol, IPPROTO_ESP);
#endif
	unregister_netdevice_notifier(&ipsec_dev_notifier);
error_netdev_notifier:
	pfkey_cleanup();
error_pfkey_init:
	ipsec_radijcleanup();
error_radijinit:
	ipsec_sadb_cleanup(0);
	ipsec_sadb_free();
error_sadb_init:
error_proc_init:
	/* ipsec_proc_init() does not cleanup after itself, so we have to do
	 * it here
	 * TODO: ipsec_proc_init() should roll back what it chaned on failure
	 */
	ipsec_proc_cleanup();
	ipsec_rcv_state_cache_cleanup();
error_rcv_state_cache:
	ipsec_xmit_state_cache_cleanup();
error_xmit_state_cache:
	return error;
}

#ifdef NET_26
void
#else
int
#endif
ipsec_cleanup(void)
{
	int error = 0;

#ifdef CONFIG_SYSCTL
	ipsec_sysctl_unregister();
#endif
#if defined(NET_26) && defined(CONFIG_IPSEC_NAT_TRAVERSAL)
# ifndef HAVE_UDP_ENCAP_CONVERT
	/* unfortunately we have two versions of this function, one with one
	 * argument and one with two. But we cannot know which one. Let's hope
	 * not many people use an old nat-t patch on a new kernel with
	 * libreswan klips >= 2.6.22
	 */
	if (udp4_unregister_esp_rcvencap(klips26_rcv_encap,
					 klips_old_encap) < 0)
		printk(KERN_ERR "KLIPS: cannot unregister klips_rcv_encap function\n");


# endif
#endif

#ifdef CONFIG_INET_IPSEC_SAREF
	ipsec_mast_cleanup_saref();
#endif

	error |= ipsec_mast_cleanup_devices();

	KLIPS_PRINT(debug_netlink, /* debug_tunnel & DB_TN_INIT, */
		    "klips_debug:ipsec_cleanup: "
		    "calling ipsec_tunnel_cleanup_devices.\n");
	error |= ipsec_tunnel_cleanup_devices();

	KLIPS_PRINT(debug_netlink, "called ipsec_tunnel_cleanup_devices");

#ifdef CONFIG_XFRM_ALTERNATE_STACK

	xfrm_deregister_alternate_rcv(ipsec_rcv);

#else   /* CONFIG_XFRM_ALTERNATE_STACK */

/* we never actually link IPCOMP to the stack */
#ifdef IPCOMP_USED_ALONE
#ifdef CONFIG_KLIPS_IPCOMP
	if (libreswan_inet_del_protocol(&comp_protocol, IPPROTO_COMP) < 0)
		printk(KERN_INFO "klips_debug:ipsec_cleanup: "
		       "comp close: can't remove protocol\n");
#endif  /* CONFIG_KLIPS_IPCOMP */
#endif  /* IPCOMP_USED_ALONE */

#ifdef CONFIG_KLIPS_AH
	if (libreswan_inet_del_protocol(&ah_protocol, IPPROTO_AH) < 0)
		printk(KERN_INFO "klips_debug:ipsec_cleanup: "
		       "ah close: can't remove protocol\n");
#endif  /* CONFIG_KLIPS_AH */

#ifdef CONFIG_KLIPS_ESP
	if (libreswan_inet_del_protocol(&esp_protocol, IPPROTO_ESP) < 0)
		printk(KERN_INFO "klips_debug:ipsec_cleanup: "
		       "esp close: can't remove protocol\n");
#ifdef CONFIG_KLIPS_IPV6
	if (libreswan_inet6_del_protocol(&esp6_protocol, IPPROTO_ESP) < 0)
		printk(KERN_INFO "klips_debug:ipsec_cleanup: "
		       "esp6 close: can't remove protocol\n");
#endif
#endif  /* CONFIG_KLIPS_ESP */

#endif  /* CONFIG_XFRM_ALTERNATE_STACK */

	error |= unregister_netdevice_notifier(&ipsec_dev_notifier);

	KLIPS_PRINT(debug_netlink, /* debug_tunnel & DB_TN_INIT, */
		    "klips_debug:ipsec_cleanup: "
		    "calling ipsec_sadb_cleanup.\n");
	error |= ipsec_sadb_cleanup(0);
	error |= ipsec_sadb_free();

	KLIPS_PRINT(debug_netlink, /* debug_tunnel & DB_TN_INIT, */
		    "klips_debug:ipsec_cleanup: "
		    "calling ipsec_radijcleanup.\n");
	error |= ipsec_radijcleanup();

	KLIPS_PRINT(debug_pfkey, /* debug_tunnel & DB_TN_INIT, */
		    "klips_debug:ipsec_cleanup: "
		    "calling pfkey_cleanup.\n");
	error |= pfkey_cleanup();

	ipsec_rcv_state_cache_cleanup();
	ipsec_xmit_state_cache_cleanup();

	ipsec_proc_cleanup();

	prng_final(&ipsec_prng);

#ifdef NET_26
	if (error)
		printk("ipsec_cleanup: error %d\n", error);
#else
	return error;

#endif
}

#if defined(MODULE) || LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
#if defined(NET_26) || LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
late_initcall(ipsec_klips_init);
module_exit(ipsec_cleanup);
#else
int init_module(void)
{
	int error = 0;

	error |= ipsec_klips_init();

	return error;
}

void cleanup_module(void)
{
	KLIPS_PRINT(debug_netlink, /* debug_tunnel & DB_TN_INIT, */
		    "klips_debug:cleanup_module: "
		    "calling ipsec_cleanup.\n");

	ipsec_cleanup();

	KLIPS_PRINT(1, "klips_info:cleanup_module: "
		    "ipsec module unloaded.\n");
}
#endif
#endif /* MODULE */
