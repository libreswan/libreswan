/*
 * @(#) Initialization code.
 * Copyright (C) 1996, 1997   John Ioannidis.
 * Copyright (C) 1998 - 2002  Richard Guy Briggs <rgb@freeswan.org>
 *               2001 - 2004  Michael Richardson <mcr@xelerance.com>
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
 * /proc system code was split out into ipsec_proc.c after rev. 1.70.
 *
 */

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h> /* printk() */

#include "openswan/ipsec_param.h"

#ifdef MALLOC_SLAB
# include <linux/slab.h> /* kmalloc() */
#else /* MALLOC_SLAB */
# include <linux/malloc.h> /* kmalloc() */
#endif /* MALLOC_SLAB */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */

#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/in.h>          /* struct sockaddr_in */
#include <linux/skbuff.h>
#include <linux/random.h>       /* get_random_bytes() */
#include <net/protocol.h>

#include <openswan.h>

#ifdef SPINLOCK
# ifdef SPINLOCK_23
#  include <linux/spinlock.h> /* *lock* */
# else /* 23_SPINLOCK */
#  include <asm/spinlock.h> /* *lock* */
# endif /* 23_SPINLOCK */
#endif /* SPINLOCK */

#include <net/ip.h>

#ifdef CONFIG_PROC_FS
# include <linux/proc_fs.h>
#endif /* CONFIG_PROC_FS */

#ifdef NETLINK_SOCK
# include <linux/netlink.h>
#else
# include <net/netlink.h>
#endif

#include "openswan/radij.h"

#include "openswan/ipsec_life.h"
#include "openswan/ipsec_stats.h"
#include "openswan/ipsec_sa.h"

#include "openswan/ipsec_encap.h"
#include "openswan/ipsec_radij.h"
#include "openswan/ipsec_xform.h"
#include "openswan/ipsec_tunnel.h"
#include "openswan/ipsec_mast.h"

#include "openswan/ipsec_rcv.h"
#include "openswan/ipsec_xmit.h"
#include "openswan/ipsec_ah.h"
#include "openswan/ipsec_esp.h"

#ifdef CONFIG_KLIPS_IPCOMP
# include "openswan/ipcomp.h"
#endif /* CONFIG_KLIPS_IPCOMP */

#include "openswan/ipsec_proto.h"
#include "openswan/ipsec_alg.h"

#include <openswan/pfkeyv2.h>
#include <openswan/pfkey.h>

#if defined(NET_26) && defined(CONFIG_IPSEC_NAT_TRAVERSAL)
#include <net/xfrmudp.h>
#endif

#ifndef HAVE_UDP_ENCAP_CONVERT
# if defined(NET_26) && defined(CONFIG_IPSEC_NAT_TRAVERSAL) && !defined(HAVE_XFRM4_UDP_REGISTER)
# warning "You are trying to build KLIPS2.6 with NAT-T support, but you did not"
# error   "properly apply the NAT-T patch to your 2.6 kernel source tree."
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

extern int ipsec_device_event(struct notifier_block *dnot, unsigned long event, void *ptr);
/*
 * the following structure is required so that we receive
 * event notifications when network devices are enabled and
 * disabled (ifconfig up and down).
 */
static struct notifier_block ipsec_dev_notifier={
	ipsec_device_event,
	NULL,
	0
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
static inline int
openswan_inet_add_protocol(struct inet_protocol *prot, unsigned protocol, char *protstr)
{
	int err = inet_add_protocol(prot, protocol);
	if (err)
		printk(KERN_ERR "KLIPS: can not register %s protocol - recompile with CONFIG_INET_%s disabled or as module\n", protstr,protstr);
	return err;
}

static inline int
openswan_inet_del_protocol(struct inet_protocol *prot, unsigned protocol)
{
	return inet_del_protocol(prot, protocol);
}

#else
static inline int
openswan_inet_add_protocol(struct inet_protocol *prot, unsigned protocol)
{
	inet_add_protocol(prot);
	return 0;
}

static inline int
openswan_inet_del_protocol(struct inet_protocol *prot, unsigned protocol)
{
	inet_del_protocol(prot);
	return 0;
}

#endif

/* void */
int
ipsec_klips_init(void)
{
	int error = 0;
	unsigned char seed[256];
#ifdef CONFIG_KLIPS_ENC_3DES
	extern int des_check_key;

	/* turn off checking of keys */
	des_check_key=0;
#endif /* CONFIG_KLIPS_ENC_3DES */

	KLIPS_PRINT(1, "klips_info:ipsec_init: "
		    "KLIPS startup, Openswan KLIPS IPsec stack version: %s\n",
		    ipsec_version_code());

        error = ipsec_xmit_state_cache_init ();
        if (error)
                goto error_xmit_state_cache;

        error = ipsec_rcv_state_cache_init ();
        if (error)
                goto error_rcv_state_cache;

	error |= ipsec_proc_init();
        if (error)
                goto error_proc_init;

#ifdef SPINLOCK
	ipsec_sadb.sadb_lock = SPIN_LOCK_UNLOCKED;
#else /* SPINLOCK */
	ipsec_sadb.sadb_lock = 0;
#endif /* SPINLOCK */

#ifndef SPINLOCK
	tdb_lock.lock = 0;
	eroute_lock.lock = 0;
#endif /* !SPINLOCK */

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
        error = xfrm_register_alternate_rcv (ipsec_rcv);
        if (error)
                goto error_xfrm_register;

#else // CONFIG_XFRM_ALTERNATE_STACK

#ifdef CONFIG_KLIPS_ESP
	error |= openswan_inet_add_protocol(&esp_protocol, IPPROTO_ESP,"ESP");
	if (error)
		goto error_openswan_inet_add_protocol_esp;

#endif /* CONFIG_KLIPS_ESP */

#ifdef CONFIG_KLIPS_AH
	error |= openswan_inet_add_protocol(&ah_protocol, IPPROTO_AH,"AH");
	if (error)
		goto error_openswan_inet_add_protocol_ah;
#endif /* CONFIG_KLIPS_AH */

/* we never actually link IPCOMP to the stack */
#ifdef IPCOMP_USED_ALONE
#ifdef CONFIG_KLIPS_IPCOMP
 	error |= openswan_inet_add_protocol(&comp_protocol, IPPROTO_COMP,"IPCOMP");
	if (error)
		goto error_openswan_inet_add_protocol_comp;
#endif /* CONFIG_KLIPS_IPCOMP */
#endif

#endif // CONFIG_XFRM_ALTERNATE_STACK

	error |= ipsec_tunnel_init_devices();
        if (error)
                goto error_tunnel_init_devices;

	error |= ipsec_mast_init_devices();
	/* XXX Don't we need to call cleanup goto on error here? */

#if defined(NET_26) && defined(CONFIG_IPSEC_NAT_TRAVERSAL)
	/* register our ESP-UDP handler */
	if(udp4_register_esp_rcvencap(klips26_rcv_encap
				      , &klips_old_encap)!=0) {
	   printk(KERN_ERR "KLIPS: can not register klips_rcv_encap function\n");
	}
#endif	


#ifdef CONFIG_SYSCTL
        error |= ipsec_sysctl_register();
        if (error)
                goto error_sysctl_register;
#endif                                                                          

	ipsec_alg_init();

	get_random_bytes((void *)seed, sizeof(seed));
	prng_init(&ipsec_prng, seed, sizeof(seed));

	return error;

        // undo ipsec_sysctl_register
error_sysctl_register:
	ipsec_tunnel_cleanup_devices();
error_tunnel_init_devices:
#ifdef CONFIG_XFRM_ALTERNATE_STACK
        xfrm_deregister_alternate_rcv(ipsec_rcv);
error_xfrm_register:
#else // CONFIG_XFRM_ALTERNATE_STACK
#ifdef IPCOMP_USED_ALONE
#ifdef CONFIG_KLIPS_IPCOMP
error_openswan_inet_add_protocol_comp:
	openswan_inet_del_protocol(&comp_protocol, IPPROTO_COMP);
#endif /* CONFIG_KLIPS_IPCOMP */
#endif
#ifdef CONFIG_KLIPS_AH
error_openswan_inet_add_protocol_ah:
	openswan_inet_del_protocol(&ah_protocol, IPPROTO_AH);
#endif
#ifdef CONFIG_KLIPS_ESP
error_openswan_inet_add_protocol_esp:
	openswan_inet_del_protocol(&esp_protocol, IPPROTO_ESP);
#endif
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
        // ipsec_proc_init() does not cleanup after itself, so we have to do it here
        // TODO: ipsec_proc_init() should roll back what it chaned on failure
	ipsec_proc_cleanup();
        ipsec_rcv_state_cache_cleanup ();
error_rcv_state_cache:
        ipsec_xmit_state_cache_cleanup ();
error_xmit_state_cache:
        return error;
}	


/* void */
int
ipsec_cleanup(void)
{
	int error = 0;

#ifdef CONFIG_SYSCTL
        ipsec_sysctl_unregister();
#endif                                                                          
#if defined(NET_26) && defined(CONFIG_IPSEC_NAT_TRAVERSAL)
	if(udp4_unregister_esp_rcvencap(klips_old_encap) < 0) {
		printk(KERN_ERR "KLIPS: can not unregister klips_rcv_encap function\n");
	}
#endif

	KLIPS_PRINT(debug_netlink, /* debug_tunnel & DB_TN_INIT, */
		    "klips_debug:ipsec_cleanup: "
		    "calling ipsec_tunnel_cleanup_devices.\n");
	error |= ipsec_tunnel_cleanup_devices();

	KLIPS_PRINT(debug_netlink, "called ipsec_tunnel_cleanup_devices");

#ifdef CONFIG_XFRM_ALTERNATE_STACK

        xfrm_deregister_alternate_rcv(ipsec_rcv);

#else // CONFIG_XFRM_ALTERNATE_STACK

/* we never actually link IPCOMP to the stack */
#ifdef IPCOMP_USED_ALONE
#ifdef CONFIG_KLIPS_IPCOMP
 	if (openswan_inet_del_protocol(&comp_protocol, IPPROTO_COMP) < 0)
		printk(KERN_INFO "klips_debug:ipsec_cleanup: "
		       "comp close: can't remove protocol\n");
#endif /* CONFIG_KLIPS_IPCOMP */
#endif /* IPCOMP_USED_ALONE */

#ifdef CONFIG_KLIPS_AH
 	if (openswan_inet_del_protocol(&ah_protocol, IPPROTO_AH) < 0)
		printk(KERN_INFO "klips_debug:ipsec_cleanup: "
		       "ah close: can't remove protocol\n");
#endif /* CONFIG_KLIPS_AH */

#ifdef CONFIG_KLIPS_ESP
 	if (openswan_inet_del_protocol(&esp_protocol, IPPROTO_ESP) < 0)
		printk(KERN_INFO "klips_debug:ipsec_cleanup: "
		       "esp close: can't remove protocol\n");
#endif /* CONFIG_KLIPS_ESP */

#endif // CONFIG_XFRM_ALTERNATE_STACK

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

        ipsec_rcv_state_cache_cleanup ();
        ipsec_xmit_state_cache_cleanup ();

        ipsec_rcv_state_cache_cleanup ();
        ipsec_xmit_state_cache_cleanup ();

	ipsec_proc_cleanup();

	prng_final(&ipsec_prng);

	return error;
}

#ifdef MODULE
int
init_module(void)
{
	int error = 0;

	error |= ipsec_klips_init();

	return error;
}

#ifndef NET_26
void
cleanup_module(void)
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

/*
 * Local variables:
 * c-file-style: "linux"
 * End:
 */
