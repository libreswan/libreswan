/*
 * @(#) routines to makes kernel 2.4 compatible with 2.6 usage.
 *
 * Copyright (C) 2004 Michael Richardson <mcr@sandelman.ottawa.on.ca>
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
 * RCSID $Id: ipsec_kern24.h,v 1.5 2005/08/05 08:48:38 mcr Exp $
 */

#ifndef _IPSEC_KERN24_H

#ifdef NET_21
#  include <linux/in6.h>
#else
     /* old kernel in.h has some IPv6 stuff, but not quite enough */
#  define	s6_addr16	s6_addr
#  define	AF_INET6	10
#  define uint8_t __u8
#  define uint16_t __u16 
#  define uint32_t __u32 
#  define uint64_t __u64 
#endif

#ifdef NET_21
# define ipsec_kfree_skb(a) kfree_skb(a)
#else /* NET_21 */
# define ipsec_kfree_skb(a) kfree_skb(a, FREE_WRITE)
#endif /* NET_21 */

/* this is in ipsec_kversion.h */
#if 0
#ifdef NETDEV_23
#if 0
#ifndef NETDEV_25
#define device net_device
#endif
#endif
# define ipsec_dev_get dev_get_by_name
# define __ipsec_dev_get __dev_get_by_name
# define ipsec_dev_put(x) dev_put(x)
# define __ipsec_dev_put(x) __dev_put(x)
# define ipsec_dev_hold(x) dev_hold(x)
#else /* NETDEV_23 */
# define ipsec_dev_get dev_get
# define __ipsec_dev_put(x) 
# define ipsec_dev_put(x)
# define ipsec_dev_hold(x) 
#endif /* NETDEV_23 */
#endif

#ifndef SPINLOCK
#  include <linux/bios32.h>
     /* simulate spin locks and read/write locks */
     typedef struct {
       volatile char lock;
     } spinlock_t;

     typedef struct {
       volatile unsigned int lock;
     } rwlock_t;                                                                     

#  define spin_lock_init(x) { (x)->lock = 0;}
#  define rw_lock_init(x) { (x)->lock = 0; }

#  define spin_lock(x) { while ((x)->lock) barrier(); (x)->lock=1;}
#  define spin_lock_irq(x) { cli(); spin_lock(x);}
#  define spin_lock_irqsave(x,flags) { save_flags(flags); spin_lock_irq(x);}

#  define spin_unlock(x) { (x)->lock=0;}
#  define spin_unlock_irq(x) { spin_unlock(x); sti();}
#  define spin_unlock_irqrestore(x,flags) { spin_unlock(x); restore_flags(flags);}

#  define read_lock(x) spin_lock(x)
#  define read_lock_irq(x) spin_lock_irq(x)
#  define read_lock_irqsave(x,flags) spin_lock_irqsave(x,flags)

#  define read_unlock(x) spin_unlock(x)
#  define read_unlock_irq(x) spin_unlock_irq(x)
#  define read_unlock_irqrestore(x,flags) spin_unlock_irqrestore(x,flags)

#  define write_lock(x) spin_lock(x)
#  define write_lock_irq(x) spin_lock_irq(x)
#  define write_lock_irqsave(x,flags) spin_lock_irqsave(x,flags)

#  define write_unlock(x) spin_unlock(x)
#  define write_unlock_irq(x) spin_unlock_irq(x)
#  define write_unlock_irqrestore(x,flags) spin_unlock_irqrestore(x,flags)
#endif /* !SPINLOCK */

#ifndef SPINLOCK_23
#  define spin_lock_bh(x)  spin_lock_irq(x)
#  define spin_unlock_bh(x)  spin_unlock_irq(x)

#  define read_lock_bh(x)  read_lock_irq(x)
#  define read_unlock_bh(x)  read_unlock_irq(x)

#  define write_lock_bh(x)  write_lock_irq(x)
#  define write_unlock_bh(x)  write_unlock_irq(x)
#endif /* !SPINLOCK_23 */

#ifndef HAVE_NETDEV_PRINTK
#define netdev_printk(sevlevel, netdev, msglevel, format, arg...) \
	printk(sevlevel "%s: " format , netdev->name , ## arg)
#endif

#ifndef NET_26
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
#define sock_flag(sk, flag)  sk->dead
#define sk_for_each(sk, node, plist) for(sk=*plist; sk!=NULL; sk = sk->next)
#endif

/* deal with 2.4 vs 2.6 issues with module counts */

/* in 2.6, all refcounts are maintained *outside* of the
 * module to deal with race conditions.
 */

#ifdef NET_26
#define KLIPS_INC_USE /* nothing */
#define KLIPS_DEC_USE /* nothing */

#else
#define KLIPS_INC_USE MOD_INC_USE_COUNT
#define KLIPS_DEC_USE MOD_DEC_USE_COUNT
#endif

extern int printk_ratelimit(void);


#define _IPSEC_KERN24_H 1

#endif /* _IPSEC_KERN24_H */

