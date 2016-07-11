/*
 * @(#) RFC2367 PF_KEYv2 Key management API domain socket I/F
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs.
 * Copyright (C) 2010-12 David McCullough <david_mccullough@mcafee.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2015 Greg Ungerer <gerg@uclinux.org>
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
 */

/*
 *		Template from /usr/src/linux-2.0.36/net/unix/af_unix.c.
 *		Hints from /usr/src/linux-2.0.36/net/ipv4/udp.c.
 */

#define __NO_VERSION__
#include <linux/module.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) && \
	!defined(AUTOCONF_INCLUDED)
# include <linux/config.h>
#endif
#include <linux/kernel.h>

#include "libreswan/ipsec_param.h"

#include <linux/major.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/socket.h>
#include <linux/un.h>
#include <linux/fcntl.h>
#include <linux/termios.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/net.h> /* struct socket */
#include <linux/in.h>
#include <linux/fs.h>
#include <linux/slab.h> /* kmalloc() */
#ifdef CONFIG_X86
# include <asm/segment.h>
#endif
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/sock.h> /* struct sock */
#include <net/protocol.h>
/* #include <net/tcp.h> */
#include <net/af_unix.h>
#ifdef CONFIG_PROC_FS
# include <linux/proc_fs.h>
#endif /* CONFIG_PROC_FS */
#ifdef HAVE_SEQ_FILE
# include <linux/seq_file.h>
#endif

#include <linux/types.h>

#include "libreswan/ipsec_param2.h"

#include <libreswan.h>

#include "libreswan/radij.h"
#include "libreswan/ipsec_encap.h"
#include "libreswan/ipsec_sa.h"

#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include "libreswan/ipsec_proto.h"
#include "libreswan/ipsec_kversion.h"
#include "libreswan/ipsec_sysctl.h"

#define SENDERR(_x) do { error = -(_x); goto errlab; } while (0)

#ifndef SOCKOPS_WRAPPED
#define SOCKOPS_WRAPPED(name) name
#endif /* SOCKOPS_WRAPPED */
#ifndef SOCKOPS_WRAP
#define SOCKOPS_WRAP(name, fam)
#endif /* SOCKOPS_WRAP */

extern struct proto_ops SOCKOPS_WRAPPED(pfkey_ops);

#ifdef NET_26
static DEFINE_RWLOCK(pfkey_sock_lock);
static HLIST_HEAD(pfkey_sock_list);
static DECLARE_WAIT_QUEUE_HEAD(pfkey_sock_wait);
static atomic_t pfkey_sock_users = ATOMIC_INIT(0);
#else
static struct sock *pfkey_sock_list = NULL;
#endif

struct supported_list *pfkey_supported_list[K_SADB_SATYPE_MAX + 1];

struct socket_list *pfkey_open_sockets = NULL;
struct socket_list *pfkey_registered_sockets[K_SADB_SATYPE_MAX + 1];

int pfkey_msg_interp(struct sock *, struct sadb_msg *);

#if defined(NET_26_24_SKALLOC) || defined(NET_44_SKALLOC)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
DEBUG_NO_STATIC int pfkey_create(struct net *net, struct socket *sock,
				 int protocol, int kern);
#else
DEBUG_NO_STATIC int pfkey_create(struct net *net, struct socket *sock,
				 int protocol);
#endif
#else
DEBUG_NO_STATIC int pfkey_create(struct socket *sock, int protocol);
#endif
DEBUG_NO_STATIC int pfkey_shutdown(struct socket *sock, int mode);
DEBUG_NO_STATIC int pfkey_release(struct socket *sock);

#ifdef NET_26
# if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
DEBUG_NO_STATIC int pfkey_sendmsg(struct socket *sock,
				  struct msghdr *msg, size_t len);
DEBUG_NO_STATIC int pfkey_recvmsg(struct socket *sock,
				  struct msghdr *msg,
				  size_t size, int flags);
# else
DEBUG_NO_STATIC int pfkey_sendmsg(struct kiocb *iocb, struct socket *sock,
				  struct msghdr *msg, size_t len);
DEBUG_NO_STATIC int pfkey_recvmsg(struct kiocb *kiocb, struct socket *sock,
				  struct msghdr *msg,
				  size_t size, int flags);
# endif
#else
DEBUG_NO_STATIC int pfkey_sendmsg(struct socket *sock, struct msghdr *msg,
				  int len, struct scm_cookie *scm);
DEBUG_NO_STATIC int pfkey_recvmsg(struct socket *sock, struct msghdr *msg,
				  int size, int flags, struct scm_cookie *scm);
#endif

static struct net_proto_family pfkey_family_ops = {
#ifdef NET_26
	.owner  = THIS_MODULE,
#endif
	.family = PF_KEY,
	.create = pfkey_create
};

struct proto_ops SOCKOPS_WRAPPED(pfkey_ops) =
{
#ifdef NET_26
	owner:          THIS_MODULE,
#endif
	family:         PF_KEY,
	release:        pfkey_release,
	bind:           sock_no_bind,
	connect:        sock_no_connect,
	socketpair:     sock_no_socketpair,
	accept:         sock_no_accept,
	getname:        sock_no_getname,
	poll:           datagram_poll,
	ioctl:          sock_no_ioctl,
	listen:         sock_no_listen,
	shutdown:       pfkey_shutdown,
	setsockopt:     sock_no_setsockopt,
	getsockopt:     sock_no_getsockopt,
	sendmsg:        pfkey_sendmsg,
	recvmsg:        pfkey_recvmsg,
	mmap:           sock_no_mmap,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
#include <linux/smp_lock.h>
#endif
SOCKOPS_WRAP(pfkey, PF_KEY);

#ifdef NET_26
static void pfkey_sock_list_grab(void)
{
	write_lock_bh(&pfkey_sock_lock);

	if (atomic_read(&pfkey_sock_users)) {
		DECLARE_WAITQUEUE(wait, current);

		add_wait_queue_exclusive(&pfkey_sock_wait, &wait);
		for (;; ) {
			set_current_state(TASK_UNINTERRUPTIBLE);
			if (atomic_read(&pfkey_sock_users) == 0)
				break;
			write_unlock_bh(&pfkey_sock_lock);
			schedule();
			write_lock_bh(&pfkey_sock_lock);
		}

		__set_current_state(TASK_RUNNING);
		remove_wait_queue(&pfkey_sock_wait, &wait);
	}
}

static __inline__ void pfkey_sock_list_ungrab(void)
{
	write_unlock_bh(&pfkey_sock_lock);
	wake_up(&pfkey_sock_wait);
}

static __inline__ void pfkey_lock_sock_list(void)
{
	/* read_lock() synchronizes us to pfkey_table_grab */

	read_lock(&pfkey_sock_lock);
	atomic_inc(&pfkey_sock_users);
	read_unlock(&pfkey_sock_lock);
}

static __inline__ void pfkey_unlock_sock_list(void)
{
	if (atomic_dec_and_test(&pfkey_sock_users))
		wake_up(&pfkey_sock_wait);
}
#endif

static int pfkey_list_remove_socket(struct socket *socketp,
			     struct socket_list **sockets)
{
	struct socket_list *socket_listp, *prev;

	if (!socketp) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_list_remove_socket: "
			    "NULL socketp handed in, failed.\n");
		return -EINVAL;
	}

	if (!sockets) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_list_remove_socket: "
			    "NULL sockets list handed in, failed.\n");
		return -EINVAL;
	}

	socket_listp = *sockets;
	prev = NULL;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_list_remove_socket: "
		    "removing sock=0p%p\n",
		    socketp);

	while (socket_listp != NULL) {
		if (socket_listp->socketp == socketp) {
			if (prev != NULL)
				prev->next = socket_listp->next;
			else
				*sockets = socket_listp->next;

			kfree((void*)socket_listp);

			break;
		}
		prev = socket_listp;
		socket_listp = socket_listp->next;
	}

	return 0;
}

int pfkey_list_insert_socket(struct socket *socketp,
			     struct socket_list **sockets)
{
	struct socket_list *socket_listp;

	if (!socketp) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_list_insert_socket: "
			    "NULL socketp handed in, failed.\n");
		return -EINVAL;
	}

	if (!sockets) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_list_insert_socket: "
			    "NULL sockets list handed in, failed.\n");
		return -EINVAL;
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_list_insert_socket: "
		    "allocating %lu bytes for socketp=0p%p\n",
		    (unsigned long) sizeof(struct socket_list),
		    socketp);

	if ((socket_listp = (struct socket_list *)
	     kmalloc(sizeof(struct socket_list), GFP_KERNEL)) == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_list_insert_socket: "
			    "memory allocation error.\n");
		return -ENOMEM;
	}

	socket_listp->socketp = socketp;
	socket_listp->next = *sockets;
	*sockets = socket_listp;

	return 0;
}

int pfkey_list_remove_supported(struct ipsec_alg_supported *supported,
				struct supported_list **supported_list)
{
	struct supported_list *supported_listp = *supported_list, *prev = NULL;

	if (!supported) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_list_remove_supported: "
			    "NULL supported handed in, failed.\n");
		return -EINVAL;
	}

	if (!supported_list) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_list_remove_supported: "
			    "NULL supported_list handed in, failed.\n");
		return -EINVAL;
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_list_remove_supported: "
		    "removing supported=0p%p\n",
		    supported);

	while (supported_listp != NULL) {
		if (supported_listp->supportedp == supported) {
			if (prev != NULL)
				prev->next = supported_listp->next;
			else
				*supported_list = supported_listp->next;

			kfree((void*)supported_listp);

			break;
		}
		prev = supported_listp;
		supported_listp = supported_listp->next;
	}

	return 0;
}

int pfkey_list_insert_supported(struct ipsec_alg_supported *supported,
				struct supported_list **supported_list)
{
	struct supported_list *supported_listp;

	if (!supported) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_list_insert_supported: "
			    "NULL supported handed in, failed.\n");
		return -EINVAL;
	}

	if (!supported_list) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_list_insert_supported: "
			    "NULL supported_list handed in, failed.\n");
		return -EINVAL;
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_list_insert_supported: "
		    "allocating %lu bytes for incoming, supported=0p%p, supported_list=0p%p\n",
		    (unsigned long) sizeof(struct supported_list),
		    supported,
		    supported_list);

	supported_listp = (struct supported_list *)
		kmalloc(sizeof(struct supported_list), GFP_KERNEL);

	if (supported_listp == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_list_insert_supported: "
			    "memory allocation error.\n");
		return -ENOMEM;
	}

	supported_listp->supportedp = supported;
	supported_listp->next = *supported_list;
	*supported_list = supported_listp;
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_list_insert_supported: "
		    "outgoing, supported=0p%p, supported_list=0p%p\n",
		    supported,
		    supported_list);

	return 0;
}

#ifdef NET_26
DEBUG_NO_STATIC void pfkey_insert_socket(struct sock *sk)
{
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_insert_socket: "
		    "sk=0p%p\n",
		    sk);
	pfkey_sock_list_grab();
	sk_add_node(sk, &pfkey_sock_list);
	pfkey_sock_list_ungrab();
}

DEBUG_NO_STATIC void pfkey_remove_socket(struct sock *sk)
{
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_remove_socket: 0p%p\n", sk);
	pfkey_sock_list_grab();
	sk_del_node_init(sk);
	pfkey_sock_list_ungrab();
}
#else

DEBUG_NO_STATIC void pfkey_insert_socket(struct sock *sk)
{
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_insert_socket: "
		    "sk=0p%p\n",
		    sk);
	cli();
	sk->next = pfkey_sock_list;
	pfkey_sock_list = sk;
	sti();
}
DEBUG_NO_STATIC void pfkey_remove_socket(struct sock *sk)
{
	struct sock **s;

	s = NULL;
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_remove_socket: .\n");

	cli();
	s = &pfkey_sock_list;

	while (*s != NULL) {
		if (*s == sk) {
			*s = sk->next;
			sk->next = NULL;
			sti();
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_remove_socket: "
				    "succeeded.\n");
			return;
		}
		s = &((*s)->next);
	}
	sti();

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_remove_socket: "
		    "not found.\n");
}
#endif

DEBUG_NO_STATIC void pfkey_destroy_socket(struct sock *sk)
{
	struct sk_buff *skb;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_destroy_socket: 0p%p\n", sk);
	pfkey_remove_socket(sk);

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_destroy_socket: "
		    "pfkey_remove_socket called, sk=0p%p\n", sk);

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_destroy_socket: "
		    "sk(0p%p)->(&0p%p)receive_queue.{next=0p%p,prev=0p%p}.\n",
		    sk,
		    &(sk->sk_receive_queue),
		    sk->sk_receive_queue.next,
		    sk->sk_receive_queue.prev);

	while (sk && ((skb = skb_dequeue(&(sk->sk_receive_queue))) != NULL)) {
		if (debug_pfkey && sysctl_ipsec_debug_verbose) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_destroy_socket: "
				    "skb=0p%p dequeued.\n", skb);
			printk(KERN_INFO "klips_debug:pfkey_destroy_socket: "
			       "pfkey_skb contents:");
			printk(" next:0p%p", skb->next);
			printk(" prev:0p%p", skb->prev);
			printk(" sk:0p%p", skb->sk);
			printk(" dev:0p%p", skb->dev);
			if (skb->dev) {
				if (skb->dev->name)
					printk(" dev->name:%s",
					       skb->dev->name);
				else
					printk(" dev->name:NULL?");
			} else {
				printk(" dev:NULL");
			}
			printk(" h:0p%p", skb_transport_header(skb));
			printk(" nh:0p%p", skb_network_header(skb));
			printk(" mac:0p%p", skb_mac_header(skb));
			printk(" dst:0p%p", skb_dst(skb));
			if (sysctl_ipsec_debug_verbose) {
				int i;

				printk(" cb");
				for (i = 0; i < 48; i++)
					printk(":%2x", skb->cb[i]);
			}
			printk(" len:%d", skb->len);
			printk(" csum:%d", skb->csum);
			printk(" cloned:%d", skb->cloned);
			printk(" pkt_type:%d", skb->pkt_type);
			printk(" ip_summed:%d", skb->ip_summed);
			printk(" priority:%d", skb->priority);
			printk(" protocol:%d", skb->protocol);
#ifdef HAVE_SOCK_SECURITY
			printk(" security:%d", skb->security);
#endif
			printk(" truesize:%d", skb->truesize);
			printk(" head:0p%p", skb->head);
			printk(" data:0p%p", skb->data);
			printk(" tail:0p%p", skb_tail_pointer(skb));
			printk(" end:0p%p", skb_end_pointer(skb));
			if (sysctl_ipsec_debug_verbose) {
				unsigned char* i;
				printk(" data");
				for (i = skb->head; i < skb_end_pointer(skb);
				     i++)
					printk(":%2x", (unsigned char)(*(i)));
			}
			printk(" destructor:0p%p", skb->destructor);
			printk("\n");
		}
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_destroy_socket: "
			    "skb=0p%p freed.\n",
			    skb);
		ipsec_kfree_skb(skb);
	}

#ifdef NET_26
	sock_set_flag(sk, SOCK_DEAD);
#else
	sk->dead = 1;
#endif
	sk_free(sk);

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_destroy_socket: destroyed.\n");
}

#ifdef HAVE_USER_NS
uint32_t pfkey_kuid_to_uid(kuid_t kuid)
{
	return from_kuid(&init_user_ns, kuid);
}
#endif

int pfkey_upmsg(struct socket *sock, struct sadb_msg *pfkey_msg)
{
	struct sock *sk;

	if (sock == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_upmsg: "
			    "NULL socket passed in.\n");
		return -EINVAL;
	}

	if (pfkey_msg == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_upmsg: "
			    "NULL pfkey_msg passed in.\n");
		return -EINVAL;
	}

	sk = sock->sk;
	return pfkey_upmsgsk(sk, pfkey_msg);
}
int pfkey_upmsgsk(struct sock *sk, struct sadb_msg *pfkey_msg)
{
	int error = 0;
	struct sk_buff * skb = NULL;

	if (sk == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_upmsg: "
			    "NULL sock passed in.\n");
		return -EINVAL;
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_upmsg: "
		    "allocating %d bytes...\n",
		    (int)(pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN));
	if (!(skb = alloc_skb(pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN,
			      GFP_ATOMIC) )) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_upmsg: "
			    "no buffers left to send up a message.\n");
		return -ENOBUFS;
	}
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_upmsg: "
		    "...allocated at 0p%p.\n",
		    skb);

	skb->dev = NULL;

	if (skb_tailroom(skb) < pfkey_msg->sadb_msg_len *
	    IPSEC_PFKEYv2_ALIGN) {
		printk(KERN_WARNING "klips_error:pfkey_upmsg: "
		       "tried to skb_put %ld, %d available.  This should never happen, please report.\n",
		       (unsigned long int)pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN,
		       skb_tailroom(skb));
		ipsec_kfree_skb(skb);
		return -ENOBUFS;
	}
	skb_set_transport_header(skb,
				 ipsec_skb_offset(skb,
						  skb_put(skb,
							  pfkey_msg->
							  sadb_msg_len *
							  IPSEC_PFKEYv2_ALIGN)));
	memcpy(skb_transport_header(skb),
		pfkey_msg,
		pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN);

	if ((error = sock_queue_rcv_skb(sk, skb)) < 0) {
		skb->sk = NULL;
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_upmsg: "
			    "error=%d calling sock_queue_rcv_skb with skb=0p%p.\n",
			    error,
			    skb);
		ipsec_kfree_skb(skb);
		return error;
	}
	return error;
}

#if defined(NET_26_12_SKALLOC) || defined(NET_26_24_SKALLOC) || defined(NET_44_SKALLOC)

static struct proto key_proto = {
	.name     = "KEY",
	.owner    = THIS_MODULE,
	.obj_size = sizeof(struct sock),

};
#endif
#if defined(NET_26_24_SKALLOC) || defined(NET_44_SKALLOC)
DEBUG_NO_STATIC int pfkey_create(struct net *net, struct socket *sock, int protocol
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, \
					 38)
				 , int kern
#endif
				 )
#else
DEBUG_NO_STATIC int pfkey_create(struct socket *sock, int protocol)
#endif
{
	struct sock *sk;

	if (sock == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_create: "
			    "socket NULL.\n");
		return -EINVAL;
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_create: "
		    "sock=0p%p type:%d state:%d flags:%ld protocol:%d\n",
		    sock,
		    sock->type,
		    (unsigned int)(sock->state),
		    sock->flags, protocol);

	if (sock->type != SOCK_RAW) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_create: "
			    "only SOCK_RAW supported.\n");
		return -ESOCKTNOSUPPORT;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
	if (!kern && !capable(CAP_NET_RAW)) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_create: "
			    "no permissions.\n");
		return -EPERM;
	}
#endif

	if (protocol != PF_KEY_V2) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_create: "
			    "protocol not PF_KEY_V2.\n");
		return -EPROTONOSUPPORT;
	}

	if (!capable(CAP_NET_ADMIN)) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_create: "
			    "must be root (or have net_admin capability) to open pfkey sockets.\n");
		return -EACCES;
	}

	sock->state = SS_UNCONNECTED;

	KLIPS_INC_USE;

#ifdef NET_26
#ifdef NET_44_SKALLOC
	sk = (struct sock *)sk_alloc(net, PF_KEY, GFP_KERNEL, &key_proto, 0);
#else
#ifdef NET_26_24_SKALLOC
	sk = (struct sock *)sk_alloc(net, PF_KEY, GFP_KERNEL, &key_proto);
#else
#ifdef NET_26_12_SKALLOC
	sk = (struct sock *)sk_alloc(PF_KEY, GFP_KERNEL, &key_proto, 1);
#else
	sk = (struct sock *)sk_alloc(PF_KEY, GFP_KERNEL, 1, NULL);
#endif
#endif
#endif
#else
	/* 2.4 interface */
	sk = (struct sock *)sk_alloc(PF_KEY, GFP_KERNEL, 1);
#endif

	if (sk == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_create: "
			    "Out of memory trying to allocate.\n");
		KLIPS_DEC_USE;
		return -ENOMEM;
	}

	sock_init_data(sock, sk);

	sk->sk_destruct = NULL;
	sk->sk_reuse = 1;
	sock->ops = &SOCKOPS_WRAPPED(pfkey_ops);

	sk->sk_family = PF_KEY;
/*	sk->num = protocol; */
	sk->sk_protocol = protocol;
#ifdef HAVE_USER_NS
	key_pid(sk) = pfkey_kuid_to_uid(current_uid());
#else
	key_pid(sk) = current_uid();
#endif

#ifdef HAVE_SOCKET_WQ
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_create: "
		    "sock->wq->fasync_list=0p%p sk_sleep(sk)=0p%p.\n",
		    sock->wq->fasync_list,
		    sk_sleep(sk));
#else
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_create: "
		    "sock->fasync_list=0p%p sk->sleep=0p%p.\n",
		    sock->fasync_list,
		    sk->sk_sleep);
#endif

	pfkey_insert_socket(sk);
	pfkey_list_insert_socket(sock, &pfkey_open_sockets);

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_create: "
		    "Socket sock=0p%p sk=0p%p initialised.\n", sock, sk);
	return 0;
}

DEBUG_NO_STATIC int pfkey_release(struct socket *sock)
{
	struct sock *sk;
	int i;

	if (sock == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_release: "
			    "No socket attached.\n");
		return 0; /* -EINVAL; */
	}

	sk = sock->sk;

	/* May not have data attached */
	if (sk == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_release: "
			    "No sk attached to sock=0p%p.\n", sock);
		return 0; /* -EINVAL; */
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_release: "
		    "sock=0p%p sk=0p%p\n", sock, sk);

	if (sock_flag(sk, SOCK_DEAD)) {
		if (sk->sk_state_change)
			sk->sk_state_change(sk);
	}

	sock->sk = NULL;

	/* Try to flush out this socket. Throw out buffers at least */
	pfkey_destroy_socket(sk);
	pfkey_list_remove_socket(sock, &pfkey_open_sockets);
	for (i = K_SADB_SATYPE_UNSPEC; i <= K_SADB_SATYPE_MAX; i++)
		pfkey_list_remove_socket(sock, &(pfkey_registered_sockets[i]));


	KLIPS_DEC_USE;
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_release: "
		    "succeeded.\n");

	return 0;
}

DEBUG_NO_STATIC int pfkey_shutdown(struct socket *sock, int mode)
{
	struct sock *sk;

	if (sock == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_shutdown: "
			    "NULL socket passed in.\n");
		return -EINVAL;
	}

	sk = sock->sk;

	if (sk == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_shutdown: "
			    "No sock attached to socket.\n");
		return -EINVAL;
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_shutdown: "
		    "mode=%x.\n", mode);
	mode++;

	if (mode & SEND_SHUTDOWN) {
		sk->sk_shutdown |= SEND_SHUTDOWN;
		sk->sk_state_change(sk);
	}

	if (mode & RCV_SHUTDOWN) {
		sk->sk_shutdown |= RCV_SHUTDOWN;
		sk->sk_state_change(sk);
	}
	return 0;
}

/*
 *	Send PF_KEY data down.
 */

DEBUG_NO_STATIC int
#ifdef NET_26
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
pfkey_sendmsg(struct socket *sock, struct msghdr *msg,
	      size_t len)
#else
pfkey_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
	      size_t len)
#endif
#else
pfkey_sendmsg(struct socket *sock, struct msghdr *msg, int len,
	      struct scm_cookie *scm)
#endif
{
	struct sock *sk;
	int error = 0;
	struct sadb_msg *pfkey_msg = NULL, *pfkey_reply = NULL;

	if (sock == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_sendmsg: "
			    "Null socket passed in.\n");
		SENDERR(EINVAL);
	}

	sk = sock->sk;

	if (sk == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_sendmsg: "
			    "Null sock passed in.\n");
		SENDERR(EINVAL);
	}

	if (msg == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_sendmsg: "
			    "Null msghdr passed in.\n");
		SENDERR(EINVAL);
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_sendmsg: .\n");
	if (sk->sk_err) {
		error = sock_error(sk);
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_sendmsg: "
			    "sk->err is non-zero, returns %d.\n",
			    error);
		SENDERR(-error);
	}

	if (!capable(CAP_NET_ADMIN)) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_sendmsg: "
			    "must be root (or have net_admin capability) to send messages to pfkey sockets.\n");
		SENDERR(EACCES);
	}

	if (msg->msg_control) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_sendmsg: "
			    "can't set flags or set msg_control.\n");
		SENDERR(EINVAL);
	}

	if (sk->sk_shutdown & SEND_SHUTDOWN) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_sendmsg: "
			    "shutdown.\n");
		send_sig(SIGPIPE, current, 0);
		SENDERR(EPIPE);
	}

	if (len < sizeof(struct sadb_msg)) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_sendmsg: "
			    "bogus msg len of %d, too small.\n", (int)len);
		SENDERR(EMSGSIZE);
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_sendmsg: "
		    "allocating %d bytes for downward message.\n",
		    (int)len);
	if ((pfkey_msg = (struct sadb_msg*)kmalloc(len, GFP_KERNEL)) == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_sendmsg: "
			    "memory allocation error.\n");
		SENDERR(ENOBUFS);
	}

	memcpy_from_msg((void *)pfkey_msg, msg, len);

	if (pfkey_msg->sadb_msg_version != PF_KEY_V2) {
		KLIPS_PRINT(1 || debug_pfkey,
			    "klips_debug:pfkey_sendmsg: "
			    "not PF_KEY_V2 msg, found %d, should be %d.\n",
			    pfkey_msg->sadb_msg_version,
			    PF_KEY_V2);
		kfree((void*)pfkey_msg);
		return -EINVAL;
	}

	if (len != pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_sendmsg: "
			    "bogus msg len of %d, not %d byte aligned.\n",
			    (int)len, (int)IPSEC_PFKEYv2_ALIGN);
		SENDERR(EMSGSIZE);
	}

	if (pfkey_msg->sadb_msg_reserved) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_sendmsg: "
			    "reserved field must be zero, set to %d.\n",
			    pfkey_msg->sadb_msg_reserved);
		SENDERR(EINVAL);
	}

	if ((pfkey_msg->sadb_msg_type > K_SADB_MAX) ||
	    (!pfkey_msg->sadb_msg_type)) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_sendmsg: "
			    "msg type too large or small:%d.\n",
			    pfkey_msg->sadb_msg_type);
		SENDERR(EINVAL);
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_sendmsg: "
		    "msg sent for parsing.\n");

	if ((error = pfkey_msg_interp(sk, pfkey_msg))) {
		struct socket_list *pfkey_socketsp;

		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_sendmsg: "
			    "pfkey_msg_parse returns %d.\n",
			    error);

		if ((pfkey_reply = (struct sadb_msg*)
		     kmalloc(sizeof(struct sadb_msg), GFP_KERNEL)) == NULL) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_sendmsg: "
				    "memory allocation error.\n");
			SENDERR(ENOBUFS);
		}
		memcpy((void*)pfkey_reply, (void*)pfkey_msg,
		       sizeof(struct sadb_msg));
		pfkey_reply->sadb_msg_errno = -error;
		pfkey_reply->sadb_msg_len = sizeof(struct sadb_msg) /
					    IPSEC_PFKEYv2_ALIGN;

		for (pfkey_socketsp = pfkey_open_sockets;
		     pfkey_socketsp;
		     pfkey_socketsp = pfkey_socketsp->next) {
			int error_upmsg = 0;
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_sendmsg: "
				    "sending up error=%d message=0p%p to socket=0p%p.\n",
				    error,
				    pfkey_reply,
				    pfkey_socketsp->socketp);
			if ((error_upmsg =
				     pfkey_upmsg(pfkey_socketsp->socketp,
						 pfkey_reply))) {
				KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_sendmsg: "
					    "sending up error message to socket=0p%p failed with error=%d.\n",
					    pfkey_socketsp->socketp,
					    error_upmsg);
				/* pfkey_msg_free(&pfkey_reply); */
				/* SENDERR(-error); */
			}
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_sendmsg: "
				    "sending up error message to socket=0p%p succeeded.\n",
				    pfkey_socketsp->socketp);
		}

		pfkey_msg_free(&pfkey_reply);

		SENDERR(-error);
	}

errlab:
	if (pfkey_msg)
		kfree((void*)pfkey_msg);

	if (error)
		return error;
	else
		return len;
}

/*
 *	Receive PF_KEY data up.
 */

DEBUG_NO_STATIC int
#ifdef NET_26
# if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
pfkey_recvmsg(struct socket *sock,
	      struct msghdr *msg,
	      size_t size,
	      int flags)
# else
pfkey_recvmsg(struct kiocb *kiocb,
	      struct socket *sock,
	      struct msghdr *msg,
	      size_t size,
	      int flags)
# endif
#else
pfkey_recvmsg(struct socket *sock,
	      struct msghdr *msg,
	      int size, int flags,
	      struct scm_cookie *scm)
#endif
{
	struct sock *sk;
	int noblock = flags & MSG_DONTWAIT;
	struct sk_buff *skb;
	int error;

	if (sock == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_recvmsg: "
			    "Null socket passed in.\n");
		return -EINVAL;
	}

	sk = sock->sk;

	if (sk == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_recvmsg: "
			    "Null sock passed in for sock=0p%p.\n", sock);
		return -EINVAL;
	}

	if (msg == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_recvmsg: "
			    "Null msghdr passed in for sock=0p%p, sk=0p%p.\n",
			    sock, sk);
		return -EINVAL;
	}

	KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
		    "klips_debug:pfkey_recvmsg: sock=0p%p sk=0p%p msg=0p%p size=%d.\n",
		    sock, sk, msg, (int)size);
	if (flags & ~MSG_PEEK) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_sendmsg: "
			    "flags (%d) other than MSG_PEEK not supported.\n",
			    flags);
		return -EOPNOTSUPP;
	}

	msg->msg_namelen = 0; /* sizeof(*ska); */

	if (sk->sk_err) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_sendmsg: "
			    "sk->sk_err=%d.\n", sk->sk_err);
		return sock_error(sk);
	}

	if ((skb = skb_recv_datagram(sk, flags, noblock, &error) ) == NULL)
		return error;

	if (size > skb->len)
		size = skb->len;
	else if (size < skb->len)
		msg->msg_flags |= MSG_TRUNC;

	skb_copy_datagram_msg(skb, 0, msg, size);
#ifdef HAVE_KERNEL_TSTAMP
	sk->sk_stamp = skb->tstamp;
#elif defined(HAVE_TSTAMP)
	sk->sk_stamp.tv_sec  = skb->tstamp.off_sec;
	sk->sk_stamp.tv_usec = skb->tstamp.off_usec;
#else
	sk->sk_stamp = skb->stamp;
#endif

	skb_free_datagram(sk, skb);
	return size;
}

#ifdef CONFIG_PROC_FS

int pfkey_show(struct seq_file *seq, void *offset)
{
	struct sock *sk;
#ifdef SK_FOR_EACH_NEED_NODE
	struct hlist_node *node;
#endif

	if (!sysctl_ipsec_debug_verbose) {
		seq_printf(seq, "    sock   pid   socket     next     prev e n p sndbf    Flags     Type St\n");
	} else {
		seq_printf(seq, "    sock   pid d    sleep   socket     next     prev e r z n p sndbf    stamp    Flags     Type St\n");
	}

	SK_FOR_EACH(sk, &pfkey_sock_list) {
		if (!sysctl_ipsec_debug_verbose) {
			seq_printf(seq,
					"%8p %5d %8p %d %d %5d %08lX %8X %2X\n",
					sk,
					key_pid(sk),
					sk->sk_socket,
					sk->sk_err,
					sk->sk_protocol,
					sk->sk_sndbuf,
					sk->sk_socket->flags,
					sk->sk_socket->type,
					sk->sk_socket->state);
		} else {
			struct timeval t;
			grab_socket_timeval(t, *sk);
			seq_printf(seq,
					"%8p %5d %d %8p %8p %d %d %d %d %5d %d.%06d %08lX %8X %2X\n",
					sk,
					key_pid(sk),
					sock_flag(sk, SOCK_DEAD),
#ifdef HAVE_SOCKET_WQ
					sk->sk_wq,
#else
					sk->sk_sleep,
#endif
					sk->sk_socket,
					sk->sk_err,
					sk->sk_reuse,
#ifdef HAVE_SOCK_ZAPPED
					sock_flag(sk, SOCK_ZAPPED),
#else
					sk->sk_zapped,
#endif
					sk->sk_protocol,
					sk->sk_sndbuf,
					(unsigned int)t.tv_sec,
					(unsigned int)t.tv_usec,
					sk->sk_socket->flags,
					sk->sk_socket->type,
					sk->sk_socket->state);
		}
	}

	return 0;
}

int pfkey_supported_show(struct seq_file *seq, void *offset)
{
	int satype;
	struct supported_list *ps;

	seq_printf(seq, "satype exttype alg_id ivlen minbits maxbits name\n");

	for (satype = K_SADB_SATYPE_UNSPEC; satype <= K_SADB_SATYPE_MAX; satype++) {
		ps = pfkey_supported_list[satype];
		while (ps != NULL) {
			struct ipsec_alg_supported *alg = ps->supportedp;
			const char *n = alg->ias_name;
			if (n == NULL) n = "unknown";

			seq_printf(seq,
					      "    %2d      %2d     %2d   %3d     %3d     %3d %20s\n",
					      satype,
					      alg->ias_exttype,
					      alg->ias_id,
					      alg->ias_ivlen,
					      alg->ias_keyminbits,
					      alg->ias_keymaxbits,
					      n);

			ps = ps->next;
		}
	}
	return 0;
}

int pfkey_registered_show(struct seq_file *seq, void *offset)
{
	int satype;
	struct socket_list *pfkey_sockets;

	seq_printf(seq, "satype   socket   pid       sk\n");

	for (satype = K_SADB_SATYPE_UNSPEC; satype <= K_SADB_SATYPE_MAX; satype++) {
		pfkey_sockets = pfkey_registered_sockets[satype];
		while (pfkey_sockets != NULL) {
			seq_printf(seq,
				     "    %2d %8p %5d %8p\n",
				     satype,
				     pfkey_sockets->socketp,
				     key_pid(pfkey_sockets->socketp->sk),
				     pfkey_sockets->socketp->sk);
			pfkey_sockets = pfkey_sockets->next;
		}
	}
	return 0;
}

#endif /* CONFIG_PROC_FS */

DEBUG_NO_STATIC int supported_add_all(int satype,
				      struct ipsec_alg_supported supported[],
				      int size)
{
	int i;
	int error = 0;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:init_pfkey: "
		    "sizeof(supported_init_<satype=%d>)[%d]/sizeof(struct ipsec_alg_supported)[%d]=%d.\n",
		    satype,
		    size,
		    (int)sizeof(struct ipsec_alg_supported),
		    (int)(size / sizeof(struct ipsec_alg_supported)));

	for (i = 0; i < size / sizeof(struct ipsec_alg_supported); i++) {

		const char *n = supported[i].ias_name;
		if (n == NULL)
			n = "unknown";

		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:init_pfkey: "
			    "i=%d inserting satype=%d exttype=%d id=%d ivlen=%d minbits=%d maxbits=%d name=%s.\n",
			    i,
			    satype,
			    supported[i].ias_exttype,
			    supported[i].ias_id,
			    supported[i].ias_ivlen,
			    supported[i].ias_keyminbits,
			    supported[i].ias_keymaxbits,
			    n);

		error |= pfkey_list_insert_supported(&(supported[i]),
						     &(pfkey_supported_list[
							       satype]));
	}
	return error;
}

DEBUG_NO_STATIC int supported_remove_all(int satype)
{
	int error = 0;
	struct ipsec_alg_supported *supportedp;

	while (pfkey_supported_list[satype]) {
		const char *n;
		supportedp = pfkey_supported_list[satype]->supportedp;

		n = supportedp->ias_name;
		if (n == NULL)
			n = "unknown";

		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:init_pfkey: "
			    "removing satype=%d exttype=%d id=%d ivlen=%d minbits=%d maxbits=%d name=%s.\n",
			    satype,
			    supportedp->ias_exttype,
			    supportedp->ias_id,
			    supportedp->ias_ivlen,
			    supportedp->ias_keyminbits,
			    supportedp->ias_keymaxbits, n);

		error |= pfkey_list_remove_supported(supportedp,
						     &(pfkey_supported_list[
							       satype]));
	}
	return error;
}

int pfkey_init(void)
{
	int error = 0;
	int i;

	static struct ipsec_alg_supported supported_init_ah[] = {
#ifdef CONFIG_KLIPS_AUTH_HMAC_MD5
		{ K_SADB_EXT_SUPPORTED_AUTH, K_SADB_AALG_MD5HMAC, 0, 128,
		  128 },
#endif          /* CONFIG_KLIPS_AUTH_HMAC_MD5 */
#ifdef CONFIG_KLIPS_AUTH_HMAC_SHA1
		{ K_SADB_EXT_SUPPORTED_AUTH, K_SADB_AALG_SHA1HMAC, 0, 160,
		  160 }
#endif          /* CONFIG_KLIPS_AUTH_HMAC_SHA1 */
	};
	static struct ipsec_alg_supported supported_init_esp[] = {
#ifdef CONFIG_KLIPS_AUTH_HMAC_MD5
		{ K_SADB_EXT_SUPPORTED_AUTH, K_SADB_AALG_MD5HMAC, 0, 128,
		  128 },
#endif          /* CONFIG_KLIPS_AUTH_HMAC_MD5 */
#ifdef CONFIG_KLIPS_AUTH_HMAC_SHA1
		{ K_SADB_EXT_SUPPORTED_AUTH, K_SADB_AALG_SHA1HMAC, 0, 160,
		  160 },
#endif          /* CONFIG_KLIPS_AUTH_HMAC_SHA1 */
#ifdef CONFIG_KLIPS_ENC_3DES
		{ K_SADB_EXT_SUPPORTED_ENCRYPT, K_SADB_EALG_3DESCBC, 64, 168,
		  168 },
#endif          /* CONFIG_KLIPS_ENC_3DES */
	};
	static struct ipsec_alg_supported supported_init_ipip[] = {
		{ K_SADB_EXT_SUPPORTED_ENCRYPT, K_SADB_X_TALG_IPv4_in_IPv4, 0,
		  32, 32 }
#if defined(CONFIG_KLIPS_IPV6)
		, { K_SADB_EXT_SUPPORTED_ENCRYPT, K_SADB_X_TALG_IPv6_in_IPv4,
		    0, 128, 32 },
		{ K_SADB_EXT_SUPPORTED_ENCRYPT, K_SADB_X_TALG_IPv4_in_IPv6, 0,
		  32, 128 },
		{ K_SADB_EXT_SUPPORTED_ENCRYPT, K_SADB_X_TALG_IPv6_in_IPv6, 0,
		  128, 128 }
#endif          /* defined(CONFIG_KLIPS_IPV6) */
	};
#ifdef CONFIG_KLIPS_IPCOMP
	static struct ipsec_alg_supported supported_init_ipcomp[] = {
		{ K_SADB_EXT_SUPPORTED_ENCRYPT, SADB_X_CALG_DEFLATE, 0, 1, 1 }
	};
#endif  /* CONFIG_KLIPS_IPCOMP */

#if 0
	printk(KERN_INFO
	       "klips_info:pfkey_init: "
	       "libreswan: initialising PF_KEYv2 domain sockets.\n");
#endif

	for (i = K_SADB_SATYPE_UNSPEC; i <= K_SADB_SATYPE_MAX; i++) {
		pfkey_registered_sockets[i] = NULL;
		pfkey_supported_list[i] = NULL;
	}

	error |= supported_add_all(K_SADB_SATYPE_AH, supported_init_ah,
				  sizeof(supported_init_ah));
	error |= supported_add_all(K_SADB_SATYPE_ESP, supported_init_esp,
				   sizeof(supported_init_esp));
#ifdef CONFIG_KLIPS_IPCOMP
	error |= supported_add_all(K_SADB_X_SATYPE_COMP, supported_init_ipcomp,
				   sizeof(supported_init_ipcomp));
#endif  /* CONFIG_KLIPS_IPCOMP */
	error |= supported_add_all(K_SADB_X_SATYPE_IPIP, supported_init_ipip,
				   sizeof(supported_init_ipip));

	error |= sock_register(&pfkey_family_ops);

	return error;
}

int pfkey_cleanup(void)
{
	int error = 0;

	printk(KERN_INFO "klips_info:pfkey_cleanup: "
	       "shutting down PF_KEY domain sockets.\n");
#ifdef VOID_SOCK_UNREGISTER
	sock_unregister(PF_KEY);
#else
	error |= sock_unregister(PF_KEY);
#endif

	error |= supported_remove_all(K_SADB_SATYPE_AH);
	error |= supported_remove_all(K_SADB_SATYPE_ESP);
#ifdef CONFIG_KLIPS_IPCOMP
	error |= supported_remove_all(K_SADB_X_SATYPE_COMP);
#endif  /* CONFIG_KLIPS_IPCOMP */
	error |= supported_remove_all(K_SADB_X_SATYPE_IPIP);

	/* other module unloading cleanup happens here */
	return error;
}

#ifdef MODULE
#if 0
int init_module(void)
{
	pfkey_init();
	return 0;
}

void cleanup_module(void)
{
	pfkey_cleanup();
}
#endif /* 0 */
#else /* MODULE */
struct net_protocol;
void pfkey_proto_init(struct net_protocol *pro)
{
	pfkey_init();
}
#endif /* MODULE */
