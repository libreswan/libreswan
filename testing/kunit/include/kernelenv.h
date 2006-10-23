/*
 * Copyright (c) 2003,2004 Jeremy Kerr & Rusty Russell
 This file is part of nfsim.

 It has been modified by Michael Richardson <mcr@xelerance.com>
 to be used by the Openswan KLIPS unit testing.
 Based upon SVN revision 3615 as released in 20050423 tarball.
 $Id: kernelenv.h,v 1.4 2005/04/28 21:18:36 mcr Exp $

 nfsim is free software; you can redistribute it and/or modify it
 under the terms of the GNU General Public License as published by the
 Free Software Foundation; either version 2 of the License, or (at
 your option) any later version.

 nfsim is distributed in the hope that it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 for more details.

 You should have received a copy of the GNU General Public License
 along with nfsim; if not, write to the Free Software Foundation,
 Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*/

/**
 * Functions to provide a simlulated kernel environment.
 */

#ifndef __HAVE_SIMULATOR_H
#define __HAVE_SIMULATOR_H 1

#define __KERNEL__ 1

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/version.h>

#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <list.h>

/* Types */
typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint64_t u64;
typedef int64_t s64;
#define __u8 u8
#define __s8 s8
#define __u16 u16
#define __s16 s16
#define __u32 u32
#define __s32 s32
#define __u64 u64
#define __s64 u64

/* avoid inclusion of asm/types.h */
#define _I386_TYPES_H


/* Hacky, but works for now */
#define BITS_PER_LONG (ULONG_MAX == 0xFFFFFFFFUL ? 32 : 64)

/* casts are necessary for constants, because we never know how for sure
 * how U/UL/ULL map to u16, u32, u64. At least not in a portable way.
 */
#define swab16(x) \
	((u16)( \
		(((u16)(x) & (u16)0x00ffU) << 8) | \
		(((u16)(x) & (u16)0xff00U) >> 8) ))
#define swab32(x) \
	((u32)( \
		(((u32)(x) & (u32)0x000000ffUL) << 24) | \
		(((u32)(x) & (u32)0x0000ff00UL) <<  8) | \
		(((u32)(x) & (u32)0x00ff0000UL) >>  8) | \
		(((u32)(x) & (u32)0xff000000UL) >> 24) ))
#define swab64(x) \
	((u64)( \
		(u64)(((u64)(x) & (u64)0x00000000000000ffULL) << 56) | \
		(u64)(((u64)(x) & (u64)0x000000000000ff00ULL) << 40) | \
		(u64)(((u64)(x) & (u64)0x0000000000ff0000ULL) << 24) | \
		(u64)(((u64)(x) & (u64)0x00000000ff000000ULL) <<  8) | \
	        (u64)(((u64)(x) & (u64)0x000000ff00000000ULL) >>  8) | \
		(u64)(((u64)(x) & (u64)0x0000ff0000000000ULL) >> 24) | \
		(u64)(((u64)(x) & (u64)0x00ff000000000000ULL) >> 40) | \
		(u64)(((u64)(x) & (u64)0xff00000000000000ULL) >> 56) ))

#define swab16p(p) (swab16(*(p)))
#define swab32p(p) (swab32(*(p)))
#define swab64p(p) (swab64(*(p)))

#include "kernelenv_endian.h"

u32 htonl(u32 hostlong);
u16 htons(u16 hostshort);
u32 ntohl(u32 netlong);
u16 ntohs(u16 netshort);

#define smp_wmb()
#define wmb()
#define barrier()
#define mb()

/* Put v in *ptr atomically and return old *ptr value. */
#define xchg(ptr,v) ({ __typeof__(*ptr) __a, *__p = (ptr); __a = *__p; *__p = (v); __a; })

#define __user

#define unlikely(x) (x)
#define likely(x) (x)

#define __stringify_1(x)	#x
#define __stringify(x)		__stringify_1(x)

/*
 * min()/max() macros that also do
 * strict type-checking.. See the
 * "unnecessary" pointer comparison.
 */
#define min(x,y) ({ \
	const typeof(x) _x = (x);	\
	const typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x < _y ? _x : _y; })

#define max(x,y) ({ \
	const typeof(x) _x = (x);	\
	const typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x > _y ? _x : _y; })

/*
 * ..and if you can't take the strict
 * types, you can specify one yourself.
 *
 * Or not use min/max at all, of course.
 */
#define min_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#define max_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })

/* logging */
#include <log.h>

#define u_int8_t	uint8_t
#define u_int16_t	uint16_t
#define u_int32_t	uint32_t
#define u_int64_t	uint64_t

#define __init
#define __inline
#define ____cacheline_aligned __attribute__((aligned(8)))

#include <talloc.h>
extern void *__vmalloc_ctx;
extern void *__kmalloc_atomic_ctx;
extern void *__kmalloc_ctx;
void *__malloc(unsigned int, void *ctx, const char *location);

#define vmalloc(s) __malloc((s), __vmalloc_ctx, __location__)
#define kmalloc(s,f) __malloc((s), (f) & GFP_ATOMIC ? __kmalloc_atomic_ctx : __kmalloc_ctx, __location__)

#define vfree(p)   talloc_unlink(__vmalloc_ctx, (p))
#define kfree(p)   talloc_free(p)

#define synchronize_net() 

#define dump_stack()

void schedule(void);

#define BUG_ON(x) do { if (x) barf("%s:%u", __FILE__, __LINE__); } while(0)
#define BUG() BUG_ON(1)

#define cli()
#define sti()


#define NR_CPUS 1
#define  SMP_CACHE_BYTES (1<<7)
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0)
#define cpu_possible(cpu)	((cpu) == 0)
#endif
#define smp_processor_id()	0
#define PAGE_SHIFT      12
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE-1))

#define	SLAB_HWCACHE_ALIGN	0x00002000UL

#define local_bh_disable()
#define local_bh_enable()

#define stricmp strcasecmp
#define strnicmp strncasecmp

extern unsigned long num_physpages;

extern void barf(const char *fmt, ...);
#define panic barf

/* kernel.h */
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#if defined(__LITTLE_ENDIAN)
#define HIPQUAD(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]
#elif defined(__BIG_ENDIAN)
#define HIPQUAD	NIPQUAD
#else
#error "Please fix asm/byteorder.h"
#endif /* __LITTLE_ENDIAN */

#define HZ 100

#define	KERN_EMERG	"EMERG:"/* system is unusable			*/
#define	KERN_ALERT	"ALERT:"/* action must be taken immediately	*/
#define	KERN_CRIT	"CRIT:"	/* critical conditions			*/
#define	KERN_ERR	"ERR;"	/* error conditions			*/
#define	KERN_WARNING	"WARN:"	/* warning conditions			*/
#define	KERN_NOTICE	"NOTICE:"/* normal but significant condition	*/
#define	KERN_INFO	"INFO:"	/* informational			*/
#define	KERN_DEBUG	"DEBUG:"/* debug-level messages			*/

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))

/* err.h */
#define ERR_PTR(x) ((void *)(x))
#define PTR_ERR(x) ((long)(x))
int IS_ERR(const void *ptr);

/* we start at time 0 */
#define INITIAL_JIFFIES 0


extern unsigned long jiffies;

#define typecheck(type,x) \
({	type __dummy; \
	typeof(x) __dummy2; \
	(void)(&__dummy == &__dummy2); \
	1; \
})


#define time_after(a,b)		\
	(typecheck(unsigned long, a) && \
	 typecheck(unsigned long, b) && \
	 ((long)(b) - (long)(a) < 0))
#define time_before(a,b)	time_after(b,a)

#define time_after_eq(a,b)	\
	(typecheck(unsigned long, a) && \
	 typecheck(unsigned long, b) && \
	 ((long)(a) - (long)(b) >= 0))
#define time_before_eq(a,b)	time_after_eq(b,a)




#define container_of(ptr, type, member) ({			\
        typeof( ((type *)0)->member ) *__mptr = (ptr);	\
        (type *)( (char *)__mptr - offsetof(type,member) );})

/* atomic.h */

#define __ARCH_I386_ATOMIC__ 1
typedef struct { volatile int counter; } atomic_t;

#define ATOMIC_INIT(i)	{ (i) }

#define atomic_read(v)		((v)->counter)
#define atomic_set(v,i)         (((v)->counter) = (i))
#define atomic_add(v,i)         (((v)->counter) += (i))

void atomic_inc(atomic_t *v);
void atomic_dec(atomic_t *v);
int atomic_dec_and_test(atomic_t *v);

/* rc_update.h  */
struct rcu_head {
	struct list_head list;
	void (*func)(void *obj);
	void *arg;
};

/* list.h's RCU stuff */
/**
 * list_for_each_rcu	-	iterate over an rcu-protected list
 * @pos:	the &struct list_head to use as a loop counter.
 * @head:	the head for your list.
 */
#define list_for_each_rcu(pos, head) \
	for (pos = (head)->next; pos != (head); \
        	pos = pos->next, ({ smp_read_barrier_depends(); 0;}), prefetch(pos->next))
        	
#define __list_for_each_rcu(pos, head) \
	for (pos = (head)->next; pos != (head); \
        	pos = pos->next, ({ smp_read_barrier_depends(); 0;}))
        	
/**
 * list_for_each_safe_rcu	-	iterate over an rcu-protected list safe
 *					against removal of list entry
 * @pos:	the &struct list_head to use as a loop counter.
 * @n:		another &struct list_head to use as temporary storage
 * @head:	the head for your list.
 */
#define list_for_each_safe_rcu(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, ({ smp_read_barrier_depends(); 0;}), n = pos->next)

/**
 * list_for_each_entry_rcu	-	iterate over rcu list of given type
 * @pos:	the type * to use as a loop counter.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry_rcu(pos, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
		     prefetch(pos->member.next);			\
	     &pos->member != (head); 					\
	     pos = list_entry(pos->member.next, typeof(*pos), member),	\
		     ({ smp_read_barrier_depends(); 0;}),		\
		     prefetch(pos->member.next))


/**
 * list_for_each_continue_rcu	-	iterate over an rcu-protected list 
 *			continuing after existing point.
 * @pos:	the &struct list_head to use as a loop counter.
 * @head:	the head for your list.
 */
#define list_for_each_continue_rcu(pos, head) \
	for ((pos) = (pos)->next, prefetch((pos)->next); (pos) != (head); \
        	(pos) = (pos)->next, ({ smp_read_barrier_depends(); 0;}), prefetch((pos)->next))


/* spinlock.h */

/* no difference between spin and rw locks at present */

typedef struct {
	volatile int lock;
	char *location;
} spinlock_t;

typedef spinlock_t rwlock_t;

#define RW_LOCK_UNLOCKED (rwlock_t) { 0, NULL }
#define SPIN_LOCK_UNLOCKED (spinlock_t) { 0, NULL }
#define DEFINE_SPINLOCK(x) spinlock_t x = SPIN_LOCK_UNLOCKED
#define DEFINE_RWLOCK(x) rwlock_t x = RW_LOCK_UNLOCKED

#define spin_lock_init(x) \
	do { \
		(x)->lock = 0; \
		(x)->location = NULL; \
	} while (0)

#define rwlock_init(x) spin_lock_init(x)


#define spin_lock(x) __generic_write_lock((x), __location__)
#define spin_unlock(x) __generic_write_unlock((x), __location__)

#define spin_lock_bh(x) __generic_write_lock((x), __location__)
#define spin_unlock_bh(x) __generic_write_unlock((x), __location__)

#define spin_lock_irq(x) __generic_write_lock((x), __location__)
#define spin_unlock_irq(x) __generic_write_unlock((x), __location__)

#define spin_lock_irqsave(x,f) __generic_write_lock((x), __location__); f++
#define spin_unlock_irqrestore(x,f) __generic_write_unlock((x), __location__); f--

#define read_lock_bh(x)  __generic_read_lock((x), __location__)
#define read_unlock_bh(x)  __generic_read_unlock((x), __location__)

#define read_lock(x)  __generic_read_lock((x), __location__)
#define read_unlock(x)  __generic_read_unlock((x), __location__)

#define write_lock_bh(x)  __generic_write_lock((x), __location__)
#define write_unlock_bh(x)  __generic_write_unlock((x), __location__)

#define rcu_read_lock()
#define rcu_read_unlock()

#define rcu_dereference(p) (p)
#define rcu_assign_pointer(p, v)	({ \
						smp_wmb(); \
						(p) = (v); \
					})

void __generic_read_lock(spinlock_t *lock, const char *location);
void __generic_read_unlock(spinlock_t *lock, const char *location);
	
void __generic_write_lock(spinlock_t *lock, const char *location);
void __generic_write_unlock(spinlock_t *lock, const char *location);
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
/* brlock.h */
#define br_write_lock_bh(lock)
#define br_write_unlock_bh(lock)
#define br_write_lock(lock)
#define br_write_unlock(lock)
#define br_read_lock_bh(lock)
#define br_read_unlock_bh(lock)
#endif

/* vsprintf.h */
unsigned long int strtoul(const char *nptr, char **endptr, int base);
#define simple_strtoul strtoul


/* socket.h */

#define AF_INET		2	/* Internet IP Protocol 	*/
#define PF_INET 	AF_INET

#define NPROTO 3


/* stat.h */
#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFLNK	 0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

#define S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)	(((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)	(((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m)	(((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m)	(((m) & S_IFMT) == S_IFSOCK)

#define S_IRWXU 00700
#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100

#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010

#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001

#define S_IRWXUGO	(S_IRWXU|S_IRWXG|S_IRWXO)
#define S_IALLUGO	(S_ISUID|S_ISGID|S_ISVTX|S_IRWXUGO)
#define S_IRUGO		(S_IRUSR|S_IRGRP|S_IROTH)
#define S_IWUGO		(S_IWUSR|S_IWGRP|S_IWOTH)
#define S_IXUGO		(S_IXUSR|S_IXGRP|S_IXOTH)

/* if.h */
#define IFNAMSIZ 16

#define PACKET_HOST		0		/* To us		*/
#define PACKET_BROADCAST	1		/* To all		*/
#define PACKET_MULTICAST	2		/* To group		*/
#define PACKET_OTHERHOST	3		/* To someone else 	*/
#define PACKET_OUTGOING		4		/* Outgoing of any type */
/* These ones are invisible by user level */
#define PACKET_LOOPBACK		5		/* MC/BRD frame looped back */
#define PACKET_FASTROUTE	6		

/* if_ether.h */

#define ETH_ALEN        6               /* Octets in one ethernet addr   */
#define ETH_HLEN        14              /* Total octets in header.       */
#define ETH_ZLEN        60              /* Min. octets in frame sans FCS */
#define ETH_DATA_LEN    1500            /* Max. octets in payload        */
#define ETH_FRAME_LEN   1514            /* Max. octets in frame sans FCS */

#define ETH_P_IP        0x0800          /* Internet Protocol packet     */

struct ethhdr 
{
        unsigned char   h_dest[ETH_ALEN];       /* destination eth addr */
        unsigned char   h_source[ETH_ALEN];     /* source ether addr    */
        unsigned short  h_proto;                /* packet type ID field */
};

/* netdevice.h */

struct net_device_stats {
	unsigned long rx_packets;
	unsigned long tx_packets;

	unsigned long rx_dropped;
	unsigned long tx_dropped;

	unsigned long rx_errors;
	unsigned long tx_errors;

	unsigned long rx_bytes;
	unsigned long tx_bytes;
};


struct net_device {
	struct list_head entry;

	char name[IFNAMSIZ];
	int ifindex;

	/* external protocol data for this interface */
	void 		*ip_ptr;

	/* private pointer for the device to play with */
	void            *priv;

	/* hardware header length (?) */
	unsigned short hard_header_len;	

	struct net_device_stats stats;
	unsigned int mtu;
};

#define dev_hold(x)
#define dev_put(x)

#define HH_DATA_MOD     16
#define LL_RESERVED_SPACE(dev) \
	(((dev)->hard_header_len&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)

extern struct net_device	*__dev_get_by_name(const char *name);

/* skbuff */

#define CHECKSUM_NONE 0
#define CHECKSUM_HW 1
#define CHECKSUM_UNNECESSARY 2

struct sk_buff {
	struct net_device	*dev;

	unsigned int		seq;

	struct sock		*sk;
	int			(*destructor)(struct sk_buff *);
	
	union {
	  	struct ethhdr	*ethernet;
	  	unsigned char 	*raw;
	} mac;

	union {
		struct iphdr	*iph;
		struct ipv6hdr	*ipv6h;
		struct arphdr	*arph;
		unsigned char	*raw;
	} nh;

	union {
		struct tcphdr	*th;
		struct udphdr	*uh;
		struct icmphdr	*icmph;
		struct igmphdr	*igmph;
		struct iphdr	*ipiph;
		unsigned char	*raw;
	} h;

	unsigned short		protocol;

	struct  dst_entry	*dst;

	unsigned char		local_df, pkt_type;

	__u32			priority;

	unsigned int		len,
				data_len,
				mac_len,
				csum;

	atomic_t		users;

	unsigned char		ip_summed,
				cloned;


	unsigned long		nfmark;
	__u32			nfcache;
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9)
	struct nf_ct_info	*nfct;
#else
	struct nf_conntrack	*nfct;
#endif
	__u32			nfctinfo;

        unsigned int		nf_debug;

	char			cb[40];

	unsigned char		*head,    /* beginning of buffer */
		                *data,    /* beginning of interesting data */
		                *tail,    /* end of interesting data */
 		                *end;     /* end of buffer */
};

struct sk_buff_head {
	/* These two members must be first. */
	struct sk_buff	*next;
	struct sk_buff	*prev;

	__u32		qlen;
	spinlock_t	lock;
};

struct skb_shared_info {
	unsigned int tso_size;
};

/* net/protocol.h */
struct net_protocol {
	int			(*handler)(struct sk_buff *skb);
	void			(*err_handler)(struct sk_buff *skb, u32 info);
	int			no_policy;
};
#define inet_protocol net_protocol


/* forward reference */
struct hh_cache;

int skb_cloned(const struct sk_buff *skb);
int skb_shared(const struct sk_buff *skb);

struct nf_conntrack {
	atomic_t use;
	void (*destroy)(struct nf_conntrack *);
};

struct nf_ct_info {
	struct nf_conntrack *master;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9)
void nf_conntrack_put(struct nf_ct_info *nfct);
void nf_conntrack_get(struct nf_ct_info *nfct);
extern void (*ip_ct_attach)(struct sk_buff *, struct nf_ct_info *);
#else
void nf_conntrack_put(struct nf_conntrack *nfct);
void nf_conntrack_get(struct nf_conntrack *nfct);
extern void (*ip_ct_attach)(struct sk_buff *, struct sk_buff *);
#endif /* 2.6.9 */

void nf_reset(struct sk_buff *skb);
void nf_reset_debug(struct sk_buff *skb);

extern void nf_ct_attach(struct sk_buff *, struct sk_buff *);

struct sk_buff *alloc_skb(unsigned int size, int priority);
void kfree_skb(struct sk_buff *skb);

unsigned int skb_headroom(const struct sk_buff *skb);
unsigned int skb_tailroom(const struct sk_buff *skb);

unsigned char *skb_put(struct sk_buff *skb, unsigned int len);
unsigned char *skb_push(struct sk_buff *skb, unsigned int len);
unsigned char *skb_pull(struct sk_buff *skb, unsigned int len);

extern unsigned int skb_cow(struct sk_buff *skb, unsigned int headroom);
int pskb_may_pull(struct sk_buff *skb, unsigned int len);

#define __skb_put  skb_put
#define __skb_push skb_push

void __skb_trim(struct sk_buff *skb, unsigned int len);
void skb_trim(struct sk_buff *skb, unsigned int len);

#define SKB_LINEAR_ASSERT(x)

void skb_reserve(struct sk_buff *skb, unsigned int len);

void copy_skb_header(struct sk_buff *new, const struct sk_buff *old);
int skb_copy_bits(const struct sk_buff *skb, int offset,
				     void *to, int len);
struct sk_buff *skb_copy_expand(const struct sk_buff *skb,
				int newheadroom, int newtailroom,
				int gfp_mask);

void skb_orphan(struct sk_buff *skb);

int skb_is_nonlinear(const struct sk_buff *skb);

extern int skb_linearize(struct sk_buff *skb, int gfp);
#define skb_copy(skb, gfp) \
	skb_copy_expand(skb, skb_headroom(skb), skb_tailroom(skb), gfp)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)
extern int skb_checksum_help(struct sk_buff *skb);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
extern int skb_checksum_help(struct sk_buff **pskb, int inward);
#else
extern int skb_checksum_help(struct sk_buff *skb, int inward);
#endif

extern struct skb_shared_info *skb_shinfo(struct sk_buff *skb);

void *skb_header_pointer(const struct sk_buff *skb, int offset,
			 int len, void *buffer);

/* net/sock.h */
#define sk_for_each(__sk, node, list) \
	hlist_for_each_entry(__sk, node, list, sk_node)

struct proto {
	char name[32];
};

struct sock_common {
	unsigned short		skc_family;
	volatile unsigned char	skc_state;
	unsigned char		skc_reuse;
	int			skc_bound_dev_if;
	struct hlist_node	skc_node;
	struct hlist_node	skc_bind_node;
	atomic_t		skc_refcnt;
};

/* LOG wants to log UID... sk_socket pointer is NULL, but needs to compile */
struct socket_file_dummy
{
	unsigned int f_uid;
};

struct socket
{
	struct socket_file_dummy *file;
};

struct sock {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
	atomic_t		sk_refcnt;
	__u32			rcv_saddr;
	__u32			daddr;
	__u16			sport, dport;
	struct			proto *prot;
	int			bound_dev_if;	
#else
	struct sock_common	__sk_common;
#define sk_family		__sk_common.skc_family
#define sk_state		__sk_common.skc_state
#define sk_reuse		__sk_common.skc_reuse
#define sk_bound_dev_if		__sk_common.skc_bound_dev_if
#define sk_node			__sk_common.skc_node
#define sk_bind_node		__sk_common.skc_bind_node
#define sk_refcnt		__sk_common.skc_refcnt

	rwlock_t		sk_callback_lock;
	struct socket		*sk_socket;
	struct proto *sk_prot;
#endif

	unsigned short		sk_type;
	void			(*sk_data_ready)(struct sock *sk, int bytes);
};

void sock_hold(struct sock *sk);
void sock_put(struct sock *sk);
void skb_set_owner_w(struct sk_buff *skb, struct sock *sk);

struct sk_buff *skb_realloc_headroom(struct sk_buff *skb, unsigned int headroom);

int skb_ip_make_writable(struct sk_buff **pskb, unsigned int writable_len);

/* netfilter.c's version: unused. */
int __unused_skb_ip_make_writable(struct sk_buff **, unsigned int);

/* net.h */
#define net_ratelimit() 1

/* in.h */
struct in_addr {
	__u32	s_addr;
};


typedef unsigned short	sa_family_t;

#define __SOCK_SIZE__	16	

struct sockaddr_in {
  sa_family_t		sin_family;	/* Address family		*/
  unsigned short int	sin_port;	/* Port number			*/
  struct in_addr	sin_addr;	/* Internet address		*/

  /* Pad to size of `struct sockaddr'. */
  unsigned char		__pad[__SOCK_SIZE__ - sizeof(short int) -
			sizeof(unsigned short int) - sizeof(struct in_addr)];
};

#define INADDR_ANY 0
#define INADDR_BROADCAST 0xffffffff

/* route.h */
#define RTO_CONN	0

#define ip_rt_put(rt)

/* notifier.h */
struct notifier_block
{
	int (*notifier_call)(struct notifier_block *self, unsigned long, void *);
	struct notifier_block *next;
	int priority;
};

int notifier_chain_register(struct notifier_block **list, struct notifier_block *n);
int notifier_chain_unregister(struct notifier_block **nl, struct notifier_block *n);
int notifier_call_chain(struct notifier_block **n, unsigned long val, void *v);


#define NOTIFY_DONE		0x0000		/* Don't care */
#define NOTIFY_OK		0x0001		/* Suits me */
#define NOTIFY_STOP_MASK	0x8000		/* Don't call further */
#define NOTIFY_BAD		(NOTIFY_STOP_MASK|0x0002)	/* Bad/Veto action	*/


#define NETDEV_UP	0x0001	/* For now you can't veto a device up/down */
#define NETDEV_DOWN	0x0002
#define NETDEV_REBOOT	0x0003	/* Tell a protocol stack a network interface
				   detected a hardware crash and restarted
				   - we can use this eg to kick tcp sessions
				   once done */
#define NETDEV_CHANGE	0x0004	/* Notify device state change */
#define NETDEV_REGISTER 0x0005
#define NETDEV_UNREGISTER	0x0006
#define NETDEV_CHANGEMTU	0x0007
#define NETDEV_CHANGEADDR	0x0008
#define NETDEV_GOING_DOWN	0x0009
#define NETDEV_CHANGENAME	0x000A


/* ip.h */
struct ip_options {
  __u32		faddr;				/* Saved first hop address */
  unsigned char	optlen;
  unsigned char srr;
  unsigned char rr;
  unsigned char ts;
  unsigned char is_setbyuser:1,			/* Set by setsockopt?			*/
                is_data:1,			/* Options in __data, rather than skb	*/
                is_strictroute:1,		/* Strict source route			*/
                srr_is_hit:1,			/* Packet destination addr was our one	*/
                is_changed:1,			/* IP checksum more not valid		*/	
                rr_needaddr:1,			/* Need to record addr of outgoing dev	*/
                ts_needtime:1,			/* Need to record timestamp		*/
                ts_needaddr:1;			/* Need to record addr of outgoing dev  */
  unsigned char router_alert;
  unsigned char __pad1;
  unsigned char __pad2;
  unsigned char __data[0];
};

struct inet_skb_parm
{
	struct ip_options	opt;		/* Compiled IP options		*/
	unsigned char		flags;

#define IPSKB_MASQUERADED	1
#define IPSKB_TRANSLATED	2
#define IPSKB_FORWARDED		4
#define IPSKB_XFRM_TUNNEL_SIZE	8
};

struct ipcm_cookie
{
	u32			addr;
	int			oif;
	struct ip_options	*opt;
};

#define IPCB(skb) ((struct inet_skb_parm*)((skb)->cb))

struct inet_sock {
	/* sk has to be the first two members of inet_sock */
	struct sock		sk;
	/* Socket demultiplex comparisons on incoming packets. */
	__u32			daddr;		/* Foreign IPv4 addr */
	__u32			rcv_saddr;	/* Bound local IPv4 addr */
	__u16			dport;		/* Destination port */
	__u16			num;		/* Local port */
	__u32			saddr;		/* Sending source */
	int			uc_ttl;		/* Unicast TTL */
	int			tos;		/* TOS */
	unsigned	   	cmsg_flags;
	struct ip_options	*opt;
	__u16			sport;		/* Source port */
	unsigned char		hdrincl;	/* Include headers ? */
	__u8			mc_ttl;		/* Multicasting TTL */
	__u8			mc_loop;	/* Loopback */
	__u8			pmtudisc;
	__u16			id;		/* ID counter for DF pkts */
	unsigned		recverr : 1,
				freebind : 1;
	int			mc_index;	/* Multicast device index */
	__u32			mc_addr;
};

#define inet_opt inet_sock

#define inet_sk(__sk) ((struct inet_sock *)__sk)

/* udp.h */
#define UDP_ENCAP	100	/* Set the socket to accept encapsulated packets */

/* UDP encapsulation types */
#define UDP_ENCAP_ESPINUDP_NON_IKE	1 /* draft-ietf-ipsec-nat-t-ike-00/01 */
#define UDP_ENCAP_ESPINUDP	2 /* draft-ietf-ipsec-udp-encaps-06 */



/* rtnetlink.h */
enum
{
	RTAX_UNSPEC,
#define RTAX_UNSPEC RTAX_UNSPEC
	RTAX_LOCK,
#define RTAX_LOCK RTAX_LOCK
	RTAX_MTU,
#define RTAX_MTU RTAX_MTU
	RTAX_WINDOW,
#define RTAX_WINDOW RTAX_WINDOW
	RTAX_RTT,
#define RTAX_RTT RTAX_RTT
	RTAX_RTTVAR,
#define RTAX_RTTVAR RTAX_RTTVAR
	RTAX_SSTHRESH,
#define RTAX_SSTHRESH RTAX_SSTHRESH
	RTAX_CWND,
#define RTAX_CWND RTAX_CWND
	RTAX_ADVMSS,
#define RTAX_ADVMSS RTAX_ADVMSS
	RTAX_REORDERING,
#define RTAX_REORDERING RTAX_REORDERING
	RTAX_HOPLIMIT,
#define RTAX_HOPLIMIT RTAX_HOPLIMIT
	RTAX_INITCWND,
#define RTAX_INITCWND RTAX_INITCWND
	RTAX_FEATURES,
#define RTAX_FEATURES RTAX_FEATURES
};

enum rt_scope_t
{
	RT_SCOPE_UNIVERSE=0,
};

#define RTAX_MAX RTAX_FEATURES

/* dst.h */
struct dst_entry
{
	struct dst_entry        *next;

	struct net_device       *dev;

	unsigned long		lastuse;
	unsigned long		expires;

	u32			metrics[RTAX_MAX];

	int			error;

	int			(*input)(struct sk_buff*);
	int			(*output)(struct sk_buff*);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
	int			pmtu;
#endif

#ifdef CONFIG_NET_CLS_ROUTE
	__u32			tclassid;
#endif

};

u32 dst_path_metric(struct dst_entry *dst, int metric);
u32 dst_pmtu(struct dst_entry *dst);

#define dst_release(x)
#define dst_hold(x)

int dst_output(struct sk_buff *skb);
int dst_input(struct sk_buff *skb);


/* semaphore.h */

/* We don't support generic semaphores: we use a simple talloc to track use */
struct semaphore {
	unsigned int count;
	unsigned int limit;
};
#define DECLARE_MUTEX(name) struct semaphore name = { 1, 1 }

#define down(x) __down((x),__location__)
#define down_interruptible(x) __down_interruptible((x),__location__)

#define up(x) __up((x),__location__)
#define down_trylock(x) __down_trylock((x),__location__)

void __down(struct semaphore *sem, const char *location);
int __down_interruptible(struct semaphore *sem, const char *location);

void __up(struct semaphore *sem, const char *location);

int __down_trylock(struct semaphore *sem, const char *location);

void sema_init(struct semaphore *sem, int val);

/* sched.h */

#define capable(x) 1

#define TASK_RUNNING		0
#define TASK_INTERRUPTIBLE	1
#define TASK_UNINTERRUPTIBLE	2
#define TASK_STOPPED		4
#define TASK_ZOMBIE		8
#define TASK_DEAD		16

#define set_current_state(x)

#define wake_up_process(x)

#define current 0

/* prefetch.h */

static inline void prefetch(const void *x) {;}

static inline void smp_read_barrier_depends(void) {;}

/* timer.h */

/* not used at the moment */
#define TIMER_MAGIC	0x4b87ad6e

struct timer_list {
	struct list_head entry;
	unsigned long expires;

	spinlock_t lock;
	unsigned long magic;

	void (*function)(unsigned long);
	unsigned long data;

	struct module *owner;
	const char *ownerfunction;

	char *use;
};

/* for internal timer management:
 * Increments the current system time, and calls any timers that
 * are have been scheduled within this period
 */
void increment_time(unsigned int inc);

#define init_timer(t) __init_timer(t,THIS_MODULE,__FUNCTION__)
void __init_timer(struct timer_list * timer, struct module *owner, const char *function);

int timer_pending(const struct timer_list * timer);
void check_timer(struct timer_list *timer);

#define del_timer(timer) __del_timer((timer), __location__)
int __del_timer(struct timer_list *timer, const char *location);
void check_timer_failed(struct timer_list *timer);

#define add_timer(timer) __add_timer((timer), __location__)
void __add_timer(struct timer_list *timer, const char *location);
int __mod_timer(struct timer_list *timer, unsigned long expires);


/* asm/bitops.h */
int test_bit(int nr, const long * addr);
int set_bit(int nr,long * addr);
#define __set_bit set_bit
int clear_bit(int nr, long * addr);

/* random */
void get_random_bytes(void *buf, int nbytes);


/* cache. simple. */
#define GFP_ATOMIC 0x01
#define GFP_KERNEL 0x02

typedef struct kmem_cache_s kmem_cache_t;

struct kmem_cache_obj {
	struct list_head entry;
	char *ptr;
};

struct kmem_cache_s {
	size_t objsize;
	const char *name;

	/* list of allocated objects */
	struct list_head objs;
	
	void (*ctor)(void *, kmem_cache_t *, unsigned long);
	void (*dtor)(void *, kmem_cache_t *, unsigned long);
};


kmem_cache_t *kmem_cache_create(const char *, size_t, size_t, unsigned long,
				       void (*)(void *, kmem_cache_t *, unsigned long),
				       void (*)(void *, kmem_cache_t *, unsigned long));

int kmem_cache_destroy(kmem_cache_t *);
void *kmem_cache_alloc(kmem_cache_t *, int);
void kmem_cache_free(kmem_cache_t *, void *);

unsigned long __get_free_pages(unsigned int gfp_mask, unsigned int order);
void free_pages(unsigned long addr, unsigned int order);
int get_order(unsigned long size);

/* wait.h */
struct __wait_queue_head {
	spinlock_t lock;
	struct list_head task_list;
};
typedef struct __wait_queue_head wait_queue_head_t;

/* netlink.h */

#define NLMSG_ALIGNTO	4
#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
#define NLMSG_LENGTH(len) ((len)+NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
#define NLMSG_DATA(nlh)  ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))
#define NLMSG_NEXT(nlh,len)	 ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
				  (struct nlmsghdr*)(((char*)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
#define NLMSG_OK(nlh,len) ((len) >= (int)sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len <= (len))
#define NLMSG_PAYLOAD(nlh,len) ((nlh)->nlmsg_len - NLMSG_SPACE((len)))

#define NLMSG_NOOP		0x1	/* Nothing.		*/
#define NLMSG_ERROR		0x2	/* Error		*/
#define NLMSG_DONE		0x3	/* End of a dump	*/
#define NLMSG_OVERRUN		0x4	/* Data lost		*/

struct nlmsghdr
{
	__u32		nlmsg_len;	/* Length of message including header */
	__u16		nlmsg_type;	/* Message content */
	__u16		nlmsg_flags;	/* Additional flags */
	__u32		nlmsg_seq;	/* Sequence number */
	__u32		nlmsg_pid;	/* Sending process PID */
};



/* module things */
#define MODULE_LICENSE(x) 
#define MODULE_AUTHOR(x) 
#define MODULE_DESCRIPTION(x) 
#define MODULE_PARM(x,n) 
#define MODULE_PARM_DESC(x,n) 
#define module_param(name, type, perm)
#define module_param_array(name, type, num, perm)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,28)
#define EXPORT_NO_SYMBOLS
#endif

#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)

void module_put(struct module *module);
int try_module_get(struct module *module);
#define try_then_request_module(x, mod...) ((x) ?: (request_module(mod), (x)))
extern int request_module(const char * name, ...) __attribute__ ((format (printf, 1, 2)));

struct __module_init { 
	int (*initcall)(void);
	const char *name;
};

struct __module_exit { 
	void (*exitcall)(void);
	const char *name;
};

#define __init
#define __initdata
#define __exit

#define MODULE_NAME_LEN (256 - sizeof(unsigned long) * 5)

/* Large alignment ensures it's not padded in section. */
struct module {
	struct list_head list;
	int (*init)(void);
	void (*exit)(void);
	long state;
	unsigned int use;
	char name[MODULE_NAME_LEN];
} __attribute__((aligned(64)));

#ifdef KBUILD_MODNAME
static struct module __this __attribute__((section("__modules"), unused)) = { .name = __stringify(KBUILD_MODNAME) };
#define THIS_MODULE &__this

#define module_init(fn) \
	static struct __module_init __initcall_##fn \
	__attribute__((__unused__)) \
	__attribute__((__section__("module_init"))) = { &fn, __stringify(KBUILD_MODNAME) }

#define module_exit(fn) \
	static struct __module_exit __exitcall_##fn \
	__attribute__((__unused__)) \
	__attribute__((__section__("module_exit"))) = { &fn, __stringify(KBUILD_MODNAME) }
#else
#define THIS_MODULE 0
#endif /* KBUILD_MODNAME */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
#define MOD_INC_USE_COUNT
#define MOD_DEC_USE_COUNT
#define __MOD_DEC_USE_COUNT(mod)
#define __MOD_INC_USE_COUNT(mod)
#define smp_num_cpus NR_CPUS
#endif

#include <core.h>
#include <message.h>
#include <proc_stuff.h>

/* percpu.h */
#define DEFINE_PER_CPU(type, name)	 __typeof__(type) per_cpu__##name

#define per_cpu(var, cpu)		(*((void)cpu, &per_cpu__##var))
#define __get_cpu_var(var)		per_cpu__##var

#define DECLARE_PER_CPU(type, name)	extern __typeof__(type) per_cpu__##name

#define EXPORT_PER_CPU_SYMBOL(var) EXPORT_SYMBOL(per_cpu__##var)
#define EXPORT_PER_CPU_SYMBOL_GPL(var) EXPORT_SYMBOL_GPL(per_cpu__##var)

/* if_ether.h */
struct ethhdr *eth_hdr(const struct sk_buff *skb);

/* jhash.h */
u32 jhash(void *key, u32 length, u32 initval);
u32 jhash2(u32 *k, u32 length, u32 initval);
u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval);
u32 jhash_2words(u32 a, u32 b, u32 initval);
u32 jhash_1word(u32 a, u32 initval);
#endif /* __HAVE_SIMULATOR_H */
