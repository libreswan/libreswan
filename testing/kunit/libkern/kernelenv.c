/*

   Copyright (c) 2003,2004 Jeremy Kerr & Rusty Russell

   This file is part of nfsim.

   nfsim is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   nfsim is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with nfsim; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <kernelenv.h>
#include "utils.h"
#include "field.h"
#if 0
#include "tui.h"
#endif

/* Root of talloc trees for different allocators */
void *__skb_ctx, *__vmalloc_ctx, *__kmalloc_ctx, *__kmalloc_atomic_ctx,
*__kmem_cache_ctx, *__lock_ctx, *__timer_ctx;

unsigned long num_physpages = 1024;

unsigned long jiffies = INITIAL_JIFFIES;

u32 htonl(u32 hostlong)
{
	return __cpu_to_be32(hostlong);
}

u16 htons(u16 hostshort)
{
	return __cpu_to_be16(hostshort);
}

u32 ntohl(u32 netlong)
{
	return __be32_to_cpu(netlong);
}

u16 ntohs(u16 netshort)
{
	return __be16_to_cpu(netshort);
}

/* skbuff */
static int nfsim_seq;

#if 0
/* We hide the shared info in hidden field (kernel puts it after
 * data).  This way valgrind can spot overruns. */
struct skb_shared_info *skb_shinfo(struct sk_buff *skb)
{
	return field_value(skb, "skb_shinfo");
}
#endif

struct skb_extra_info {
	unsigned char *data;
	unsigned int len, writable_len;
};

/* Create an skb: first amount that is linear, then the rest. */
struct sk_buff *nfsim_nonlinear_skb(const void *data1,
				    unsigned int size1,
				    const void *data2,
				    unsigned int size2)
{
	struct sk_buff *skb;

#ifdef WANT_SKB_SHINFO
	struct skb_extra_info *extra;
	struct skb_shared_info *sinfo;
#endif

	/* Skb header. */
	skb = talloc_zero(__skb_ctx, struct sk_buff);

#ifdef WANT_SKB_SHINFO
	/* Save copy of data, all non-writable. */
	extra = talloc(skb, struct skb_extra_info);
	extra->len = size1 + size2;
	extra->writable_len = 0;
	extra->data = talloc_size(extra, extra->len);
	memcpy(extra->data, data1, size1);
	memcpy(extra->data + size1, data2, size2);
	field_attach(skb, "extra_data", extra);

	/* Place linear data in skb. */
	skb->data = talloc_memdup(skb, extra->data, size1);
#endif

#ifdef WANT_SKB_SHINFO
	sinfo = talloc(skb, struct skb_shared_info);
	field_attach(skb, "skb_shinfo", sinfo);
#endif

	atomic_set(&skb->users, 1);

	skb->head = skb->data;
	skb->end = skb->tail = skb->data + size1;
	skb->len = size1 + size2;

	skb->seq = ++nfsim_seq;

#ifdef WANT_SKB_SHINFO
	/* set shinfo fields */
	skb_shinfo(skb)->tso_size = 0;
#endif

	return skb;
}

/* Normal, linear skb. */
/*static*/ struct sk_buff *nfsim_skb(unsigned int size)
{
	struct sk_buff *skb;

#ifdef WANT_SKB_SHINFO
	struct skb_shared_info *sinfo;
#endif

	/* Skb header. */
	skb = talloc_zero(__skb_ctx, struct sk_buff);

	/* Place linear data in skb. */
	skb->data = talloc_size(skb, size);

#ifdef WANT_SKB_SHINFO
	sinfo = talloc(skb, struct skb_shared_info);
	field_attach(skb, "skb_shinfo", sinfo);
#endif

	atomic_set(&skb->users, 1);
	skb->head = skb->tail = skb->data;
	skb->len = 0;
	skb->end = skb->data + size;

	skb->seq = ++nfsim_seq;

#ifdef WANT_SKB_SHINFO
	/* set shinfo fields */
	skb_shinfo(skb)->tso_size = 0;
#endif
	return skb;
}

#ifdef NFSIM_CHECK
void nfsim_check_packet(const struct sk_buff *skb)
{
	struct skb_extra_info *extra = field_value(skb, "extra_data");
	unsigned int linear_len = skb->end - skb->head;

	if (!extra)
		return;

	/* Packet should not have been changed where not writable. */
	if (!memeq(skb->head + extra->writable_len,
		   extra->data + extra->writable_len,
		   linear_len - extra->writable_len))
		barf("skb modified without being made writable!");
}

/* Internal routine to say we updated skb. */
void nfsim_update_skb(struct sk_buff *skb, void *vp, unsigned int size)
{
	unsigned char *p = (unsigned char *)vp;
	struct skb_extra_info *extra = field_value(skb, "extra_data");
	unsigned int off = p - (unsigned char *)skb->head;

	if (!extra)
		return;

	if (off + size > extra->len)
		barf("Bad nfsim_update_skb %i");

	/* If it wasn't already writable, copy update to master. */
	if (off + size > extra->writable_len)
		memcpy(extra->data + off, p, size);

	nfsim_check_packet(skb);
}
#else
#define nfsim_check_packet(skb)
#define nfsim_update_skb(skb, vp, size)
#endif

/* Defined to return a linear skb. */
struct sk_buff *alloc_skb(unsigned int size, int priority)
{
	if (should_i_fail(__func__))
		return NULL;

	return nfsim_skb(size);
}

void kfree_skb(struct sk_buff *skb)
{
#ifdef CONFIG_NETFILTER
	nf_conntrack_put(skb->nfct);
#endif
	if (skb->dst)
		dst_release(skb->dst);

	talloc_free(skb);
}

unsigned char *skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *tmp = skb->tail;

	skb->tail += len;
	skb->len += len;
	if (skb->tail > skb->end)
		barf("skb_put will overrun buffer");
	return tmp;
}

unsigned char *skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data -= len;
	skb->len  += len;
	if (skb->data < skb->head)
		barf("skb_push will underrun buffer");
	return skb->data;
}

unsigned char *skb_pull(struct sk_buff *skb, unsigned int len)
{
	skb->data += len;
	skb->len  -= len;

	if (skb->data < skb->head)
		barf("skb_pull will underrun buffer");

	return skb->data;
}

/* Defined to return a writable, linear skb. */
struct sk_buff *skb_copy_expand(const struct sk_buff *skb,
				int newheadroom, int newtailroom, int gfp_mask)
{
	struct sk_buff *n;

	nfsim_check_packet(skb);

	if (should_i_fail(__func__))
		return NULL;

	n = nfsim_skb(newheadroom + skb->len + newtailroom);
	skb_reserve(n, newheadroom);
	skb_put(n, skb->len);

	if (skb_copy_bits(skb, 0, n->data, skb->len))
		barf("skb_copy_bits failed");

	copy_skb_header(n, skb);

	return n;
}

unsigned int skb_headroom(const struct sk_buff *skb)
{
	return skb->data - skb->head;
}

unsigned int skb_tailroom(const struct sk_buff *skb)
{
	return skb_is_nonlinear(skb) ? 0 : skb->end - skb->tail;
}

unsigned int skb_cow(struct sk_buff *skb, unsigned int headroom)
{
	int delta = (headroom > 16 ? headroom : 16) - skb_headroom(skb);

	if (delta < 0)
		delta = 0;

	if (delta || skb_cloned(skb)) {
		/* XXX not yet written */
		lsw_abort();
		//return pskb_expand_head(skb, (delta + 15) & ~15, 0, GFP_ATOMIC);
	}
	return 0;
}

void skb_reserve(struct sk_buff *skb, unsigned int len)
{
	skb->data += len;
	skb->tail += len;
	if (skb->data > skb->end || skb->tail > skb->end)
		barf("skb_reserve: too much");
}

/* careful with this one.. */
#define __copy(member) new->member = old->member

void copy_skb_header(struct sk_buff *new, const struct sk_buff *old)
{
	unsigned long offset = new->data - old->data;

	__copy(dev);
	__copy(seq);
	__copy(local_df);
	__copy(len);
	__copy(csum);
	__copy(ip_summed);
	__copy(nfmark);
	__copy(nfcache);
	__copy(nfct);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 9)
	__copy(nfctinfo);
#endif
	nf_conntrack_get(new->nfct);

	/* dst_clone() ? */
	__copy(dst);

	new->h.raw  = old->h.raw  + offset;
	new->nh.raw = old->nh.raw + offset;

#if 0
	if (field_exists(old, "dump_flags"))
		field_attach(new, "dump_flags",
			     talloc_strdup(NULL,
					   field_value(old, "dump_flags")));
#endif
}

#undef __copy

static inline int nfsim_linear_length(const struct sk_buff *skb)
{
	return skb->end - skb->data;
}

int skb_copy_bits(const struct sk_buff *skb, int offset,
		  void *vto, int len)
{
	unsigned char *to = (unsigned char *)vto;

#ifdef WANT_SKB_SHINFO
	struct skb_extra_info *extra = field_value(skb, "extra_data");
#endif

	nfsim_check_packet(skb);

	if (offset > (int)skb->len - len)
		return -EFAULT;

	/* Can we copy some from linear part of packet? */
	if (offset < nfsim_linear_length(skb)) {
		int len_from_data =
			min(len, nfsim_linear_length(skb) - offset);

		memcpy(to, skb->data + offset, len_from_data);
		offset += len_from_data;
		len -= len_from_data;
		to += len_from_data;
	}

#ifdef WANT_SKB_SHINFO
	/* Copy from nonlinear part. */
	if (extra)
		memcpy(to, extra->data + skb_headroom(skb) + offset, len);
	else
		assert(len == 0);
#endif
	return 0;
}

struct sk_buff *skb_realloc_headroom(struct sk_buff *skb,
				     unsigned int headroom)
{
	int delta = headroom - skb_headroom(skb);

	return skb_copy_expand(skb, delta > 0 ? delta : 0, 0, GFP_ATOMIC);
}

int pskb_may_pull(struct sk_buff *skb, unsigned int len)
{
	return len <= skb_headroom(skb);
}

static int __skb_checksum_help(struct sk_buff *skb, int inward)
{
	unsigned int csum;
	int ret = 0, offset = skb->h.raw - skb->data;

	if (inward) {
		skb->ip_summed = CHECKSUM_NONE;
		goto out;
	}

	if (skb_shared(skb)  || skb_cloned(skb)) {
		struct sk_buff *newskb = skb_copy(skb, GFP_ATOMIC);
		if (!newskb) {
			ret = -ENOMEM;
			goto out;
		}
		if (skb->sk)
			skb_set_owner_w(newskb, skb->sk);
		kfree_skb(skb);
		skb = newskb;
	}

	if (offset > (int)skb->len)
		BUG();
	csum = skb_checksum(skb, offset, skb->len - offset, 0);

	offset = skb->tail - skb->h.raw;
	if (offset <= 0)
		BUG();
	if (skb->csum + 2 > offset)
		BUG();

	*(u16*)(skb->h.raw + skb->csum) = csum_fold(csum);
	skb->ip_summed = CHECKSUM_NONE;
out:
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 7)
int skb_checksum_help(struct sk_buff *skb)
{
	return __skb_checksum_help(skb, 0);
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 10)
int skb_checksum_help(struct sk_buff **pskb, int inward)
{
	return __skb_checksum_help(*pskb, inward);
}
#else
int skb_checksum_help(struct sk_buff *skb, int inward)
{
	return __skb_checksum_help(skb, inward);
}
#endif

int skb_cloned(const struct sk_buff *skb)
{
	return skb->cloned;
}

int skb_shared(const struct sk_buff *skb)
{
	return atomic_read(&skb->users) != 1;
}

unsigned int skb_checksum(const struct sk_buff *skb, int offset,
			  int len, unsigned int csum)
{
	char data[len];

	if (skb_copy_bits(skb, offset, data, len) != 0)
		barf("skb_checksum invalid length");

	return csum_partial(data, len, csum);
}

void __skb_trim(struct sk_buff *skb, unsigned int len)
{
	skb->len  = len;
	skb->tail = skb->data + len;
}

void skb_trim(struct sk_buff *skb, unsigned int len)
{
	if (skb->len > len)
		__skb_trim(skb, len);
}

void skb_orphan(struct sk_buff *skb)
{
	if (skb->destructor)
		skb->destructor(skb);
	skb->destructor = NULL;
	skb->sk         = NULL;
}

int skb_is_nonlinear(const struct sk_buff *skb)
{
	nfsim_check_packet(skb);

	return skb->data + skb->len > skb->end;
}

int skb_ip_make_writable(struct sk_buff **pskb, unsigned int writable_len)
{
	struct sk_buff *new;
	struct skb_extra_info *extra;
	char data[(*pskb)->len];

	nfsim_check_packet(*pskb);

	if (writable_len > (*pskb)->len)
		return 0;

	if (should_i_fail(__func__))
		return 0;

	/* Use skb_copy_bits, which handles packet whatever shape. */
	skb_copy_bits(*pskb, 0, data, (*pskb)->len);

	extra = field_value(*pskb, "extra_data");
	if (extra && writable_len < extra->writable_len)
		writable_len = extra->writable_len;

	/* Always reallocate, to catch cached pointers. */
	new = nfsim_nonlinear_skb(data, writable_len,
				  data + writable_len,
				  (*pskb)->len - writable_len);
	copy_skb_header(new, *pskb);
	extra = field_value(new, "extra_data");
	extra->writable_len = writable_len;

	if ((*pskb)->sk)
		skb_set_owner_w(new, (*pskb)->sk);

	kfree_skb(*pskb);
	*pskb = new;
	return 1;
}

int skb_linearize(struct sk_buff *skb, int len)
{
	unsigned char *new_head;
	unsigned int headroom = skb_headroom(skb);

	nfsim_check_packet(skb);

	if (should_i_fail(__func__))
		return -ENOMEM;

	new_head = talloc_size(skb, skb->len + headroom);
	memcpy(new_head, skb->head, headroom);
	skb_copy_bits(skb, 0, new_head + headroom, skb->len);

	skb->data = new_head + headroom;
	skb->tail = skb->end = new_head + headroom + skb->len;
	talloc_free(skb->head);
	skb->head = new_head;

	/* Don't need this on writable, linear packets. */
	field_detach(skb, "extra_data");
	return 0;
}

/* Either copy into buffer or give pointer to in-place. */
void *skb_header_pointer(const struct sk_buff *skb, int offset,
			 int len, void *buffer)
{
	nfsim_check_packet(skb);

	if (offset + len > skb->len)
		return NULL;

	/* We should test copying even if not required. */
	if (!should_i_fail_once(__func__)) {
		if (offset + len <= nfsim_linear_length(skb))
			return skb->data + offset;
	}

	if (skb_copy_bits(skb, offset, buffer, len) < 0)
		barf("skb_header_pointer: logic error");

	return buffer;
}

void sock_hold(struct sock *sk)
{
	atomic_inc(&sk->sk_refcnt);
}

void sock_put(struct sock *sk)
{
	if (atomic_dec_and_test(&sk->sk_refcnt))
		free(sk);
}

void skb_set_owner_w(struct sk_buff *skb, struct sock *sk)
{
	/*
	   sock_hold(sk);
	   skb->sk = sk;
	   skb->destructor = sock_wfree;
	   atomic_add(skb->truesize, &sk->sk_wmem_alloc);
	 */
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 9)
void nf_conntrack_put(struct nf_ct_info *nfct)
{
	if (nfct && atomic_dec_and_test(&nfct->master->use))
		nfct->master->destroy(nfct->master);
}
void nf_conntrack_get(struct nf_ct_info *nfct)
{
	if (nfct)
		atomic_inc(&nfct->master->use);
}
#else
void nf_conntrack_put(struct nf_conntrack *nfct)
{
	if (nfct && atomic_dec_and_test(&nfct->use))
		nfct->destroy(nfct);
}
void nf_conntrack_get(struct nf_conntrack *nfct)
{
	if (nfct)
		atomic_inc(&nfct->use);
}
void (*ip_ct_attach)(struct sk_buff *, struct sk_buff *);
#endif /* 2.6.9 */

void nf_reset(struct sk_buff *skb)
{
	nf_conntrack_put(skb->nfct);
	skb->nfct = NULL;
#ifdef CONFIG_NETFILTER_DEBUG
	skb->nf_debug = 0;
#endif
}
void nf_reset_debug(struct sk_buff *skb)
{
#ifdef CONFIG_NETFILTER_DEBUG
	skb->nf_debug = 0;
#endif
}

u32 dst_path_metric(struct dst_entry *dst, int metric)
{
	return 1500;
/*	return dst->path->metrics[metric-1]; */
}

u32 dst_pmtu(struct dst_entry *dst)
{
	u32 mtu = dst_path_metric(dst, RTAX_MTU);

	/* Yes, _exactly_. This is paranoia. */
	barrier();
	return mtu;
}

int dst_output(struct sk_buff *skb)
{
	assert(skb);
	assert(skb->dst);
	assert(skb->dst->output);
	return skb->dst->output(skb);
}

int dst_input(struct sk_buff *skb)
{
	assert(skb);
	assert(skb->dst);
	assert(skb->dst->input);
	return skb->dst->input(skb);
}

struct ethhdr *eth_hdr(const struct sk_buff *skb)
{
	return (struct ethhdr *)skb->mac.raw;
}

/* spinlock: use talloc for unreleased lock detection */
void __generic_write_lock(spinlock_t *lock, const char *location)
{
	if (lock->lock)
		panic("write lock (called at %s) already held by %s.\n",
		      location, lock->location);
	lock->lock = -1;
	lock->location = talloc_strdup(__lock_ctx, location);
}

void __generic_write_unlock(spinlock_t *lock, const char *location)
{
	if (lock->lock != -1) {
		fprintf(stderr, "write lock (called at %s) isn't held\n",
			location);
	}
	lock->lock = 0;
	talloc_free(lock->location);
	lock->location = NULL;
}

void __generic_read_lock(spinlock_t *lock, const char *location)
{
	if (lock->lock == -1)
		panic("read lock (called at %s) already held by %s.\n",
		      location, lock->location);
	lock->lock++;
	talloc_free(lock->location);
	lock->location = talloc_strdup(__lock_ctx, location);
}

void __generic_read_unlock(spinlock_t *lock, const char *location)
{
	if (lock->lock <= 0) {
		fprintf(stderr, "read lock (called at %s) isn't held\n",
			location);
	}
	lock->lock--;

	if (lock->lock == 0) {
		talloc_free(lock->location);
		lock->location = NULL;
	}
}

/* semaphore */
void __down(struct semaphore *sem, const char *location)
{
	if (!(sem->count)--)
		barf("down() unavailable at %s\n", location);

	field_attach_static(sem, location, NULL);
}

int __down_interruptible(struct semaphore *sem, const char *location)
{
	if (should_i_fail(location))
		return -EINTR;

	if (!(sem->count)--)
		barf("down() unavailable at %s\n", location);

	field_attach_static(sem, location, NULL);
	return 0;
}

void __up(struct semaphore *sem, const char *location)
{
	if (++(sem->count) > sem->limit)
		panic("up() unavailable at %s\n", location);
	field_detach_all(sem);
}

int __down_trylock(struct semaphore *sem, const char *location)
{
	if (sem->count) {
		sem->count--;
		field_attach_static(sem, location, NULL);
		return 0;
	}
	return 1;
}

void sema_init(struct semaphore *sem, int val)
{
	sem->count = val;
	sem->limit = val;
}

/* bitops.h */
int test_bit(int nr, const long * addr)
{
	int mask;

	addr += nr >> 5;
	mask = 1 << (nr & 0x1f);
	return (mask & *addr) != 0;
}

int set_bit(int nr, long * addr)
{
	int mask, retval;

	addr += nr >> 5;
	mask = 1 << (nr & 0x1f);
	cli();
	retval = (mask & *addr) != 0;
	*addr |= mask;
	sti();
	return retval;
}

int clear_bit(int nr, long * addr)
{
	int mask, retval;

	addr += nr >> 5;
	mask = 1 << (nr & 0x1f);
	cli();
	retval = (mask & *addr) != 0;
	*addr &= ~mask;
	sti();
	return retval;
}

/* timer */
LIST_HEAD(__timers);
LIST_HEAD(__running_timers);

void __init_timer(struct timer_list * timer, struct module *owner,
		  const char *function)
{
	timer->magic = TIMER_MAGIC;
	timer->owner = owner;
	timer->ownerfunction = function;
	timer->use = NULL;
}

void __add_timer(struct timer_list *timer, const char *location)
{
	struct timer_list *t;

	list_for_each_entry(t, &__timers, entry) {
		if (time_after(t->expires, timer->expires))
			break;
	}
	list_add_tail(&timer->entry, &t->entry);
	timer->use = talloc_strdup(__timer_ctx, location);
}

int __del_timer(struct timer_list *timer, const char *location)
{
	if (!timer->use)
		return 0;

	if (should_i_fail_once(location)) {
		/* Pretend it's running now. */
		list_del(&timer->entry);
		list_add(&timer->entry, &__running_timers);
		return 0;
	}

	list_del(&timer->entry);
	talloc_free(timer->use);
	timer->use = NULL;

	return 1;
}

static bool do_running_timers(const char *cmd)
{
	struct timer_list *t, *next;

	list_for_each_entry_safe(t, next, &__running_timers, entry) {
		list_del(&t->entry);
		talloc_free(t->use);
		t->function(t->data);
	}
	return true;
}

void schedule(void)
{
	do_running_timers("schedule()");
}

static void setup_running_timers(void)
{
#if 0
	tui_register_pre_post_hook(NULL, do_running_timers);
#endif
}
init_call(setup_running_timers);

int timer_pending(const struct timer_list * timer)
{
	/* straightforward at present - timers are guaranteed to
	   be run at the expiry time
	 */
	return timer->expires > jiffies;
}

void increment_time(unsigned int inc)
{
	struct list_head *i;
	struct timer_list *t;

	jiffies += inc;

	i = __timers.next;

	while (i != &__timers) {
		t = list_entry(i, struct timer_list, entry);
		if (time_before(jiffies, t->expires))
			break;
		nfsim_log(LOG_UI, "running timer to %s:%s()", t->owner->name,
			  t->ownerfunction, t->function);
		i = i->next;
		list_del(&t->entry);
		talloc_free(t->use);
		t->use = NULL;
		t->function(t->data);
	}
}

/* notifier */
/*static rwlock_t notifier_lock = RW_LOCK_UNLOCKED;*/

int notifier_chain_register(struct notifier_block **list,
			    struct notifier_block *n)
{
	/* Detect if they don't unregister. */
	field_attach_static(n, "notifier_chain_register", NULL);

	/*write_lock(&notifier_lock);*/
	while (*list) {
		if (n->priority > (*list)->priority)
			break;
		list = &((*list)->next);
	}
	n->next = *list;
	*list = n;
	/*write_unlock(&notifier_lock);*/
	return 0;
}

int notifier_chain_unregister(struct notifier_block **nl,
			      struct notifier_block *n)
{
	/*write_lock(&notifier_lock);*/
	while ((*nl) != NULL) {
		if ((*nl) == n) {
			*nl = n->next;
			/*write_unlock(&notifier_lock);*/
			field_detach_all(n);
			return 0;
		}
		nl = &((*nl)->next);
	}
	/*write_unlock(&notifier_lock);*/
	return -ENOENT;
}

int notifier_call_chain(struct notifier_block **n, unsigned long val, void *v)
{
	int ret = NOTIFY_DONE;
	struct notifier_block *nb = *n;

	while (nb) {
		ret = nb->notifier_call(nb, val, v);
		if (ret & NOTIFY_STOP_MASK)
			return ret;

		nb = nb->next;
	}
	return ret;
}

/* random */
void get_random_bytes(void *buf, int nbytes)
{
	while (nbytes--)
		*((char *)buf + nbytes) = random();

}

/* cache */
void *__malloc(unsigned int size, void *ctx, const char *location)
{
	if (should_i_fail(__func__))
		return NULL;

	return _talloc_zero(ctx, size, location);
}

#if 0
kmem_cache_t *kmem_cache_create(const char *name, size_t objsize,
				size_t offset, unsigned long flags,
				void (*ctor)(void *, kmem_cache_t *,
					     unsigned long),
				void (*dtor)(void *, kmem_cache_t *,
					     unsigned long))
{
	kmem_cache_t *cache;

	if (should_i_fail(__func__))
		return NULL;

	cache = talloc(__kmem_cache_ctx, kmem_cache_t);
	cache->name = name;
	cache->objsize = objsize;
	cache->ctor = ctor;
	cache->dtor = dtor;
	INIT_LIST_HEAD(&cache->objs);

	return cache;
}

int kmem_cache_destroy(kmem_cache_t *cache)
{
	talloc_free(cache);
	return 0;
}

void *kmem_cache_alloc(kmem_cache_t *cache, int flags)
{
	struct kmem_cache_obj *obj;

	if (should_i_fail(__func__))
		return NULL;

	obj = talloc(cache, struct kmem_cache_obj);
	obj->ptr = talloc_size(obj, cache->objsize);

	list_add(&obj->entry, &cache->objs);

	return obj->ptr;

}
void kmem_cache_free(kmem_cache_t *cache, void *ptr)
{
	struct kmem_cache_obj *i;

	list_for_each_entry(i, &(cache->objs), entry) {
		if (i->ptr == ptr) {
			list_del(&i->entry);
			talloc_free(i);
			return;
		}
	}

	panic("[cache] attempting to free non-cache memory\n");
}
#endif

unsigned long __get_free_pages(unsigned int gfp_mask, unsigned int order)
{
	return (unsigned long)(kmalloc(PAGE_SIZE << order, gfp_mask));
}

void free_pages(unsigned long addr, unsigned int order)
{
	memset((void *)addr, 0, PAGE_SIZE << order);
	kfree((void *)addr);
}

int get_order(unsigned long size)
{
	int order;

	size = (size - 1) >> (PAGE_SHIFT - 1);
	order = -1;
	do {
		size >>= 1;
		order++;
	} while (size);
	return order;
}

/* jhash.h: Jenkins hash support.
 *
 * Copyright (C) 1996 Bob Jenkins (bob_jenkins@burtleburtle.net)
 *
 * http://burtleburtle.net/bob/hash/
 *
 * These are the credits from Bob's sources:
 *
 * lookup2.c, by Bob Jenkins, December 1996, Public Domain.
 * hash(), hash2(), hash3, and mix() are externally useful functions.
 * Routines to test the hash are included if SELF_TEST is defined.
 * You can use this free for any purpose.  It has no warranty.
 *
 * Copyright (C) 2003 David S. Miller (davem@redhat.com)
 *
 * I've modified Bob's hash to be useful in the Linux kernel, and
 * any bugs present are surely my fault.  -DaveM
 */

/* NOTE: Arguments are modified. */
#define __jhash_mix(a, b, c) \
	{ \
		a -= b; a -= c; a ^= (c >> 13); \
		b -= c; b -= a; b ^= (a << 8); \
		c -= a; c -= b; c ^= (b >> 13); \
		a -= b; a -= c; a ^= (c >> 12);  \
		b -= c; b -= a; b ^= (a << 16); \
		c -= a; c -= b; c ^= (b >> 5); \
		a -= b; a -= c; a ^= (c >> 3);  \
		b -= c; b -= a; b ^= (a << 10); \
		c -= a; c -= b; c ^= (b >> 15); \
	}

/* The golden ration: an arbitrary value */
#define JHASH_GOLDEN_RATIO      0x9e3779b9

/* The most generic version, hashes an arbitrary sequence
 * of bytes.  No alignment or length assumptions are made about
 * the input key.
 */
u32 jhash(void *key, u32 length, u32 initval)
{
	u32 a, b, c, len;
	u8 *k = key;

	len = length;
	a = b = JHASH_GOLDEN_RATIO;
	c = initval;

	while (len >= 12) {
		a +=
			(k[0] +
			 ((u32)k[1] <<
			  8) + ((u32)k[2] << 16) + ((u32)k[3] << 24));
		b +=
			(k[4] +
			 ((u32)k[5] <<
			  8) + ((u32)k[6] << 16) + ((u32)k[7] << 24));
		c +=
			(k[8] +
			 ((u32)k[9] <<
			  8) + ((u32)k[10] << 16) + ((u32)k[11] << 24));

		__jhash_mix(a, b, c);

		k += 12;
		len -= 12;
	}

	c += length;
	switch (len) {
	case 11: c += ((u32)k[10] << 24);
	case 10: c += ((u32)k[9] << 16);
	case 9: c += ((u32)k[8] << 8);
	case 8: b += ((u32)k[7] << 24);
	case 7: b += ((u32)k[6] << 16);
	case 6: b += ((u32)k[5] << 8);
	case 5: b += k[4];
	case 4: a += ((u32)k[3] << 24);
	case 3: a += ((u32)k[2] << 16);
	case 2: a += ((u32)k[1] << 8);
	case 1: a += k[0];
	}

	__jhash_mix(a, b, c);

	return c;
}

/* A special optimized version that handles 1 or more of u32s.
 * The length parameter here is the number of u32s in the key.
 */
u32 jhash2(u32 *k, u32 length, u32 initval)
{
	u32 a, b, c, len;

	a = b = JHASH_GOLDEN_RATIO;
	c = initval;
	len = length;

	while (len >= 3) {
		a += k[0];
		b += k[1];
		c += k[2];
		__jhash_mix(a, b, c);
		k += 3;
		len -= 3;
	}

	c += length * 4;

	switch (len) {
	case 2: b += k[1];
	case 1: a += k[0];
	}

	__jhash_mix(a, b, c);

	return c;
}

/* A special ultra-optimized versions that knows they are hashing exactly
 * 3, 2 or 1 word(s).
 *
 * NOTE: In partilar the "c += length; __jhash_mix(a,b,c);" normally
 *       done at the end is not done here.
 */
u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval)
{
	a += JHASH_GOLDEN_RATIO;
	b += JHASH_GOLDEN_RATIO;
	c += initval;

	__jhash_mix(a, b, c);

	return c;
}

u32 jhash_2words(u32 a, u32 b, u32 initval)
{
	return jhash_3words(a, b, 0, initval);
}

u32 jhash_1word(u32 a, u32 initval)
{
	return jhash_3words(a, 0, 0, initval);
}

int request_module(const char * name, ...)
{
	return 0;
}

void kernelenv_init(void)
{
	__vmalloc_ctx = talloc_named_const(nfsim_tallocs, 1, "vmallocs");
	__kmalloc_ctx = talloc_named_const(nfsim_tallocs, 1, "kmallocs");
	__kmalloc_atomic_ctx = talloc_named_const(nfsim_tallocs, 1,
						  "kmallocs (atomic)");
	__skb_ctx = talloc_named_const(nfsim_tallocs, 1, "skbs");
	__kmem_cache_ctx = talloc_named_const(nfsim_tallocs, 1, "kmem caches");
	__lock_ctx = talloc_named_const(nfsim_tallocs, 1, "locks");
	__timer_ctx = talloc_named_const(nfsim_tallocs, 1, "timers");
}

int IS_ERR(const void *ptr)
{
	return (unsigned long)ptr > (unsigned long)-1000L;
}

void atomic_inc(atomic_t *v)
{
	v->counter++;
}

void atomic_dec(atomic_t *v)
{
	v->counter--;
}

int atomic_dec_and_test(atomic_t *v)
{
	return --(v->counter) == 0;
}
