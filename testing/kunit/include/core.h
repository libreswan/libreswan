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

/**
 * Definitions provided by the core netfilter code
 */
#ifndef __HAVE_CORE_H
#define __HAVE_CORE_H 1

#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <kernelenv.h>
#include <utils.h>

#include <linux/list.h>

extern struct list_head interfaces;

struct net_device *interface_by_name(const char *name);

/* This should be enough to fool you all.  Bwahahahahah! */
extern struct net_device *loopback_dev_p;
#define loopback_dev (*loopback_dev_p)

/**
 * allow protocols modules to send packets.
 */
int nf_send(struct sk_buff *skb);
int nf_send_local(struct sk_buff *skb);

int nf_rcv(struct sk_buff *skb);
int nf_rcv_local(struct sk_buff *skb);

/* Create an skb: first amount that is linear, then the rest. */
struct sk_buff *nfsim_nonlinear_skb(const void *data1, unsigned int size1,
				    const void *data2, unsigned int size2);

/* Check packet is OK. */
void nfsim_check_packet(const struct sk_buff *skb);
/* Internal routine to say we updated packet. */
void nfsim_update_skb(struct sk_buff *skb, void *p, unsigned int size);
/*
 * simulator queueing
 */
struct nfsim_queueitem {
	struct list_head list;
	struct sk_buff          *skb;
	struct nf_info          *info;
	int id;
};

extern struct list_head nfsim_queue;

#define NF_DROP 0
#define NF_ACCEPT 1
#define NF_STOLEN 2
#define NF_QUEUE 3
#define NF_REPEAT 4
#define NF_MAX_VERDICT NF_REPEAT

#define NF_MAX_HOOKS 8

#define NFC_UNKNOWN 0x4000
#define NFC_ALTERED 0x8000

const char *nf_retval(int retval);
int nf_retval_by_name(const char *name);

extern struct list_head nf_hooks[NPROTO][NF_MAX_HOOKS];

extern const char *nf_hooknames[NPROTO][NF_MAX_HOOKS];

typedef unsigned int nf_hookfn (unsigned int hooknum,
				struct sk_buff **skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *));

struct nf_sockopt_ops {
	struct list_head list;

	int pf;

	/* Non-inclusive ranges: use 0/0/NULL to never get called. */
	int set_optmin;
	int set_optmax;
	int (*set)(struct sock *sk, int optval, void *user, unsigned int len);

	int get_optmin;
	int get_optmax;
	int (*get)(struct sock *sk, int optval, void *user, int *len);

	/* Number of users inside set() or get(). */
	unsigned int use;
	struct task_struct *cleanup_task;

	struct module *owner;
};

struct nf_hook_ops {
	struct list_head list;

	/* User fills in from here down. */
	nf_hookfn *hook;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
	struct module *owner;
#endif
	int pf;
	int hooknum;
	/* Hooks are ordered in ascending priority. */
	int priority;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
	struct module *owner;
#endif
};

/* Each queued (to userspace) skbuff has one of these. */
struct nf_info {
	/* The ops struct which sent us to userspace. */
	struct nf_hook_ops *elem;

	/* If we're sent to userspace, this keeps housekeeping info */
	int pf;
	unsigned int hook;
	struct net_device *indev, *outdev;
	int (*okfn)(struct sk_buff *);
};

/* Function to register/unregister hook points. */
#define nf_register_hook(reg) \
	__nf_register_hook_wrapper(reg, THIS_MODULE, __location__)
int __nf_register_hook_wrapper(struct nf_hook_ops *reg, struct module *owner,
			       const char *location);
#define nf_unregister_hook(reg) \
	__nf_unregister_hook_wrapper(reg)
void __nf_unregister_hook_wrapper(struct nf_hook_ops *reg);
int __nf_register_hook(struct nf_hook_ops *reg);
void __nf_unregister_hook(struct nf_hook_ops *reg);

/* Functions to register get/setsockopt ranges (non-inclusive).  You
   need to check permissions yourself! */
#define nf_register_sockopt(reg) \
	__nf_register_sockopt_wrapper(reg, THIS_MODULE, __location__)
int __nf_register_sockopt_wrapper(struct nf_sockopt_ops *reg,
				  struct module *owner, const char *location);
#define nf_unregister_sockopt(reg) \
	__nf_unregister_sockopt_wrapper(reg)
void __nf_unregister_sockopt_wrapper(struct nf_sockopt_ops *reg);

int __nf_register_sockopt(struct nf_sockopt_ops *reg);
void __nf_unregister_sockopt(struct nf_sockopt_ops *reg);

int nf_setsockopt(struct sock *sk, int pf, int val, char *opt, int len);
int nf_getsockopt(struct sock *sk, int pf, int val, char *opt, int *len);

typedef void nf_logfn (unsigned int hooknum,
		       const struct sk_buff *skb,
		       const struct net_device *in,
		       const struct net_device *out,
		       const char *prefix);

/* Function to register/unregister log function. */
int nf_log_register(int pf, nf_logfn *logfn);
void nf_log_unregister(int pf, nf_logfn *logfn);

/* Calls the registered backend logging function */
void nf_log_packet(int pf,
		   unsigned int hooknum,
		   const struct sk_buff *skb,
		   const struct net_device *in,
		   const struct net_device *out,
		   const char *fmt, ...);

int nf_hook_slow(int pf, unsigned int hook, struct sk_buff *skb,
		 struct net_device *indev,
		 struct net_device *outdev,
		 int (*okfn)(struct sk_buff *)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
		 , int hook_thresh
#endif
		 );

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 5, 0)
#define NF_HOOK(pf, hook, skb, indev, outdev, okfn)                     \
	nf_hook_slow((pf), (hook), (skb), (indev), (outdev), (okfn), INT_MIN)
#else
#define NF_HOOK(pf, hook, skb, indev, outdev, okfn)                     \
	nf_hook_slow((pf), (hook), (skb), (indev), (outdev), (okfn))
#endif

#define NF_HOOK_THRESH nf_hook_slow

/* Packet queuing */
typedef int (*nf_queue_outfn_t)(struct sk_buff *skb,
				struct nf_info *info, void *data);
extern int nf_register_queue_handler(int pf,
				     nf_queue_outfn_t outfn, void *data);
extern int nf_unregister_queue_handler(int pf);
extern void nf_reinject(struct sk_buff *skb,
			struct nf_info *info,
			unsigned int verdict);

/* Like alloc_skb, but never fails even when failtest on. */
struct sk_buff *alloc_skb_internal(unsigned int size, int gfp_mask,
				   const char *loc);

#include <ipv4.h>

static inline int complete_read(int fd, char *buf, int len)
{
	int ret = 0;
	char *ptr = buf;

	while (ptr < buf + len) {
		ret = read(fd, ptr, len - (ptr - buf));
		if (ret < 0)
			return ret;

		ptr += ret;
	}

	return len;
}

unsigned int skb_checksum(const struct sk_buff *skb, int offset,
			  int len, unsigned int csum);

const char *describe_packet(struct sk_buff *skb);

/* We want logging for every hook */
unsigned int call_elem_hook(struct nf_hook_ops *ops,
			    unsigned int hooknum,
			    struct sk_buff **skb,
			    const struct net_device *in,
			    const struct net_device *out,
			    int (*okfn)(struct sk_buff *));

/* netlink sockets */

int netlink_register_notifier(struct notifier_block *nb);
int netlink_unregister_notifier(struct notifier_block *nb);

struct sock * netlink_kernel_create(int unit,
				    void (*input)(struct sock *sk, int len));

void netlink_ack(struct sk_buff *in_skb, struct nlmsghdr *nlh, int err);

int netlink_unicast(struct sock *ssk, struct sk_buff *skb, u32 pid,
		    int nonblock);

bool load_all_modules(void);
bool unload_all_modules(void);

void check_allocations(void);
void netfilter_init(void);

/* tools/ifconfig.c: used to create initial devices. */
struct net_device *create_device(const char *name, int argc, char **);

/* For failtest to test malloc etc failures. */
bool should_i_fail(const char *func);
bool should_i_fail_once(const char *location);
bool get_failtest(void);
extern unsigned int suppress_failtest;
extern unsigned int failpoints;

/* Proc interface. */
bool nfsim_proc_cat(const char *name);
bool nfsim_proc_write(const char *name, char *argv[]);
void proc_cleanup(void);

/* Root for all kernel code allocations (so we check memory leaks) */
extern void *nfsim_tallocs;

/* If the test has a name, this is it. */
extern const char *nfsim_testname;

/* Hack for valgrind */
extern void check_for_valgrind_errors(void);

enum exitcodes {
	/* EXIT_SUCCESS, EXIT_FAILURE is in stdlib.h */
	EXIT_SCRIPTFAIL = EXIT_FAILURE + 1,
	EXIT_SILENT,
};

/* init code */
typedef void (*initcall_t)(void);
#define init_call(fn) \
	static initcall_t __initcall_ ## fn \
	__attribute__((__unused__)) \
	__attribute__((__section__("init_call"))) = &fn

/* distributed command line options */
struct cmdline_option {
	struct option opt;
	void (*parse)(struct option *opt);
};
#define cmdline_opt(_name, _has_arg, _c, _fn)                                \
	static struct cmdline_option __cat(__cmdlnopt_, __unique_id(_fn))      \
	__attribute__((__unused__))                                           \
	__attribute__((__section__("cmdline")))                               \
		= { .opt = { .name = _name, .has_arg = _has_arg, .val = _c },         \
		    .parse = _fn }

extern int netif_rx(struct sk_buff *skb);

#endif /* __HAVE_CORE_H */
