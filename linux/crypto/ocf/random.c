/*
 * A system independant way of adding entropy to the kernels pool
 * this way the drivers can focus on the real work and we can take
 * care of pushing it to the appropriate place in the kernel.
 *
 * This should be fast and callable from timers/interrupts
 *
 * This code written by David McCullough <dmccullough@cyberguard.com>
 * Copyright (C) 2004-2005 Intel Corporation.  All Rights Reserved.
 *
 * LICENSE TERMS
 *
 * The free distribution and use of this software in both source and binary
 * form is allowed (with or without changes) provided that:
 *
 *   1. distributions of this source code include the above copyright
 *      notice, this list of conditions and the following disclaimer;
 *
 *   2. distributions in binary form include the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other associated materials;
 *
 *   3. the copyright holder's name is not used to endorse products
 *      built using this software without specific written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this product
 * may be distributed under the terms of the GNU General Public License (GPL),
 * in which case the provisions of the GPL apply INSTEAD OF those given above.
 *
 * DISCLAIMER
 *
 * This software is provided 'as is' with no explicit or implied warranties
 * in respect of its properties, including, but not limited to, correctness
 * and/or fitness for purpose.
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/unistd.h>
#include <linux/poll.h>
#include <linux/random.h>
#include <linux/jiffies.h>
#include <crypto/cryptodev.h>

#ifdef FIPS_TEST_RNG
#include "rndtest.h"
#endif

/*
 * a hack to access the debug levels from the crypto driver
 */
extern int *crypto_debug;
#define debug (*crypto_debug)

/*
 * a list of all registered random providers
 */
static LIST_HEAD(random_ops);
static int started = 0;
static int initted = 0;

struct random_op {
	struct list_head random_list;
	u_int32_t driverid;
	int (*read_random)(void *arg, u_int32_t *buf, int len);
	void *arg;
};

static int random_proc(void *arg);

static pid_t		randomproc = (pid_t) -1;
static spinlock_t	random_lock;

static inline _syscall3(int,open,const char *,file,int, flags, int, mode);
static inline _syscall3(int,ioctl,int,fd,unsigned int,cmd,unsigned long,arg);
static inline _syscall3(int,poll,struct pollfd *,pollfds,unsigned int,nfds,long,timeout);

#define RND_STIR_INTERVAL  10
static int rnd_stir_interval = RND_STIR_INTERVAL;
module_param(rnd_stir_interval, int, 0644);
MODULE_PARM_DESC(rnd_stir_interval, "How often to add entropy, even when not needed");

/*
 * just init the spin locks
 */
static int
crypto_random_init(void)
{
	spin_lock_init(&random_lock);
	initted = 1;
	return(0);
}

/*
 * Add the given random reader to our list (if not present)
 * and start the thread (if not already started)
 *
 * we have to assume that driver id is ok for now
 */
int
crypto_rregister(
	u_int32_t driverid,
	int (*read_random)(void *arg, u_int32_t *buf, int len),
	void *arg)
{
	unsigned long flags;
	int ret = 0;
	struct random_op	*rops, *tmp;

	dprintk("%s,%d: %s(0x%x, %p, %p)\n", __FILE__, __LINE__,
			__FUNCTION__, driverid, read_random, arg);

	/* FIXME: currently random support is broken for 64bit OS's */
	if (sizeof(int) != sizeof(long))
		return 0;

	if (!initted)
		crypto_random_init();

#if 0
	struct cryptocap	*cap;

	cap = crypto_checkdriver(driverid);
	if (!cap)
		return EINVAL;
#endif

	list_for_each_entry_safe(rops, tmp, &random_ops, random_list) {
		if (rops->driverid == driverid && rops->read_random == read_random)
			return EEXIST;
	}

	rops = (struct random_op *) kmalloc(sizeof(*rops), GFP_KERNEL);
	if (!rops)
		return ENOMEM;

	rops->driverid    = driverid;
	rops->read_random = read_random;
	rops->arg = arg;
	list_add_tail(&rops->random_list, &random_ops);

	spin_lock_irqsave(&random_lock, flags);
	if (!started) {
		randomproc = kernel_thread(random_proc, NULL, CLONE_FS|CLONE_FILES);
		if (randomproc < 0) {
			ret = randomproc;
			printk("crypto: crypto_rregister cannot start random thread; "
					"error %d", ret);
		} else
			started = 1;
	}
	spin_unlock_irqrestore(&random_lock, flags);

	return ret;
}
EXPORT_SYMBOL(crypto_rregister);

int
crypto_runregister_all(u_int32_t driverid)
{
	struct random_op *rops, *tmp;
	unsigned long flags;

	dprintk("%s,%d: %s(0x%x)\n", __FILE__, __LINE__, __FUNCTION__, driverid);

	list_for_each_entry_safe(rops, tmp, &random_ops, random_list) {
		if (rops->driverid == driverid) {
			list_del(&rops->random_list);
			kfree(rops);
		}
	}

	spin_lock_irqsave(&random_lock, flags);
	if (list_empty(&random_ops) && started) {
		kill_proc(randomproc, SIGKILL, 1);
		randomproc = (pid_t) -1;
		started = 0;
	}
	spin_unlock_irqrestore(&random_lock, flags);
	return(0);
}
EXPORT_SYMBOL(crypto_runregister_all);

/*
 * while we need more entropy, continue to read random data from
 * the drivers
 */
static int
random_proc(void *arg)
{
	int n;
	int done;
	int wantcnt;
	int bufcnt= 0;

	daemonize("ocf-random");

	(void) get_fs();
	set_fs(get_ds());

#ifdef FIPS_TEST_RNG
#define NUM_INT (RNDTEST_NBYTES/sizeof(int))
#else
#define NUM_INT 32
#endif

	done = 0;            /* hard to know why we'd exit */
	wantcnt = NUM_INT;   /* start by adding some entropy */

	while (!done) {
		static int			buf[NUM_INT];
		struct random_op	*rops, *tmp;

#ifdef FIPS_TEST_RNG
		wantcnt = NUM_INT;
#endif

		/* see if we can get enough entropy to make the world
		 * a better place.
		 */
		while (bufcnt < wantcnt && bufcnt < NUM_INT) {
			list_for_each_entry_safe(rops, tmp, &random_ops, random_list) {
				n = (*rops->read_random)(rops->arg, &buf[bufcnt],
							 NUM_INT - bufcnt);

				/* on failure remove the random number generator */
				if (n == -1) {
					list_del(&rops->random_list);
					printk("crypto: RNG (driverid=0x%x) failed, disabling\n",
							rops->driverid);
					kfree(rops);
				} else if (n > 0)
					bufcnt += n;
			}
		}


#ifdef FIPS_TEST_RNG
		if (rndtest_buf((unsigned char *) &buf[2])) {
			dprintk("crypto: buffer had fips errors, discarding\n");
			bufcnt = 0;
		}
#endif

		/*
		 * if we have a certified buffer,  we can send some data
		 * to /dev/random and move along
		 */
		if (bufcnt) {
			/* add what we have */
			random_input_words(buf, bufcnt, bufcnt*sizeof(int)*8);
			bufcnt = 0;
		}
		
		/* give up CPU for a bit, just in case */
		schedule();

		/* wait for needing more */
		wantcnt = random_input_wait();

		if(wantcnt <= 0) {
			/* clear any signals that there might be */
			if (signal_pending(current)) {
				flush_signals(current);
			}
		}

		wantcnt = wantcnt / (sizeof(int)*8);
		
		if(wantcnt > 4096) {
			wantcnt = 32;
		}
	}

	return 0;
}


