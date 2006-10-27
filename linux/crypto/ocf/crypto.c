/*  $OpenBSD: crypto.c,v 1.38 2002/06/11 11:14:29 beck Exp $    */
/*
 * Linux port done by David McCullough <dmccullough@cyberguard.com>
 * Copyright (C) 2004-2005 Intel Corporation.  All Rights Reserved.
 * The license and original author are listed below.
 *
 * The author of this code is Angelos D. Keromytis (angelos@cis.upenn.edu)
 *
 * This code was written by Angelos D. Keromytis in Athens, Greece, in
 * February 2000. Network Security Technologies Inc. (NSTI) kindly
 * supported the development of this code.
 *
 * Copyright (c) 2000, 2001 Angelos D. Keromytis
 *
 * Permission to use, copy, and modify this software with or without fee
 * is hereby granted, provided that this entire notice is included in
 * all source code copies of any software which is or includes a copy or
 * modification of this software.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTY. IN PARTICULAR, NONE OF THE AUTHORS MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE
 * MERCHANTABILITY OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR
 * PURPOSE.
 *
__FBSDID("$FreeBSD: src/sys/opencrypto/crypto.c,v 1.16 2005/01/07 02:29:16 imp Exp $");
 */


#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <crypto/cryptodev.h>

/*
 * keep track of whether or not we have been initialised, a big
 * issue if we are linked into the kernel and a driver gets started before
 * us
 */
static int crypto_initted = 0;

/*
 * Crypto drivers register themselves by allocating a slot in the
 * crypto_drivers table with crypto_get_driverid() and then registering
 * each algorithm they support with crypto_register() and crypto_kregister().
 */

static spinlock_t crypto_drivers_lock;		/* lock on driver table */
#define	CRYPTO_DRIVER_LOCK() \
			({ \
				spin_lock_irqsave(&crypto_drivers_lock, d_flags); \
				dprintk("%s,%d: DRIVER_LOCK()\n", __FILE__, __LINE__); \
			 })
#define	CRYPTO_DRIVER_UNLOCK() \
			({ \
			 	dprintk("%s,%d: DRIVER_UNLOCK()\n", __FILE__, __LINE__); \
				spin_unlock_irqrestore(&crypto_drivers_lock, d_flags); \
			 })
static struct cryptocap *crypto_drivers = NULL;
static int crypto_drivers_num = 0;

/*
 * There are two queues for crypto requests; one for symmetric (e.g.
 * cipher) operations and one for asymmetric (e.g. MOD)operations.
 * A single mutex is used to lock access to both queues.  We could
 * have one per-queue but having one simplifies handling of block/unblock
 * operations.
 */
static LIST_HEAD(crp_q);		/* request queues */
static LIST_HEAD(crp_kq);

static int crypto_q_locked = 0;	/* on !SMP systems, spin locks do nothing :-( */
static spinlock_t crypto_q_lock;
#define	CRYPTO_Q_LOCK() \
			({ \
				spin_lock_irqsave(&crypto_q_lock, q_flags); \
			 	dprintk("%s,%d: Q_LOCK()\n", __FILE__, __LINE__); \
				crypto_q_locked++; \
			 })
#define	CRYPTO_Q_UNLOCK() \
			({ \
			 	dprintk("%s,%d: Q_UNLOCK()\n", __FILE__, __LINE__); \
				crypto_q_locked--; \
				spin_unlock_irqrestore(&crypto_q_lock, q_flags); \
			 })

/*
 * There are two queues for processing completed crypto requests; one
 * for the symmetric and one for the asymmetric ops.  We only need one
 * but have two to avoid type futzing (cryptop vs. cryptkop).  A single
 * mutex is used to lock access to both queues.  Note that this lock
 * must be separate from the lock on request queues to insure driver
 * callbacks don't generate lock order reversals.
 */
static LIST_HEAD(crp_ret_q);		/* callback queues */
static LIST_HEAD(crp_ret_kq);

static spinlock_t crypto_ret_q_lock;
#define	CRYPTO_RETQ_LOCK() \
			({ \
				spin_lock_irqsave(&crypto_ret_q_lock, r_flags); \
				dprintk("%s,%d: RETQ_LOCK\n", __FILE__, __LINE__); \
			 })
#define	CRYPTO_RETQ_UNLOCK() \
			({ \
			 	dprintk("%s,%d: RETQ_UNLOCK\n", __FILE__, __LINE__); \
				spin_unlock_irqrestore(&crypto_ret_q_lock, r_flags); \
			 })

static kmem_cache_t *cryptop_zone;
static kmem_cache_t *cryptodesc_zone;

static int debug = 0;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug,
	   "Enable debug");

/*
 * Maximum number of outstanding crypto requests before we start
 * failing requests.  We need this to prevent DOS when too many
 * requests are arriving for us to keep up.  Otherwise we will
 * run the system out of memory.  Since crypto is slow,  we are
 * usually the bottleneck that needs to say, enough is enough.
 *
 * We cannot print errors when this condition occurs,  we are already too
 * slow,  printing anything will just kill us
 */

static atomic_t crypto_q_cnt;
static int crypto_q_max = 1000;
module_param(crypto_q_max, int, 0644);
MODULE_PARM_DESC(crypto_q_max,
		"Maximum number of outstanding crypto requests");

/*
 * for extern files to get at the ocf drivers version of debug
 */
int *crypto_debug = &debug;
EXPORT_SYMBOL(crypto_debug);

static int crypto_verbose = 0;
module_param(crypto_verbose, int, 0644);
MODULE_PARM_DESC(crypto_verbose,
	   "Enable verbose crypto startup");

static int	crypto_userasymcrypto = 1;	/* userland may do asym crypto reqs */
module_param(crypto_userasymcrypto, int, 0644);
MODULE_PARM_DESC(crypto_userasymcrypto,
	   "Enable/disable user-mode access to asymmetric crypto support");

static int	crypto_devallowsoft = 0;	/* only use hardware crypto for asym */
module_param(crypto_devallowsoft, int, 0644);
MODULE_PARM_DESC(crypto_devallowsoft,
	   "Enable/disable use of software asym crypto support");

static pid_t	cryptoproc = (pid_t) -1;
static struct	completion cryptoproc_exited;
static DECLARE_WAIT_QUEUE_HEAD(cryptoproc_wait);
static pid_t	cryptoretproc = (pid_t) -1;
static struct	completion cryptoretproc_exited;
static DECLARE_WAIT_QUEUE_HEAD(cryptoretproc_wait);

static	int crypto_proc(void *arg);
static	int crypto_ret_proc(void *arg);
static	int crypto_invoke(struct cryptop *crp, int hint);
static	int crypto_kinvoke(struct cryptkop *krp, int hint);
static	void crypto_exit(void);
static  int crypto_init(void);

static	struct cryptostats cryptostats;


/*
 * Create a new session.
 */
int
crypto_newsession(u_int64_t *sid, struct cryptoini *cri, enum cryptodev_selection desired_device)
{
	struct cryptoini *cr;
	u_int32_t hid, lid;
	int err = EINVAL;
	unsigned long d_flags;
	struct cryptocap *cap = NULL;

	if (!crypto_initted) {
		int i = crypto_init();
		if (i) {
			printk("crypto: failed to init crypto (%d)!\n", i);
			return(-1);
		}
	}

	dprintk("%s(desired=%d)\n", __FUNCTION__, desired_device);
	CRYPTO_DRIVER_LOCK();

	if (crypto_drivers == NULL || crypto_drivers_num==0) {
		dprintk("%s,%d: %s - no drivers\n", __FILE__, __LINE__, __FUNCTION__);
		goto done;
	}

	/*
	 * The algorithm we use here is pretty stupid; just use the
	 * first driver that supports all the algorithms we need,
	 * unless the caller has been explicit about what they want.
	 *
	 * XXX We need more smarts here (in real life too, but that's
	 * XXX another story altogether).
	 */

	if(desired_device >= 0) {
		if(desired_device >= crypto_drivers_num ||
		   (cap = &crypto_drivers[desired_device]) == NULL ||
		   cap->cc_newsession == NULL ||
		   cap->cc_flags & CRYPTOCAP_F_CLEANUP) {
			err = ENOENT;
			goto done;
		}
		hid = cap->cc_hid;
	}
		
	if(desired_device < 0) {
		for (hid = 0; hid < crypto_drivers_num; hid++) {
			dprintk("trying hid=%d\n", hid);
			cap = &crypto_drivers[hid];
			/*
			 * If it's not initialized or has remaining sessions
			 * referencing it, skip.
			 */
			if (cap->cc_newsession == NULL ||
			    (cap->cc_flags & CRYPTOCAP_F_CLEANUP)) {
				dprintk("%s,%d: %s hid=%d %d 0x%x\n", __FILE__, __LINE__,
					__FUNCTION__, hid, cap->cc_newsession == NULL,
					cap->cc_flags & CRYPTOCAP_F_CLEANUP);
				continue;
			}
			
			/* Hardware required -- ignore software drivers. */
			if (desired_device==CRYPTO_ANYHARDWARE && (cap->cc_flags & CRYPTOCAP_F_SOFTWARE)) {
				dprintk("%s,%d: %s skip not HW\n",__FILE__,__LINE__,__FUNCTION__);
				continue;
			}
			/* Software required -- ignore hardware drivers. */
			if (desired_device==CRYPTO_ANYSOFTWARE && (cap->cc_flags & CRYPTOCAP_F_SOFTWARE) == 0) {
				dprintk("%s,%d: %s skip not SW\n",__FILE__,__LINE__,__FUNCTION__);
				continue;
			}
			
			/* See if all the algorithms are supported. */
			for (cr = cri; cr; cr = cr->cri_next) {
				if (cap->cc_alg[cr->cri_alg] == 0) {
					dprintk("%s,%d: %s alg %d not supported\n",
						__FILE__, __LINE__, __FUNCTION__, cr->cri_alg);
					break;
				}
			}

			if(cr == NULL) break;
		}

		/* if we found nothing, clear cap */
		if(hid == crypto_drivers_num) cap=NULL;
	}
			
	if (cap != NULL) {
		/* Ok, all algorithms are supported. */
		
		/*
		 * Can't do everything in one session.
		 *
		 * XXX Fix this. We need to inject a "virtual" session layer right
		 * XXX about here.
		 */
		
		/*
		 * up the number of sessions before we unlock so that this
		 * cap does not go away while we are busy,  we unlock so that
		 * newsession may sleep (for whatever reason, alloc etc).
		 */
		cap->cc_sessions++;
		CRYPTO_DRIVER_UNLOCK();
		
		/* Call the driver initialization routine. */
		lid = hid;		/* Pass the driver ID. */
		err = -99;

		/* just paranoia here */
		if(cap->cc_newsession) {
			err = (*cap->cc_newsession)(cap->cc_arg, &lid, cri);
		}

		if (err == 0) {
			/* XXX assert (hid &~ 0xffffff) == 0 */
			/* XXX assert (cap->cc_flags &~ 0xff) == 0 */
			(*sid) = ((cap->cc_flags & 0xff) << 24) | hid;
			(*sid) <<= 32;
			(*sid) |= (lid & 0xffffffff);
		} else {
			dprintk("%s,%d: %s - newsession returned %d\n",
				__FILE__, __LINE__, __FUNCTION__, err);
			cap->cc_sessions--;
			if ((cap->cc_flags & CRYPTOCAP_F_CLEANUP) &&
			    cap->cc_sessions == 0)
				memset(cap, 0, sizeof(struct cryptocap));
		}
		return err;
	}
done:
	CRYPTO_DRIVER_UNLOCK();
	return err;
}

/*
 * Delete an existing session (or a reserved session on an unregistered
 * driver).
 */
int
crypto_freesession(u_int64_t sid)
{
	u_int32_t hid;
	int err;
	unsigned long d_flags;

	dprintk("%s()\n", __FUNCTION__);
	CRYPTO_DRIVER_LOCK();

	if (crypto_drivers == NULL) {
		err = EINVAL;
		goto done;
	}

	/* Determine two IDs. */
	hid = CRYPTO_SESID2HID(sid);

	if (hid >= crypto_drivers_num) {
		dprintk("%s - INVALID DRIVER NUM %d\n", __FUNCTION__, hid);
		err = ENOENT;
		goto done;
	}

	if (crypto_drivers[hid].cc_sessions)
		crypto_drivers[hid].cc_sessions--;

	/* Call the driver cleanup routine, if available. */
	if (crypto_drivers[hid].cc_freesession)
		err = crypto_drivers[hid].cc_freesession(
				crypto_drivers[hid].cc_arg, sid);
	else
		err = 0;

	/*
	 * If this was the last session of a driver marked as invalid,
	 * make the entry available for reuse.
	 */
	if ((crypto_drivers[hid].cc_flags & CRYPTOCAP_F_CLEANUP) &&
	    crypto_drivers[hid].cc_sessions == 0)
		memset(&crypto_drivers[hid], 0, sizeof(struct cryptocap));

done:
	CRYPTO_DRIVER_UNLOCK();
	return err;
}

void crypto_devicename(u_int64_t sid, char *namebuf)
{
	u_int32_t hid;
	int err;
	unsigned long d_flags;

	dprintk("%s()\n", __FUNCTION__);
	CRYPTO_DRIVER_LOCK();

	if (crypto_drivers == NULL) {
		err = EINVAL;
		goto done;
	}

	/* Determine two IDs. */
	hid = CRYPTO_SESID2HID(sid);

	if (hid >= crypto_drivers_num) {
		dprintk("%s - INVALID DRIVER NUM %d\n", __FUNCTION__, hid);
		err = ENOENT;
		goto done;
	}

	namebuf[0]='\0';
	strncpy(namebuf, crypto_drivers[hid].cc_name, sizeof(crypto_drivers[hid].cc_name));

done:
	CRYPTO_DRIVER_UNLOCK();
	return;
}

/*
 * sets the cc_hid to element number.
 */
static void crypto_init_drivernum(void)
{
	int i; 
	
	for(i=0; i<crypto_drivers_num; i++) {
		crypto_drivers[i].cc_hid = i;
	}
}
			
/*
 * Return an unused driver id.  Used by drivers prior to registering
 * support for the algorithms they handle.
 */
int32_t
crypto_get_driverid(u_int32_t flags, char *drivername)
{
	struct cryptocap *newdrv;
	int i;
	unsigned long d_flags;

	dprintk("%s()\n", __FUNCTION__);

	if (!crypto_initted) {
		i = crypto_init();
		if (i) {
			printk("crypto: failed to init crypto (%d)!\n", i);
			return(-1);
		}
	}

	CRYPTO_DRIVER_LOCK();

	if(flags & CRYPTOCAP_F_SOFTWARE) {
		i = 0;
		if(i > crypto_drivers_num) {
			crypto_drivers_num = i;
		}
	} else {
		/* unit 0 is always reserved for software */
		for (i = 1; i < crypto_drivers_num; i++)
			if (crypto_drivers[i].cc_process == NULL &&
			    (crypto_drivers[i].cc_flags & CRYPTOCAP_F_CLEANUP) == 0 &&
			    crypto_drivers[i].cc_sessions == 0)
				break;
	}

	/* Out of entries, allocate some more. */
	if (i >= crypto_drivers_num) {
		int new_num = crypto_drivers_num;

		if(new_num == 0) new_num=1;

		while(i >= new_num) {
			new_num = new_num * 2;
			/* Be careful about wrap-around. */
			if (new_num <= crypto_drivers_num) {
				CRYPTO_DRIVER_UNLOCK();
				printk("crypto: driver count wraparound!\n");
				return -1;
			}
		}

		newdrv = kmalloc(new_num * sizeof(struct cryptocap),
				 GFP_KERNEL);
		if (newdrv == NULL) {
			CRYPTO_DRIVER_UNLOCK();
			printk("crypto: no space to expand driver table!\n");
			return -1;
		}

		memcpy(newdrv, crypto_drivers,
				crypto_drivers_num * sizeof(struct cryptocap));
		memset(&crypto_drivers[crypto_drivers_num], 0,
		       (new_num-crypto_drivers_num)* sizeof(struct cryptocap));

		crypto_drivers_num = new_num;

		kfree(crypto_drivers);
		crypto_drivers = newdrv;
		crypto_init_drivernum();
	}

	/* NB: state is zero'd on free */
	crypto_drivers[i].cc_sessions = 1;	/* Mark */
	crypto_drivers[i].cc_flags = flags;
	crypto_drivers[i].cc_name[0]='\0';
	strncpy(crypto_drivers[i].cc_name, drivername, sizeof(crypto_drivers[i].cc_name));
	if (crypto_verbose)
		printk("crypto: assign driver %u, flags %u\n", i, flags);

	CRYPTO_DRIVER_UNLOCK();

	return i;
}

static struct cryptocap *
crypto_checkdriver(u_int32_t hid)
{
	dprintk("%s(hid=%d)\n", __FUNCTION__, hid);
	if (crypto_drivers == NULL) {
		dprintk("%s,%d: %s no drivers\n", __FILE__, __LINE__, __FUNCTION__);
		return NULL;
	}
	return (hid >= crypto_drivers_num ? NULL : &crypto_drivers[hid]);
}

/*
 * Register support for a key-related algorithm.  This routine
 * is called once for each algorithm supported a driver.
 */
int
crypto_kregister(u_int32_t driverid, int kalg, u_int32_t flags,
    int (*kprocess)(void*, struct cryptkop *, int),
    void *karg)
{
	struct cryptocap *cap;
	int err;
	unsigned long d_flags;

	dprintk("%s()\n", __FUNCTION__);
	CRYPTO_DRIVER_LOCK();

	cap = crypto_checkdriver(driverid);
	if (cap != NULL &&
	    (CRK_ALGORITM_MIN <= kalg && kalg <= CRK_ALGORITHM_MAX)) {
		/*
		 * XXX Do some performance testing to determine placing.
		 * XXX We probably need an auxiliary data structure that
		 * XXX describes relative performances.
		 */

		cap->cc_kalg[kalg] = flags | CRYPTO_ALG_FLAG_SUPPORTED;
		if (crypto_verbose)
			printk("crypto: driver %u registers key alg %u flags %u\n"
				, driverid
				, kalg
				, flags
			);

		if (cap->cc_kprocess == NULL) {
			cap->cc_karg = karg;
			cap->cc_kprocess = kprocess;
		}
		err = 0;
	} else
		err = EINVAL;

	CRYPTO_DRIVER_UNLOCK();
	return err;
}

/*
 * Register support for a non-key-related algorithm.  This routine
 * is called once for each such algorithm supported by a driver.
 */
int
crypto_register(u_int32_t driverid, int alg, u_int16_t maxoplen,
    u_int32_t flags,
    int (*newses)(void*, u_int32_t*, struct cryptoini*),
    int (*freeses)(void*, u_int64_t),
    int (*process)(void*, struct cryptop *, int),
    void *arg)
{
	struct cryptocap *cap;
	int err;
	unsigned long d_flags;

	dprintk("%s(id=0x%x, alg=%d, maxoplen=%d, flags=0x%x, newses=%p, "
			"freeses=%p, process=%p, arg=%p)\n", __FUNCTION__,
			driverid, alg, maxoplen, flags, newses, freeses, process, arg);
	CRYPTO_DRIVER_LOCK();

	cap = crypto_checkdriver(driverid);
	/* NB: algorithms are in the range [1..max] */
	if (cap != NULL &&
	    (CRYPTO_ALGORITHM_MIN <= alg && alg <= CRYPTO_ALGORITHM_MAX)) {
		/*
		 * XXX Do some performance testing to determine placing.
		 * XXX We probably need an auxiliary data structure that
		 * XXX describes relative performances.
		 */

		cap->cc_alg[alg] = flags | CRYPTO_ALG_FLAG_SUPPORTED;
		cap->cc_max_op_len[alg] = maxoplen;
		if (crypto_verbose)
			printk("crypto: driver %u registers alg %u flags %u maxoplen %u\n"
				, driverid
				, alg
				, flags
				, maxoplen
			);

		if (cap->cc_process == NULL) {
			dprintk("%s - add drivers routines\n", __FUNCTION__);
			cap->cc_arg = arg;
			cap->cc_newsession = newses;
			dprintk("%s - newsession = %p\n", __FUNCTION__, cap->cc_newsession);
			cap->cc_process = process;
			cap->cc_freesession = freeses;
			cap->cc_sessions = 0;		/* Unmark */
		}
		err = 0;
	} else
		err = EINVAL;

	CRYPTO_DRIVER_UNLOCK();
	return err;
}

/*
 * Unregister a crypto driver. If there are pending sessions using it,
 * leave enough information around so that subsequent calls using those
 * sessions will correctly detect the driver has been unregistered and
 * reroute requests.
 */
int
crypto_unregister(u_int32_t driverid, int alg)
{
	int i, err;
	unsigned long d_flags;
	u_int32_t ses;
	struct cryptocap *cap;

	dprintk("%s()\n", __FUNCTION__);
	CRYPTO_DRIVER_LOCK();

	cap = crypto_checkdriver(driverid);
	if (cap != NULL &&
	    (CRYPTO_ALGORITHM_MIN <= alg && alg <= CRYPTO_ALGORITHM_MAX) &&
	    cap->cc_alg[alg] != 0) {
		cap->cc_alg[alg] = 0;
		cap->cc_max_op_len[alg] = 0;

		/* Was this the last algorithm ? */
		for (i = 1; i <= CRYPTO_ALGORITHM_MAX; i++)
			if (cap->cc_alg[i] != 0)
				break;

		if (i == CRYPTO_ALGORITHM_MAX + 1) {
			ses = cap->cc_sessions;
			memset(cap, 0, sizeof(struct cryptocap));
			if (ses != 0) {
				/*
				 * If there are pending sessions, just mark as invalid.
				 */
				cap->cc_flags |= CRYPTOCAP_F_CLEANUP;
				cap->cc_sessions = ses;
			}
		}
		err = 0;
	} else
		err = EINVAL;

	CRYPTO_DRIVER_UNLOCK();
	return err;
}

/*
 * Unregister all algorithms associated with a crypto driver.
 * If there are pending sessions using it, leave enough information
 * around so that subsequent calls using those sessions will
 * correctly detect the driver has been unregistered and reroute
 * requests.
 */
int
crypto_unregister_all(u_int32_t driverid)
{
	int i, err;
	unsigned long d_flags;
	u_int32_t ses;
	struct cryptocap *cap;

	dprintk("%s()\n", __FUNCTION__);
	CRYPTO_DRIVER_LOCK();

	cap = crypto_checkdriver(driverid);
	if (cap != NULL) {
		crypto_runregister_all(driverid);
	}
	if (cap != NULL) {
		for (i = CRYPTO_ALGORITHM_MIN; i <= CRYPTO_ALGORITHM_MAX; i++) {
			cap->cc_alg[i] = 0;
			cap->cc_max_op_len[i] = 0;
		}
		ses = cap->cc_sessions;
		memset(cap, 0, sizeof(struct cryptocap));
		if (ses != 0) {
			/*
			 * If there are pending sessions, just mark as invalid.
			 */
			cap->cc_flags |= CRYPTOCAP_F_CLEANUP;
			cap->cc_sessions = ses;
		}
		err = 0;
	} else
		err = EINVAL;

	CRYPTO_DRIVER_UNLOCK();
	return err;
}

/*
 * Clear blockage on a driver.  The what parameter indicates whether
 * the driver is now ready for cryptop's and/or cryptokop's.
 */
int
crypto_unblock(u_int32_t driverid, int what)
{
	struct cryptocap *cap;
	int needwakeup, err;
	unsigned long q_flags;

	dprintk("%s()\n", __FUNCTION__);
	CRYPTO_Q_LOCK();
	cap = crypto_checkdriver(driverid);
	if (cap != NULL) {
		needwakeup = 0;
		if (what & CRYPTO_SYMQ) {
			needwakeup |= cap->cc_qblocked;
			cap->cc_qblocked = 0;
		}
		if (what & CRYPTO_ASYMQ) {
			needwakeup |= cap->cc_kqblocked;
			cap->cc_kqblocked = 0;
		}
		if (needwakeup)
			wake_up_interruptible(&cryptoproc_wait);
		err = 0;
	} else
		err = EINVAL;
	CRYPTO_Q_UNLOCK();

	return err;
}

/*
 * Add a crypto request to a queue, to be processed by the kernel thread.
 */
int
crypto_dispatch(struct cryptop *crp)
{
	u_int32_t hid = CRYPTO_SESID2HID(crp->crp_sid);
	int result;
	unsigned long q_flags;
	struct cryptocap *cap;

	dprintk("%s()\n", __FUNCTION__);

	cryptostats.cs_ops++;

	if (atomic_read(&crypto_q_cnt) >= crypto_q_max) {
		cryptostats.cs_drops++;
		return ENOMEM;
	}
	atomic_inc(&crypto_q_cnt);

	cap = crypto_checkdriver(hid);

	CRYPTO_Q_LOCK();
	/*
	 * always batch requests to the software drivers so that we
	 * do not hold locks for too long
	 */
	if (cap && (cap->cc_flags & CRYPTOCAP_F_SOFTWARE) == 0 &&
			(crp->crp_flags & CRYPTO_F_BATCH) == 0) {
		/*
		 * Caller marked the request to be processed
		 * immediately; dispatch it directly to the
		 * driver unless the driver is currently blocked.
		 */
		if (cap && !cap->cc_qblocked) {
			CRYPTO_Q_UNLOCK();
			result = crypto_invoke(crp, 0);
			CRYPTO_Q_LOCK();
			if (result == ERESTART) {
				/*
				 * The driver ran out of resources, mark the
				 * driver ``blocked'' for cryptop's and put
				 * the request on the queue.
				 *
				 * XXX ops are placed at the tail so their
				 * order is preserved but this can place them
				 * behind batch'd ops.
				 */
				crypto_drivers[hid].cc_qblocked = 1;
				list_add_tail(&crp->crp_list, &crp_q);
				cryptostats.cs_blocks++;
				result = 0;
			}
		} else {
			/*
			 * The driver is blocked, just queue the op until
			 * it unblocks and the kernel thread gets kicked.
			 */
			list_add_tail(&crp->crp_list, &crp_q);
			result = 0;
		}
	} else {
		int wasempty;
		/*
		 * Caller marked the request as ``ok to delay'';
		 * queue it for the dispatch thread.  This is desirable
		 * when the operation is low priority and/or suitable
		 * for batching.
		 */
		wasempty = list_empty(&crp_q);
		list_add_tail(&crp->crp_list, &crp_q);
		if (wasempty)
			wake_up_interruptible(&cryptoproc_wait);
		result = 0;
	}
	if (result != 0)
		atomic_dec(&crypto_q_cnt);
	CRYPTO_Q_UNLOCK();

	return result;
}

/*
 * Add an asymetric crypto request to a queue,
 * to be processed by the kernel thread.
 */
int
crypto_kdispatch(struct cryptkop *krp)
{
	struct cryptocap *cap;
	int result;
	unsigned long q_flags;

	dprintk("%s()\n", __FUNCTION__);
	cryptostats.cs_kops++;

	CRYPTO_Q_LOCK();
	cap = crypto_checkdriver(krp->krp_hid);
	if (cap && !cap->cc_kqblocked) {
		CRYPTO_Q_UNLOCK();
		result = crypto_kinvoke(krp, 0);
		CRYPTO_Q_LOCK();
		if (result == ERESTART) {
			/*
			 * The driver ran out of resources, mark the
			 * driver ``blocked'' for cryptkop's and put
			 * the request back in the queue.  It would
			 * best to put the request back where we got
			 * it but that's hard so for now we put it
			 * at the front.  This should be ok; putting
			 * it at the end does not work.
			 */
			crypto_drivers[krp->krp_hid].cc_kqblocked = 1;
			list_add_tail(&krp->krp_list, &crp_kq);
			cryptostats.cs_kblocks++;
		}
	} else {
		/*
		 * The driver is blocked, just queue the op until
		 * it unblocks and the kernel thread gets kicked.
		 */
		list_add_tail(&krp->krp_list, &crp_kq);
		result = 0;
	}
	CRYPTO_Q_UNLOCK();

	return result;
}

/*
 * Dispatch an assymetric crypto request to the appropriate crypto devices.
 */
static int
crypto_kinvoke(struct cryptkop *krp, int hint)
{
	u_int32_t hid;
	int error;

	dprintk("%s()\n", __FUNCTION__);

	/* Sanity checks. */
	if (krp == NULL) {
		dprintk("%s,%d: null krp\n", __FILE__, __LINE__);
		return EINVAL;
	}
	if (krp->krp_callback == NULL) {
		dprintk("%s,%d: null krp_callback\n", __FILE__, __LINE__);
		kfree(krp);		/* XXX allocated in cryptodev */
		return EINVAL;
	}

	for (hid = 0; hid < crypto_drivers_num; hid++) {
		if ((crypto_drivers[hid].cc_flags & CRYPTOCAP_F_SOFTWARE) &&
		    !crypto_devallowsoft)
			continue;
		if (crypto_drivers[hid].cc_kprocess == NULL)
			continue;
		if ((crypto_drivers[hid].cc_kalg[krp->krp_op] &
		    CRYPTO_ALG_FLAG_SUPPORTED) == 0)
			continue;
		break;
	}
	if (hid < crypto_drivers_num) {
		krp->krp_hid = hid;
		error = crypto_drivers[hid].cc_kprocess(
				crypto_drivers[hid].cc_karg, krp, hint);
	} else {
		dprintk("%s,%d: ENODEV\n", __FILE__, __LINE__);
		error = ENODEV;
	}

	if (error) {
		krp->krp_status = error;
		crypto_kdone(krp);
	}
	return 0;
}


/*
 * Dispatch a crypto request to the appropriate crypto devices.
 */
static int
crypto_invoke(struct cryptop *crp, int hint)
{
	u_int32_t hid;
	int (*process)(void*, struct cryptop *, int);

	dprintk("%s()\n", __FUNCTION__);

	/* Sanity checks. */
	if (crp == NULL)
		return EINVAL;
	if (crp->crp_callback == NULL) {
		crypto_freereq(crp);
		return EINVAL;
	}
	if (crp->crp_desc == NULL) {
		crp->crp_etype = EINVAL;
		crypto_done(crp);
		return 0;
	}

	hid = CRYPTO_SESID2HID(crp->crp_sid);
	if (hid < crypto_drivers_num) {
		if (crypto_drivers[hid].cc_flags & CRYPTOCAP_F_CLEANUP)
			crypto_freesession(crp->crp_sid);
		process = crypto_drivers[hid].cc_process;
	} else {
		printk("%s() found hid(%d) >= crypto_drivers_num(%d)\n",
			__FUNCTION__, hid, crypto_drivers_num);
		process = NULL;
	}

	if (process == NULL) {
		struct cryptodesc *crd;
		u_int64_t nid;

		/*
		 * Driver has unregistered; migrate the session and return
		 * an error to the caller so they'll resubmit the op.
		 */
		for (crd = crp->crp_desc; crd->crd_next; crd = crd->crd_next)
			crd->CRD_INI.cri_next = &(crd->crd_next->CRD_INI);

		if (crypto_newsession(&nid, &(crp->crp_desc->CRD_INI), CRYPTO_ANYDEVICE) == 0)
			crp->crp_sid = nid;

		crp->crp_etype = EAGAIN;
		dprintk("%s() driver EAGAIN\n", __FUNCTION__);
		crypto_done(crp);
		return 0;
	} else {
		/*
		 * Invoke the driver to process the request.
		 */
		return (*process)(crypto_drivers[hid].cc_arg, crp, hint);
	}
}

/*
 * Release a set of crypto descriptors.
 */
void
crypto_freereq(struct cryptop *crp)
{
	struct cryptodesc *crd;

	if (crp == NULL)
		return;

	while ((crd = crp->crp_desc) != NULL) {
		crp->crp_desc = crd->crd_next;
		kmem_cache_free(cryptodesc_zone, crd);
	}

	kmem_cache_free(cryptop_zone, crp);
}

/*
 * Acquire a set of crypto descriptors.
 */
struct cryptop *
crypto_getreq(int num)
{
	struct cryptodesc *crd;
	struct cryptop *crp;

	crp = kmem_cache_alloc(cryptop_zone, SLAB_ATOMIC);
	if (crp != NULL) {
		memset(crp, 0, sizeof(*crp));
		INIT_LIST_HEAD(&crp->crp_list);
		init_waitqueue_head(&crp->crp_waitq);
		while (num--) {
			crd = kmem_cache_alloc(cryptodesc_zone, SLAB_ATOMIC);
			if (crd == NULL) {
				crypto_freereq(crp);
				return NULL;
			}
			memset(crd, 0, sizeof(*crd));
			crd->crd_next = crp->crp_desc;
			crp->crp_desc = crd;
		}
	}
	return crp;
}

/*
 * Invoke the callback on behalf of the driver.
 */
void
crypto_done(struct cryptop *crp)
{
	dprintk("%s()\n", __FUNCTION__);
	if ((crp->crp_flags & CRYPTO_F_DONE) == 0) {
		crp->crp_flags |= CRYPTO_F_DONE;
		atomic_dec(&crypto_q_cnt);
	} else
		printk("crypto: crypto_done op already done, flags 0x%x",
				crp->crp_flags);
	if (crp->crp_etype != 0)
		cryptostats.cs_errs++;
	/*
	 * CBIMM means unconditionally do the callback immediately;
	 * CBIFSYNC means do the callback immediately only if the
	 * operation was done synchronously.  Both are used to avoid
	 * doing extraneous context switches; the latter is mostly
	 * used with the software crypto driver.
	 */
	if ((crp->crp_flags & CRYPTO_F_CBIMM) ||
	    ((crp->crp_flags & CRYPTO_F_CBIFSYNC) &&
	     (CRYPTO_SESID2CAPS(crp->crp_sid) & CRYPTOCAP_F_SYNC))) {
		/*
		 * Do the callback directly.  This is ok when the
		 * callback routine does very little (e.g. the
		 * /dev/crypto callback method just does a wakeup).
		 */
		crp->crp_callback(crp);
	} else {
		int wasempty;
		unsigned long r_flags;
		/*
		 * Normal case; queue the callback for the thread.
		 */
		CRYPTO_RETQ_LOCK();
		wasempty = list_empty(&crp_ret_q);
		list_add_tail(&crp->crp_list, &crp_ret_q);

		if (wasempty)
			wake_up_interruptible(&cryptoretproc_wait);	/*shared wait channel */
		CRYPTO_RETQ_UNLOCK();
	}
}

/*
 * Invoke the callback on behalf of the driver.
 */
void
crypto_kdone(struct cryptkop *krp)
{
	if ((krp->krp_flags & CRYPTO_KF_DONE) != 0)
		printk("crypto: crypto_kdone op already done, flags 0x%x",
				krp->krp_flags);
	krp->krp_flags |= CRYPTO_KF_DONE;
	if (krp->krp_status != 0)
		cryptostats.cs_kerrs++;

	/*
	 * CBIMM means unconditionally do the callback immediately;
	 * This is used to avoid doing extraneous context switches
	 */
	if ((krp->krp_flags & CRYPTO_KF_CBIMM)) {
		/*
		 * Do the callback directly.  This is ok when the
		 * callback routine does very little (e.g. the
		 * /dev/crypto callback method just does a wakeup).
		 */
		krp->krp_callback(krp);
	} else {
		int wasempty;
		unsigned long r_flags;

		/*
		 * Normal case; queue the callback for the thread.
		 */
		CRYPTO_RETQ_LOCK();
		wasempty = list_empty(&crp_ret_kq);
		list_add_tail(&krp->krp_list, &crp_ret_kq);

		if (wasempty)
			wake_up_interruptible(&cryptoretproc_wait);/* shared wait channel */
		CRYPTO_RETQ_UNLOCK();
	}
}

int
crypto_getfeat(int *featp)
{
	int hid, kalg, feat = 0;
	unsigned long d_flags;

	if (!crypto_userasymcrypto)
		goto out;	  

	CRYPTO_DRIVER_LOCK();
	for (hid = 0; hid < crypto_drivers_num; hid++) {
		if ((crypto_drivers[hid].cc_flags & CRYPTOCAP_F_SOFTWARE) &&
		    !crypto_devallowsoft) {
			continue;
		}
		if (crypto_drivers[hid].cc_kprocess == NULL)
			continue;
		for (kalg = 0; kalg < CRK_ALGORITHM_MAX; kalg++)
			if ((crypto_drivers[hid].cc_kalg[kalg] &
			    CRYPTO_ALG_FLAG_SUPPORTED) != 0)
				feat |=  1 << kalg;
	}
	CRYPTO_DRIVER_UNLOCK();
out:
	*featp = feat;
	return (0);
}

/*
 * Crypto thread, dispatches crypto requests.
 */
static int
crypto_proc(void *arg)
{
	struct cryptop *crp, *submit;
	struct cryptkop *krp, *krpp;
	struct cryptocap *cap;
	int result, hint;
	unsigned long q_flags;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	daemonize();
	spin_lock_irq(&current->sigmask_lock);
	sigemptyset(&current->blocked);
	recalc_sigpending(current);
	spin_unlock_irq(&current->sigmask_lock);
	sprintf(current->comm, "crypto");
#else
	daemonize("crypto");
#endif

	CRYPTO_Q_LOCK();
	for (;;) {
		/*
		 * Find the first element in the queue that can be
		 * processed and look-ahead to see if multiple ops
		 * are ready for the same driver.
		 */
		submit = NULL;
		hint = 0;
		list_for_each_entry(crp, &crp_q, crp_list) {
			u_int32_t hid = CRYPTO_SESID2HID(crp->crp_sid);
			cap = crypto_checkdriver(hid);
			if (cap == NULL || cap->cc_process == NULL) {
				/* Op needs to be migrated, process it. */
				if (submit == NULL)
					submit = crp;
				break;
			}
			if (!cap->cc_qblocked) {
				if (submit != NULL) {
					/*
					 * We stop on finding another op,
					 * regardless whether its for the same
					 * driver or not.  We could keep
					 * searching the queue but it might be
					 * better to just use a per-driver
					 * queue instead.
					 */
					if (CRYPTO_SESID2HID(submit->crp_sid) == hid)
						hint = CRYPTO_HINT_MORE;
					break;
				} else {
					submit = crp;
					if ((submit->crp_flags & CRYPTO_F_BATCH) == 0)
						break;
					/* keep scanning for more are q'd */
				}
			}
		}
		if (submit != NULL) {
			list_del(&submit->crp_list);
			CRYPTO_Q_UNLOCK();
			result = crypto_invoke(submit, hint);
			CRYPTO_Q_LOCK();
			if (result == ERESTART) {
				/*
				 * The driver ran out of resources, mark the
				 * driver ``blocked'' for cryptop's and put
				 * the request back in the queue.  It would
				 * best to put the request back where we got
				 * it but that's hard so for now we put it
				 * at the front.  This should be ok; putting
				 * it at the end does not work.
				 */
				/* XXX validate sid again? */
				crypto_drivers[CRYPTO_SESID2HID(submit->crp_sid)].cc_qblocked = 1;
				list_add(&submit->crp_list, &crp_q);
				cryptostats.cs_blocks++;
			}
		}

		/* As above, but for key ops */
		krp = NULL;
		list_for_each_entry(krpp, &crp_kq, krp_list) {
			cap = crypto_checkdriver(krpp->krp_hid);
			if (cap == NULL || cap->cc_kprocess == NULL) {
				/* Op needs to be migrated, process it. */
				krp = krpp;
				break;
			}
			if (!cap->cc_kqblocked) {
				krp = krpp;
				break;
			}
		}
		if (krp != NULL) {
			list_del(&krp->krp_list);
			CRYPTO_Q_UNLOCK();
			result = crypto_kinvoke(krp, 0);
			CRYPTO_Q_LOCK();
			if (result == ERESTART) {
				/*
				 * The driver ran out of resources, mark the
				 * driver ``blocked'' for cryptkop's and put
				 * the request back in the queue.  It would
				 * best to put the request back where we got
				 * it but that's hard so for now we put it
				 * at the front.  This should be ok; putting
				 * it at the end does not work.
				 */
				/* XXX validate sid again? */
				crypto_drivers[krp->krp_hid].cc_kqblocked = 1;
				list_add(&krp->krp_list, &crp_kq);
				cryptostats.cs_kblocks++;
			}
		}

		if (submit == NULL && krp == NULL) {
			/*
			 * Nothing more to be processed.  Sleep until we're
			 * woken because there are more ops to process.
			 * This happens either by submission or by a driver
			 * becoming unblocked and notifying us through
			 * crypto_unblock.  Note that when we wakeup we
			 * start processing each queue again from the
			 * front. It's not clear that it's important to
			 * preserve this ordering since ops may finish
			 * out of order if dispatched to different devices
			 * and some become blocked while others do not.
			 */
			dprintk("%s - sleeping\n", __FUNCTION__);
			CRYPTO_Q_UNLOCK();
			wait_event_interruptible(cryptoproc_wait,
					cryptoproc == (pid_t) -1 ||
					!list_empty(&crp_q) ||
					!list_empty(&crp_kq));
			if (signal_pending (current)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
				spin_lock_irq(&current->sigmask_lock);
#endif
				flush_signals(current);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
				spin_unlock_irq(&current->sigmask_lock);
#endif
			}
			CRYPTO_Q_LOCK();
			dprintk("%s - awake\n", __FUNCTION__);
			if (cryptoproc == (pid_t) -1)
				break;
			cryptostats.cs_intrs++;
		}
	}
	CRYPTO_Q_UNLOCK();
	complete_and_exit(&cryptoproc_exited, 0);
}

/*
 * Crypto returns thread, does callbacks for processed crypto requests.
 * Callbacks are done here, rather than in the crypto drivers, because
 * callbacks typically are expensive and would slow interrupt handling.
 */
static int
crypto_ret_proc(void *arg)
{
	struct cryptop *crpt;
	struct cryptkop *krpt;
	unsigned long  r_flags;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	daemonize();
	spin_lock_irq(&current->sigmask_lock);
	sigemptyset(&current->blocked);
	recalc_sigpending(current);
	spin_unlock_irq(&current->sigmask_lock);
	sprintf(current->comm, "crypto_ret");
#else
	daemonize("crypto_ret");
#endif

	CRYPTO_RETQ_LOCK();
	for (;;) {
		/* Harvest return q's for completed ops */
		crpt = NULL;
		if (!list_empty(&crp_ret_q))
			crpt = list_entry(crp_ret_q.next, typeof(*crpt), crp_list);
		if (crpt != NULL)
			list_del(&crpt->crp_list);

		krpt = NULL;
		if (!list_empty(&crp_ret_kq))
			krpt = list_entry(crp_ret_kq.next, typeof(*krpt), krp_list);
		if (krpt != NULL)
			list_del(&krpt->krp_list);

		if (crpt != NULL || krpt != NULL) {
			CRYPTO_RETQ_UNLOCK();
			/*
			 * Run callbacks unlocked.
			 */
			if (crpt != NULL)
				crpt->crp_callback(crpt);
			if (krpt != NULL)
				krpt->krp_callback(krpt);
			CRYPTO_RETQ_LOCK();
		} else {
			/*
			 * Nothing more to be processed.  Sleep until we're
			 * woken because there are more returns to process.
			 */
			dprintk("%s - sleeping\n", __FUNCTION__);
			CRYPTO_RETQ_UNLOCK();
			wait_event_interruptible(cryptoretproc_wait,
					cryptoretproc == (pid_t) -1 ||
					!list_empty(&crp_ret_q) ||
					!list_empty(&crp_ret_kq));
			if (signal_pending (current)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
				spin_lock_irq(&current->sigmask_lock);
#endif
				flush_signals(current);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
				spin_unlock_irq(&current->sigmask_lock);
#endif
			}
			CRYPTO_RETQ_LOCK();
			dprintk("%s - awake\n", __FUNCTION__);
			if (cryptoretproc == (pid_t) -1) {
				dprintk("%s - EXITING!\n", __FUNCTION__);
				break;
			}
			cryptostats.cs_rets++;
		}
	}
	CRYPTO_RETQ_UNLOCK();
	complete_and_exit(&cryptoretproc_exited, 0);
}


static int
crypto_init(void)
{
	int error;

	dprintk("%s(0x%x)\n", __FUNCTION__, (int) crypto_init);

	if (crypto_initted)
		return 0;
	crypto_initted = 1;

	atomic_set(&crypto_q_cnt, 0);

	spin_lock_init(&crypto_drivers_lock);
	spin_lock_init(&crypto_q_lock);
	spin_lock_init(&crypto_ret_q_lock);

	cryptop_zone = kmem_cache_create("cryptop", sizeof(struct cryptop),
				       0, SLAB_HWCACHE_ALIGN, NULL, NULL);
	cryptodesc_zone = kmem_cache_create("cryptodesc", sizeof(struct cryptodesc),
				       0, SLAB_HWCACHE_ALIGN, NULL, NULL);
	if (cryptodesc_zone == NULL || cryptop_zone == NULL) {
		printk("crypto: crypto_init cannot setup crypto zones\n");
		error = ENOMEM;
		goto bad;
	}

	crypto_drivers_num = CRYPTO_DRIVERS_INITIAL;
	crypto_drivers = kmalloc(crypto_drivers_num * sizeof(struct cryptocap),
			GFP_KERNEL);
	if (crypto_drivers == NULL) {
		printk("crypto: crypto_init cannot setup crypto drivers\n");
		error = ENOMEM;
		goto bad;
	}

	memset(crypto_drivers, 0, crypto_drivers_num * sizeof(struct cryptocap));
	crypto_init_drivernum();


	init_completion(&cryptoproc_exited);
	init_completion(&cryptoretproc_exited);

	cryptoproc = 0; /* to avoid race condition where proc runs first */
	cryptoproc = kernel_thread(crypto_proc, NULL, CLONE_FS|CLONE_FILES);
	if (cryptoproc < 0) {
		error = cryptoproc;
		printk("crypto: crypto_init cannot start crypto thread; error %d",
			error);
		goto bad;
	}

	cryptoretproc = 0; /* to avoid race condition where proc runs first */
	cryptoretproc = kernel_thread(crypto_ret_proc, NULL, CLONE_FS|CLONE_FILES);
	if (cryptoretproc < 0) {
		error = cryptoretproc;
		printk("crypto: crypto_init cannot start cryptoret thread; error %d",
				error);
		goto bad;
	}

	return 0;
bad:
	crypto_exit();
	return error;
}


static void
crypto_exit(void)
{
	pid_t p;
	unsigned long d_flags;

	dprintk("%s()\n", __FUNCTION__);
	/*
	 * Terminate any crypto threads.
	 */
	CRYPTO_DRIVER_LOCK();

	p = cryptoproc;
	cryptoproc = (pid_t) -1;
	kill_proc(p, SIGTERM, 1);
	wake_up_interruptible(&cryptoproc_wait);
	wait_for_completion(&cryptoproc_exited);

	p = cryptoretproc;
	cryptoretproc = (pid_t) -1;
	kill_proc(p, SIGTERM, 1);
	wake_up_interruptible(&cryptoretproc_wait);
	wait_for_completion(&cryptoretproc_exited);

	CRYPTO_DRIVER_UNLOCK();

	/* XXX flush queues??? */

	/* 
	 * Reclaim dynamically allocated resources.
	 */
	if (crypto_drivers != NULL)
		kfree(crypto_drivers);

	if (cryptodesc_zone != NULL)
		kmem_cache_destroy(cryptodesc_zone);
	if (cryptop_zone != NULL)
		kmem_cache_destroy(cryptop_zone);
}


EXPORT_SYMBOL(crypto_newsession);
EXPORT_SYMBOL(crypto_freesession);
EXPORT_SYMBOL(crypto_get_driverid);
EXPORT_SYMBOL(crypto_kregister);
EXPORT_SYMBOL(crypto_register);
EXPORT_SYMBOL(crypto_unregister);
EXPORT_SYMBOL(crypto_unregister_all);
EXPORT_SYMBOL(crypto_unblock);
EXPORT_SYMBOL(crypto_dispatch);
EXPORT_SYMBOL(crypto_kdispatch);
EXPORT_SYMBOL(crypto_freereq);
EXPORT_SYMBOL(crypto_getreq);
EXPORT_SYMBOL(crypto_done);
EXPORT_SYMBOL(crypto_kdone);
EXPORT_SYMBOL(crypto_getfeat);

module_init(crypto_init);
module_exit(crypto_exit);

MODULE_LICENSE("BSD");
MODULE_AUTHOR("David McCullough <dmccullough@cyberguard.com>");
MODULE_DESCRIPTION("OCF (OpenBSD Cryptographic Framework)");
