/*	$OpenBSD: cryptodev.c,v 1.52 2002/06/19 07:22:46 deraadt Exp $	*/

/*-
 * Linux port done by David McCullough <david_mccullough@au.securecomputing.com>
 * Copyright (C) 2004-2005 Intel Corporation.
 * The license and original author are listed below.
 *
 * Copyright (c) 2001 Theo de Raadt
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Effort sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F30602-01-2-0537.
 *
__FBSDID("$FreeBSD: src/sys/opencrypto/cryptodev.c,v 1.25 2005/02/27 22:10:25 phk Exp $");
 */

#include <linux/config.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/miscdevice.h>
#include <linux/version.h>
#include <linux/uio.h>
#include <asm/uaccess.h>

#include <crypto/cryptodev.h>

static int debug = 0;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug,
	   "Enable debug");

static enum cryptodev_selection crypto_devsel = CRYPTO_ANYDEVICE;
module_param(crypto_devsel, int, 0644);
MODULE_PARM_DESC(crypto_devsel,
	   "Select cryptodev drivers: -1=software only, 1=HW only, 0=any");

struct csession_info {
	u_int16_t	blocksize;
	u_int16_t	minkey, maxkey;

	u_int16_t	keysize;
	/* u_int16_t	hashsize;  */
	u_int16_t	authsize;
	/* u_int16_t	ctxsize; */
};

struct csession {
	struct list_head	list;
	u_int64_t	sid;
	u_int32_t	ses;

	wait_queue_head_t waitq;

	u_int32_t	cipher;

	u_int32_t	mac;

	caddr_t		key;
	int		keylen;
	u_char		tmp_iv[EALG_MAX_BLOCK_LEN];

	caddr_t		mackey;
	int		mackeylen;
	u_char		tmp_mac[CRYPTO_MAX_MAC_LEN];

	struct csession_info info;

	struct iovec	iovec;
	struct uio	uio;
	int		error;
};

struct fcrypt {
	struct list_head	csessions;
	int		sesn;
};

static struct csession *csefind(struct fcrypt *, u_int);
static int csedelete(struct fcrypt *, struct csession *);
static struct csession *cseadd(struct fcrypt *, struct csession *);
static struct csession *csecreate(struct fcrypt *, u_int64_t,
		struct cryptoini *crie, struct cryptoini *cria, struct csession_info *);
static int csefree(struct csession *);

static	int cryptodev_op(struct csession *, struct crypt_op *);
static	int cryptodev_key(struct crypt_kop *);

static int cryptodev_cb(void *);
static int cryptodev_open(struct inode *inode, struct file *filp);

static int
cryptodev_op(struct csession *cse, struct crypt_op *cop)
{
	struct cryptop *crp = NULL;
	struct cryptodesc *crde = NULL, *crda = NULL;
	int error = 0;

	dprintk("%s()\n", __FUNCTION__);
	if (cop->len > 256*1024-4) {
		dprintk("%s: %d > 256k\n", __FUNCTION__, cop->len);
		return (E2BIG);
	}

	if (cse->info.blocksize && (cop->len % cse->info.blocksize) != 0) {
		dprintk("%s: blocksize=%d len=%d\n", __FUNCTION__, cse->info.blocksize,
				cop->len);
		return (EINVAL);
	}

	cse->uio.uio_iov = &cse->iovec;
	cse->uio.uio_iovcnt = 1;
	cse->uio.uio_offset = 0;
#if 0
	cse->uio.uio_resid = cop->len;
	cse->uio.uio_segflg = UIO_SYSSPACE;
	cse->uio.uio_rw = UIO_WRITE;
	cse->uio.uio_td = td;
#endif
	cse->uio.uio_iov[0].iov_len = cop->len;
	cse->uio.uio_iov[0].iov_base = kmalloc(cop->len, GFP_KERNEL);

	crp = crypto_getreq((cse->info.blocksize != 0) + (cse->info.authsize != 0));
	if (crp == NULL) {
		dprintk("%s: ENOMEM\n", __FUNCTION__);
		error = ENOMEM;
		goto bail;
	}

	if (cse->info.authsize) {
		crda = crp->crp_desc;
		if (cse->info.blocksize)
			crde = crda->crd_next;
	} else {
		if (cse->info.blocksize)
			crde = crp->crp_desc;
		else {
			dprintk("%s: bad request\n", __FUNCTION__);
			error = EINVAL;
			goto bail;
		}
	}

	if ((error = copy_from_user(cse->uio.uio_iov[0].iov_base, cop->src,
					cop->len))) {
		dprintk("%s: bad copy\n", __FUNCTION__);
		goto bail;
	}

	if (crda) {
		crda->crd_skip = 0;
		crda->crd_len = cop->len;
		crda->crd_inject = 0;	/* ??? */

		crda->crd_alg = cse->mac;
		crda->crd_key = cse->mackey;
		crda->crd_klen = cse->mackeylen * 8;
	}

	if (crde) {
		if (cop->op == COP_ENCRYPT)
			crde->crd_flags |= CRD_F_ENCRYPT;
		else
			crde->crd_flags &= ~CRD_F_ENCRYPT;
		crde->crd_len = cop->len;
		crde->crd_inject = 0;

		crde->crd_alg = cse->cipher;
		crde->crd_key = cse->key;
		crde->crd_klen = cse->keylen * 8;
	}

	crp->crp_ilen = cop->len;
	crp->crp_flags = CRYPTO_F_IOV | CRYPTO_F_CBIMM
		       | (cop->flags & COP_F_BATCH);
	crp->crp_buf = (caddr_t)&cse->uio;
	crp->crp_callback = (int (*) (struct cryptop *)) cryptodev_cb;
	crp->crp_sid = cse->sid;
	crp->crp_opaque = (void *)cse;

	if (cop->iv) {
		if (crde == NULL) {
			error = EINVAL;
			dprintk("%s no crde\n", __FUNCTION__);
			goto bail;
		}
		if (cse->cipher == CRYPTO_ARC4) { /* XXX use flag? */
			error = EINVAL;
			dprintk("%s arc4 with IV\n", __FUNCTION__);
			goto bail;
		}
		if ((error = copy_from_user(cse->tmp_iv, cop->iv,
					    cse->info.blocksize))) {
			dprintk("%s bad iv copy\n", __FUNCTION__);
			goto bail;
		}
		memcpy(crde->crd_iv, cse->tmp_iv, cse->info.blocksize);
		crde->crd_flags |= CRD_F_IV_EXPLICIT | CRD_F_IV_PRESENT;
		crde->crd_skip = 0;
	} else if (cse->cipher == CRYPTO_ARC4) { /* XXX use flag? */
		crde->crd_skip = 0;
	} else if (crde) {
		crde->crd_flags |= CRD_F_IV_PRESENT;
		crde->crd_skip = cse->info.blocksize;
		crde->crd_len -= cse->info.blocksize;
	}

	if (cop->mac) {
		if (crda == NULL) {
			error = EINVAL;
			dprintk("%s no crda\n", __FUNCTION__);
			goto bail;
		}
		crp->crp_mac=cse->tmp_mac;
		crp->crp_maclen=sizeof(cse->tmp_mac);
	}

	/*
	 * Let the dispatch run unlocked, then, interlock against the
	 * callback before checking if the operation completed and going
	 * to sleep.  This insures drivers don't inherit our lock which
	 * results in a lock order reversal between crypto_dispatch forced
	 * entry and the crypto_done callback into us.
	 */
	error = crypto_dispatch(crp);
	if (error == 0) {
		dprintk("%s about to WAIT\n", __FUNCTION__);
		/*
		 * we really need to wait for driver to complete to maintain
		 * state,  luckily interrupts will be remembered
		 */
		do {
			error = wait_event_interruptible(crp->crp_waitq,
					((crp->crp_flags & CRYPTO_F_DONE) != 0));
			/*
			 * we can't break out of this loop or we will leave behind
			 * a huge mess,  however,  staying here means if your driver
			 * is broken user applications can hang and not be killed.
			 * The solution,  fix your driver :-)
			 *
			 * XXX - MCR says BS, processes should always be killable.
			 */
			if (error) {
				schedule();
				error = 0;
			}
		} while ((crp->crp_flags & CRYPTO_F_DONE) == 0);
		dprintk("%s finished WAITING error=%d\n", __FUNCTION__, error);
	}

	if (crp->crp_etype != 0) {
		error = crp->crp_etype;
		dprintk("%s error in crp processing\n", __FUNCTION__);
		goto bail;
	}

	if (cse->error) {
		error = cse->error;
		dprintk("%s error in cse processing\n", __FUNCTION__);
		goto bail;
	}

	if (cop->dst && (error = copy_to_user(cop->dst,
					cse->uio.uio_iov[0].iov_base, cop->len))) {
		dprintk("%s bad dst copy\n", __FUNCTION__);
		error = EFAULT;
		goto bail;
	}

	if (cop->mac && (error=copy_to_user(cop->mac, crp->crp_mac,
                                       cse->info.authsize))) {
		dprintk("%s bad mac copy\n", __FUNCTION__);
		error = EFAULT;
		goto bail;
	}

bail:
	if (crp)
		crypto_freereq(crp);
	if (cse->uio.uio_iov[0].iov_base)
		kfree(cse->uio.uio_iov[0].iov_base);

	return (error);
}

static int
cryptodev_cb(void *op)
{
	struct cryptop *crp = (struct cryptop *) op;
	struct csession *cse = (struct csession *)crp->crp_opaque;

	dprintk("%s()\n", __FUNCTION__);
	cse->error = crp->crp_etype;
	if (crp->crp_etype == EAGAIN) {
		crp->crp_flags &= ~CRYPTO_F_DONE;
#ifdef NOTYET
		/*
		 * DAVIDM I am fairly sure that we should turn this into a batch
		 * request to stop bad karma/lockup, revisit
		 */
		crp->crp_flags |= CRYPTO_F_BATCH;
#endif
		return crypto_dispatch(crp);
	}
	wake_up_interruptible(&crp->crp_waitq);
	return (0);
}

static int
cryptodevkey_cb(void *op)
{
	struct cryptkop *krp = (struct cryptkop *) op;
	dprintk("%s()\n", __FUNCTION__);
	wake_up_interruptible(&krp->krp_waitq);
	return (0);
}

static int
cryptodev_key(struct crypt_kop *kop)
{
	struct cryptkop *krp = NULL;
	int error = EINVAL;
	int in, out, size, i;

	dprintk("%s()\n", __FUNCTION__);
	if (kop->crk_iparams + kop->crk_oparams > CRK_MAXPARAM) {
		dprintk("%s params too big\n", __FUNCTION__);
		return (EFBIG);
	}

	in = kop->crk_iparams;
	out = kop->crk_oparams;
	switch (kop->crk_op) {
	case CRK_MOD_EXP:
		if ((in == 3 || in == 4) && out == 1)
			break;
		return (EINVAL);
	case CRK_ADD:
		if (in == 2 && out == 1)
			break;
		return (EINVAL);
	case CRK_MOD_ADD:
		if (in == 3 && out == 1)
			break;
		return (EINVAL);
	case CRK_MOD_EXP_CRT:
		if (in == 6 && out == 1)
			break;
		return (EINVAL);
	case CRK_DSA_SIGN:
		if (in == 5 && out == 2)
			break;
		return (EINVAL);
	case CRK_DSA_VERIFY:
		if (in == 7 && out == 0)
			break;
		return (EINVAL);
	case CRK_DH_COMPUTE_KEY:
		if (in == 3 && out == 1)
			break;
		return (EINVAL);
	default:
		return (EINVAL);
	}

	krp = (struct cryptkop *)kmalloc(sizeof *krp, GFP_KERNEL);
	if (!krp)
		return (ENOMEM);
	memset(krp, 0, sizeof *krp);
	krp->krp_op = kop->crk_op;
	krp->krp_status = kop->crk_status;
	krp->krp_iparams = kop->crk_iparams;
	krp->krp_oparams = kop->crk_oparams;
	krp->krp_status = 0;
	krp->krp_flags = CRYPTO_KF_CBIMM;
	krp->krp_callback = (int (*) (struct cryptkop *)) cryptodevkey_cb;
	init_waitqueue_head(&krp->krp_waitq);

	for (i = 0; i < CRK_MAXPARAM; i++)
		krp->krp_param[i].crp_nbits = kop->crk_param[i].crp_nbits;
	for (i = 0; i < krp->krp_iparams + krp->krp_oparams; i++) {
		size = (krp->krp_param[i].crp_nbits + 7) / 8;
		if (size == 0)
			continue;
		krp->krp_param[i].crp_p = (caddr_t) kmalloc(size, GFP_KERNEL);
		if (i >= krp->krp_iparams)
			continue;
		error = copy_from_user(krp->krp_param[i].crp_p,
				kop->crk_param[i].crp_p, size);
		if (error)
			goto fail;
	}

	error = crypto_kdispatch(krp);
	if (error)
		goto fail;

	do {
		error = wait_event_interruptible(krp->krp_waitq,
				((krp->krp_flags & CRYPTO_KF_DONE) != 0));
		/*
		 * we can't break out of this loop or we will leave behind
		 * a huge mess,  however,  staying here means if your driver
		 * is broken user applications can hang and not be killed.
		 * The solution,  fix your driver :-)
		 */
		if (error) {
			schedule();
			error = 0;
		}
	} while ((krp->krp_flags & CRYPTO_KF_DONE) == 0);

	dprintk("%s finished WAITING error=%d\n", __FUNCTION__, error);
	
	if (krp->krp_status != 0) {
		error = krp->krp_status;
		goto fail;
	}

	for (i = krp->krp_iparams; i < krp->krp_iparams + krp->krp_oparams; i++) {
		size = (krp->krp_param[i].crp_nbits + 7) / 8;
		if (size == 0)
			continue;
		error = copy_to_user(kop->crk_param[i].crp_p, krp->krp_param[i].crp_p,
				size);
		if (error)
			goto fail;
	}

fail:
	if (krp) {
		kop->crk_status = krp->krp_status;
		for (i = 0; i < CRK_MAXPARAM; i++) {
			if (krp->krp_param[i].crp_p)
				kfree(krp->krp_param[i].crp_p);
		}
		kfree(krp);
	}
	return (error);
}


static struct csession *
csefind(struct fcrypt *fcr, u_int ses)
{
	struct csession *cse;

	dprintk("%s()\n", __FUNCTION__);
	list_for_each_entry(cse, &fcr->csessions, list)
		if (cse->ses == ses)
			return (cse);
	return (NULL);
}

static int
csedelete(struct fcrypt *fcr, struct csession *cse_del)
{
	struct csession *cse;

	dprintk("%s()\n", __FUNCTION__);
	list_for_each_entry(cse, &fcr->csessions, list) {
		if (cse == cse_del) {
			list_del(&cse->list);
			return (1);
		}
	}
	return (0);
}
	
static struct csession *
cseadd(struct fcrypt *fcr, struct csession *cse)
{
	dprintk("%s()\n", __FUNCTION__);
	list_add_tail(&cse->list, &fcr->csessions);
	cse->ses = fcr->sesn++;
	return (cse);
}

static struct csession *
csecreate(struct fcrypt *fcr, u_int64_t sid, struct cryptoini *crie,
	struct cryptoini *cria, struct csession_info *info)
{
	struct csession *cse;

	dprintk("%s()\n", __FUNCTION__);
	cse = (struct csession *) kmalloc(sizeof(struct csession), GFP_KERNEL);
	if (cse == NULL)
		return NULL;
	memset(cse, 0, sizeof(struct csession));

	INIT_LIST_HEAD(&cse->list);
	init_waitqueue_head(&cse->waitq);

	cse->key = crie->cri_key;
	cse->keylen = crie->cri_klen/8;
	cse->mackey = cria->cri_key;
	cse->mackeylen = cria->cri_klen/8;
	cse->sid = sid;
	cse->cipher = crie->cri_alg;
	cse->mac = cria->cri_alg;
	cse->info = *info;
	cseadd(fcr, cse);
	return (cse);
}

static int
csefree(struct csession *cse)
{
	int error;

	dprintk("%s()\n", __FUNCTION__);
	error = crypto_freesession(cse->sid);
	if (cse->key)
		kfree(cse->key);
	if (cse->mackey)
		kfree(cse->mackey);
	kfree(cse);
	return(error);
}

static int
cryptodev_ioctl(
	struct inode *inode,
	struct file *filp,
	unsigned int cmd,
	unsigned long arg)
{
	struct cryptoini cria, crie;
	struct fcrypt *fcr = filp->private_data;
	struct csession *cse;
	struct csession_info info;
	struct session_op sop;
	struct crypt_op cop;
	struct crypt_kop kop;
	u_int64_t sid;
	u_int32_t ses;
	int feat, fd, error = 0;
	mm_segment_t fs;
	extern asmlinkage long sys_dup(unsigned int fildes);

	dprintk("%s()\n", __FUNCTION__);

	switch (cmd) {

	case CRIOGET: {
		dprintk("%s(CRIOGET)\n", __FUNCTION__);
		fs = get_fs();
		set_fs(get_ds());
		for (fd = 0; fd < files_fdtable(current->files)->max_fds; fd++)
			if (files_fdtable(current->files)->fd[fd] == filp)
				break;
		fd = sys_dup(fd);
		set_fs(fs);
		put_user(fd, (int *) arg);
		return fd == -1 ? -errno : 0;
		}

	case CIOCGSESSION:
		dprintk("%s(CIOCGSESSION)\n", __FUNCTION__);
		memset(&crie, 0, sizeof(crie));
		memset(&cria, 0, sizeof(cria));
		memset(&info, 0, sizeof(info));

		if(copy_from_user(&sop, (void*)arg, sizeof(sop))) {
		  dprintk("%s(CIOCGSESSION) - bad copy\n", __FUNCTION__);
		  error = EFAULT;
		  goto bail;
		}

		switch (sop.cipher) {
		case 0:
			dprintk("%s(CIOCGSESSION) - no cipher\n", __FUNCTION__);
			break;
		case CRYPTO_NULL_CBC:
			info.blocksize = 4;
			info.minkey = 0;
			info.maxkey = 256;
			break;
		case CRYPTO_DES_CBC:
			info.blocksize = 8;
			info.minkey = 8;
			info.maxkey = 8;
			break;
		case CRYPTO_3DES_CBC:
			info.blocksize = 8;
			info.minkey = 24;
			info.maxkey = 24;
			break;
		case CRYPTO_BLF_CBC:
			info.blocksize = 8;
			info.minkey = 5;
			info.maxkey = 56;
			break;
		case CRYPTO_CAST_CBC:
			info.blocksize = 8;
			info.minkey = 5;
			info.maxkey = 16;
			break;
		case CRYPTO_SKIPJACK_CBC:
			info.blocksize = 8;
			info.minkey = 10;
			info.maxkey = 10;
			break;
		case CRYPTO_AES_CBC:
			info.blocksize = 16;
			info.minkey = 16;
			info.maxkey = 32;
			break;
		case CRYPTO_ARC4:
			info.blocksize = 1;
			info.minkey = 1;
			info.maxkey = 32;
			break;
		default:
			dprintk("%s(CIOCGSESSION) - bad cipher\n", __FUNCTION__);
			error = EINVAL;
			goto bail;
		}

		switch (sop.mac) {
		case 0:
			dprintk("%s(CIOCGSESSION) - no mac\n", __FUNCTION__);
			break;
		case CRYPTO_NULL_HMAC:
			info.keysize = 0;
			info.authsize = 12;
			break;
		case CRYPTO_MD5:
			info.keysize = 16;
			info.authsize = 16;
			break;
		case CRYPTO_SHA1:
			info.keysize = 20;
			info.authsize = 20;
			break;
		case CRYPTO_MD5_HMAC:
			info.keysize = 16;
			info.authsize = 12;
			break;
		case CRYPTO_SHA1_HMAC:
			info.keysize = 20;
			info.authsize = 12;
			break;
		case CRYPTO_SHA2_HMAC:
			if (sop.mackeylen != 32 && sop.mackeylen != 48 &&
					sop.mackeylen != 64) {
				dprintk("%s(CIOCGSESSION) - bad key\n", __FUNCTION__);
				error = EINVAL;
				goto bail;
			}
			info.keysize = sop.mackeylen;
			info.authsize = 12;  /* HMAC is always truncated to 96-bits */
			break;
		case CRYPTO_RIPEMD160_HMAC:
			info.keysize = 20;
			info.authsize = 12;
			break;
		default:
			dprintk("%s(CIOCGSESSION) - bad mac\n", __FUNCTION__);
			error = EINVAL;
			goto bail;
		}

		if (info.blocksize) {
			crie.cri_alg = sop.cipher;
			crie.cri_klen = sop.keylen * 8;
			if (sop.keylen > info.maxkey || sop.keylen < info.minkey) {
				dprintk("%s(CIOCGSESSION) - bad key\n", __FUNCTION__);
				error = EINVAL;
				goto bail;
			}

			crie.cri_key = (u_int8_t *) kmalloc(crie.cri_klen/8, GFP_KERNEL);
			if (copy_from_user(crie.cri_key, sop.key,
							crie.cri_klen/8)) {
				dprintk("%s(CIOCGSESSION) - bad copy\n", __FUNCTION__);
				error = EFAULT;
				goto bail;
			}
			if (info.authsize)
				crie.cri_next = &cria;
		}

		if (info.authsize) {
			cria.cri_alg = sop.mac;
			cria.cri_klen = sop.mackeylen * 8;
			if (sop.mackeylen != info.keysize) {
				dprintk("%s(CIOCGSESSION) - mackeylen %d\n", __FUNCTION__,
						sop.mackeylen);
				error = EINVAL;
				goto bail;
			}

			if (cria.cri_klen) {
				cria.cri_key = (u_int8_t *) kmalloc(cria.cri_klen/8,GFP_KERNEL);
				if (copy_from_user(cria.cri_key, sop.mackey,
								cria.cri_klen / 8)) {
					dprintk("%s(CIOCGSESSION) - bad copy\n", __FUNCTION__);
					error = EFAULT;
					goto bail;
				}
			}
		}

		error = crypto_newsession(&sid, (info.blocksize ? &crie : &cria),
				crypto_devsel);
		if (error) {
			dprintk("%s(CIOCGSESSION) - newsession %d\n", __FUNCTION__, error);
			goto bail;
		}

		cse = csecreate(fcr, sid, &crie, &cria, &info);
		if (cse == NULL) {
			crypto_freesession(sid);
			error = EINVAL;
			dprintk("%s(CIOCGSESSION) - csecreate failed\n", __FUNCTION__);
			goto bail;
		}
		sop.ses = cse->ses;
		crypto_devicename(sid, sop.crypto_device_name);

		if (copy_to_user((void*)arg, &sop, sizeof(sop))) {
			dprintk("%s(CIOCGSESSION) - bad copy\n", __FUNCTION__);
			error = EFAULT;
		}

bail:
		if (error) {
			dprintk("%s(CIOCGSESSION) - bail %d\n", __FUNCTION__, error);
			if (crie.cri_key)
				kfree(crie.cri_key);
			if (cria.cri_key)
				kfree(cria.cri_key);
		}
		break;

	case CIOCFSESSION:
		dprintk("%s(CIOCFSESSION)\n", __FUNCTION__);
		if(copy_from_user(&ses, (void*)arg, sizeof(ses))) {
			dprintk("%s(CIOCFSESSION) - bad copy\n", __FUNCTION__);
			error = EFAULT;
			goto bail;
		}
		cse = csefind(fcr, ses);
		if (cse == NULL) {
			error = EINVAL;
			dprintk("%s(CIOCFSESSION) - Fail %d\n", __FUNCTION__, error);
			break;
		}
		csedelete(fcr, cse);
		error = csefree(cse);
		break;

	case CIOCCRYPT:
		dprintk("%s(CIOCCRYPT)\n", __FUNCTION__);
		if(copy_from_user(&cop, (void*)arg, sizeof(cop))) {
		  dprintk("%s(CIOCCRYPT) - bad copy\n", __FUNCTION__);
		  error = EFAULT;
		  goto bail;
		}
		cse = csefind(fcr, cop.ses);
		if (cse == NULL) {
			error = EINVAL;
			dprintk("%s(CIOCCRYPT) - Fail %d\n", __FUNCTION__, error);
			break;
		}
		error = cryptodev_op(cse, &cop);
		if(copy_to_user((void*)arg, &cop, sizeof(cop))) {
		  dprintk("%s(CIOCCRYPT) - bad return copy\n", __FUNCTION__);
		  error = EFAULT;
		  goto bail;
		}
		break;
	case CIOCKEY:
		dprintk("%s(CIOCKEY)\n", __FUNCTION__);
		if(copy_from_user(&kop, (void*)arg, sizeof(kop))) {
		  dprintk("%s(CIOCKEY) - bad copy\n", __FUNCTION__);
		  error = EFAULT;
		  goto bail;
		}
		error = cryptodev_key(&kop);
		if(copy_to_user((void*)arg, &kop, sizeof(kop))) {
		  dprintk("%s(CIOCGKEY) - bad return copy\n", __FUNCTION__);
		  error = EFAULT;
		  goto bail;
		}
		break;
	case CIOCASYMFEAT:
		dprintk("%s(CIOCASYMFEAT)\n", __FUNCTION__);
		error = crypto_getfeat(&feat);
		if (!error) {
		  error = copy_to_user((void*)arg, &feat, sizeof(feat));
		}
		break;

	default:
		dprintk("%s(unknown ioctl 0x%x)\n", __FUNCTION__, cmd);
		error = EINVAL;
		break;
	}
	return(-error);
}

static int
cryptodev_open(struct inode *inode, struct file *filp)
{
	struct fcrypt *fcr;

	dprintk("%s()\n", __FUNCTION__);
	if (filp->private_data) {
		printk("cryptodev: Private data already exists !\n");
		return(0);
	}

	fcr = kmalloc(sizeof(*fcr), GFP_KERNEL);
	if (!fcr) {
		dprintk("%s() - malloc failed\n", __FUNCTION__);
		return(-ENOMEM);
	}
	memset(fcr, 0, sizeof(*fcr));

	INIT_LIST_HEAD(&fcr->csessions);
	filp->private_data = fcr;
	return(0);
}

static int
cryptodev_release(struct inode *inode, struct file *filp)
{
	struct fcrypt *fcr = filp->private_data;
	struct csession *cse, *tmp;

	dprintk("%s()\n", __FUNCTION__);
	if (!filp) {
		printk("cryptodev: No private data on release\n");
		return(0);
	}

	list_for_each_entry_safe(cse, tmp, &fcr->csessions, list) {
		list_del(&cse->list);
		(void)csefree(cse);
	}
	filp->private_data = NULL;
	kfree(fcr);
	return(0);
}

static struct file_operations cryptodev_fops = {
	.owner = THIS_MODULE,
	.open = cryptodev_open,
	.release = cryptodev_release,
	.ioctl = cryptodev_ioctl,
};

static struct miscdevice cryptodev = {
	.minor = CRYPTODEV_MINOR,
	.name = "crypto",
	.fops = &cryptodev_fops,
};

static int __init
cryptodev_init(void)
{
	int rc;

	dprintk("%s(%p)\n", __FUNCTION__, cryptodev_init);
	rc = misc_register(&cryptodev);
	if (rc) {
		printk(KERN_ERR "cryptodev: registration of /dev/crypto failed\n");
		return(rc);
	}

	return(0);
}

static void __exit
cryptodev_exit(void)
{
	dprintk("%s()\n", __FUNCTION__);
	misc_deregister(&cryptodev);
}

module_init(cryptodev_init);
module_exit(cryptodev_exit);

MODULE_LICENSE("BSD");
MODULE_AUTHOR("David McCullough <david_mccullough@au.securecomputing.com>");
MODULE_DESCRIPTION("Cryptodev (user interface to OCF)");
