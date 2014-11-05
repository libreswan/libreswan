/*	$FreeBSD: src/sys/opencrypto/cryptodev.h,v 1.25 2007/05/09 19:37:02 gnn Exp $	*/
/*	$OpenBSD: cryptodev.h,v 1.31 2002/06/11 11:14:29 beck Exp $	*/

/*-
 * Linux port done by David McCullough <david_mccullough@mcafee.com>
 * Copyright (C) 2006-2010 David McCullough
 * Copyright (C) 2004-2005 Intel Corporation.
 * The license and original author are listed below.
 *
 * The author of this code is Angelos D. Keromytis (angelos@cis.upenn.edu)
 * Copyright (c) 2002-2006 Sam Leffler, Errno Consulting
 *
 * This code was written by Angelos D. Keromytis in Athens, Greece, in
 * February 2000. Network Security Technologies Inc. (NSTI) kindly
 * supported the development of this code.
 *
 * Copyright (c) 2000 Angelos D. Keromytis
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
 */

#ifndef _CRYPTO_CRYPTO_H_
#define _CRYPTO_CRYPTO_H_

/* Some initial values */
#define CRYPTO_DRIVERS_INITIAL  4
#define CRYPTO_SW_SESSIONS      32

/* Hash values */
#define NULL_HASH_LEN           0
#define MD5_HASH_LEN            16
#define SHA1_HASH_LEN           20
#define RIPEMD160_HASH_LEN      20
#define SHA2_256_HASH_LEN       32
#define SHA2_384_HASH_LEN       48
#define SHA2_512_HASH_LEN       64
#define MD5_KPDK_HASH_LEN       16
#define SHA1_KPDK_HASH_LEN      20
/* Maximum hash algorithm result length */
#define HASH_MAX_LEN            SHA2_512_HASH_LEN /* Keep this updated */

/* HMAC values */
#define NULL_HMAC_BLOCK_LEN                     1
#define MD5_HMAC_BLOCK_LEN                      64
#define SHA1_HMAC_BLOCK_LEN                     64
#define RIPEMD160_HMAC_BLOCK_LEN        64
#define SHA2_256_HMAC_BLOCK_LEN         64
#define SHA2_384_HMAC_BLOCK_LEN         128
#define SHA2_512_HMAC_BLOCK_LEN         128
/* Maximum HMAC block length */
#define HMAC_MAX_BLOCK_LEN              SHA2_512_HMAC_BLOCK_LEN /* Keep this updated */
#define HMAC_IPAD_VAL                   0x36
#define HMAC_OPAD_VAL                   0x5C

/* Encryption algorithm block sizes */
#define NULL_BLOCK_LEN                  1
/* #define DES_BLOCK_LEN                   8 obsoleted */
#define DES3_BLOCK_LEN                  8
/* #define BLOWFISH_BLOCK_LEN              8 obsoleted */
#define SKIPJACK_BLOCK_LEN              8
#define CAST128_BLOCK_LEN               8
#define RIJNDAEL128_BLOCK_LEN   16
#define AES_BLOCK_LEN                   RIJNDAEL128_BLOCK_LEN
#define CAMELLIA_BLOCK_LEN              16
#define ARC4_BLOCK_LEN                  1
#define EALG_MAX_BLOCK_LEN              AES_BLOCK_LEN /* Keep this updated */

/* Encryption algorithm min and max key sizes */
#define NULL_MIN_KEY_LEN                0
#define NULL_MAX_KEY_LEN                0
#define DES_MIN_KEY_LEN                 8
#define DES_MAX_KEY_LEN                 8
#define DES3_MIN_KEY_LEN                24
#define DES3_MAX_KEY_LEN                24
/* #define BLOWFISH_MIN_KEY_LEN    4 obsoleted */
/* #define BLOWFISH_MAX_KEY_LEN    56 obsoleted */
#define SKIPJACK_MIN_KEY_LEN    10
#define SKIPJACK_MAX_KEY_LEN    10
#define CAST128_MIN_KEY_LEN             5
#define CAST128_MAX_KEY_LEN             16
#define RIJNDAEL128_MIN_KEY_LEN 16
#define RIJNDAEL128_MAX_KEY_LEN 32
#define AES_MIN_KEY_LEN                 RIJNDAEL128_MIN_KEY_LEN
#define AES_MAX_KEY_LEN                 RIJNDAEL128_MAX_KEY_LEN
#define CAMELLIA_MIN_KEY_LEN    16
#define CAMELLIA_MAX_KEY_LEN    32
#define ARC4_MIN_KEY_LEN                1
#define ARC4_MAX_KEY_LEN                256

/* Max size of data that can be processed */
#define CRYPTO_MAX_DATA_LEN             64 * 1024 - 1

#define CRYPTO_ALGORITHM_MIN    1
#define CRYPTO_DES_CBC                  1
#define CRYPTO_3DES_CBC                 2
#define CRYPTO_BLF_CBC                  3
#define CRYPTO_CAST_CBC                 4
#define CRYPTO_SKIPJACK_CBC             5
#define CRYPTO_MD5_HMAC                 6
#define CRYPTO_SHA1_HMAC                7
#define CRYPTO_RIPEMD160_HMAC   8
#define CRYPTO_MD5_KPDK                 9
#define CRYPTO_SHA1_KPDK                10
#define CRYPTO_RIJNDAEL128_CBC  11              /* 128 bit blocksize */
#define CRYPTO_AES_CBC                  11      /* 128 bit blocksize -- the same as above */
#define CRYPTO_ARC4                             12
#define CRYPTO_MD5                              13
#define CRYPTO_SHA1                             14
#define CRYPTO_NULL_HMAC                15
#define CRYPTO_NULL_CBC                 16
#define CRYPTO_DEFLATE_COMP             17 /* Deflate compression algorithm */
#define CRYPTO_SHA2_256_HMAC    18
#define CRYPTO_SHA2_384_HMAC    19
#define CRYPTO_SHA2_512_HMAC    20
#define CRYPTO_CAMELLIA_CBC             21
#define CRYPTO_SHA2_256                 22
#define CRYPTO_SHA2_384                 23
#define CRYPTO_SHA2_512                 24
#define CRYPTO_RIPEMD160                25
#define CRYPTO_LZS_COMP                 26
#define CRYPTO_ALGORITHM_MAX    26 /* Keep updated - see above */

/* Algorithm flags */
#define CRYPTO_ALG_FLAG_SUPPORTED       0x01    /* Algorithm is supported */
#define CRYPTO_ALG_FLAG_RNG_ENABLE      0x02    /* Has HW RNG for DH/DSA */
#define CRYPTO_ALG_FLAG_DSA_SHA         0x04    /* Can do SHA on msg */

/*
 * Crypto driver/device flags.  They can set in the crid
 * parameter when creating a session or submitting a key
 * op to affect the device/driver assigned.  If neither
 * of these are specified then the crid is assumed to hold
 * the driver id of an existing (and suitable) device that
 * must be used to satisfy the request.
 */
#define CRYPTO_FLAG_HARDWARE    0x01000000      /* hardware accelerated */
#define CRYPTO_FLAG_SOFTWARE    0x02000000      /* software implementation */

/* NB: deprecated */
struct session_op {
	u_int32_t cipher;               /* ie. CRYPTO_DES_CBC */
	u_int32_t mac;                  /* ie. CRYPTO_MD5_HMAC */

	u_int32_t keylen;               /* cipher key */
	caddr_t key;
	int mackeylen;                  /* mac key */
	caddr_t mackey;

	u_int32_t ses;                  /* returns: session # */
};

struct session2_op {
	u_int32_t cipher;               /* ie. CRYPTO_DES_CBC */
	u_int32_t mac;                  /* ie. CRYPTO_MD5_HMAC */

	u_int32_t keylen;               /* cipher key */
	caddr_t key;
	int mackeylen;                  /* mac key */
	caddr_t mackey;

	u_int32_t ses;                  /* returns: session # */
	int crid;                       /* driver id + flags (rw) */
	int pad[4];                     /* for future expansion */
};

struct crypt_op {
	u_int32_t ses;
	u_int16_t op;                   /* i.e. COP_ENCRYPT */
#define COP_NONE        0
#define COP_ENCRYPT     1
#define COP_DECRYPT     2
	u_int16_t flags;
#define COP_F_BATCH     0x0008          /* Batch op if possible */
	u_int len;
	caddr_t src, dst;               /* become iov[] inside kernel */
	caddr_t mac;                    /* must be big enough for chosen MAC */
	caddr_t iv;
};

/*
 * Parameters for looking up a crypto driver/device by
 * device name or by id.  The latter are returned for
 * created sessions (crid) and completed key operations.
 */
struct crypt_find_op {
	int crid;                       /* driver id + flags */
	char name[32];                  /* device/driver name */
};

/* bignum parameter, in packed bytes, ... */
struct crparam {
	caddr_t crp_p;
	u_int crp_nbits;
};

#define CRK_MAXPARAM    8

struct crypt_kop {
	u_int crk_op;                   /* ie. CRK_MOD_EXP or other */
	u_int crk_status;               /* return status */
	u_short crk_iparams;            /* # of input parameters */
	u_short crk_oparams;            /* # of output parameters */
	u_int crk_crid;                 /* NB: only used by CIOCKEY2 (rw) */
	struct crparam crk_param[CRK_MAXPARAM];
};
#define CRK_ALGORITM_MIN        0
#define CRK_MOD_EXP             0
#define CRK_MOD_EXP_CRT         1
#define CRK_DSA_SIGN            2
#define CRK_DSA_VERIFY          3
#define CRK_DH_COMPUTE_KEY      4
#define CRK_ALGORITHM_MAX       4 /* Keep updated - see below */

#define CRF_MOD_EXP             (1 << CRK_MOD_EXP)
#define CRF_MOD_EXP_CRT         (1 << CRK_MOD_EXP_CRT)
#define CRF_DSA_SIGN            (1 << CRK_DSA_SIGN)
#define CRF_DSA_VERIFY          (1 << CRK_DSA_VERIFY)
#define CRF_DH_COMPUTE_KEY      (1 << CRK_DH_COMPUTE_KEY)

/*
 * done against open of /dev/crypto, to get a cloned descriptor.
 * Please use F_SETFD against the cloned descriptor.
 */
#define CRIOGET         _IOWR('c', 100, u_int32_t)
#define CRIOASYMFEAT    CIOCASYMFEAT
#define CRIOFINDDEV     CIOCFINDDEV

/* the following are done against the cloned descriptor */
#define CIOCGSESSION    _IOWR('c', 101, struct session_op)
#define CIOCFSESSION    _IOW('c', 102, u_int32_t)
#define CIOCCRYPT       _IOWR('c', 103, struct crypt_op)
#define CIOCKEY         _IOWR('c', 104, struct crypt_kop)
#define CIOCASYMFEAT    _IOR('c', 105, u_int32_t)
#define CIOCGSESSION2   _IOWR('c', 106, struct session2_op)
#define CIOCKEY2        _IOWR('c', 107, struct crypt_kop)
#define CIOCFINDDEV     _IOWR('c', 108, struct crypt_find_op)

struct cryptotstat {
	struct timespec acc;            /* total accumulated time */
	struct timespec min;            /* min time */
	struct timespec max;            /* max time */
	u_int32_t count;                /* number of observations */
};

struct cryptostats {
	u_int32_t cs_ops;               /* symmetric crypto ops submitted */
	u_int32_t cs_errs;              /* symmetric crypto ops that failed */
	u_int32_t cs_kops;              /* asymetric/key ops submitted */
	u_int32_t cs_kerrs;             /* asymetric/key ops that failed */
	u_int32_t cs_intrs;             /* crypto swi thread activations */
	u_int32_t cs_rets;              /* crypto return thread activations */
	u_int32_t cs_blocks;            /* symmetric op driver block */
	u_int32_t cs_kblocks;           /* symmetric op driver block */
	/*
	 * When CRYPTO_TIMING is defined at compile time and the
	 * sysctl debug.crypto is set to 1, the crypto system will
	 * accumulate statistics about how long it takes to process
	 * crypto requests at various points during processing.
	 */
	struct cryptotstat cs_invoke;   /* crypto_dipsatch -> crypto_invoke */
	struct cryptotstat cs_done;     /* crypto_invoke -> crypto_done */
	struct cryptotstat cs_cb;       /* crypto_done -> callback */
	struct cryptotstat cs_finis;    /* callback -> callback return */

	u_int32_t cs_drops;             /* crypto ops dropped due to congestion */
};

#ifdef __KERNEL__

/* Standard initialization structure beginning */
struct cryptoini {
	int cri_alg;                            /* Algorithm to use */
	int cri_klen;                           /* Key length, in bits */
	int cri_mlen;                           /* Number of bytes we want from the
	                                           entire hash. 0 means all. */
	caddr_t cri_key;                        /* key to use */
	u_int8_t cri_iv[EALG_MAX_BLOCK_LEN];    /* IV to use */
	struct cryptoini *cri_next;
};

/* Describe boundaries of a single crypto operation */
struct cryptodesc {
	int crd_skip;                   /* How many bytes to ignore from start */
	int crd_len;                    /* How many bytes to process */
	int crd_inject;                 /* Where to inject results, if applicable */
	int crd_flags;

#define CRD_F_ENCRYPT           0x01    /* Set when doing encryption */
#define CRD_F_IV_PRESENT        0x02    /* When encrypting, IV is already in
	                                   place, so don't copy. */
#define CRD_F_IV_EXPLICIT       0x04    /* IV explicitly provided */
#define CRD_F_DSA_SHA_NEEDED    0x08    /* Compute SHA-1 of buffer for DSA */
#define CRD_F_KEY_EXPLICIT      0x10    /* Key explicitly provided */
#define CRD_F_COMP              0x0f    /* Set when doing compression */

	struct cryptoini CRD_INI;       /* Initialization/context data */
#define crd_iv          CRD_INI.cri_iv
#define crd_key         CRD_INI.cri_key
#define crd_alg         CRD_INI.cri_alg
#define crd_klen        CRD_INI.cri_klen
#define crd_mlen        CRD_INI.cri_mlen

	struct cryptodesc *crd_next;
};

/* Structure describing complete operation */
struct cryptop {
	struct list_head crp_next;
	wait_queue_head_t crp_waitq;

	u_int64_t crp_sid;              /* Session ID */
	int crp_ilen;                   /* Input data total length */
	int crp_olen;                   /* Result total length */

	int crp_etype;                  /*
	                                 * Error type (zero means no error).
	                                 * All error codes except EAGAIN
	                                 * indicate possible data corruption (as in,
	                                 * the data have been touched). On all
	                                 * errors, the crp_sid may have changed
	                                 * (reset to a new one), so the caller
	                                 * should always check and use the new
	                                 * value on future requests.
	                                 */
	int crp_flags;

#define CRYPTO_F_SKBUF          0x0001          /* Input/output are skbuf chains */
#define CRYPTO_F_IOV            0x0002          /* Input/output are uio */
#define CRYPTO_F_REL            0x0004          /* Must return data in same place */
#define CRYPTO_F_BATCH          0x0008          /* Batch op if possible */
#define CRYPTO_F_CBIMM          0x0010          /* Do callback immediately */
#define CRYPTO_F_DONE           0x0020          /* Operation completed */
#define CRYPTO_F_CBIFSYNC       0x0040          /* Do CBIMM if op is synchronous */

	caddr_t crp_buf;                        /* Data to be processed */
	caddr_t crp_opaque;                     /* Opaque pointer, passed along */
	struct cryptodesc *crp_desc;            /* Linked list of processing descriptors */

	int (*crp_callback)(struct cryptop *);  /* Callback function */
};

#define CRYPTO_BUF_CONTIG       0x0
#define CRYPTO_BUF_IOV          0x1
#define CRYPTO_BUF_SKBUF                0x2

#define CRYPTO_OP_DECRYPT       0x0
#define CRYPTO_OP_ENCRYPT       0x1

/*
 * Hints passed to process methods.
 */
#define CRYPTO_HINT_MORE        0x1     /* more ops coming shortly */

struct cryptkop {
	struct list_head krp_next;
	wait_queue_head_t krp_waitq;

	int krp_flags;
#define CRYPTO_KF_DONE          0x0001          /* Operation completed */
#define CRYPTO_KF_CBIMM         0x0002          /* Do callback immediately */

	u_int krp_op;                           /* ie. CRK_MOD_EXP or other */
	u_int krp_status;                       /* return status */
	u_short krp_iparams;                    /* # of input parameters */
	u_short krp_oparams;                    /* # of output parameters */
	u_int krp_crid;                         /* desired device, etc. */
	u_int32_t krp_hid;
	struct crparam krp_param[CRK_MAXPARAM]; /* kvm */
	int (*krp_callback)(struct cryptkop *);
};

#include <ocf-compat.h>

/*
 * Session ids are 64 bits.  The lower 32 bits contain a "local id" which
 * is a driver-private session identifier.  The upper 32 bits contain a
 * "hardware id" used by the core crypto code to identify the driver and
 * a copy of the driver's capabilities that can be used by client code to
 * optimize operation.
 */
#define CRYPTO_SESID2HID(_sid)  (((_sid) >> 32) & 0x00ffffff)
#define CRYPTO_SESID2CAPS(_sid) (((_sid) >> 32) & 0xff000000)
#define CRYPTO_SESID2LID(_sid)  (((u_int32_t) (_sid)) & 0xffffffff)

extern int crypto_newsession(u_int64_t *sid, struct cryptoini *cri, int hard);
extern int crypto_freesession(u_int64_t sid);
#define CRYPTOCAP_F_HARDWARE    CRYPTO_FLAG_HARDWARE
#define CRYPTOCAP_F_SOFTWARE    CRYPTO_FLAG_SOFTWARE
#define CRYPTOCAP_F_SYNC        0x04000000      /* operates synchronously */
extern int32_t crypto_get_driverid(device_t dev, int flags);
extern int crypto_find_driver(const char *);
extern device_t crypto_find_device_byhid(int hid);
extern int crypto_getcaps(int hid);
extern int crypto_register(u_int32_t driverid, int alg, u_int16_t maxoplen,
			   u_int32_t flags);
extern int crypto_kregister(u_int32_t, int, u_int32_t);
extern int crypto_unregister(u_int32_t driverid, int alg);
extern int crypto_unregister_all(u_int32_t driverid);
extern int crypto_dispatch(struct cryptop *crp);
extern int crypto_kdispatch(struct cryptkop *);
#define CRYPTO_SYMQ     0x1
#define CRYPTO_ASYMQ    0x2
extern int crypto_unblock(u_int32_t, int);
extern void crypto_done(struct cryptop *crp);
extern void crypto_kdone(struct cryptkop *);
extern int crypto_getfeat(int *);

extern void crypto_freereq(struct cryptop *crp);
extern struct cryptop *crypto_getreq(int num);

extern int crypto_usercrypto;           /* userland may do crypto requests */
extern int crypto_userasymcrypto;       /* userland may do asym crypto reqs */
extern int crypto_devallowsoft;         /* only use hardware crypto */

/*
 * random number support,  crypto_unregister_all will unregister
 */
extern int crypto_rregister(u_int32_t driverid,
			    int (*read_random)(void *arg, u_int32_t *buf,
					       int len), void *arg);
extern int crypto_runregister_all(u_int32_t driverid);

/*
 * Crypto-related utility routines used mainly by drivers.
 *
 * XXX these don't really belong here; but for now they're
 *     kept apart from the rest of the system.
 */
struct uio;
extern void cuio_copydata(struct uio *uio, int off, int len, caddr_t cp);
extern void cuio_copyback(struct uio *uio, int off, int len, caddr_t cp);
extern struct iovec *cuio_getptr(struct uio *uio, int loc, int *off);

extern void crypto_copyback(int flags, caddr_t buf, int off, int size,
			    caddr_t in);
extern void crypto_copydata(int flags, caddr_t buf, int off, int size,
			    caddr_t out);
extern int crypto_apply(int flags, caddr_t buf, int off, int len,
			int (*f)(void *, void *, u_int), void *arg);

#endif  /* __KERNEL__ */
#endif  /* _CRYPTO_CRYPTO_H_ */
