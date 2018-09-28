/*
 * @(#) Definitions of IPsec Security Association (ipsec_sa)
 *
 * Copyright (C) 2001, 2002, 2003
 *                      Richard Guy Briggs  <rgb@freeswan.org>
 *                  and Michael Richardson  <mcr@freeswan.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * This file derived from ipsec_xform.h on 2001/9/18 by mcr.
 *
 */

/*
 * This file describes the IPsec Security Association Structure.
 *
 * This structure keeps track of a single transform that may be done
 * to a set of packets. It can describe applying the transform or
 * apply the reverse. (e.g. compression vs expansion). However, it
 * only describes one at a time. To describe both, two structures would
 * be used, but since the sides of the transform are performed
 * on different machines typically it is usual to have only one side
 * of each association.
 *
 */

#ifndef _IPSEC_SA_H_

#ifdef __KERNEL__
#include "libreswan/ipsec_stats.h"
#include "libreswan/ipsec_life.h"
#include "libreswan/ipsec_eroute.h"
#endif /* __KERNEL__ */
#include "libreswan/ipsec_param.h"

#include "libreswan/pfkeyv2.h"

/* SAs are held in a table.
 * Entries in this table are referenced by IPsecSAref_t values.
 * IPsecSAref_t values are conceptually subscripts.  Because
 * we want to allocate the table piece-meal, the subscripting
 * is implemented with two levels, a bit like paged virtual memory.
 * This representation mechanism is known as an Iliffe Vector.
 *
 * The Main table (AKA the refTable) consists of 2^IPSEC_SA_REF_MAINTABLE_IDX_WIDTH
 * pointers to subtables.
 * Each subtable has 2^IPSEC_SA_REF_SUBTABLE_IDX_WIDTH entries, each of which
 * is a pointer to an SA.
 *
 * An IPsecSAref_t contains either an exceptional value (signified by the
 * high-order bit being on) or a reference to a table entry.  A table entry
 * reference has the subtable subscript in the low-order
 * IPSEC_SA_REF_SUBTABLE_IDX_WIDTH bits and the Main table subscript
 * in the next lowest IPSEC_SA_REF_MAINTABLE_IDX_WIDTH bits.
 *
 * The Maintable entry for an IPsecSAref_t x, a pointer to its subtable, is
 * IPsecSAref2table(x).  It is of type struct IPsecSArefSubTable *.
 *
 * The pointer to the SA for x is IPsecSAref2SA(x).  It is of type
 * struct ipsec_sa*.  The macro definition clearly shows the two-level
 * access needed to find the SA pointer.
 *
 * The Maintable is allocated when IPsec is initialized.
 * Each subtable is allocated when needed, but the first is allocated
 * when IPsec is initialized.
 *
 * IPsecSAref_t is designed to be smaller than an NFmark so that
 * they can be stored in NFmarks and still leave a few bits for other
 * purposes.  The spare bits are in the low order of the NFmark
 * but in the high order of the IPsecSAref_t, so conversion is required.
 * We pick the upper bits of NFmark on the theory that they are less likely to
 * interfere with more pedestrian uses of nfmark.
 */

typedef unsigned short int IPsecRefTableUnusedCount;

#define IPSEC_SA_REF_TABLE_NUM_ENTRIES (1 << IPSEC_SA_REF_TABLE_IDX_WIDTH)

#ifdef __KERNEL__

#define IPSEC_SA_REF_SUBTABLE_IDX_WIDTH \
	(IPSEC_SA_REF_TABLE_IDX_WIDTH - IPSEC_SA_REF_MAINTABLE_IDX_WIDTH)

#if IPSEC_SA_REF_SUBTABLE_IDX_WIDTH <= 0
#error "IPSEC_SA_REF_TABLE_IDX_WIDTH("IPSEC_SA_REF_TABLE_IDX_WIDTH") MUST be > IPSEC_SA_REF_MAINTABLE_IDX_WIDTH("IPSEC_SA_REF_MAINTABLE_IDX_WIDTH")"
#endif

#define IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES \
		(1 << IPSEC_SA_REF_MAINTABLE_IDX_WIDTH)

#define IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES \
		(1 << IPSEC_SA_REF_SUBTABLE_IDX_WIDTH)

#define IPSEC_SA_REF_SUBTABLE_SIZE \
		(IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES * sizeof(struct ipsec_sa *))

#ifdef CONFIG_NETFILTER
#define IPSEC_SA_REF_HOST_FIELD(x) ((struct sk_buff*)(x))->nfmark
/* ??? typeof is a GCCism */
#define IPSEC_SA_REF_HOST_FIELD_TYPE typeof(IPSEC_SA_REF_HOST_FIELD(NULL))
#else /* CONFIG_NETFILTER */
/* just make it work for now, it doesn't matter, since there is no nfmark */
#define IPSEC_SA_REF_HOST_FIELD_TYPE unsigned long
#endif /* CONFIG_NETFILTER */
#define IPSEC_SA_REF_HOST_FIELD_WIDTH \
		(8 * sizeof(IPSEC_SA_REF_HOST_FIELD_TYPE))
#define IPSEC_SA_REF_FIELD_WIDTH (8 * sizeof(IPsecSAref_t))

#define IPSEC_SA_REF_MAX         (~IPSEC_SAREF_NULL)
#define IPSEC_SAREF_FIRST        1
/* from libreswan.h #define IPSEC_SA_REF_MASK        (IPSEC_SA_REF_MAX >> (IPSEC_SA_REF_FIELD_WIDTH - IPSEC_SA_REF_TABLE_IDX_WIDTH)) */
#define IPSEC_SA_REF_TABLE_MASK \
	(IPSEC_SA_REF_MAX \
	    >> (IPSEC_SA_REF_FIELD_WIDTH - IPSEC_SA_REF_MAINTABLE_IDX_WIDTH) \
	    << IPSEC_SA_REF_SUBTABLE_IDX_WIDTH)
#define IPSEC_SA_REF_ENTRY_MASK \
	(IPSEC_SA_REF_MAX \
	    >> (IPSEC_SA_REF_FIELD_WIDTH - IPSEC_SA_REF_SUBTABLE_IDX_WIDTH))

#define IPsecSAref2table(x) \
	(((x) & IPSEC_SA_REF_TABLE_MASK) >> IPSEC_SA_REF_SUBTABLE_IDX_WIDTH)
#define IPsecSAref2entry(x) ((x) & IPSEC_SA_REF_ENTRY_MASK)
#define IPsecSArefBuild(x, y) (((x) << IPSEC_SA_REF_SUBTABLE_IDX_WIDTH) + (y))

#define IPsecSAref2SA(x) (ipsec_sadb.refTable[IPsecSAref2table(x)]->entry[ \
				  IPsecSAref2entry(x)])
#define IPsecSA2SAref(x) ((x)->ips_ref)
#define IPsecSA2SArefhim(x) ((x)->ips_refhim)

#define EMT_INBOUND     0x01    /* SA direction, 1=inbound */

/* 'struct ipsec_sa' should be 64bit aligned when allocated. */
struct ipsec_sa {
	atomic_t ips_refcount;                  /* reference count for this struct */
	int ips_marked_deleted;                 /* used with reference counting */
	IPsecSAref_t ips_ref;                   /* reference table entry number */
	IPsecSAref_t ips_refhim;                /* ref of paired SA, if any */
	struct ipsec_sa *ips_next;              /* pointer to next xform */
	struct ipsec_sa *ips_prev;              /* pointer to prev xform */

	struct ipsec_sa *ips_hnext;             /* next in hash chain */

	struct ifnet    *ips_rcvif;             /* related rcv encap interface */

	struct xform_functions *ips_xformfuncs; /* pointer to routines to process this SA */

	struct net_device *ips_out;             /* what interface to emerge on */
	__u8 ips_transport_direct;              /* if true, punt directly to
						 * the protocol layer
						 */
	struct socket  *ips_sock;               /* cache of transport socket */

	ip_said ips_said;                       /* SA ID */

	__u32 ips_seq;                          /* seq num of msg that initiated this SA */
	__u32 ips_pid;                          /* PID of process that initiated this SA */
	__u8 ips_authalg;                       /* auth algorithm for this SA */
	__u8 ips_encalg;                        /* enc algorithm for this SA */

	struct ipsec_stats ips_errs;

	__u8 ips_replaywin;                     /* replay window size */
	enum sadb_sastate ips_state;            /* state of SA */
	__u32 ips_replaywin_lastseq;            /* last pkt sequence num */
	__u64 ips_replaywin_bitmap;             /* bitmap of received pkts */
	__u32 ips_replaywin_maxdiff;            /* max pkt sequence difference */

	__u32 ips_flags;                        /* generic xform flags */

	struct ipsec_lifetimes ips_life;        /* lifetime records */

	/* selector information */
	__u8 ips_transport_protocol;		/* protocol for this SA, if ports are involved */
	struct sockaddr *ips_addr_s;		/* src sockaddr */
	struct sockaddr *ips_addr_d;		/* dst sockaddr */
	struct sockaddr *ips_addr_p;		/* proxy sockaddr */
	__u16 ips_addr_s_size;
	__u16 ips_addr_d_size;
	__u16 ips_addr_p_size;
	ip_address ips_flow_s;
	ip_address ips_flow_d;
	ip_address ips_mask_s;
	ip_address ips_mask_d;

	__u16 ips_key_bits_a;                   /* size of authkey in bits */
	__u16 ips_auth_bits;                    /* size of authenticator in bits */
	__u16 ips_key_bits_e;                   /* size of enckey in bits */
	__u16 ips_iv_bits;                      /* size of IV in bits */
	__u8 ips_iv_size;
	__u16 ips_key_a_size;
	__u16 ips_key_e_size;

	caddr_t ips_key_a;                      /* authentication key */
	caddr_t ips_key_e;                      /* encryption key */
	caddr_t ips_iv;                         /* Initialisation Vector */

	struct ident ips_ident_s;               /* identity src */
	struct ident ips_ident_d;               /* identity dst */

	/* these are included even if CONFIG_KLIPS_IPCOMP is off */
	__u16 ips_comp_adapt_tries;             /* ipcomp self-adaption tries */
	__u16 ips_comp_adapt_skip;              /* ipcomp self-adaption to-skip */
	__u64 ips_comp_ratio_cbytes;            /* compressed bytes */
	__u64 ips_comp_ratio_dbytes;            /* decompressed (or uncompressed) bytes */

	__u8 ips_natt_type;
	__u8 ips_natt_reserved[3];
	__u16 ips_natt_sport;
	__u16 ips_natt_dport;

	struct sockaddr *ips_natt_oa;
	__u16 ips_natt_oa_size;
	__u16 ips_natt_reserved2;

#if 0
	__u32 ips_sens_dpd;
	__u8 ips_sens_sens_level;
	__u8 ips_sens_sens_len;
	__u64 *ips_sens_sens_bitmap;
	__u8 ips_sens_integ_level;
	__u8 ips_sens_integ_len;
	__u64 *ips_sens_integ_bitmap;
#endif
	struct ipsec_alg_enc *ips_alg_enc;
	struct ipsec_alg_auth *ips_alg_auth;

	int ocf_in_use;
	int64_t ocf_cryptoid;

#	define IPSEC_REFALLOC  0
#	define IPSEC_REFINTERN 1
#	define IPSEC_REFSAADD  2
#	define IPSEC_REFOTHER  3
#	define IPSEC_REFPROC   4
#	define IPSEC_REFTX     5
#	define IPSEC_REFRX     6
#	define IPSEC_REFSA     7

#if 0   /* IPSEC_SA_RECOUNT_DEBUG */
	/*
	 * define IPSEC_SA_RECOUNT_DEBUG to track recounts by use, makes
	 * it a lot easier to determine problems with refcount and SA freeing
	 */

#	define IPSEC_SA_RECOUNT_DEBUG 1
	unsigned char ips_track[IPSEC_REFSA + 1];

	struct ipsec_sa *ips_raw;
#endif
};

struct IPsecSArefSubTable {
	struct ipsec_sa *entry[IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES];
};

struct ipsec_sadb {
	struct IPsecSArefSubTable *refTable[IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES];
	IPsecSAref_t refFreeList[IPSEC_SA_REF_FREELIST_NUM_ENTRIES];
	int refFreeListHead;
	int refFreeListTail;
	IPsecSAref_t refFreeListCont;
	IPsecSAref_t said_hash[SADB_HASHMOD];
	spinlock_t sadb_lock;
};

extern struct ipsec_sadb ipsec_sadb;

extern int ipsec_sadb_init(void);
extern struct ipsec_sa *ipsec_sa_alloc(int *error); /* pass in error var by pointer */
extern int ipsec_sa_free(struct ipsec_sa *ips);

#define ipsec_sa_get(ips, type) __ipsec_sa_get(ips, __FUNCTION__, __LINE__, \
					       type)
extern struct ipsec_sa * __ipsec_sa_get(struct ipsec_sa *ips, const char
					*func, int line, int type);

#define ipsec_sa_put(ips, type) __ipsec_sa_put(ips, __FUNCTION__, __LINE__, \
					       type)
extern void __ipsec_sa_put(struct ipsec_sa *ips, const char *func, int line,
			   int type);

extern int ipsec_sa_add(struct ipsec_sa *ips);
extern void ipsec_sa_rm(struct ipsec_sa *ips);
extern int ipsec_sadb_cleanup(__u8 proto);
extern int ipsec_sadb_free(void);
extern int ipsec_sa_wipe(struct ipsec_sa *ips);
extern int ipsec_sa_intern(struct ipsec_sa *ips);
extern struct ipsec_sa *ipsec_sa_getbyref(IPsecSAref_t ref, int type);

extern void ipsec_sa_untern(struct ipsec_sa *ips);
#endif /* __KERNEL__ */

enum ipsec_direction {
	ipsec_incoming = 1,
	ipsec_outgoing = 2
};

#define _IPSEC_SA_H_
#endif /* _IPSEC_SA_H_ */
