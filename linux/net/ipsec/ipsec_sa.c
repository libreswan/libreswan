/*
 * Common routines for IPsec SA maintenance routines.
 *
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001, 2002  Richard Guy Briggs.
 * Copyright (C) 2012  Paul Wouters  <paul@libreswan.org>
 * Copyright (C) 2012  David McCullough <david_mccullough@mcafee.com>
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
 * This is the file formerly known as "ipsec_xform.h"
 *
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) && \
	!defined(AUTOCONF_INCLUDED)
#include <linux/config.h>
#endif
#include <linux/kernel.h> /* printk() */

#include "libreswan/ipsec_param.h"

#include <linux/slab.h>         /* kmalloc() */
#include <linux/vmalloc.h>      /* vmalloc() */
#include <linux/errno.h>        /* error codes */
#include <linux/types.h>        /* size_t */
#include <linux/interrupt.h>    /* mark_bh */

#include <linux/netdevice.h>    /* struct device, and other headers */
#include <linux/etherdevice.h>  /* eth_type_trans */
#include <linux/ip.h>           /* struct iphdr */
#include <linux/skbuff.h>
#include <libreswan.h>
#include <linux/spinlock.h> /* *lock* */

#include <net/ip.h>

#include "libreswan/radij.h"

#include "libreswan/ipsec_stats.h"
#include "libreswan/ipsec_life.h"
#include "libreswan/ipsec_sa.h"
#include "libreswan/ipsec_xform.h"

#include "libreswan/ipsec_encap.h"
#include "libreswan/ipsec_radij.h"
#include "libreswan/ipsec_xform.h"
#include "libreswan/ipsec_ipe4.h"
#include "libreswan/ipsec_ah.h"
#include "libreswan/ipsec_esp.h"
#include "libreswan/ipsec_ipip.h"
#ifdef CONFIG_KLIPS_IPCOMP
#include "libreswan/ipsec_ipcomp.h"
#endif /* CONFIG_KLIPS_COMP */

#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include "libreswan/ipsec_proto.h"
#include "libreswan/ipsec_alg.h"

#ifdef CONFIG_KLIPS_OCF
# include "ipsec_ocf.h"
#endif

#define SENDERR(_x) do { error = -(_x); goto errlab; } while (0)

struct ipsec_sa *ipsec_sadb_hash[SADB_HASHMOD];
DEFINE_SPINLOCK(tdb_lock);

#ifdef IPSEC_SA_RECOUNT_DEBUG
struct ipsec_sa *ipsec_sa_raw = NULL;
#endif

struct ipsec_sadb ipsec_sadb;

/* the sub table must be narrower (or equal) in bits than the variable type
   in the main table to count the number of unused entries in it. */
typedef struct {
	/* kind of compile-time, but not preprocessor time, assertion */
	int testSizeOf_refSubTable :
	((sizeof(IPsecRefTableUnusedCount) * 8) <
	 IPSEC_SA_REF_SUBTABLE_IDX_WIDTH ? -1 : 1);
} dummy;

/* The field where the saref will be hosted in the skb must be wide enough to
   accommodate the information it needs to store. */
typedef struct {
	/* kind of compile-time, but not preprocessor time, assertion */
	int testSizeOf_refField :
	(IPSEC_SA_REF_HOST_FIELD_WIDTH <
	 IPSEC_SA_REF_TABLE_IDX_WIDTH ? -1 : 1 );
} dummy2;

#define IPS_HASH(said) (((said)->spi + (said)->dst.u.v4.sin_addr.s_addr + \
			 (said)->proto) % SADB_HASHMOD)

static int ipsec_saref_verify_slot(IPsecSAref_t ref);
static int ipsec_SArefSubTable_alloc(unsigned table);
static int ipsec_saref_freelist_init(void);
static IPsecSAref_t ipsec_SAref_alloc(int *erorr); /* pass in error var by pointer */

static int ipsec_SAref_recycle(void)
{
	int table, i;
	int error = 0;
	int entry;
	int addone;

	ipsec_sadb.refFreeListHead = IPSEC_SAREF_NULL;
	ipsec_sadb.refFreeListTail = IPSEC_SAREF_NULL;

	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_SAref_recycle: "
		    "recycling, continuing from SAref=%d (0p%p), table=%d, entry=%d.\n",
		    ipsec_sadb.refFreeListCont,
		    (ipsec_sadb.refTable[IPsecSAref2table(ipsec_sadb.
			refFreeListCont)] != NULL) ?
			    IPsecSAref2SA(ipsec_sadb.refFreeListCont) : NULL,
		    IPsecSAref2table(ipsec_sadb.refFreeListCont),
		    IPsecSAref2entry(ipsec_sadb.refFreeListCont));

	/* add one additional table entry */
	addone = 0;

	for (i = 0; i < IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES; i++) {
		if (ipsec_sadb.refFreeListCont ==
		    IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES *
		    IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES) {
			KLIPS_PRINT(debug_xform,
				    "klips_debug:ipsec_SAref_recycle: "
				    "end of table reached, continuing at start..\n");
			ipsec_sadb.refFreeListCont = IPSEC_SAREF_FIRST;
		}

		table = IPsecSAref2table(ipsec_sadb.refFreeListCont);
		if (ipsec_sadb.refTable[table] == NULL) {
			if (addone == 0) {
				addone = 1;
				error = ipsec_SArefSubTable_alloc(table);
				if (error)
					return error;
				else
					break;
			}
		}
		for (entry = IPsecSAref2entry(ipsec_sadb.refFreeListCont);
		     entry < IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES;
		     entry++) {
			if (ipsec_sadb.refTable[table]->entry[entry] == NULL) {
				ipsec_sadb.refFreeList[++ipsec_sadb.
						       refFreeListTail] =
					IPsecSArefBuild(table, entry);
				if (ipsec_sadb.refFreeListTail ==
				    (IPSEC_SA_REF_FREELIST_NUM_ENTRIES - 1)) {
					ipsec_sadb.refFreeListHead =
						IPSEC_SAREF_FIRST;
					ipsec_sadb.refFreeListCont =
						ipsec_sadb.refFreeList[
							ipsec_sadb.
							refFreeListTail
						] + 1;
					KLIPS_PRINT(debug_xform,
						    "klips_debug:ipsec_SAref_recycle: "
						    "SArefFreeList refilled.\n");
					return 0;
				}
			}
			ipsec_sadb.refFreeListCont++;
		}
	}

	if (ipsec_sadb.refFreeListTail == IPSEC_SAREF_NULL) {
		KLIPS_PRINT(debug_xform,
			    "klips_debug:ipsec_SAref_recycle: "
			    "out of room in the SArefTable.\n");

		return -ENOSPC;
	}

	ipsec_sadb.refFreeListHead = IPSEC_SAREF_FIRST;
	ipsec_sadb.refFreeListCont =
		ipsec_sadb.refFreeList[ipsec_sadb.refFreeListTail] + 1;
	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_SAref_recycle: "
		    "SArefFreeList partly refilled to %d of %d.\n",
		    ipsec_sadb.refFreeListTail,
		    IPSEC_SA_REF_FREELIST_NUM_ENTRIES);
	return 0;
}

static int ipsec_SArefSubTable_alloc(unsigned table)
{
	unsigned entry;
	struct IPsecSArefSubTable *SArefsub;

	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_SArefSubTable_alloc: "
		    "allocating %zu bytes for table %u of %u.\n",
		    IPSEC_SA_REF_SUBTABLE_SIZE,
		    table, IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES);

	/* allocate another sub-table */
	SArefsub = kmalloc(IPSEC_SA_REF_SUBTABLE_SIZE, GFP_ATOMIC);
	if (SArefsub == NULL) {
		KLIPS_PRINT(debug_xform,
			    "klips_debug:ipsec_SArefSubTable_alloc: "
			    "error allocating memory for table %u of %u!\n",
			    table,
			    IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES);
		return -ENOMEM;
	}

	/* add this sub-table to the main table */
	ipsec_sadb.refTable[table] = SArefsub;

	/* initialise each element to NULL */
	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_SArefSubTable_alloc: "
		    "initialising %u elements (2 ^ %u) of table %u.\n",
		    IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES,
		    IPSEC_SA_REF_SUBTABLE_IDX_WIDTH,
		    table);
	for (entry = 0; entry < IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES; entry++)
		SArefsub->entry[entry] = NULL;

	return 0;
}

static int ipsec_saref_verify_slot(IPsecSAref_t ref)
{
	int ref_table = IPsecSAref2table(ref);

	if (ipsec_sadb.refTable[ref_table] == NULL)
		return ipsec_SArefSubTable_alloc(ref_table);

	return 0;
}

int ipsec_saref_freelist_init(void)
{
	int i;

	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_saref_freelist_init: "
		    "initialising %u elements of FreeList.\n",
		    IPSEC_SA_REF_FREELIST_NUM_ENTRIES);

	for (i = 0; i < IPSEC_SA_REF_FREELIST_NUM_ENTRIES; i++)
		ipsec_sadb.refFreeList[i] = IPSEC_SAREF_NULL;
	ipsec_sadb.refFreeListHead = IPSEC_SAREF_NULL;
	ipsec_sadb.refFreeListCont = IPSEC_SAREF_FIRST;
	ipsec_sadb.refFreeListTail = IPSEC_SAREF_NULL;

	return 0;
}

int ipsec_sadb_init(void)
{
	int error = 0;
	unsigned i;

	for (i = 0; i < SADB_HASHMOD; i++)
		ipsec_sadb_hash[i] = NULL;
	/* parts above are for the old style SADB hash table */

	/* initialise SA reference table */

	/* initialise the main table */
	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_sadb_init: "
		    "initialising main table of size %u (2 ^ %u).\n",
		    IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES,
		    IPSEC_SA_REF_MAINTABLE_IDX_WIDTH);
	{
		unsigned table;
		for (table = 0; table < IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES;
		     table++)
			ipsec_sadb.refTable[table] = NULL;
	}

	/* allocate the first sub-table */
	error = ipsec_SArefSubTable_alloc(0);
	if (error)
		return error;

	error = ipsec_saref_freelist_init();
	return error;
}

static IPsecSAref_t ipsec_SAref_alloc(int *error) /* pass in error var by pointer */
{
	IPsecSAref_t SAref;

	KLIPS_PRINT(debug_xform,
		    "ipsec_SAref_alloc: "
		    "SAref requested... head=%d, cont=%d, tail=%d, listsize=%d.\n",
		    ipsec_sadb.refFreeListHead,
		    ipsec_sadb.refFreeListCont,
		    ipsec_sadb.refFreeListTail,
		    IPSEC_SA_REF_FREELIST_NUM_ENTRIES);

	if (ipsec_sadb.refFreeListHead == IPSEC_SAREF_NULL) {
		KLIPS_PRINT(debug_xform,
			    "ipsec_SAref_alloc: "
			    "FreeList empty, recycling...\n");
		*error = ipsec_SAref_recycle();
		if (*error)
			return IPSEC_SAREF_NULL;
	}

	SAref = ipsec_sadb.refFreeList[ipsec_sadb.refFreeListHead];
	if (SAref == IPSEC_SAREF_NULL) {
		KLIPS_ERROR(debug_xform,
			    "ipsec_SAref_alloc: "
			    "unexpected error, refFreeListHead = %d points to invalid entry.\n",
			    ipsec_sadb.refFreeListHead);
		*error = -ESPIPE;
		return IPSEC_SAREF_NULL;
	}

	KLIPS_PRINT(debug_xform,
		    "ipsec_SAref_alloc: "
		    "allocating SAref=%d, table=%u, entry=%u of %u.\n",
		    SAref,
		    IPsecSAref2table(SAref),
		    IPsecSAref2entry(SAref),
		    IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES *
		    IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES);

	ipsec_sadb.refFreeList[ipsec_sadb.refFreeListHead] = IPSEC_SAREF_NULL;
	ipsec_sadb.refFreeListHead++;
	if (ipsec_sadb.refFreeListHead > ipsec_sadb.refFreeListTail) {
		KLIPS_PRINT(debug_xform,
			    "ipsec_SAref_alloc: "
			    "last FreeList entry allocated, resetting list head to empty.\n");
		ipsec_sadb.refFreeListHead = IPSEC_SAREF_NULL;
	}

	return SAref;
}

#if 0
int ipsec_sa_print(struct ipsec_sa *ips)
{
	char sa[SATOT_BUF];
	size_t sa_len;

	printk(KERN_INFO "klips_debug:   SA:");
	if (ips == NULL) {
		printk("NULL\n");
		return -ENOENT;
	}
	printk(" ref=%d", ips->ips_ref);
	printk(" refcount=%d", atomic_read(&ips->ips_refcount));
	if (ips->ips_hnext != NULL)
		printk(" hnext=0p%p", ips->ips_hnext);
	if (ips->ips_next != NULL)
		printk(" next=0p%p", ips->ips_next);
	if (ips->ips_prev != NULL)
		printk(" prev=0p%p", ips->ips_prev);
	sa_len = KLIPS_SATOT(1, &ips->ips_said, 0, sa, sizeof(sa));
	printk(" said=%s", sa_len ? sa : " (error)");
	if (ips->ips_seq)
		printk(" seq=%u", ips->ips_seq);
	if (ips->ips_pid)
		printk(" pid=%u", ips->ips_pid);
	if (ips->ips_authalg)
		printk(" authalg=%u", ips->ips_authalg);
	if (ips->ips_encalg)
		printk(" encalg=%u", ips->ips_encalg);
	printk(" XFORM=%s%s%s", IPS_XFORM_NAME(ips));
	if (ips->ips_replaywin)
		printk(" ooowin=%u", ips->ips_replaywin);
	if (ips->ips_flags)
		printk(" flags=%u", ips->ips_flags);
	if (ips->ips_addr_s) {
		char buf[SUBNETTOA_BUF];
		sin_addrtot(ips->ips_addr_s, 0, buf, sizeof(buf));
		printk(" src=%s", buf);
	}
	if (ips->ips_addr_d) {
		char buf[SUBNETTOA_BUF];
		sin_addrtot(ips->ips_addr_s, 0, buf, sizeof(buf));
		printk(" dst=%s", buf);
	}
	if (ips->ips_addr_p) {
		char buf[SUBNETTOA_BUF];
		sin_addrtot(ips->ips_addr_p, 0, buf, sizeof(buf));
		printk(" proxy=%s", buf);
	}
	if (ips->ips_key_bits_a)
		printk(" key_bits_a=%u", ips->ips_key_bits_a);
	if (ips->ips_key_bits_e)
		printk(" key_bits_e=%u", ips->ips_key_bits_e);

	printk("\n");
	return 0;
}
#endif

struct ipsec_sa*ipsec_sa_alloc(int *error) /* pass in error var by pointer */
{
	struct ipsec_sa *ips;

	if ((ips = kmalloc(sizeof(*ips), GFP_ATOMIC) ) == NULL) {
		KLIPS_PRINT(debug_xform,
			    "ipsec_sa_alloc: "
			    "memory allocation error\n");
		*error = -ENOMEM;
		return NULL;
	}
	memset((caddr_t)ips, 0, sizeof(*ips));

#ifdef IPSEC_SA_RECOUNT_DEBUG
	ips->ips_raw = ipsec_sa_raw;
	ipsec_sa_raw = ips;
#endif

	/* return with at least counter = 1 */
	ipsec_sa_get(ips, IPSEC_REFALLOC);

	*error = 0;
	return ips;
}

void ipsec_sa_untern(struct ipsec_sa *ips)
{
	IPsecSAref_t ref = ips->ips_ref;
	int error;

	/* verify that we are removing correct item! */
	error = ipsec_saref_verify_slot(ref);
	if (error)
		return;

	if (IPsecSAref2SA(ref) == ips) {
		IPsecSAref2SA(ref) = NULL;
		ipsec_sa_put(ips, IPSEC_REFINTERN);
	} else {
		KLIPS_PRINT(debug_xform,
			    "ipsec_sa_untern: "
			    "ref=%u -> %p but untern'ing %p\n", ref,
			    IPsecSAref2SA(ref), ips);
	}

}

int ipsec_sa_intern(struct ipsec_sa *ips)
{
	int error = 0;
	IPsecSAref_t ref = ips->ips_ref;

	if (ref == IPSEC_SAREF_NULL) {
		ref = ipsec_SAref_alloc(&error); /* pass in error return by pointer */
		KLIPS_PRINT(debug_xform,
			    "ipsec_sa_intern: "
			    "allocated ref=%u for sa %p\n", ref, ips);

		if (ref == IPSEC_SAREF_NULL) {
			KLIPS_PRINT(debug_xform,
				    "ipsec_sa_intern: "
				    "SAref allocation error\n");
			return error;
		}

		ips->ips_ref = ref;
	}

	error = ipsec_saref_verify_slot(ref);
	if (error)
		return error;

	ipsec_sa_get(ips, IPSEC_REFINTERN);
	/*
	 * if there is an existing SA at this reference, then free it
	 * note, that nsa might == ips!. That's okay, we just incremented
	 * the reference count above.
	 */
	{
		struct ipsec_sa *nsa = IPsecSAref2SA(ref);
		if (nsa)
			ipsec_sa_put(nsa, IPSEC_REFINTERN);
	}

	KLIPS_PRINT(debug_xform,
		    "ipsec_sa_intern: "
		    "SAref[%d]=%p\n",
		    ips->ips_ref, ips);
	IPsecSAref2SA(ips->ips_ref) = ips;

	/* return OK */
	return 0;
}

struct ipsec_sa *ipsec_sa_getbyid(ip_said *said, int type)
{
	int hashval;
	struct ipsec_sa *ips;
	char sa[SATOT_BUF];
	size_t sa_len;

	if (said == NULL) {
		KLIPS_PRINT(debug_xform,
			    "ipsec_sa_getbyid: "
			    "null pointer passed in!\n");
		return NULL;
	}

	hashval = IPS_HASH(said);

	sa_len = KLIPS_SATOT(debug_xform, said, 0, sa, sizeof(sa));
	KLIPS_PRINT(debug_xform,
		    "ipsec_sa_getbyid: "
		    "linked entry in ipsec_sa table for hash=%d of SA:%s requested.\n",
		    hashval,
		    sa_len ? sa : " (error)");

	if ((ips = ipsec_sadb_hash[hashval]) == NULL) {
		KLIPS_PRINT(debug_xform,
			    "ipsec_sa_getbyid: "
			    "no entries in ipsec_sa table for hash=%d of SA:%s.\n",
			    hashval,
			    sa_len ? sa : " (error)");
		return NULL;
	}

	for (; ips; ips = ips->ips_hnext) {
		if (ips->ips_said.spi == said->spi &&
		    ip_address_eq(&ips->ips_said.dst, &said->dst) &&
		    ips->ips_said.proto == said->proto) {
			ipsec_sa_get(ips, type);
			return ips;
		}
	}

	KLIPS_PRINT(debug_xform,
		    "ipsec_sa_getbyid: "
		    "no entry in linked list for hash=%d of SA:%s.\n",
		    hashval,
		    sa_len ? sa : " (error)");
	return NULL;
}

struct ipsec_sa *ipsec_sa_getbyref(IPsecSAref_t ref, int type)
{
	struct ipsec_sa *ips;
	struct IPsecSArefSubTable *st =
		ipsec_sadb.refTable[IPsecSAref2table(ref)];

	if (st == NULL)
		return NULL;

	ips = st->entry[IPsecSAref2entry(ref)];
	if (ips)
		ipsec_sa_get(ips, type);
	return ips;
}

void __ipsec_sa_put(struct ipsec_sa *ips, const char *func, int line, int type)
{
	if (ips == NULL) {
		KLIPS_PRINT(debug_xform,
			    "ipsec_sa_put: "
			    "null pointer passed in!\n");
		return;
	}

	if (debug_xform) {
		char sa[SATOT_BUF];
		size_t sa_len;
		sa_len = KLIPS_SATOT(debug_xform, &ips->ips_said, 0, sa,
				     sizeof(sa));

		KLIPS_PRINT(debug_xform,
			    "ipsec_sa_put: "
			    "ipsec_sa %p SA:%s, ref:%d reference count (%d--) decremented by %s:%d.\n",
			    ips,
			    sa_len ? sa : " (error)",
			    ips->ips_ref,
			    atomic_read(&ips->ips_refcount),
			    func, line);
	}

#ifdef IPSEC_SA_RECOUNT_DEBUG
	if (type >= 0 && type < sizeof(ips->ips_track)) {
		unsigned long flags;
		local_irq_save(flags);
		if (ips->ips_track[type] == 0)
			printk("ipsec_sa_put: UNDERFLOW for %d @ %s %d\n",
			       type, func, line);
		else
			ips->ips_track[type]--;
		local_irq_restore(flags);
	} else {
		printk("BAD BAD BAD @ %s %d\n", func, line);
	}
#endif

	if (atomic_dec_and_test(&ips->ips_refcount)) {
		KLIPS_PRINT(debug_xform,
			    "ipsec_sa_put: freeing %p\n",
			    ips);
		/* it was zero */
		ipsec_sa_wipe(ips);
	}
}

struct ipsec_sa *__ipsec_sa_get(struct ipsec_sa *ips, const char *func,
				int line, int type)
{
	if (ips == NULL)
		return NULL;

	if (debug_xform) {
		char sa[SATOT_BUF];
		size_t sa_len;
		sa_len = KLIPS_SATOT(debug_xform, &ips->ips_said, 0, sa,
				     sizeof(sa));

		KLIPS_PRINT(debug_xform,
			    "ipsec_sa_get: "
			    "ipsec_sa %p SA:%s, ref:%d reference count (%d++) incremented by %s:%d.\n",
			    ips,
			    sa_len ? sa : " (error)",
			    ips->ips_ref,
			    atomic_read(&ips->ips_refcount),
			    func, line);
	}

	atomic_inc(&ips->ips_refcount);

#ifdef IPSEC_SA_RECOUNT_DEBUG
	if (type >= 0 && type < sizeof(ips->ips_track)) {
		unsigned long flags;
		local_irq_save(flags);
		if (ips->ips_track[type] == 255)
			printk("ipsec_sa_get: OVERFLOW for %d @ %s %d\n", type,
			       func, line);
		else
			ips->ips_track[type]++;
		local_irq_restore(flags);
	} else {
		printk("BAD BAD BAD @ %s %d\n", func, line);
	}
#endif

#if 0
	/*
	 * DAVIDM: if we include this code it means the SA is freed immediately
	 * on creation and then reused ! Not sure why it is here.
	 */

	if (atomic_dec_and_test(&ips->ips_refcount)) {
		KLIPS_PRINT(debug_xform,
			    "ipsec_sa_get: freeing %p\n",
			    ips);
		/* it was zero */
		ipsec_sa_wipe(ips);
	}
#endif

	return ips;
}

/*
   The ipsec_sa table better *NOT* be locked before it is handed in, or SMP locks will happen
 */
int ipsec_sa_add(struct ipsec_sa *ips)
{
	int error = 0;
	unsigned int hashval;

	if (ips == NULL) {
		KLIPS_PRINT(debug_xform,
			    "klips_error:ipsec_sa_add: "
			    "null pointer passed in!\n");
		return -ENODATA;
	}
	hashval = IPS_HASH(&ips->ips_said);

	ipsec_sa_get(ips, IPSEC_REFSAADD);
	spin_lock_bh(&tdb_lock);

	ips->ips_hnext = ipsec_sadb_hash[hashval];
	ipsec_sadb_hash[hashval] = ips;

	spin_unlock_bh(&tdb_lock);

	return error;
}

/*
 * remove it from the hash chain, decrementing hash count
 */
void ipsec_sa_rm(struct ipsec_sa *ips)
{
	unsigned int hashval;
	char sa[SATOT_BUF];
	size_t sa_len;

	if (ips == NULL)
		return;

	hashval = IPS_HASH(&ips->ips_said);

	sa_len = KLIPS_SATOT(debug_xform, &ips->ips_said, 0, sa, sizeof(sa));
	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_sa_del: "
		    "unhashing SA:%s (ref=%u), hashval=%d.\n",
		    sa_len ? sa : " (error)",
		    ips->ips_ref,
		    hashval);

	if (ipsec_sadb_hash[hashval] == NULL)
		return;

	if (ips == ipsec_sadb_hash[hashval]) {
		ipsec_sadb_hash[hashval] = ipsec_sadb_hash[hashval]->ips_hnext;
		ips->ips_hnext = NULL;
		ipsec_sa_put(ips, IPSEC_REFSAADD);
		KLIPS_PRINT(debug_xform,
			    "klips_debug:ipsec_sa_del: "
			    "successfully unhashed first ipsec_sa in chain.\n");
		return;
	} else {
		struct ipsec_sa *ipstp;

		for (ipstp = ipsec_sadb_hash[hashval];
		     ipstp;
		     ipstp = ipstp->ips_hnext) {
			if (ipstp->ips_hnext == ips) {
				ipstp->ips_hnext = ips->ips_hnext;
				ips->ips_hnext = NULL;
				ipsec_sa_put(ips, IPSEC_REFSAADD);
				KLIPS_PRINT(debug_xform,
					    "klips_debug:ipsec_sa_del: "
					    "successfully unhashed link in ipsec_sa chain.\n");
				return;
			}
		}
	}
}

#if 0
/*
 * The ipsec_sa table better be locked before it is handed in,
 * or races might happen.
 *
 * this routine assumes the SA has a refcount==0, and we free it.
 * we also assume that the pointers are already cleaned up.
 */
static int ipsec_sa_del(struct ipsec_sa *ips)
{
	unsigned int hashval;
	struct ipsec_sa *ipstp;
	char sa[SATOT_BUF];
	size_t sa_len;

	if (ips == NULL) {
		KLIPS_ERROR(debug_xform,
			    "klips_error:ipsec_sa_del: "
			    "null pointer passed in!\n");
		return -ENODATA;
	}

	if (ips->ips_next) {
		struct ipsec_sa *in = ips->ips_next;

		ips->ips_next = NULL;
		ipsec_sa_put(in);
	}

	sa_len = KLIPS_SATOT(debug_xform, &ips->ips_said, 0, sa, sizeof(sa));
	hashval = IPS_HASH(&ips->ips_said);

	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_sa_del: "
		    "deleting SA:%s (ref=%u), hashval=%d.\n",
		    sa_len ? sa : " (error)",
		    ips->ips_ref,
		    hashval);

	if (ipsec_sadb_hash[hashval] == NULL) {
		/* if this is NULL, then we can be sure that the SA was never
		 * added to the SADB, so we just free it.
		 */
		KLIPS_PRINT(debug_xform,
			    "klips_debug:ipsec_sa_del: "
			    "no entries in ipsec_sa table for hash=%d (ref=%u) of SA:%s.\n",
			    hashval,
			    ips->ips_ref,
			    sa_len ? sa : " (error)");
		return -ENOENT;
	}

	if (ips == ipsec_sadb_hash[hashval]) {
		ipsec_sadb_hash[hashval] = ipsec_sadb_hash[hashval]->ips_hnext;
		ips->ips_hnext = NULL;

		ipsec_sa_put(ips);
		KLIPS_PRINT(debug_xform,
			    "klips_debug:ipsec_sa_del: "
			    "successfully deleted first ipsec_sa in chain.\n");
		return 0;
	} else {
		for (ipstp = ipsec_sadb_hash[hashval];
		     ipstp;
		     ipstp = ipstp->ips_hnext) {
			if (ipstp->ips_hnext == ips) {
				ipstp->ips_hnext = ips->ips_hnext;
				ips->ips_hnext = NULL;
				ipsec_sa_put(ips);
				KLIPS_PRINT(debug_xform,
					    "klips_debug:ipsec_sa_del: "
					    "successfully deleted link in ipsec_sa chain.\n");
				return 0;
			}
		}
	}

	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_sa_del: "
		    "no entries in linked list for hash=%d of SA:%s.\n",
		    hashval,
		    sa_len ? sa : " (error)");
	return -ENOENT;
}
#endif

int ipsec_sadb_cleanup(__u8 proto)
{
	unsigned i;
	int error = 0;
	struct ipsec_sa *ips;

	/* struct ipsec_sa *ipsnext, **ipsprev; */
	/* char sa[SATOT_BUF]; */
	/* size_t sa_len; */

	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_sadb_cleanup: "
		    "cleaning up proto=%d.\n",
		    proto);

	spin_lock_bh(&tdb_lock);

	for (i = 0; i < SADB_HASHMOD; i++) {
		ips = ipsec_sadb_hash[i];

		while (ips) {
			ipsec_sadb_hash[i] = ips->ips_hnext;
			ips->ips_hnext = NULL;
			ipsec_sa_put(ips, IPSEC_REFSAADD);

			ips = ipsec_sadb_hash[i];
		}
	}

/* errlab: */

	spin_unlock_bh(&tdb_lock);

#if IPSEC_SA_REF_CODE
	/* clean up SA reference table */

	/* go through the ref table and clean out all the SAs */
	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_sadb_cleanup: "
		    "removing SAref entries and tables.");
	{
		unsigned table, entry;
		for (table = 0; table < IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES;
		     table++) {
			KLIPS_PRINT(debug_xform,
				    "klips_debug:ipsec_sadb_cleanup: "
				    "cleaning SAref table=%u.\n",
				    table);
			if (ipsec_sadb.refTable[table] == NULL) {
				printk("\n");
				KLIPS_PRINT(debug_xform,
					    "klips_debug:ipsec_sadb_cleanup: "
					    "cleaned %u used refTables.\n",
					    table);
				break;
			}
			for (entry = 0;
			     entry < IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES;
			     entry++) {
				if (ipsec_sadb.refTable[table]->entry[entry] !=
				    NULL) {
					struct ipsec_sa *sa1 =
						ipsec_sadb.refTable[table]->
						entry[entry];
					ipsec_sa_put(sa1, IPSEC_REFOTHER);
					ipsec_sadb.refTable[table]->entry[entry
					] = NULL;
				}
			}
		}
	}
#endif  /* IPSEC_SA_REF_CODE */

	return error;
}

int ipsec_sadb_free(void)
{
	int error = 0;

	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_sadb_free: "
		    "freeing SArefTable memory.\n");

	/* clean up SA reference table */

	/* go through the ref table and clean out all the SAs if any are
	   left and free table memory */
	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_sadb_free: "
		    "removing SAref entries and tables.\n");
	{
		unsigned table, entry;
		for (table = 0; table < IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES;
		     table++) {
			KLIPS_PRINT(debug_xform,
				    "klips_debug:ipsec_sadb_free: "
				    "removing SAref table=%u.\n",
				    table);
			if (ipsec_sadb.refTable[table] == NULL) {
				KLIPS_PRINT(debug_xform,
					    "klips_debug:ipsec_sadb_free: "
					    "removed %u used refTables.\n",
					    table);
				break;
			}
			for (entry = 0;
			     entry < IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES;
			     entry++) {
				if (ipsec_sadb.refTable[table]->entry[entry] !=
				    NULL) {
					struct ipsec_sa *sa1 =
						ipsec_sadb.refTable[table]->
						entry[entry];

					BUG_ON(atomic_read(&sa1->ips_refcount) ==
					       1);
					ipsec_sa_put(sa1, IPSEC_REFSAADD);
					ipsec_sadb.refTable[table]->entry[entry]
						= NULL;
				}
			}
			kfree(ipsec_sadb.refTable[table]);
			ipsec_sadb.refTable[table] = NULL;
		}
	}

	return error;
}

int ipsec_sa_wipe(struct ipsec_sa *ips)
{
	int hashval;
	struct ipsec_sa **tpp;

	if (ips == NULL)
		return -ENODATA;

#if IPSEC_SA_REF_CODE
	/* remove me from the SArefTable */
	if (debug_xform) {
		char sa[SATOT_BUF];
		size_t sa_len;
		struct IPsecSArefSubTable *subtable = NULL;

		if (IPsecSAref2table(IPsecSA2SAref(ips)) <
		    IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES &&
		    ipsec_sadb.refTable != NULL)
			subtable = ipsec_sadb.refTable[
				IPsecSAref2table(IPsecSA2SAref(ips))];

		sa_len = KLIPS_SATOT(debug_xform, &ips->ips_said, 0, sa,
				     sizeof(sa));
		KLIPS_PRINT(debug_xform,
			    "klips_debug:ipsec_sa_wipe: "
			    "removing SA=%s(0p%p), SAref=%d, table=%d(0p%p), entry=%d from the refTable.\n",
			    sa_len ? sa : " (error)",
			    ips,
			    ips->ips_ref,
			    IPsecSAref2table(IPsecSA2SAref(ips)),
			    subtable,
			    subtable ? IPsecSAref2entry(IPsecSA2SAref(ips)) : 0);
	}

	if (ips->ips_ref != IPSEC_SAREF_NULL) {
		struct IPsecSArefSubTable *subtable = NULL;
		int ref_table = IPsecSAref2table(IPsecSA2SAref(ips));
		int ref_entry = IPsecSAref2entry(IPsecSA2SAref(ips));

		if (ref_table < IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES) {
			subtable = ipsec_sadb.refTable[ref_table];
			if (subtable != NULL &&
			    subtable->entry[ref_entry] == ips) {
				subtable->entry[ref_entry] = NULL;
			}
		}
		ips->ips_ref = IPSEC_SAREF_NULL;
	}
#endif  /* IPSEC_SA_REF_CODE */

	/* paranoid clean up */
	if (ips->ips_addr_s != NULL) {
		memset((caddr_t)(ips->ips_addr_s), 0, ips->ips_addr_s_size);
		kfree(ips->ips_addr_s);
	}
	ips->ips_addr_s = NULL;

	if (ips->ips_addr_d != NULL) {
		memset((caddr_t)(ips->ips_addr_d), 0, ips->ips_addr_d_size);
		kfree(ips->ips_addr_d);
	}
	ips->ips_addr_d = NULL;

	if (ips->ips_addr_p != NULL) {
		memset((caddr_t)(ips->ips_addr_p), 0, ips->ips_addr_p_size);
		kfree(ips->ips_addr_p);
	}
	ips->ips_addr_p = NULL;

	if (ips->ips_natt_oa) {
		memset((caddr_t)(ips->ips_natt_oa), 0, ips->ips_natt_oa_size);
		kfree(ips->ips_natt_oa);
	}
	ips->ips_natt_oa = NULL;

	if (ips->ips_key_a != NULL) {
#ifdef CONFIG_KLIPS_ALG
		if (ips->ips_alg_auth &&
		    ips->ips_alg_auth->ixt_a_destroy_key)
		{
			ips->ips_alg_auth->ixt_a_destroy_key(ips->ips_alg_auth,
							     ips->ips_key_a);
		} else
#endif
		{
			memset((caddr_t)(ips->ips_key_a), 0, ips->ips_key_a_size);
			kfree(ips->ips_key_a);
		}
	}
	ips->ips_key_a = NULL;

	if (ips->ips_key_e != NULL) {
#ifdef CONFIG_KLIPS_ALG
		if (ips->ips_alg_enc &&
		    ips->ips_alg_enc->ixt_e_destroy_key) {
			ips->ips_alg_enc->ixt_e_destroy_key(ips->ips_alg_enc,
							    ips->ips_key_e);
		} else
#endif
		{
			memset((caddr_t)(ips->ips_key_e), 0,
			       ips->ips_key_e_size);
			kfree(ips->ips_key_e);
		}
	}
	ips->ips_key_e = NULL;

	if (ips->ips_iv != NULL) {
		memset((caddr_t)(ips->ips_iv), 0, ips->ips_iv_size);
		kfree(ips->ips_iv);
	}
	ips->ips_iv = NULL;

#ifdef CONFIG_KLIPS_OCF
	if (ips->ocf_in_use)
		ipsec_ocf_sa_free(ips);
#endif

	if (ips->ips_ident_s.data != NULL) {
		memset((caddr_t)(ips->ips_ident_s.data),
		       0,
		       ips->ips_ident_s.len * IPSEC_PFKEYv2_ALIGN -
		       sizeof(struct sadb_ident));
		kfree(ips->ips_ident_s.data);
	}
	ips->ips_ident_s.data = NULL;

	if (ips->ips_ident_d.data != NULL) {
		memset((caddr_t)(ips->ips_ident_d.data),
		       0,
		       ips->ips_ident_d.len * IPSEC_PFKEYv2_ALIGN -
		       sizeof(struct sadb_ident));
		kfree(ips->ips_ident_d.data);
	}
	ips->ips_ident_d.data = NULL;

#ifdef CONFIG_KLIPS_ALG
	if (ips->ips_alg_enc || ips->ips_alg_auth)
		ipsec_alg_sa_wipe(ips);
	ips->ips_alg_enc = NULL;
	ips->ips_alg_auth = NULL;

#endif
	if (ips->ips_prev)
		ips->ips_prev->ips_next = ips->ips_next;
	if (ips->ips_next) {
		ips->ips_next->ips_prev = ips->ips_prev;
		ipsec_sa_put(ips->ips_next, IPSEC_REFALLOC);
	}
	ips->ips_next = NULL;
	ips->ips_prev = NULL;

	hashval = IPS_HASH(&ips->ips_said);
	tpp = &ipsec_sadb_hash[hashval];
	while (*tpp) {
		if (*tpp == ips)
			*tpp = ips->ips_hnext;
		else
			tpp = &((*tpp)->ips_hnext);
	}
	if (ips->ips_hnext)
		ipsec_sa_put(ips->ips_hnext, IPSEC_REFALLOC);
	ips->ips_hnext = NULL;

	BUG_ON(atomic_read(&ips->ips_refcount) != 0);

#ifdef IPSEC_SA_RECOUNT_DEBUG
	if (ips == ipsec_sa_raw) {
		ipsec_sa_raw = ips->ips_raw;
	} else {
		struct ipsec_sa *raw = ipsec_sa_raw;
		while (raw) {
			if (raw->ips_raw == ips) {
				raw->ips_raw = ips->ips_raw;
				break;
			}
			raw = raw->ips_raw;
		}
	}
#endif
	if (ips->ips_out != NULL) {
		ipsec_dev_put(ips->ips_out);
		ips->ips_out = NULL;
	}

	memset((caddr_t)ips, 0, sizeof(*ips));
	kfree(ips);
	ips = NULL;

	return 0;
}

extern int sysctl_ipsec_debug_verbose;

int ipsec_sa_init(struct ipsec_sa *ipsp)
{
	int error = 0;
	char sa[SATOT_BUF];
	size_t sa_len;

#ifdef CONFIG_KLIPS_DEBUG
	char ipaddr_txt[ADDRTOA_BUF];
	char ipaddr2_txt[ADDRTOA_BUF];
#endif
#if defined (CONFIG_KLIPS_AUTH_HMAC_MD5) || \
	defined (CONFIG_KLIPS_AUTH_HMAC_SHA1)
	unsigned char kb[AHMD596_BLKLEN];
	int i;
#endif

	if (ipsp == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "ipsec_sa_init: "
			    "ipsp is NULL, fatal\n");
		SENDERR(EINVAL);
	}

	sa_len = KLIPS_SATOT(debug_pfkey, &ipsp->ips_said, 0, sa, sizeof(sa));

	KLIPS_PRINT(debug_pfkey,
		    "ipsec_sa_init: "
		    "(pfkey defined) called for SA:%s\n",
		    sa_len ? sa : " (error)");

	KLIPS_PRINT(debug_pfkey,
		    "ipsec_sa_init: "
		    "calling init routine of %s%s%s\n",
		    IPS_XFORM_NAME(ipsp));

	switch (ipsp->ips_said.proto) {
#ifdef CONFIG_KLIPS_IPIP
	case IPPROTO_IPIP: {
		ipsp->ips_xformfuncs = ipip_xform_funcs;
#ifdef CONFIG_KLIPS_DEBUG
		sin_addrtot(ipsp->ips_addr_s, 0, ipaddr_txt,
			    sizeof(ipaddr_txt));
		sin_addrtot(ipsp->ips_addr_d, 0, ipaddr2_txt,
			    sizeof(ipaddr2_txt));
		KLIPS_PRINT(debug_pfkey,
			    "ipsec_sa_init: "
			    "(pfkey defined) IPIP ipsec_sa set for %s->%s.\n",
			    ipaddr_txt,
			    ipaddr2_txt);
#endif
	}
	break;
#endif          /* !CONFIG_KLIPS_IPIP */

#ifdef CONFIG_KLIPS_AH
	case IPPROTO_AH:

		ipsp->ips_xformfuncs = ah_xform_funcs;

#ifdef CONFIG_KLIPS_OCF
		if (ipsec_ocf_sa_init(ipsp, ipsp->ips_authalg, 0))
			break;
#endif

#ifdef CONFIG_KLIPS_ALG
		error = ipsec_alg_auth_key_create(ipsp);
		if ((error < 0) && (error != -EPROTO))
			SENDERR(-error);

		if (error == -EPROTO) {
			/* perform manual key generation,
			   ignore this particular error */
			error = 0;
#endif              /* CONFIG_KLIPS_ALG */

		switch (ipsp->ips_authalg) {
# ifdef CONFIG_KLIPS_AUTH_HMAC_MD5
		case AH_MD5: {
			unsigned char *akp;
			unsigned int aks;
			MD5_CTX *ictx;
			MD5_CTX *octx;

			if (ipsp->ips_key_bits_a != (AHMD596_KLEN * 8)) {
				KLIPS_PRINT(debug_pfkey,
					    "ipsec_sa_init: "
					    "incorrect key size: %d bits -- must be %d bits\n" /*octets (bytes)\n"*/,
					    ipsp->ips_key_bits_a, AHMD596_KLEN *
					    8);
				SENDERR(EINVAL);
			}

#  if KLIPS_DIVULGE_HMAC_KEY
			KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
				    "ipsec_sa_init: "
				    "hmac md5-96 key is 0x%08x %08x %08x %08x\n",
				    ntohl(*(((__u32 *)ipsp->ips_key_a) + 0)),
				    ntohl(*(((__u32 *)ipsp->ips_key_a) + 1)),
				    ntohl(*(((__u32 *)ipsp->ips_key_a) + 2)),
				    ntohl(*(((__u32 *)ipsp->ips_key_a) + 3)));
#  endif                        /* KLIPS_DIVULGE_HMAC_KEY */

			ipsp->ips_auth_bits = AHMD596_ALEN * 8;

			/* save the pointer to the key material */
			akp = ipsp->ips_key_a;
			aks = ipsp->ips_key_a_size;

			KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
				    "ipsec_sa_init: "
				    "allocating %zu bytes for md5_ctx.\n",
				    sizeof(struct md5_ctx));
			if ((ipsp->ips_key_a = (caddr_t)
					       kmalloc(sizeof(struct md5_ctx),
						       GFP_ATOMIC)) == NULL) {
				ipsp->ips_key_a = akp;
				SENDERR(ENOMEM);
			}
			ipsp->ips_key_a_size = sizeof(struct md5_ctx);

			for (i = 0; i < DIVUP(ipsp->ips_key_bits_a, 8); i++)
				kb[i] = akp[i] ^ HMAC_IPAD;
			for (; i < AHMD596_BLKLEN; i++)
				kb[i] = HMAC_IPAD;

			ictx = &(((struct md5_ctx*)(ipsp->ips_key_a))->ictx);
			osMD5Init(ictx);
			osMD5Update(ictx, kb, AHMD596_BLKLEN);

			for (i = 0; i < AHMD596_BLKLEN; i++)
				kb[i] ^= (HMAC_IPAD ^ HMAC_OPAD);

			octx = &(((struct md5_ctx*)(ipsp->ips_key_a))->octx);
			osMD5Init(octx);
			osMD5Update(octx, kb, AHMD596_BLKLEN);

#  if KLIPS_DIVULGE_HMAC_KEY
			KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
				    "ipsec_sa_init: "
				    "MD5 ictx=0x%08x %08x %08x %08x octx=0x%08x %08x %08x %08x\n",
				    ((__u32*)ictx)[0],
				    ((__u32*)ictx)[1],
				    ((__u32*)ictx)[2],
				    ((__u32*)ictx)[3],
				    ((__u32*)octx)[0],
				    ((__u32*)octx)[1],
				    ((__u32*)octx)[2],
				    ((__u32*)octx)[3] );
#  endif                        /* KLIPS_DIVULGE_HMAC_KEY */

			/* zero key buffer -- paranoid */
			memset(akp, 0, aks);
			kfree(akp);
		}
		break;
# endif                 /* CONFIG_KLIPS_AUTH_HMAC_MD5 */
# ifdef CONFIG_KLIPS_AUTH_HMAC_SHA1
		case AH_SHA: {
			unsigned char *akp;
			unsigned int aks;
			SHA1_CTX *ictx;
			SHA1_CTX *octx;

			if (ipsp->ips_key_bits_a != (AHSHA196_KLEN * 8)) {
				KLIPS_PRINT(debug_pfkey,
					    "ipsec_sa_init: "
					    "incorrect key size: %d bits -- must be %d bits\n" /*octets (bytes)\n"*/,
					    ipsp->ips_key_bits_a, AHSHA196_KLEN *
					    8);
				SENDERR(EINVAL);
			}

#  if KLIPS_DIVULGE_HMAC_KEY
			KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
				    "ipsec_sa_init: "
				    "hmac sha1-96 key is 0x%08x %08x %08x %08x\n",
				    ntohl(*(((__u32 *)ipsp->ips_key_a) + 0)),
				    ntohl(*(((__u32 *)ipsp->ips_key_a) + 1)),
				    ntohl(*(((__u32 *)ipsp->ips_key_a) + 2)),
				    ntohl(*(((__u32 *)ipsp->ips_key_a) + 3)));
#  endif                        /* KLIPS_DIVULGE_HMAC_KEY */

			ipsp->ips_auth_bits = AHSHA196_ALEN * 8;

			/* save the pointer to the key material */
			akp = ipsp->ips_key_a;
			aks = ipsp->ips_key_a_size;

			KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
				    "ipsec_sa_init: "
				    "allocating %zu bytes for sha1_ctx.\n",
				    sizeof(struct sha1_ctx));
			if ((ipsp->ips_key_a = (caddr_t)
					       kmalloc(sizeof(struct sha1_ctx),
						       GFP_ATOMIC)) == NULL) {
				ipsp->ips_key_a = akp;
				SENDERR(ENOMEM);
			}
			ipsp->ips_key_a_size = sizeof(struct sha1_ctx);

			for (i = 0; i < DIVUP(ipsp->ips_key_bits_a, 8); i++)
				kb[i] = akp[i] ^ HMAC_IPAD;
			for (; i < AHMD596_BLKLEN; i++)
				kb[i] = HMAC_IPAD;

			ictx = &(((struct sha1_ctx*)(ipsp->ips_key_a))->ictx);
			SHA1Init(ictx);
			SHA1Update(ictx, kb, AHSHA196_BLKLEN);

			for (i = 0; i < AHSHA196_BLKLEN; i++)
				kb[i] ^= (HMAC_IPAD ^ HMAC_OPAD);

			octx = &(((struct sha1_ctx*)(ipsp->ips_key_a))->octx);
			SHA1Init(octx);
			SHA1Update(octx, kb, AHSHA196_BLKLEN);

#  if KLIPS_DIVULGE_HMAC_KEY
			KLIPS_PRINT(debug_pfkey && sysctl_ipsec_debug_verbose,
				    "ipsec_sa_init: "
				    "SHA1 ictx=0x%08x %08x %08x %08x octx=0x%08x %08x %08x %08x\n",
				    ((__u32*)ictx)[0],
				    ((__u32*)ictx)[1],
				    ((__u32*)ictx)[2],
				    ((__u32*)ictx)[3],
				    ((__u32*)octx)[0],
				    ((__u32*)octx)[1],
				    ((__u32*)octx)[2],
				    ((__u32*)octx)[3] );
#  endif                        /* KLIPS_DIVULGE_HMAC_KEY */
			/* zero key buffer -- paranoid */
			memset(akp, 0, aks);
			kfree(akp);
		}
		break;
# endif                 /* CONFIG_KLIPS_AUTH_HMAC_SHA1 */
		default:
			KLIPS_PRINT(debug_pfkey,
				    "ipsec_sa_init: "
				    "authalg=%d support not available in the kernel",
				    ipsp->ips_authalg);
			SENDERR(EINVAL);
		}
#ifdef CONFIG_KLIPS_ALG
			/* closure of the -EPROTO condition above */
		}
#endif
		break;
#endif          /* CONFIG_KLIPS_AH */

#ifdef CONFIG_KLIPS_ESP
	case IPPROTO_ESP:
		ipsp->ips_xformfuncs = esp_xform_funcs;
		{
#ifdef CONFIG_KLIPS_OCF
			if (ipsec_ocf_sa_init(ipsp, ipsp->ips_authalg,
					      ipsp->ips_encalg))
				break;
#endif

#ifdef CONFIG_KLIPS_ALG
			error = ipsec_alg_enc_key_create(ipsp);
			if (error < 0)
				SENDERR(-error);

			error = ipsec_alg_auth_key_create(ipsp);
			if ((error < 0) && (error != -EPROTO))
				SENDERR(-error);

			if (error == -EPROTO) {
				/* perform manual key generation,
				   ignore this particular error */
				error = 0;
#endif                  /* CONFIG_KLIPS_ALG */

			switch (ipsp->ips_authalg) {
#if defined (CONFIG_KLIPS_AUTH_HMAC_MD5) || \
				defined (CONFIG_KLIPS_AUTH_HMAC_SHA1)
				unsigned char *akp;
				unsigned int aks;
#endif
# ifdef CONFIG_KLIPS_AUTH_HMAC_MD5
			case AH_MD5: {
				MD5_CTX *ictx;
				MD5_CTX *octx;

				if (ipsp->ips_key_bits_a !=
				    (AHMD596_KLEN * 8)) {
					KLIPS_PRINT(debug_pfkey,
						    "ipsec_sa_init: "
						    "incorrect authorisation key size: %d bits -- must be %d bits\n" /*octets (bytes)\n"*/,
						    ipsp->ips_key_bits_a,
						    AHMD596_KLEN * 8);
					SENDERR(EINVAL);
				}

#  if KLIPS_DIVULGE_HMAC_KEY
				KLIPS_PRINT(
					debug_pfkey && sysctl_ipsec_debug_verbose,
					"ipsec_sa_init: "
					"hmac md5-96 key is 0x%08x %08x %08x %08x\n",
					ntohl(*(((__u32 *)(ipsp->ips_key_a)) +
						0)),
					ntohl(*(((__u32 *)(ipsp->ips_key_a)) +
						1)),
					ntohl(*(((__u32 *)(ipsp->ips_key_a)) +
						2)),
					ntohl(*(((__u32 *)(ipsp->ips_key_a)) +
						3)));
#  endif                                /* KLIPS_DIVULGE_HMAC_KEY */
				ipsp->ips_auth_bits = AHMD596_ALEN * 8;

				/* save the pointer to the key material */
				akp = ipsp->ips_key_a;
				aks = ipsp->ips_key_a_size;

				KLIPS_PRINT(
					debug_pfkey && sysctl_ipsec_debug_verbose,
					"ipsec_sa_init: "
					"allocating %zu bytes for md5_ctx.\n",
					sizeof(struct md5_ctx));
				if ((ipsp->ips_key_a = (caddr_t)
					kmalloc(sizeof(struct md5_ctx),
						GFP_ATOMIC)) == NULL) {
					ipsp->ips_key_a = akp;
					SENDERR(ENOMEM);
				}
				ipsp->ips_key_a_size = sizeof(struct md5_ctx);

				for (i = 0; i < DIVUP(ipsp->ips_key_bits_a, 8);
				     i++)
					kb[i] = akp[i] ^ HMAC_IPAD;
				for (; i < AHMD596_BLKLEN; i++)
					kb[i] = HMAC_IPAD;

				ictx = &(((struct md5_ctx*)(ipsp->ips_key_a))
					  ->ictx);
				osMD5Init(ictx);
				osMD5Update(ictx, kb, AHMD596_BLKLEN);

				for (i = 0; i < AHMD596_BLKLEN; i++)
					kb[i] ^= (HMAC_IPAD ^ HMAC_OPAD);

				octx = &(((struct md5_ctx*)(ipsp->ips_key_a))
					  ->octx);
				osMD5Init(octx);
				osMD5Update(octx, kb, AHMD596_BLKLEN);

#  if KLIPS_DIVULGE_HMAC_KEY
				KLIPS_PRINT(
					debug_pfkey && sysctl_ipsec_debug_verbose,
					"ipsec_sa_init: "
					"MD5 ictx=0x%08x %08x %08x %08x octx=0x%08x %08x %08x %08x\n",
					((__u32*)ictx)[0],
					((__u32*)ictx)[1],
					((__u32*)ictx)[2],
					((__u32*)ictx)[3],
					((__u32*)octx)[0],
					((__u32*)octx)[1],
					((__u32*)octx)[2],
					((__u32*)octx)[3] );
#  endif                                /* KLIPS_DIVULGE_HMAC_KEY */
				/* paranoid */
				memset(akp, 0, aks);
				kfree(akp);
				break;
			}
# endif                         /* CONFIG_KLIPS_AUTH_HMAC_MD5 */
# ifdef CONFIG_KLIPS_AUTH_HMAC_SHA1
			case AH_SHA: {
				SHA1_CTX *ictx;
				SHA1_CTX *octx;

				if (ipsp->ips_key_bits_a !=
				    (AHSHA196_KLEN * 8)) {
					KLIPS_PRINT(debug_pfkey,
						    "ipsec_sa_init: "
						    "incorrect authorisation key size: %d bits -- must be %d bits\n" /*octets (bytes)\n"*/,
						    ipsp->ips_key_bits_a,
						    AHSHA196_KLEN * 8);
					SENDERR(EINVAL);
				}

#  if KLIPS_DIVULGE_HMAC_KEY
				KLIPS_PRINT(
					debug_pfkey && sysctl_ipsec_debug_verbose,
					"ipsec_sa_init: "
					"hmac sha1-96 key is 0x%08x %08x %08x %08x\n",
					ntohl(*(((__u32 *)ipsp->ips_key_a) +
						0)),
					ntohl(*(((__u32 *)ipsp->ips_key_a) +
						1)),
					ntohl(*(((__u32 *)ipsp->ips_key_a) +
						2)),
					ntohl(*(((__u32 *)ipsp->ips_key_a) +
						3)));
#  endif                                /* KLIPS_DIVULGE_HMAC_KEY */
				ipsp->ips_auth_bits = AHSHA196_ALEN * 8;

				/* save the pointer to the key material */
				akp = ipsp->ips_key_a;
				aks = ipsp->ips_key_a_size;

				KLIPS_PRINT(
					debug_pfkey && sysctl_ipsec_debug_verbose,
					"ipsec_sa_init: "
					"allocating %zu bytes for sha1_ctx.\n",
					sizeof(struct sha1_ctx));
				if ((ipsp->ips_key_a = (caddr_t)
					kmalloc(sizeof(struct sha1_ctx),
						GFP_ATOMIC)) == NULL) {
					ipsp->ips_key_a = akp;
					SENDERR(ENOMEM);
				}
				ipsp->ips_key_a_size = sizeof(struct sha1_ctx);

				for (i = 0; i < DIVUP(ipsp->ips_key_bits_a, 8);
				     i++)
					kb[i] = akp[i] ^ HMAC_IPAD;
				for (; i < AHMD596_BLKLEN; i++)
					kb[i] = HMAC_IPAD;

				ictx = &(((struct sha1_ctx*)(ipsp->ips_key_a))
					  ->ictx);
				SHA1Init(ictx);
				SHA1Update(ictx, kb, AHSHA196_BLKLEN);

				for (i = 0; i < AHSHA196_BLKLEN; i++)
					kb[i] ^= (HMAC_IPAD ^ HMAC_OPAD);

				octx = &((struct sha1_ctx*)(ipsp->ips_key_a))
					->octx;
				SHA1Init(octx);
				SHA1Update(octx, kb, AHSHA196_BLKLEN);

#  if KLIPS_DIVULGE_HMAC_KEY
				KLIPS_PRINT(
					debug_pfkey && sysctl_ipsec_debug_verbose,
					"ipsec_sa_init: "
					"SHA1 ictx=0x%08x %08x %08x %08x octx=0x%08x %08x %08x %08x\n",
					((__u32*)ictx)[0],
					((__u32*)ictx)[1],
					((__u32*)ictx)[2],
					((__u32*)ictx)[3],
					((__u32*)octx)[0],
					((__u32*)octx)[1],
					((__u32*)octx)[2],
					((__u32*)octx)[3] );
#  endif                                /* KLIPS_DIVULGE_HMAC_KEY */
				memset(akp, 0, aks);
				kfree(akp);
				break;
			}
# endif                         /* CONFIG_KLIPS_AUTH_HMAC_SHA1 */
			case AH_NONE:
				break;
			default:
				KLIPS_PRINT(debug_pfkey,
					    "ipsec_sa_init: "
					    "authalg=%d support not available in the kernel.\n",
					    ipsp->ips_authalg);
				SENDERR(EINVAL);
			}
#ifdef CONFIG_KLIPS_ALG
			/* closure of the -EPROTO condition above */
		}
#endif

			ipsp->ips_iv_size =
				ipsp->ips_alg_enc->ixt_common.ixt_support.
				ias_ivlen / 8;

			/* Create IV */
			if (ipsp->ips_iv_size) {
				if ((ipsp->ips_iv = (caddr_t)
					kmalloc(ipsp->ips_iv_size,
						GFP_ATOMIC)) == NULL)
					SENDERR(ENOMEM);
				prng_bytes(&ipsec_prng, (char *)ipsp->ips_iv,
					   ipsp->ips_iv_size);
				ipsp->ips_iv_bits = ipsp->ips_iv_size * 8;
			}
		}
		break;
#endif          /* !CONFIG_KLIPS_ESP */
#ifdef CONFIG_KLIPS_IPCOMP
	case IPPROTO_COMP:

		ipsp->ips_xformfuncs = ipcomp_xform_funcs;

		ipsp->ips_comp_adapt_tries = 0;
		ipsp->ips_comp_adapt_skip = 0;
		ipsp->ips_comp_ratio_cbytes = 0;
		ipsp->ips_comp_ratio_dbytes = 0;

#ifdef CONFIG_KLIPS_OCF
		if (ipsec_ocf_comp_sa_init(ipsp, ipsp->ips_encalg))
			break;
#endif

		ipsp->ips_comp_adapt_tries = 0;
		ipsp->ips_comp_adapt_skip = 0;
		ipsp->ips_comp_ratio_cbytes = 0;
		ipsp->ips_comp_ratio_dbytes = 0;
		break;
#endif          /* CONFIG_KLIPS_IPCOMP */
	default:
		printk(KERN_ERR "KLIPS sa initialization: "
		       "proto=%d unknown.\n",
		       ipsp->ips_said.proto);
		SENDERR(EINVAL);
	}

errlab:
	return error;
}
